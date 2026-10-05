//! Background retention worker: permanently drops soft-deleted IP memberships once they age out.
//!
//! A soft delete (`ip_records.is_deleted`) is reversible by design — it exists so a mistyped
//! `DELETE`, or one issued by a compromised delegated key, is recoverable. That safety net is only
//! worth anything if it is *bounded*: without a purge the table grows forever and "deleted" data
//! lives indefinitely, which is a data-retention problem rather than a safety feature.
//!
//! 92 days ≈ one quarter, chosen so a record deleted at the start of a quarter survives review at
//! its end. Configurable through [`RETENTION_DAYS_ENV`]; `0` disables purging entirely for
//! operators who would rather keep everything and manage it themselves.

use std::time::Duration;

use chrono::Utc;
use sea_orm::{
    ColumnTrait, DatabaseConnection, DbErr, EntityTrait, QueryFilter, TransactionTrait,
    sea_query::{Expr, ExprTrait, Query},
};
use tokio::sync::mpsc;

use crate::entities::{ip_record, ip_record_group_membership, webhook_execution};

/// Days a soft-deleted record is kept before the purge removes it for good.
pub const DEFAULT_RETENTION_DAYS: i64 = 92;

/// Overrides [`DEFAULT_RETENTION_DAYS`]. `0` disables purging.
pub const RETENTION_DAYS_ENV: &str = "IP_RETENTION_DAYS";

/// Overrides the interval between sweeps, in seconds. Defaults to hourly.
pub const RETENTION_SWEEP_ENV: &str = "IP_RETENTION_SWEEP_SECONDS";

/// Default seconds between sweeps.
const DEFAULT_SWEEP_SECONDS: u64 = 3600;

/// Reads the configured retention window, falling back to [`DEFAULT_RETENTION_DAYS`].
///
/// A malformed value warns and falls back rather than aborting startup — matching how the rest of
/// the codebase treats bad overrides — and the fallback is the *safe* direction here: keeping data
/// longer than intended is recoverable, deleting it early is not.
pub fn retention_days_from_env() -> i64 {
    match std::env::var(RETENTION_DAYS_ENV) {
        Ok(raw) => match raw.trim().parse::<i64>() {
            Ok(days) if days >= 0 => days,
            _ => {
                tracing::warn!(
                    "Invalid {RETENTION_DAYS_ENV} value {raw:?} — falling back to \
                     {DEFAULT_RETENTION_DAYS} days."
                );
                DEFAULT_RETENTION_DAYS
            }
        },
        Err(_) => DEFAULT_RETENTION_DAYS,
    }
}

/// Reads the configured sweep interval, clamped to at least one second.
fn sweep_seconds_from_env() -> u64 {
    match std::env::var(RETENTION_SWEEP_ENV) {
        Ok(raw) => std::cmp::max(raw.trim().parse::<u64>().unwrap_or(DEFAULT_SWEEP_SECONDS), 1),
        Err(_) => DEFAULT_SWEEP_SECONDS,
    }
}

/// Permanently deletes soft-deleted memberships whose `deleted_at` is older than `retention_days`,
/// then removes any canonical address row that no group still references.
///
/// Returns the number of memberships removed. A non-positive `retention_days` disables purging and
/// is a no-op, so an operator can retain the trash indefinitely without also disabling the worker.
///
/// Both conditions are required on a membership: a row with `deleted_at` set but `is_deleted =
/// false` is a *restored* membership that kept its old timestamp, and purging it would silently
/// destroy live data.
///
/// Order matters: memberships first, then orphaned addresses. The cause history goes with its
/// membership via `ON DELETE CASCADE`. An address still held by another group keeps its row.
pub async fn purge_expired_ip_records(
    db: &DatabaseConnection,
    retention_days: i64,
) -> Result<u64, DbErr> {
    if retention_days <= 0 {
        return Ok(0);
    }

    let threshold = (Utc::now() - chrono::Duration::days(retention_days)).naive_utc();

    let txn = db.begin().await?;
    let result = ip_record_group_membership::Entity::delete_many()
        .filter(ip_record_group_membership::Column::IsDeleted.eq(true))
        .filter(ip_record_group_membership::Column::DeletedAt.is_not_null())
        .filter(ip_record_group_membership::Column::DeletedAt.lt(threshold))
        .exec(&txn)
        .await?;

    ip_record::Entity::delete_many()
        .filter(
            Expr::col((ip_record::Entity, ip_record::Column::Id)).not_in_subquery(
                Query::select()
                    .column((ip_record_group_membership::Entity, ip_record_group_membership::Column::IpRecordId))
                    .from(ip_record_group_membership::Entity)
                    .to_owned(),
            ),
        )
        .exec(&txn)
        .await?;

    txn.commit().await?;
    Ok(result.rows_affected)
}

/// Runs the retention sweep on a fixed interval until shutdown.
///
/// The worker owns the receiving half of a channel whose sender lives in `main`; dropping that
/// sender is the shutdown signal, so the worker stops cleanly during graceful shutdown rather than
/// being aborted mid-delete. The first tick fires immediately, so a process restarted more often
/// than the sweep interval still clears its backlog.
pub async fn run_retention_worker(db: DatabaseConnection, mut shutdown: mpsc::Receiver<()>) {
    let retention_days = retention_days_from_env();
    if retention_days <= 0 {
        tracing::info!(
            "IP retention purge is disabled ({RETENTION_DAYS_ENV}=0): soft-deleted records are \
             kept indefinitely."
        );
        return;
    }

    let sweep_seconds = sweep_seconds_from_env();
    tracing::info!(
        retention_days,
        sweep_seconds,
        "IP retention worker started — soft-deleted records are purged after {retention_days} days."
    );

    let mut ticker = tokio::time::interval(Duration::from_secs(sweep_seconds));
    // If a sweep runs long (a large backlog on slow storage), skip the ticks it missed rather than
    // firing them back to back the moment it finishes.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                match purge_expired_ip_records(&db, retention_days).await {
                    Ok(0) => tracing::debug!("Retention sweep: nothing to purge."),
                    Ok(n) => tracing::info!("Retention sweep: purged {n} soft-deleted IP record(s)."),
                    Err(e) => tracing::error!("Retention sweep failed: {e}"),
                }
            }
            _ = shutdown.recv() => break,
        }
    }

    tracing::info!("IP retention worker shut down.");
}

// ─────────────────────────────────────────────────────────────
// Webhook execution history retention
// ─────────────────────────────────────────────────────────────
//
// `webhook_executions` (one row per outbound HTTP attempt a dispatch makes, `src/dispatch.rs`) is
// operational delivery history, not data anyone is expected to keep indefinitely — unlike the
// soft-deleted IP records above, there is no "undo" story for it, only "how long is it worth
// investigating a delivery problem." Success and failure get **different** windows rather than one
// shared one: a confirmed-successful delivery has nothing left to look at once it is confirmed, while
// a failure is exactly the row an operator is most likely to still need days later to diagnose a
// flaky or newly-broken receiver.

/// Hours a successful (`is_success = true`) execution row is kept before the purge removes it.
pub const DEFAULT_EXECUTION_RETENTION_SUCCESS_HOURS: i64 = 24;

/// Hours a failed (`is_success = false`) execution row is kept — a full week, deliberately much
/// longer than the success window, since a failure is what an operator comes back to investigate.
pub const DEFAULT_EXECUTION_RETENTION_FAILURE_HOURS: i64 = 168;

/// Overrides [`DEFAULT_EXECUTION_RETENTION_SUCCESS_HOURS`]. `0` disables purging successful rows.
pub const EXECUTION_RETENTION_SUCCESS_HOURS_ENV: &str = "WEBHOOK_EXECUTION_RETENTION_SUCCESS_HOURS";

/// Overrides [`DEFAULT_EXECUTION_RETENTION_FAILURE_HOURS`]. `0` disables purging failed rows.
pub const EXECUTION_RETENTION_FAILURE_HOURS_ENV: &str = "WEBHOOK_EXECUTION_RETENTION_FAILURE_HOURS";

/// Reads one of the two execution-retention windows, falling back to `default` on an unset or
/// malformed value. Shared by both env vars above rather than duplicated, since the parse-and-warn
/// behaviour is identical — only the variable name and default differ.
fn execution_retention_hours_from_env(env_var: &str, default: i64) -> i64 {
    match std::env::var(env_var) {
        Ok(raw) => match raw.trim().parse::<i64>() {
            Ok(hours) if hours >= 0 => hours,
            _ => {
                tracing::warn!(
                    "Invalid {env_var} value {raw:?} — falling back to {default} hours."
                );
                default
            }
        },
        Err(_) => default,
    }
}

/// Permanently deletes `webhook_executions` rows older than their outcome's configured window.
///
/// Returns the number of rows removed. Each threshold is independently disable-able (a non-positive
/// value keeps that outcome's rows forever) — an operator who wants to keep every failure but not
/// every success can express that directly, rather than the two being coupled to one knob.
pub async fn purge_expired_webhook_executions(
    db: &DatabaseConnection,
    success_retention_hours: i64,
    failure_retention_hours: i64,
) -> Result<u64, DbErr> {
    let mut removed = 0u64;

    if success_retention_hours > 0 {
        let threshold = (Utc::now() - chrono::Duration::hours(success_retention_hours)).naive_utc();
        let result = webhook_execution::Entity::delete_many()
            .filter(webhook_execution::Column::IsSuccess.eq(true))
            .filter(webhook_execution::Column::CreatedAt.lt(threshold))
            .exec(db)
            .await?;
        removed += result.rows_affected;
    }

    if failure_retention_hours > 0 {
        let threshold = (Utc::now() - chrono::Duration::hours(failure_retention_hours)).naive_utc();
        let result = webhook_execution::Entity::delete_many()
            .filter(webhook_execution::Column::IsSuccess.eq(false))
            .filter(webhook_execution::Column::CreatedAt.lt(threshold))
            .exec(db)
            .await?;
        removed += result.rows_affected;
    }

    Ok(removed)
}

/// Runs the webhook-execution retention sweep on a fixed interval until shutdown.
///
/// Its own task and its own shutdown channel, separate from [`run_retention_worker`] above — the two
/// sweep different tables on independent schedules-in-principle (they happen to share
/// [`RETENTION_SWEEP_ENV`]'s cadence today, but nothing ties that together structurally), and a slow
/// sweep in one must never delay the other's tick.
pub async fn run_webhook_execution_retention_worker(
    db: DatabaseConnection,
    mut shutdown: mpsc::Receiver<()>,
) {
    let success_hours = execution_retention_hours_from_env(
        EXECUTION_RETENTION_SUCCESS_HOURS_ENV,
        DEFAULT_EXECUTION_RETENTION_SUCCESS_HOURS,
    );
    let failure_hours = execution_retention_hours_from_env(
        EXECUTION_RETENTION_FAILURE_HOURS_ENV,
        DEFAULT_EXECUTION_RETENTION_FAILURE_HOURS,
    );

    if success_hours <= 0 && failure_hours <= 0 {
        tracing::info!(
            "Webhook execution retention purge is fully disabled: execution history is kept \
             indefinitely."
        );
        return;
    }

    let sweep_seconds = sweep_seconds_from_env();
    tracing::info!(
        success_hours,
        failure_hours,
        sweep_seconds,
        "Webhook execution retention worker started."
    );

    let mut ticker = tokio::time::interval(Duration::from_secs(sweep_seconds));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                match purge_expired_webhook_executions(&db, success_hours, failure_hours).await {
                    Ok(0) => tracing::debug!("Execution retention sweep: nothing to purge."),
                    Ok(n) => tracing::info!("Execution retention sweep: purged {n} execution row(s)."),
                    Err(e) => tracing::error!("Execution retention sweep failed: {e}"),
                }
            }
            _ = shutdown.recv() => break,
        }
    }

    tracing::info!("Webhook execution retention worker shut down.");
}
