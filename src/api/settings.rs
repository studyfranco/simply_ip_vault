//! System settings & introspection endpoint (`GET /api/settings`).
//! Master-only: reports effective runtime configuration and entity counts.

use axum::Extension;
use axum::Json;
use axum::extract::State;
use axum::response::IntoResponse;
use sea_orm::{
    ConnectionTrait, EntityTrait, QuerySelect,
    sea_query::{Asterisk, Expr, Func},
};
use serde::Serialize;

use crate::entities::{api_key, audit_log, ip_group, ip_record, webhook_config, webhook_execution};
use crate::error::AppError;
use crate::state::AppState;

/// Counts rows directly using `SELECT COUNT(*) FROM <table>` without allocating a subquery.
async fn count_entity<E, C>(db: &C) -> Result<u64, AppError>
where
    E: EntityTrait,
    C: ConnectionTrait,
{
    let count: Option<i64> = E::find()
        .select_only()
        .expr_as(Func::count(Expr::col(Asterisk)), "num_items")
        .into_tuple::<i64>()
        .one(db)
        .await?;
    Ok(std::cmp::max(count.unwrap_or(0), 0) as u64)
}

/// Runtime system configuration and entity counts shown on the System Settings tab.
#[derive(Debug, Serialize)]
pub struct SettingsResponse {
    /// Peers whose forwarding headers are believed.
    pub trusted_proxies: Vec<String>,
    /// Whether secrets-at-rest encryption is active.
    pub encryption_enabled: bool,
    /// Number of concurrent background webhook workers.
    pub webhook_workers: usize,
    /// Interval between webhook dispatch sweeps, in milliseconds.
    pub webhook_dispatch_interval_ms: u64,
    /// In-memory queue capacity for pending webhook events.
    pub webhook_queue_capacity: usize,
    /// Maximum retry attempts for failed webhook dispatches.
    pub webhook_max_retries: u32,
    /// Total IP records currently stored.
    pub ip_record_count: u64,
    /// Total IP groups defined.
    pub ip_group_count: u64,
    /// Total active API keys.
    pub api_key_count: u64,
    /// Total webhook configurations.
    pub webhook_count: u64,
    /// Total webhook dispatch executions retained.
    pub execution_count: u64,
    /// Total audit log records retained.
    pub audit_log_count: u64,
}

/// Handles `GET /api/settings`. Master-only.
pub async fn get_settings(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    if !caller.is_master {
        return Err(AppError::Forbidden(
            "System settings are visible to the Master key only".to_owned(),
        ));
    }

    let ip_record_count = count_entity::<ip_record::Entity, _>(&state.db).await?;
    let ip_group_count = count_entity::<ip_group::Entity, _>(&state.db).await?;
    let api_key_count = count_entity::<api_key::Entity, _>(&state.db).await?;
    let webhook_count = count_entity::<webhook_config::Entity, _>(&state.db).await?;
    let execution_count = count_entity::<webhook_execution::Entity, _>(&state.db).await?;
    let audit_log_count = count_entity::<audit_log::Entity, _>(&state.db).await?;

    Ok(Json(SettingsResponse {
        trusted_proxies: state.trusted_proxies.matchers().iter().map(ToString::to_string).collect(),
        encryption_enabled: state.cipher.is_encrypting(),
        webhook_workers: crate::config::webhook_workers(),
        webhook_dispatch_interval_ms: crate::config::webhook_dispatch_interval().as_millis() as u64,
        webhook_queue_capacity: crate::config::webhook_queue_capacity(),
        webhook_max_retries: crate::config::webhook_max_retries(),
        ip_record_count,
        ip_group_count,
        api_key_count,
        webhook_count,
        execution_count,
        audit_log_count,
    }))
}
