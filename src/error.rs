//! Application errors

use axum::{
    http::StatusCode,
    response::{IntoResponse, Response},
    Json,
};
use serde_json::json;
use thiserror::Error;

/// Global application error type
#[derive(Error, Debug)]
pub enum AppError {
    /// Database error
    #[error("Database error: {0}")]
    DbError(#[from] sea_orm::DbErr),

    /// Invalid input
    #[error("Invalid input: {0}")]
    InvalidInput(String),

    /// Unauthorized access
    #[error("Unauthorized: {0}")]
    Unauthorized(String),

    /// Forbidden access
    #[error("Forbidden: {0}")]
    Forbidden(String),

    /// Resource not found
    #[error("Not Found")]
    NotFound,

    /// The request conflicts with the current state of a resource (e.g. a unique-name collision)
    #[error("Conflict: {0}")]
    Conflict(String),

    /// A conflict the caller is expected to *resolve*, carrying the structured detail needed to do so.
    ///
    /// Exists for `RBAC_MODEL.md` §6's pre-flight inventory, which requires the refusal to return "a
    /// structured payload enumerating each owned entity with enough detail to decide its fate: type,
    /// id, name, and current owner". A bare message would make the caller go and find that itself, and
    /// the whole point of the refusal is that the service already knows.
    ///
    /// The `details` object is merged into the response body alongside `error`, so a client that only
    /// reads `error` behaves exactly as it does for [`Self::Conflict`].
    #[error("Conflict: {message}")]
    ConflictWithDetails {
        /// Human-readable summary, in the same `error` field every other variant uses.
        message: String,
        /// Machine-readable detail, merged into the response body at the top level.
        details: serde_json::Value,
    },

    /// A request body an extractor refused, carrying the extractor's own status verbatim.
    ///
    /// Exists so [`crate::extract::StrictJson`] can normalize the response *shape* — every failure on
    /// these routes is `{"error": …}` — without also normalizing the response *meaning*. A payload
    /// over the router-wide body limit arrives as the same rejection type as a payload with an
    /// unknown field, and flattening both to `400` would tell a caller that sent 4 MiB that its
    /// fields were wrong. The status is the extractor's to decide; only the body is ours.
    #[error("Request rejected: {1}")]
    BodyRejected(StatusCode, String),

    /// Internal server error
    #[error("Internal Server Error")]
    Internal,
}

/// Whether a [`sea_orm::DbErr`] is a transient lock/contention failure — the pool timing out
/// waiting for a connection, or the database itself refusing a statement because something else
/// holds the lock right now — as opposed to a genuine query/schema/data error.
///
/// The distinction matters because the two call for different responses. `busy_timeout`
/// ([`crate::db::SQLITE_BUSY_TIMEOUT_MS`]) already makes SQLite *wait* for ordinary contention
/// rather than fail immediately, so an error reaching here means that wait was exhausted — the
/// request did nothing wrong, it lost a race. `503` (not `500`) tells a well-behaved caller to
/// retry, the same reasoning [`crate::api::readiness_check`] already applies to a database that
/// cannot be reached at all.
///
/// Checked via the portable `DatabaseError::code()` (a SQLSTATE-shaped string, or SQLite's numeric
/// result code as a string) rather than matching the message text: message wording is not part of
/// any driver's stability contract, and this service is explicitly SQL-agnostic (`AGENT.MD`,
/// SQLite default / Postgres-ready).
///
/// `"55P03"`/`"40001"`/`"40P01"` are Postgres's `lock_not_available`/`serialization_failure`/
/// `deadlock_detected`. SQLite's side is not a fixed string: `sqlx`'s SQLite driver reports the
/// *extended* result code, not the primary one — a stale-snapshot write conflict under WAL (the
/// shape [`crate::api::handle_ip_upsert`]'s own `Immediate`-transaction comment describes) comes
/// back as `"517"` (`SQLITE_BUSY_SNAPSHOT`), not `"5"` (plain `SQLITE_BUSY`); a busy_timeout
/// exhausted while waiting on the write lock is `"773"` (`SQLITE_BUSY_TIMEOUT`). All of them share
/// the same low byte as their primary code — SQLite's extended codes are always
/// `primary | (variant << 8)` — so masking with `& 0xFF` and checking for `5`
/// (`SQLITE_BUSY`) or `6` (`SQLITE_LOCKED`) catches every variant without enumerating them.
fn is_transient_lock_error(err: &sea_orm::DbErr) -> bool {
    // Pool exhaustion surfaces as `ConnectionAcquire`, not as a runtime error, so it is matched
    // here as well: it is the same transient condition, and a client should retry it.
    if matches!(err, sea_orm::DbErr::ConnectionAcquire(_)) {
        return true;
    }
    let runtime_err = match err {
        sea_orm::DbErr::Conn(e) | sea_orm::DbErr::Exec(e) | sea_orm::DbErr::Query(e) => e,
        _ => return false,
    };
    let sea_orm::RuntimeErr::SqlxError(sqlx_err) = runtime_err else { return false };
    match sqlx_err.as_ref() {
        sea_orm::SqlxError::PoolTimedOut => true,
        sea_orm::SqlxError::Database(db_err) => match db_err.code().as_deref() {
            Some("55P03") | Some("40001") | Some("40P01") => true,
            Some(code) => code.parse::<u32>().is_ok_and(|n| matches!(n & 0xFF, 5 | 6)),
            None => false,
        },
        _ => false,
    }
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        // Handled ahead of the flat match because it is the one variant whose body is not just
        // `{"error": ...}` — the structured detail is merged in at the top level rather than nested,
        // so `error` reads identically to every other variant for a client that ignores the rest.
        if let AppError::ConflictWithDetails { message, details } = self {
            let mut body = json!({ "error": message });
            if let (Some(object), Some(extra)) = (body.as_object_mut(), details.as_object()) {
                for (k, v) in extra {
                    object.insert(k.clone(), v.clone());
                }
            }
            return (StatusCode::CONFLICT, Json(body)).into_response();
        }

        let (status, error_message) = match self {
            AppError::DbError(err) => {
                tracing::error!("Database error: {}", err);
                if is_transient_lock_error(&err) {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Database busy or query timeout, please retry".to_string(),
                    )
                } else {
                    (StatusCode::INTERNAL_SERVER_ERROR, "Internal database error".to_string())
                }
            }
            AppError::InvalidInput(msg) => (StatusCode::BAD_REQUEST, msg),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            AppError::Forbidden(msg) => (StatusCode::FORBIDDEN, msg),
            AppError::NotFound => (StatusCode::NOT_FOUND, "Resource not found".to_string()),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg),
            // Returned above; repeated here only because the match must stay exhaustive.
            AppError::ConflictWithDetails { message, .. } => (StatusCode::CONFLICT, message),
            AppError::BodyRejected(status, msg) => (status, msg),
            AppError::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "An internal server error occurred".to_string()),
        };

        let body = Json(json!({
            "error": error_message,
        }));

        (status, body).into_response()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::{ActiveModelTrait, ActiveValue::Set, Database, EntityTrait, TransactionTrait};
    use sea_orm_migration::MigratorTrait;

    /// A genuine `SQLITE_BUSY`, not a synthetic one — reproduced the same way
    /// [`crate::api::handle_ip_upsert`]'s own module comment describes it happening for real: a
    /// `BEGIN DEFERRED` transaction (the default) takes its read snapshot at its first statement,
    /// and a concurrent writer committing before this transaction's own first write leaves that
    /// snapshot stale. SQLite refuses to upgrade a stale snapshot to a write lock — immediately,
    /// **not** subject to `busy_timeout`'s retry loop (that only governs *waiting for a lock*, not
    /// a snapshot conflict) — which is exactly why this test needs no artificial timeout knob to
    /// observe the failure fast.
    ///
    /// Deliberately built from the same production helpers ([`crate::db::run_migrations_isolated`],
    /// [`crate::db::connect`]) every other concurrency test in this suite uses, rather than
    /// hand-rolled connection options — this is the busy_timeout/WAL configuration a real deployment
    /// actually runs with, not a synthetic stand-in for it.
    #[tokio::test]
    async fn genuine_sqlite_busy_is_recognized_as_transient_and_maps_to_503() {
        let dir = std::env::temp_dir().join(format!("error_rs_busy_test_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let url = format!("sqlite://{}", dir.join("v.db").display());
        crate::db::run_migrations_isolated(&url).await.unwrap();
        let db = crate::db::connect(&url).await.unwrap();

        // A plain (deferred) transaction; the SELECT below is its first statement and pins the
        // snapshot it will see for the rest of its life.
        let txn = db.begin().await.unwrap();
        let _ = crate::entities::ip_group::Entity::find().all(&txn).await.unwrap();

        // A concurrent commit on a *different* pooled connection, advancing the database past the
        // snapshot `txn` already pinned.
        crate::entities::ip_group::ActiveModel {
            id: Set(uuid::Uuid::new_v4()),
            name: Set("busy-test-outside".to_owned()),
            group_type: Set("banlist".to_owned()),
            owner_key_id: Set(None),
            description: Set(None),
            created_at: Set(chrono::Utc::now().naive_utc()),
        }
        .insert(&db)
        .await
        .unwrap();

        // `txn` now attempts to write against its now-stale snapshot.
        let result = crate::entities::ip_group::ActiveModel {
            id: Set(uuid::Uuid::new_v4()),
            name: Set("busy-test-inside".to_owned()),
            group_type: Set("banlist".to_owned()),
            owner_key_id: Set(None),
            description: Set(None),
            created_at: Set(chrono::Utc::now().naive_utc()),
        }
        .insert(&txn)
        .await;

        let err = result.expect_err("txn must be refused — its snapshot went stale under it");
        assert!(is_transient_lock_error(&err), "expected a recognized transient lock error, got: {err:?}");

        let app_err = AppError::from(err);
        let response = app_err.into_response();
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);

        txn.rollback().await.ok();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The negative case: an ordinary, non-transient database error (here, a unique-constraint
    /// violation) must still map to `500`, not `503` — the distinction is not "any `DbError`",
    /// it is specifically lock/pool contention.
    #[tokio::test]
    async fn an_ordinary_db_error_is_not_misclassified_as_transient() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        crate::migration::Migrator::up(&db, None).await.unwrap();

        let id = uuid::Uuid::new_v4();
        let make = || crate::entities::ip_group::ActiveModel {
            id: Set(id),
            name: Set("dup-name-test".to_owned()),
            group_type: Set("banlist".to_owned()),
            owner_key_id: Set(None),
            description: Set(None),
            created_at: Set(chrono::Utc::now().naive_utc()),
        };
        make().insert(&db).await.unwrap();
        let err = make().insert(&db).await.expect_err("inserting the same id twice must violate the primary key");

        assert!(!is_transient_lock_error(&err), "a unique-constraint violation must not be classified as transient: {err:?}");
        let response = AppError::from(err).into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }
}
