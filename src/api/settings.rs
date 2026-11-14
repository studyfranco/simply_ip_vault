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
#[derive(Debug, Serialize, Clone)]
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

    // Fast check: return cached settings if fresh (< 120s / 2 minutes).
    // Prevents repeated expensive full table counts when multiple tabs or dashboard pollers refresh.
    {
        let cache_read = state.settings_cache.read().await;
        if let Some((ts, ref payload)) = *cache_read {
            if ts.elapsed() < std::time::Duration::from_secs(120) {
                return Ok(Json(payload.clone()).into_response());
            }
        }
    }

    // Acquire singleflight lock to serialize concurrent settings requests
    // and prevent database lock contention / disk cache thrashing.
    let _singleflight_guard = state.settings_lock.lock().await;

    // Double-checked locking: check cache again after acquiring lock.
    {
        let cache_read = state.settings_cache.read().await;
        if let Some((ts, ref payload)) = *cache_read {
            if ts.elapsed() < std::time::Duration::from_secs(120) {
                return Ok(Json(payload.clone()).into_response());
            }
        }
    }

    let ip_record_count = count_entity::<ip_record::Entity, _>(&state.db).await?;
    let ip_group_count = count_entity::<ip_group::Entity, _>(&state.db).await?;
    let api_key_count = count_entity::<api_key::Entity, _>(&state.db).await?;
    let webhook_count = count_entity::<webhook_config::Entity, _>(&state.db).await?;
    let execution_count = count_entity::<webhook_execution::Entity, _>(&state.db).await?;
    let audit_log_count = count_entity::<audit_log::Entity, _>(&state.db).await?;

    let response = SettingsResponse {
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
    };

    {
        let mut cache_write = state.settings_cache.write().await;
        *cache_write = Some((std::time::Instant::now(), response.clone()));
    }

    Ok(Json(response).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::Extension;
    use axum::extract::State;
    use sea_orm_migration::MigratorTrait;

    #[tokio::test]
    async fn settings_caches_response_and_reuses_it() {
        let db = sea_orm::Database::connect("sqlite::memory:").await.unwrap();
        crate::migration::Migrator::up(&db, None).await.unwrap();
        let (tx, _rx) = tokio::sync::mpsc::channel(10);
        let state = AppState::new(db, tx).unwrap();

        let master_key = api_key::Model {
            id: uuid::Uuid::new_v4(),
            name: "test-master".to_owned(),
            key_hash: "hash".to_owned(),
            signing_secret: None,
            prefix: "pref1234".to_owned(),
            bound_ips: None,
            is_master: true,
            can_manage_keys: true,
            can_manage_webhooks: true,
            can_create_groups: true,
            parent_key_id: None,
            created_at: chrono::Utc::now().naive_utc(),
            updated_at: chrono::Utc::now().naive_utc(),
        };

        // First call populates cache
        let _ = get_settings(State(state.clone()), Extension(master_key.clone()))
            .await
            .unwrap();
        assert!(state.settings_cache.read().await.is_some());

        // Second call hits cache
        let _ = get_settings(State(state.clone()), Extension(master_key))
            .await
            .unwrap();
        let cache_val = state.settings_cache.read().await.as_ref().unwrap().1.clone();
        assert_eq!(cache_val.ip_record_count, 0);
    }
}
