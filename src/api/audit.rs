//! Audit log endpoint.
//!
//! Master-only, and its own module rather than a tail on another: it is the one read surface that
//! spans every domain, so filing it under any single one would be arbitrary.

use axum::{
    Extension,
    extract::{Json, State},
    response::IntoResponse,
};
use sea_orm::{ColumnTrait, Condition, EntityTrait, QueryFilter, QueryOrder, QuerySelect};
use serde::Deserialize;

use crate::entities::{api_key, audit_log};
use crate::error::AppError;
use crate::extract::StrictQuery;
use crate::state::AppState;

// ─────────────────────────────────────────────────────────────
// Audit Logs
// ─────────────────────────────────────────────────────────────

/// Query parameters for audit log listing. `deny_unknown_fields` so a misspelled parameter (a
/// caller writing `actions` for `action`) is refused with `400` rather than silently ignored and
/// answered as though no filter had been given.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditLogQuery {
    /// Filter by exact action type (e.g. `IP_ADD`)
    pub action: Option<String>,
    /// Filter by client IP substring
    pub client_ip: Option<String>,
    /// Filter by acting key name, prefix, or UUID
    pub api_key: Option<String>,
    /// Filter by start timestamp (inclusive, RFC 3339)
    pub since: Option<String>,
    /// Filter by end timestamp (inclusive, RFC 3339)
    pub until: Option<String>,
    /// Pagination limit
    pub limit: Option<u64>,
    /// Pagination offset
    pub offset: Option<u64>,
}

/// Handles GET /api/v1/audit-logs. Restricted to master keys: audit entries span every key and
/// group in the system, so a scoped key seeing them would be an RBAC leak regardless of its
/// per-group grants.
pub async fn list_audit_logs(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    StrictQuery(query): StrictQuery<AuditLogQuery>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden(
            "Only master keys can view audit logs".to_owned(),
        ));
    }

    let mut q = audit_log::Entity::find().order_by_desc(audit_log::Column::Timestamp);
    if let Some(action) = query
        .action
        .as_deref()
        .map(str::trim)
        .filter(|a| !a.is_empty())
    {
        q = q.filter(audit_log::Column::Action.eq(action));
    }
    if let Some(client_ip) = query
        .client_ip
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        q = q.filter(audit_log::Column::ClientIp.contains(client_ip));
    }
    if let Some(key_filter) = query
        .api_key
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let mut cond = Condition::any()
            .add(audit_log::Column::ApiKeyName.contains(key_filter))
            .add(audit_log::Column::ApiKeyPrefix.contains(key_filter));
        if let Ok(uuid) = uuid::Uuid::parse_str(key_filter) {
            cond = cond.add(audit_log::Column::ApiKeyId.eq(uuid));
        }
        q = q.filter(cond);
    }
    if let Some(since_raw) = query
        .since
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let since_dt = chrono::DateTime::parse_from_rfc3339(since_raw)
            .map_err(|_| AppError::InvalidInput("Malformed 'since' RFC 3339 timestamp".to_owned()))?
            .naive_utc();
        q = q.filter(audit_log::Column::Timestamp.gte(since_dt));
    }
    if let Some(until_raw) = query
        .until
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let until_dt = chrono::DateTime::parse_from_rfc3339(until_raw)
            .map_err(|_| AppError::InvalidInput("Malformed 'until' RFC 3339 timestamp".to_owned()))?
            .naive_utc();
        q = q.filter(audit_log::Column::Timestamp.lte(until_dt));
    }

    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);
    let logs = q.limit(limit).offset(offset).all(&state.db).await?;

    Ok(Json(logs))
}
