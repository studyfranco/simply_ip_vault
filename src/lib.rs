#![warn(missing_docs)]
//! Simply IP Vault Library
//! This module provides the core API router, state, and webhook logic.

use axum::{
    Router,
    extract::DefaultBodyLimit,
    routing::{delete, get, post, put},
};
use sea_orm::DatabaseConnection;
use tokio::sync::mpsc;
use tower_http::services::ServeDir;
use tower_http::trace::TraceLayer;

/// Compile-time default ceiling on any request body, in bytes.
///
/// **Superseded at runtime by [`config::max_body_bytes`]**, which reads `MAX_BODY_SIZE_MIB` and
/// falls back to this. Kept as a named constant because the reasoning below is about the *limit*,
/// not about where its value comes from, and because both layers still resolve through one function
/// so they cannot disagree.
///
/// **The single source of truth for both body limits.** It is applied as an explicit
/// [`DefaultBodyLimit`] over the whole router *and* referenced by
/// `middleware::MAX_SIGNED_BODY_BYTES`, so the two can never drift apart. Three reasons it is
/// stated here rather than left implicit:
///
/// - **It is a security boundary, so it should be written down.** Every handler takes its payload
///   as `Json<T>`, which buffers the whole body in memory before the handler runs — and the auth
///   middleware buffers it earlier still, because the signature covers the raw bytes. Without a
///   bound, an unauthenticated caller can force unbounded allocation.
/// - **The two layers must agree exactly.** If the middleware's buffer were the larger of the two,
///   a body between the limits would be fully read and HMAC'd only to be rejected by the extractor
///   afterwards — paying the memory cost of a payload the service had already decided not to
///   accept. Independently-chosen constants are how parser-differential bugs start.
/// - **Axum's default is a default, not a guarantee.** Pinning it means a dependency upgrade cannot
///   silently widen the exposure.
///
/// A body over the limit is rejected with `413 Payload Too Large` before it is read to completion.
pub const MAX_REQUEST_BODY_BYTES: usize = config::DEFAULT_MAX_BODY_MIB * 1024 * 1024;

pub mod api;
pub mod config;
pub mod crypto;
pub mod db;
/// The outbound webhook dispatcher. Named `dispatch` rather than `webhooks` so it is never confused
/// with [`api::webhooks`], which configures them rather than sending them.
pub mod dispatch;
pub mod entities;
pub mod error;
pub mod extract;
pub mod maintenance;
pub mod master;
pub mod middleware;
pub mod migration;
pub mod replay;
pub mod retention;
pub mod state;

use state::{AppState, WebhookEvent};

/// Creates the complete Axum router for the application.
pub fn create_app(state: AppState) -> Router {
    // Protected API routes
    let api_routes = Router::new()
        .route("/auth/me", get(api::get_me))
        .route("/ips", get(api::list_ips))
        .route("/ips", delete(api::delete_ip))
        // Restore a soft-deleted membership. Identified by address and group, like DELETE /ips.
        .route("/ips/restore", post(api::restore_ip_record))
        .route("/system/purge-ips", post(api::purge_ip_records))
        // Bulk synchronisation for the companion exporter/sync worker. Distinct from the singular
        // `/ips` routes above: it is transactional, and its `full_replace` mode expresses "and
        // everything else in this group is gone", which no per-record call can.
        .route("/records/batch", post(api::batch_records))
        .route("/ban", post(api::handle_ban))
        .route("/white", post(api::handle_white))
        // Admin endpoints
        .route("/keys", post(api::create_api_key))
        .route("/keys", get(api::list_api_keys))
        .route("/keys/{id}", put(api::update_api_key))
        .route("/keys/{id}", delete(api::delete_api_key))
        .route("/keys/{id}/rotate", post(api::rotate_api_key))
        // Narrower sibling of `/rotate`: re-keys only the HMAC signing secret, leaving the key's
        // identity and RBAC grants untouched.
        .route("/keys/{id}/rotate-secret", post(api::rotate_signing_secret))
        .route("/keys/{id}/groups", post(api::update_key_group_permissions))
        // `/permissions` is the same assignment handler as `/groups` under a name that matches
        // the new revoke route below; `/groups` is kept working for backward compatibility.
        .route("/keys/{id}/permissions", post(api::update_key_group_permissions))
        .route("/keys/{id}/permissions/{group_identifier}", delete(api::revoke_key_group_permission))
        .route("/groups", post(api::create_ip_group))
        .route("/groups", get(api::list_ip_groups))
        .route("/groups/{id}", delete(api::delete_ip_group))
        .route("/ip_groups", post(api::create_ip_group))
        .route("/ip_groups", get(api::list_ip_groups))
        .route("/ip_groups/{id}", delete(api::delete_ip_group))
        // Ownership reassignment, master-only (RBAC_MODEL.md §3). Separate routes rather than a
        // field on the update payloads: `ip_groups` has no update endpoint at all, and folding a
        // master-only field into a delegable one invites a guard that checks the wrong thing.
        .route("/groups/{id}/owner", put(api::reassign_group_owner))
        .route("/ip_groups/{id}/owner", put(api::reassign_group_owner))
        .route("/webhooks", post(api::create_webhook))
        .route("/webhooks", get(api::list_webhooks))
        // Ahead of `/webhooks/{id}` in this list purely for readability — axum's router (matchit)
        // already prefers a literal segment over a path parameter at the same position regardless
        // of registration order, so `executions` can never be swallowed by `{id}`.
        .route("/webhooks/executions", get(api::list_webhook_executions))
        .route("/webhooks/executions/{id}", delete(api::delete_webhook_execution))
        .route("/webhooks/{id}", put(api::update_webhook))
        .route("/webhooks/{id}", delete(api::delete_webhook))
        .route("/webhooks/{id}/owner", put(api::reassign_webhook_owner))
        .route("/webhooks/{id}/test", post(api::test_webhook))
        .route("/webhooks/{id}/clone", post(api::clone_webhook))
        .route("/audit-logs", get(api::list_audit_logs))
        .layer(axum::middleware::from_fn_with_state(
            state.clone(),
            middleware::auth_middleware,
        ));

    // Root Router
    Router::new()
        .fallback_service(ServeDir::new("static"))
        // Liveness and readiness, mounted **here rather than inside `api_routes`** so they sit
        // outside `auth_middleware`. That placement is the entire point: the callers are Docker's
        // `HEALTHCHECK`, a Kubernetes probe, and a load balancer, none of which can compute an
        // HMAC over a body with a rolling timestamp. Both handlers are written to be safe without a
        // caller identity — no data, no error detail, no writes. See [`api::health`].
        //
        // Declared as routes rather than left to the static fallback, so a file dropped into
        // `static/health` could never shadow a probe.
        .route("/health", get(api::health_check))
        .route("/ready", get(api::readiness_check))
        // `/healthz` and `/readyz` are the Kubernetes-idiomatic spellings and cost nothing to
        // accept. Matching `simply_hook_executor` here matters more than usual: an operator writing
        // one set of manifests for both services should not have to remember which of the pair uses
        // which spelling.
        .route("/healthz", get(api::health_check))
        .route("/readyz", get(api::readiness_check))
        .nest("/api", api_routes)
        // Applied *outside* the nest so it covers `/api/*` and the static fallback alike. Inside,
        // it would leave the SPA path — which never reaches the auth middleware — unbounded, and a
        // limit that can be sidestepped by aiming at a different route is not a limit. No route
        // overrides it: `DefaultBodyLimit` is set exactly once, here.
        // `DefaultBodyLimit::max`, not `RequestBodyLimitLayer`. The latter rejects at the tower
        // layer with a bare `413` and no body, which would break the `{"error": …}` contract every
        // other failure on these routes honours — and `AppError::BodyRejected` exists precisely to
        // carry the extractor's status through *with* that shape. The limit is read once at router
        // construction, so it is fixed for the life of the process like every other security bound.
        .layer(DefaultBodyLimit::max(config::max_body_bytes()))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// Helper to create AppState and background worker.
///
/// Fails when a security-relevant environment variable is malformed — a bad `VAULT_ENCRYPTION_KEY`
/// (see [`crypto::SecretCipher::from_env`]) or a bad `TRUSTED_PROXIES` entry (see
/// [`config::TrustedProxies::from_env`]). Neither is recoverable: the first would write signing
/// secrets in the clear for an operator who believes they are encrypted, and the second would apply
/// a trust boundary different from the one they configured.
pub fn setup_state(
    db: DatabaseConnection,
) -> Result<
    (AppState, mpsc::Sender<WebhookEvent>, tokio::task::JoinHandle<()>),
    state::StartupConfigError,
> {
    let (tx, rx) = mpsc::channel::<WebhookEvent>(config::webhook_queue_capacity());
    let db_worker = db.clone();
    let worker_handle = tokio::spawn(async move {
        dispatch::run_webhook_worker(db_worker, rx).await;
    });

    let state = AppState::new(db, tx.clone())?;

    Ok((state, tx, worker_handle))
}
