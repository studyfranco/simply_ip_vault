//! Unauthenticated liveness and readiness probes.
//!
//! # The one part of the API that is deliberately public
//!
//! Every other route in this service sits behind [`crate::middleware::auth_middleware`], which
//! demands an HMAC over a body with a rolling timestamp. These two do not, and that is the point: an
//! orchestrator restarting a wedged container, or a load balancer deciding whether to send traffic,
//! has no credential and must not need one. Requiring an API key for a liveness check means the probe
//! fails exactly when the credential store is the thing that broke — the moment the answer matters
//! most. Minting a long-lived key for the platform to hold is the worse trade.
//!
//! Because they are public, they are held to a rule the authenticated routes are not: **they must
//! disclose nothing an anonymous caller could not already infer.** A probe that leaked a version
//! string, a hostname, a row count, or a database error message would be a free reconnaissance
//! endpoint for anyone who can open a socket. See [`readiness_check`] for how a failing dependency is
//! reported without saying anything about it.
//!
//! # Liveness and readiness are different questions
//!
//! Conflating them is the classic way to turn a brief dependency outage into an outage of your own:
//!
//! - [`health_check`] answers *"is this process alive?"* It touches nothing and cannot fail. An
//!   orchestrator uses it to decide whether to **restart** the container.
//! - [`readiness_check`] answers *"can this process serve traffic right now?"* It reaches the
//!   database. A load balancer uses it to decide whether to **route** to the container.
//!
//! If liveness also checked the database, then a database that went away for thirty seconds would
//! make every replica fail liveness, and the orchestrator would kill and restart all of them — which
//! does not fix a database and does destroy any in-flight work. Restarting a process because
//! something *else* is broken is strictly harmful, so liveness stays local by construction.

use axum::{Json, extract::State, http::StatusCode, response::IntoResponse};
use sea_orm::{EntityTrait, QuerySelect};
use serde_json::json;

use crate::state::AppState;

/// Handles `GET /health` (and `/healthz`) — liveness. Always `200 OK`.
///
/// It takes no [`State`], which is not an oversight but the guarantee: a handler that cannot reach
/// the database cannot be made to fail by the database being down, and the compiler enforces that
/// rather than a comment asking future editors to remember it.
///
/// The body is a fixed two-field document. `service` is the crate name, already implied by whatever
/// the caller connected to, and `status` is a constant. Nothing here varies with runtime state, so
/// nothing here can leak it.
///
/// A `version` field was reported here until the parity audit and has been removed. It told an
/// anonymous caller which build is deployed, which is the first thing worth knowing before looking up
/// what that build is vulnerable to — a free reconnaissance answer on a route that exists to be
/// polled by machines. An operator who needs the version has the image tag and the log banner.
pub async fn health_check() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "service": env!("CARGO_PKG_NAME"),
        })),
    )
}

/// Handles `GET /ready` (and `/readyz`) — readiness. `200` when this process can serve traffic,
/// `503` when it cannot.
///
/// Two things are checked, and both are properties of *this process* rather than of the request:
///
/// 1. **The database answers.** A bounded read of at most one id — not a `COUNT(*)`, which on a large
///    `api_keys` table would make every probe a table scan and turn the health check itself into
///    load. A probe that can be amplified into unbounded work is a denial-of-service primitive aimed
///    at the endpoint that exists to report health.
/// 2. **The Master identity is pinned.** `main.rs` pins before binding the listener, so in production
///    this is a `OnceLock` read that cannot be false. It is asserted anyway because that ordering is
///    a *convention* enforced by one line, and a future edit that bound first would otherwise produce
///    a service reporting itself ready while every master-only route quietly refused.
///
/// # The response body says as little as possible
///
/// `{"status":"ready","database":"up"}` or `{"status":"unavailable","database":"up"|"down"}` — the
/// same vocabulary the peer uses. A failing probe does **not** name which check failed and never
/// carries the error: `DbErr` renders connection strings, host names, and driver internals, and those
/// go to the operator's log at `error` level where an operator can read them and an anonymous caller
/// cannot. A load balancer needs one bit.
///
/// `503` rather than `500` is deliberate: it is the status that tells a well-behaved proxy to stop
/// routing here and retry, whereas `500` describes a request that failed. Nothing about this request
/// failed — the answer *is* "not ready", and it was produced successfully.
///
/// > **Two deliberate divergences from `simply_hook_executor`.** The peer probes with a literal
/// > `SELECT 1`; this service uses a typed SeaORM query, because `verify_convergence.sh` bans raw SQL
/// > for DML anywhere in `src/` and an allowlisted exception would be a hole in a gate that is worth
/// > more than the one saved query. The peer also does not check the Master pin. Both differences
/// > make this side stricter, and both are recorded in `AGENT_NOTES.MD`.
pub async fn readiness_check(State(state): State<AppState>) -> impl IntoResponse {
    if let Err(e) = crate::entities::prelude::ApiKey::find()
        .select_only()
        .column(crate::entities::api_key::Column::Id)
        .limit(1)
        .into_tuple::<uuid::Uuid>()
        .all(&state.db)
        .await
    {
        tracing::error!("Readiness probe failed: the database is unreachable: {e}");
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "unavailable", "database": "down" })),
        );
    }

    if state.master_pin.get().is_none() {
        tracing::error!(
            "Readiness probe failed: no Master identity is pinned. This process should not have \
             bound its listener — see main.rs and RBAC_MODEL.md §5."
        );
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({ "status": "unavailable", "database": "up" })),
        );
    }

    (
        StatusCode::OK,
        Json(json!({ "status": "ready", "database": "up" })),
    )
}
