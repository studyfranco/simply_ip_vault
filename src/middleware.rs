//! Authentication middleware

use axum::{
    body::Body,
    extract::State,
    http::Request,
    middleware::Next,
    response::Response,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};
use sha2::{Digest, Sha256};
use ipnet::IpNet;

use crate::crypto::{self, MAX_TIMESTAMP_SKEW_SECS};
use crate::entities::prelude::ApiKey;
use crate::error::AppError;
use crate::state::AppState;

/// Largest request body the auth middleware will buffer in order to verify its signature, in bytes.
///
/// The signature covers the raw body, so the body must be fully read *before* the request reaches a
/// handler. That makes the allocation unavoidable, and therefore a cap required.
///
/// Resolved through [`crate::config::max_body_bytes`], the **same function** the router's
/// `DefaultBodyLimit` calls — not a separately-chosen constant. Two independently-picked numbers
/// leave a band of sizes that one layer accepts and the other refuses, which is exactly the
/// parser-differential shape that turns into a bug: a body between the limits would be fully
/// buffered and HMAC'd here only to be rejected by the extractor afterwards, paying the memory cost
/// of a payload the service had already decided not to accept. One function, two callers, no band.
///
/// **How exposed this allocation is.** Buffering happens *after* the key lookup (step 3 of the
/// ordering below), so reaching it requires a caller whose key hash is in the database — not an
/// anonymous one. That is what makes a 10 MiB default defensible where it would not be if the body
/// were read first. It is still a per-in-flight-request cost multiplied by concurrency, so an
/// operator issuing many low-trust keys should lower `MAX_BODY_SIZE_MIB` rather than assume the
/// default is free.
fn max_signed_body_bytes() -> usize {
    crate::config::max_body_bytes()
}

/// The resolved client IP for the current request (rightmost `X-Forwarded-For` hop, `X-Real-IP`,
/// or raw TCP peer address — see [`auth_middleware`]). Inserted into request extensions so
/// downstream handlers can attribute audit log entries to a real client address without
/// re-deriving it. A dedicated newtype (rather than a bare `Extension<std::net::IpAddr>`) avoids
/// ever silently colliding with some other, unrelated `IpAddr` extension in the future.
#[derive(Clone, Copy, Debug)]
pub struct ClientIp(pub std::net::IpAddr);

/// Validates `X-Timestamp` against the server clock, returning the header's raw string for signing.
///
/// The raw string — not a re-serialized integer — is what gets fed to the HMAC: the caller signed
/// the exact bytes it sent, so normalizing (e.g. stripping a leading zero) would break otherwise
/// valid requests.
///
/// The parsed value is deliberately *not* returned. [`crate::replay::ReplayGuard`] used to need it
/// to decide when a recorded signature could be forgotten; it now expires entries against the
/// monotonic clock instead, so the caller-supplied timestamp no longer influences retention at all.
/// That is the point of the change — a value an attacker controls should not be able to shorten how
/// long its own signature is remembered.
///
/// Failures are reported as `401 Unauthorized` rather than `400 Bad Request`: a missing, malformed,
/// or stale timestamp is a failure to authenticate the request, and `AGENT.MD` specifies `401` for
/// the anti-replay rejection specifically.
fn validate_timestamp(headers: &axum::http::HeaderMap) -> Result<String, AppError> {
    let raw = headers
        .get("X-Timestamp")
        .and_then(|h| h.to_str().ok())
        .map(str::trim)
        .ok_or_else(|| AppError::Unauthorized("Missing X-Timestamp header".to_owned()))?;

    let supplied: i64 = raw
        .parse()
        .map_err(|_| AppError::Unauthorized("Malformed X-Timestamp header".to_owned()))?;

    let skew = chrono::Utc::now().timestamp().saturating_sub(supplied).abs();
    if skew > MAX_TIMESTAMP_SKEW_SECS {
        tracing::warn!(
            "Rejected request: X-Timestamp is {}s off the server clock (limit {}s)",
            skew,
            MAX_TIMESTAMP_SKEW_SECS
        );
        return Err(AppError::Unauthorized(format!(
            "Request timestamp outside the permitted {MAX_TIMESTAMP_SKEW_SECS}s window"
        )));
    }

    Ok(raw.to_owned())
}

/// The request target a signature is computed over: the path **plus the query string** when one is
/// present.
///
/// `OriginalUri` is essential here, not a nicety: this middleware is layered *inside*
/// `.nest("/api", ...)`, and nesting rewrites `req.uri()` to the path relative to the mount point
/// (`/ips`, not `/api/ips`). Clients sign the URL they actually requested, so signing the stripped
/// target would make every signature mismatch. The `uri` fallback only applies if the route is ever
/// un-nested, in which case the two are identical anyway.
fn signed_target(parts: &axum::http::request::Parts) -> String {
    let uri = parts
        .extensions
        .get::<axum::extract::OriginalUri>()
        .map(|original| &original.0)
        .unwrap_or(&parts.uri);

    uri.path_and_query()
        .map(|pq| pq.as_str().to_owned())
        .unwrap_or_else(|| uri.path().to_owned())
}

/// Middleware enforcing HMAC-SHA256 request authentication, anti-replay, and CIDR restrictions.
///
/// Every `/api/*` request must carry three headers:
/// - `X-API-Key` — the plaintext key, used only to look up the key record by its SHA-256 hash.
/// - `X-Timestamp` — current UTC Unix time in seconds; must be within
///   [`MAX_TIMESTAMP_SKEW_SECS`] of the server's clock or the request is rejected as a replay.
/// - `X-Signature-256` — `sha256=<hex>`, an HMAC-SHA256 over `METHOD\nTARGET\nTIMESTAMP\nRAW_BODY`
///   keyed with the looked-up key's `signing_secret`, where `TARGET` is the full request target
///   **including the query string**. The `sha256=` prefix is **required**; a bare hex digest is
///   rejected. See [`crypto::verify_signature`].
///
/// This is **unconditional for every key**. There is no per-key mode, no `REQUIRE_SIGNED_REQUESTS`
/// switch, and no route that opts out — `simply_ip_vault` is the internal, higher-trust half of the
/// pair and never speaks to third-party senders, so there is no interoperability argument for a
/// weaker posture. Callers are shell scripts (fail2ban, portsentry) that compute this with one
/// `openssl dgst -sha256 -hmac`, which is not an operational burden worth trading authentication
/// for. `simply_hook_executor` keeps a per-key configurable posture for the opposite reason; that
/// asymmetry is intentional.
///
/// # Ordering: authenticate, then authorize
///
/// 1. Resolve the client IP (no I/O beyond a possible cached DNS lookup).
/// 2. Validate `X-Timestamp` — no database round-trip, so a stale or absent timestamp costs an
///    unauthenticated caller nothing of ours.
/// 3. Look up the key by hash.
/// 4. Buffer the body and verify the HMAC.
/// 5. Reject a signature already seen inside the window (replay).
/// 6. **Only then** check `bound_ips`.
///
/// Step 6 must stay last. Running the network-binding check before the signature would let a caller
/// who cannot prove possession of the signing secret learn, from the `403`-vs-`401` distinction
/// alone, whether a key it merely guessed is bound to the caller's own network — an oracle that
/// turns key guessing into key *mapping*. Both failures must be indistinguishable until the caller
/// has proven it holds the secret.
pub async fn auth_middleware(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::ConnectInfo(addr): axum::extract::ConnectInfo<std::net::SocketAddr>,
    req: Request<Body>,
    next: Next,
) -> Result<Response, AppError> {
    // `X-Forwarded-For`/`X-Real-IP` are honoured **only** when the TCP peer is a configured trusted
    // proxy; every other caller is identified by its peer address alone. See
    // `crate::config::resolve_client_ip` — this is what stops any client from satisfying an
    // arbitrary `bound_ips` restriction by writing an allowed address into a request header.
    //
    // `resolved()` is what turns a hostname entry into addresses. It is awaited per request so a
    // container that moved is picked up within the DNS reuse window rather than at the next
    // restart; with no hostnames configured it is a refcount bump and touches neither lock nor
    // resolver.
    let trusted_proxies = state.trusted_proxies.resolved().await;
    let client_ip = crate::config::resolve_client_ip(addr.ip(), &headers, &trusted_proxies);

    // Freshness first: it needs no database round-trip, so a stale or absent timestamp is rejected
    // before an unauthenticated caller can cost us a query.
    let timestamp = validate_timestamp(&headers)?;

    let auth_header = req
        .headers()
        .get("X-API-Key")
        .and_then(|h| h.to_str().ok())
        .ok_or(AppError::Unauthorized("Missing API Key".to_owned()))?;

    let provided_signature = headers
        .get("X-Signature-256")
        .and_then(|h| h.to_str().ok())
        .map(|s| s.to_owned())
        .ok_or_else(|| AppError::Unauthorized("Missing X-Signature-256 header".to_owned()))?;

    // A malformed *shape* is worth naming, because the alternative is an operator staring at
    // "Invalid request signature" while their HMAC is in fact correct. `crypto::verify_signature`
    // enforces this too and is the authority — this check exists only so the 401 is diagnosable, and
    // it must stay a pure string test on a value the caller already sent us. It reveals nothing: the
    // header format is public, and the answer does not depend on the key, the secret, or the body.
    //
    // Placed before the key lookup for the same reason `validate_timestamp` is: a request that
    // cannot be well-formed should not cost a database round-trip.
    if !provided_signature.trim().starts_with(crypto::SIGNATURE_PREFIX) {
        return Err(AppError::Unauthorized(
            "X-Signature-256 must be formatted as sha256=<hex>".to_owned(),
        ));
    }

    // Hash the provided key
    let mut hasher = Sha256::new();
    hasher.update(auth_header.as_bytes());
    let key_hash = hex::encode(hasher.finalize());

    // Find the API key in the database
    let key_record = ApiKey::find()
        .filter(crate::entities::api_key::Column::KeyHash.eq(key_hash))
        .one(&state.db)
        .await
        .map_err(AppError::DbError)?
        .ok_or(AppError::Unauthorized("Invalid API Key".to_owned()))?;

    // Verify the HMAC signature *before* the CIDR check: authenticate, then authorize. Running the
    // network-binding check first would let a caller who cannot prove possession of the signing
    // secret learn — from the 403-vs-401 distinction alone — whether a key it merely guessed is
    // bound to the caller's own network. The signed message covers the raw body, so the body has to
    // be buffered here and re-attached below for the handler to deserialize.
    let signing_secret = key_record
        .signing_secret
        .as_deref()
        .ok_or_else(|| {
            tracing::warn!(
                "API key {} ({}) has no signing secret — it predates HMAC authentication.",
                key_record.id,
                key_record.prefix
            );
            AppError::Unauthorized(
                "This API key has no signing secret; rotate it to obtain one".to_owned(),
            )
        })
        .map(|stored| state.cipher.open(stored).map_err(AppError::from))??;

    let method = req.method().as_str().to_owned();

    let (parts, body) = req.into_parts();
    // The full request target, query string included — see `crypto::verify_signature`.
    let target = signed_target(&parts);
    let body_bytes = axum::body::to_bytes(body, max_signed_body_bytes())
        .await
        .map_err(|e| {
            tracing::warn!("Rejected request: unreadable or oversized body: {}", e);
            AppError::InvalidInput("Request body unreadable or too large to sign".to_owned())
        })?;

    // On success this hands back the raw decoded digest, which is what the replay guard is keyed on.
    // Taking the bytes from here rather than re-parsing the header means `sha256=AB…` and
    // `sha256=ab…` cannot be recorded as two distinct single uses.
    let Some(digest) = crypto::verify_signature(
        &signing_secret,
        &method,
        &target,
        &timestamp,
        &body_bytes,
        &provided_signature,
    ) else {
        tracing::warn!(
            "Rejected request: invalid X-Signature-256 for key {} on {} {}",
            key_record.prefix,
            method,
            target
        );
        return Err(AppError::Unauthorized("Invalid request signature".to_owned()));
    };

    // Freshness proves the request is *recent*; it does not prove it is *new*. An attacker who
    // captured one authentic request — a mirrored packet on a plain-HTTP LAN link, a proxy access
    // log, a debug trace — can resend those exact bytes for the rest of the window and every copy
    // verifies, because every field the signature covers is unchanged. Recording each accepted
    // signature until its timestamp leaves the window closes that.
    //
    // Deliberately *after* verification: recording unverified signatures would let an
    // unauthenticated caller both exhaust memory and pre-insert a signature a legitimate client is
    // about to send, turning the guard into a denial-of-service tool against that client.
    if !state.replay.check_and_record(key_record.id, &digest) {
        tracing::warn!(
            "Rejected replay: X-Signature-256 for key {} on {} {} was already used within the \
             {MAX_TIMESTAMP_SKEW_SECS}s window",
            key_record.prefix,
            method,
            target
        );
        return Err(AppError::Unauthorized(
            "This request signature has already been used; sign a fresh request".to_owned(),
        ));
    }

    // Now that the caller has proven it holds the signing secret, authorize its source network.
    let bound_ips_str = key_record.bound_ips.as_deref().unwrap_or("");
    let networks: Vec<IpNet> = bound_ips_str
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| {
            s.parse::<IpNet>().or_else(|_| {
                s.parse::<std::net::IpAddr>()
                    .map(|ip| IpNet::from(crate::config::normalize_ip(ip)))
            })
        })
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| {
            tracing::error!("Invalid CIDR in database: {:?}", key_record.bound_ips);
            AppError::Internal
        })?;

    // An empty `bound_ips` means "unrestricted" and is how a key opts out; a *populated* one is
    // enforced against every key, master included. Exempting master keys made the single most
    // powerful credential in the system the only one whose network restriction was decorative —
    // and it silently ignored a restriction an operator had explicitly configured, which is worse
    // than never offering the field.
    let is_allowed = networks.is_empty() || networks.iter().any(|net| net.contains(&client_ip));

    if !is_allowed {
        tracing::warn!(
            "Access denied: Client IP {} not in bound networks {:?} for key {} (master={})",
            client_ip,
            key_record.bound_ips,
            key_record.prefix,
            key_record.is_master
        );
        return Err(AppError::Forbidden("Client IP not allowed".to_owned()));
    }

    // The pinned-master check, applied at the one point a key model enters the request.
    //
    // This is the *only* call site, and it has to stay that way. Every authorization guard downstream
    // reads `key.is_master`, and there are dozens of them; if the check lived in the guards it would
    // have to be repeated in each, and the first one written without it would be a silent hole.
    // Demoting the record here instead means a promoted impostor arrives at every existing handler —
    // and every handler written after this — as the ordinary key it actually is, with no per-handler
    // cooperation required. See [`crate::master::MasterPin::authenticate`] for why it demotes rather
    // than rejects, and for the §5 reasoning behind the whole mechanism.
    let mut key_record = key_record;
    state.master_pin.authenticate(&state.db, &mut key_record).await;

    let key_id = key_record.id;
    let mut req = Request::from_parts(parts, Body::from(body_bytes));
    req.extensions_mut().insert(ClientIp(client_ip));
    req.extensions_mut().insert(key_record);

    let res = next.run(req).await;
    if res.status().is_server_error() {
        state.replay.unrecord(key_id, &digest);
    }

    Ok(res)
}
