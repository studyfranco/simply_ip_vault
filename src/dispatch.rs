//! The outbound webhook dispatcher: the background worker that *sends* notifications.
//!
//! # Why this is `dispatch` and not `webhooks`
//!
//! It was `src/webhooks.rs` until the structural audit, which sat one directory away from
//! `src/api/webhooks.rs` — and the two do entirely different jobs. That module is the CRUD surface
//! for webhook **configuration**: a caller creating, listing, and deleting `webhook_config` rows.
//! This one is the **runtime**: it consumes [`WebhookEvent`]s off a channel, resolves each target
//! against the SSRF filter below, signs the body, and makes the outbound HTTP call. Nothing here
//! serves a request, and nothing in `api/webhooks.rs` ever sends one.
//!
//! Two files with the same name whose only distinction was a path prefix is the shape that gets
//! imported wrongly — and, worse, *reviewed* wrongly, because a diff header reading `webhooks.rs`
//! does not say which of the two security models applies.

use std::time::Duration;
use std::str::FromStr;
use std::net::IpAddr;
use crate::entities::{prelude::*, webhook_config::{self, AuthMode, DEFAULT_HMAC_TEMPLATE}, webhook_execution};
use crate::state::WebhookEvent;
use reqwest::{Client, header::{HeaderMap, HeaderName, HeaderValue}};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter};
use serde::Serialize;
use tokio::sync::mpsc::Receiver;
use tokio::task::JoinSet;
use tracing::{error, info, warn};
use hmac::{Hmac, Mac, KeyInit};
use sha2::Sha256;
use uuid::Uuid;

const WEBHOOK_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_INFLIGHT: usize = 64;

/// Longest response-body snippet kept for logging or the "Test Webhook" UI result. A receiver's
/// error page can run to megabytes; the point of the snippet is to name what went wrong, not to
/// mirror the response, so anything past this is a truncation signal, not lost diagnostic value.
const RESPONSE_SNIPPET_MAX_BYTES: usize = 500;

/// Whether a single resolved address is one this instance must never be induced to talk to.
///
/// Deliberately a pure function over an already-resolved [`IpAddr`], so it is unit-testable without
/// any DNS: every interesting case (metadata service, loopback, RFC 1918, IPv4-mapped IPv6) is just
/// an address literal.
///
/// The IPv4-mapped IPv6 normalization is load-bearing. `::ffff:127.0.0.1` is a perfectly ordinary
/// way to write the loopback address, and `Ipv6Addr::is_loopback` is `false` for it — checking the
/// v6 form alone would let `http://[::ffff:127.0.0.1]/` walk straight through. `crate::middleware`
/// already normalizes inbound addresses the same way; this keeps the two directions consistent.
fn is_blocked_address(ip: IpAddr) -> bool {
    // Unwrap `::ffff:a.b.c.d` to `a.b.c.d` so the IPv4 rules below actually apply to it.
    let ip = ip.to_canonical();

    match ip {
        IpAddr::V4(v4) => {
            // `is_link_local()` is what blocks 169.254.0.0/16, and therefore the cloud metadata
            // endpoints (169.254.169.254 on AWS/GCP/Azure) that are the highest-value SSRF target
            // on any hosted deployment.
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || v4.is_documentation()
                // 100.64.0.0/10 — CGNAT space, routinely used for internal service meshes.
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
                // 0.0.0.0/8 — "this network"; on Linux 0.x.y.z reaches the local host.
                || v4.octets()[0] == 0
                // 192.0.0.0/24 (IETF protocol assignments) and 198.18.0.0/15 (benchmarking).
                || v4.octets()[..3] == [192, 0, 0]
                || (v4.octets()[0] == 198 && (v4.octets()[1] & 0xfe) == 18)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                // fc00::/7 unique-local and fe80::/10 link-local.
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

/// Screens a webhook target URL against the SSRF blocklist before any connection is attempted.
///
/// **Every** address the host resolves to is checked, not just the first. A hostname with two A
/// records — one public, one `127.0.0.1` — would otherwise pass this gate on the public record while
/// the HTTP client independently re-resolves and picks the loopback one.
///
/// This remains a check-then-connect design, so it cannot stop a DNS rebinding attack where the
/// second resolution (the client's own) returns a different answer than the one screened here.
/// Closing that requires resolving once and pinning the socket address, i.e. a custom `reqwest`
/// connector — see the SSRF entry in `AGENT_NOTES.MD`.
async fn is_url_safe(url_str: &str, allow_private: bool) -> bool {
    if allow_private { return true; }

    let url = match reqwest::Url::parse(url_str) {
        Ok(u) => u,
        Err(_) => return false,
    };

    // Only http/https can be dispatched at all; anything else fails closed rather than relying on
    // the HTTP client to reject it later.
    if url.scheme() != "http" && url.scheme() != "https" {
        return false;
    }

    let host_str = match url.host_str() {
        Some(h) => h,
        None => return false,
    };

    let port = url.port_or_known_default().unwrap_or(80);

    let addrs: Vec<IpAddr> = match tokio::net::lookup_host((host_str, port)).await {
        Ok(addrs) => addrs.map(|a| a.ip()).collect(),
        Err(_) => return false,
    };

    // A name that resolves to nothing is not dispatchable; fail closed rather than "no bad
    // addresses found, therefore safe".
    if addrs.is_empty() {
        return false;
    }

    !addrs.into_iter().any(is_blocked_address)
}

/// Expands a `CANONICAL_V1` webhook's `hmac_template` into the exact bytes to be signed.
///
/// Two substitutions happen in a **single left-to-right pass**, so neither can act on the other's
/// output:
///
/// - **Escapes.** `\n`, `\r`, `\t` and `\\` become the characters they name. Every other backslash
///   sequence is emitted verbatim (`\d` stays `\d`). Templates travel through a single-line HTML
///   text input in the dashboard, where a real newline cannot be typed — yet the canonical string is
///   defined in terms of newlines, so the escape layer is what makes the field usable at all.
/// - **Placeholders.** `{method}`, `{path}`, `{timestamp}` and `{body}` are replaced by their values.
///   Any other `{...}` is literal text, which is what lets a JSON body template coexist with this
///   syntax.
///
/// The single pass is the security-relevant part: a two-phase "unescape, then replace" would let a
/// request body containing the characters `{path}` inject the target path into the signed string,
/// and a "replace, then unescape" would let a body containing `\n` forge field boundaries. Values
/// substituted here are never rescanned.
///
/// A literal path written into the template (e.g. `{method}\n/api/hooks/42/execute\n{timestamp}\n{body}`)
/// therefore overrides the `{path}` derived from `target_url` with no extra machinery — the receiver
/// behind a path-rewriting reverse proxy sees, and signs over, the path *it* was handed.
pub fn resolve_hmac_template(
    template: &str,
    method: &str,
    path: &str,
    timestamp: &str,
    body: &str,
) -> String {
    const PLACEHOLDERS: [&str; 4] = ["{method}", "{path}", "{timestamp}", "{body}"];

    let values = [method, path, timestamp, body];
    let mut out = String::with_capacity(template.len() + body.len());
    let mut rest = template;

    while !rest.is_empty() {
        // `find` over the two characters that can start a substitution; everything up to the next
        // one is literal and copied wholesale.
        let Some(idx) = rest.find(['\\', '{']) else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..idx]);
        rest = &rest[idx..];

        if let Some(escaped) = rest.strip_prefix('\\') {
            let mut chars = escaped.chars();
            match chars.next() {
                Some('n') => out.push('\n'),
                Some('r') => out.push('\r'),
                Some('t') => out.push('\t'),
                Some('\\') => out.push('\\'),
                // Unknown escape (or a trailing lone backslash): keep both characters as written
                // rather than guessing — silently dropping input from a signed string is worse than
                // an obviously-wrong signature the operator can see and fix.
                Some(other) => {
                    out.push('\\');
                    out.push(other);
                }
                None => {
                    out.push('\\');
                    break;
                }
            }
            rest = chars.as_str();
            continue;
        }

        match PLACEHOLDERS
            .iter()
            .position(|placeholder| rest.starts_with(placeholder))
        {
            Some(i) => {
                out.push_str(values[i]);
                rest = &rest[PLACEHOLDERS[i].len()..];
            }
            None => {
                out.push('{');
                rest = &rest[1..];
            }
        }
    }

    out
}

/// Expands `$name` placeholders in `template` against a fixed `(placeholder, value)` table, in a
/// single left-to-right pass with no rescanning: once a value is inserted it is copied to the
/// output verbatim and never checked again for a placeholder of its own.
///
/// That discipline is shared with [`resolve_hmac_template`] and load-bearing for the same reason:
/// `cause` in particular is arbitrary caller-supplied text (anyone with `can_write` on a group may
/// set it via `/api/ban`/`/api/white`), and a two-phase "substitute, then rescan for more
/// placeholders" evaluator would let a `cause` of `"$group_name"` have *its own* placeholder text
/// expanded by a later substitution — one variable's value influencing what another variable
/// expands to, which is not what either an operator writing a template or a caller writing a cause
/// string could reasonably expect.
///
/// No placeholder here may be a prefix of another (`$ip` vs `$ip_v6`, say) — `find`-then-`starts_with`
/// resolves ties by iteration order, not longest-match, so a prefix relationship would make the
/// shorter placeholder shadow the longer one. The fixed set in [`resolve_event_variables`] has none.
fn substitute_placeholders(template: &str, substitutions: &[(&str, &str)]) -> String {
    let mut out = String::with_capacity(template.len());
    let mut rest = template;

    while !rest.is_empty() {
        let Some(idx) = rest.find('$') else {
            out.push_str(rest);
            break;
        };
        out.push_str(&rest[..idx]);
        rest = &rest[idx..];

        match substitutions.iter().find(|(placeholder, _)| rest.starts_with(placeholder)) {
            Some((placeholder, value)) => {
                out.push_str(value);
                rest = &rest[placeholder.len()..];
            }
            None => {
                out.push('$');
                rest = &rest[1..];
            }
        }
    }

    out
}

/// The one evaluator behind both `payload_template` and `target_url` — so a webhook's destination
/// can route on the same event data its body carries, and so a change to what a variable means
/// never has to be made twice.
///
/// Available variables: `$target_address`/`$ip` (the address the event concerns — for a bare IPv6
/// host ban, the original canonicalized host IPv6 address), `$normalized_address` (the `/48`-truncated
/// subnet for non-whitelist bare IPv6 host bans, or `$target_address` otherwise), `$action`/`$event`
/// (`IP_ADD`/`IP_UPDATE`/`IP_DELETE`/`TEST`), `$cause` (the freeform reason, or `"Unknown"` if none
/// was given), `$group_name` (the target group's name, or empty if the event has none),
/// `$group_id` (the target group's UUID, or empty), and `$timestamp` (the dispatch's Unix
/// timestamp, in seconds — the same value `CANONICAL_V1` signs and sends as `X-Timestamp`, so a
/// receiver correlating the two sees one number, not two that merely happen to be close).
///
/// **On using an event-derived variable in `target_url`'s host/authority**: every dispatch
/// re-screens its *resolved* URL through [`is_url_safe`] before connecting, so a hostile `$cause`
/// steering a naively-templated host cannot reach a private or link-local address — but it can
/// still redirect the request to a different *public* host than the operator intended. Variables
/// are safest confined to the path or query; putting one in the host trades some of the operator's
/// own control over the destination to whoever can set that variable's source field.
fn resolve_event_variables(template: &str, event: &WebhookEvent, timestamp: &str) -> String {
    let group_id = event.group_id.map(|g| g.to_string()).unwrap_or_default();
    let group_name = event.group_name.as_deref().unwrap_or("");
    let cause = event.cause.as_deref().unwrap_or("Unknown");
    let normalized_address =
        crate::api::normalize_ipv6_ban_storage(&event.address, !event.is_whitelist);

    substitute_placeholders(
        template,
        &[
            ("$target_address", event.address.as_str()),
            ("$normalized_address", normalized_address.as_str()),
            ("$ip", event.address.as_str()),
            ("$action", event.action.as_str()),
            ("$event", event.action.as_str()),
            ("$cause", cause),
            ("$group_name", group_name),
            ("$group_id", group_id.as_str()),
            ("$timestamp", timestamp),
        ],
    )
}

/// Builds the HTTP client every outbound webhook call — dispatch or live test — is made through.
///
/// One function so the two paths cannot drift on the properties that matter: the timeout, and
/// **redirects refused rather than followed**. `is_url_safe` screens the *configured* target; a
/// receiver answering `302 Location: http://169.254.169.254/latest/meta-data/` would otherwise be
/// followed by `reqwest`'s default policy without re-screening, handing the signed payload and any
/// `X-API-Key` to whatever the redirect points at. A 3xx response is surfaced as a failed delivery
/// instead.
fn build_webhook_client() -> reqwest::Result<Client> {
    Client::builder()
        .timeout(WEBHOOK_TIMEOUT)
        .user_agent("SimplyFirewall/2.0")
        .redirect(reqwest::redirect::Policy::none())
        .build()
}

/// Whether `ALLOW_PRIVATE_WEBHOOKS=true` is set — the documented development escape hatch that lets
/// [`is_url_safe`] pass every target unscreened. Read fresh on every call rather than cached: unlike
/// the security-relevant startup variables in `config.rs`, this one is explicitly meant to be safe to
/// flip on a running dev instance, and caching it would make that lie.
fn allow_private_webhooks() -> bool {
    std::env::var("ALLOW_PRIVATE_WEBHOOKS").unwrap_or_else(|_| "false".to_owned()) == "true"
}

/// The three pieces of an outbound webhook call: where it goes, what headers it carries (including
/// any signature), and the body. Everything about *how* a `webhook_config` row and a [`WebhookEvent`]
/// become an HTTP request lives in [`prepare_dispatch`]; this is just its output.
struct PreparedDispatch {
    /// The fully **resolved** destination — every `$variable` in `webhook_configs.target_url`
    /// already expanded against the triggering event. Everything downstream (the SSRF re-screen,
    /// the actual HTTP call, the persisted `webhook_executions` row) reads this field and never the
    /// raw template, so a resolution bug can only be visible here, in one place.
    target_url: String,
    headers: HeaderMap,
    payload: String,
}

/// Resolves a `webhook_config` row and an event into a ready-to-send HTTP request: payload template
/// substitution, custom headers, and whichever authentication scheme [`AuthMode`] selects (API key
/// header, HMAC signature, both, or neither).
///
/// Shared by [`dispatch_worker`]'s real dispatch loop and [`send_test_dispatch`]'s live "Test
/// Webhook" endpoint, so a test exercises the **exact** bytes and headers a real delivery would use —
/// not a hand-approximated stand-in that could pass while the real path is broken.
///
/// Returns `Err` with a human-readable reason for a config that cannot be turned into a request at
/// all (an unusable header name/value, an HMAC key that cannot be constructed, an unparseable target
/// URL for `CANONICAL_V1`'s path derivation). None of these depend on the network, so they are
/// distinguished from a delivery failure — there is no request to have failed yet.
fn prepare_dispatch(
    config: &webhook_config::Model,
    event: &WebhookEvent,
) -> Result<PreparedDispatch, String> {
    // Computed once and reused everywhere a timestamp is needed in this dispatch — the `$timestamp`
    // template variable and (for `CANONICAL_V1`) the signed `X-Timestamp` header both mean "when
    // this attempt was prepared", so they must be the same number, not two calls to `Utc::now()`
    // a few instructions apart that happen to usually agree.
    let timestamp = chrono::Utc::now().timestamp().to_string();

    let payload = resolve_event_variables(&config.payload_template, event, &timestamp);
    // Resolved *before* anything downstream reads it: the SSRF re-screen, the HTTP client, and the
    // `CANONICAL_V1` path derivation below must all see the real destination, not the unexpanded
    // template — a signature computed over `{path}` derived from the template would not match the
    // path the receiver actually gets on the wire.
    let target_url = resolve_event_variables(&config.target_url, event, &timestamp);

    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", HeaderValue::from_static("application/json"));

    if let Some(hjson) = &config.headers_json
        && let Ok(map) = serde_json::from_str::<std::collections::HashMap<String, String>>(hjson)
    {
        for (k, v) in map {
            if let (Ok(h_name), Ok(h_val)) = (HeaderName::from_str(&k), HeaderValue::from_str(&v)) {
                headers.insert(h_name, h_val);
            }
        }
    }

    let mode = AuthMode::from_stored(&config.auth_mode);

    // NULL means "this service's standard", resolved here rather than backfilled into every row —
    // see `m20260811_000012`. An empty `signature_prefix` is a *meaningful* value (a receiver
    // wanting a bare hex digest), which is why only NULL falls back.
    let signature_header = config
        .signature_header
        .as_deref()
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .unwrap_or(webhook_config::DEFAULT_SIGNATURE_HEADER)
        .to_owned();
    let signature_prefix = config
        .signature_prefix
        .clone()
        .unwrap_or_else(|| webhook_config::DEFAULT_SIGNATURE_PREFIX.to_owned());

    // Sent by the two modes that identify the caller by key. Inserted before the signature so it is
    // covered by nothing and can never be confused for one; a blank column means "no such header"
    // rather than an empty one, which some receivers treat as a real (and failing) credential.
    if mode.sends_api_key()
        && let Some(api_key) = config.api_key.as_deref().filter(|k| !k.is_empty())
    {
        let hv = HeaderValue::from_str(api_key)
            .map_err(|e| format!("webhook api_key is not a valid header value: {e}"))?;
        headers.insert("X-API-Key", hv);
    }

    let signature = match mode {
        // Signature and nothing else: HMAC over the body alone. `sends_api_key()` excludes this
        // mode, so the key header above was skipped even if `api_key` is populated — that is the
        // defining property of HMAC_ONLY, not an oversight. A receiver that chose signature-only
        // authentication must not be handed a reusable bearer secret it never asked for.
        AuthMode::HmacOnly => {
            let mut mac = Hmac::<Sha256>::new_from_slice(config.secret_token.as_bytes())
                .map_err(|e| format!("failed to create HMAC key: {e}"))?;
            mac.update(payload.as_bytes());
            Some(format!("{}{}", signature_prefix, hex::encode(mac.finalize().into_bytes())))
        }
        // CANONICAL_V1: sign the resolved hmac_template and send the timestamp alongside, so the
        // receiver can run its own anti-replay check. Prefixed `sha256=`, exactly like HMAC_ONLY
        // above and exactly like what the inbound API middleware now requires — that is the whole
        // point of this mode: with the default template the header is byte-identical to one
        // `crypto::compute_signature` would produce, so a dispatch authenticates directly against
        // another instance's /api/* route (and against `simply_hook_executor`, which has always
        // required the prefix).
        AuthMode::CanonicalV1 => {
            // The path is taken from the *resolved* target URL — the template with any
            // `$action`/`$ip`/etc. variables already expanded — so the signature covers the path a
            // receiver will actually see on the wire, not a literal `$action` that was never
            // dispatched anywhere. A URL that failed to parse cannot be dispatched at all, so
            // failing here loses nothing (`is_url_safe` would reject it moments later regardless).
            let path = reqwest::Url::parse(&target_url)
                .map_err(|e| format!("unparseable webhook target URL: {e}"))?
                .path()
                .to_owned();
            let template = config.hmac_template.as_deref().unwrap_or(DEFAULT_HMAC_TEMPLATE);
            let message = resolve_hmac_template(template, "POST", &path, &timestamp, &payload);

            let mut mac = Hmac::<Sha256>::new_from_slice(config.secret_token.as_bytes())
                .map_err(|e| format!("failed to create canonical webhook HMAC key: {e}"))?;
            mac.update(message.as_bytes());

            if let Ok(hv) = HeaderValue::from_str(&timestamp) {
                headers.insert("X-Timestamp", hv);
            }
            Some(format!("{}{}", signature_prefix, hex::encode(mac.finalize().into_bytes())))
        }
        // No signature to compute: the key header above (API_KEY_ONLY) or nothing at all (NONE) is
        // the whole credential.
        AuthMode::ApiKeyOnly | AuthMode::None => None,
    };

    if let Some(sig_val) = signature {
        // The header name is caller-configurable, so it is parsed rather than assumed: an unusable
        // name must fail the whole prepare step, not send the signature under a name the receiver
        // will not read.
        let name = HeaderName::from_bytes(signature_header.as_bytes())
            .map_err(|_| format!("signature header '{signature_header}' is not a valid HTTP header name"))?;
        let hv = HeaderValue::from_str(&sig_val)
            .map_err(|e| format!("computed signature is not a valid header value: {e}"))?;
        headers.insert(name, hv);
    }

    Ok(PreparedDispatch { target_url, headers, payload })
}

/// Truncates a response body to [`RESPONSE_SNIPPET_MAX_BYTES`] for logging or the "Test Webhook" UI,
/// noting truncation rather than silently cutting the string mid-thought.
///
/// Truncates on a `char` boundary rather than a byte count directly — `reqwest::Response::text`
/// already validated the body as UTF-8, and slicing mid-codepoint would panic.
fn snippet(body: &str) -> String {
    match body.char_indices().nth(RESPONSE_SNIPPET_MAX_BYTES) {
        None => body.to_owned(),
        Some((cut, _)) => format!("{}… ({} bytes total)", &body[..cut], body.len()),
    }
}

/// Whether a delivery attempt should be retried, and why it succeeded or failed when it should not
/// be.
enum DispatchOutcome {
    /// `2xx`. Nothing more to do.
    Success { status: u16 },
    /// A network-level failure (timeout, connection refused, DNS failure, TLS error — anything that
    /// never produced an HTTP response) or a `5xx` response. The receiver, or the network path to
    /// it, may recover, so this is worth retrying.
    Transient { status: Option<u16>, reason: String },
    /// A `4xx` response (or any other non-`5xx`, non-`2xx`/`3xx` status this service does not
    /// otherwise treat as success). The request reached the receiver and the receiver rejected it
    /// outright — a bad signature, a missing permission, a URL the receiver does not serve. Retrying
    /// the identical request will not change that answer, so this fails on the first attempt.
    Permanent { status: Option<u16>, reason: String },
}

/// Sends one HTTP attempt and classifies the result into [`DispatchOutcome`].
///
/// Reads the response body whenever a response was received at all — success included, not only
/// failure, so whatever the receiver said back (a JSON acknowledgement, a tracking id) is available
/// to persist. A network-level error never produced a body to read.
async fn attempt_delivery(
    client: &Client,
    target_url: &str,
    headers: HeaderMap,
    payload: String,
) -> (DispatchOutcome, Option<String>) {
    match client.post(target_url).headers(headers).body(payload).send().await {
        Ok(resp) => {
            let status = resp.status();
            let is_success = status.is_success();
            let body = resp.text().await.ok().filter(|b| !b.is_empty()).map(|b| snippet(&b));
            if is_success {
                return (DispatchOutcome::Success { status: status.as_u16() }, body);
            }
            let reason = format!("HTTP {status}");
            if status.is_server_error() {
                (DispatchOutcome::Transient { status: Some(status.as_u16()), reason }, body)
            } else {
                (DispatchOutcome::Permanent { status: Some(status.as_u16()), reason }, body)
            }
        }
        // Every network-level failure — timeout, connection refused, DNS resolution failure, TLS
        // handshake failure — is transient: none of them says anything about whether the *request*
        // was acceptable, only that this attempt could not complete one. `reqwest::Error` carries no
        // status in this branch by construction (a status implies a response was received).
        Err(e) => (DispatchOutcome::Transient { status: None, reason: e.to_string() }, None),
    }
}

/// Identity and event context for one dispatch attempt — everything [`log_execution`] needs to
/// describe *which* delivery a `webhook_executions` row belongs to, beyond what [`PreparedDispatch`]
/// already carries. Bundled so passing it through [`dispatch_with_retries`]/
/// [`dispatch_with_retries_config`] doesn't keep growing their own parameter lists as more of an
/// event's data becomes worth persisting per attempt.
struct DispatchContext {
    webhook_id: Uuid,
    webhook_name: String,
    event_type: String,
    /// The address the triggering event concerned — persisted per attempt (not read back from
    /// `webhook_configs`, which has no address of its own) so the Executions tab can search and
    /// filter by it.
    target_address: String,
    cause: Option<String>,
}

/// Delivers one webhook, retrying transient failures with exponential backoff up to
/// `config::webhook_max_retries` times before giving up.
///
/// A thin wrapper around [`dispatch_with_retries_config`] that supplies the live, `OnceLock`-cached
/// configuration — split out purely so the retry *loop itself* (attempt counting, backoff growth,
/// when it stops) is reachable with small, fast, deterministic values in a test, the same reason
/// `config::clamp_pool_max` and friends are split from the functions that cache their inputs.
async fn dispatch_with_retries(
    client: Client,
    prepared: PreparedDispatch,
    ctx: DispatchContext,
    db: DatabaseConnection,
) {
    dispatch_with_retries_config(
        client,
        prepared,
        ctx,
        crate::config::webhook_max_retries(),
        crate::config::webhook_retry_backoff_ms(),
        db,
    )
    .await
}

/// Persists one `webhook_executions` row for a single HTTP attempt — success, transient, or
/// permanent alike, one row per attempt including retries, never a row for the delivery as a whole.
///
/// Never fatal to the dispatch it is recording: a database error here is logged and swallowed. The
/// alternative — letting a failed *log write* affect a real delivery's outcome or retry behaviour —
/// would make the observability feature a new way for dispatch to break, which is backwards.
async fn log_execution(
    db: &DatabaseConnection,
    ctx: &DispatchContext,
    resolved_target_url: &str,
    status_code: Option<u16>,
    is_success: bool,
    duration_ms: i64,
    response_body: Option<&str>,
) {
    let row = webhook_execution::ActiveModel {
        id: Set(Uuid::new_v4()),
        webhook_id: Set(ctx.webhook_id),
        event_type: Set(ctx.event_type.clone()),
        status_code: Set(status_code.map(i32::from)),
        is_success: Set(is_success),
        // `duration_ms` is `i32` in the schema — a single HTTP attempt exceeding ~24 days is not a
        // real value to preserve exactly, so this saturates rather than panicking or wrapping.
        duration_ms: Set(duration_ms.try_into().unwrap_or(i32::MAX)),
        response_body: Set(response_body.map(str::to_owned)),
        resolved_target_url: Set(Some(resolved_target_url.to_owned())),
        target_address: Set(Some(ctx.target_address.clone())),
        cause: Set(ctx.cause.clone()),
        created_at: Set(chrono::Utc::now().naive_utc()),
    };
    if let Err(e) = row.insert(db).await {
        error!(webhook_id = %ctx.webhook_id, "Failed to record webhook execution history: {e}");
    }
}

/// Logs at `info` on success, `warn` on a transient failure that will be retried, and `error` on the
/// final failure — transient-and-exhausted or permanent-on-the-first-attempt alike — with the target
/// URL, HTTP status (when one was received), the error reason, the attempt count, and a response body
/// snippet when one is available. An operator grepping logs for a broken integration should never
/// need to reproduce the failure to learn what it was.
///
/// Every attempt — including ones that will be retried — is also persisted to `webhook_executions`
/// via [`log_execution`], so the dashboard's Executions tab shows the same retry history these logs
/// describe.
async fn dispatch_with_retries_config(
    client: Client,
    prepared: PreparedDispatch,
    ctx: DispatchContext,
    max_retries: u32,
    base_backoff_ms: u64,
    db: DatabaseConnection,
) {
    let PreparedDispatch { target_url, headers, payload } = prepared;

    let mut attempt: u32 = 1;
    loop {
        let started = std::time::Instant::now();
        let (outcome, body) =
            attempt_delivery(&client, &target_url, headers.clone(), payload.clone()).await;
        let duration_ms = started.elapsed().as_millis() as i64;

        match outcome {
            DispatchOutcome::Success { status } => {
                info!(
                    webhook = %ctx.webhook_name, url = %target_url, status, attempt,
                    body = %body.as_deref().unwrap_or(""), "Webhook delivered"
                );
                log_execution(&db, &ctx, &target_url, Some(status), true, duration_ms, body.as_deref())
                    .await;
                return;
            }
            DispatchOutcome::Permanent { status, reason } => {
                error!(
                    webhook = %ctx.webhook_name, url = %target_url, status, attempt, reason = %reason,
                    body = %body.as_deref().unwrap_or(""),
                    "Webhook delivery failed with a non-retryable error; not retrying"
                );
                // Whatever the receiver actually said back, when it said anything — `reason` here is
                // only ever the computed `"HTTP {status}"` string, which the body (when present) is
                // strictly more informative than.
                let detail = body.as_deref().or(Some(reason.as_str()));
                log_execution(&db, &ctx, &target_url, status, false, duration_ms, detail).await;
                return;
            }
            DispatchOutcome::Transient { status, reason } if attempt <= max_retries => {
                // `attempt` is 1-based, so the first retry (attempt 1 -> 2) waits one base interval,
                // the second waits two, and so on — genuine exponential growth rather than a fixed
                // pause repeated `max_retries` times. Shifting is capped well short of overflow;
                // `webhook_max_retries` is itself clamped to at most 10, so this never approaches it.
                let backoff_ms = base_backoff_ms.saturating_mul(1u64 << (attempt - 1).min(20));
                warn!(
                    webhook = %ctx.webhook_name, url = %target_url, status, attempt, max_retries,
                    backoff_ms, reason = %reason, body = %body.as_deref().unwrap_or(""),
                    "Webhook delivery failed with a transient error; retrying"
                );
                let detail = body.as_deref().or(Some(reason.as_str()));
                log_execution(&db, &ctx, &target_url, status, false, duration_ms, detail).await;
                tokio::time::sleep(Duration::from_millis(backoff_ms)).await;
                attempt += 1;
            }
            DispatchOutcome::Transient { status, reason } => {
                error!(
                    webhook = %ctx.webhook_name, url = %target_url, status, attempt, max_retries,
                    reason = %reason, body = %body.as_deref().unwrap_or(""),
                    "Webhook delivery failed with a transient error and exhausted its retries; \
                     giving up"
                );
                let detail = body.as_deref().or(Some(reason.as_str()));
                log_execution(&db, &ctx, &target_url, status, false, duration_ms, detail).await;
                return;
            }
        }
    }
}

/// The result of one live "Test Webhook" dispatch — the response `POST /api/webhooks/{id}/test`
/// returns for the dashboard's test modal to render before the caller decides whether to save.
#[derive(Serialize)]
pub struct WebhookTestResult {
    /// Whether the receiver answered with a `2xx` status.
    pub success: bool,
    /// The HTTP status code received, when a response was received at all.
    pub status: Option<u16>,
    /// Response headers, when a response was received. Keys are lower-cased header names; a header
    /// sent multiple times is joined with `", "`, matching how a browser's `fetch` would report it.
    pub headers: Option<std::collections::HashMap<String, String>>,
    /// A truncated response body, when one was available and short enough to be worth showing (see
    /// [`RESPONSE_SNIPPET_MAX_BYTES`]).
    pub body: Option<String>,
    /// A human-readable failure reason — a network error, a non-2xx status, an SSRF refusal, or a
    /// configuration problem (e.g. an unusable header value) caught before any request was sent.
    /// `None` exactly when `success` is `true`.
    pub error: Option<String>,
    /// Whether the failure was this instance's own SSRF filter refusing the target, rather than
    /// anything the receiver did or didn't do — worth distinguishing in the UI, since the fix is
    /// "point this webhook somewhere reachable", not "check the receiver's logs".
    pub blocked_by_ssrf_filter: bool,
}

/// Dispatches a single, explicit test event to `config`'s target — the live "Test Webhook" action in
/// the dashboard's webhook editor.
///
/// Runs the **exact same** request-construction path as a real dispatch ([`prepare_dispatch`]) and
/// the **exact same** SSRF screen ([`is_url_safe`]) — a test that skipped either would validate a
/// request the receiver would never actually get, or would turn "Test Webhook" into an SSRF probe an
/// authorized-but-untrusted caller could aim at the deployment's internal network.
///
/// Deliberately **not** retried: this is a synchronous, human-observed check, and an operator who
/// clicks "Test Webhook" wants to know within seconds whether *this* attempt succeeded, not to wait
/// out several minutes of exponential backoff against a receiver that might be down for a reason a
/// human should investigate instead.
///
/// Logs a `webhook_executions` row (`event_type = "TEST"`) for the one HTTP attempt actually made —
/// same as a real dispatch's retry loop, so a test dispatch shows up in the Executions tab exactly
/// like the delivery it stands in for. No row is logged if the request never reached the network at
/// all (a `prepare_dispatch` failure or an SSRF refusal): neither is an HTTP attempt, so neither has
/// a status code or duration worth recording.
pub async fn send_test_dispatch(
    db: &DatabaseConnection,
    config: &webhook_config::Model,
    event: &WebhookEvent,
) -> WebhookTestResult {
    send_test_dispatch_with_privacy(db, config, event, allow_private_webhooks()).await
}

/// The testable core of [`send_test_dispatch`], taking the private-network allowance as a parameter
/// instead of reading `ALLOW_PRIVATE_WEBHOOKS` internally.
///
/// Split out for the same reason `dispatch_with_retries_config` is: `std::env::set_var` is
/// process-wide and `#[tokio::test]` functions run concurrently, so two tests that each need a
/// *different* value of this setting cannot both mutate the real environment variable without racing
/// each other. Taking the value as an argument sidesteps that entirely rather than serializing tests
/// against a lock.
async fn send_test_dispatch_with_privacy(
    db: &DatabaseConnection,
    config: &webhook_config::Model,
    event: &WebhookEvent,
    allow_private: bool,
) -> WebhookTestResult {
    let prepared = match prepare_dispatch(config, event) {
        Ok(p) => p,
        Err(reason) => {
            return WebhookTestResult {
                success: false,
                status: None,
                headers: None,
                body: None,
                error: Some(reason),
                blocked_by_ssrf_filter: false,
            };
        }
    };

    if !is_url_safe(&prepared.target_url, allow_private).await {
        warn!(url = %prepared.target_url, webhook = %config.name, "Test dispatch blocked by SSRF protection");
        return WebhookTestResult {
            success: false,
            status: None,
            headers: None,
            body: None,
            error: Some(
                "target_url resolves to an address this service refuses to contact (SSRF protection)"
                    .to_owned(),
            ),
            blocked_by_ssrf_filter: true,
        };
    }

    let client = match build_webhook_client() {
        Ok(c) => c,
        Err(e) => {
            return WebhookTestResult {
                success: false,
                status: None,
                headers: None,
                body: None,
                error: Some(format!("failed to build HTTP client: {e}")),
                blocked_by_ssrf_filter: false,
            };
        }
    };

    let ctx = DispatchContext {
        webhook_id: config.id,
        webhook_name: config.name.clone(),
        event_type: "TEST".to_owned(),
        target_address: event.address.clone(),
        cause: event.cause.clone(),
    };

    let started = std::time::Instant::now();
    let outcome = client.post(&prepared.target_url).headers(prepared.headers).body(prepared.payload).send().await;
    let duration_ms = started.elapsed().as_millis() as i64;

    match outcome {
        Ok(resp) => {
            let status = resp.status();
            let headers = resp
                .headers()
                .iter()
                .map(|(k, v)| (k.as_str().to_owned(), v.to_str().unwrap_or("<binary>").to_owned()))
                .collect();
            let success = status.is_success();
            let body = resp.text().await.ok().filter(|b| !b.is_empty()).map(|b| snippet(&b));
            let error = if success { None } else { Some(format!("receiver responded with HTTP {status}")) };
            // Whatever the receiver said back, on success or failure alike — not the computed
            // `error` summary, which the body (when present) is strictly more informative than.
            let detail = body.as_deref().or(error.as_deref());
            log_execution(db, &ctx, &prepared.target_url, Some(status.as_u16()), success, duration_ms, detail)
                .await;
            WebhookTestResult {
                success,
                status: Some(status.as_u16()),
                headers: Some(headers),
                body,
                error,
                blocked_by_ssrf_filter: false,
            }
        }
        Err(e) => {
            let reason = e.to_string();
            log_execution(db, &ctx, &prepared.target_url, None, false, duration_ms, Some(&reason)).await;
            WebhookTestResult {
                success: false,
                status: None,
                headers: None,
                body: None,
                error: Some(reason),
                blocked_by_ssrf_filter: false,
            }
        }
    }
}

/// Runs the background webhook worker, processing events and dispatching HTTP requests
pub async fn run_webhook_worker(db: DatabaseConnection, rx: Receiver<WebhookEvent>) {
    let workers = crate::config::webhook_workers();
    let interval = crate::config::webhook_dispatch_interval();

    // One receiver, many consumers. `mpsc::Receiver` is not clonable — deliberately, since an mpsc
    // channel has exactly one consumer by definition — so the workers share it behind a mutex and
    // take turns calling `recv`. The lock is held only across the `recv` itself and released before
    // any dispatch, so the workers serialise on *picking up* an event and run its HTTP calls
    // concurrently. That is the intended shape: the queue is the contended resource, the network is
    // not.
    let shared = std::sync::Arc::new(tokio::sync::Mutex::new(rx));
    let mut pool = JoinSet::new();

    info!(
        workers,
        interval_ms = interval.as_millis() as u64,
        capacity = crate::config::webhook_queue_capacity(),
        "Starting webhook dispatch pool"
    );

    for id in 0..workers {
        let db = db.clone();
        let shared = shared.clone();
        pool.spawn(async move { dispatch_worker(id, db, shared, interval).await });
    }

    while pool.join_next().await.is_some() {}
    info!("Webhook dispatch pool shut down.");
}

/// One worker: take an event, dispatch it, pause, repeat.
///
/// The pause is **after** the work rather than before it, so a service that receives one event an
/// hour never waits for it. Throttling exists to flatten bursts, not to add latency to a quiet
/// system, and `interval == 0` skips the sleep entirely.
async fn dispatch_worker(
    id: usize,
    db: DatabaseConnection,
    rx: std::sync::Arc<tokio::sync::Mutex<Receiver<WebhookEvent>>>,
    interval: Duration,
) {
    let client = match build_webhook_client() {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to build webhook HTTP client, worker will not start: {}", e);
            return;
        }
    };

    let mut join_set = JoinSet::new();

    info!(worker = id, "Webhook worker started.");

    loop {
        // Scoped so the guard drops before any dispatch below — holding it across the HTTP calls
        // would serialise the whole pool behind one slow receiver and make `WEBHOOK_WORKERS`
        // decorative.
        let event = {
            let mut guard = rx.lock().await;
            match guard.recv().await {
                Some(event) => event,
                None => break,
            }
        };

        info!(address = %event.address, action = %event.action, "Processing event for webhooks");

        let gid = match event.group_id {
            Some(id) => id,
            None => continue,
        };

        let configs = match WebhookConfig::find()
            .filter(webhook_config::Column::GroupId.eq(gid))
            .filter(webhook_config::Column::IsActive.eq(true))
            .all(&db).await {
            Ok(c) => c,
            Err(e) => {
                error!("Failed to fetch webhook configs: {}", e);
                continue;
            }
        };

        for config in configs {
            // `events` is `None` for "all events" (the historical default); when set, it's a
            // comma-separated allowlist of actions this specific webhook cares about.
            if let Some(events) = &config.events {
                let subscribed = events.split(',').map(|s| s.trim()).any(|a| a == event.action);
                if !subscribed {
                    continue;
                }
            }

            if join_set.len() >= MAX_INFLIGHT {
                let _ = join_set.join_next().await;
            }

            let prepared = match prepare_dispatch(&config, &event) {
                Ok(p) => p,
                Err(reason) => {
                    error!(webhook = %config.name, reason = %reason, "Webhook dispatch could not be prepared; skipping");
                    continue;
                }
            };

            let client = client.clone();
            let ctx = DispatchContext {
                webhook_id: config.id,
                webhook_name: config.name.clone(),
                event_type: event.action.clone(),
                target_address: event.address.clone(),
                cause: event.cause.clone(),
            };
            let exec_db = db.clone();

            join_set.spawn(async move {
                if !is_url_safe(&prepared.target_url, allow_private_webhooks()).await {
                    warn!(url = %prepared.target_url, webhook = %ctx.webhook_name, "Webhook blocked by SSRF protection");
                    return;
                }
                dispatch_with_retries(client, prepared, ctx, exec_db).await;
            });
        }

        while let Some(Ok(_)) = join_set.try_join_next() {}

        // Paces this worker's *events*. One event may still fan out to several configs
        // concurrently, so the aggregate ceiling is `WEBHOOK_WORKERS / interval` events per second.
        if !interval.is_zero() {
            tokio::time::sleep(interval).await;
        }
    }

    info!(worker = id, "Webhook channel closed, draining pending tasks...");
    while join_set.join_next().await.is_some() {}
    info!(worker = id, "Webhook worker shut down.");
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::PaginatorTrait;

    #[test]
    fn default_template_reproduces_the_canonical_v1_string() {
        let resolved = resolve_hmac_template(DEFAULT_HMAC_TEMPLATE, "POST", "/api/ban", "1700", "{}");
        assert_eq!(resolved, "POST\n/api/ban\n1700\n{}");

        // The whole point of CANONICAL_V1 mode: the bytes a dispatch signs are the bytes an inbound
        // request would have signed, so a webhook can authenticate against another instance's API.
        let inbound = crate::crypto::canonical_v1_payload("POST", "/api/ban", "1700", b"{}");
        assert_eq!(resolved.as_bytes(), inbound.as_slice());
    }

    #[test]
    fn a_literal_path_in_the_template_overrides_the_url_derived_one() {
        let resolved = resolve_hmac_template(
            r"{method}\n/api/hooks/42/execute\n{timestamp}\n{body}",
            "POST",
            "/proxied/elsewhere",
            "1700",
            "payload",
        );
        assert_eq!(resolved, "POST\n/api/hooks/42/execute\n1700\npayload");
    }

    #[test]
    fn escapes_are_expanded_and_unknown_ones_kept_verbatim() {
        assert_eq!(resolve_hmac_template(r"a\nb\tc\rd", "", "", "", ""), "a\nb\tc\rd");
        // `\\n` is an escaped backslash followed by `n`, NOT a newline.
        assert_eq!(resolve_hmac_template(r"a\\nb", "", "", "", ""), r"a\nb");
        assert_eq!(resolve_hmac_template(r"a\db", "", "", "", ""), r"a\db");
        assert_eq!(resolve_hmac_template(r"trailing\", "", "", "", ""), r"trailing\");
    }

    #[test]
    fn unknown_braces_are_literal_so_json_templates_survive() {
        assert_eq!(
            resolve_hmac_template(r#"{"sig":"{body}","x":{"y":1}}"#, "", "", "", "B"),
            r#"{"sig":"B","x":{"y":1}}"#
        );
    }

    #[test]
    fn substituted_values_are_never_rescanned() {
        // A body that contains template syntax must land in the signed string verbatim. If it were
        // rescanned, a caller controlling the `cause` field of an IP record could inject the
        // method/path/timestamp of their choosing into what the receiver verifies.
        let hostile = r"{path}\n{timestamp}";
        let resolved = resolve_hmac_template(DEFAULT_HMAC_TEMPLATE, "POST", "/api/ban", "1700", hostile);
        assert_eq!(resolved, format!("POST\n/api/ban\n1700\n{hostile}"));
        assert!(resolved.ends_with(r"{path}\n{timestamp}"));
    }

    #[test]
    fn field_order_and_separators_are_load_bearing() {
        let a = resolve_hmac_template(DEFAULT_HMAC_TEMPLATE, "POST", "/api/ban", "1700", "x");
        let b = resolve_hmac_template(DEFAULT_HMAC_TEMPLATE, "POST", "/api/ba", "n1700", "x");
        assert_ne!(a, b, "the \\n delimiter must keep adjacent fields unambiguous");
    }

    fn sample_event() -> WebhookEvent {
        WebhookEvent {
            action: "IP_ADD".to_owned(),
            address: "203.0.113.42".to_owned(),
            is_whitelist: false,
            group_id: Some(Uuid::nil()),
            group_name: Some("hijack-group".to_owned()),
            cause: Some("suspicious traffic".to_owned()),
        }
    }

    /// `$action`/`$event`, `$ip`/`$target_address`, `$cause`, `$group_name`, and `$group_id` all
    /// expand — the exact set `target_url` gained templating support for, checked against the one
    /// evaluator both it and `payload_template` now share.
    #[test]
    fn resolve_event_variables_expands_every_documented_placeholder() {
        let event = sample_event();
        let resolved = resolve_event_variables(
            "https://x.example/$action/$event/$ip/$target_address/$cause/$group_name/$group_id/$timestamp",
            &event,
            "1700",
        );
        assert_eq!(
            resolved,
            "https://x.example/IP_ADD/IP_ADD/203.0.113.42/203.0.113.42/suspicious traffic/\
             hijack-group/00000000-0000-0000-0000-000000000000/1700"
        );
    }

    /// A `cause` of `"Unknown"` and empty group fields are what an event with no cause and no group
    /// expands to — not a literal `$cause`/`$group_name` left in the URL, which is what a caller
    /// forgetting to handle the `None` case would produce.
    #[test]
    fn resolve_event_variables_falls_back_sensibly_when_event_data_is_absent() {
        let event = WebhookEvent {
            action: "TEST".to_owned(),
            address: "127.0.0.1/32".to_owned(),
            is_whitelist: false,
            group_id: None,
            group_name: None,
            cause: None,
        };
        let resolved = resolve_event_variables("$cause|$group_name|$group_id|", &event, "0");
        assert_eq!(resolved, "Unknown|||");
    }

    /// The injection-safety property `resolve_hmac_template` already has, carried over to the new
    /// evaluator: a `cause` a caller fully controls (via `/api/ban`/`/api/white`) must not be able to
    /// inject a *different* variable's placeholder text and have a later substitution expand it.
    #[test]
    fn substitute_placeholders_never_rescans_an_inserted_value() {
        let mut event = sample_event();
        event.cause = Some("$group_name".to_owned());
        let resolved = resolve_event_variables("cause=$cause group=$group_name", &event, "1700");
        assert_eq!(
            resolved,
            "cause=$group_name group=hijack-group",
            "the literal text a caller wrote into `cause` must survive verbatim, not be expanded a \
             second time because it happens to match another placeholder"
        );
    }

    /// `target_url` templating end to end: `prepare_dispatch` must resolve `$action`/`$ip` in the
    /// target URL, not just in the payload — this is the property that was entirely missing before,
    /// since `target_url` was previously used verbatim.
    #[test]
    fn target_url_variables_are_resolved_by_prepare_dispatch() {
        let config = webhook_config::Model {
            id: Uuid::new_v4(),
            name: "templated-target".to_owned(),
            target_url: "https://x.example/hooks/$action?ip=$ip".to_owned(),
            secret_token: String::new(),
            auth_mode: AuthMode::NONE.to_owned(),
            api_key: None,
            hmac_template: None,
            signature_header: None,
            signature_prefix: None,
            headers_json: None,
            payload_template: "{}".to_owned(),
            group_id: Uuid::new_v4(),
            is_active: true,
            events: None,
            owner_key_id: None,
            created_at: chrono::Utc::now().naive_utc(),
        };
        let event = sample_event();

        let prepared = prepare_dispatch(&config, &event).expect("a plain-text target resolves");
        assert_eq!(prepared.target_url, "https://x.example/hooks/IP_ADD?ip=203.0.113.42");
    }

    /// `CANONICAL_V1` must sign the path of the *resolved* target URL. Before this, the path fed to
    /// `resolve_hmac_template` came from `config.target_url` directly — with a templated URL, that
    /// path would still contain the literal `$action`, so the signature would cover a path the
    /// receiver's own request line never has, and the receiver's independent verification would
    /// fail every dispatch.
    #[test]
    fn canonical_v1_signs_the_resolved_path_not_the_template() {
        let mut config = webhook_config::Model {
            id: Uuid::new_v4(),
            name: "templated-canonical".to_owned(),
            target_url: "https://x.example/hooks/$action".to_owned(),
            secret_token: "shared-secret".to_owned(),
            auth_mode: AuthMode::CanonicalV1.as_str().to_owned(),
            api_key: None,
            hmac_template: None,
            signature_header: None,
            signature_prefix: None,
            headers_json: None,
            payload_template: "{}".to_owned(),
            group_id: Uuid::new_v4(),
            is_active: true,
            events: None,
            owner_key_id: None,
            created_at: chrono::Utc::now().naive_utc(),
        };
        let event = sample_event();

        let prepared_add = prepare_dispatch(&config, &event).expect("resolves");
        let sig_add = prepared_add.headers.get("X-Signature-256").expect("signed").clone();

        // A different action resolves to a different path — `/hooks/IP_DELETE`, not `/hooks/IP_ADD`
        // — so if the signature covered the unresolved template (constant regardless of `$action`),
        // these two would be identical. They must not be.
        config.target_url = "https://x.example/hooks/$action".to_owned();
        let mut delete_event = event.clone();
        delete_event.action = "IP_DELETE".to_owned();
        let prepared_delete = prepare_dispatch(&config, &delete_event).expect("resolves");
        let sig_delete = prepared_delete.headers.get("X-Signature-256").expect("signed").clone();

        assert_ne!(
            sig_add, sig_delete,
            "the signature must cover the resolved path, which differs between the two actions"
        );
    }

    /// The SSRF blocklist, exercised as a pure function over resolved addresses.
    ///
    /// The cloud metadata endpoint is called out explicitly rather than left implicit in
    /// "link-local": it is the single highest-value SSRF target on a hosted deployment, and a
    /// refactor that dropped `is_link_local()` would otherwise silently reopen it.
    #[test]
    fn blocked_addresses_cover_metadata_loopback_and_rfc1918() {
        for blocked in [
            "169.254.169.254", // AWS/GCP/Azure instance metadata
            "169.254.0.1",
            "127.0.0.1",
            "127.1.2.3",
            "10.0.0.5",
            "172.16.4.4",
            "172.31.255.255",
            "192.168.1.1",
            "0.0.0.0",
            "0.0.0.1",
            "100.64.0.1",   // CGNAT
            "100.127.0.1",  // CGNAT upper bound
            "192.0.0.1",    // IETF protocol assignments
            "198.18.0.1",   // benchmarking range
            "255.255.255.255",
            "::1",
            "::",
            "fd00::1",           // unique-local
            "fe80::1",           // link-local
            "::ffff:127.0.0.1",  // IPv4-mapped loopback — false for Ipv6Addr::is_loopback
            "::ffff:169.254.169.254",
            "::ffff:10.0.0.1",
        ] {
            let ip: IpAddr = blocked.parse().expect("test address literal parses");
            assert!(is_blocked_address(ip), "{blocked} must be blocked as an SSRF target");
        }

        // Ordinary public addresses must still be dispatchable, or the feature is useless.
        for allowed in ["1.1.1.1", "8.8.8.8", "93.184.216.34", "172.32.0.1", "100.63.255.255", "2606:4700::1111"] {
            let ip: IpAddr = allowed.parse().expect("test address literal parses");
            assert!(!is_blocked_address(ip), "{allowed} is public and must be allowed");
        }
    }

    #[tokio::test]
    async fn url_screening_rejects_literals_and_non_http_schemes() {
        // Address literals need no DNS, so these assertions are hermetic.
        assert!(!is_url_safe("http://127.0.0.1:8080/hook", false).await);
        assert!(!is_url_safe("http://169.254.169.254/latest/meta-data/", false).await);
        assert!(!is_url_safe("http://[::ffff:127.0.0.1]/hook", false).await);
        assert!(!is_url_safe("http://10.0.0.1/hook", false).await);
        assert!(!is_url_safe("file:///etc/passwd", false).await);
        assert!(!is_url_safe("gopher://127.0.0.1:70/", false).await);
        assert!(!is_url_safe("not a url", false).await);

        // The documented development escape hatch still bypasses the whole check.
        assert!(is_url_safe("http://127.0.0.1:8080/hook", true).await);
    }

    #[test]
    fn from_stored_never_downgrades_an_unreadable_mode_to_none() {
        assert_eq!(AuthMode::from_stored("wat"), AuthMode::HmacOnly);
        assert_eq!(AuthMode::from_stored(""), AuthMode::HmacOnly);
        assert_eq!(AuthMode::from_stored("canonical_v1"), AuthMode::CanonicalV1);
        assert_eq!(AuthMode::from_stored(" NONE "), AuthMode::None);
    }

    /// **The database connection used to fetch a webhook's targets must be released well before
    /// the outbound HTTP call returns — not merely "eventually", but before a slow receiver's
    /// response arrives.**
    ///
    /// This is the property a production report asked to have audited: `sqlx::pool::acquire`
    /// warnings during webhook dispatch, consistent with a connection being held across the HTTP
    /// round trip. Reading `dispatch_worker` shows exactly one database call in the whole function
    /// (`WebhookConfig::find()...all(&db)`), returning an owned `Vec` *before* the per-config loop
    /// begins, and the `join_set.spawn` that performs the actual `client.post(...).send().await`
    /// captures `client`/`headers`/`payload`/`target_url` by value — never `db`. That is a static
    /// read of the code; this test is the dynamic proof; on SQLite's single-connection pool
    /// (`db::SQLITE_MEMORY_MAX_CONNECTIONS = 1`), if the dispatcher held its connection across the HTTP
    /// call, a concurrent, unrelated query against the same pool would have nowhere to go and would
    /// block for as long as the slow receiver takes to answer. It does not.
    #[tokio::test]
    async fn the_db_connection_is_released_before_the_slow_http_call_returns() {
        use sea_orm::{ActiveModelTrait, Database, Set};
        use sea_orm_migration::MigratorTrait;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let db = Database::connect("sqlite::memory:").await.expect("in-memory sqlite opens");
        crate::migration::Migrator::up(&db, None).await.expect("migrations apply");

        // A receiver that accepts the connection, reads the request, then sits on its hands for
        // far longer than a healthy pool acquisition should ever take before answering. The delay
        // is the whole point: if the dispatcher's DB connection were still checked out while this
        // is in flight, the concurrent query below would be made to wait for it too.
        const SLOW_RESPONSE_DELAY: Duration = Duration::from_secs(2);
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("loopback listener binds");
        let addr = listener.local_addr().expect("listener has a local address");
        tokio::spawn(async move {
            if let Ok((mut socket, _)) = listener.accept().await {
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                tokio::time::sleep(SLOW_RESPONSE_DELAY).await;
                let _ = socket
                    .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .await;
            }
        });

        let group_id = uuid::Uuid::new_v4();
        crate::entities::ip_group::ActiveModel {
            id: Set(group_id),
            name: Set("dispatch-release-test-group".to_owned()),
            group_type: Set("banlist".to_owned()),
            owner_key_id: Set(None),
            description: Set(None),
            created_at: Set(chrono::Utc::now().naive_utc()),
        }
        .insert(&db)
        .await
        .expect("group inserts");

        crate::entities::webhook_config::ActiveModel {
            id: Set(uuid::Uuid::new_v4()),
            name: Set("slow-receiver".to_owned()),
            target_url: Set(format!("http://{addr}/slow")),
            secret_token: Set(String::new()),
            auth_mode: Set(AuthMode::NONE.to_owned()),
            api_key: Set(None),
            hmac_template: Set(None),
            signature_header: Set(None),
            signature_prefix: Set(None),
            headers_json: Set(None),
            payload_template: Set("{}".to_owned()),
            group_id: Set(group_id),
            is_active: Set(true),
            events: Set(None),
            owner_key_id: Set(None),
            created_at: Set(chrono::Utc::now().naive_utc()),
        }
        .insert(&db)
        .await
        .expect("webhook config inserts");

        // The target is loopback, which the SSRF filter blocks by default — this is the documented
        // escape hatch `dispatch_worker` reads once at startup, not a security-relevant bypass of
        // anything this test is checking.
        // SAFETY: no other test in this binary spawns `run_webhook_worker`, so nothing else reads
        // or writes this variable concurrently.
        unsafe { std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "true") };

        let (tx, rx) = tokio::sync::mpsc::channel(4);
        let worker_db = db.clone();
        let worker = tokio::spawn(async move {
            run_webhook_worker(worker_db, rx).await;
        });

        tx.send(WebhookEvent {
            action: "IP_ADD".to_owned(),
            address: "203.0.113.77".to_owned(),
            is_whitelist: false,
            group_id: Some(group_id),
            group_name: None,
            cause: None,
        })
        .await
        .expect("the worker's channel accepts the event");

        // Give the worker a moment to pick up the event, run its one DB query, and reach the point
        // of dialing the slow socket — comfortably inside the 2s the receiver will make it wait,
        // so if a connection were still held at this instant, the query below would observe it.
        tokio::time::sleep(Duration::from_millis(300)).await;

        let concurrent_query_started = std::time::Instant::now();
        let concurrent_result = tokio::time::timeout(
            Duration::from_millis(750),
            crate::entities::ip_group::Entity::find().all(&db),
        )
        .await;
        let concurrent_elapsed = concurrent_query_started.elapsed();

        // SAFETY: same single-writer justification as the `set_var` above.
        unsafe { std::env::remove_var("ALLOW_PRIVATE_WEBHOOKS") };

        assert!(
            concurrent_result.is_ok(),
            "a concurrent, unrelated query on the same 1-connection pool timed out after {concurrent_elapsed:?} \
             while a slow webhook dispatch was in flight — the dispatcher is holding the database \
             connection across the HTTP call"
        );
        assert!(
            concurrent_elapsed < SLOW_RESPONSE_DELAY,
            "the concurrent query took {concurrent_elapsed:?}, at least as long as the slow \
             receiver's {SLOW_RESPONSE_DELAY:?} delay — it was made to wait for a connection the \
             dispatch worker should already have released"
        );

        drop(tx);
        let _ = tokio::time::timeout(Duration::from_secs(5), worker).await;
    }

    /// A tiny raw-socket HTTP server that answers each accepted connection with the next status
    /// code from `statuses` (repeating the last one once exhausted) and always closes the
    /// connection. Every retry attempt therefore opens a fresh connection, which is what makes the
    /// returned counter's final value exactly the number of attempts a caller made — the property
    /// [`permanent_4xx_errors_are_not_retried`] and [`retries_are_exhausted_after_max_attempts`]
    /// both assert against directly, rather than inferring attempt count from timing.
    async fn spawn_status_sequence_server(
        statuses: Vec<u16>,
    ) -> (std::net::SocketAddr, std::sync::Arc<std::sync::atomic::AtomicUsize>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("loopback listener binds");
        let addr = listener.local_addr().expect("listener has a local address");
        let counter = Arc::new(AtomicUsize::new(0));
        let counter_accept = counter.clone();

        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { break };
                let n = counter_accept.fetch_add(1, Ordering::SeqCst);
                let status = *statuses.get(n).unwrap_or_else(|| {
                    statuses.last().expect("at least one status configured")
                });
                let reason = match status {
                    200 => "OK",
                    403 => "Forbidden",
                    404 => "Not Found",
                    500 => "Internal Server Error",
                    503 => "Service Unavailable",
                    _ => "Status",
                };
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;
                    let response =
                        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });

        (addr, counter)
    }

    fn dummy_prepared(target_url: String) -> PreparedDispatch {
        PreparedDispatch { target_url, headers: HeaderMap::new(), payload: "{}".to_owned() }
    }

    /// A minimal [`DispatchContext`] for tests that only care about the retry loop's behaviour, not
    /// the event data now persisted alongside it.
    fn dummy_ctx(webhook_id: Uuid, event_type: &str) -> DispatchContext {
        DispatchContext {
            webhook_id,
            webhook_name: "test-webhook".to_owned(),
            event_type: event_type.to_owned(),
            target_address: "203.0.113.1".to_owned(),
            cause: None,
        }
    }

    /// Like [`spawn_status_sequence_server`] but answers with a real body instead of
    /// `Content-Length: 0` — the counterpart needed to prove a receiver's actual reply survives into
    /// `webhook_executions.response_body`, not just the status code.
    async fn spawn_body_sequence_server(responses: Vec<(u16, &'static str)>) -> std::net::SocketAddr {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("loopback listener binds");
        let addr = listener.local_addr().expect("listener has a local address");

        tokio::spawn(async move {
            let mut n = 0usize;
            loop {
                let Ok((mut socket, _)) = listener.accept().await else { break };
                let (status, body) = *responses
                    .get(n)
                    .unwrap_or_else(|| responses.last().expect("at least one response configured"));
                n += 1;
                tokio::spawn(async move {
                    let mut buf = [0u8; 1024];
                    let _ = socket.read(&mut buf).await;
                    let response = format!(
                        "HTTP/1.1 {status} Status\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });

        addr
    }

    /// A migrated in-memory database holding one group and one webhook, for tests that need
    /// `log_execution`'s `webhook_id` foreign key to resolve to a real row.
    async fn seed_test_webhook(db: &DatabaseConnection) -> Uuid {
        use sea_orm::{ActiveModelTrait, Set};

        let group_id = Uuid::new_v4();
        crate::entities::ip_group::ActiveModel {
            id: Set(group_id),
            name: Set(format!("exec-log-test-{group_id}")),
            group_type: Set("banlist".to_owned()),
            owner_key_id: Set(None),
            description: Set(None),
            created_at: Set(chrono::Utc::now().naive_utc()),
        }
        .insert(db)
        .await
        .expect("group inserts");

        let webhook_id = Uuid::new_v4();
        webhook_config::ActiveModel {
            id: Set(webhook_id),
            name: Set("exec-log-test-webhook".to_owned()),
            target_url: Set("http://127.0.0.1:1/unused".to_owned()),
            secret_token: Set(String::new()),
            auth_mode: Set(AuthMode::NONE.to_owned()),
            api_key: Set(None),
            hmac_template: Set(None),
            signature_header: Set(None),
            signature_prefix: Set(None),
            headers_json: Set(None),
            payload_template: Set("{}".to_owned()),
            group_id: Set(group_id),
            is_active: Set(true),
            events: Set(None),
            owner_key_id: Set(None),
            created_at: Set(chrono::Utc::now().naive_utc()),
        }
        .insert(db)
        .await
        .expect("webhook config inserts");

        webhook_id
    }

    /// The count of `webhook_executions` rows recorded for `webhook_id`, for asserting that
    /// [`log_execution`] actually wrote what the retry loop or test dispatch did.
    async fn execution_count(db: &DatabaseConnection, webhook_id: Uuid) -> u64 {
        webhook_execution::Entity::find()
            .filter(webhook_execution::Column::WebhookId.eq(webhook_id))
            .count(db)
            .await
            .expect("counting execution rows succeeds")
    }

    async fn migrated_memory_db() -> DatabaseConnection {
        use sea_orm_migration::MigratorTrait;
        let db = sea_orm::Database::connect("sqlite::memory:").await.expect("in-memory sqlite opens");
        crate::migration::Migrator::up(&db, None).await.expect("migrations apply");
        db
    }

    /// [`attempt_delivery`] sorts a `2xx` into `Success`, a `4xx` into `Permanent`, and a `5xx` into
    /// `Transient` — the exact split the retry engine's "retry 5xx, fail immediately on 4xx" contract
    /// depends on, checked here against real HTTP responses rather than assumed from the status code
    /// alone.
    #[tokio::test]
    async fn attempt_delivery_classifies_2xx_4xx_and_5xx_correctly() {
        let client = build_webhook_client().expect("client builds");

        let (addr, _) = spawn_status_sequence_server(vec![200]).await;
        let (outcome, _) =
            attempt_delivery(&client, &format!("http://{addr}/"), HeaderMap::new(), String::new()).await;
        assert!(matches!(outcome, DispatchOutcome::Success { status: 200 }));

        let (addr, _) = spawn_status_sequence_server(vec![403]).await;
        let (outcome, _) =
            attempt_delivery(&client, &format!("http://{addr}/"), HeaderMap::new(), String::new()).await;
        assert!(matches!(outcome, DispatchOutcome::Permanent { status: Some(403), .. }));

        let (addr, _) = spawn_status_sequence_server(vec![503]).await;
        let (outcome, _) =
            attempt_delivery(&client, &format!("http://{addr}/"), HeaderMap::new(), String::new()).await;
        assert!(matches!(outcome, DispatchOutcome::Transient { status: Some(503), .. }));

        // No response at all — nothing is listening on this port — is transient too: a network-level
        // failure says nothing about whether the request itself was acceptable.
        let (outcome, _) =
            attempt_delivery(&client, "http://127.0.0.1:1", HeaderMap::new(), String::new()).await;
        assert!(matches!(outcome, DispatchOutcome::Transient { status: None, .. }));
    }

    /// A receiver's actual reply must come back on **every** outcome that reached the network —
    /// success included, not only failure. Before this, the body was read only on a non-2xx
    /// response; a 200 with a JSON acknowledgement was discarded entirely.
    #[tokio::test]
    async fn attempt_delivery_captures_the_receivers_body_on_success_and_on_failure() {
        let client = build_webhook_client().expect("client builds");

        let addr = spawn_body_sequence_server(vec![(200, "{\"received\":true}")]).await;
        let (outcome, body) =
            attempt_delivery(&client, &format!("http://{addr}/"), HeaderMap::new(), String::new()).await;
        assert!(matches!(outcome, DispatchOutcome::Success { status: 200 }));
        assert_eq!(body.as_deref(), Some("{\"received\":true}"));

        let addr = spawn_body_sequence_server(vec![(500, "downstream exploded")]).await;
        let (outcome, body) =
            attempt_delivery(&client, &format!("http://{addr}/"), HeaderMap::new(), String::new()).await;
        assert!(matches!(outcome, DispatchOutcome::Transient { status: Some(500), .. }));
        assert_eq!(body.as_deref(), Some("downstream exploded"));
    }

    /// A receiver that fails twice with `503` and then succeeds is retried exactly enough times to
    /// reach the success — proving the loop advances past a transient failure rather than either
    /// giving up early or retrying past a success it already got.
    #[tokio::test]
    async fn transient_errors_are_retried_until_success() {
        let (addr, counter) = spawn_status_sequence_server(vec![503, 503, 200]).await;
        let client = build_webhook_client().expect("client builds");
        let db = migrated_memory_db().await;
        let webhook_id = seed_test_webhook(&db).await;

        dispatch_with_retries_config(
            client,
            dummy_prepared(format!("http://{addr}/")),
            dummy_ctx(webhook_id, "IP_ADD"),
            /* max_retries */ 5,
            /* base_backoff_ms */ 1,
            db.clone(),
        )
        .await;

        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "two failing attempts plus the one that succeeded"
        );
        assert_eq!(
            execution_count(&db, webhook_id).await,
            3,
            "one webhook_executions row per HTTP attempt, including the two that were retried"
        );
    }

    /// A `403` must fail on the very first attempt — the defining "do NOT retry" case from the
    /// brief. `max_retries` is set high enough (5) that a passing count of 1 can only mean the
    /// classification, not an exhausted budget, stopped the loop.
    #[tokio::test]
    async fn permanent_4xx_errors_are_not_retried() {
        let (addr, counter) = spawn_status_sequence_server(vec![403]).await;
        let client = build_webhook_client().expect("client builds");
        let db = migrated_memory_db().await;
        let webhook_id = seed_test_webhook(&db).await;

        dispatch_with_retries_config(
            client,
            dummy_prepared(format!("http://{addr}/")),
            dummy_ctx(webhook_id, "IP_ADD"),
            /* max_retries */ 5,
            /* base_backoff_ms */ 1,
            db.clone(),
        )
        .await;

        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a 4xx response must not be retried at all"
        );

        let rows = webhook_execution::Entity::find()
            .filter(webhook_execution::Column::WebhookId.eq(webhook_id))
            .all(&db)
            .await
            .expect("querying execution rows succeeds");
        assert_eq!(rows.len(), 1, "exactly one recorded attempt");
        assert_eq!(rows[0].status_code, Some(403));
        assert!(!rows[0].is_success);
        assert_eq!(rows[0].event_type, "IP_ADD");
    }

    /// A receiver that always answers `503` is retried exactly `max_retries` times beyond the
    /// initial attempt, then given up on — not retried forever, and not given up on early.
    #[tokio::test]
    async fn retries_are_exhausted_after_max_attempts() {
        let (addr, counter) = spawn_status_sequence_server(vec![503]).await;
        let client = build_webhook_client().expect("client builds");
        let db = migrated_memory_db().await;
        let webhook_id = seed_test_webhook(&db).await;

        dispatch_with_retries_config(
            client,
            dummy_prepared(format!("http://{addr}/")),
            dummy_ctx(webhook_id, "IP_ADD"),
            /* max_retries */ 2,
            /* base_backoff_ms */ 1,
            db.clone(),
        )
        .await;

        assert_eq!(
            counter.load(std::sync::atomic::Ordering::SeqCst),
            3,
            "the initial attempt plus exactly 2 retries, then giving up"
        );
        assert_eq!(
            execution_count(&db, webhook_id).await,
            3,
            "every attempt is recorded, exhausted retries included"
        );
    }

    /// A successful dispatch's `webhook_executions` row must hold the receiver's actual response
    /// body — not `NULL`, and not a computed "HTTP 200" placeholder — proving the body survives the
    /// full path from `attempt_delivery` through `log_execution`, not just `attempt_delivery`'s
    /// return value in isolation.
    #[tokio::test]
    async fn a_successful_dispatch_persists_the_receivers_response_body() {
        let addr = spawn_body_sequence_server(vec![(200, "{\"ack\":\"ok\"}")]).await;
        let client = build_webhook_client().expect("client builds");
        let db = migrated_memory_db().await;
        let webhook_id = seed_test_webhook(&db).await;

        dispatch_with_retries_config(
            client,
            dummy_prepared(format!("http://{addr}/")),
            dummy_ctx(webhook_id, "IP_ADD"),
            /* max_retries */ 5,
            /* base_backoff_ms */ 1,
            db.clone(),
        )
        .await;

        let rows = webhook_execution::Entity::find()
            .filter(webhook_execution::Column::WebhookId.eq(webhook_id))
            .all(&db)
            .await
            .expect("querying execution rows succeeds");
        assert_eq!(rows.len(), 1);
        assert!(rows[0].is_success);
        assert_eq!(
            rows[0].response_body.as_deref(),
            Some("{\"ack\":\"ok\"}"),
            "a success must persist the receiver's actual body, not a computed placeholder or NULL"
        );
    }

    /// A dispatch's `webhook_executions` row must record the resolved target URL it actually dialed
    /// and the triggering event's address/cause — the data Task 2's search and filters (`ip`,
    /// `search`, `group_id`) depend on existing per-row, not only on the parent `webhook_configs`
    /// row, since the same webhook's resolved URL and event data vary attempt to attempt.
    #[tokio::test]
    async fn a_dispatch_persists_the_resolved_url_and_event_context() {
        let addr = spawn_status_sequence_server(vec![200]).await.0;
        let client = build_webhook_client().expect("client builds");
        let db = migrated_memory_db().await;
        let webhook_id = seed_test_webhook(&db).await;

        let resolved_url = format!("http://{addr}/hooks/IP_ADD");
        let ctx = DispatchContext {
            webhook_id,
            webhook_name: "context-test-webhook".to_owned(),
            event_type: "IP_ADD".to_owned(),
            target_address: "203.0.113.99".to_owned(),
            cause: Some("port scan".to_owned()),
        };

        dispatch_with_retries_config(
            client,
            dummy_prepared(resolved_url.clone()),
            ctx,
            /* max_retries */ 5,
            /* base_backoff_ms */ 1,
            db.clone(),
        )
        .await;

        let rows = webhook_execution::Entity::find()
            .filter(webhook_execution::Column::WebhookId.eq(webhook_id))
            .all(&db)
            .await
            .expect("querying execution rows succeeds");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].resolved_target_url.as_deref(), Some(resolved_url.as_str()));
        assert_eq!(rows[0].target_address.as_deref(), Some("203.0.113.99"));
        assert_eq!(rows[0].cause.as_deref(), Some("port scan"));
    }

    /// A permanently-failed dispatch's `webhook_executions` row must hold the receiver's actual
    /// reply when one was received, in preference to the computed "HTTP 403" reason string — the
    /// body is strictly more informative whenever it is present.
    #[tokio::test]
    async fn a_failed_dispatch_prefers_the_receivers_actual_reply_over_the_computed_reason() {
        let addr = spawn_body_sequence_server(vec![(403, "forbidden: bad signature")]).await;
        let client = build_webhook_client().expect("client builds");
        let db = migrated_memory_db().await;
        let webhook_id = seed_test_webhook(&db).await;

        dispatch_with_retries_config(
            client,
            dummy_prepared(format!("http://{addr}/")),
            dummy_ctx(webhook_id, "IP_ADD"),
            /* max_retries */ 5,
            /* base_backoff_ms */ 1,
            db.clone(),
        )
        .await;

        let rows = webhook_execution::Entity::find()
            .filter(webhook_execution::Column::WebhookId.eq(webhook_id))
            .all(&db)
            .await
            .expect("querying execution rows succeeds");
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0].response_body.as_deref(),
            Some("forbidden: bad signature"),
            "a body-bearing failure must persist the receiver's actual reply, not the computed \
             'HTTP 403' reason"
        );
    }

    /// [`send_test_dispatch`] runs the live "Test Webhook" path end-to-end against a real receiver,
    /// exercising [`prepare_dispatch`] (auth-mode signing, payload templating) and the HTTP call
    /// together — proving the test endpoint dispatches the *exact* request a real event would.
    #[tokio::test]
    async fn send_test_dispatch_reports_success_against_a_healthy_receiver() {
        let (addr, _) = spawn_status_sequence_server(vec![200]).await;
        let db = migrated_memory_db().await;
        let webhook_id = seed_test_webhook(&db).await;
        let config = webhook_config::Model {
            id: webhook_id,
            name: "test-target".to_owned(),
            target_url: format!("http://{addr}/hook"),
            secret_token: "shared-secret".to_owned(),
            auth_mode: AuthMode::HmacOnly.as_str().to_owned(),
            api_key: None,
            hmac_template: None,
            signature_header: None,
            signature_prefix: None,
            headers_json: None,
            payload_template: "{\"event\":\"test\"}".to_owned(),
            group_id: uuid::Uuid::new_v4(),
            is_active: true,
            events: None,
            owner_key_id: None,
            created_at: chrono::Utc::now().naive_utc(),
        };
        let event = WebhookEvent {
            action: "TEST".to_owned(),
            address: "127.0.0.1/32".to_owned(),
            is_whitelist: false,
            group_id: Some(config.group_id),
            group_name: None,
            cause: Some("unit test".to_owned()),
        };

        // `_with_privacy(..., true)` rather than setting `ALLOW_PRIVATE_WEBHOOKS` and calling the
        // public `send_test_dispatch`: the env var is process-wide and this binary's tests run
        // concurrently, so a test needing it "true" and one needing it unset (see the SSRF test
        // below) would race on the same global. Passing the value directly sidesteps that.
        let result = send_test_dispatch_with_privacy(&db, &config, &event, true).await;

        assert!(result.success, "a 200 response must report success: {:?}", result.error);
        assert_eq!(result.status, Some(200));
        assert!(result.error.is_none());

        let rows = webhook_execution::Entity::find()
            .filter(webhook_execution::Column::WebhookId.eq(webhook_id))
            .all(&db)
            .await
            .expect("querying execution rows succeeds");
        assert_eq!(rows.len(), 1, "the live test dispatch is recorded as one execution");
        assert_eq!(rows[0].event_type, "TEST");
        assert_eq!(rows[0].status_code, Some(200));
        assert!(rows[0].is_success);
    }

    /// The live test path runs through the **same** SSRF screen as a real dispatch — an
    /// authorized-but-untrusted caller must not be able to use "Test Webhook" to probe addresses the
    /// service would otherwise refuse to contact.
    #[tokio::test]
    async fn send_test_dispatch_is_blocked_by_the_ssrf_filter_by_default() {
        let db = migrated_memory_db().await;
        let webhook_id = seed_test_webhook(&db).await;
        let config = webhook_config::Model {
            id: webhook_id,
            name: "loopback-target".to_owned(),
            target_url: "http://127.0.0.1:1/hook".to_owned(),
            secret_token: String::new(),
            auth_mode: AuthMode::NONE.to_owned(),
            api_key: None,
            hmac_template: None,
            signature_header: None,
            signature_prefix: None,
            headers_json: None,
            payload_template: "{}".to_owned(),
            group_id: uuid::Uuid::new_v4(),
            is_active: true,
            events: None,
            owner_key_id: None,
            created_at: chrono::Utc::now().naive_utc(),
        };
        let event = WebhookEvent {
            action: "TEST".to_owned(),
            address: "127.0.0.1/32".to_owned(),
            is_whitelist: false,
            group_id: Some(config.group_id),
            group_name: None,
            cause: None,
        };

        // `_with_privacy(..., false)` — the default, production posture — for the same
        // race-avoidance reason as the success test above.
        let result = send_test_dispatch_with_privacy(&db, &config, &event, false).await;

        assert!(!result.success);
        assert!(result.blocked_by_ssrf_filter, "a loopback target must be reported as SSRF-blocked");
        assert!(result.status.is_none(), "a blocked target must never have been dialed at all");
        assert_eq!(
            execution_count(&db, webhook_id).await,
            0,
            "a request the SSRF filter refused was never attempted, so it must not be logged as one"
        );
    }
}
