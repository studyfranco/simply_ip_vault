//! Deployment configuration read from the environment, and the client-IP resolution it governs.
//!
//! The only setting here is [`TRUSTED_PROXIES_ENV`], but it is a security control rather than a
//! convenience: it decides whether `X-Forwarded-For` and `X-Real-IP` — headers any client can write
//! freely — are allowed to influence the address that `api_keys.bound_ips` is matched against.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use ipnetwork::IpNetwork;
use tokio::sync::RwLock;

/// Default listen address: every interface.
const DEFAULT_BIND_HOST: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
/// Default listen port.
const DEFAULT_BIND_PORT: u16 = 3000;

/// Resolves the socket address the HTTP server binds to, from `BIND_HOST`/`HOST` and `PORT`.
///
/// Reads the environment and delegates to [`parse_bind_addr`], which holds the logic so it can be
/// unit-tested without mutating process-global state.
///
/// The address was previously hardcoded to `0.0.0.0:3000`, which meant an operator had no way to
/// confine the service to a loopback or management interface short of a firewall — and no way to
/// run a second instance on one host, which the test suite needs in order to assert startup
/// behaviour at all.
pub fn resolve_bind_addr() -> SocketAddr {
    // `BIND_HOST` wins over `HOST` because `HOST` is a widely-used variable that some environments
    // set to something entirely unrelated (a hostname, a build target triple); an operator who sets
    // the explicit name should not have it silently overridden by ambient configuration.
    let host = std::env::var("BIND_HOST").or_else(|_| std::env::var("HOST")).ok();
    let port = std::env::var("PORT").ok();
    parse_bind_addr(host.as_deref(), port.as_deref())
}

/// Builds a listen address from optional raw `host`/`port` strings.
///
/// Both are parsed leniently: an unparseable value logs a warning and falls back to the default
/// rather than aborting startup, matching how the rest of this module treats malformed overrides.
///
/// A host must be a **literal IP address**. Resolving a hostname here could yield several addresses
/// with no principled way to choose between them, and binding the wrong interface is a security
/// problem rather than a convenience one — the opposite of `TRUSTED_PROXIES`, where a name is
/// exactly what is wanted because every address it resolves to is equally trusted.
///
/// Port `0` is passed through deliberately: the OS then assigns an ephemeral free port, which is
/// what a socket-activated deployment or a test harness wants.
pub fn parse_bind_addr(host: Option<&str>, port: Option<&str>) -> SocketAddr {
    let ip = match host.map(str::trim).filter(|h| !h.is_empty()) {
        Some(raw) => match raw.parse::<IpAddr>() {
            Ok(ip) => ip,
            Err(_) => {
                tracing::warn!(
                    "Invalid bind host {raw:?} (expected a literal IP address such as 0.0.0.0, \
                     127.0.0.1, or ::) — falling back to {DEFAULT_BIND_HOST}"
                );
                DEFAULT_BIND_HOST
            }
        },
        None => DEFAULT_BIND_HOST,
    };

    let port = match port.map(str::trim).filter(|p| !p.is_empty()) {
        Some(raw) => match raw.parse::<u16>() {
            Ok(port) => port,
            Err(_) => {
                tracing::warn!(
                    "Invalid PORT {raw:?} — falling back to {DEFAULT_BIND_PORT}"
                );
                DEFAULT_BIND_PORT
            }
        },
        None => DEFAULT_BIND_PORT,
    };

    SocketAddr::new(ip, port)
}

/// Comma-separated list of IPs, CIDRs, or **hostnames** whose members are allowed to set
/// `X-Forwarded-For` and `X-Real-IP` (e.g. `TRUSTED_PROXIES=10.0.0.0/8,192.168.1.5,traefik`).
///
/// **Unset means trust nothing**, which is the safe default but *not* the convenient one: behind a
/// reverse proxy with this unset, every request resolves to the proxy's own address, so a key bound
/// to a real client CIDR will be rejected with `403`. That is the correct failure direction — the
/// alternative is silently honouring a header the client controls — but it does mean a proxied
/// deployment **must** set this variable. See [`resolve_client_ip`].
pub const TRUSTED_PROXIES_ENV: &str = "TRUSTED_PROXIES";

// ─────────────────────────────────────────────────────────────
// Operational tuning
// ─────────────────────────────────────────────────────────────
//
// Every value below is read **once** into a `OnceLock` and cached. Re-reading the environment per
// request would make the effective configuration a moving target — the same class of value this
// module's header rules out for the security settings, for the same reason: a limit that can change
// under a running process is one nobody can reason about after the fact.
//
// All three fail *soft*. A malformed number logs a warning and uses the default, because none of them
// is a security boundary: throttling a notification queue too fast or too slow is a performance
// choice, and refusing to boot over it would trade a real outage for a tuning mistake. Contrast
// `TRUSTED_PROXIES` and `VAULT_ENCRYPTION_KEY`, which abort startup — those *are* boundaries.

/// Reads a numeric environment variable, falling back to `default` with a warning if unusable.
pub(crate) fn numeric_env<T>(name: &str, default: T) -> T
where
    T: std::str::FromStr + std::fmt::Display + Copy,
{
    match std::env::var(name) {
        Err(_) => default,
        Ok(raw) => match raw.trim().parse::<T>() {
            Ok(value) => value,
            Err(_) => {
                tracing::warn!(
                    "{name}={raw:?} is not a valid number; using the default of {default}"
                );
                default
            }
        },
    }
}

/// Parallel webhook dispatch workers. Env `WEBHOOK_WORKERS`, default 4.
pub const WEBHOOK_WORKERS_ENV: &str = "WEBHOOK_WORKERS";

/// Delay each worker waits between events, in milliseconds. Env `WEBHOOK_DISPATCH_INTERVAL_MS`.
pub const WEBHOOK_INTERVAL_ENV: &str = "WEBHOOK_DISPATCH_INTERVAL_MS";

/// Depth of the in-memory webhook queue. Env `WEBHOOK_QUEUE_CAPACITY`.
pub const WEBHOOK_QUEUE_ENV: &str = "WEBHOOK_QUEUE_CAPACITY";

/// Maximum retry attempts for a transient webhook delivery failure. Env `WEBHOOK_MAX_RETRIES`.
pub const WEBHOOK_MAX_RETRIES_ENV: &str = "WEBHOOK_MAX_RETRIES";

/// Base backoff between retry attempts, in milliseconds, doubled on each subsequent attempt. Env
/// `WEBHOOK_RETRY_BACKOFF_MS`.
pub const WEBHOOK_RETRY_BACKOFF_ENV: &str = "WEBHOOK_RETRY_BACKOFF_MS";

/// Number of worker tasks consuming the webhook channel. **Clamped to at least 1.**
///
/// Zero would mean nothing drains the queue: every send would fill the buffer and then fail, and the
/// service would look healthy while delivering nothing. A configuration that silently disables a
/// subsystem should not be reachable by typing `0`.
///
/// Raised from the historical default of 1 to 4: a production deployment saw the queue saturate
/// (`capacity=1024`, dropped notifications logged at `warn`) under an ordinary bulk-ban burst, and a
/// single worker was the bottleneck — four lets the pool drain roughly four times as fast without
/// changing anything about how a single event fans out to its configs.
pub fn webhook_workers() -> usize {
    static VALUE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| numeric_env::<usize>(WEBHOOK_WORKERS_ENV, 4).max(1))
}

/// Pause a worker takes after finishing one event, in milliseconds. `0` disables throttling.
///
/// This paces **events per worker**, not individual HTTP calls: one event may fan out to several
/// webhook configs, and those still dispatch concurrently. The aggregate ceiling is therefore
/// `webhook_workers() / interval` events per second — with the defaults (4 workers, 50ms), 80 per
/// second.
///
/// The default is deliberately non-zero — pacing still matters, an unthrottled worker turns a bulk
/// operation into a synchronised burst against every configured receiver at once, which reads, from
/// the receiver's side, as a denial-of-service originating from us. Lowered from the historical
/// 500ms to 50ms: 500ms limited a single worker to two events per second, which is what let the
/// queue in `webhook_workers`'s doc comment saturate in the first place; 50ms keeps the
/// burst-flattening property (still one event at a time per worker, never an unthrottled flood)
/// while draining an order of magnitude faster.
pub fn webhook_dispatch_interval() -> std::time::Duration {
    static VALUE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    std::time::Duration::from_millis(*VALUE.get_or_init(|| numeric_env::<u64>(WEBHOOK_INTERVAL_ENV, 50)))
}

/// Capacity of the webhook channel. **Clamped to at least 1** — `mpsc::channel(0)` panics.
///
/// Raised from the historical 100, then again from 1,024: throttling makes a full queue likelier
/// than an unthrottled channel would, and a production deployment still saturated the queue at 1,024
/// under a bulk-ban burst even with pacing. 4,096 alongside the faster 4-worker/50ms pool above gives
/// substantially more headroom before the drop path in `state::AppState::enqueue_webhook` — which
/// remains the correct behaviour for whatever headroom does eventually run out: the event is dropped
/// with a warning rather than blocking the request that produced it.
pub fn webhook_queue_capacity() -> usize {
    static VALUE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| numeric_env::<usize>(WEBHOOK_QUEUE_ENV, 4_096).max(1))
}

/// Maximum number of retry attempts after an initial transient delivery failure. **Clamped to at
/// most 10** — an unbounded value would let one stuck receiver hold a dispatch worker's attention
/// indefinitely via exponential backoff, at the expense of every other event waiting behind it.
///
/// Only *transient* failures are retried at all — a connection timeout, a network error, or a `5xx`
/// response. A `4xx` response is treated as a configuration or authorization problem the target will
/// not resolve by being asked again, and fails on the first attempt. See
/// `dispatch::classify_dispatch_outcome`.
pub fn webhook_max_retries() -> u32 {
    static VALUE: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| numeric_env::<u32>(WEBHOOK_MAX_RETRIES_ENV, 3).min(10))
}

/// Base delay before the first retry, in milliseconds, doubled on each subsequent attempt
/// (`backoff * 2^(attempt - 1)`, so with the default 1000ms: 1s, 2s, 4s, ...). **Clamped to at least
/// 1ms** — `0` would turn "backoff" into an immediate, tight retry loop against a receiver that just
/// said it was struggling.
pub fn webhook_retry_backoff_ms() -> u64 {
    static VALUE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| numeric_env::<u64>(WEBHOOK_RETRY_BACKOFF_ENV, 1_000).max(1))
}

/// Maximum request body size in mebibytes. Env `MAX_BODY_SIZE_MIB`, default 10.
pub const MAX_BODY_SIZE_ENV: &str = "MAX_BODY_SIZE_MIB";

/// Default body limit in MiB, used when [`MAX_BODY_SIZE_ENV`] is unset or unparseable.
///
/// Raised from 3 to 10 for `POST /api/records/batch`: ten thousand records with causes and timestamps
/// exceeds 3 MiB comfortably, and a batch endpoint whose documented maximum cannot be submitted is
/// not a batch endpoint.
pub const DEFAULT_MAX_BODY_MIB: usize = 10;

/// The request body ceiling in bytes, resolved once.
///
/// **Read by two layers that must agree exactly**: the router's `DefaultBodyLimit`, and
/// `middleware::auth_middleware`, which buffers the body to verify its HMAC. If the middleware's
/// buffer were the larger of the two, a body between the limits would be fully read and hashed only
/// to be rejected by the extractor afterwards — paying the memory cost of a payload the service had
/// already decided not to accept. One function, called by both, is what makes that impossible rather
/// than merely unlikely.
///
/// **On raising it.** The middleware buffers *after* the key lookup, so reaching this allocation
/// requires a caller holding a key whose hash is in the database — not an anonymous one. It is still
/// a per-in-flight-request cost multiplied by concurrency, so an operator running many low-trust keys
/// should lower it rather than assume the default is free.
///
/// Clamped to at least 1 MiB: a smaller ceiling rejects ordinary key-creation payloads and would
/// present as the API being broken rather than as a misconfiguration.
pub fn max_body_bytes() -> usize {
    static VALUE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| {
        numeric_env::<usize>(MAX_BODY_SIZE_ENV, DEFAULT_MAX_BODY_MIB).max(1) * 1024 * 1024
    })
}

// ─────────────────────────────────────────────────────────────
// Database pool tuning
// ─────────────────────────────────────────────────────────────
//
// Two tiers read these same four environment variables with two different sets of defaults and
// ceilings. `database_max_connections`/`database_min_connections` below are the PostgreSQL/MySQL
// tier (default 50/10, no ceiling beyond what the operator asks for).
// `sqlite_file_max_connections`/`sqlite_file_min_connections`, further down, are the file-backed
// SQLite tier — same two variable names, its own defaults (10/2) and a hard ceiling
// (`SQLITE_FILE_MAX_CONNECTIONS_CEILING`) that no requested value can exceed. **Neither tier ever
// reaches `sqlite::memory:`**: `src/db.rs::connect` pins that one to exactly one connection,
// unconditionally, because an in-memory database is a single, unshareable buffer — a second
// connection to it is not a second reader, it is an empty database that never saw the migrations
// the first one applied. See that module's header for the full in-memory-vs-file split, and for why
// even the file tier's ceiling exists at all (SQLite's single-writer lock makes a wide pool mostly
// theoretical benefit for writes, real benefit for concurrent reads, and real risk of lock-wait
// pile-ups past a fairly low number of connections).
//
// Defaults for the PostgreSQL/MySQL tier are chosen for a deployment fielding the production
// symptom this was added for (`sqlx::pool::acquire: acquired connection exceeded slow threshold`):
// 50 max / 10 min gives headroom under a webhook-dispatch burst without the pool constantly growing
// and shrinking from zero, and a 10s acquire timeout turns a starved pool into a clear, bounded
// `500` instead of a request hanging for as long as the caller's own client timeout allows.

/// Maximum PostgreSQL/MySQL pool connections. Env `DATABASE_MAX_CONNECTIONS`, default 50.
pub const DATABASE_MAX_CONNECTIONS_ENV: &str = "DATABASE_MAX_CONNECTIONS";

/// Minimum PostgreSQL/MySQL connections kept warm. Env `DATABASE_MIN_CONNECTIONS`, default 10.
pub const DATABASE_MIN_CONNECTIONS_ENV: &str = "DATABASE_MIN_CONNECTIONS";

/// Idle duration before a pooled PostgreSQL/MySQL connection is closed, in seconds. Env
/// `DATABASE_IDLE_TIMEOUT_SECS`, default 600.
pub const DATABASE_IDLE_TIMEOUT_ENV: &str = "DATABASE_IDLE_TIMEOUT_SECS";

/// Maximum time a request waits to acquire a pooled PostgreSQL/MySQL connection, in seconds. Env
/// `DATABASE_ACQUIRE_TIMEOUT_SECS`, default 10.
pub const DATABASE_ACQUIRE_TIMEOUT_ENV: &str = "DATABASE_ACQUIRE_TIMEOUT_SECS";

/// Clamps a requested pool ceiling to at least 1 — `sqlx::Pool` panics on `0`.
///
/// Split out from [`database_max_connections`] purely so it is unit-testable. That wrapper's own
/// value is cached in a `OnceLock` seeded from the real environment on first call, which makes it
/// unsuitable for a test that wants to see what several different inputs clamp to in one process —
/// the same reason `db::has_index`'s catalog-query selection was split from `db::has_index` itself.
fn clamp_pool_max(requested: u32) -> u32 {
    requested.max(1)
}

/// Clamps a requested pool floor to at most `max` — sqlx accepts `min > max` at the API level and
/// the pool simply never reaches the requested minimum, which reads as the setting being silently
/// ignored rather than the misconfiguration it is. Split out for the same testability reason as
/// [`clamp_pool_max`].
fn clamp_pool_min(requested: u32, max: u32) -> u32 {
    requested.min(max)
}

/// Clamps a requested acquire timeout to at least 1 second — `0` is indistinguishable from "never
/// wait" to sqlx, which would turn ordinary pool contention into a guaranteed failure on any
/// request that did not win the race. Split out for the same testability reason as
/// [`clamp_pool_max`].
fn clamp_acquire_timeout_secs(requested: u64) -> u64 {
    requested.max(1)
}

/// The pool's connection ceiling. **Clamped to at least 1** — see [`clamp_pool_max`].
pub fn database_max_connections() -> u32 {
    static VALUE: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| clamp_pool_max(numeric_env::<u32>(DATABASE_MAX_CONNECTIONS_ENV, 50)))
}

/// The pool's warm-connection floor. **Clamped to at most [`database_max_connections`]** — see
/// [`clamp_pool_min`].
pub fn database_min_connections() -> u32 {
    static VALUE: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| {
        clamp_pool_min(numeric_env::<u32>(DATABASE_MIN_CONNECTIONS_ENV, 10), database_max_connections())
    })
}

/// How long an idle pooled connection may sit before being closed.
pub fn database_idle_timeout() -> std::time::Duration {
    static VALUE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    std::time::Duration::from_secs(*VALUE.get_or_init(|| {
        numeric_env::<u64>(DATABASE_IDLE_TIMEOUT_ENV, 600)
    }))
}

/// How long a request waits for the pool to hand back a connection before failing. **Clamped to at
/// least 1 second** — see [`clamp_acquire_timeout_secs`].
pub fn database_acquire_timeout() -> std::time::Duration {
    static VALUE: std::sync::OnceLock<u64> = std::sync::OnceLock::new();
    std::time::Duration::from_secs(*VALUE.get_or_init(|| {
        clamp_acquire_timeout_secs(numeric_env::<u64>(DATABASE_ACQUIRE_TIMEOUT_ENV, 10))
    }))
}

/// Hard ceiling on the file-backed SQLite tier's connection count, regardless of what
/// `DATABASE_MAX_CONNECTIONS` requests.
///
/// Not a default — a *ceiling*. SQLite permits any number of concurrent readers under WAL, but
/// exactly one writer at a time (`busy_timeout` governs how long the rest queue for it); past a
/// fairly small number of connections, the marginal reader throughput a wider pool buys is real but
/// small, while the chance of a burst of writers queuing behind the single write lock — and each
/// holding a checked-out connection while it waits — grows with pool size. 10 is generous headroom
/// for read parallelism without inviting that. Unlike the PostgreSQL/MySQL tier, an operator cannot
/// raise this by setting `DATABASE_MAX_CONNECTIONS` higher; it can only lower it.
const SQLITE_FILE_MAX_CONNECTIONS_CEILING: u32 = 10;

/// Clamps a requested file-backed-SQLite pool ceiling to `[1, SQLITE_FILE_MAX_CONNECTIONS_CEILING]`.
/// Split out for the same testability reason as [`clamp_pool_max`], which this composes with.
fn clamp_sqlite_file_max(requested: u32) -> u32 {
    clamp_pool_max(requested).min(SQLITE_FILE_MAX_CONNECTIONS_CEILING)
}

/// The file-backed SQLite tier's connection ceiling: `DATABASE_MAX_CONNECTIONS`, default 10,
/// clamped to at least 1 and to at most [`SQLITE_FILE_MAX_CONNECTIONS_CEILING`] — see
/// [`clamp_sqlite_file_max`].
///
/// **Never consulted for `sqlite::memory:`** — `src/db.rs::connect` pins that case to exactly one
/// connection before this function is ever called, by branching on the storage type rather than by
/// this function detecting it. See the module header for why an in-memory database cannot use more
/// than one connection at all, safely or not: it is a single unshareable buffer, not a slower disk.
pub fn sqlite_file_max_connections() -> u32 {
    static VALUE: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| clamp_sqlite_file_max(numeric_env::<u32>(DATABASE_MAX_CONNECTIONS_ENV, 10)))
}

/// The file-backed SQLite tier's warm-connection floor: `DATABASE_MIN_CONNECTIONS`, default 2,
/// clamped to at most [`sqlite_file_max_connections`].
pub fn sqlite_file_min_connections() -> u32 {
    static VALUE: std::sync::OnceLock<u32> = std::sync::OnceLock::new();
    *VALUE.get_or_init(|| {
        clamp_pool_min(numeric_env::<u32>(DATABASE_MIN_CONNECTIONS_ENV, 2), sqlite_file_max_connections())
    })
}

/// Environment variable overriding the generated bootstrap master key.
pub const INITIAL_MASTER_KEY_ENV: &str = "INITIAL_MASTER_KEY";

/// Required length of a master key in hex characters — 32 bytes of entropy.
///
/// Not an arbitrary policy number: it is exactly what [`crate::api::generate_random_key`] produces
/// (`[u8; 32]`, hex-encoded), so the rule below demands of an operator precisely what the service
/// demands of itself. A validator that accepted less than the generator emits would be a rule the
/// service does not follow.
pub const MASTER_KEY_HEX_LEN: usize = 64;

/// [`INITIAL_MASTER_KEY_ENV`] was set to something that is not a 32-byte hex key.
#[derive(Debug, thiserror::Error)]
#[error(
    "{INITIAL_MASTER_KEY_ENV} must be exactly {MASTER_KEY_HEX_LEN} hexadecimal characters (32 bytes \
     of entropy) — the same shape this service generates for itself. Got {got} character(s){detail}. \
     Generate one with `openssl rand -hex 32`, or unset the variable to have one generated. \
     Refusing to start: a weak master key is the single credential that can administer everything."
)]
pub struct InvalidInitialMasterKey {
    /// How many characters were supplied.
    pub got: usize,
    /// `", and it contains non-hexadecimal characters"` when that is also true, else empty.
    pub detail: &'static str,
}

/// Validates an operator-supplied bootstrap master key, or explains why it is unusable.
///
/// # Why this is fatal rather than a warning
///
/// `INITIAL_MASTER_KEY` exists for deterministic test and CI bootstrap, and until now it accepted
/// **any** non-empty string with only a log line objecting. That log line already said the right
/// thing — "a human-chosen, low-entropy secret defeats the point of generating a random 256-bit
/// key" — and then let it through anyway, which is the shape of control that reads like a safeguard
/// and stops nothing. A warning in a startup log is not read by the person who set
/// `INITIAL_MASTER_KEY=changeme` in a compose file.
///
/// The credential this guards is the one that can administer every other credential, so the failure
/// direction has to be refusal. There is no legitimate deployment that needs a short master key: an
/// operator who wants a *deterministic* one still gets it, they just have to supply 64 hex
/// characters, and one that wants a *strong* one leaves the variable unset.
///
/// Checked before any of it reaches the database, so a rejected key never becomes the master row.
///
/// > **Deliberate divergence.** `simply_hook_executor` accepts any non-empty
/// > `INITIAL_MASTER_KEY`. This service is stricter on purpose, and the asymmetry is recorded in
/// > `AGENT_NOTES.MD` rather than being converged away.
pub fn validate_initial_master_key(raw: &str) -> Result<(), InvalidInitialMasterKey> {
    let is_hex = raw.chars().all(|c| c.is_ascii_hexdigit());
    if raw.len() == MASTER_KEY_HEX_LEN && is_hex {
        return Ok(());
    }
    Err(InvalidInitialMasterKey {
        got: raw.chars().count(),
        detail: if is_hex { "" } else { ", and it contains non-hexadecimal characters" },
    })
}

/// How long a successful hostname resolution is reused before being looked up again.
///
/// Short on purpose. A container that is recreated keeps its name and gets a new address, and until
/// this expires the old address is still trusted while the new one is not — the first is a (brief)
/// over-trust of an address the orchestrator has probably already reassigned, the second a visible
/// `403`. 30s keeps both windows small without turning every request into a DNS lookup.
const POSITIVE_TTL: Duration = Duration::from_secs(30);

/// How long a *failed* resolution is remembered before being retried — negative caching.
///
/// Deliberately much shorter than [`POSITIVE_TTL`], because a name that is failing is one an
/// operator is probably in the middle of fixing, but deliberately non-zero, which is the point:
/// without it, every request arriving while a configured hostname is unresolvable triggers its own
/// DNS lookup. A hot path behind a dead name then turns this service into a resolution amplifier —
/// one inbound request becomes one outbound query, at whatever rate the caller chooses — which is a
/// DoS both against the resolver and against this process's own latency. With it, the cost is
/// bounded to one query per name per interval no matter how much traffic arrives.
const NEGATIVE_TTL: Duration = Duration::from_secs(5);

/// How long after boot an initially-unresolvable hostname is given before the failure is reported
/// as persistent.
///
/// A daemon and its reverse proxy usually start together, and the proxy's DNS record may not exist
/// for the first few seconds of the daemon's life. Aborting startup over that would turn an
/// ordinary boot race into a crash loop — and a crash loop is strictly worse than running, because a
/// service that is up with one proxy entry disabled still serves every other caller correctly,
/// while one that is down serves nobody. The entry stays untrusted for the duration (fail closed,
/// for that entry only), and the outcome is logged either way.
const BOOT_GRACE_PERIOD: Duration = Duration::from_secs(60);

/// A `TRUSTED_PROXIES` entry that is not a valid spelling of anything, and why.
///
/// Distinct from a hostname that merely fails to resolve *right now*: this is a value that can
/// never become usable no matter what DNS does, so it is a configuration error rather than a
/// transient one. See [`InvalidTrustedProxies`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidProxyEntry {
    /// The entry exactly as written, so the operator can find it in their configuration.
    pub entry: String,
    /// Why it was refused, phrased to name the mistake rather than the rule.
    pub reason: &'static str,
}

/// Startup refusal: at least one `TRUSTED_PROXIES` entry was syntactically impossible.
///
/// # Why this aborts rather than dropping the entry
///
/// Every other malformed override in this module falls back to a default, because the fallback is
/// unambiguous and safe. This one is neither. `TRUSTED_PROXIES` is the list of peers permitted to
/// *rewrite the client address every authorization decision is made against*, and an entry that
/// cannot be parsed leaves that boundary in a state nobody has established:
///
/// - Silently dropping it fails **closed** for the entry itself, but the operator wrote it because
///   they have a proxy there. Every request through that proxy is then attributed to the proxy's own
///   address, so a CIDR-bound key gets `403` — an outage whose cause is one `warn!` line in a log
///   nobody reads until the incident.
/// - The mistake is usually one character (`10.0.0.0/8x`, `10.0.0.256`), and a one-character typo
///   silently changing which network is trusted is precisely the class of error a trust boundary
///   must not absorb quietly.
///
/// Refusing to start converts both into a loud, immediate, unmissable failure at the only moment the
/// operator is watching. It is safe to be this strict *because* the check is purely syntactic: a
/// hostname that is well-formed but currently unresolvable is not an error here at all — it keeps
/// the [`BOOT_GRACE_PERIOD`] path, because DNS being down is a transient condition and crash-looping
/// through it would be strictly worse than serving with one entry disabled.
#[derive(Debug, thiserror::Error)]
#[error(
    "{} invalid {TRUSTED_PROXIES_ENV} entr{}: {}",
    entries.len(),
    if entries.len() == 1 { "y" } else { "ies" },
    entries.iter().map(|e| format!("{:?} ({})", e.entry, e.reason)).collect::<Vec<_>>().join("; ")
)]
pub struct InvalidTrustedProxies {
    /// Every rejected entry, so one restart surfaces all of the typos rather than the first.
    pub entries: Vec<InvalidProxyEntry>,
}

/// A `TRUSTED_PROXIES` entry: either a fixed network or a name resolved at request time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ProxyMatcher {
    /// A literal address or CIDR range, matched directly.
    Network(IpNetwork),
    /// A hostname (`traefik`, `proxy.internal`) resolved via DNS.
    ///
    /// Kept as a name rather than resolved once at startup because that is the entire point: in
    /// Docker and Kubernetes a service name outlives the address behind it, and a container
    /// restart that changes the IP must not silently stop the proxy from being trusted.
    Hostname(String),
}

impl std::fmt::Display for ProxyMatcher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Network(network) => write!(f, "{network}"),
            Self::Hostname(name) => write!(f, "{name}"),
        }
    }
}

/// One hostname's last resolution attempt.
#[derive(Clone)]
struct HostnameState {
    /// What the name resolved to, empty when the lookup failed.
    addresses: Vec<IpNetwork>,
    /// When the attempt ran.
    attempted_at: Instant,
    /// Whether it produced at least one address.
    resolved: bool,
}

impl HostnameState {
    /// Whether this attempt may still be reused, per the positive/negative TTL split.
    fn is_fresh(&self, positive: Duration, negative: Duration) -> bool {
        let ttl = if self.resolved { positive } else { negative };
        self.attempted_at.elapsed() < ttl
    }
}

/// The merged view every request is matched against, plus the per-hostname state behind it.
#[derive(Default)]
struct ResolutionCache {
    /// Literal networks merged with whatever the hostnames currently resolve to.
    snapshot: Arc<Vec<IpNetwork>>,
    /// Per-hostname attempt state, which is what makes negative caching per-name rather than
    /// all-or-nothing: one dead entry must not force the healthy ones to be re-resolved on its
    /// short retry interval.
    hosts: HashMap<String, HostnameState>,
    /// Whether `snapshot` reflects the current `hosts` map.
    built: bool,
}

/// The set of peers whose forwarding headers are believed.
///
/// Holds the parsed `TRUSTED_PROXIES` specification plus a short-lived cache of resolved hostnames.
/// Cloning shares the cache, so every handler sees one resolution rather than each maintaining its
/// own.
#[derive(Clone, Debug, Default)]
pub struct TrustedProxies {
    /// The configuration exactly as written, for logging.
    matchers: Arc<Vec<ProxyMatcher>>,
    /// Literal entries, precomputed. Also the complete answer when no hostnames are configured —
    /// the common case, served for the cost of an `Arc` clone and no lock at all.
    networks: Arc<Vec<IpNetwork>>,
    /// Hostname entries awaiting resolution.
    hostnames: Arc<Vec<String>>,
    /// Reuse window for a successful lookup.
    positive_ttl: Duration,
    /// Reuse window for a failed lookup.
    negative_ttl: Duration,
    cache: Arc<RwLock<ResolutionCache>>,
}

impl std::fmt::Debug for ResolutionCache {
    /// Renders nothing of substance: a `{:?}` of application state should describe what the
    /// operator configured, not which addresses a name happened to resolve to a moment ago.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("<resolution cache>")
    }
}

impl TrustedProxies {
    /// Builds from an already-parsed matcher list.
    pub fn new(matchers: Vec<ProxyMatcher>) -> Self {
        let networks: Vec<IpNetwork> = matchers
            .iter()
            .filter_map(|m| match m {
                ProxyMatcher::Network(net) => Some(*net),
                ProxyMatcher::Hostname(_) => None,
            })
            .collect();
        let hostnames: Vec<String> = matchers
            .iter()
            .filter_map(|m| match m {
                ProxyMatcher::Hostname(name) => Some(name.clone()),
                ProxyMatcher::Network(_) => None,
            })
            .collect();

        Self {
            matchers: Arc::new(matchers),
            networks: Arc::new(networks),
            hostnames: Arc::new(hostnames),
            positive_ttl: POSITIVE_TTL,
            negative_ttl: NEGATIVE_TTL,
            cache: Arc::new(RwLock::new(ResolutionCache::default())),
        }
    }

    /// Reads and parses [`TRUSTED_PROXIES_ENV`], refusing to build if any entry is malformed.
    ///
    /// Every rejected entry is logged on its own `FATAL:` line before the error is returned, because
    /// the error travels up to `main` and is printed once: an operator with three typos should see
    /// three lines naming three entries, not one line naming the first. This runs before any DNS
    /// resolution or grace-period logic — the check is syntactic, so there is nothing to wait for.
    ///
    /// An **unset** variable is not an error. That is the zero-configuration case, and it means
    /// "trust nothing", which is the safe posture rather than an ambiguous one.
    pub fn from_env() -> Result<Self, InvalidTrustedProxies> {
        let Ok(raw) = std::env::var(TRUSTED_PROXIES_ENV) else {
            return Ok(Self::default());
        };

        match parse_trusted_proxies(&raw) {
            Ok(matchers) => Ok(Self::new(matchers)),
            Err(entries) => {
                for invalid in &entries {
                    tracing::error!(
                        "FATAL: {} entry '{}' is not a valid IP address, CIDR range, or hostname \
                         ({}). Refusing to start with an ambiguous trust boundary.",
                        TRUSTED_PROXIES_ENV,
                        invalid.entry,
                        invalid.reason
                    );
                }
                Err(InvalidTrustedProxies { entries })
            }
        }
    }

    /// Overrides both DNS reuse windows. Test-facing: a suite cannot wait 30 seconds to observe
    /// that a re-resolution happened, nor 5 to observe that one was suppressed.
    #[cfg(test)]
    pub fn with_ttls(mut self, positive: Duration, negative: Duration) -> Self {
        self.positive_ttl = positive;
        self.negative_ttl = negative;
        self
    }

    /// Whether anything at all is trusted. An empty configuration ignores forwarding headers.
    pub fn is_empty(&self) -> bool {
        self.matchers.is_empty()
    }

    /// The configured matchers, for startup logging.
    pub fn matchers(&self) -> &[ProxyMatcher] {
        &self.matchers
    }

    /// The networks to match this request against, resolving hostnames when their cache entry has
    /// expired.
    ///
    /// Returns an [`Arc`] rather than a fresh `Vec` so the steady-state cost is a refcount bump.
    /// The no-hostname case — every deployment that names its proxies by address — never touches
    /// the lock or the resolver at all.
    ///
    /// Resolving the *whole set* into one flat list, rather than testing hostnames lazily on a
    /// per-address basis, is what lets [`resolve_client_ip`] treat a hostname-identified proxy
    /// exactly like a CIDR one while walking the `X-Forwarded-For` chain. A lazy design cannot do
    /// that without a DNS lookup per header entry, and so ends up skipping only the literal hops —
    /// which silently reports the inner proxy as the client in precisely the containerized topology
    /// hostname support exists to serve.
    pub async fn resolved(&self) -> Arc<Vec<IpNetwork>> {
        if self.hostnames.is_empty() {
            return Arc::clone(&self.networks);
        }

        {
            let cache = self.cache.read().await;
            if cache.built
                && self
                    .hostnames
                    .iter()
                    .all(|name| {
                        cache
                            .hosts
                            .get(name)
                            .is_some_and(|s| s.is_fresh(self.positive_ttl, self.negative_ttl))
                    })
            {
                return Arc::clone(&cache.snapshot);
            }
        }

        // Re-check under the write lock: several requests can queue behind one expiry, and only the
        // first should pay for the lookup. This is the other half of the anti-amplification
        // property — negative caching bounds retries over time, this bounds them across concurrent
        // requests at one instant.
        let mut cache = self.cache.write().await;
        self.refresh_locked(&mut cache).await;
        Arc::clone(&cache.snapshot)
    }

    /// Re-resolves every hostname whose cached attempt has expired, then rebuilds the snapshot.
    async fn refresh_locked(&self, cache: &mut ResolutionCache) {
        for name in self.hostnames.iter() {
            if cache
                .hosts
                .get(name)
                .is_some_and(|s| s.is_fresh(self.positive_ttl, self.negative_ttl))
            {
                continue;
            }

            let addresses = resolve_hostname(name).await;
            let resolved = !addresses.is_empty();
            cache.hosts.insert(
                name.clone(),
                HostnameState { addresses, attempted_at: Instant::now(), resolved },
            );
        }

        let mut merged = (*self.networks).clone();
        for name in self.hostnames.iter() {
            if let Some(state) = cache.hosts.get(name) {
                merged.extend(state.addresses.iter().copied());
            }
        }
        cache.snapshot = Arc::new(merged);
        cache.built = true;
    }

    /// Resolves every configured hostname once at boot, reporting the names that failed.
    ///
    /// Returns the list of unresolvable entries so the caller can decide what to say about them.
    /// It never returns an error and never panics: a name that does not resolve is simply not
    /// trusted, which is the safe direction, and is a per-entry outcome rather than a service-wide
    /// one.
    pub async fn prime(&self) -> Vec<String> {
        if self.hostnames.is_empty() {
            return Vec::new();
        }

        let mut cache = self.cache.write().await;
        // Force a real attempt rather than reusing whatever a concurrent request just cached.
        cache.hosts.clear();
        self.refresh_locked(&mut cache).await;

        self.hostnames
            .iter()
            .filter(|name| !cache.hosts.get(*name).is_some_and(|s| s.resolved))
            .cloned()
            .collect()
    }

    /// Primes the set at boot and, if anything failed to resolve, retries once after
    /// [`BOOT_GRACE_PERIOD`] on a detached task.
    ///
    /// The service is fully operational throughout — the unresolved entries are simply untrusted
    /// until they resolve, and normal per-request refresh will pick them up whenever they start
    /// working. The grace retry exists so the *logs* distinguish a boot race that healed itself
    /// from a genuine misconfiguration, without an operator having to correlate timestamps.
    pub fn prime_with_grace(&self) {
        let proxies = self.clone();
        tokio::spawn(async move {
            let failed = proxies.prime().await;
            if failed.is_empty() {
                if !proxies.hostnames.is_empty() {
                    tracing::info!(
                        "All {} {} hostname entr{} resolved at startup.",
                        proxies.hostnames.len(),
                        TRUSTED_PROXIES_ENV,
                        if proxies.hostnames.len() == 1 { "y" } else { "ies" }
                    );
                }
                return;
            }

            tracing::error!(
                "{} hostname entr{} did not resolve at startup: {:?}. Those peers are NOT trusted \
                 and their forwarding headers will be ignored; every other entry is unaffected and \
                 the service is serving normally. Retrying in {}s.",
                TRUSTED_PROXIES_ENV,
                if failed.len() == 1 { "y" } else { "ies" },
                failed,
                BOOT_GRACE_PERIOD.as_secs()
            );

            tokio::time::sleep(BOOT_GRACE_PERIOD).await;
            let still_failing = proxies.prime().await;
            if still_failing.is_empty() {
                tracing::info!(
                    "All {} hostname entries resolved after the {}s grace period; \
                     they are trusted from now on.",
                    TRUSTED_PROXIES_ENV,
                    BOOT_GRACE_PERIOD.as_secs()
                );
            } else {
                tracing::error!(
                    "{} hostname entr{} still unresolvable after the {}s grace period: {:?}. \
                     Continuing to serve with {} entr{} disabled — check the name and the \
                     resolver. Resolution is retried automatically; no restart is required.",
                    TRUSTED_PROXIES_ENV,
                    if still_failing.len() == 1 { "y" } else { "ies" },
                    BOOT_GRACE_PERIOD.as_secs(),
                    still_failing,
                    still_failing.len(),
                    if still_failing.len() == 1 { "y" } else { "ies" }
                );
            }
        });
    }
}

/// Resolves one hostname to the host routes it currently names.
///
/// A failure yields nothing rather than propagating: an unresolvable name means "this proxy is not
/// currently trusted", which is the safe direction to fail in. A DNS outage must never be able to
/// *widen* what the daemon believes, and a container that is down should stop being trusted rather
/// than keep a stale grant alive.
async fn resolve_hostname(hostname: &str) -> Vec<IpNetwork> {
    // Port 0: `lookup_host` wants a socket address, but only the address half is used.
    match tokio::net::lookup_host((hostname, 0u16)).await {
        Ok(addrs) => {
            let networks: Vec<IpNetwork> =
                addrs.map(|addr| IpNetwork::from(normalize_ip(addr.ip()))).collect();
            if networks.is_empty() {
                tracing::warn!(
                    "TRUSTED_PROXIES hostname {hostname:?} resolved to no addresses; it is not \
                     trusted until it does."
                );
            } else {
                tracing::debug!(
                    "TRUSTED_PROXIES hostname {hostname:?} resolved to {}",
                    networks.iter().map(|n| n.ip().to_string()).collect::<Vec<_>>().join(", ")
                );
            }
            networks
        }
        Err(e) => {
            tracing::warn!(
                "Could not resolve TRUSTED_PROXIES hostname {hostname:?}: {e}. It is not trusted \
                 until resolution succeeds."
            );
            Vec::new()
        }
    }
}

/// Parses a `TRUSTED_PROXIES` value into matchers, or reports every entry that is unusable.
///
/// Three spellings are accepted, tried in order: a CIDR range (`172.16.0.0/12`), a bare address
/// (`127.0.0.1`, promoted to a single-host network so nobody has to remember `/32`), and otherwise
/// a hostname (`traefik`) resolved at request time.
///
/// Anything else is a **hard error** rather than a dropped entry — see [`InvalidTrustedProxies`] for
/// why a trust boundary is the one setting in this module that must not degrade quietly. Every bad
/// entry is collected rather than the first, so an operator fixing a mistyped list needs one restart
/// and not one per typo.
///
/// The check is purely syntactic and does no I/O: a well-formed hostname is accepted here whether or
/// not it currently resolves, which is what keeps a DNS outage from becoming a refusal to boot.
pub fn parse_trusted_proxies(raw: &str) -> Result<Vec<ProxyMatcher>, Vec<InvalidProxyEntry>> {
    let mut matchers = Vec::new();
    let mut invalid = Vec::new();

    for entry in raw.split(',').map(str::trim).filter(|e| !e.is_empty()) {
        if let Ok(net) = entry.parse::<IpNetwork>() {
            matchers.push(ProxyMatcher::Network(net));
        } else if let Ok(addr) = entry.parse::<IpAddr>() {
            matchers.push(ProxyMatcher::Network(IpNetwork::from(addr)));
        } else {
            match hostname_rejection(entry) {
                None => matchers.push(ProxyMatcher::Hostname(entry.to_owned())),
                Some(reason) => {
                    invalid.push(InvalidProxyEntry { entry: entry.to_owned(), reason });
                }
            }
        }
    }

    if invalid.is_empty() { Ok(matchers) } else { Err(invalid) }
}

/// Why `entry` cannot be a DNS name, or `None` when it is shaped like one.
///
/// Returns the *reason* rather than a bool because the reason is the entire value of this check to
/// an operator: "not a valid hostname" sends them to the manual, "made only of digits and dots"
/// sends them to the typo.
///
/// Deliberately strict about the two shapes that are *nearly* addresses. An entry reaching this
/// point already failed to parse as an address and as a CIDR, and the ways that happens are a typo
/// and a hostname:
///
/// - Anything containing `/` or `:` is refused, since those characters appear only in prefix and
///   IPv6 syntax — so a near-miss CIDR like `10.0.0.0/99` surfaces as the configuration error it is
///   rather than a name that silently never matches.
/// - Anything made only of digits and dots is refused for the same reason: `10.0.0.256` is a
///   mistyped IPv4 literal, not a hostname, and treating it as one would hide the typo behind a
///   perfectly quiet non-match.
/// - The first and last characters must be alphanumeric. That is stricter than the RFC, which
///   permits a trailing `.` to mark a fully-qualified name, and the strictness is the point: a
///   trailing separator is far more often a stray comma-splice or a copy-paste artefact than a
///   deliberate root anchor, and `tokio::net::lookup_host` treats `proxy.` and `proxy` identically
///   anyway. This is byte-for-byte the rule `simply_hook_executor::config::is_hostname_like`
///   applies, so both services refuse exactly the same set.
fn hostname_rejection(entry: &str) -> Option<&'static str> {
    if entry.is_empty() {
        return Some("empty");
    }
    if entry.len() > 253 {
        return Some("longer than the 253-character limit on a DNS name");
    }
    if entry.contains('/') || entry.contains(':') {
        return Some(
            "contains '/' or ':', which appear only in CIDR and IPv6 syntax, so this is a \
             malformed address rather than a hostname",
        );
    }
    let bytes = entry.as_bytes();
    let edges_are_alphanumeric = bytes
        .first()
        .zip(bytes.last())
        .is_some_and(|(first, last)| first.is_ascii_alphanumeric() && last.is_ascii_alphanumeric());
    if !edges_are_alphanumeric {
        return Some("a hostname must begin and end with a letter or a digit");
    }
    if entry.chars().all(|c| c.is_ascii_digit() || c == '.') {
        return Some("made only of digits and dots, so this is a malformed IPv4 literal");
    }
    if !entry.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.' || c == '_') {
        return Some("contains characters that cannot appear in a DNS name");
    }
    None
}

/// Normalizes an IPv4-mapped IPv6 address (`::ffff:192.168.1.1`) down to its plain IPv4 form.
///
/// Dual-stack listeners and reverse proxies routinely surface IPv4 clients this way. Without this,
/// such a peer would fail to match an IPv4 CIDR in either `bound_ips` or `TRUSTED_PROXIES` — the
/// first causing a spurious `403`, the second silently downgrading a trusted proxy to an untrusted
/// one.
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(IpAddr::V6(v6)),
        v4 => v4,
    }
}

/// Reports whether `ip` falls inside any of the `trusted` networks.
fn is_trusted(ip: IpAddr, trusted: &[IpNetwork]) -> bool {
    trusted.iter().any(|net| net.contains(ip))
}

/// Determines the client address to authorize against `bound_ips`, and to record in the audit trail.
///
/// **The forwarding headers are only consulted when `peer` — the immediate TCP peer, which cannot
/// be forged — is itself inside `trusted`.** Any other client gets its TCP address used verbatim,
/// no matter what it claims in `X-Forwarded-For`. This is the whole point: `X-Forwarded-For` is a
/// plain request header, so honouring it from an arbitrary peer turns `bound_ips` from a network
/// restriction into a self-asserted one that any caller can satisfy by typing an allowed address
/// into a header.
///
/// When the peer *is* trusted, the header is walked **right to left, skipping addresses that are
/// themselves trusted proxies**, and the first remaining address is the client. Rightmost-first is
/// what makes the prefix unforgeable: each proxy appends the address it actually saw, so entries to
/// the left of the last trusted hop are hearsay supplied by the client. Skipping trusted entries is
/// what makes a *chain* of proxies work — with `client → P1 → P2 → us`, the header reads
/// `client, P1` and the rightmost entry is `P1`, a proxy rather than the client.
///
/// `trusted` is the resolved snapshot from [`TrustedProxies::resolved`], so hostname-configured and
/// CIDR-configured hops are indistinguishable here and both are skipped.
///
/// `X-Real-IP` (single-valued, no chain) is consulted only when `X-Forwarded-For` is absent or
/// yields nothing, under exactly the same trust precondition.
///
/// Falls back to `peer` whenever the headers are absent, unparseable, or contain nothing but
/// trusted proxies — never to an unvalidated claim.
///
/// This function is byte-for-byte the same algorithm as `simply_hook_executor`'s; see
/// `scripts/verify_convergence.sh`, which diffs the two mechanically so drift is caught by CI
/// rather than by the next audit.
pub fn resolve_client_ip(
    peer: IpAddr,
    headers: &axum::http::HeaderMap,
    trusted: &[IpNetwork],
) -> IpAddr {
    let peer = normalize_ip(peer);

    // The load-bearing check. Everything below is unreachable for an untrusted caller.
    if !is_trusted(peer, trusted) {
        return peer;
    }

    if let Some(forwarded) = headers.get("X-Forwarded-For").and_then(|h| h.to_str().ok()) {
        let client = forwarded
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .filter_map(|s| s.parse::<IpAddr>().ok())
            .map(normalize_ip)
            .rev()
            .find(|ip| !is_trusted(*ip, trusted));

        if let Some(client) = client {
            return client;
        }
        // A header listing only trusted proxies (or nothing parseable) says nothing about the
        // client; fall through rather than inventing one.
    }

    if let Some(real_ip) = headers
        .get("X-Real-IP")
        .and_then(|h| h.to_str().ok())
        .map(str::trim)
        .and_then(|s| s.parse::<IpAddr>().ok())
    {
        return normalize_ip(real_ip);
    }

    peer
}

#[cfg(test)]
mod master_key_tests {
    use super::*;

    /// What the service generates for itself must satisfy the rule it imposes on operators.
    ///
    /// The important assertion in this file. If `generate_random_key` and `MASTER_KEY_HEX_LEN` ever
    /// drift apart, a deployment that let the service pick its own key would still boot while an
    /// operator supplying an identically-shaped one would be refused — a rule the service does not
    /// follow itself, and the kind of inconsistency that gets "fixed" by deleting the check.
    #[test]
    fn a_self_generated_key_passes_the_operator_rule() {
        for _ in 0..64 {
            let generated = crate::api::generate_random_key();
            assert_eq!(generated.len(), MASTER_KEY_HEX_LEN);
            assert!(validate_initial_master_key(&generated).is_ok());
        }
    }

    #[test]
    fn exactly_64_hex_characters_are_accepted_in_either_case() {
        assert!(validate_initial_master_key(&"a".repeat(64)).is_ok());
        assert!(validate_initial_master_key(&"F".repeat(64)).is_ok());
        assert!(validate_initial_master_key(&"0123456789abcdefABCDEF".repeat(3)[..64]).is_ok());
    }

    /// Both failure directions, and the boundary on each side — 63 and 65 are the off-by-ones a
    /// length check gets wrong.
    #[test]
    fn wrong_length_or_non_hex_is_refused() {
        for bad in [
            "".to_owned(),
            "a".repeat(63),
            "a".repeat(65),
            "changeme".to_owned(),
            "e2e_master_secret_key_for_testing_123456789".to_owned(),
            // 64 characters, but `g` is not a hex digit — the case a bare length check would pass.
            format!("{}g", "a".repeat(63)),
        ] {
            assert!(
                validate_initial_master_key(&bad).is_err(),
                "{bad:?} must be refused"
            );
        }
    }

    /// The refusal has to tell an operator what to do; a bare "invalid" would send them guessing.
    #[test]
    fn the_refusal_names_the_requirement_and_the_remedy() {
        let text = validate_initial_master_key("changeme").unwrap_err().to_string();
        assert!(text.contains("64 hexadecimal characters"), "{text}");
        assert!(text.contains("openssl rand -hex 32"), "{text}");
        assert!(text.contains("Refusing to start"), "{text}");
        assert!(text.contains("Got 8 character(s)"), "the actual length is reported: {text}");
        assert!(
            text.contains("non-hexadecimal"),
            "a non-hex value says so, rather than only complaining about length: {text}"
        );

        // A right-length, wrong-alphabet key must not be told it is the wrong length.
        let hex_only = validate_initial_master_key(&"a".repeat(63)).unwrap_err().to_string();
        assert!(!hex_only.contains("non-hexadecimal"), "{hex_only}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers(pairs: &[(&str, &str)]) -> axum::http::HeaderMap {
        let mut map = axum::http::HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                axum::http::HeaderName::from_bytes(name.as_bytes()).expect("valid header name"),
                axum::http::HeaderValue::from_str(value).expect("valid header value"),
            );
        }
        map
    }

    fn proxies(entries: &str) -> TrustedProxies {
        TrustedProxies::new(parse(entries))
    }

    /// Parses entries a fixture asserts are all valid.
    fn parse(entries: &str) -> Vec<ProxyMatcher> {
        parse_trusted_proxies(entries).expect("fixture entries must all be usable")
    }

    /// The entries a malformed configuration reports, in order.
    fn rejections(entries: &str) -> Vec<InvalidProxyEntry> {
        parse_trusted_proxies(entries).expect_err("these entries must be refused")
    }

    /// The literal networks in a parsed configuration, for assertions about parsing itself.
    fn only_networks(entries: &str) -> Vec<IpNetwork> {
        parse(entries)
            .into_iter()
            .filter_map(|m| match m {
                ProxyMatcher::Network(n) => Some(n),
                ProxyMatcher::Hostname(_) => None,
            })
            .collect()
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().expect("test address literal parses")
    }

    #[test]
    fn bare_addresses_and_cidrs_both_parse() {
        let networks = only_networks("10.0.0.0/8, 192.168.1.5 ,, ::1");
        assert_eq!(networks.len(), 3, "empty entries are skipped, not counted");
        assert!(networks[1].contains(ip("192.168.1.5")), "a bare address becomes a /32");
        assert!(!networks[1].contains(ip("192.168.1.6")), "...and covers only itself");
    }

    #[test]
    fn entries_are_classified_as_network_or_hostname_and_garbage_is_rejected() {
        assert_eq!(
            parse("10.0.0.0/8, traefik, proxy.internal"),
            vec![
                ProxyMatcher::Network("10.0.0.0/8".parse().expect("valid CIDR")),
                ProxyMatcher::Hostname("traefik".to_owned()),
                ProxyMatcher::Hostname("proxy.internal".to_owned()),
            ],
            "all three are usable spellings"
        );

        // A near-miss CIDR must NOT be quietly demoted to a hostname: the `/` makes it impossible
        // as a DNS name, so it surfaces as a configuration error instead of a silent non-match.
        let refused = rejections("10.0.0.0/99, 10.0.0.0/8");
        assert_eq!(refused.len(), 1, "the well-formed entry alongside it is not an error");
        assert_eq!(refused[0].entry, "10.0.0.0/99");

        // Nor may a mistyped IPv4 literal become a hostname — the same reasoning, and the case the
        // peer service already rejected while this one did not.
        for typo in ["999.1.1.1", "10.0.0.256", "1.2.3.4.5", "10..0.1"] {
            let refused = rejections(typo);
            assert_eq!(refused.len(), 1, "{typo:?} must be reported exactly once");
            assert_eq!(refused[0].entry, typo);
        }

        // Other impossible shapes, including the two the strict edge rule adds: a trailing `.` and
        // a leading `_`, both of which the older predicate accepted as names.
        let refused = rejections("-leading, trailing-, .dotted, has space, trailing.dot., _under");
        assert_eq!(
            refused.iter().map(|r| r.entry.as_str()).collect::<Vec<_>>(),
            ["-leading", "trailing-", ".dotted", "has space", "trailing.dot.", "_under"],
            "every bad entry is collected, so one restart surfaces all of the typos"
        );
    }

    /// A rejection has to say *which* mistake was made, because that is the whole difference between
    /// an operator finding a typo and an operator reading the manual.
    #[test]
    fn a_rejected_entry_names_the_mistake_rather_than_the_rule() {
        let cases = [
            ("10.0.0.0/8x", "CIDR and IPv6 syntax"),
            ("10.0.0.256", "malformed IPv4 literal"),
            ("proxy.internal.", "begin and end with a letter or a digit"),
            ("pro xy", "cannot appear in a DNS name"),
        ];
        for (entry, expected) in cases {
            let refused = rejections(entry);
            assert!(
                refused[0].reason.contains(expected),
                "{entry:?} was refused for {:?}, which does not mention {expected:?}",
                refused[0].reason
            );
        }

        // A 254-character label is over the DNS limit and must say so rather than falling through
        // to the character check, which it would also pass.
        let too_long = "a".repeat(254);
        assert!(rejections(&too_long)[0].reason.contains("253-character"));
    }

    /// The strict edge rule is the one behaviour shared byte-for-byte with the peer service, so it
    /// gets its own test rather than being asserted only through `parse_trusted_proxies`.
    #[test]
    fn hostname_syntax_matches_the_peer_services_rule() {
        for name in ["traefik", "proxy.internal", "a", "x1-y2.example.com", "under_score.local"] {
            assert!(hostname_rejection(name).is_none(), "{name:?} must be accepted");
        }
        for name in ["proxy.", "-proxy", "proxy-", ".proxy", "_proxy", "proxy_", "10.0.0.0/8"] {
            assert!(hostname_rejection(name).is_some(), "{name:?} must be refused");
        }
    }

    #[test]
    fn hostname_entries_contribute_no_literal_networks() {
        assert!(only_networks("traefik, proxy.internal").is_empty());
        assert_eq!(only_networks("traefik, 172.16.0.0/12").len(), 1);
    }

    #[tokio::test]
    async fn resolution_is_a_no_op_when_only_addresses_are_configured() {
        let trusted = proxies("127.0.0.1,10.0.0.0/8");
        let resolved = trusted.resolved().await;
        assert_eq!(resolved.len(), 2);
        assert!(is_trusted(ip("10.1.2.3"), &resolved));
        // Same allocation each time: the no-hostname path must not rebuild or lock anything.
        assert!(Arc::ptr_eq(&resolved, &trusted.resolved().await));
    }

    /// `localhost` resolves on every platform this runs on, so it exercises the real DNS path —
    /// cache miss, resolution, and a second call served from the cache.
    #[tokio::test]
    async fn a_hostname_entry_is_resolved_and_matched() {
        let trusted = proxies("localhost");
        let resolved = trusted.resolved().await;

        assert!(
            is_trusted(ip("127.0.0.1"), &resolved) || is_trusted(ip("::1"), &resolved),
            "localhost should resolve to a loopback address: {resolved:?}"
        );
        // Served from cache the second time: the same allocation, no second lookup.
        assert!(Arc::ptr_eq(&resolved, &trusted.resolved().await));

        assert!(!is_trusted(ip("203.0.113.9"), &resolved), "an unrelated address must not match");
    }

    /// Docker/Traefik shape: a container name alongside the bridge network CIDR. Either may match.
    #[tokio::test]
    async fn docker_style_configuration_matches_by_cidr_or_by_name() {
        let trusted = proxies("172.16.0.0/12, localhost").resolved().await;

        assert!(is_trusted(ip("172.17.0.5"), &trusted), "docker bridge CIDR matches");
        assert!(is_trusted(ip("127.0.0.1"), &trusted), "the named service matches");
        assert!(!is_trusted(ip("192.0.2.7"), &trusted), "anything else does not");
    }

    /// Failing closed matters: a DNS outage must never be able to *widen* what is trusted, and it
    /// must not take the healthy entries down with it.
    #[tokio::test]
    async fn an_unresolvable_hostname_trusts_nobody_but_disables_only_itself() {
        let trusted = proxies("this-host-does-not-exist.invalid, 10.0.0.0/8");
        let resolved = trusted.resolved().await;

        assert!(is_trusted(ip("10.1.2.3"), &resolved), "the literal entry still applies");
        assert_eq!(resolved.len(), 1, "the unresolvable name contributes nothing: {resolved:?}");
        assert!(!is_trusted(ip("127.0.0.1"), &resolved));
    }

    /// Negative caching: a name that cannot resolve must not be looked up again on the very next
    /// request. Without this, traffic arriving while a hostname is down becomes one DNS query per
    /// request — a resolution storm this service would be amplifying on someone else's behalf.
    #[tokio::test]
    async fn a_failed_resolution_is_negatively_cached_rather_than_retried_per_request() {
        let trusted = proxies("this-host-does-not-exist.invalid")
            .with_ttls(Duration::from_secs(30), Duration::from_secs(30));

        let first = trusted.resolved().await;
        // Within the negative TTL every further call is served from cache — same allocation, so no
        // second lookup happened.
        assert!(Arc::ptr_eq(&first, &trusted.resolved().await));
        assert!(Arc::ptr_eq(&first, &trusted.resolved().await));
        assert!(first.is_empty());
    }

    /// ...but the negative entry does expire, so a name that starts working is picked up without a
    /// restart. That is the property that makes container addresses usable at all.
    #[tokio::test]
    async fn a_negative_entry_expires_so_recovery_needs_no_restart() {
        let trusted = proxies("this-host-does-not-exist.invalid")
            .with_ttls(Duration::from_secs(30), Duration::ZERO);

        let first = trusted.resolved().await;
        assert!(!Arc::ptr_eq(&first, &trusted.resolved().await), "a zero negative TTL re-resolves");
    }

    /// ...and so does a *successful* one, which is the direction that actually carries risk.
    ///
    /// [`POSITIVE_TTL`] is the window during which a recreated container keeps its **old** address
    /// trusted — an address the orchestrator may already have handed to something else. An entry
    /// that never lapsed would be a standing grant to whoever inherited it, clearable only by
    /// restarting the service. `AGENT.MD` accepts 30s precisely *because* it expires.
    ///
    /// Both halves are asserted, because each alone is too weak:
    ///
    /// - [`HostnameState::is_fresh`] is checked directly against a synthesized `attempted_at`, so
    ///   the predicate is pinned with no dependence on wall-clock timing. The third assertion is the
    ///   load-bearing one: a *resolved* entry must be governed by the positive TTL even when the
    ///   negative TTL is enormous, which is what stops the two windows from being silently swapped.
    /// - `resolved()` is then driven end to end, since `is_fresh` being correct buys nothing if the
    ///   cache never consults it.
    ///
    /// The sleep is four times the TTL rather than a hair over it: this suite runs in parallel, and
    /// a margin measured in whole multiples is what keeps the test from failing on a loaded machine.
    #[tokio::test]
    async fn a_successful_resolution_is_re_queried_once_its_positive_ttl_expires() {
        const POSITIVE: Duration = Duration::from_millis(50);
        const NEGATIVE: Duration = Duration::from_secs(5);

        let fresh = HostnameState {
            addresses: vec![IpNetwork::from(ip("127.0.0.1"))],
            attempted_at: Instant::now(),
            resolved: true,
        };
        assert!(fresh.is_fresh(POSITIVE, NEGATIVE), "an attempt made just now is reusable");

        let lapsed = HostnameState {
            attempted_at: Instant::now()
                .checked_sub(POSITIVE)
                .expect("the monotonic clock is older than the TTL"),
            ..fresh.clone()
        };
        assert!(!lapsed.is_fresh(POSITIVE, NEGATIVE), "an attempt one full TTL old is stale");
        assert!(
            !lapsed.is_fresh(POSITIVE, Duration::from_secs(3600)),
            "a resolved entry must expire on the positive TTL, never on the negative one"
        );

        // End to end: the cache must actually act on that.
        let trusted = proxies("localhost").with_ttls(POSITIVE, NEGATIVE);
        let first = trusted.resolved().await;
        assert!(
            !first.is_empty(),
            "localhost must resolve, or this test would be exercising the negative path instead"
        );

        tokio::time::sleep(POSITIVE * 4).await;

        // A new allocation means `refresh_locked` ran: `resolved()` hands back the *same* `Arc`
        // whenever every entry is still fresh, so pointer inequality is the re-query.
        assert!(
            !Arc::ptr_eq(&first, &trusted.resolved().await),
            "an expired positive entry must be looked up again rather than trusted indefinitely"
        );
    }

    /// A healthy name must not be dragged onto the short negative interval by an unhealthy one
    /// sharing the configuration — the reason attempt state is tracked per hostname.
    #[tokio::test]
    async fn a_healthy_hostname_keeps_its_positive_ttl_alongside_a_failing_one() {
        let trusted = proxies("localhost, this-host-does-not-exist.invalid")
            .with_ttls(Duration::from_secs(30), Duration::ZERO);

        let resolved = trusted.resolved().await;
        assert!(
            is_trusted(ip("127.0.0.1"), &resolved) || is_trusted(ip("::1"), &resolved),
            "the healthy entry resolved"
        );
        // The failing entry is re-attempted (zero negative TTL), and `localhost` is still trusted
        // afterwards — it was reused from cache rather than being re-resolved and possibly lost.
        let again = trusted.resolved().await;
        assert!(is_trusted(ip("127.0.0.1"), &again) || is_trusted(ip("::1"), &again));
    }

    /// Boot priming reports exactly which entries failed, so the caller can log a specific name
    /// rather than a generic "something is wrong".
    #[tokio::test]
    async fn priming_reports_only_the_entries_that_failed() {
        assert!(proxies("10.0.0.0/8").prime().await.is_empty(), "no hostnames, nothing to report");
        assert!(proxies("localhost").prime().await.is_empty(), "a resolvable name is not reported");

        let failed = proxies("localhost, this-host-does-not-exist.invalid, 10.0.0.0/8")
            .prime()
            .await;
        assert_eq!(failed, vec!["this-host-does-not-exist.invalid".to_owned()]);
    }

    /// The service must come up regardless — priming is diagnostics, never a gate.
    #[tokio::test]
    async fn priming_a_wholly_unresolvable_configuration_still_leaves_a_usable_set() {
        let trusted = proxies("this-host-does-not-exist.invalid, 192.0.2.0/24");
        let failed = trusted.prime().await;
        assert_eq!(failed.len(), 1);

        let resolved = trusted.resolved().await;
        assert!(is_trusted(ip("192.0.2.7"), &resolved), "the literal entry serves normally");
    }

    /// The core anti-spoofing property: with no trusted proxies configured, the forwarding headers
    /// are inert no matter what they say.
    #[test]
    fn forwarding_headers_are_ignored_when_nothing_is_trusted() {
        let hdrs = headers(&[("X-Forwarded-For", "8.8.8.8"), ("X-Real-IP", "8.8.8.8")]);
        assert_eq!(resolve_client_ip(ip("203.0.113.9"), &hdrs, &[]), ip("203.0.113.9"));
    }

    /// The same, but from a peer that is merely *not on the list* while others are — the check is
    /// per-peer, not "is anything configured at all".
    #[test]
    fn an_untrusted_peer_cannot_spoof_even_when_proxies_are_configured() {
        let trusted = only_networks("10.0.0.0/8");
        let hdrs = headers(&[("X-Forwarded-For", "10.0.0.1"), ("X-Real-IP", "10.0.0.1")]);

        // A hostile client claiming to be the trusted proxy itself still gets its own address used.
        assert_eq!(resolve_client_ip(ip("203.0.113.9"), &hdrs, &trusted), ip("203.0.113.9"));

        // ...including when it claims an address inside a key's bound CIDR.
        let hdrs = headers(&[("X-Forwarded-For", "192.168.1.1")]);
        assert_eq!(resolve_client_ip(ip("203.0.113.9"), &hdrs, &trusted), ip("203.0.113.9"));
    }

    #[test]
    fn a_trusted_peer_may_declare_the_client() {
        let trusted = only_networks("10.0.0.0/8");
        let hdrs = headers(&[("X-Forwarded-For", "203.0.113.50")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted), ip("203.0.113.50"));
    }

    /// Rightmost-first is what makes a client-supplied prefix unforgeable: a client that sends
    /// `X-Forwarded-For: 8.8.8.8` gets its real address appended by the proxy, and only that
    /// appended entry is honoured.
    #[test]
    fn a_client_supplied_prefix_is_ignored_in_favour_of_the_proxy_appended_entry() {
        let trusted = only_networks("10.0.0.0/8");
        let hdrs = headers(&[("X-Forwarded-For", "8.8.8.8, 203.0.113.50")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted), ip("203.0.113.50"));
    }

    /// A chain of trusted proxies: the rightmost entries are proxies, and the first non-proxy
    /// address walking leftwards is the real client.
    #[test]
    fn trusted_hops_are_skipped_walking_right_to_left() {
        let trusted = only_networks("10.0.0.0/8,172.16.0.0/12");
        let hdrs = headers(&[("X-Forwarded-For", "203.0.113.50, 172.16.0.9, 10.0.0.2")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted), ip("203.0.113.50"));

        // A forged address to the left of the real client is still never reached.
        let hdrs = headers(&[("X-Forwarded-For", "8.8.8.8, 203.0.113.50, 10.0.0.2")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted), ip("203.0.113.50"));
    }

    /// The convergence fix: a hop identified by *hostname* must be skipped exactly like a CIDR one.
    /// Resolving the whole set up front is what makes this possible — the previous lazy design
    /// consulted only literal networks during the walk and so reported the inner proxy as the
    /// client in a chained container topology.
    #[tokio::test]
    async fn a_hostname_identified_hop_is_skipped_like_a_cidr_hop() {
        // `localhost` stands in for a container name; it resolves to the loopback address, which
        // therefore appears in the chain as a trusted hop that must be peeled.
        let trusted = proxies("localhost, 172.16.0.0/12").resolved().await;

        let hdrs = headers(&[("X-Forwarded-For", "203.0.113.50, 127.0.0.1")]);
        assert_eq!(
            resolve_client_ip(ip("172.16.0.9"), &hdrs, &trusted),
            ip("203.0.113.50"),
            "the name-resolved hop must be peeled, not reported as the client"
        );

        // Both orders of the chain behave the same way.
        let hdrs = headers(&[("X-Forwarded-For", "203.0.113.50, 172.16.0.9, 127.0.0.1")]);
        assert_eq!(resolve_client_ip(ip("127.0.0.1"), &hdrs, &trusted), ip("203.0.113.50"));
    }

    /// A trusted peer identified purely by hostname must still have its forwarding header honoured.
    #[tokio::test]
    async fn a_hostname_identified_proxy_may_declare_the_client() {
        let trusted = proxies("localhost").resolved().await;
        let hdrs = headers(&[("X-Forwarded-For", "203.0.113.50")]);
        assert_eq!(resolve_client_ip(ip("127.0.0.1"), &hdrs, &trusted), ip("203.0.113.50"));

        // ...and a peer that does not resolve to that name still cannot.
        assert_eq!(resolve_client_ip(ip("203.0.113.9"), &hdrs, &trusted), ip("203.0.113.9"));
    }

    /// A header naming nothing but proxies carries no information about the client, so the peer is
    /// used rather than an arbitrary pick from the chain.
    #[test]
    fn an_all_proxy_chain_falls_back_to_the_peer() {
        let trusted = only_networks("10.0.0.0/8");
        let hdrs = headers(&[("X-Forwarded-For", "10.0.0.2, 10.0.0.3")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted), ip("10.0.0.1"));
    }

    #[test]
    fn garbage_headers_fall_back_to_the_peer_rather_than_failing_open() {
        let trusted = only_networks("10.0.0.0/8");
        for value in ["", "   ", "not-an-ip", ",,,", "8.8.8.8.8"] {
            let hdrs = headers(&[("X-Forwarded-For", value)]);
            assert_eq!(
                resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted),
                ip("10.0.0.1"),
                "unparseable X-Forwarded-For {value:?} must fall back to the peer"
            );
        }
    }

    #[test]
    fn real_ip_is_honoured_only_from_a_trusted_peer_and_only_without_xff() {
        let trusted = only_networks("10.0.0.0/8");

        let hdrs = headers(&[("X-Real-IP", "203.0.113.50")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted), ip("203.0.113.50"));
        assert_eq!(resolve_client_ip(ip("203.0.113.9"), &hdrs, &trusted), ip("203.0.113.9"));

        // X-Forwarded-For wins when both are present, so a proxy that sets both cannot be played
        // off against itself.
        let hdrs = headers(&[("X-Forwarded-For", "198.51.100.7"), ("X-Real-IP", "203.0.113.50")]);
        assert_eq!(resolve_client_ip(ip("10.0.0.1"), &hdrs, &trusted), ip("198.51.100.7"));
    }

    #[test]
    fn bind_addr_defaults_to_all_interfaces_on_3000() {
        assert_eq!(parse_bind_addr(None, None).to_string(), "0.0.0.0:3000");
        // Empty strings are treated as "unset", so an unset variable in a unit or compose file
        // behaves the same as an absent one.
        assert_eq!(parse_bind_addr(Some(""), Some("  ")).to_string(), "0.0.0.0:3000");
    }

    #[test]
    fn bind_addr_honors_host_and_port_overrides() {
        assert_eq!(parse_bind_addr(Some("127.0.0.1"), Some("8080")).to_string(), "127.0.0.1:8080");
        assert_eq!(
            parse_bind_addr(Some(" 127.0.0.1 "), Some(" 8080 ")).to_string(),
            "127.0.0.1:8080"
        );
        // Port 0 is passed through so the OS can assign an ephemeral port.
        assert_eq!(parse_bind_addr(Some("127.0.0.1"), Some("0")).to_string(), "127.0.0.1:0");
        // IPv6 literals bind too.
        let addr = parse_bind_addr(Some("::1"), Some("9000"));
        assert!(addr.is_ipv6());
        assert_eq!(addr.port(), 9000);
    }

    #[test]
    fn bind_addr_falls_back_on_malformed_values() {
        // A hostname is not a literal IP and is rejected rather than resolved — several addresses
        // with no principled way to choose, and binding the wrong interface is a security problem.
        assert_eq!(parse_bind_addr(Some("localhost"), Some("8080")).to_string(), "0.0.0.0:8080");
        assert_eq!(
            parse_bind_addr(Some("127.0.0.1"), Some("not-a-port")).to_string(),
            "127.0.0.1:3000"
        );
        assert_eq!(parse_bind_addr(Some("127.0.0.1"), Some("70000")).to_string(), "127.0.0.1:3000");
        assert_eq!(parse_bind_addr(Some("999.1.1.1"), Some("-1")).to_string(), "0.0.0.0:3000");
    }

    /// An IPv4-mapped peer must still match an IPv4 `TRUSTED_PROXIES` entry — otherwise a
    /// dual-stack listener silently demotes a configured proxy to untrusted.
    #[test]
    fn ipv4_mapped_addresses_are_normalized_on_both_sides() {
        let trusted = only_networks("10.0.0.0/8");
        let hdrs = headers(&[("X-Forwarded-For", "::ffff:203.0.113.50")]);
        assert_eq!(resolve_client_ip(ip("::ffff:10.0.0.1"), &hdrs, &trusted), ip("203.0.113.50"));
    }

    /// Serializes the tests that read [`TRUSTED_PROXIES_ENV`].
    ///
    /// The environment is process-global and this suite runs in parallel, so two tests setting the
    /// same variable would interleave. Poisoning is recovered from rather than propagated: one
    /// failing test must not cascade into "the other four also failed", which hides the real cause.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Runs `body` with [`TRUSTED_PROXIES_ENV`] set to `value` (or unset when `None`), restoring
    /// whatever was there before.
    fn with_trusted_proxies_env<T>(value: Option<&str>, body: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let previous = std::env::var(TRUSTED_PROXIES_ENV).ok();

        // SAFETY: `ENV_LOCK` is held for the whole body, and every test in this module that touches
        // this variable goes through this helper, so no other thread reads or writes it meanwhile.
        // The restore below runs on the success path; a panicking `body` aborts the test process's
        // view of this variable only, and the next test sets it again before reading.
        unsafe {
            match value {
                Some(raw) => std::env::set_var(TRUSTED_PROXIES_ENV, raw),
                None => std::env::remove_var(TRUSTED_PROXIES_ENV),
            }
        }

        let outcome = body();

        // SAFETY: as above — still under `ENV_LOCK`.
        unsafe {
            match previous {
                Some(raw) => std::env::set_var(TRUSTED_PROXIES_ENV, raw),
                None => std::env::remove_var(TRUSTED_PROXIES_ENV),
            }
        }
        outcome
    }

    /// A syntactically impossible entry must stop the daemon **before** anything else happens.
    ///
    /// This is the abort half of the split that gives this module its shape. `from_env` is the exact
    /// call `main` makes, and in `main` it sits ahead of the database connection and far ahead of
    /// `prime_with_grace`, so an `Err` here *is* the refusal to start — there is no later stage that
    /// could decide to carry on with a partial list.
    ///
    /// Every bad entry must come back, not just the first: an operator who mistyped three lines
    /// should need one restart to find all three.
    #[test]
    fn a_malformed_entry_refuses_to_build_the_trust_boundary_at_all() {
        let err = with_trusted_proxies_env(Some("10.0.0.0/99, 127.0.0.1, proxy., !nope"), || {
            TrustedProxies::from_env().expect_err("a malformed entry must abort")
        });

        assert_eq!(
            err.entries.iter().map(|e| e.entry.as_str()).collect::<Vec<_>>(),
            ["10.0.0.0/99", "proxy.", "!nope"],
            "all three bad entries are reported, and the good one is not"
        );

        // The `Display` an operator actually sees has to carry the entries and their reasons; an
        // error that only says "invalid configuration" would send them back to the logs.
        let rendered = err.to_string();
        assert!(rendered.contains("10.0.0.0/99"), "the rendered error names the entry: {rendered}");
        assert!(rendered.contains("CIDR"), "...and why it was refused: {rendered}");
    }

    /// ...whereas a name that is merely *unresolvable* is not a configuration error at all.
    ///
    /// This is the other half, and the one that has to keep working: DNS is a runtime dependency
    /// that goes away and comes back, and a daemon that refuses to boot while it is away turns a
    /// brief resolver outage into a crash loop — strictly worse than serving with one proxy entry
    /// disabled. `.invalid` is reserved by RFC 2606 precisely so it can never resolve.
    ///
    /// `prime` is what `prime_with_grace` calls, so driving it directly asserts the grace path's
    /// substance — the name is *kept*, reported as failing, and left for the next retry — without
    /// waiting out the 60-second timer.
    #[tokio::test]
    async fn an_unresolvable_hostname_is_kept_and_left_to_the_grace_period() {
        let trusted =
            with_trusted_proxies_env(Some("127.0.0.1, definitely-not-a-real-host.invalid"), || {
                TrustedProxies::from_env().expect("valid syntax must build even when DNS fails")
            });

        assert_eq!(trusted.matchers().len(), 2, "the unresolvable name is kept as a matcher");

        let failed = trusted.prime().await;
        assert_eq!(
            failed,
            vec!["definitely-not-a-real-host.invalid".to_owned()],
            "it is reported as failing, which is what the grace-period retry acts on"
        );

        // Failing to resolve must not disturb the entries that did: the literal is still trusted,
        // and the dead name simply contributes no addresses.
        let resolved = trusted.resolved().await;
        assert!(is_trusted(ip("127.0.0.1"), &resolved), "the literal entry is unaffected");
        assert_eq!(resolved.len(), 1, "the dead name contributes nothing rather than everything");
    }

    /// An unset variable is the zero-configuration case, not a malformed one.
    #[test]
    fn an_unset_variable_trusts_nothing_without_complaining() {
        let trusted = with_trusted_proxies_env(None, || {
            TrustedProxies::from_env().expect("unset is not an error")
        });
        assert!(trusted.is_empty(), "unset means trust nothing");
    }

    // ── Database pool tuning ────────────────────────────────────────────

    /// Runs `body` with environment variable `name` set to `value` (or unset when `None`),
    /// restoring whatever was there before. Unlike [`with_trusted_proxies_env`], this takes the
    /// variable name as a parameter rather than being pinned to one — every test below uses its own
    /// name (`CONFIG_TEST_*`, never a real `DATABASE_*`/`WEBHOOK_*` constant), so no `ENV_LOCK`-style
    /// mutex is needed: two tests using two different names cannot race on either.
    fn with_env<T>(name: &str, value: Option<&str>, body: impl FnOnce() -> T) -> T {
        let previous = std::env::var(name).ok();
        // SAFETY: `name` is a `CONFIG_TEST_*` name unique to the calling test, never a real
        // production variable and never shared with another test, so no other thread reads or
        // writes it while this body runs.
        unsafe {
            match value {
                Some(raw) => std::env::set_var(name, raw),
                None => std::env::remove_var(name),
            }
        }
        let outcome = body();
        unsafe {
            match previous {
                Some(raw) => std::env::set_var(name, raw),
                None => std::env::remove_var(name),
            }
        }
        outcome
    }

    /// [`numeric_env`] itself is untested despite backing seven public settings (`WEBHOOK_WORKERS`,
    /// `MAX_BODY_SIZE_MIB`, and now the four `DATABASE_*` pool settings) — this is the first direct
    /// coverage of the shared parser all of them go through, not only the new callers.
    #[test]
    fn numeric_env_parses_falls_back_and_recovers_from_garbage() {
        with_env("CONFIG_TEST_NUMERIC_VALID", Some("42"), || {
            assert_eq!(numeric_env::<u32>("CONFIG_TEST_NUMERIC_VALID", 7), 42);
        });
        with_env("CONFIG_TEST_NUMERIC_UNSET", None, || {
            assert_eq!(numeric_env::<u32>("CONFIG_TEST_NUMERIC_UNSET", 7), 7, "missing falls back to the default");
        });
        with_env("CONFIG_TEST_NUMERIC_GARBAGE", Some("not-a-number"), || {
            assert_eq!(numeric_env::<u32>("CONFIG_TEST_NUMERIC_GARBAGE", 7), 7, "unparseable falls back rather than panicking");
        });
        with_env("CONFIG_TEST_NUMERIC_WHITESPACE", Some("  15  "), || {
            assert_eq!(numeric_env::<u32>("CONFIG_TEST_NUMERIC_WHITESPACE", 7), 15, "surrounding whitespace is trimmed");
        });
    }

    /// `DATABASE_MAX_CONNECTIONS=0` must not reach `sqlx::Pool`, which panics on it.
    #[test]
    fn pool_max_connections_is_clamped_to_at_least_one() {
        assert_eq!(clamp_pool_max(0), 1);
        assert_eq!(clamp_pool_max(1), 1);
        assert_eq!(clamp_pool_max(50), 50, "an ordinary value passes through unchanged");
    }

    /// `DATABASE_MIN_CONNECTIONS` greater than the configured max must not silently be ignored by
    /// sqlx (which accepts the pair and simply never reaches the requested floor) — it is clamped
    /// down to the max here instead, where the effective value is visible.
    #[test]
    fn pool_min_connections_is_clamped_to_the_configured_max() {
        assert_eq!(clamp_pool_min(10, 50), 10, "a min below max passes through unchanged");
        assert_eq!(clamp_pool_min(100, 50), 50, "a min above max is pulled down to it");
        assert_eq!(clamp_pool_min(50, 50), 50, "min == max is not treated as a violation");
    }

    /// The file-backed SQLite tier's ceiling composes [`clamp_pool_max`]'s floor of 1 with its own
    /// hard ceiling of [`SQLITE_FILE_MAX_CONNECTIONS_CEILING`] — an operator can request less than
    /// the PostgreSQL/MySQL tier's default, but never more than this tier allows.
    #[test]
    fn sqlite_file_max_is_clamped_to_one_and_ceilinged_at_ten() {
        assert_eq!(clamp_sqlite_file_max(0), 1, "the same zero-floor as the shared pool clamp");
        assert_eq!(clamp_sqlite_file_max(5), 5, "an ordinary value under the ceiling passes through");
        assert_eq!(
            clamp_sqlite_file_max(SQLITE_FILE_MAX_CONNECTIONS_CEILING),
            SQLITE_FILE_MAX_CONNECTIONS_CEILING,
            "exactly the ceiling is not itself a violation"
        );
        assert_eq!(
            clamp_sqlite_file_max(1_000),
            SQLITE_FILE_MAX_CONNECTIONS_CEILING,
            "a request far above the PostgreSQL/MySQL tier's own default must still be capped for \
             file-backed SQLite"
        );
    }

    /// `DATABASE_ACQUIRE_TIMEOUT_SECS=0` is indistinguishable from "never wait" to sqlx, which
    /// would turn ordinary pool contention into a guaranteed failure on any request that lost the
    /// race for a connection.
    #[test]
    fn acquire_timeout_is_clamped_to_at_least_one_second() {
        assert_eq!(clamp_acquire_timeout_secs(0), 1);
        assert_eq!(clamp_acquire_timeout_secs(1), 1);
        assert_eq!(clamp_acquire_timeout_secs(10), 10, "an ordinary value passes through unchanged");
    }

    /// The four `DATABASE_*_ENV` constants are exactly the names `AGENT_NOTES.MD` and `db.rs`'s
    /// module header document, and exactly the names `scripts/test_e2e.sh` sets when it boots a
    /// throwaway instance to prove these are read without aborting startup. A rename here that is
    /// not mirrored in either of those two places would desynchronise silently — this pins the
    /// three-way agreement's vault-side half.
    #[test]
    fn env_var_names_match_what_is_documented() {
        assert_eq!(DATABASE_MAX_CONNECTIONS_ENV, "DATABASE_MAX_CONNECTIONS");
        assert_eq!(DATABASE_MIN_CONNECTIONS_ENV, "DATABASE_MIN_CONNECTIONS");
        assert_eq!(DATABASE_IDLE_TIMEOUT_ENV, "DATABASE_IDLE_TIMEOUT_SECS");
        assert_eq!(DATABASE_ACQUIRE_TIMEOUT_ENV, "DATABASE_ACQUIRE_TIMEOUT_SECS");
    }
}
