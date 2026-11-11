//! Application state: the database handle, the background webhook channel, and the three security
//! primitives every request consults — the trusted-proxy set, the at-rest cipher, and the
//! anti-replay guard.
//!
//! All three are built **once at startup** and carried here rather than re-derived per request.
//! That is deliberate: each is an input to an authorization decision, and a value that can change
//! under a running process (an environment variable re-read mid-flight, a cipher rebuilt from a key
//! that may since have been edited) is one that cannot be reasoned about.

use std::sync::Arc;

use sea_orm::DatabaseConnection;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use uuid::Uuid;

use crate::config::TrustedProxies;
use crate::crypto::SecretCipher;
use crate::master::MasterPin;
use crate::replay::ReplayGuard;

// SQLite pragmas and pool construction used to live here. They are now `crate::db`, which puts
// "how the database is opened" in one module beside migrations rather than inside application
// state — and mirrors `simply_hook_executor`'s `src/db.rs`, which is what
// `scripts/verify_convergence.sh` diffs against.

/// Represents a webhook event triggered by the system
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WebhookEvent {
    /// The action that occurred: `"IP_ADD"`, `"IP_UPDATE"`, or `"IP_DELETE"` — matches
    /// `audit_log::Model::action`'s vocabulary and is what `webhook_config::Model::events`
    /// filters against in the dispatcher.
    pub action: String,
    /// Target address
    pub address: String,
    /// Is whitelist
    pub is_whitelist: bool,
    /// Associated group ID
    pub group_id: Option<Uuid>,
    /// The group's name at the moment the event was raised — carried alongside `group_id` so the
    /// dispatcher's `$group_name` template variable can expand to an actual name rather than
    /// requiring a database lookup from inside `prepare_dispatch` (a synchronous, DB-free function
    /// by design). `None` only when no group is associated with the event at all.
    pub group_name: Option<String>,
    /// Cause for the event
    pub cause: Option<String>,
}

/// A security-relevant environment variable was malformed, so the daemon must not start.
///
/// Both variants share one property that makes them fatal rather than recoverable: each configures a
/// *security boundary*, and for each the only alternative to aborting is to silently apply a
/// boundary different from the one the operator wrote. Everything else this service reads from the
/// environment — the bind address, the port — falls back to a documented default, because a default
/// listen port is unambiguous in a way that "some subset of your trusted proxies" is not.
#[derive(Debug, thiserror::Error)]
pub enum StartupConfigError {
    /// `VAULT_ENCRYPTION_KEY` (or its alias) is not a usable key.
    #[error(transparent)]
    EncryptionKey(#[from] crate::crypto::CryptoError),
    /// At least one `TRUSTED_PROXIES` entry is not a valid address, CIDR, or hostname.
    #[error(transparent)]
    TrustedProxies(#[from] crate::config::InvalidTrustedProxies),
}

/// Global application state shared across handlers
#[derive(Clone)]
pub struct AppState {
    /// Database connection pool
    pub db: DatabaseConnection,
    /// Channel sender for webhook events
    pub webhook_tx: mpsc::Sender<WebhookEvent>,
    /// Peers allowed to set `X-Forwarded-For`/`X-Real-IP`, from
    /// [`TRUSTED_PROXIES`](crate::config::TRUSTED_PROXIES_ENV) — literal CIDRs and/or hostnames
    /// resolved at request time.
    ///
    /// **Empty means no proxy is trusted**, so forwarding headers are ignored entirely. See
    /// [`crate::config::resolve_client_ip`].
    pub trusted_proxies: TrustedProxies,
    /// The at-rest cipher for `signing_secret`, built once from the environment at startup.
    ///
    /// Shared behind an [`Arc`] because [`SecretCipher`] holds cipher state that is expensive to
    /// rebuild and must not be rebuilt per request.
    pub cipher: Arc<SecretCipher>,
    /// Signatures already accepted inside the current anti-replay window.
    ///
    /// Shared behind an [`Arc`] rather than cloned per handler: a per-clone guard would accept a
    /// replay on any request served through a different clone, which is to say most of them. See
    /// [`crate::replay`].
    pub replay: Arc<ReplayGuard>,
    /// The identity of the one key permitted to act as Master, fixed at boot.
    ///
    /// The rule this enforces, and the attack it closes, live in [`crate::master`] — the short form
    /// is that §5's uniqueness index guarantees *at most one* master row but says nothing about
    /// **which** row, so the cardinality and the identity need separate defences. `main.rs` calls
    /// [`MasterPin::pin_at_boot`] before the listener binds, and
    /// [`crate::middleware::auth_middleware`] calls [`MasterPin::authenticate`] on the way in.
    ///
    /// Shared behind an [`Arc`] so every clone of the state observes the same pin; a per-clone cell
    /// would let each handler resolve its own, which is the bug the type exists to prevent,
    /// reintroduced one `#[derive(Clone)]` at a time.
    pub master_pin: Arc<MasterPin>,
    /// In-memory short-lived cache for analytical statistics (`GET /api/stats/analytics`), TTL ~30s.
    /// Prevents repeated expensive full-table queries when multiple dashboard tabs or users refresh.
    pub analytics_cache: Arc<tokio::sync::RwLock<Option<(std::time::Instant, serde_json::Value)>>>,
}

impl AppState {
    /// Builds state with the trusted-proxy list and cipher read from the environment.
    ///
    /// Returns an error if either security-relevant variable is malformed, and neither failure is
    /// recoverable here:
    ///
    /// - A bad `VAULT_ENCRYPTION_KEY` — see [`SecretCipher::from_env`] — because falling back to
    ///   plaintext would write signing secrets in the clear for an operator who believes they are
    ///   encrypted.
    /// - A bad `TRUSTED_PROXIES` entry — see [`crate::config::InvalidTrustedProxies`] — because
    ///   dropping it silently leaves the set of peers allowed to rewrite the client address
    ///   different from the set the operator wrote down.
    pub fn new(
        db: DatabaseConnection,
        webhook_tx: mpsc::Sender<WebhookEvent>,
    ) -> Result<Self, StartupConfigError> {
        Ok(Self {
            db,
            webhook_tx,
            trusted_proxies: TrustedProxies::from_env()?,
            cipher: Arc::new(SecretCipher::from_env()?),
            replay: Arc::new(ReplayGuard::default()),
            master_pin: Arc::new(MasterPin::new()),
            analytics_cache: Arc::new(tokio::sync::RwLock::new(None)),
        })
    }

    /// Builds state from explicit parts, bypassing the environment.
    ///
    /// Exists for tests, which need to exercise both the trusted and untrusted proxy paths — and
    /// both cipher modes — within one process, something process-wide environment variables cannot
    /// express.
    pub fn with_parts(
        db: DatabaseConnection,
        webhook_tx: mpsc::Sender<WebhookEvent>,
        trusted_proxies: Vec<crate::config::ProxyMatcher>,
        cipher: SecretCipher,
    ) -> Self {
        Self {
            db,
            webhook_tx,
            trusted_proxies: TrustedProxies::new(trusted_proxies),
            cipher: Arc::new(cipher),
            replay: Arc::new(ReplayGuard::default()),
            master_pin: Arc::new(MasterPin::new()),
            analytics_cache: Arc::new(tokio::sync::RwLock::new(None)),
        }
    }

    /// Builds state whose Master identity is fixed to `master_key_id` without a database lookup.
    ///
    /// For tests that need the *negative* case: a key that claims mastery and is not the pinned
    /// identity. Reaching that through [`MasterPin::pin_at_boot`] is impossible by construction — it
    /// only ever pins a row that really is the sole Master — so the alternative is dropping the §5
    /// index and writing a second master row, which exercises two failures at once and cannot
    /// distinguish them.
    pub fn with_pinned_master(mut self, master_key_id: Uuid) -> Self {
        self.master_pin = Arc::new(MasterPin::pinned_to(master_key_id));
        self
    }

    /// Queues a webhook event without ever blocking the request that produced it.
    ///
    /// # Why `try_send` and not `send().await`
    ///
    /// The handlers used to `await` the send. That was harmless while the worker drained the channel
    /// as fast as events arrived — and stopped being harmless the moment dispatch became throttled.
    /// At the default pace one worker handles two events per second, so a bulk operation fills the
    /// queue in well under a second and every subsequent `send().await` parks the HTTP handler until
    /// a slot frees. A firewall API that stops answering because a *notification* queue is full has
    /// its priorities backwards: the ban is the product, the webhook is a courtesy.
    ///
    /// So a full queue drops the event and logs it at `warn`. That is a real loss and is stated
    /// plainly rather than hidden — the log names the address and the depth, so an operator sees
    /// exactly what to raise. It is also not a new class of loss: the previous code discarded the
    /// send result entirely (`let _ = …`), so a closed channel already dropped events silently.
    ///
    /// Raise `WEBHOOK_QUEUE_CAPACITY`, add workers, or lower `WEBHOOK_DISPATCH_INTERVAL_MS` if this
    /// appears in a log. Consumers that cannot tolerate loss should poll
    /// `GET /api/ips?since=…&include_deleted=true` instead; the webhook stream is best-effort by
    /// construction and always has been.
    pub fn enqueue_webhook(&self, event: WebhookEvent) {
        if let Err(e) = self.webhook_tx.try_send(event) {
            match e {
                mpsc::error::TrySendError::Full(dropped) => tracing::warn!(
                    address = %dropped.address,
                    action = %dropped.action,
                    capacity = crate::config::webhook_queue_capacity(),
                    "Webhook queue is full; dropping this notification rather than stalling the \
                     request that produced it. Raise WEBHOOK_QUEUE_CAPACITY or WEBHOOK_WORKERS, or \
                     lower WEBHOOK_DISPATCH_INTERVAL_MS."
                ),
                mpsc::error::TrySendError::Closed(dropped) => tracing::warn!(
                    address = %dropped.address,
                    "Webhook channel is closed; the dispatcher is not running"
                ),
            }
        }
    }

    /// Builds state with an explicit trusted-proxy list and the zero-config plaintext cipher.
    ///
    /// The common test constructor; prefer [`AppState::with_parts`] when the cipher matters.
    pub fn with_trusted_proxies(
        db: DatabaseConnection,
        webhook_tx: mpsc::Sender<WebhookEvent>,
        trusted_proxies: Vec<crate::config::ProxyMatcher>,
    ) -> Self {
        Self::with_parts(db, webhook_tx, trusted_proxies, SecretCipher::Plaintext)
    }
}
