//! The `webhook_configs` table: HTTP endpoints notified when IP events occur within a specific
//! IP group.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// A single webhook subscription: where to send events for a group, and how to sign/shape them.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "webhook_configs")]
pub struct Model {
    /// Unique webhook configuration ID.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Human-readable name for the webhook.
    pub name: String,
    /// HTTP/HTTPS target endpoint URL. Validated against SSRF (private/loopback/link-local
    /// targets are rejected at dispatch time) unless `ALLOW_PRIVATE_WEBHOOKS=true`.
    pub target_url: String,
    /// Shared secret used to generate the HMAC SHA-256 signature (`X-Signature-256`) on every
    /// dispatched request. Empty for the unsigned modes (`API_KEY_ONLY`, `NONE`), which have no
    /// HMAC to key.
    pub secret_token: String,
    /// How outbound dispatches authenticate — one of `"CANONICAL_V1"`, `"HMAC_ONLY"`,
    /// `"API_KEY_ONLY"`, `"NONE"`. See [`AuthMode`], which is the parsed form; this column stores
    /// its string representation.
    ///
    /// Stored as a plain `String` rather than a SeaORM enum column to stay SQL-agnostic per
    /// `AGENT.MD` (a native `ENUM` type is PostgreSQL/MySQL-specific and has no SQLite equivalent).
    /// Values are validated at the API boundary, and [`AuthMode::from_stored`] fails safe on
    /// anything unrecognized.
    pub auth_mode: String,
    /// Value sent as the `X-API-Key` header, for receivers that identify the caller by key on top
    /// of (or instead of) a signature. Used by `CANONICAL_V1` and `API_KEY_ONLY`; ignored by
    /// `HMAC_ONLY` and `NONE`.
    ///
    /// A plaintext credential for a *remote* system, not one of this instance's own keys — there is
    /// nothing to hash it against here, so it is stored and sent verbatim, and never returned by
    /// any read endpoint.
    pub api_key: Option<String>,
    /// The canonical string signed in `CANONICAL_V1` mode, with `{method}`, `{path}`,
    /// `{timestamp}` and `{body}` placeholders. `None` means [`DEFAULT_HMAC_TEMPLATE`].
    ///
    /// See [`resolve_hmac_template`](crate::dispatch::resolve_hmac_template) for the substitution
    /// and escape rules.
    pub hmac_template: Option<String>,
    /// Header the signature is sent in. `None` means [`DEFAULT_SIGNATURE_HEADER`].
    ///
    /// Configurable because receivers disagree: a peer instance of this service and
    /// `simply_hook_executor` both expect `X-Signature-256`, while GitHub-style consumers expect
    /// `X-Hub-Signature-256`. Stored NULL rather than backfilled so an untouched row keeps meaning
    /// "whatever this service considers standard" instead of pinning today's answer forever.
    pub signature_header: Option<String>,
    /// Prefix on the hex digest. `None` means [`DEFAULT_SIGNATURE_PREFIX`]; `Some("")` means none.
    ///
    /// The empty string is a meaningful value here, not an unset one — some receivers expect a bare
    /// hex digest and reject `sha256=`. That distinction is why this is `Option<String>` and not a
    /// `String` defaulted at the DDL layer.
    pub signature_prefix: Option<String>,
    /// Custom JSON key-value object of HTTP headers to inject into requests.
    pub headers_json: Option<String>,
    /// Template string with dynamic variables (e.g.
    /// `{"ip":"$target_address","group":"$group_name"}`).
    pub payload_template: String,
    /// The IP group this webhook monitors.
    pub group_id: Uuid,
    /// Toggle to enable/disable webhook dispatching without deleting the configuration.
    pub is_active: bool,
    /// When `true`, `$target_address` and `$ip` emit the `/48`-normalized IPv6 subnet for
    /// non-whitelist bare host IPv6 bans (e.g. for firewall hooks like `launch.block.ip`).
    /// When `false` (default), they emit the exact full address (e.g. for AbuseIPDB reporting).
    pub send_normalized_ipv6: bool,
    /// Comma-separated subset of `IP_ADD`/`IP_UPDATE`/`IP_DELETE` this webhook should fire for.
    /// `None` means all events (the historical, pre-filtering behavior).
    pub events: Option<String>,
    /// The key that created this dispatch target, or `None` when unassigned.
    ///
    /// A webhook is a **dispatch target** in `RBAC_MODEL.md`'s terminology, not a managed resource:
    /// creator-private, "visible exclusively to their creator and Master", and "never exposed by the
    /// shared-resource rule". This column is what makes that expressible — before it, a webhook was
    /// reachable by any `can_manage_webhooks` holder with `can_read` on its group, which is precisely
    /// the shared-resource rule §4 forbids applying here.
    ///
    /// `None` on every pre-migration row, which under §3/§4 means Master-only until a master
    /// reassigns it. That is a deliberate narrowing, accepted rather than guessed around.
    #[serde(default)]
    pub owner_key_id: Option<Uuid>,
    /// Creation timestamp.
    pub created_at: DateTime,
}

/// The `hmac_template` used when a `CANONICAL_V1` webhook leaves the column `NULL`.
///
/// The `\n` are **two-character escape sequences**, not real newlines, because this value round-trips
/// through a single-line HTML text input in the dashboard where a literal newline cannot be typed.
/// [`resolve_hmac_template`](crate::dispatch::resolve_hmac_template) expands them, so the bytes
/// actually signed are the same `METHOD\nPATH\nTIMESTAMP\nBODY` the inbound API verifies.
pub const DEFAULT_HMAC_TEMPLATE: &str = r"{method}\n{path}\n{timestamp}\n{body}";

/// Header the signature is sent in when `signature_header` is NULL.
///
/// The same header the inbound middleware verifies, which is what lets one instance dispatch
/// directly into another's authenticated API without either side configuring anything.
pub const DEFAULT_SIGNATURE_HEADER: &str = "X-Signature-256";

/// Prefix on the hex digest when `signature_prefix` is NULL.
///
/// Deliberately the same constant the inbound verifier requires — see `crypto::SIGNATURE_PREFIX`,
/// which is mandatory rather than stripped-if-present. Naming the algorithm in the header value is
/// what makes a future migration to a different digest detectable by a receiver instead of silent.
pub const DEFAULT_SIGNATURE_PREFIX: &str = "sha256=";

/// How an outbound webhook dispatch authenticates itself to its receiver.
///
/// Kept as a real type rather than stringly-typed comparisons scattered through the dispatcher, so
/// adding a future mode is a compiler-enforced exhaustive match instead of a hunt for `==` checks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthMode {
    /// HMAC-SHA256 over the webhook's resolved `hmac_template`, sent as
    /// `X-Signature-256: sha256=<hex>` alongside `X-Timestamp` and (when set) `X-API-Key`.
    ///
    /// With the default template this is byte-for-byte the construction the inbound API middleware
    /// verifies, which is what lets one `simply_ip_vault` instance dispatch directly into another's
    /// authenticated API (and what `simply_hook_executor` expects). A custom template covers
    /// receivers that sit behind a path-rewriting reverse proxy, or that canonicalize differently.
    CanonicalV1,
    /// HMAC-SHA256 over the raw request body only, and **no key header of any kind**.
    ///
    /// The mode for generic third-party receivers (GitHub-style webhook consumers) that authenticate
    /// the signature and nothing else. Named `HMAC_ONLY` since the schema change in
    /// `m20260811_000012`; it was `BODY_ONLY`, which described the *input* to the HMAC and left
    /// readers to infer the more important half — that this mode sends a signature **and nothing
    /// else**. Rows and payloads carrying the old spelling are still accepted, see [`Self::parse`].
    ///
    /// The header name and prefix are configurable per webhook (`signature_header`,
    /// `signature_prefix`) for receivers that expect `X-Hub-Signature-256` or an unprefixed digest.
    HmacOnly,
    /// Sends `X-API-Key` and no signature at all — for APIs whose only credential is a bearer-style
    /// key. Requires `api_key` to be set.
    ApiKeyOnly,
    /// Sends the payload with no authentication headers whatsoever.
    ///
    /// Legitimate for a receiver that authenticates by network position (a private listener reachable
    /// only from this host) or by something already inside `headers_json`; a deliberate,
    /// explicitly-chosen opt-out rather than a default anyone can drift into.
    None,
}

impl AuthMode {
    /// The string written to `webhook_configs.auth_mode` for canonical signing.
    pub const CANONICAL_V1: &'static str = "CANONICAL_V1";
    /// The string written to `webhook_configs.auth_mode` for signature-only dispatch.
    pub const HMAC_ONLY: &'static str = "HMAC_ONLY";
    /// The pre-`m20260811_000012` spelling of [`Self::HMAC_ONLY`], still accepted on input.
    ///
    /// Kept as a parse-only alias rather than deleted: a caller's stored automation may still send
    /// it, and refusing a value this service itself wrote would break integrations to no purpose.
    /// It is never *emitted* — [`Self::as_str`] returns the new spelling — so a round-trip through
    /// the API migrates a client's configuration for it.
    pub const BODY_ONLY_LEGACY: &'static str = "BODY_ONLY";
    /// The string written to `webhook_configs.auth_mode` for key-only authentication.
    pub const API_KEY_ONLY: &'static str = "API_KEY_ONLY";
    /// The string written to `webhook_configs.auth_mode` for unauthenticated dispatches.
    pub const NONE: &'static str = "NONE";

    /// Every accepted value, for API validation and error messages.
    pub const ALL: [&'static str; 4] = [
        Self::CANONICAL_V1,
        Self::HMAC_ONLY,
        Self::API_KEY_ONLY,
        Self::NONE,
    ];

    /// Parses a caller-supplied value, accepting any casing. `None` if unrecognized.
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_uppercase().as_str() {
            Self::CANONICAL_V1 => Some(Self::CanonicalV1),
            Self::HMAC_ONLY | Self::BODY_ONLY_LEGACY => Some(Self::HmacOnly),
            Self::API_KEY_ONLY => Some(Self::ApiKeyOnly),
            Self::NONE => Some(Self::None),
            _ => None,
        }
    }

    /// Parses a value already persisted in the database, falling back to [`Self::HmacOnly`].
    ///
    /// Fails *safe* rather than erroring: a row with an unrecognized mode (hand-edited SQL, or a
    /// downgrade after a future mode is added) still dispatches under a signing scheme instead of
    /// silently dropping the event or panicking inside the worker. The fallback is `HMAC_ONLY`, not
    /// the column default `CANONICAL_V1` — an unreadable mode must resolve to *more* signing, never
    /// less, and never to [`Self::None`].
    pub fn from_stored(value: &str) -> Self {
        Self::parse(value).unwrap_or_else(|| {
            tracing::warn!(
                "Unrecognized webhook auth_mode {:?} in database; falling back to {}",
                value,
                Self::HMAC_ONLY
            );
            Self::HmacOnly
        })
    }

    /// The canonical string representation, for storage and API responses.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CanonicalV1 => Self::CANONICAL_V1,
            Self::HmacOnly => Self::HMAC_ONLY,
            Self::ApiKeyOnly => Self::API_KEY_ONLY,
            Self::None => Self::NONE,
        }
    }

    /// Whether this mode computes an HMAC, and therefore requires a non-empty `secret_token`.
    pub fn requires_secret(self) -> bool {
        matches!(self, Self::CanonicalV1 | Self::HmacOnly)
    }

    /// Whether this mode sends `X-API-Key`. Only `API_KEY_ONLY` *requires* a value; `CANONICAL_V1`
    /// sends one when configured and omits the header otherwise, since a plain HMAC receiver has no
    /// use for it.
    ///
    /// **[`Self::HmacOnly`] never sends one**, even when `api_key` is populated on the row — that is
    /// the defining property of the mode and the reason it was renamed. A receiver choosing
    /// signature-only authentication has said it does not want a bearer credential, and shipping one
    /// anyway would put a reusable secret on the wire for a peer that never asked for it and may not
    /// protect it.
    pub fn sends_api_key(self) -> bool {
        matches!(self, Self::CanonicalV1 | Self::ApiKeyOnly)
    }
}

/// Relations from `webhook_configs` to other entities.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// The IP group this webhook is scoped to.
    #[sea_orm(
        belongs_to = "super::ip_group::Entity",
        from = "Column::GroupId",
        to = "super::ip_group::Column::Id",
        on_update = "NoAction",
        on_delete = "Cascade"
    )]
    IpGroup,
    /// This webhook's dispatch attempts.
    #[sea_orm(has_many = "super::webhook_execution::Entity")]
    WebhookExecution,
}

impl Related<super::ip_group::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::IpGroup.def()
    }
}

impl Related<super::webhook_execution::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::WebhookExecution.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
