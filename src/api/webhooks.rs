//! Webhook config endpoints: creation, listing, update, deletion, and owner reassignment.
//!
//! The specification's *creator-private entity* — visible only to its `owner_key_id` and Master,
//! never exposed by the shared-resource visibility rule (§4).

use axum::{Extension, extract::{Json, State}, response::IntoResponse};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, Condition, EntityTrait, QueryFilter,
    QueryOrder, QuerySelect,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::prelude::WebhookConfig;
use crate::entities::{api_key, webhook_config, webhook_execution};
use crate::error::AppError;
use crate::extract::{StrictJson, StrictPath, StrictQuery};
use crate::middleware::ClientIp;
use crate::state::AppState;

use super::{
    caller_group_permission, create_audit_log, normalize_ip_or_cidr, IP_EVENT_ACTIONS,
    ReassignOwnerPayload, resolve_owner_assignment, resource_owner,
};

/// Handles PUT /api/v1/webhooks/:id/owner — the dispatch-target counterpart to
/// [`reassign_group_owner`], and the only way a pre-migration webhook becomes visible to anyone but
/// the master again.
pub async fn reassign_webhook_owner(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
    StrictJson(payload): StrictJson<ReassignOwnerPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden(
            "Only the master key can reassign resource ownership".to_owned(),
        ));
    }

    let webhook = WebhookConfig::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    let owner = resolve_owner_assignment(&state.db, payload.owner_key_id).await?;

    let webhook_name = webhook.name.clone();
    let mut active: webhook_config::ActiveModel = webhook.into();
    active.owner_key_id = Set(owner);
    active.update(&state.db).await?;

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "WEBHOOK_OWNER_REASSIGN",
        None,
        None,
        Some(match owner {
            Some(owner_id) => format!("Owner of '{webhook_name}' set to {owner_id}"),
            None => format!("Owner of '{webhook_name}' cleared (master-only)"),
        }),
    )
    .await?;

    Ok(Json(serde_json::json!({ "id": id, "owner_key_id": owner })))
}


// ─────────────────────────────────────────────────────────────
// Admin CRUD — Webhooks
// ─────────────────────────────────────────────────────────────

/// Payload for webhook creation. `deny_unknown_fields` so a typo'd or stale field is refused
/// rather than silently dropped.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateWebhookPayload {
    /// Webhook name
    pub name: String,
    /// Target URL
    pub target_url: String,
    /// Shared secret keying the HMAC. Required by `CANONICAL_V1` and `BODY_ONLY`; may be omitted
    /// (and is stored as an empty string) by the modes that compute no signature.
    pub secret_token: Option<String>,
    /// Custom headers
    pub headers_json: Option<String>,
    /// Payload Template
    pub payload_template: String,
    /// Target IP Group
    pub group_id: Uuid,
    /// Is Active
    pub is_active: Option<bool>,
    /// Comma-separated subset of `IP_ADD`/`IP_UPDATE`/`IP_DELETE` to trigger on. `None` (the
    /// default if omitted) means all events — the historical, pre-filtering behavior.
    pub events: Option<String>,
    /// How dispatches authenticate: `"CANONICAL_V1"` (default), `"BODY_ONLY"`, `"API_KEY_ONLY"`, or
    /// `"NONE"`.
    pub auth_mode: Option<String>,
    /// Deprecated alias for [`Self::auth_mode`], accepted so callers written against the
    /// short-lived `signature_mode` field keep working. Ignored when `auth_mode` is also present.
    pub signature_mode: Option<String>,
    /// Value to send as `X-API-Key` on each dispatch. Required by `API_KEY_ONLY`; optional for
    /// `CANONICAL_V1`; ignored by the other modes.
    pub api_key: Option<String>,
    /// Canonical string template for `CANONICAL_V1`, with `{method}`/`{path}`/`{timestamp}`/`{body}`
    /// placeholders. Omitted or empty means the default `{method}\n{path}\n{timestamp}\n{body}`.
    pub hmac_template: Option<String>,
    /// Header the signature is sent in. Omitted or empty means `X-Signature-256`.
    ///
    /// For receivers that expect a different name — `X-Hub-Signature-256` is the common one. Applies
    /// to both signing modes.
    pub signature_header: Option<String>,
    /// Prefix on the hex digest. Omitted means `sha256=`; an explicit `""` sends a bare digest.
    ///
    /// The empty string is meaningful rather than absent here, which is why it is not normalised
    /// away: some receivers reject a prefixed value outright.
    pub signature_prefix: Option<String>,
    /// When `true`, `$target_address` and `$ip` expand to the `/48`-normalized IPv6 subnet for
    /// non-whitelist bare host IPv6 bans (intended for firewall hooks like `launch.block.ip`).
    /// Defaults to `false` so reporting endpoints like AbuseIPDB receive exact full IPv6 hosts.
    pub send_normalized_ipv6: Option<bool>,
}


/// Handles POST /api/v1/webhooks
pub async fn create_webhook(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictJson(payload): StrictJson<CreateWebhookPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_webhooks {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    // A webhook is a standing export of everything that happens in its group, to a URL the creator
    // chooses. `can_manage_webhooks` alone therefore was not sufficient authority: it let a key
    // scoped to one group subscribe to the events of *every* group — including ones it cannot read
    // through any other endpoint — and stream them to a server it controls. Requiring `can_read` on
    // the target group keeps a webhook's reach bounded by the creator's own reach.
    if !key.is_master {
        let perm = caller_group_permission(&state.db, key.id, payload.group_id).await?;
        if !perm.is_some_and(|p| p.can_read) {
            return Err(AppError::Forbidden(
                "Permission denied: you have no read access to the target group".to_owned(),
            ));
        }
    }

    let parsed_url = reqwest::Url::parse(&payload.target_url)
        .map_err(|_| AppError::InvalidInput("Invalid target_url: must be a well-formed URL".to_owned()))?;
    if parsed_url.scheme() != "http" && parsed_url.scheme() != "https" {
        return Err(AppError::InvalidInput("Invalid target_url: scheme must be http or https".to_owned()));
    }
    if parsed_url.host_str().is_none() {
        return Err(AppError::InvalidInput("Invalid target_url: missing host".to_owned()));
    }

    if let Some(events) = &payload.events {
        for token in events.split(',').map(|s| s.trim()) {
            if !IP_EVENT_ACTIONS.contains(&token) {
                return Err(AppError::InvalidInput(format!(
                    "Invalid events entry '{token}': must be one of {}",
                    IP_EVENT_ACTIONS.join(", ")
                )));
            }
        }
    }

    // Rejected rather than silently defaulted: a caller who asks for an auth mode and gets a
    // different one would ship a receiver that rejects every dispatch, with nothing to point at.
    let requested_mode = payload.auth_mode.as_deref().or(payload.signature_mode.as_deref());
    let auth_mode = match requested_mode {
        None => webhook_config::AuthMode::CanonicalV1,
        Some(raw) => webhook_config::AuthMode::parse(raw).ok_or_else(|| {
            AppError::InvalidInput(format!(
                "Invalid auth_mode '{raw}': must be one of {}",
                webhook_config::AuthMode::ALL.join(", ")
            ))
        })?,
    };

    // Empty strings are normalized to `None` up front, so "field present but blank" (what an
    // untouched HTML input posts) and "field absent" mean the same thing everywhere downstream.
    let api_key = payload.api_key.as_deref().map(str::trim).filter(|v| !v.is_empty()).map(str::to_owned);
    let hmac_template = payload.hmac_template.as_deref().filter(|v| !v.is_empty()).map(str::to_owned);
    let secret_token = payload.secret_token.clone().unwrap_or_default();

    // Each mode's own preconditions. Catching these here turns a webhook that would have failed
    // silently on every future dispatch — in a background worker, where the operator sees only a
    // log line — into an error on the request that configured it.
    if auth_mode.requires_secret() && secret_token.is_empty() {
        return Err(AppError::InvalidInput(format!(
            "auth_mode '{}' computes an HMAC and requires a non-empty secret_token",
            auth_mode.as_str()
        )));
    }
    if auth_mode == webhook_config::AuthMode::ApiKeyOnly && api_key.is_none() {
        return Err(AppError::InvalidInput(
            "auth_mode 'API_KEY_ONLY' requires a non-empty api_key".to_owned(),
        ));
    }
    if let Some(template) = &hmac_template
        && !template.contains("{body}")
    {
        return Err(AppError::InvalidInput(
            "hmac_template must contain {body}: a signature that does not cover the payload authenticates nothing".to_owned(),
        ));
    }

    let id = Uuid::new_v4();
    let now = chrono::Utc::now().naive_utc();
    let model = webhook_config::ActiveModel {
        id: Set(id),
        name: Set(payload.name.clone()),
        target_url: Set(payload.target_url.clone()),
        secret_token: Set(secret_token),
        auth_mode: Set(auth_mode.as_str().to_owned()),
        api_key: Set(api_key),
        hmac_template: Set(hmac_template),
        // Trimmed to `None` when blank so "unset" has exactly one representation in the column, and
        // the dispatcher's fallback is reached rather than an empty header name being attempted.
        // `signature_prefix` is *not* given that treatment: `Some("")` is a real choice there.
        signature_header: Set(payload
            .signature_header
            .as_deref()
            .map(str::trim)
            .filter(|h| !h.is_empty())
            .map(str::to_owned)),
        signature_prefix: Set(payload.signature_prefix.clone()),
        headers_json: Set(payload.headers_json.clone()),
        payload_template: Set(payload.payload_template.clone()),
        group_id: Set(payload.group_id),
        // §4 makes a webhook creator-private. This column is the "creator" half; without it the only
        // scoping available was the group's, which is the shared-resource rule §4 forbids here.
        owner_key_id: Set(resource_owner(&key)),
        is_active: Set(payload.is_active.unwrap_or(true)),
        send_normalized_ipv6: Set(payload.send_normalized_ipv6.unwrap_or(false)),
        events: Set(payload.events.clone()),
        created_at: Set(now),
    };
    webhook_config::Entity::insert(model).exec(&state.db).await?;

    create_audit_log(&state.db, &key, client_ip.0, "WEBHOOK_CREATE", None, None, Some(payload.target_url.clone())).await?;

    Ok(Json(serde_json::json!({
        "id": id,
        "target_url": payload.target_url,
        "auth_mode": auth_mode.as_str(),
        "send_normalized_ipv6": payload.send_normalized_ipv6.unwrap_or(false),
    })))
}


/// Public-safe summary of a webhook configuration. Deliberately omits `secret_token` **and**
/// `api_key`: unlike `api_keys.key_hash` (a hash of a high-entropy generated value), both are
/// caller-supplied plaintext credentials for a remote system — leaking `secret_token` would let any
/// reader with `can_manage_webhooks` forge valid `X-Signature-256` signatures, and leaking `api_key`
/// would hand them a working credential on the receiving system outright.
#[derive(Serialize)]
pub struct WebhookSummary {
    /// Webhook ID
    pub id: Uuid,
    /// Webhook name
    pub name: String,
    /// Target URL
    pub target_url: String,
    /// Custom headers (JSON-encoded)
    pub headers_json: Option<String>,
    /// Payload template
    pub payload_template: String,
    /// Target IP group
    pub group_id: Uuid,
    /// Whether dispatching is currently enabled
    pub is_active: bool,
    /// Comma-separated subset of `IP_ADD`/`IP_UPDATE`/`IP_DELETE` this webhook fires for; `None`
    /// means all events.
    pub events: Option<String>,
    /// How dispatches authenticate: `"CANONICAL_V1"`, `"HMAC_ONLY"`, `"API_KEY_ONLY"` or `"NONE"`.
    /// Safe to expose — it describes the *scheme*, not the `secret_token` or `api_key` behind it.
    pub auth_mode: String,
    /// The canonical string template used in `CANONICAL_V1` mode, resolved to the effective value
    /// (the default when the column is unset) so the dashboard shows what is actually signed.
    /// Contains only placeholders and literal structure, never secret material.
    pub hmac_template: String,
    /// Whether an `X-API-Key` is configured, without disclosing it. The dashboard needs to render
    /// the field as populated; nothing needs its value back.
    pub has_api_key: bool,
    /// The header the signature is actually sent in, resolved to the effective value rather than
    /// echoed as stored — so the dashboard shows what a receiver will see, not a NULL.
    pub signature_header: String,
    /// The prefix actually applied to the digest, resolved the same way. May legitimately be empty.
    pub signature_prefix: String,
    /// When `true`, `$target_address` and `$ip` emit `/48` for non-whitelist bare host IPv6 bans.
    pub send_normalized_ipv6: bool,
    /// Creation timestamp
    pub created_at: chrono::NaiveDateTime,
}


impl From<webhook_config::Model> for WebhookSummary {
    fn from(w: webhook_config::Model) -> Self {
        // Normalized through the enum so a hand-edited or legacy row is reported as the mode it
        // will actually be dispatched with, rather than as whatever string happens to be stored.
        let auth_mode = webhook_config::AuthMode::from_stored(&w.auth_mode);
        WebhookSummary {
            id: w.id,
            name: w.name,
            target_url: w.target_url,
            headers_json: w.headers_json,
            payload_template: w.payload_template,
            group_id: w.group_id,
            is_active: w.is_active,
            send_normalized_ipv6: w.send_normalized_ipv6,
            events: w.events,
            auth_mode: auth_mode.as_str().to_owned(),
            hmac_template: w
                .hmac_template
                .unwrap_or_else(|| webhook_config::DEFAULT_HMAC_TEMPLATE.to_owned()),
            has_api_key: w.api_key.is_some_and(|k| !k.is_empty()),
            signature_header: w
                .signature_header
                .unwrap_or_else(|| webhook_config::DEFAULT_SIGNATURE_HEADER.to_owned()),
            signature_prefix: w
                .signature_prefix
                .unwrap_or_else(|| webhook_config::DEFAULT_SIGNATURE_PREFIX.to_owned()),
            created_at: w.created_at,
        }
    }
}


/// Payload for updating an existing webhook. Every field is optional; omitted fields are left as
/// they are.
///
/// `secret_token` is deliberately **not** settable to an empty string here — see
/// [`update_webhook`] for why a repointed webhook must always end up with a fresh secret.
/// `deny_unknown_fields` so a typo'd or stale field is refused rather than silently dropped.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateWebhookPayload {
    /// New human-readable name.
    pub name: Option<String>,
    /// New target endpoint. Changing this forces the `secret_token` to be regenerated.
    pub target_url: Option<String>,
    /// New canonical-string template. Changing this also forces regeneration, since the template
    /// decides what the signature actually attests to.
    pub hmac_template: Option<String>,
    /// Explicit replacement secret. When omitted and a rotation is required, one is generated and
    /// returned in the response.
    pub secret_token: Option<String>,
    /// New custom headers, JSON-encoded.
    pub headers_json: Option<String>,
    /// New payload template.
    pub payload_template: Option<String>,
    /// New event filter.
    pub events: Option<String>,
    /// Enable or disable dispatching.
    pub is_active: Option<bool>,
    /// New target IP group. Subject to the same `can_read` check `create_webhook` applies — a
    /// non-master caller may only retarget a webhook onto a group it can already read. Not gated by
    /// the privileged-webhook rule below: it changes which events trigger dispatch, not where a
    /// credential is sent or what is signed.
    pub group_id: Option<Uuid>,
    /// New auth mode: `"CANONICAL_V1"`, `"BODY_ONLY"`, `"API_KEY_ONLY"`, or `"NONE"`. Changing into a
    /// signing mode forces `secret_token` rotation, the same as repointing does — see
    /// [`update_webhook`].
    pub auth_mode: Option<String>,
    /// New `X-API-Key` value. An empty (or whitespace-only) string clears it; a non-empty string
    /// replaces it. On a webhook that is *already* privileged (a non-empty `api_key` stored today),
    /// changing this is master-only — see [`update_webhook`]'s privileged-webhook gate.
    pub api_key: Option<String>,
    /// New header the signature is sent in. Empty (or whitespace-only) clears it back to the default
    /// (`X-Signature-256`).
    pub signature_header: Option<String>,
    /// New prefix on the hex digest. `Some("")` sends a bare digest; omit to leave unchanged.
    pub signature_prefix: Option<String>,
    /// Toggle whether `$target_address` and `$ip` emit `/48` for non-whitelist bare host IPv6 bans.
    pub send_normalized_ipv6: Option<bool>,
}


/// Response from [`update_webhook`]. Carries the new `secret_token` **only** when the update forced
/// a rotation, and only on this one response — no read endpoint ever echoes it again.
#[derive(Serialize)]
pub struct UpdateWebhookResponse {
    /// The updated webhook, in the same public-safe shape as the listing.
    #[serde(flatten)]
    pub webhook: WebhookSummary,
    /// Whether this update rotated the signing secret.
    pub secret_rotated: bool,
    /// The freshly generated secret, present only when `secret_rotated` is true *and* the caller
    /// did not supply its own replacement.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_token: Option<String>,
}


/// Handles `PUT /api/v1/webhooks/{id}` — edits a webhook in place. Every stored field is editable
/// this way: name, target, group, auth mode, secret, api key, headers, payload template, event
/// filter, signature header/prefix, and active state.
///
/// **Repointing a webhook invalidates its secret.** If `target_url`, `hmac_template`, or `auth_mode`
/// changes into a signing mode, the `secret_token` is replaced — with the caller's own value if it
/// supplied one, otherwise with a freshly generated secret returned once in this response.
///
/// This is the anti-hijack property. `secret_token` is write-only: no endpoint returns it, so a
/// caller who can edit a webhook cannot read the secret it currently signs with. Without forced
/// rotation, that caller could instead point the webhook at a server it controls and simply *wait*
/// — the next dispatch would arrive at the attacker's endpoint carrying a valid
/// `X-Signature-256` over an attacker-chosen payload, handing over a working forgery oracle for the
/// receiver's shared secret. Rotating on repoint means the secret a webhook holds is only ever
/// usable against the destination it was configured for.
///
/// Changing `hmac_template` is treated identically: the template decides which bytes the signature
/// covers, so a caller who can rewrite it (e.g. to a constant that ignores `{body}`) can make the
/// existing secret vouch for content it never saw. Changing `auth_mode` into a signing mode is
/// treated the same way for the mirror-image reason: a secret that was never chosen as (or was
/// appropriate for) an HMAC key should not silently become one.
///
/// **A privileged webhook's identity fields are master-only to edit.** A webhook that already
/// carries a non-empty `api_key` authenticates as a real caller on the receiving system — changing
/// its `target_url`, `hmac_template`, `auth_mode`, or `api_key` is master-only, on top of the
/// rotation above, for the same reason a repoint alone would not be safe: none of those changes are
/// undone by rotating `secret_token`, since the `api_key` itself belongs to the remote system and is
/// never rotated by this endpoint. Every other field on a privileged webhook — name, group, payload
/// template, event filter, signature header/prefix, active state — stays editable by any
/// `can_manage_webhooks` holder that owns it.
pub async fn update_webhook(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
    StrictJson(payload): StrictJson<UpdateWebhookPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_webhooks {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let target = WebhookConfig::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;

    // Same scoping as create/delete, and for the same §4 reason: a dispatch target is visible to its
    // creator and Master and to nobody else, so a webhook the caller does not own is one it cannot
    // edit. `404` keeps "not yours" and "does not exist" indistinguishable from outside.
    //
    // This endpoint renames webhooks, which §3 names as a lifecycle action — but the ownership test
    // is the same test either way, so it is applied once here rather than split into "you may repoint
    // it but not rename it", which would be a distinction with no holder.
    if !key.is_master && target.owner_key_id != Some(key.id) {
        return Err(AppError::NotFound);
    }

    if let Some(url) = &payload.target_url {
        let parsed = reqwest::Url::parse(url).map_err(|_| {
            AppError::InvalidInput("Invalid target_url: must be a well-formed URL".to_owned())
        })?;
        if parsed.scheme() != "http" && parsed.scheme() != "https" {
            return Err(AppError::InvalidInput(
                "Invalid target_url: scheme must be http or https".to_owned(),
            ));
        }
        if parsed.host_str().is_none() {
            return Err(AppError::InvalidInput("Invalid target_url: missing host".to_owned()));
        }
    }

    if let Some(events) = &payload.events {
        for token in events.split(',').map(|s| s.trim()) {
            if !IP_EVENT_ACTIONS.contains(&token) {
                return Err(AppError::InvalidInput(format!(
                    "Invalid events entry '{token}': must be one of {}",
                    IP_EVENT_ACTIONS.join(", ")
                )));
            }
        }
    }

    if let Some(template) = &payload.hmac_template
        && !template.contains("{body}")
    {
        return Err(AppError::InvalidInput(
            "hmac_template must contain {body}: a signature that does not cover the payload authenticates nothing".to_owned(),
        ));
    }

    // Same `can_read` check `create_webhook` applies to the group a webhook is created against —
    // retargeting one onto a group the caller cannot read would be an equivalent way to reach data
    // outside the caller's own scope, just via an edit instead of a fresh POST.
    if let Some(group_id) = payload.group_id
        && group_id != target.group_id
        && !key.is_master
    {
        let perm = caller_group_permission(&state.db, key.id, group_id).await?;
        if !perm.is_some_and(|p| p.can_read) {
            return Err(AppError::Forbidden(
                "Permission denied: you have no read access to the target group".to_owned(),
            ));
        }
    }

    // Rejected rather than silently defaulted — same reasoning as `create_webhook`.
    let requested_mode = match &payload.auth_mode {
        Some(raw) => Some(webhook_config::AuthMode::parse(raw).ok_or_else(|| {
            AppError::InvalidInput(format!(
                "Invalid auth_mode '{raw}': must be one of {}",
                webhook_config::AuthMode::ALL.join(", ")
            ))
        })?),
        None => None,
    };

    // Compared against the *effective* current values so that setting a field to what it already
    // holds is not treated as a repoint — an idempotent PUT from a dashboard that submits every
    // field on every save must not churn the secret on each click.
    let effective_template =
        target.hmac_template.as_deref().unwrap_or(webhook_config::DEFAULT_HMAC_TEMPLATE);
    let url_changed = payload.target_url.as_deref().is_some_and(|u| u != target.target_url);
    let template_changed = payload
        .hmac_template
        .as_deref()
        .filter(|t| !t.is_empty())
        .is_some_and(|t| t != effective_template);

    let current_mode = webhook_config::AuthMode::from_stored(&target.auth_mode);
    let auth_mode_changed = requested_mode.is_some_and(|m| m != current_mode);
    let effective_mode = requested_mode.unwrap_or(current_mode);

    // Empty strings normalize to `None`, matching `create_webhook`'s own treatment — "field present
    // but blank" and "field absent" mean the same thing everywhere downstream.
    let requested_api_key = payload
        .api_key
        .as_deref()
        .map(str::trim)
        .map(|v| if v.is_empty() { None } else { Some(v.to_owned()) });
    let api_key_changed = requested_api_key.is_some();
    let effective_api_key = match &requested_api_key {
        Some(new_value) => new_value.clone(),
        None => target.api_key.clone(),
    };

    // A *privileged* webhook carries a credential the receiver recognizes as an identity — an
    // `api_key`, which is how instance chaining works (`AGENT.MD` §4): its dispatches authenticate
    // as a real API caller on the receiving system. Repointing one, or changing what it signs, aims
    // a working credential at a destination of the editor's choosing; changing the auth mode or the
    // `api_key` value itself achieves the same hijack by other means — forced secret rotation alone
    // does not undo any of these, because the `api_key` is not rotated and cannot be (it belongs to
    // the remote system, not this one).
    //
    // So for these four fields, editing an *already-privileged* webhook is master-only. Every other
    // property — name, payload template, event filter, group, enabled/disabled, signature header and
    // prefix — stays editable by any `can_manage_webhooks` holder, and non-privileged webhooks are
    // unaffected. (A non-master owner may still freely *create* a privileged webhook, or set an
    // `api_key` on one that doesn't have one yet — this gate is about editing a credential that is
    // already live, not about a non-master ever holding one.)
    if (url_changed || template_changed || auth_mode_changed || api_key_changed)
        && target.api_key.as_deref().is_some_and(|k| !k.is_empty())
        && !key.is_master
    {
        tracing::warn!(
            "Blocked webhook edit: key {} attempted to alter target_url/hmac_template/auth_mode/\
             api_key on privileged webhook '{}' (carries an api_key)",
            key.prefix,
            target.name
        );
        return Err(AppError::Forbidden(
            "This webhook sends an api_key credential; only a master key may change its \
             target_url, hmac_template, auth_mode, or api_key"
                .to_owned(),
        ));
    }

    // The same per-mode preconditions `create_webhook` enforces, checked against the *effective*
    // post-update state so a transition into a mode this webhook cannot yet satisfy is refused up
    // front rather than saved and left to fail silently on the next dispatch.
    if effective_mode == webhook_config::AuthMode::ApiKeyOnly && effective_api_key.is_none() {
        return Err(AppError::InvalidInput(
            "auth_mode 'API_KEY_ONLY' requires a non-empty api_key".to_owned(),
        ));
    }

    // Only the signing modes have a secret worth protecting; forcing a rotation on API_KEY_ONLY or
    // NONE would mint a secret that is never used and cannot be verified against anything. A mode
    // change into a signing mode rotates too, on the same anti-hijack logic as a repoint: a secret
    // that was never meant to be used as an HMAC key (or was appropriate under a different mode)
    // should not be inherited silently.
    let must_rotate =
        (url_changed || template_changed || auth_mode_changed) && effective_mode.requires_secret();

    let supplied_secret = payload.secret_token.as_deref().map(str::trim).filter(|s| !s.is_empty());
    let mut generated_secret = None;

    let new_secret = match (must_rotate, supplied_secret) {
        // Caller brought its own replacement: honour it, and do not echo it back.
        (_, Some(supplied)) => Some(supplied.to_owned()),
        // Repointed with no replacement offered: generate one and hand it over exactly once.
        (true, None) => {
            let secret = crate::crypto::generate_signing_secret();
            generated_secret = Some(secret.clone());
            Some(secret)
        }
        (false, None) => None,
    };

    // Defensive final check: belt-and-braces given `must_rotate` should already cover every
    // transition into a signing mode, but this keeps the invariant enforced on every path rather
    // than resting entirely on that one computation staying correct as the function grows.
    let final_secret_present = new_secret.is_some() || !target.secret_token.is_empty();
    if effective_mode.requires_secret() && !final_secret_present {
        return Err(AppError::InvalidInput(format!(
            "auth_mode '{}' computes an HMAC and requires a non-empty secret_token",
            effective_mode.as_str()
        )));
    }

    let mut active: webhook_config::ActiveModel = target.clone().into();
    if let Some(name) = payload.name {
        active.name = Set(name);
    }
    if let Some(url) = payload.target_url {
        active.target_url = Set(url);
    }
    if let Some(template) = payload.hmac_template {
        active.hmac_template = Set(Some(template).filter(|t| !t.is_empty()));
    }
    if let Some(headers) = payload.headers_json {
        active.headers_json = Set(Some(headers));
    }
    if let Some(template) = payload.payload_template {
        active.payload_template = Set(template);
    }
    if let Some(events) = payload.events {
        active.events = Set(Some(events));
    }
    if let Some(is_active) = payload.is_active {
        active.is_active = Set(is_active);
    }
    if let Some(secret) = new_secret {
        active.secret_token = Set(secret);
    }
    if let Some(group_id) = payload.group_id {
        active.group_id = Set(group_id);
    }
    if let Some(mode) = requested_mode {
        active.auth_mode = Set(mode.as_str().to_owned());
    }
    if requested_api_key.is_some() {
        active.api_key = Set(effective_api_key.clone());
    }
    if let Some(header) = &payload.signature_header {
        active.signature_header = Set(Some(header.trim().to_owned()).filter(|h| !h.is_empty()));
    }
    if let Some(prefix) = payload.signature_prefix {
        active.signature_prefix = Set(Some(prefix));
    }
    if let Some(send_normalized_ipv6) = payload.send_normalized_ipv6 {
        active.send_normalized_ipv6 = Set(send_normalized_ipv6);
    }

    let updated = active.update(&state.db).await?;

    let detail = if must_rotate {
        format!(
            "Updated webhook '{}' (secret_token rotated)",
            updated.name
        )
    } else {
        format!("Updated webhook '{}'", updated.name)
    };
    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "WEBHOOK_UPDATE",
        None,
        None,
        Some(detail),
    )
    .await?;

    Ok(Json(UpdateWebhookResponse {
        webhook: WebhookSummary::from(updated),
        secret_rotated: must_rotate,
        secret_token: generated_secret,
    }))
}


/// Payload for `POST /api/v1/webhooks/{id}/clone`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloneWebhookPayload {
    /// Name for the new, cloned webhook.
    pub name: String,
}


/// Response from [`clone_webhook`]. Carries a freshly generated `secret_token` **only** when the
/// clone's auth mode requires one — the same "shown once, never echoed again" shape
/// [`UpdateWebhookResponse`] uses for a forced rotation, since a clone's secret is deliberately never
/// copied from its source (see [`clone_webhook`]'s doc comment).
#[derive(Serialize)]
pub struct CloneWebhookResponse {
    /// The newly created webhook, in the same public-safe shape as the listing.
    #[serde(flatten)]
    pub webhook: WebhookSummary,
    /// The freshly generated signing secret, present only when the effective auth mode required one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_token: Option<String>,
}


/// Handles `POST /api/v1/webhooks/{id}/clone` — duplicates an existing webhook's configuration under
/// a new name, so an operator can stand up a variant (a different target group, a different event
/// subset) without re-typing every field by hand.
///
/// # Authorization
///
/// Same base gate as every other endpoint in this file (`is_master || can_manage_webhooks`), then:
///
/// - **Ownership of the source webhook** — the same §4 test [`update_webhook`]/[`delete_webhook`]
///   apply: master or the webhook's own `owner_key_id`, `404` (not `403`) otherwise, matching this
///   file's oracle discipline. A webhook outside the caller's scope must be indistinguishable from
///   one that does not exist.
/// - **Read access to the source webhook's target group** — the same check [`create_webhook`]
///   applies to a brand-new webhook. Cloning must not become a second way to reach a group's
///   configuration without ever having held `can_read` on it.
/// - **Master-only when the source webhook is privileged** (carries a non-empty `api_key`). A
///   privileged webhook's `api_key` authenticates as a real caller on the receiving system — the same
///   credential-duplication concern [`update_webhook`]'s privileged-webhook gate exists for, one step
///   earlier: cloning one hands the same credential to a *second*, independently-editable dispatch
///   target, which is a broader exposure than editing the original in place. Checked even against the
///   source webhook's own non-master owner — owning a privileged webhook is not the same authority as
///   being trusted to fan its credential out to a new target.
///
/// # What is duplicated
///
/// Every configuration property: `target_url`, `group_id`, `auth_mode`, `signature_header`,
/// `signature_prefix`, `hmac_template`, `payload_template`, `headers_json`, `events`, `is_active`, and
/// `api_key`. `owner_key_id` is **not** copied — the clone is owned by the *caller*
/// ([`resource_owner`], the same rule every other creation endpoint follows), not by the source
/// webhook's owner, since the caller is the one asking for a new dispatch target to exist.
///
/// `secret_token` is deliberately **never** copied. Two webhooks sharing one HMAC secret means a
/// receiver able to verify one dispatch can verify the other, and a compromise of either target's
/// secret exposes both — the opposite of what cloning into a separate, independently editable webhook
/// is for. A fresh secret is generated whenever the effective `auth_mode` requires one (the same
/// [`webhook_config::AuthMode::requires_secret`] test [`create_webhook`] applies) and returned exactly
/// once in this response.
pub async fn clone_webhook(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
    StrictJson(payload): StrictJson<CloneWebhookPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_webhooks {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let source = WebhookConfig::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    if !key.is_master && source.owner_key_id != Some(key.id) {
        return Err(AppError::NotFound);
    }

    if !key.is_master {
        let perm = caller_group_permission(&state.db, key.id, source.group_id).await?;
        if !perm.is_some_and(|p| p.can_read) {
            return Err(AppError::Forbidden(
                "Permission denied: you have no read access to the target group".to_owned(),
            ));
        }
    }

    if source.api_key.as_deref().is_some_and(|k| !k.is_empty()) && !key.is_master {
        tracing::warn!(
            "Blocked webhook clone: key {} attempted to clone privileged webhook '{}' (carries an \
             api_key)",
            key.prefix,
            source.name
        );
        return Err(AppError::Forbidden(
            "This webhook sends an api_key credential; only a master key may clone it".to_owned(),
        ));
    }

    let auth_mode = webhook_config::AuthMode::from_stored(&source.auth_mode);
    // Never inherited from the source — see this handler's own doc comment. Generated fresh exactly
    // like `create_webhook` would for a brand-new webhook in this mode.
    let generated_secret = auth_mode.requires_secret().then(crate::crypto::generate_signing_secret);
    let secret_token = generated_secret.clone().unwrap_or_default();

    let new_id = Uuid::new_v4();
    let now = chrono::Utc::now().naive_utc();
    let cloned = webhook_config::Model {
        id: new_id,
        name: payload.name.clone(),
        target_url: source.target_url.clone(),
        secret_token,
        auth_mode: auth_mode.as_str().to_owned(),
        api_key: source.api_key.clone(),
        hmac_template: source.hmac_template.clone(),
        signature_header: source.signature_header.clone(),
        signature_prefix: source.signature_prefix.clone(),
        headers_json: source.headers_json.clone(),
        payload_template: source.payload_template.clone(),
        group_id: source.group_id,
        // §4 makes a webhook creator-private, owned by whoever asked for it to exist — the caller
        // here, not the source webhook's own owner (`resource_owner` is `None` for a master, matching
        // every other creation endpoint).
        owner_key_id: resource_owner(&key),
        is_active: source.is_active,
        send_normalized_ipv6: source.send_normalized_ipv6,
        events: source.events.clone(),
        created_at: now,
    };
    let active: webhook_config::ActiveModel = cloned.clone().into();
    webhook_config::Entity::insert(active).exec(&state.db).await?;

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "WEBHOOK_CLONE",
        None,
        None,
        Some(format!(
            "Cloned '{}' ({}) as '{}' ({new_id})",
            source.name, source.id, payload.name
        )),
    )
    .await?;

    Ok((
        axum::http::StatusCode::CREATED,
        Json(CloneWebhookResponse {
            webhook: WebhookSummary::from(cloned),
            secret_token: generated_secret,
        }),
    ))
}


/// Handles GET /api/v1/webhooks
pub async fn list_webhooks(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_webhooks {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    // §4: "Dispatch targets: visible exclusively to their creator and Master. They are never exposed
    // by the shared-resource rule above."
    //
    // This was scoped by *group readability*, which is that shared-resource rule — so every
    // `can_manage_webhooks` holder with `can_read` on a group saw every other tenant's integrations in
    // it, target URL and configured headers included. A webhook row is a description of where a
    // tenant sends its data and what it puts in the request; a shared banlist is not a reason to hand
    // that over.
    //
    // Pre-migration rows carry `owner_key_id = NULL` and so appear to nobody but the master until
    // reassigned — the deliberate consequence of the null backfill, recorded in AGENT_NOTES.MD.
    let mut query = WebhookConfig::find();
    if !key.is_master {
        query = query.filter(webhook_config::Column::OwnerKeyId.eq(key.id));
    }

    let webhooks = query.all(&state.db).await?;
    let summaries: Vec<WebhookSummary> = webhooks.into_iter().map(WebhookSummary::from).collect();
    Ok(Json(summaries))
}


/// Handles DELETE /api/v1/webhooks/:id
pub async fn delete_webhook(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_webhooks {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    // A webhook is a **dispatch target**: creator-private, and never reachable through the group it
    // watches. Scoping deletion by group readability — what this did before — is the shared-resource
    // rule §4 explicitly forbids applying to a dispatch target, and it meant any `can_manage_webhooks`
    // holder with `can_read` on a group could delete another tenant's integration.
    //
    // `404` rather than `403` for a webhook the caller does not own: it never appeared in that
    // caller's `GET /api/webhooks`, so its existence is not something to confirm. That is §4's oracle
    // discipline, which Phase 3 extends to the rest of the surface.
    let target = WebhookConfig::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    if !key.is_master && target.owner_key_id != Some(key.id) {
        return Err(AppError::NotFound);
    }

    let result = WebhookConfig::delete_by_id(id).exec(&state.db).await?;
    if result.rows_affected == 0 {
        return Err(AppError::NotFound);
    }

    create_audit_log(&state.db, &key, client_ip.0, "WEBHOOK_DELETE", None, None, Some(id.to_string())).await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}


/// Handles `POST /api/v1/webhooks/{id}/test` — a live, synchronous, human-observed dispatch used by
/// the dashboard's "Test Webhook" action, so an operator can see whether a configuration actually
/// reaches its receiver before saving it.
///
/// Same authority as [`update_webhook`]/[`delete_webhook`]: `can_manage_webhooks` (or master), and
/// ownership of the specific webhook (§4 creator-private; `404`, not `403`, for one the caller does
/// not own, matching every other webhook endpoint's oracle discipline). Testing reveals whether a
/// receiver accepts the *current* configuration — target, headers, auth mode, secret — so it needs
/// exactly the authority that can already read and change all of those, no more and no less.
///
/// The event dispatched is synthetic and fixed — address `127.0.0.1/32`, action `TEST` — never a real
/// record, and it bypasses the webhook's own `events` filter entirely: an explicit, human-triggered
/// test must run regardless of what live traffic the webhook is subscribed to, or a webhook scoped to
/// `IP_DELETE` only could never be tested at all.
pub async fn test_webhook(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_webhooks {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let target = WebhookConfig::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;
    if !key.is_master && target.owner_key_id != Some(key.id) {
        return Err(AppError::NotFound);
    }

    // Fetched purely so the synthetic test event's `$group_name` template variable expands to the
    // same real name a live dispatch would see — a group deleted out from under a still-configured
    // webhook (orphaning `group_id`) degrades to `None` rather than failing the test outright.
    let group_name = crate::entities::ip_group::Entity::find_by_id(target.group_id)
        .one(&state.db)
        .await?
        .map(|g| g.name);

    let event = crate::state::WebhookEvent {
        action: "TEST".to_owned(),
        address: "127.0.0.1/32".to_owned(),
        is_whitelist: false,
        group_id: Some(target.group_id),
        group_name,
        cause: Some("Manual test dispatch from the dashboard".to_owned()),
    };

    let result = crate::dispatch::send_test_dispatch(&state.db, &target, &event).await;

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "WEBHOOK_TEST",
        None,
        None,
        Some(format!(
            "Tested webhook '{}': {}",
            target.name,
            if result.success {
                "delivered".to_owned()
            } else {
                format!("failed — {}", result.error.as_deref().unwrap_or("unknown error"))
            }
        )),
    )
    .await?;

    Ok(Json(result))
}


/// Query parameters for `GET /api/v1/webhooks/executions`. `deny_unknown_fields` so a misspelled
/// filter (`success` for `is_success`) is refused with `400` rather than silently ignored and
/// answered as though no filter had been given — the same reasoning as `AuditLogQuery`.
///
/// Every filter below is combined with every other by `AND`, and all of them are combined by `AND`
/// with the caller's own ownership scoping (see [`list_webhook_executions`]) — a non-master caller
/// narrowing by, say, `group_id` never sees a row outside webhooks it owns, no matter how broad the
/// filter itself would otherwise be. A filter matching nothing the caller may see returns an empty
/// page, never an error that would confirm something exists outside that scope.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookExecutionQuery {
    /// Narrow to one webhook's delivery history.
    pub webhook_id: Option<Uuid>,
    /// Filter by exact event type (`IP_ADD`, `IP_UPDATE`, `IP_DELETE`, `TEST`).
    pub event_type: Option<String>,
    /// Filter to only successful (`true`) or only failed (`false`) attempts. Superseded by `status`
    /// when both are given; kept for callers already using it.
    pub is_success: Option<bool>,
    /// Richer status filter: `"success"`, `"failed"`, or a bare HTTP status code (e.g. `"503"`).
    /// A code matches `status_code` exactly, so it only ever returns rows that received that exact
    /// response — a `5xx` that was retried and eventually succeeded still has a `"503"` row for the
    /// attempt that got one, distinct from the later `"200"` row for the one that didn't.
    pub status: Option<String>,
    /// Free-text search across the owning webhook's name, the triggering event's address, and its
    /// cause — the three fields an operator is likely to recognise a delivery by by eye. Matches
    /// any one of the three (`OR`), not all three at once.
    pub search: Option<String>,
    /// Narrow to executions whose webhook currently targets this group. Reflects the webhook's
    /// *current* `group_id`, not whatever it was at dispatch time — `webhook_configs.group_id` is
    /// itself editable (see `update_webhook`), and this table does not separately pin a historical
    /// value the way `target_address`/`cause` do.
    pub group_id: Option<Uuid>,
    /// Substring filter on the triggering event's address, normalized the same way `GET /api/ips`'s
    /// own `ip` filter is — a full parseable address/CIDR is canonicalized first so it still matches
    /// the stored form, while a genuine fragment passes through unchanged.
    pub ip: Option<String>,
    /// Lower bound on `created_at`, as a Unix timestamp in seconds (inclusive).
    pub from_date: Option<i64>,
    /// Upper bound on `created_at`, as a Unix timestamp in seconds (inclusive).
    pub to_date: Option<i64>,
    /// Pagination limit. Defaults to 50, matching `AuditLogQuery`.
    pub limit: Option<u64>,
    /// Pagination offset.
    pub offset: Option<u64>,
}


/// Handles `GET /api/v1/webhooks/executions` — the delivery history behind the dashboard's
/// Executions tab.
///
/// Same base gate as every other endpoint in this file — `is_master || can_manage_webhooks` — and
/// then, for a non-master caller, narrowed further to **ownership**: only executions for webhooks
/// it owns (`webhook_configs.owner_key_id = caller.id`), the same test `update_webhook`/
/// `delete_webhook`/`test_webhook` already apply. `can_manage_keys` satisfies neither half — it
/// authorises managing *keys*, not reading any webhook's delivery history, owned or not. This
/// table carries no `owner_key_id` of its own; visibility is derived entirely by joining through
/// `webhook_id`, which is why the ownership check below runs as a first query for the caller's own
/// webhook ids rather than a column filter on this table directly.
///
/// Narrower than the peer's own model: `RBAC_MODEL.md` documents `simply_hook_executor`'s
/// "Execution record" (its own creator-private entity, analogous to this table) as additionally
/// readable via a dedicated `can_view_execution` grant on the parent Hook. `simply_ip_vault` has no
/// equivalent verb; ownership is the only path to visibility here. See `SCHEMA.MD`'s
/// `webhook_executions` section for this documented as a deliberate divergence.
pub async fn list_webhook_executions(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    StrictQuery(query): StrictQuery<WebhookExecutionQuery>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_webhooks {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let mut q = webhook_execution::Entity::find()
        .order_by_desc(webhook_execution::Column::CreatedAt);

    if !key.is_master {
        let owned_ids: Vec<Uuid> = WebhookConfig::find()
            .filter(webhook_config::Column::OwnerKeyId.eq(key.id))
            .select_only()
            .column(webhook_config::Column::Id)
            .into_tuple()
            .all(&state.db)
            .await?;
        q = q.filter(webhook_execution::Column::WebhookId.is_in(owned_ids));
    }

    if let Some(webhook_id) = query.webhook_id {
        q = q.filter(webhook_execution::Column::WebhookId.eq(webhook_id));
    }
    if let Some(event_type) = &query.event_type
        && !event_type.is_empty()
    {
        q = q.filter(webhook_execution::Column::EventType.eq(event_type));
    }
    if let Some(is_success) = query.is_success {
        q = q.filter(webhook_execution::Column::IsSuccess.eq(is_success));
    }

    if let Some(status) = &query.status
        && !status.is_empty()
    {
        match status.to_ascii_lowercase().as_str() {
            "success" => q = q.filter(webhook_execution::Column::IsSuccess.eq(true)),
            "failed" | "failure" | "error" => {
                q = q.filter(webhook_execution::Column::IsSuccess.eq(false));
            }
            code => {
                let parsed: u16 = code.parse().map_err(|_| {
                    AppError::InvalidInput(format!(
                        "Invalid status filter '{status}': must be 'success', 'failed', or a \
                         numeric HTTP status code"
                    ))
                })?;
                q = q.filter(webhook_execution::Column::StatusCode.eq(i32::from(parsed)));
            }
        }
    }

    if let Some(group_id) = query.group_id {
        let group_webhook_ids: Vec<Uuid> = WebhookConfig::find()
            .filter(webhook_config::Column::GroupId.eq(group_id))
            .select_only()
            .column(webhook_config::Column::Id)
            .into_tuple()
            .all(&state.db)
            .await?;
        q = q.filter(webhook_execution::Column::WebhookId.is_in(group_webhook_ids));
    }

    if let Some(ip) = &query.ip
        && !ip.is_empty()
    {
        q = q.filter(webhook_execution::Column::TargetAddress.contains(normalize_ip_or_cidr(ip.trim())));
    }

    if let Some(search) = &query.search
        && !search.trim().is_empty()
    {
        let term = search.trim();
        // A webhook whose *name* matches is resolved to ids first, same pattern `list_ips` uses for
        // `groups`/`group_name` — SeaORM has no cross-table OR without a raw join, and this repo's
        // own hygiene tests forbid raw SQL outside a documented allowlist this file is not on.
        let name_matched_ids: Vec<Uuid> = WebhookConfig::find()
            .filter(webhook_config::Column::Name.contains(term))
            .select_only()
            .column(webhook_config::Column::Id)
            .into_tuple()
            .all(&state.db)
            .await?;
        q = q.filter(
            Condition::any()
                .add(webhook_execution::Column::TargetAddress.contains(term))
                .add(webhook_execution::Column::Cause.contains(term))
                .add(webhook_execution::Column::WebhookId.is_in(name_matched_ids)),
        );
    }

    if let Some(from) = query.from_date {
        let threshold = chrono::DateTime::from_timestamp(from, 0)
            .ok_or_else(|| AppError::InvalidInput("Invalid `from_date` timestamp".to_owned()))?
            .naive_utc();
        q = q.filter(webhook_execution::Column::CreatedAt.gte(threshold));
    }
    if let Some(to) = query.to_date {
        let threshold = chrono::DateTime::from_timestamp(to, 0)
            .ok_or_else(|| AppError::InvalidInput("Invalid `to_date` timestamp".to_owned()))?
            .naive_utc();
        q = q.filter(webhook_execution::Column::CreatedAt.lte(threshold));
    }

    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);
    let executions = q.limit(limit).offset(offset).all(&state.db).await?;

    Ok(Json(executions))
}


/// Handles `DELETE /api/v1/webhooks/executions/{id}` — removes a single execution-history row.
///
/// Same base gate as every other endpoint in this file, and the same ownership scoping
/// [`list_webhook_executions`] applies: a non-master caller may delete only an execution whose
/// webhook it owns. This table has no `owner_key_id` of its own, so the check joins through
/// `webhook_id` exactly like the listing does, just for one row instead of filtering a page of them.
///
/// `404`, not `403`, for an execution the caller may not delete — whether because it does not exist
/// at all or because its webhook belongs to someone else, matching every other handler in this
/// file's oracle discipline: a row outside the caller's scope must be indistinguishable from a row
/// that was never there.
///
/// Not pre-flight-inventoried under `RBAC_MODEL.md` §6: an execution row confers no rights and has
/// no children of its own to resolve first — see the schema migration's module header for why this
/// table sits outside §6 entirely, the same as `audit_logs`. A single ownership check is the whole
/// authority question, same as [`delete_webhook`].
pub async fn delete_webhook_execution(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_webhooks {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let execution = webhook_execution::Entity::find_by_id(id).one(&state.db).await?.ok_or(AppError::NotFound)?;

    if !key.is_master {
        let owner = WebhookConfig::find_by_id(execution.webhook_id)
            .one(&state.db)
            .await?
            .and_then(|w| w.owner_key_id);
        if owner != Some(key.id) {
            return Err(AppError::NotFound);
        }
    }

    let result = webhook_execution::Entity::delete_by_id(id).exec(&state.db).await?;
    if result.rows_affected == 0 {
        return Err(AppError::NotFound);
    }

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "WEBHOOK_EXECUTION_DELETE",
        None,
        None,
        Some(id.to_string()),
    )
    .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}
