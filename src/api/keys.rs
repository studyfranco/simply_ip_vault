//! API key endpoints: identity, creation, listing, lifecycle, rotation, and per-group grants.
//!
//! The largest module, and deliberately not split further: `RBAC_MODEL.md` R1–R7 are about how keys
//! delegate to other keys, so subtree walking, visibility scoping and permission grants are one
//! subject. Splitting them would put a rule's mechanism in one file and its guard in another.

use axum::{
    Extension,
    extract::{Json, State},
    response::IntoResponse,
};
use chrono::Utc;
use ipnet::IpNet;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, Condition, EntityTrait, QueryFilter,
    sea_query::OnConflict,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::prelude::{ApiKey, IpGroup, WebhookConfig};
use crate::entities::{api_key, api_key_group_permission, ip_group, webhook_config};
use crate::error::AppError;
use crate::extract::{OptionalStrictJson, StrictJson, StrictPath};
use crate::middleware::ClientIp;
use crate::state::AppState;

use super::{
    caller_group_permission, create_audit_log, format_key_reference, generate_random_key,
    get_or_create_group, guard_delegated_group_grant, guard_group_manage, guard_master_immutable,
    guard_master_target, guard_may_administer_any_group, guard_scope_elevation, hash_key,
    resolve_group_by_identifier, resolve_group_ref_flexible, resolve_owner_assignment,
    resource_owner, widens_permissions,
};

// ─────────────────────────────────────────────────────────────
// Auth Handlers
// ─────────────────────────────────────────────────────────────

/// Permission payload for a group
#[derive(Serialize)]
pub struct MePermission {
    /// Group ID
    pub group_id: Uuid,
    /// Group Name
    pub group_name: String,
    /// Can read
    pub can_read: bool,
    /// Can write
    pub can_write: bool,
    /// Can delete
    pub can_delete: bool,
    /// May administer this group's permission rows (revoke-only authority; see `AGENT.MD` §2)
    pub can_manage: bool,
}

/// Identity and permission payload returned to the client
#[derive(Serialize)]
pub struct MeResponse {
    /// API Key ID
    pub id: Uuid,
    /// Key Name
    pub name: String,
    /// Bound CIDRs
    pub bound_ips: Option<String>,
    /// Master status
    pub is_master: bool,
    /// Global key management
    pub can_manage_keys: bool,
    /// Global webhook management
    pub can_manage_webhooks: bool,
    /// Global group creation
    pub can_create_groups: bool,
    /// Granular permissions
    pub group_permissions: Vec<MePermission>,
}

/// Handles GET /api/v1/auth/me
pub async fn get_me(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    let perms = api_key_group_permission::Entity::find()
        .filter(api_key_group_permission::Column::ApiKeyId.eq(key.id))
        .find_also_related(ip_group::Entity)
        .all(&state.db)
        .await?;

    let mut group_permissions = Vec::new();
    for (p, g) in perms {
        if let Some(group) = g {
            group_permissions.push(MePermission {
                group_id: p.group_id,
                group_name: group.name,
                can_read: p.can_read,
                can_write: p.can_write,
                can_delete: p.can_delete,
                can_manage: p.can_manage,
            });
        }
    }

    Ok(Json(MeResponse {
        id: key.id,
        name: key.name,
        bound_ips: key.bound_ips,
        is_master: key.is_master,
        can_manage_keys: key.can_manage_keys,
        can_manage_webhooks: key.can_manage_webhooks,
        can_create_groups: key.can_create_groups,
        group_permissions,
    }))
}

// ─────────────────────────────────────────────────────────────
// Admin CRUD — API Keys
// ─────────────────────────────────────────────────────────────

/// Input to update group permissions
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupPermInput {
    /// Target group, by ID *or* by name (a plain string, not a strictly-typed UUID, so passing a
    /// name here doesn't trip Axum's deserialization). Provide this or `group_name`, not both.
    pub group_id: Option<String>,
    /// Target group, by name. Equivalent to putting a name into `group_id`; kept as a separate
    /// field for backward compatibility. Provide this or `group_id`, not both. A name that
    /// doesn't exist yet may be auto-created (permission allowing); an unresolvable `group_id`
    /// (whether UUID- or name-shaped) is a `404` instead — an identifier is never auto-created.
    pub group_name: Option<String>,
    /// Can read
    pub can_read: bool,
    /// Can write. Requires `can_read` (AGENT.MD least-privilege rule).
    pub can_write: bool,
    /// Can delete. Requires `can_read` (AGENT.MD least-privilege rule).
    pub can_delete: bool,
    /// May administer this group's permission rows — the resource-scoped revoke authority.
    ///
    /// Defaulted rather than required, so every client written before the column existed keeps
    /// working and its payloads mean exactly what they meant before: no administrative right.
    #[serde(default)]
    pub can_manage: bool,
}

/// Payload for creating an API Key.
///
/// `deny_unknown_fields` is a §5 control, not tidiness: it is what makes the *absence* of `is_master`
/// a refusal rather than a silent discard. Serde ignores unknown fields by default, so without it a
/// struct that simply lacks the field would accept `{"is_master": true}`, drop it, and report
/// success — the one outcome worse than either accepting or rejecting it. Paired with
/// [`crate::extract::StrictJson`], which renders the rejection as `400`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateApiKeyPayload {
    /// Name
    pub name: String,
    /// Bound CIDRs
    pub bound_ips: Option<String>,
    // No `is_master`, and `deny_unknown_fields` above is what makes that absence mean something.
    // §5: "Removing the field from the payload type is required; rejecting it at the handler is not
    // sufficient, since a later handler can reintroduce the path." It briefly lived here as an
    // `Option<bool>` that a guard rejected — which worked, and put the only thing standing between a
    // payload and master status inside a function call any refactor could drop. Now the type cannot
    // carry it and serde refuses the request outright.
    /// Manage keys flag
    pub can_manage_keys: Option<bool>,
    /// Manage webhooks flag
    pub can_manage_webhooks: Option<bool>,
    /// Create groups flag
    pub can_create_groups: Option<bool>,
}

/// Response after creating API key
#[derive(Serialize)]
pub struct CreateApiKeyResponse {
    /// ID
    pub id: Uuid,
    /// Raw key string
    pub plaintext_key: String,
    /// The key's HMAC signing secret, for computing `X-Signature-256`. Returned **only** here, at
    /// creation: the stored copy is encrypted at rest (when `VAULT_ENCRYPTION_KEY` is set) and is
    /// never echoed by any read endpoint, so a caller that loses it must rotate the key.
    pub signing_secret: String,
    /// Name
    pub name: String,
    /// Bound ips
    pub bound_ips: Option<String>,
}

/// Handles POST /api/v1/keys
pub async fn create_api_key(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictJson(payload): StrictJson<CreateApiKeyPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    // Nobody mints a master any more, master included. There is no check for it here because there is
    // nothing left to check: `CreateApiKeyPayload` cannot carry `is_master`, the request is refused
    // before this function runs, and the unique index over the engine-derived `master_marker` would
    // refuse a second row even if it were not (`RBAC_MODEL.md` §5).

    // Only a master key may mint a key carrying master-only scopes. Without this,
    // `can_manage_keys` was transitively equivalent to `is_master`: a key manager could create a
    // key with `can_manage_keys`, chain it, and reach every credential in the system.
    //
    // A brand-new key holds none of these, so `held` is all-false: every `true` here is a grant.
    guard_scope_elevation(
        &key,
        [
            payload.can_manage_keys,
            payload.can_create_groups,
            payload.can_manage_webhooks,
        ],
        [false, false, false],
    )?;

    if let Some(bips) = &payload.bound_ips {
        for cidr in bips.split(',') {
            let _: IpNet = super::support::parse_cidr_or_ip(cidr)
                .map_err(|_| AppError::InvalidInput(format!("Invalid CIDR: {}", cidr)))?;
        }
    }

    let plaintext_key = generate_random_key();
    let key_hash = hash_key(&plaintext_key);
    let prefix = plaintext_key.chars().take(8).collect::<String>();
    // The signing secret is independent of the API key: leaking one must not compromise the other.
    let signing_secret = crate::crypto::generate_signing_secret();
    let stored_signing_secret = state.cipher.seal(&signing_secret)?;
    let id = Uuid::new_v4();
    let now = Utc::now().naive_utc();

    let model = api_key::ActiveModel {
        id: Set(id),
        key_hash: Set(key_hash),
        signing_secret: Set(Some(stored_signing_secret)),
        name: Set(payload.name.clone()),
        prefix: Set(prefix),
        bound_ips: Set(payload.bound_ips.clone()),
        // Hardcoded, not derived from the payload: the field that once fed this is now rejected
        // above. The engine derives `master_marker` from this `false`, so the row leaves the marker
        // NULL and does not contend for the unique index — no application write is involved.
        is_master: Set(false),
        // R3: recorded for cascade deletion and visibility scoping, and read by no permission guard.
        // A daughter of the Master is an ordinary daughter key.
        parent_key_id: Set(Some(key.id)),
        can_manage_keys: Set(payload.can_manage_keys.unwrap_or(false)),
        can_manage_webhooks: Set(payload.can_manage_webhooks.unwrap_or(false)),
        can_create_groups: Set(payload.can_create_groups.unwrap_or(false)),
        created_at: Set(now),
        updated_at: Set(now),
    };

    api_key::Entity::insert(model).exec(&state.db).await?;

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "KEY_CREATE",
        None,
        None,
        Some(payload.name.clone()),
    )
    .await?;

    Ok(Json(CreateApiKeyResponse {
        id,
        plaintext_key,
        signing_secret,
        name: payload.name,
        bound_ips: payload.bound_ips,
    }))
}

/// Public-safe summary of an API key, in one of the two shapes `RBAC_MODEL.md` §4 allows a
/// non-master caller to see.
///
/// [`Self::view`] says which, and it is not decoration — the two shapes carry genuinely different
/// information, and a client that treats an absent field as `false` rather than as *withheld* will
/// draw a key as unprivileged when it may not be.
///
/// - **`"full"`** — a key inside the caller's own subtree. §4: "a parent sees its own key subtree in
///   full, minus raw secrets — its daughters, their granted rights, and their bound IPs." Everything
///   below is populated. `key_hash` and `signing_secret` are absent from this struct entirely and
///   always have been: the hash of a live credential has no reason to leave the server.
/// - **`"minimal"`** — a key visible *only* because it holds a permission row on a resource the
///   caller manages. §4: "a parent sees, in minimal form only, any key holding a permission row on a
///   resource it manages: id, name, and that key's rights on that resource alone. Global flags, bound
///   IPs, and unrelated resource memberships remain hidden. A single shared resource must never become
///   a keyhole into another parent's whole configuration." Only `id`, `name` and the rights **on the
///   shared groups themselves** are present.
///
/// A master sees every key in the `"full"` shape.
///
/// One wart, stated rather than hidden: `bound_ips` is `None` both when it is withheld (minimal view)
/// and when the key genuinely has no CIDR restriction (full view). [`Self::view`] disambiguates, and
/// that is what it is for.
#[derive(Serialize)]
pub struct ApiKeySummary {
    /// Key ID
    pub id: Uuid,
    /// Key name
    pub name: String,
    /// Which §4 visibility scope produced this entry: `"full"` or `"minimal"`.
    pub view: &'static str,
    /// First 8 characters of the plaintext key, for display/identification only. Full view only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix: Option<String>,
    /// Bound CIDRs. Full view only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_ips: Option<String>,
    /// Master flag. Full view only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_master: Option<bool>,
    /// Global key management scope. Full view only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub can_manage_keys: Option<bool>,
    /// Global webhook management scope. Full view only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub can_manage_webhooks: Option<bool>,
    /// Global group creation scope. Full view only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub can_create_groups: Option<bool>,
    /// The key that created this one. Full view only, and carries no authority (R3).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_key_id: Option<Uuid>,
    /// Key creation timestamp. Full view only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created_at: Option<chrono::NaiveDateTime>,
    /// Per-group permissions. **All** of them in the full view; in the minimal view, only the rows on
    /// groups the caller itself manages.
    pub group_permissions: Vec<MePermission>,
}

/// The `"full"` view: everything about a key except its secrets.
pub fn build_full_api_key_summary(
    k: api_key::Model,
    group_permissions: Vec<MePermission>,
) -> ApiKeySummary {
    ApiKeySummary {
        id: k.id,
        name: k.name,
        view: "full",
        prefix: Some(k.prefix),
        bound_ips: k.bound_ips,
        is_master: Some(k.is_master),
        can_manage_keys: Some(k.can_manage_keys),
        can_manage_webhooks: Some(k.can_manage_webhooks),
        can_create_groups: Some(k.can_create_groups),
        parent_key_id: k.parent_key_id,
        created_at: Some(k.created_at),
        group_permissions,
    }
}

/// The `"minimal"` view: id, name, and this key's rights on `visible_groups` and nothing else.
pub(crate) fn build_minimal_api_key_summary(
    k: api_key::Model,
    group_permissions: Vec<MePermission>,
) -> ApiKeySummary {
    ApiKeySummary {
        id: k.id,
        name: k.name,
        view: "minimal",
        prefix: None,
        bound_ips: None,
        is_master: None,
        can_manage_keys: None,
        can_manage_webhooks: None,
        can_create_groups: None,
        parent_key_id: None,
        created_at: None,
        group_permissions,
    }
}

/// The `"full"` view: everything about a key except its secrets.
pub(crate) async fn full_api_key_summary(
    db: &sea_orm::DatabaseConnection,
    k: api_key::Model,
) -> Result<ApiKeySummary, AppError> {
    let group_permissions = key_group_permissions(db, k.id, None).await?;
    Ok(build_full_api_key_summary(k, group_permissions))
}

/// The `"minimal"` view: id, name, and this key's rights on `visible_groups` and nothing else.
#[allow(dead_code)]
pub(crate) async fn minimal_api_key_summary(
    db: &sea_orm::DatabaseConnection,
    k: api_key::Model,
    visible_groups: &[Uuid],
) -> Result<ApiKeySummary, AppError> {
    let group_permissions = key_group_permissions(db, k.id, Some(visible_groups)).await?;
    Ok(build_minimal_api_key_summary(k, group_permissions))
}

/// One key's permission rows, optionally narrowed to a set of groups.
///
/// `Some(&[])` is a meaningful argument and returns nothing — a caller that manages no groups sees no
/// shared rows, which is different from `None` ("no filter, return everything").
pub async fn key_group_permissions(
    db: &sea_orm::DatabaseConnection,
    key_id: Uuid,
    only_groups: Option<&[Uuid]>,
) -> Result<Vec<MePermission>, AppError> {
    let mut map = batch_key_group_permissions(db, &[key_id], only_groups).await?;
    Ok(map.remove(&key_id).unwrap_or_default())
}

/// Batch-fetches permission rows for multiple keys, eliminating N+1 queries.
pub async fn batch_key_group_permissions(
    db: &sea_orm::DatabaseConnection,
    key_ids: &[Uuid],
    only_groups: Option<&[Uuid]>,
) -> Result<std::collections::HashMap<Uuid, Vec<MePermission>>, AppError> {
    if key_ids.is_empty() {
        return Ok(std::collections::HashMap::new());
    }

    let mut condition =
        Condition::all().add(api_key_group_permission::Column::ApiKeyId.is_in(key_ids.to_vec()));
    if let Some(groups) = only_groups {
        condition = condition.add(api_key_group_permission::Column::GroupId.is_in(groups.to_vec()));
    }

    let perms = api_key_group_permission::Entity::find()
        .filter(condition)
        .find_also_related(ip_group::Entity)
        .all(db)
        .await?;

    let mut map: std::collections::HashMap<Uuid, Vec<MePermission>> =
        std::collections::HashMap::new();
    for (p, g) in perms {
        if let Some(group) = g {
            map.entry(p.api_key_id).or_default().push(MePermission {
                group_id: p.group_id,
                group_name: group.name,
                can_read: p.can_read,
                can_write: p.can_write,
                can_delete: p.can_delete,
                can_manage: p.can_manage,
            });
        }
    }

    Ok(map)
}

/// Every key at or below `root` in the `parent_key_id` tree, `root` included.
///
/// Iterative breadth-first rather than recursive, with a `visited` set: `parent_key_id` has no
/// database-level foreign key and nothing in the schema prevents a cycle, so a hand-edited row could
/// otherwise put this in an infinite loop — inside a request handler, holding a connection. The
/// visited set makes a cycle terminate at the cost of one extra pass instead of taking the process
/// down.
///
/// One query per level, not one per key: the level's ids go into a single `IN` clause against the
/// `idx-api_keys-parent_key_id` index added in §7's migration.
pub(crate) async fn collect_key_subtree(
    db: &sea_orm::DatabaseConnection,
    root: Uuid,
) -> Result<std::collections::HashSet<Uuid>, AppError> {
    let mut visited = std::collections::HashSet::from([root]);
    let mut frontier = vec![root];

    while !frontier.is_empty() {
        let children: Vec<Uuid> = api_key::Entity::find()
            .filter(api_key::Column::ParentKeyId.is_in(frontier.clone()))
            .all(db)
            .await?
            .into_iter()
            .map(|k| k.id)
            .collect();

        frontier = children
            .into_iter()
            .filter(|id| visited.insert(*id))
            .collect();
    }

    Ok(visited)
}

/// The groups a caller *manages* in R2's sense — the ones whose shared keys it may see in minimal
/// form.
///
/// Deliberately the same test the write path uses (`can_manage_keys` globally **and** `can_manage` on
/// the row), so §4's "a resource it manages" and R2's "manage" cannot drift into meaning two
/// different things. A master manages everything and never reaches this.
pub(crate) async fn groups_the_caller_manages(
    db: &sea_orm::DatabaseConnection,
    caller: &api_key::Model,
) -> Result<Vec<Uuid>, AppError> {
    if !caller.can_manage_keys {
        return Ok(Vec::new());
    }

    Ok(api_key_group_permission::Entity::find()
        .filter(
            Condition::all()
                .add(api_key_group_permission::Column::ApiKeyId.eq(caller.id))
                .add(api_key_group_permission::Column::CanManage.eq(true)),
        )
        .all(db)
        .await?
        .into_iter()
        .map(|p| p.group_id)
        .collect())
}

/// Whether `target` is inside the caller's **own subtree** — the scope §4 grants full visibility over,
/// and the scope every credential-level operation on another key is bounded by.
///
/// Distinct from the shared-resource scope on purpose. §4 lets a parent see, in minimal form, a key
/// that merely shares a resource it manages; it does not follow that the parent may rotate that key's
/// credential or rewrite its bound IPs. Seeing a name is not administering a credential, so
/// `update`/`delete`/`rotate`/`rotate-secret` use this and nothing wider.
pub(crate) async fn caller_can_administer_key(
    db: &sea_orm::DatabaseConnection,
    caller: &api_key::Model,
    target: Uuid,
) -> Result<bool, AppError> {
    if caller.is_master {
        return Ok(true);
    }
    Ok(collect_key_subtree(db, caller.id).await?.contains(&target))
}

/// Resolves a key-targeted request to its row, or to the `404` §4's oracle discipline requires.
///
/// §4: "Any key, resource, or dispatch target outside the caller's visibility scope must return the
/// identical status and body the service would return if that id did not exist."
///
/// This replaced a `403` that used to come from `guard_master_target`, whose stated reasoning was that
/// "the caller legitimately holds `can_manage_keys` and can already see the key in `GET /api/keys`".
/// That reasoning was true when key listing was unscoped and is false now: a delegated manager no
/// longer sees the master, or anything outside its subtree, so a `403` here would confirm the
/// existence of a key the caller cannot otherwise observe. The master key is the obvious case — a
/// `403` on `POST /keys/{id}/rotate` was a way to enumerate it.
///
/// **This does not touch the authenticate-then-authorize ordering.** That rule governs *unauthenticated*
/// callers probing key bindings through `401`-vs-`403` and lives in the middleware; this one governs
/// *authenticated* callers distinguishing absent from invisible. §4 is explicit that both hold and
/// neither may be satisfied by regressing the other.
pub(crate) async fn find_administrable_key(
    db: &sea_orm::DatabaseConnection,
    caller: &api_key::Model,
    target: Uuid,
) -> Result<api_key::Model, AppError> {
    let key = ApiKey::find_by_id(target)
        .one(db)
        .await?
        .ok_or(AppError::NotFound)?;

    if !caller_can_administer_key(db, caller, target).await? {
        return Err(AppError::NotFound);
    }

    Ok(key)
}

/// Handles GET /api/v1/keys — **§4's three visibility scopes, in one listing.**
///
/// | Caller | Sees |
/// | :--- | :--- |
/// | Master | every key, `"full"` |
/// | `can_manage_keys` holder | its own subtree `"full"`, plus every key sharing a group it manages, `"minimal"` |
/// | anyone else | `403` — this is a key-administration endpoint |
///
/// # What this replaced
///
/// Every key in the system, in full, to any `can_manage_keys` holder: global flags, `bound_ips`, and
/// every group membership of every other tenant. §4 calls the shape out by name — "A single shared
/// resource must never become a keyhole into another parent's whole configuration" — and the previous
/// behaviour did not even require a shared resource. A delegated key manager scoped to one group could
/// read the entire installation's key inventory, which is a map of what to attack next.
pub async fn list_api_keys(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    if key.is_master {
        let keys = ApiKey::find().all(&state.db).await?;
        let key_ids: Vec<Uuid> = keys.iter().map(|k| k.id).collect();
        let mut perm_map = batch_key_group_permissions(&state.db, &key_ids, None).await?;
        let summaries: Vec<ApiKeySummary> = keys
            .into_iter()
            .map(|k| {
                let perms = perm_map.remove(&k.id).unwrap_or_default();
                build_full_api_key_summary(k, perms)
            })
            .collect();
        return Ok(Json(summaries));
    }

    let subtree = collect_key_subtree(&state.db, key.id).await?;
    let managed_groups = groups_the_caller_manages(&state.db, &key).await?;

    // Keys sharing a managed group. Empty when the caller manages nothing, which `is_in([])` already
    // expresses — but the query is skipped rather than issued, since "manages nothing" is the common
    // case for a scoped manager and there is no reason to ask the database about it.
    let shared: Vec<Uuid> = if managed_groups.is_empty() {
        Vec::new()
    } else {
        api_key_group_permission::Entity::find()
            .filter(api_key_group_permission::Column::GroupId.is_in(managed_groups.clone()))
            .all(&state.db)
            .await?
            .into_iter()
            .map(|p| p.api_key_id)
            .filter(|id| !subtree.contains(id))
            .collect()
    };

    // Batch fetch subtree keys and their permissions in 2 queries instead of 2*N queries
    let subtree_keys: Vec<api_key::Model> = if subtree.is_empty() {
        Vec::new()
    } else {
        ApiKey::find()
            .filter(api_key::Column::Id.is_in(subtree.clone()))
            .all(&state.db)
            .await?
    };
    let mut subtree_map: std::collections::HashMap<Uuid, api_key::Model> =
        subtree_keys.into_iter().map(|k| (k.id, k)).collect();
    let subtree_ids: Vec<Uuid> = subtree
        .iter()
        .filter(|id| subtree_map.contains_key(id))
        .copied()
        .collect();
    let mut subtree_perm_map = batch_key_group_permissions(&state.db, &subtree_ids, None).await?;

    let mut summaries = Vec::new();
    for id in subtree {
        // A subtree member could have been deleted between the walk and here; skipping is correct
        // rather than erroring, and the caller sees the same list it would have a moment later.
        if let Some(k) = subtree_map.remove(&id) {
            let perms = subtree_perm_map.remove(&id).unwrap_or_default();
            summaries.push(build_full_api_key_summary(k, perms));
        }
    }

    let mut seen: std::collections::HashSet<Uuid> = summaries.iter().map(|s| s.id).collect();
    let shared_to_fetch: Vec<Uuid> = shared.into_iter().filter(|id| seen.insert(*id)).collect();

    if !shared_to_fetch.is_empty() {
        let shared_keys: Vec<api_key::Model> = ApiKey::find()
            .filter(api_key::Column::Id.is_in(shared_to_fetch.clone()))
            .all(&state.db)
            .await?;
        let mut shared_perm_map =
            batch_key_group_permissions(&state.db, &shared_to_fetch, Some(&managed_groups)).await?;
        let mut shared_map: std::collections::HashMap<Uuid, api_key::Model> =
            shared_keys.into_iter().map(|k| (k.id, k)).collect();
        for id in shared_to_fetch {
            if let Some(k) = shared_map.remove(&id) {
                let perms = shared_perm_map.remove(&id).unwrap_or_default();
                summaries.push(build_minimal_api_key_summary(k, perms));
            }
        }
    }

    Ok(Json(summaries))
}

/// One entity owned by a key inside the subtree being deleted, as it appears in §6's pre-flight
/// inventory.
///
/// §6 requires "enough detail to decide its fate: type, id, name, and current owner". `owner_name` is
/// carried alongside `owner_key_id` because the id alone is a UUID the caller would then have to go
/// and look up — and the keys it would look it up in are the ones about to be deleted.
#[derive(Serialize)]
pub struct OwnedEntity {
    /// `"group"` or `"webhook"` — the value a resolution entry must echo back.
    pub entity_type: &'static str,
    /// The entity's id, and the key of its resolution entry.
    pub id: Uuid,
    /// Human-readable name.
    pub name: String,
    /// The key inside the doomed subtree that owns it.
    pub owner_key_id: Uuid,
    /// That key's name.
    pub owner_name: String,
}

/// What to do with one inventoried entity.
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Resolution {
    /// Destroy the entity along with the keys.
    Delete,
    /// Transfer it to a surviving key.
    Reassign {
        /// The new owner. Must exist, must not be the master, and must not itself be inside the
        /// subtree being deleted.
        owner_key_id: Uuid,
    },
}

/// One entry in the resolution map.
///
/// Deliberately **not** `#[serde(deny_unknown_fields)]`: serde refuses to compile that combined
/// with `#[serde(flatten)]` on `resolution` below (the flattened field's unknown-key detection and
/// the container's cannot coexist). [`Resolution`] itself carries the constraint instead — it denies
/// unknown fields per variant — so an unrecognized field inside the `action`-tagged payload is still
/// refused; only a field sitting *outside* both `entity_type`/`id` and the flattened variant's own
/// fields would pass through unnoticed, and there is no such field for one to occupy.
#[derive(Deserialize)]
pub struct ResolutionEntry {
    /// Must match the inventory entry's `entity_type`.
    pub entity_type: String,
    /// Must match the inventory entry's `id`.
    pub id: Uuid,
    /// What to do with it.
    #[serde(flatten)]
    pub resolution: Resolution,
}

/// Optional body for `DELETE /api/v1/keys/:id`.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DeleteKeyPayload {
    /// One entry per inventoried entity. Partial maps are refused.
    #[serde(default)]
    pub resolutions: Vec<ResolutionEntry>,
}

/// Every group and webhook owned by any key in `subtree`, with its owner's name resolved.
///
/// §6: "Before any key deletion, the service walks the entire subtree being deleted and collects every
/// resource and dispatch target owned by any key within it." **The entire subtree**, not just the
/// target — a daughter's webhooks would otherwise vanish silently when its parent is removed, which is
/// exactly what §6's "data is never destroyed implicitly" forbids.
pub(crate) async fn inventory_owned_entities(
    db: &sea_orm::DatabaseConnection,
    subtree: &[Uuid],
) -> Result<Vec<OwnedEntity>, AppError> {
    let owners: std::collections::HashMap<Uuid, String> = ApiKey::find()
        .filter(api_key::Column::Id.is_in(subtree.to_vec()))
        .all(db)
        .await?
        .into_iter()
        .map(|k| (k.id, k.name))
        .collect();
    let owner_name = |id: Uuid| {
        owners
            .get(&id)
            .cloned()
            .unwrap_or_else(|| "<deleted>".to_owned())
    };

    let mut inventory = Vec::new();

    for group in ip_group::Entity::find()
        .filter(ip_group::Column::OwnerKeyId.is_in(subtree.to_vec()))
        .all(db)
        .await?
    {
        // `is_in` cannot match a NULL, so the owner is `Some` by construction; the fallback keeps
        // this total rather than making an inventory walk panic.
        let owner = group.owner_key_id.unwrap_or_default();
        inventory.push(OwnedEntity {
            entity_type: "group",
            id: group.id,
            name: group.name,
            owner_key_id: owner,
            owner_name: owner_name(owner),
        });
    }

    for hook in webhook_config::Entity::find()
        .filter(webhook_config::Column::OwnerKeyId.is_in(subtree.to_vec()))
        .all(db)
        .await?
    {
        let owner = hook.owner_key_id.unwrap_or_default();
        inventory.push(OwnedEntity {
            entity_type: "webhook",
            id: hook.id,
            name: hook.name,
            owner_key_id: owner,
            owner_name: owner_name(owner),
        });
    }

    Ok(inventory)
}

/// Handles DELETE /api/v1/keys/:id — **§6's cascade, gated on the pre-flight inventory.**
///
/// # The shape of the operation
///
/// 1. Walk the target's entire `parent_key_id` subtree.
/// 2. Inventory every group and webhook owned by **any** key in it.
/// 3. If the inventory is non-empty and the request carries no resolution map, **refuse** with `409`
///    and the inventory itself — type, id, name, and current owner for each entity.
/// 4. On resubmission, require an explicit resolution for **every** inventoried entity. A partial map
///    is refused; so is one naming an entity that is not in the inventory.
/// 5. Only then delete: resolutions first, then the whole subtree.
///
/// # Why a refusal and not a cascade
///
/// §6: "Data is never destroyed implicitly. IP Groups, Hooks, IP Records, Webhook Configs, and
/// Executors must never disappear as a side effect of removing a key." Deleting a key is a routine
/// act of credential hygiene; deleting the banlist that key maintained is not, and the two must not be
/// spelled the same way. The refusal is what turns "remove this key" into a decision the caller makes
/// with the inventory in front of it.
///
/// The interim `ON DELETE SET NULL` this replaces — orphaning owned resources to unowned, and
/// daughters to root-level — is gone. Orphaning is not destruction, but it silently produced
/// resources only a master could ever act on again, and §6 asks for the decision instead.
///
/// # Which keys may be deleted at all
///
/// The subtree is resolved through [`find_administrable_key`], so a caller can only ever delete inside
/// its own subtree (§4). The caller itself, and the master, are refused explicitly rather than left to
/// the subtree walk: a caller is the root of its own subtree, and the master is in nobody's.
pub async fn delete_api_key(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
    // `OptionalStrictJson` rather than `Json<T>`: `DELETE` has always been callable with no body at
    // all, and every existing client calls it that way — an empty body means "no resolutions", which
    // is exactly the request that gets the inventory back. See [`crate::extract::OptionalStrictJson`]
    // for why this is a type rather than a `Bytes` parameter parsed by hand, which is what it
    // replaced.
    OptionalStrictJson(payload): OptionalStrictJson<DeleteKeyPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    if id == key.id {
        return Err(AppError::Forbidden("Cannot delete yourself".to_owned()));
    }

    let target = find_administrable_key(&state.db, &key, id).await?;
    guard_master_target(&key, &target)?;
    guard_master_immutable(&target, "deleted")?;
    let target_ref = format_key_reference(&target.name, id);

    let subtree: Vec<Uuid> = collect_key_subtree(&state.db, id)
        .await?
        .into_iter()
        .collect();
    // A cycle in `parent_key_id` (only reachable through direct database edits — the API always sets
    // the parent to a key that already exists) could otherwise put the caller inside the subtree of a
    // key it is deleting, and take its own credential with it.
    if subtree.contains(&key.id) {
        return Err(AppError::Conflict(
            "Refusing to delete: the subtree of this key contains your own key, which indicates a              cycle in parent_key_id. Resolve it directly in the database."
                .to_owned(),
        ));
    }

    let inventory = inventory_owned_entities(&state.db, &subtree).await?;

    if !inventory.is_empty() && payload.resolutions.is_empty() {
        return Err(AppError::ConflictWithDetails {
            message: format!(
                "Refusing to delete {target_ref}: {} owned entit{} in its subtree need an explicit                  resolution. Resubmit this request with a `resolutions` array assigning each one                  either {{\"action\":\"delete\"}} or {{\"action\":\"reassign\",\"owner_key_id\":\"…\"}}.",
                inventory.len(),
                if inventory.len() == 1 { "y" } else { "ies" }
            ),
            details: serde_json::json!({
                "subtree_key_count": subtree.len(),
                "owned_entities": inventory,
            }),
        });
    }

    // Every inventoried entity, exactly once, and nothing else. Checked before a single write, so a
    // rejected map leaves the installation untouched.
    let mut resolutions: std::collections::HashMap<(String, Uuid), &Resolution> =
        std::collections::HashMap::new();
    for entry in &payload.resolutions {
        if resolutions
            .insert((entry.entity_type.clone(), entry.id), &entry.resolution)
            .is_some()
        {
            return Err(AppError::InvalidInput(format!(
                "Duplicate resolution for {} {}",
                entry.entity_type, entry.id
            )));
        }
    }

    let missing: Vec<&OwnedEntity> = inventory
        .iter()
        .filter(|e| !resolutions.contains_key(&(e.entity_type.to_owned(), e.id)))
        .collect();
    if !missing.is_empty() {
        return Err(AppError::ConflictWithDetails {
            message: format!(
                "Refusing to delete {target_ref}: the resolution map is incomplete — {} entit{}                  unresolved. Partial maps are not applied.",
                missing.len(),
                if missing.len() == 1 {
                    "y is"
                } else {
                    "ies are"
                }
            ),
            details: serde_json::json!({ "unresolved": missing }),
        });
    }

    let inventoried: std::collections::HashSet<(String, Uuid)> = inventory
        .iter()
        .map(|e| (e.entity_type.to_owned(), e.id))
        .collect();
    if let Some(extra) = resolutions.keys().find(|k| !inventoried.contains(*k)) {
        return Err(AppError::InvalidInput(format!(
            "Resolution names {} {}, which is not owned by any key in this subtree",
            extra.0, extra.1
        )));
    }

    // Validate every reassignment target before applying any of them. Reassigning to a key inside the
    // doomed subtree is refused specifically: it looks like a rescue and is a delayed deletion.
    let doomed: std::collections::HashSet<Uuid> = subtree.iter().copied().collect();
    for resolution in resolutions.values() {
        if let Resolution::Reassign { owner_key_id } = resolution {
            resolve_owner_assignment(&state.db, Some(*owner_key_id)).await?;
            if doomed.contains(owner_key_id) {
                return Err(AppError::InvalidInput(format!(
                    "Cannot reassign to key {owner_key_id}: it is itself inside the subtree being                      deleted, so the entity would be orphaned the moment this request completes"
                )));
            }
        }
    }

    // Everything below this line writes. Every validation is above it.
    let mut deleted_entities = 0usize;
    let mut reassigned_entities = 0usize;
    for entity in &inventory {
        let resolution = resolutions[&(entity.entity_type.to_owned(), entity.id)];
        match (entity.entity_type, resolution) {
            ("group", Resolution::Delete) => {
                IpGroup::delete_by_id(entity.id).exec(&state.db).await?;
                deleted_entities += 1;
            }
            ("webhook", Resolution::Delete) => {
                WebhookConfig::delete_by_id(entity.id)
                    .exec(&state.db)
                    .await?;
                deleted_entities += 1;
            }
            ("group", Resolution::Reassign { owner_key_id }) => {
                ip_group::Entity::update_many()
                    .col_expr(
                        ip_group::Column::OwnerKeyId,
                        sea_orm::sea_query::Expr::value(Some(*owner_key_id)),
                    )
                    .filter(ip_group::Column::Id.eq(entity.id))
                    .exec(&state.db)
                    .await?;
                reassigned_entities += 1;
            }
            ("webhook", Resolution::Reassign { owner_key_id }) => {
                webhook_config::Entity::update_many()
                    .col_expr(
                        webhook_config::Column::OwnerKeyId,
                        sea_orm::sea_query::Expr::value(Some(*owner_key_id)),
                    )
                    .filter(webhook_config::Column::Id.eq(entity.id))
                    .exec(&state.db)
                    .await?;
                reassigned_entities += 1;
            }
            // `entity_type` is set by `inventory_owned_entities` from a closed set of two literals.
            (other, _) => {
                tracing::error!("Unhandled inventory entity type {other:?}");
                return Err(AppError::Internal);
            }
        }
    }

    // The cascade itself. `api_key_group_permissions` rows follow by foreign key; nothing else does,
    // which is the point.
    let result = ApiKey::delete_many()
        .filter(api_key::Column::Id.is_in(subtree.clone()))
        .exec(&state.db)
        .await?;
    if result.rows_affected == 0 {
        return Err(AppError::NotFound);
    }

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "KEY_DELETE",
        None,
        None,
        Some(format!(
            "Deleted key {target_ref} and {} descendant key(s); {deleted_entities} owned \
             entit(y/ies) deleted, {reassigned_entities} reassigned",
            subtree.len().saturating_sub(1)
        )),
    )
    .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Payload for updating an existing API key's name, `bound_ips`, and global scope flags.
///
/// Carries no `is_master`, and denies unknown fields so that saying so is enforceable — the same §5
/// arrangement as [`CreateApiKeyPayload`], for the same reason. This struct has now held the field in
/// all three possible ways: absent and silently discarded, present and rejected by a guard, and
/// absent and rejected by the type. Only the last one cannot be undone by editing a handler.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateApiKeyPayload {
    /// New name, if changing it
    pub name: Option<String>,
    /// New bound CIDRs, if changing them
    pub bound_ips: Option<String>,
    /// New value for the "manage keys" global scope, if changing it
    pub can_manage_keys: Option<bool>,
    /// New value for the "manage webhooks" global scope, if changing it
    pub can_manage_webhooks: Option<bool>,
    /// New value for the "create groups" global scope, if changing it
    pub can_create_groups: Option<bool>,
}

/// Handles PUT /api/v1/keys/:id — updates name, `bound_ips`, and global scope flags in place.
pub async fn update_api_key(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
    StrictJson(payload): StrictJson<UpdateApiKeyPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let target = find_administrable_key(&state.db, &key, id).await?;
    guard_master_target(&key, &target)?;

    // §5's one exception: the Master may edit its own `bound_ips`, and nothing else about it is
    // reachable. Every other field is refused here rather than silently dropped, so an operator who
    // tried to rename the master learns that it did not happen.
    //
    // `key.id == target.id` is the "its own" half. With uniqueness enforced there is no other master
    // to be the caller, so in practice this only ever refuses the master editing itself in a way §5
    // forbids — but stating it explicitly means the rule does not quietly depend on the constraint
    // holding.
    if target.is_master {
        let touches_other_fields = payload.name.is_some()
            || payload.can_manage_keys.is_some()
            || payload.can_manage_webhooks.is_some()
            || payload.can_create_groups.is_some();
        if touches_other_fields {
            guard_master_immutable(&target, "renamed or re-scoped")?;
        }
        if key.id != target.id {
            return Err(AppError::Forbidden(
                "Only the master key itself may edit its bound_ips".to_owned(),
            ));
        }
    }

    // The master-only scopes cannot be granted to *anyone* by a non-master, self or otherwise.
    // `target`'s current values are the baseline, so re-submitting a scope the key already holds
    // is a no-op rather than a rejection.
    guard_scope_elevation(
        &key,
        [
            payload.can_manage_keys,
            payload.can_create_groups,
            payload.can_manage_webhooks,
        ],
        [
            target.can_manage_keys,
            target.can_create_groups,
            target.can_manage_webhooks,
        ],
    )?;

    // A dedicated self-escalation check for `can_manage_webhooks` stood here. It is now subsumed
    // exactly, not dropped: it fired when a non-master targeted itself with `can_manage_webhooks:
    // true` while not holding it, and in that case `target` *is* the caller, so the guard above sees
    // `requested = Some(true)` against `held = false` and refuses on R4 grounds. The scope moved onto
    // MASTER_ONLY_SCOPES, which makes the narrower rule redundant rather than merely usually-true.

    if let Some(bips) = &payload.bound_ips {
        for cidr in bips.split(',') {
            let _: IpNet = super::support::parse_cidr_or_ip(cidr)
                .map_err(|_| AppError::InvalidInput(format!("Invalid CIDR: {cidr}")))?;
        }
    }

    let mut active: api_key::ActiveModel = target.into();
    if let Some(name) = payload.name {
        active.name = Set(name);
    }
    if let Some(bips) = payload.bound_ips {
        active.bound_ips = Set(Some(bips));
    }
    if let Some(v) = payload.can_manage_keys {
        active.can_manage_keys = Set(v);
    }
    if let Some(v) = payload.can_manage_webhooks {
        active.can_manage_webhooks = Set(v);
    }
    if let Some(v) = payload.can_create_groups {
        active.can_create_groups = Set(v);
    }
    active.updated_at = Set(Utc::now().naive_utc());
    let updated = active.update(&state.db).await?;
    // Uses the post-update name (not the pre-update one) — if this call renamed the key, the
    // resulting name is what a reader will actually recognize it by later.
    let target_ref = format_key_reference(&updated.name, id);

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "KEY_UPDATE",
        None,
        None,
        Some(format!("Updated key {target_ref}")),
    )
    .await?;

    Ok(Json(full_api_key_summary(&state.db, updated).await?))
}

/// Response after rotating an API key's secret
#[derive(Serialize)]
pub struct RotateKeyResponse {
    /// Key ID
    pub id: Uuid,
    /// The new plaintext key. Shown only once — only its hash is stored.
    pub plaintext_key: String,
    /// The new HMAC signing secret. Shown only once, like [`Self::plaintext_key`].
    pub signing_secret: String,
}

/// Handles POST /api/v1/keys/:id/rotate — generates a new secret for an existing key, returning
/// the plaintext once while immediately invalidating the previous secret (the old `key_hash` is
/// overwritten, not kept around).
///
/// Rotation replaces **both** credentials: the API key *and* its HMAC signing secret. Leaving the
/// old signing secret in place would defeat the point of rotating after a suspected compromise, and
/// it doubles as the recovery path for keys created before `signing_secret` existed (which carry
/// `NULL` and cannot authenticate until rotated).
pub async fn rotate_api_key(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let target = find_administrable_key(&state.db, &key, id).await?;
    guard_master_target(&key, &target)?;
    guard_master_immutable(&target, "rotated")?;
    let target_ref = format_key_reference(&target.name, id);

    let plaintext_key = generate_random_key();
    let key_hash = hash_key(&plaintext_key);
    let prefix = plaintext_key.chars().take(8).collect::<String>();
    let signing_secret = crate::crypto::generate_signing_secret();
    let stored_signing_secret = state.cipher.seal(&signing_secret)?;

    let mut active: api_key::ActiveModel = target.into();
    active.key_hash = Set(key_hash);
    active.prefix = Set(prefix);
    active.signing_secret = Set(Some(stored_signing_secret));
    active.updated_at = Set(Utc::now().naive_utc());
    active.update(&state.db).await?;

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "KEY_ROTATE",
        None,
        None,
        Some(format!("Rotated secret for key {target_ref}")),
    )
    .await?;

    Ok(Json(RotateKeyResponse {
        id,
        plaintext_key,
        signing_secret,
    }))
}

/// Response after rotating only an API key's HMAC signing secret.
#[derive(Serialize)]
pub struct RotateSigningSecretResponse {
    /// Key ID — unchanged by this operation.
    pub id: Uuid,
    /// Key name — unchanged by this operation, echoed back so the caller can confirm which key it
    /// just re-keyed without a second lookup.
    pub name: String,
    /// The new signing secret, in plaintext. Returned **only** here: the stored copy is encrypted at
    /// rest when `VAULT_ENCRYPTION_KEY` is set, and no read endpoint ever echoes it.
    pub signing_secret: String,
}

/// Handles `POST /api/keys/{id}/rotate-secret` — replaces a key's HMAC signing secret in place.
///
/// Distinct from [`rotate_api_key`] (`POST /api/keys/{id}/rotate`), which replaces *both*
/// credentials. This narrower operation exists because the two secrets have very different blast
/// radii: rotating `X-API-Key` forces every client to be reconfigured with a new identity, whereas
/// rotating only the signing secret re-keys the HMAC while the key's id, name, `bound_ips`, global
/// scopes, and every per-group permission grant stay exactly as they were. That makes it the right
/// tool for routine credential hygiene, and for recovering a key whose `signing_secret` is `NULL`
/// because it predates HMAC authentication.
///
/// The previous signing secret stops working the instant this returns — the column is overwritten,
/// not versioned — so callers must be updated in lockstep.
pub async fn rotate_signing_secret(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_manage_keys {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let target = find_administrable_key(&state.db, &key, id).await?;
    guard_master_target(&key, &target)?;
    guard_master_immutable(&target, "re-keyed")?;
    let target_name = target.name.clone();
    let target_ref = format_key_reference(&target_name, id);

    let signing_secret = crate::crypto::generate_signing_secret();
    let stored_signing_secret = state.cipher.seal(&signing_secret)?;

    // Only `signing_secret` (and the bookkeeping `updated_at`) is touched: `key_hash`, `prefix`,
    // `name`, `bound_ips` and every global scope are left untouched by construction, and the
    // separate `api_key_group_permissions` rows are never referenced at all.
    let mut active: api_key::ActiveModel = target.into();
    active.signing_secret = Set(Some(stored_signing_secret));
    active.updated_at = Set(Utc::now().naive_utc());
    active.update(&state.db).await?;

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "KEY_SECRET_ROTATE",
        None,
        None,
        Some(format!("Rotated signing secret for key {target_ref}")),
    )
    .await?;

    Ok(Json(RotateSigningSecretResponse {
        id,
        name: target_name,
        signing_secret,
    }))
}

/// Handles POST /api/v1/keys/:id/groups
pub async fn update_key_group_permissions(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
    StrictJson(payload): StrictJson<GroupPermInput>,
) -> Result<impl IntoResponse, AppError> {
    // R2 in its group-independent form, run before any lookup so a caller with no administrative
    // standing anywhere cannot probe what exists. The precise per-group test runs below, once the
    // group is resolved.
    guard_may_administer_any_group(&state.db, &key).await?;

    let target_key = ApiKey::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    if target_key.is_master {
        return Err(AppError::InvalidInput(
            "Cannot configure M:N permissions on a master key".to_owned(),
        ));
    }

    // Self-targeting is permitted, and is bounded rather than blocked. `guard_delegated_group_grant`
    // below compares the request against the caller's *own* row — which, when the caller is the
    // target, is the very row being written — so the result can never exceed what was already held.
    // A self-directed call is therefore always a reduction or a no-op, which is the same authority
    // the dedicated revoke path grants, reached through the other endpoint.
    //
    // An earlier revision refused this outright to prevent a ratchet: grant yourself what you
    // already hold, then widen from the fresh row. The ratchet was never reachable — widening is
    // exactly what the per-verb check refuses — so the block only stopped a manager from dropping
    // its own access, which is the one self-directed change nobody needs protecting from.

    if (payload.can_write || payload.can_delete) && !payload.can_read {
        return Err(AppError::InvalidInput(
            "can_write or can_delete require can_read to be true".to_owned(),
        ));
    }

    let target_group_id: Uuid;
    let resolved_group_name: String;
    let existing_group = resolve_group_ref_flexible(
        &state.db,
        payload.group_id.as_deref(),
        payload.group_name.as_deref(),
    )
    .await?;

    if let Some(g) = existing_group {
        target_group_id = g.id;
        resolved_group_name = g.name;
    } else if let Some(group_name) = &payload.group_name {
        if !key.is_master && !key.can_create_groups {
            return Err(AppError::Forbidden(
                "Permission denied: Target group does not exist and you cannot create groups"
                    .to_owned(),
            ));
        }

        let group =
            get_or_create_group(&state.db, group_name, "banlist", resource_owner(&key)).await?;
        target_group_id = group.id;
        resolved_group_name = group.name;
    } else {
        return Err(AppError::NotFound);
    }

    // Checked after the group is resolved (so the name in the error is the real one) but before any
    // write.
    //
    // The `group_name` auto-create path above creates the group but provisions **no** permission row
    // for the creator, so a non-master arriving that way holds no `can_manage` on it and the R2 gate
    // below refuses. That is the specification's answer, not an oversight: R2 requires a
    // `can_manage = true` row and creating a resource does not mint one. Only a master can open a
    // brand-new group up for delegation.
    let caller_perm = caller_group_permission(&state.db, key.id, target_group_id).await?;
    let target_perm = caller_group_permission(&state.db, id, target_group_id).await?;

    // **Endpoint parity (R6, final sentence).** Which rule applies is a property of the *request*,
    // not of the route it arrived on. Both directions now share the same R2 admission test; the
    // classification decides whether the per-verb R1 ceiling applies on top.
    //
    // A payload that adds any verb the target lacks — or creates the row at all — is a grant, and
    // gets R2 + R1. A payload that only lowers an existing row is a **revocation reached through the
    // general update endpoint**, which R6 says must be classified as revocation "regardless of which
    // endpoint it arrives at", and gets R2 alone: no proof of authority over the verb being removed,
    // and self-targeting permitted. Splitting on the request rather than the route is what keeps
    // "revoke the row" and "update the row to a lower value" from drifting apart.
    if widens_permissions(&payload, target_perm.as_ref()) {
        guard_delegated_group_grant(
            &key,
            caller_perm.as_ref(),
            &resolved_group_name,
            "grant",
            &payload,
        )?;
    } else {
        guard_group_manage(&key, caller_perm.as_ref(), &resolved_group_name, "revoke")?;
    }

    let now = Utc::now().naive_utc();
    let perm_model = api_key_group_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(id),
        group_id: Set(target_group_id),
        can_read: Set(payload.can_read),
        can_write: Set(payload.can_write),
        can_delete: Set(payload.can_delete),
        can_manage: Set(payload.can_manage),
        created_at: Set(now),
    };

    api_key_group_permission::Entity::insert(perm_model)
        .on_conflict(
            OnConflict::columns([
                api_key_group_permission::Column::ApiKeyId,
                api_key_group_permission::Column::GroupId,
            ])
            .update_columns([
                api_key_group_permission::Column::CanRead,
                api_key_group_permission::Column::CanWrite,
                api_key_group_permission::Column::CanDelete,
                api_key_group_permission::Column::CanManage,
            ])
            .to_owned(),
        )
        .exec(&state.db)
        .await?;

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "KEY_PERM_UPDATE",
        None,
        Some(resolved_group_name),
        Some(format!(
            "Updated permissions for key {}",
            format_key_reference(&target_key.name, id)
        )),
    )
    .await?;

    Ok(axum::http::StatusCode::OK)
}

/// Handles DELETE /api/v1/keys/:id/permissions/:group_identifier — removes a key's permission
/// mapping for a specific group. `group_identifier` may be either the group's UUID or its name.
///
/// # Managing the group is the whole authority test
///
/// Admission is [`guard_group_manage`] — R2's conjunction, the same test the grant path starts from:
/// **Master**, or **global `can_manage_keys` together with `can_manage = true` on the caller's own
/// row for this group**. Neither half alone.
///
/// What revocation does *not* require is anything about the verbs themselves. R6: "Removing a
/// permission requires manage rights on the resource only; the revoker need not hold the verb being
/// removed, and may revoke its own permissions." Both are load-bearing:
///
/// **Per-verb revocation** would conflate two controls. Guarding a *grant* per verb is an
/// anti-escalation control: conferring `can_write` when you hold only `can_read` manufactures
/// authority that did not exist. Removing `can_write` manufactures nothing — no key anywhere ends up
/// with more access than before, the caller included. What removal genuinely threatens is
/// **integrity**: this service keeps `fail2ban`-style automation writing to shared banlists, so
/// stripping the key that maintains another tenant's list stops that tenant's blocking, and the
/// symptom ("bans stopped landing") sits several audit-log pages from the cause. R2's conjunction is
/// what bounds that threat — it confines every revocation to a group the caller was explicitly given
/// `can_manage` on, *and* to a caller trusted with credentials at all. A per-verb test on top would
/// buy no further containment while producing a genuinely strange shape: a grant you were trusted to
/// create could be one you were forbidden to undo.
///
/// **Self-targeting** is permitted for a related reason. It was once refused to prevent a ratchet —
/// grant yourself what you already hold, then widen from the fresh row — but the ratchet does not
/// exist: [`guard_delegated_group_grant`] compares a self-directed request against the caller's *own*
/// row, which is the very row being written, so the result can never exceed what was already held.
/// With escalation impossible, the block only forbade a manager from dropping its own access, making
/// the least-privilege action require a master.
///
/// The counterpart safeguard is that a master's view never depends on a permission row existing, so
/// a group whose last manager revokes itself stays visible and re-grantable rather than becoming
/// invisible. See [`list_ip_groups`].
pub async fn revoke_key_group_permission(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath((id, group_identifier)): StrictPath<(Uuid, String)>,
) -> Result<impl IntoResponse, AppError> {
    // R2 in its group-independent form, kept ahead of the group lookup so a caller with no
    // administrative standing anywhere is refused without learning whether the group exists. *Which*
    // group it manages is checked precisely below.
    guard_may_administer_any_group(&state.db, &key).await?;

    let group = resolve_group_by_identifier(&state.db, &group_identifier)
        .await?
        .ok_or(AppError::NotFound)?;

    // A missing grant is the `404` this endpoint has always returned, and it is established before
    // the authority check below so a caller learns "no such grant" before it learns anything about
    // its own standing — and so a nonexistent grant cannot become a `403` that confirms the group
    // exists to someone with no access to it.
    if caller_group_permission(&state.db, id, group.id)
        .await?
        .is_none()
    {
        return Err(AppError::NotFound);
    }

    let caller_perm = caller_group_permission(&state.db, key.id, group.id).await?;
    guard_group_manage(&key, caller_perm.as_ref(), &group.name, "revoke")?;

    let result = api_key_group_permission::Entity::delete_many()
        .filter(
            Condition::all()
                .add(api_key_group_permission::Column::ApiKeyId.eq(id))
                .add(api_key_group_permission::Column::GroupId.eq(group.id)),
        )
        .exec(&state.db)
        .await?;

    if result.rows_affected == 0 {
        return Err(AppError::NotFound);
    }

    let target = ApiKey::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;
    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "KEY_PERM_REVOKE",
        None,
        Some(group.name),
        Some(format!(
            "Revoked permissions for key {}",
            format_key_reference(&target.name, id)
        )),
    )
    .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}
