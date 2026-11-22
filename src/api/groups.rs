//! IP Group endpoints: creation, listing, deletion, and owner reassignment.
//!
//! The specification's *managed resource* — shared, carrying per-key permission rows, and governed
//! by the R2 conjunction.

use std::collections::{BTreeSet, HashMap};

use axum::{
    Extension,
    extract::{Json, State},
    response::IntoResponse,
};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, Condition, ConnectionTrait, DatabaseBackend,
    EntityTrait, JoinType, QueryFilter, QueryOrder, QuerySelect, RelationTrait, SqlErr,
    SqliteTransactionMode, TransactionOptions, TransactionTrait,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::prelude::IpGroup;
use crate::entities::{api_key, api_key_group_permission, ip_group, ip_group_exclusion};
use crate::error::AppError;
use crate::extract::{StrictJson, StrictPath};
use crate::middleware::ClientIp;
use crate::state::AppState;

use super::{
    ReassignOwnerPayload, create_audit_log, guard_resource_lifecycle, resolve_owner_assignment,
    resource_owner,
};

// ─────────────────────────────────────────────────────────────
// Admin CRUD — IP Groups
// ─────────────────────────────────────────────────────────────

/// Payload for creating an IP group. `deny_unknown_fields` so an unrecognized field is refused
/// rather than silently ignored — see `crate::extract`'s module doc for why a silent drop is worse
/// than either accepting or rejecting it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateIpGroupPayload {
    /// Group Name
    pub name: String,
    /// Group type: `"banlist"` or `"whitelist"`. Defaults to `"banlist"` if omitted or set to
    /// anything else — this endpoint deliberately never rejects the request over this field.
    pub group_type: Option<String>,
    /// Opts a banlist into accepting private network ranges.
    #[serde(default)]
    pub allow_private_ips: Option<bool>,
    /// Whitelist groups whose active memberships protect overlapping bans.
    #[serde(default)]
    pub excluded_whitelist_ids: Vec<Uuid>,
}

/// Editable group metadata and ban policy.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateIpGroupPayload {
    /// New unique name, if supplied.
    pub name: Option<String>,
    /// New private-range policy, if supplied.
    pub allow_private_ips: Option<bool>,
    /// Replacement whitelist exclusions, if supplied.
    pub excluded_whitelist_ids: Option<Vec<Uuid>>,
}

/// Group metadata and its configured whitelist exclusions.
#[derive(Serialize)]
pub struct GroupSummary {
    /// Existing group fields, serialized at the top level.
    #[serde(flatten)]
    pub group: ip_group::Model,
    /// Protected whitelist IDs.
    pub excluded_whitelist_ids: Vec<Uuid>,
    /// Protected whitelist names in the same order as the IDs.
    pub excluded_whitelist_names: Vec<String>,
}

async fn group_summaries(
    db: &impl ConnectionTrait,
    groups: Vec<ip_group::Model>,
) -> Result<Vec<GroupSummary>, AppError> {
    use ip_group_exclusion::Column as Exclusion;
    let mut exclusions: HashMap<Uuid, (Vec<Uuid>, Vec<String>)> = HashMap::new();
    // Chunk IDs so this also works on SQLite builds with a small bind-variable limit.
    for chunk in groups.chunks(500) {
        let rows = ip_group_exclusion::Entity::find()
            .select_only()
            .column(Exclusion::GroupId)
            .column(Exclusion::ExcludedGroupId)
            .column(ip_group::Column::Name)
            .join(
                JoinType::InnerJoin,
                ip_group_exclusion::Relation::ExcludedGroup.def(),
            )
            .filter(Exclusion::GroupId.is_in(chunk.iter().map(|g| g.id)))
            .order_by_asc(Exclusion::ExcludedGroupId)
            .into_tuple::<(Uuid, Uuid, String)>()
            .all(db)
            .await?;
        for (id, excluded_id, name) in rows {
            let (ids, names) = exclusions.entry(id).or_default();
            ids.push(excluded_id);
            names.push(name);
        }
    }
    Ok(groups
        .into_iter()
        .map(|group| {
            let (excluded_whitelist_ids, excluded_whitelist_names) =
                exclusions.remove(&group.id).unwrap_or_default();
            GroupSummary {
                group,
                excluded_whitelist_ids,
                excluded_whitelist_names,
            }
        })
        .collect())
}

async fn validate_ban_policy(
    db: &impl ConnectionTrait,
    id: Uuid,
    group_type: &str,
    allow_private_ips: bool,
    excluded_ids: &[Uuid],
) -> Result<BTreeSet<Uuid>, AppError> {
    if group_type == "whitelist" && (allow_private_ips || !excluded_ids.is_empty()) {
        return Err(AppError::InvalidInput(
            "Ban policy can only be configured on a banlist group".to_owned(),
        ));
    }
    let ids: BTreeSet<_> = excluded_ids.iter().copied().collect();
    if ids.contains(&id) {
        return Err(AppError::InvalidInput(
            "A group cannot exclude itself".to_owned(),
        ));
    }
    let ids_to_validate: Vec<_> = ids.iter().copied().collect();
    for chunk in ids_to_validate.chunks(500) {
        let count = IpGroup::find()
            .select_only()
            .column(ip_group::Column::Id)
            .filter(ip_group::Column::Id.is_in(chunk.iter().copied()))
            .filter(ip_group::Column::GroupType.eq("whitelist"))
            .into_tuple::<Uuid>()
            .all(db)
            .await?
            .len();
        if count != chunk.len() {
            return Err(AppError::InvalidInput(
                "Every excluded ID must identify an existing whitelist group".to_owned(),
            ));
        }
    }
    Ok(ids)
}

async fn insert_exclusions(
    db: &impl ConnectionTrait,
    group_id: Uuid,
    excluded_ids: BTreeSet<Uuid>,
) -> Result<(), AppError> {
    let excluded_ids: Vec<_> = excluded_ids.into_iter().collect();
    for chunk in excluded_ids.chunks(400) {
        ip_group_exclusion::Entity::insert_many(chunk.iter().map(|&excluded_group_id| {
            ip_group_exclusion::ActiveModel {
                group_id: Set(group_id),
                excluded_group_id: Set(excluded_group_id),
            }
        }))
        .exec_without_returning(db)
        .await?;
    }
    Ok(())
}

fn group_write_error(err: sea_orm::DbErr, name: &str) -> AppError {
    if matches!(err.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) {
        return AppError::Conflict(format!("A group named '{name}' already exists"));
    }
    err.into()
}

/// Handles POST /api/v1/groups
pub async fn create_ip_group(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictJson(payload): StrictJson<CreateIpGroupPayload>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master && !key.can_create_groups {
        return Err(AppError::Forbidden("Permission denied".to_owned()));
    }

    let group_type = match payload.group_type.as_deref() {
        Some("whitelist") => "whitelist",
        _ => "banlist",
    };

    let id = Uuid::new_v4();
    let now = crate::time_serde::now_utc();
    let txn = state
        .db
        .begin_with_options(TransactionOptions {
            sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
            ..Default::default()
        })
        .await?;
    let allow_private_ips = payload.allow_private_ips.unwrap_or(false);
    let excluded_ids = validate_ban_policy(
        &txn,
        id,
        group_type,
        allow_private_ips,
        &payload.excluded_whitelist_ids,
    )
    .await?;
    let model = ip_group::ActiveModel {
        id: Set(id),
        name: Set(payload.name.clone()),
        group_type: Set(group_type.to_owned()),
        allow_private_ips: Set(allow_private_ips),
        description: Set(None),
        owner_key_id: Set(resource_owner(&key)),
        created_at: Set(now),
    };
    let group = model
        .insert(&txn)
        .await
        .map_err(|err| group_write_error(err, &payload.name))?;
    insert_exclusions(&txn, id, excluded_ids).await?;

    if !key.is_master {
        let perm = api_key_group_permission::ActiveModel {
            id: Set(Uuid::new_v4()),
            api_key_id: Set(key.id),
            group_id: Set(id),
            can_read: Set(true),
            can_write: Set(true),
            can_delete: Set(true),
            // See the auto-provisioning note in `upsert_ip`: creating a group does not confer
            // authority over other keys' rows on it.
            can_manage: Set(false),
            created_at: Set(now),
        };
        api_key_group_permission::Entity::insert(perm)
            .exec(&txn)
            .await?;
    }

    create_audit_log(
        &txn,
        &key,
        client_ip.0,
        "GROUP_CREATE",
        None,
        Some(payload.name.clone()),
        None,
    )
    .await?;

    let response = group_summaries(&txn, vec![group])
        .await?
        .pop()
        .ok_or(AppError::Internal)?;
    state.commit_membership_write(txn).await?;
    Ok(Json(response))
}

/// Handles PUT /api/groups/{id} and its alias with master or owner authority.
pub async fn update_ip_group(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
    StrictJson(payload): StrictJson<UpdateIpGroupPayload>,
) -> Result<impl IntoResponse, AppError> {
    let txn = state
        .db
        .begin_with_options(TransactionOptions {
            sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
            ..Default::default()
        })
        .await?;
    let mut query = IpGroup::find_by_id(id);
    if txn.get_database_backend() != DatabaseBackend::Sqlite {
        query = query.lock_exclusive();
    }
    let group = query.one(&txn).await?.ok_or(AppError::NotFound)?;
    guard_resource_lifecycle(&key, group.owner_key_id, "group", "update")?;
    let excluded_ids = validate_ban_policy(
        &txn,
        id,
        &group.group_type,
        payload.allow_private_ips.unwrap_or(group.allow_private_ips),
        payload
            .excluded_whitelist_ids
            .as_deref()
            .unwrap_or_default(),
    )
    .await?;

    let name = payload.name.as_deref().unwrap_or(&group.name).to_owned();
    let mut active: ip_group::ActiveModel = group.into();
    if let Some(name) = payload.name {
        active.name = Set(name);
    }
    if let Some(allow_private_ips) = payload.allow_private_ips {
        active.allow_private_ips = Set(allow_private_ips);
    }
    let group = active
        .update(&txn)
        .await
        .map_err(|err| group_write_error(err, &name))?;
    let mut purge_events = Vec::new();
    if payload.excluded_whitelist_ids.is_some() {
        let has_exclusions = !excluded_ids.is_empty();
        ip_group_exclusion::Entity::delete_many()
            .filter(ip_group_exclusion::Column::GroupId.eq(id))
            .exec(&txn)
            .await?;
        insert_exclusions(&txn, id, excluded_ids).await?;
        if has_exclusions && group.group_type != "whitelist" {
            let protected = super::records::load_protected_networks(&txn, id).await?;
            purge_events = super::records::purge_excluded_bans_for_networks(
                &txn,
                &key,
                client_ip.0,
                &[(group.id, group.name.clone())],
                &protected,
                crate::time_serde::now_utc(),
                false,
            )
            .await?;
        }
    }
    create_audit_log(
        &txn,
        &key,
        client_ip.0,
        "GROUP_UPDATE",
        None,
        Some(name),
        Some(id.to_string()),
    )
    .await?;
    let response = group_summaries(&txn, vec![group])
        .await?
        .pop()
        .ok_or(AppError::Internal)?;
    state.commit_membership_write(txn).await?;
    for event in purge_events {
        state.enqueue_webhook(event);
    }
    Ok(Json(response))
}

/// Handles GET /api/v1/groups and GET /`api/v1/ip_groups`
///
/// Master keys see all active IP groups. Non-master and daughter keys see only the IP groups
/// where they hold at least `can_read` (or `can_write` / `can_delete` / `can_manage`) permissions.
/// If a key has access to zero groups, returns 200 OK with an empty list `[]`.
pub async fn list_ip_groups(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    let mut query = IpGroup::find();
    if !key.is_master {
        let accessible_groups: Vec<Uuid> = api_key_group_permission::Entity::find()
            .filter(
                Condition::all()
                    .add(api_key_group_permission::Column::ApiKeyId.eq(key.id))
                    .add(
                        Condition::any()
                            .add(api_key_group_permission::Column::CanRead.eq(true))
                            .add(api_key_group_permission::Column::CanWrite.eq(true))
                            .add(api_key_group_permission::Column::CanDelete.eq(true))
                            .add(api_key_group_permission::Column::CanManage.eq(true)),
                    ),
            )
            .all(&state.db)
            .await?
            .into_iter()
            .map(|p| p.group_id)
            .collect();

        if accessible_groups.is_empty() {
            return Ok(Json(vec![]));
        }

        query = query.filter(ip_group::Column::Id.is_in(accessible_groups));
    }

    let groups = query.all(&state.db).await?;
    Ok(Json(group_summaries(&state.db, groups).await?))
}

/// Handles DELETE /api/v1/groups/:id — a **lifecycle** action, restricted by §3 to the Master and the
/// group's `owner_key_id`.
///
/// Previously master-only, which satisfied "not just anyone" without expressing why. §3 names the
/// owner as the second holder of this authority, and names what does *not* confer it: neither
/// `can_manage` on the group's permission rows nor any read/write/delete verb over its contents. A
/// group with no owner recorded — every pre-migration row, and everything a master creates — stays
/// master-only, which is exactly the authority that existed before.
pub async fn delete_ip_group(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    let group = IpGroup::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;
    guard_resource_lifecycle(&key, group.owner_key_id, "group", "delete")?;

    let result = IpGroup::delete_by_id(id).exec(&state.db).await?;
    state.invalidate_membership_queries();
    if result.rows_affected == 0 {
        return Err(AppError::NotFound);
    }

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "GROUP_DELETE",
        None,
        None,
        Some(id.to_string()),
    )
    .await?;

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Handles PUT /api/v1/groups/:id/owner — **§3: "Master may reassign `owner_key_id` on any resource
/// or dispatch target at any time."**
///
/// Master-only, and deliberately not delegable even to the current owner. Ownership is the authority
/// to destroy the resource, so a transferable owner flag would let a tenant hand that authority
/// onward without the master who granted it ever seeing the transfer — the same amplification R1
/// forbids for permission verbs, one level up. It is also the sole recovery path for the `NULL`
/// backfill: every pre-migration resource arrives here to be assigned an owner.
pub async fn reassign_group_owner(
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

    let group = IpGroup::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;
    let owner = resolve_owner_assignment(&state.db, payload.owner_key_id).await?;

    let group_name = group.name.clone();
    let mut active: ip_group::ActiveModel = group.into();
    active.owner_key_id = Set(owner);
    active.update(&state.db).await?;
    state.invalidate_membership_queries();

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "GROUP_OWNER_REASSIGN",
        None,
        Some(group_name),
        Some(match owner {
            Some(owner_id) => format!("Owner set to {owner_id}"),
            None => "Owner cleared (master-only)".to_owned(),
        }),
    )
    .await?;

    Ok(Json(serde_json::json!({ "id": id, "owner_key_id": owner })))
}
