//! IP record endpoints: ban/whitelist upsert, listing, membership soft delete, restore, purge, and
//! batch synchronisation.
//!
//! An address is canonical (`ip_records`). Its operational state — lock, last observation, soft
//! delete, cause history — belongs to its membership in one group (`ip_record_group_memberships`).
//! Every endpoint here that changes state therefore acts on a `(target_address, group)` pair, and
//! a change in one group never touches the same address's membership in another.

use axum::{Extension, extract::{Json, State}, response::IntoResponse};
use chrono::Utc;
use ipnetwork::IpNetwork;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, Condition, ConnectionTrait,
    DatabaseTransaction, EntityTrait, JoinType, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, RelationTrait, SqlErr, SqliteTransactionMode, TransactionOptions,
    TransactionTrait,
    sea_query::{Expr, ExprTrait, Func, Query},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::{
    api_key, api_key_group_permission, ip_group, ip_record, ip_record_cause,
    ip_record_group_membership,
};
use crate::error::AppError;
use crate::extract::{StrictJson, StrictQuery};
use crate::middleware::ClientIp;
use crate::state::{AppState, WebhookEvent};

use super::{
    create_audit_log, format_key_reference, get_or_create_group, normalize_ip_or_cidr,
    resolve_group_ref, resource_owner,
};

// ─────────────────────────────────────────────────────────────
// Ban / Whitelist
// ─────────────────────────────────────────────────────────────

/// Payload for banning or whitelisting an address. `deny_unknown_fields` so a typo'd or stale field
/// is refused rather than silently dropped.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BanWhitePayload {
    /// The target IP address or CIDR range.
    pub target_address: String,
    /// The group, by ID. Provide this or `group_name`, not both.
    pub group_id: Option<Uuid>,
    /// The group, by name. Provide this or `group_id`, not both. Unlike `group_id`, a name that does
    /// not exist yet may be auto-created, permission allowing.
    pub group_name: Option<String>,
    /// The reason for the ban or whitelist. Recorded in the cause history when present; an absent
    /// cause writes no history row.
    pub cause: Option<String>,
}

/// Handles `POST /api/ban`: adds an address to a banlist group.
pub async fn handle_ban(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictJson(payload): StrictJson<BanWhitePayload>,
) -> Result<impl IntoResponse, AppError> {
    handle_ip_upsert(state, key, client_ip.0, payload, false).await
}

/// Refuses an address that must never be banned, whatever the caller asked for.
///
/// Loopback, unspecified, RFC 1918 / link-local IPv4, and link-local / unique-local IPv6. Banning any
/// of them is either meaningless or actively harmful: a rule covering `127.0.0.1` or `10.0.0.0/8`
/// propagates through the webhook dispatchers to every downstream firewall and can cut a fleet off
/// from itself. Shared by the single-record and batch paths so neither can bypass it.
pub(crate) fn guard_bannable_address(network: &IpNetwork) -> Result<(), AppError> {
    let ip = network.network();
    if ip.is_loopback() || ip.is_unspecified() {
        return Err(AppError::InvalidInput("Cannot ban loopback or unspecified addresses".to_owned()));
    }
    match ip {
        std::net::IpAddr::V4(v4) => {
            if v4.is_private() || v4.is_link_local() {
                return Err(AppError::InvalidInput("Cannot ban private or link-local IPv4 addresses".to_owned()));
            }
        }
        std::net::IpAddr::V6(v6) => {
            let is_link_local = (v6.segments()[0] & 0xffc0) == 0xfe80;
            let is_unique_local = (v6.segments()[0] & 0xfe00) == 0xfc00;
            if is_link_local || is_unique_local {
                return Err(AppError::InvalidInput("Cannot ban link-local or unique-local IPv6 addresses".to_owned()));
            }
        }
    }
    Ok(())
}

/// Handles `POST /api/white`: adds an address to a whitelist group.
pub async fn handle_white(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictJson(payload): StrictJson<BanWhitePayload>,
) -> Result<impl IntoResponse, AppError> {
    handle_ip_upsert(state, key, client_ip.0, payload, true).await
}

/// Returns the canonical address row, creating it if this is the first time the address is seen.
///
/// Safe under concurrency: a unique violation on the insert means another writer created the same
/// address first, so the existing row is read back instead.
async fn find_or_insert_address<C: ConnectionTrait>(
    db: &C,
    address: &str,
    now: chrono::NaiveDateTime,
) -> Result<(ip_record::Model, bool), AppError> {
    if let Some(existing) = ip_record::Entity::find()
        .filter(ip_record::Column::TargetAddress.eq(address))
        .one(db)
        .await?
    {
        return Ok((existing, false));
    }
    let model = ip_record::ActiveModel {
        id: Set(Uuid::new_v4()),
        target_address: Set(address.to_owned()),
        created_at: Set(now),
    };
    match model.insert(db).await {
        Ok(created) => Ok((created, true)),
        Err(err) if matches!(err.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) => {
            let existing = ip_record::Entity::find()
                .filter(ip_record::Column::TargetAddress.eq(address))
                .one(db)
                .await?
                .ok_or(AppError::Internal)?;
            Ok((existing, false))
        }
        Err(err) => Err(err.into()),
    }
}

pub(crate) async fn handle_ip_upsert(
    state: AppState,
    key: api_key::Model,
    client_ip: std::net::IpAddr,
    payload: BanWhitePayload,
    is_whitelist: bool,
) -> Result<impl IntoResponse, AppError> {
    let network: IpNetwork = payload.target_address.parse()
        .map_err(|_| AppError::InvalidInput("Invalid IP or CIDR format".to_owned()))?;
    let normalized_address = normalize_ip_or_cidr(&payload.target_address);

    if !is_whitelist {
        guard_bannable_address(&network)?;
    }

    let target_group_id: Uuid;
    let resolved_group_name: String;

    let existing_group = resolve_group_ref(&state.db, payload.group_id, payload.group_name.as_deref()).await?;

    if let Some(g) = existing_group {
        target_group_id = g.id;
        resolved_group_name = g.name;

        if !key.is_master {
            let perm = api_key_group_permission::Entity::find()
                .filter(
                    Condition::all()
                        .add(api_key_group_permission::Column::ApiKeyId.eq(key.id))
                        .add(api_key_group_permission::Column::GroupId.eq(target_group_id))
                )
                .one(&state.db)
                .await?;

            if let Some(p) = perm {
                if !p.can_write {
                    return Err(AppError::Forbidden("Permission denied: You do not have write access to this group".to_owned()));
                }
            } else {
                return Err(AppError::Forbidden("Permission denied: You have no access strictly mapped to this group".to_owned()));
            }
        }

        // Group-type validation runs after the RBAC check: a caller with no access to the group must
        // learn nothing about it, including its type, from a 400 instead of the 403 it should get.
        if is_whitelist && g.group_type == "banlist" {
            return Err(AppError::InvalidInput(format!(
                "Cannot whitelist IP into group '{resolved_group_name}': group type is 'banlist'. Use /api/ban or target a whitelist group."
            )));
        }
        if !is_whitelist && g.group_type == "whitelist" {
            return Err(AppError::InvalidInput(format!(
                "Cannot ban IP into group '{resolved_group_name}': group type is 'whitelist'. Use /api/white or target a banlist group."
            )));
        }
    } else if let Some(group_name) = &payload.group_name {
        if !key.is_master && !key.can_create_groups {
            return Err(AppError::Forbidden("Permission denied: Target group does not exist and you cannot create groups".to_owned()));
        }

        let default_type = if is_whitelist { "whitelist" } else { "banlist" };
        let group = get_or_create_group(&state.db, group_name, default_type, resource_owner(&key)).await?;
        target_group_id = group.id;
        resolved_group_name = group.name;

        if !key.is_master {
            let now = Utc::now().naive_utc();
            let perm = api_key_group_permission::ActiveModel {
                id: Set(Uuid::new_v4()),
                api_key_id: Set(key.id),
                group_id: Set(target_group_id),
                can_read: Set(true),
                can_write: Set(true),
                can_delete: Set(true),
                // Auto-provisioning confers read/write/delete and nothing more (AGENT.MD §2).
                can_manage: Set(false),
                created_at: Set(now),
            };
            api_key_group_permission::Entity::insert(perm)
                .on_conflict(
                    sea_orm::sea_query::OnConflict::columns([
                        api_key_group_permission::Column::ApiKeyId,
                        api_key_group_permission::Column::GroupId,
                    ])
                    .do_nothing()
                    .to_owned()
                )
                .exec_without_returning(&state.db)
                .await?;
        }
    } else {
        // A group id that matches nothing is never something a client can legitimately invent.
        return Err(AppError::NotFound);
    }

    let now = Utc::now().naive_utc();
    let cause = payload
        .cause
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(str::to_owned);

    // `Immediate`: this transaction reads before it writes, and a deferred one would take its
    // snapshot at the first read and be refused the write lock if another writer committed in
    // between (SQLITE_BUSY without busy_timeout). See AGENT.MD's SQLite bullets.
    let txn = state
        .db
        .begin_with_options(TransactionOptions {
            sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
            ..Default::default()
        })
        .await?;

    let (address_row, _) = find_or_insert_address(&txn, &normalized_address, now).await?;

    let existing = ip_record_group_membership::Entity::find()
        .filter(ip_record_group_membership::Column::IpRecordId.eq(address_row.id))
        .filter(ip_record_group_membership::Column::GroupId.eq(target_group_id))
        .one(&txn)
        .await?;

    let (membership_id, action) = match existing {
        Some(membership) => {
            if membership.is_locked {
                return Err(AppError::Forbidden("This IP is protected and cannot be modified".to_owned()));
            }
            // Re-registering a soft-deleted membership resurrects it, so a deletion never makes the
            // address permanently unbannable in that group.
            let was_deleted = membership.is_deleted;
            let mut active: ip_record_group_membership::ActiveModel = membership.into();
            active.last_seen_at = Set(now);
            if was_deleted {
                active.is_deleted = Set(false);
                active.deleted_at = Set(None);
                active.deleted_by = Set(None);
            }
            let updated = active.update(&txn).await?;
            (updated.id, "IP_UPDATE")
        }
        None => {
            let id = Uuid::new_v4();
            ip_record_group_membership::ActiveModel {
                id: Set(id),
                ip_record_id: Set(address_row.id),
                group_id: Set(target_group_id),
                is_locked: Set(false),
                created_at: Set(now),
                last_seen_at: Set(now),
                is_deleted: Set(false),
                deleted_at: Set(None),
                deleted_by: Set(None),
            }
            .insert(&txn)
            .await?;
            (id, "IP_ADD")
        }
    };

    if let Some(text) = &cause {
        ip_record_cause::ActiveModel {
            id: Set(Uuid::new_v4()),
            membership_id: Set(membership_id),
            cause: Set(text.clone()),
            created_at: Set(now),
        }
        .insert(&txn)
        .await?;
    }

    create_audit_log(
        &txn,
        &key,
        client_ip,
        action,
        Some(normalized_address.clone()),
        Some(resolved_group_name.clone()),
        Some(format!("Added IP to group. Whitelist: {}", is_whitelist)),
    )
    .await?;

    txn.commit().await?;

    state.enqueue_webhook(WebhookEvent {
        action: action.to_owned(),
        address: normalized_address,
        is_whitelist,
        group_id: Some(target_group_id),
        group_name: Some(resolved_group_name),
        cause,
    });

    Ok(axum::http::StatusCode::OK)
}

// ─────────────────────────────────────────────────────────────
// Listing
// ─────────────────────────────────────────────────────────────

/// Query parameters for IP listing. `deny_unknown_fields` so a misspelled filter is refused with
/// `400` rather than silently matching everything.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryFilters {
    /// Filter by groups (comma-separated group names).
    pub groups: Option<String>,
    /// Filter by a single group name, in addition to `groups`.
    pub group_name: Option<String>,
    /// Filter by a single group ID, in addition to `groups`/`group_name`.
    pub group_id: Option<Uuid>,
    /// Filter by a substring of the target address.
    pub ip: Option<String>,
    /// Filter by a substring of any cause reported against the membership.
    pub cause: Option<String>,
    /// Filter by group type: `ban`/`banlist` or `white`/`whitelist`.
    pub status: Option<String>,
    /// Maximum age in seconds, based on the membership's `last_seen_at`.
    pub max_age: Option<i64>,
    /// Differential-sync cutoff, as a Unix timestamp in seconds.
    ///
    /// A membership is in scope when its `last_seen_at` is at or after the cutoff, or — with
    /// `include_deleted=true` — when it was soft-deleted at or after it. Scoped per membership: a
    /// change in one group never makes the same address look changed in another.
    pub since: Option<i64>,
    /// Pagination limit.
    pub limit: Option<u64>,
    /// Pagination offset.
    pub offset: Option<u64>,
    /// `"iplist"` (accepted under either key) returns `{"ip_list": [...]}` of matched addresses.
    pub format: Option<String>,
    /// Synonym for `format`.
    pub mode: Option<String>,
    /// Also return soft-deleted memberships. Available to any caller, scoped exactly as live ones.
    pub include_deleted: Option<bool>,
    /// Wrap the response in `{data, total, limit, offset, total_pages}`. Opt-in; the bare array is
    /// the default. Ignored under `format=iplist`.
    pub include_total: Option<bool>,
}

/// One membership as the API presents it: an address's state within one group.
#[derive(Serialize)]
pub struct IpRecordResponse {
    /// The membership's identifier. Use it, with the group, to refer to this row.
    pub id: Uuid,
    /// The canonical address this membership is for.
    pub ip_record_id: Uuid,
    /// The address or CIDR range.
    pub target_address: String,
    /// The group this membership is in.
    pub group_name: String,
    /// The group's type (`banlist` or `whitelist`).
    pub group_type: String,
    /// The most recently reported cause for this membership, if any cause was ever reported.
    pub cause: Option<String>,
    /// Whether this membership is locked.
    pub is_locked: bool,
    /// When this address was first linked into this group.
    pub created_at: chrono::NaiveDateTime,
    /// The latest observation of this address in this group.
    pub last_seen_at: chrono::NaiveDateTime,
    /// Whether this membership is soft-deleted. Always `false` in a normal listing.
    pub is_deleted: bool,
    /// When it was soft-deleted, if it was.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<chrono::NaiveDateTime>,
    /// The key that soft-deleted it. **Master only**; omitted for every other caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_by: Option<String>,
}

/// Response envelope for `GET /api/ips?include_total=true`.
#[derive(Serialize)]
pub struct IpRecordsEnvelope {
    /// The page of memberships.
    pub data: Vec<IpRecordResponse>,
    /// Total memberships matching every filter, across all pages.
    pub total: u64,
    /// The effective `limit`.
    pub limit: u64,
    /// The effective `offset`.
    pub offset: u64,
    /// `ceil(total / limit)`, or `0` when there is nothing to page through.
    pub total_pages: u64,
}

/// The empty-result shape for [`list_ips`] in whichever response form the caller asked for.
fn empty_ips_response(format_iplist: bool, include_total: bool, limit: u64, offset: u64) -> axum::response::Response {
    if format_iplist {
        return Json(serde_json::json!({ "ip_list": Vec::<String>::new() })).into_response();
    }
    if include_total {
        return Json(IpRecordsEnvelope { data: Vec::new(), total: 0, limit, offset, total_pages: 0 }).into_response();
    }
    Json(Vec::<IpRecordResponse>::new()).into_response()
}

/// Above this many groups, [`fetch_merged_page`]'s one-query-per-group approach costs more than a
/// single `GroupId IN (...)` query with a sort. The production complaint this exists for ("group_id
/// IN (?, ?, ?, ?)") is a handful of groups; past this bound, a broad RBAC grant or a long `groups=`
/// list falls back to the plain `IN (...)` query instead.
const MERGE_MAX_GROUPS: usize = 16;
/// Above this `offset + limit`, each per-group query in [`fetch_merged_page`] would itself need to
/// fetch too many rows to stay cheap (every one of them fetches `offset + limit`, since the globally
/// correct page can draw unevenly from any group). Deep pagination across several groups falls back
/// to the single `IN (...)` query instead — slower, but correct, and a rare access pattern next to
/// the first few pages a dashboard actually loads.
const MERGE_MAX_FETCH: u64 = 2000;

/// Counts memberships matching `condition`, scoped to `groups` when given.
///
/// With `groups`, this sums one indexed per-group count instead of running a single `GroupId IN
/// (...)` count — kept symmetric with [`fetch_merged_page`] so the two agree on what the group
/// filter means, even though a count has no `ORDER BY` to break and `IN (...)` alone would already
/// be index-covered.
async fn count_matching(
    db: &sea_orm::DatabaseConnection,
    condition: &Condition,
    address_filter_present: bool,
    groups: Option<&[Uuid]>,
) -> Result<u64, AppError> {
    // One query, never split per group. `fetch_merged_page` splits because an `ORDER BY` across a
    // `GroupId IN (...)` cannot be served from the per-group partial index without a sort. A count
    // has no order to satisfy, so that reason never applied to it: `GroupId IN (...)` stays a
    // covering-index scan (confirmed with `EXPLAIN QUERY PLAN` against this schema). Splitting it
    // would only add round trips for no benefit.
    let mut scoped = condition.clone();
    if let Some(ids) = groups {
        scoped = scoped.add(ip_record_group_membership::Column::GroupId.is_in(ids.iter().copied()));
    }
    let mut query = ip_record_group_membership::Entity::find();
    if address_filter_present {
        query = query.join(JoinType::InnerJoin, ip_record_group_membership::Relation::IpRecord.def());
    }
    // `COUNT(*)`, not `COUNT(id)`: the partial index on `(group_id, last_seen_at)` does not carry
    // `id`, so counting that column forces a table lookup per matching row and loses "COVERING
    // INDEX" — about 10x slower on this schema (measured: COUNT(id) 1.4ms vs COUNT(*) 0.14ms per
    // group at 100k rows; this is also what made the production `COUNT(... IN (?,?,?,?))` query
    // take 5.8s). `COUNT(*)` needs no column value, so SQLite answers it from the index alone.
    let count: Option<i64> = query
        .filter(scoped)
        .select_only()
        .expr_as(Func::count(Expr::col(sea_orm::sea_query::Asterisk)), "row_count")
        .into_tuple::<i64>()
        .one(db)
        .await?;
    Ok(std::cmp::max(count.unwrap_or(0), 0) as u64)
}

/// Fetches one page across a small, explicit set of groups without an SQL `ORDER BY` that spans
/// them.
///
/// The partial index `idx_memberships_active_last_seen` is `(group_id, last_seen_at DESC) WHERE
/// is_deleted = FALSE` — it sorts *within* one `group_id`, not across several. A `GroupId IN
/// (...)` with `ORDER BY last_seen_at` therefore cannot be served from it directly; SQLite scans
/// the matching rows and sorts them in a temp b-tree instead, which is what turns a page read into
/// a full scan as a group grows. Querying each group individually keeps every query on the
/// indexed, pre-sorted path: no sort, and no more than `offset + limit` rows read per group. The
/// (small, bounded) merge happens in Rust instead, which is cheap exactly because each input is
/// already sorted and the inputs are few.
async fn fetch_merged_page(
    db: &sea_orm::DatabaseConnection,
    condition: &Condition,
    group_ids: &[Uuid],
    offset: u64,
    limit: u64,
) -> Result<Vec<(ip_record_group_membership::Model, Option<ip_record::Model>)>, AppError> {
    let take = offset.saturating_add(limit);
    let mut merged = Vec::with_capacity(group_ids.len() * take as usize);
    for &group_id in group_ids {
        let scoped = condition.clone().add(ip_record_group_membership::Column::GroupId.eq(group_id));
        let rows = ip_record_group_membership::Entity::find()
            .join(JoinType::InnerJoin, ip_record_group_membership::Relation::IpRecord.def())
            .select_also(ip_record::Entity)
            .filter(scoped)
            .order_by_desc(ip_record_group_membership::Column::LastSeenAt)
            .limit(take)
            .all(db)
            .await?;
        merged.extend(rows);
    }
    merged.sort_by_key(|(m, _)| std::cmp::Reverse(m.last_seen_at));
    Ok(merged.into_iter().skip(offset as usize).take(limit as usize).collect())
}

/// Handles `GET /api/ips`: lists memberships, scoped to groups the caller may read.
pub async fn list_ips(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    StrictQuery(filters): StrictQuery<QueryFilters>,
) -> Result<impl IntoResponse, AppError> {
    let include_deleted = filters.include_deleted.unwrap_or(false);
    let format_iplist = matches!(filters.format.as_deref(), Some("iplist"))
        || matches!(filters.mode.as_deref(), Some("iplist"));
    let include_total = filters.include_total.unwrap_or(false) && !format_iplist;
    let limit = filters.limit.unwrap_or(50);
    let offset = filters.offset.unwrap_or(0);

    let mut condition = Condition::all();
    if !include_deleted {
        condition = condition.add(ip_record_group_membership::Column::IsDeleted.eq(false));
    }

    // Every group constraint — RBAC read scope, the group parameters, and status — is collected and
    // intersected, then applied once. A non-overlapping request is answered without a query.
    let mut group_constraints: Vec<std::collections::HashSet<Uuid>> = Vec::new();

    if !key.is_master {
        let accessible_groups: std::collections::HashSet<Uuid> = api_key_group_permission::Entity::find()
            .filter(
                Condition::all()
                    .add(api_key_group_permission::Column::ApiKeyId.eq(key.id))
                    .add(api_key_group_permission::Column::CanRead.eq(true))
            )
            .all(&state.db)
            .await?
            .into_iter()
            .map(|p| p.group_id)
            .collect();
        if accessible_groups.is_empty() {
            return Ok(empty_ips_response(format_iplist, include_total, limit, offset));
        }
        group_constraints.push(accessible_groups);
    }

    let mut group_names: Vec<String> = Vec::new();
    if let Some(groups) = &filters.groups
        && !groups.is_empty()
    {
        group_names.extend(groups.split(',').map(|s| s.trim().to_owned()).filter(|s| !s.is_empty()));
    }
    if let Some(name) = &filters.group_name {
        let trimmed = name.trim();
        if !trimmed.is_empty() {
            group_names.push(trimmed.to_owned());
        }
    }
    let mut gids: std::collections::HashSet<Uuid> = std::collections::HashSet::new();
    let mut group_filter_requested = false;
    if !group_names.is_empty() {
        group_filter_requested = true;
        gids.extend(
            ip_group::Entity::find()
                .filter(ip_group::Column::Name.is_in(group_names))
                .all(&state.db)
                .await?
                .into_iter()
                .map(|g| g.id),
        );
    }
    if let Some(gid) = filters.group_id {
        group_filter_requested = true;
        gids.insert(gid);
    }
    if group_filter_requested {
        group_constraints.push(gids);
    }

    if let Some(status) = &filters.status
        && !status.is_empty()
    {
        let group_type = match status.as_str() {
            "ban" | "banlist" => "banlist",
            "white" | "whitelist" => "whitelist",
            other => return Err(AppError::InvalidInput(format!("Invalid status filter: {other}"))),
        };
        let typed: std::collections::HashSet<Uuid> = ip_group::Entity::find()
            .filter(ip_group::Column::GroupType.eq(group_type))
            .all(&state.db)
            .await?
            .into_iter()
            .map(|g| g.id)
            .collect();
        group_constraints.push(typed);
    }

    // A small, explicit group set (RBAC scope intersected with `groups`/`group_id`/`status`) is
    // served as one indexed query per group instead of a single `GroupId IN (...)`. See
    // `fetch_merged_page`'s doc comment for why: SQLite's partial index sorts within one group_id,
    // not across several, so `IN (...)` with `ORDER BY last_seen_at` falls back to a full sort —
    // confirmed against this schema as the cause of the reported 56–91s multi-group query.
    let mut merge_group_ids: Option<Vec<Uuid>> = None;
    if !group_constraints.is_empty() {
        let mut intersected = group_constraints.pop().expect("just checked non-empty");
        for set in &group_constraints {
            intersected.retain(|g| set.contains(g));
        }
        if intersected.is_empty() {
            return Ok(empty_ips_response(format_iplist, include_total, limit, offset));
        }
        if intersected.len() > 1
            && intersected.len() <= MERGE_MAX_GROUPS
            && offset.saturating_add(limit) <= MERGE_MAX_FETCH
        {
            merge_group_ids = Some(intersected.into_iter().collect());
        } else {
            condition = condition.add(ip_record_group_membership::Column::GroupId.is_in(intersected));
        }
    }

    let address_filter_present = matches!(&filters.ip, Some(ip) if !ip.is_empty());
    if let Some(ip) = &filters.ip
        && !ip.is_empty()
    {
        condition = condition.add(ip_record::Column::TargetAddress.contains(normalize_ip_or_cidr(ip.trim())));
    }

    // A cause lives in the history table, so a cause filter selects memberships through a subquery
    // rather than a join: a membership matches if any cause it has ever had contains the text.
    if let Some(cause) = &filters.cause
        && !cause.is_empty()
    {
        let matching = Query::select()
            .column((ip_record_cause::Entity, ip_record_cause::Column::MembershipId))
            .from(ip_record_cause::Entity)
            .and_where(ip_record_cause::Column::Cause.contains(cause.trim()))
            .to_owned();
        condition = condition.add(
            Expr::col((ip_record_group_membership::Entity, ip_record_group_membership::Column::Id))
                .in_subquery(matching),
        );
    }

    if let Some(age) = filters.max_age {
        let threshold = Utc::now().naive_utc() - chrono::Duration::seconds(age);
        condition = condition.add(ip_record_group_membership::Column::LastSeenAt.gte(threshold));
    }

    if let Some(since) = filters.since {
        let threshold = chrono::DateTime::from_timestamp(since, 0)
            .ok_or_else(|| AppError::InvalidInput("Invalid `since` timestamp".to_owned()))?
            .naive_utc();
        let mut window = Condition::any()
            .add(ip_record_group_membership::Column::LastSeenAt.gte(threshold));
        if include_deleted {
            window = window.add(
                Condition::all()
                    .add(ip_record_group_membership::Column::IsDeleted.eq(true))
                    .add(ip_record_group_membership::Column::DeletedAt.gte(threshold)),
            );
        }
        condition = condition.add(window);
    }

    let total = if include_total {
        Some(count_matching(&state.db, &condition, address_filter_present, merge_group_ids.as_deref()).await?)
    } else {
        None
    };

    let page = match &merge_group_ids {
        Some(ids) => fetch_merged_page(&state.db, &condition, ids, offset, limit).await?,
        None => {
            ip_record_group_membership::Entity::find()
                .join(JoinType::InnerJoin, ip_record_group_membership::Relation::IpRecord.def())
                .select_also(ip_record::Entity)
                .filter(condition)
                .order_by_desc(ip_record_group_membership::Column::LastSeenAt)
                .limit(limit)
                .offset(offset)
                .all(&state.db)
                .await?
        }
    };

    if format_iplist {
        let mut ip_list: Vec<String> = page
            .into_iter()
            .filter_map(|(_, record)| record.map(|r| r.target_address))
            .collect();
        ip_list.sort();
        ip_list.dedup();
        return Ok(Json(serde_json::json!({ "ip_list": ip_list })).into_response());
    }

    // Resolve group names and the latest cause for the whole page in two queries, not one per row.
    let page_group_ids: Vec<Uuid> = page.iter().map(|(m, _)| m.group_id).collect();
    let groups: std::collections::HashMap<Uuid, ip_group::Model> = if page_group_ids.is_empty() {
        std::collections::HashMap::new()
    } else {
        ip_group::Entity::find()
            .filter(ip_group::Column::Id.is_in(page_group_ids))
            .all(&state.db)
            .await?
            .into_iter()
            .map(|g| (g.id, g))
            .collect()
    };
    let page_membership_ids: Vec<Uuid> = page.iter().map(|(m, _)| m.id).collect();
    let mut latest_cause: std::collections::HashMap<Uuid, String> = std::collections::HashMap::new();
    if !page_membership_ids.is_empty() {
        // Newest first, so the first row seen for a membership is its latest cause.
        for row in ip_record_cause::Entity::find()
            .filter(ip_record_cause::Column::MembershipId.is_in(page_membership_ids))
            .order_by_desc(ip_record_cause::Column::CreatedAt)
            .all(&state.db)
            .await?
        {
            latest_cause.entry(row.membership_id).or_insert(row.cause);
        }
    }

    let mut items = Vec::with_capacity(page.len());
    for (mem, record) in page {
        let Some(record) = record else { continue };
        let Some(group) = groups.get(&mem.group_id) else { continue };
        items.push(IpRecordResponse {
            id: mem.id,
            ip_record_id: record.id,
            target_address: record.target_address,
            group_name: group.name.clone(),
            group_type: group.group_type.clone(),
            cause: latest_cause.get(&mem.id).cloned(),
            is_locked: mem.is_locked,
            created_at: mem.created_at,
            last_seen_at: mem.last_seen_at,
            is_deleted: mem.is_deleted,
            deleted_at: mem.deleted_at,
            deleted_by: if key.is_master { mem.deleted_by } else { None },
        });
    }

    if let Some(total) = total {
        let total_pages = if limit == 0 { 0 } else { total.div_ceil(limit) };
        return Ok(Json(IpRecordsEnvelope { data: items, total, limit, offset, total_pages }).into_response());
    }
    Ok(Json(items).into_response())
}

// ─────────────────────────────────────────────────────────────
// Membership delete, restore, purge
// ─────────────────────────────────────────────────────────────

/// Identifies one membership by its address and its group.
///
/// Carried in the URL query, a JSON body, or both (query values win on overlap), so clients that
/// cannot send a body on `DELETE` still work. `deny_unknown_fields` so a typo is refused.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct MembershipRef {
    /// The address or CIDR range.
    pub target_address: Option<String>,
    /// The group, by ID. Provide this or `group_name`, not both.
    pub group_id: Option<Uuid>,
    /// The group, by name. Provide this or `group_id`, not both.
    pub group_name: Option<String>,
}

impl MembershipRef {
    fn merge(self, other: MembershipRef) -> MembershipRef {
        MembershipRef {
            target_address: self.target_address.or(other.target_address),
            group_id: self.group_id.or(other.group_id),
            group_name: self.group_name.or(other.group_name),
        }
    }
}

/// Query for `DELETE /api/ips`: the membership to delete, and whether to purge it outright.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DeleteIpQuery {
    /// The address or CIDR range.
    pub target_address: Option<String>,
    /// The group, by ID.
    pub group_id: Option<Uuid>,
    /// The group, by name.
    pub group_name: Option<String>,
    /// Master-only: remove the membership row outright instead of soft-deleting it.
    pub hard: Option<bool>,
}

/// Parses a [`MembershipRef`] from the query string and/or a JSON body.
fn membership_ref_from(query: MembershipRef, body: &axum::body::Bytes) -> Result<MembershipRef, AppError> {
    let from_body: MembershipRef = if body.is_empty() {
        MembershipRef::default()
    } else {
        serde_json::from_slice(body).map_err(|e| AppError::InvalidInput(format!("Invalid JSON body: {e}")))?
    };
    Ok(query.merge(from_body))
}

/// Resolves a membership from an address and a group reference, applying the same oracle rule as
/// every other lookup: an unknown address, an unknown group, and an address not in that group all
/// answer `404`.
async fn find_membership(
    db: &DatabaseTransaction,
    address: &str,
    group: &ip_group::Model,
) -> Result<(ip_record::Model, ip_record_group_membership::Model), AppError> {
    let record = ip_record::Entity::find()
        .filter(ip_record::Column::TargetAddress.eq(address))
        .one(db)
        .await?
        .ok_or(AppError::NotFound)?;
    let membership = ip_record_group_membership::Entity::find()
        .filter(ip_record_group_membership::Column::IpRecordId.eq(record.id))
        .filter(ip_record_group_membership::Column::GroupId.eq(group.id))
        .one(db)
        .await?
        .ok_or(AppError::NotFound)?;
    Ok((record, membership))
}

/// Handles `DELETE /api/ips`: soft-deletes one address's membership in one group.
///
/// Identified by `target_address` and the group, as a query, a JSON body, or both. Only this group's
/// membership is touched; the same address in any other group is unaffected. Non-masters soft-delete
/// only. `hard=true` is master-only and removes the membership row, along with the address row if no
/// group still holds it.
pub async fn delete_ip(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictQuery(query): StrictQuery<DeleteIpQuery>,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    let hard = query.hard.unwrap_or(false);
    let body_ref: DeleteIpQuery = if body.is_empty() {
        DeleteIpQuery::default()
    } else {
        serde_json::from_slice(&body).map_err(|e| AppError::InvalidInput(format!("Invalid JSON body: {e}")))?
    };
    let hard = hard || body_ref.hard.unwrap_or(false);
    let reference = MembershipRef {
        target_address: query.target_address.or(body_ref.target_address),
        group_id: query.group_id.or(body_ref.group_id),
        group_name: query.group_name.or(body_ref.group_name),
    };

    let target_address = reference
        .target_address
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::InvalidInput("target_address is required (query or JSON body)".to_owned()))?;
    let target_address = normalize_ip_or_cidr(&target_address);

    let group = resolve_group_ref(&state.db, reference.group_id, reference.group_name.as_deref())
        .await?
        .ok_or(AppError::NotFound)?;

    if !key.is_master {
        let perm = api_key_group_permission::Entity::find()
            .filter(
                Condition::all()
                    .add(api_key_group_permission::Column::ApiKeyId.eq(key.id))
                    .add(api_key_group_permission::Column::GroupId.eq(group.id))
            )
            .one(&state.db)
            .await?;
        match perm {
            Some(p) if !p.can_delete => {
                return Err(AppError::Forbidden("Permission denied: You do not have delete permissions over this group".to_owned()));
            }
            Some(_) => {}
            None => return Err(AppError::Forbidden("Permission denied".to_owned())),
        }
    }
    if hard && !key.is_master {
        return Err(AppError::Forbidden("Only a master key can permanently delete an IP membership".to_owned()));
    }

    let now = Utc::now().naive_utc();
    let txn = state
        .db
        .begin_with_options(TransactionOptions {
            sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
            ..Default::default()
        })
        .await?;

    let (record, membership) = find_membership(&txn, &target_address, &group).await?;
    if membership.is_locked {
        return Err(AppError::Forbidden("Protected records cannot be deleted".to_owned()));
    }

    if hard {
        ip_record_group_membership::Entity::delete_by_id(membership.id).exec(&txn).await?;
        // An address held by no group any more has nothing left to describe; remove it too.
        let remaining = ip_record_group_membership::Entity::find()
            .filter(ip_record_group_membership::Column::IpRecordId.eq(record.id))
            .count(&txn)
            .await?;
        if remaining == 0 {
            ip_record::Entity::delete_by_id(record.id).exec(&txn).await?;
        }
        create_audit_log(
            &txn,
            &key,
            client_ip.0,
            "IP_HARD_DELETE",
            Some(target_address.clone()),
            Some(group.name.clone()),
            Some("Permanently deleted".to_owned()),
        )
        .await?;
    } else if !membership.is_deleted {
        let mut active: ip_record_group_membership::ActiveModel = membership.into();
        active.is_deleted = Set(true);
        active.deleted_at = Set(Some(now));
        active.deleted_by = Set(Some(key.id.to_string()));
        active.update(&txn).await?;
        create_audit_log(
            &txn,
            &key,
            client_ip.0,
            "IP_SOFT_DELETE",
            Some(target_address.clone()),
            Some(group.name.clone()),
            Some(format!("Soft-deleted by key {}", format_key_reference(&key.name, key.id))),
        )
        .await?;
    } else {
        // Already in the trash: report success without moving `deleted_at`, so a repeat cannot
        // extend the retention window and keep the row out of the purge indefinitely.
        txn.commit().await?;
        return Ok(axum::http::StatusCode::NO_CONTENT);
    }

    txn.commit().await?;

    state.enqueue_webhook(WebhookEvent {
        action: "IP_DELETE".to_owned(),
        address: target_address,
        is_whitelist: group.group_type == "whitelist",
        group_id: Some(group.id),
        group_name: Some(group.name.clone()),
        cause: Some("Deleted via API".to_owned()),
    });

    Ok(axum::http::StatusCode::NO_CONTENT)
}

/// Handles `POST /api/ips/restore`: brings one soft-deleted membership back. Master only.
///
/// Identified by address and group, as a query, a JSON body, or both.
pub async fn restore_ip_record(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictQuery(query): StrictQuery<MembershipRef>,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden("Only a master key can restore a deleted IP membership".to_owned()));
    }
    let reference = membership_ref_from(query, &body)?;
    let target_address = reference
        .target_address
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::InvalidInput("target_address is required (query or JSON body)".to_owned()))?;
    let target_address = normalize_ip_or_cidr(&target_address);
    let group = resolve_group_ref(&state.db, reference.group_id, reference.group_name.as_deref())
        .await?
        .ok_or(AppError::NotFound)?;

    let txn = state
        .db
        .begin_with_options(TransactionOptions {
            sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
            ..Default::default()
        })
        .await?;
    let (_record, membership) = find_membership(&txn, &target_address, &group).await?;
    if !membership.is_deleted {
        return Err(AppError::InvalidInput("This IP membership is not deleted; nothing to restore".to_owned()));
    }
    let mut active: ip_record_group_membership::ActiveModel = membership.into();
    active.is_deleted = Set(false);
    active.deleted_at = Set(None);
    active.deleted_by = Set(None);
    active.update(&txn).await?;
    create_audit_log(
        &txn,
        &key,
        client_ip.0,
        "IP_RESTORE",
        Some(target_address.clone()),
        Some(group.name.clone()),
        Some("Restored from soft delete".to_owned()),
    )
    .await?;
    txn.commit().await?;

    Ok(Json(serde_json::json!({
        "target_address": target_address,
        "group_name": group.name,
        "is_deleted": false,
        "restored": true,
    })))
}

/// Body for [`purge_ip_records`]. Optional; an empty body uses the configured retention window.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PurgeIpsPayload {
    /// Override the retention window for this sweep only, in days. `0` is rejected: the destructive
    /// reading must never be the one a typo selects.
    pub older_than_days: Option<i64>,
}

/// Handles `POST /api/system/purge-ips`: permanently drops memberships soft-deleted past retention.
///
/// Master only and irreversible. Runs the same sweep as the background worker.
pub async fn purge_ip_records(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden("Only a master key can purge deleted IP memberships".to_owned()));
    }
    let payload: PurgeIpsPayload = if body.is_empty() {
        PurgeIpsPayload::default()
    } else {
        serde_json::from_slice(&body).map_err(|e| AppError::InvalidInput(format!("Invalid JSON body: {e}")))?
    };
    let retention_days = match payload.older_than_days {
        None => crate::retention::retention_days_from_env(),
        Some(days) if days > 0 => days,
        Some(days) => {
            return Err(AppError::InvalidInput(format!(
                "older_than_days must be a positive number of days, got {days}"
            )));
        }
    };
    let purged = crate::retention::purge_expired_ip_records(&state.db, retention_days).await?;
    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "IP_PURGE",
        None,
        None,
        Some(format!("Purged {purged} membership(s) soft-deleted over {retention_days} days ago")),
    )
    .await?;
    Ok(Json(serde_json::json!({
        "purged": purged,
        "retention_days": retention_days,
    })))
}

// ─────────────────────────────────────────────────────────────
// Batch synchronisation
// ─────────────────────────────────────────────────────────────

/// Largest batch accepted in one request. Bounds the single write transaction, which holds SQLite's
/// global write lock for its whole duration.
pub const MAX_BATCH_RECORDS: usize = 10_000;

/// How a batch reconciles against what is already in the group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BatchMode {
    /// Add and update the listed addresses, leaving everything else in the group alone.
    #[default]
    Upsert,
    /// Additionally soft-delete every live, unlocked membership in the group that the batch omits.
    FullReplace,
}

/// One address in a batch.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchRecordInput {
    /// The address or CIDR range. Canonicalised before use.
    pub target_address: String,
    /// A cause to append to this membership's history. Absent writes no history row.
    pub cause: Option<String>,
    /// Soft-delete state to apply to this membership.
    pub is_deleted: Option<bool>,
    /// When the address was first recorded, and when this membership was created if it is new.
    pub created_at: Option<chrono::NaiveDateTime>,
    /// Deprecated alias for `last_seen_at`, retained so existing sync clients keep working. Ignored
    /// when `last_seen_at` is present.
    pub updated_at: Option<chrono::NaiveDateTime>,
    /// The observation time for this membership. Defaults to now.
    pub last_seen_at: Option<chrono::NaiveDateTime>,
    /// Soft-delete timestamp. Only meaningful alongside `is_deleted: true`.
    pub deleted_at: Option<chrono::NaiveDateTime>,
}

/// Payload for `POST /api/records/batch`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchRecordsPayload {
    /// Target group by name. Created if absent and the caller may create groups.
    pub group_name: String,
    /// Reconciliation mode. Defaults to `upsert`.
    #[serde(default)]
    pub mode: BatchMode,
    /// The addresses. Duplicates after canonicalisation are refused.
    pub records: Vec<BatchRecordInput>,
    /// Suppresses webhook dispatch for every membership this batch touches.
    #[serde(default)]
    pub skip_webhooks: Option<bool>,
}

/// What a batch did, counted by outcome.
#[derive(Debug, Default, Serialize)]
pub struct BatchRecordsResponse {
    /// New canonical addresses created.
    pub created: u64,
    /// Existing memberships updated.
    pub updated: u64,
    /// Soft-deleted memberships brought back to live.
    pub restored: u64,
    /// Memberships left untouched because they are locked.
    pub locked_skipped: u64,
    /// Memberships soft-deleted because `full_replace` omitted them.
    pub soft_deleted: u64,
    /// New memberships created in the target group.
    pub linked: u64,
}

/// Handles `POST /api/records/batch`: synchronises many addresses into one group in one transaction.
///
/// Authorization: `upsert` needs `can_write` on the group; `full_replace` needs `can_write` and
/// `can_delete`, because it soft-deletes what it omits. Master bypasses the per-group check.
///
/// Atomic: the per-address work, the `full_replace` sweep and the audit row commit together or not
/// at all. Webhook events are buffered and sent only after the commit.
pub async fn batch_records(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictJson(payload): StrictJson<BatchRecordsPayload>,
) -> Result<impl IntoResponse, AppError> {
    if payload.records.len() > MAX_BATCH_RECORDS {
        return Err(AppError::InvalidInput(format!(
            "Batch too large: {} records, limit is {MAX_BATCH_RECORDS}. Split it and retry.",
            payload.records.len()
        )));
    }

    // Validate everything before taking the write lock.
    let mut normalized: Vec<(String, &BatchRecordInput)> = Vec::with_capacity(payload.records.len());
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for record in &payload.records {
        let _network: IpNetwork = record.target_address.parse().map_err(|_| {
            AppError::InvalidInput(format!("Invalid IP or CIDR format: {:?}", record.target_address))
        })?;
        let address = normalize_ip_or_cidr(&record.target_address);
        if !seen.insert(address.clone()) {
            return Err(AppError::InvalidInput(format!(
                "Duplicate target_address in batch after canonicalisation: {address}"
            )));
        }
        normalized.push((address, record));
    }

    let existing = ip_group::Entity::find()
        .filter(ip_group::Column::Name.eq(payload.group_name.clone()))
        .one(&state.db)
        .await?;
    let group = match existing {
        Some(g) => {
            if !key.is_master {
                let perm = api_key_group_permission::Entity::find()
                    .filter(
                        Condition::all()
                            .add(api_key_group_permission::Column::ApiKeyId.eq(key.id))
                            .add(api_key_group_permission::Column::GroupId.eq(g.id)),
                    )
                    .one(&state.db)
                    .await?
                    .ok_or_else(|| {
                        AppError::Forbidden("Permission denied: You have no access strictly mapped to this group".to_owned())
                    })?;
                if !perm.can_write {
                    return Err(AppError::Forbidden("Permission denied: You do not have write access to this group".to_owned()));
                }
                if payload.mode == BatchMode::FullReplace && !perm.can_delete {
                    return Err(AppError::Forbidden(
                        "Permission denied: mode 'full_replace' soft-deletes the memberships it omits and therefore requires delete access to this group, not only write access"
                            .to_owned(),
                    ));
                }
            }
            g
        }
        None => {
            if !key.is_master && !key.can_create_groups {
                return Err(AppError::Forbidden(
                    "Permission denied: Target group does not exist and you cannot create groups".to_owned(),
                ));
            }
            get_or_create_group(&state.db, &payload.group_name, "banlist", resource_owner(&key)).await?
        }
    };

    if group.group_type != "whitelist" {
        for (address, _) in &normalized {
            let network: IpNetwork = address
                .parse()
                .map_err(|_| AppError::InvalidInput(format!("Invalid IP or CIDR format: {address}")))?;
            guard_bannable_address(&network)?;
        }
    }

    let now = Utc::now().naive_utc();
    let txn = state
        .db
        .begin_with_options(TransactionOptions {
            sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
            ..Default::default()
        })
        .await?;
    let mut summary = BatchRecordsResponse::default();
    let skip_webhooks = payload.skip_webhooks.unwrap_or(false);
    let mut webhook_events: Vec<WebhookEvent> = Vec::new();

    for (address, input) in &normalized {
        let (record, record_is_new) = find_or_insert_address(&txn, address, input.created_at.unwrap_or(now)).await?;
        if record_is_new {
            summary.created += 1;
        }

        let existing = ip_record_group_membership::Entity::find()
            .filter(ip_record_group_membership::Column::IpRecordId.eq(record.id))
            .filter(ip_record_group_membership::Column::GroupId.eq(group.id))
            .one(&txn)
            .await?;

        let observed_at = input.last_seen_at.or(input.updated_at).unwrap_or(now);
        let (membership_id, action) = match existing {
            Some(m) if m.is_locked => {
                summary.locked_skipped += 1;
                continue;
            }
            Some(m) => {
                let was_deleted = m.is_deleted;
                let id = m.id;
                let mut active: ip_record_group_membership::ActiveModel = m.into();
                active.last_seen_at = Set(observed_at);
                match input.is_deleted {
                    Some(true) => {
                        active.is_deleted = Set(true);
                        active.deleted_at = Set(Some(input.deleted_at.unwrap_or(now)));
                        active.deleted_by = Set(Some(key.id.to_string()));
                    }
                    _ if was_deleted => {
                        active.is_deleted = Set(false);
                        active.deleted_at = Set(None);
                        active.deleted_by = Set(None);
                        summary.restored += 1;
                    }
                    _ => {}
                }
                active.update(&txn).await?;
                summary.updated += 1;
                (id, "IP_UPDATE")
            }
            None => {
                let id = Uuid::new_v4();
                let deleted = input.is_deleted == Some(true);
                ip_record_group_membership::ActiveModel {
                    id: Set(id),
                    ip_record_id: Set(record.id),
                    group_id: Set(group.id),
                    is_locked: Set(false),
                    created_at: Set(input.created_at.unwrap_or(now)),
                    last_seen_at: Set(observed_at),
                    is_deleted: Set(deleted),
                    deleted_at: Set(if deleted { Some(input.deleted_at.unwrap_or(now)) } else { None }),
                    deleted_by: Set(if deleted { Some(key.id.to_string()) } else { None }),
                }
                .insert(&txn)
                .await?;
                summary.linked += 1;
                (id, "IP_ADD")
            }
        };

        if let Some(text) = input.cause.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
            ip_record_cause::ActiveModel {
                id: Set(Uuid::new_v4()),
                membership_id: Set(membership_id),
                cause: Set(text.to_owned()),
                created_at: Set(now),
            }
            .insert(&txn)
            .await?;
        }

        if !skip_webhooks {
            webhook_events.push(WebhookEvent {
                action: action.to_owned(),
                address: address.clone(),
                is_whitelist: group.group_type == "whitelist",
                group_id: Some(group.id),
                group_name: Some(group.name.clone()),
                cause: input.cause.clone(),
            });
        }
    }

    // full_replace: soft-delete this group's live, unlocked memberships that the batch omits.
    if payload.mode == BatchMode::FullReplace {
        let candidates = ip_record_group_membership::Entity::find()
            .join(JoinType::InnerJoin, ip_record_group_membership::Relation::IpRecord.def())
            .select_also(ip_record::Entity)
            .filter(
                Condition::all()
                    .add(ip_record_group_membership::Column::GroupId.eq(group.id))
                    .add(ip_record_group_membership::Column::IsDeleted.eq(false))
                    // A lock is an administrative guarantee a remote sync must not clear.
                    .add(ip_record_group_membership::Column::IsLocked.eq(false)),
            )
            .all(&txn)
            .await?;
        for (membership, record) in candidates {
            let Some(record) = record else { continue };
            if seen.contains(&record.target_address) {
                continue;
            }
            let swept_address = record.target_address;
            let mut active: ip_record_group_membership::ActiveModel = membership.into();
            active.is_deleted = Set(true);
            active.deleted_at = Set(Some(now));
            active.deleted_by = Set(Some(key.id.to_string()));
            active.update(&txn).await?;
            summary.soft_deleted += 1;
            if !skip_webhooks {
                webhook_events.push(WebhookEvent {
                    action: "IP_DELETE".to_owned(),
                    address: swept_address,
                    is_whitelist: group.group_type == "whitelist",
                    group_id: Some(group.id),
                    group_name: Some(group.name.clone()),
                    cause: Some("Removed via batch full_replace synchronisation".to_owned()),
                });
            }
        }
    }

    create_audit_log(
        &txn,
        &key,
        client_ip.0,
        "batch_records_updated",
        None,
        Some(group.name.clone()),
        Some(format!(
            "mode={} submitted={} created={} updated={} restored={} locked_skipped={} soft_deleted={}",
            match payload.mode {
                BatchMode::Upsert => "upsert",
                BatchMode::FullReplace => "full_replace",
            },
            normalized.len(),
            summary.created,
            summary.updated,
            summary.restored,
            summary.locked_skipped,
            summary.soft_deleted,
        )),
    )
    .await?;

    txn.commit().await?;

    for event in webhook_events {
        state.enqueue_webhook(event);
    }

    tracing::info!(
        group = %group.name,
        created = summary.created,
        updated = summary.updated,
        soft_deleted = summary.soft_deleted,
        locked_skipped = summary.locked_skipped,
        skip_webhooks,
        "Batch record synchronisation committed"
    );

    Ok(Json(summary))
}
