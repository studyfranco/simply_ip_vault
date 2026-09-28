//! IP record endpoints: ban/white, listing, soft delete, restore, and purge.
//!
//! The specification's *resource data* — records live inside IP Groups and inherit their
//! authorization from the group's permission row rather than carrying one of their own.

use axum::{Extension, extract::{Json, State}, response::IntoResponse};
use chrono::Utc;
use ipnetwork::IpNetwork;
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, Condition, EntityTrait, JoinType,
    QueryFilter, QueryOrder, QuerySelect, RelationTrait, SqliteTransactionMode,
    TransactionOptions, TransactionTrait, sea_query::{Expr, Func, OnConflict}, SqlErr,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::{
    api_key, api_key_group_permission, ip_group, ip_record, ip_record_group_membership,
};
use crate::error::AppError;
use crate::extract::{StrictJson, StrictPath, StrictQuery};
use crate::middleware::ClientIp;
use crate::state::{AppState, WebhookEvent};

use super::{
    create_audit_log, format_key_reference, get_or_create_group, normalize_ip_or_cidr,
    resolve_group_ref, resource_owner,
};

// ─────────────────────────────────────────────────────────────
// IP Ban / Whitelist
// ─────────────────────────────────────────────────────────────

/// Payload for banning or whitelisting an IP address. `deny_unknown_fields` so a typo'd or
/// stale field is refused rather than silently dropped.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BanWhitePayload {
    /// The target IP address or CIDR range
    pub target_address: String,
    /// The group to associate the IP with, by ID. Provide this or `group_name`, not both.
    pub group_id: Option<Uuid>,
    /// The group to associate the IP with, by name. Provide this or `group_id`, not both. Unlike
    /// `group_id`, a name that doesn't exist yet may be auto-created (permission allowing).
    pub group_name: Option<String>,
    /// The reason for the ban or whitelist
    pub cause: Option<String>,
}


/// Handles POST /api/v1/ban to add an IP to a banlist group
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
/// from itself.
///
/// **Extracted so the batch endpoint cannot bypass it.** It was inline in [`handle_ip_upsert`], which
/// meant a second write path — exactly what `POST /api/records/batch` is — would have silently
/// accepted what the single-record path refuses. A validation rule enforced at one of two entrances
/// is not a validation rule; it is a speed bump on the door people happen to use.
///
/// Whitelists are exempt by construction: this is only called for banlist targets, since whitelisting
/// a private range is the ordinary reason to have a whitelist at all.
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




/// Handles POST /api/v1/white to add an IP to a whitelist group
pub async fn handle_white(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictJson(payload): StrictJson<BanWhitePayload>,
) -> Result<impl IntoResponse, AppError> {
    handle_ip_upsert(state, key, client_ip.0, payload, true).await
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
    // Canonicalized once, up front, and used for every lookup/storage/event below instead of the
    // raw client-submitted string — otherwise "X/32" and "X" would be treated as different
    // addresses (two ip_records rows, a "not found" on delete, etc.) despite meaning the same
    // thing.
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

        // Group-type validation runs strictly AFTER the RBAC check above (and unconditionally,
        // even for master keys, which bypass that check but not this one): a caller with no
        // access to the group must learn nothing about it — including its type — via a 400
        // instead of the 403 they should actually get.
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
        // group_id (if given) is never auto-creatable — only reachable here when group_name was
        // supplied instead, since resolve_group_ref requires exactly one of the two.
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
                // Auto-provisioning confers read/write/delete and nothing more, per `AGENT.MD` §2.
                // `can_manage` is administrative authority over other keys' rows, so it stays an
                // explicit grant from someone who already holds it rather than something a key
                // awards itself as a side effect of creating a group.
                can_manage: Set(false),
                created_at: Set(now),
            };
            // on_conflict do_nothing: a concurrent burst from this same key racing to create the
            // same new group would otherwise hit the (api_key_id, group_id) unique index here too.
            api_key_group_permission::Entity::insert(perm)
                .on_conflict(
                    OnConflict::columns([api_key_group_permission::Column::ApiKeyId, api_key_group_permission::Column::GroupId])
                        .do_nothing()
                        .to_owned()
                )
                .exec_without_returning(&state.db)
                .await?;
        }
    } else {
        // group_id was supplied but doesn't match any existing group. Unlike group_name, an ID
        // is never something a client can legitimately invent, so there's nothing to create.
        return Err(AppError::NotFound);
    }

    let now = Utc::now().naive_utc();
    let record_id: Uuid;

    // The record upsert, the membership insert, and the audit log write used to be three separate
    // round trips against the pool — each its own implicit transaction, each its own write-lock
    // acquisition. Under concurrent load that is three chances to queue behind another writer
    // instead of one, which is what production logs described as 1-2s on a "simple" insert: not
    // slow disk I/O on any single statement, but three serialized lock waits stacked into one
    // request. Combined into one transaction here, the same logical operation takes the write lock
    // once.
    //
    // `Immediate` rather than a plain `begin()` (SQLite's default `BEGIN DEFERRED`), mirroring
    // `batch_records`' own reasoning: the loop below reads before it writes (a `SELECT` per
    // attempt, ahead of that attempt's own `INSERT`/`UPDATE`), and a deferred transaction only
    // takes its read snapshot at that first `SELECT` — a concurrent writer committing between this
    // transaction's first read and its first write would leave the snapshot stale, and SQLite
    // refuses to upgrade a stale snapshot to a write lock (`SQLITE_BUSY` immediately, without ever
    // invoking the `busy_timeout` handler that retries ordinary contention). `Immediate` takes the
    // write lock up front, before the first read, so there is no snapshot left to go stale.
    let txn = state
        .db
        .begin_with_options(TransactionOptions {
            sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
            ..Default::default()
        })
        .await?;

    // find-then-insert races under true concurrency: two requests can both see no existing
    // record and both attempt to insert the same (unique) target_address. Rather than trying to
    // cram the is_locked check and "only overwrite cause if provided" semantics into a single
    // atomic ON CONFLICT DO UPDATE, retry as a normal update on the one specific, portably
    // detectable failure mode that means "a concurrent request just won this race": a unique
    // constraint violation on the insert. Effectively unreachable now that the whole operation
    // holds an `Immediate` write lock from the start — a second writer queues for that lock rather
    // than interleaving with this one — but kept as defensive handling rather than deleted, since
    // nothing about this loop's own correctness depended on the transaction wrapping to be right.
    loop {
        let existing_record = ip_record::Entity::find()
            .filter(ip_record::Column::TargetAddress.eq(normalized_address.clone()))
            .one(&txn)
            .await?;

        if let Some(record) = existing_record {
            if record.is_locked {
                return Err(AppError::Forbidden("This IP is protected and cannot be modified".to_owned()));
            }

            // Re-registering a soft-deleted address resurrects it. The alternative — refusing, or
            // silently re-adding a row that stays hidden — would make `target_address`'s unique
            // constraint into a denial: an address someone deleted last week could never be banned
            // again until a master emptied the trash. The deletion metadata is cleared so the
            // record is indistinguishable from one that was never deleted, and its 92-day
            // retention clock does not keep running against a now-live record.
            let was_deleted = record.is_deleted;

            let mut active_rec: ip_record::ActiveModel = record.into();
            active_rec.last_seen_at = Set(now);
            active_rec.updated_at = Set(now);
            if was_deleted {
                active_rec.is_deleted = Set(false);
                active_rec.deleted_at = Set(None);
                active_rec.deleted_by = Set(None);
            }
            if let Some(c) = &payload.cause {
                active_rec.cause = Set(Some(c.clone()));
            }
            let updated = active_rec.update(&txn).await?;
            record_id = updated.id;
            if was_deleted {
                tracing::info!(
                    address = %normalized_address,
                    "Re-registration restored a soft-deleted IP record"
                );
            }
            break;
        }

        let new_id = Uuid::new_v4();
        let model = ip_record::ActiveModel {
            id: Set(new_id),
            target_address: Set(normalized_address.clone()),
            cause: Set(payload.cause.clone()),
            is_locked: Set(false),
            created_at: Set(now),
            updated_at: Set(now),
            last_seen_at: Set(now),
            is_deleted: Set(false),
            deleted_at: Set(None),
            deleted_by: Set(None),
        };
        match ip_record::Entity::insert(model).exec(&txn).await {
            Ok(_) => {
                record_id = new_id;
                break;
            }
            Err(err) if matches!(err.sql_err(), Some(SqlErr::UniqueConstraintViolation(_))) => {
                continue;
            }
            Err(err) => return Err(err.into()),
        }
    }

    // Read before the write, not inferred from an affected-row count: the membership row now
    // carries its own `created_at`/`updated_at` (`m20260926_120000`), and the upsert below always
    // touches a row — insert *or* update — so `exec_without_returning`'s row count can no longer
    // distinguish the two the way a `DO NOTHING` conflict used to. An explicit read is also what
    // lets `created_at` survive a re-registration into the same group: it is set only on the insert
    // branch and never included in the conflict's `update_column` list below.
    let membership_is_new = ip_record_group_membership::Entity::find_by_id((record_id, target_group_id))
        .one(&txn)
        .await?
        .is_none();

    let mem = ip_record_group_membership::ActiveModel {
        ip_record_id: Set(record_id),
        group_id: Set(target_group_id),
        created_at: Set(now),
        updated_at: Set(now),
    };
    // Upsert, not `DO NOTHING`: a re-registration into a group the address already belongs to is a
    // real touch of *that group's* membership and must advance its `updated_at` — the whole point
    // of moving these columns onto the membership row in the first place (see the migration's
    // module comment). `created_at` is deliberately absent from `update_column`, so a conflict
    // leaves it exactly as first recorded.
    ip_record_group_membership::Entity::insert(mem)
        .on_conflict(
            OnConflict::columns([ip_record_group_membership::Column::IpRecordId, ip_record_group_membership::Column::GroupId])
                .update_column(ip_record_group_membership::Column::UpdatedAt)
                .to_owned()
        )
        .exec_without_returning(&txn)
        .await?;

    // Deliberately keyed off the *membership* being new, not the underlying `ip_record` row: an
    // address already banned in Group A that now also gets added to Group B is an `IP_ADD` from
    // Group B's perspective (and Group B's webhooks) even though the `ip_record` row itself
    // already existed — only a re-registration into a group it's *already* a member of is a true
    // `IP_UPDATE`.
    let action = if membership_is_new { "IP_ADD" } else { "IP_UPDATE" };

    create_audit_log(
        &txn,
        &key,
        client_ip,
        action,
        Some(normalized_address.clone()),
        Some(resolved_group_name.clone()),
        Some(format!("Added IP to group. Whitelist: {}", is_whitelist))
    ).await?;

    // Committed before the webhook event is enqueued below — a webhook must never fire (or, worse,
    // a receiver act) for a record that a rolled-back transaction means was never actually banned.
    txn.commit().await?;

    let event = WebhookEvent {
        action: action.to_owned(),
        address: normalized_address,
        is_whitelist,
        group_id: Some(target_group_id),
        group_name: Some(resolved_group_name),
        cause: payload.cause,
    };
    state.enqueue_webhook(event);

    Ok(axum::http::StatusCode::OK)
}


// ─────────────────────────────────────────────────────────────
// IP Record Listing & Deletion
// ─────────────────────────────────────────────────────────────

/// Query parameters for IP listing. `deny_unknown_fields` so a misspelled filter (`groups_name`
/// for `group_name`) is refused with `400` rather than silently matching everything.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryFilters {
    /// Filter by groups (comma-separated group names)
    pub groups: Option<String>,
    /// Filter by a single group name (in addition to `groups`)
    pub group_name: Option<String>,
    /// Filter by a single group ID (in addition to `groups`/`group_name`)
    pub group_id: Option<Uuid>,
    /// Filter by a substring of the target address
    pub ip: Option<String>,
    /// Filter by a substring of the cause
    pub cause: Option<String>,
    /// Filter by group type: `ban`/`banlist` or `white`/`whitelist`
    pub status: Option<String>,
    /// Maximum age in seconds, based on `last_seen_at`
    pub max_age: Option<i64>,
    /// Differential-sync cutoff, as a Unix timestamp in seconds.
    ///
    /// A record is in scope when **either** its `last_seen_at` is at or after the cutoff, **or** —
    /// with `include_deleted=true` — it was soft-deleted at or after it. Both arms are needed: soft
    /// delete does not move `last_seen_at`, so a record last seen before the cutoff and deleted
    /// after it would otherwise be invisible, and its deletion unreplicable *forever* (see the
    /// filter's own comment in `list_ips`).
    ///
    /// Poll with the timestamp of the previous response to receive additions, re-registrations and
    /// tombstones since then, and nothing already delivered.
    pub since: Option<i64>,
    /// Pagination limit
    pub limit: Option<u64>,
    /// Pagination offset
    pub offset: Option<u64>,
    /// When set to `"iplist"` (accepted under either query key), returns a lightweight
    /// `{"ip_list": [...]}` payload of just the matched addresses instead of full records.
    pub format: Option<String>,
    /// Synonym for `format` — `format=iplist` and `mode=iplist` are both accepted.
    pub mode: Option<String>,
    /// Also return soft-deleted records (the "trash" view).
    ///
    /// **Available to any caller, scoped exactly as live records are.** A non-master sees soft-deleted
    /// records only inside groups it holds `can_read` on, because the same `accessible_groups` filter
    /// that bounds the live listing bounds this one — there is no separate code path for deleted rows
    /// to escape through. Master sees everything.
    ///
    /// Requesting a group the caller cannot read is **not an error**. It contributes nothing to the
    /// result, exactly as a group that does not exist would. That is `RBAC_MODEL.md` §4 oracle
    /// discipline: answering `403` here would tell an unauthorised caller that the group exists,
    /// which is precisely the distinction §4 forbids a caller from drawing.
    pub include_deleted: Option<bool>,
    /// Wrap the response in a `{"data": [...], "total": ..., "limit": ..., "offset": ...,
    /// "total_pages": ...}` envelope instead of returning the bare array. `false`/omitted (the
    /// default) keeps the historical root-array shape, so an existing client that expects `[...]`
    /// is unaffected by this parameter's existence. Ignored under `format=iplist`/`mode=iplist`,
    /// which has its own fixed `{"ip_list": [...]}` shape.
    pub include_total: Option<bool>,
}


/// Response payload for a single IP record
#[derive(Serialize)]
pub struct IpRecordResponse {
    /// IP Record ID
    pub id: Uuid,
    /// Target address
    pub target_address: String,
    /// Associated group name
    pub group_name: String,
    /// Associated group type (`banlist` or `whitelist`)
    pub group_type: String,
    /// Cause for addition
    pub cause: Option<String>,
    /// Lock status
    pub is_locked: bool,
    /// When this record was linked into **this row's group** (`ip_record_group_memberships.created_at`,
    /// `m20260926_120000`) — not when the underlying address was first ever seen anywhere, which can
    /// be much earlier for an address that already belonged to another group. An address in three
    /// groups has one `ip_records` row but three distinct membership rows, and each carries its own
    /// history; this is that group's own.
    pub created_at: chrono::NaiveDateTime,
    /// When this record was last re-registered **into this row's group specifically**
    /// (`ip_record_group_memberships.updated_at`). Re-registering the same address into a
    /// *different* group does not advance this field — that is the property it exists to provide.
    /// Before `m20260926_120000` this field echoed the shared `ip_records.updated_at`, which made
    /// every group an address belonged to look freshly touched whenever *any* of them was, and made
    /// `since`-based delta sync (below) report spurious changes to groups nothing happened in.
    pub updated_at: chrono::NaiveDateTime,
    /// Last seen at — the underlying address's own freshness, **not** scoped to this group. Used by
    /// `max_age`, which is deliberately an address-wide question ("is this address still active
    /// anywhere") rather than a per-membership one; unlike `created_at`/`updated_at` above, this
    /// field is unaffected by which group re-registered the address.
    pub last_seen_at: chrono::NaiveDateTime,
    /// Whether the record is soft-deleted. Always `false` in a normal listing; `true` only appears
    /// under `include_deleted=true`.
    ///
    /// Emitted unconditionally rather than skipped when false: a delta-sync consumer needs to
    /// distinguish "this record is live" from "this field was omitted", and a tombstone that
    /// serialises identically to a live row is useless for replication.
    pub is_deleted: bool,
    /// When it was soft-deleted, if it was. Naive UTC, like every other timestamp on this type.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_at: Option<chrono::NaiveDateTime>,
    /// Which API key soft-deleted it — **Master only**.
    ///
    /// The column stores a raw key id. `RBAC_MODEL.md` §4 limits what one key may learn about another
    /// to id, name and rights *on a shared resource*, and nothing entitles a group reader to the
    /// identity of an unrelated key. Widening `include_deleted` to non-masters must not smuggle that
    /// out as a side effect, so it is `None` for every non-master caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_by: Option<String>,
}


/// Response envelope for `GET /api/ips?include_total=true`.
///
/// Opt-in via `include_total` rather than the default shape: the root array `[...]` is this
/// endpoint's contract since before pagination metadata existed, and every exporter/sync worker
/// polling it expects to deserialize a bare list. Switching the default would break every one of
/// them silently; requiring the flag makes the wider shape something a client asks for.
#[derive(Serialize)]
pub struct IpRecordsEnvelope {
    /// The page of records, identical in shape and ordering to the bare-array response.
    pub data: Vec<IpRecordResponse>,
    /// Total records matching every filter *except* `limit`/`offset` — i.e. across all pages, not
    /// just this one. Scoped by the same RBAC/group filtering as `data`.
    pub total: u64,
    /// Echoes the effective `limit` this response was paginated with.
    pub limit: u64,
    /// Echoes the effective `offset` this response was paginated with.
    pub offset: u64,
    /// `ceil(total / limit)`, or `0` when `total` is `0` or `limit` is `0` (there is nothing, or
    /// no page size to divide it by, either way no page count to report).
    pub total_pages: u64,
}


/// The empty-result shape for [`list_ips`], in whichever response form the caller asked for.
///
/// Shared by every early return that already knows the answer is "nothing" before a data query
/// ever runs — a non-master with no readable groups at all, or a set of group filters that
/// intersect to nothing — so the three response shapes (`iplist`, the `include_total` envelope,
/// the bare array) can never drift out of sync with what the equivalent non-empty response looks
/// like for the same request.
fn empty_ips_response(format_iplist: bool, include_total: bool, limit: u64, offset: u64) -> axum::response::Response {
    if format_iplist {
        return Json(serde_json::json!({ "ip_list": Vec::<String>::new() })).into_response();
    }
    if include_total {
        return Json(IpRecordsEnvelope { data: Vec::new(), total: 0, limit, offset, total_pages: 0 }).into_response();
    }
    Json(Vec::<IpRecordResponse>::new()).into_response()
}

/// Handles GET /api/v1/ips to list IP records
pub async fn list_ips(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    StrictQuery(filters): StrictQuery<QueryFilters>,
) -> Result<impl IntoResponse, AppError> {

    // Manual join fetching because of M:N
    let query = ip_record_group_membership::Entity::find()
        .find_also_related(ip_record::Entity);

    // Soft-deleted records are excluded unless the caller asks for them. Applied here, before every
    // other filter, so no later branch can accidentally reintroduce them — including the `iplist`
    // export format, which shares this query.
    //
    // The flag is **not** master-gated. It used to be, and the restriction bought nothing: the
    // group-scoping filter below already confines a non-master to the groups it holds `can_read` on,
    // and a soft-deleted row in a group you may read is not more sensitive than a live one in the
    // same group. Gating the flag instead of the rows made the trash view unavailable to the
    // delta-sync consumers that need it — an exporter cannot replicate deletions it cannot see.
    //
    // What is *not* done here is equally deliberate: no caller is refused for naming a group it
    // cannot read. Such a group simply contributes nothing, exactly as a nonexistent one would.
    // Refusing would turn this endpoint into an existence oracle over group names, which §4 forbids.
    // Resolved up front so every early return below can build the same response shape the normal
    // path would, instead of forcing the caller through a second request just to learn the page
    // size or format it already asked for.
    let include_deleted = filters.include_deleted.unwrap_or(false);
    let format_iplist = matches!(filters.format.as_deref(), Some("iplist"))
        || matches!(filters.mode.as_deref(), Some("iplist"));
    let include_total = filters.include_total.unwrap_or(false) && !format_iplist;
    let limit = filters.limit.unwrap_or(50);
    let offset = filters.offset.unwrap_or(0);

    // Every filter below is accumulated into one `Condition` instead of chained onto `query`
    // directly, so the exact same condition can be applied to both the data query and (when
    // `include_total` asks for one) the count query further down. Two independently maintained
    // `.filter()` chains covering "the same" rows is exactly how a count and the page it describes
    // drift apart over time — sharing one `Condition` makes that impossible by construction rather
    // than by discipline.
    let mut condition = Condition::all();

    if !include_deleted {
        condition = condition.add(ip_record::Column::IsDeleted.eq(false));
    }

    // Every `group_id` constraint — RBAC read-scoping, the `groups`/`group_name`/`group_id`
    // params, and `status` — is collected as its own set here and intersected in Rust, rather than
    // chained onto the query as separate `IN (...)` clauses on the same column. Both forms are
    // correct SQL (ANDing several `IN` clauses on one column *is* their intersection), but a
    // caller can supply more than one of these at once, and computing the intersection here —
    // rather than asking the query planner to discover it during execution — means a request whose
    // accessible groups and requested groups don't overlap gets answered without touching the
    // database at all, the same shortcut the "no accessible groups" case below already took.
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

    // `groups` (comma-separated) and `group_name` (single) both narrow by group name.
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
    // `group_id` narrows the same way, just by ID instead of by name; combined with any
    // name-based matches above using OR semantics (both are just ways to pick "these groups").
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
        let gids: std::collections::HashSet<Uuid> = ip_group::Entity::find()
            .filter(ip_group::Column::GroupType.eq(group_type))
            .all(&state.db)
            .await?
            .into_iter()
            .map(|g| g.id)
            .collect();
        group_constraints.push(gids);
    }

    if !group_constraints.is_empty() {
        // Popping the first set as the accumulator and retaining against the rest computes the
        // intersection of all of them without an extra allocation per constraint.
        let mut intersected = group_constraints.pop().expect("just checked non-empty");
        for set in &group_constraints {
            intersected.retain(|g| set.contains(g));
        }
        if intersected.is_empty() {
            return Ok(empty_ips_response(format_iplist, include_total, limit, offset));
        }
        condition = condition.add(ip_record_group_membership::Column::GroupId.is_in(intersected));
    }

    if let Some(ip) = &filters.ip
        && !ip.is_empty()
    {
        // Best-effort: if the filter value happens to be a full, parseable address/CIDR (e.g. a
        // caller pastes "188.190.74.128/32" to look up a record stored as the bare host form),
        // normalize it so the substring match still finds it. A genuine partial fragment like
        // "74.128" doesn't parse and passes through unchanged, preserving substring search.
        condition = condition.add(ip_record::Column::TargetAddress.contains(normalize_ip_or_cidr(ip.trim())));
    }

    if let Some(cause) = &filters.cause
        && !cause.is_empty()
    {
        condition = condition.add(ip_record::Column::Cause.contains(cause.trim()));
    }

    if let Some(age) = filters.max_age {
        let threshold = Utc::now().naive_utc() - chrono::Duration::seconds(age);
        condition = condition.add(ip_record::Column::LastSeenAt.gte(threshold));
    }

    // The differential-sync cutoff. Two columns can put a record in scope, and using only one was a
    // bug that made deletions unreplicable — see below.
    //
    // The primary arm reads the **membership's own** `updated_at` (`m20260926_120000`), not the
    // shared `ip_records.updated_at` it used to: an address re-registered into Group A must not
    // look changed to a consumer polling `since=` scoped to Group B, since nothing about Group B's
    // membership happened. Re-registering into a group the address already belongs to advances
    // that *same* group's membership `updated_at` (see `handle_ip_upsert`'s upsert), so a poll
    // scoped to that group still sees the change exactly as before — only the cross-group leak is
    // closed.
    //
    // The deletion arm is unchanged and still reads `ip_records.deleted_at`: a soft delete removes
    // the address from *every* group's view at once (`RBAC_MODEL.md`/`AGENT.MD` §3's soft-delete
    // lifecycle is a whole-record operation, not a per-membership one — see `delete_ip_record`), so
    // the tombstone is correctly a record-level, not membership-level, event. Before this migration
    // the deletion arm was also the one that made a delta-sync consumer's `last_seen_at`-based
    // primary arm insufficient on its own: soft delete deliberately does not touch `last_seen_at`
    // (a delete is not a re-sighting), so an address last seen at T0 and deleted at T1 would fail
    // `last_seen_at >= since` for every cutoff after T0, and — since `last_seen_at` only moves
    // forward on re-registration, which by definition never happens to a deleted record — no later
    // poll could ever correct that either. So a record is in scope when **either** arm crosses the
    // cutoff. The deletion arm stays gated on `include_deleted`, same as before: without the flag a
    // tombstone must stay invisible exactly as it does in an unfiltered listing, and matching on
    // `deleted_at` there would leak the trash into ordinary reads for anyone who passed `since`.
    if let Some(since) = filters.since {
        let threshold = chrono::DateTime::from_timestamp(since, 0)
            .ok_or_else(|| AppError::InvalidInput("Invalid `since` timestamp".to_owned()))?
            .naive_utc();

        let mut window = Condition::any().add(ip_record_group_membership::Column::UpdatedAt.gte(threshold));
        if include_deleted {
            window = window.add(
                Condition::all()
                    // `deleted_at >= threshold` alone would already exclude live rows, since NULL
                    // compares as unknown rather than true. The flag is named anyway: it says what
                    // this arm is *for*, and it lets the engine use `idx_ip_records_is_deleted`.
                    .add(ip_record::Column::IsDeleted.eq(true))
                    .add(ip_record::Column::DeletedAt.gte(threshold)),
            );
        }
        condition = condition.add(window);
    }

    // Count and page share one transaction whenever both are needed, so a write landing between
    // the two queries cannot make `total` describe a different snapshot than `data` does. A plain
    // (deferred) transaction takes no lock for read-only statements, so this only costs one held
    // connection across two round trips instead of two separately-pooled ones — not the
    // `Immediate` write-lock pattern the mutating handlers in this file use.
    //
    // No subquery, no column projection beyond the count itself: the historical
    // `PaginatorTrait::count()` wraps the fully-projected two-entity join in
    // `SELECT COUNT(*) FROM (<12-column SELECT ... FROM ... LEFT JOIN ...>) AS sub_query`, which
    // makes SQLite materialize every matched row's columns just to discard them. This instead
    // drives the count directly off a single-entity `Select`, the same `.select_only()` +
    // typed-tuple pattern `readiness_check` (`src/api/health.rs`) already uses for its own
    // as-cheap-as-possible probe query.
    let (total, memberships) = if include_total {
        let txn = state.db.begin().await?;

        let count: Option<i64> = ip_record_group_membership::Entity::find()
            .join(JoinType::LeftJoin, ip_record_group_membership::Relation::IpRecord.def())
            .filter(condition.clone())
            .select_only()
            .expr_as(
                Func::count(Expr::col((
                    ip_record_group_membership::Entity,
                    ip_record_group_membership::Column::IpRecordId,
                ))),
                "row_count",
            )
            .into_tuple::<i64>()
            .one(&txn)
            .await?;
        let total = count.unwrap_or(0).max(0) as u64;

        // Latest activity first: whichever (record, group) pairing was most recently added or
        // re-registered (a ban "renewed" by a fresh match into *this* group) sorts to the top,
        // matching AGENT.MD's ordering requirement. Sorts on the membership's own `updated_at`
        // (`m20260926_120000`), not the shared record's — see this file's `since` comment above for
        // why a record-level column made every group an address belonged to reorder whenever any
        // one of them changed.
        let page = query
            .filter(condition)
            .order_by_desc(ip_record_group_membership::Column::UpdatedAt)
            .limit(limit)
            .offset(offset)
            .all(&txn)
            .await?;

        txn.commit().await?;
        (Some(total), page)
    } else {
        let page = query
            .filter(condition)
            .order_by_desc(ip_record_group_membership::Column::UpdatedAt)
            .limit(limit)
            .offset(offset)
            .all(&state.db)
            .await?;
        (None, page)
    };

    if format_iplist {
        // Lightweight path: skip the per-row group lookup below entirely (not needed for a flat
        // address list), and de-duplicate — an address matched via multiple group memberships in
        // the same query would otherwise appear once per membership.
        let mut ip_list: Vec<String> = memberships
            .into_iter()
            .filter_map(|(_, record_opt)| record_opt.map(|r| r.target_address))
            .collect();
        ip_list.sort();
        ip_list.dedup();
        return Ok(Json(serde_json::json!({ "ip_list": ip_list })).into_response());
    }

    let mut items = Vec::with_capacity(memberships.len());
    for (mem, record_opt) in memberships {
        let Some(record) = record_opt else { continue };
        let Some(group) = ip_group::Entity::find_by_id(mem.group_id).one(&state.db).await? else {
            continue;
        };

        items.push(IpRecordResponse {
            id: record.id,
            target_address: record.target_address,
            group_name: group.name,
            group_type: group.group_type,
            cause: record.cause,
            is_locked: record.is_locked,
            // From the membership row, not the record — see `IpRecordResponse::created_at`'s doc.
            created_at: mem.created_at,
            updated_at: mem.updated_at,
            last_seen_at: record.last_seen_at,
            is_deleted: record.is_deleted,
            deleted_at: record.deleted_at,
            // Master only — see the field's doc comment. A group reader may see *that* a record was
            // deleted, never *which key* did it.
            deleted_by: if key.is_master { record.deleted_by } else { None },
        });
    }

    if let Some(total) = total {
        let total_pages = if limit == 0 { 0 } else { total.div_ceil(limit) };
        return Ok(Json(IpRecordsEnvelope { data: items, total, limit, offset, total_pages }).into_response());
    }

    Ok(Json(items).into_response())
}


/// Whether the caller may act on a record, given its group memberships.
///
/// A record can belong to several groups; the caller needs `can_delete` on **at least one** of
/// them, which is the same rule the group-scoped `DELETE /api/ips` applies. Master keys short-
/// circuit. A record with no memberships at all (orphaned by a group deletion) is master-only,
/// since there is no group left to derive authority from.
pub(crate) async fn caller_may_delete_record(
    db: &sea_orm::DatabaseConnection,
    key: &api_key::Model,
    record_id: Uuid,
) -> Result<bool, AppError> {
    if key.is_master {
        return Ok(true);
    }

    let group_ids: Vec<Uuid> = ip_record_group_membership::Entity::find()
        .filter(ip_record_group_membership::Column::IpRecordId.eq(record_id))
        .all(db)
        .await?
        .into_iter()
        .map(|m| m.group_id)
        .collect();

    if group_ids.is_empty() {
        return Ok(false);
    }

    let deletable = api_key_group_permission::Entity::find()
        .filter(
            Condition::all()
                .add(api_key_group_permission::Column::ApiKeyId.eq(key.id))
                .add(api_key_group_permission::Column::GroupId.is_in(group_ids))
                .add(api_key_group_permission::Column::CanDelete.eq(true)),
        )
        .one(db)
        .await?;

    Ok(deletable.is_some())
}


/// Query parameters for [`delete_ip_record`]. `deny_unknown_fields` so a typo'd parameter is
/// refused rather than silently ignored.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DeleteRecordQuery {
    /// Master-only: drop the row outright instead of soft-deleting it.
    pub hard: Option<bool>,
}


/// Handles `DELETE /api/ips/{id}` — soft-deletes an IP record, or hard-deletes it for a master.
///
/// **Soft delete is the default and the only option for a non-master.** The row stays, marked
/// `is_deleted` with `deleted_at`/`deleted_by` set, and disappears from every read (see
/// [`list_ips`]) until a master restores it or [`crate::retention`] purges it after 92 days.
///
/// The reason a delegated key never gets a hard delete: `can_delete` on a group is a routine,
/// widely-handed-out scope, and the blast radius of it being misused — or of the key being stolen —
/// should be a recoverable mistake rather than permanent data loss. Making destruction master-only
/// costs a legitimate operator one extra step and costs an attacker the ability to cover their
/// tracks.
///
/// Distinct from `DELETE /api/ips` (query/body form), which removes a record's membership in **one
/// group** and leaves the record itself alone. This route acts on the record as a whole.
pub async fn delete_ip_record(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
    StrictQuery(params): StrictQuery<DeleteRecordQuery>,
) -> Result<impl IntoResponse, AppError> {
    let record = ip_record::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    if !caller_may_delete_record(&state.db, &key, id).await? {
        return Err(AppError::Forbidden(
            "Permission denied: you have no delete access to any group holding this record".to_owned(),
        ));
    }

    if record.is_locked {
        return Err(AppError::Forbidden("Protected records cannot be deleted".to_owned()));
    }

    let hard = params.hard.unwrap_or(false);
    if hard && !key.is_master {
        return Err(AppError::Forbidden(
            "Only a master key can permanently delete an IP record".to_owned(),
        ));
    }

    let address = record.target_address.clone();

    if hard {
        ip_record::Entity::delete_by_id(id).exec(&state.db).await?;
        create_audit_log(
            &state.db,
            &key,
            client_ip.0,
            "IP_HARD_DELETE",
            Some(address.clone()),
            None,
            Some("Permanently deleted".to_owned()),
        )
        .await?;

        return Ok(Json(serde_json::json!({
            "id": id,
            "target_address": address,
            "deleted": "permanent",
        })));
    }

    // Already in the trash: report success without moving `deleted_at`, so a repeated call cannot
    // silently extend the retention window and keep a record out of the purge indefinitely.
    if record.is_deleted {
        return Ok(Json(serde_json::json!({
            "id": id,
            "target_address": address,
            "deleted": "soft",
            "already_deleted": true,
        })));
    }

    let now = Utc::now().naive_utc();
    let mut active: ip_record::ActiveModel = record.into();
    active.is_deleted = Set(true);
    active.deleted_at = Set(Some(now));
    active.deleted_by = Set(Some(key.id.to_string()));
    active.updated_at = Set(now);
    active.update(&state.db).await?;

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "IP_SOFT_DELETE",
        Some(address.clone()),
        None,
        Some(format!("Soft-deleted by key {}", format_key_reference(&key.name, key.id))),
    )
    .await?;

    Ok(Json(serde_json::json!({
        "id": id,
        "target_address": address,
        "deleted": "soft",
        "already_deleted": false,
    })))
}


/// Handles `POST /api/ips/{id}/restore` — brings a soft-deleted record back. Master only.
///
/// Restoration is master-only even though a delegated key could have caused the deletion: the whole
/// point of the trash is that recovering from a compromised or careless key does not depend on that
/// same key's authority.
pub async fn restore_ip_record(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictPath(id): StrictPath<Uuid>,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden(
            "Only a master key can restore a deleted IP record".to_owned(),
        ));
    }

    let record = ip_record::Entity::find_by_id(id)
        .one(&state.db)
        .await?
        .ok_or(AppError::NotFound)?;

    if !record.is_deleted {
        return Err(AppError::InvalidInput(
            "This IP record is not deleted; nothing to restore".to_owned(),
        ));
    }

    let address = record.target_address.clone();
    let now = Utc::now().naive_utc();

    // The deletion metadata is cleared, not just the flag: leaving a stale `deleted_at` behind
    // would leave the record one flag-flip away from being purged as if it had been in the trash
    // all along.
    let mut active: ip_record::ActiveModel = record.into();
    active.is_deleted = Set(false);
    active.deleted_at = Set(None);
    active.deleted_by = Set(None);
    active.updated_at = Set(now);
    let restored = active.update(&state.db).await?;

    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "IP_RESTORE",
        Some(address.clone()),
        None,
        Some("Restored from soft delete".to_owned()),
    )
    .await?;

    Ok(Json(serde_json::json!({
        "id": restored.id,
        "target_address": address,
        "is_deleted": false,
        "restored": true,
    })))
}


/// Body for [`purge_ip_records`]. Optional; an empty body uses the configured retention window.
/// `deny_unknown_fields` so a typo'd field is refused rather than silently ignored.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PurgeIpsPayload {
    /// Override the retention window for this sweep only, in days.
    ///
    /// `0` is rejected rather than treated as "purge everything": the difference between "empty the
    /// trash" and "empty the trash older than zero days" is one character, and the destructive
    /// reading should never be the one a typo selects.
    pub older_than_days: Option<i64>,
}


/// Handles `POST /api/system/purge-ips` — permanently drops soft-deleted records past retention.
///
/// Master only, and irreversible. Runs the same sweep as the background worker
/// ([`crate::retention::purge_expired_ip_records`]), exposed as an endpoint so an operator can
/// reclaim space or honour a deletion request without waiting for the next tick.
pub async fn purge_ip_records(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    if !key.is_master {
        return Err(AppError::Forbidden(
            "Only a master key can purge deleted IP records".to_owned(),
        ));
    }

    let payload: PurgeIpsPayload = if body.is_empty() {
        PurgeIpsPayload::default()
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| AppError::InvalidInput(format!("Invalid JSON body: {e}")))?
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
        Some(format!("Purged {purged} record(s) soft-deleted over {retention_days} days ago")),
    )
    .await?;

    Ok(Json(serde_json::json!({
        "purged": purged,
        "retention_days": retention_days,
    })))
}


/// Parameters for deleting an IP record from a group. Every field is optional here because this
/// same shape is used to parse both the URL query string and an optional JSON body — the handler
/// merges the two and only then checks that the required combination was actually supplied.
/// `deny_unknown_fields` applies uniformly to both parses: the query string through
/// [`crate::extract::StrictQuery`], the body through the handler's own `serde_json::from_slice`.
#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DeleteIpQuery {
    /// IP to delete
    pub target_address: Option<String>,
    /// Group to delete from, by ID. Provide this or `group_name`, not both.
    pub group_id: Option<Uuid>,
    /// Group to delete from, by name. Provide this or `group_id`, not both.
    pub group_name: Option<String>,
}


impl DeleteIpQuery {
    /// Fills in any field left `None` by `self` with the corresponding field from `other`.
    fn merge(self, other: DeleteIpQuery) -> DeleteIpQuery {
        DeleteIpQuery {
            target_address: self.target_address.or(other.target_address),
            group_id: self.group_id.or(other.group_id),
            group_name: self.group_name.or(other.group_name),
        }
    }
}


/// Handles DELETE /api/v1/ips. Accepts `target_address` and `group_id`/`group_name` from the URL
/// query string, a JSON request body, or a mix of both (query values win on overlap) — some HTTP
/// clients refuse to attach a body to `DELETE`, others prefer a body over query-string params, so
/// this endpoint accommodates either without producing a deserialization error for either shape.
pub async fn delete_ip(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictQuery(query_params): StrictQuery<DeleteIpQuery>,
    body: axum::body::Bytes,
) -> Result<impl IntoResponse, AppError> {
    let body_params: DeleteIpQuery = if body.is_empty() {
        DeleteIpQuery::default()
    } else {
        serde_json::from_slice(&body)
            .map_err(|e| AppError::InvalidInput(format!("Invalid JSON body: {e}")))?
    };
    let params = query_params.merge(body_params);

    let target_address = params
        .target_address
        .filter(|s| !s.is_empty())
        .ok_or_else(|| AppError::InvalidInput("target_address is required (query or JSON body)".to_owned()))?;
    // Canonicalize before the lookup below: a record banned as "X/32" must still be found (and
    // deletable) by a caller passing plain "X", and vice versa.
    let target_address = normalize_ip_or_cidr(&target_address);

    let group = resolve_group_ref(&state.db, params.group_id, params.group_name.as_deref())
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

        if let Some(p) = perm {
            if !p.can_delete {
                return Err(AppError::Forbidden("Permission denied: You do not have delete permissions over this group".to_owned()));
            }
        } else {
            return Err(AppError::Forbidden("Permission denied".to_owned()));
        }
    }

    // The record lookup, the membership delete, and the audit log write combined into one
    // `Immediate` transaction — same reasoning as `handle_ip_upsert`'s own: three separate writes
    // against the pool were three separate write-lock acquisitions per logical delete, and
    // `Immediate` takes that lock up front rather than risking a stale-snapshot `SQLITE_BUSY` on
    // the upgrade from this transaction's own leading read.
    let txn = state
        .db
        .begin_with_options(TransactionOptions {
            sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
            ..Default::default()
        })
        .await?;

    let record = ip_record::Entity::find()
        .filter(ip_record::Column::TargetAddress.eq(&target_address))
        .one(&txn)
        .await?
        .ok_or(AppError::NotFound)?;

    if record.is_locked {
        return Err(AppError::Forbidden("Protected records cannot be deleted".to_owned()));
    }

    let mem_result = ip_record_group_membership::Entity::delete_by_id((record.id, group.id))
        .exec(&txn)
        .await?;

    if mem_result.rows_affected == 0 {
        return Err(AppError::NotFound);
    }

    create_audit_log(
        &txn,
        &key,
        client_ip.0,
        "IP_DELETE",
        Some(target_address),
        Some(group.name.clone()),
        None
    ).await?;

    // Committed before the webhook event is enqueued below — same reasoning as `handle_ip_upsert`:
    // a webhook must never fire for a delete a rolled-back transaction means never happened.
    txn.commit().await?;

    let event = WebhookEvent {
        action: "IP_DELETE".to_owned(),
        address: record.target_address.clone(),
        is_whitelist: group.group_type == "whitelist",
        group_id: Some(group.id),
        group_name: Some(group.name.clone()),
        cause: Some("Deleted via API".to_owned()),
    };
    state.enqueue_webhook(event);

    Ok(axum::http::StatusCode::NO_CONTENT)
}


// ═════════════════════════════════════════════════════════════
// POST /api/records/batch — bulk synchronisation
// ═════════════════════════════════════════════════════════════

/// Largest batch accepted in one request.
///
/// The 3 MiB body limit already bounds this indirectly, but indirectly is the problem: the ceiling
/// would then depend on how verbose each record happened to be, so the same client could succeed with
/// 40 000 terse entries and fail with 8 000 wordy ones. An explicit count gives a stable contract and
/// a message that says what to do about it.
///
/// It also bounds the transaction. Every record below is a `SELECT` plus an `INSERT`/`UPDATE` inside
/// one `BEGIN IMMEDIATE`, and on SQLite — a single-writer engine — that transaction holds the write
/// lock for its whole duration. An unbounded batch is a self-inflicted outage for every other caller.
pub const MAX_BATCH_RECORDS: usize = 10_000;

/// How a batch reconciles against what is already in the group.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum BatchMode {
    /// Add and update the listed records, leaving everything else in the group alone.
    #[default]
    Upsert,
    /// Additionally soft-delete every active, unlocked record in the group that the batch omits.
    ///
    /// The destructive mode, and the reason this endpoint requires `can_delete` rather than
    /// `can_write` when it is selected — see [`batch_records`].
    FullReplace,
}

/// One record in a batch.
///
/// Every timestamp is optional and falls back to "now". A synchronising client that has real
/// timestamps from its own store should send them, so the vault's view matches the source of truth
/// rather than recording when the sync happened to run.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BatchRecordInput {
    /// The address or CIDR. Canonicalised before use, so `1.2.3.4/32` and `1.2.3.4` are one record.
    pub target_address: String,
    /// Reason or metadata. Omitted leaves an existing value untouched; it does not clear it.
    pub cause: Option<String>,
    /// Soft-delete state to apply. `Some(false)` on a deleted record restores it.
    pub is_deleted: Option<bool>,
    /// Creation timestamp, used only when the record is new. **Never overwrites an existing one.**
    pub created_at: Option<chrono::NaiveDateTime>,
    /// Last-update timestamp. Defaults to now.
    pub updated_at: Option<chrono::NaiveDateTime>,
    /// Last-activity timestamp. Defaults to now.
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
    /// The records. Duplicates (after canonicalisation) are refused.
    pub records: Vec<BatchRecordInput>,
    /// Suppresses webhook dispatch for every record this batch touches. `false`/omitted (the
    /// default) dispatches exactly as `POST /api/ban`/`/white`/`DELETE /api/ips` would, one event per
    /// record outcome. Meant for bulk imports and large synchronisation runs, where a multi-thousand-
    /// record batch would otherwise enqueue a multi-thousand-event burst — the record writes and
    /// audit trail are identical either way; only the notification side effect is gated.
    #[serde(default)]
    pub skip_webhooks: Option<bool>,
}

/// What a batch did, counted by outcome.
#[derive(Debug, Default, Serialize)]
pub struct BatchRecordsResponse {
    /// Rows inserted.
    pub created: u64,
    /// Existing rows updated.
    pub updated: u64,
    /// Rows that were soft-deleted and are now live again.
    pub restored: u64,
    /// Rows left untouched because `is_locked` was set.
    pub locked_skipped: u64,
    /// Rows soft-deleted because `full_replace` omitted them.
    pub soft_deleted: u64,
    /// Memberships created linking a record to the target group.
    pub linked: u64,
}

/// Handles `POST /api/records/batch` — synchronise many records into one group atomically.
///
/// Built for the companion exporter and sync worker, which reconcile an external source of truth
/// against this service on a schedule. Doing that through `POST /api/ban` one address at a time costs
/// a round trip and a transaction each; more importantly it has no way to express "and everything
/// else in this group is gone", which is what `full_replace` is for.
///
/// # Authorization
///
/// | Mode | Requires |
/// | :--- | :--- |
/// | `upsert` | `can_write` on the group |
/// | `full_replace` | `can_write` **and** `can_delete` |
///
/// The second row is the one that matters. `full_replace` soft-deletes every unlisted record, so a
/// key holding only `can_write` could otherwise empty a group by sending an empty batch — deletion
/// through a write verb. `RBAC_MODEL.md` keeps operational verbs distinct precisely so that holding
/// one does not confer another, and a bulk endpoint is exactly where that boundary erodes quietly.
///
/// Master bypasses the per-group check, as everywhere else.
///
/// # Atomicity
///
/// Everything runs in one transaction: the per-record work, the `full_replace` sweep, and the audit
/// row. A partially applied sync is worse than a failed one — the client cannot tell which half
/// landed, and a retry would double-apply the part that did. The audit row is written *inside* the
/// transaction for the same reason: an entry that survives a rollback describes something that never
/// happened.
///
/// # What it will not do
///
/// - **Touch a locked record.** `is_locked` rows are counted in `locked_skipped` and left exactly as
///   they are, in both modes. They are also excluded from the `full_replace` sweep.
/// - **Hard-delete anything.** `full_replace` soft-deletes; the rows remain, attributed to the caller
///   via `deleted_by`, and `RBAC_MODEL.md` §6's "data is never destroyed implicitly" holds.
/// - **Bypass address validation.** Banlist targets go through [`guard_bannable_address`], the same
///   guard `handle_ip_upsert` uses, so a batch cannot insert `127.0.0.1` into a banlist that the
///   single-record path refuses.
///
/// # Webhook dispatch
///
/// Every record outcome (a new address linked into the group, an existing one updated, or one
/// `full_replace` swept into a soft delete) enqueues the same [`WebhookEvent`] shape
/// `handle_ip_upsert`/`delete_ip` raise for their single-record equivalents — classified `IP_ADD`
/// when the group membership itself is new and `IP_UPDATE` otherwise, matching those handlers'
/// existing "keyed off the membership, not the underlying row" rule, and `IP_DELETE` for the
/// `full_replace` sweep. `payload.skip_webhooks` (`false`/omitted by default) suppresses all of it —
/// the record writes and the audit row are identical either way, only the notification side effect
/// is gated. Events are buffered during the transaction and only handed to
/// [`AppState::enqueue_webhook`] after it commits, for the same reason `handle_ip_upsert`/`delete_ip`
/// enqueue after their own commit: a webhook must never fire for a write a rolled-back transaction
/// means never happened.
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

    // Canonicalise and validate everything *before* opening the transaction. A batch that is going to
    // be rejected should not first acquire the write lock, and on SQLite that lock is global.
    let mut normalized: Vec<(String, &BatchRecordInput)> = Vec::with_capacity(payload.records.len());
    let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
    for record in &payload.records {
        let network: IpNetwork = record.target_address.parse().map_err(|_| {
            AppError::InvalidInput(format!(
                "Invalid IP or CIDR format: {:?}",
                record.target_address
            ))
        })?;
        let address = normalize_ip_or_cidr(&record.target_address);
        // Refused rather than last-one-wins. Two entries for one address after canonicalisation
        // (`1.2.3.4` and `1.2.3.4/32`) mean the client's own view is inconsistent, and silently
        // picking one would make the result depend on payload order.
        if !seen.insert(address.clone()) {
            return Err(AppError::InvalidInput(format!(
                "Duplicate target_address in batch after canonicalisation: {address}"
            )));
        }
        normalized.push((address, record));
        // Validation against the group type happens below, once the group is resolved — the network
        // is parsed here only to reject malformed input before any lock is taken.
        let _ = network;
    }

    // ── Group resolution and authorization ──────────────────────────────────
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
                        AppError::Forbidden(
                            "Permission denied: You have no access strictly mapped to this group"
                                .to_owned(),
                        )
                    })?;

                if !perm.can_write {
                    return Err(AppError::Forbidden(
                        "Permission denied: You do not have write access to this group".to_owned(),
                    ));
                }
                // The whole reason this check exists — see the doc comment. `full_replace` deletes,
                // and a write verb must not confer deletion.
                if payload.mode == BatchMode::FullReplace && !perm.can_delete {
                    return Err(AppError::Forbidden(
                        "Permission denied: mode 'full_replace' soft-deletes the records it omits \
                         and therefore requires delete access to this group, not only write access"
                            .to_owned(),
                    ));
                }
            }
            g
        }
        None => {
            if !key.is_master && !key.can_create_groups {
                return Err(AppError::Forbidden(
                    "Permission denied: Target group does not exist and you cannot create groups"
                        .to_owned(),
                ));
            }
            // A batch into a group that does not exist yet has nothing to replace, so the mode makes
            // no difference to what happens — but the permission check above still applied.
            get_or_create_group(&state.db, &payload.group_name, "banlist", resource_owner(&key))
                .await?
        }
    };

    // Banlist targets are held to the same address rules as `POST /api/ban`. Checked after the
    // authorization above, so a caller with no access to the group learns nothing about its type.
    if group.group_type != "whitelist" {
        for (address, _) in &normalized {
            let network: IpNetwork = address
                .parse()
                .map_err(|_| AppError::InvalidInput(format!("Invalid IP or CIDR format: {address}")))?;
            guard_bannable_address(&network)?;
        }
    }

    // ── The transaction ─────────────────────────────────────────────────────
    let now = Utc::now().naive_utc();
    // `Immediate` rather than a plain `begin()` (SQLite's default `BEGIN DEFERRED`): this
    // transaction reads before it writes (a `SELECT` per record, ahead of that record's own
    // `INSERT`/`UPDATE`), and a deferred transaction only takes a read snapshot at that first
    // `SELECT`. On a single-connection SQLite pool that distinction was invisible — nothing else
    // could commit in between regardless — but a file-backed pool may now hold more than one
    // connection, and a concurrent writer committing between this transaction's first read and its
    // first write leaves the snapshot stale. SQLite refuses to upgrade a stale snapshot to a write
    // lock and returns `SQLITE_BUSY` **immediately**, without invoking the `busy_timeout` handler —
    // that handler retries ordinary lock contention, not this. `Immediate` sidesteps the whole
    // failure mode by taking the write lock up front, before the first read, so there is no snapshot
    // left to go stale; a concurrent writer is then ordinary lock contention, and `busy_timeout` does
    // apply and does queue it. Ignored (harmlessly) on non-SQLite backends.
    let txn = state
        .db
        .begin_with_options(TransactionOptions {
            sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
            ..Default::default()
        })
        .await?;
    let mut summary = BatchRecordsResponse::default();
    let skip_webhooks = payload.skip_webhooks.unwrap_or(false);
    // Buffered rather than enqueued as each record is processed: an event raised mid-transaction
    // could still be rolled back by a later record's error, and a webhook that already fired cannot
    // be un-fired. Handed to `state.enqueue_webhook` only once `txn.commit()` below has succeeded.
    let mut webhook_events: Vec<WebhookEvent> = Vec::new();

    for (address, input) in &normalized {
        let existing = ip_record::Entity::find()
            .filter(ip_record::Column::TargetAddress.eq(address.clone()))
            .one(&txn)
            .await?;

        let record_id = match existing {
            Some(record) if record.is_locked => {
                // Left exactly as it is — not updated, not linked, not counted as anything else.
                summary.locked_skipped += 1;
                continue;
            }
            Some(record) => {
                let was_deleted = record.is_deleted;
                let id = record.id;
                let mut active: ip_record::ActiveModel = record.into();

                // `created_at` is deliberately never written here: it records when this service
                // first saw the address, and a re-sync is not a creation.
                active.last_seen_at = Set(input.last_seen_at.unwrap_or(now));
                active.updated_at = Set(input.updated_at.unwrap_or(now));
                if let Some(cause) = &input.cause {
                    active.cause = Set(Some(cause.clone()));
                }

                match input.is_deleted {
                    Some(true) => {
                        active.is_deleted = Set(true);
                        active.deleted_at = Set(Some(input.deleted_at.unwrap_or(now)));
                        active.deleted_by = Set(Some(key.id.to_string()));
                    }
                    // Explicitly live, or the batch says nothing and the record was deleted — either
                    // way a sync that lists an address is asserting it exists, so it comes back.
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
                id
            }
            None => {
                let id = Uuid::new_v4();
                let deleted = input.is_deleted.unwrap_or(false);
                ip_record::ActiveModel {
                    id: Set(id),
                    target_address: Set(address.clone()),
                    cause: Set(input.cause.clone()),
                    // Never set from the payload. A client cannot mint a locked record and thereby
                    // make it immune to its own later syncs.
                    is_locked: Set(false),
                    created_at: Set(input.created_at.unwrap_or(now)),
                    updated_at: Set(input.updated_at.unwrap_or(now)),
                    last_seen_at: Set(input.last_seen_at.unwrap_or(now)),
                    is_deleted: Set(deleted),
                    deleted_at: Set(if deleted { Some(input.deleted_at.unwrap_or(now)) } else { None }),
                    deleted_by: Set(if deleted { Some(key.id.to_string()) } else { None }),
                }
                .insert(&txn)
                .await?;
                summary.created += 1;
                id
            }
        };

        // Read before the write, same reasoning as `handle_ip_upsert`: the upsert below always
        // touches a row, so the affected-row count can no longer distinguish "linked for the first
        // time" from "already linked, touched again" the way a `DO NOTHING` conflict's count used to.
        let membership_is_new = ip_record_group_membership::Entity::find_by_id((record_id, group.id))
            .one(&txn)
            .await?
            .is_none();
        if membership_is_new {
            summary.linked += 1;
        }

        ip_record_group_membership::Entity::insert(
            ip_record_group_membership::ActiveModel {
                ip_record_id: Set(record_id),
                group_id: Set(group.id),
                created_at: Set(input.created_at.unwrap_or(now)),
                updated_at: Set(input.updated_at.unwrap_or(now)),
            },
        )
        .on_conflict(
            OnConflict::columns([
                ip_record_group_membership::Column::IpRecordId,
                ip_record_group_membership::Column::GroupId,
            ])
            // Not `do_nothing()`: a batch re-asserting an address already linked to this group is a
            // real touch of *that group's* membership and must advance its `updated_at` — see
            // `m20260926_120000`'s module comment. `created_at` is absent from this list, so a
            // conflict leaves it exactly as first recorded.
            .update_column(ip_record_group_membership::Column::UpdatedAt)
            .to_owned(),
        )
        .exec_without_returning(&txn)
        .await?;

        if !skip_webhooks {
            // Same classification `handle_ip_upsert` uses: a new membership is an `IP_ADD` even when
            // the underlying `ip_record` row already existed under a different group, since that is
            // what changed from this group's own perspective; anything else touched in this pass is
            // an `IP_UPDATE`.
            let action = if membership_is_new { "IP_ADD" } else { "IP_UPDATE" };
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

    // ── full_replace: soft-delete what the batch omitted ────────────────────
    if payload.mode == BatchMode::FullReplace {
        let member_ids: Vec<Uuid> = ip_record_group_membership::Entity::find()
            .filter(ip_record_group_membership::Column::GroupId.eq(group.id))
            .all(&txn)
            .await?
            .into_iter()
            .map(|m| m.ip_record_id)
            .collect();

        if !member_ids.is_empty() {
            let candidates = ip_record::Entity::find()
                .filter(
                    Condition::all()
                        .add(ip_record::Column::Id.is_in(member_ids))
                        .add(ip_record::Column::IsDeleted.eq(false))
                        // Locked rows are exempt from the sweep as well as from the updates above:
                        // an administrative lock that a remote sync could clear would not be a lock.
                        .add(ip_record::Column::IsLocked.eq(false)),
                )
                .all(&txn)
                .await?;

            for record in candidates {
                if seen.contains(&record.target_address) {
                    continue;
                }
                let swept_address = record.target_address.clone();
                let mut active: ip_record::ActiveModel = record.into();
                active.is_deleted = Set(true);
                active.deleted_at = Set(Some(now));
                active.deleted_by = Set(Some(key.id.to_string()));
                active.updated_at = Set(now);
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
    }

    // One aggregated row, not one per record: a 10 000-record sync would otherwise bury every other
    // event in the trail and turn the audit log into the batch's own transcript.
    create_audit_log(
        &txn,
        &key,
        client_ip.0,
        "batch_records_updated",
        None,
        Some(group.name.clone()),
        Some(format!(
            "mode={} submitted={} created={} updated={} restored={} locked_skipped={} \
             soft_deleted={}",
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

    // Committed before any event is enqueued, same as `handle_ip_upsert`/`delete_ip`: a webhook must
    // never fire for a batch whose transaction rolled back.
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
