//! IP record endpoints: ban/whitelist upsert, listing, membership soft delete, restore, purge, and
//! batch synchronisation.
//!
//! An address is canonical (`ip_records`). Its operational state — lock, last observation, soft
//! delete, cause history — belongs to its membership in one group (`ip_record_group_memberships`).
//! Every endpoint here that changes state therefore acts on a `(target_address, group)` pair, and
//! a change in one group never touches the same address's membership in another.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};

use axum::{
    Extension,
    extract::{Json, State},
    response::IntoResponse,
};
use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use sea_orm::{
    ActiveModelTrait,
    ActiveValue::Set,
    ColumnTrait, Condition, ConnectionTrait, DatabaseTransaction, EntityTrait, JoinType,
    QueryFilter, QueryOrder, QuerySelect, QueryTrait, RelationTrait, SqlErr, SqliteTransactionMode,
    TransactionOptions, TransactionTrait,
    sea_query::{Expr, ExprTrait, Func, Query},
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::{
    api_key, api_key_group_permission, ip_group, ip_group_exclusion, ip_record, ip_record_cause,
    ip_record_group_membership,
};
use crate::error::AppError;
use crate::extract::{StrictJson, StrictQuery};
use crate::middleware::ClientIp;
use crate::state::{AppState, WebhookEvent};

use super::{
    create_audit_log, format_key_reference, get_or_create_group_with_status, normalize_ip_or_cidr,
    normalize_ipv6_ban_storage, resolve_group_ref, resource_owner,
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

fn networks_overlap(a: &IpNet, b: &IpNet) -> bool {
    a.contains(&b.network()) || b.contains(&a.network())
}

/// Rejects bans that overlap protected ranges, including IPv4-mapped IPv6 ranges.
pub(crate) fn guard_bannable_address(
    network: &IpNet,
    allow_private_ips: bool,
) -> Result<(), AppError> {
    const ALWAYS_BLOCKED_V4: [(Ipv4Addr, u8); 10] = [
        (Ipv4Addr::UNSPECIFIED, 8),
        (Ipv4Addr::LOCALHOST, 8),
        (Ipv4Addr::new(169, 254, 0, 0), 16),
        (Ipv4Addr::new(192, 0, 0, 0), 24),
        (Ipv4Addr::new(192, 0, 2, 0), 24),
        (Ipv4Addr::new(198, 18, 0, 0), 15),
        (Ipv4Addr::new(198, 51, 100, 0), 24),
        (Ipv4Addr::new(203, 0, 113, 0), 24),
        (Ipv4Addr::new(224, 0, 0, 0), 4),
        (Ipv4Addr::new(240, 0, 0, 0), 4), // Includes the limited broadcast address.
    ];
    const PRIVATE_V4: [(Ipv4Addr, u8); 4] = [
        (Ipv4Addr::new(10, 0, 0, 0), 8),
        (Ipv4Addr::new(100, 64, 0, 0), 10),
        (Ipv4Addr::new(172, 16, 0, 0), 12),
        (Ipv4Addr::new(192, 168, 0, 0), 16),
    ];
    const ALWAYS_BLOCKED_V6: [(Ipv6Addr, u8); 8] = [
        (Ipv6Addr::UNSPECIFIED, 128),
        (Ipv6Addr::LOCALHOST, 128),
        (Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 0), 10),
        (Ipv6Addr::new(0xff00, 0, 0, 0, 0, 0, 0, 0), 8),
        (Ipv6Addr::new(0x0100, 0, 0, 0, 0, 0, 0, 0), 64),
        (Ipv6Addr::new(0x0064, 0xff9b, 0, 0, 0, 0, 0, 0), 96),
        (Ipv6Addr::new(0x2001, 0x0db8, 0, 0, 0, 0, 0, 0), 32),
        (Ipv6Addr::new(0x3fff, 0, 0, 0, 0, 0, 0, 0), 20),
    ];
    const ULA: Ipv6Net = Ipv6Net::new_assert(Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 0), 7);

    let overlaps_v4 = |&(address, prefix): &(Ipv4Addr, u8)| {
        let range = match network {
            IpNet::V4(_) => IpNet::V4(Ipv4Net::new_assert(address, prefix)),
            IpNet::V6(_) => IpNet::V6(Ipv6Net::new_assert(address.to_ipv6_mapped(), 96 + prefix)),
        };
        networks_overlap(network, &range)
    };
    let blocked = ALWAYS_BLOCKED_V4.iter().any(overlaps_v4)
        || ALWAYS_BLOCKED_V6.iter().any(|&(address, prefix)| {
            networks_overlap(network, &IpNet::V6(Ipv6Net::new_assert(address, prefix)))
        })
        || (!allow_private_ips
            && (PRIVATE_V4.iter().any(overlaps_v4) || networks_overlap(network, &IpNet::V6(ULA))));
    if blocked {
        return Err(AppError::InvalidInput(
            "Cannot ban an address or CIDR that overlaps a protected IP range".to_owned(),
        ));
    }
    Ok(())
}

pub(crate) async fn load_protected_networks(
    db: &impl ConnectionTrait,
    group_id: Uuid,
) -> Result<Vec<(IpNet, String)>, AppError> {
    let excluded_groups = ip_group_exclusion::Entity::find()
        .select_only()
        .column(ip_group_exclusion::Column::ExcludedGroupId)
        .column(ip_group::Column::Name)
        .join(
            JoinType::InnerJoin,
            ip_group_exclusion::Relation::ExcludedGroup.def(),
        )
        .filter(ip_group_exclusion::Column::GroupId.eq(group_id))
        .into_tuple::<(Uuid, String)>()
        .all(db)
        .await?;
    if excluded_groups.is_empty() {
        return Ok(Vec::new());
    }

    let mut memberships_by_group: Vec<(String, Vec<Uuid>)> =
        Vec::with_capacity(excluded_groups.len());
    let mut unique_record_ids: Vec<Uuid> = Vec::new();
    let mut seen_record_ids: HashSet<Uuid> = HashSet::new();

    for (excluded_group_id, group_name) in excluded_groups {
        let record_ids = ip_record_group_membership::Entity::find()
            .select_only()
            .column(ip_record_group_membership::Column::IpRecordId)
            .filter(ip_record_group_membership::Column::GroupId.eq(excluded_group_id))
            .filter(ip_record_group_membership::Column::IsDeleted.eq(false))
            .into_tuple::<Uuid>()
            .all(db)
            .await?;
        for &record_id in &record_ids {
            if seen_record_ids.insert(record_id) {
                unique_record_ids.push(record_id);
            }
        }
        memberships_by_group.push((group_name, record_ids));
    }

    if unique_record_ids.is_empty() {
        return Ok(Vec::new());
    }

    let mut networks_by_id: HashMap<Uuid, IpNet> = HashMap::with_capacity(unique_record_ids.len());
    for chunk in unique_record_ids.chunks(500) {
        let rows = ip_record::Entity::find()
            .select_only()
            .column(ip_record::Column::Id)
            .column(ip_record::Column::TargetAddress)
            .filter(ip_record::Column::Id.is_in(chunk.iter().copied()))
            .into_tuple::<(Uuid, String)>()
            .all(db)
            .await?;
        for (id, address) in rows {
            let network =
                super::support::parse_cidr_or_ip(&address).map_err(|()| AppError::Internal)?;
            networks_by_id.insert(id, network);
        }
    }

    let mut protected = Vec::new();
    for (group_name, record_ids) in memberships_by_group {
        for record_id in record_ids {
            let network = networks_by_id
                .get(&record_id)
                .copied()
                .ok_or(AppError::Internal)?;
            protected.push((network, group_name.clone()));
        }
    }
    Ok(protected)
}

fn matching_whitelists(
    protected: &[(IpNet, String)],
    input: IpNet,
    stored: IpNet,
) -> impl Iterator<Item = &str> {
    protected.iter().filter_map(move |(network, name)| {
        (networks_overlap(network, &input) || networks_overlap(network, &stored))
            .then_some(name.as_str())
    })
}

fn validate_ban_networks(
    input: &IpNet,
    stored_address: &str,
    allow_private_ips: bool,
) -> Result<IpNet, AppError> {
    guard_bannable_address(input, allow_private_ips)?;
    let stored =
        super::support::parse_cidr_or_ip(stored_address).map_err(|()| AppError::Internal)?;
    if stored != *input {
        guard_bannable_address(&stored, allow_private_ips)?;
    }
    Ok(stored)
}

async fn load_excluding_banlists(
    db: &impl ConnectionTrait,
    whitelist_group_id: Uuid,
) -> Result<Vec<(Uuid, String)>, AppError> {
    ip_group_exclusion::Entity::find()
        .select_only()
        .column(ip_group::Column::Id)
        .column(ip_group::Column::Name)
        .join(
            JoinType::InnerJoin,
            ip_group_exclusion::Relation::Group.def(),
        )
        .filter(ip_group_exclusion::Column::ExcludedGroupId.eq(whitelist_group_id))
        .into_tuple::<(Uuid, String)>()
        .all(db)
        .await
        .map_err(Into::into)
}

fn collect_exact_and_supernet_candidates(net: &IpNet, out: &mut HashSet<String>) {
    let trunc = net.trunc();
    out.insert(trunc.to_string());
    match trunc {
        IpNet::V4(v4) => {
            if v4.prefix_len() == 32 {
                out.insert(v4.network().to_string());
            }
            for prefix in 0..v4.prefix_len() {
                out.insert(
                    Ipv4Net::new_assert(v4.network(), prefix)
                        .trunc()
                        .to_string(),
                );
            }
        }
        IpNet::V6(v6) => {
            if v6.prefix_len() == 128 {
                out.insert(v6.network().to_string());
            }
            if v6.network().to_ipv4_mapped().is_none() {
                out.insert(Ipv6Net::new_assert(v6.network(), 48).trunc().to_string());
            }
            for prefix in 0..v6.prefix_len() {
                out.insert(
                    Ipv6Net::new_assert(v6.network(), prefix)
                        .trunc()
                        .to_string(),
                );
            }
        }
    }
}

enum SubnetRange {
    Range { start: String, end: String },
    FullBanlistScan,
}

fn subnet_candidate_ranges(net: &IpNet) -> Vec<SubnetRange> {
    match net.trunc() {
        IpNet::V4(v4) if v4.prefix_len() < 32 => {
            let [a, b, c, _] = v4.network().octets();
            let prefix = v4.prefix_len();
            if prefix >= 24 {
                vec![SubnetRange::Range {
                    start: format!("{a}.{b}.{c}."),
                    end: format!("{a}.{b}.{c}/"),
                }]
            } else if prefix >= 16 {
                vec![SubnetRange::Range {
                    start: format!("{a}.{b}."),
                    end: format!("{a}.{b}/"),
                }]
            } else if prefix >= 8 {
                vec![SubnetRange::Range {
                    start: format!("{a}."),
                    end: format!("{a}/"),
                }]
            } else {
                let count = 1u16 << (8 - prefix);
                if count <= 16 {
                    (0..count)
                        .map(|delta| {
                            let octet = u16::from(a) + delta;
                            SubnetRange::Range {
                                start: format!("{octet}."),
                                end: format!("{octet}/"),
                            }
                        })
                        .collect()
                } else {
                    vec![SubnetRange::FullBanlistScan]
                }
            }
        }
        IpNet::V6(v6) if v6.prefix_len() < 128 => {
            let segments = v6.network().segments();
            let h1 = segments[0];
            let h2 = segments[1];
            let prefix = v6.prefix_len();
            if prefix >= 16 && h1 != 0 {
                if prefix >= 32 && h2 != 0 {
                    vec![SubnetRange::Range {
                        start: format!("{h1:x}:{h2:x}:"),
                        end: format!("{h1:x}:{h2:x};"),
                    }]
                } else {
                    vec![SubnetRange::Range {
                        start: format!("{h1:x}:"),
                        end: format!("{h1:x};"),
                    }]
                }
            } else {
                vec![SubnetRange::FullBanlistScan]
            }
        }
        _ => Vec::new(),
    }
}

async fn find_matching_excluded_records(
    txn: &DatabaseTransaction,
    banlist_ids: &[Uuid],
    protected: &[(IpNet, String)],
) -> Result<HashMap<Uuid, (String, String)>, AppError> {
    let mut exact_candidates = HashSet::new();
    let mut range_scans = Vec::new();
    let mut needs_full_banlist_scan = false;

    for (net, _) in protected {
        collect_exact_and_supernet_candidates(net, &mut exact_candidates);
        for range in subnet_candidate_ranges(net) {
            match range {
                SubnetRange::FullBanlistScan => {
                    needs_full_banlist_scan = true;
                    break;
                }
                SubnetRange::Range { start, end } => range_scans.push((start, end)),
            }
        }
    }

    let mut candidates: HashMap<Uuid, String> = HashMap::new();
    if needs_full_banlist_scan {
        let mut unique_record_ids: Vec<Uuid> = Vec::new();
        let mut seen_record_ids: HashSet<Uuid> = HashSet::new();
        for &banlist_id in banlist_ids {
            let record_ids = ip_record_group_membership::Entity::find()
                .select_only()
                .column(ip_record_group_membership::Column::IpRecordId)
                .filter(ip_record_group_membership::Column::GroupId.eq(banlist_id))
                .filter(ip_record_group_membership::Column::IsDeleted.eq(false))
                .into_tuple::<Uuid>()
                .all(txn)
                .await?;
            for record_id in record_ids {
                if seen_record_ids.insert(record_id) {
                    unique_record_ids.push(record_id);
                }
            }
        }
        for chunk in unique_record_ids.chunks(500) {
            let rows = ip_record::Entity::find()
                .select_only()
                .column(ip_record::Column::Id)
                .column(ip_record::Column::TargetAddress)
                .filter(ip_record::Column::Id.is_in(chunk.iter().copied()))
                .into_tuple::<(Uuid, String)>()
                .all(txn)
                .await?;
            candidates.extend(rows);
        }
    } else {
        let exact_vec: Vec<String> = exact_candidates.into_iter().collect();
        for chunk in exact_vec.chunks(500) {
            let rows = ip_record::Entity::find()
                .filter(ip_record::Column::TargetAddress.is_in(chunk.iter().cloned()))
                .select_only()
                .column(ip_record::Column::Id)
                .column(ip_record::Column::TargetAddress)
                .into_tuple::<(Uuid, String)>()
                .all(txn)
                .await?;
            candidates.extend(rows);
        }

        for (start, end) in range_scans {
            let rows = ip_record::Entity::find()
                .filter(ip_record::Column::TargetAddress.gte(start))
                .filter(ip_record::Column::TargetAddress.lt(end))
                .select_only()
                .column(ip_record::Column::Id)
                .column(ip_record::Column::TargetAddress)
                .into_tuple::<(Uuid, String)>()
                .all(txn)
                .await?;
            candidates.extend(rows);
        }
    }

    let mut matched = HashMap::new();
    for (id, addr) in candidates {
        let Ok(candidate_net) = super::support::parse_cidr_or_ip(&addr) else {
            continue;
        };
        if let Some((_, wl_name)) = protected
            .iter()
            .find(|(protected_net, _)| networks_overlap(&candidate_net, protected_net))
        {
            matched.insert(id, (addr, wl_name.clone()));
        }
    }
    Ok(matched)
}

async fn soft_delete_excluded_memberships(
    txn: &DatabaseTransaction,
    key: &api_key::Model,
    client_ip: std::net::IpAddr,
    banlist_groups: &[(Uuid, String)],
    matched: &HashMap<Uuid, (String, String)>,
    now: time::PrimitiveDateTime,
    skip_webhooks: bool,
) -> Result<Vec<WebhookEvent>, AppError> {
    let banlist_ids: Vec<Uuid> = banlist_groups.iter().map(|(id, _)| *id).collect();
    let banlist_name_by_id: HashMap<Uuid, &str> = banlist_groups
        .iter()
        .map(|(id, name)| (*id, name.as_str()))
        .collect();
    let matched_ids: Vec<Uuid> = matched.keys().copied().collect();
    let mut webhook_events = Vec::new();

    for chunk in matched_ids.chunks(500) {
        let memberships = ip_record_group_membership::Entity::find()
            .filter(ip_record_group_membership::Column::IsDeleted.eq(false))
            .filter(ip_record_group_membership::Column::GroupId.is_in(banlist_ids.iter().copied()))
            .filter(ip_record_group_membership::Column::IpRecordId.is_in(chunk.iter().copied()))
            .all(txn)
            .await?;

        if memberships.is_empty() {
            continue;
        }

        let membership_ids: Vec<Uuid> = memberships.iter().map(|m| m.id).collect();
        ip_record_group_membership::Entity::update_many()
            .col_expr(
                ip_record_group_membership::Column::IsDeleted,
                Expr::value(true),
            )
            .col_expr(
                ip_record_group_membership::Column::DeletedAt,
                Expr::value(Some(now)),
            )
            .col_expr(
                ip_record_group_membership::Column::DeletedBy,
                Expr::value(Some(key.id.to_string())),
            )
            .filter(ip_record_group_membership::Column::Id.is_in(membership_ids))
            .exec(txn)
            .await?;

        for m in memberships {
            let Some((address, wl_name)) = matched.get(&m.ip_record_id) else {
                continue;
            };
            let ban_name = banlist_name_by_id
                .get(&m.group_id)
                .copied()
                .unwrap_or_default()
                .to_owned();
            let reason = format!("Excluded by whitelist {wl_name}");
            create_audit_log(
                txn,
                key,
                client_ip,
                "IP_SOFT_DELETE",
                Some(address.clone()),
                Some(ban_name.clone()),
                Some(reason.clone()),
            )
            .await?;
            if !skip_webhooks {
                webhook_events.push(WebhookEvent {
                    action: "IP_DELETE".to_owned(),
                    address: address.clone(),
                    is_whitelist: false,
                    group_id: Some(m.group_id),
                    group_name: Some(ban_name),
                    cause: Some(reason),
                });
            }
        }
    }

    Ok(webhook_events)
}

/// Retroactively soft-deletes active bans in `banlist_groups` that overlap any network in
/// `protected`, using indexed exact/supernet/range lookups (never a full `ip_records` scan).
pub(crate) async fn purge_excluded_bans_for_networks(
    txn: &DatabaseTransaction,
    key: &api_key::Model,
    client_ip: std::net::IpAddr,
    banlist_groups: &[(Uuid, String)],
    protected: &[(IpNet, String)],
    now: time::PrimitiveDateTime,
    skip_webhooks: bool,
) -> Result<Vec<WebhookEvent>, AppError> {
    if banlist_groups.is_empty() || protected.is_empty() {
        return Ok(Vec::new());
    }

    let banlist_ids: Vec<Uuid> = banlist_groups.iter().map(|(id, _)| *id).collect();
    let matched = find_matching_excluded_records(txn, &banlist_ids, protected).await?;
    if matched.is_empty() {
        return Ok(Vec::new());
    }

    soft_delete_excluded_memberships(
        txn,
        key,
        client_ip,
        banlist_groups,
        &matched,
        now,
        skip_webhooks,
    )
    .await
}

async fn enforce_exclusions(
    db: &impl ConnectionTrait,
    group_id: Uuid,
    input: IpNet,
    stored: IpNet,
) -> Result<(), AppError> {
    let protected = load_protected_networks(db, group_id).await?;
    let names: BTreeSet<_> = matching_whitelists(&protected, input, stored).collect();
    if !names.is_empty() {
        return Err(AppError::Conflict(format!(
            "Ban overlaps protected whitelist groups: {}",
            names.into_iter().collect::<Vec<_>>().join(", ")
        )));
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
    now: time::PrimitiveDateTime,
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

async fn authorize_ip_upsert(
    db: &impl ConnectionTrait,
    key: &api_key::Model,
    group: &ip_group::Model,
    is_whitelist: bool,
) -> Result<(), AppError> {
    if !key.is_master {
        let perm = api_key_group_permission::Entity::find()
            .filter(
                Condition::all()
                    .add(api_key_group_permission::Column::ApiKeyId.eq(key.id))
                    .add(api_key_group_permission::Column::GroupId.eq(group.id)),
            )
            .one(db)
            .await?;

        if let Some(p) = perm {
            if !p.can_write {
                return Err(AppError::Forbidden(
                    "Permission denied: You do not have write access to this group".to_owned(),
                ));
            }
        } else {
            return Err(AppError::Forbidden(
                "Permission denied: You have no access strictly mapped to this group".to_owned(),
            ));
        }
    }

    if is_whitelist && group.group_type == "banlist" {
        return Err(AppError::InvalidInput(format!(
            "Cannot whitelist IP into group '{}': group type is 'banlist'. Use /api/ban or target a whitelist group.",
            group.name
        )));
    }
    if !is_whitelist && group.group_type == "whitelist" {
        return Err(AppError::InvalidInput(format!(
            "Cannot ban IP into group '{}': group type is 'whitelist'. Use /api/white or target a banlist group.",
            group.name
        )));
    }
    Ok(())
}

async fn resolve_upsert_target_group(
    db: &impl ConnectionTrait,
    key: &api_key::Model,
    group_id: Option<Uuid>,
    group_name: Option<&str>,
    ban: Option<(&IpNet, &str)>,
) -> Result<ip_group::Model, AppError> {
    let is_whitelist = ban.is_none();
    if let Some(g) = resolve_group_ref(db, group_id, group_name).await? {
        authorize_ip_upsert(db, key, &g, is_whitelist).await?;
        return Ok(g);
    }

    let Some(group_name) = group_name else {
        return Err(AppError::NotFound);
    };

    if !key.is_master && !key.can_create_groups {
        return Err(AppError::Forbidden(
            "Permission denied: Target group does not exist and you cannot create groups"
                .to_owned(),
        ));
    }

    if let Some((input, stored_address)) = ban {
        validate_ban_networks(input, stored_address, false)?;
    }

    let default_type = if is_whitelist { "whitelist" } else { "banlist" };
    let (group, created) =
        get_or_create_group_with_status(db, group_name, default_type, resource_owner(key)).await?;
    if !created {
        authorize_ip_upsert(db, key, &group, is_whitelist).await?;
        return Ok(group);
    }

    if !key.is_master {
        let now = crate::time_serde::now_utc();
        let perm = api_key_group_permission::ActiveModel {
            id: Set(Uuid::new_v4()),
            api_key_id: Set(key.id),
            group_id: Set(group.id),
            can_read: Set(true),
            can_write: Set(true),
            can_delete: Set(true),
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
                .to_owned(),
            )
            .exec_without_returning(db)
            .await?;
    }

    Ok(group)
}

async fn apply_membership_upsert(
    txn: &DatabaseTransaction,
    target_group_id: Uuid,
    stored_address: &str,
    cause: Option<&str>,
    now: time::PrimitiveDateTime,
) -> Result<&'static str, AppError> {
    let (address_row, _) = find_or_insert_address(txn, stored_address, now).await?;

    let existing = ip_record_group_membership::Entity::find()
        .filter(ip_record_group_membership::Column::IpRecordId.eq(address_row.id))
        .filter(ip_record_group_membership::Column::GroupId.eq(target_group_id))
        .one(txn)
        .await?;

    let (membership_id, action) = if let Some(membership) = existing {
        if membership.is_locked {
            return Err(AppError::Forbidden(
                "This IP is protected and cannot be modified".to_owned(),
            ));
        }
        let was_deleted = membership.is_deleted;
        let mut active: ip_record_group_membership::ActiveModel = membership.into();
        active.last_seen_at = Set(now);
        if was_deleted {
            active.is_deleted = Set(false);
            active.deleted_at = Set(None);
            active.deleted_by = Set(None);
        }
        let updated = active.update(txn).await?;
        (updated.id, "IP_UPDATE")
    } else {
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
        .insert(txn)
        .await?;
        (id, "IP_ADD")
    };

    if let Some(text) = cause {
        ip_record_cause::ActiveModel {
            id: Set(Uuid::new_v4()),
            membership_id: Set(membership_id),
            cause: Set(text.to_owned()),
            created_at: Set(now),
        }
        .insert(txn)
        .await?;
    }

    Ok(action)
}

pub(crate) async fn handle_ip_upsert(
    state: AppState,
    key: api_key::Model,
    client_ip: std::net::IpAddr,
    payload: BanWhitePayload,
    is_whitelist: bool,
) -> Result<impl IntoResponse, AppError> {
    let network: IpNet = super::support::parse_cidr_or_ip(&payload.target_address)
        .map_err(|()| AppError::InvalidInput("Invalid IP or CIDR format".to_owned()))?;
    let canonical_input_address = normalize_ip_or_cidr(&payload.target_address);
    let normalize_v6_48 = !is_whitelist && state.is_ipv6_48_normalization_enabled();
    let stored_address = normalize_ipv6_ban_storage(&payload.target_address, normalize_v6_48);

    let txn = state
        .db
        .begin_with_options(TransactionOptions {
            sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
            ..Default::default()
        })
        .await?;
    let ban = (!is_whitelist).then_some((&network, stored_address.as_str()));
    let group = resolve_upsert_target_group(
        &txn,
        &key,
        payload.group_id,
        payload.group_name.as_deref(),
        ban,
    )
    .await?;
    if !is_whitelist {
        let stored = validate_ban_networks(&network, &stored_address, group.allow_private_ips)?;
        enforce_exclusions(&txn, group.id, network, stored).await?;
    }
    let target_group_id = group.id;
    let resolved_group_name = group.name;
    let now = crate::time_serde::now_utc();
    let cause = payload
        .cause
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
        .map(str::to_owned);

    let action = apply_membership_upsert(
        &txn,
        target_group_id,
        &stored_address,
        cause.as_deref(),
        now,
    )
    .await?;

    let purge_events = if is_whitelist {
        let banlists = load_excluding_banlists(&txn, target_group_id).await?;
        if banlists.is_empty() {
            Vec::new()
        } else {
            let protected = vec![(network, resolved_group_name.clone())];
            purge_excluded_bans_for_networks(
                &txn, &key, client_ip, &banlists, &protected, now, false,
            )
            .await?
        }
    } else {
        Vec::new()
    };

    create_audit_log(
        &txn,
        &key,
        client_ip,
        action,
        Some(stored_address.clone()),
        Some(resolved_group_name.clone()),
        Some(format!("Added IP to group. Whitelist: {is_whitelist}")),
    )
    .await?;

    state.commit_membership_write(txn).await?;

    state.enqueue_webhook(WebhookEvent {
        action: action.to_owned(),
        address: canonical_input_address,
        is_whitelist,
        group_id: Some(target_group_id),
        group_name: Some(resolved_group_name),
        cause,
    });
    for event in purge_events {
        state.enqueue_webhook(event);
    }

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
    /// Filter by an IP, CIDR, address prefix, or substring.
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
    /// Pagination offset. Mutually exclusive with `cursor`.
    pub offset: Option<u64>,
    /// Keyset pagination cursor. Pass an empty string (`cursor=`) for the first page, or the
    /// `next_cursor` returned by the previous page. Mutually exclusive with `offset` and
    /// `format=iplist`. Wraps the response in `{data, next_cursor}`.
    pub cursor: Option<String>,
    /// `"iplist"` (accepted under either key) returns `{"ip_list": [...]}` of matched addresses;
    /// `"minimal"` returns only `(target_address, last_seen_at, is_deleted)` per row, skipping the
    /// group and cause resolution queries.
    pub format: Option<String>,
    /// Synonym for `format`.
    pub mode: Option<String>,
    /// Also return soft-deleted memberships. Available to any caller, scoped exactly as live ones.
    pub include_deleted: Option<bool>,
    /// Wrap the response in `{data, total, limit, offset, total_pages, next_cursor}`. Opt-in; the
    /// bare array is the default when neither `include_total` nor `cursor` is passed. Ignored under
    /// `format=iplist`.
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
    #[serde(with = "crate::time_serde")]
    pub created_at: time::PrimitiveDateTime,
    /// The latest observation of this address in this group.
    #[serde(with = "crate::time_serde")]
    pub last_seen_at: time::PrimitiveDateTime,
    /// Whether this membership is soft-deleted. Always `false` in a normal listing.
    pub is_deleted: bool,
    /// When it was soft-deleted, if it was.
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "crate::time_serde::option")]
    pub deleted_at: Option<time::PrimitiveDateTime>,
    /// The key that soft-deleted it. **Master only**; omitted for every other caller.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted_by: Option<String>,
}

/// Stripped membership row returned under `format=minimal` / `mode=minimal`.
///
/// Carries only the three fields a downstream feed exporter consumes (`target_address`,
/// `last_seen_at`, `is_deleted`), allowing [`list_ips`] to skip the per-page `ip_groups` and
/// `ip_record_causes` lookup queries entirely.
#[derive(Serialize)]
pub struct MinimalIpRecordResponse {
    /// The address or CIDR range.
    pub target_address: String,
    /// The latest observation of this address in this group.
    #[serde(with = "crate::time_serde")]
    pub last_seen_at: time::PrimitiveDateTime,
    /// Whether this membership is soft-deleted.
    pub is_deleted: bool,
}

/// Response envelope for `GET /api/ips?include_total=true`.
#[derive(Serialize)]
pub struct IpRecordsEnvelope<T = IpRecordResponse> {
    /// The page of memberships.
    pub data: Vec<T>,
    /// Total memberships matching every filter, across all pages.
    pub total: u64,
    /// The effective `limit`.
    pub limit: u64,
    /// The effective `offset`.
    pub offset: u64,
    /// `ceil(total / limit)`, or `0` when there is nothing to page through.
    pub total_pages: u64,
    /// Opaque keyset cursor for the next page, or `None` when this page reached the end.
    pub next_cursor: Option<String>,
}

/// Response envelope for `GET /api/ips?cursor=…` when `include_total` is not requested.
///
/// Omits `total` / `total_pages` so cursor pagination never pays for a `COUNT(*)` query; the end of
/// the walk is signalled by `next_cursor: None`.
#[derive(Serialize)]
pub struct IpRecordsCursorEnvelope<T = IpRecordResponse> {
    /// The page of memberships.
    pub data: Vec<T>,
    /// Opaque keyset cursor for the next page, or `None` when this page reached the end.
    pub next_cursor: Option<String>,
}

/// Decoded keyset cursor: the `(last_seen_at, membership_id)` boundary of the previous page's last
/// row, matching `ORDER BY last_seen_at DESC, id ASC`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct KeysetCursor {
    last_seen_at: time::PrimitiveDateTime,
    id: Uuid,
}

impl KeysetCursor {
    /// Encodes a row's sort key into an opaque hex token (`hex("<last_seen_at>|<id>")`).
    ///
    /// Hex is URL-safe without percent-encoding (`0-9a-f` only) and already in the dependency tree.
    fn encode(last_seen_at: time::PrimitiveDateTime, id: Uuid) -> Result<String, AppError> {
        let timestamp = last_seen_at
            .assume_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .map_err(|error| AppError::DbError(sea_orm::DbErr::Custom(error.to_string())))?;
        Ok(hex::encode(format!("{timestamp}|{id}")))
    }

    /// Parses an opaque cursor token. Rejects malformed hex, missing delimiters, or invalid
    /// timestamps/UUIDs with `400 Bad Request`.
    fn decode(encoded: &str) -> Result<Self, AppError> {
        let bytes = hex::decode(encoded.trim())
            .map_err(|_| AppError::InvalidInput("Invalid cursor: malformed encoding".to_owned()))?;
        let text = std::str::from_utf8(&bytes)
            .map_err(|_| AppError::InvalidInput("Invalid cursor: non-UTF-8 payload".to_owned()))?;
        let (ts_str, id_str) = text.split_once('|').ok_or_else(|| {
            AppError::InvalidInput("Invalid cursor: missing delimiter".to_owned())
        })?;
        let last_seen_at = crate::time_serde::parse(ts_str)
            .map_err(|_| AppError::InvalidInput("Invalid cursor: bad timestamp".to_owned()))?;
        let id = Uuid::parse_str(id_str)
            .map_err(|_| AppError::InvalidInput("Invalid cursor: bad membership id".to_owned()))?;
        Ok(Self { last_seen_at, id })
    }

    /// Keyset seek predicate for `ORDER BY last_seen_at DESC, id ASC`:
    /// `last_seen_at <= :cur_ts AND (last_seen_at < :cur_ts OR (last_seen_at = :cur_ts AND id > :cur_id))`.
    ///
    /// The leading `last_seen_at <= :cur_ts` conjunct is algebraically redundant with the `OR`
    /// clause beside it, and load-bearing for SQLite's query planner: SQLite does not extract a
    /// range bound on `last_seen_at` out of a disjunction, so without the top-level `<=` term it
    /// scans the `group_id = ?` index partition from the newest row down (`O(offset)`). With it,
    /// the B-tree seek jumps straight to `(group_id = ?, last_seen_at <= :cur_ts)`.
    fn condition(self) -> Condition {
        Condition::all()
            .add(ip_record_group_membership::Column::LastSeenAt.lte(self.last_seen_at))
            .add(
                Condition::any()
                    .add(ip_record_group_membership::Column::LastSeenAt.lt(self.last_seen_at))
                    .add(
                        Condition::all()
                            .add(
                                ip_record_group_membership::Column::LastSeenAt
                                    .eq(self.last_seen_at),
                            )
                            .add(ip_record_group_membership::Column::Id.gt(self.id)),
                    ),
            )
    }
}

/// The empty-result shape for [`list_ips`] in whichever response form the caller asked for.
fn empty_ips_response(
    format_iplist: bool,
    include_total: bool,
    cursor_mode: bool,
    limit: u64,
    offset: u64,
) -> axum::response::Response {
    if format_iplist {
        return Json(serde_json::json!({ "ip_list": Vec::<String>::new() })).into_response();
    }
    if include_total {
        return Json(IpRecordsEnvelope::<IpRecordResponse> {
            data: Vec::new(),
            total: 0,
            limit,
            offset,
            total_pages: 0,
            next_cursor: None,
        })
        .into_response();
    }
    if cursor_mode {
        return Json(IpRecordsCursorEnvelope::<IpRecordResponse> {
            data: Vec::new(),
            next_cursor: None,
        })
        .into_response();
    }
    Json(Vec::<IpRecordResponse>::new()).into_response()
}

/// Above this many groups, [`fetch_merged_page`]'s one-query-per-group approach costs more than a
/// single `GroupId IN (...)` query with a sort. The production complaint this exists for (`group_id
/// IN (?, ?, ?, ?)`) is a handful of groups; past this bound, a broad RBAC grant or a long `groups=`
/// list falls back to the plain `IN (...)` query instead.
const MERGE_MAX_GROUPS: usize = 16;
/// Above this `offset + limit`, each per-group query in [`fetch_merged_page`] would itself need to
/// fetch too many rows to stay cheap (every one of them fetches `offset + limit`, since the globally
/// correct page can draw unevenly from any group). Deep pagination across several groups falls back
/// to the single `IN (...)` query instead — slower, but correct, and a rare access pattern next to
/// the first few pages a dashboard actually loads.
const MERGE_MAX_FETCH: u64 = 2000;

/// How the resolved group constraint is applied to the membership query.
enum GroupScope {
    /// No group constraint (master querying all groups).
    Unfiltered,
    /// Exactly one group ID.
    Single(Uuid),
    /// A small set of groups (`<= MERGE_MAX_GROUPS`) fetched individually by [`fetch_merged_page`]
    /// and counted with a single `IN (...)` predicate in [`count_matching`].
    Merge(Vec<Uuid>),
    /// A large set of groups or deep offset pagination that uses `GroupId IN (...)`.
    In(Vec<Uuid>),
}

impl GroupScope {
    fn predicate(&self) -> Option<sea_orm::sea_query::SimpleExpr> {
        match self {
            Self::Unfiltered => None,
            Self::Single(only_id) => Some(ip_record_group_membership::Column::GroupId.eq(*only_id)),
            Self::Merge(ids) | Self::In(ids) => {
                Some(ip_record_group_membership::Column::GroupId.is_in(ids.iter().copied()))
            }
        }
    }
}

/// Combines a base [`Condition`] with an optional group predicate and an optional `since` window.
///
/// When both `since` and `include_deleted` are active alongside a group predicate (`group_id = ?`
/// or `group_id IN (...)`), the group predicate is distributed into both arms of the `OR`:
///
/// ```sql
/// ((group_id = ? AND last_seen_at >= ?) OR (group_id = ? AND is_deleted = ? AND deleted_at >= ?))
/// ```
///
/// Factoring `group_id = ?` out at the top level (`group_id = ? AND (last_seen_at >= ? OR ...)`)
/// tempts SQLite's planner into scanning the entire `group_id` partition of
/// `idx_memberships_group_last_seen` in `ORDER BY last_seen_at DESC` order — which cannot stop at
/// `last_seen_at < threshold` because older rows might still satisfy `deleted_at >= threshold`.
/// Distributing `group_id` into each arm removes the top-level equality, forcing SQLite's planner
/// to use `MULTI-INDEX OR` (`idx_memberships_group_last_seen` for the `last_seen_at` range seek +
/// `idx_memberships_group_deleted_at` for the `deleted_at` range seek).
#[must_use]
pub fn apply_group_and_since_scope(
    base: &Condition,
    group_pred: Option<sea_orm::sea_query::SimpleExpr>,
    since_threshold: Option<time::PrimitiveDateTime>,
    include_deleted: bool,
) -> Condition {
    let mut cond = base.clone();
    match (group_pred, since_threshold, include_deleted) {
        (Some(gp), Some(threshold), true) => {
            cond = cond.add(
                Condition::any()
                    .add(
                        Condition::all()
                            .add(gp.clone())
                            .add(ip_record_group_membership::Column::LastSeenAt.gte(threshold)),
                    )
                    .add(
                        Condition::all()
                            .add(gp)
                            .add(ip_record_group_membership::Column::IsDeleted.eq(true))
                            .add(ip_record_group_membership::Column::DeletedAt.gte(threshold)),
                    ),
            );
        }
        (None, Some(threshold), true) => {
            cond = cond.add(
                Condition::any()
                    .add(ip_record_group_membership::Column::LastSeenAt.gte(threshold))
                    .add(
                        Condition::all()
                            .add(ip_record_group_membership::Column::IsDeleted.eq(true))
                            .add(ip_record_group_membership::Column::DeletedAt.gte(threshold)),
                    ),
            );
        }
        (gp, since_opt, _) => {
            if let Some(gp) = gp {
                cond = cond.add(gp);
            }
            if let Some(threshold) = since_opt {
                cond = cond.add(
                    Condition::any()
                        .add(ip_record_group_membership::Column::LastSeenAt.gte(threshold)),
                );
            }
        }
    }
    cond
}

fn membership_query(
    address: Option<&Condition>,
    scoped: Condition,
    select_record: bool,
) -> sea_orm::Select<ip_record_group_membership::Entity> {
    use ip_record_group_membership::{Column as Membership, Entity as Memberships};

    let mut query = Memberships::find();
    if let Some(matching) = address {
        // Keep the address seek on the outer side of the join. SQLite can then
        // probe memberships by record ID before sorting just the matched rows.
        QueryTrait::query(&mut query)
            .from_clear()
            .from(ip_record::Entity)
            .cross_join(Memberships);
        let query = query.filter(matching.clone()).filter(
            Expr::col((Memberships, Membership::IpRecordId))
                .equals((ip_record::Entity, ip_record::Column::Id)),
        );
        // SQLite can prefer a covering group/status or sort index and scan it
        // once per address. Keep the remaining scope as a residual predicate so
        // the inner lookup uses the record ID before applying the scope.
        if scoped.is_empty() {
            query
        } else {
            let predicate: Expr = Expr::case(scoped, true).finally(false).into();
            query.filter(predicate)
        }
    } else {
        if select_record {
            query = query.join(
                JoinType::InnerJoin,
                ip_record_group_membership::Relation::IpRecord.def(),
            );
        }
        query.filter(scoped)
    }
}

/// Counts memberships matching the authorized scope and filters.
async fn count_matching(
    state: &AppState,
    scoped: Condition,
    address: Option<&Condition>,
    cacheable: bool,
) -> Result<u64, AppError> {
    // `COUNT(*)`, not `COUNT(id)`: the partial index on `(group_id, last_seen_at)` does not carry
    // `id`, so counting that column forces a table lookup per matching row and loses "COVERING
    // INDEX" — about 10x slower on this schema (measured: COUNT(id) 1.4ms vs COUNT(*) 0.14ms per
    // group at 100k rows; this is also what made the production `COUNT(... IN (?,?,?,?))` query
    // take 5.8s). `COUNT(*)` needs no column value, so SQLite answers it from the index alone.
    let query = membership_query(address, scoped, false)
        .select_only()
        .expr_as(
            Func::count(Expr::col(sea_orm::sea_query::Asterisk)),
            "row_count",
        );
    let count = || async {
        let result = query.clone().into_tuple::<i64>().one(&state.db).await?;
        Ok(std::cmp::max(result.unwrap_or(0), 0).cast_unsigned())
    };
    if !cacheable {
        return count().await;
    }
    let key = format!("{:?}", query.build(state.db.get_database_backend()));
    state.cached_membership_count(key, count).await
}

/// Fetches one page across a small, explicit set of groups without an SQL `ORDER BY` that spans
/// them.
///
struct MergedPageFetch<'a> {
    base_condition: &'a Condition,
    since_threshold: Option<time::PrimitiveDateTime>,
    include_deleted: bool,
    cursor: Option<KeysetCursor>,
    group_ids: &'a [Uuid],
    offset: u64,
    limit: u64,
}

/// The partial index `idx_memberships_active_last_seen` is `(group_id, last_seen_at DESC, id ASC,
/// …) WHERE is_deleted = FALSE` — it sorts *within* one `group_id`, not across several. A `GroupId
/// IN (...)` with `ORDER BY last_seen_at` therefore cannot be served from it directly; SQLite scans
/// the matching rows and sorts them in a temp b-tree instead, which is what turns a page read into
/// a full scan as a group grows. Querying each group individually keeps every query on the
/// indexed, pre-sorted path: no sort, and no more than `offset + limit` rows read per group (just
/// `limit` in cursor mode, where `offset` is `0`). The merge happens in Rust instead, which is
/// cheap because each input is already sorted and the inputs are few.
async fn fetch_merged_page(
    db: &sea_orm::DatabaseConnection,
    fetch: MergedPageFetch<'_>,
) -> Result<Vec<(ip_record_group_membership::Model, Option<ip_record::Model>)>, AppError> {
    let take = fetch.offset.saturating_add(fetch.limit);
    let mut merged = Vec::with_capacity(
        fetch
            .group_ids
            .len()
            .saturating_mul(usize::try_from(take).unwrap_or(usize::MAX)),
    );
    for &group_id in fetch.group_ids {
        let mut scoped = apply_group_and_since_scope(
            fetch.base_condition,
            Some(ip_record_group_membership::Column::GroupId.eq(group_id)),
            fetch.since_threshold,
            fetch.include_deleted,
        );
        if let Some(cur) = fetch.cursor {
            scoped = scoped.add(cur.condition());
        }
        let rows = ip_record_group_membership::Entity::find()
            .join(
                JoinType::InnerJoin,
                ip_record_group_membership::Relation::IpRecord.def(),
            )
            .select_also(ip_record::Entity)
            .filter(scoped)
            .order_by_desc(ip_record_group_membership::Column::LastSeenAt)
            .order_by_asc(ip_record_group_membership::Column::Id)
            .limit(take)
            .all(db)
            .await?;
        merged.extend(rows);
    }
    merged.sort_by_key(|(m, _)| (std::cmp::Reverse(m.last_seen_at), m.id));
    Ok(merged
        .into_iter()
        .skip(usize::try_from(fetch.offset).unwrap_or(usize::MAX))
        .take(usize::try_from(fetch.limit).unwrap_or(usize::MAX))
        .collect())
}

async fn resolve_list_group_scope(
    db: &sea_orm::DatabaseConnection,
    key: &api_key::Model,
    filters: &QueryFilters,
    cursor_mode: bool,
    limit: u64,
    offset: u64,
) -> Result<Option<GroupScope>, AppError> {
    let mut group_constraints: Vec<std::collections::HashSet<Uuid>> = Vec::new();

    if !key.is_master {
        let accessible_groups: std::collections::HashSet<Uuid> =
            api_key_group_permission::Entity::find()
                .filter(
                    Condition::all()
                        .add(api_key_group_permission::Column::ApiKeyId.eq(key.id))
                        .add(api_key_group_permission::Column::CanRead.eq(true)),
                )
                .all(db)
                .await?
                .into_iter()
                .map(|p| p.group_id)
                .collect();
        if accessible_groups.is_empty() {
            return Ok(None);
        }
        group_constraints.push(accessible_groups);
    }

    let mut group_names: Vec<String> = Vec::new();
    if let Some(groups) = &filters.groups
        && !groups.is_empty()
    {
        group_names.extend(
            groups
                .split(',')
                .map(|s| s.trim().to_owned())
                .filter(|s| !s.is_empty()),
        );
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
                .all(db)
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
            other => {
                return Err(AppError::InvalidInput(format!(
                    "Invalid status filter: {other}"
                )));
            }
        };
        let typed: std::collections::HashSet<Uuid> = ip_group::Entity::find()
            .filter(ip_group::Column::GroupType.eq(group_type))
            .all(db)
            .await?
            .into_iter()
            .map(|g| g.id)
            .collect();
        group_constraints.push(typed);
    }

    let mut group_scope = GroupScope::Unfiltered;
    if let Some(mut intersected) = group_constraints.pop() {
        for set in &group_constraints {
            intersected.retain(|g| set.contains(g));
        }
        if intersected.is_empty() {
            return Ok(None);
        }
        if intersected.len() == 1 {
            if let Some(only_id) = intersected.into_iter().next() {
                group_scope = GroupScope::Single(only_id);
            }
        } else if intersected.len() <= MERGE_MAX_GROUPS
            && (cursor_mode || offset.saturating_add(limit) <= MERGE_MAX_FETCH)
        {
            group_scope = GroupScope::Merge(intersected.into_iter().collect());
        } else {
            group_scope = GroupScope::In(intersected.into_iter().collect());
        }
    }

    Ok(Some(group_scope))
}

fn address_range(prefix: &str) -> sea_orm::sea_query::SimpleExpr {
    // All callers supply a nonempty ASCII address prefix. Increment its last byte to
    // get the exclusive upper bound, without including the next lexical prefix.
    let (last, head) = prefix.split_at(prefix.len() - 1);
    let upper = format!("{last}{}", char::from(head.as_bytes()[0] + 1));
    ip_record::Column::TargetAddress
        .gte(prefix)
        .and(ip_record::Column::TargetAddress.lt(upper))
}

fn is_address_prefix(term: &str) -> bool {
    if term.contains(':') {
        // Complete a partial last hextet (including a trailing colon) and allow
        // omitted trailing hextets. Parsing rejects invalid compression and lengths.
        let completed = if term.ends_with(':') && !term.ends_with("::") {
            format!("{term}0")
        } else {
            term.to_owned()
        };
        completed.parse::<Ipv6Addr>().is_ok()
            || format!("{completed}::").parse::<Ipv6Addr>().is_ok()
    } else if term.contains('.') {
        let octets: Vec<_> = term.split('.').collect();
        octets.len() <= 4
            && octets.iter().enumerate().all(|(index, octet)| {
                (octet.is_empty() && index > 0 && index + 1 == octets.len())
                    || (octet.bytes().all(|b| b.is_ascii_digit()) && octet.parse::<u8>().is_ok())
            })
    } else {
        false
    }
}

fn address_condition(term: &str, normalize_ipv6: bool) -> Condition {
    let mut matching = Condition::any();
    if term.parse::<IpNet>().is_ok() || term.parse::<std::net::IpAddr>().is_ok() {
        let canonical = normalize_ip_or_cidr(term);
        if canonical.contains('/') {
            return matching.add(ip_record::Column::TargetAddress.eq(canonical));
        }
        // Preserve lookup by a network's bare base address with a slash-bounded range.
        matching = matching
            .add(address_range(&format!("{canonical}/")))
            .add(ip_record::Column::TargetAddress.eq(&canonical));
        let normalized = normalize_ipv6_ban_storage(term, normalize_ipv6);
        if normalized != canonical {
            matching = matching.add(ip_record::Column::TargetAddress.eq(normalized));
        }
    } else if is_address_prefix(term) {
        matching = matching.add(address_range(&term.to_ascii_lowercase()));
    } else {
        matching = matching.add(ip_record::Column::TargetAddress.contains(term));
    }
    matching
}

fn build_list_filter_condition(
    state: &AppState,
    filters: &QueryFilters,
    include_deleted: bool,
) -> (Condition, Option<Condition>) {
    let mut condition = Condition::all();
    if !include_deleted {
        condition = condition.add(ip_record_group_membership::Column::IsDeleted.eq(false));
    }

    let address = filters
        .ip
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(|term| address_condition(term, state.is_ipv6_48_normalization_enabled()));

    if let Some(cause) = filters
        .cause
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        let matching = Query::select()
            .column((
                ip_record_cause::Entity,
                ip_record_cause::Column::MembershipId,
            ))
            .from(ip_record_cause::Entity)
            .and_where(ip_record_cause::Column::Cause.contains(cause))
            .to_owned();
        condition = condition.add(
            Expr::col((
                ip_record_group_membership::Entity,
                ip_record_group_membership::Column::Id,
            ))
            .in_subquery(matching),
        );
    }

    if let Some(age) = filters.max_age {
        let threshold = crate::time_serde::now_utc().saturating_sub(time::Duration::seconds(age));
        condition = condition.add(ip_record_group_membership::Column::LastSeenAt.gte(threshold));
    }

    (condition, address)
}

async fn format_list_ips_response(
    db: &sea_orm::DatabaseConnection,
    key: &api_key::Model,
    page: Vec<(ip_record_group_membership::Model, Option<ip_record::Model>)>,
    opts: ListResponseOpts,
) -> Result<axum::response::Response, AppError> {
    if opts.format_iplist {
        let mut ip_list: Vec<String> = page
            .into_iter()
            .filter_map(|(_, record)| record.map(|r| r.target_address))
            .collect();
        ip_list.sort();
        ip_list.dedup();
        return Ok(Json(serde_json::json!({ "ip_list": ip_list })).into_response());
    }

    if opts.format_minimal {
        let items: Vec<MinimalIpRecordResponse> = page
            .into_iter()
            .filter_map(|(mem, record)| {
                let record = record?;
                Some(MinimalIpRecordResponse {
                    target_address: record.target_address,
                    last_seen_at: mem.last_seen_at,
                    is_deleted: mem.is_deleted,
                })
            })
            .collect();
        return Ok(list_items_response(items, opts));
    }

    let page_group_ids: Vec<Uuid> = page.iter().map(|(m, _)| m.group_id).collect();
    let groups: std::collections::HashMap<Uuid, ip_group::Model> = if page_group_ids.is_empty() {
        std::collections::HashMap::new()
    } else {
        ip_group::Entity::find()
            .filter(ip_group::Column::Id.is_in(page_group_ids))
            .all(db)
            .await?
            .into_iter()
            .map(|g| (g.id, g))
            .collect()
    };
    let page_membership_ids: Vec<Uuid> = page.iter().map(|(m, _)| m.id).collect();
    let mut latest_cause: std::collections::HashMap<Uuid, String> =
        std::collections::HashMap::new();
    if !page_membership_ids.is_empty() {
        for row in ip_record_cause::Entity::find()
            .filter(ip_record_cause::Column::MembershipId.is_in(page_membership_ids))
            .order_by_desc(ip_record_cause::Column::CreatedAt)
            .all(db)
            .await?
        {
            latest_cause.entry(row.membership_id).or_insert(row.cause);
        }
    }

    let mut items = Vec::with_capacity(page.len());
    for (mem, record) in page {
        let Some(record) = record else { continue };
        let Some(group) = groups.get(&mem.group_id) else {
            continue;
        };
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

    Ok(list_items_response(items, opts))
}

fn list_items_response<T: Serialize>(
    items: Vec<T>,
    opts: ListResponseOpts,
) -> axum::response::Response {
    if let Some(total) = opts.total {
        let total_pages = if opts.limit == 0 {
            0
        } else {
            total.div_ceil(opts.limit)
        };
        return Json(IpRecordsEnvelope {
            data: items,
            total,
            limit: opts.limit,
            offset: opts.offset,
            total_pages,
            next_cursor: opts.next_cursor,
        })
        .into_response();
    }
    if opts.cursor_mode {
        return Json(IpRecordsCursorEnvelope {
            data: items,
            next_cursor: opts.next_cursor,
        })
        .into_response();
    }
    Json(items).into_response()
}

struct ListResponseOpts {
    format_iplist: bool,
    format_minimal: bool,
    total: Option<u64>,
    cursor_mode: bool,
    limit: u64,
    offset: u64,
    next_cursor: Option<String>,
}

struct ListPageRequest<'a> {
    condition: &'a Condition,
    address: Option<&'a Condition>,
    group_predicate: Option<sea_orm::sea_query::SimpleExpr>,
    since_threshold: Option<time::PrimitiveDateTime>,
    include_deleted: bool,
    cursor: Option<KeysetCursor>,
    offset: u64,
    limit: u64,
    needs_next_cursor: bool,
}

async fn fetch_list_page(
    db: &sea_orm::DatabaseConnection,
    group_scope: &GroupScope,
    request: ListPageRequest<'_>,
) -> Result<Vec<(ip_record_group_membership::Model, Option<ip_record::Model>)>, AppError> {
    let ListPageRequest {
        condition,
        address,
        group_predicate,
        since_threshold,
        include_deleted,
        cursor,
        offset,
        limit,
        needs_next_cursor,
    } = request;
    let fetch_limit = if needs_next_cursor {
        limit.saturating_add(1)
    } else {
        limit
    };

    let page = if limit == 0 {
        Vec::new()
    } else {
        match group_scope {
            GroupScope::Merge(ids) if address.is_none() => {
                fetch_merged_page(
                    db,
                    MergedPageFetch {
                        base_condition: condition,
                        since_threshold,
                        include_deleted,
                        cursor,
                        group_ids: ids,
                        offset,
                        limit: fetch_limit,
                    },
                )
                .await?
            }
            _ => {
                let mut page_condition = apply_group_and_since_scope(
                    condition,
                    group_predicate,
                    since_threshold,
                    include_deleted,
                );
                if let Some(cursor) = cursor {
                    page_condition = page_condition.add(cursor.condition());
                }
                membership_query(address, page_condition, true)
                    .select_also(ip_record::Entity)
                    .order_by_desc(ip_record_group_membership::Column::LastSeenAt)
                    .order_by_asc(ip_record_group_membership::Column::Id)
                    .limit(fetch_limit)
                    .offset(offset)
                    .all(db)
                    .await?
            }
        }
    };

    Ok(page)
}

fn parse_list_cursor(
    filters: &QueryFilters,
    format_iplist: bool,
) -> Result<Option<KeysetCursor>, AppError> {
    if filters.cursor.is_some() && filters.offset.is_some() {
        return Err(AppError::InvalidInput(
            "`cursor` and `offset` are mutually exclusive".to_owned(),
        ));
    }
    if filters.cursor.is_some() && format_iplist {
        return Err(AppError::InvalidInput(
            "`cursor` cannot be combined with `format=iplist`".to_owned(),
        ));
    }
    Ok(match filters.cursor.as_deref().map(str::trim) {
        None | Some("") => None,
        Some(token) => Some(KeysetCursor::decode(token)?),
    })
}

fn parse_since_threshold(since: i64) -> Result<time::PrimitiveDateTime, AppError> {
    time::OffsetDateTime::from_unix_timestamp(since)
        .map(crate::time_serde::utc_datetime)
        .map_err(|_| AppError::InvalidInput("Invalid `since` timestamp".to_owned()))
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
    let format_minimal = matches!(filters.format.as_deref(), Some("minimal"))
        || matches!(filters.mode.as_deref(), Some("minimal"));
    let include_total = filters.include_total.unwrap_or(false) && !format_iplist;
    let limit = filters.limit.unwrap_or(50);
    let offset = filters.offset.unwrap_or(0);

    let parsed_cursor = parse_list_cursor(&filters, format_iplist)?;
    let cursor_mode = filters.cursor.is_some();

    let Some(group_scope) =
        resolve_list_group_scope(&state.db, &key, &filters, cursor_mode, limit, offset).await?
    else {
        return Ok(empty_ips_response(
            format_iplist,
            include_total,
            cursor_mode,
            limit,
            offset,
        ));
    };

    let (condition, address) = build_list_filter_condition(&state, &filters, include_deleted);
    let since_threshold = filters.since.map(parse_since_threshold).transpose()?;

    let count_group_pred = group_scope.predicate();

    let needs_next_cursor = (cursor_mode || include_total) && limit > 0;
    let mut page = fetch_list_page(
        &state.db,
        &group_scope,
        ListPageRequest {
            condition: &condition,
            address: address.as_ref(),
            group_predicate: count_group_pred.clone(),
            since_threshold,
            include_deleted,
            cursor: parsed_cursor,
            offset,
            limit,
            needs_next_cursor,
        },
    )
    .await?;

    let total = if !include_total {
        None
    } else if parsed_cursor.is_none()
        && limit > 0
        && (page.len() as u64) <= limit
        && (offset == 0 || !page.is_empty())
    {
        Some(offset.saturating_add(page.len() as u64))
    } else {
        let count_cond = apply_group_and_since_scope(
            &condition,
            count_group_pred,
            since_threshold,
            include_deleted,
        );
        Some(
            count_matching(
                &state,
                count_cond,
                address.as_ref(),
                !include_deleted && filters.max_age.is_none(),
            )
            .await?,
        )
    };

    let has_more = needs_next_cursor && (page.len() as u64) > limit;
    if has_more {
        page.truncate(usize::try_from(limit).unwrap_or(usize::MAX));
    }
    let next_cursor = if has_more {
        page.last()
            .map(|(m, _)| KeysetCursor::encode(m.last_seen_at, m.id))
            .transpose()?
    } else {
        None
    };

    format_list_ips_response(
        &state.db,
        &key,
        page,
        ListResponseOpts {
            format_iplist,
            format_minimal,
            total,
            cursor_mode,
            limit,
            offset,
            next_cursor,
        },
    )
    .await
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
fn membership_ref_from(
    query: MembershipRef,
    body: &axum::body::Bytes,
) -> Result<MembershipRef, AppError> {
    let from_body: MembershipRef = if body.is_empty() {
        MembershipRef::default()
    } else {
        serde_json::from_slice(body)
            .map_err(|e| AppError::InvalidInput(format!("Invalid JSON body: {e}")))?
    };
    Ok(query.merge(from_body))
}

/// Resolves a membership from an address and a group reference, applying the same oracle rule as
/// every other lookup: an unknown address, an unknown group, and an address not in that group all
/// answer `404`.
///
/// When `normalize_ipv6_to_48` is enabled and the group is not a whitelist, if the exact
/// `address` is not present in the group and `address` is a bare IPv6 host, this also checks the
/// normalized `/48` subnet so callers can unban or restore by either the original host IP or the
/// stored `/48` prefix.
async fn find_membership(
    db: &DatabaseTransaction,
    address: &str,
    group: &ip_group::Model,
    normalize_ipv6_to_48: bool,
) -> Result<(ip_record::Model, ip_record_group_membership::Model), AppError> {
    if let Some(record) = ip_record::Entity::find()
        .filter(ip_record::Column::TargetAddress.eq(address))
        .one(db)
        .await?
        && let Some(membership) = ip_record_group_membership::Entity::find()
            .filter(ip_record_group_membership::Column::IpRecordId.eq(record.id))
            .filter(ip_record_group_membership::Column::GroupId.eq(group.id))
            .one(db)
            .await?
    {
        return Ok((record, membership));
    }

    if normalize_ipv6_to_48 && group.group_type != "whitelist" {
        let addr_48 = normalize_ipv6_ban_storage(address, true);
        if addr_48 != address
            && let Some(record) = ip_record::Entity::find()
                .filter(ip_record::Column::TargetAddress.eq(&addr_48))
                .one(db)
                .await?
            && let Some(membership) = ip_record_group_membership::Entity::find()
                .filter(ip_record_group_membership::Column::IpRecordId.eq(record.id))
                .filter(ip_record_group_membership::Column::GroupId.eq(group.id))
                .one(db)
                .await?
        {
            return Ok((record, membership));
        }
    }

    Err(AppError::NotFound)
}

/// Handles `DELETE /api/ips`: soft-deletes one address's membership in one group.
///
/// Identified by `target_address` and the group, as a query, a JSON body, or both. Only this group's
/// membership is touched; the same address in any other group is unaffected. Non-masters soft-delete
/// only. `hard=true` is master-only and removes the membership row, along with the address row if no
/// group still holds it.
struct MembershipDeletion<'a> {
    key: &'a api_key::Model,
    client_ip: std::net::IpAddr,
    group: &'a ip_group::Model,
    record: &'a ip_record::Model,
    hard: bool,
    now: time::PrimitiveDateTime,
}

async fn apply_membership_deletion(
    txn: &DatabaseTransaction,
    membership: ip_record_group_membership::Model,
    request: MembershipDeletion<'_>,
) -> Result<bool, AppError> {
    let MembershipDeletion {
        key,
        client_ip,
        group,
        record,
        hard,
        now,
    } = request;
    if hard {
        ip_record_group_membership::Entity::delete_by_id(membership.id)
            .exec(txn)
            .await?;
        let no_remaining = ip_record_group_membership::Entity::find()
            .filter(ip_record_group_membership::Column::IpRecordId.eq(record.id))
            .select_only()
            .column(ip_record_group_membership::Column::Id)
            .limit(1)
            .into_tuple::<Uuid>()
            .one(txn)
            .await?
            .is_none();
        if no_remaining {
            ip_record::Entity::delete_by_id(record.id).exec(txn).await?;
        }
        create_audit_log(
            txn,
            key,
            client_ip,
            "IP_HARD_DELETE",
            Some(record.target_address.clone()),
            Some(group.name.clone()),
            Some("Permanently deleted".to_owned()),
        )
        .await?;
        return Ok(true);
    }

    if membership.is_deleted {
        return Ok(false);
    }

    let mut active: ip_record_group_membership::ActiveModel = membership.into();
    active.is_deleted = Set(true);
    active.deleted_at = Set(Some(now));
    active.deleted_by = Set(Some(key.id.to_string()));
    active.update(txn).await?;
    create_audit_log(
        txn,
        key,
        client_ip,
        "IP_SOFT_DELETE",
        Some(record.target_address.clone()),
        Some(group.name.clone()),
        Some(format!(
            "Soft-deleted by key {}",
            format_key_reference(&key.name, key.id)
        )),
    )
    .await?;
    Ok(true)
}

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
        serde_json::from_slice(&body)
            .map_err(|e| AppError::InvalidInput(format!("Invalid JSON body: {e}")))?
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
        .ok_or_else(|| {
            AppError::InvalidInput("target_address is required (query or JSON body)".to_owned())
        })?;
    let target_address = normalize_ip_or_cidr(&target_address);

    let group = resolve_group_ref(
        &state.db,
        reference.group_id,
        reference.group_name.as_deref(),
    )
    .await?
    .ok_or(AppError::NotFound)?;

    if !key.is_master {
        let perm = api_key_group_permission::Entity::find()
            .filter(
                Condition::all()
                    .add(api_key_group_permission::Column::ApiKeyId.eq(key.id))
                    .add(api_key_group_permission::Column::GroupId.eq(group.id)),
            )
            .one(&state.db)
            .await?;
        match perm {
            Some(p) if !p.can_delete => {
                return Err(AppError::Forbidden(
                    "Permission denied: You do not have delete permissions over this group"
                        .to_owned(),
                ));
            }
            Some(_) => {}
            None => return Err(AppError::Forbidden("Permission denied".to_owned())),
        }
    }
    if hard && !key.is_master {
        return Err(AppError::Forbidden(
            "Only a master key can permanently delete an IP membership".to_owned(),
        ));
    }

    let now = crate::time_serde::now_utc();
    let txn = state
        .db
        .begin_with_options(TransactionOptions {
            sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
            ..Default::default()
        })
        .await?;

    let (record, membership) = find_membership(
        &txn,
        &target_address,
        &group,
        state.is_ipv6_48_normalization_enabled(),
    )
    .await?;
    let stored_address = record.target_address.clone();
    if membership.is_locked {
        return Err(AppError::Forbidden(
            "Protected records cannot be deleted".to_owned(),
        ));
    }

    let emit_webhook = apply_membership_deletion(
        &txn,
        membership,
        MembershipDeletion {
            key: &key,
            client_ip: client_ip.0,
            group: &group,
            record: &record,
            hard,
            now,
        },
    )
    .await?;

    state.commit_membership_write(txn).await?;

    if emit_webhook {
        state.enqueue_webhook(WebhookEvent {
            action: "IP_DELETE".to_owned(),
            address: stored_address,
            is_whitelist: group.group_type == "whitelist",
            group_id: Some(group.id),
            group_name: Some(group.name),
            cause: Some("Deleted via API".to_owned()),
        });
    }

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
        return Err(AppError::Forbidden(
            "Only a master key can restore a deleted IP membership".to_owned(),
        ));
    }
    let reference = membership_ref_from(query, &body)?;
    let target_address = reference
        .target_address
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AppError::InvalidInput("target_address is required (query or JSON body)".to_owned())
        })?;
    let target_address = normalize_ip_or_cidr(&target_address);
    let txn = state
        .db
        .begin_with_options(TransactionOptions {
            sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
            ..Default::default()
        })
        .await?;
    let group = resolve_group_ref(&txn, reference.group_id, reference.group_name.as_deref())
        .await?
        .ok_or(AppError::NotFound)?;

    let (record, membership) = find_membership(
        &txn,
        &target_address,
        &group,
        state.is_ipv6_48_normalization_enabled(),
    )
    .await?;
    let stored_address = record.target_address;
    if !membership.is_deleted {
        return Err(AppError::InvalidInput(
            "This IP membership is not deleted; nothing to restore".to_owned(),
        ));
    }
    if group.group_type != "whitelist" {
        let network = super::support::parse_cidr_or_ip(&target_address)
            .map_err(|()| AppError::InvalidInput("Invalid IP or CIDR format".to_owned()))?;
        let stored = validate_ban_networks(&network, &stored_address, group.allow_private_ips)?;
        enforce_exclusions(&txn, group.id, network, stored).await?;
    }
    let mut active: ip_record_group_membership::ActiveModel = membership.into();
    active.is_deleted = Set(false);
    active.deleted_at = Set(None);
    active.deleted_by = Set(None);
    active.update(&txn).await?;
    let purge_events = if group.group_type == "whitelist" {
        let banlists = load_excluding_banlists(&txn, group.id).await?;
        if banlists.is_empty() {
            Vec::new()
        } else {
            let network = super::support::parse_cidr_or_ip(&stored_address)
                .map_err(|()| AppError::Internal)?;
            let protected = vec![(network, group.name.clone())];
            purge_excluded_bans_for_networks(
                &txn,
                &key,
                client_ip.0,
                &banlists,
                &protected,
                crate::time_serde::now_utc(),
                false,
            )
            .await?
        }
    } else {
        Vec::new()
    };
    create_audit_log(
        &txn,
        &key,
        client_ip.0,
        "IP_RESTORE",
        Some(stored_address.clone()),
        Some(group.name.clone()),
        Some("Restored from soft delete".to_owned()),
    )
    .await?;
    state.commit_membership_write(txn).await?;
    for event in purge_events {
        state.enqueue_webhook(event);
    }

    Ok(Json(serde_json::json!({
        "target_address": stored_address,
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
        return Err(AppError::Forbidden(
            "Only a master key can purge deleted IP memberships".to_owned(),
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
    if purged > 0 {
        state.invalidate_membership_queries();
    }
    create_audit_log(
        &state.db,
        &key,
        client_ip.0,
        "IP_PURGE",
        None,
        None,
        Some(format!(
            "Purged {purged} membership(s) soft-deleted over {retention_days} days ago"
        )),
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
    #[serde(default, with = "crate::time_serde::option")]
    pub created_at: Option<time::PrimitiveDateTime>,
    /// Deprecated alias for `last_seen_at`, retained so existing sync clients keep working. Ignored
    /// when `last_seen_at` is present.
    #[serde(default, with = "crate::time_serde::option")]
    pub updated_at: Option<time::PrimitiveDateTime>,
    /// The observation time for this membership. Defaults to now.
    #[serde(default, with = "crate::time_serde::option")]
    pub last_seen_at: Option<time::PrimitiveDateTime>,
    /// Soft-delete timestamp. Only meaningful alongside `is_deleted: true`.
    #[serde(default, with = "crate::time_serde::option")]
    pub deleted_at: Option<time::PrimitiveDateTime>,
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
    /// Submitted records overlapping a protected whitelist.
    pub skipped_excluded: usize,
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
type MembershipUpdatesByState = std::collections::BTreeMap<
    (
        time::PrimitiveDateTime,
        bool,
        Option<time::PrimitiveDateTime>,
        Option<String>,
    ),
    Vec<Uuid>,
>;

fn validate_batch_inputs(
    records: &[BatchRecordInput],
) -> Result<Vec<(String, &BatchRecordInput)>, AppError> {
    if records.len() > MAX_BATCH_RECORDS {
        return Err(AppError::InvalidInput(format!(
            "Batch too large: {} records, limit is {MAX_BATCH_RECORDS}. Split it and retry.",
            records.len()
        )));
    }
    let mut parsed_inputs = Vec::with_capacity(records.len());
    let mut seen_inputs = std::collections::HashSet::new();
    for record in records {
        let _network: IpNet =
            super::support::parse_cidr_or_ip(&record.target_address).map_err(|()| {
                AppError::InvalidInput(format!(
                    "Invalid IP or CIDR format: {:?}",
                    record.target_address
                ))
            })?;
        let canonical_input = normalize_ip_or_cidr(&record.target_address);
        if !seen_inputs.insert(canonical_input.clone()) {
            return Err(AppError::InvalidInput(format!(
                "Duplicate target_address in batch after canonicalisation: {canonical_input}"
            )));
        }
        parsed_inputs.push((canonical_input, record));
    }
    Ok(parsed_inputs)
}

async fn resolve_batch_group(
    db: &impl ConnectionTrait,
    key: &api_key::Model,
    group_name: &str,
    mode: BatchMode,
) -> Result<ip_group::Model, AppError> {
    let existing = resolve_group_ref(db, None, Some(group_name)).await?;
    let (group, created) = if let Some(group) = existing {
        (group, false)
    } else {
        if !key.is_master && !key.can_create_groups {
            return Err(AppError::Forbidden(
                "Permission denied: Target group does not exist and you cannot create groups"
                    .to_owned(),
            ));
        }
        get_or_create_group_with_status(db, group_name, "banlist", resource_owner(key)).await?
    };
    if !key.is_master && !created {
        let perm = api_key_group_permission::Entity::find()
            .filter(
                Condition::all()
                    .add(api_key_group_permission::Column::ApiKeyId.eq(key.id))
                    .add(api_key_group_permission::Column::GroupId.eq(group.id)),
            )
            .one(db)
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
        if mode == BatchMode::FullReplace && !perm.can_delete {
            return Err(AppError::Forbidden(
                "Permission denied: mode 'full_replace' soft-deletes the memberships it omits and therefore requires delete access to this group, not only write access"
                    .to_owned(),
            ));
        }
    }
    Ok(group)
}

struct BatchContext<'a> {
    key: &'a api_key::Model,
    group: &'a ip_group::Model,
    is_whitelist: bool,
    skip_webhooks: bool,
    now: time::PrimitiveDateTime,
}

type BatchRecordModels = std::collections::HashMap<String, ip_record::Model>;
type BatchMembershipModels = std::collections::HashMap<Uuid, ip_record_group_membership::Model>;

async fn prepare_batch_records(
    txn: &DatabaseTransaction,
    ctx: &BatchContext<'_>,
    chunk: &[(String, String, &BatchRecordInput)],
    summary: &mut BatchRecordsResponse,
) -> Result<(BatchRecordModels, BatchMembershipModels), AppError> {
    let mut chunk_addrs: Vec<String> = chunk.iter().map(|(addr, _, _)| addr.clone()).collect();
    chunk_addrs.sort();
    chunk_addrs.dedup();
    let mut prefetched_records: std::collections::HashMap<String, ip_record::Model> =
        ip_record::Entity::find()
            .filter(ip_record::Column::TargetAddress.is_in(chunk_addrs))
            .all(txn)
            .await?
            .into_iter()
            .map(|r| (r.target_address.clone(), r))
            .collect();

    let prefetched_memberships: std::collections::HashMap<Uuid, ip_record_group_membership::Model> =
        if prefetched_records.is_empty() {
            std::collections::HashMap::new()
        } else {
            let record_ids: Vec<Uuid> = prefetched_records.values().map(|r| r.id).collect();
            ip_record_group_membership::Entity::find()
                .filter(ip_record_group_membership::Column::GroupId.eq(ctx.group.id))
                .filter(ip_record_group_membership::Column::IpRecordId.is_in(record_ids))
                .all(txn)
                .await?
                .into_iter()
                .map(|m| (m.ip_record_id, m))
                .collect()
        };

    let mut new_records: Vec<ip_record::ActiveModel> = Vec::new();
    for (address, _, input) in chunk {
        if !prefetched_records.contains_key(address) {
            let id = Uuid::new_v4();
            let created_at = input.created_at.unwrap_or(ctx.now);
            new_records.push(ip_record::ActiveModel {
                id: Set(id),
                target_address: Set(address.clone()),
                created_at: Set(created_at),
            });
            prefetched_records.insert(
                address.clone(),
                ip_record::Model {
                    id,
                    target_address: address.clone(),
                    created_at,
                },
            );
            summary.created += 1;
        }
    }
    if !new_records.is_empty() {
        ip_record::Entity::insert_many(new_records)
            .exec_without_returning(txn)
            .await?;
    }

    Ok((prefetched_records, prefetched_memberships))
}

#[derive(Default)]
struct BatchMembershipWrites {
    new_memberships: Vec<ip_record_group_membership::ActiveModel>,
    updates_by_state: MembershipUpdatesByState,
}

fn plan_batch_membership(
    ctx: &BatchContext<'_>,
    input: &BatchRecordInput,
    record_id: Uuid,
    prefetched_memberships: &mut BatchMembershipModels,
    writes: &mut BatchMembershipWrites,
    summary: &mut BatchRecordsResponse,
) -> Option<(Uuid, &'static str)> {
    let existing = prefetched_memberships.remove(&record_id);
    let observed_at = input.last_seen_at.or(input.updated_at).unwrap_or(ctx.now);
    let planned = match existing {
        Some(m) if m.is_locked => {
            prefetched_memberships.insert(record_id, m);
            summary.locked_skipped += 1;
            return None;
        }
        Some(m) => {
            let id = m.id;
            let (target_is_deleted, target_deleted_at, target_deleted_by) = match input.is_deleted {
                Some(true) => (
                    true,
                    Some(input.deleted_at.unwrap_or(ctx.now)),
                    Some(ctx.key.id.to_string()),
                ),
                _ if m.is_deleted => {
                    summary.restored += 1;
                    (false, None, None)
                }
                _ => (false, m.deleted_at, m.deleted_by),
            };
            for ids in writes.updates_by_state.values_mut() {
                ids.retain(|&existing_id| existing_id != id);
            }
            writes
                .updates_by_state
                .entry((
                    observed_at,
                    target_is_deleted,
                    target_deleted_at,
                    target_deleted_by.clone(),
                ))
                .or_default()
                .push(id);
            prefetched_memberships.insert(
                record_id,
                ip_record_group_membership::Model {
                    id,
                    ip_record_id: record_id,
                    group_id: ctx.group.id,
                    is_locked: false,
                    created_at: m.created_at,
                    last_seen_at: observed_at,
                    is_deleted: target_is_deleted,
                    deleted_at: target_deleted_at,
                    deleted_by: target_deleted_by,
                },
            );
            summary.updated += 1;
            (id, "IP_UPDATE")
        }
        None => {
            let id = Uuid::new_v4();
            let deleted = input.is_deleted == Some(true);
            let created_at = input.created_at.unwrap_or(ctx.now);
            let deleted_at = deleted.then(|| input.deleted_at.unwrap_or(ctx.now));
            let deleted_by = deleted.then(|| ctx.key.id.to_string());
            writes
                .new_memberships
                .push(ip_record_group_membership::ActiveModel {
                    id: Set(id),
                    ip_record_id: Set(record_id),
                    group_id: Set(ctx.group.id),
                    is_locked: Set(false),
                    created_at: Set(created_at),
                    last_seen_at: Set(observed_at),
                    is_deleted: Set(deleted),
                    deleted_at: Set(deleted_at),
                    deleted_by: Set(deleted_by.clone()),
                });
            prefetched_memberships.insert(
                record_id,
                ip_record_group_membership::Model {
                    id,
                    ip_record_id: record_id,
                    group_id: ctx.group.id,
                    is_locked: false,
                    created_at,
                    last_seen_at: observed_at,
                    is_deleted: deleted,
                    deleted_at,
                    deleted_by,
                },
            );
            summary.linked += 1;
            (id, "IP_ADD")
        }
    };

    Some(planned)
}

async fn apply_batch_chunk(
    txn: &DatabaseTransaction,
    ctx: &BatchContext<'_>,
    chunk: &[(String, String, &BatchRecordInput)],
    summary: &mut BatchRecordsResponse,
    webhook_events: &mut Vec<WebhookEvent>,
) -> Result<(), AppError> {
    let (prefetched_records, mut prefetched_memberships) =
        prepare_batch_records(txn, ctx, chunk, summary).await?;
    let mut writes = BatchMembershipWrites::default();
    let mut new_causes: Vec<ip_record_cause::ActiveModel> = Vec::new();

    for (address, canonical_input, input) in chunk {
        let Some(record) = prefetched_records.get(address) else {
            continue;
        };
        let Some((membership_id, action)) = plan_batch_membership(
            ctx,
            input,
            record.id,
            &mut prefetched_memberships,
            &mut writes,
            summary,
        ) else {
            continue;
        };

        if let Some(text) = input
            .cause
            .as_deref()
            .map(str::trim)
            .filter(|c| !c.is_empty())
        {
            new_causes.push(ip_record_cause::ActiveModel {
                id: Set(Uuid::new_v4()),
                membership_id: Set(membership_id),
                cause: Set(text.to_owned()),
                created_at: Set(ctx.now),
            });
        }

        if !ctx.skip_webhooks {
            webhook_events.push(WebhookEvent {
                action: action.to_owned(),
                address: canonical_input.clone(),
                is_whitelist: ctx.is_whitelist,
                group_id: Some(ctx.group.id),
                group_name: Some(ctx.group.name.clone()),
                cause: input.cause.clone(),
            });
        }
    }

    if !writes.new_memberships.is_empty() {
        ip_record_group_membership::Entity::insert_many(writes.new_memberships)
            .exec_without_returning(txn)
            .await?;
    }

    for ((obs_at, is_del, del_at, del_by), ids) in writes.updates_by_state {
        if ids.is_empty() {
            continue;
        }
        ip_record_group_membership::Entity::update_many()
            .col_expr(
                ip_record_group_membership::Column::LastSeenAt,
                Expr::value(obs_at),
            )
            .col_expr(
                ip_record_group_membership::Column::IsDeleted,
                Expr::value(is_del),
            )
            .col_expr(
                ip_record_group_membership::Column::DeletedAt,
                Expr::value(del_at),
            )
            .col_expr(
                ip_record_group_membership::Column::DeletedBy,
                Expr::value(del_by),
            )
            .filter(ip_record_group_membership::Column::Id.is_in(ids))
            .exec(txn)
            .await?;
    }

    if !new_causes.is_empty() {
        ip_record_cause::Entity::insert_many(new_causes)
            .exec_without_returning(txn)
            .await?;
    }

    Ok(())
}

async fn sweep_full_replace_omissions(
    txn: &DatabaseTransaction,
    ctx: &BatchContext<'_>,
    seen_stored: &std::collections::HashSet<String>,
    summary: &mut BatchRecordsResponse,
    webhook_events: &mut Vec<WebhookEvent>,
) -> Result<(), AppError> {
    let candidates = ip_record_group_membership::Entity::find()
        .join(
            JoinType::InnerJoin,
            ip_record_group_membership::Relation::IpRecord.def(),
        )
        .select_also(ip_record::Entity)
        .filter(
            Condition::all()
                .add(ip_record_group_membership::Column::GroupId.eq(ctx.group.id))
                .add(ip_record_group_membership::Column::IsDeleted.eq(false))
                .add(ip_record_group_membership::Column::IsLocked.eq(false)),
        )
        .all(txn)
        .await?;
    let mut swept_ids: Vec<Uuid> = Vec::new();
    for (membership, record) in candidates {
        let Some(record) = record else { continue };
        if seen_stored.contains(&record.target_address) {
            continue;
        }
        let swept_address = record.target_address;
        swept_ids.push(membership.id);
        summary.soft_deleted += 1;
        if !ctx.skip_webhooks {
            webhook_events.push(WebhookEvent {
                action: "IP_DELETE".to_owned(),
                address: swept_address,
                is_whitelist: ctx.is_whitelist,
                group_id: Some(ctx.group.id),
                group_name: Some(ctx.group.name.clone()),
                cause: Some("Removed via batch full_replace synchronisation".to_owned()),
            });
        }
    }
    let deleted_by = Some(ctx.key.id.to_string());
    for id_chunk in swept_ids.chunks(500) {
        ip_record_group_membership::Entity::update_many()
            .col_expr(
                ip_record_group_membership::Column::IsDeleted,
                Expr::value(true),
            )
            .col_expr(
                ip_record_group_membership::Column::DeletedAt,
                Expr::value(Some(ctx.now)),
            )
            .col_expr(
                ip_record_group_membership::Column::DeletedBy,
                Expr::value(deleted_by.clone()),
            )
            .filter(ip_record_group_membership::Column::Id.is_in(id_chunk.iter().copied()))
            .exec(txn)
            .await?;
    }
    Ok(())
}

async fn purge_batch_whitelist_exclusions(
    txn: &DatabaseTransaction,
    ctx: &BatchContext<'_>,
    client_ip: std::net::IpAddr,
    normalized: &[(String, String, &BatchRecordInput)],
    webhook_events: &mut Vec<WebhookEvent>,
) -> Result<(), AppError> {
    if !ctx.is_whitelist || normalized.is_empty() {
        return Ok(());
    }
    let banlists = load_excluding_banlists(txn, ctx.group.id).await?;
    if banlists.is_empty() {
        return Ok(());
    }
    let mut batch_protected = Vec::with_capacity(normalized.len());
    for (stored_address, _, _) in normalized {
        let net =
            super::support::parse_cidr_or_ip(stored_address).map_err(|()| AppError::Internal)?;
        batch_protected.push((net, ctx.group.name.clone()));
    }
    let purge_events = purge_excluded_bans_for_networks(
        txn,
        ctx.key,
        client_ip,
        &banlists,
        &batch_protected,
        ctx.now,
        ctx.skip_webhooks,
    )
    .await?;
    webhook_events.extend(purge_events);
    Ok(())
}

pub async fn batch_records(
    State(state): State<AppState>,
    Extension(key): Extension<api_key::Model>,
    Extension(client_ip): Extension<ClientIp>,
    StrictJson(payload): StrictJson<BatchRecordsPayload>,
) -> Result<impl IntoResponse, AppError> {
    let parsed_inputs = validate_batch_inputs(&payload.records)?;
    let txn = state
        .db
        .begin_with_options(TransactionOptions {
            sqlite_transaction_mode: Some(SqliteTransactionMode::Immediate),
            ..Default::default()
        })
        .await?;
    let group = resolve_batch_group(&txn, &key, &payload.group_name, payload.mode).await?;
    let is_whitelist = group.group_type == "whitelist";
    let protected = if is_whitelist {
        Vec::new()
    } else {
        load_protected_networks(&txn, group.id).await?
    };
    let normalize_v6_48 = !is_whitelist && state.is_ipv6_48_normalization_enabled();
    let mut normalized = Vec::with_capacity(parsed_inputs.len());
    let mut seen_stored = std::collections::HashSet::new();
    let mut summary = BatchRecordsResponse::default();
    for (canonical_input, record) in parsed_inputs {
        let stored_address = normalize_ipv6_ban_storage(&record.target_address, normalize_v6_48);
        if !is_whitelist {
            let network = super::support::parse_cidr_or_ip(&canonical_input)
                .map_err(|()| AppError::Internal)?;
            let stored = validate_ban_networks(&network, &stored_address, group.allow_private_ips)?;
            if matching_whitelists(&protected, network, stored)
                .next()
                .is_some()
            {
                summary.skipped_excluded += 1;
                continue;
            }
        }
        seen_stored.insert(stored_address.clone());
        normalized.push((stored_address, canonical_input, record));
    }

    let now = crate::time_serde::now_utc();
    let skip_webhooks = payload.skip_webhooks.unwrap_or(false);
    let mut webhook_events: Vec<WebhookEvent> = Vec::new();
    let ctx = BatchContext {
        key: &key,
        group: &group,
        is_whitelist,
        skip_webhooks,
        now,
    };

    for chunk in normalized.chunks(500) {
        apply_batch_chunk(&txn, &ctx, chunk, &mut summary, &mut webhook_events).await?;
    }

    if payload.mode == BatchMode::FullReplace {
        sweep_full_replace_omissions(&txn, &ctx, &seen_stored, &mut summary, &mut webhook_events)
            .await?;
    }

    purge_batch_whitelist_exclusions(&txn, &ctx, client_ip.0, &normalized, &mut webhook_events)
        .await?;

    create_audit_log(
        &txn,
        &key,
        client_ip.0,
        "batch_records_updated",
        None,
        Some(group.name.clone()),
        Some(format!(
            "mode={} submitted={} created={} updated={} restored={} locked_skipped={} soft_deleted={} skipped_excluded={}",
            match payload.mode {
                BatchMode::Upsert => "upsert",
                BatchMode::FullReplace => "full_replace",
            },
            payload.records.len(),
            summary.created,
            summary.updated,
            summary.restored,
            summary.locked_skipped,
            summary.soft_deleted,
            summary.skipped_excluded,
        )),
    )
    .await?;

    state.commit_membership_write(txn).await?;

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guard_bannable_address_rejects_loopback_and_unspecified() {
        assert!(guard_bannable_address(&"127.0.0.1/32".parse().unwrap(), false).is_err());
        assert!(guard_bannable_address(&"127.0.0.0/8".parse().unwrap(), false).is_err());
        assert!(guard_bannable_address(&"::1/128".parse().unwrap(), false).is_err());
        assert!(guard_bannable_address(&"0.0.0.0/32".parse().unwrap(), false).is_err());
        assert!(guard_bannable_address(&"::/128".parse().unwrap(), false).is_err());
    }

    #[test]
    fn guard_bannable_address_rejects_rfc1918_and_link_local() {
        assert!(guard_bannable_address(&"10.0.0.1/32".parse().unwrap(), false).is_err());
        assert!(guard_bannable_address(&"172.16.5.0/24".parse().unwrap(), false).is_err());
        assert!(guard_bannable_address(&"192.168.1.0/24".parse().unwrap(), false).is_err());
        assert!(guard_bannable_address(&"169.254.10.1/32".parse().unwrap(), false).is_err());
        assert!(guard_bannable_address(&"fe80::1/64".parse().unwrap(), false).is_err());
        assert!(guard_bannable_address(&"fc00::1/64".parse().unwrap(), false).is_err());
        assert!(guard_bannable_address(&"100.64.0.1/32".parse().unwrap(), false).is_err());
        assert!(guard_bannable_address(&"224.0.0.1/32".parse().unwrap(), false).is_err());
        assert!(guard_bannable_address(&"240.0.0.1/32".parse().unwrap(), false).is_err());
        assert!(guard_bannable_address(&"ff02::1/128".parse().unwrap(), false).is_err());
        assert!(guard_bannable_address(&"64:ff9b::1/128".parse().unwrap(), false).is_err());
        assert!(guard_bannable_address(&"100::1/128".parse().unwrap(), false).is_err());
        assert!(guard_bannable_address(&"::ffff:127.0.0.1/128".parse().unwrap(), false).is_err());
        assert!(guard_bannable_address(&"::ffff:10.0.0.1/128".parse().unwrap(), false).is_err());
    }

    #[test]
    fn opt_in_allows_only_private_cgnat_and_ula_ranges() {
        for cidr in [
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "100.64.0.0/10",
            "fc00::/7",
            "::ffff:10.0.0.0/104",
        ] {
            let net = cidr.parse().unwrap();
            assert!(guard_bannable_address(&net, false).is_err(), "{cidr}");
            assert!(guard_bannable_address(&net, true).is_ok(), "{cidr}");
        }
        for cidr in [
            "126.0.0.0/7",
            "::ffff:126.0.0.0/103",
            "::ffff:169.254.0.0/112",
            "fe80::/10",
            "224.0.0.0/4",
            "ff00::/8",
            "192.0.2.0/24",
            "2001:db8::/32",
            "::ffff:198.18.0.0/111",
            "255.255.255.255/32",
            "192.0.0.0/24",
            "100::/64",
            "64:ff9b::/96",
            "::/0",
        ] {
            assert!(
                guard_bannable_address(&cidr.parse().unwrap(), true).is_err(),
                "{cidr}"
            );
        }
    }

    #[test]
    fn guard_bannable_address_accepts_public_routable_ips() {
        assert!(guard_bannable_address(&"8.8.8.8/32".parse().unwrap(), false).is_ok());
        assert!(guard_bannable_address(&"1.1.1.0/24".parse().unwrap(), false).is_ok());
        assert!(
            guard_bannable_address(&"2606:4700:4700::1111/128".parse().unwrap(), false).is_ok()
        );
        assert!(guard_bannable_address(&"2001:4860:4860::8888/32".parse().unwrap(), false).is_ok());
    }
}
