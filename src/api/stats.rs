//! Ban Analytics & Recidivism endpoints (`GET /api/stats/analytics` and `GET /api/stats/intersection`).
//! Provides high-level security insights into multi-group bans, recidivist IPs, and trigger causes.

use std::collections::HashSet;

use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::{Extension, Json};
use chrono::NaiveDateTime;
use sea_orm::sea_query::{Alias, Expr, ExprTrait, Func, Query as SqQuery};
use sea_orm::{
    ColumnTrait, ConnectionTrait, EntityTrait, JoinType, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, QueryTrait, RelationTrait,
};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::entities::{
    api_key, api_key_group_permission, ip_group, ip_record, ip_record_cause,
    ip_record_group_membership,
};
use crate::error::AppError;
use crate::state::AppState;

/// Breakdown for a single group in analytics.
#[derive(Debug, Serialize)]
pub struct GroupStat {
    /// Unique identifier of the group.
    pub group_id: Uuid,
    /// Name of the group.
    pub group_name: String,
    /// Type of the group (e.g. manual, dynamic, static).
    pub group_type: String,
    /// Total active (non-deleted) IP records in this group.
    pub active_count: u64,
    /// Number of active IPs in this group that also belong to at least one other group.
    pub shared_count: u64,
}

/// A frequent ban cause with occurrence count.
#[derive(Debug, Serialize)]
pub struct CauseStat {
    /// Ban cause / reason text.
    pub cause: String,
    /// Number of active records associated with this cause.
    pub count: u64,
}

/// A recidivist IP present across multiple active groups.
#[derive(Debug, Serialize)]
pub struct RecidivistIp {
    /// Primary key of the IP record.
    pub ip_record_id: Uuid,
    /// IP address string (IPv4 or IPv6).
    pub target_address: String,
    /// Total number of distinct active groups containing this IP.
    pub group_count: u64,
    /// Names of the active groups containing this IP.
    pub group_names: Vec<String>,
    /// Earliest recorded creation timestamp across memberships.
    pub first_seen: Option<NaiveDateTime>,
    /// Most recent last_seen timestamp across memberships.
    pub last_seen: Option<NaiveDateTime>,
    /// Most recent ban causes across memberships.
    pub latest_causes: Vec<String>,
}

/// Breakdown of active IPs by subnet.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CidrStat {
    /// CIDR subnet prefix (e.g. "192.168.1.0/24" or "2001:db8::/64").
    pub subnet: String,
    /// Number of active IPs within this subnet.
    pub active_count: u64,
}

/// Breakdown of active memberships by locked (manual/permanent) vs unlocked (dynamic/temporary).
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LockedBreakdown {
    /// Total active memberships count across authorized groups.
    pub total_active: u64,
    /// Count of active memberships where `is_locked = true`.
    pub locked_count: u64,
    /// Count of active memberships where `is_locked = false`.
    pub dynamic_count: u64,
}

/// Activity velocity metrics over a given time window.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct VelocityStat {
    /// Count of active memberships added or seen (`last_seen_at >= threshold`).
    pub active_added_or_seen: u64,
    /// Count of memberships soft-deleted (`is_deleted = true` and `deleted_at >= threshold`).
    pub soft_deleted: u64,
}

/// Response payload for `GET /api/stats/analytics`.
#[derive(Debug, Serialize)]
pub struct AnalyticsResponse {
    /// Total distinct active IP addresses across authorized groups.
    pub total_active_ips: u64,
    /// Number of active IP addresses appearing in two or more groups.
    pub recidivist_ips_count: u64,
    /// Percentage of active IPs that appear in two or more groups (0.0 to 100.0).
    pub recidivism_rate_pct: f64,
    /// Breakdown of active and shared counts by group.
    pub groups: Vec<GroupStat>,
    /// Top ban causes ranked by frequency.
    pub top_causes: Vec<CauseStat>,
    /// Top recidivist IP addresses with their group memberships and causes.
    pub top_recidivists: Vec<RecidivistIp>,
    /// Top subnets (/24 for IPv4, /48 or /64 for IPv6) by active IP count.
    pub cidr_breakdown: Vec<CidrStat>,
    /// Active memberships breakdown: locked vs dynamic.
    pub locked_breakdown: LockedBreakdown,
    /// Membership activity velocity over the last 24 hours.
    pub velocity_24h: VelocityStat,
    /// Membership activity velocity over the last 7 days.
    pub velocity_7d: VelocityStat,
}

/// Information about a group participating in the intersection.
#[derive(Debug, Serialize)]
pub struct IntersectedGroup {
    /// Unique identifier of the group.
    pub id: Uuid,
    /// Name of the group.
    pub name: String,
}

/// Query parameters for `GET /api/stats/intersection`.
#[derive(Debug, Deserialize)]
pub struct IntersectionQuery {
    /// Comma-separated list of group names or UUIDs (e.g. `groups=Fail2ban,Seedbox_Ban,PortScan`).
    pub groups: Option<String>,
    /// Optional legacy parameter: first group.
    pub group_a: Option<String>,
    /// Optional legacy parameter: second group.
    pub group_b: Option<String>,
    /// Maximum number of records to return (1-100, default 50).
    pub limit: Option<u64>,
    /// Offset for pagination.
    pub offset: Option<u64>,
}

/// An IP address belonging to all compared groups.
#[derive(Debug, Serialize)]
pub struct IntersectionItem {
    /// Primary key of the IP record.
    pub ip_record_id: Uuid,
    /// IP address string.
    pub target_address: String,
    /// Last seen timestamp mapped by group name.
    pub group_last_seen: std::collections::HashMap<String, Option<NaiveDateTime>>,
    /// Last seen timestamp in the first group (for backward compatibility).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_a: Option<NaiveDateTime>,
    /// Last seen timestamp in the second group (for backward compatibility).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen_b: Option<NaiveDateTime>,
}

/// Response payload for `GET /api/stats/intersection`.
#[derive(Debug, Serialize)]
pub struct IntersectionResponse {
    /// List of groups evaluated in the intersection.
    pub groups: Vec<IntersectedGroup>,
    /// UUID of group A (for backward compatibility).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_a_id: Option<Uuid>,
    /// Name of group A (for backward compatibility).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_a_name: Option<String>,
    /// UUID of group B (for backward compatibility).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_b_id: Option<Uuid>,
    /// Name of group B (for backward compatibility).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_b_name: Option<String>,
    /// Total count of IPs present across all compared groups.
    pub total_overlap: u64,
    /// Paginated list of intersecting IP records.
    pub items: Vec<IntersectionItem>,
}

/// Canonicalizes an address to a /24 IPv4 or /48-/64 IPv6 subnet prefix for aggregation.
fn to_subnet_prefix(raw: &str) -> Option<String> {
    if let Ok(net) = crate::api::support::parse_cidr_or_ip(raw) {
        match net {
            ipnet::IpNet::V4(v4) => {
                if v4.prefix_len() <= 24 {
                    Some(format!("{}/{}", v4.network(), v4.prefix_len()))
                } else {
                    let oct = v4.addr().octets();
                    Some(format!("{}.{}.{}.0/24", oct[0], oct[1], oct[2]))
                }
            }
            ipnet::IpNet::V6(v6) => {
                if v6.prefix_len() <= 64 {
                    Some(format!("{}/{}", v6.network(), v6.prefix_len()))
                } else if let Ok(net64) = ipnet::Ipv6Net::new(v6.addr(), 64) {
                    Some(format!("{}/64", net64.network()))
                } else {
                    Some(format!("{}/64", v6.network()))
                }
            }
        }
    } else {
        None
    }
}

/// Calculates added/seen and soft-deleted membership velocity for a given threshold window.
async fn compute_velocity(
    db: &sea_orm::DatabaseConnection,
    authorized_groups: Option<&HashSet<Uuid>>,
    threshold: NaiveDateTime,
) -> Result<VelocityStat, AppError> {
    let mut active_q = ip_record_group_membership::Entity::find()
        .filter(ip_record_group_membership::Column::IsDeleted.eq(false))
        .filter(
            sea_orm::Condition::any()
                .add(ip_record_group_membership::Column::CreatedAt.gte(threshold))
                .add(ip_record_group_membership::Column::LastSeenAt.gte(threshold)),
        );
    if let Some(allowed) = authorized_groups {
        active_q = active_q.filter(
            ip_record_group_membership::Column::GroupId.is_in(allowed.iter().copied()),
        );
    }
    let active_added_or_seen = active_q.count(db).await?;

    let mut deleted_q = ip_record_group_membership::Entity::find()
        .filter(ip_record_group_membership::Column::IsDeleted.eq(true))
        .filter(ip_record_group_membership::Column::DeletedAt.gte(threshold));
    if let Some(allowed) = authorized_groups {
        deleted_q = deleted_q.filter(
            ip_record_group_membership::Column::GroupId.is_in(allowed.iter().copied()),
        );
    }
    let soft_deleted = deleted_q.count(db).await?;

    Ok(VelocityStat {
        active_added_or_seen,
        soft_deleted,
    })
}

/// Resolves groups the caller is authorized to view.
async fn resolve_authorized_groups(
    db: &sea_orm::DatabaseConnection,
    caller: &api_key::Model,
) -> Result<Option<HashSet<Uuid>>, AppError> {
    if caller.is_master {
        return Ok(None);
    }
    let allowed: HashSet<Uuid> = api_key_group_permission::Entity::find()
        .filter(
            sea_orm::Condition::all()
                .add(api_key_group_permission::Column::ApiKeyId.eq(caller.id))
                .add(api_key_group_permission::Column::CanRead.eq(true)),
        )
        .all(db)
        .await?
        .into_iter()
        .map(|p| p.group_id)
        .collect();
    Ok(Some(allowed))
}

/// Handles `GET /api/stats/analytics`.
pub async fn get_analytics(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
) -> Result<impl IntoResponse, AppError> {
    let authorized_groups = resolve_authorized_groups(&state.db, &caller).await?;
    if let Some(ref allowed) = authorized_groups
        && allowed.is_empty()
    {
        return Ok(Json(AnalyticsResponse {
                total_active_ips: 0,
                recidivist_ips_count: 0,
                recidivism_rate_pct: 0.0,
                groups: Vec::new(),
                top_causes: Vec::new(),
                top_recidivists: Vec::new(),
                cidr_breakdown: Vec::new(),
                locked_breakdown: LockedBreakdown {
                    total_active: 0,
                    locked_count: 0,
                    dynamic_count: 0,
                },
                velocity_24h: VelocityStat {
                    active_added_or_seen: 0,
                    soft_deleted: 0,
                },
                velocity_7d: VelocityStat {
                    active_added_or_seen: 0,
                    soft_deleted: 0,
                },
            }).into_response());
    }

    if caller.is_master {
        let cache_read = state.analytics_cache.read().await;
        if let Some((ts, ref payload)) = *cache_read
            && ts.elapsed() < std::time::Duration::from_secs(30)
        {
            return Ok(Json(payload.clone()).into_response());
        }
    }

    // 1. Total unique active IPs
    let mut total_q = ip_record_group_membership::Entity::find()
        .filter(ip_record_group_membership::Column::IsDeleted.eq(false));
    if let Some(ref allowed) = authorized_groups {
        total_q = total_q.filter(
            ip_record_group_membership::Column::GroupId.is_in(allowed.iter().copied()),
        );
    }
    let total_active_ips: i64 = total_q
        .select_only()
        .expr_as(
            Func::count_distinct(Expr::col(
                ip_record_group_membership::Column::IpRecordId,
            )),
            "cnt",
        )
        .into_tuple::<i64>()
        .one(&state.db)
        .await?
        .unwrap_or(0);
    let total_active_ips = std::cmp::max(total_active_ips, 0) as u64;

    // 2. Multi-group (recidivist) IPs count calculated directly in the engine via subquery
    let mut rec_sub = ip_record_group_membership::Entity::find()
        .filter(ip_record_group_membership::Column::IsDeleted.eq(false));
    if let Some(ref allowed) = authorized_groups {
        rec_sub = rec_sub.filter(
            ip_record_group_membership::Column::GroupId.is_in(allowed.iter().copied()),
        );
    }
    let rec_sub_query = rec_sub
        .select_only()
        .column(ip_record_group_membership::Column::IpRecordId)
        .group_by(ip_record_group_membership::Column::IpRecordId)
        .having(
            Expr::expr(Func::count_distinct(Expr::col(
                ip_record_group_membership::Column::GroupId,
            )))
            .gt(1),
        )
        .into_query();

    let rec_cnt_stmt = SqQuery::select()
        .expr_as(Func::count(Expr::col(sea_orm::sea_query::Asterisk)), Alias::new("cnt"))
        .from_subquery(rec_sub_query, Alias::new("sub"))
        .to_owned();

    let row = state.db.query_one(&rec_cnt_stmt).await?;
    let recidivist_ips_count: u64 = row
        .and_then(|r| r.try_get::<i64>("", "cnt").ok())
        .map(|c| std::cmp::max(c, 0) as u64)
        .unwrap_or(0);

    let recidivism_rate_pct = if total_active_ips > 0 {
        ((recidivist_ips_count as f64) * 100.0) / (total_active_ips as f64)
    } else {
        0.0
    };

    // 3. Groups breakdown with active and shared counts computed in 2 batch queries
    let mut groups_query = ip_group::Entity::find();
    if let Some(ref allowed) = authorized_groups {
        groups_query =
            groups_query.filter(ip_group::Column::Id.is_in(allowed.iter().copied()));
    }
    let all_groups = groups_query.all(&state.db).await?;

    // Batch 1: active counts by group
    let mut active_counts_q = ip_record_group_membership::Entity::find()
        .filter(ip_record_group_membership::Column::IsDeleted.eq(false));
    if let Some(ref allowed) = authorized_groups {
        active_counts_q = active_counts_q.filter(
            ip_record_group_membership::Column::GroupId.is_in(allowed.iter().copied()),
        );
    }
    let active_counts: Vec<(Uuid, i64)> = active_counts_q
        .select_only()
        .column(ip_record_group_membership::Column::GroupId)
        .expr_as(Func::count(Expr::col(sea_orm::sea_query::Asterisk)), "cnt")
        .group_by(ip_record_group_membership::Column::GroupId)
        .into_tuple::<(Uuid, i64)>()
        .all(&state.db)
        .await?;
    let active_counts_map: std::collections::HashMap<Uuid, u64> = active_counts
        .into_iter()
        .map(|(gid, cnt)| (gid, std::cmp::max(cnt, 0) as u64))
        .collect();

    // Batch 2: shared counts by group using a single group-presence query
    let mut shared_sub = ip_record_group_membership::Entity::find()
        .filter(ip_record_group_membership::Column::IsDeleted.eq(false));
    if let Some(ref allowed) = authorized_groups {
        shared_sub = shared_sub.filter(
            ip_record_group_membership::Column::GroupId.is_in(allowed.iter().copied()),
        );
    }
    let shared_sub_query = shared_sub
        .select_only()
        .column(ip_record_group_membership::Column::IpRecordId)
        .group_by(ip_record_group_membership::Column::IpRecordId)
        .having(
            Expr::expr(Func::count_distinct(Expr::col(
                ip_record_group_membership::Column::GroupId,
            )))
            .gt(1),
        )
        .into_query();

    let mut shared_counts_q = ip_record_group_membership::Entity::find()
        .filter(ip_record_group_membership::Column::IsDeleted.eq(false))
        .filter(
            Expr::col(ip_record_group_membership::Column::IpRecordId)
                .in_subquery(shared_sub_query),
        );
    if let Some(ref allowed) = authorized_groups {
        shared_counts_q = shared_counts_q.filter(
            ip_record_group_membership::Column::GroupId.is_in(allowed.iter().copied()),
        );
    }
    let shared_counts: Vec<(Uuid, i64)> = shared_counts_q
        .select_only()
        .column(ip_record_group_membership::Column::GroupId)
        .expr_as(Func::count(Expr::col(sea_orm::sea_query::Asterisk)), "cnt")
        .group_by(ip_record_group_membership::Column::GroupId)
        .into_tuple::<(Uuid, i64)>()
        .all(&state.db)
        .await?;
    let shared_counts_map: std::collections::HashMap<Uuid, u64> = shared_counts
        .into_iter()
        .map(|(gid, cnt)| (gid, std::cmp::max(cnt, 0) as u64))
        .collect();

    let mut groups = Vec::with_capacity(all_groups.len());
    for g in all_groups {
        let active_count = active_counts_map.get(&g.id).copied().unwrap_or(0);
        let shared_count = shared_counts_map.get(&g.id).copied().unwrap_or(0);
        groups.push(GroupStat {
            group_id: g.id,
            group_name: g.name,
            group_type: g.group_type,
            active_count,
            shared_count,
        });
    }

    // 4. Top causes across active memberships
    let mut cause_q = ip_record_cause::Entity::find()
        .join(
            JoinType::InnerJoin,
            ip_record_cause::Relation::IpRecordGroupMembership.def(),
        )
        .filter(ip_record_group_membership::Column::IsDeleted.eq(false));
    if let Some(ref allowed) = authorized_groups {
        cause_q = cause_q.filter(
            ip_record_group_membership::Column::GroupId.is_in(allowed.iter().copied()),
        );
    }
    let cause_tuples: Vec<(String, i64)> = cause_q
        .select_only()
        .column(ip_record_cause::Column::Cause)
        .expr_as(Func::count(Expr::col(sea_orm::sea_query::Asterisk)), "cnt")
        .group_by(ip_record_cause::Column::Cause)
        .order_by_desc(Expr::col(Alias::new("cnt")))
        .limit(10)
        .into_tuple::<(String, i64)>()
        .all(&state.db)
        .await?;
    let top_causes: Vec<CauseStat> = cause_tuples
        .into_iter()
        .filter(|(c, _)| !c.trim().is_empty())
        .map(|(cause, cnt)| CauseStat {
            cause,
            count: std::cmp::max(cnt, 0) as u64,
        })
        .collect();

    // 5. Top Recidivist IPs: limited to top 50 in SQL and batch-fetched without N+1 queries
    let mut top_rec_q = ip_record_group_membership::Entity::find()
        .filter(ip_record_group_membership::Column::IsDeleted.eq(false));
    if let Some(ref allowed) = authorized_groups {
        top_rec_q = top_rec_q.filter(
            ip_record_group_membership::Column::GroupId.is_in(allowed.iter().copied()),
        );
    }

    let top_rec_tuples: Vec<(Uuid, i64)> = top_rec_q
        .select_only()
        .column(ip_record_group_membership::Column::IpRecordId)
        .expr_as(
            Func::count_distinct(Expr::col(ip_record_group_membership::Column::GroupId)),
            "grp_cnt",
        )
        .group_by(ip_record_group_membership::Column::IpRecordId)
        .having(
            Expr::expr(Func::count_distinct(Expr::col(
                ip_record_group_membership::Column::GroupId,
            )))
            .gt(1),
        )
        .order_by_desc(Expr::col(Alias::new("grp_cnt")))
        .order_by_asc(ip_record_group_membership::Column::IpRecordId)
        .limit(50)
        .into_tuple::<(Uuid, i64)>()
        .all(&state.db)
        .await?;

    let top_recidivists = if top_rec_tuples.is_empty() {
        Vec::new()
    } else {
        let top_ids: Vec<Uuid> = top_rec_tuples.iter().map(|(id, _)| *id).collect();

        // Batch fetch records
        let records = ip_record::Entity::find()
            .filter(ip_record::Column::Id.is_in(top_ids.iter().copied()))
            .all(&state.db)
            .await?;
        let records_map: std::collections::HashMap<Uuid, ip_record::Model> =
            records.into_iter().map(|r| (r.id, r)).collect();

        // Batch fetch memberships and their associated groups
        let mut m_query = ip_record_group_membership::Entity::find()
            .join(
                JoinType::InnerJoin,
                ip_record_group_membership::Relation::IpGroup.def(),
            )
            .filter(ip_record_group_membership::Column::IpRecordId.is_in(top_ids.iter().copied()))
            .filter(ip_record_group_membership::Column::IsDeleted.eq(false));
        if let Some(ref allowed) = authorized_groups {
            m_query = m_query.filter(
                ip_record_group_membership::Column::GroupId.is_in(allowed.iter().copied()),
            );
        }
        let memberships_with_groups = m_query.select_also(ip_group::Entity).all(&state.db).await?;
        let mut group_names_by_ip: std::collections::HashMap<Uuid, Vec<String>> =
            std::collections::HashMap::new();
        for (m, grp_opt) in memberships_with_groups {
            if let Some(grp) = grp_opt {
                let list = group_names_by_ip.entry(m.ip_record_id).or_default();
                if !list.contains(&grp.name) {
                    list.push(grp.name);
                }
            }
        }

        // Batch aggregate first_seen and last_seen
        let time_tuples: Vec<(Uuid, Option<NaiveDateTime>, Option<NaiveDateTime>)> =
            ip_record_group_membership::Entity::find()
                .filter(ip_record_group_membership::Column::IpRecordId.is_in(top_ids.iter().copied()))
                .select_only()
                .column(ip_record_group_membership::Column::IpRecordId)
                .expr_as(
                    Func::min(Expr::col(ip_record_group_membership::Column::CreatedAt)),
                    "min_created",
                )
                .expr_as(
                    Func::max(Expr::col(ip_record_group_membership::Column::LastSeenAt)),
                    "max_seen",
                )
                .group_by(ip_record_group_membership::Column::IpRecordId)
                .into_tuple::<(Uuid, Option<NaiveDateTime>, Option<NaiveDateTime>)>()
                .all(&state.db)
                .await?;
        let mut times_by_ip: std::collections::HashMap<
            Uuid,
            (Option<NaiveDateTime>, Option<NaiveDateTime>),
        > = time_tuples.into_iter().map(|(id, c, s)| (id, (c, s))).collect();

        // Batch fetch latest causes
        let mut cause_query = ip_record_cause::Entity::find()
            .join(
                JoinType::InnerJoin,
                ip_record_cause::Relation::IpRecordGroupMembership.def(),
            )
            .filter(ip_record_group_membership::Column::IpRecordId.is_in(top_ids.iter().copied()))
            .filter(ip_record_group_membership::Column::IsDeleted.eq(false));
        if let Some(ref allowed) = authorized_groups {
            cause_query = cause_query.filter(
                ip_record_group_membership::Column::GroupId.is_in(allowed.iter().copied()),
            );
        }
        let cause_rows: Vec<(Uuid, String)> = cause_query
            .order_by_desc(ip_record_cause::Column::CreatedAt)
            .select_only()
            .column(ip_record_group_membership::Column::IpRecordId)
            .column(ip_record_cause::Column::Cause)
            .into_tuple::<(Uuid, String)>()
            .all(&state.db)
            .await?;

        let mut causes_by_ip: std::collections::HashMap<Uuid, Vec<String>> =
            std::collections::HashMap::new();
        for (ip_id, cause) in cause_rows {
            if !cause.trim().is_empty() {
                let list = causes_by_ip.entry(ip_id).or_default();
                if list.len() < 3 && !list.contains(&cause) {
                    list.push(cause);
                }
            }
        }

        let mut result = Vec::with_capacity(top_rec_tuples.len());
        for (rec_id, grp_cnt) in top_rec_tuples {
            let Some(r) = records_map.get(&rec_id) else { continue };
            let empty_groups = Vec::new();
            let mut group_names = group_names_by_ip.get(&rec_id).unwrap_or(&empty_groups).clone();
            group_names.sort();
            let (first_seen, last_seen) = times_by_ip.remove(&rec_id).unwrap_or((None, None));
            let empty_causes = Vec::new();
            let latest_causes = causes_by_ip.get(&rec_id).unwrap_or(&empty_causes).clone();

            result.push(RecidivistIp {
                ip_record_id: rec_id,
                target_address: r.target_address.clone(),
                group_count: std::cmp::max(grp_cnt, group_names.len() as i64) as u64,
                group_names,
                first_seen,
                last_seen,
                latest_causes,
            });
        }
        result
    };

    // 6. CIDR / Subnet distribution (/24 for IPv4, /48-/64 for IPv6)
    let mut active_ip_q = ip_record::Entity::find()
        .join(
            JoinType::InnerJoin,
            ip_record::Relation::IpRecordGroupMembership.def(),
        )
        .filter(ip_record_group_membership::Column::IsDeleted.eq(false));
    if let Some(ref allowed) = authorized_groups {
        active_ip_q = active_ip_q.filter(
            ip_record_group_membership::Column::GroupId.is_in(allowed.iter().copied()),
        );
    }
    let addresses: Vec<String> = active_ip_q
        .select_only()
        .column(ip_record::Column::TargetAddress)
        .distinct()
        .limit(25000)
        .into_tuple::<String>()
        .all(&state.db)
        .await?;

    let mut subnet_counts: std::collections::HashMap<String, u64> = std::collections::HashMap::new();
    for addr in addresses {
        if let Some(subnet) = to_subnet_prefix(&addr) {
            *subnet_counts.entry(subnet).or_default() += 1;
        }
    }
    let mut cidr_breakdown: Vec<CidrStat> = subnet_counts
        .into_iter()
        .map(|(subnet, active_count)| CidrStat {
            subnet,
            active_count,
        })
        .collect();
    cidr_breakdown.sort_by(|a, b| {
        b.active_count
            .cmp(&a.active_count)
            .then_with(|| a.subnet.cmp(&b.subnet))
    });
    cidr_breakdown.truncate(10);

    // 7. Locked vs dynamic breakdown
    let mut locked_q = ip_record_group_membership::Entity::find()
        .filter(ip_record_group_membership::Column::IsDeleted.eq(false));
    if let Some(ref allowed) = authorized_groups {
        locked_q = locked_q.filter(
            ip_record_group_membership::Column::GroupId.is_in(allowed.iter().copied()),
        );
    }
    let locked_rows: Vec<(bool, i64)> = locked_q
        .select_only()
        .column(ip_record_group_membership::Column::IsLocked)
        .expr_as(Func::count(Expr::col(sea_orm::sea_query::Asterisk)), "cnt")
        .group_by(ip_record_group_membership::Column::IsLocked)
        .into_tuple::<(bool, i64)>()
        .all(&state.db)
        .await?;

    let mut locked_count = 0u64;
    let mut dynamic_count = 0u64;
    for (is_locked, cnt) in locked_rows {
        let count = std::cmp::max(cnt, 0) as u64;
        if is_locked {
            locked_count += count;
        } else {
            dynamic_count += count;
        }
    }
    let total_active = locked_count + dynamic_count;
    let locked_breakdown = LockedBreakdown {
        total_active,
        locked_count,
        dynamic_count,
    };

    // 8. Velocity breakdown (24h & 7d)
    let now = chrono::Utc::now().naive_utc();
    let threshold_24h = now - chrono::Duration::hours(24);
    let threshold_7d = now - chrono::Duration::days(7);

    let velocity_24h =
        compute_velocity(&state.db, authorized_groups.as_ref(), threshold_24h).await?;
    let velocity_7d = compute_velocity(&state.db, authorized_groups.as_ref(), threshold_7d).await?;

    let response = AnalyticsResponse {
        total_active_ips,
        recidivist_ips_count,
        recidivism_rate_pct,
        groups,
        top_causes,
        top_recidivists,
        cidr_breakdown,
        locked_breakdown,
        velocity_24h,
        velocity_7d,
    };

    if caller.is_master
        && let Ok(val) = serde_json::to_value(&response)
    {
        let mut cache_write = state.analytics_cache.write().await;
        *cache_write = Some((std::time::Instant::now(), val));
    }

    Ok(Json(response).into_response())
}

/// Handles `GET /api/stats/intersection`.
pub async fn get_intersection(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Query(query): Query<IntersectionQuery>,
) -> Result<impl IntoResponse, AppError> {
    let authorized_groups = resolve_authorized_groups(&state.db, &caller).await?;

    // Collect requested group names/UUIDs from query params
    let mut requested: Vec<String> = Vec::new();
    if let Some(ref list) = query.groups {
        for s in list.split(',') {
            let trimmed = s.trim();
            if !trimmed.is_empty() && !requested.iter().any(|r| r.eq_ignore_ascii_case(trimmed)) {
                requested.push(trimmed.to_owned());
            }
        }
    }
    if let Some(ref a) = query.group_a {
        let trimmed = a.trim();
        if !trimmed.is_empty() && !requested.iter().any(|r| r.eq_ignore_ascii_case(trimmed)) {
            requested.push(trimmed.to_owned());
        }
    }
    if let Some(ref b) = query.group_b {
        let trimmed = b.trim();
        if !trimmed.is_empty() && !requested.iter().any(|r| r.eq_ignore_ascii_case(trimmed)) {
            requested.push(trimmed.to_owned());
        }
    }

    if requested.len() < 2 {
        return Err(AppError::InvalidInput(
            "At least two groups must be specified for an intersection".to_owned(),
        ));
    }

    // Resolve each group entity
    let mut resolved_groups: Vec<ip_group::Model> = Vec::with_capacity(requested.len());
    for item in &requested {
        let parsed_uuid = Uuid::parse_str(item).unwrap_or_default();
        let group = ip_group::Entity::find()
            .filter(
                sea_orm::Condition::any()
                    .add(ip_group::Column::Name.eq(item.as_str()))
                    .add(ip_group::Column::Id.eq(parsed_uuid)),
            )
            .one(&state.db)
            .await?
            .ok_or(AppError::NotFound)?;
        resolved_groups.push(group);
    }

    // RBAC check
    if let Some(ref allowed) = authorized_groups {
        for group in &resolved_groups {
            if !allowed.contains(&group.id) {
                return Err(AppError::Forbidden(
                    "You do not have permission to view one or more of these groups".to_owned(),
                ));
            }
        }
    }

    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let offset = query.offset.unwrap_or(0);

    let n = resolved_groups.len();
    let group_ids: Vec<Uuid> = resolved_groups.iter().map(|g| g.id).collect();

    // 1. Efficient total_overlap count pushed down directly to database via subquery count
    let isect_sub_query = ip_record_group_membership::Entity::find()
        .filter(ip_record_group_membership::Column::IsDeleted.eq(false))
        .filter(
            ip_record_group_membership::Column::GroupId.is_in(group_ids.iter().copied()),
        )
        .select_only()
        .column(ip_record_group_membership::Column::IpRecordId)
        .group_by(ip_record_group_membership::Column::IpRecordId)
        .having(
            Func::count_distinct(Expr::col(ip_record_group_membership::Column::GroupId))
                .eq(n as i64),
        )
        .into_query();

    let count_stmt = SqQuery::select()
        .expr_as(Func::count(Expr::col(sea_orm::sea_query::Asterisk)), Alias::new("cnt"))
        .from_subquery(isect_sub_query, Alias::new("sub"))
        .to_owned();

    let row = state.db.query_one(&count_stmt).await?;
    let total_overlap: u64 = row
        .and_then(|r| r.try_get::<i64>("", "cnt").ok())
        .map(|c| std::cmp::max(c, 0) as u64)
        .unwrap_or(0);

    // 2. Fetch only the paged IP record IDs directly via SQL with LIMIT & OFFSET
    let paged_ids: Vec<Uuid> = if total_overlap == 0 || offset >= total_overlap {
        Vec::new()
    } else {
        ip_record_group_membership::Entity::find()
            .filter(ip_record_group_membership::Column::IsDeleted.eq(false))
            .filter(
                ip_record_group_membership::Column::GroupId.is_in(group_ids.iter().copied()),
            )
            .select_only()
            .column(ip_record_group_membership::Column::IpRecordId)
            .group_by(ip_record_group_membership::Column::IpRecordId)
            .having(
                Func::count_distinct(Expr::col(ip_record_group_membership::Column::GroupId))
                    .eq(n as i64),
            )
            .order_by_asc(ip_record_group_membership::Column::IpRecordId)
            .limit(limit)
            .offset(offset)
            .into_tuple::<Uuid>()
            .all(&state.db)
            .await?
    };

    // 3. Batch-fetch records and memberships for paged IDs to eliminate N+1 queries
    let items = if paged_ids.is_empty() {
        Vec::new()
    } else {
        let records = ip_record::Entity::find()
            .filter(ip_record::Column::Id.is_in(paged_ids.iter().copied()))
            .all(&state.db)
            .await?;
        let records_map: std::collections::HashMap<Uuid, ip_record::Model> =
            records.into_iter().map(|r| (r.id, r)).collect();

        let memberships = ip_record_group_membership::Entity::find()
            .filter(ip_record_group_membership::Column::IpRecordId.is_in(paged_ids.iter().copied()))
            .filter(ip_record_group_membership::Column::GroupId.is_in(group_ids.iter().copied()))
            .filter(ip_record_group_membership::Column::IsDeleted.eq(false))
            .all(&state.db)
            .await?;

        let mut memberships_by_ip: std::collections::HashMap<
            Uuid,
            Vec<ip_record_group_membership::Model>,
        > = std::collections::HashMap::new();
        for m in memberships {
            memberships_by_ip.entry(m.ip_record_id).or_default().push(m);
        }

        let mut items = Vec::with_capacity(paged_ids.len());
        for rec_id in &paged_ids {
            let Some(r) = records_map.get(rec_id) else { continue };
            let empty_vec = Vec::new();
            let m_list = memberships_by_ip.get(rec_id).unwrap_or(&empty_vec);

            let mut group_last_seen = std::collections::HashMap::new();
            for m in m_list {
                if let Some(grp) = resolved_groups.iter().find(|g| g.id == m.group_id) {
                    group_last_seen.insert(grp.name.clone(), Some(m.last_seen_at));
                }
            }

            let last_seen_a = resolved_groups.first().and_then(|ga| {
                m_list.iter().find(|m| m.group_id == ga.id).map(|m| m.last_seen_at)
            });
            let last_seen_b = resolved_groups.get(1).and_then(|gb| {
                m_list.iter().find(|m| m.group_id == gb.id).map(|m| m.last_seen_at)
            });

            items.push(IntersectionItem {
                ip_record_id: *rec_id,
                target_address: r.target_address.clone(),
                group_last_seen,
                last_seen_a,
                last_seen_b,
            });
        }
        items
    };

    let groups = resolved_groups
        .iter()
        .map(|g| IntersectedGroup {
            id: g.id,
            name: g.name.clone(),
        })
        .collect();

    Ok(Json(IntersectionResponse {
        groups,
        group_a_id: resolved_groups.first().map(|g| g.id),
        group_a_name: resolved_groups.first().map(|g| g.name.clone()),
        group_b_id: resolved_groups.get(1).map(|g| g.id),
        group_b_name: resolved_groups.get(1).map(|g| g.name.clone()),
        total_overlap,
        items,
    }))
}
