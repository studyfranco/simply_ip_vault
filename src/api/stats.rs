//! Ban Analytics & Recidivism endpoints (`GET /api/stats/analytics` and `GET /api/stats/intersection`).
//! Provides high-level security insights into multi-group bans, recidivist IPs, and trigger causes.

use std::collections::{HashMap, HashSet};

use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::{Extension, Json};
use sea_orm::sea_query::{Alias, Expr, ExprTrait, Func, Query as SqQuery};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseConnection, EntityTrait, PaginatorTrait, QueryFilter,
    QueryOrder, QuerySelect, QueryTrait,
};
use serde::{Deserialize, Serialize};
use time::PrimitiveDateTime;
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
    #[serde(with = "crate::time_serde::option")]
    pub first_seen: Option<PrimitiveDateTime>,
    /// Most recent `last_seen` timestamp across memberships.
    #[serde(with = "crate::time_serde::option")]
    pub last_seen: Option<PrimitiveDateTime>,
    /// Most recent ban causes across memberships.
    pub latest_causes: Vec<String>,
}

/// Breakdown of active IPs by subnet.
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CidrStat {
    /// CIDR subnet prefix (e.g. "192.168.1.0/24" or "`2001:db8::/64`").
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
    #[serde(with = "crate::time_serde::map")]
    pub group_last_seen: HashMap<String, Option<PrimitiveDateTime>>,
    /// Last seen timestamp in the first group (for backward compatibility).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "crate::time_serde::option")]
    pub last_seen_a: Option<PrimitiveDateTime>,
    /// Last seen timestamp in the second group (for backward compatibility).
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "crate::time_serde::option")]
    pub last_seen_b: Option<PrimitiveDateTime>,
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
    threshold: PrimitiveDateTime,
) -> Result<VelocityStat, AppError> {
    // For active memberships, last_seen_at is always >= created_at. Filtering by last_seen_at >= threshold
    // covers both newly created and re-seen active memberships, allowing SQLite to use the composite
    // index `idx_memberships_is_deleted_last_seen` in a fast B-tree range scan rather than falling back
    // to a full table scan across millions of records.
    let mut active_q = ip_record_group_membership::Entity::find()
        .filter(ip_record_group_membership::Column::IsDeleted.eq(false))
        .filter(ip_record_group_membership::Column::LastSeenAt.gte(threshold));
    if let Some(allowed) = authorized_groups {
        active_q = active_q
            .filter(ip_record_group_membership::Column::GroupId.is_in(allowed.iter().copied()));
    }
    let active_added_or_seen = active_q.count(db).await?;

    let mut deleted_q = ip_record_group_membership::Entity::find()
        .filter(ip_record_group_membership::Column::IsDeleted.eq(true))
        .filter(ip_record_group_membership::Column::DeletedAt.gte(threshold));
    if let Some(allowed) = authorized_groups {
        deleted_q = deleted_q
            .filter(ip_record_group_membership::Column::GroupId.is_in(allowed.iter().copied()));
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
        })
        .into_response());
    }

    // Analytics caching per authorization scope and committed membership revision.
    let cache_key: Option<Vec<Uuid>> = authorized_groups.as_ref().map(|g| {
        let mut v: Vec<Uuid> = g.iter().copied().collect();
        v.sort();
        v
    });

    {
        let cache_read = state.analytics_cache.read().await;
        if let Some((revision, ts, payload)) = cache_read.get(&cache_key)
            && *revision == state.membership_revision()
            && ts.elapsed() < crate::state::MEMBERSHIP_CACHE_TTL
        {
            return Ok(Json(payload.clone()).into_response());
        }
    }

    // Acquire singleflight lock to serialize concurrent analytics requests
    // and prevent database lock contention. Moving the owned guard into a spawned task
    // ensures that even if an impatient HTTP proxy disconnects mid-flight, the computation
    // finishes and populates `analytics_cache` for the retry.
    let singleflight_guard = state.analytics_lock.clone().lock_owned().await;

    {
        let cache_read = state.analytics_cache.read().await;
        if let Some((revision, ts, payload)) = cache_read.get(&cache_key)
            && *revision == state.membership_revision()
            && ts.elapsed() < crate::state::MEMBERSHIP_CACHE_TTL
        {
            return Ok(Json(payload.clone()).into_response());
        }
    }

    let state_clone = state.clone();
    let handle = tokio::spawn(async move {
        let _guard = singleflight_guard;
        compute_and_cache_analytics(state_clone, authorized_groups, cache_key).await
    });

    let response = handle.await.map_err(|e| {
        tracing::error!("Analytics background task failed: {e}");
        AppError::Internal
    })??;

    Ok(Json(response).into_response())
}

async fn compute_and_cache_analytics(
    state: AppState,
    authorized_groups: Option<HashSet<Uuid>>,
    cache_key: Option<Vec<Uuid>>,
) -> Result<AnalyticsResponse, AppError> {
    let revision = state.membership_revision();
    // 1. Groups & active counts by group
    let mut groups_query = ip_group::Entity::find();
    if let Some(ref allowed) = authorized_groups {
        groups_query = groups_query.filter(ip_group::Column::Id.is_in(allowed.iter().copied()));
    }
    let all_groups = groups_query.all(&state.db).await?;
    let group_name_by_id: HashMap<Uuid, String> =
        all_groups.iter().map(|g| (g.id, g.name.clone())).collect();

    let active_counts_map = active_counts_by_group(&state.db, authorized_groups.as_ref()).await?;

    let total_active_memberships: u64 = active_counts_map.values().copied().sum();
    let non_empty_groups = active_counts_map.values().filter(|&&c| c > 0).count();

    // 2. Single covering-index scan to compute recidivist IPs, total unique active IPs,
    //    shared counts per group, and top 50 recidivist tuples.
    //    Because `(ip_record_id, group_id)` is UNIQUE (`idx_memberships_ip_group`), `COUNT(*)`
    //    per `ip_record_id` is identical to `COUNT(DISTINCT group_id)`, and
    //    `total_active_ips = total_active_memberships - SUM(grp_cnt - 1)`.
    let RecidivismSummary {
        total_active_ips,
        recidivist_ips_count,
        shared_counts_map,
        top_rec_tuples,
    } = summarize_recidivism(
        &state.db,
        authorized_groups.as_ref(),
        total_active_memberships,
        non_empty_groups,
    )
    .await?;

    let recidivism_rate_pct = if total_active_ips > 0 {
        (count_to_f64(recidivist_ips_count) * 100.0) / count_to_f64(total_active_ips)
    } else {
        0.0
    };

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

    let top_causes = top_active_causes(&state.db, authorized_groups.as_ref()).await?;
    let top_recidivists =
        load_top_recidivists(&state.db, top_rec_tuples, &group_name_by_id).await?;
    let cidr_breakdown = subnet_distribution(&state.db, authorized_groups.as_ref()).await?;

    // 7. Locked vs dynamic breakdown
    // Query only `is_deleted = false AND is_locked = true` via `idx_memberships_is_deleted_is_locked`
    // and derive `dynamic_count` from `total_active_memberships`.
    let mut locked_q = ip_record_group_membership::Entity::find()
        .filter(ip_record_group_membership::Column::IsDeleted.eq(false))
        .filter(ip_record_group_membership::Column::IsLocked.eq(true));
    if let Some(ref allowed) = authorized_groups {
        locked_q = locked_q
            .filter(ip_record_group_membership::Column::GroupId.is_in(allowed.iter().copied()));
    }
    let locked_count = locked_q.count(&state.db).await?;
    let total_active = std::cmp::max(total_active_memberships, locked_count);
    let dynamic_count = total_active.saturating_sub(locked_count);
    let locked_breakdown = LockedBreakdown {
        total_active,
        locked_count,
        dynamic_count,
    };

    // 8. Velocity breakdown (24h & 7d)
    let now = crate::time_serde::now_utc();
    let threshold_24h = now - time::Duration::hours(24);
    let threshold_7d = now - time::Duration::days(7);

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

    if let Ok(val) = serde_json::to_value(&response) {
        let mut cache_write = state.analytics_cache.write().await;
        cache_write.retain(|_, (cached_revision, ts, _)| {
            *cached_revision == revision && ts.elapsed() < crate::state::MEMBERSHIP_CACHE_TTL
        });
        if cache_write.len() < 256 && revision == state.membership_revision() {
            cache_write.insert(cache_key, (revision, std::time::Instant::now(), val));
        }
    }

    Ok(response)
}

/// Handles `GET /api/stats/intersection`.
pub async fn get_intersection(
    State(state): State<AppState>,
    Extension(caller): Extension<api_key::Model>,
    Query(query): Query<IntersectionQuery>,
) -> Result<impl IntoResponse, AppError> {
    let authorized_groups = resolve_authorized_groups(&state.db, &caller).await?;

    let resolved_groups =
        resolve_intersection_groups(&state.db, &query, authorized_groups.as_ref()).await?;

    let limit = query.limit.unwrap_or(50).clamp(1, 100);
    let offset = query.offset.unwrap_or(0);

    let n = i64::try_from(resolved_groups.len()).map_err(|_| AppError::Internal)?;
    let group_ids: Vec<Uuid> = resolved_groups.iter().map(|g| g.id).collect();

    // 1. Efficient total_overlap count pushed down directly to database via subquery count
    let isect_sub_query = ip_record_group_membership::Entity::find()
        .filter(ip_record_group_membership::Column::IsDeleted.eq(false))
        .filter(ip_record_group_membership::Column::GroupId.is_in(group_ids.iter().copied()))
        .select_only()
        .column(ip_record_group_membership::Column::IpRecordId)
        .group_by(ip_record_group_membership::Column::IpRecordId)
        .having(Func::count_distinct(Expr::col(ip_record_group_membership::Column::GroupId)).eq(n))
        .into_query();

    let count_stmt = SqQuery::select()
        .expr_as(
            Func::count(Expr::col(sea_orm::sea_query::Asterisk)),
            Alias::new("cnt"),
        )
        .from_subquery(isect_sub_query, Alias::new("sub"))
        .to_owned();

    let row = state.db.query_one(&count_stmt).await?;
    let total_overlap: u64 = row
        .and_then(|r| r.try_get::<i64>("", "cnt").ok())
        .map_or(0, nonnegative_count);

    // 2. Fetch only the paged IP record IDs directly via SQL with LIMIT & OFFSET
    let paged_ids: Vec<Uuid> = if total_overlap == 0 || offset >= total_overlap {
        Vec::new()
    } else {
        ip_record_group_membership::Entity::find()
            .filter(ip_record_group_membership::Column::IsDeleted.eq(false))
            .filter(ip_record_group_membership::Column::GroupId.is_in(group_ids.iter().copied()))
            .select_only()
            .column(ip_record_group_membership::Column::IpRecordId)
            .group_by(ip_record_group_membership::Column::IpRecordId)
            .having(
                Func::count_distinct(Expr::col(ip_record_group_membership::Column::GroupId)).eq(n),
            )
            .order_by_asc(ip_record_group_membership::Column::IpRecordId)
            .limit(limit)
            .offset(offset)
            .into_tuple::<Uuid>()
            .all(&state.db)
            .await?
    };

    let items =
        load_intersection_items(&state.db, &resolved_groups, &group_ids, &paged_ids).await?;

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

fn nonnegative_count(count: i64) -> u64 {
    u64::try_from(count).unwrap_or(0)
}

fn count_to_f64(count: u64) -> f64 {
    let [low, high] = [
        u32::try_from(count & u64::from(u32::MAX)).unwrap_or_default(),
        u32::try_from(count >> 32).unwrap_or_default(),
    ];
    f64::from(high).mul_add(4_294_967_296.0, f64::from(low))
}

async fn active_counts_by_group(
    db: &DatabaseConnection,
    authorized_groups: Option<&HashSet<Uuid>>,
) -> Result<HashMap<Uuid, u64>, AppError> {
    let mut active_counts_q = ip_record_group_membership::Entity::find()
        .filter(ip_record_group_membership::Column::IsDeleted.eq(false));
    if let Some(allowed) = authorized_groups {
        active_counts_q = active_counts_q
            .filter(ip_record_group_membership::Column::GroupId.is_in(allowed.iter().copied()));
    }
    let active_counts: Vec<(Uuid, i64)> = active_counts_q
        .select_only()
        .column(ip_record_group_membership::Column::GroupId)
        .expr_as(Func::count(Expr::col(sea_orm::sea_query::Asterisk)), "cnt")
        .group_by(ip_record_group_membership::Column::GroupId)
        .into_tuple::<(Uuid, i64)>()
        .all(db)
        .await?;
    Ok(active_counts
        .into_iter()
        .map(|(gid, cnt)| (gid, nonnegative_count(cnt)))
        .collect())
}

async fn shared_counts_by_group(
    db: &DatabaseConnection,
    authorized_groups: Option<&HashSet<Uuid>>,
    recidivist_tuples: &[(Uuid, i64)],
) -> Result<HashMap<Uuid, u64>, AppError> {
    let mut shared_map: HashMap<Uuid, u64> = HashMap::new();
    if !recidivist_tuples.is_empty() {
        if recidivist_tuples.len() <= 50_000 {
            let rec_ids: Vec<Uuid> = recidivist_tuples.iter().map(|(id, _)| *id).collect();
            for chunk in rec_ids.chunks(900) {
                let mut sq = ip_record_group_membership::Entity::find()
                    .filter(ip_record_group_membership::Column::IsDeleted.eq(false))
                    .filter(
                        ip_record_group_membership::Column::IpRecordId.is_in(chunk.iter().copied()),
                    );
                if let Some(allowed) = authorized_groups {
                    sq = sq.filter(
                        ip_record_group_membership::Column::GroupId.is_in(allowed.iter().copied()),
                    );
                }
                let chunk_counts: Vec<(Uuid, i64)> = sq
                    .select_only()
                    .column(ip_record_group_membership::Column::GroupId)
                    .expr_as(Func::count(Expr::col(sea_orm::sea_query::Asterisk)), "cnt")
                    .group_by(ip_record_group_membership::Column::GroupId)
                    .into_tuple::<(Uuid, i64)>()
                    .all(db)
                    .await?;
                for (gid, cnt) in chunk_counts {
                    *shared_map.entry(gid).or_default() += nonnegative_count(cnt);
                }
            }
        } else {
            let mut shared_sub = ip_record_group_membership::Entity::find()
                .filter(ip_record_group_membership::Column::IsDeleted.eq(false));
            if let Some(allowed) = authorized_groups {
                shared_sub = shared_sub.filter(
                    ip_record_group_membership::Column::GroupId.is_in(allowed.iter().copied()),
                );
            }
            let shared_sub_query = shared_sub
                .select_only()
                .column(ip_record_group_membership::Column::IpRecordId)
                .group_by(ip_record_group_membership::Column::IpRecordId)
                .having(Expr::expr(Func::count(Expr::col(sea_orm::sea_query::Asterisk))).gt(1))
                .into_query();

            let mut shared_counts_q = ip_record_group_membership::Entity::find()
                .filter(ip_record_group_membership::Column::IsDeleted.eq(false))
                .filter(
                    Expr::col(ip_record_group_membership::Column::IpRecordId)
                        .in_subquery(shared_sub_query),
                );
            if let Some(allowed) = authorized_groups {
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
                .all(db)
                .await?;
            for (gid, cnt) in shared_counts {
                shared_map.insert(gid, nonnegative_count(cnt));
            }
        }
    }

    Ok(shared_map)
}

struct RecidivismSummary {
    total_active_ips: u64,
    recidivist_ips_count: u64,
    shared_counts_map: HashMap<Uuid, u64>,
    top_rec_tuples: Vec<(Uuid, i64)>,
}

async fn summarize_recidivism(
    db: &DatabaseConnection,
    authorized_groups: Option<&HashSet<Uuid>>,
    total_active_memberships: u64,
    non_empty_groups: usize,
) -> Result<RecidivismSummary, AppError> {
    Ok(if non_empty_groups <= 1 {
        RecidivismSummary {
            total_active_ips: total_active_memberships,
            recidivist_ips_count: 0,
            shared_counts_map: HashMap::new(),
            top_rec_tuples: Vec::new(),
        }
    } else {
        let mut rec_q = ip_record_group_membership::Entity::find()
            .filter(ip_record_group_membership::Column::IsDeleted.eq(false));
        if let Some(allowed) = authorized_groups {
            rec_q = rec_q
                .filter(ip_record_group_membership::Column::GroupId.is_in(allowed.iter().copied()));
        }
        let mut recidivist_tuples: Vec<(Uuid, i64)> = rec_q
            .select_only()
            .column(ip_record_group_membership::Column::IpRecordId)
            .expr_as(
                Func::count(Expr::col(sea_orm::sea_query::Asterisk)),
                "grp_cnt",
            )
            .group_by(ip_record_group_membership::Column::IpRecordId)
            .having(Expr::expr(Func::count(Expr::col(sea_orm::sea_query::Asterisk))).gt(1))
            .into_tuple::<(Uuid, i64)>()
            .all(db)
            .await?;

        let rec_count = recidivist_tuples.len() as u64;
        let excess_memberships: u64 = recidivist_tuples
            .iter()
            .map(|(_, cnt)| nonnegative_count(cnt.saturating_sub(1)))
            .sum();
        let unique_active_ips = total_active_memberships.saturating_sub(excess_memberships);

        let shared_map = shared_counts_by_group(db, authorized_groups, &recidivist_tuples).await?;

        recidivist_tuples.sort_unstable_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        recidivist_tuples.truncate(50);

        RecidivismSummary {
            total_active_ips: unique_active_ips,
            recidivist_ips_count: rec_count,
            shared_counts_map: shared_map,
            top_rec_tuples: recidivist_tuples,
        }
    })
}

async fn top_active_causes(
    db: &DatabaseConnection,
    authorized_groups: Option<&HashSet<Uuid>>,
) -> Result<Vec<CauseStat>, AppError> {
    // 4. Top causes across active memberships.
    // Drive the aggregation from `ip_record_causes` (using covering index `idx_causes_cause_membership`)
    // rather than an `INNER JOIN` that scans all 7M memberships as the outer loop.
    let has_deleted_memberships = if authorized_groups.is_none() {
        ip_record_group_membership::Entity::find()
            .filter(ip_record_group_membership::Column::IsDeleted.eq(true))
            .select_only()
            .column(ip_record_group_membership::Column::Id)
            .limit(1)
            .into_tuple::<Uuid>()
            .one(db)
            .await?
            .is_some()
    } else {
        true
    };

    let mut cause_q = ip_record_cause::Entity::find();
    if authorized_groups.is_some() || has_deleted_memberships {
        let mut exists_sub = SqQuery::select();
        exists_sub
            .expr(Expr::val(1))
            .from(ip_record_group_membership::Entity)
            .and_where(
                Expr::col((
                    ip_record_group_membership::Entity,
                    ip_record_group_membership::Column::Id,
                ))
                .equals((
                    ip_record_cause::Entity,
                    ip_record_cause::Column::MembershipId,
                )),
            )
            .and_where(
                Expr::col((
                    ip_record_group_membership::Entity,
                    ip_record_group_membership::Column::IsDeleted,
                ))
                .eq(false),
            );
        if let Some(allowed) = authorized_groups {
            exists_sub.and_where(
                Expr::col((
                    ip_record_group_membership::Entity,
                    ip_record_group_membership::Column::GroupId,
                ))
                .is_in(allowed.iter().copied()),
            );
        }
        cause_q = cause_q.filter(Expr::exists(exists_sub));
    }

    let cause_tuples: Vec<(String, i64)> = cause_q
        .select_only()
        .column(ip_record_cause::Column::Cause)
        .expr_as(Func::count(Expr::col(sea_orm::sea_query::Asterisk)), "cnt")
        .group_by(ip_record_cause::Column::Cause)
        .order_by_desc(Expr::col(Alias::new("cnt")))
        .limit(10)
        .into_tuple::<(String, i64)>()
        .all(db)
        .await?;
    Ok(cause_tuples
        .into_iter()
        .filter(|(c, _)| !c.trim().is_empty())
        .map(|(cause, cnt)| CauseStat {
            cause,
            count: nonnegative_count(cnt),
        })
        .collect())
}

async fn latest_causes_by_ip(
    db: &DatabaseConnection,
    membership_to_ip: &HashMap<Uuid, Uuid>,
) -> Result<HashMap<Uuid, Vec<String>>, AppError> {
    // Batch fetch latest causes directly by `membership_id IN (...)` via `idx-irc-membership_id`
    let mut causes_by_ip: HashMap<Uuid, Vec<String>> = HashMap::new();
    if !membership_to_ip.is_empty() {
        let cause_rows: Vec<(Uuid, String)> = ip_record_cause::Entity::find()
            .filter(ip_record_cause::Column::MembershipId.is_in(membership_to_ip.keys().copied()))
            .order_by_desc(ip_record_cause::Column::CreatedAt)
            .select_only()
            .column(ip_record_cause::Column::MembershipId)
            .column(ip_record_cause::Column::Cause)
            .into_tuple::<(Uuid, String)>()
            .all(db)
            .await?;

        for (membership_id, cause) in cause_rows {
            if !cause.trim().is_empty()
                && let Some(&ip_id) = membership_to_ip.get(&membership_id)
            {
                let list = causes_by_ip.entry(ip_id).or_default();
                if list.len() < 3 && !list.contains(&cause) {
                    list.push(cause);
                }
            }
        }
    }

    Ok(causes_by_ip)
}

async fn load_top_recidivists(
    db: &DatabaseConnection,
    top_rec_tuples: Vec<(Uuid, i64)>,
    group_name_by_id: &HashMap<Uuid, String>,
) -> Result<Vec<RecidivistIp>, AppError> {
    // 5. Top Recidivist IPs: batch-fetched using direct index lookups on `top_ids`
    Ok(if top_rec_tuples.is_empty() {
        Vec::new()
    } else {
        let top_ids: Vec<Uuid> = top_rec_tuples.iter().map(|(id, _)| *id).collect();

        // Batch fetch records
        let records = ip_record::Entity::find()
            .filter(ip_record::Column::Id.is_in(top_ids.iter().copied()))
            .all(db)
            .await?;
        let records_map: HashMap<Uuid, ip_record::Model> =
            records.into_iter().map(|r| (r.id, r)).collect();

        // Fetch all memberships for the top 50 IPs via `idx-irgm-ip_record_id` without
        // filtering on `is_deleted` in SQL (which would tempt SQLite's planner into scanning
        // `idx_memberships_is_deleted_last_seen` across millions of rows).
        let top_memberships = ip_record_group_membership::Entity::find()
            .filter(ip_record_group_membership::Column::IpRecordId.is_in(top_ids.iter().copied()))
            .all(db)
            .await?;

        let mut group_names_by_ip: HashMap<Uuid, Vec<String>> = HashMap::new();
        let mut times_by_ip: HashMap<Uuid, (Option<PrimitiveDateTime>, Option<PrimitiveDateTime>)> =
            HashMap::new();
        let mut membership_to_ip: HashMap<Uuid, Uuid> = HashMap::new();

        for m in top_memberships {
            let entry = times_by_ip.entry(m.ip_record_id).or_insert((None, None));
            entry.0 = Some(match entry.0 {
                Some(prev) => std::cmp::min(prev, m.created_at),
                None => m.created_at,
            });
            entry.1 = Some(match entry.1 {
                Some(prev) => std::cmp::max(prev, m.last_seen_at),
                None => m.last_seen_at,
            });

            if !m.is_deleted
                && let Some(grp_name) = group_name_by_id.get(&m.group_id)
            {
                membership_to_ip.insert(m.id, m.ip_record_id);
                let list = group_names_by_ip.entry(m.ip_record_id).or_default();
                if !list.contains(grp_name) {
                    list.push(grp_name.clone());
                }
            }
        }

        let causes_by_ip = latest_causes_by_ip(db, &membership_to_ip).await?;

        let mut result = Vec::with_capacity(top_rec_tuples.len());
        for (rec_id, grp_cnt) in top_rec_tuples {
            let Some(r) = records_map.get(&rec_id) else {
                continue;
            };
            let empty_groups = Vec::new();
            let mut group_names = group_names_by_ip
                .get(&rec_id)
                .unwrap_or(&empty_groups)
                .clone();
            group_names.sort();
            let (first_seen, last_seen) = times_by_ip.remove(&rec_id).unwrap_or((None, None));
            let empty_causes = Vec::new();
            let latest_causes = causes_by_ip.get(&rec_id).unwrap_or(&empty_causes).clone();

            result.push(RecidivistIp {
                ip_record_id: rec_id,
                target_address: r.target_address.clone(),
                group_count: std::cmp::max(nonnegative_count(grp_cnt), group_names.len() as u64),
                group_names,
                first_seen,
                last_seen,
                latest_causes,
            });
        }
        result
    })
}

async fn subnet_distribution(
    db: &DatabaseConnection,
    authorized_groups: Option<&HashSet<Uuid>>,
) -> Result<Vec<CidrStat>, AppError> {
    // 6. CIDR / Subnet distribution (/24 for IPv4, /48-/64 for IPv6)
    // Query active IP record IDs first via covering index, avoiding multi-million row Cartesian joins
    let mut active_ip_q = ip_record_group_membership::Entity::find()
        .filter(ip_record_group_membership::Column::IsDeleted.eq(false));
    if let Some(allowed) = authorized_groups {
        active_ip_q = active_ip_q
            .filter(ip_record_group_membership::Column::GroupId.is_in(allowed.iter().copied()));
    }
    let ip_ids: Vec<Uuid> = active_ip_q
        .select_only()
        .column(ip_record_group_membership::Column::IpRecordId)
        .distinct()
        .limit(10000)
        .into_tuple::<Uuid>()
        .all(db)
        .await?;

    let addresses: Vec<String> = if ip_ids.is_empty() {
        Vec::new()
    } else {
        ip_record::Entity::find()
            .filter(ip_record::Column::Id.is_in(ip_ids))
            .select_only()
            .column(ip_record::Column::TargetAddress)
            .into_tuple::<String>()
            .all(db)
            .await?
    };

    let mut subnet_counts: HashMap<String, u64> = HashMap::new();
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

    Ok(cidr_breakdown)
}

async fn resolve_intersection_groups(
    db: &DatabaseConnection,
    query: &IntersectionQuery,
    authorized_groups: Option<&HashSet<Uuid>>,
) -> Result<Vec<ip_group::Model>, AppError> {
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
            .one(db)
            .await?
            .ok_or(AppError::NotFound)?;
        resolved_groups.push(group);
    }

    // RBAC check
    if let Some(allowed) = authorized_groups {
        for group in &resolved_groups {
            if !allowed.contains(&group.id) {
                return Err(AppError::Forbidden(
                    "You do not have permission to view one or more of these groups".to_owned(),
                ));
            }
        }
    }

    Ok(resolved_groups)
}

async fn load_intersection_items(
    db: &DatabaseConnection,
    resolved_groups: &[ip_group::Model],
    group_ids: &[Uuid],
    paged_ids: &[Uuid],
) -> Result<Vec<IntersectionItem>, AppError> {
    // 3. Batch-fetch records and memberships for paged IDs to eliminate N+1 queries
    Ok(if paged_ids.is_empty() {
        Vec::new()
    } else {
        let records = ip_record::Entity::find()
            .filter(ip_record::Column::Id.is_in(paged_ids.iter().copied()))
            .all(db)
            .await?;
        let records_map: HashMap<Uuid, ip_record::Model> =
            records.into_iter().map(|r| (r.id, r)).collect();

        let memberships = ip_record_group_membership::Entity::find()
            .filter(ip_record_group_membership::Column::IpRecordId.is_in(paged_ids.iter().copied()))
            .filter(ip_record_group_membership::Column::GroupId.is_in(group_ids.iter().copied()))
            .filter(ip_record_group_membership::Column::IsDeleted.eq(false))
            .all(db)
            .await?;

        let mut memberships_by_ip: HashMap<Uuid, Vec<ip_record_group_membership::Model>> =
            HashMap::new();
        for m in memberships {
            memberships_by_ip.entry(m.ip_record_id).or_default().push(m);
        }

        let mut items = Vec::with_capacity(paged_ids.len());
        for rec_id in paged_ids {
            let Some(r) = records_map.get(rec_id) else {
                continue;
            };
            let empty_vec = Vec::new();
            let m_list = memberships_by_ip.get(rec_id).unwrap_or(&empty_vec);

            let mut group_last_seen = HashMap::new();
            for m in m_list {
                if let Some(grp) = resolved_groups.iter().find(|g| g.id == m.group_id) {
                    group_last_seen.insert(grp.name.clone(), Some(m.last_seen_at));
                }
            }

            let last_seen_a = resolved_groups.first().and_then(|ga| {
                m_list
                    .iter()
                    .find(|m| m.group_id == ga.id)
                    .map(|m| m.last_seen_at)
            });
            let last_seen_b = resolved_groups.get(1).and_then(|gb| {
                m_list
                    .iter()
                    .find(|m| m.group_id == gb.id)
                    .map(|m| m.last_seen_at)
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
    })
}
