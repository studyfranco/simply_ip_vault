//! Ban Analytics & Recidivism endpoints (`GET /api/stats/analytics` and `GET /api/stats/intersection`).
//! Provides high-level security insights into multi-group bans, recidivist IPs, and trigger causes.

use std::collections::HashSet;

use axum::extract::{Query, State};
use axum::response::IntoResponse;
use axum::{Extension, Json};
use chrono::NaiveDateTime;
use sea_orm::sea_query::{Alias, Expr, ExprTrait, Func};
use sea_orm::{
    ColumnTrait, EntityTrait, JoinType, PaginatorTrait, QueryFilter, QueryOrder,
    QuerySelect, RelationTrait,
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
    if let Some(ref allowed) = authorized_groups {
        if allowed.is_empty() {
            return Ok(Json(AnalyticsResponse {
                total_active_ips: 0,
                recidivist_ips_count: 0,
                recidivism_rate_pct: 0.0,
                groups: Vec::new(),
                top_causes: Vec::new(),
                top_recidivists: Vec::new(),
            }));
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

    // 2. Multi-group (recidivist) IPs: list of ip_record_id appearing in >= 2 active groups
    let mut count_rec_q = ip_record_group_membership::Entity::find()
        .filter(ip_record_group_membership::Column::IsDeleted.eq(false));
    if let Some(ref allowed) = authorized_groups {
        count_rec_q = count_rec_q.filter(
            ip_record_group_membership::Column::GroupId.is_in(allowed.iter().copied()),
        );
    }
    let recidivist_ips_list: Vec<Uuid> = count_rec_q
        .select_only()
        .column(ip_record_group_membership::Column::IpRecordId)
        .group_by(ip_record_group_membership::Column::IpRecordId)
        .having(
            Expr::expr(Func::count_distinct(Expr::col(
                ip_record_group_membership::Column::GroupId,
            )))
            .gt(1),
        )
        .into_tuple::<Uuid>()
        .all(&state.db)
        .await?;

    let recidivist_ips_count = recidivist_ips_list.len() as u64;
    let recidivist_set: HashSet<Uuid> = recidivist_ips_list.iter().copied().collect();

    let recidivism_rate_pct = if total_active_ips > 0 {
        ((recidivist_ips_count as f64) * 100.0) / (total_active_ips as f64)
    } else {
        0.0
    };

    // 3. Groups breakdown with shared counts
    let mut groups_query = ip_group::Entity::find();
    if let Some(ref allowed) = authorized_groups {
        groups_query =
            groups_query.filter(ip_group::Column::Id.is_in(allowed.iter().copied()));
    }
    let all_groups = groups_query.all(&state.db).await?;
    let mut groups = Vec::new();
    for g in all_groups {
        let active_count = ip_record_group_membership::Entity::find()
            .filter(ip_record_group_membership::Column::GroupId.eq(g.id))
            .filter(ip_record_group_membership::Column::IsDeleted.eq(false))
            .count(&state.db)
            .await?;

        let mut shared_count = 0;
        if !recidivist_set.is_empty() {
            shared_count = ip_record_group_membership::Entity::find()
                .filter(ip_record_group_membership::Column::GroupId.eq(g.id))
                .filter(ip_record_group_membership::Column::IsDeleted.eq(false))
                .filter(
                    ip_record_group_membership::Column::IpRecordId
                        .is_in(recidivist_set.iter().copied()),
                )
                .count(&state.db)
                .await?;
        }
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

    // 5. Top Recidivist IPs (top 50)
    let top_50_ids: Vec<Uuid> = recidivist_ips_list.into_iter().take(50).collect();
    let mut top_recidivists = Vec::new();
    for rec_id in top_50_ids {
        let record = ip_record::Entity::find_by_id(rec_id)
            .one(&state.db)
            .await?;
        let Some(rec) = record else { continue };

        let mut m_query = ip_record_group_membership::Entity::find()
            .join(
                JoinType::InnerJoin,
                ip_record_group_membership::Relation::IpGroup.def(),
            )
            .filter(ip_record_group_membership::Column::IpRecordId.eq(rec_id))
            .filter(ip_record_group_membership::Column::IsDeleted.eq(false));
        if let Some(ref allowed) = authorized_groups {
            m_query = m_query.filter(
                ip_record_group_membership::Column::GroupId.is_in(allowed.iter().copied()),
            );
        }
        let memberships = m_query.select_also(ip_group::Entity).all(&state.db).await?;
        let group_names: Vec<String> = memberships
            .into_iter()
            .filter_map(|(_, g)| g.map(|grp| grp.name))
            .collect();

        let first_seen = ip_record_group_membership::Entity::find()
            .filter(ip_record_group_membership::Column::IpRecordId.eq(rec_id))
            .order_by_asc(ip_record_group_membership::Column::CreatedAt)
            .one(&state.db)
            .await?
            .map(|m| m.created_at);

        let last_seen = ip_record_group_membership::Entity::find()
            .filter(ip_record_group_membership::Column::IpRecordId.eq(rec_id))
            .order_by_desc(ip_record_group_membership::Column::LastSeenAt)
            .one(&state.db)
            .await?
            .map(|m| m.last_seen_at);

        let causes: Vec<String> = ip_record_cause::Entity::find()
            .join(
                JoinType::InnerJoin,
                ip_record_cause::Relation::IpRecordGroupMembership.def(),
            )
            .filter(ip_record_group_membership::Column::IpRecordId.eq(rec_id))
            .filter(ip_record_group_membership::Column::IsDeleted.eq(false))
            .order_by_desc(ip_record_cause::Column::CreatedAt)
            .limit(3)
            .select_only()
            .column(ip_record_cause::Column::Cause)
            .into_tuple::<String>()
            .all(&state.db)
            .await?;

        top_recidivists.push(RecidivistIp {
            ip_record_id: rec_id,
            target_address: rec.target_address,
            group_count: group_names.len() as u64,
            group_names,
            first_seen,
            last_seen,
            latest_causes: causes,
        });
    }

    Ok(Json(AnalyticsResponse {
        total_active_ips,
        recidivist_ips_count,
        recidivism_rate_pct,
        groups,
        top_causes,
        top_recidivists,
    }))
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

    let candidate_ip_ids: Vec<Uuid> = ip_record_group_membership::Entity::find()
        .filter(ip_record_group_membership::Column::IsDeleted.eq(false))
        .filter(ip_record_group_membership::Column::GroupId.is_in(group_ids.iter().copied()))
        .select_only()
        .column(ip_record_group_membership::Column::IpRecordId)
        .group_by(ip_record_group_membership::Column::IpRecordId)
        .having(
            Func::count_distinct(Expr::col(ip_record_group_membership::Column::GroupId))
                .eq(n as i64),
        )
        .into_tuple::<Uuid>()
        .all(&state.db)
        .await?;

    let total_overlap = candidate_ip_ids.len() as u64;
    let paged_ids: Vec<Uuid> = candidate_ip_ids
        .into_iter()
        .skip(offset as usize)
        .take(limit as usize)
        .collect();

    let mut items = Vec::with_capacity(paged_ids.len());
    for rec_id in paged_ids {
        let rec = ip_record::Entity::find_by_id(rec_id).one(&state.db).await?;
        let Some(r) = rec else { continue };

        let memberships = ip_record_group_membership::Entity::find()
            .filter(ip_record_group_membership::Column::IpRecordId.eq(rec_id))
            .filter(ip_record_group_membership::Column::GroupId.is_in(group_ids.iter().copied()))
            .filter(ip_record_group_membership::Column::IsDeleted.eq(false))
            .all(&state.db)
            .await?;

        let mut group_last_seen = std::collections::HashMap::new();
        for m in &memberships {
            if let Some(grp) = resolved_groups.iter().find(|g| g.id == m.group_id) {
                group_last_seen.insert(grp.name.clone(), Some(m.last_seen_at));
            }
        }

        let last_seen_a = resolved_groups.first().and_then(|ga| {
            memberships
                .iter()
                .find(|m| m.group_id == ga.id)
                .map(|m| m.last_seen_at)
        });
        let last_seen_b = resolved_groups.get(1).and_then(|gb| {
            memberships
                .iter()
                .find(|m| m.group_id == gb.id)
                .map(|m| m.last_seen_at)
        });

        items.push(IntersectionItem {
            ip_record_id: rec_id,
            target_address: r.target_address,
            group_last_seen,
            last_seen_a,
            last_seen_b,
        });
    }

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
