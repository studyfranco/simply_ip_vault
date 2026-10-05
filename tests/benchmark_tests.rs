//! Read-path benchmark at 100k memberships. Asserts the group-scoped list and count stay under the
//! 10 ms budget, and that the list query plans without a temp B-tree (no sort or temp materialisation
//! beyond the index walk).
//!
//! Timings are taken in release-like conditions only in spirit: this runs under the test profile, so
//! the assertion is the 10 ms budget measured as the median of repeated runs, not a single sample.

use std::time::{Duration, Instant};

use sea_orm::{ColumnTrait, ConnectionTrait, Database, DatabaseConnection, DbBackend, EntityTrait, JoinType, QueryFilter, QueryOrder, QuerySelect, RelationTrait, Statement, sea_query::Expr, sea_query::Func};
use sea_orm_migration::MigratorTrait;

use simply_ip_vault::entities::{ip_group, ip_record, ip_record_group_membership};
use simply_ip_vault::migration;

const ROWS: i64 = 100_000;
const GROUPS: i64 = 10;
const BUDGET: Duration = Duration::from_millis(10);
const RUNS: usize = 15;

async fn seed(db: &DatabaseConnection) {
    let stmts = [
        // Groups: ids are deterministic so the seeding SQL can reference them by number.
        format!(
            "INSERT INTO ip_groups (id, name, group_type, description, owner_key_id, created_at)
             WITH RECURSIVE g(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM g WHERE n < {GROUPS})
             SELECT unhex(printf('%032x', n)), 'bench-group-' || n, 'banlist', NULL, NULL, datetime('now') FROM g"
        ),
        format!(
            "INSERT INTO ip_records (id, target_address, created_at)
             WITH RECURSIVE s(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM s WHERE n < {ROWS})
             SELECT unhex(printf('%032x', n)), printf('203.%d.%d.%d', (n>>16)&255, (n>>8)&255, n&255), datetime('now')
             FROM s"
        ),
        // Memberships: each address lands in one group, and every 20th membership is soft-deleted so
        // the partial index is exercised against a realistic mix of live and deleted rows.
        format!(
            "INSERT INTO ip_record_group_memberships
                (id, ip_record_id, group_id, is_locked, created_at, last_seen_at, is_deleted, deleted_at, deleted_by)
             WITH RECURSIVE s(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM s WHERE n < {ROWS})
             SELECT unhex(printf('%032x', n + 1000000)),
                    unhex(printf('%032x', n)),
                    unhex(printf('%032x', (n % {GROUPS}) + 1)),
                    0,
                    datetime('now', '-' || (n % 86400) || ' seconds'),
                    datetime('now', '-' || (n % 86400) || ' seconds'),
                    CASE WHEN n % 20 = 0 THEN 1 ELSE 0 END,
                    CASE WHEN n % 20 = 0 THEN datetime('now') ELSE NULL END,
                    CASE WHEN n % 20 = 0 THEN 'bench' ELSE NULL END
             FROM s"
        ),
    ];
    for sql in stmts {
        db.execute_unprepared(&sql).await.expect("seed statement");
    }
    db.execute_unprepared("ANALYZE").await.expect("analyze");
}

async fn fresh_db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migration::Migrator::up(&db, None).await.unwrap();
    seed(&db).await;
    db
}

fn group_name(g: i64) -> String {
    format!("bench-group-{g}")
}

async fn group_id(db: &DatabaseConnection, name: &str) -> uuid::Uuid {
    ip_group::Entity::find()
        .filter(ip_group::Column::Name.eq(name))
        .one(db)
        .await
        .unwrap()
        .expect("group seeded")
        .id
}

/// The exact page query the list endpoint issues for one group.
async fn page_query(db: &DatabaseConnection, group: uuid::Uuid) -> usize {
    ip_record_group_membership::Entity::find()
        .join(JoinType::InnerJoin, ip_record_group_membership::Relation::IpRecord.def())
        .select_also(ip_record::Entity)
        .filter(ip_record_group_membership::Column::GroupId.eq(group))
        .filter(ip_record_group_membership::Column::IsDeleted.eq(false))
        .order_by_desc(ip_record_group_membership::Column::LastSeenAt)
        .limit(50)
        .all(db)
        .await
        .unwrap()
        .len()
}

/// The exact count the endpoint issues for `include_total=true` over one group.
async fn count_query(db: &DatabaseConnection, group: uuid::Uuid) -> i64 {
    let n: Option<i64> = ip_record_group_membership::Entity::find()
        .filter(ip_record_group_membership::Column::GroupId.eq(group))
        .filter(ip_record_group_membership::Column::IsDeleted.eq(false))
        .select_only()
        .expr_as(Func::count(Expr::col((ip_record_group_membership::Entity, ip_record_group_membership::Column::Id))), "row_count")
        .into_tuple::<i64>()
        .one(db)
        .await
        .unwrap();
    n.unwrap_or(0)
}

/// Median of `RUNS` timed executions, after one warm-up. The median is what the budget is judged on,
/// so a single scheduler hiccup cannot fail the build and cannot hide a real regression either.
async fn median<F, Fut>(mut f: F) -> Duration
where
    F: FnMut() -> Fut,
    Fut: std::future::Future,
{
    let _ = f().await;
    let mut samples = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let start = Instant::now();
        let _ = f().await;
        samples.push(start.elapsed());
    }
    samples.sort();
    samples[RUNS / 2]
}

async fn explain(db: &DatabaseConnection, sql: &str) -> String {
    db.query_all_raw(Statement::from_string(DbBackend::Sqlite, format!("EXPLAIN QUERY PLAN {sql}")))
        .await
        .unwrap()
        .into_iter()
        .map(|row| row.try_get::<String>("", "detail").unwrap_or_default())
        .collect::<Vec<_>>()
        .join(" | ")
}

#[tokio::test]
async fn group_scoped_list_and_count_meet_the_10ms_budget_at_100k_rows() {
    let db = fresh_db().await;
    let g = group_id(&db, &group_name(1)).await;

    let page = median(|| page_query(&db, g)).await;
    let count = median(|| count_query(&db, g)).await;
    println!("100k rows: group-scoped page median = {page:?}, count median = {count:?}");

    assert!(page < BUDGET, "group-scoped page query took {page:?}, budget is {BUDGET:?}");
    assert!(count < BUDGET, "group-scoped count took {count:?}, budget is {BUDGET:?}");
}

#[tokio::test]
async fn group_scoped_list_plan_has_no_temp_b_tree() {
    let db = fresh_db().await;
    let plan = explain(
        &db,
        "SELECT m.id FROM ip_record_group_memberships m
         WHERE m.group_id = x'00000000000000000000000000000001' AND m.is_deleted = FALSE
         ORDER BY m.last_seen_at DESC LIMIT 50",
    )
    .await;
    println!("list plan: {plan}");
    assert!(!plan.contains("TEMP B-TREE"), "list query sorts through a temp b-tree: {plan}");
    assert!(plan.contains("idx_memberships_active_last_seen"), "list query must use the partial index: {plan}");
}
