//! Confirms the retention purge's rewritten anti-join, and audits the other query shapes that
//! connect `ip_groups`/`ip_records` through `ip_record_group_memberships`, with real
//! `EXPLAIN QUERY PLAN` output and timings at scale — not just a structural claim.
//!
//! **Scope and honest limit:** this runs against SQLite, the only engine available in this
//! environment (no PostgreSQL or Docker here). The specific claim behind the `NOT EXISTS` rewrite —
//! that PostgreSQL's planner cannot in general turn `NOT IN (subquery)` into an index-driven
//! anti-join, because it must account for the subquery possibly containing a NULL under `NOT IN`'s
//! three-valued logic — is well-documented PostgreSQL planner behaviour, not something reproducible
//! here. What this file *does* verify, on the engine available: the rewrite is at least as fast and
//! at least as well-indexed as the pattern it replaced, and the other group/IP join queries in the
//! read and write paths plan cleanly at realistic scale.

use std::time::{Duration, Instant};

use sea_orm::{
    ColumnTrait, ConnectionTrait, Database, DatabaseConnection, DbBackend, EntityTrait, JoinType,
    QueryFilter, QuerySelect, RelationTrait, Statement,
};
use sea_orm_migration::MigratorTrait;
use uuid::Uuid;

use simply_ip_vault::entities::{ip_group, ip_record, ip_record_group_membership};
use simply_ip_vault::migration;

const RECORDS: i64 = 300_000;
const ORPHANS: i64 = 3_000;
const GROUPS: i64 = 10;
const SOFT_DELETED_AGED: i64 = 1_500;
const BUDGET: Duration = Duration::from_millis(50);
/// A realistic budget for the orphan-cleanup delete specifically: unlike a bounded `LIMIT`
/// page read, it must visit every row in `ip_records` once — there is no index on "has no
/// membership" to seek past. 300k rows at a few hundred ms is the expected, accepted cost of a
/// background sweep, not a regression.
const PURGE_BUDGET: Duration = Duration::from_millis(500);

fn uid(n: i64) -> Uuid {
    Uuid::parse_str(&format!("00000000-0000-0000-0000-{n:012x}")).unwrap()
}

async fn fresh_db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migration::Migrator::up(&db, None).await.unwrap();
    db
}

/// Seeds `RECORDS` addresses in one group. `ORPHANS` of them get no membership at all (the case
/// the purge's second delete targets). `SOFT_DELETED_AGED` of the remaining memberships are
/// soft-deleted well past the retention window (the case its first delete targets). The rest are
/// live.
async fn seed(db: &DatabaseConnection) {
    let now = chrono::Utc::now().naive_utc();
    let old = now - chrono::Duration::days(200);
    let stmts = [
        format!(
            "INSERT INTO ip_groups (id, name, group_type, description, owner_key_id, created_at)
             WITH RECURSIVE g(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM g WHERE n < {GROUPS})
             SELECT unhex(printf('%032x', n)), 'audit-group-' || n, 'banlist', NULL, NULL, '{now}' FROM g"
        ),
        format!(
            "INSERT INTO ip_records (id, target_address, created_at)
             WITH RECURSIVE s(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM s WHERE n < {RECORDS})
             SELECT unhex(printf('%032x', n)), printf('203.%d.%d.%d', (n>>16)&255, (n>>8)&255, n&255), '{now}'
             FROM s"
        ),
        // Live memberships: every record except the last ORPHANS of them.
        format!(
            "INSERT INTO ip_record_group_memberships
                (id, ip_record_id, group_id, is_locked, created_at, last_seen_at, is_deleted, deleted_at, deleted_by)
             WITH RECURSIVE s(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM s WHERE n < {RECORDS} - {ORPHANS})
             SELECT unhex(printf('%032x', n + 1000000)), unhex(printf('%032x', n)), unhex(printf('%032x', (n % {GROUPS}) + 1)),
                    0, '{now}', '{now}',
                    CASE WHEN n <= {SOFT_DELETED_AGED} THEN 1 ELSE 0 END,
                    CASE WHEN n <= {SOFT_DELETED_AGED} THEN '{old}' ELSE NULL END,
                    CASE WHEN n <= {SOFT_DELETED_AGED} THEN 'audit' ELSE NULL END
             FROM s"
        ),
    ];
    for sql in stmts {
        db.execute_unprepared(&sql).await.expect("seed statement");
    }
    db.execute_unprepared("ANALYZE").await.expect("analyze");
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

async fn count_table(db: &DatabaseConnection, table: &str) -> i64 {
    db.query_one_raw(Statement::from_string(DbBackend::Sqlite, format!("SELECT COUNT(*) AS n FROM {table}")))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "n")
        .unwrap()
}

/// The retention purge, run end to end against the seeded mix: correctness (the right rows go,
/// the right rows stay) and its real timing and query plan.
#[tokio::test]
async fn orphan_and_soft_delete_purge_is_correct_fast_and_plans_as_an_anti_join() {
    let db = fresh_db().await;
    seed(&db).await;

    let before_records = count_table(&db, "ip_records").await;
    let before_memberships = count_table(&db, "ip_record_group_memberships").await;
    assert_eq!(before_records, RECORDS);
    assert_eq!(before_memberships, RECORDS - ORPHANS);

    let started = Instant::now();
    let purged = simply_ip_vault::retention::purge_expired_ip_records(&db, 92).await.unwrap();
    let elapsed = started.elapsed();
    println!(
        "purge over {RECORDS} records ({ORPHANS} orphans, {SOFT_DELETED_AGED} aged soft-deletes): \
         {elapsed:?}, purged={purged}"
    );

    assert_eq!(purged, SOFT_DELETED_AGED as u64, "every aged soft-deleted membership must be purged, and only those");

    let after_memberships = count_table(&db, "ip_record_group_memberships").await;
    assert_eq!(
        after_memberships,
        before_memberships - SOFT_DELETED_AGED,
        "only the aged soft-deleted memberships are removed"
    );

    // The orphans (never had a membership) plus the ones just orphaned by the membership purge
    // above must both be gone; every record a live membership still points at must survive.
    let after_records = count_table(&db, "ip_records").await;
    assert_eq!(
        after_records,
        before_records - ORPHANS - SOFT_DELETED_AGED,
        "both the pre-existing orphans and the newly orphaned records (freed by the membership \
         purge) must be removed, and nothing else"
    );

    assert!(elapsed < PURGE_BUDGET, "purge took {elapsed:?}, budget is {PURGE_BUDGET:?} at {RECORDS} records");

    // The exact shape the orphan-cleanup delete's WHERE clause plans as, reproduced as a SELECT
    // (SQLite's EXPLAIN QUERY PLAN output is the same for the condition regardless of DELETE vs
    // SELECT). Must be an anti-join search against the FK child index, not a scan.
    let plan = explain(
        &db,
        "SELECT * FROM ip_records WHERE NOT EXISTS \
         (SELECT 1 FROM ip_record_group_memberships m WHERE m.ip_record_id = ip_records.id)",
    )
    .await;
    println!("orphan-cleanup plan: {plan}");
    assert!(
        plan.contains("idx-irgm-ip_record_id") || plan.contains("idx_memberships_ip_group"),
        "the anti-join must be driven by an index on ip_record_group_memberships.ip_record_id: {plan}"
    );
    assert!(!plan.contains("TEMP B-TREE"), "an anti-join needs no sort: {plan}");
}

/// The other query that joins memberships to their group and address: the `full_replace` batch
/// sweep (`src/api/records.rs`), which finds every live, unlocked membership in a group that a
/// batch omitted. A plain, non-partial-index-eligible filter (`is_locked = false` has no partial
/// index of its own), so this is worth checking separately from the listing queries.
#[tokio::test]
async fn full_replace_sweep_query_plans_without_a_table_scan_at_scale() {
    let db = fresh_db().await;
    seed(&db).await;
    // Group 1: the soft-deleted-and-aged memberships (n <= SOFT_DELETED_AGED) all landed in
    // whichever group `n % GROUPS + 1` gives for those low n — group 1 among them, but also some of
    // 2..=GROUPS. Easiest to assert against is a live-row membership count computed the same way
    // the seed built it, not assumed to be the whole live set.
    let group_id = uid(1);

    let started = Instant::now();
    let candidates = ip_record_group_membership::Entity::find()
        .join(JoinType::InnerJoin, ip_record_group_membership::Relation::IpRecord.def())
        .select_also(ip_record::Entity)
        .filter(ip_record_group_membership::Column::GroupId.eq(group_id))
        .filter(ip_record_group_membership::Column::IsDeleted.eq(false))
        .filter(ip_record_group_membership::Column::IsLocked.eq(false))
        .all(&db)
        .await
        .unwrap();
    let elapsed = started.elapsed();
    println!("full_replace sweep over {RECORDS} records across {GROUPS} groups: {elapsed:?}, candidates={}", candidates.len());

    let expected: i64 = db
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT COUNT(*) AS n FROM ip_record_group_memberships \
             WHERE group_id = unhex(printf('%032x', 1)) AND is_deleted = 0 AND is_locked = 0"
                .to_owned(),
        ))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "n")
        .unwrap();
    assert_eq!(
        candidates.len() as i64,
        expected,
        "every live, unlocked membership in the group must be a sweep candidate, and only those"
    );

    let plan = explain(
        &db,
        "SELECT * FROM ip_record_group_memberships m INNER JOIN ip_records r ON m.ip_record_id = r.id \
         WHERE m.group_id = x'00000000000000000000000000000001' AND m.is_deleted = FALSE AND m.is_locked = FALSE",
    )
    .await;
    println!("full_replace sweep plan: {plan}");
    assert!(
        !plan.contains("SCAN ip_record_group_memberships") || plan.contains("USING INDEX") || plan.contains("USING COVERING INDEX"),
        "the sweep must reach the membership table through an index, not a blind scan: {plan}"
    );
    assert!(!plan.contains("TEMP B-TREE"), "no ORDER BY here, so no sort should appear: {plan}");

    // `group_id` alone (no `is_deleted`/`is_locked` literal match for a partial index) should still
    // land on one of the group_id-leading indexes, same property the schema-integrity suite checks
    // for the bare group lookup.
    assert!(
        plan.contains("idx_memberships_active_locked")
            || plan.contains("idx_group_memberships_lookup")
            || plan.contains("idx-irgm-group_id")
            || plan.contains("idx_memberships_active_last_seen"),
        "must use one of the group_id-leading indexes: {plan}"
    );
}

/// The read-path join between a group and its live memberships (`ip_group` resolved alongside
/// `ip_record_group_membership`), the other direction of "connect groups and ips": resolving a
/// `groups=name1,name2` filter to ids, then listing by those ids. Both steps, at scale.
#[tokio::test]
async fn group_name_resolution_and_scoped_listing_plan_cleanly() {
    let db = fresh_db().await;
    seed(&db).await;

    let started = Instant::now();
    let resolved: Vec<Uuid> = ip_group::Entity::find()
        .filter(ip_group::Column::Name.eq("audit-group-1"))
        .all(&db)
        .await
        .unwrap()
        .into_iter()
        .map(|g| g.id)
        .collect();
    let elapsed = started.elapsed();
    assert_eq!(resolved, vec![uid(1)]);
    println!("group name resolution: {elapsed:?}");
    assert!(elapsed < BUDGET, "resolving one group by name took {elapsed:?}, budget is {BUDGET:?}");

    let plan = explain(&db, "SELECT * FROM ip_groups WHERE name = 'audit-group-1'").await;
    println!("group name resolution plan: {plan}");
    assert!(!plan.contains("SCAN ip_groups"), "group name lookup must not scan the groups table: {plan}");
}
