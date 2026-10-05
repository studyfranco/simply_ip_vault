//! Startup cost of the membership refactor on a database that already holds real volume.
//!
//! Ignored by default: seeding a million rows takes longer than the rest of the suite. Run with
//!   `cargo test --release --test migration_backfill_perf -- --ignored --nocapture`
//! and set `BACKFILL_RECORDS` to change the size (default 1,000,000).
//!
//! The seed is built with the same query builders the application uses; nothing here is raw SQL.
//! The assertion is the one the migration exists to meet: the refactor and its indexes complete in
//! under five seconds.

use std::time::{Duration, Instant};

use sea_orm::{ConnectionTrait, Database, sea_query::{Alias, Asterisk, Expr, Func, Query}};
use sea_orm_migration::{MigratorTrait, prelude::DeriveIden};
use simply_ip_vault::migration;
use uuid::Uuid;

const BUDGET: Duration = Duration::from_secs(5);
const BATCH: i64 = 1000;
const GROUPS: i64 = 4;

#[derive(DeriveIden)]
enum Groups {
    #[sea_orm(iden = "ip_groups")]
    Table,
    Id,
    Name,
    GroupType,
    CreatedAt,
}

#[derive(DeriveIden)]
enum Records {
    #[sea_orm(iden = "ip_records")]
    Table,
    Id,
    TargetAddress,
    Cause,
    IsLocked,
    CreatedAt,
    UpdatedAt,
    LastSeenAt,
    IsDeleted,
    DeletedAt,
    DeletedBy,
}

#[derive(DeriveIden)]
enum Memberships {
    #[sea_orm(iden = "ip_record_group_memberships")]
    Table,
    IpRecordId,
    GroupId,
    CreatedAt,
    UpdatedAt,
}

fn group_id(n: i64) -> Uuid {
    Uuid::from_u128(n as u128)
}

fn record_id(n: i64) -> Uuid {
    Uuid::from_u128(1_000_000_000 + n as u128)
}

#[tokio::test]
#[ignore = "seeds a large database; run explicitly with --ignored"]
async fn membership_refactor_backfills_a_large_database_within_budget() {
    let records: i64 = std::env::var("BACKFILL_RECORDS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(1_000_000);

    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}/backfill.db?mode=rwc", dir.path().display());
    let db = Database::connect(&url).await.unwrap();
    // The same pragmas production runs under (cache, mmap, WAL, foreign keys), applied to this
    // connection so the migration is timed under them.
    simply_ip_vault::db::apply_sqlite_pragmas(&db).await.unwrap();

    // The schema as it stood before the refactor.
    let all = migration::Migrator::migrations();
    let refactor = all
        .iter()
        .position(|m| m.name().contains("refactor_membership_state"))
        .expect("the refactor is registered");
    migration::Migrator::up(&db, Some(refactor as u32)).await.unwrap();

    let now = chrono::Utc::now().naive_utc();
    let mut groups = Query::insert();
    groups.into_table(Groups::Table).columns([Groups::Id, Groups::Name, Groups::GroupType, Groups::CreatedAt]);
    for g in 1..=GROUPS {
        groups.values_panic([group_id(g).into(), format!("perf-group-{g}").into(), "banlist".into(), now.into()]);
    }
    db.execute(&groups).await.unwrap();

    // Records, with a cause on every third one and a soft-deleted one in twenty.
    let mut n = 1;
    while n <= records {
        let end = (n + BATCH - 1).min(records);
        let mut stmt = Query::insert();
        stmt.into_table(Records::Table).columns([
            Records::Id, Records::TargetAddress, Records::Cause, Records::IsLocked, Records::CreatedAt,
            Records::UpdatedAt, Records::LastSeenAt, Records::IsDeleted, Records::DeletedAt, Records::DeletedBy,
        ]);
        for i in n..=end {
            let seen = now - chrono::Duration::seconds(i % 86_400);
            let deleted = i % 20 == 0;
            stmt.values_panic([
                record_id(i).into(),
                format!("10.{}.{}.{}", (i >> 16) & 255, (i >> 8) & 255, i & 255).into(),
                (i % 3 == 0).then(|| format!("seeded cause {i}")).into(),
                false.into(),
                now.into(),
                seen.into(),
                seen.into(),
                deleted.into(),
                deleted.then_some(now).into(),
                deleted.then(|| "perf".to_owned()).into(),
            ]);
        }
        db.execute(&stmt).await.unwrap();
        n = end + 1;
    }

    // Memberships: one per record in its primary group, plus a second group for every fifth record.
    let mut rows: Vec<(Uuid, Uuid, i64)> = Vec::new();
    for i in 1..=records {
        rows.push((record_id(i), group_id((i % GROUPS) + 1), i));
        if i % 5 == 0 {
            rows.push((record_id(i), group_id(((i + 1) % GROUPS) + 1), i));
        }
    }
    for chunk in rows.chunks(BATCH as usize) {
        let mut stmt = Query::insert();
        stmt.into_table(Memberships::Table).columns([
            Memberships::IpRecordId, Memberships::GroupId, Memberships::CreatedAt, Memberships::UpdatedAt,
        ]);
        for (record, group, i) in chunk {
            let seen = now - chrono::Duration::seconds(i % 86_400);
            stmt.values_panic([(*record).into(), (*group).into(), now.into(), seen.into()]);
        }
        db.execute(&stmt).await.unwrap();
    }

    let count_stmt = Query::select()
        .expr_as(Func::count(Expr::col(Asterisk)), Alias::new("n"))
        .from(Memberships::Table)
        .to_owned();
    let memberships: i64 = db.query_one(&count_stmt).await.unwrap().unwrap().try_get("", "n").unwrap();
    println!("seeded {records} records and {memberships} memberships");

    let started = Instant::now();
    migration::Migrator::up(&db, None).await.unwrap();
    let elapsed = started.elapsed();
    println!("membership refactor and index strategy: {elapsed:?} for {records} records");

    assert!(elapsed < BUDGET, "backfill took {elapsed:?}, budget is {BUDGET:?}");
}
