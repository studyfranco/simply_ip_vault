//! Debug-profile regression test for the membership refactor and its indexes.

use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseConnection, EntityTrait, sea_query::Query,
};
use simply_ip_vault::migration::{DeriveIden, MigratorTrait, SchemaManager};
use simply_ip_vault::{
    entities::{ip_record, ip_record_cause, ip_record_group_membership},
    migration,
};
use time::PrimitiveDateTime;
use uuid::Uuid;

const BUDGET: Duration = Duration::from_secs(2);
const RECORDS: i64 = 2_000;
const BATCH: i64 = 500;
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
    Uuid::from_u128(u128::try_from(n).unwrap())
}

fn record_id(n: i64) -> Uuid {
    Uuid::from_u128(1_000_000_000 + u128::try_from(n).unwrap())
}

fn address(n: i64) -> String {
    format!("10.0.{}.{}", n >> 8, n & 255)
}

fn observation_time(created_at: PrimitiveDateTime, record: i64, group: i64) -> PrimitiveDateTime {
    created_at - time::Duration::seconds(record * GROUPS + group)
}

#[tokio::test]
async fn membership_refactor_preserves_legacy_data_within_budget() {
    let started = Instant::now();
    let dir = tempfile::tempdir().unwrap();
    let url = format!("sqlite://{}/backfill.db?mode=rwc", dir.path().display());
    let mut options = ConnectOptions::new(url);
    options.max_connections(1);
    let db = Database::connect(options).await.unwrap();
    simply_ip_vault::db::apply_sqlite_pragmas(&db)
        .await
        .unwrap();

    let refactor = migration::Migrator::migrations()
        .iter()
        .position(|m| m.name() == "m20261006_120000_refactor_membership_state")
        .expect("the refactor is registered");
    migration::Migrator::up(&db, Some(u32::try_from(refactor).unwrap()))
        .await
        .unwrap();

    let created_at = time::macros::datetime!(2026-10-05 12:00:00);
    seed_legacy_backfill_rows(&db, created_at).await;

    let migration_started = Instant::now();
    migration::Migrator::up(&db, Some(1)).await.unwrap();
    let migration_elapsed = migration_started.elapsed();

    assert_backfill(&db, created_at).await;
    let schema = SchemaManager::new(&db);
    for index in ["idx_memberships_ip_group", "idx_group_memberships_lookup"] {
        assert!(
            schema
                .has_index("ip_record_group_memberships", index)
                .await
                .unwrap(),
            "missing backfilled membership index {index}"
        );
    }
    db.close().await.unwrap();
    drop(dir);
    let elapsed = started.elapsed();
    println!(
        "membership refactor and indexes took {migration_elapsed:?}, full test took {elapsed:?}"
    );
    assert!(
        elapsed < BUDGET,
        "full backfill test took {elapsed:?}, budget is {BUDGET:?}"
    );
}

async fn assert_backfill(db: &DatabaseConnection, created_at: PrimitiveDateTime) {
    let records: HashMap<_, _> = ip_record::Entity::find()
        .all(db)
        .await
        .unwrap()
        .into_iter()
        .map(|row| (row.id, row))
        .collect();
    assert_eq!(records.len(), usize::try_from(RECORDS).unwrap());

    let membership_rows = ip_record_group_membership::Entity::find()
        .all(db)
        .await
        .unwrap();
    assert_eq!(
        membership_rows.len(),
        usize::try_from(RECORDS + RECORDS / 5).unwrap()
    );
    let mut memberships: HashMap<_, _> = membership_rows
        .into_iter()
        .map(|row| ((row.ip_record_id, row.group_id), row))
        .collect();

    let cause_rows = ip_record_cause::Entity::find().all(db).await.unwrap();
    let cause_count = cause_rows.len();
    let mut causes: HashMap<_, _> = cause_rows
        .into_iter()
        .map(|row| (row.membership_id, row))
        .collect();
    assert_eq!(
        causes.len(),
        cause_count,
        "duplicate cause rows for one membership"
    );

    for i in 1..=RECORDS {
        let record = &records[&record_id(i)];
        assert_eq!(record.target_address, address(i));
        assert_eq!(record.created_at, created_at);

        for group in legacy_groups(i) {
            let membership = memberships
                .remove(&(record.id, group_id(group)))
                .unwrap_or_else(|| panic!("missing membership for record {i}, group {group}"));
            let deleted = i % 20 == 0;
            assert_eq!(membership.is_locked, i % 7 == 0);
            assert_eq!(membership.is_deleted, deleted);
            assert_eq!(membership.deleted_at, deleted.then_some(created_at));
            assert_eq!(membership.deleted_by.as_deref(), deleted.then_some("perf"));
            assert_eq!(membership.created_at, created_at);
            assert_eq!(
                membership.last_seen_at,
                observation_time(created_at, i, group)
            );

            let cause = causes.remove(&membership.id);
            if i % 3 == 0 {
                let cause = cause.expect("missing backfilled cause");
                assert_eq!(cause.cause, format!("seeded cause {i}"));
                assert_eq!(cause.created_at, created_at);
            } else {
                assert!(cause.is_none());
            }
        }
    }
    assert!(memberships.is_empty());
    assert!(causes.is_empty());
}

fn legacy_groups(record: i64) -> impl Iterator<Item = i64> {
    let primary = record % GROUPS + 1;
    let secondary = (record % 5 == 0).then_some((record + 1) % GROUPS + 1);
    std::iter::once(primary).chain(secondary)
}

async fn seed_legacy_backfill_rows(db: &DatabaseConnection, created_at: PrimitiveDateTime) {
    let mut groups = Query::insert();
    groups.into_table(Groups::Table).columns([
        Groups::Id,
        Groups::Name,
        Groups::GroupType,
        Groups::CreatedAt,
    ]);
    for g in 1..=GROUPS {
        groups.values_panic([
            group_id(g).into(),
            format!("perf-group-{g}").into(),
            "banlist".into(),
            created_at.into(),
        ]);
    }
    db.execute(&groups).await.unwrap();

    // Records, with a cause on every third one and a soft-deleted one in twenty.
    let mut n = 1;
    while n <= RECORDS {
        let end = (n + BATCH - 1).min(RECORDS);
        let mut stmt = Query::insert();
        stmt.into_table(Records::Table).columns([
            Records::Id,
            Records::TargetAddress,
            Records::Cause,
            Records::IsLocked,
            Records::CreatedAt,
            Records::UpdatedAt,
            Records::LastSeenAt,
            Records::IsDeleted,
            Records::DeletedAt,
            Records::DeletedBy,
        ]);
        for i in n..=end {
            let seen = created_at - time::Duration::seconds(i);
            let deleted = i % 20 == 0;
            stmt.values_panic([
                record_id(i).into(),
                address(i).into(),
                (i % 3 == 0).then(|| format!("seeded cause {i}")).into(),
                (i % 7 == 0).into(),
                created_at.into(),
                seen.into(),
                seen.into(),
                deleted.into(),
                deleted.then_some(created_at).into(),
                deleted.then(|| "perf".to_owned()).into(),
            ]);
        }
        db.execute(&stmt).await.unwrap();
        n = end + 1;
    }

    // Memberships: one per record in its primary group, plus a second group for every fifth record.
    let rows: Vec<_> = (1..=RECORDS)
        .flat_map(|record| legacy_groups(record).map(move |group| (record, group)))
        .collect();
    for chunk in rows.chunks(usize::try_from(BATCH).unwrap()) {
        let mut stmt = Query::insert();
        stmt.into_table(Memberships::Table).columns([
            Memberships::IpRecordId,
            Memberships::GroupId,
            Memberships::CreatedAt,
            Memberships::UpdatedAt,
        ]);
        for &(record, group) in chunk {
            stmt.values_panic([
                record_id(record).into(),
                group_id(group).into(),
                created_at.into(),
                observation_time(created_at, record, group).into(),
            ]);
        }
        db.execute(&stmt).await.unwrap();
    }
}
