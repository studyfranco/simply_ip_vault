//! Makes the IP address canonical and moves its operational state onto the membership.
//!
//! # The model
//!
//! Before: `ip_records` carried one copy of the address *and* its state (`cause`, `is_locked`,
//! `last_seen_at`, soft-delete columns), shared by every group the address belongs to, and
//! `ip_record_group_memberships` only linked the two. Any state change for one group therefore
//! changed the shared row seen by every other group.
//!
//! After: `ip_records` is `(id, target_address, created_at)` — the address, nothing else. Each
//! `ip_record_group_memberships` row is a stateful membership: its own `id`, `is_locked`,
//! `created_at`, `last_seen_at` (the single timestamp for the latest observation in that group),
//! and soft-delete columns. Causes move to `ip_record_causes`, an append-only history with one row
//! per reported cause and none for an absent one.
//!
//! # Data
//!
//! Every existing membership becomes one new membership, taking its state from the record it
//! points at (`is_locked`, soft delete). Its `last_seen_at` is the old per-group `updated_at`, which
//! is the most specific observation time the old schema recorded for that group. A non-null cause
//! becomes one `ip_record_causes` row, dated to the membership's creation. Nothing is dropped: the
//! row counts before and after are the memberships' and the records' own.
//!
//! # Ordering
//!
//! Foreign keys are enforced, so dropping a parent that still has children cascades. The rebuild
//! therefore creates the new tables under temporary names, copies into them, drops the old
//! children and then the old parent, and only then renames. No step drops a table that a live
//! foreign key still references.
//!
//! # Reversal
//!
//! Not reversible: several records' memberships collapse into one canonical record, and a
//! membership's state cannot be split back onto a shared row without choosing which group's copy
//! wins. `down` refuses rather than guessing.

use sea_orm::{ConnectionTrait, sea_query::{self, Index as SqIndex, Query}};
use sea_orm_migration::prelude::*;
use uuid::Uuid;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum IpRecords {
    Table,
    Id,
    TargetAddress,
    Cause,
    IsLocked,
    CreatedAt,
    LastSeenAt,
    IsDeleted,
    DeletedAt,
    DeletedBy,
}

#[derive(DeriveIden)]
enum IpRecordsNew {
    #[sea_orm(iden = "ip_records_new")]
    Table,
}

#[derive(DeriveIden)]
enum Memberships {
    #[sea_orm(iden = "ip_record_group_memberships")]
    Table,
    Id,
    IpRecordId,
    GroupId,
    CreatedAt,
    UpdatedAt,
    LastSeenAt,
    IsLocked,
    IsDeleted,
    DeletedAt,
    DeletedBy,
}

#[derive(DeriveIden)]
enum MembershipsNew {
    #[sea_orm(iden = "ip_record_group_memberships_new")]
    Table,
}

#[derive(DeriveIden)]
enum Causes {
    #[sea_orm(iden = "ip_record_causes")]
    Table,
    Id,
    MembershipId,
    Cause,
    CreatedAt,
}

#[derive(DeriveIden)]
enum IpGroups {
    Table,
    Id,
}

/// One address row read from the old schema.
struct OldRecord {
    id: Uuid,
    target_address: String,
    cause: Option<String>,
    is_locked: bool,
    created_at: chrono::NaiveDateTime,
    is_deleted: bool,
    deleted_at: Option<chrono::NaiveDateTime>,
    deleted_by: Option<String>,
}

/// One old membership, with the per-group `updated_at` the old schema recorded for it.
struct OldMembership {
    ip_record_id: Uuid,
    group_id: Uuid,
    created_at: chrono::NaiveDateTime,
    updated_at: chrono::NaiveDateTime,
}

async fn read_records(db: &SchemaManagerConnection<'_>) -> Result<Vec<OldRecord>, DbErr> {
    let stmt = Query::select()
        .columns([
            IpRecords::Id,
            IpRecords::TargetAddress,
            IpRecords::Cause,
            IpRecords::IsLocked,
            IpRecords::CreatedAt,
            IpRecords::LastSeenAt,
            IpRecords::IsDeleted,
            IpRecords::DeletedAt,
            IpRecords::DeletedBy,
        ])
        .from(IpRecords::Table)
        .to_owned();
    db.query_all(&stmt)
        .await?
        .into_iter()
        .map(|row| {
            Ok(OldRecord {
                id: row.try_get("", "id")?,
                target_address: row.try_get("", "target_address")?,
                cause: row.try_get("", "cause")?,
                is_locked: row.try_get("", "is_locked")?,
                created_at: row.try_get("", "created_at")?,
                is_deleted: row.try_get("", "is_deleted")?,
                deleted_at: row.try_get("", "deleted_at")?,
                deleted_by: row.try_get("", "deleted_by")?,
            })
        })
        .collect()
}

async fn read_memberships(db: &SchemaManagerConnection<'_>) -> Result<Vec<OldMembership>, DbErr> {
    let stmt = Query::select()
        .columns([
            Memberships::IpRecordId,
            Memberships::GroupId,
            Memberships::CreatedAt,
            Memberships::UpdatedAt,
        ])
        .from(Memberships::Table)
        .to_owned();
    db.query_all(&stmt)
        .await?
        .into_iter()
        .map(|row| {
            Ok(OldMembership {
                ip_record_id: row.try_get("", "ip_record_id")?,
                group_id: row.try_get("", "group_id")?,
                created_at: row.try_get("", "created_at")?,
                updated_at: row.try_get("", "updated_at")?,
            })
        })
        .collect()
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        let records = read_records(conn).await?;
        let memberships = read_memberships(conn).await?;
        let by_id: std::collections::HashMap<Uuid, &OldRecord> =
            records.iter().map(|r| (r.id, r)).collect();

        // 1. The canonical address table, under a temporary name.
        manager
            .create_table(
                Table::create()
                    .table(IpRecordsNew::Table)
                    .col(ColumnDef::new(IpRecords::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(IpRecords::TargetAddress).string().not_null().unique_key())
                    .col(ColumnDef::new(IpRecords::CreatedAt).date_time().not_null())
                    .to_owned(),
            )
            .await?;
        for r in &records {
            let stmt = Query::insert()
                .into_table(IpRecordsNew::Table)
                .columns([IpRecords::Id, IpRecords::TargetAddress, IpRecords::CreatedAt])
                .values_panic([r.id.into(), r.target_address.clone().into(), r.created_at.into()])
                .to_owned();
            conn.execute(&stmt).await?;
        }

        // 2. The stateful memberships, under a temporary name, referencing the new address table.
        manager
            .create_table(
                Table::create()
                    .table(MembershipsNew::Table)
                    .col(ColumnDef::new(Memberships::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Memberships::IpRecordId).uuid().not_null())
                    .col(ColumnDef::new(Memberships::GroupId).uuid().not_null())
                    .col(ColumnDef::new(Memberships::IsLocked).boolean().not_null().default(false))
                    .col(ColumnDef::new(Memberships::CreatedAt).date_time().not_null())
                    .col(ColumnDef::new(Memberships::LastSeenAt).date_time().not_null())
                    .col(ColumnDef::new(Memberships::IsDeleted).boolean().not_null().default(false))
                    .col(ColumnDef::new(Memberships::DeletedAt).date_time())
                    .col(ColumnDef::new(Memberships::DeletedBy).string())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-irgm-ip_record_id")
                            .from(MembershipsNew::Table, Memberships::IpRecordId)
                            .to(IpRecordsNew::Table, IpRecords::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-irgm-group_id")
                            .from(MembershipsNew::Table, Memberships::GroupId)
                            .to(IpGroups::Table, IpGroups::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;

        // The old `(ip_record_id, group_id)` primary key becomes a unique index under its brief
        // name. A membership is still one per (address, group); the index is that constraint and
        // the upsert target, so a second identical index is not created alongside it.
        let mut cause_rows: Vec<(Uuid, String, chrono::NaiveDateTime)> = Vec::new();
        for m in &memberships {
            let record = by_id.get(&m.ip_record_id).ok_or_else(|| {
                DbErr::Migration(format!(
                    "membership references missing ip_record {} — refusing to migrate a dangling row",
                    m.ip_record_id
                ))
            })?;
            let membership_id = Uuid::new_v4();
            let stmt = Query::insert()
                .into_table(MembershipsNew::Table)
                .columns([
                    Memberships::Id,
                    Memberships::IpRecordId,
                    Memberships::GroupId,
                    Memberships::IsLocked,
                    Memberships::CreatedAt,
                    Memberships::LastSeenAt,
                    Memberships::IsDeleted,
                    Memberships::DeletedAt,
                    Memberships::DeletedBy,
                ])
                .values_panic([
                    membership_id.into(),
                    m.ip_record_id.into(),
                    m.group_id.into(),
                    record.is_locked.into(),
                    m.created_at.into(),
                    m.updated_at.into(),
                    record.is_deleted.into(),
                    record.deleted_at.into(),
                    record.deleted_by.clone().into(),
                ])
                .to_owned();
            conn.execute(&stmt).await?;
            if let Some(cause) = record.cause.as_ref().filter(|c| !c.is_empty()) {
                cause_rows.push((membership_id, cause.clone(), m.created_at));
            }
        }
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .unique()
                    .name("idx_memberships_ip_group")
                    .table(MembershipsNew::Table)
                    .col(Memberships::IpRecordId)
                    .col(Memberships::GroupId)
                    .to_owned(),
            )
            .await?;

        // 3. Drop the old children, then the old parent. Nothing references the old parent any
        // more, so no cascade can reach a row that is being kept.
        manager.drop_table(Table::drop().table(Memberships::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(IpRecords::Table).to_owned()).await?;

        // 4. Rename the new tables into place. SQLite rewrites the foreign keys that point at the
        // temporary name, so they end up referencing the real names.
        manager
            .rename_table(Table::rename().table(IpRecordsNew::Table, IpRecords::Table).to_owned())
            .await?;
        manager
            .rename_table(Table::rename().table(MembershipsNew::Table, Memberships::Table).to_owned())
            .await?;

        // 5. Causes: append-only, one row per reported cause, referencing the final membership table.
        manager
            .create_table(
                Table::create()
                    .table(Causes::Table)
                    .col(ColumnDef::new(Causes::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Causes::MembershipId).uuid().not_null())
                    .col(ColumnDef::new(Causes::Cause).text().not_null())
                    .col(ColumnDef::new(Causes::CreatedAt).date_time().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-irc-membership_id")
                            .from(Causes::Table, Causes::MembershipId)
                            .to(Memberships::Table, Memberships::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        for (membership_id, cause, created_at) in cause_rows {
            let stmt = Query::insert()
                .into_table(Causes::Table)
                .columns([Causes::Id, Causes::MembershipId, Causes::Cause, Causes::CreatedAt])
                .values_panic([Uuid::new_v4().into(), membership_id.into(), cause.into(), created_at.into()])
                .to_owned();
            conn.execute(&stmt).await?;
        }

        // 6. Indexes. Every foreign-key child column leads one: the membership's `ip_record_id` is
        // covered by the unique index above, its `group_id` by the lookup below, and a cause's
        // `membership_id` by the composite that also serves "latest cause for this membership".
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_group_memberships_lookup")
                    .table(Memberships::Table)
                    .col(Memberships::GroupId)
                    .col(Memberships::IpRecordId)
                    .to_owned(),
            )
            .await?;
        manager.create_index(partial_active_index_on_real_table()).await?;
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_causes_membership_created")
                    .table(Causes::Table)
                    .col(Causes::MembershipId)
                    .col((Causes::CreatedAt, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;
        // The `is_deleted` / `deleted_at` purge sweep and the retention tombstone arm both read
        // these on the membership now.
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_memberships_deleted_at")
                    .table(Memberships::Table)
                    .col(Memberships::DeletedAt)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, _manager: &SchemaManager) -> Result<(), DbErr> {
        Err(DbErr::Migration(
            "m20261006_120000_refactor_membership_state is not reversible: membership state cannot be \
             split back onto a shared address row without choosing which group's copy wins."
                .to_owned(),
        ))
    }
}

/// The partial index, built against the table's final name once the rename has happened.
fn partial_active_index_on_real_table() -> IndexCreateStatement {
    SqIndex::create()
        .if_not_exists()
        .name("idx_memberships_active_last_seen")
        .table(Memberships::Table)
        .col(Memberships::GroupId)
        .col((Memberships::LastSeenAt, IndexOrder::Desc))
        .and_where(sea_query::Expr::col(Memberships::IsDeleted).eq(false))
        .to_owned()
}
