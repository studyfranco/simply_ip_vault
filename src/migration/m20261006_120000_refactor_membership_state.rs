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
//! # Ordering and cost
//!
//! Foreign keys are enforced, so dropping a parent that still has children cascades. The rebuild
//! therefore creates the new tables under temporary names, copies into them, drops the old
//! children and then the old parent, and only then renames. No step drops a table that a live
//! foreign key still references.
//!
//! Every copy is one set-based `INSERT ... SELECT` run by SQLite itself. Nothing is read into
//! Rust, so memory use does not grow with the table size and the work is one pass per table. The
//! indexes are built after the copies, so SQLite fills each B-tree in a single sorted pass rather
//! than maintaining it row by row. Row counts are checked against the source before the old tables
//! are dropped; a mismatch aborts the migration and the transaction rolls back.
//!
//! # Reversal
//!
//! Not reversible: several records' memberships collapse into one canonical record, and a
//! membership's state cannot be split back onto a shared row without choosing which group's copy
//! wins. `down` refuses rather than guessing.

use sea_orm::{
    DatabaseBackend,
    sea_query::{self, Alias, Asterisk, Expr, ExprTrait, Func, Index as SqIndex, IndexOrder, Query},
};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// The pre-refactor `ip_records`, read by the copies below.
#[derive(DeriveIden)]
enum IpRecords {
    Table,
    Id,
    TargetAddress,
    Cause,
    IsLocked,
    CreatedAt,
    IsDeleted,
    DeletedAt,
    DeletedBy,
}

#[derive(DeriveIden)]
enum IpRecordsNew {
    #[sea_orm(iden = "ip_records_new")]
    Table,
}

/// Both the pre-refactor membership table and, under its final name, the post-refactor one.
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
enum CausesNew {
    #[sea_orm(iden = "ip_record_causes_new")]
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

/// Surrogate id: UUID generated according to the database backend dialect.
fn random_id(backend: DatabaseBackend) -> Expr {
    match backend {
        DatabaseBackend::Postgres => Func::cust(Alias::new("gen_random_uuid")).into(),
        _ => Func::cust(Alias::new("randomblob")).arg(Expr::val(16)).into(),
    }
}

/// Row count of `table`, computed by the engine. Used to prove a copy kept every row.
async fn count(manager: &SchemaManager<'_>, table: impl IntoIden) -> Result<i64, DbErr> {
    let stmt = Query::select()
        .expr_as(Func::count(Expr::col(Asterisk)), Alias::new("n"))
        .from(table)
        .to_owned();
    let row = manager
        .get_connection()
        .query_one(&stmt)
        .await?
        .ok_or_else(|| DbErr::Migration("COUNT(*) returned no row".to_owned()))?;
    row.try_get("", "n")
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        let conn = manager.get_connection();
        let backend = manager.get_database_backend();
        // 1. The canonical address table, under a temporary name, filled by one engine-side copy.
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
        let copy_records = Query::insert()
            .into_table(IpRecordsNew::Table)
            .columns([IpRecords::Id, IpRecords::TargetAddress, IpRecords::CreatedAt])
            .select_from(
                Query::select()
                    .columns([IpRecords::Id, IpRecords::TargetAddress, IpRecords::CreatedAt])
                    .from(IpRecords::Table)
                    .to_owned(),
            )
            .map_err(|e| DbErr::Migration(e.to_string()))?
            .to_owned();
        conn.execute(&copy_records).await?;

        // 2. The stateful memberships, under a temporary name. Each old membership joins the record
        // it points at, which supplies the state (`is_locked`, soft delete) that moves onto the
        // membership. `last_seen_at` is the old per-group `updated_at`.
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
        let copy_memberships = Query::insert()
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
            .select_from(
                Query::select()
                    .expr(random_id(backend))
                    .column((Memberships::Table, Memberships::IpRecordId))
                    .column((Memberships::Table, Memberships::GroupId))
                    .column((IpRecords::Table, IpRecords::IsLocked))
                    .column((Memberships::Table, Memberships::CreatedAt))
                    .column((Memberships::Table, Memberships::UpdatedAt))
                    .column((IpRecords::Table, IpRecords::IsDeleted))
                    .column((IpRecords::Table, IpRecords::DeletedAt))
                    .column((IpRecords::Table, IpRecords::DeletedBy))
                    .from(Memberships::Table)
                    .inner_join(
                        IpRecords::Table,
                        Expr::col((IpRecords::Table, IpRecords::Id))
                            .equals((Memberships::Table, Memberships::IpRecordId)),
                    )
                    .to_owned(),
            )
            .map_err(|e| DbErr::Migration(e.to_string()))?
            .to_owned();
        conn.execute(&copy_memberships).await?;

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

        // Every old membership must have become exactly one new membership, and every record one
        // canonical address. The inner join drops a membership whose record is missing, so the
        // counts are the check that nothing was lost before the sources are dropped.
        let old_memberships = count(manager, Memberships::Table).await?;
        let new_memberships = count(manager, MembershipsNew::Table).await?;
        if old_memberships != new_memberships {
            return Err(DbErr::Migration(format!(
                "membership copy kept {new_memberships} of {old_memberships} rows — refusing to drop \
                 the source; check for memberships whose ip_record is missing"
            )));
        }
        let old_records = count(manager, IpRecords::Table).await?;
        let new_records = count(manager, IpRecordsNew::Table).await?;
        if old_records != new_records {
            return Err(DbErr::Migration(format!(
                "address copy kept {new_records} of {old_records} rows — refusing to drop the source"
            )));
        }

        // 3. Causes: append-only, one row per membership whose record carried a non-empty cause,
        // dated to the membership's creation.
        manager
            .create_table(
                Table::create()
                    .table(CausesNew::Table)
                    .col(ColumnDef::new(Causes::Id).uuid().not_null().primary_key())
                    .col(ColumnDef::new(Causes::MembershipId).uuid().not_null())
                    .col(ColumnDef::new(Causes::Cause).text().not_null())
                    .col(ColumnDef::new(Causes::CreatedAt).date_time().not_null())
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-irc-membership_id")
                            .from(CausesNew::Table, Causes::MembershipId)
                            .to(MembershipsNew::Table, Memberships::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::Cascade),
                    )
                    .to_owned(),
            )
            .await?;
        let copy_causes = Query::insert()
            .into_table(CausesNew::Table)
            .columns([Causes::Id, Causes::MembershipId, Causes::Cause, Causes::CreatedAt])
            .select_from(
                Query::select()
                    .expr(random_id(backend))
                    .column((MembershipsNew::Table, Memberships::Id))
                    .column((IpRecords::Table, IpRecords::Cause))
                    .column((Memberships::Table, Memberships::CreatedAt))
                    .from(Memberships::Table)
                    .inner_join(
                        IpRecords::Table,
                        Expr::col((IpRecords::Table, IpRecords::Id))
                            .equals((Memberships::Table, Memberships::IpRecordId)),
                    )
                    .inner_join(
                        MembershipsNew::Table,
                        Expr::col((MembershipsNew::Table, Memberships::IpRecordId))
                            .equals((Memberships::Table, Memberships::IpRecordId))
                            .and(
                                Expr::col((MembershipsNew::Table, Memberships::GroupId))
                                    .equals((Memberships::Table, Memberships::GroupId)),
                            ),
                    )
                    .and_where(Expr::col((IpRecords::Table, IpRecords::Cause)).is_not_null())
                    .and_where(Expr::col((IpRecords::Table, IpRecords::Cause)).ne(""))
                    .to_owned(),
            )
            .map_err(|e| DbErr::Migration(e.to_string()))?
            .to_owned();
        conn.execute(&copy_causes).await?;

        // 4. Drop the old children, then the old parent. Nothing references the old parent any
        // more, so no cascade can reach a row that is being kept.
        manager.drop_table(Table::drop().table(Memberships::Table).to_owned()).await?;
        manager.drop_table(Table::drop().table(IpRecords::Table).to_owned()).await?;
        // 5. Rename into place. SQLite rewrites the foreign keys that name a temporary table, so
        // the causes table ends up referencing the real membership table.
        manager
            .rename_table(Table::rename().table(IpRecordsNew::Table, IpRecords::Table).to_owned())
            .await?;
        manager
            .rename_table(Table::rename().table(MembershipsNew::Table, Memberships::Table).to_owned())
            .await?;
        manager
            .rename_table(Table::rename().table(CausesNew::Table, Causes::Table).to_owned())
            .await?;

        // 6. Performance indexes built after data population.
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .unique()
                    .name("idx_memberships_ip_group")
                    .table(Memberships::Table)
                    .col(Memberships::IpRecordId)
                    .col(Memberships::GroupId)
                    .to_owned(),
            )
            .await?;

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

        // Active listing per group, newest observation first.
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_memberships_active_last_seen")
                    .table(Memberships::Table)
                    .col(Memberships::GroupId)
                    .col((Memberships::LastSeenAt, IndexOrder::Desc))
                    .and_where(Expr::col(Memberships::IsDeleted).eq(false))
                    .to_owned(),
            )
            .await?;

        // Active listing across all groups, newest first.
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_memberships_global_active_last_seen")
                    .table(Memberships::Table)
                    .col((Memberships::LastSeenAt, IndexOrder::Desc))
                    .and_where(Expr::col(Memberships::IsDeleted).eq(false))
                    .to_owned(),
            )
            .await?;

        // Active lock filter per group.
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_memberships_active_locked")
                    .table(Memberships::Table)
                    .col(Memberships::GroupId)
                    .col(Memberships::IsLocked)
                    .and_where(Expr::col(Memberships::IsDeleted).eq(false))
                    .to_owned(),
            )
            .await?;

        // Soft-delete retention cleanup index.
        manager
            .drop_index(SqIndex::drop().if_exists().name("idx_memberships_deleted_at").table(Memberships::Table).to_owned())
            .await?;
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_memberships_deleted_at")
                    .table(Memberships::Table)
                    .col(Memberships::DeletedAt)
                    .and_where(Expr::col(Memberships::IsDeleted).eq(true))
                    .to_owned(),
            )
            .await?;

        // Cause history lookup index.
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
