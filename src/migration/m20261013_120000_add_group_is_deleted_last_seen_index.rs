//! Adds composite covering index `idx_memberships_group_is_deleted_last_seen` on
//! `ip_record_group_memberships (group_id, is_deleted, last_seen_at DESC, id ASC, ip_record_id, is_locked, created_at, deleted_at, deleted_by)`.
//!
//! # Root cause of slow statements on single-group listing and count
//!
//! When single-group listings or counts are requested (e.g. `GET /api/ips?group_id=<uuid>&include_total=true`
//! or `groups=<name>`):
//!
//! 1. Count query:
//!    `SELECT COUNT(*) AS row_count FROM ip_record_group_memberships WHERE is_deleted = ? AND group_id = ?`
//!    In SQLite, partial indexes like `idx_memberships_active_last_seen` (`WHERE is_deleted = FALSE`)
//!    cannot be used when `is_deleted = ?` is passed as a query parameter because SQLite cannot
//!    prove at prepare/planning time that parameter `?` satisfies the partial index filter.
//!    Without an index leading with both `(group_id, is_deleted)`, SQLite falls back to
//!    `idx-irgm-group_id (group_id=?)`, which does not contain `is_deleted` and requires a separate
//!    random table page lookup for every single membership in the group (taking ~13.6s on large groups).
//!
//! 2. Page and cursor listing:
//!    `SELECT ... FROM ip_record_group_memberships INNER JOIN ip_records ... WHERE is_deleted = ? AND group_id = ? ORDER BY last_seen_at DESC, id ASC LIMIT ? OFFSET ?`
//!    Because `idx_memberships_is_deleted_last_seen` begins with `is_deleted`, SQLite's planner was choosing
//!    it to satisfy the `ORDER BY last_seen_at DESC, id ASC`, scanning across ALL active records across the
//!    entire database (7 million rows) and checking `group_id = ?` row-by-row (~10s to ~20s latency).
//!
//! Composite index `idx_memberships_group_is_deleted_last_seen` on
//! `(group_id, is_deleted, last_seen_at DESC, id ASC, ip_record_id, is_locked, created_at, deleted_at, deleted_by)`:
//! 1. Allows both count and listing queries to perform an exact binary seek on `(group_id = ?, is_deleted = ?)`.
//! 2. Serves `ORDER BY last_seen_at DESC, id ASC` in exact B-tree sort order without a temporary B-tree or scan.
//! 3. Covers all selected columns (`USING COVERING INDEX`), eliminating random bookmark lookups into the membership table.

use sea_orm::sea_query::{Index as SqIndex, IndexOrder};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Memberships {
    #[sea_orm(iden = "ip_record_group_memberships")]
    Table,
    Id,
    IpRecordId,
    GroupId,
    IsLocked,
    CreatedAt,
    LastSeenAt,
    IsDeleted,
    DeletedAt,
    DeletedBy,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_memberships_group_is_deleted_last_seen")
                    .table(Memberships::Table)
                    .col(Memberships::GroupId)
                    .col(Memberships::IsDeleted)
                    .col((Memberships::LastSeenAt, IndexOrder::Desc))
                    .col((Memberships::Id, IndexOrder::Asc))
                    .col(Memberships::IpRecordId)
                    .col(Memberships::IsLocked)
                    .col(Memberships::CreatedAt)
                    .col(Memberships::DeletedAt)
                    .col(Memberships::DeletedBy)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                SqIndex::drop()
                    .if_exists()
                    .name("idx_memberships_group_is_deleted_last_seen")
                    .table(Memberships::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
