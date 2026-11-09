//! Adds composite index `idx_memberships_is_deleted_last_seen` on
//! `ip_record_group_memberships (is_deleted, last_seen_at DESC, id ASC)`.
//!
//! # Root cause of slow statements on global active/trash counts and listings
//!
//! When global counts are requested (e.g. `GET /api/ips?include_total=true` without a group filter,
//! or trash view counts), SeaORM issues:
//! `SELECT COUNT(*) AS row_count FROM ip_record_group_memberships WHERE is_deleted = ?`
//!
//! In SQLite, partial indexes (`WHERE is_deleted = FALSE`) cannot be used when `is_deleted = ?` is
//! passed as a query parameter because SQLite cannot verify at plan time that `?` satisfies the
//! index's filter predicate. Without an index leading with `is_deleted`, SQLite falls back to a full
//! table scan across all 7 million rows (~5.8 GB table on disk), taking ~285 seconds.
//!
//! Furthermore, unfiltered master listings (`WHERE is_deleted = false ORDER BY last_seen_at DESC, id ASC`)
//! require an index ordered by `last_seen_at DESC, id ASC` under the `is_deleted` filter to avoid
//! a temporary B-tree sort (`USE TEMP B-TREE FOR ORDER BY`).
//!
//! Composite index `idx_memberships_is_deleted_last_seen` on `(is_deleted, last_seen_at DESC, id ASC)`
//! satisfies both simultaneously:
//! 1. `COUNT(*) ... WHERE is_deleted = ?` performs a fast covering index seek (< 10ms).
//! 2. Unfiltered page and cursor queries stream in exact sort order without a temporary B-tree.

use sea_orm::sea_query::{Index as SqIndex, IndexOrder};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Memberships {
    #[sea_orm(iden = "ip_record_group_memberships")]
    Table,
    Id,
    LastSeenAt,
    IsDeleted,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_memberships_is_deleted_last_seen")
                    .table(Memberships::Table)
                    .col(Memberships::IsDeleted)
                    .col((Memberships::LastSeenAt, IndexOrder::Desc))
                    .col((Memberships::Id, IndexOrder::Asc))
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
                    .name("idx_memberships_is_deleted_last_seen")
                    .table(Memberships::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
