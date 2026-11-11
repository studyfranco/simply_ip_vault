//! Fixes SQLite query planner regressions on group-scoped and global membership listings.
//!
//! # Root Cause of Catastrophic Query Degradation (500s - 1000s)
//!
//! 1. Group-scoped listings (`GET /api/ips?group_id=...` and `fetch_merged_page`):
//!    In `m20261111_120000_add_analytics_and_overlap_indexes`, `idx_memberships_group_is_deleted_ip_record`
//!    was added on `(group_id, is_deleted, ip_record_id)` for shared group checks.
//!    Because SQLite's cost estimator favors indexes with fewer columns when filtering by
//!    `WHERE group_id = ? AND is_deleted = ?`, SQLite chose this 3-column index instead of
//!    `idx_memberships_group_is_deleted_last_seen` (10 columns).
//!    However, `idx_memberships_group_is_deleted_ip_record` does NOT contain `(last_seen_at DESC, id ASC)`.
//!    As a result, SQLite could not stream rows in pre-sorted order and fell back to:
//!    `USE TEMP B-TREE FOR ORDER BY`, scanning every single row in the group into a temporary B-tree
//!    file on disk. On large groups (hundreds of thousands of rows), this took between 500s and 1025s
//!    per query!
//!    Furthermore, `idx_memberships_group_is_deleted_last_seen` already has `(group_id, is_deleted)`
//!    as its leading columns and covers `ip_record_id`, so `idx_memberships_group_is_deleted_ip_record`
//!    is completely redundant.
//!    Dropping `idx_memberships_group_is_deleted_ip_record` immediately forces SQLite to use
//!    `idx_memberships_group_is_deleted_last_seen`, restoring < 1ms streaming execution with zero temp sorts.
//!
//! 2. Unfiltered global listings (`GET /api/ips` without group filters):
//!    `idx_memberships_is_deleted_last_seen` was originally created on only `(is_deleted, last_seen_at DESC, id ASC)`.
//!    Recreating it as a full covering index containing all selected membership columns:
//!    `(is_deleted, last_seen_at DESC, id ASC, ip_record_id, group_id, is_locked, created_at, deleted_at, deleted_by)`
//!    enables SQLite to stream active records without touching table data pages or incurring bookmark lookups.

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
        // 1. Drop the harmful redundant index that stole group-scoped listing plans and forced temp b-tree sorts.
        manager
            .drop_index(
                SqIndex::drop()
                    .if_exists()
                    .name("idx_memberships_group_is_deleted_ip_record")
                    .table(Memberships::Table)
                    .to_owned(),
            )
            .await?;

        // 2. Drop and recreate `idx_memberships_is_deleted_last_seen` as a full covering index.
        manager
            .drop_index(
                SqIndex::drop()
                    .if_exists()
                    .name("idx_memberships_is_deleted_last_seen")
                    .table(Memberships::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_memberships_is_deleted_last_seen")
                    .table(Memberships::Table)
                    .col(Memberships::IsDeleted)
                    .col((Memberships::LastSeenAt, IndexOrder::Desc))
                    .col((Memberships::Id, IndexOrder::Asc))
                    .col(Memberships::IpRecordId)
                    .col(Memberships::GroupId)
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
        // Recreate the 3-column index if rolled back
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_memberships_group_is_deleted_ip_record")
                    .table(Memberships::Table)
                    .col(Memberships::GroupId)
                    .col(Memberships::IsDeleted)
                    .col(Memberships::IpRecordId)
                    .to_owned(),
            )
            .await?;

        // Revert `idx_memberships_is_deleted_last_seen` to its non-covering form
        manager
            .drop_index(
                SqIndex::drop()
                    .if_exists()
                    .name("idx_memberships_is_deleted_last_seen")
                    .table(Memberships::Table)
                    .to_owned(),
            )
            .await?;

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
}
