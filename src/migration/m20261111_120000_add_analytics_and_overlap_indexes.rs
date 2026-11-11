//! Adds composite covering indexes on `ip_record_group_memberships` for analytics,
//! multi-group intersection, distinct IP counting, and shared group presence.
//!
//! # Root Cause of Analytical Query Latencies
//!
//! 1. `COUNT(DISTINCT ip_record_id) WHERE is_deleted = false`:
//!    Without an index leading with `is_deleted` and containing `ip_record_id`, SQLite was scanning
//!    all 7+ million rows and performing random table lookups to construct a temporary B-tree for
//!    distinct counting (`USE TEMP B-TREE FOR count(DISTINCT)`), taking ~338 seconds on production disks.
//!
//! 2. Multi-group intersection & recidivists (`GROUP BY ip_record_id HAVING COUNT(DISTINCT group_id) > 1`):
//!    Scanning `ip_record_group_memberships` to group by `ip_record_id` under `is_deleted = false`
//!    requires sorting or hashing millions of rows unless a covering index presents
//!    `(is_deleted, ip_record_id, group_id)` in pre-sorted order.
//!
//! 3. Shared group membership checks (`EXISTS (SELECT 1 ... WHERE group_id != ? AND ip_record_id = ?)`):
//!    Looking up if an IP exists in other groups requires an index on `(group_id, is_deleted, ip_record_id)`.
//!
//! # Indexes Added
//!
//! - `idx_memberships_is_deleted_ip_record_group` on `(is_deleted, ip_record_id, group_id)`:
//!   Enables index-only scans for `COUNT(DISTINCT ip_record_id)` and recidivist groupings without
//!   touching table data pages.
//! - `idx_memberships_group_is_deleted_ip_record` on `(group_id, is_deleted, ip_record_id)`:
//!   Enables fast covering lookups for group-scoped membership existence tests.

use sea_orm::sea_query::Index as SqIndex;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Memberships {
    #[sea_orm(iden = "ip_record_group_memberships")]
    Table,
    IpRecordId,
    GroupId,
    IsDeleted,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_memberships_is_deleted_ip_record_group")
                    .table(Memberships::Table)
                    .col(Memberships::IsDeleted)
                    .col(Memberships::IpRecordId)
                    .col(Memberships::GroupId)
                    .to_owned(),
            )
            .await?;

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

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                SqIndex::drop()
                    .name("idx_memberships_group_is_deleted_ip_record")
                    .table(Memberships::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                SqIndex::drop()
                    .name("idx_memberships_is_deleted_ip_record_group")
                    .table(Memberships::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
