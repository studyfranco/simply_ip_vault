//! Adds performance indexes for `simply_ip_vault` analytical aggregation queries,
//! locking breakdowns, velocity counters, and ban cause distributions.
//!
//! # Problem Solved
//!
//! 1. `locked_breakdown` (`WHERE is_deleted = false GROUP BY is_locked`):
//!    Scanning millions of active memberships without an index on `(is_deleted, is_locked)`
//!    caused a full table scan taking ~63s on slow disks.
//!
//! 2. `compute_velocity` deleted counts (`WHERE is_deleted = true AND deleted_at >= ?`):
//!    Composite index on `(is_deleted, deleted_at)` allows B-tree range scans with parameterized
//!    bound variables in milliseconds instead of scanning data pages.
//!
//! 3. `top_causes` (`GROUP BY cause` on `ip_record_causes`):
//!    Indexing `(cause, membership_id)` enables SQLite to resolve cause counts
//!    via index-only scan rather than loading and sorting all cause rows.

use sea_orm::sea_query::Index as SqIndex;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Memberships {
    #[sea_orm(iden = "ip_record_group_memberships")]
    Table,
    IsDeleted,
    IsLocked,
    DeletedAt,
}

#[derive(DeriveIden)]
enum Causes {
    #[sea_orm(iden = "ip_record_causes")]
    Table,
    MembershipId,
    Cause,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // 1. Covering index for active vs locked breakdown
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_memberships_is_deleted_is_locked")
                    .table(Memberships::Table)
                    .col(Memberships::IsDeleted)
                    .col(Memberships::IsLocked)
                    .to_owned(),
            )
            .await?;

        // 2. Covering index for soft-deleted deleted_at range scans (retention & velocity)
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_memberships_is_deleted_deleted_at")
                    .table(Memberships::Table)
                    .col(Memberships::IsDeleted)
                    .col(Memberships::DeletedAt)
                    .to_owned(),
            )
            .await?;

        // 3. Index on causes for fast cause aggregation
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_causes_cause_membership")
                    .table(Causes::Table)
                    .col(Causes::Cause)
                    .col(Causes::MembershipId)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                SqIndex::drop()
                    .name("idx_causes_cause_membership")
                    .table(Causes::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                SqIndex::drop()
                    .name("idx_memberships_is_deleted_deleted_at")
                    .table(Memberships::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                SqIndex::drop()
                    .name("idx_memberships_is_deleted_is_locked")
                    .table(Memberships::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
