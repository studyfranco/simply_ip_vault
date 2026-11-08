//! Re-aligns `idx_memberships_global_active_last_seen` to place `id ASC` immediately following
//! `last_seen_at DESC`, and adds indexes for global differential sync and unfiltered listings.
//!
//! # Root cause of slow statements on global listings (`GET /api/ips`)
//!
//! When `GET /api/ips` is called without a group filter (e.g. by the web UI or master consumers):
//! 1. The page query orders by `ORDER BY last_seen_at DESC, id ASC LIMIT ? OFFSET ?`.
//!    In `m20261009_120000_make_listing_indexes_covering`, `idx_memberships_global_active_last_seen`
//!    was constructed with `group_id` before `covering_tail`, giving columns:
//!    `last_seen_at DESC, group_id, id, ...`
//!    Because `group_id` sat between `last_seen_at` and `id`, SQLite could not use the index to
//!    guarantee `id ASC` ordering. `EXPLAIN QUERY PLAN` fell back to
//!    `USE TEMP B-TREE FOR LAST TERM OF ORDER BY`, scanning all active rows across the entire table
//!    and sorting in a temporary B-tree (~1.95s in production for a single 50-row page).
//!    Reordering the index columns to `(last_seen_at DESC, id ASC, group_id, …)` allows SQLite to
//!    stream directly from the covering index in exact sort order with no temp B-tree, reading only
//!    the requested `limit` rows (< 1ms).
//! 2. Global differential sync (`(last_seen_at >= ?) OR (is_deleted = TRUE AND deleted_at >= ?)`)
//!    and unfiltered listings with `include_deleted=true` benefit from `idx_memberships_global_last_seen`
//!    on `(last_seen_at DESC, id ASC)` and `idx_memberships_global_deleted_at` on
//!    `(deleted_at DESC, id ASC) WHERE is_deleted = TRUE`, enabling `MULTI-INDEX OR` seeks.

use sea_orm::sea_query::{Expr, ExprTrait, Index as SqIndex, IndexOrder};
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
        // 1. Recreate `idx_memberships_global_active_last_seen` with `id ASC` directly after `last_seen_at DESC`.
        manager
            .drop_index(
                SqIndex::drop()
                    .if_exists()
                    .name("idx_memberships_global_active_last_seen")
                    .table(Memberships::Table)
                    .to_owned(),
            )
            .await?;

        let mut global = SqIndex::create()
            .if_not_exists()
            .name("idx_memberships_global_active_last_seen")
            .table(Memberships::Table)
            .col((Memberships::LastSeenAt, IndexOrder::Desc))
            .col(Memberships::Id)
            .col(Memberships::GroupId)
            .col(Memberships::IpRecordId)
            .col(Memberships::IsLocked)
            .col(Memberships::CreatedAt)
            .col(Memberships::IsDeleted)
            .col(Memberships::DeletedAt)
            .col(Memberships::DeletedBy)
            .to_owned();
        global.and_where(Expr::col(Memberships::IsDeleted).eq(false));
        manager.create_index(global).await?;

        // 2. Composite index on `(last_seen_at DESC, id ASC)` across all rows (active and deleted).
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_memberships_global_last_seen")
                    .table(Memberships::Table)
                    .col((Memberships::LastSeenAt, IndexOrder::Desc))
                    .col(Memberships::Id)
                    .to_owned(),
            )
            .await?;

        // 3. Partial index on `(deleted_at DESC, id ASC)` for soft-deleted rows.
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_memberships_global_deleted_at")
                    .table(Memberships::Table)
                    .col((Memberships::DeletedAt, IndexOrder::Desc))
                    .col(Memberships::Id)
                    .and_where(Expr::col(Memberships::IsDeleted).eq(true))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for name in [
            "idx_memberships_global_deleted_at",
            "idx_memberships_global_last_seen",
            "idx_memberships_global_active_last_seen",
        ] {
            manager
                .drop_index(
                    SqIndex::drop()
                        .if_exists()
                        .name(name)
                        .table(Memberships::Table)
                        .to_owned(),
                )
                .await?;
        }

        // Restore the previous column ordering from m20261009_120000.
        let mut global = SqIndex::create()
            .if_not_exists()
            .name("idx_memberships_global_active_last_seen")
            .table(Memberships::Table)
            .col((Memberships::LastSeenAt, IndexOrder::Desc))
            .col(Memberships::GroupId)
            .col(Memberships::Id)
            .col(Memberships::IpRecordId)
            .col(Memberships::IsLocked)
            .col(Memberships::CreatedAt)
            .col(Memberships::IsDeleted)
            .col(Memberships::DeletedAt)
            .col(Memberships::DeletedBy)
            .to_owned();
        global.and_where(Expr::col(Memberships::IsDeleted).eq(false));
        manager.create_index(global).await?;

        Ok(())
    }
}
