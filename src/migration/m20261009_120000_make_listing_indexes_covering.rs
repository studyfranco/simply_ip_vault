//! Widens `idx_memberships_active_last_seen` and `idx_memberships_global_active_last_seen` into
//! covering indexes, so the group-scoped and unfiltered listing queries never need a bookmark
//! lookup back into the table.
//!
//! Both indexes previously stored only `(group_id, last_seen_at)` / `(last_seen_at)` — enough to
//! seek and sort, but `list_ips` and `fetch_merged_page` (`src/api/records.rs`) select every other
//! membership column too (`id`, `ip_record_id`, `is_locked`, `created_at`, `deleted_at`,
//! `deleted_by`), none of which live in the index. `EXPLAIN QUERY PLAN` confirms the difference:
//! without the extra columns the plan reads `SEARCH ... USING INDEX`, meaning one additional
//! random read per returned row to fetch them from the table; with them it reads `SEARCH ...
//! USING COVERING INDEX`, meaning none. On a page of up to `limit` rows that is up to `limit`
//! random reads eliminated per query — on networked or mechanical storage, where a random read can
//! cost orders of magnitude more than a sequential one, this is the dominant cost a correct query
//! plan still pays, and the one a partial index on just the sort/filter columns cannot avoid.
//!
//! The cost is a larger index: each entry now carries most of the row, roughly doubling what these
//! two indexes store. Worth it for a read path this central, and a one-time migration cost against
//! a cost paid by every listing request afterwards.

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

/// The columns `list_ips`/`fetch_merged_page` select beyond the key columns each index leads
/// with — added as trailing, non-key columns so SQLite can answer the whole row from the index.
fn covering_tail(stmt: &mut IndexCreateStatement) -> &mut IndexCreateStatement {
    stmt.col(Memberships::Id)
        .col(Memberships::IpRecordId)
        .col(Memberships::IsLocked)
        .col(Memberships::CreatedAt)
        .col(Memberships::IsDeleted)
        .col(Memberships::DeletedAt)
        .col(Memberships::DeletedBy)
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                SqIndex::drop()
                    .if_exists()
                    .name("idx_memberships_active_last_seen")
                    .table(Memberships::Table)
                    .to_owned(),
            )
            .await?;
        let mut active = SqIndex::create()
            .if_not_exists()
            .name("idx_memberships_active_last_seen")
            .table(Memberships::Table)
            .col(Memberships::GroupId)
            .col((Memberships::LastSeenAt, IndexOrder::Desc))
            .to_owned();
        covering_tail(&mut active);
        active.and_where(Expr::col(Memberships::IsDeleted).eq(false));
        manager.create_index(active).await?;

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
            .to_owned();
        global.col(Memberships::GroupId);
        covering_tail(&mut global);
        global.and_where(Expr::col(Memberships::IsDeleted).eq(false));
        manager.create_index(global).await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Restores the narrower, non-covering indexes this migration widened.
        manager
            .drop_index(
                SqIndex::drop()
                    .if_exists()
                    .name("idx_memberships_active_last_seen")
                    .table(Memberships::Table)
                    .to_owned(),
            )
            .await?;
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
        manager
            .drop_index(
                SqIndex::drop()
                    .if_exists()
                    .name("idx_memberships_global_active_last_seen")
                    .table(Memberships::Table)
                    .to_owned(),
            )
            .await?;
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
        Ok(())
    }
}
