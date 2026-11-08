//! Adds composite indexes for group-scoped differential sync (`since` + `include_deleted=true`),
//! group-scoped trash/all-memberships listing (`include_deleted=true`), and action-filtered audit
//! log queries (`GET /api/v1/audit-logs?action=…`).
//!
//! # Root cause of the ~1.5s slow statements in production
//!
//! Differential sync consumers poll `GET /api/ips?groups=<group>&since=<ts>&include_deleted=true`
//! (with and without `include_total=true`) every few minutes. That combination emits:
//!
//! ```sql
//! WHERE (group_id = ? AND last_seen_at >= ?)
//!    OR (group_id = ? AND is_deleted = ? AND deleted_at >= ?)
//! ORDER BY last_seen_at DESC, id ASC
//! LIMIT ? OFFSET ?
//! ```
//!
//! Prior to this migration:
//! 1. `idx_memberships_active_last_seen` is a partial index (`WHERE is_deleted = FALSE`), so any
//!    query with `include_deleted=true` is ineligible to use it.
//! 2. `idx_memberships_deleted_at` indexed only `(deleted_at) WHERE is_deleted = TRUE` without
//!    `group_id` as its leading column.
//! 3. As a result, `EXPLAIN QUERY PLAN` fell back to scanning every membership in the group via
//!    `idx-irgm-group_id (group_id=?)`, performing one table lookup per row across multi-million
//!    row groups, and sorting via `USE TEMP B-TREE FOR ORDER BY` (~1.5s per `COUNT(*)` and ~1.5s
//!    per `SELECT`, even when `rows_returned=0`).
//!
//! # Indexes added by this migration
//!
//! - `idx_memberships_group_last_seen` on `ip_record_group_memberships (group_id, last_seen_at DESC, id)`:
//!   - Serves Branch 1 of SQLite's `MULTI-INDEX OR` (`group_id=? AND last_seen_at>?`) on
//!     differential sync queries.
//!   - Serves group-scoped `include_deleted=true` listings (both `offset` and keyset `cursor`
//!     pagination) in index order without `USE TEMP B-TREE FOR ORDER BY`.
//!   - Deliberately kept compact (`(group_id, last_seen_at DESC, id)` rather than duplicating all
//!     nine columns): if `deleted_at` were included as a covering column, SQLite's planner would
//!     prefer scanning the entire `group_id` partition of this index over `MULTI-INDEX OR`.
//! - `idx_memberships_group_deleted_at` on `ip_record_group_memberships (group_id, deleted_at DESC, id) WHERE is_deleted = TRUE`:
//!   - Partial over soft-deleted rows only, so active IP inserts and `last_seen_at` updates pay
//!     zero index maintenance cost.
//!   - Serves Branch 2 of SQLite's `MULTI-INDEX OR` (`group_id=? AND deleted_at>?`) on
//!     differential sync queries.
//! - `idx_audit_logs_action_timestamp` on `audit_logs (action, timestamp DESC)`:
//!   - Serves `GET /api/v1/audit-logs?action=…` (`ORDER BY timestamp DESC LIMIT ?`) directly from
//!     the B-tree without sorting every matching action row in a temporary B-tree.

use sea_orm::sea_query::{Expr, ExprTrait, Index as SqIndex, IndexOrder};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Memberships {
    #[sea_orm(iden = "ip_record_group_memberships")]
    Table,
    Id,
    GroupId,
    LastSeenAt,
    IsDeleted,
    DeletedAt,
}

#[derive(DeriveIden)]
enum AuditLogs {
    #[sea_orm(iden = "audit_logs")]
    Table,
    Action,
    Timestamp,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_memberships_group_last_seen")
                    .table(Memberships::Table)
                    .col(Memberships::GroupId)
                    .col((Memberships::LastSeenAt, IndexOrder::Desc))
                    .col(Memberships::Id)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_memberships_group_deleted_at")
                    .table(Memberships::Table)
                    .col(Memberships::GroupId)
                    .col((Memberships::DeletedAt, IndexOrder::Desc))
                    .col(Memberships::Id)
                    .and_where(Expr::col(Memberships::IsDeleted).eq(true))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_audit_logs_action_timestamp")
                    .table(AuditLogs::Table)
                    .col(AuditLogs::Action)
                    .col((AuditLogs::Timestamp, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (table, name) in [
            (
                AuditLogs::Table.into_iden(),
                "idx_audit_logs_action_timestamp",
            ),
            (
                Memberships::Table.into_iden(),
                "idx_memberships_group_deleted_at",
            ),
            (
                Memberships::Table.into_iden(),
                "idx_memberships_group_last_seen",
            ),
        ] {
            manager
                .drop_index(
                    SqIndex::drop()
                        .if_exists()
                        .name(name)
                        .table(table)
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
