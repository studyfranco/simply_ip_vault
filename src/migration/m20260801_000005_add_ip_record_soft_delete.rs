//! Adds soft-delete columns to `ip_records`: `is_deleted`, `deleted_at`, `deleted_by`.
//!
//! Deleting an IP record used to be irreversible, which made a mistyped `DELETE` — or a compromised
//! delegated key — permanently destructive. A soft delete keeps the row for a 92-day retention
//! window (`crate::retention`) during which a master key can inspect or restore it, after which it
//! is purged for real.
//!
//! Additive and defaulted, so every existing row becomes `is_deleted = false` — i.e. exactly the
//! visibility it already had. `is_deleted` is `NOT NULL` with a default rather than nullable: there
//! is no meaningful "unknown" state, and a nullable flag would force every read filter to spell out
//! `IS NULL OR = false`, which is the kind of condition that eventually gets one branch wrong.
//!
//! `deleted_by` is `TEXT` holding the acting key's UUID rather than a foreign key, matching
//! `SCHEMA.MD`. A FK would either block deleting that key later or null the attribution out via
//! `ON DELETE SET NULL`, and the point of an attribution field is that it survives the actor.

use super::prelude::*;

/// Identifiers this migration touches. `Table` is re-declared locally rather than imported from the
/// initial-schema migration so that module can stay private; `DeriveIden` maps the variants to the
/// same `snake_case` names, so they address the same table.
#[derive(DeriveIden)]
enum IpRecords {
    /// The `ip_records` table.
    Table,
    /// Whether the record is soft-deleted and hidden from normal reads.
    IsDeleted,
    /// When the soft delete happened; `NULL` while the record is live.
    DeletedAt,
    /// The `api_keys.id` (as text) of whoever soft-deleted it; `NULL` while live.
    DeletedBy,
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &'static str {
        "m20260801_000005_add_ip_record_soft_delete"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        // One column per `alter_table` call: SQLite's ALTER TABLE accepts a single ADD COLUMN per
        // statement, and SeaORM does not split a multi-column alter for it. Three statements are
        // portable across every backend; one is not.
        manager
            .alter_table(
                Table::alter()
                    .table(IpRecords::Table)
                    .add_column(
                        ColumnDef::new(IpRecords::IsDeleted)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(IpRecords::Table)
                    .add_column(ColumnDef::new(IpRecords::DeletedAt).date_time().null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(IpRecords::Table)
                    .add_column(ColumnDef::new(IpRecords::DeletedBy).text().null())
                    .to_owned(),
            )
            .await?;

        // Every normal read filters on `is_deleted`, and the purge sweep scans `deleted_at`, so
        // both are indexed. Without the first, hiding soft-deleted rows would turn each listing
        // into a full scan as the trash accumulates.
        manager
            .create_index(
                Index::create()
                    .name("idx_ip_records_is_deleted")
                    .table(IpRecords::Table)
                    .col(IpRecords::IsDeleted)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx_ip_records_deleted_at")
                    .table(IpRecords::Table)
                    .col(IpRecords::DeletedAt)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name("idx_ip_records_deleted_at")
                    .table(IpRecords::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name("idx_ip_records_is_deleted")
                    .table(IpRecords::Table)
                    .to_owned(),
            )
            .await?;

        for column in [
            IpRecords::DeletedBy,
            IpRecords::DeletedAt,
            IpRecords::IsDeleted,
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(IpRecords::Table)
                        .drop_column(column)
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
