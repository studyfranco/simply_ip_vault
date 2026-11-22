//! Indexes `ip_records.updated_at` so delta queries do not scan the table.
//!
//! # What this is for
//!
//! The companion exporter and sync worker replicate this service's state incrementally: "give me
//! everything that changed since timestamp T". That is a range scan over a timestamp column, run on a
//! schedule, against the largest table in the schema — the shape that is cheap with an index and
//! quadratic without one, because every poll rescans every row ever written.
//!
//! `RBAC_MODEL.md` §7 already requires indexes on "every column the authenticated hot paths search
//! on". A polling exporter turns `updated_at` into exactly such a column.
//!
//! # Why only `updated_at`
//!
//! The other two columns a delta consumer filters on are already covered, and adding them again would
//! leave duplicate indexes that cost writes and buy nothing:
//!
//! | Column | Index | Created by |
//! | :--- | :--- | :--- |
//! | `last_seen_at` | `idx-ip_records-last_seen_at` | `m20230101_000001` |
//! | `deleted_at` | `idx_ip_records_deleted_at` | `m20260801_000005` |
//! | `is_deleted` | `idx_ip_records_is_deleted` | `m20260801_000005` |
//! | **`updated_at`** | **this migration** | — |
//!
//! Tombstones matter as much as live rows to a replica — a consumer that cannot see deletions
//! diverges silently — which is why `deleted_at` was indexed when soft delete landed and why
//! `include_deleted=true` is no longer master-only.
//!
//! # Single-column, not composite
//!
//! A composite `(updated_at, deleted_at)` was considered and rejected. A delta query filters on
//! `updated_at` alone; `deleted_at` is *projected*, not searched. A composite leading with
//! `updated_at` would serve that query no better than this one while being wider, and its second
//! column would be dead weight on every insert.

use super::prelude::*;

/// The index this migration exists to create.
const UPDATED_AT_INDEX: &str = "idx-ip_records-updated_at";

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &'static str {
        "m20260811_000011_index_ip_record_delta_columns"
    }
}

#[derive(DeriveIden)]
enum IpRecords {
    Table,
    UpdatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    // Idempotent: this migration is additive, and a deployment that created the
                    // index by hand before upgrading should not be blocked from applying it.
                    .if_not_exists()
                    .name(UPDATED_AT_INDEX)
                    .table(IpRecords::Table)
                    .col(IpRecords::UpdatedAt)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name(UPDATED_AT_INDEX)
                    .table(IpRecords::Table)
                    .to_owned(),
            )
            .await
    }
}
