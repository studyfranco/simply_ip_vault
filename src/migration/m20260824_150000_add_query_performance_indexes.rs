//! Adds the two indexes `EXPLAIN QUERY PLAN` confirms are actually missing for the endpoints
//! production logs named as slow under load: `GET /api/ips`'s join+filter+sort, and the group-scoped
//! membership lookup every RBAC-scoped listing performs.
//!
//! # Verified before writing this, not assumed from the symptom
//!
//! Running `EXPLAIN QUERY PLAN` against the schema as it stood before this migration:
//!
//! ```text
//! -- list_ips's join, filtered on is_deleted, sorted on updated_at:
//! SEARCH ip_records USING INDEX idx_ip_records_is_deleted (is_deleted=?)
//! SEARCH ip_record_group_memberships USING COVERING INDEX sqlite_autoindex_..._1 (ip_record_id=?)
//! USE TEMP B-TREE FOR ORDER BY                              <-- the reported slowness
//!
//! -- a group-scoped membership lookup (every RBAC accessible-groups filter does this):
//! SCAN ip_record_group_memberships                          <-- full table scan
//! ```
//!
//! `idx_ip_records_is_deleted` (from `m20260801_000005`) satisfies the `WHERE` clause but says
//! nothing about order, so SQLite still has to materialize and sort every matching row itself — the
//! "USE TEMP B-TREE" line is exactly the symptom production logs described (20-42s on this query
//! under load: the temp b-tree's memory/disk churn scales with the *matching* row count, not the
//! page returned). And `ip_record_group_memberships`'s only index is its primary key,
//! `(ip_record_id, group_id)` (`m20230101_000001`) — leading with `ip_record_id`, so a lookup
//! filtered by `group_id` alone (what every accessible-groups / `groups=`/`group_id=` filter in
//! `list_ips` does) cannot use it and falls back to a full scan.
//!
//! After this migration, the same two `EXPLAIN QUERY PLAN`s read:
//!
//! ```text
//! SEARCH ip_records USING INDEX idx_ip_records_deleted_updated (is_deleted=?)
//! SEARCH ip_record_group_memberships USING COVERING INDEX sqlite_autoindex_..._1 (ip_record_id=?)
//!
//! SEARCH ip_record_group_memberships USING COVERING INDEX idx_group_memberships_lookup (group_id=?)
//! ```
//!
//! No temp b-tree, no scan. `tests/schema_integrity_tests.rs`'s
//! `list_ips_query_plan_uses_indexes_not_a_temp_b_tree_or_table_scan` pins both plans so a future
//! migration or query rewrite that reintroduces either regresses loudly instead of silently.
//!
//! # Why only two indexes, not the four a naive read of the symptom list suggests
//!
//! The other two obvious-looking candidates already exist, verified by grepping every prior
//! migration rather than assumed from the column name:
//!
//! | Candidate | Already exists as | Added by |
//! | :--- | :--- | :--- |
//! | `ip_records(updated_at DESC)` alone | `idx-ip_records-updated_at` | `m20260811_000011` |
//! | `audit_logs(timestamp DESC)` | `idx-audit_logs-timestamp` | `m20230101_000001` |
//!
//! Adding either again would be a duplicate index: identical lookup capability, a second copy of
//! the same B-tree to maintain on every write, and nothing a query planner would ever prefer it
//! over its twin for — exactly the "costs writes and buys nothing" `m20260811_000011` already
//! reasoned through for a different composite. `idx_ip_records_deleted_updated` is not redundant
//! with `idx-ip_records-updated_at` despite overlapping on `updated_at`: a single-column
//! `updated_at` index cannot also satisfy an `is_deleted` equality filter for free, which is the
//! whole reason `list_ips`'s planner was choosing `idx_ip_records_is_deleted` instead and still
//! needing the temp b-tree — see above.
//!
//! A single-column, DESC-declared `ip_records(updated_at DESC)` was also considered on its own
//! merits and rejected for the same reason `m20260811_000011` needed no DESC declaration at all:
//! SQLite's B-tree indexes are traversed in either direction at equal cost, so an ASC-declared
//! single-column index already serves a `DESC` `ORDER BY` with no extra sort step. `DESC` only
//! matters *within* a composite, where it fixes the *relative* order of the second column once the
//! first is pinned — which is exactly why it appears on `idx_ip_records_deleted_updated`'s second
//! column above and would have bought nothing as a standalone index's only column.

use super::prelude::*;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &'static str {
        "m20260824_150000_add_query_performance_indexes"
    }
}

#[derive(DeriveIden)]
enum IpRecords {
    Table,
    IsDeleted,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum IpRecordGroupMemberships {
    Table,
    GroupId,
    IpRecordId,
}

const DELETED_UPDATED_INDEX: &str = "idx_ip_records_deleted_updated";
const GROUP_MEMBERSHIPS_LOOKUP_INDEX: &str = "idx_group_memberships_lookup";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    // Idempotent, matching every other additive index migration in this crate: a
                    // deployment that created either index by hand ahead of upgrading is not
                    // blocked from applying this one.
                    .if_not_exists()
                    .name(DELETED_UPDATED_INDEX)
                    .table(IpRecords::Table)
                    .col(IpRecords::IsDeleted)
                    .col((IpRecords::UpdatedAt, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name(GROUP_MEMBERSHIPS_LOOKUP_INDEX)
                    .table(IpRecordGroupMemberships::Table)
                    .col(IpRecordGroupMemberships::GroupId)
                    .col(IpRecordGroupMemberships::IpRecordId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name(GROUP_MEMBERSHIPS_LOOKUP_INDEX)
                    .table(IpRecordGroupMemberships::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                Index::drop()
                    .name(DELETED_UPDATED_INDEX)
                    .table(IpRecords::Table)
                    .to_owned(),
            )
            .await
    }
}
