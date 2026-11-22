//! Adds `created_at`/`updated_at` to `ip_record_group_memberships` — the join table associating
//! an `ip_records` row with an `ip_groups` row — so "when was this address's membership in *this*
//! group created/touched" becomes a property of the membership, not a property of the shared
//! address row.
//!
//! # The bug this closes
//!
//! `ip_records.updated_at`/`created_at` describe the address row, and one address row is shared by
//! every group it belongs to (`RBAC_MODEL.md`/`AGENT.MD` §3: "An IP can belong to multiple
//! `IpGroup`s simultaneously"). Before this migration, `GET /api/ips`'s delta-sync (`since`) filter
//! and its `ORDER BY` both read that shared column. So banning an address into Group A — an event
//! that concerns Group A alone — advanced `ip_records.updated_at`, which made the *same* address's
//! row in Group B's listing look freshly changed too, even though nothing about Group B's
//! membership was touched. A differential-sync consumer polling `GET /api/ips?groups=B&since=T`
//! (`simply_ip_exporter`, `simply_ip_sync` in `example/`) would then see a "change" in Group B and
//! re-trigger whatever it does on change — a webhook, a firewall reload — for a group that never
//! actually changed.
//!
//! The fix is to give the *membership* its own `created_at`/`updated_at`, updated only when
//! *this* (record, group) pairing is the one being touched — see `api::records::handle_ip_upsert`
//! and `batch_records`, which now upsert the membership row (`ON CONFLICT ... DO UPDATE SET
//! updated_at`) instead of only inserting it, and `list_ips`, whose `since` filter and `ORDER BY`
//! now read the membership's own columns. `ip_records.updated_at`/`last_seen_at` are unchanged in
//! meaning and untouched by this migration — `max_age` filtering is deliberately still address-wide
//! freshness, a genuinely different question from "did this group's view of the address change".
//!
//! # Backfill
//!
//! A pre-existing membership row was never timestamped, so there is no true per-membership history
//! to recover. The closest honest reconstruction is the address's own `ip_records.created_at`/
//! `updated_at` at the moment of this migration — not a fabricated "just now" value, which would
//! make every pre-existing membership look freshly touched to the first delta-sync poll after
//! upgrade, and not a NULL, which `AGENT.MD`'s own precedent (`m20260811_000010`'s attribution
//! columns) treats as worse than a value that is merely approximate. It is approximate — a
//! membership predating this migration might genuinely have been created or last touched long
//! after the address row itself was — but it is the same order of approximation `since`-based
//! delta sync already tolerated before this migration existed at all, and it converges to exact
//! going forward as every future insert/update sets the membership's own columns directly.
//!
//! # Why a full rebuild on SQLite, not a plain `ADD COLUMN`
//!
//! Both new columns are `NOT NULL`, and the correct value for each existing row is *someone else's
//! column* — a per-row computed backfill, not a constant. SQLite's `ADD COLUMN ... NOT NULL`
//! requires a constant `DEFAULT`, which cannot express "copy from the joined `ip_records` row", so
//! the columns are added nullable, backfilled with a correlated `UPDATE`, and only then tightened —
//! and tightening nullability on SQLite has no `ALTER COLUMN` at all, hence the rebuild. PostgreSQL
//! and MySQL take the same three steps without a rebuild, via `ALTER COLUMN`/`MODIFY COLUMN`
//! directly, mirroring `m20260811_000010`'s own branch.
//!
//! `idx_group_memberships_lookup` (`m20260824_150000`) is recreated after the SQLite rebuild, since
//! dropping the table drops it too. A new composite, `idx_membership_group_updated`
//! (`group_id`, `updated_at DESC`), is added for the same reason `idx_ip_records_deleted_updated`
//! was: `list_ips`'s join now filters on `group_id` and sorts on the membership's `updated_at`
//! together, and `EXPLAIN QUERY PLAN` (see `tests/schema_integrity_tests.rs`) confirmed this
//! composite is what lets that combination avoid a `TEMP B-TREE` sort step.
//!
//! # `idx_ip_records_deleted_updated` is dropped, not kept alongside the new index
//!
//! That composite (`m20260824_150000`) existed for exactly one query: `list_ips`'s old
//! `ORDER BY ip_records.updated_at`. This migration replaces that sort with one on the
//! membership's own `updated_at`, and grepping `src/` for `ip_record::Column::UpdatedAt` afterward
//! finds no remaining query use anywhere — so the index would sit on every future `ip_records`
//! write (every ban/whitelist/re-registration) serving nothing, exactly the "costs writes, buys
//! nothing" anti-pattern `AGENT.MD`'s indexing guidance and `m20260824_150000`'s own header both
//! warn against. `ip_records.updated_at` the *column* is unaffected — still written, still
//! meaningful as "when any field on this address last changed" — only the index built for a query
//! shape that no longer exists is removed.

use super::prelude::*;
use sea_orm::DatabaseBackend;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &'static str {
        "m20260926_120000_add_membership_timestamps"
    }
}

#[derive(DeriveIden)]
enum IpRecordGroupMemberships {
    Table,
    IpRecordId,
    GroupId,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum IpRecordGroupMembershipsRebuild {
    #[sea_orm(iden = "ip_record_group_memberships_rebuild")]
    Table,
}

#[derive(DeriveIden)]
enum IpRecords {
    Table,
    Id,
    IsDeleted,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
enum IpGroups {
    Table,
    Id,
}

const LOOKUP_INDEX: &str = "idx_group_memberships_lookup";
const GROUP_UPDATED_INDEX: &str = "idx_membership_group_updated";
const DELETED_UPDATED_INDEX: &str = "idx_ip_records_deleted_updated";

/// Recreates both indexes `ip_record_group_memberships` needs — the pre-existing group lookup
/// (`m20260824_150000`) and the new `group+updated_at` composite this migration adds — after
/// whichever path (rebuild or plain `ADD COLUMN`) just ran.
async fn recreate_indexes(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name(LOOKUP_INDEX)
                .table(IpRecordGroupMemberships::Table)
                .col(IpRecordGroupMemberships::GroupId)
                .col(IpRecordGroupMemberships::IpRecordId)
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name(GROUP_UPDATED_INDEX)
                .table(IpRecordGroupMemberships::Table)
                .col(IpRecordGroupMemberships::GroupId)
                .col((IpRecordGroupMemberships::UpdatedAt, IndexOrder::Desc))
                .to_owned(),
        )
        .await
}

/// Copies every existing row's `created_at`/`updated_at` from its `ip_records` counterpart. Used
/// both by the SQLite rebuild's `INSERT ... SELECT` and, on other backends, by a correlated
/// `UPDATE` against the nullable columns `ADD COLUMN` just created.
fn record_timestamp(column: IpRecords) -> Expr {
    Expr::from(
        Query::select()
            .column(column)
            .from(IpRecords::Table)
            .and_where(Expr::col((IpRecords::Table, IpRecords::Id)).eq(Expr::col((
                IpRecordGroupMemberships::Table,
                IpRecordGroupMemberships::IpRecordId,
            ))))
            .to_owned(),
    )
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        let backend = manager.get_database_backend();

        // `idx_ip_records_deleted_updated` (`m20260824_150000`) existed solely to serve
        // `list_ips`'s `ORDER BY ip_records.updated_at` — the query shape this migration replaces
        // with a sort on the membership's own `updated_at` instead (see the module comment). Grepping
        // `src/` for `ip_record::Column::UpdatedAt` after this change finds no remaining query use at
        // all, so keeping this index would be exactly the "costs every future write, buys nothing"
        // anti-pattern `m20260824_150000`'s own header warns against for its own candidates.
        manager
            .drop_index(
                Index::drop()
                    .if_exists()
                    .name(DELETED_UPDATED_INDEX)
                    .table(IpRecords::Table)
                    .to_owned(),
            )
            .await?;

        if backend == DatabaseBackend::Sqlite {
            return add_sqlite_membership_timestamps(manager).await;
        }

        // PostgreSQL / MySQL: add nullable, backfill via a correlated UPDATE, then tighten.
        manager
            .alter_table(
                Table::alter()
                    .table(IpRecordGroupMemberships::Table)
                    .add_column(ColumnDef::new(IpRecordGroupMemberships::CreatedAt).date_time())
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(IpRecordGroupMemberships::Table)
                    .add_column(ColumnDef::new(IpRecordGroupMemberships::UpdatedAt).date_time())
                    .to_owned(),
            )
            .await?;

        manager
            .exec_stmt(
                Query::update()
                    .table(IpRecordGroupMemberships::Table)
                    .value(
                        IpRecordGroupMemberships::CreatedAt,
                        record_timestamp(IpRecords::CreatedAt),
                    )
                    .value(
                        IpRecordGroupMemberships::UpdatedAt,
                        record_timestamp(IpRecords::UpdatedAt),
                    )
                    .to_owned(),
            )
            .await?;

        for column in [
            IpRecordGroupMemberships::CreatedAt,
            IpRecordGroupMemberships::UpdatedAt,
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(IpRecordGroupMemberships::Table)
                        .modify_column(ColumnDef::new(column).date_time().not_null())
                        .to_owned(),
                )
                .await?;
        }

        recreate_indexes(manager).await
    }

    async fn down(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name(GROUP_UPDATED_INDEX)
                    .table(IpRecordGroupMemberships::Table)
                    .to_owned(),
            )
            .await?;

        // Restores exactly what `m20260824_150000` created, so a rollback leaves the schema as it
        // stood immediately before this migration ran.
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name(DELETED_UPDATED_INDEX)
                    .table(IpRecords::Table)
                    .col(IpRecords::IsDeleted)
                    .col((IpRecords::UpdatedAt, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        if manager.get_database_backend() == DatabaseBackend::Sqlite {
            return remove_sqlite_membership_timestamps(manager).await;
        }

        manager
            .alter_table(
                Table::alter()
                    .table(IpRecordGroupMemberships::Table)
                    .drop_column(IpRecordGroupMemberships::CreatedAt)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(IpRecordGroupMemberships::Table)
                    .drop_column(IpRecordGroupMemberships::UpdatedAt)
                    .to_owned(),
            )
            .await
    }
}

async fn add_sqlite_membership_timestamps(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    // The lookup index is dropped along with the old table; recreated below.
    manager
        .create_table(
            Table::create()
                .table(IpRecordGroupMembershipsRebuild::Table)
                .col(
                    ColumnDef::new(IpRecordGroupMemberships::IpRecordId)
                        .uuid()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(IpRecordGroupMemberships::GroupId)
                        .uuid()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(IpRecordGroupMemberships::CreatedAt)
                        .date_time()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(IpRecordGroupMemberships::UpdatedAt)
                        .date_time()
                        .not_null(),
                )
                .primary_key(
                    Index::create()
                        .name("pk-ip_record_group_memberships")
                        .col(IpRecordGroupMemberships::IpRecordId)
                        .col(IpRecordGroupMemberships::GroupId),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-irgm-ip_record_id")
                        .from(
                            IpRecordGroupMembershipsRebuild::Table,
                            IpRecordGroupMemberships::IpRecordId,
                        )
                        .to(IpRecords::Table, IpRecords::Id)
                        .on_delete(ForeignKeyAction::Cascade)
                        .on_update(ForeignKeyAction::Cascade),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-irgm-group_id")
                        .from(
                            IpRecordGroupMembershipsRebuild::Table,
                            IpRecordGroupMemberships::GroupId,
                        )
                        .to(IpGroups::Table, IpGroups::Id)
                        .on_delete(ForeignKeyAction::Cascade)
                        .on_update(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await?;

    manager
        .exec_stmt(
            Query::insert()
                .into_table(IpRecordGroupMembershipsRebuild::Table)
                .columns([
                    IpRecordGroupMemberships::IpRecordId,
                    IpRecordGroupMemberships::GroupId,
                    IpRecordGroupMemberships::CreatedAt,
                    IpRecordGroupMemberships::UpdatedAt,
                ])
                .select_from(
                    Query::select()
                        .columns([
                            IpRecordGroupMemberships::IpRecordId,
                            IpRecordGroupMemberships::GroupId,
                        ])
                        .expr(record_timestamp(IpRecords::CreatedAt))
                        .expr(record_timestamp(IpRecords::UpdatedAt))
                        .from(IpRecordGroupMemberships::Table)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Custom(e.to_string()))?
                .to_owned(),
        )
        .await?;

    manager
        .drop_table(
            Table::drop()
                .table(IpRecordGroupMemberships::Table)
                .to_owned(),
        )
        .await?;
    manager
        .rename_table(
            Table::rename()
                .table(
                    IpRecordGroupMembershipsRebuild::Table,
                    IpRecordGroupMemberships::Table,
                )
                .to_owned(),
        )
        .await?;

    recreate_indexes(manager).await
}

async fn remove_sqlite_membership_timestamps(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_table(
            Table::create()
                .table(IpRecordGroupMembershipsRebuild::Table)
                .col(
                    ColumnDef::new(IpRecordGroupMemberships::IpRecordId)
                        .uuid()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(IpRecordGroupMemberships::GroupId)
                        .uuid()
                        .not_null(),
                )
                .primary_key(
                    Index::create()
                        .name("pk-ip_record_group_memberships")
                        .col(IpRecordGroupMemberships::IpRecordId)
                        .col(IpRecordGroupMemberships::GroupId),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-irgm-ip_record_id")
                        .from(
                            IpRecordGroupMembershipsRebuild::Table,
                            IpRecordGroupMemberships::IpRecordId,
                        )
                        .to(IpRecords::Table, IpRecords::Id)
                        .on_delete(ForeignKeyAction::Cascade)
                        .on_update(ForeignKeyAction::Cascade),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-irgm-group_id")
                        .from(
                            IpRecordGroupMembershipsRebuild::Table,
                            IpRecordGroupMemberships::GroupId,
                        )
                        .to(IpGroups::Table, IpGroups::Id)
                        .on_delete(ForeignKeyAction::Cascade)
                        .on_update(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await?;

    manager
        .exec_stmt(
            Query::insert()
                .into_table(IpRecordGroupMembershipsRebuild::Table)
                .columns([
                    IpRecordGroupMemberships::IpRecordId,
                    IpRecordGroupMemberships::GroupId,
                ])
                .select_from(
                    Query::select()
                        .columns([
                            IpRecordGroupMemberships::IpRecordId,
                            IpRecordGroupMemberships::GroupId,
                        ])
                        .from(IpRecordGroupMemberships::Table)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Custom(e.to_string()))?
                .to_owned(),
        )
        .await?;

    manager
        .drop_table(
            Table::drop()
                .table(IpRecordGroupMemberships::Table)
                .to_owned(),
        )
        .await?;
    manager
        .rename_table(
            Table::rename()
                .table(
                    IpRecordGroupMembershipsRebuild::Table,
                    IpRecordGroupMemberships::Table,
                )
                .to_owned(),
        )
        .await?;

    manager
        .create_index(
            Index::create()
                .if_not_exists()
                .name(LOOKUP_INDEX)
                .table(IpRecordGroupMemberships::Table)
                .col(IpRecordGroupMemberships::GroupId)
                .col(IpRecordGroupMemberships::IpRecordId)
                .to_owned(),
        )
        .await
}
