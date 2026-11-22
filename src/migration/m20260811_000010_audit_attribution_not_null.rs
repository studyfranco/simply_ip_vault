//! Makes `audit_logs.api_key_name`, `.api_key_prefix` and `.client_ip` `NOT NULL`.
//!
//! # Why the audit trail needs this and not merely a convention
//!
//! `audit_logs.api_key_id` is `ON DELETE SET NULL`, deliberately: deleting a credential must not
//! erase the record of what it did. The name and prefix are therefore not a convenience — they are
//! the **only** attribution that survives the key, a point-in-time snapshot rather than a live join.
//! A row whose `api_key_id` has been nulled by a cascade *and* whose `api_key_name` was never
//! written is an audit entry that records an action with no actor at all.
//!
//! Nothing in the service produces such a row today: all twenty `create_audit_log` call sites pass a
//! key and a resolved client address, because every audited route runs behind `auth_middleware`. The
//! columns were nullable only because the original schema declared them so. That gap between "cannot
//! happen" and "cannot be represented" is what this migration closes — and it closes it at the layer
//! that holds for a writer which is not this application, which is the same argument `RBAC_MODEL.md`
//! §5 makes about the master marker.
//!
//! # Historical rows
//!
//! Pre-existing rows may legitimately hold NULLs, so each column is backfilled before the constraint
//! is applied. The fallbacks are deliberately *not* plausible values: `"(unknown)"` cannot be
//! confused with a real key name, prefix or address, so a reader can tell "we did not record this"
//! apart from "this is what was recorded". Silently substituting something that looks real would be
//! worse than the NULL it replaces.
//!
//! # Why SQLite needs a table rebuild
//!
//! SQLite has no `ALTER TABLE … ALTER COLUMN`. Tightening a column's nullability there means
//! creating the table afresh, copying the rows, dropping the original and renaming — the documented
//! twelve-step procedure. PostgreSQL and MySQL take `ALTER COLUMN … SET NOT NULL` directly.
//!
//! The replacement table is built with `SeaORM`'s schema builder rather than hand-written DDL, so its
//! column types are byte-for-byte what the original migration produced. Hand-writing the `CREATE
//! TABLE` would mean guessing how `SeaORM` renders `uuid` and `date_time` on each backend, and a near
//! miss would silently change a column's affinity while every test still passed.

use super::prelude::*;
use sea_orm::DatabaseBackend;

/// The value written where attribution was never recorded.
///
/// Chosen to be unmistakably not a key name, a prefix, or an address. See the module header.
const UNRECORDED: &str = "(unknown)";

/// The three columns this migration constrains.
const ATTRIBUTION_COLUMNS: [AuditLogs; 3] = [
    AuditLogs::ApiKeyName,
    AuditLogs::ApiKeyPrefix,
    AuditLogs::ClientIp,
];

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &'static str {
        "m20260811_000010_audit_attribution_not_null"
    }
}

/// `audit_logs`, and the transient name its SQLite rebuild lands in.
#[derive(Clone, Copy, DeriveIden)]
enum AuditLogs {
    Table,
    Id,
    ApiKeyId,
    ApiKeyName,
    ApiKeyPrefix,
    ClientIp,
    Action,
    TargetAddress,
    GroupNames,
    Details,
    Timestamp,
}

#[derive(DeriveIden)]
enum ApiKeys {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum AuditLogsRebuild {
    #[sea_orm(iden = "audit_logs_rebuild")]
    Table,
}

/// The table definition, with the three attribution columns nullable or not as asked.
///
/// One function for both the rebuild and the `down` path so the two cannot describe different
/// tables — the failure mode of a hand-maintained pair being that `down` quietly drops a column.
fn table_definition(table: TableRef, attribution_not_null: bool) -> TableCreateStatement {
    let attribution = |name: AuditLogs| {
        let mut col = ColumnDef::new(name);
        col.string();
        if attribution_not_null {
            col.not_null();
        }
        col.clone()
    };

    let mut stmt = Table::create();
    stmt.table(table)
        .col(
            ColumnDef::new(AuditLogs::Id)
                .uuid()
                .not_null()
                .primary_key(),
        )
        .col(ColumnDef::new(AuditLogs::ApiKeyId).uuid())
        .col(attribution(AuditLogs::ApiKeyName))
        .col(attribution(AuditLogs::ApiKeyPrefix))
        .col(attribution(AuditLogs::ClientIp))
        .col(ColumnDef::new(AuditLogs::Action).string().not_null())
        .col(ColumnDef::new(AuditLogs::TargetAddress).string())
        .col(ColumnDef::new(AuditLogs::GroupNames).string())
        .col(ColumnDef::new(AuditLogs::Details).text())
        .col(ColumnDef::new(AuditLogs::Timestamp).date_time().not_null())
        .foreign_key(
            ForeignKey::create()
                .name("fk-audit_logs-api_key_id")
                .from(AuditLogs::Table, AuditLogs::ApiKeyId)
                .to(ApiKeys::Table, ApiKeys::Id)
                // Preserved exactly. Changing this to CASCADE would let an attacker erase their own
                // trail by deleting their key, which is the whole reason the denormalized columns
                // above exist.
                .on_delete(ForeignKeyAction::SetNull)
                .on_update(ForeignKeyAction::NoAction),
        );
    stmt.clone()
}

/// The two indexes the initial schema put on `audit_logs`, recreated after a rebuild.
///
/// A rebuild drops them with the old table. Losing them would turn every audit listing into a table
/// scan — a silent performance regression that no test would notice.
async fn recreate_indexes(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    manager
        .create_index(
            Index::create()
                .name("idx-audit_logs-action")
                .table(AuditLogs::Table)
                .col(AuditLogs::Action)
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .name("idx-audit_logs-timestamp")
                .table(AuditLogs::Table)
                .col(AuditLogs::Timestamp)
                .to_owned(),
        )
        .await
}

/// Rebuilds `audit_logs` under a new definition, carrying every row across.
///
/// The column list is written out explicitly on both sides of the `INSERT … SELECT` rather than
/// relying on `SELECT *`. Positional copying is what turns a future column reorder into silent data
/// corruption — names moving into the address column, with every type still checking out.
async fn rebuild(manager: &SchemaManager<'_>, attribution_not_null: bool) -> Result<(), DbErr> {
    manager
        .create_table(table_definition(
            AuditLogsRebuild::Table.into_table_ref(),
            attribution_not_null,
        ))
        .await?;

    let columns = [
        AuditLogs::Id,
        AuditLogs::ApiKeyId,
        AuditLogs::ApiKeyName,
        AuditLogs::ApiKeyPrefix,
        AuditLogs::ClientIp,
        AuditLogs::Action,
        AuditLogs::TargetAddress,
        AuditLogs::GroupNames,
        AuditLogs::Details,
        AuditLogs::Timestamp,
    ];
    manager
        .exec_stmt(
            Query::insert()
                .into_table(AuditLogsRebuild::Table)
                .columns(columns)
                .select_from(
                    Query::select()
                        .columns(columns)
                        .from(AuditLogs::Table)
                        .to_owned(),
                )
                .map_err(|e| DbErr::Custom(e.to_string()))?
                .to_owned(),
        )
        .await?;

    manager
        .drop_table(Table::drop().table(AuditLogs::Table).to_owned())
        .await?;
    manager
        .rename_table(
            Table::rename()
                .table(AuditLogsRebuild::Table, AuditLogs::Table)
                .to_owned(),
        )
        .await?;

    recreate_indexes(manager).await
}

/// Replaces NULL attribution with [`UNRECORDED`] so the constraint can be applied to old rows.
async fn backfill(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    for column in ATTRIBUTION_COLUMNS {
        manager
            .exec_stmt(
                Query::update()
                    .table(AuditLogs::Table)
                    .value(column, UNRECORDED)
                    .and_where(Expr::col(column).is_null())
                    .to_owned(),
            )
            .await?;
    }
    Ok(())
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        // Order matters: the constraint cannot be applied while a single NULL remains, and on the
        // rebuild path the copy would fail rather than the ALTER.
        backfill(manager).await?;

        if manager.get_database_backend() == DatabaseBackend::Sqlite {
            return rebuild(manager, true).await;
        }

        for column in ATTRIBUTION_COLUMNS {
            manager
                .alter_table(
                    Table::alter()
                        .table(AuditLogs::Table)
                        .modify_column(ColumnDef::new(column).string().not_null())
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        // Relaxing a constraint needs no backfill; the rows already satisfy the looser shape.
        if manager.get_database_backend() == DatabaseBackend::Sqlite {
            return rebuild(manager, false).await;
        }

        for column in ATTRIBUTION_COLUMNS {
            manager
                .alter_table(
                    Table::alter()
                        .table(AuditLogs::Table)
                        .modify_column(ColumnDef::new(column).string().null())
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fallback must not be mistakable for a real value.
    ///
    /// A backfill that wrote `"system"` or `"127.0.0.1"` would be indistinguishable from a genuine
    /// record, which is a worse outcome than the NULL it replaces: the reader loses the ability to
    /// tell "not recorded" from "recorded as this".
    #[test]
    fn the_backfill_value_cannot_be_confused_with_a_real_one() {
        assert!(
            UNRECORDED.starts_with('('),
            "{UNRECORDED} must not look like a key name or address"
        );
        assert!(
            !UNRECORDED
                .chars()
                .any(|c| c.is_ascii_alphanumeric() && c.is_uppercase())
        );
        assert!(
            UNRECORDED.parse::<std::net::IpAddr>().is_err(),
            "must not parse as an address"
        );
    }

    /// Both table definitions must agree on everything except the three columns under test.
    ///
    /// Guards the `down` path specifically: a hand-maintained pair drifts, and the direction it
    /// drifts in is a dropped column nobody notices until a rollback loses data.
    #[test]
    fn the_two_definitions_differ_only_in_nullability() {
        let strict = table_definition(AuditLogs::Table.into_table_ref(), true)
            .to_string(sea_orm::sea_query::SqliteQueryBuilder);
        let loose = table_definition(AuditLogs::Table.into_table_ref(), false)
            .to_string(sea_orm::sea_query::SqliteQueryBuilder);

        assert_ne!(strict, loose, "the flag must actually change the DDL");
        assert_eq!(
            strict.matches("NOT NULL").count(),
            loose.matches("NOT NULL").count() + ATTRIBUTION_COLUMNS.len(),
            "exactly the three attribution columns gain NOT NULL:\n  {strict}\n  {loose}"
        );
        for column in ATTRIBUTION_COLUMNS {
            let column = column.unquoted();
            assert!(
                strict.contains(column),
                "{column} missing from the strict definition"
            );
            assert!(
                loose.contains(column),
                "{column} missing from the loose definition"
            );
        }
        // The cascade that makes the denormalized columns necessary must survive a rebuild.
        assert!(
            strict.contains("SET NULL"),
            "the ON DELETE SET NULL cascade is preserved"
        );
    }
}
