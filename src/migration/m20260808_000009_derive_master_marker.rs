//! Replaces the hand-maintained `api_keys.master_marker` with one the **database engine derives**
//! from `is_master`, so that `RBAC_MODEL.md` §5 — "enforced by a database constraint rather than by
//! application logic alone" — is actually true.
//!
//! # What `m20260807_000007_add_api_key_master_marker` got wrong
//!
//! That migration added `master_marker VARCHAR(16) NULL` under a plain unique index and left
//! `bootstrap_master_key` responsible for writing `'master'` into it. The unique index is real, but
//! it constrains the *marker*, not `is_master` — and NULLs do not collide in a unique index on any
//! supported engine. So a writer that sets `is_master = true` and simply omits the marker is
//! accepted, and the database now holds two masters. That is not a hypothetical; it was demonstrated
//! against a live database built from those migrations:
//!
//! ```sql
//! INSERT INTO api_keys (id, name, key_hash, prefix, is_master, can_manage_keys,
//!                       can_manage_webhooks, can_create_groups, created_at, updated_at)
//! VALUES (x'…', 'Usurper', 'hash', 'usurper1', 1, 1, 1, 1, '…', '…');
//! -- Ok(ExecResult { changes: 1 })  →  2 rows now have is_master = true
//! ```
//!
//! The constraint held only for a writer that chose to cooperate, which is the definition of
//! "application logic alone". Every test that existed passed, because every test supplied the marker.
//!
//! # Why a generated column, and why still not a partial index
//!
//! The direct spelling remains unavailable: `CREATE UNIQUE INDEX … ON api_keys (is_master) WHERE
//! is_master` needs partial indexes, which **MySQL does not have**, and `Cargo.toml` enables the
//! MySQL driver. The marker column is still the portable substitute. What changes is who writes it.
//!
//! `master_marker INTEGER GENERATED ALWAYS AS (CASE WHEN is_master THEN 1 ELSE NULL END)` cannot be
//! assigned by anyone: every supported engine rejects an `INSERT` or `UPDATE` that targets a
//! generated column. The marker is therefore a pure function of `is_master`, evaluated by the
//! engine, and the unique index over it means a second `is_master = true` row is refused no matter
//! which client, migration, or `psql` session attempts it. The bypass above becomes a constraint
//! violation rather than a successful write.
//!
//! # Storage class is pinned per backend, and the pairing is unit-tested
//!
//! The one dialect split is `STORED` vs `VIRTUAL`:
//!
//! - **PostgreSQL** accepts only `STORED`; `VIRTUAL` arrived in PostgreSQL 18 and the floor here is
//!   older than that.
//! - **SQLite** accepts only `VIRTUAL` for a column added through `ALTER TABLE` — a `STORED` column
//!   would have to be materialized for existing rows, which `ALTER TABLE ADD COLUMN` cannot do.
//! - **MySQL** accepts either; `VIRTUAL` is chosen because it avoids rewriting the table.
//!
//! Getting that pairing backwards produces a migration that works on the developer's SQLite and
//! fails on the operator's PostgreSQL at startup, so [`tests`] pins each backend's storage class.
//!
//! # A pre-existing second master stops the migration
//!
//! Checked before anything is altered, so an inconsistent database is left exactly as found rather
//! than half-migrated. The error names every offending row — id, name, and prefix — because a
//! database with two masters has no correct interpretation this migration could pick: which key is
//! legitimate is an operator's judgement. Failing loudly is recoverable in one `UPDATE`, and the
//! message says which one to run. (Creating the unique index would fail on its own anyway; the
//! explicit check exists to fail with an actionable message instead of a driver's constraint error.)

use super::prelude::*;
use sea_orm::{ConnectionTrait, DatabaseBackend};

/// The unique index that does the enforcing. Same name `m20260807_000007…` used, so operators and
/// the §7 schema assertions keep looking at one index across the two migrations.
const MARKER_INDEX: &str = "idx-api_keys-master_marker";

/// Identifiers this migration touches, re-declared locally so the initial-schema module stays
/// private. `DeriveIden` maps the variants to the same `snake_case` names.
#[derive(DeriveIden)]
enum ApiKeys {
    /// The `api_keys` table.
    Table,
    Id,
    Name,
    Prefix,
    IsMaster,
    /// The marker column — dropped as a plain column here, re-added as a generated one.
    MasterMarker,
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &'static str {
        "m20260808_000009_derive_master_marker"
    }
}

impl Migration {
    fn add_marker_column(backend: DatabaseBackend) -> TableAlterStatement {
        let storage = match backend {
            DatabaseBackend::Postgres => "STORED",
            _ => "VIRTUAL",
        };
        Table::alter()
            .table(ApiKeys::Table)
            .add_column(
                ColumnDef::new(ApiKeys::MasterMarker)
                    .integer()
                    .extra(format!(
                        "GENERATED ALWAYS AS (CASE WHEN is_master THEN 1 ELSE NULL END) {storage}"
                    )),
            )
            .to_owned()
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        let db = manager.get_connection();
        let backend = db.get_database_backend();

        // Before any DDL: refuse to migrate a database that already holds more than one master.
        let masters = db
            .query_all(
                &*Query::select()
                    .columns([ApiKeys::Id, ApiKeys::Name, ApiKeys::Prefix])
                    .from(ApiKeys::Table)
                    .and_where(Expr::col(ApiKeys::IsMaster).eq(true)),
            )
            .await?;
        if masters.len() > 1 {
            let rows: Vec<String> = masters
                .iter()
                .map(|row| {
                    let id = row
                        .try_get::<uuid::Uuid>("", "id")
                        .map_or_else(|_| "<unreadable id>".to_owned(), |id| id.to_string());
                    let name = row
                        .try_get::<String>("", "name")
                        .unwrap_or_else(|_| "<unreadable>".into());
                    let prefix = row
                        .try_get::<String>("", "prefix")
                        .unwrap_or_else(|_| "<unreadable>".into());
                    format!("id={id} name={name:?} prefix={prefix}")
                })
                .collect();
            return Err(DbErr::Custom(format!(
                "Refusing to migrate: {} rows have is_master = true, but RBAC_MODEL.md §5 requires \
                 exactly one. This migration makes the marker engine-derived, so the unique index \
                 would reject the extra rows and leave the schema half-applied. Offending rows:\n  \
                 {}\nDecide which key is the Master and set is_master to false on the \
                 others, then restart.",
                masters.len(),
                rows.join("\n  ")
            )));
        }

        // Index first: SQLite refuses `DROP COLUMN` on a column that participates in an index, and
        // the ordering is correct on the other two engines regardless.
        manager
            .drop_index(
                Index::drop()
                    .name(MARKER_INDEX)
                    .table(ApiKeys::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .drop_column(ApiKeys::MasterMarker)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(Self::add_marker_column(backend))
            .await?;

        // No backfill: the engine evaluates the expression for every existing row the moment the
        // column exists. That is the difference this migration is about — there is nothing left for
        // application code to keep in step.
        manager
            .create_index(
                Index::create()
                    .name(MARKER_INDEX)
                    .table(ApiKeys::Table)
                    .col(ApiKeys::MasterMarker)
                    .unique()
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .drop_index(
                Index::drop()
                    .name(MARKER_INDEX)
                    .table(ApiKeys::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .drop_column(ApiKeys::MasterMarker)
                    .to_owned(),
            )
            .await?;

        // Restore the plain column `m20260807_000007…` left behind, so that migration's own `down`
        // still has something to drop. Re-populated from `is_master` for the same reason the
        // generated column needed no backfill — the value is a function of it either way.
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .add_column(ColumnDef::new(ApiKeys::MasterMarker).string_len(16).null())
                    .to_owned(),
            )
            .await?;
        manager
            .exec_stmt(
                Query::update()
                    .table(ApiKeys::Table)
                    .value(ApiKeys::MasterMarker, "master")
                    .and_where(Expr::col(ApiKeys::IsMaster).eq(true))
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .name(MARKER_INDEX)
                    .table(ApiKeys::Table)
                    .col(ApiKeys::MasterMarker)
                    .unique()
                    .to_owned(),
            )
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// PostgreSQL is the one backend that cannot take `VIRTUAL`, and SQLite the one that cannot take
    /// `STORED` on a column added through `ALTER TABLE`. Getting the pair backwards fails only
    /// against a real server of the affected engine, which the unit suite never starts — so the
    /// dialect choice is pinned here rather than discovered at an operator's startup.
    #[test]
    fn each_backend_gets_the_only_storage_class_it_accepts() {
        assert!(
            Migration::add_marker_column(DatabaseBackend::Postgres)
                .to_string(PostgresQueryBuilder)
                .ends_with("STORED"),
            "PostgreSQL supports only STORED generated columns before version 18"
        );
        assert!(
            Migration::add_marker_column(DatabaseBackend::Sqlite)
                .to_string(SqliteQueryBuilder)
                .ends_with("VIRTUAL"),
            "SQLite supports only VIRTUAL for a generated column added via ALTER TABLE"
        );
        assert!(
            Migration::add_marker_column(DatabaseBackend::MySql)
                .to_string(MysqlQueryBuilder)
                .ends_with("VIRTUAL"),
            "MySQL accepts both; VIRTUAL avoids rewriting the table"
        );
    }

    /// The marker must be *derived*, never assignable. A literal default, or any expression that does
    /// not read `is_master`, reintroduces exactly the bypass this migration exists to close.
    #[test]
    fn the_marker_is_generated_from_is_master_on_every_backend() {
        for backend in [
            DatabaseBackend::Postgres,
            DatabaseBackend::Sqlite,
            DatabaseBackend::MySql,
        ] {
            let ddl =
                sea_orm::StatementBuilder::build(&Migration::add_marker_column(backend), &backend)
                    .sql;
            assert!(
                ddl.contains("GENERATED ALWAYS AS") && ddl.contains("is_master"),
                "{backend:?} marker must be generated from is_master, got: {ddl}"
            );
            assert!(
                ddl.contains("ELSE NULL"),
                "{backend:?} marker must be NULL for non-masters, or every non-master row would \
                 collide on the unique index: {ddl}"
            );
        }
    }
}
