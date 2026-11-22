//! Adds `api_keys.master_marker` as an **application-maintained** column. Superseded by
//! `m20260808_000009_derive_master_marker`, which is what actually enforces `RBAC_MODEL.md` §5.
//!
//! # This migration did not do what it claimed
//!
//! Its original text said this column gave the database-level guarantee that exactly one Master key
//! exists. It did not, and the correction is left here rather than rewritten away because the
//! reasoning below is the exact shape of the mistake.
//!
//! The unique index is real, but it constrains `master_marker`, not `is_master`, and the two were
//! kept in step by `bootstrap_master_key` — application logic. NULLs do not collide in a unique
//! index, so a writer that sets `is_master = true` and omits the marker is accepted, and the
//! database then holds two masters. Demonstrated live, not inferred:
//!
//! ```sql
//! INSERT INTO api_keys (id, name, key_hash, prefix, is_master, can_manage_keys,
//!                       can_manage_webhooks, can_create_groups, created_at, updated_at)
//! VALUES (x'…', 'Usurper', 'hash', 'usurper1', 1, 1, 1, 1, '…', '…');
//! -- accepted; 2 rows now have is_master = true
//! ```
//!
//! §5 says "enforced by a database constraint rather than by application logic alone", and a marker
//! the application must remember to populate is application logic in a schema costume. The fix is to
//! let the engine derive the marker from `is_master` — see `m20260808_000009_derive_master_marker`,
//! which drops this column and re-adds it as `GENERATED ALWAYS AS (…)`.
//!
//! The historical behavior is preserved for databases that have yet to run this migration.
//!
//! # Why a marker column and not a partial unique index
//!
//! Still correct, and still the reason 000009 keeps a marker column. The obvious spelling is
//! `CREATE UNIQUE INDEX ... ON api_keys (is_master) WHERE is_master = true`. PostgreSQL and SQLite
//! both support that; **MySQL does not**, and `AGENT.MD` requires the data layer to stay SQL-agnostic
//! across all three drivers this crate enables. The portable substitute is a nullable column carrying
//! a single non-null value under a plain unique index. Null values do not collide in a unique index on
//! any of the three engines, so every non-master row is free to leave it `NULL` while at most one row
//! may ever hold the marker.
//!
//! What 000009 changes is not the shape but the *writer*: the marker becomes a generated column, and
//! no client can set or omit it.
//!
//! # A pre-existing second master stops the migration
//!
//! If the database already contains more than one master, this migration fails with an error naming
//! the offending ids rather than picking a winner. Demoting a key silently would strip an operator's
//! authority without asking; failing loudly is recoverable in one `UPDATE`, and the message says
//! which one to run. A single master (the overwhelmingly common case) backfills silently.

use super::prelude::*;
use sea_orm::ConnectionTrait;

/// The one non-null value this migration's `master_marker` ever carried. Local to this module: the
/// API-side constant it once mirrored has been deleted along with every write path, because the
/// column is generated from `is_master` after `m20260808_000009_derive_master_marker` and nothing may
/// assign it. An already-applied migration must keep describing what it actually did, so the literal
/// stays here rather than being re-pointed at anything current.
const MASTER_MARKER: &str = "master";

/// Identifiers this migration touches. `Table` is re-declared locally rather than imported from the
/// initial-schema migration so that module can stay private; `DeriveIden` maps the variants to the
/// same `snake_case` names, so they address the same table.
#[derive(DeriveIden)]
enum ApiKeys {
    /// The `api_keys` table.
    Table,
    Id,
    IsMaster,
    /// The uniqueness marker: `'master'` on the Master key, `NULL` on every other key.
    MasterMarker,
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &'static str {
        "m20260807_000007_add_api_key_master_marker"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        let db = manager.get_connection();

        // Checked *before* the column is added, so a database with two masters is left exactly as it
        // was found rather than half-migrated. `is_master` is a boolean on every backend, and
        // comparing against `true` rather than `1` keeps PostgreSQL happy without a cast.
        let duplicates = db
            .query_all(
                &*Query::select()
                    .columns([ApiKeys::Id])
                    .from(ApiKeys::Table)
                    .and_where(Expr::col(ApiKeys::IsMaster).eq(true)),
            )
            .await?;
        if duplicates.len() > 1 {
            let ids: Vec<String> = duplicates
                .iter()
                .map(|row| {
                    row.try_get::<uuid::Uuid>("", "id")
                        .map_or_else(|_| "<unreadable id>".to_owned(), |id| id.to_string())
                })
                .collect();
            return Err(DbErr::Custom(format!(
                "Refusing to migrate: {} keys have is_master = true ({}), but RBAC_MODEL.md §5 \
                 requires exactly one. Decide which key is the Master and set is_master to false \
                 on the others, then restart.",
                duplicates.len(),
                ids.join(", ")
            )));
        }

        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    // `string_len(16)` rather than a bare `string()`: MySQL cannot index a `TEXT`
                    // column without a prefix length, and a short `VARCHAR` sidesteps the InnoDB key
                    // length ceiling entirely. The value is a fixed 6-character literal.
                    .add_column(ColumnDef::new(ApiKeys::MasterMarker).string_len(16).null())
                    .to_owned(),
            )
            .await?;

        // Backfill before the index exists. Guaranteed to touch at most one row by the check above.
        manager
            .exec_stmt(
                Query::update()
                    .table(ApiKeys::Table)
                    .value(ApiKeys::MasterMarker, MASTER_MARKER)
                    .and_where(Expr::col(ApiKeys::IsMaster).eq(true))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-api_keys-master_marker")
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
                    .name("idx-api_keys-master_marker")
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
            .await
    }
}
