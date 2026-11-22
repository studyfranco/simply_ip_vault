//! Adds `api_keys.signing_secret`, the per-key HMAC secret used to verify `X-Signature-256`.
//!
//! Added as a separate, additive migration rather than by editing the initial schema: the initial
//! migration has already run against existing databases, so changing it would leave those databases
//! silently missing the column (`SeaORM` would never re-run an already-applied migration).
//!
//! The column is **nullable** so this migration never fails on a table that already has rows.
//! Pre-existing keys therefore carry `NULL` and cannot produce a valid signature — the middleware
//! rejects them with `401` and a message pointing at `POST /api/keys/{id}/rotate`, which mints a
//! fresh secret. That is the intended migration path for an existing deployment, and it is a
//! deliberate choice over back-filling random secrets here: a secret generated inside a migration
//! could never be shown to its owner, so it would be unusable anyway.

use super::prelude::*;

/// Identifiers this migration touches. `Table` is re-declared locally rather than imported from the
/// initial-schema migration so that module can stay private (exporting it would leak a pile of
/// undocumented public idens and trip the crate's `#![warn(missing_docs)]`). `DeriveIden` maps both
/// variants to the same `snake_case` names the initial migration used, so they address the same table.
#[derive(DeriveIden)]
enum ApiKeys {
    /// The `api_keys` table.
    Table,
    /// The `signing_secret` column added by this migration.
    SigningSecret,
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &'static str {
        "m20260729_000002_add_api_key_signing_secret"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .add_column(ColumnDef::new(ApiKeys::SigningSecret).text().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .drop_column(ApiKeys::SigningSecret)
                    .to_owned(),
            )
            .await
    }
}
