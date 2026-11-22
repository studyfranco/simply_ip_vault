//! Adds `webhook_configs.signature_mode`, selecting how outbound dispatches are signed.
//!
//! Additive and defaulted to `'BODY_ONLY'` — the exact behaviour every existing webhook already has
//! — so applying this migration changes nothing about how current webhooks are delivered. Opting a
//! webhook into `'CANONICAL_V1'` is an explicit, per-row decision, because it changes both the signed
//! message and the set of headers sent, which a third-party receiver would reject if flipped
//! underneath it.
//!
//! `NOT NULL` with a default (rather than nullable) keeps the entity a plain `String`: there is no
//! meaningful "unset" mode, and every dispatch must pick one.

use super::prelude::*;

/// Identifiers this migration touches. `Table` is re-declared locally rather than imported from the
/// initial-schema migration so that module can stay private (exporting it would leak a pile of
/// undocumented public idens and trip the crate's `#![warn(missing_docs)]`). `DeriveIden` maps both
/// variants to the same `snake_case` names the initial migration used, so they address the same table.
#[derive(DeriveIden)]
enum WebhookConfigs {
    /// The `webhook_configs` table.
    Table,
    /// The `signature_mode` column added by this migration.
    SignatureMode,
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &'static str {
        "m20260730_000003_add_webhook_signature_mode"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(WebhookConfigs::Table)
                    .add_column(
                        ColumnDef::new(WebhookConfigs::SignatureMode)
                            .text()
                            .not_null()
                            .default("BODY_ONLY"),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(WebhookConfigs::Table)
                    .drop_column(WebhookConfigs::SignatureMode)
                    .to_owned(),
            )
            .await
    }
}
