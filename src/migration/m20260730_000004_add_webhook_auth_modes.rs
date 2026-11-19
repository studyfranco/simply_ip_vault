//! Generalizes `webhook_configs.signature_mode` into a four-valued `auth_mode`, and adds the two
//! columns the new modes need: `api_key` (sent as `X-API-Key`) and `hmac_template` (the dynamic
//! canonical string).
//!
//! `signature_mode` only ever described *how to sign*; it could not express "authenticate with an
//! API key and no signature" or "send nothing at all", both of which real third-party receivers
//! want. `auth_mode` is a strict superset — its `BODY_ONLY` and `CANONICAL_V1` values mean exactly
//! what `signature_mode`'s did — so this replaces the column rather than adding a second, partly
//! redundant one that could contradict it.
//!
//! The replacement is add → backfill → drop, not a rename, for one reason: the new column's default
//! is `'CANONICAL_V1'` and no portable `ALTER TABLE` can change an existing column's default. The
//! backfill is what keeps that default from rewriting history — every row already in the table keeps
//! the mode it was dispatching under, and only *newly inserted* rows pick up the new default.
//!
//! `api_key` and `hmac_template` are nullable: they are meaningless in `NONE` mode, and
//! `hmac_template` is meaningless in every mode except `CANONICAL_V1`. `NULL` reads back as "use the
//! built-in default template", so existing `CANONICAL_V1` rows keep signing the exact same bytes.

use sea_orm_migration::prelude::*;

/// Identifiers this migration touches. `Table` and `SignatureMode` are re-declared locally rather
/// than imported from the migrations that created them, so those modules can stay private
/// (exporting them would leak a pile of undocumented public idens and trip the crate's
/// `#![warn(missing_docs)]`). `DeriveIden` maps every variant to the same `snake_case` name the
/// earlier migrations used, so they address the same table and columns.
#[derive(DeriveIden)]
enum WebhookConfigs {
    /// The `webhook_configs` table.
    Table,
    /// The `signature_mode` column, superseded and dropped by this migration.
    SignatureMode,
    /// The `auth_mode` column added by this migration.
    AuthMode,
    /// The `api_key` column added by this migration.
    ApiKey,
    /// The `hmac_template` column added by this migration.
    HmacTemplate,
}

/// The default canonical string, mirroring [`crate::entities::webhook_config::DEFAULT_HMAC_TEMPLATE`].
///
/// Duplicated as a literal rather than referenced, because a migration must keep producing the
/// schema it produced on the day it was written even if the entity's default is changed later.
/// The `\n` here are two-character escape sequences in the stored text, expanded at dispatch time —
/// see the entity's `DEFAULT_HMAC_TEMPLATE` docs for why.
const DEFAULT_HMAC_TEMPLATE: &str = r"{method}\n{path}\n{timestamp}\n{body}";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(WebhookConfigs::Table)
                    .add_column(
                        ColumnDef::new(WebhookConfigs::AuthMode)
                            .text()
                            .not_null()
                            .default("CANONICAL_V1"),
                    )
                    .to_owned(),
            )
            .await?;

        // Carry every existing row across verbatim. Without this the `CANONICAL_V1` default would
        // silently re-sign existing `BODY_ONLY` webhooks under a different scheme, which their
        // receivers would reject on the very next event.
        manager
            .exec_stmt(
                Query::update()
                    .table(WebhookConfigs::Table)
                    .value(
                        WebhookConfigs::AuthMode,
                        Expr::col(WebhookConfigs::SignatureMode),
                    )
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(WebhookConfigs::Table)
                    .drop_column(WebhookConfigs::SignatureMode)
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(WebhookConfigs::Table)
                    .add_column(ColumnDef::new(WebhookConfigs::ApiKey).text().null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(WebhookConfigs::Table)
                    .add_column(
                        ColumnDef::new(WebhookConfigs::HmacTemplate)
                            .text()
                            .null()
                            .default(DEFAULT_HMAC_TEMPLATE),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
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
            .await?;

        // Only the two modes `signature_mode` can express survive the round trip; `API_KEY_ONLY`
        // and `NONE` have no representation there and fall back to the restored column's
        // `BODY_ONLY` default, which is the conservative choice (it signs, rather than silently
        // dropping authentication).
        for mode in ["BODY_ONLY", "CANONICAL_V1"] {
            manager
                .exec_stmt(
                    Query::update()
                        .table(WebhookConfigs::Table)
                        .value(WebhookConfigs::SignatureMode, mode)
                        .and_where(Expr::col(WebhookConfigs::AuthMode).eq(mode))
                        .to_owned(),
                )
                .await?;
        }

        for column in [
            WebhookConfigs::HmacTemplate,
            WebhookConfigs::ApiKey,
            WebhookConfigs::AuthMode,
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(WebhookConfigs::Table)
                        .drop_column(column)
                        .to_owned(),
                )
                .await?;
        }

        Ok(())
    }
}
