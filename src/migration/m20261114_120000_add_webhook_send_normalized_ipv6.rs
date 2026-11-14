//! Adds `webhook_configs.send_normalized_ipv6` so each webhook explicitly chooses whether
//! `$target_address` and `$ip` expand to the `/48`-normalized IPv6 subnet or keep the full original
//! address.
//!
//! Default is `false` (full address preserved) so reporting/sync receivers such as AbuseIPDB
//! continue receiving exact host IPv6 addresses without breaking existing configurations, while
//! firewall execution webhooks (e.g., `launch.block.ip`) can explicitly opt in to receiving the
//! `/48`-normalized network for bare host IPv6 bans.

use sea_orm_migration::prelude::*;

/// Identifiers this migration addresses.
#[derive(DeriveIden)]
enum WebhookConfigs {
    /// The `webhook_configs` table.
    Table,
    /// Explicit per-webhook flag controlling whether `$target_address` / `$ip` emit `/48` for host IPv6 bans.
    SendNormalizedIpv6,
}

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
                        ColumnDef::new(WebhookConfigs::SendNormalizedIpv6)
                            .boolean()
                            .not_null()
                            .default(false),
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
                    .drop_column(WebhookConfigs::SendNormalizedIpv6)
                    .to_owned(),
            )
            .await
    }
}
