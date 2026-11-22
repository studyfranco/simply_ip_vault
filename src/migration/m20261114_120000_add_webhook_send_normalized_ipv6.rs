//! Adds `webhook_configs.send_normalized_ipv6` so each webhook explicitly chooses whether
//! `$target_address` and `$ip` expand to the `/48`-normalized IPv6 subnet or keep the full original
//! address.
//!
//! Default is `false` (full address preserved) so reporting/sync receivers such as `AbuseIPDB`
//! continue receiving exact host IPv6 addresses without breaking existing configurations, while
//! firewall execution webhooks (e.g., `launch.block.ip`) can explicitly opt in to receiving the
//! `/48`-normalized network for bare host IPv6 bans.

use super::prelude::*;

/// Identifiers this migration addresses.
#[derive(DeriveIden)]
enum WebhookConfigs {
    /// The `webhook_configs` table.
    Table,
    /// Explicit per-webhook flag controlling whether `$target_address` / `$ip` emit `/48` for host IPv6 bans.
    SendNormalizedIpv6,
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &'static str {
        "m20261114_120000_add_webhook_send_normalized_ipv6"
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
                        ColumnDef::new(WebhookConfigs::SendNormalizedIpv6)
                            .boolean()
                            .not_null()
                            .default(false),
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
                    .drop_column(WebhookConfigs::SendNormalizedIpv6)
                    .to_owned(),
            )
            .await
    }
}
