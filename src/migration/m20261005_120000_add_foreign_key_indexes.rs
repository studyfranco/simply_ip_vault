//! Indexes every foreign-key column that did not already lead an index.
//!
//! SQLite does not create an index for the child side of a foreign key. Without one, deleting a
//! parent row has to scan the child table to find the rows its cascade or `SET NULL` must touch:
//! deleting an API key scans all of `audit_logs` to null out `api_key_id`, and deleting an IP group
//! scans `webhook_configs` for its cascade. Both tables grow without bound, so both scans grow with
//! them.
//!
//! Columns already covered as the leading column of an index are not listed: the
//! `api_key_group_permissions` pair, `ip_record_group_memberships.ip_record_id` (leading column of
//! its primary key), `ip_record_group_memberships.group_id` (`idx_group_memberships_lookup`), and
//! `webhook_executions.webhook_id`.
//!
//! Additive and idempotent (`IF NOT EXISTS`). A deployment that created one of these by hand first
//! is not blocked from applying it.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum AuditLogs {
    Table,
    ApiKeyId,
}

#[derive(DeriveIden)]
enum WebhookConfigs {
    Table,
    GroupId,
}

const AUDIT_LOGS_API_KEY_INDEX: &str = "idx-audit_logs-api_key_id";
const WEBHOOK_CONFIGS_GROUP_INDEX: &str = "idx-webhook_configs-group_id";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name(AUDIT_LOGS_API_KEY_INDEX)
                    .table(AuditLogs::Table)
                    .col(AuditLogs::ApiKeyId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                Index::create()
                    .if_not_exists()
                    .name(WEBHOOK_CONFIGS_GROUP_INDEX)
                    .table(WebhookConfigs::Table)
                    .col(WebhookConfigs::GroupId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(Index::drop().name(AUDIT_LOGS_API_KEY_INDEX).table(AuditLogs::Table).to_owned())
            .await?;
        manager
            .drop_index(Index::drop().name(WEBHOOK_CONFIGS_GROUP_INDEX).table(WebhookConfigs::Table).to_owned())
            .await
    }
}
