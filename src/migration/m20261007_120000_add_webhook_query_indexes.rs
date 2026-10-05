//! Covering indexes for the webhook read paths, and removal of the single-column indexes they
//! supersede.
//!
//! - `webhook_configs (group_id, is_active)`: dispatch selects a group's active webhooks. The
//!   composite leads with `group_id`, so it also serves every lookup the single-column index did.
//! - `webhook_executions (webhook_id, created_at DESC)`: a webhook's delivery history, newest
//!   first, without a temp b-tree sort. Also the foreign-key child index for `webhook_id`.
//!
//! Both superseded single-column indexes are dropped in the same migration. Keeping them would
//! cost a second index write on every insert for no query the composite cannot answer.

use sea_orm::sea_query::{Index as SqIndex, IndexOrder};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum WebhookConfigs {
    #[sea_orm(iden = "webhook_configs")]
    Table,
    GroupId,
    IsActive,
}

#[derive(DeriveIden)]
enum WebhookExecutions {
    #[sea_orm(iden = "webhook_executions")]
    Table,
    WebhookId,
    CreatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_webhooks_group_active")
                    .table(WebhookConfigs::Table)
                    .col(WebhookConfigs::GroupId)
                    .col(WebhookConfigs::IsActive)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                SqIndex::drop()
                    .if_exists()
                    .name("idx-webhook_configs-group_id")
                    .table(WebhookConfigs::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_webhook_exec_lookup")
                    .table(WebhookExecutions::Table)
                    .col(WebhookExecutions::WebhookId)
                    .col((WebhookExecutions::CreatedAt, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(
                SqIndex::drop()
                    .if_exists()
                    .name("idx-webhook_executions-webhook_id")
                    .table(WebhookExecutions::Table)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Restores the single-column indexes this migration superseded.
        manager
            .drop_index(SqIndex::drop().if_exists().name("idx_webhook_exec_lookup").table(WebhookExecutions::Table).to_owned())
            .await?;
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx-webhook_executions-webhook_id")
                    .table(WebhookExecutions::Table)
                    .col(WebhookExecutions::WebhookId)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_index(SqIndex::drop().if_exists().name("idx_webhooks_group_active").table(WebhookConfigs::Table).to_owned())
            .await?;
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx-webhook_configs-group_id")
                    .table(WebhookConfigs::Table)
                    .col(WebhookConfigs::GroupId)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }
}
