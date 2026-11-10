//! Adds indexes to optimize lookup, status filtering, temporal queries, and retention sweeps.
//!
//! # Optimization Targets
//!
//! 1. `webhook_executions (is_success, created_at DESC)`:
//!    Retention worker (`src/retention.rs`) purges expired executions with:
//!    `delete_many().filter(is_success.eq(true)).filter(created_at.lt(threshold))`
//!    `delete_many().filter(is_success.eq(false)).filter(created_at.lt(threshold))`
//!    Additionally, `list_webhook_executions` frequently filters on `is_success` / status and
//!    orders by `created_at DESC`. Without this index, every hourly retention sweep and status
//!    query executes a full table scan over the execution history.
//!
//! 2. `webhook_executions (status_code, created_at DESC)`:
//!    `list_webhook_executions` supports filtering by specific numeric HTTP status code (e.g. 500, 404)
//!    ordered by `created_at DESC`.
//!
//! 3. `webhook_executions (event_type, created_at DESC)`:
//!    `list_webhook_executions` filters by event type (`IP_ADD`, `IP_UPDATE`, `IP_DELETE`, `TEST`)
//!    ordered by `created_at DESC`.
//!
//! 4. `ip_groups (group_type)`:
//!    `GET /api/ips` with `status=ban` or `status=white` filters groups by `group_type`
//!    (`ip_group::Entity::find().filter(ip_group::Column::GroupType.eq(group_type))`).
//!    Indexed to ensure fast equality lookup.
//!
//! 5. `audit_logs (api_key_id, timestamp DESC)`:
//!    `list_audit_logs` filters by actor API key ID and orders by `timestamp DESC`.
//!    Serves the filter and sort without temporary sorting.

use sea_orm::sea_query::{Index as SqIndex, IndexOrder};
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum WebhookExecutions {
    #[sea_orm(iden = "webhook_executions")]
    Table,
    IsSuccess,
    StatusCode,
    EventType,
    CreatedAt,
}

#[derive(DeriveIden)]
enum IpGroups {
    #[sea_orm(iden = "ip_groups")]
    Table,
    GroupType,
}

#[derive(DeriveIden)]
enum AuditLogs {
    #[sea_orm(iden = "audit_logs")]
    Table,
    ApiKeyId,
    Timestamp,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_webhook_executions_success_created")
                    .table(WebhookExecutions::Table)
                    .col(WebhookExecutions::IsSuccess)
                    .col((WebhookExecutions::CreatedAt, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_webhook_executions_status_code_created")
                    .table(WebhookExecutions::Table)
                    .col(WebhookExecutions::StatusCode)
                    .col((WebhookExecutions::CreatedAt, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_webhook_executions_event_type_created")
                    .table(WebhookExecutions::Table)
                    .col(WebhookExecutions::EventType)
                    .col((WebhookExecutions::CreatedAt, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx-ip_groups-group_type")
                    .table(IpGroups::Table)
                    .col(IpGroups::GroupType)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx_audit_logs_api_key_timestamp")
                    .table(AuditLogs::Table)
                    .col(AuditLogs::ApiKeyId)
                    .col((AuditLogs::Timestamp, IndexOrder::Desc))
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_index(
                SqIndex::drop()
                    .if_exists()
                    .name("idx_webhook_executions_success_created")
                    .table(WebhookExecutions::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                SqIndex::drop()
                    .if_exists()
                    .name("idx_webhook_executions_status_code_created")
                    .table(WebhookExecutions::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                SqIndex::drop()
                    .if_exists()
                    .name("idx_webhook_executions_event_type_created")
                    .table(WebhookExecutions::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                SqIndex::drop()
                    .if_exists()
                    .name("idx-ip_groups-group_type")
                    .table(IpGroups::Table)
                    .to_owned(),
            )
            .await?;

        manager
            .drop_index(
                SqIndex::drop()
                    .if_exists()
                    .name("idx_audit_logs_api_key_timestamp")
                    .table(AuditLogs::Table)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
