//! Removes inherited VARCHAR limits on fields that hold URLs, sealed secrets, and attribution.
//! SQLite already gives VARCHAR and TEXT the same affinity and imposes no VARCHAR length limit.

use super::prelude::*;
use sea_orm::DatabaseBackend;

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &'static str {
        "m20261119_120000_widen_variable_length_columns"
    }
}

#[derive(DeriveIden)]
enum WebhookConfigs {
    Table,
    SecretToken,
    TargetUrl,
    SignatureHeader,
    SignaturePrefix,
}

#[derive(DeriveIden)]
enum AuditLogs {
    Table,
    ApiKeyName,
    ApiKeyPrefix,
    ClientIp,
    TargetAddress,
    GroupNames,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        if manager.get_database_backend() == DatabaseBackend::Sqlite {
            return Ok(());
        }

        // Already TEXT: api_keys.signing_secret, api_keys.bound_ips, webhook_configs.api_key,
        // and webhook_executions.{resolved_target_url,target_address}.
        manager
            .alter_table(
                Table::alter()
                    .table(WebhookConfigs::Table)
                    .modify_column(
                        ColumnDef::new(WebhookConfigs::SecretToken)
                            .text()
                            .not_null(),
                    )
                    .modify_column(ColumnDef::new(WebhookConfigs::TargetUrl).text().not_null())
                    .modify_column(
                        ColumnDef::new(WebhookConfigs::SignatureHeader)
                            .text()
                            .null(),
                    )
                    .modify_column(
                        ColumnDef::new(WebhookConfigs::SignaturePrefix)
                            .text()
                            .null(),
                    )
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(AuditLogs::Table)
                    .modify_column(ColumnDef::new(AuditLogs::ApiKeyName).text().not_null())
                    .modify_column(ColumnDef::new(AuditLogs::ApiKeyPrefix).text().not_null())
                    .modify_column(ColumnDef::new(AuditLogs::ClientIp).text().not_null())
                    .modify_column(ColumnDef::new(AuditLogs::TargetAddress).text().null())
                    .modify_column(ColumnDef::new(AuditLogs::GroupNames).text().null())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, _manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        // Keep the widened types so a rollback preserves values written since the upgrade.
        Ok(())
    }
}
