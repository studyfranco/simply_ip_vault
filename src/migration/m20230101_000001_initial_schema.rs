use sea_orm_migration::prelude::*;

#[derive(DeriveIden)]
pub enum IpRecords {
    Table,
    Id,
    TargetAddress,
    Cause,
    IsLocked,
    CreatedAt,
    UpdatedAt,
    LastSeenAt,
}

#[derive(DeriveIden)]
pub enum IpGroups {
    Table,
    Id,
    Name,
    GroupType,
    Description,
    CreatedAt,
}

#[derive(DeriveIden)]
pub enum IpRecordGroupMemberships {
    Table,
    IpRecordId,
    GroupId,
}

#[derive(DeriveIden)]
pub enum ApiKeys {
    Table,
    Id,
    KeyHash,
    Name,
    Prefix,
    BoundIps,
    IsMaster,
    CanManageKeys,
    CanManageWebhooks,
    CanCreateGroups,
    CreatedAt,
    UpdatedAt,
}

#[derive(DeriveIden)]
pub enum ApiKeyGroupPermissions {
    Table,
    Id,
    ApiKeyId,
    GroupId,
    CanRead,
    CanWrite,
    CanDelete,
    CreatedAt,
}

#[derive(DeriveIden)]
pub enum WebhookConfigs {
    Table,
    Id,
    Name,
    TargetUrl,
    SecretToken,
    HeadersJson,
    PayloadTemplate,
    GroupId,
    IsActive,
    Events,
    CreatedAt,
}

#[derive(DeriveIden)]
pub enum AuditLogs {
    Table,
    Id,
    ApiKeyId,
    ApiKeyName,
    ApiKeyPrefix,
    ClientIp,
    Action,
    TargetAddress,
    GroupNames,
    Details,
    Timestamp,
}

#[derive(DeriveMigrationName)]
pub struct Migration;

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        create_ip_groups(manager).await?;
        create_ip_records(manager).await?;
        create_ip_record_group_memberships(manager).await?;
        create_api_keys(manager).await?;
        create_api_key_group_permissions(manager).await?;
        create_webhook_configs(manager).await?;
        create_audit_logs_and_indexes(manager).await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(AuditLogs::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(WebhookConfigs::Table).to_owned())
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(ApiKeyGroupPermissions::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(ApiKeys::Table).to_owned())
            .await?;
        manager
            .drop_table(
                Table::drop()
                    .table(IpRecordGroupMemberships::Table)
                    .to_owned(),
            )
            .await?;
        manager
            .drop_table(Table::drop().table(IpRecords::Table).to_owned())
            .await?;
        manager
            .drop_table(Table::drop().table(IpGroups::Table).to_owned())
            .await?;
        Ok(())
    }
}

async fn create_ip_groups(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    // Create ip_groups table
    manager
        .create_table(
            Table::create()
                .table(IpGroups::Table)
                .if_not_exists()
                .col(ColumnDef::new(IpGroups::Id).uuid().not_null().primary_key())
                .col(
                    ColumnDef::new(IpGroups::Name)
                        .string()
                        .not_null()
                        .unique_key(),
                )
                .col(
                    ColumnDef::new(IpGroups::GroupType)
                        .string()
                        .not_null()
                        .default("banlist"),
                )
                .col(ColumnDef::new(IpGroups::Description).text())
                .col(ColumnDef::new(IpGroups::CreatedAt).date_time().not_null())
                .to_owned(),
        )
        .await?;
    Ok(())
}

async fn create_ip_records(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    // Create ip_records table
    manager
        .create_table(
            Table::create()
                .table(IpRecords::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(IpRecords::Id)
                        .uuid()
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(IpRecords::TargetAddress)
                        .string()
                        .not_null()
                        .unique_key(),
                )
                .col(ColumnDef::new(IpRecords::Cause).text())
                .col(
                    ColumnDef::new(IpRecords::IsLocked)
                        .boolean()
                        .not_null()
                        .default(false),
                )
                .col(ColumnDef::new(IpRecords::CreatedAt).date_time().not_null())
                .col(ColumnDef::new(IpRecords::UpdatedAt).date_time().not_null())
                .col(ColumnDef::new(IpRecords::LastSeenAt).date_time().not_null())
                .to_owned(),
        )
        .await?;
    Ok(())
}

async fn create_ip_record_group_memberships(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    // Create ip_record_group_memberships table
    manager
        .create_table(
            Table::create()
                .table(IpRecordGroupMemberships::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(IpRecordGroupMemberships::IpRecordId)
                        .uuid()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(IpRecordGroupMemberships::GroupId)
                        .uuid()
                        .not_null(),
                )
                .primary_key(
                    Index::create()
                        .name("pk-ip_record_group_memberships")
                        .col(IpRecordGroupMemberships::IpRecordId)
                        .col(IpRecordGroupMemberships::GroupId),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-irgm-ip_record_id")
                        .from(
                            IpRecordGroupMemberships::Table,
                            IpRecordGroupMemberships::IpRecordId,
                        )
                        .to(IpRecords::Table, IpRecords::Id)
                        .on_delete(ForeignKeyAction::Cascade)
                        .on_update(ForeignKeyAction::Cascade),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-irgm-group_id")
                        .from(
                            IpRecordGroupMemberships::Table,
                            IpRecordGroupMemberships::GroupId,
                        )
                        .to(IpGroups::Table, IpGroups::Id)
                        .on_delete(ForeignKeyAction::Cascade)
                        .on_update(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await?;
    Ok(())
}

async fn create_api_keys(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    // Create api_keys table
    manager
        .create_table(
            Table::create()
                .table(ApiKeys::Table)
                .if_not_exists()
                .col(ColumnDef::new(ApiKeys::Id).uuid().not_null().primary_key())
                .col(ColumnDef::new(ApiKeys::Name).string().not_null())
                .col(
                    ColumnDef::new(ApiKeys::KeyHash)
                        .string()
                        .not_null()
                        .unique_key(),
                )
                .col(ColumnDef::new(ApiKeys::Prefix).string().not_null())
                .col(ColumnDef::new(ApiKeys::BoundIps).text())
                .col(
                    ColumnDef::new(ApiKeys::IsMaster)
                        .boolean()
                        .not_null()
                        .default(false),
                )
                .col(
                    ColumnDef::new(ApiKeys::CanManageKeys)
                        .boolean()
                        .not_null()
                        .default(false),
                )
                .col(
                    ColumnDef::new(ApiKeys::CanManageWebhooks)
                        .boolean()
                        .not_null()
                        .default(false),
                )
                .col(
                    ColumnDef::new(ApiKeys::CanCreateGroups)
                        .boolean()
                        .not_null()
                        .default(false),
                )
                .col(ColumnDef::new(ApiKeys::CreatedAt).date_time().not_null())
                .col(ColumnDef::new(ApiKeys::UpdatedAt).date_time().not_null())
                .to_owned(),
        )
        .await?;

    // Create indexes for api_keys
    manager
        .create_index(
            Index::create()
                .name("idx-api_keys-prefix")
                .table(ApiKeys::Table)
                .col(ApiKeys::Prefix)
                .to_owned(),
        )
        .await?;
    Ok(())
}

async fn create_api_key_group_permissions(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    // Create api_key_group_permissions junction table
    manager
        .create_table(
            Table::create()
                .table(ApiKeyGroupPermissions::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(ApiKeyGroupPermissions::Id)
                        .uuid()
                        .not_null()
                        .primary_key(),
                )
                .col(
                    ColumnDef::new(ApiKeyGroupPermissions::ApiKeyId)
                        .uuid()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ApiKeyGroupPermissions::GroupId)
                        .uuid()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(ApiKeyGroupPermissions::CanRead)
                        .boolean()
                        .not_null()
                        .default(true),
                )
                .col(
                    ColumnDef::new(ApiKeyGroupPermissions::CanWrite)
                        .boolean()
                        .not_null()
                        .default(false),
                )
                .col(
                    ColumnDef::new(ApiKeyGroupPermissions::CanDelete)
                        .boolean()
                        .not_null()
                        .default(false),
                )
                .col(
                    ColumnDef::new(ApiKeyGroupPermissions::CreatedAt)
                        .date_time()
                        .not_null(),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-akgp-api_key_id")
                        .from(
                            ApiKeyGroupPermissions::Table,
                            ApiKeyGroupPermissions::ApiKeyId,
                        )
                        .to(ApiKeys::Table, ApiKeys::Id)
                        .on_delete(ForeignKeyAction::Cascade)
                        .on_update(ForeignKeyAction::Cascade),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-akgp-group_id")
                        .from(
                            ApiKeyGroupPermissions::Table,
                            ApiKeyGroupPermissions::GroupId,
                        )
                        .to(IpGroups::Table, IpGroups::Id)
                        .on_delete(ForeignKeyAction::Cascade)
                        .on_update(ForeignKeyAction::Cascade),
                )
                .to_owned(),
        )
        .await?;

    // Create unique index for api_key_group_permissions
    manager
        .create_index(
            Index::create()
                .name("idx-akgp-api_key_id-group_id")
                .table(ApiKeyGroupPermissions::Table)
                .col(ApiKeyGroupPermissions::ApiKeyId)
                .col(ApiKeyGroupPermissions::GroupId)
                .unique()
                .to_owned(),
        )
        .await?;
    Ok(())
}

async fn create_webhook_configs(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    // Create webhook_configs table
    manager
        .create_table(
            Table::create()
                .table(WebhookConfigs::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(WebhookConfigs::Id)
                        .uuid()
                        .not_null()
                        .primary_key(),
                )
                .col(ColumnDef::new(WebhookConfigs::Name).string().not_null())
                .col(
                    ColumnDef::new(WebhookConfigs::TargetUrl)
                        .string()
                        .not_null(),
                )
                .col(
                    ColumnDef::new(WebhookConfigs::SecretToken)
                        .string()
                        .not_null(),
                )
                .col(ColumnDef::new(WebhookConfigs::HeadersJson).text())
                .col(
                    ColumnDef::new(WebhookConfigs::PayloadTemplate)
                        .text()
                        .not_null(),
                )
                .col(ColumnDef::new(WebhookConfigs::GroupId).uuid().not_null())
                .col(
                    ColumnDef::new(WebhookConfigs::IsActive)
                        .boolean()
                        .not_null()
                        .default(true),
                )
                .col(ColumnDef::new(WebhookConfigs::Events).string())
                .col(
                    ColumnDef::new(WebhookConfigs::CreatedAt)
                        .date_time()
                        .not_null(),
                )
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-webhook_configs-group_id")
                        .from(WebhookConfigs::Table, WebhookConfigs::GroupId)
                        .to(IpGroups::Table, IpGroups::Id)
                        .on_delete(ForeignKeyAction::Cascade)
                        .on_update(ForeignKeyAction::NoAction),
                )
                .to_owned(),
        )
        .await?;
    Ok(())
}

async fn create_audit_logs_and_indexes(manager: &SchemaManager<'_>) -> Result<(), DbErr> {
    // Create audit_logs table
    manager
        .create_table(
            Table::create()
                .table(AuditLogs::Table)
                .if_not_exists()
                .col(
                    ColumnDef::new(AuditLogs::Id)
                        .uuid()
                        .not_null()
                        .primary_key(),
                )
                .col(ColumnDef::new(AuditLogs::ApiKeyId).uuid())
                .col(ColumnDef::new(AuditLogs::ApiKeyName).string())
                .col(ColumnDef::new(AuditLogs::ApiKeyPrefix).string())
                .col(ColumnDef::new(AuditLogs::ClientIp).string())
                .col(ColumnDef::new(AuditLogs::Action).string().not_null())
                .col(ColumnDef::new(AuditLogs::TargetAddress).string())
                .col(ColumnDef::new(AuditLogs::GroupNames).string())
                .col(ColumnDef::new(AuditLogs::Details).text())
                .col(ColumnDef::new(AuditLogs::Timestamp).date_time().not_null())
                .foreign_key(
                    ForeignKey::create()
                        .name("fk-audit_logs-api_key_id")
                        .from(AuditLogs::Table, AuditLogs::ApiKeyId)
                        .to(ApiKeys::Table, ApiKeys::Id)
                        .on_delete(ForeignKeyAction::SetNull)
                        .on_update(ForeignKeyAction::NoAction),
                )
                .to_owned(),
        )
        .await?;

    // Create index on audit_logs.action and timestamp
    manager
        .create_index(
            Index::create()
                .name("idx-audit_logs-action")
                .table(AuditLogs::Table)
                .col(AuditLogs::Action)
                .to_owned(),
        )
        .await?;
    manager
        .create_index(
            Index::create()
                .name("idx-audit_logs-timestamp")
                .table(AuditLogs::Table)
                .col(AuditLogs::Timestamp)
                .to_owned(),
        )
        .await?;

    // Create index on ip_records.last_seen_at
    manager
        .create_index(
            Index::create()
                .name("idx-ip_records-last_seen_at")
                .table(IpRecords::Table)
                .col(IpRecords::LastSeenAt)
                .to_owned(),
        )
        .await?;
    Ok(())
}
