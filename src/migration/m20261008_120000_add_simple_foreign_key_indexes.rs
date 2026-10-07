//! A dedicated, single-column index on every foreign-key child column and every `ORDER BY` column,
//! even where a composite or partial index already leads with or covers it.
//!
//! A composite index serves an equality lookup on its leading column exactly as well as a plain
//! index on that column alone — it is the same B-tree prefix. This migration adds the plain index
//! anyway, so every foreign key has one without relying on a composite's column order to keep
//! covering it. Two of these (`webhook_configs.group_id`, `webhook_executions.webhook_id`) restore
//! indexes `m20261007_120000_add_webhook_query_indexes` dropped in favour of the composite it
//! added; this migration keeps both rather than reopening that one, which already shipped.
//!
//! `ip_record_group_memberships.last_seen_at` is a genuine, load-bearing addition rather than a
//! duplicate: the partial `(group_id, last_seen_at DESC) WHERE is_deleted = FALSE` index excludes
//! soft-deleted rows by construction, so it cannot serve an `ORDER BY last_seen_at` under
//! `include_deleted=true`. A plain index on the column alone can. `ip_record_causes.created_at` is
//! not currently load-bearing — the one query that orders by it always filters by `membership_id`
//! first, which the existing `(membership_id, created_at DESC)` composite already serves — it is
//! added for the same explicit guarantee as the foreign-key indexes above.
//!
//! The cost of the redundant entries is real and worth naming: each is one more B-tree every
//! insert, update, and delete on its table maintains, for no read this schema's own query shapes
//! need beyond what an existing composite or partial index already serves. Kept anyway because it
//! was asked for directly.

use sea_orm::sea_query::Index as SqIndex;
use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum Memberships {
    #[sea_orm(iden = "ip_record_group_memberships")]
    Table,
    IpRecordId,
    GroupId,
    LastSeenAt,
}

#[derive(DeriveIden)]
enum ApiKeyGroupPermissions {
    #[sea_orm(iden = "api_key_group_permissions")]
    Table,
    ApiKeyId,
}

#[derive(DeriveIden)]
enum WebhookConfigs {
    #[sea_orm(iden = "webhook_configs")]
    Table,
    GroupId,
}

#[derive(DeriveIden)]
enum WebhookExecutions {
    #[sea_orm(iden = "webhook_executions")]
    Table,
    WebhookId,
}

#[derive(DeriveIden)]
enum Causes {
    #[sea_orm(iden = "ip_record_causes")]
    Table,
    MembershipId,
    CreatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for (name, table, column) in [
            ("idx-irgm-ip_record_id", Memberships::Table, Memberships::IpRecordId),
            ("idx-irgm-group_id", Memberships::Table, Memberships::GroupId),
            ("idx-irgm-last_seen_at", Memberships::Table, Memberships::LastSeenAt),
        ] {
            manager
                .create_index(SqIndex::create().if_not_exists().name(name).table(table).col(column).to_owned())
                .await?;
        }
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx-akgp-api_key_id")
                    .table(ApiKeyGroupPermissions::Table)
                    .col(ApiKeyGroupPermissions::ApiKeyId)
                    .to_owned(),
            )
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
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx-irc-membership_id")
                    .table(Causes::Table)
                    .col(Causes::MembershipId)
                    .to_owned(),
            )
            .await?;
        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name("idx-irc-created_at")
                    .table(Causes::Table)
                    .col(Causes::CreatedAt)
                    .to_owned(),
            )
            .await?;
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for name in [
            "idx-irgm-ip_record_id",
            "idx-irgm-group_id",
            "idx-irgm-last_seen_at",
            "idx-akgp-api_key_id",
            "idx-webhook_configs-group_id",
            "idx-webhook_executions-webhook_id",
            "idx-irc-membership_id",
            "idx-irc-created_at",
        ] {
            manager.drop_index(SqIndex::drop().if_exists().name(name).to_owned()).await?;
        }
        Ok(())
    }
}
