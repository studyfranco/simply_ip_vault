//! Adds `webhook_executions`: one row per outbound HTTP attempt a webhook dispatch makes,
//! including retries — the delivery history the dashboard's "Executions" tab reads.
//!
//! # Why `webhook_id` is `ON DELETE CASCADE`, not `SET NULL`
//!
//! `audit_logs.api_key_id` is the precedent for a log table referencing a deletable row, and it uses
//! `SET NULL` specifically so the trail survives the key's deletion — `api_key_name`/`api_key_prefix`
//! are denormalized alongside it, so a nulled row still says *who* acted even after the key is gone.
//!
//! This table has no such denormalized identity for the webhook, and deliberately so: an execution
//! row is meaningless without knowing which webhook produced it, so a `SET NULL` row would be an
//! orphan with nothing left to attribute it to — worse than not existing. `SET NULL` would also break
//! the RBAC model outright: visibility here is entirely derived through `webhook_id ->
//! webhook_configs.owner_key_id` (there is no `owner_key_id` on this table itself — see
//! `api::webhooks::list_executions`), so a nulled `webhook_id` would make that row invisible to any
//! owner while remaining silently readable to Master, a leak in the opposite direction from what §4
//! asks for. `CASCADE` disposes of an execution row the moment its webhook can no longer own it,
//! which is also consistent with retention already bounding this table to a handful of hours or days
//! (see `retention::run_webhook_execution_retention_worker`) — the rows are operational history, not
//! data anyone is expected to keep past their webhook's own lifetime.
//!
//! # Why this is not pre-flight-inventoried under `RBAC_MODEL.md` §6
//!
//! §6 requires a key-deletion cascade to inventory "every resource and creator-private entity owned
//! by any key within [the subtree]" and refuse until each is resolved. An execution row is neither —
//! it carries no `owner_key_id`, confers no rights, and cannot itself be created or reassigned by a
//! caller. It is operational log data, governed the same way `audit_logs` already is (also absent
//! from pre-flight inventory, also not itself a managed resource or creator-private entity). Deleting
//! the *webhook* a key owns already goes through the existing ownership/lifecycle guard on
//! `webhook_configs`; its executions simply go with it via this cascade, the same way
//! `webhook_configs` rows already go with a deleted `ip_groups` row with no pre-flight step of their
//! own (`m20230101_000001_initial_schema`'s `ip_groups` -> `webhook_configs` cascade).

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

/// The `webhook_configs` table, referenced by this migration's foreign key.
#[derive(DeriveIden)]
enum WebhookConfigs {
    Table,
    Id,
}

#[derive(DeriveIden)]
enum WebhookExecutions {
    Table,
    Id,
    WebhookId,
    EventType,
    StatusCode,
    IsSuccess,
    DurationMs,
    ErrorMessage,
    CreatedAt,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .create_table(
                Table::create()
                    .table(WebhookExecutions::Table)
                    .if_not_exists()
                    .col(
                        ColumnDef::new(WebhookExecutions::Id)
                            .uuid()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(WebhookExecutions::WebhookId)
                            .uuid()
                            .not_null(),
                    )
                    // `IP_ADD`/`IP_UPDATE`/`IP_DELETE` (the same vocabulary `webhook_configs.events`
                    // and `audit_logs.action` already use) plus `TEST` for a live "Test Webhook"
                    // dispatch (`api::webhooks::test_webhook`) — never filtered against a fixed
                    // enum, matching every other free-text action/event column in this schema.
                    .col(
                        ColumnDef::new(WebhookExecutions::EventType)
                            .string()
                            .not_null(),
                    )
                    // NULL means the attempt never received an HTTP response at all — a network
                    // error, a timeout, a DNS failure — as distinct from a response that carried a
                    // status this service doesn't treat as success. `is_success` is the column to
                    // filter success/failure on; this one is diagnostic detail, and its NULL-ness is
                    // itself informative (see `dispatch::DispatchOutcome`, whose `status: Option<u16>`
                    // this column mirrors exactly).
                    .col(ColumnDef::new(WebhookExecutions::StatusCode).integer())
                    .col(
                        ColumnDef::new(WebhookExecutions::IsSuccess)
                            .boolean()
                            .not_null(),
                    )
                    // Wall-clock time of the one HTTP attempt this row records, not a cumulative
                    // total across retries — each retry attempt is its own row (see `dispatch.rs`'s
                    // module header), so summing this column across a delivery's rows is how a
                    // caller gets the cumulative figure if they want it.
                    .col(
                        ColumnDef::new(WebhookExecutions::DurationMs)
                            .integer()
                            .not_null(),
                    )
                    .col(ColumnDef::new(WebhookExecutions::ErrorMessage).text())
                    .col(
                        ColumnDef::new(WebhookExecutions::CreatedAt)
                            .date_time()
                            .not_null(),
                    )
                    .foreign_key(
                        ForeignKey::create()
                            .name("fk-webhook_executions-webhook_id")
                            .from(WebhookExecutions::Table, WebhookExecutions::WebhookId)
                            .to(WebhookConfigs::Table, WebhookConfigs::Id)
                            .on_delete(ForeignKeyAction::Cascade)
                            .on_update(ForeignKeyAction::NoAction),
                    )
                    .to_owned(),
            )
            .await?;

        // `webhook_id`: every RBAC-scoped listing query and the FK itself both search on it.
        manager
            .create_index(
                Index::create()
                    .name("idx-webhook_executions-webhook_id")
                    .table(WebhookExecutions::Table)
                    .col(WebhookExecutions::WebhookId)
                    .to_owned(),
            )
            .await?;
        // `created_at`: the retention sweep's age filter, and the listing's newest-first ordering.
        manager
            .create_index(
                Index::create()
                    .name("idx-webhook_executions-created_at")
                    .table(WebhookExecutions::Table)
                    .col(WebhookExecutions::CreatedAt)
                    .to_owned(),
            )
            .await?;
        // `is_success`: the retention sweep filters on it directly (24h success / 7d failure are two
        // different thresholds against the same column), so a composite covering index — rather than
        // two single-column indexes the sweep would otherwise merge itself — is what actually serves
        // that query.
        manager
            .create_index(
                Index::create()
                    .name("idx-webhook_executions-is_success-created_at")
                    .table(WebhookExecutions::Table)
                    .col(WebhookExecutions::IsSuccess)
                    .col(WebhookExecutions::CreatedAt)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(WebhookExecutions::Table).to_owned())
            .await
    }
}
