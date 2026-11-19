//! Renames `webhook_executions.error_message` to `response_body`.
//!
//! # Why this is a rename, not a new column
//!
//! Until this migration, the column was populated only on failure — with a computed string like
//! `"HTTP 500"`, not the receiver's actual response — and left `NULL` on success even when the
//! receiver returned a body worth keeping (a JSON acknowledgement, a tracking id, a human-readable
//! confirmation). Both of those were narrower than what the column's data actually is: whatever the
//! receiver said back, on every attempt that reached the network, success or failure alike. Adding
//! a second column would have left two overlapping "what did the receiver say" fields with no clean
//! rule for which one a reader should trust; renaming and re-scoping the existing one keeps there
//! being exactly one place to look.
//!
//! `dispatch::log_execution`'s caller now passes the actual response body (truncated, see
//! `dispatch::RESPONSE_SNIPPET_MAX_BYTES`) whenever a response was received at all, falling back to
//! the failure reason only when no response ever arrived (a network-level error, a timeout) — there
//! is no body to have kept in that case.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum WebhookExecutions {
    Table,
    ErrorMessage,
    ResponseBody,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(WebhookExecutions::Table)
                    .rename_column(
                        WebhookExecutions::ErrorMessage,
                        WebhookExecutions::ResponseBody,
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(WebhookExecutions::Table)
                    .rename_column(
                        WebhookExecutions::ResponseBody,
                        WebhookExecutions::ErrorMessage,
                    )
                    .to_owned(),
            )
            .await
    }
}
