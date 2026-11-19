//! Adds `webhook_executions.resolved_target_url`, `.target_address`, and `.cause`.
//!
//! # Why these three, together
//!
//! `target_url` on `webhook_configs` can now contain `$variable` placeholders (`$action`, `$ip`,
//! `$cause`, `$group_name`, `$group_id`, `$timestamp` — see `dispatch::resolve_event_variables`),
//! expanded fresh for every dispatch. The *template* stays on `webhook_configs`, fixed per webhook;
//! what actually varies per attempt — the real URL that was dialed, and the event data behind it —
//! belongs on the row that already exists per attempt, `webhook_executions`. Without it, "what
//! address did this specific delivery actually hit" is unanswerable once the template contains a
//! variable, since the same webhook's resolved URL differs event to event.
//!
//! `target_address` and `cause` ride along for the same reason and enable the same thing the URL
//! column does: the Executions tab's free-text search and its `ip`/filter parameters need to match
//! against the event an attempt was *for*, not just the webhook it went through — data that,
//! before this migration, existed only transiently inside the `WebhookEvent` that triggered the
//! dispatch and was never persisted anywhere queryable.
//!
//! All three are nullable. Every row from before this migration predates the concept and has
//! nothing to backfill it with; every row from now on populates all three unconditionally (an
//! event always has an address and a resolved URL, even when `target_url` contained no variables
//! to resolve — resolution is a no-op on a template with nothing to substitute, not a skipped
//! step).
//!
//! Three separate `alter_table` calls, one column each: SQLite's `ALTER TABLE` accepts exactly one
//! `ADD COLUMN`/`DROP COLUMN` per statement, the same constraint `m20260801_000005`'s module header
//! documents.

use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum WebhookExecutions {
    Table,
    ResolvedTargetUrl,
    TargetAddress,
    Cause,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(WebhookExecutions::Table)
                    .add_column(ColumnDef::new(WebhookExecutions::ResolvedTargetUrl).text())
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(WebhookExecutions::Table)
                    .add_column(ColumnDef::new(WebhookExecutions::TargetAddress).text())
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(WebhookExecutions::Table)
                    .add_column(ColumnDef::new(WebhookExecutions::Cause).text())
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for column in [
            WebhookExecutions::ResolvedTargetUrl,
            WebhookExecutions::TargetAddress,
            WebhookExecutions::Cause,
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(WebhookExecutions::Table)
                        .drop_column(column)
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
