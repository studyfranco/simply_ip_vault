//! Renames the `BODY_ONLY` webhook auth mode to `HMAC_ONLY`, and makes the signature header
//! configurable.
//!
//! # Why rename
//!
//! `BODY_ONLY` named the *input* to the HMAC — the body, rather than a canonical string — and left
//! the more important half to be inferred: that this mode sends a signature and **nothing else**, no
//! `X-API-Key`, no bearer credential. Operators read the name as "sign the body, and whatever else we
//! normally send", which is the misreading that matters, because the whole point of choosing it is
//! that a receiver gets no reusable secret.
//!
//! The old spelling is still **parsed** (`AuthMode::BODY_ONLY_LEGACY`) so a client's stored
//! automation keeps working; it is simply never emitted again. This migration rewrites the stored
//! rows so the database agrees with the API.
//!
//! # Why the header and prefix become columns
//!
//! Both were hardcoded to `X-Signature-256` and `sha256=`. That is right for a peer instance of this
//! service and for `simply_hook_executor`, and wrong for a large share of third-party receivers:
//! GitHub-style consumers expect `X-Hub-Signature-256`, and some expect a bare hex digest with no
//! prefix at all. A receiver that cannot be configured to match had no way to accept our dispatches.
//!
//! Both columns are **nullable, defaulting to the previous hardcoded values at read time** rather
//! than being backfilled. Existing rows therefore keep their exact behaviour with no data rewrite,
//! and a NULL column reads as "whatever this service considers standard" rather than pinning a
//! historical choice into every old row.
//!
//! # What is deliberately *not* configurable: the algorithm
//!
//! The digest stays SHA-256. Making it selectable would mean accepting SHA-1 — the algorithm the
//! receivers that want a custom header name most often ask for — and this service would then be
//! generating signatures it knows to be forgeable, at the request of the least security-conscious
//! integration on the list. `crypto::SIGNATURE_PREFIX` and the inbound verifier are SHA-256
//! throughout, and `scripts/verify_convergence.sh` asserts that the prefix is mandatory rather than
//! stripped-if-present. A per-row algorithm column would be the one place that could quietly opt out.

use sea_orm_migration::prelude::*;

/// The value replacing `BODY_ONLY` in `webhook_configs.auth_mode`.
const HMAC_ONLY: &str = "HMAC_ONLY";

/// The value being replaced.
const BODY_ONLY: &str = "BODY_ONLY";

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum WebhookConfigs {
    Table,
    AuthMode,
    SignatureHeader,
    SignaturePrefix,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        for column in [
            WebhookConfigs::SignatureHeader,
            WebhookConfigs::SignaturePrefix,
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(WebhookConfigs::Table)
                        // Nullable and undefaulted: NULL means "use this service's standard", which
                        // is resolved in `dispatch.rs`. A DDL default would freeze today's answer
                        // into every row written from now on.
                        .add_column(ColumnDef::new(column).string().null())
                        .to_owned(),
                )
                .await?;
        }

        rewrite_mode(manager, BODY_ONLY, HMAC_ONLY).await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        // Data first, then the columns it might have referenced — the reverse of `up`.
        rewrite_mode(manager, HMAC_ONLY, BODY_ONLY).await?;

        for column in [
            WebhookConfigs::SignatureHeader,
            WebhookConfigs::SignaturePrefix,
        ] {
            manager
                .alter_table(
                    Table::alter()
                        .table(WebhookConfigs::Table)
                        .drop_column(column)
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}

/// Rewrites every `auth_mode` equal to `from` so that it reads `to`.
///
/// Both values are compile-time constants from this module, never caller input; they are bound
/// rather than interpolated anyway, because a migration is exactly the place where a habit of
/// interpolating "obviously safe" values gets copied into one that is not.
async fn rewrite_mode(manager: &SchemaManager<'_>, from: &str, to: &str) -> Result<(), DbErr> {
    manager
        .exec_stmt(
            Query::update()
                .table(WebhookConfigs::Table)
                .value(WebhookConfigs::AuthMode, to)
                .and_where(Expr::col(WebhookConfigs::AuthMode).eq(from))
                .to_owned(),
        )
        .await
}
