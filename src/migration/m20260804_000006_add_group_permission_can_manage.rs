//! Adds `api_key_group_permissions.can_manage` — the right to administer *this group's* grants.
//!
//! Until now the only authority that could touch a group's permission rows was the global
//! `api_keys.can_manage_keys` flag, which reaches **every** key and **every** group. That made the
//! smallest grantable unit of delegation far larger than most delegations actually want: handing
//! someone the ability to take a verb away from one key on one group also handed them the ability
//! to rewrite credentials across the entire system.
//!
//! `can_manage` is the resource-scoped counterpart. It is deliberately **not** symmetric with
//! `can_manage_keys`: it satisfies the *revoke* path only. Granting and widening still require the
//! global flag, because conferring a verb can raise authority and a resource-scoped right must not
//! become a way to mint new ones. See `AGENT.MD` §2.
//!
//! Additive, `NOT NULL DEFAULT false`, and no backfill: every existing row becomes `can_manage =
//! false`, which is exactly the authority it had a moment before the migration ran. Existing
//! `can_manage_keys` holders are unaffected — their path is unchanged and does not consult this
//! column. `NOT NULL` with a default rather than nullable for the same reason the soft-delete flag
//! is: there is no meaningful "unknown" here, and a nullable boolean would force every check to
//! spell out `IS NULL OR = false`, which is the kind of condition that eventually gets one branch
//! wrong — and getting it wrong here means failing *open* on a permission check.

use super::prelude::*;

/// Identifiers this migration touches. `Table` is re-declared locally rather than imported from the
/// initial-schema migration so that module can stay private; `DeriveIden` maps the variants to the
/// same `snake_case` names, so they address the same table.
#[derive(DeriveIden)]
enum ApiKeyGroupPermissions {
    /// The `api_key_group_permissions` table.
    Table,
    /// Whether this key may administer the permission rows on this group.
    CanManage,
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &'static str {
        "m20260804_000006_add_group_permission_can_manage"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeyGroupPermissions::Table)
                    .add_column(
                        ColumnDef::new(ApiKeyGroupPermissions::CanManage)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeyGroupPermissions::Table)
                    .drop_column(ApiKeyGroupPermissions::CanManage)
                    .to_owned(),
            )
            .await
    }
}
