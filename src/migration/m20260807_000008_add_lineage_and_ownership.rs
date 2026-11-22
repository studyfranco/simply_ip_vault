//! Adds key lineage (`api_keys.parent_key_id`) and resource ownership (`owner_key_id` on
//! `ip_groups` and `webhook_configs`), plus the indexes `RBAC_MODEL.md` §7 requires.
//!
//! # What each column is for, and what it is emphatically not for
//!
//! - **`parent_key_id`** records which key created this one. §3/§6 use it for cascade deletion and
//!   §4 uses it for visibility scoping, and **R3 forbids deriving any authority from it**:
//!   "`parent_key_id` exists solely for cascading deletion and visibility scoping. A daughter of the
//!   Master key is an ordinary daughter key with no elevated standing. Rights are never derived from
//!   key lineage." No guard reads this column.
//! - **`owner_key_id`** records which key a resource belongs to. §3 gives Master and the owner —
//!   and nobody else — authority to delete or rename the entity itself. Holding `can_manage` or any
//!   operational verb confers none: "a parent that merely uses a resource must not be able to delete
//!   it."
//!
//! # Backfill: everything stays `NULL`, deliberately
//!
//! Existing rows have no recorded lineage or owner, and every candidate for inventing one is worse
//! than leaving it blank:
//!
//! - **Lineage.** Nothing in the schema records who created an existing key. `created_at` ordering
//!   would let us guess "the master created everything", which is usually true and occasionally very
//!   wrong — and a guessed subtree is a guessed *cascade*, so a wrong guess deletes keys nobody
//!   intended to delete when §6 lands.
//! - **Ownership.** `audit_logs` holds `GROUP_CREATE` and `WEBHOOK_CREATE` entries naming the acting
//!   key, which is tempting. It is not authoritative: the audit log is prunable by retention, its
//!   `api_key_id` is `ON DELETE SET NULL`, and groups created through the auto-provisioning paths
//!   predate any endpoint that logged them consistently. Reconstructing ownership from a lossy trail
//!   would hand lifecycle authority — the right to *delete a resource* — to whichever key happened
//!   to survive in a log row.
//!
//! `NULL` means "unassigned", and §3's authority test reads it as "no owner, therefore Master only".
//! That is a safe default: it withholds authority rather than inventing it, and a master can assign
//! ownership deliberately through `PUT /api/groups/{id}/owner` and `PUT /api/webhooks/{id}/owner`.
//!
//! # No database-level foreign keys on these three columns
//!
//! The other cross-table references in this schema carry real FKs, declared inside `CREATE TABLE` by
//! the initial migration. These three cannot: **SQLite has no `ALTER TABLE … ADD CONSTRAINT`**, and
//! `AGENT.MD` requires the data layer to stay SQL-agnostic across all three enabled backends. The
//! choice is a constraint that exists on PostgreSQL and MySQL and silently does not on the default
//! development backend — where every test in this repository runs — or no constraint and an explicit
//! application-level rule. A referential guarantee that holds in production and not in CI is worse
//! than none, because it is the CI run that would have caught the violation.
//!
//! So referential integrity is enforced in `src/api.rs` instead, in both directions:
//!
//! - **On assignment**, the referenced key is looked up before the column is written, so a dangling
//!   id cannot be introduced through the API.
//! - **On deletion**, `delete_api_key` nulls the `parent_key_id` of the deleted key's daughters and
//!   the `owner_key_id` of everything it owned — the application-level equivalent of
//!   `ON DELETE SET NULL`, and deliberately *not* `CASCADE`. §6 is explicit that "data is never
//!   destroyed implicitly": IP Groups and Webhook Configs "must never disappear as a side effect of
//!   removing a key". A `CASCADE` on `parent_key_id` would be worse still — it would delete an entire
//!   subtree the moment anyone ran a direct `DELETE`, bypassing the pre-flight inventory §6 requires.
//!   The recursive cascade is application logic gated on that inventory, not a schema behaviour.
//!
//! Reads stay defensive regardless: a resource whose `owner_key_id` names a key that no longer exists
//! is treated as unowned, which withholds authority rather than granting it to nobody in particular.

use super::prelude::*;

/// The `api_keys` table and the lineage column added to it.
#[derive(DeriveIden)]
enum ApiKeys {
    /// The `api_keys` table.
    Table,
    /// The key that created this one. `NULL` for the Master and for every pre-migration row.
    ParentKeyId,
    /// Existing column, indexed here per §7's "the key-hash lookup column".
    KeyHash,
}

/// The `ip_groups` table and its ownership column.
#[derive(DeriveIden)]
enum IpGroups {
    /// The `ip_groups` table.
    Table,
    /// The key holding lifecycle authority over this group.
    OwnerKeyId,
}

/// The `webhook_configs` table and its ownership column.
#[derive(DeriveIden)]
enum WebhookConfigs {
    /// The `webhook_configs` table.
    Table,
    /// The key that created this dispatch target. §4 makes it the only non-Master key that may see
    /// it at all.
    OwnerKeyId,
}

/// The `api_key_group_permissions` table, for §7's join-column index.
#[derive(DeriveIden)]
enum ApiKeyGroupPermissions {
    /// The `api_key_group_permissions` table.
    Table,
    /// The group side of the join.
    GroupId,
}

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &'static str {
        "m20260807_000008_add_lineage_and_ownership"
    }
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .add_column_if_not_exists(ColumnDef::new(ApiKeys::ParentKeyId).uuid().null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(IpGroups::Table)
                    .add_column_if_not_exists(ColumnDef::new(IpGroups::OwnerKeyId).uuid().null())
                    .to_owned(),
            )
            .await?;

        manager
            .alter_table(
                Table::alter()
                    .table(WebhookConfigs::Table)
                    .add_column_if_not_exists(
                        ColumnDef::new(WebhookConfigs::OwnerKeyId).uuid().null(),
                    )
                    .to_owned(),
            )
            .await?;

        // §7's index list: "`parent_key_id`, `owner_key_id`, the key-hash lookup column, and the
        // permission-table join columns — every column the authenticated hot paths search on."
        //
        // `key_hash` already carries a unique index from the initial schema (uniqueness implies an
        // index on every supported backend), and `(api_key_id, group_id)` covers the permission join
        // from the `api_key_id` side. What neither covers is a lookup by `group_id` alone — a
        // composite index cannot serve a query that does not constrain its leading column — and §6's
        // pre-flight inventory and §4's shared-resource view both walk a group's permission rows.
        manager
            .create_index(
                Index::create()
                    .name("idx-api_keys-parent_key_id")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::ParentKeyId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-ip_groups-owner_key_id")
                    .table(IpGroups::Table)
                    .col(IpGroups::OwnerKeyId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-webhook_configs-owner_key_id")
                    .table(WebhookConfigs::Table)
                    .col(WebhookConfigs::OwnerKeyId)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                Index::create()
                    .name("idx-akgp-group_id")
                    .table(ApiKeyGroupPermissions::Table)
                    .col(ApiKeyGroupPermissions::GroupId)
                    .to_owned(),
            )
            .await?;

        // Belt-and-braces on §7's "key-hash lookup column". `key_hash` was declared `unique_key()` in
        // the initial schema, which every supported backend implements with an index, so this is a
        // restatement rather than a new access path — created under a distinct name so it cannot
        // collide with the constraint-backing index, and tolerated as a no-op if the backend already
        // considers one present.
        let _ = manager
            .create_index(
                Index::create()
                    .name("idx-api_keys-key_hash")
                    .table(ApiKeys::Table)
                    .col(ApiKeys::KeyHash)
                    .to_owned(),
            )
            .await;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        for (name, table) in [
            ("idx-api_keys-key_hash", ApiKeys::Table),
            ("idx-api_keys-parent_key_id", ApiKeys::Table),
        ] {
            let _ = manager
                .drop_index(Index::drop().name(name).table(table).to_owned())
                .await;
        }
        let _ = manager
            .drop_index(
                Index::drop()
                    .name("idx-ip_groups-owner_key_id")
                    .table(IpGroups::Table)
                    .to_owned(),
            )
            .await;
        let _ = manager
            .drop_index(
                Index::drop()
                    .name("idx-webhook_configs-owner_key_id")
                    .table(WebhookConfigs::Table)
                    .to_owned(),
            )
            .await;
        let _ = manager
            .drop_index(
                Index::drop()
                    .name("idx-akgp-group_id")
                    .table(ApiKeyGroupPermissions::Table)
                    .to_owned(),
            )
            .await;

        manager
            .alter_table(
                Table::alter()
                    .table(WebhookConfigs::Table)
                    .drop_column(WebhookConfigs::OwnerKeyId)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(IpGroups::Table)
                    .drop_column(IpGroups::OwnerKeyId)
                    .to_owned(),
            )
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(ApiKeys::Table)
                    .drop_column(ApiKeys::ParentKeyId)
                    .to_owned(),
            )
            .await
    }
}
