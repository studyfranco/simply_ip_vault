//! The `api_keys` table: authentication tokens, global access rights, and CIDR network bindings.

use sea_orm::entity::prelude::{TimeDateTime as DateTime, *};
use serde::{Deserialize, Serialize};

/// A single API key: its identity, global RBAC scopes, and network binding rule.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "SeaORM DeriveEntityModel requires flat 1:1 fields for SQL BOOLEAN columns"
)]
#[sea_orm(table_name = "api_keys")]
pub struct Model {
    /// Unique identifier for the API key.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Human-readable key description.
    pub name: String,
    /// SHA-256 hash of the secret API key (the plaintext key is never stored).
    #[sea_orm(unique)]
    pub key_hash: String,
    /// The key's HMAC-SHA256 signing secret, used to verify the `X-Signature-256` request header.
    ///
    /// Unlike [`Self::key_hash`], this cannot be a one-way hash — verifying a signature requires
    /// the secret verbatim — so it is instead sealed with XChaCha20-Poly1305 whenever
    /// `VAULT_ENCRYPTION_KEY` is configured, and stored hex-encoded but unencrypted otherwise
    /// (development fallback). Always read it through [`crate::state::AppState::cipher`]'s
    /// [`open`](crate::crypto::SecretCipher::open) rather than using the field directly.
    ///
    /// `None` for keys created before this column existed; such keys cannot authenticate and must be
    /// rotated (`POST /api/keys/{id}/rotate`) to obtain a secret.
    ///
    /// Never serialized: `api_key::Model` derives `Serialize` and is carried in request extensions,
    /// so `skip_serializing` is a standing guard against this secret leaking into any response body
    /// that ever serializes a whole model.
    #[serde(skip_serializing)]
    #[serde(default)]
    pub signing_secret: Option<String>,
    /// First 8 characters of the plaintext key, kept for display and fast lookup.
    pub prefix: String,
    /// Comma-separated CIDR ranges allowed to use this key (e.g. `127.0.0.1/32,::/0`). An empty
    /// value means no CIDR restriction is enforced.
    pub bound_ips: Option<String>,
    /// Bypasses all group permission checks (and CIDR binding checks) when `true`.
    ///
    /// Not reachable through any API payload: `RBAC_MODEL.md` §5 makes master status a
    /// bootstrap-only property, and `create_api_key`/`update_api_key` reject a request that carries
    /// the field at all. The only writer is `bootstrap_master_key`.
    pub is_master: bool,
    // `api_keys.master_marker` is deliberately **not declared here**, and its absence is the
    // enforcement mechanism rather than an oversight.
    //
    // The column exists — `INTEGER GENERATED ALWAYS AS (CASE WHEN is_master THEN 1 ELSE NULL END)`
    // under a unique index — and is what makes "exactly one Master" a schema fact rather than a
    // convention (`RBAC_MODEL.md` §5, `migration::m20260808_000009_derive_master_marker`). Because
    // the engine generates it, every backend rejects an `INSERT` or `UPDATE` that names it. SeaORM
    // builds explicit column lists from this struct, so leaving the field out is what guarantees no
    // query ever names it. Declaring it — even as a read-only `Option` — would put it back into every
    // generated `INSERT` and break all key creation.
    //
    // It previously lived here as an application-maintained `Option<String>`, which is precisely the
    // arrangement §5 rules out: a writer could set `is_master` and leave the marker NULL, and NULLs
    // do not collide in a unique index. Do not reintroduce the field.
    /// Global privilege to create/edit/delete other API keys.
    pub can_manage_keys: bool,
    /// Global privilege to manage webhook configurations.
    pub can_manage_webhooks: bool,
    /// Global privilege to create new IP groups.
    pub can_create_groups: bool,
    /// The key that created this one, or `None` for the Master key and for every key that predates
    /// the lineage column.
    ///
    /// **Confers no authority whatsoever.** `RBAC_MODEL.md` R3: "`parent_key_id` exists solely for
    /// cascading deletion and visibility scoping. A daughter of the Master key is an ordinary
    /// daughter key with no elevated standing. Rights are never derived from key lineage." No
    /// permission guard reads this field, and a test asserts a daughter of Master holds no more than
    /// any other daughter.
    ///
    /// No database-level foreign key backs it — SQLite has no `ALTER TABLE … ADD CONSTRAINT`, and the
    /// data layer stays SQL-agnostic. `create_api_key` validates the reference on write and
    /// `delete_api_key` clears it on removal; see the migration for why an application rule beats a
    /// constraint that only exists on two of the three backends.
    #[serde(default)]
    pub parent_key_id: Option<Uuid>,
    /// Key generation timestamp.
    #[serde(with = "crate::time_serde")]
    pub created_at: DateTime,
    /// Key last-update timestamp.
    #[serde(with = "crate::time_serde")]
    pub updated_at: DateTime,
}

/// Relations from `api_keys` to other entities.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// This key's per-group permission grants.
    #[sea_orm(has_many = "super::api_key_group_permission::Entity")]
    ApiKeyGroupPermission,
    /// Audit log entries attributed to this key.
    #[sea_orm(has_many = "super::audit_log::Entity")]
    AuditLog,
}

impl Related<super::api_key_group_permission::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApiKeyGroupPermission.def()
    }
}

impl Related<super::audit_log::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::AuditLog.def()
    }
}

impl Related<super::ip_group::Entity> for Entity {
    fn to() -> RelationDef {
        super::api_key_group_permission::Relation::IpGroup.def()
    }
    fn via() -> Option<RelationDef> {
        Some(
            super::api_key_group_permission::Relation::ApiKey
                .def()
                .rev(),
        )
    }
}

impl ActiveModelBehavior for ActiveModel {}
