//! The `audit_logs` table: the security audit trail tracking mutating operations across the
//! application.

use sea_orm::entity::prelude::{TimeDateTime as DateTime, *};
use serde::{Deserialize, Serialize};

/// A single audit trail entry for a mutating operation.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "audit_logs")]
pub struct Model {
    /// Unique audit log entry ID.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The API key that performed the action, if any (`None` for system/bootstrap actions, or
    /// if the key was later deleted — the FK is `ON DELETE SET NULL`).
    pub api_key_id: Option<Uuid>,
    /// The acting key's name, denormalized at write time so the audit trail stays legible even
    /// after that key is later deleted (unlike `api_key_id`, this is never nulled out by a
    /// cascade — it's a point-in-time snapshot, not a live join).
    ///
    /// **`NOT NULL` since `m20260811_000010`.** Because `api_key_id` is `ON DELETE SET NULL`, this
    /// and `api_key_prefix` are the *only* attribution that survives the key. A row with a nulled
    /// FK and no name would record an action with no actor at all. Historical rows that predate the
    /// constraint carry the literal `(unknown)`, which is deliberately not mistakable for a real
    /// key name.
    pub api_key_name: String,
    /// The acting key's prefix, denormalized for the same reason as `api_key_name`. `NOT NULL`.
    pub api_key_prefix: String,
    /// The caller's resolved client IP (rightmost `X-Forwarded-For` hop, `X-Real-IP`, or raw TCP
    /// peer address — see `middleware::auth_middleware`). `NOT NULL`: every audited route runs
    /// behind `auth_middleware`, which always resolves an address before a handler sees the request.
    pub client_ip: String,
    /// Operation type, e.g. `IP_ADD`, `IP_DELETE`, `KEY_CREATE`, `KEY_DELETE`, `KEY_PERM_UPDATE`,
    /// `GROUP_CREATE`, `GROUP_DELETE`, `WEBHOOK_CREATE`, `WEBHOOK_DELETE` (non-exhaustive).
    pub action: String,
    /// Target IP or CIDR range affected, if applicable.
    pub target_address: Option<String>,
    /// Comma-separated list of group names involved, if applicable.
    pub group_names: Option<String>,
    /// Additional context or a raw payload overview.
    pub details: Option<String>,
    /// Log creation timestamp.
    #[serde(with = "crate::time_serde")]
    pub timestamp: DateTime,
}

/// Relations from `audit_logs` to other entities.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// The API key that performed the audited action.
    #[sea_orm(
        belongs_to = "super::api_key::Entity",
        from = "Column::ApiKeyId",
        to = "super::api_key::Column::Id",
        on_update = "NoAction",
        on_delete = "SetNull"
    )]
    ApiKey,
}

impl Related<super::api_key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApiKey.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
