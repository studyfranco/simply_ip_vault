//! The `api_key_group_permissions` M:N junction table: fine-grained read/write/delete rights
//! that a given API key holds over a given IP group.

use sea_orm::entity::prelude::{TimeDateTime as DateTime, *};
use serde::{Deserialize, Serialize};

/// A single (API key, IP group) permission grant.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[expect(
    clippy::struct_excessive_bools,
    reason = "SeaORM DeriveEntityModel requires flat 1:1 fields for SQL BOOLEAN columns"
)]
#[sea_orm(table_name = "api_key_group_permissions")]
pub struct Model {
    /// Unique identifier for the permission grant.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The API key this grant applies to.
    pub api_key_id: Uuid,
    /// The IP group this grant applies to.
    pub group_id: Uuid,
    /// Permission to view IPs within this group.
    pub can_read: bool,
    /// Permission to add/update IPs in this group. Implies `can_read`.
    pub can_write: bool,
    /// Permission to remove IPs from this group. Implies `can_read`.
    pub can_delete: bool,
    /// Permission to administer *this group's* permission rows.
    ///
    /// Resource-scoped counterpart to the global `api_keys.can_manage_keys`, and deliberately
    /// narrower than it: this satisfies the **revoke** path only. Granting or widening a verb still
    /// requires `can_manage_keys`, because conferring authority must not be delegable by a right
    /// that is itself scoped to one group. See `AGENT.MD` §2.
    pub can_manage: bool,
    /// Assignment timestamp.
    #[serde(with = "crate::time_serde")]
    pub created_at: DateTime,
}

/// Relations from `api_key_group_permissions` to the entities it joins.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// The API key holding this grant.
    #[sea_orm(
        belongs_to = "super::api_key::Entity",
        from = "Column::ApiKeyId",
        to = "super::api_key::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    ApiKey,
    /// The IP group this grant covers.
    #[sea_orm(
        belongs_to = "super::ip_group::Entity",
        from = "Column::GroupId",
        to = "super::ip_group::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    IpGroup,
}

impl Related<super::api_key::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApiKey.def()
    }
}

impl Related<super::ip_group::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::IpGroup.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
