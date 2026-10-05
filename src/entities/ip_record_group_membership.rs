//! The `ip_record_group_memberships` table: one address's state within one group.
//!
//! This is where an address's operational state lives. The same address in two groups has two rows
//! here, and a change to one never touches the other. `last_seen_at` is the single timestamp for
//! the latest observation in this group.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// One address's stateful membership in one group.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "ip_record_group_memberships")]
pub struct Model {
    /// Surrogate identifier. Operations on a membership (lock, restore, purge) address it by this.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The address this membership is for.
    pub ip_record_id: Uuid,
    /// The group this membership is in.
    pub group_id: Uuid,
    /// When `true`, this membership cannot be modified or deleted through the API.
    pub is_locked: bool,
    /// When this address was first linked into this group.
    pub created_at: DateTime,
    /// The latest observation of this address in this group.
    pub last_seen_at: DateTime,
    /// Whether this membership is soft-deleted. Hidden from every read and from webhook dispatch
    /// until restored or purged by retention.
    pub is_deleted: bool,
    /// When the soft delete happened; `None` while live. The retention purge measures against this.
    pub deleted_at: Option<DateTime>,
    /// The `api_keys.id` of whoever soft-deleted it, as text. Not a foreign key, so the attribution
    /// outlives the key that performed the deletion.
    pub deleted_by: Option<String>,
}

/// Relations from `ip_record_group_memberships` to the entities it joins.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// The address this membership is for.
    #[sea_orm(
        belongs_to = "super::ip_record::Entity",
        from = "Column::IpRecordId",
        to = "super::ip_record::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    IpRecord,
    /// The group this membership is in.
    #[sea_orm(
        belongs_to = "super::ip_group::Entity",
        from = "Column::GroupId",
        to = "super::ip_group::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    IpGroup,
    /// The cause history recorded against this membership.
    #[sea_orm(has_many = "super::ip_record_cause::Entity")]
    IpRecordCause,
}

impl Related<super::ip_record::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::IpRecord.def()
    }
}

impl Related<super::ip_group::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::IpGroup.def()
    }
}

impl Related<super::ip_record_cause::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::IpRecordCause.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
