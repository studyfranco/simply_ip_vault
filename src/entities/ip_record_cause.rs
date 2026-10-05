//! The `ip_record_causes` table: an append-only history of the causes reported for a membership.
//!
//! One row per reported cause. A report with no cause writes no row, so an absent cause is simply
//! the absence of rows.

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// One cause reported against a membership, with the time it was reported.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "ip_record_causes")]
pub struct Model {
    /// Unique identifier of this cause entry.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The membership this cause was reported against.
    pub membership_id: Uuid,
    /// The cause text.
    pub cause: String,
    /// When this cause was reported.
    pub created_at: DateTime,
}

/// Relations from `ip_record_causes` to the membership it belongs to.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// The membership this cause belongs to.
    #[sea_orm(
        belongs_to = "super::ip_record_group_membership::Entity",
        from = "Column::MembershipId",
        to = "super::ip_record_group_membership::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    IpRecordGroupMembership,
}

impl Related<super::ip_record_group_membership::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::IpRecordGroupMembership.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
