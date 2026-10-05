//! The `ip_records` table: a canonical IP address or CIDR range.
//!
//! The row carries only the address and when it was first seen. Everything that varies by group —
//! lock, last observation, soft delete, cause — lives on
//! [`ip_record_group_membership`](crate::entities::ip_record_group_membership).

use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// A single IP address or CIDR range, shared by every group it belongs to.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "ip_records")]
pub struct Model {
    /// Unique identifier of the address.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// The address or CIDR range, canonicalised before storage. Unique: re-registering the same
    /// address reuses this row.
    #[sea_orm(unique)]
    pub target_address: String,
    /// When the address was first recorded anywhere.
    pub created_at: DateTime,
}

/// Relations from `ip_records` to other entities.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// Group memberships of this address.
    #[sea_orm(has_many = "super::ip_record_group_membership::Entity")]
    IpRecordGroupMembership,
}

impl ActiveModelBehavior for ActiveModel {}
