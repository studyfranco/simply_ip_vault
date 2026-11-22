//! The `ip_groups` table: logical, named collections of IP rules (e.g. `fail2ban`, `sshd`,
//! `vpn_whitelist`), each tagged as either a `banlist` or a `whitelist`.

use sea_orm::entity::prelude::{
    ActiveModelBehavior, DeriveEntityModel, DerivePrimaryKey, DeriveRelation, EntityTrait,
    EnumIter, PrimaryKeyTrait, Related, RelationDef, RelationTrait, TimeDateTime as DateTime, Uuid,
};
use serde::{Deserialize, Serialize};

/// A named collection of IP records, tagged as a `banlist` or `whitelist`.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Eq, Serialize, Deserialize)]
#[sea_orm(table_name = "ip_groups")]
pub struct Model {
    /// Unique identifier for the group.
    #[sea_orm(primary_key, auto_increment = false)]
    pub id: Uuid,
    /// Group name used in API requests and the UI. Must be unique.
    #[sea_orm(unique)]
    pub name: String,
    /// The group's type: `"banlist"` or `"whitelist"`. Defaults to `"banlist"`.
    pub group_type: String,
    /// Whether bans may cover RFC1918, CGNAT, or IPv6 ULA addresses.
    #[serde(default)]
    pub allow_private_ips: bool,
    /// Optional detailed description of the group's purpose.
    pub description: Option<String>,
    /// The key holding lifecycle authority over this group, or `None` when unassigned.
    ///
    /// `RBAC_MODEL.md` §3: deleting or renaming the group itself is "restricted exclusively to Master
    /// and the designated `owner_key_id`", and "holding manage rights or any operational verb confers
    /// no lifecycle authority: a parent that merely uses a resource must not be able to delete it."
    /// Master may reassign it at any time.
    ///
    /// `None` on every pre-migration row: nothing in the schema recorded who created them, and
    /// inventing an owner would hand out the right to delete a resource. Unassigned reads as
    /// "Master only".
    #[serde(default)]
    pub owner_key_id: Option<Uuid>,
    /// Group creation timestamp.
    #[serde(with = "crate::time_serde")]
    pub created_at: DateTime,
}

/// Relations from `ip_groups` to other entities.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// Webhooks that fire on changes to IPs in this group.
    #[sea_orm(has_many = "super::webhook_config::Entity")]
    WebhookConfig,
    /// API-key permission grants scoped to this group.
    #[sea_orm(has_many = "super::api_key_group_permission::Entity")]
    ApiKeyGroupPermission,
    /// IP record memberships belonging to this group.
    #[sea_orm(has_many = "super::ip_record_group_membership::Entity")]
    IpRecordGroupMembership,
    /// Exclusions configured on this banlist.
    #[sea_orm(has_many = "super::ip_group_exclusion::Entity")]
    IpGroupExclusion,
}

impl Related<super::webhook_config::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::WebhookConfig.def()
    }
}

impl Related<super::api_key_group_permission::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::ApiKeyGroupPermission.def()
    }
}

impl Related<super::ip_record_group_membership::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::IpRecordGroupMembership.def()
    }
}

impl Related<super::ip_record::Entity> for Entity {
    fn to() -> RelationDef {
        super::ip_record_group_membership::Relation::IpRecord.def()
    }
    fn via() -> Option<RelationDef> {
        Some(
            super::ip_record_group_membership::Relation::IpGroup
                .def()
                .rev(),
        )
    }
}

impl Related<super::api_key::Entity> for Entity {
    fn to() -> RelationDef {
        super::api_key_group_permission::Relation::ApiKey.def()
    }
    fn via() -> Option<RelationDef> {
        Some(
            super::api_key_group_permission::Relation::IpGroup
                .def()
                .rev(),
        )
    }
}

impl Related<super::ip_group_exclusion::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::IpGroupExclusion.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
