//! Whitelist groups whose active ranges are protected from bans in a specific banlist.

use sea_orm::entity::prelude::*;

/// One banlist-to-whitelist exclusion.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
#[sea_orm(table_name = "ip_group_exclusions")]
pub struct Model {
    /// Banlist whose policy references this exclusion.
    #[sea_orm(primary_key, auto_increment = false)]
    pub group_id: Uuid,
    /// Whitelist whose active memberships are protected.
    #[sea_orm(primary_key, auto_increment = false)]
    pub excluded_group_id: Uuid,
}

/// The banlist and whitelist endpoints of the exclusion.
#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    /// The banlist.
    #[sea_orm(
        belongs_to = "super::ip_group::Entity",
        from = "Column::GroupId",
        to = "super::ip_group::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    Group,
    /// The protected whitelist.
    #[sea_orm(
        belongs_to = "super::ip_group::Entity",
        from = "Column::ExcludedGroupId",
        to = "super::ip_group::Column::Id",
        on_update = "Cascade",
        on_delete = "Cascade"
    )]
    ExcludedGroup,
}

impl Related<super::ip_group::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::Group.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
