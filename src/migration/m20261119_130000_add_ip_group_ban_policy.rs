use sea_orm_migration::prelude::*;

#[derive(DeriveMigrationName)]
pub struct Migration;

#[derive(DeriveIden)]
enum IpGroups {
    Table,
    Id,
    AllowPrivateIps,
}

#[derive(DeriveIden, Clone, Copy)]
enum IpGroupExclusions {
    Table,
    GroupId,
    ExcludedGroupId,
}

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        use IpGroupExclusions::{ExcludedGroupId, GroupId};
        manager
            .alter_table(
                Table::alter()
                    .table(IpGroups::Table)
                    .add_column(
                        ColumnDef::new(IpGroups::AllowPrivateIps)
                            .boolean()
                            .not_null()
                            .default(false),
                    )
                    .to_owned(),
            )
            .await?;
        let mut table = Table::create();
        table
            .table(IpGroupExclusions::Table)
            .col(ColumnDef::new(GroupId).uuid().not_null())
            .col(ColumnDef::new(ExcludedGroupId).uuid().not_null())
            .primary_key(Index::create().col(GroupId).col(ExcludedGroupId));
        for (column, name) in [
            (GroupId, "fk_ip_group_exclusions_group"),
            (ExcludedGroupId, "fk_ip_group_exclusions_excluded_group"),
        ] {
            table.foreign_key(
                ForeignKey::create()
                    .name(name)
                    .from(IpGroupExclusions::Table, column)
                    .to(IpGroups::Table, IpGroups::Id)
                    .on_delete(ForeignKeyAction::Cascade)
                    .on_update(ForeignKeyAction::Cascade),
            );
        }
        manager.create_table(table).await?;
        manager
            .create_index(
                Index::create()
                    .name("idx_ip_group_exclusions_excluded_group_id")
                    .table(IpGroupExclusions::Table)
                    .col(ExcludedGroupId)
                    .to_owned(),
            )
            .await
    }

    async fn down(&self, manager: &SchemaManager) -> Result<(), DbErr> {
        manager
            .drop_table(Table::drop().table(IpGroupExclusions::Table).to_owned())
            .await?;
        manager
            .alter_table(
                Table::alter()
                    .table(IpGroups::Table)
                    .drop_column(IpGroups::AllowPrivateIps)
                    .to_owned(),
            )
            .await
    }
}
