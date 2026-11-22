//! Cover membership counts, last-seen listing scopes, and address-first lookups.

use super::prelude::*;
use sea_orm::sea_query::{Index as SqIndex, IndexOrder, IntoIndexColumn};

use crate::entities::ip_record_group_membership::{Column, Entity};

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &'static str {
        "m20261119_140000_add_membership_lookup_indexes"
    }
}

const NAMES: [&str; 4] = [
    "idx_memberships_active_group_count",
    "idx_memberships_active_seen_id",
    "idx_memberships_active_group_seen_id",
    "idx_memberships_record_active",
];

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        use Column::{GroupId, Id, IpRecordId, IsDeleted, LastSeenAt};

        let seen = (LastSeenAt, IndexOrder::Desc).into_index_column();
        let id = (Id, IndexOrder::Asc).into_index_column();
        let indexes = [
            vec![IsDeleted.into_index_column(), GroupId.into_index_column()],
            vec![IsDeleted.into_index_column(), seen.clone(), id.clone()],
            vec![
                IsDeleted.into_index_column(),
                GroupId.into_index_column(),
                seen,
                id,
            ],
            vec![
                IpRecordId.into_index_column(),
                IsDeleted.into_index_column(),
            ],
        ];

        for (name, columns) in NAMES.into_iter().zip(indexes) {
            let mut index = SqIndex::create();
            index.if_not_exists().name(name).table(Entity);
            for column in columns {
                index.col(column);
            }
            manager.create_index(index).await?;
        }
        Ok(())
    }

    async fn down(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        for name in NAMES {
            manager
                .drop_index(
                    SqIndex::drop()
                        .if_exists()
                        .name(name)
                        .table(Entity)
                        .to_owned(),
                )
                .await?;
        }
        Ok(())
    }
}
