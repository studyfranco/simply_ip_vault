//! Make `idx_causes_membership_created` cover `(membership_id, created_at DESC, cause)`.

use super::prelude::*;
use sea_orm::sea_query::{Index as SqIndex, IndexOrder, IntoIndexColumn};

use crate::entities::ip_record_cause::{Column, Entity};

pub struct Migration;

impl MigrationName for Migration {
    fn name(&self) -> &'static str {
        "m20261122_120000_cover_causes_latest_lookup"
    }
}

const INDEX_NAME: &str = "idx_causes_membership_created";

#[async_trait::async_trait]
impl MigrationTrait for Migration {
    async fn up(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .drop_index(
                SqIndex::drop()
                    .if_exists()
                    .name(INDEX_NAME)
                    .table(Entity)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name(INDEX_NAME)
                    .table(Entity)
                    .col(Column::MembershipId)
                    .col((Column::CreatedAt, IndexOrder::Desc).into_index_column())
                    .col(Column::Cause)
                    .to_owned(),
            )
            .await?;

        Ok(())
    }

    async fn down(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr> {
        manager
            .drop_index(
                SqIndex::drop()
                    .if_exists()
                    .name(INDEX_NAME)
                    .table(Entity)
                    .to_owned(),
            )
            .await?;

        manager
            .create_index(
                SqIndex::create()
                    .if_not_exists()
                    .name(INDEX_NAME)
                    .table(Entity)
                    .col(Column::MembershipId)
                    .col((Column::CreatedAt, IndexOrder::Desc).into_index_column())
                    .to_owned(),
            )
            .await?;

        Ok(())
    }
}
