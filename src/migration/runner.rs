//! Schema operations and migration history backed by `SeaORM` and `sea-schema`.

use std::collections::HashSet;

use sea_orm::{
    ConnectionTrait, DatabaseConnection, DatabaseExecutor, DbBackend, DbErr, IntoDatabaseExecutor,
    StatementBuilder, TransactionTrait,
};
use sea_schema::probe::SchemaProbe;

use super::prelude::*;

mod history {
    use sea_orm::entity::prelude::*;

    #[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel)]
    #[sea_orm(table_name = "seaql_migrations")]
    pub struct Model {
        #[sea_orm(primary_key, auto_increment = false)]
        pub version: String,
        pub applied_at: i64,
    }

    #[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
    pub enum Relation {}

    impl ActiveModelBehavior for ActiveModel {}
}

/// Executes schema changes on a connection or transaction.
pub struct SchemaManager<'c> {
    connection: DatabaseExecutor<'c>,
}

macro_rules! schema_operations {
    ($($method:ident: $statement:ty => $doc:literal),* $(,)?) => {
        $(
            #[doc = $doc]
            ///
            /// # Errors
            ///
            /// Returns the database error if the statement fails.
            pub async fn $method(&self, statement: $statement) -> Result<(), DbErr> {
                self.exec_stmt(statement).await
            }
        )*
    };
}

macro_rules! schema_probes {
    ($($method:ident($($arg:ident),+) => $doc:literal),* $(,)?) => {
        $(
            #[doc = $doc]
            ///
            /// # Errors
            ///
            /// Returns an error if the catalog query fails or its result is invalid.
            pub async fn $method(&self, $($arg: impl AsRef<str>),+) -> Result<bool, DbErr> {
                let statement = match self.get_database_backend() {
                    DbBackend::Sqlite => sea_schema::sqlite::Sqlite.$method($($arg),+),
                    DbBackend::Postgres => sea_schema::postgres::Postgres.$method($($arg),+),
                    DbBackend::MySql => sea_schema::mysql::MySql.$method($($arg),+),
                    backend => return Err(DbErr::BackendNotSupported {
                        db: backend.as_str(),
                        ctx: stringify!($method),
                    }),
                };
                self.connection.query_one(&statement).await?
                    .ok_or_else(|| DbErr::Custom(concat!(stringify!($method), " returned no result").into()))?
                    .try_get("", stringify!($method))
            }
        )*
    };
}

impl<'c> SchemaManager<'c> {
    /// Wraps a `SeaORM` connection or transaction.
    #[must_use]
    pub fn new(connection: impl IntoDatabaseExecutor<'c>) -> Self {
        Self {
            connection: connection.into_database_executor(),
        }
    }

    /// Returns the executor used by schema and data changes.
    #[must_use]
    pub fn get_connection(&self) -> &DatabaseExecutor<'c> {
        &self.connection
    }

    /// Returns the database backend.
    #[must_use]
    pub fn get_database_backend(&self) -> DbBackend {
        self.connection.get_database_backend()
    }

    /// Executes a query-builder statement.
    ///
    /// # Errors
    ///
    /// Returns the database error if the statement fails.
    pub async fn exec_stmt(&self, statement: impl StatementBuilder) -> Result<(), DbErr> {
        self.connection.execute(&statement).await.map(|_| ())
    }

    schema_operations! {
        create_table: TableCreateStatement => "Creates a table.",
        alter_table: TableAlterStatement => "Alters a table.",
        rename_table: TableRenameStatement => "Renames a table.",
        drop_table: TableDropStatement => "Drops a table.",
        create_index: IndexCreateStatement => "Creates an index.",
        drop_index: IndexDropStatement => "Drops an index.",
    }

    schema_probes! {
        has_table(table) => "Checks for a table in the current schema.",
        has_column(table, column) => "Checks for a column on the given table.",
        has_index(table, index) => "Checks for an index on the given table.",
    }
}

/// Identifies a migration by its persisted version string.
pub trait MigrationName {
    /// Returns the version recorded in the migration history.
    fn name(&self) -> &'static str;
}

/// Applies and reverses a schema or data migration.
#[async_trait::async_trait]
pub trait MigrationTrait: MigrationName + Send + Sync {
    /// Applies this migration.
    ///
    /// # Errors
    ///
    /// Returns an error if a schema or data change fails.
    async fn up(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr>;

    /// Reverses this migration.
    ///
    /// # Errors
    ///
    /// Returns an error if the migration is irreversible or a change fails.
    async fn down(&self, manager: &SchemaManager<'_>) -> Result<(), DbErr>;
}

/// Runs an ordered registry of migrations against the legacy migration ledger.
#[async_trait::async_trait]
pub trait MigratorTrait {
    /// Returns migrations in application order.
    fn migrations() -> Vec<Box<dyn MigrationTrait>>;

    /// Applies pending migrations in registry order, optionally limited by step count.
    ///
    /// # Errors
    ///
    /// Returns an error if the migration history is unknown or a migration fails.
    #[must_use]
    async fn up(db: &DatabaseConnection, steps: Option<u32>) -> Result<(), DbErr> {
        run(db, Self::migrations(), steps, Direction::Up).await
    }

    /// Reverses applied migrations in reverse registry order, optionally limited by step count.
    ///
    /// # Errors
    ///
    /// Returns an error if the migration history is unknown or a rollback fails.
    #[must_use]
    async fn down(db: &DatabaseConnection, steps: Option<u32>) -> Result<(), DbErr> {
        run(db, Self::migrations(), steps, Direction::Down).await
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Direction {
    Up,
    Down,
}

async fn run(
    db: &DatabaseConnection,
    mut migrations: Vec<Box<dyn MigrationTrait>>,
    steps: Option<u32>,
    direction: Direction,
) -> Result<(), DbErr> {
    use sea_orm::{EntityTrait, Schema};

    let manager = SchemaManager::new(db);
    let table = Schema::new(manager.get_database_backend())
        .create_table_from_entity(history::Entity)
        .if_not_exists()
        .take();
    manager.create_table(table).await?;

    let applied: HashSet<_> = history::Entity::find()
        .all(db)
        .await?
        .into_iter()
        .map(|row| row.version)
        .collect();
    for version in &applied {
        if !migrations
            .iter()
            .any(|migration| migration.name() == version)
        {
            return Err(DbErr::Custom(format!(
                "Unknown applied migration {version}"
            )));
        }
    }
    if direction == Direction::Down {
        migrations.reverse();
    }
    let limit = steps.map_or(usize::MAX, |steps| steps as usize);
    for migration in migrations
        .iter()
        .filter(|migration| applied.contains(migration.name()) == (direction == Direction::Down))
        .take(limit)
    {
        // Preserve the former runner's backend defaults. PostgreSQL commits each
        // DDL change and its ledger entry together.
        if manager.get_database_backend() == DbBackend::Postgres {
            let transaction = db.begin().await?;
            run_step(
                &SchemaManager::new(&transaction),
                migration.as_ref(),
                direction,
            )
            .await?;
            transaction.commit().await?;
        } else {
            run_step(&manager, migration.as_ref(), direction).await?;
        }
    }
    Ok(())
}

async fn run_step(
    manager: &SchemaManager<'_>,
    migration: &dyn MigrationTrait,
    direction: Direction,
) -> Result<(), DbErr> {
    use sea_orm::{ActiveValue::Set, EntityTrait};

    let db = manager.get_connection();
    match direction {
        Direction::Up => {
            migration.up(manager).await?;
            history::Entity::insert(history::ActiveModel {
                version: Set(migration.name().to_owned()),
                applied_at: Set(time::OffsetDateTime::now_utc().unix_timestamp()),
            })
            .exec(db)
            .await?;
        }
        Direction::Down => {
            migration.down(manager).await?;
            history::Entity::delete_by_id(migration.name().to_owned())
                .exec(db)
                .await?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use sea_orm::{ActiveValue::Set, Database, EntityTrait, QueryOrder};

    use super::*;
    use crate::migration::Migrator;

    #[tokio::test]
    async fn resumes_a_database_with_legacy_migration_history() {
        let legacy_versions = [
            "m20230101_000001_initial_schema",
            "m20260729_000002_add_api_key_signing_secret",
            "m20260730_000003_add_webhook_signature_mode",
            "m20260730_000004_add_webhook_auth_modes",
            "m20260801_000005_add_ip_record_soft_delete",
            "m20260804_000006_add_group_permission_can_manage",
            "m20260807_000007_add_api_key_master_marker",
            "m20260807_000008_add_lineage_and_ownership",
            "m20260808_000009_derive_master_marker",
            "m20260811_000010_audit_attribution_not_null",
            "m20260811_000011_index_ip_record_delta_columns",
            "m20260811_000012_webhook_hmac_only_mode",
            "m20260824_093000_add_webhook_executions",
            "m20260824_110000_webhook_execution_response_body",
            "m20260824_140000_webhook_execution_event_context",
            "m20260824_150000_add_query_performance_indexes",
            "m20260926_120000_add_membership_timestamps",
            "m20261005_120000_add_foreign_key_indexes",
            "m20261006_120000_refactor_membership_state",
            "m20261007_120000_add_webhook_query_indexes",
            "m20261008_120000_add_simple_foreign_key_indexes",
            "m20261009_120000_make_listing_indexes_covering",
            "m20261010_120000_add_differential_sync_indexes",
            "m20261011_120000_optimize_global_listing_and_counts",
            "m20261012_120000_add_memberships_is_deleted_index",
            "m20261013_120000_add_group_is_deleted_last_seen_index",
            "m20261014_120000_add_query_optimization_indexes",
            "m20261111_120000_add_analytics_and_overlap_indexes",
            "m20261111_160000_add_stats_perf_indexes",
            "m20261111_190000_fix_sqlite_listing_index_regression",
            "m20261114_120000_add_webhook_send_normalized_ipv6",
            "m20261119_120000_widen_variable_length_columns",
            "m20261119_130000_add_ip_group_ban_policy",
            "m20261119_140000_add_membership_lookup_indexes",
        ];
        let migrations = Migrator::migrations();
        assert_eq!(
            migrations
                .iter()
                .map(|migration| migration.name())
                .collect::<Vec<_>>(),
            legacy_versions
        );

        let db = Database::connect("sqlite::memory:").await.unwrap();
        let manager = SchemaManager::new(&db);
        let table = Alias::new("seaql_migrations");
        manager
            .create_table(
                Table::create()
                    .table(table.clone())
                    .col(
                        ColumnDef::new(Alias::new("version"))
                            .string()
                            .not_null()
                            .primary_key(),
                    )
                    .col(
                        ColumnDef::new(Alias::new("applied_at"))
                            .big_integer()
                            .not_null(),
                    )
                    .take(),
            )
            .await
            .unwrap();

        let (latest_version, earlier_versions) = legacy_versions.split_last().unwrap();
        for (migration, version) in migrations.iter().zip(earlier_versions) {
            migration.up(&manager).await.unwrap();
            history::Entity::insert(history::ActiveModel {
                version: Set((*version).to_owned()),
                applied_at: Set(1_700_000_000),
            })
            .exec(&db)
            .await
            .unwrap();
        }

        Migrator::up(&db, None).await.unwrap();
        let rows = history::Entity::find()
            .order_by_asc(history::Column::Version)
            .all(&db)
            .await
            .unwrap();
        assert_eq!(rows.len(), legacy_versions.len());
        for (row, version) in rows.iter().zip(earlier_versions) {
            assert_eq!(&row.version, version);
            assert_eq!(row.applied_at, 1_700_000_000);
        }
        let latest = rows.last().unwrap();
        assert_eq!(&latest.version, latest_version);
        assert!(latest.applied_at > 1_700_000_000);

        Migrator::down(&db, Some(1)).await.unwrap();
        assert_eq!(
            history::Entity::find().all(&db).await.unwrap().len(),
            earlier_versions.len()
        );
        Migrator::up(&db, None).await.unwrap();
    }

    #[tokio::test]
    async fn creates_the_legacy_migration_table_on_a_fresh_database() {
        let db = Database::connect("sqlite::memory:").await.unwrap();
        Migrator::up(&db, Some(0)).await.unwrap();
        let columns = db
            .query_all(
                &Query::select()
                    .columns([
                        Alias::new("name"),
                        Alias::new("type"),
                        Alias::new("notnull"),
                        Alias::new("pk"),
                    ])
                    .from_function(
                        Func::cust(Alias::new("pragma_table_info")).arg("seaql_migrations"),
                        Alias::new("info"),
                    )
                    .take(),
            )
            .await
            .unwrap();
        let schema: Vec<(String, String, i32, i32)> = columns
            .iter()
            .map(|column| {
                (
                    column.try_get("", "name").unwrap(),
                    column
                        .try_get::<String>("", "type")
                        .unwrap()
                        .to_ascii_lowercase(),
                    column.try_get("", "notnull").unwrap(),
                    column.try_get("", "pk").unwrap(),
                )
            })
            .collect();
        assert_eq!(schema.len(), 2);
        // SeaQuery renders a 64-bit integer as SQLite INTEGER.
        assert_eq!(
            schema[0],
            ("version".to_owned(), "varchar".to_owned(), 1, 1)
        );
        assert_eq!(
            schema[1],
            ("applied_at".to_owned(), "integer".to_owned(), 1, 0)
        );
    }
}
