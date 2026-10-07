//! Database migration registry for `simply_ip_vault`. Migrations run automatically on startup.
pub use sea_orm_migration::prelude::*;

mod m20230101_000001_initial_schema;
mod m20260729_000002_add_api_key_signing_secret;
mod m20260730_000003_add_webhook_signature_mode;
mod m20260730_000004_add_webhook_auth_modes;
mod m20260801_000005_add_ip_record_soft_delete;
mod m20260804_000006_add_group_permission_can_manage;
mod m20260807_000007_add_api_key_master_marker;
mod m20260807_000008_add_lineage_and_ownership;
mod m20260808_000009_derive_master_marker;
mod m20260811_000010_audit_attribution_not_null;
mod m20260811_000011_index_ip_record_delta_columns;
mod m20260811_000012_webhook_hmac_only_mode;
mod m20260824_093000_add_webhook_executions;
mod m20260824_110000_webhook_execution_response_body;
mod m20260824_140000_webhook_execution_event_context;
mod m20260824_150000_add_query_performance_indexes;
mod m20260926_120000_add_membership_timestamps;
mod m20261005_120000_add_foreign_key_indexes;
mod m20261006_120000_refactor_membership_state;
mod m20261007_120000_add_webhook_query_indexes;
mod m20261008_120000_add_simple_foreign_key_indexes;

/// The ordered set of all schema migrations for `simply_ip_vault`.
pub struct Migrator;

#[async_trait::async_trait]
impl MigratorTrait for Migrator {
    fn migrations() -> Vec<Box<dyn MigrationTrait>> {
        vec![
            Box::new(m20230101_000001_initial_schema::Migration),
            Box::new(m20260729_000002_add_api_key_signing_secret::Migration),
            Box::new(m20260730_000003_add_webhook_signature_mode::Migration),
            Box::new(m20260730_000004_add_webhook_auth_modes::Migration),
            Box::new(m20260801_000005_add_ip_record_soft_delete::Migration),
            Box::new(m20260804_000006_add_group_permission_can_manage::Migration),
            Box::new(m20260807_000007_add_api_key_master_marker::Migration),
            Box::new(m20260807_000008_add_lineage_and_ownership::Migration),
            Box::new(m20260808_000009_derive_master_marker::Migration),
            Box::new(m20260811_000010_audit_attribution_not_null::Migration),
            Box::new(m20260811_000011_index_ip_record_delta_columns::Migration),
            Box::new(m20260811_000012_webhook_hmac_only_mode::Migration),
            Box::new(m20260824_093000_add_webhook_executions::Migration),
            Box::new(m20260824_110000_webhook_execution_response_body::Migration),
            Box::new(m20260824_140000_webhook_execution_event_context::Migration),
            Box::new(m20260824_150000_add_query_performance_indexes::Migration),
            Box::new(m20260926_120000_add_membership_timestamps::Migration),
            Box::new(m20261005_120000_add_foreign_key_indexes::Migration),
            Box::new(m20261006_120000_refactor_membership_state::Migration),
            Box::new(m20261007_120000_add_webhook_query_indexes::Migration),
            Box::new(m20261008_120000_add_simple_foreign_key_indexes::Migration),
        ]
    }
}
