//! SeaORM entity definitions mirroring the tables described in `SCHEMA.MD`.

/// Re-exports of every entity type, for ergonomic `use crate::entities::prelude::*` imports.
pub mod prelude;

/// The `api_keys` table: authentication tokens, global rights, and CIDR bindings.
pub mod api_key;
/// The `api_key_group_permissions` M:N junction table between API keys and IP groups.
pub mod api_key_group_permission;
/// The `ip_groups` table: named, taggable collections of IP records.
pub mod ip_group;
/// The `ip_records` table: individual banned/whitelisted IPs or CIDR ranges.
pub mod ip_record;
/// The `ip_record_group_memberships` M:N junction table between IP records and groups.
pub mod ip_record_group_membership;
/// The `ip_record_causes` table: append-only cause history per membership.
pub mod ip_record_cause;
/// The `webhook_configs` table: outbound webhook endpoints scoped to an IP group.
pub mod webhook_config;
/// The `webhook_executions` table: one row per outbound HTTP attempt a webhook dispatch makes.
pub mod webhook_execution;
/// The `audit_logs` table: the audit trail of mutating operations.
pub mod audit_log;
