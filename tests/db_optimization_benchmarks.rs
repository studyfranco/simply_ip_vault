//! Systematic database query optimization benchmarks and plan verification.
//!
//! Validates execution time and query plans before and after optimizations:
//! 1. `webhook_executions`: `idx_webhook_executions_success_created`,
//!    `idx_webhook_executions_status_code_created`, `idx_webhook_executions_event_type_created`.
//! 2. `ip_groups`: `idx-ip_groups-group_type`.
//! 3. `audit_logs`: `idx_audit_logs_api_key_timestamp`.
//! 4. API keys listing: Batched permission loading vs N+1 queries.

use chrono::{Duration as ChronoDuration, Utc};
use sea_orm::{
    ColumnTrait, ConnectionTrait, DatabaseBackend, DatabaseConnection, EntityTrait, QueryFilter,
    QueryOrder, QuerySelect, Statement,
};
use sea_orm_migration::MigratorTrait;
use std::time::Instant;
use uuid::Uuid;

use simply_ip_vault::entities::{
    api_key, api_key_group_permission, audit_log, ip_group, webhook_config, webhook_execution,
};

/// Boots an in-memory SQLite database up to a specific migration step, or all if `None`.
async fn bench_db_with_migrations(steps: Option<u32>) -> DatabaseConnection {
    let db = simply_ip_vault::db::connect("sqlite::memory:")
        .await
        .expect("in-memory sqlite connects");
    simply_ip_vault::migration::Migrator::up(&db, steps)
        .await
        .expect("migrations apply");
    db
}

/// Runs `EXPLAIN QUERY PLAN` for a SQL query string.
async fn explain(db: &DatabaseConnection, sql: &str) -> String {
    let rows = db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            format!("EXPLAIN QUERY PLAN {sql};"),
        ))
        .await
        .expect("explain query plan runs");
    rows.into_iter()
        .map(|r| r.try_get::<String>("", "detail").unwrap())
        .collect::<Vec<_>>()
        .join(" | ")
}

#[tokio::test]
async fn bench_webhook_executions_retention_and_status_optimization() {
    // db_before has migrations up to 26 (WITHOUT migration 27 indexes)
    let db_before = bench_db_with_migrations(Some(26)).await;
    // db_after has ALL migrations (WITH migration 27 indexes)
    let db_after = bench_db_with_migrations(None).await;

    let group_id = Uuid::new_v4();
    let webhook_id = Uuid::new_v4();
    let now = Utc::now().naive_utc();

    for db in [&db_before, &db_after] {
        ip_group::Entity::insert(ip_group::ActiveModel {
            id: sea_orm::Set(group_id),
            name: sea_orm::Set("bench_group".to_owned()),
            group_type: sea_orm::Set("banlist".to_owned()),
            description: sea_orm::Set(None),
            owner_key_id: sea_orm::Set(None),
            created_at: sea_orm::Set(now),
        })
        .exec(db)
        .await
        .unwrap();

        webhook_config::Entity::insert(webhook_config::ActiveModel {
            id: sea_orm::Set(webhook_id),
            name: sea_orm::Set("bench_hook".to_owned()),
            target_url: sea_orm::Set("https://example.com/webhook".to_owned()),
            secret_token: sea_orm::Set("secret".to_owned()),
            auth_mode: sea_orm::Set("CANONICAL_V1".to_owned()),
            api_key: sea_orm::Set(None),
            hmac_template: sea_orm::Set(None),
            signature_header: sea_orm::Set(None),
            signature_prefix: sea_orm::Set(None),
            headers_json: sea_orm::Set(None),
            payload_template: sea_orm::Set(r#"{"test":true}"#.to_owned()),
            group_id: sea_orm::Set(group_id),
            is_active: sea_orm::Set(true),
            events: sea_orm::Set(None),
            owner_key_id: sea_orm::Set(None),
            created_at: sea_orm::Set(now),
        })
        .exec(db)
        .await
        .unwrap();

        // Seed 10,000 execution rows in batches of 500
        let mut rows = Vec::with_capacity(500);
        for i in 0..10_000 {
            let is_success = i % 2 == 0;
            let status_code = if is_success { 200 } else { 500 + (i % 5) };
            let event_type = match i % 3 {
                0 => "IP_ADD",
                1 => "IP_UPDATE",
                _ => "IP_DELETE",
            };
            let age_hours = (i % 100) as i64;
            let created_at = now - ChronoDuration::hours(age_hours);

            rows.push(webhook_execution::ActiveModel {
                id: sea_orm::Set(Uuid::new_v4()),
                webhook_id: sea_orm::Set(webhook_id),
                event_type: sea_orm::Set(event_type.to_owned()),
                status_code: sea_orm::Set(Some(status_code)),
                is_success: sea_orm::Set(is_success),
                duration_ms: sea_orm::Set(10 + (i % 50)),
                response_body: sea_orm::Set(Some("ok".to_owned())),
                resolved_target_url: sea_orm::Set(Some("https://example.com/webhook".to_owned())),
                target_address: sea_orm::Set(Some(format!("10.0.{}.{}", (i / 256) % 256, i % 256))),
                cause: sea_orm::Set(None),
                created_at: sea_orm::Set(created_at),
            });

            if rows.len() >= 500 {
                webhook_execution::Entity::insert_many(rows.split_off(0))
                    .exec(db)
                    .await
                    .unwrap();
            }
        }
        if !rows.is_empty() {
            webhook_execution::Entity::insert_many(rows)
                .exec(db)
                .await
                .unwrap();
        }
    }

    // 1. Verify query plan BEFORE optimization (no index on (status_code, created_at))
    let sql = "SELECT * FROM webhook_executions WHERE status_code = 500 ORDER BY created_at DESC LIMIT 50";
    let plan_before = explain(&db_before, sql).await;
    println!("Webhook executions status plan (BEFORE optimization): {plan_before}");
    assert!(
        plan_before.contains("SCAN webhook_executions") || plan_before.contains("TEMP B-TREE"),
        "Before optimization must do full table scan or sort: {plan_before}"
    );

    // 2. Verify query plan AFTER optimization
    let plan_after = explain(&db_after, sql).await;
    println!("Webhook executions status plan (AFTER optimization): {plan_after}");
    assert!(
        plan_after.contains("idx_webhook_executions_status_code_created"),
        "After optimization must use idx_webhook_executions_status_code_created: {plan_after}"
    );
    assert!(
        !plan_after.contains("TEMP B-TREE"),
        "After optimization must not use TEMP B-TREE: {plan_after}"
    );

    // 3. Measure execution times
    let start_before = Instant::now();
    for _ in 0..50 {
        let _ = webhook_execution::Entity::find()
            .filter(webhook_execution::Column::StatusCode.eq(500))
            .order_by_desc(webhook_execution::Column::CreatedAt)
            .limit(50)
            .all(&db_before)
            .await
            .unwrap();
    }
    let dur_before = start_before.elapsed() / 50;

    let start_after = Instant::now();
    for _ in 0..50 {
        let _ = webhook_execution::Entity::find()
            .filter(webhook_execution::Column::StatusCode.eq(500))
            .order_by_desc(webhook_execution::Column::CreatedAt)
            .limit(50)
            .all(&db_after)
            .await
            .unwrap();
    }
    let dur_after = start_after.elapsed() / 50;

    println!(
        "Webhook executions query (10,000 rows): before = {:?}, after = {:?}",
        dur_before, dur_after
    );
    assert!(
        dur_after < std::time::Duration::from_millis(10),
        "Optimized query should complete well under 10ms budget, took {:?}",
        dur_after
    );
}

#[tokio::test]
async fn bench_audit_logs_api_key_timestamp_optimization() {
    let db_before = bench_db_with_migrations(Some(26)).await;
    let db_after = bench_db_with_migrations(None).await;

    let key_id = Uuid::new_v4();
    let other_key_id = Uuid::new_v4();
    let now = Utc::now().naive_utc();

    for db in [&db_before, &db_after] {
        for kid in [key_id, other_key_id] {
            api_key::Entity::insert(api_key::ActiveModel {
                id: sea_orm::Set(kid),
                name: sea_orm::Set("bench_key".to_owned()),
                key_hash: sea_orm::Set(format!("hash_{kid}")),
                signing_secret: sea_orm::Set(Some("v1.plain.1234".to_owned())),
                prefix: sea_orm::Set("bk_12345".to_owned()),
                bound_ips: sea_orm::Set(None),
                is_master: sea_orm::Set(false),
                can_manage_keys: sea_orm::Set(false),
                can_manage_webhooks: sea_orm::Set(false),
                can_create_groups: sea_orm::Set(false),
                parent_key_id: sea_orm::Set(None),
                created_at: sea_orm::Set(now),
                updated_at: sea_orm::Set(now),
            })
            .exec(db)
            .await
            .unwrap();
        }

        // Seed 5,000 audit log entries in batches of 500
        let mut rows = Vec::with_capacity(500);
        for i in 0..5_000 {
            let acting_key = if i % 2 == 0 { key_id } else { other_key_id };
            rows.push(audit_log::ActiveModel {
                id: sea_orm::Set(Uuid::new_v4()),
                api_key_id: sea_orm::Set(Some(acting_key)),
                api_key_name: sea_orm::Set("bench_key".to_owned()),
                api_key_prefix: sea_orm::Set("bk_12345".to_owned()),
                client_ip: sea_orm::Set("127.0.0.1".to_owned()),
                action: sea_orm::Set("IP_ADD".to_owned()),
                target_address: sea_orm::Set(Some("192.168.1.1".to_owned())),
                group_names: sea_orm::Set(Some("bench".to_owned())),
                details: sea_orm::Set(None),
                timestamp: sea_orm::Set(now - ChronoDuration::seconds(i as i64)),
            });

            if rows.len() >= 500 {
                audit_log::Entity::insert_many(rows.split_off(0))
                    .exec(db)
                    .await
                    .unwrap();
            }
        }
        if !rows.is_empty() {
            audit_log::Entity::insert_many(rows).exec(db).await.unwrap();
        }
    }

    let sql = format!(
        "SELECT * FROM audit_logs WHERE api_key_id = X'{}' ORDER BY timestamp DESC LIMIT 50",
        hex::encode(key_id.as_bytes())
    );

    // Plan BEFORE optimization has a TEMP B-TREE because idx-audit_logs-api_key_id does not carry timestamp
    let plan_before = explain(&db_before, &sql).await;
    println!("Audit logs query plan (BEFORE optimization): {plan_before}");
    assert!(
        plan_before.contains("TEMP B-TREE"),
        "Before optimization must sort in temporary B-tree: {plan_before}"
    );

    // Plan AFTER optimization uses idx_audit_logs_api_key_timestamp without TEMP B-TREE
    let plan_after = explain(&db_after, &sql).await;
    println!("Audit logs query plan (AFTER optimization): {plan_after}");
    assert!(
        plan_after.contains("idx_audit_logs_api_key_timestamp"),
        "After optimization must use idx_audit_logs_api_key_timestamp: {plan_after}"
    );
    assert!(
        !plan_after.contains("TEMP B-TREE"),
        "After optimization must not sort in temporary B-tree: {plan_after}"
    );

    let start_before = Instant::now();
    for _ in 0..50 {
        let _ = audit_log::Entity::find()
            .filter(audit_log::Column::ApiKeyId.eq(key_id))
            .order_by_desc(audit_log::Column::Timestamp)
            .limit(50)
            .all(&db_before)
            .await
            .unwrap();
    }
    let dur_before = start_before.elapsed() / 50;

    let start_after = Instant::now();
    for _ in 0..50 {
        let _ = audit_log::Entity::find()
            .filter(audit_log::Column::ApiKeyId.eq(key_id))
            .order_by_desc(audit_log::Column::Timestamp)
            .limit(50)
            .all(&db_after)
            .await
            .unwrap();
    }
    let dur_after = start_after.elapsed() / 50;

    println!(
        "Audit logs by key query (5,000 rows): before = {:?}, after = {:?}",
        dur_before, dur_after
    );
    assert!(
        dur_after < std::time::Duration::from_millis(10),
        "Optimized query should complete well under 10ms budget, took {:?}",
        dur_after
    );
}

#[tokio::test]
async fn bench_api_keys_batching_vs_n_plus_one() {
    let db = bench_db_with_migrations(None).await;

    // Seed 10 groups
    let mut group_ids = Vec::new();
    for i in 0..10 {
        let gid = Uuid::new_v4();
        ip_group::Entity::insert(ip_group::ActiveModel {
            id: sea_orm::Set(gid),
            name: sea_orm::Set(format!("group_{i}")),
            group_type: sea_orm::Set("banlist".to_owned()),
            description: sea_orm::Set(None),
            owner_key_id: sea_orm::Set(None),
            created_at: sea_orm::Set(Utc::now().naive_utc()),
        })
        .exec(&db)
        .await
        .unwrap();
        group_ids.push(gid);
    }

    // Seed 50 keys, each with 3 group permissions
    let mut key_ids = Vec::new();
    let now = Utc::now().naive_utc();
    for i in 0..50 {
        let kid = Uuid::new_v4();
        api_key::Entity::insert(api_key::ActiveModel {
            id: sea_orm::Set(kid),
            name: sea_orm::Set(format!("key_{i}")),
            key_hash: sea_orm::Set(format!("hash_{i}")),
            signing_secret: sea_orm::Set(Some("v1.plain.1234".to_owned())),
            prefix: sea_orm::Set(format!("k_{i:06}")),
            bound_ips: sea_orm::Set(None),
            is_master: sea_orm::Set(false),
            can_manage_keys: sea_orm::Set(false),
            can_manage_webhooks: sea_orm::Set(false),
            can_create_groups: sea_orm::Set(false),
            parent_key_id: sea_orm::Set(None),
            created_at: sea_orm::Set(now),
            updated_at: sea_orm::Set(now),
        })
        .exec(&db)
        .await
        .unwrap();
        key_ids.push(kid);

        for g_idx in 0..3 {
            api_key_group_permission::Entity::insert(api_key_group_permission::ActiveModel {
                id: sea_orm::Set(Uuid::new_v4()),
                api_key_id: sea_orm::Set(kid),
                group_id: sea_orm::Set(group_ids[(i + g_idx) % group_ids.len()]),
                can_read: sea_orm::Set(true),
                can_write: sea_orm::Set(false),
                can_delete: sea_orm::Set(false),
                can_manage: sea_orm::Set(false),
                created_at: sea_orm::Set(now),
            })
            .exec(&db)
            .await
            .unwrap();
        }
    }

    // 1. Measure N+1 unbatched loading (51 queries for 50 keys)
    let start_n_plus_one = Instant::now();
    for _ in 0..10 {
        let keys = api_key::Entity::find().all(&db).await.unwrap();
        let mut summaries = Vec::with_capacity(keys.len());
        for k in keys {
            let perms = simply_ip_vault::api::key_group_permissions(&db, k.id, None)
                .await
                .unwrap();
            summaries.push(simply_ip_vault::api::build_full_api_key_summary(k, perms));
        }
        assert_eq!(summaries.len(), 50);
    }
    let dur_n_plus_one = start_n_plus_one.elapsed() / 10;

    // 2. Measure batched loading (2 queries total for 50 keys)
    let start_batched = Instant::now();
    for _ in 0..10 {
        let keys = api_key::Entity::find().all(&db).await.unwrap();
        let kids: Vec<Uuid> = keys.iter().map(|k| k.id).collect();
        let mut perm_map = simply_ip_vault::api::batch_key_group_permissions(&db, &kids, None)
            .await
            .unwrap();
        let summaries: Vec<_> = keys
            .into_iter()
            .map(|k| {
                let perms = perm_map.remove(&k.id).unwrap_or_default();
                simply_ip_vault::api::build_full_api_key_summary(k, perms)
            })
            .collect();
        assert_eq!(summaries.len(), 50);
    }
    let dur_batched = start_batched.elapsed() / 10;

    println!(
        "API keys listing for 50 keys: N+1 unbatched (51 queries) = {:?}, batched (2 queries) = {:?}",
        dur_n_plus_one, dur_batched
    );
    assert!(
        dur_batched < dur_n_plus_one,
        "Batched query ({:?}) must be faster than N+1 ({:?})",
        dur_batched,
        dur_n_plus_one
    );
}
