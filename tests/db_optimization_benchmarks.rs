//! Systematic database query optimization benchmarks and plan verification.
//!
//! Validates execution time and query plans before and after optimizations:
//! 1. `webhook_executions`: `idx_webhook_executions_success_created`,
//!    `idx_webhook_executions_status_code_created`, `idx_webhook_executions_event_type_created`.
//! 2. `ip_groups`: `idx-ip_groups-group_type`.
//! 3. `audit_logs`: `idx_audit_logs_api_key_timestamp`.
//! 4. API keys listing: Batched permission loading vs N+1 queries.

use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseBackend, DatabaseConnection,
    EntityTrait, JoinType, QueryFilter, QueryOrder, QuerySelect, QueryTrait, RelationTrait,
    Statement,
};
use simply_ip_vault::migration::MigratorTrait;
use std::time::Instant;
use time::Duration;
use uuid::Uuid;

use simply_ip_vault::entities::{
    api_key, api_key_group_permission, audit_log, ip_group, ip_group_exclusion, ip_record,
    ip_record_group_membership, webhook_config, webhook_execution,
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
    let now = simply_ip_vault::time_serde::now_utc();

    for db in [&db_before, &db_after] {
        ip_group::Entity::insert(ip_group::ActiveModel {
            id: sea_orm::Set(group_id),
            name: sea_orm::Set("bench_group".to_owned()),
            allow_private_ips: sea_orm::NotSet,
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
            send_normalized_ipv6: sea_orm::NotSet,
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
            let age_hours = i64::from(i % 100);
            let created_at = now - Duration::hours(age_hours);

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

    measure_webhook_status_queries(&db_before, &db_after).await;
}

async fn measure_webhook_status_queries(
    db_before: &DatabaseConnection,
    db_after: &DatabaseConnection,
) {
    // 3. Measure execution times
    let start_before = Instant::now();
    for _ in 0..50 {
        let _ = webhook_execution::Entity::find()
            .filter(webhook_execution::Column::StatusCode.eq(500))
            .order_by_desc(webhook_execution::Column::CreatedAt)
            .limit(50)
            .all(db_before)
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
            .all(db_after)
            .await
            .unwrap();
    }
    let dur_after = start_after.elapsed() / 50;

    println!(
        "Webhook executions query (10,000 rows): before = {dur_before:?}, after = {dur_after:?}"
    );
    assert!(
        dur_after < std::time::Duration::from_millis(10),
        "Optimized query should complete well under 10ms budget, took {dur_after:?}"
    );
}

#[tokio::test]
async fn bench_audit_logs_api_key_timestamp_optimization() {
    let db_before = bench_db_with_migrations(Some(26)).await;
    let db_after = bench_db_with_migrations(None).await;

    let key_id = Uuid::new_v4();
    let other_key_id = Uuid::new_v4();
    seed_audit_benchmark(&db_before, &db_after, key_id, other_key_id).await;
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
        "Audit logs by key query (5,000 rows): before = {dur_before:?}, after = {dur_after:?}"
    );
    assert!(
        dur_after < std::time::Duration::from_millis(10),
        "Optimized query should complete well under 10ms budget, took {dur_after:?}"
    );
}

async fn seed_audit_benchmark(
    db_before: &DatabaseConnection,
    db_after: &DatabaseConnection,
    key_id: Uuid,
    other_key_id: Uuid,
) {
    let now = simply_ip_vault::time_serde::now_utc();

    for db in [db_before, db_after] {
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
                timestamp: sea_orm::Set(now - Duration::seconds(i64::from(i))),
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
}

#[tokio::test]
async fn bench_api_keys_batching_vs_n_plus_one() {
    let db = bench_db_with_migrations(None).await;

    seed_api_keys_benchmark(&db).await;

    for _ in 0..5 {
        time_individual_key_listing(&db).await;
        time_batched_key_listing(&db).await;
    }

    // Pair the samples so both paths run under similar load. The median keeps a scheduler
    // pause in one sample from dominating the comparison.
    let mut individual_samples = Vec::with_capacity(21);
    let mut batched_samples = Vec::with_capacity(21);
    for sample in 0..21 {
        let (individual, batched) = if sample % 2 == 0 {
            (
                time_individual_key_listing(&db).await,
                time_batched_key_listing(&db).await,
            )
        } else {
            let batched = time_batched_key_listing(&db).await;
            (time_individual_key_listing(&db).await, batched)
        };
        individual_samples.push(individual);
        batched_samples.push(batched);
    }
    individual_samples.sort_unstable();
    batched_samples.sort_unstable();
    let dur_n_plus_one = individual_samples[individual_samples.len() / 2];
    let dur_batched = batched_samples[batched_samples.len() / 2];

    println!(
        "API keys listing for 50 keys: N+1 unbatched (51 queries) = {dur_n_plus_one:?}, batched (2 queries) = {dur_batched:?}"
    );
    assert!(
        dur_batched < dur_n_plus_one,
        "Batched query ({dur_batched:?}) must be faster than N+1 ({dur_n_plus_one:?})"
    );
}

async fn seed_api_keys_benchmark(db: &DatabaseConnection) {
    // Seed 10 groups
    let mut group_ids = Vec::new();
    for i in 0..10 {
        let gid = Uuid::new_v4();
        ip_group::Entity::insert(ip_group::ActiveModel {
            id: sea_orm::Set(gid),
            name: sea_orm::Set(format!("group_{i}")),
            allow_private_ips: sea_orm::NotSet,
            group_type: sea_orm::Set("banlist".to_owned()),
            description: sea_orm::Set(None),
            owner_key_id: sea_orm::Set(None),
            created_at: sea_orm::Set(simply_ip_vault::time_serde::now_utc()),
        })
        .exec(db)
        .await
        .unwrap();
        group_ids.push(gid);
    }

    // Seed 50 keys, each with 3 group permissions
    let now = simply_ip_vault::time_serde::now_utc();
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
        .exec(db)
        .await
        .unwrap();

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
            .exec(db)
            .await
            .unwrap();
        }
    }
}

async fn time_individual_key_listing(db: &DatabaseConnection) -> std::time::Duration {
    let started = Instant::now();
    let keys = api_key::Entity::find().all(db).await.unwrap();
    let mut summaries = Vec::with_capacity(keys.len());
    for key in keys {
        let perms = simply_ip_vault::api::key_group_permissions(db, key.id, None)
            .await
            .unwrap();
        summaries.push(simply_ip_vault::api::build_full_api_key_summary(key, perms));
    }
    assert_eq!(summaries.len(), 50);
    started.elapsed()
}

async fn time_batched_key_listing(db: &DatabaseConnection) -> std::time::Duration {
    let started = Instant::now();
    let keys = api_key::Entity::find().all(db).await.unwrap();
    let ids: Vec<Uuid> = keys.iter().map(|key| key.id).collect();
    let mut permissions = simply_ip_vault::api::batch_key_group_permissions(db, &ids, None)
        .await
        .unwrap();
    let summaries: Vec<_> = keys
        .into_iter()
        .map(|key| {
            let perms = permissions.remove(&key.id).unwrap_or_default();
            simply_ip_vault::api::build_full_api_key_summary(key, perms)
        })
        .collect();
    assert_eq!(summaries.len(), 50);
    started.elapsed()
}

struct ExclusionBenchFixture {
    ban_group: Uuid,
    wl_alpha: Uuid,
    wl_beta: Uuid,
    shared_record: Uuid,
    alpha_record: Uuid,
}

async fn seed_exclusion_join_benchmark(db: &DatabaseConnection) -> ExclusionBenchFixture {
    let ban_group = Uuid::parse_str("00000000-0000-0000-0000-000000000001").unwrap();
    let wl_alpha = Uuid::parse_str("00000000-0000-0000-0000-000000000011").unwrap();
    let wl_beta = Uuid::parse_str("00000000-0000-0000-0000-000000000012").unwrap();
    let now = simply_ip_vault::time_serde::now_utc();

    let stmts = [
        "INSERT INTO ip_groups (id, name, group_type, allow_private_ips, description, owner_key_id, created_at)
         WITH RECURSIVE g(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM g WHERE n < 10)
         SELECT unhex(printf('%032x', n)), 'ban-group-' || n, 'banlist', 0, NULL, NULL, datetime('now') FROM g",
        "INSERT INTO ip_records (id, target_address, created_at)
         WITH RECURSIVE s(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM s WHERE n < 50000)
         SELECT unhex(printf('%032x', n)), printf('198.18.%d.%d', (n>>8)&255, n&255), datetime('now') FROM s",
        "INSERT INTO ip_record_group_memberships
            (id, ip_record_id, group_id, is_locked, created_at, last_seen_at, is_deleted, deleted_at, deleted_by)
         WITH RECURSIVE s(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM s WHERE n < 50000)
         SELECT unhex(printf('%032x', n + 1000000)),
                unhex(printf('%032x', n)),
                unhex(printf('%032x', (n % 10) + 1)),
                0, datetime('now'), datetime('now'), 0, NULL, NULL
         FROM s",
    ];
    for sql in stmts {
        db.execute_unprepared(sql).await.unwrap();
    }

    for (id, name) in [(wl_alpha, "wl-alpha"), (wl_beta, "wl-beta")] {
        ip_group::Entity::insert(ip_group::ActiveModel {
            id: sea_orm::Set(id),
            name: sea_orm::Set(name.to_owned()),
            allow_private_ips: sea_orm::Set(false),
            group_type: sea_orm::Set("whitelist".to_owned()),
            description: sea_orm::Set(None),
            owner_key_id: sea_orm::Set(None),
            created_at: sea_orm::Set(now),
        })
        .exec(db)
        .await
        .unwrap();
    }

    let alpha_record = Uuid::new_v4();
    let shared_record = Uuid::new_v4();
    for (rid, addr) in [
        (alpha_record, "203.10.10.0/24"),
        (shared_record, "203.10.20.5"),
    ] {
        ip_record::Entity::insert(ip_record::ActiveModel {
            id: sea_orm::Set(rid),
            target_address: sea_orm::Set(addr.to_owned()),
            created_at: sea_orm::Set(now),
        })
        .exec(db)
        .await
        .unwrap();
    }
    for (rid, gid) in [
        (alpha_record, wl_alpha),
        (shared_record, wl_alpha),
        (shared_record, wl_beta),
    ] {
        ip_record_group_membership::Entity::insert(ip_record_group_membership::ActiveModel {
            id: sea_orm::Set(Uuid::new_v4()),
            ip_record_id: sea_orm::Set(rid),
            group_id: sea_orm::Set(gid),
            is_locked: sea_orm::Set(false),
            created_at: sea_orm::Set(now),
            last_seen_at: sea_orm::Set(now),
            is_deleted: sea_orm::Set(false),
            deleted_at: sea_orm::Set(None),
            deleted_by: sea_orm::Set(None),
        })
        .exec(db)
        .await
        .unwrap();
    }

    ExclusionBenchFixture {
        ban_group,
        wl_alpha,
        wl_beta,
        shared_record,
        alpha_record,
    }
}

async fn assert_load_protected_networks_query_plans(
    db: &DatabaseConnection,
    fx: &ExclusionBenchFixture,
    phase: &str,
) {
    let step1_stmt = ip_group_exclusion::Entity::find()
        .select_only()
        .column(ip_group_exclusion::Column::ExcludedGroupId)
        .column(ip_group::Column::Name)
        .join(
            JoinType::InnerJoin,
            ip_group_exclusion::Relation::ExcludedGroup.def(),
        )
        .filter(ip_group_exclusion::Column::GroupId.eq(fx.ban_group))
        .build(DatabaseBackend::Sqlite);
    let step1_plan = db
        .query_all_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            format!("EXPLAIN QUERY PLAN {}", step1_stmt.sql),
            step1_stmt.values.map_or_else(Vec::new, |v| v.0),
        ))
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.try_get::<String>("", "detail").unwrap())
        .collect::<Vec<_>>()
        .join(" | ");
    println!("load_protected_networks Step 1 plan ({phase}): {step1_plan}");
    assert!(
        step1_plan.contains("SEARCH ip_group_exclusions USING"),
        "Step 1 must seek ip_group_exclusions via index ({phase}): {step1_plan}"
    );
    assert!(
        !step1_plan.contains("ip_record_group_memberships") && !step1_plan.contains("ip_records"),
        "Step 1 must NEVER reference ip_record_group_memberships or ip_records ({phase}): {step1_plan}"
    );

    let step2_stmt = ip_record_group_membership::Entity::find()
        .select_only()
        .column(ip_record_group_membership::Column::IpRecordId)
        .filter(ip_record_group_membership::Column::GroupId.eq(fx.wl_alpha))
        .filter(ip_record_group_membership::Column::IsDeleted.eq(false))
        .build(DatabaseBackend::Sqlite);
    let step2_plan = db
        .query_all_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            format!("EXPLAIN QUERY PLAN {}", step2_stmt.sql),
            step2_stmt.values.map_or_else(Vec::new, |v| v.0),
        ))
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.try_get::<String>("", "detail").unwrap())
        .collect::<Vec<_>>()
        .join(" | ");
    println!("load_protected_networks Step 2 membership plan ({phase}): {step2_plan}");
    assert!(
        step2_plan.contains("SEARCH ip_record_group_memberships USING COVERING INDEX")
            && (step2_plan.contains("(group_id=? AND is_deleted=?)")
                || step2_plan.contains("(is_deleted=? AND group_id=?)")),
        "Step 2 must use covering index on (group_id, is_deleted) ({phase}): {step2_plan}"
    );
    assert!(
        !step2_plan.contains("SCAN ip_record_group_memberships"),
        "Step 2 must NEVER scan ip_record_group_memberships ({phase}): {step2_plan}"
    );

    let pk_stmt = ip_record::Entity::find()
        .select_only()
        .column(ip_record::Column::Id)
        .column(ip_record::Column::TargetAddress)
        .filter(ip_record::Column::Id.is_in([fx.alpha_record, fx.shared_record]))
        .build(DatabaseBackend::Sqlite);
    let pk_plan = db
        .query_all_raw(Statement::from_sql_and_values(
            DatabaseBackend::Sqlite,
            format!("EXPLAIN QUERY PLAN {}", pk_stmt.sql),
            pk_stmt.values.map_or_else(Vec::new, |v| v.0),
        ))
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.try_get::<String>("", "detail").unwrap())
        .collect::<Vec<_>>()
        .join(" | ");
    println!("load_protected_networks Step 2 record PK plan ({phase}): {pk_plan}");
    assert!(
        pk_plan.contains("SEARCH ip_records USING INDEX") && !pk_plan.contains("SCAN ip_records"),
        "Step 2 record batch lookup must use PK index ({phase}): {pk_plan}"
    );
}

fn signed_ban_request(
    key: &str,
    secret: &str,
    target_address: &str,
    group_name: &str,
    ts_offset: i64,
) -> axum::http::Request<axum::body::Body> {
    let body = serde_json::json!({
        "target_address": target_address,
        "group_name": group_name,
        "cause": "exclusion bench"
    })
    .to_string();
    let ts = (time::OffsetDateTime::now_utc().unix_timestamp() + ts_offset).to_string();
    let sig = simply_ip_vault::crypto::compute_signature(
        secret,
        "POST",
        "/api/ban",
        &ts,
        body.as_bytes(),
    )
    .unwrap();
    axum::http::Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("Content-Type", "application/json")
        .header("X-API-Key", key)
        .header("X-Timestamp", ts)
        .header("X-Signature-256", sig)
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            8080,
        ))))
        .body(axum::body::Body::from(body))
        .unwrap()
}

async fn seed_bench_master_key(db: &DatabaseConnection) -> (String, String) {
    let key = "exbench000000000000000000000000000000000000000000000000000000001".to_owned();
    let secret = format!("signing-secret-for-{key}");
    api_key::ActiveModel {
        id: sea_orm::Set(Uuid::new_v4()),
        key_hash: sea_orm::Set(simply_ip_vault::api::hash_key(&key)),
        signing_secret: sea_orm::Set(Some(format!("v1.plain.{}", hex::encode(&secret)))),
        name: sea_orm::Set("Exclusion Bench Master".to_owned()),
        bound_ips: sea_orm::Set(None),
        is_master: sea_orm::Set(true),
        can_manage_keys: sea_orm::Set(true),
        can_manage_webhooks: sea_orm::Set(true),
        can_create_groups: sea_orm::Set(true),
        parent_key_id: sea_orm::Set(None),
        prefix: sea_orm::Set("exbench0".to_owned()),
        created_at: sea_orm::Set(simply_ip_vault::time_serde::now_utc()),
        updated_at: sea_orm::Set(simply_ip_vault::time_serde::now_utc()),
    }
    .insert(db)
    .await
    .unwrap();
    (key, secret)
}

async fn assert_excluded_whitelist_ban_enforcement(
    db: &DatabaseConnection,
    app: &axum::Router,
    fx: &ExclusionBenchFixture,
    key: &str,
    secret: &str,
) {
    use tower::ServiceExt as _;

    let max_ban_budget = std::time::Duration::from_millis(50);
    let t2 = Instant::now();
    let ok_res = app
        .clone()
        .oneshot(signed_ban_request(
            key,
            secret,
            "203.10.99.9",
            "ban-group-1",
            4,
        ))
        .await
        .unwrap();
    let elapsed_one_ok = t2.elapsed();
    assert_eq!(ok_res.status(), axum::http::StatusCode::OK);
    assert!(
        elapsed_one_ok < max_ban_budget,
        "POST /api/ban with 1 excluded whitelist took {elapsed_one_ok:?}"
    );

    let t3 = Instant::now();
    let conflict_res = app
        .clone()
        .oneshot(signed_ban_request(
            key,
            secret,
            "203.10.10.42",
            "ban-group-1",
            6,
        ))
        .await
        .unwrap();
    let elapsed_one_conflict = t3.elapsed();
    assert_eq!(conflict_res.status(), axum::http::StatusCode::CONFLICT);
    assert!(
        elapsed_one_conflict < max_ban_budget,
        "POST /api/ban conflict check with 1 excluded whitelist took {elapsed_one_conflict:?}"
    );

    ip_group_exclusion::ActiveModel {
        group_id: sea_orm::Set(fx.ban_group),
        excluded_group_id: sea_orm::Set(fx.wl_beta),
    }
    .insert(db)
    .await
    .unwrap();
    let multi_res = app
        .clone()
        .oneshot(signed_ban_request(
            key,
            secret,
            "203.10.20.5",
            "ban-group-1",
            8,
        ))
        .await
        .unwrap();
    assert_eq!(multi_res.status(), axum::http::StatusCode::CONFLICT);
    let body_bytes = axum::body::to_bytes(multi_res.into_body(), usize::MAX)
        .await
        .unwrap();
    let body_text = String::from_utf8_lossy(&body_bytes);
    assert!(
        body_text.contains("wl-alpha, wl-beta"),
        "Shared IP across multiple excluded whitelists must report all whitelist names: {body_text}"
    );
}

#[tokio::test]
async fn load_protected_networks_avoids_join_inversion_before_and_after_analyze() {
    use tower::ServiceExt as _;

    let db = bench_db_with_migrations(None).await;
    let fx = seed_exclusion_join_benchmark(&db).await;
    let (key, secret) = seed_bench_master_key(&db).await;
    let (tx, _rx) = tokio::sync::mpsc::channel(256);
    let state = simply_ip_vault::state::AppState::with_trusted_proxies(db.clone(), tx, Vec::new());
    let app = simply_ip_vault::create_app(state);
    let max_ban_budget = std::time::Duration::from_millis(50);

    // 1. Empty ip_group_exclusions BEFORE ANALYZE
    assert_load_protected_networks_query_plans(&db, &fx, "empty exclusions, pre-ANALYZE").await;
    let t0 = Instant::now();
    let res = app
        .clone()
        .oneshot(signed_ban_request(
            &key,
            &secret,
            "203.10.20.5",
            "ban-group-1",
            0,
        ))
        .await
        .unwrap();
    let elapsed_empty_pre = t0.elapsed();
    assert_eq!(res.status(), axum::http::StatusCode::OK);
    assert!(
        elapsed_empty_pre < max_ban_budget,
        "POST /api/ban with 0 exclusions pre-ANALYZE took {elapsed_empty_pre:?}"
    );

    // 2. Empty ip_group_exclusions AFTER ANALYZE
    db.execute_unprepared("ANALYZE").await.unwrap();
    assert_load_protected_networks_query_plans(&db, &fx, "empty exclusions, post-ANALYZE").await;
    let t1 = Instant::now();
    let res = app
        .clone()
        .oneshot(signed_ban_request(
            &key,
            &secret,
            "203.10.21.1",
            "ban-group-1",
            2,
        ))
        .await
        .unwrap();
    let elapsed_empty_post = t1.elapsed();
    assert_eq!(res.status(), axum::http::StatusCode::OK);
    assert!(
        elapsed_empty_post < max_ban_budget,
        "POST /api/ban with 0 exclusions post-ANALYZE took {elapsed_empty_post:?}"
    );

    // 3. Link 1 excluded whitelist (wl-alpha) on ban-group-1 (plus a bystander exclusion on ban-group-2),
    //    test BEFORE and AFTER ANALYZE
    let ban_group_2_id = Uuid::parse_str("00000000-0000-0000-0000-000000000002").unwrap();
    for gid in [fx.ban_group, ban_group_2_id] {
        ip_group_exclusion::ActiveModel {
            group_id: sea_orm::Set(gid),
            excluded_group_id: sea_orm::Set(fx.wl_alpha),
        }
        .insert(&db)
        .await
        .unwrap();
    }
    assert_load_protected_networks_query_plans(&db, &fx, "1 exclusion, pre-ANALYZE").await;
    db.execute_unprepared("ANALYZE").await.unwrap();
    assert_load_protected_networks_query_plans(&db, &fx, "1 exclusion, post-ANALYZE").await;

    assert_excluded_whitelist_ban_enforcement(&db, &app, &fx, &key, &secret).await;
}
