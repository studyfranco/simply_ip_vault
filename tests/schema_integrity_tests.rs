//! Referential-integrity tests: what the **engine** does when a row goes away.
//!
//! # Why these are integration tests and not unit tests
//!
//! Every one of them depends on `PRAGMA foreign_keys=ON`, and in SQLite that pragma is
//! **per-connection and off by default**. A cascade is therefore not a property of the schema alone;
//! it is a property of the schema *plus the connection that was opened*. So each test here builds its
//! database through [`simply_ip_vault::db::connect`] — the real production path, the one that sets the
//! pragma — rather than through `Database::connect`, which would leave foreign keys disabled and make
//! every assertion below pass or fail for reasons unrelated to the schema.
//!
//! That is also why they are **file-backed**. `sqlite::memory:` is what the rest of the suite uses,
//! and it is fine for behaviour, but it cannot exercise the pool that `connect` actually builds.
//!
//! # What a cascade test is worth
//!
//! `PRAGMA foreign_keys` returning `1` says the switch is set. It does not say the engine acted on it,
//! and it says nothing at all about *which* action each constraint declares. `ON DELETE CASCADE` and
//! `ON DELETE SET NULL` are one word apart in a migration and produce opposite outcomes — one erases
//! an audit trail, the other preserves it — and no type in Rust distinguishes them. The only way to
//! know which is deployed is to delete a row and look.
//!
//! # Deletes here are direct, and that is deliberate
//!
//! Nothing below goes through an API handler. `RBAC_MODEL.md` §6 forbids the service from destroying
//! data implicitly, and `delete_api_key` enforces that with a pre-flight inventory and a refusal —
//! so the *application* never reaches these constraints in the first place. These tests are about the
//! layer underneath: what the database would do if a row were removed by a restore, an operator, a
//! future migration, or a handler written by someone who had not read §6. Testing that through the
//! handler would prove only that the handler refuses, which is a different fact and is already
//! covered in `tests/security_tests.rs`.

use chrono::Utc;
use sea_orm::{
    ActiveValue::Set, ColumnTrait, ConnectionTrait, DatabaseBackend, DatabaseConnection,
    EntityTrait, PaginatorTrait, QueryFilter, Statement,
};
use uuid::Uuid;

use simply_ip_vault::entities::{
    api_key, api_key_group_permission, audit_log, ip_group, ip_record,
    ip_record_group_membership, webhook_config, webhook_execution,
};

/// A temporary directory holding one database file, removed on drop.
///
/// Every test gets its own. That is what makes "orphaned rows from a prior test run" structurally
/// impossible here rather than something to clean up: there is no shared database to inherit state
/// from, and a panicking test leaves nothing behind for the next one to trip over.
struct TempDb(std::path::PathBuf);

impl TempDb {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!("vault_fk_{}", Uuid::new_v4()));
        std::fs::create_dir_all(&dir).expect("temp dir is creatable");
        Self(dir)
    }

    fn url(&self) -> String {
        format!("sqlite://{}", self.0.join("v.db").display())
    }
}

impl Drop for TempDb {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A migrated, file-backed database opened the way production opens it: migrations first, on their
/// own isolated single-connection pool, then the (now potentially multi-connection) application
/// pool — see `db::run_migrations_isolated`'s doc comment. Running migrations directly against
/// `db::connect`'s pool here would reintroduce the exact `duplicate column name: master_marker`
/// race that isolation exists to prevent, now that a file-backed pool is no longer pinned to one
/// connection.
async fn fresh_db(tmp: &TempDb) -> DatabaseConnection {
    simply_ip_vault::db::run_migrations_isolated(&tmp.url())
        .await
        .expect("every migration applies on the isolated pool");
    simply_ip_vault::db::connect(&tmp.url()).await.expect("a file-backed sqlite pool opens")
}

/// A single-connection, file-backed pool for tests that drive `Migrator::up` to a partial version
/// themselves and need every call — including the DDL-heavy migration 9, which drops and re-adds
/// `master_marker` — to land on the one connection they go on to use.
///
/// Deliberately **not** `db::connect`: that pool may now hold more than one connection for a
/// file-backed database, on the assumption (documented on `connect`) that migrations are already
/// complete before it opens. These tests apply DDL after opening it, so that assumption does not
/// hold here — using `db::connect` would reintroduce the exact `duplicate column name:
/// master_marker` race the isolated-migration pool exists to prevent.
async fn partial_migration_db(tmp: &TempDb) -> DatabaseConnection {
    use sea_orm::sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr;

    let options = SqliteConnectOptions::from_str(&tmp.url())
        .expect("the url parses")
        .create_if_missing(true)
        .foreign_keys(true);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("the pool opens");
    sea_orm::SqlxSqliteConnector::from_sqlx_sqlite_pool(pool)
}

/// Seeds a non-master key. `parent` threads the `parent_key_id` chain when a test needs one.
async fn seed_key(db: &DatabaseConnection, name: &str, parent: Option<Uuid>) -> Uuid {
    let id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    api_key::Entity::insert(api_key::ActiveModel {
        id: Set(id),
        name: Set(name.to_owned()),
        key_hash: Set(simply_ip_vault::api::hash_key(&plaintext)),
        signing_secret: Set(Some("secret".to_owned())),
        prefix: Set(plaintext[..8].to_owned()),
        bound_ips: Set(None),
        is_master: Set(false),
        can_manage_keys: Set(false),
        can_manage_webhooks: Set(false),
        can_create_groups: Set(false),
        parent_key_id: Set(parent),
        created_at: Set(Utc::now().naive_utc()),
        updated_at: Set(Utc::now().naive_utc()),
    })
    .exec(db)
    .await
    .expect("the key inserts");
    id
}

/// Seeds a group owned by `owner`.
async fn seed_group(db: &DatabaseConnection, name: &str, owner: Option<Uuid>) -> Uuid {
    let id = Uuid::new_v4();
    ip_group::Entity::insert(ip_group::ActiveModel {
        id: Set(id),
        name: Set(name.to_owned()),
        group_type: Set("blacklist".to_owned()),
        description: Set(None),
        owner_key_id: Set(owner),
        created_at: Set(Utc::now().naive_utc()),
    })
    .exec(db)
    .await
    .expect("the group inserts");
    id
}

/// Seeds an IP record and places it in `group`.
async fn seed_record_in_group(db: &DatabaseConnection, address: &str, group: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let now = Utc::now().naive_utc();
    ip_record::Entity::insert(ip_record::ActiveModel {
        id: Set(id),
        target_address: Set(address.to_owned()),
        cause: Set(None),
        is_locked: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
        last_seen_at: Set(now),
        is_deleted: Set(false),
        deleted_at: Set(None),
        deleted_by: Set(None),
    })
    .exec(db)
    .await
    .expect("the record inserts");

    ip_record_group_membership::Entity::insert(ip_record_group_membership::ActiveModel {
        ip_record_id: Set(id),
        group_id: Set(group),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    })
    .exec(db)
    .await
    .expect("the membership inserts");
    id
}

/// Grants `key` a permission row on `group`.
async fn seed_permission(db: &DatabaseConnection, key: Uuid, group: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    api_key_group_permission::Entity::insert(api_key_group_permission::ActiveModel {
        id: Set(id),
        api_key_id: Set(key),
        group_id: Set(group),
        can_read: Set(true),
        can_write: Set(true),
        can_delete: Set(false),
        can_manage: Set(false),
        created_at: Set(Utc::now().naive_utc()),
    })
    .exec(db)
    .await
    .expect("the permission inserts");
    id
}

/// Seeds a webhook config bound to `group`.
async fn seed_webhook(db: &DatabaseConnection, name: &str, group: Uuid, owner: Option<Uuid>) -> Uuid {
    let id = Uuid::new_v4();
    webhook_config::Entity::insert(webhook_config::ActiveModel {
        id: Set(id),
        name: Set(name.to_owned()),
        target_url: Set("https://example.invalid/hook".to_owned()),
        secret_token: Set("token".to_owned()),
        auth_mode: Set("none".to_owned()),
        api_key: Set(None),
        hmac_template: Set(None),
        signature_header: Set(None),
        signature_prefix: Set(None),
        headers_json: Set(None),
        payload_template: Set("{}".to_owned()),
        group_id: Set(group),
        is_active: Set(true),
        events: Set(None),
        owner_key_id: Set(owner),
        created_at: Set(Utc::now().naive_utc()),
    })
    .exec(db)
    .await
    .expect("the webhook inserts");
    id
}

/// Writes one `webhook_executions` row for `webhook` — a single successful `IP_ADD` attempt, since
/// only its existence and survival matter to the cascade tests that use this, not its content.
async fn seed_execution(db: &DatabaseConnection, webhook: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    webhook_execution::Entity::insert(webhook_execution::ActiveModel {
        id: Set(id),
        webhook_id: Set(webhook),
        event_type: Set("IP_ADD".to_owned()),
        status_code: Set(Some(200)),
        is_success: Set(true),
        duration_ms: Set(5),
        response_body: Set(None),
        resolved_target_url: Set(None),
        target_address: Set(None),
        cause: Set(None),
        created_at: Set(Utc::now().naive_utc()),
    })
    .exec(db)
    .await
    .expect("the execution row inserts");
    id
}

/// Writes an audit row attributed to `key`, denormalizing its name and prefix as the service does.
async fn seed_audit_log(db: &DatabaseConnection, key: Uuid, name: &str, action: &str) -> Uuid {
    let id = Uuid::new_v4();
    audit_log::Entity::insert(audit_log::ActiveModel {
        id: Set(id),
        api_key_id: Set(Some(key)),
        api_key_name: Set(name.to_owned()),
        api_key_prefix: Set("abcd1234".to_owned()),
        client_ip: Set("203.0.113.7".to_owned()),
        action: Set(action.to_owned()),
        target_address: Set(Some("198.51.100.4".to_owned())),
        group_names: Set(None),
        details: Set(None),
        timestamp: Set(Utc::now().naive_utc()),
    })
    .exec(db)
    .await
    .expect("the audit row inserts");
    id
}

// ─────────────────────────────────────────────────────────────
// Deleting an API key
// ─────────────────────────────────────────────────────────────

/// Deleting a key removes its group grants — `fk-akgp-api_key_id`, `ON DELETE CASCADE`.
///
/// A grant is a statement about a key that no longer exists. Leaving it behind would be worse than
/// untidy: `api_key_group_permissions` is what every §2 authorization check reads, and a stale row
/// becomes live authority again the moment a new key is minted with the recycled id.
///
/// The unrelated key's grant is asserted to survive in the same test, because "cascade deleted
/// everything" and "cascade deleted the right thing" are different outcomes and only one is correct.
#[tokio::test]
async fn deleting_an_api_key_cascades_to_its_group_permissions() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    let group = seed_group(&db, "blocked", None).await;
    let doomed = seed_key(&db, "doomed", None).await;
    let bystander = seed_key(&db, "bystander", None).await;
    seed_permission(&db, doomed, group).await;
    seed_permission(&db, bystander, group).await;

    assert_eq!(
        api_key_group_permission::Entity::find().count(&db).await.unwrap(),
        2,
        "both grants exist before the delete"
    );

    api_key::Entity::delete_by_id(doomed).exec(&db).await.expect("the key deletes");

    assert_eq!(
        api_key_group_permission::Entity::find()
            .filter(api_key_group_permission::Column::ApiKeyId.eq(doomed))
            .count(&db)
            .await
            .unwrap(),
        0,
        "the deleted key's grants must not survive it — with foreign_keys off they would, and a \
         recycled id would silently inherit them"
    );
    assert_eq!(
        api_key_group_permission::Entity::find()
            .filter(api_key_group_permission::Column::ApiKeyId.eq(bystander))
            .count(&db)
            .await
            .unwrap(),
        1,
        "an unrelated key's grant is untouched: the cascade is scoped, not a table wipe"
    );
}

/// Deleting a key **nulls** its audit rows and keeps them — `fk-audit_logs-api_key_id`,
/// `ON DELETE SET NULL`.
///
/// This is the one constraint in the schema where `CASCADE` would be actively harmful, and it is the
/// reason this test exists as a separate assertion rather than a variation of the one above. An audit
/// log whose rows vanish when the acting key is deleted is an audit log an attacker can erase by
/// deleting their own credential — the single cheapest way to destroy the evidence of what they did.
///
/// The denormalized `api_key_name` and `api_key_prefix` are asserted to survive too. They are why the
/// nulled FK is acceptable: the trail stays legible as a point-in-time snapshot ("key 'worker_bot'
/// did this") rather than degrading to an anonymous row once the join target is gone.
#[tokio::test]
async fn deleting_an_api_key_preserves_its_audit_trail_and_nulls_the_reference() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    let key = seed_key(&db, "worker_bot", None).await;
    let entry = seed_audit_log(&db, key, "worker_bot", "IP_ADD").await;

    api_key::Entity::delete_by_id(key).exec(&db).await.expect("the key deletes");

    let row = audit_log::Entity::find_by_id(entry)
        .one(&db)
        .await
        .unwrap()
        .expect("the audit row must survive the deletion of the key that wrote it");

    assert_eq!(row.api_key_id, None, "the dangling reference is nulled, not left pointing nowhere");
    assert_eq!(
        row.api_key_name,
        "worker_bot",
        "the denormalized name survives — this is what keeps the trail readable after the join \
         target is gone"
    );
    assert_eq!(row.api_key_prefix, "abcd1234");
    assert_eq!(row.action, "IP_ADD");
}

/// A key's *children* are not destroyed by deleting it.
///
/// `api_keys.parent_key_id` carries **no** foreign key: it was added by a later migration, and SQLite
/// cannot add a constraint to an existing table without rebuilding it. That is a deliberate outcome
/// and worth pinning, because the alternatives are both wrong. `CASCADE` would make deleting a parent
/// silently destroy an entire subtree of credentials, which §6 forbids in the strongest terms. Even
/// `SET NULL` would quietly re-root daughters at the top level, promoting them out of the subtree that
/// bounded their visibility under §4.
///
/// So the database does nothing here, and `delete_api_key` does the work instead — refusing with an
/// inventory until the caller resolves each affected entity explicitly. This test asserts the
/// database's half of that arrangement: the row survives with its parent reference intact, leaving
/// the decision to the application rather than pre-empting it.
#[tokio::test]
async fn deleting_a_parent_key_does_not_touch_its_daughters_at_the_database_layer() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    let parent = seed_key(&db, "parent", None).await;
    let daughter = seed_key(&db, "daughter", Some(parent)).await;

    api_key::Entity::delete_by_id(parent).exec(&db).await.expect("the parent deletes");

    let row = api_key::Entity::find_by_id(daughter)
        .one(&db)
        .await
        .unwrap()
        .expect("a daughter key is never destroyed as a side effect — RBAC_MODEL.md §6");
    assert_eq!(
        row.parent_key_id,
        Some(parent),
        "the parent reference is left exactly as it was: neither cascaded nor silently re-rooted, \
         because both would be decisions the database is not entitled to make"
    );
}

// ─────────────────────────────────────────────────────────────
// Deleting a group
// ─────────────────────────────────────────────────────────────

/// Deleting a group cascades to all three tables that reference it, and to nothing else.
///
/// Three constraints fire at once — `fk-akgp-group_id`, `fk-irgm-group_id`, and
/// `fk-webhook_configs-group_id` — which is exactly why they are asserted together: a migration that
/// rebuilt this table and dropped one of the three would leave the other two working, and a test
/// covering only one of them would stay green.
///
/// The IP **records** are asserted to survive. Only the membership rows are collection-scoped; a
/// record can belong to several groups, and destroying the address itself because one of its groups
/// was removed would be the implicit data loss §6 rules out.
#[tokio::test]
async fn deleting_a_group_cascades_to_permissions_memberships_and_webhooks() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    let key = seed_key(&db, "operator", None).await;
    let doomed = seed_group(&db, "doomed", Some(key)).await;
    let survivor = seed_group(&db, "survivor", Some(key)).await;

    seed_permission(&db, key, doomed).await;
    seed_permission(&db, key, survivor).await;
    let record = seed_record_in_group(&db, "198.51.100.9", doomed).await;
    seed_webhook(&db, "doomed_hook", doomed, Some(key)).await;
    seed_webhook(&db, "surviving_hook", survivor, Some(key)).await;

    // The record also belongs to the surviving group, so its own row must outlive the delete.
    ip_record_group_membership::Entity::insert(ip_record_group_membership::ActiveModel {
        ip_record_id: Set(record),
        group_id: Set(survivor),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    })
    .exec(&db)
    .await
    .expect("a record may belong to several groups");

    ip_group::Entity::delete_by_id(doomed).exec(&db).await.expect("the group deletes");

    assert_eq!(
        api_key_group_permission::Entity::find()
            .filter(api_key_group_permission::Column::GroupId.eq(doomed))
            .count(&db)
            .await
            .unwrap(),
        0,
        "grants on a group that no longer exists must not survive it"
    );
    assert_eq!(
        ip_record_group_membership::Entity::find()
            .filter(ip_record_group_membership::Column::GroupId.eq(doomed))
            .count(&db)
            .await
            .unwrap(),
        0,
        "memberships in a deleted group are removed"
    );
    assert_eq!(
        webhook_config::Entity::find()
            .filter(webhook_config::Column::GroupId.eq(doomed))
            .count(&db)
            .await
            .unwrap(),
        0,
        "a webhook whose only subject is gone would fire on nothing"
    );

    assert!(
        ip_record::Entity::find_by_id(record).one(&db).await.unwrap().is_some(),
        "the IP record itself survives: it is a member of another group, and an address is not \
         owned by any one collection"
    );
    assert_eq!(
        ip_record_group_membership::Entity::find()
            .filter(ip_record_group_membership::Column::GroupId.eq(survivor))
            .count(&db)
            .await
            .unwrap(),
        1,
        "the surviving group keeps its membership"
    );
    assert_eq!(
        webhook_config::Entity::find()
            .filter(webhook_config::Column::GroupId.eq(survivor))
            .count(&db)
            .await
            .unwrap(),
        1,
        "the surviving group keeps its webhook"
    );
}

/// Deleting a webhook removes its delivery history — `fk-webhook_executions-webhook_id`,
/// `ON DELETE CASCADE`.
///
/// The one FK in the schema that deliberately does **not** follow `audit_logs.api_key_id`'s
/// `SET NULL` precedent (see the migration's own module header for the full reasoning): a nulled
/// `webhook_id` would be an execution row attributable to nothing, since this table carries no
/// denormalized webhook name the way `audit_logs` carries `api_key_name`/`api_key_prefix`. This test
/// is the one place that reasoning is actually checked against the live engine rather than only
/// argued about in a doc comment — exactly the standard this file's own header sets: "the only way
/// to know which [FK action] is deployed is to delete a row and look."
///
/// Also exercises the transitive path one level up: deleting a *group* cascades to its webhooks
/// (already covered above) and, transitively, to their executions too — proven here by seeding the
/// doomed webhook's execution and then deleting the *group*, not the webhook directly.
#[tokio::test]
async fn deleting_a_webhook_cascades_to_its_execution_history() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    let group = seed_group(&db, "exec-cascade-group", None).await;
    let doomed_webhook = seed_webhook(&db, "doomed_hook", group, None).await;
    let surviving_webhook = seed_webhook(&db, "surviving_hook", group, None).await;
    let doomed_execution = seed_execution(&db, doomed_webhook).await;
    let surviving_execution = seed_execution(&db, surviving_webhook).await;

    webhook_config::Entity::delete_by_id(doomed_webhook).exec(&db).await.expect("the webhook deletes");

    assert!(
        webhook_execution::Entity::find_by_id(doomed_execution).one(&db).await.unwrap().is_none(),
        "an execution row belonging to a webhook that no longer exists must not survive it — with \
         foreign_keys off it would, orphaned and unreachable by any owner"
    );
    assert!(
        webhook_execution::Entity::find_by_id(surviving_execution).one(&db).await.unwrap().is_some(),
        "an unrelated webhook's execution history is untouched: the cascade is scoped to the \
         deleted webhook, not a table wipe"
    );

    // Transitive case: deleting the *group* cascades to `surviving_hook` (proven above) and, one
    // level further, to that webhook's own execution history.
    ip_group::Entity::delete_by_id(group).exec(&db).await.expect("the group deletes");
    assert!(
        webhook_execution::Entity::find_by_id(surviving_execution).one(&db).await.unwrap().is_none(),
        "deleting a group must cascade through its webhooks to their execution history too, not \
         stop one level short at the webhook_configs row"
    );
}

/// Deleting an IP record removes its memberships — `fk-irgm-ip_record_id`, `ON DELETE CASCADE`.
///
/// The mirror of the group case, and it matters for the same reason: `ip_record_group_memberships`
/// has a composite primary key over both columns, so a membership orphaned by a deleted record would
/// block re-inserting that record into the same group afterwards with a primary-key collision on a
/// row nothing can see.
#[tokio::test]
async fn deleting_an_ip_record_cascades_to_its_group_memberships() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    let group = seed_group(&db, "blocked", None).await;
    let record = seed_record_in_group(&db, "198.51.100.20", group).await;

    ip_record::Entity::delete_by_id(record).exec(&db).await.expect("the record deletes");

    assert_eq!(
        ip_record_group_membership::Entity::find()
            .filter(ip_record_group_membership::Column::IpRecordId.eq(record))
            .count(&db)
            .await
            .unwrap(),
        0,
        "memberships of a deleted record are removed"
    );
    assert!(
        ip_group::Entity::find_by_id(group).one(&db).await.unwrap().is_some(),
        "the group survives: a cascade travels from the referenced row to the referencing one, \
         never the other way"
    );
}

// ─────────────────────────────────────────────────────────────
// Orphans
// ─────────────────────────────────────────────────────────────

/// **ADVERSARIAL.** An orphan cannot be written, even by a writer that bypasses the entity layer.
///
/// Every other test in this file deletes through SeaORM and checks the aftermath, which proves the
/// constraints fire but not that they cannot be *evaded*. This one goes around the entity API
/// entirely and issues the `INSERT` as raw SQL — the shape a restore script, a migration, or a second
/// process sharing the file would take. A constraint that only holds for cooperative writers is not a
/// constraint, and with `foreign_keys` off SQLite accepts every statement below without a word.
#[tokio::test]
async fn raw_sql_cannot_write_a_row_referencing_a_nonexistent_parent() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    let ghost = Uuid::new_v4();

    let orphan_grant = db
        .execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            format!(
                "INSERT INTO api_key_group_permissions \
                 (id, api_key_id, group_id, can_read, can_write, can_delete, can_manage, created_at) \
                 VALUES ('{}', '{ghost}', '{ghost}', 1, 0, 0, 0, '2026-01-01 00:00:00')",
                Uuid::new_v4()
            ),
        ))
        .await;
    assert!(
        orphan_grant.is_err(),
        "a grant naming a key and group that do not exist must be refused at the engine"
    );

    let orphan_membership = db
        .execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            format!(
                "INSERT INTO ip_record_group_memberships (ip_record_id, group_id) \
                 VALUES ('{ghost}', '{ghost}')"
            ),
        ))
        .await;
    assert!(orphan_membership.is_err(), "a membership naming neither a record nor a group is refused");

    let orphan_webhook = db
        .execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            format!(
                "INSERT INTO webhook_configs \
                 (id, name, target_url, secret_token, auth_mode, payload_template, group_id, \
                  is_active, created_at) \
                 VALUES ('{}', 'ghost', 'https://x.invalid', 't', 'none', '{{}}', '{ghost}', 1, \
                  '2026-01-01 00:00:00')",
                Uuid::new_v4()
            ),
        ))
        .await;
    assert!(orphan_webhook.is_err(), "a webhook bound to a group that does not exist is refused");
}

/// A freshly migrated database contains no violated references, by the engine's own reckoning.
///
/// `PRAGMA foreign_key_check` walks every foreign key in the schema and returns one row per
/// violation. An empty result is the strongest available statement that the migration chain — nine
/// migrations, including one that rebuilds `api_keys` to add the generated `master_marker` column —
/// leaves the database referentially clean.
///
/// This is the check that catches the failure mode the others cannot. SQLite enforces foreign keys
/// only on connections that asked it to, so a migration run with the pragma off can write orphans
/// that no later statement will ever notice; and `PRAGMA foreign_keys` is a **no-op inside a
/// transaction**, which is where migrations run. Asserting the outcome directly is worth more than
/// reasoning about whether it could have happened.
#[tokio::test]
async fn a_migrated_database_has_no_orphaned_rows() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    let violations = db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "PRAGMA foreign_key_check;".to_owned(),
        ))
        .await
        .expect("the integrity check runs");

    assert!(
        violations.is_empty(),
        "the migration chain must leave no dangling references; {} row(s) reported",
        violations.len()
    );
}

/// The same check, after a realistic sequence of writes and deletes.
///
/// A schema can be clean when empty and dirty in use. This seeds the full shape the service produces
/// — keys with daughters, groups, records in several groups, grants, webhooks, audit rows — then
/// deletes from the middle of it and asks the engine to walk every constraint again.
#[tokio::test]
async fn deletes_across_the_whole_schema_leave_no_orphans() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    let parent = seed_key(&db, "parent", None).await;
    let daughter = seed_key(&db, "daughter", Some(parent)).await;
    let group_a = seed_group(&db, "group_a", Some(parent)).await;
    let group_b = seed_group(&db, "group_b", Some(daughter)).await;

    seed_permission(&db, parent, group_a).await;
    seed_permission(&db, daughter, group_a).await;
    seed_permission(&db, daughter, group_b).await;

    let record = seed_record_in_group(&db, "198.51.100.30", group_a).await;
    ip_record_group_membership::Entity::insert(ip_record_group_membership::ActiveModel {
        ip_record_id: Set(record),
        group_id: Set(group_b),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    })
    .exec(&db)
    .await
    .expect("the second membership inserts");

    seed_webhook(&db, "hook_a", group_a, Some(parent)).await;
    seed_webhook(&db, "hook_b", group_b, Some(daughter)).await;
    seed_audit_log(&db, parent, "parent", "IP_ADD").await;
    seed_audit_log(&db, daughter, "daughter", "IP_DELETE").await;

    // Delete from the middle: a group with dependents, then a key with grants and audit rows.
    ip_group::Entity::delete_by_id(group_a).exec(&db).await.expect("the group deletes");
    api_key::Entity::delete_by_id(daughter).exec(&db).await.expect("the key deletes");

    let violations = db
        .query_all_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "PRAGMA foreign_key_check;".to_owned(),
        ))
        .await
        .expect("the integrity check runs");
    assert!(
        violations.is_empty(),
        "cascading deletes must leave the database referentially clean; {} violation(s)",
        violations.len()
    );

    // And the audit trail is still there, which is the property worth the most in this file.
    assert_eq!(
        audit_log::Entity::find().count(&db).await.unwrap(),
        2,
        "no audit row is destroyed by deleting the key that wrote it"
    );
}

// ─────────────────────────────────────────────────────────────
// Join tables: no orphan may survive a delete
// ─────────────────────────────────────────────────────────────

/// Every row in both join tables whose referenced parent no longer exists.
///
/// Deliberately **not** `PRAGMA foreign_key_check`. That pragma asks SQLite whether SQLite is
/// satisfied, which is a circular question to put to the engine whose enforcement is under test — if
/// the constraints were declared wrongly, or dropped by a table rebuild, `foreign_key_check` would
/// walk whatever constraints remain and cheerfully report nothing. This walks the data instead, from
/// the application's own idea of what the parents are, so it holds an opinion the schema cannot
/// silently change. Both checks are worth having; they fail for different reasons.
async fn join_table_orphans(db: &DatabaseConnection) -> Vec<String> {
    let mut orphans = Vec::new();

    let key_ids: Vec<Uuid> = api_key::Entity::find()
        .all(db)
        .await
        .unwrap()
        .into_iter()
        .map(|k| k.id)
        .collect();
    let group_ids: Vec<Uuid> = ip_group::Entity::find()
        .all(db)
        .await
        .unwrap()
        .into_iter()
        .map(|g| g.id)
        .collect();
    let record_ids: Vec<Uuid> = ip_record::Entity::find()
        .all(db)
        .await
        .unwrap()
        .into_iter()
        .map(|r| r.id)
        .collect();

    for perm in api_key_group_permission::Entity::find().all(db).await.unwrap() {
        if !key_ids.contains(&perm.api_key_id) {
            orphans.push(format!("api_key_group_permissions {} -> missing key {}", perm.id, perm.api_key_id));
        }
        if !group_ids.contains(&perm.group_id) {
            orphans.push(format!("api_key_group_permissions {} -> missing group {}", perm.id, perm.group_id));
        }
    }

    for m in ip_record_group_membership::Entity::find().all(db).await.unwrap() {
        if !record_ids.contains(&m.ip_record_id) {
            orphans.push(format!("ip_record_group_memberships -> missing record {}", m.ip_record_id));
        }
        if !group_ids.contains(&m.group_id) {
            orphans.push(format!("ip_record_group_memberships -> missing group {}", m.group_id));
        }
    }

    orphans
}

/// Deleting a key, then a group, leaves **no orphan row in either join table** — checked by walking
/// the data rather than by asking the engine.
///
/// The two join tables are where a missed cascade does the most damage, and they fail differently.
/// A stale `api_key_group_permissions` row is *live authority*: it is what every §2 check reads, so
/// it grants access again the moment its id is reused. A stale `ip_record_group_memberships` row is
/// a phantom membership — the address still appears in a group that no longer exists, and because
/// the table's primary key spans both columns, it also blocks ever re-adding that record to a group
/// with the same id.
#[tokio::test]
async fn deleting_a_key_and_a_group_leaves_no_orphans_in_either_join_table() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    let doomed_key = seed_key(&db, "doomed_key", None).await;
    let surviving_key = seed_key(&db, "surviving_key", None).await;
    let doomed_group = seed_group(&db, "doomed_group", Some(surviving_key)).await;
    let surviving_group = seed_group(&db, "surviving_group", Some(surviving_key)).await;

    // Four grants across the two-by-two matrix, so each delete has both a victim and a bystander.
    seed_permission(&db, doomed_key, doomed_group).await;
    seed_permission(&db, doomed_key, surviving_group).await;
    seed_permission(&db, surviving_key, doomed_group).await;
    seed_permission(&db, surviving_key, surviving_group).await;

    let record = seed_record_in_group(&db, "198.51.100.40", doomed_group).await;
    ip_record_group_membership::Entity::insert(ip_record_group_membership::ActiveModel {
        ip_record_id: Set(record),
        group_id: Set(surviving_group),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    })
    .exec(&db)
    .await
    .expect("the record joins the surviving group too");

    assert_eq!(api_key_group_permission::Entity::find().count(&db).await.unwrap(), 4);
    assert_eq!(ip_record_group_membership::Entity::find().count(&db).await.unwrap(), 2);
    assert!(join_table_orphans(&db).await.is_empty(), "the fixture starts clean");

    api_key::Entity::delete_by_id(doomed_key).exec(&db).await.expect("the key deletes");
    assert_eq!(
        join_table_orphans(&db).await,
        Vec::<String>::new(),
        "deleting a key must leave no grant pointing at it"
    );
    assert_eq!(
        api_key_group_permission::Entity::find().count(&db).await.unwrap(),
        2,
        "exactly the two grants belonging to the deleted key are gone"
    );

    ip_group::Entity::delete_by_id(doomed_group).exec(&db).await.expect("the group deletes");
    assert_eq!(
        join_table_orphans(&db).await,
        Vec::<String>::new(),
        "deleting a group must leave no grant and no membership pointing at it"
    );
    assert_eq!(
        api_key_group_permission::Entity::find().count(&db).await.unwrap(),
        1,
        "only the surviving key's grant on the surviving group remains"
    );
    assert_eq!(
        ip_record_group_membership::Entity::find().count(&db).await.unwrap(),
        1,
        "only the membership in the surviving group remains"
    );

    // The record itself is untouched by either delete: an address is not owned by a key, and it
    // belongs to more than one group.
    assert!(ip_record::Entity::find_by_id(record).one(&db).await.unwrap().is_some());
}

/// Deleting a key does **not** disturb `ip_record_group_memberships`.
///
/// The complement of the cascades above, and it guards a plausible over-correction rather than an
/// omission. `api_keys` has no relationship to memberships at all — a key *administers* groups, it
/// does not own the addresses in them — so a future migration that added a cascade from keys to
/// memberships would silently erase banlist entries when a credential was rotated out. That would
/// look tidy and be data loss, exactly what §6 forbids.
#[tokio::test]
async fn deleting_a_key_does_not_touch_ip_record_memberships() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    let key = seed_key(&db, "operator", None).await;
    let group = seed_group(&db, "blocked", Some(key)).await;
    seed_permission(&db, key, group).await;
    let record = seed_record_in_group(&db, "198.51.100.50", group).await;

    api_key::Entity::delete_by_id(key).exec(&db).await.expect("the key deletes");

    assert_eq!(
        api_key_group_permission::Entity::find().count(&db).await.unwrap(),
        0,
        "the key's own grant is gone"
    );
    assert_eq!(
        ip_record_group_membership::Entity::find()
            .filter(ip_record_group_membership::Column::GroupId.eq(group))
            .count(&db)
            .await
            .unwrap(),
        1,
        "the membership survives: deleting a credential must never erase the banlist it maintained"
    );
    assert!(ip_record::Entity::find_by_id(record).one(&db).await.unwrap().is_some());
    assert!(ip_group::Entity::find_by_id(group).one(&db).await.unwrap().is_some());
    assert!(join_table_orphans(&db).await.is_empty());
}

/// **The control.** With `foreign_keys` OFF, the same delete leaves orphans behind.
///
/// Every other test in this file asserts that a cascade happened. None of them, alone, says *why* —
/// and "SQLite would have done that anyway" is a real possibility a reader is entitled to rule out.
/// This opens a pool identical to the production one except for `.foreign_keys(false)`, runs the same
/// group delete, and shows the grants and memberships surviving as dangling rows.
///
/// That makes the pragma the attributable cause rather than a setting the suite merely happens to
/// have on. It is worth the extra test because the failure it guards is silent in the worst way:
/// SQLite does not warn when foreign keys are off, it simply stops enforcing them, and the resulting
/// `api_key_group_permissions` rows are live authority that no application-level test would notice.
///
/// This is also the one place in the suite that builds a connection by hand rather than through
/// `db::connect`, which is precisely the point — it is demonstrating what `db::connect` buys.
#[tokio::test]
async fn with_foreign_keys_off_the_same_delete_leaves_dangling_rows() {
    use sea_orm::sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    use std::str::FromStr;

    let tmp = TempDb::new();

    // Identical to `db::connect` except for the one line under test. `max_connections(1)` is kept
    // because migrations need it; the journal and synchronous settings are irrelevant here.
    let options = SqliteConnectOptions::from_str(&tmp.url())
        .expect("the url parses")
        .create_if_missing(true)
        .foreign_keys(false);
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("the pool opens");
    let db = sea_orm::SqlxSqliteConnector::from_sqlx_sqlite_pool(pool);
    simply_ip_vault::db::run_migrations(&db).await.expect("every migration applies");

    // Sanity: the switch really is off. Without this the test could pass because the fixture broke.
    let pragma = db
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "PRAGMA foreign_keys;".to_owned(),
        ))
        .await
        .expect("the pragma reads")
        .expect("a row is returned");
    assert_eq!(
        pragma.try_get::<i32>("", "foreign_keys").unwrap(),
        0,
        "this test is meaningless unless foreign keys are genuinely off"
    );

    let key = seed_key(&db, "operator", None).await;
    let group = seed_group(&db, "doomed", Some(key)).await;
    seed_permission(&db, key, group).await;
    seed_record_in_group(&db, "198.51.100.60", group).await;

    ip_group::Entity::delete_by_id(group).exec(&db).await.expect("the group deletes");

    assert_eq!(
        api_key_group_permission::Entity::find().count(&db).await.unwrap(),
        1,
        "with foreign keys off the grant survives its group — this is the orphan the pragma prevents"
    );
    assert_eq!(
        ip_record_group_membership::Entity::find().count(&db).await.unwrap(),
        1,
        "and so does the membership"
    );

    let orphans = join_table_orphans(&db).await;
    assert_eq!(
        orphans.len(),
        2,
        "both join tables are left dangling; with the pragma on this list is empty: {orphans:?}"
    );
}

// ─────────────────────────────────────────────────────────────
// Audit attribution: NOT NULL, and what the rebuild had to preserve
// ─────────────────────────────────────────────────────────────
//
// `m20260811_000010` makes `api_key_name`, `api_key_prefix` and `client_ip` NOT NULL. On SQLite that
// is not an `ALTER COLUMN` — the engine has none — but a full table rebuild: create, copy, drop,
// rename. A rebuild is the most dangerous shape of migration there is, because everything it forgets
// to recreate simply stops existing, and nothing fails. The tests below pin each thing it had to
// carry across.

/// The constraint is enforced by the **engine**, against a writer that bypasses the entity layer.
///
/// The Rust type says `String`, so no application path can produce a NULL — but the type is not what
/// is deployed, and a restore, an operator, or a future migration writes SQL directly. This asserts
/// the column, not the struct.
#[tokio::test]
async fn audit_attribution_columns_reject_null_from_raw_sql() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;
    let key = seed_key(&db, "operator", None).await;

    for column in ["api_key_name", "api_key_prefix", "client_ip"] {
        // Every other column is supplied; only the one under test is NULL, so a refusal can only be
        // that column's constraint rather than an incidental error.
        let sql = format!(
            "INSERT INTO audit_logs \
             (id, api_key_id, api_key_name, api_key_prefix, client_ip, action, timestamp) \
             VALUES (x'{}', x'{}', {}, {}, {}, 'IP_ADD', '2026-01-01 00:00:00')",
            Uuid::new_v4().simple(),
            key.simple(),
            if column == "api_key_name" { "NULL" } else { "'n'" },
            if column == "api_key_prefix" { "NULL" } else { "'p'" },
            if column == "client_ip" { "NULL" } else { "'203.0.113.1'" },
        );
        let outcome = db.execute_raw(Statement::from_string(DatabaseBackend::Sqlite, sql)).await;
        assert!(
            outcome.is_err(),
            "a NULL {column} must be refused — an audit row with no actor records an action nobody \
             performed"
        );
    }

    // The control: the same statement with every column supplied must succeed. Without it, a
    // malformed INSERT would make all three assertions above pass for the wrong reason forever.
    let ok = db
        .execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            format!(
                "INSERT INTO audit_logs \
                 (id, api_key_id, api_key_name, api_key_prefix, client_ip, action, timestamp) \
                 VALUES (x'{}', x'{}', 'n', 'p', '203.0.113.1', 'IP_ADD', '2026-01-01 00:00:00')",
                Uuid::new_v4().simple(),
                key.simple()
            ),
        ))
        .await;
    assert!(ok.is_ok(), "a fully attributed row must still insert: {ok:?}");
}

/// The rebuild preserved `ON DELETE SET NULL` on `api_key_id`.
///
/// The single highest-risk thing about this migration. That cascade is what lets a key be deleted
/// without erasing what it did; a rebuild that dropped the foreign key, or recreated it as `CASCADE`,
/// would turn deleting a credential into deleting its own audit trail — and the only symptom would be
/// rows quietly disappearing.
#[tokio::test]
async fn the_audit_rebuild_preserved_the_set_null_cascade() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    let key = seed_key(&db, "worker_bot", None).await;
    let entry = seed_audit_log(&db, key, "worker_bot", "IP_ADD").await;

    api_key::Entity::delete_by_id(key).exec(&db).await.expect("the key deletes");

    let row = audit_log::Entity::find_by_id(entry)
        .one(&db)
        .await
        .unwrap()
        .expect("the audit row must survive the key that wrote it");
    assert_eq!(row.api_key_id, None, "the dangling reference is nulled");
    assert_eq!(
        row.api_key_name, "worker_bot",
        "and the denormalized attribution survives — which is now NOT NULL, so this is the only \
         record of who acted"
    );
    assert_eq!(row.api_key_prefix, "abcd1234");
}

/// The rebuild preserved both indexes.
///
/// They are dropped with the old table and must be recreated by hand. Losing one turns every audit
/// listing into a table scan — a regression no functional test would ever notice.
#[tokio::test]
async fn the_audit_rebuild_preserved_both_indexes() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    // Through `db::has_index`, the production helper, rather than `SchemaManager::has_index` — so
    // this test exercises the code path that actually runs at boot on every backend.
    for index in ["idx-audit_logs-action", "idx-audit_logs-timestamp"] {
        assert!(
            simply_ip_vault::db::has_index(&db, "audit_logs", index).await.unwrap(),
            "{index} did not survive the table rebuild"
        );
    }

    // And it must be able to say "no" — an index checker that always answers true would make the
    // assertions above, and the §5 boot check, meaningless.
    assert!(
        !simply_ip_vault::db::has_index(&db, "audit_logs", "idx-audit_logs-nonexistent")
            .await
            .unwrap(),
        "has_index must report an absent index as absent"
    );
}

/// **`GET /api/ips`'s join, filtered on `is_deleted` and (usually) `group_id`, sorted on the
/// *membership's* `updated_at` — and a bare group-scoped membership lookup — must use an index for
/// the filter and the sort, and must never fall back to a full table scan.**
///
/// `has_index` (above) only proves an index *exists*; it says nothing about whether the query
/// planner actually reaches for it, which is the property that was actually missing (production
/// logs reported 20-42s on exactly this join under load) and the property `m20260824_150000`'s own
/// module header verified empirically before writing the migration it added. `EXPLAIN QUERY PLAN`'s
/// output is the only source of truth for that — `USE TEMP B-TREE FOR ORDER BY` and `SCAN <table>`
/// are the two lines whose *absence* this test pins, so a future migration or query rewrite that
/// reintroduces either regresses loudly here rather than silently in production.
///
/// Updated by `m20260926_120000`: `list_ips` now sorts on `ip_record_group_memberships.updated_at`,
/// not `ip_records.updated_at` (see that migration's module comment for why), so the query shapes
/// pinned here changed to match. Three shapes, not two — the group-scoped shape *replaces* the old
/// two-shape coverage; the unfiltered shape is new and pins a real, accepted trade-off rather than
/// silently losing coverage of it.
#[tokio::test]
async fn list_ips_query_plan_uses_indexes_not_a_temp_b_tree_or_table_scan() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    let plan_lines = |db: &DatabaseConnection, sql: &'static str| {
        let db = db.clone();
        async move {
            db.query_all_raw(Statement::from_string(DatabaseBackend::Sqlite, sql))
                .await
                .expect("EXPLAIN QUERY PLAN runs")
                .into_iter()
                .map(|row| row.try_get::<String>("", "detail").unwrap_or_default())
                .collect::<Vec<_>>()
        }
    };

    // The common, group-scoped shape: every non-master call, and every `groups=`/`group_id=`/
    // `status=`-filtered one, carries a `group_id` predicate alongside `is_deleted`. Reproduced as
    // raw SQL because `EXPLAIN QUERY PLAN` has no SeaORM query-builder equivalent to prefix onto a
    // `Select`.
    let scoped_plan = plan_lines(
        &db,
        "EXPLAIN QUERY PLAN \
         SELECT * FROM ip_record_group_memberships \
         LEFT JOIN ip_records ON ip_records.id = ip_record_group_memberships.ip_record_id \
         WHERE ip_records.is_deleted = false \
         AND ip_record_group_memberships.group_id = '00000000-0000-0000-0000-000000000000' \
         ORDER BY ip_record_group_memberships.updated_at DESC \
         LIMIT 50 OFFSET 0",
    )
    .await;
    assert!(
        scoped_plan.iter().any(|l| l.contains("idx_membership_group_updated")),
        "a group-scoped listing must use the (group_id, updated_at) composite: {scoped_plan:?}"
    );
    assert!(
        !scoped_plan.iter().any(|l| l.contains("TEMP B-TREE")),
        "the composite index must make a separate sort step unnecessary for the common, \
         group-scoped case: {scoped_plan:?}"
    );
    assert!(
        !scoped_plan.iter().any(|l| l.contains("SCAN ip_record_group_memberships") || l.contains("SCAN ip_records")),
        "neither table may be reached by a full SCAN: {scoped_plan:?}"
    );

    // The unfiltered shape: a master browsing every group at once, with no `group_id` predicate to
    // drive either side of the join. **Documented trade-off, not a regression to chase down.** No
    // index on `ip_record_group_memberships` can drive this query from the `ip_records` side (where
    // `is_deleted` lives) while also supplying pre-sorted order on `updated_at` (which lives on
    // the *other* table) — a single-table index cannot span both. Verified by trying anyway: adding
    // a bare `(updated_at DESC)` index changed nothing about this specific plan. The old
    // `ip_records`-driven, record-level sort avoided this by living entirely on one table, at the
    // cost of the correctness bug `m20260926_120000` exists to fix; this is the accepted trade for
    // that fix. Bounded in practice by `LIMIT 50` and by this being the *unfiltered* master view
    // specifically, not the common path.
    let unfiltered_plan = plan_lines(
        &db,
        "EXPLAIN QUERY PLAN \
         SELECT * FROM ip_record_group_memberships \
         LEFT JOIN ip_records ON ip_records.id = ip_record_group_memberships.ip_record_id \
         WHERE ip_records.is_deleted = false \
         ORDER BY ip_record_group_memberships.updated_at DESC \
         LIMIT 50 OFFSET 0",
    )
    .await;
    assert!(
        unfiltered_plan.iter().any(|l| l.contains("TEMP B-TREE")),
        "if this ever stops needing a temp b-tree, the trade-off above no longer holds and this \
         test (and its doc comment) should be simplified rather than left describing a cost that \
         went away: {unfiltered_plan:?}"
    );

    // The bare group-scoped lookup every RBAC accessible-groups filter (and the `full_replace`
    // sweep) performs — `WHERE group_id = ?` alone, the shape the membership table's primary key
    // (`ip_record_id, group_id` — the *other* column order) cannot serve. Two indexes now lead
    // with `group_id` (the pre-existing `idx_group_memberships_lookup` and the new
    // `idx_membership_group_updated`), and on an empty, unanalyzed test database the planner's
    // choice between two otherwise-equivalent options isn't a property worth pinning by name —
    // only "no full scan" is.
    let group_lookup_plan =
        plan_lines(&db, "EXPLAIN QUERY PLAN SELECT * FROM ip_record_group_memberships WHERE group_id = '00000000-0000-0000-0000-000000000000'")
            .await;
    assert!(
        group_lookup_plan.iter().any(|l| l.contains("idx_group_memberships_lookup") || l.contains("idx_membership_group_updated")),
        "the group_id lookup must use one of the group_id-leading indexes: {group_lookup_plan:?}"
    );
    assert!(
        !group_lookup_plan.iter().any(|l| l.contains("SCAN")),
        "a group_id lookup must never fall back to a full table scan: {group_lookup_plan:?}"
    );
}

/// **`list_ips`'s unfiltered (no `group_id`) query, at a size where a missing index is no longer a
/// rounding error — now measuring an accepted trade-off rather than proving it away.**
///
/// The reported production symptom was 20-42 *seconds*, not milliseconds — which means the bound
/// worth asserting is "unmistakably fast", not a specific fractional-millisecond figure. A literal
/// sub-millisecond assertion would be dishonest here: this path runs through SeaORM's query
/// builder, sqlx's async row mapping, and a pooled connection acquisition, all of which cost more
/// than the index lookup itself does.
///
/// This is the **one query shape** (`is_deleted` + `ORDER BY`, no `group_id` predicate — a master
/// browsing every group at once) that `m20260926_120000` could not give a temp-b-tree-free plan:
/// see `list_ips_query_plan_uses_indexes_not_a_temp_b_tree_or_table_scan`'s own doc comment for why
/// no single-table index can drive this join *and* supply pre-sorted order once the filter and the
/// sort live on opposite sides of it. That migration measured **~67ms** here (up from ~3ms when
/// this same shape could still use `idx_ip_records_deleted_updated`, before it was removed as
/// dead weight — see that migration's module comment). The bound below is set with real margin
/// above that measurement, because the property worth pinning is "still nowhere near the reported
/// 20-42 *seconds*", not "as fast as the now-impossible fully-indexed plan used to be" — this test
/// would need rewriting, not just a smaller number, if that ever became untrue.
///
/// 50,000 rows is not arbitrary: a scale still small enough to seed and run in under two seconds,
/// while large enough that a real regression (a full table scan, say) would be unmistakable rather
/// than lost in fixed overhead.
#[tokio::test]
async fn list_ips_query_completes_quickly_at_realistic_scale() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    const GROUPS: usize = 10;
    const RECORDS_PER_GROUP: usize = 5_000;
    const BULK_CHUNK: usize = 500; // sqlite's default bound on bound parameters per statement.

    let mut group_ids = Vec::with_capacity(GROUPS);
    for g in 0..GROUPS {
        group_ids.push(seed_group(&db, &format!("bench-group-{g}"), None).await);
    }

    let now = Utc::now().naive_utc();
    let mut record_models = Vec::with_capacity(GROUPS * RECORDS_PER_GROUP);
    let mut membership_models = Vec::with_capacity(GROUPS * RECORDS_PER_GROUP);
    for (g, &group_id) in group_ids.iter().enumerate() {
        for i in 0..RECORDS_PER_GROUP {
            let id = Uuid::new_v4();
            // A spread of ages (not all identical) and roughly 10% soft-deleted — the mixed shape
            // `WHERE is_deleted = false ORDER BY updated_at DESC` actually has to sort/filter
            // through, rather than a pathological all-identical-value case an index could shortcut
            // in a way real data never does.
            let updated_at = now - chrono::Duration::seconds((g * RECORDS_PER_GROUP + i) as i64);
            record_models.push(ip_record::ActiveModel {
                id: Set(id),
                target_address: Set(format!("10.{g}.{}.{}", i / 250, i % 250)),
                cause: Set(Some("bench seed".to_owned())),
                is_locked: Set(false),
                created_at: Set(updated_at),
                updated_at: Set(updated_at),
                last_seen_at: Set(updated_at),
                is_deleted: Set(i % 10 == 0),
                deleted_at: Set(None),
                deleted_by: Set(None),
            });
            membership_models.push(ip_record_group_membership::ActiveModel {
                ip_record_id: Set(id),
                group_id: Set(group_id),
                created_at: Set(updated_at),
                updated_at: Set(updated_at),
            });
        }
    }
    for chunk in record_models.chunks(BULK_CHUNK) {
        ip_record::Entity::insert_many(chunk.to_vec()).exec(&db).await.expect("bulk record insert");
    }
    for chunk in membership_models.chunks(BULK_CHUNK) {
        ip_record_group_membership::Entity::insert_many(chunk.to_vec())
            .exec(&db)
            .await
            .expect("bulk membership insert");
    }

    // The exact shape `list_ips` builds: `find_also_related` + `filter(IsDeleted)` +
    // `order_by_desc(UpdatedAt)` + `limit`/`offset` — reproduced via the same SeaORM query builder
    // `list_ips` itself calls, not hand-written SQL, so this exercises the real ORM/async path.
    use sea_orm::{ColumnTrait, QueryFilter, QueryOrder, QuerySelect};

    let started = std::time::Instant::now();
    let page = ip_record_group_membership::Entity::find()
        .find_also_related(ip_record::Entity)
        .filter(ip_record::Column::IsDeleted.eq(false))
        .order_by_desc(ip_record_group_membership::Column::UpdatedAt)
        .limit(50)
        .offset(0)
        .all(&db)
        .await
        .expect("the paginated query succeeds");
    let elapsed = started.elapsed();
    // Visible on a passing run too (`cargo test -- --nocapture`), not only in a failure message —
    // the actual measured number is the point of a benchmark test, not just the pass/fail verdict.
    println!(
        "list_ips query: {elapsed:?} against {} seeded records (50-row page)",
        GROUPS * RECORDS_PER_GROUP
    );

    assert_eq!(page.len(), 50, "a full page of results at this row count");
    assert!(
        elapsed < std::time::Duration::from_millis(500),
        "list_ips's unfiltered query took {elapsed:?} against {} seeded records — measured at \
         ~67ms on this machine (a temp-b-tree sort, the accepted trade-off this test's own doc \
         comment explains), so 500ms is a generous margin against CI variance, not the honest \
         average; nowhere near the reported 20-42 *seconds* either way",
        GROUPS * RECORDS_PER_GROUP
    );
}

/// **`GET /api/ips?include_total=true`'s count query, at the same 50,000-row scale as the test
/// above — and an honest report of what actually bounds it.**
///
/// # The bound this asserts is measured, not the one a symptom report suggested
///
/// A prior investigation into this endpoint's `include_total` count reported production numbers
/// in the 15–37 *second* range and suggested a sub-10ms fix was possible at any scale. Measuring
/// both the historical `PaginatorTrait::count()` (which wraps the fully-projected join in
/// `SELECT COUNT(*) FROM (<12-column SELECT>) AS sub_query`) and the replacement used here (a
/// single-entity `Select` + `.select_only()` + a typed tuple, the same pattern
/// `src/api/health.rs`'s `readiness_check` already uses — no subquery, no column projection
/// beyond the count itself) at this test's own 50,000-row seed found:
///
/// - **Scoped to one group** (~4,500 matching rows after the 10% soft-deleted are excluded — the
///   realistic shape for a non-master key, which typically holds access to a handful of groups,
///   not the whole table): both versions complete in single-digit milliseconds, and the new one is
///   measurably but not dramatically faster (~4.3ms vs ~4.9ms average over 20 iterations in a
///   debug build on this machine).
/// - **Scoped to all ten groups** (~45,000 matching rows — the master-equivalent case): both
///   versions take on the order of 200ms, with **no measurable difference between them**.
///
/// Neither number is close to 15–37 seconds, and neither is reliably under 10ms — because an exact
/// `COUNT(*)` is inherently `O(matching rows)`: something has to visit every row an index says
/// matches in order to count it, and no rewrite of the query changes that. The subquery-wrapped
/// form and the direct form both do that same index walk; the difference between them is the
/// (comparatively small) cost of materializing 12 columns per row into a discarded intermediate
/// result versus not — real, but not the dominant cost at either scale measured here. This test
/// pins the property that *is* true and *is* worth guaranteeing: comfortably-bounded latency that
/// scales with **the caller's own accessible row count**, not with the size of the whole table —
/// asserted generously above the measured average so it does not flake on a loaded CI runner,
/// following the same "measured, not aspirational" philosophy as
/// `list_ips_query_completes_quickly_at_realistic_scale` above.
#[tokio::test]
async fn list_ips_include_total_count_scales_with_the_callers_own_rows_not_the_whole_table() {
    use sea_orm::{sea_query::{Expr, Func}, ColumnTrait, Condition, JoinType, QueryFilter, QuerySelect, RelationTrait};

    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    const GROUPS: usize = 10;
    const RECORDS_PER_GROUP: usize = 5_000;
    const BULK_CHUNK: usize = 500;

    let mut group_ids = Vec::with_capacity(GROUPS);
    for g in 0..GROUPS {
        group_ids.push(seed_group(&db, &format!("count-bench-group-{g}"), None).await);
    }

    let now = Utc::now().naive_utc();
    let mut record_models = Vec::with_capacity(GROUPS * RECORDS_PER_GROUP);
    let mut membership_models = Vec::with_capacity(GROUPS * RECORDS_PER_GROUP);
    for (g, &group_id) in group_ids.iter().enumerate() {
        for i in 0..RECORDS_PER_GROUP {
            let id = Uuid::new_v4();
            let updated_at = now - chrono::Duration::seconds((g * RECORDS_PER_GROUP + i) as i64);
            record_models.push(ip_record::ActiveModel {
                id: Set(id),
                target_address: Set(format!("10.{g}.{}.{}", i / 250, i % 250)),
                cause: Set(Some("count bench seed".to_owned())),
                is_locked: Set(false),
                created_at: Set(updated_at),
                updated_at: Set(updated_at),
                last_seen_at: Set(updated_at),
                is_deleted: Set(i % 10 == 0),
                deleted_at: Set(None),
                deleted_by: Set(None),
            });
            membership_models.push(ip_record_group_membership::ActiveModel {
                ip_record_id: Set(id),
                group_id: Set(group_id),
                created_at: Set(updated_at),
                updated_at: Set(updated_at),
            });
        }
    }
    for chunk in record_models.chunks(BULK_CHUNK) {
        ip_record::Entity::insert_many(chunk.to_vec()).exec(&db).await.expect("bulk record insert");
    }
    for chunk in membership_models.chunks(BULK_CHUNK) {
        ip_record_group_membership::Entity::insert_many(chunk.to_vec())
            .exec(&db)
            .await
            .expect("bulk membership insert");
    }

    let typed_count = |gids: Vec<Uuid>| {
        let db = db.clone();
        async move {
            let condition = Condition::all()
                .add(ip_record::Column::IsDeleted.eq(false))
                .add(ip_record_group_membership::Column::GroupId.is_in(gids));
            ip_record_group_membership::Entity::find()
                .join(JoinType::LeftJoin, ip_record_group_membership::Relation::IpRecord.def())
                .filter(condition)
                .select_only()
                .expr_as(
                    Func::count(Expr::col((
                        ip_record_group_membership::Entity,
                        ip_record_group_membership::Column::IpRecordId,
                    ))),
                    "row_count",
                )
                .into_tuple::<i64>()
                .one(&db)
                .await
                .expect("the count query succeeds")
                .unwrap_or(0)
        }
    };

    // Single-group scope: the realistic shape for a non-master key.
    let started = std::time::Instant::now();
    let single_group_total = typed_count(vec![group_ids[0]]).await;
    let single_group_elapsed = started.elapsed();
    println!("include_total count, 1 group (~4,500 matching rows): {single_group_elapsed:?}");
    assert_eq!(single_group_total, 4_500, "9/10 of 5,000 seeded records in the group are live");
    assert!(
        single_group_elapsed < std::time::Duration::from_millis(50),
        "a single-group-scoped count took {single_group_elapsed:?} against 4,500 matching rows — \
         measured at ~4-5ms on this machine, so 50ms is a generous margin, not the honest average"
    );

    // All-groups scope: the master-equivalent worst case at this seed size. Nowhere near the
    // 15-37 *second* figure a prior symptom report described, but also nowhere near 10ms — see
    // this test's own module comment for why an exact COUNT(*) cannot honestly promise that.
    let started = std::time::Instant::now();
    let all_groups_total = typed_count(group_ids.clone()).await;
    let all_groups_elapsed = started.elapsed();
    println!("include_total count, 10 groups (~45,000 matching rows): {all_groups_elapsed:?}");
    assert_eq!(all_groups_total, 45_000, "9/10 of 50,000 seeded records across all groups are live");
    assert!(
        all_groups_elapsed < std::time::Duration::from_secs(2),
        "a full-table-scoped count took {all_groups_elapsed:?} against 45,000 matching rows — \
         measured at ~200ms on this machine; 2s is a generous margin against CI variance, and even \
         that is three orders of magnitude below the reported 15-37s symptom"
    );
}

/// **`include_total=true` combined with `groups`, `since`, and the default `is_deleted=false`
/// filter — the shape that exercises every source of a `group_id` constraint at once (RBAC
/// read-scoping, the `groups` parameter, and — indirectly, since `status` shares the same
/// mechanism — group-type filtering) — must produce exactly one `group_id IN (...)` predicate,
/// not one per source.**
///
/// Reproduces `list_ips`'s own condition-building shape (RBAC accessible-groups intersected with
/// the `groups=` parameter, both collected as sets and combined into one `Condition` before any
/// `.filter()` call — see that function's own comment) rather than driving it through the live
/// HTTP handler: this is a property of the *query text itself*, and `QueryTrait::build` reads that
/// off the query builder directly and deterministically, with no server, connection, or global
/// logging state to coordinate across a parallel test run.
#[tokio::test]
async fn list_ips_complex_filters_produce_one_group_id_predicate_not_several() {
    use sea_orm::{sea_query::{Expr, Func}, ColumnTrait, Condition, DbBackend, JoinType, QueryFilter, QueryOrder, QuerySelect, QueryTrait, RelationTrait};

    let accessible_groups: std::collections::HashSet<Uuid> = [Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4()].into();
    let requested_groups: std::collections::HashSet<Uuid> = [*accessible_groups.iter().next().unwrap()].into();

    // The exact reduction `list_ips` performs: collect every group_id source as a set, intersect,
    // and add exactly one `.is_in(...)` — never one `.filter()` call per source.
    let mut intersected = accessible_groups.clone();
    intersected.retain(|g| requested_groups.contains(g));
    assert!(!intersected.is_empty(), "the test's own fixture must actually overlap");

    let since_threshold = Utc::now().naive_utc() - chrono::Duration::seconds(3600);
    let condition = Condition::all()
        .add(ip_record::Column::IsDeleted.eq(false))
        .add(ip_record_group_membership::Column::GroupId.is_in(intersected))
        .add(
            Condition::any().add(ip_record::Column::LastSeenAt.gte(since_threshold)),
        );

    let data_sql = ip_record_group_membership::Entity::find()
        .find_also_related(ip_record::Entity)
        .filter(condition.clone())
        .order_by_desc(ip_record_group_membership::Column::UpdatedAt)
        .limit(50)
        .offset(0)
        .build(DbBackend::Sqlite)
        .sql;

    let count_sql = ip_record_group_membership::Entity::find()
        .join(JoinType::LeftJoin, ip_record_group_membership::Relation::IpRecord.def())
        .filter(condition)
        .select_only()
        .expr_as(
            Func::count(Expr::col((
                ip_record_group_membership::Entity,
                ip_record_group_membership::Column::IpRecordId,
            ))),
            "row_count",
        )
        .build(DbBackend::Sqlite)
        .sql;

    for (label, sql) in [("data query", &data_sql), ("count query", &count_sql)] {
        let occurrences = sql.matches("group_id IN").count() + sql.matches("group_id\" IN").count();
        assert_eq!(
            occurrences, 1,
            "{label} must contain exactly one group_id IN (...) predicate, found {occurrences} in: {sql}"
        );
    }
}

/// Historical rows survive the constraint, and say so honestly.
///
/// Migrations 1–9 are applied, a row with NULL attribution is written the way the old schema allowed,
/// and only then is migration 10 applied. This is the upgrade path a real deployment takes, and it is
/// the one path the rest of the suite cannot exercise — every other test starts from a fully migrated
/// database where such a row is already impossible.
#[tokio::test]
async fn rows_written_before_the_constraint_are_backfilled_not_dropped() {
    use sea_orm_migration::MigratorTrait;

    let tmp = TempDb::new();
    let db = partial_migration_db(&tmp).await;

    // Everything up to and including m20260808_000009, but not m20260811_000010.
    simply_ip_vault::migration::Migrator::up(&db, Some(9)).await.expect("nine migrations apply");

    let key = seed_key(&db, "legacy", None).await;
    let legacy = Uuid::new_v4();
    db.execute_raw(Statement::from_string(
        DatabaseBackend::Sqlite,
        format!(
            "INSERT INTO audit_logs (id, api_key_id, action, timestamp) \
             VALUES (x'{}', x'{}', 'IP_ADD', '2020-01-01 00:00:00')",
            legacy.simple(),
            key.simple()
        ),
    ))
    .await
    .expect("the old schema permitted unattributed rows");

    // Now the constraint lands.
    simply_ip_vault::migration::Migrator::up(&db, None).await.expect("the backfill migration applies");

    let row = audit_log::Entity::find_by_id(legacy)
        .one(&db)
        .await
        .unwrap()
        .expect("a historical row must be backfilled, never discarded");

    assert_eq!(row.api_key_name, "(unknown)");
    assert_eq!(row.api_key_prefix, "(unknown)");
    assert_eq!(row.client_ip, "(unknown)");
    assert_eq!(row.action, "IP_ADD", "the rest of the row is carried across untouched");
    assert_eq!(row.api_key_id, Some(key), "including the foreign key");
    assert!(
        row.client_ip.parse::<std::net::IpAddr>().is_err(),
        "the fallback must not be mistakable for a real address — a reader has to be able to tell \
         'not recorded' from 'recorded as this'"
    );
}

/// **A production database upgrading through `m20260926_120000`, with real pre-existing data —
/// specifically including an address that already belongs to more than one group.**
///
/// Every other test in this file builds its fixture *after* all migrations have run. This one
/// does the opposite on purpose: it seeds two IP groups, an address linked into **both** of them,
/// and a second address linked into only one, all under the schema exactly as it stood immediately
/// before this migration (`ip_record_group_memberships` with only its two original columns,
/// inserted via raw SQL since that shape no longer exists in `src/entities/` to build against) —
/// then applies the migration and checks what a live upgrade would actually do to that data.
///
/// This is the scenario the migration's own module comment describes as "approximate": a
/// pre-existing membership has no true creation/touch history to recover, so both columns are
/// backfilled from the *record's* `created_at`/`updated_at`. For a record in two groups, that
/// means **both** memberships receive the identical backfilled value — correctly, since that value
/// is genuinely the best available answer for both, and the two are expected to diverge only from
/// this point forward as real per-membership activity accumulates. Asserted explicitly rather than
/// assumed, because "the fix" without this test would only have been verified for the single-group
/// case every other fixture in this file happens to construct.
#[tokio::test]
async fn upgrading_a_populated_database_backfills_every_membership_including_multi_group_ones() {
    use sea_orm_migration::MigratorTrait;

    let tmp = TempDb::new();
    let db = partial_migration_db(&tmp).await;

    // Everything up to and including m20260824_150000 (the 16th migration), but not this one.
    simply_ip_vault::migration::Migrator::up(&db, Some(16)).await.expect("sixteen migrations apply");

    let group_a = seed_group(&db, "prod-group-a", None).await;
    let group_b = seed_group(&db, "prod-group-b", None).await;

    // A record that has existed for a while and was touched more recently — distinct, recognizable
    // values so a wrong column (or a transposition) would be visible, not coincidentally correct.
    let shared_created = chrono::NaiveDateTime::parse_from_str("2026-06-01 08:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
    let shared_updated = chrono::NaiveDateTime::parse_from_str("2026-08-15 12:30:00", "%Y-%m-%d %H:%M:%S").unwrap();
    let shared_record = Uuid::new_v4();
    simply_ip_vault::entities::ip_record::Entity::insert(simply_ip_vault::entities::ip_record::ActiveModel {
        id: Set(shared_record),
        target_address: Set("203.0.113.50".to_owned()),
        cause: Set(Some("production seed".to_owned())),
        is_locked: Set(false),
        created_at: Set(shared_created),
        updated_at: Set(shared_updated),
        last_seen_at: Set(shared_updated),
        is_deleted: Set(false),
        deleted_at: Set(None),
        deleted_by: Set(None),
    })
    .exec(&db)
    .await
    .expect("the record inserts under the pre-migration schema");

    // A second, single-group record, so the test also covers the ordinary case alongside the
    // multi-group one rather than only the latter.
    let solo_created = chrono::NaiveDateTime::parse_from_str("2026-07-01 09:00:00", "%Y-%m-%d %H:%M:%S").unwrap();
    let solo_updated = chrono::NaiveDateTime::parse_from_str("2026-08-20 16:45:00", "%Y-%m-%d %H:%M:%S").unwrap();
    let solo_record = Uuid::new_v4();
    simply_ip_vault::entities::ip_record::Entity::insert(simply_ip_vault::entities::ip_record::ActiveModel {
        id: Set(solo_record),
        target_address: Set("203.0.113.51".to_owned()),
        cause: Set(None),
        is_locked: Set(false),
        created_at: Set(solo_created),
        updated_at: Set(solo_updated),
        last_seen_at: Set(solo_updated),
        is_deleted: Set(false),
        deleted_at: Set(None),
        deleted_by: Set(None),
    })
    .exec(&db)
    .await
    .expect("the second record inserts");

    // Three membership rows, under the OLD two-column shape — raw SQL because the current
    // `ip_record_group_membership::ActiveModel` already requires `created_at`/`updated_at` and
    // cannot express a row the pre-migration schema would accept.
    for (record, group) in [(shared_record, group_a), (shared_record, group_b), (solo_record, group_a)] {
        db.execute_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            format!(
                "INSERT INTO ip_record_group_memberships (ip_record_id, group_id) VALUES (x'{}', x'{}')",
                record.simple(),
                group.simple()
            ),
        ))
        .await
        .expect("the old schema accepts a membership row with no timestamps");
    }

    // The upgrade.
    simply_ip_vault::migration::Migrator::up(&db, None).await.expect("the membership-timestamp migration applies");

    // Nothing lost, nothing duplicated: exactly the three memberships seeded above, still linking
    // the same (record, group) pairs.
    let all_memberships = simply_ip_vault::entities::ip_record_group_membership::Entity::find()
        .all(&db)
        .await
        .expect("memberships are still queryable through the new entity shape");
    assert_eq!(all_memberships.len(), 3, "no membership row was lost or duplicated by the rebuild");

    let shared_memberships: Vec<_> = all_memberships.iter().filter(|m| m.ip_record_id == shared_record).collect();
    assert_eq!(shared_memberships.len(), 2, "the multi-group record must still hold both of its memberships");
    let shared_groups: std::collections::HashSet<Uuid> = shared_memberships.iter().map(|m| m.group_id).collect();
    assert_eq!(shared_groups, [group_a, group_b].into(), "linked to exactly the two groups seeded, no others");

    // The multi-group case this test exists for: BOTH of the shared record's memberships were
    // backfilled from that same record, and therefore agree with each other and with the record.
    for m in &shared_memberships {
        assert_eq!(m.created_at, shared_created, "backfilled created_at must match the record's own, for group {}", m.group_id);
        assert_eq!(m.updated_at, shared_updated, "backfilled updated_at must match the record's own, for group {}", m.group_id);
    }

    let solo_membership = all_memberships
        .iter()
        .find(|m| m.ip_record_id == solo_record)
        .expect("the single-group record's membership survives too");
    assert_eq!(solo_membership.group_id, group_a);
    assert_eq!(solo_membership.created_at, solo_created);
    assert_eq!(solo_membership.updated_at, solo_updated);

    // Foreign keys still function post-rebuild: deleting the shared record must cascade and leave
    // group_b with none of its memberships, not an orphaned row.
    simply_ip_vault::entities::ip_record::Entity::delete_by_id(shared_record)
        .exec(&db)
        .await
        .expect("the delete succeeds");
    let remaining = simply_ip_vault::entities::ip_record_group_membership::Entity::find()
        .filter(simply_ip_vault::entities::ip_record_group_membership::Column::IpRecordId.eq(shared_record))
        .all(&db)
        .await
        .expect("query succeeds");
    assert!(remaining.is_empty(), "ON DELETE CASCADE must still cascade after the rebuild");

    // The index swap actually happened: the new composite exists, and the one built solely for the
    // record-level sort this migration retires does not.
    assert!(
        simply_ip_vault::db::has_index(&db, "ip_record_group_memberships", "idx_membership_group_updated")
            .await
            .unwrap(),
        "the new (group_id, updated_at) composite must exist after the upgrade"
    );
    assert!(
        simply_ip_vault::db::has_index(&db, "ip_record_group_memberships", "idx_group_memberships_lookup")
            .await
            .unwrap(),
        "the pre-existing group_id lookup index must survive the rebuild"
    );
    assert!(
        !simply_ip_vault::db::has_index(&db, "ip_records", "idx_ip_records_deleted_updated")
            .await
            .unwrap(),
        "the index built for the record-level sort this migration retires must be gone, not just unused"
    );
}

/// The copy is by column name, not by position.
///
/// A rebuild that copies positionally looks correct until a column order changes, at which point
/// names land in the address column and every type still checks out. Asserted with values that make
/// a transposition visible.
#[tokio::test]
async fn the_audit_rebuild_did_not_transpose_columns() {
    use sea_orm_migration::MigratorTrait;

    let tmp = TempDb::new();
    let db = partial_migration_db(&tmp).await;
    simply_ip_vault::migration::Migrator::up(&db, Some(9)).await.expect("nine migrations apply");

    let key = seed_key(&db, "before", None).await;
    let id = Uuid::new_v4();
    db.execute_raw(Statement::from_string(
        DatabaseBackend::Sqlite,
        format!(
            "INSERT INTO audit_logs \
             (id, api_key_id, api_key_name, api_key_prefix, client_ip, action, target_address, \
              group_names, details, timestamp) \
             VALUES (x'{}', x'{}', 'NAME', 'PREFIX', '198.51.100.7', 'ACTION', 'TARGET', \
              'GROUPS', 'DETAILS', '2021-02-03 04:05:06')",
            id.simple(),
            key.simple()
        ),
    ))
    .await
    .expect("the row inserts");

    simply_ip_vault::migration::Migrator::up(&db, None).await.expect("the rebuild applies");

    let row = audit_log::Entity::find_by_id(id).one(&db).await.unwrap().expect("row survives");
    assert_eq!(row.api_key_name, "NAME");
    assert_eq!(row.api_key_prefix, "PREFIX");
    assert_eq!(row.client_ip, "198.51.100.7");
    assert_eq!(row.action, "ACTION");
    assert_eq!(row.target_address.as_deref(), Some("TARGET"));
    assert_eq!(row.group_names.as_deref(), Some("GROUPS"));
    assert_eq!(row.details.as_deref(), Some("DETAILS"));
    assert_eq!(row.api_key_id, Some(key));
}

/// Every column a delta-sync consumer filters on is indexed.
///
/// The exporter and sync worker poll "what changed since T" on a schedule against the largest table
/// in the schema. Without an index that is a full scan per poll, and it degrades as the table grows
/// rather than failing outright — the kind of regression that shows up as a slow dashboard months
/// later and is never traced back to a missing line in a migration.
///
/// Asserted through `db::has_index`, the same helper the §5 boot check uses, so this also exercises
/// that path on every run.
#[tokio::test]
async fn the_delta_sync_columns_are_indexed() {
    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    for index in [
        "idx-ip_records-updated_at",
        "idx_ip_records_deleted_at",
        "idx_ip_records_is_deleted",
        "idx-ip_records-last_seen_at",
    ] {
        assert!(
            simply_ip_vault::db::has_index(&db, "ip_records", index).await.unwrap(),
            "{index} is missing — a delta query on that column scans the whole table"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// Address canonicalisation, and the uniqueness constraint behind it
// ─────────────────────────────────────────────────────────────
//
// `ip_records.target_address` is UNIQUE, so canonicalisation is what decides whether two spellings
// are one ban or two. That makes `normalize_ip_or_cidr` a *schema* concern as much as a formatting
// one, which is why these live here rather than beside the handlers.

/// Every spelling of one IPv6 host canonicalises to the same string, and the database enforces it.
///
/// IPv6 has more redundant spellings than any other address family — leading zeros, `::` compression,
/// an explicit `/128` — and a service that stored them separately would let the same host be banned
/// four times, unbanned once, and remain blocked. The canonical form is what makes the UNIQUE index
/// meaningful rather than decorative.
///
/// Asserted twice over: first that the function agrees, then that a **second insert really collides**.
/// The first alone would pass if the column had silently lost its constraint.
#[tokio::test]
async fn every_spelling_of_one_ipv6_host_is_one_record() {
    use simply_ip_vault::api::normalize_ip_or_cidr;

    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;

    let spellings = [
        "2001:db8::1/128",
        "2001:0db8:0000:0000:0000:0000:0000:0001/128",
        "2001:0db8:0000:0000:0000:0000:0000:0001",
        "2001:db8::1",
        // Mixed case is the same address; IPv6 literals are case-insensitive.
        "2001:DB8::1",
    ];

    let canonical = normalize_ip_or_cidr(spellings[0]);
    assert_eq!(canonical, "2001:db8::1", "the canonical form drops /128 and compresses");
    for spelling in spellings {
        assert_eq!(
            normalize_ip_or_cidr(spelling),
            canonical,
            "{spelling} must canonicalise to {canonical}"
        );
    }

    // Now the half that matters: the engine refuses the duplicate, so even a writer that skipped the
    // helper cannot produce two rows for one host.
    let group = seed_group(&db, "v6", None).await;
    seed_record_in_group(&db, &canonical, group).await;

    let collision = ip_record::Entity::insert(ip_record::ActiveModel {
        id: Set(Uuid::new_v4()),
        target_address: Set(canonical.clone()),
        cause: Set(None),
        is_locked: Set(false),
        created_at: Set(Utc::now().naive_utc()),
        updated_at: Set(Utc::now().naive_utc()),
        last_seen_at: Set(Utc::now().naive_utc()),
        is_deleted: Set(false),
        deleted_at: Set(None),
        deleted_by: Set(None),
    })
    .exec(&db)
    .await;
    assert!(
        collision.is_err(),
        "target_address is UNIQUE — a second row for the same canonical host must be refused"
    );
}

/// Submitting a CIDR with host bits set stores the **network** address.
///
/// `192.168.1.50/24` and `192.168.1.0/24` name the same range, and since Session 55 they are the
/// same record. Before that they were two rows with independent lifecycles: banning through one and
/// unbanning through the other left the range blocked, with nothing in the API to explain why.
#[tokio::test]
async fn test_cidr_host_bit_normalization() {
    use simply_ip_vault::api::normalize_ip_or_cidr;

    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;
    let group = seed_group(&db, "mask", None).await;

    assert_eq!(normalize_ip_or_cidr("192.168.1.50/24"), "192.168.1.0/24");

    // What actually reaches the column is what matters; the helper agreeing is necessary, not
    // sufficient. A write path that forgot to canonicalise would still store the raw string.
    seed_record_in_group(&db, &normalize_ip_or_cidr("192.168.1.50/24"), group).await;
    let stored = ip_record::Entity::find().all(&db).await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(
        stored[0].target_address, "192.168.1.0/24",
        "the saved target_address is the network address, not the address as typed"
    );

    // Masking follows the prefix length rather than the octet boundary — the case a naive
    // implementation that zeroed trailing octets would get wrong.
    assert_eq!(normalize_ip_or_cidr("192.168.1.130/25"), "192.168.1.128/25");
    assert_eq!(normalize_ip_or_cidr("192.168.1.126/25"), "192.168.1.0/25");

    // Single hosts are untouched: a /32 is not a network to be masked, it *is* the address.
    assert_eq!(normalize_ip_or_cidr("192.168.1.50/32"), "192.168.1.50");
    assert_eq!(normalize_ip_or_cidr("192.168.1.50"), "192.168.1.50");
}

/// Two spellings of one network with different host bits address the **same row**.
///
/// This is the deduplication the change exists for. The second write must find and update the
/// record the first created — not insert a second — which is what makes the UNIQUE constraint do the
/// work instead of leaving it to whoever typed the address.
#[tokio::test]
async fn test_cidr_deduplication_different_host_bits() {
    use simply_ip_vault::api::normalize_ip_or_cidr;

    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;
    let group = seed_group(&db, "dedupe", None).await;

    let first = normalize_ip_or_cidr("192.168.1.50/24");
    let second = normalize_ip_or_cidr("192.168.1.100/24");
    let third = normalize_ip_or_cidr("192.168.1.255/24");
    assert_eq!(first, second, "different host bits, one network");
    assert_eq!(first, third, "including the broadcast address");
    assert_eq!(first, "192.168.1.0/24");

    let id = seed_record_in_group(&db, &first, group).await;

    // A second insert under the other spelling collides, because both canonicalise to one string.
    // Asserted at the engine rather than only through the helper: even a writer that skipped
    // canonicalisation entirely cannot produce two rows for the *canonical* form.
    let collision = ip_record::Entity::insert(ip_record::ActiveModel {
        id: Set(Uuid::new_v4()),
        target_address: Set(second.clone()),
        cause: Set(None),
        is_locked: Set(false),
        created_at: Set(Utc::now().naive_utc()),
        updated_at: Set(Utc::now().naive_utc()),
        last_seen_at: Set(Utc::now().naive_utc()),
        is_deleted: Set(false),
        deleted_at: Set(None),
        deleted_by: Set(None),
    })
    .exec(&db)
    .await;
    assert!(collision.is_err(), "the second spelling must collide, not create a second row");

    // Lookup by either spelling finds the one record — the property a caller actually depends on
    // when it bans through one form and unbans through another.
    for spelling in ["192.168.1.50/24", "192.168.1.100/24", "192.168.1.0/24"] {
        let found = ip_record::Entity::find()
            .filter(ip_record::Column::TargetAddress.eq(normalize_ip_or_cidr(spelling)))
            .one(&db)
            .await
            .unwrap()
            .unwrap_or_else(|| panic!("{spelling} must resolve to the stored record"));
        assert_eq!(found.id, id, "{spelling} resolves to the same row");
    }

    assert_eq!(ip_record::Entity::find().all(&db).await.unwrap().len(), 1, "exactly one row");
}

/// IPv6 subnets are masked on the same rule as IPv4.
///
/// Worth its own test rather than a line in the one above: v6 masking operates on 128 bits and on a
/// compressed textual form, and an implementation that special-cased v4 octets would pass every
/// assertion there while failing here.
#[tokio::test]
async fn test_ipv6_cidr_host_bit_normalization() {
    use simply_ip_vault::api::normalize_ip_or_cidr;

    let tmp = TempDb::new();
    let db = fresh_db(&tmp).await;
    let group = seed_group(&db, "v6mask", None).await;

    assert_eq!(normalize_ip_or_cidr("2001:db8::fe/64"), "2001:db8::/64");
    // Host bits above the low byte, and a prefix that is not a multiple of 16.
    assert_eq!(normalize_ip_or_cidr("2001:db8:0:0:dead:beef:0:1/64"), "2001:db8::/64");
    assert_eq!(normalize_ip_or_cidr("2001:db8::1234/56"), "2001:db8::/56");
    assert_eq!(normalize_ip_or_cidr("2001:db8:abcd:ef01::1/60"), "2001:db8:abcd:ef00::/60");

    // A /128 stays an exact host, as does a bare address.
    assert_eq!(normalize_ip_or_cidr("2001:db8::fe/128"), "2001:db8::fe");
    assert_eq!(normalize_ip_or_cidr("2001:db8::fe"), "2001:db8::fe");

    seed_record_in_group(&db, &normalize_ip_or_cidr("2001:db8::fe/64"), group).await;
    let stored = ip_record::Entity::find().all(&db).await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].target_address, "2001:db8::/64");

    // And a different host inside the same /64 is the same record.
    assert_eq!(
        normalize_ip_or_cidr("2001:db8::9999/64"),
        stored[0].target_address,
        "any host inside the prefix canonicalises to the network"
    );
}
