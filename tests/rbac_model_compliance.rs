//! Rule-indexed compliance suite for `RBAC_MODEL.md`.
//!
//! # What makes this file different from the other two suites
//!
//! `rbac_integration_tests.rs` asks "does the feature work?". `security_tests.rs` asks "can it be
//! made to *not* work?". This one asks a third question: **"is the specification enforced?"** — and
//! answers it in a form that can be audited by reading test names.
//!
//! **Every test name begins with the rule or section it enforces**: `r1_`…`r7_` for the core
//! governance rules, `s3_`…`s7_` for the numbered sections. `scripts/verify_convergence.sh` parses
//! this file for those prefixes and **fails if any rule has no test**, so a rule added to the
//! specification cannot quietly go uncovered — the convergence check breaks until someone writes the
//! test.
//!
//! # What that buys, and what it does not
//!
//! Coverage by name is a real property and a shallow one: a test named `r2_…` proves a rule is
//! *thought about*, not that it is *enforced*. The second half is mutation testing, reported in
//! `AGENT_NOTES.MD` — for each rule, the enforcement is disabled in `src/` and the corresponding test
//! must fail. A rule whose mutation does not fire is recorded there as untested rather than counted
//! as covered, because a test that also passes against unfixed code proves nothing.
//!
//! # Deliberately self-contained
//!
//! The harness below duplicates a small amount of setup from the other suites rather than sharing it,
//! for the same reason `security_tests.rs` does: a refactor of the functional tests must not be able
//! to silently weaken the suite that proves the model is enforced.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, Database, DatabaseConnection, EntityTrait,
    QueryFilter,
};
use sea_orm_migration::MigratorTrait;
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

use simply_ip_vault::{create_app, migration, state::AppState};

// ─────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────

async fn setup() -> (DatabaseConnection, axum::Router) {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migration::Migrator::up(&db, None).await.unwrap();
    let (webhook_tx, rx) = tokio::sync::mpsc::channel(100);
    // The receiver is leaked deliberately: dropping it closes the channel, and a handler that
    // dispatches a webhook event would then see a send error rather than the success path under test.
    std::mem::forget(rx);
    let app = create_app(AppState::with_trusted_proxies(
        db.clone(),
        webhook_tx,
        Vec::new(),
    ));
    (db, app)
}

fn peer(req: axum::http::request::Builder) -> axum::http::request::Builder {
    req.extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
        [127, 0, 0, 1],
        8080,
    ))))
}

/// A seeded key's signing secret, derived from its plaintext so [`signed`] can rediscover it.
fn secret_of(api_key: &str) -> String {
    format!("compliance-secret-for-{api_key}")
}

/// The same secret in the shape the database stores (`SecretCipher::open` is strictly fail-closed and
/// rejects anything without a recognized prefix).
fn stored_secret(api_key: &str) -> String {
    format!("v1.plain.{}", hex::encode(secret_of(api_key)))
}

/// Signs a request `offset` seconds from now, deriving the secret from the builder's `X-API-Key`.
///
/// The offset is not a workaround for the anti-replay guard — it is how an in-process test models
/// elapsed time that a real caller gets for free. A signature covers method, target, timestamp and
/// body and nothing else, so two identical calls in one wall-clock second produce one signature,
/// which is by definition a replay.
fn signed(
    builder: axum::http::request::Builder,
    offset: i64,
    body: impl Into<String>,
) -> Request<Body> {
    let derived = builder
        .headers_ref()
        .and_then(|h| h.get("X-API-Key"))
        .and_then(|v| v.to_str().ok())
        .map(secret_of);
    sign_with(builder, derived.as_deref(), offset, body.into())
}

/// Signs with an explicitly supplied secret, for keys minted through `POST /api/keys` whose secret is
/// server-generated.
fn signed_as(
    builder: axum::http::request::Builder,
    secret: &str,
    offset: i64,
    body: impl Into<String>,
) -> Request<Body> {
    sign_with(builder, Some(secret), offset, body.into())
}

fn sign_with(
    builder: axum::http::request::Builder,
    secret: Option<&str>,
    offset: i64,
    body: String,
) -> Request<Body> {
    let method = builder
        .method_ref()
        .map_or_else(|| "GET".to_owned(), |m| m.as_str().to_owned());
    let target = builder.uri_ref().map_or_else(
        || "/".to_owned(),
        |u| {
            u.path_and_query()
                .map_or_else(|| u.path().to_owned(), |pq| pq.as_str().to_owned())
        },
    );
    let timestamp = (chrono::Utc::now().timestamp() + offset).to_string();

    let mut builder = builder.header("X-Timestamp", &timestamp);
    if let Some(secret) = secret {
        let signature = simply_ip_vault::crypto::compute_signature(
            secret,
            &method,
            &target,
            &timestamp,
            body.as_bytes(),
        )
        .unwrap();
        builder = builder.header("X-Signature-256", signature);
    }
    builder.body(Body::from(body)).unwrap()
}

/// Attempts to write a second Master **the way an attacker or a careless operator would**: straight
/// at the table, with `is_master` set and `master_marker` simply not mentioned.
///
/// This helper exists so the adversarial shape is written once and cannot drift into a cooperative
/// one. Two properties are load-bearing and neither is obvious:
///
/// - **No `ActiveModel`.** `SeaORM` builds column lists from the entity, and `master_marker` is not on
///   the entity, so an `ActiveModel` insert is adversarial only by accident of our own type
///   definitions. Raw SQL is adversarial by construction, and stays adversarial if someone
///   reintroduces the field.
/// - **The marker is omitted, not set to NULL.** Both are refused now, but omission is the shape that
///   was *accepted* under the previous schema, so it is the shape worth regressing against.
///
/// Returns the driver's result rather than asserting, so callers can assert on the error text.
async fn adversarial_master_insert(
    db: &DatabaseConnection,
    name: &str,
    prefix: &str,
) -> Result<sea_orm::ExecResult, sea_orm::DbErr> {
    use sea_orm::ConnectionTrait;
    // `x'…'` for the id: SeaORM stores `Uuid` as a 16-byte BLOB on SQLite, so a hyphenated literal
    // would insert fine and then fail to decode on read — which would look like the constraint
    // working when it had not.
    db.execute_raw(sea_orm::Statement::from_string(
        db.get_database_backend(),
        format!(
            "INSERT INTO api_keys (id, name, key_hash, prefix, is_master, can_manage_keys, \
             can_manage_webhooks, can_create_groups, created_at, updated_at) \
             VALUES (x'{}', '{name}', '{}', '{prefix}', true, true, true, true, \
              '2026-08-08 00:00:00', '2026-08-08 00:00:00')",
            Uuid::new_v4().simple(),
            simply_ip_vault::api::hash_key(&simply_ip_vault::api::generate_random_key()),
        ),
    ))
    .await
}

const KEYS_SCOPE: simply_ip_vault::api::AdminScopes = simply_ip_vault::api::AdminScopes {
    can_manage_keys: true,
    can_manage_webhooks: false,
    can_create_groups: false,
};

const NO_ADMIN_SCOPES: simply_ip_vault::api::AdminScopes = simply_ip_vault::api::AdminScopes {
    can_manage_keys: false,
    can_manage_webhooks: false,
    can_create_groups: false,
};

const ALL_ADMIN_SCOPES: simply_ip_vault::api::AdminScopes = simply_ip_vault::api::AdminScopes {
    can_manage_keys: true,
    can_manage_webhooks: true,
    can_create_groups: true,
};

const KEYS_AND_WEBHOOKS_SCOPE: simply_ip_vault::api::AdminScopes =
    simply_ip_vault::api::AdminScopes {
        can_manage_keys: true,
        can_manage_webhooks: true,
        can_create_groups: false,
    };

async fn key(
    db: &DatabaseConnection,
    name: &str,
    is_master: bool,
    scopes: simply_ip_vault::api::AdminScopes,
) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(id),
        key_hash: Set(simply_ip_vault::api::hash_key(&plaintext)),
        signing_secret: Set(Some(stored_secret(&plaintext))),
        name: Set(name.to_owned()),
        bound_ips: Set(None),
        is_master: Set(is_master),
        can_manage_keys: Set(scopes.can_manage_keys),
        can_manage_webhooks: Set(scopes.can_manage_webhooks),
        can_create_groups: Set(scopes.can_create_groups),
        parent_key_id: Set(None),
        prefix: Set("compl001".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(db)
    .await
    .unwrap();
    (id, plaintext)
}

async fn group(db: &DatabaseConnection, name: &str, owner: Option<Uuid>) -> Uuid {
    let id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(id),
        name: Set(name.to_owned()),
        allow_private_ips: Set(false),
        group_type: Set("banlist".to_owned()),
        description: Set(None),
        owner_key_id: Set(owner),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(db)
    .await
    .unwrap();
    id
}

const GROUP_READ: simply_ip_vault::api::GroupCapabilities =
    simply_ip_vault::api::GroupCapabilities {
        can_read: true,
        can_write: false,
        can_delete: false,
    };

const GROUP_READ_WRITE_DELETE: simply_ip_vault::api::GroupCapabilities =
    simply_ip_vault::api::GroupCapabilities {
        can_read: true,
        can_write: true,
        can_delete: true,
    };

const GROUP_READ_WRITE: simply_ip_vault::api::GroupCapabilities =
    simply_ip_vault::api::GroupCapabilities {
        can_read: true,
        can_write: true,
        can_delete: false,
    };

async fn grant(
    db: &DatabaseConnection,
    key_id: Uuid,
    group_id: Uuid,
    capabilities: simply_ip_vault::api::GroupCapabilities,
    manage: bool,
) {
    simply_ip_vault::entities::api_key_group_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(key_id),
        group_id: Set(group_id),
        can_read: Set(capabilities.can_read),
        can_write: Set(capabilities.can_write),
        can_delete: Set(capabilities.can_delete),
        can_manage: Set(manage),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(db)
    .await
    .unwrap();
}

async fn set_parent(db: &DatabaseConnection, child: Uuid, parent: Option<Uuid>) {
    let mut active: simply_ip_vault::entities::api_key::ActiveModel =
        simply_ip_vault::entities::prelude::ApiKey::find_by_id(child)
            .one(db)
            .await
            .unwrap()
            .unwrap()
            .into();
    active.parent_key_id = Set(parent);
    active.update(db).await.unwrap();
}

/// Sends a request and returns `(status, body-as-string)`.
async fn send(app: &axum::Router, req: Request<Body>) -> (StatusCode, String) {
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8(bytes.to_vec()).unwrap())
}

/// A `POST /api/keys/{target}/permissions` body.
fn perm_body(
    group_name: &str,
    capabilities: simply_ip_vault::api::GroupCapabilities,
    manage: bool,
) -> String {
    json!({
        "group_name": group_name,
        "can_read": capabilities.can_read,
        "can_write": capabilities.can_write,
        "can_delete": capabilities.can_delete,
        "can_manage": manage,
    })
    .to_string()
}

// ─────────────────────────────────────────────────────────────
// R1 — Non-amplification
// ─────────────────────────────────────────────────────────────

/// **R1.** "A caller may only grant rights it currently holds itself. A holder of a single read-level
/// verb may grant that verb and nothing more. Applies at every tier below Master."
///
/// Asserted per verb, from a caller that satisfies R2's conjunction so the refusal is R1's and not
/// R2's — otherwise the test would pass against a build with no per-verb check at all.
#[tokio::test]
async fn r1_non_amplification_a_caller_cannot_grant_a_verb_it_does_not_hold() {
    let (db, app) = setup().await;
    let (caller_id, caller) = key(&db, "Reader-manager", false, KEYS_SCOPE).await;
    let (target_id, _t) = key(&db, "Target", false, NO_ADMIN_SCOPES).await;

    let g = group(&db, "r1-group", None).await;
    // Read only, plus the administrative flag: admitted by R2, bounded by R1.
    grant(&db, caller_id, g, GROUP_READ, true).await;

    let attempt = |read, write, del, manage, offset| {
        let (app, caller) = (app.clone(), caller.clone());
        async move {
            let req = signed(
                peer(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/api/keys/{target_id}/permissions"))
                        .header("X-API-Key", &caller)
                        .header("Content-Type", "application/json"),
                ),
                offset,
                perm_body(
                    "r1-group",
                    simply_ip_vault::api::GroupCapabilities {
                        can_read: read,
                        can_write: write,
                        can_delete: del,
                    },
                    manage,
                ),
            );
            send(&app, req).await.0
        }
    };

    assert_eq!(
        attempt(true, false, false, false, 1).await,
        StatusCode::OK,
        "the verb it holds"
    );
    assert_eq!(
        attempt(true, true, false, false, 2).await,
        StatusCode::FORBIDDEN,
        "can_write"
    );
    assert_eq!(
        attempt(true, false, true, false, 3).await,
        StatusCode::FORBIDDEN,
        "can_delete"
    );

    let landed = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .filter(simply_ip_vault::entities::api_key_group_permission::Column::ApiKeyId.eq(target_id))
        .one(&db)
        .await
        .unwrap()
        .expect("the permitted grant landed");
    assert!(landed.can_read && !landed.can_write && !landed.can_delete);
}

// ─────────────────────────────────────────────────────────────
// R2 — Manage is a conjunction
// ─────────────────────────────────────────────────────────────

/// **R2.** "Managing a specific resource requires holding both global `can_manage_keys` AND a
/// `can_manage = true` row for that specific resource. Neither alone is sufficient. `can_manage_keys`
/// is never a global bypass of per-resource RBAC."
///
/// All four caller classes, in both directions, so the conjunction cannot regress into either half.
#[tokio::test]
async fn r2_conjunction_neither_half_alone_confers_management() {
    let (db, app) = setup().await;
    let g = group(&db, "r2-group", None).await;

    let (global_id, global) = key(&db, "Global half", false, KEYS_SCOPE).await;
    grant(&db, global_id, g, GROUP_READ_WRITE_DELETE, false).await;

    let (scoped_id, scoped) = key(&db, "Scoped half", false, NO_ADMIN_SCOPES).await;
    grant(&db, scoped_id, g, GROUP_READ_WRITE_DELETE, true).await;

    let (both_id, both) = key(&db, "Both halves", false, KEYS_SCOPE).await;
    grant(&db, both_id, g, GROUP_READ_WRITE_DELETE, true).await;

    let (victim_id, _v) = key(&db, "Victim", false, NO_ADMIN_SCOPES).await;

    let grant_as = |caller: String, offset| {
        let app = app.clone();
        async move {
            let req = signed(
                peer(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/api/keys/{victim_id}/permissions"))
                        .header("X-API-Key", &caller)
                        .header("Content-Type", "application/json"),
                ),
                offset,
                perm_body("r2-group", GROUP_READ_WRITE, false),
            );
            send(&app, req).await.0
        }
    };
    let revoke_as = |caller: String, offset| {
        let app = app.clone();
        async move {
            let req = signed(
                peer(
                    Request::builder()
                        .method("DELETE")
                        .uri(format!("/api/keys/{victim_id}/permissions/r2-group"))
                        .header("X-API-Key", &caller),
                ),
                offset,
                "",
            );
            send(&app, req).await.0
        }
    };

    assert_eq!(
        grant_as(global.clone(), 1).await,
        StatusCode::FORBIDDEN,
        "can_manage_keys alone"
    );
    assert_eq!(
        grant_as(scoped.clone(), 2).await,
        StatusCode::FORBIDDEN,
        "can_manage alone"
    );
    assert_eq!(
        grant_as(both.clone(), 3).await,
        StatusCode::OK,
        "both halves"
    );

    assert_eq!(
        revoke_as(global, 4).await,
        StatusCode::FORBIDDEN,
        "can_manage_keys alone"
    );
    assert_eq!(
        revoke_as(scoped, 5).await,
        StatusCode::FORBIDDEN,
        "can_manage alone"
    );
    assert_eq!(
        revoke_as(both, 6).await,
        StatusCode::NO_CONTENT,
        "both halves"
    );
}

// ─────────────────────────────────────────────────────────────
// R3 — Parentage confers no authority
// ─────────────────────────────────────────────────────────────

/// **R3.** "`parent_key_id` exists solely for cascading deletion and visibility scoping. A daughter of
/// the Master key is an ordinary daughter key with no elevated standing. Rights are never derived
/// from key lineage."
///
/// A three-way differential — child of Master, child of an ordinary parent, and no parent at all —
/// holding identical scopes and identical grants, so lineage is the only variable. Two arms would
/// miss the likeliest mutation (`parent_key_id.is_some()`), which elevates both children together and
/// leaves them agreeing.
#[tokio::test]
async fn r3_lineage_confers_no_authority() {
    let (db, app) = setup().await;
    let (master_id, _m) = key(&db, "Master", true, ALL_ADMIN_SCOPES).await;
    let (parent_id, _p) = key(&db, "Ordinary parent", false, KEYS_SCOPE).await;

    let (royal_id, royal) = key(&db, "Master's child", false, KEYS_SCOPE).await;
    let (commoner_id, commoner) = key(&db, "Parent's child", false, KEYS_SCOPE).await;
    let (orphan_id, orphan) = key(&db, "No parent", false, KEYS_SCOPE).await;
    set_parent(&db, royal_id, Some(master_id)).await;
    set_parent(&db, commoner_id, Some(parent_id)).await;
    set_parent(&db, orphan_id, None).await;

    // `home` satisfies the group-independent pre-gate; `target` is what the probes attack, and the
    // caller holds only a plain row there. Without the two-group shape the pre-gate would refuse
    // first and mask any lineage-sensitive branch in the guard under test.
    let home = group(&db, "r3-home", None).await;
    let target = group(&db, "r3-target", None).await;
    for id in [royal_id, commoner_id, orphan_id] {
        grant(&db, id, home, GROUP_READ_WRITE_DELETE, true).await;
        grant(&db, id, target, GROUP_READ_WRITE_DELETE, false).await;
    }
    let (victim_id, _v) = key(&db, "Victim", false, NO_ADMIN_SCOPES).await;
    grant(&db, victim_id, target, GROUP_READ, false).await;

    let probe = |caller: String, offset: i64| {
        let app = app.clone();
        async move {
            let mut answers = Vec::new();
            let req = signed(
                peer(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/api/keys/{victim_id}/permissions"))
                        .header("X-API-Key", &caller)
                        .header("Content-Type", "application/json"),
                ),
                offset,
                perm_body("r3-target", GROUP_READ_WRITE, false),
            );
            answers.push(send(&app, req).await.0);

            let req = signed(
                peer(
                    Request::builder()
                        .method("DELETE")
                        .uri(format!("/api/keys/{victim_id}/permissions/r3-target"))
                        .header("X-API-Key", &caller),
                ),
                offset + 1,
                "",
            );
            answers.push(send(&app, req).await.0);

            let req = signed(
                peer(
                    Request::builder()
                        .uri("/api/audit-logs")
                        .header("X-API-Key", &caller),
                ),
                offset + 2,
                "",
            );
            answers.push(send(&app, req).await.0);

            let req = signed(
                peer(
                    Request::builder()
                        .method("DELETE")
                        .uri(format!("/api/groups/{target}"))
                        .header("X-API-Key", &caller),
                ),
                offset + 3,
                "",
            );
            answers.push(send(&app, req).await.0);
            answers
        }
    };

    let a = probe(royal, 10).await;
    let b = probe(commoner, 20).await;
    let c = probe(orphan, 30).await;
    assert_eq!(a, b, "descent from the master must change nothing");
    assert_eq!(a, c, "having a parent at all must change nothing");
    assert!(
        a.iter().all(|s| *s == StatusCode::FORBIDDEN),
        "and the shared answer must be refusal, not three matching successes: {a:?}"
    );
}

// ─────────────────────────────────────────────────────────────
// R4 — Only Master creates parents
// ─────────────────────────────────────────────────────────────

/// **R4.** "Only the Master key may grant `can_manage_keys` or resource-creation rights. A parent key
/// can never mint another parent key."
///
/// This service has two resource-creation rights where the specification names one:
/// `can_create_groups` (managed resources) and `can_manage_webhooks` (dispatch targets, this
/// service's spelling of `can_create_webhooks`). Both are covered, on both the create and update
/// paths.
#[tokio::test]
async fn r4_only_master_grants_global_scopes() {
    let (db, app) = setup().await;
    let (_master_id, master) = key(&db, "Master", true, ALL_ADMIN_SCOPES).await;
    let (parent_id, parent) = key(&db, "Parent", false, ALL_ADMIN_SCOPES).await;
    let (victim_id, _v) = key(&db, "Victim", false, NO_ADMIN_SCOPES).await;
    set_parent(&db, victim_id, Some(parent_id)).await;

    for (n, scope) in [
        "can_manage_keys",
        "can_create_groups",
        "can_manage_webhooks",
    ]
    .into_iter()
    .enumerate()
    {
        let n = i64::try_from(n).unwrap() * 10;

        // Create path.
        let req = signed(
            peer(
                Request::builder()
                    .method("POST")
                    .uri("/api/keys")
                    .header("X-API-Key", &parent)
                    .header("Content-Type", "application/json"),
            ),
            n + 1,
            json!({ "name": format!("minted-{scope}"), scope: true }).to_string(),
        );
        assert_eq!(
            send(&app, req).await.0,
            StatusCode::FORBIDDEN,
            "a parent must not mint a key holding '{scope}' — even one it holds itself"
        );

        // Update path.
        let req = signed(
            peer(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/keys/{victim_id}"))
                    .header("X-API-Key", &parent)
                    .header("Content-Type", "application/json"),
            ),
            n + 2,
            json!({ scope: true }).to_string(),
        );
        assert_eq!(
            send(&app, req).await.0,
            StatusCode::FORBIDDEN,
            "nor elevate an existing key into '{scope}'"
        );

        // The master may.
        let req = signed(
            peer(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/keys/{victim_id}"))
                    .header("X-API-Key", &master)
                    .header("Content-Type", "application/json"),
            ),
            n + 3,
            json!({ scope: true }).to_string(),
        );
        assert_eq!(
            send(&app, req).await.0,
            StatusCode::OK,
            "the master grants '{scope}'"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// R5 — Manage may propagate sideways
// ─────────────────────────────────────────────────────────────

/// **R5.** "A parent holding manage rights on a resource may grant manage rights on that resource to
/// another existing parent key (bounded by R1 and R2), but this can never elevate a daughter key to
/// parent status."
///
/// Both halves. The second is what makes the first safe: `can_manage` handed to a key without
/// `can_manage_keys` confers nothing, because R2 needs both — so the flag can travel sideways between
/// parents without ever creating one.
#[tokio::test]
async fn r5_manage_propagates_sideways_without_creating_parents() {
    let (db, app) = setup().await;
    let g = group(&db, "r5-group", None).await;

    let (alice_id, alice) = key(&db, "Parent A", false, KEYS_SCOPE).await;
    grant(&db, alice_id, g, GROUP_READ_WRITE_DELETE, true).await;
    let (bob_id, bob) = key(&db, "Parent B", false, KEYS_SCOPE).await;
    grant(&db, bob_id, g, GROUP_READ_WRITE, false).await;
    let (daughter_id, daughter) = key(&db, "Daughter", false, NO_ADMIN_SCOPES).await;

    // Sideways: Alice confers `can_manage` on Bob, who is already a parent.
    let req = signed(
        peer(
            Request::builder()
                .method("POST")
                .uri(format!("/api/keys/{bob_id}/permissions"))
                .header("X-API-Key", &alice)
                .header("Content-Type", "application/json"),
        ),
        1,
        perm_body("r5-group", GROUP_READ_WRITE, true),
    );
    assert_eq!(
        send(&app, req).await.0,
        StatusCode::OK,
        "manage may propagate sideways"
    );

    // ...and Bob can now actually use it.
    let (victim_id, _v) = key(&db, "Victim", false, NO_ADMIN_SCOPES).await;
    let req = signed(
        peer(
            Request::builder()
                .method("POST")
                .uri(format!("/api/keys/{victim_id}/permissions"))
                .header("X-API-Key", &bob)
                .header("Content-Type", "application/json"),
        ),
        2,
        perm_body("r5-group", GROUP_READ, false),
    );
    assert_eq!(
        send(&app, req).await.0,
        StatusCode::OK,
        "the conferred flag is real"
    );

    // Downward: the same grant to a key with no `can_manage_keys` confers nothing usable.
    let req = signed(
        peer(
            Request::builder()
                .method("POST")
                .uri(format!("/api/keys/{daughter_id}/permissions"))
                .header("X-API-Key", &alice)
                .header("Content-Type", "application/json"),
        ),
        3,
        perm_body("r5-group", GROUP_READ_WRITE, true),
    );
    assert_eq!(
        send(&app, req).await.0,
        StatusCode::OK,
        "the row is written"
    );

    let req = signed(
        peer(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/keys/{victim_id}/permissions/r5-group"))
                .header("X-API-Key", &daughter),
        ),
        4,
        "",
    );
    assert_eq!(
        send(&app, req).await.0,
        StatusCode::FORBIDDEN,
        "a daughter holding can_manage is still not a parent — R2 needs both halves"
    );
}

// ─────────────────────────────────────────────────────────────
// R6 — Revocation is never escalation
// ─────────────────────────────────────────────────────────────

/// **R6.** "Removing a permission requires manage rights on the resource only; the revoker need not
/// hold the verb being removed, and may revoke its own permissions. Reducing an existing permission
/// row through a general update endpoint is classified as revocation under this rule, regardless of
/// which endpoint it arrives at."
///
/// Three clauses, three assertions. The last one uses the shape that distinguishes it: a reduction
/// that *leaves* a verb the caller does not hold. Every other reduction is also within the caller's
/// own verbs, so routing one through the grant path by mistake would give the same answer and no test
/// would notice.
#[tokio::test]
async fn r6_revocation_needs_no_verb_and_permits_self_revocation() {
    let (db, app) = setup().await;
    let g = group(&db, "r6-group", None).await;

    let (mgr_id, mgr) = key(&db, "Read-only manager", false, KEYS_SCOPE).await;
    grant(&db, mgr_id, g, GROUP_READ, true).await;
    let (worker_id, _w) = key(&db, "Worker", false, NO_ADMIN_SCOPES).await;
    grant(&db, worker_id, g, GROUP_READ_WRITE_DELETE, false).await;

    // 1. Removes verbs it does not hold, through the dedicated route.
    let req = signed(
        peer(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/keys/{worker_id}/permissions/r6-group"))
                .header("X-API-Key", &mgr),
        ),
        1,
        "",
    );
    assert_eq!(
        send(&app, req).await.0,
        StatusCode::NO_CONTENT,
        "the revoker need not hold the verbs it removes"
    );

    // 2. Endpoint parity, in the shape that distinguishes it.
    grant(&db, worker_id, g, GROUP_READ_WRITE_DELETE, false).await;
    let req = signed(
        peer(
            Request::builder()
                .method("POST")
                .uri(format!("/api/keys/{worker_id}/permissions"))
                .header("X-API-Key", &mgr)
                .header("Content-Type", "application/json"),
        ),
        2,
        // Drops `can_delete`, keeps `can_write` — which the manager does not hold. It adds no verb,
        // so it is a revocation; on the grant path the surviving `can_write` would trip R1's ceiling.
        perm_body("r6-group", GROUP_READ_WRITE, false),
    );
    assert_eq!(
        send(&app, req).await.0,
        StatusCode::OK,
        "a reduction through the general endpoint is a revocation regardless of which endpoint it arrives at"
    );
    let row = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .filter(simply_ip_vault::entities::api_key_group_permission::Column::ApiKeyId.eq(worker_id))
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert!(
        row.can_read && row.can_write && !row.can_delete,
        "only the dropped verb changed"
    );

    // 3. Self-revocation.
    let req = signed(
        peer(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/keys/{mgr_id}/permissions/r6-group"))
                .header("X-API-Key", &mgr),
        ),
        3,
        "",
    );
    assert_eq!(
        send(&app, req).await.0,
        StatusCode::NO_CONTENT,
        "a manager may revoke itself"
    );
}

// ─────────────────────────────────────────────────────────────
// R7 — Granting is bounded by R1 and R2 together
// ─────────────────────────────────────────────────────────────

/// **R7.** "Granting is bounded by R1 and R2 together, simultaneously and without exception."
///
/// R1 and R2 each have their own test above. R7 is the claim that neither can be satisfied *instead*
/// of the other, so this asserts the composition: a caller that passes R1 but fails R2 is refused, a
/// caller that passes R2 but fails R1 is refused, and only satisfying both succeeds.
#[tokio::test]
async fn r7_granting_requires_r1_and_r2_simultaneously() {
    let (db, app) = setup().await;
    let g = group(&db, "r7-group", None).await;
    let (victim_id, _v) = key(&db, "Victim", false, NO_ADMIN_SCOPES).await;

    // Passes R1 (holds every verb it tries to confer), fails R2 (no `can_manage` row).
    let (r1_only_id, r1_only) = key(&db, "R1 only", false, KEYS_SCOPE).await;
    grant(&db, r1_only_id, g, GROUP_READ_WRITE_DELETE, false).await;

    // Passes R2 (both halves), fails R1 (does not hold `can_write`).
    let (r2_only_id, r2_only) = key(&db, "R2 only", false, KEYS_SCOPE).await;
    grant(&db, r2_only_id, g, GROUP_READ, true).await;

    // Passes both.
    let (both_id, both) = key(&db, "Both", false, KEYS_SCOPE).await;
    grant(&db, both_id, g, GROUP_READ_WRITE_DELETE, true).await;

    let attempt = |caller: String, offset| {
        let app = app.clone();
        async move {
            let req = signed(
                peer(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/api/keys/{victim_id}/permissions"))
                        .header("X-API-Key", &caller)
                        .header("Content-Type", "application/json"),
                ),
                offset,
                perm_body("r7-group", GROUP_READ_WRITE, false),
            );
            send(&app, req).await.0
        }
    };

    assert_eq!(
        attempt(r1_only, 1).await,
        StatusCode::FORBIDDEN,
        "R1 without R2 is not enough"
    );
    assert_eq!(
        attempt(r2_only, 2).await,
        StatusCode::FORBIDDEN,
        "R2 without R1 is not enough"
    );
    assert_eq!(attempt(both, 3).await, StatusCode::OK, "both together");
}

// ─────────────────────────────────────────────────────────────
// §3 — Resource lifecycle & ownership
// ─────────────────────────────────────────────────────────────

/// **§3.** "Resource lifecycle actions — deleting or renaming the entity itself — are restricted
/// exclusively to Master and the designated `owner_key_id`. Holding manage rights or any operational
/// verb confers no lifecycle authority: a parent that merely uses a resource must not be able to
/// delete it." And: "Master may reassign `owner_key_id` on any resource or dispatch target at any
/// time."
///
/// The refused caller is the most privileged non-owner the model allows: `can_manage_keys` globally
/// and every verb including `can_manage` on the group itself.
#[tokio::test]
async fn s3_lifecycle_authority_belongs_to_master_and_owner_only() {
    let (db, app) = setup().await;
    let (_master_id, master) = key(&db, "Master", true, ALL_ADMIN_SCOPES).await;
    let (owner_id, owner) = key(&db, "Owner", false, NO_ADMIN_SCOPES).await;
    let (privileged_id, privileged) = key(&db, "Privileged non-owner", false, KEYS_SCOPE).await;

    let g = group(&db, "s3-group", Some(owner_id)).await;
    grant(&db, privileged_id, g, GROUP_READ_WRITE_DELETE, true).await;

    let delete_as = |caller: String, offset| {
        let app = app.clone();
        async move {
            let req = signed(
                peer(
                    Request::builder()
                        .method("DELETE")
                        .uri(format!("/api/groups/{g}"))
                        .header("X-API-Key", &caller),
                ),
                offset,
                "",
            );
            send(&app, req).await.0
        }
    };

    assert_eq!(
        delete_as(privileged, 1).await,
        StatusCode::FORBIDDEN,
        "every verb on a group confers no authority over the group itself"
    );
    assert!(
        simply_ip_vault::entities::prelude::IpGroup::find_by_id(g)
            .one(&db)
            .await
            .unwrap()
            .is_some(),
        "the refusal blocked the delete rather than reporting one"
    );

    // Master reassigns, and the authority moves with the ownership.
    let (new_owner_id, _n) = key(&db, "New owner", false, NO_ADMIN_SCOPES).await;
    let req = signed(
        peer(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/groups/{g}/owner"))
                .header("X-API-Key", &master)
                .header("Content-Type", "application/json"),
        ),
        2,
        json!({ "owner_key_id": new_owner_id.to_string() }).to_string(),
    );
    assert_eq!(
        send(&app, req).await.0,
        StatusCode::OK,
        "a master may reassign ownership"
    );

    assert_eq!(
        delete_as(owner, 3).await,
        StatusCode::FORBIDDEN,
        "the previous owner lost lifecycle authority with the reassignment"
    );
    assert_eq!(
        delete_as(master, 4).await,
        StatusCode::NO_CONTENT,
        "and a master may always delete"
    );
}

// ─────────────────────────────────────────────────────────────
// §4 — Visibility & oracle discipline
// ─────────────────────────────────────────────────────────────

/// **§4, visibility.** Own subtree in full; a key sharing a managed resource in minimal form only;
/// nothing else at all. "A single shared resource must never become a keyhole into another parent's
/// whole configuration."
#[tokio::test]
async fn s4_visibility_scopes_bound_what_a_key_listing_returns() {
    let (db, app) = setup().await;
    let (caller_id, caller) = key(&db, "Caller", false, KEYS_SCOPE).await;
    let (daughter_id, _d) = key(&db, "Daughter", false, NO_ADMIN_SCOPES).await;
    set_parent(&db, daughter_id, Some(caller_id)).await;

    let shared = group(&db, "s4-shared", None).await;
    grant(&db, caller_id, shared, GROUP_READ_WRITE_DELETE, true).await;

    let (peer_id, _p) = key(&db, "Other tenant", false, ALL_ADMIN_SCOPES).await;
    let private = group(&db, "s4-private", None).await;
    grant(&db, peer_id, shared, GROUP_READ, false).await;
    grant(&db, peer_id, private, GROUP_READ_WRITE_DELETE, true).await;

    let (stranger_id, _s) = key(&db, "Stranger", false, ALL_ADMIN_SCOPES).await;

    let req = signed(
        peer(
            Request::builder()
                .uri("/api/keys")
                .header("X-API-Key", &caller),
        ),
        1,
        "",
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(status, StatusCode::OK);
    let listing: Vec<serde_json::Value> = serde_json::from_str(&body).unwrap();
    let find = |id: Uuid| listing.iter().find(|k| k["id"] == id.to_string());

    assert!(
        find(stranger_id).is_none(),
        "an unrelated key must not appear"
    );
    assert_eq!(find(caller_id).unwrap()["view"], "full");
    assert_eq!(find(daughter_id).unwrap()["view"], "full");

    let shared_entry = find(peer_id).expect("a key sharing a managed group is listed");
    assert_eq!(shared_entry["view"], "minimal");
    for withheld in [
        "bound_ips",
        "is_master",
        "can_manage_keys",
        "can_manage_webhooks",
        "prefix",
    ] {
        assert!(
            shared_entry.get(withheld).is_none(),
            "§4: '{withheld}' must not leak through a shared resource"
        );
    }
    assert_eq!(
        shared_entry["group_permissions"].as_array().unwrap().len(),
        1,
        "only the shared group, not every membership"
    );
    assert!(
        !body.contains("s4-private"),
        "a shared resource must not become a keyhole into another parent's configuration"
    );
}

/// **§4, oracle discipline.** "Any key, resource, or dispatch target outside the caller's visibility
/// scope must return the identical status and body the service would return if that id did not
/// exist."
///
/// Status *and* body: a `404` whose body differs is still an oracle, just a quieter one.
#[tokio::test]
async fn s4_oracle_discipline_out_of_scope_is_indistinguishable_from_nonexistent() {
    let (db, app) = setup().await;
    let (master_id, _m) = key(&db, "Master", true, ALL_ADMIN_SCOPES).await;
    let (_caller_id, caller) = key(&db, "Caller", false, KEYS_AND_WEBHOOKS_SCOPE).await;
    let (stranger_id, _s) = key(&db, "Stranger", false, NO_ADMIN_SCOPES).await;
    let absent = Uuid::new_v4();

    let probe = |method: &'static str, path: String, offset: i64| {
        let (app, caller) = (app.clone(), caller.clone());
        async move {
            let req = signed(
                peer(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("X-API-Key", &caller),
                ),
                offset,
                "",
            );
            send(&app, req).await
        }
    };

    for (n, (method, suffix)) in [
        ("DELETE", ""),
        ("POST", "/rotate"),
        ("POST", "/rotate-secret"),
    ]
    .into_iter()
    .enumerate()
    {
        let n = i64::try_from(n).unwrap() * 10;
        let missing = probe(method, format!("/api/keys/{absent}{suffix}"), n + 1).await;
        let invisible = probe(method, format!("/api/keys/{stranger_id}{suffix}"), n + 2).await;
        let master_probe = probe(method, format!("/api/keys/{master_id}{suffix}"), n + 3).await;

        assert_eq!(missing.0, StatusCode::NOT_FOUND);
        assert_eq!(
            invisible, missing,
            "{method}{suffix}: invisible must match nonexistent"
        );
        assert_eq!(
            master_probe, missing,
            "{method}{suffix}: the master must not be enumerable"
        );
    }
}

/// **§4, the counterpart control.** Oracle discipline "is a distinct control from the
/// authenticate-then-authorize ordering rule … Both hold simultaneously; neither may be satisfied by
/// regressing the other."
///
/// Making every refusal a `404` would satisfy oracle discipline and destroy this one: a CIDR
/// rejection would become "no such key", which is the inference the ordering rule exists to prevent.
#[tokio::test]
async fn s4_authenticate_then_authorize_ordering_survives_oracle_discipline() {
    let (db, app) = setup().await;
    let (bound_id, bound) = key(&db, "Bound", false, NO_ADMIN_SCOPES).await;
    let mut active: simply_ip_vault::entities::api_key::ActiveModel =
        simply_ip_vault::entities::prelude::ApiKey::find_by_id(bound_id)
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .into();
    active.bound_ips = Set(Some("203.0.113.0/24".to_owned()));
    active.update(&db).await.unwrap();

    // Unproven caller, real key: 401.
    let req = signed_as(
        peer(
            Request::builder()
                .uri("/api/auth/me")
                .header("X-API-Key", &bound),
        ),
        "wrong-secret",
        1,
        "",
    );
    assert_eq!(send(&app, req).await.0, StatusCode::UNAUTHORIZED);

    // Unproven caller, key that does not exist: the same 401, indistinguishable.
    let req = signed_as(
        peer(
            Request::builder()
                .uri("/api/auth/me")
                .header("X-API-Key", "0".repeat(64)),
        ),
        "wrong-secret",
        2,
        "",
    );
    assert_eq!(send(&app, req).await.0, StatusCode::UNAUTHORIZED);

    // Proven caller, wrong network: 403, **not** 404.
    let req = signed(
        peer(
            Request::builder()
                .uri("/api/auth/me")
                .header("X-API-Key", &bound),
        ),
        3,
        "",
    );
    assert_eq!(
        send(&app, req).await.0,
        StatusCode::FORBIDDEN,
        "collapsing this to 404 would regress the authenticate-then-authorize ordering"
    );
}

// ─────────────────────────────────────────────────────────────
// §5 — Master key guarantees
// ─────────────────────────────────────────────────────────────

/// **§5.** Exactly one Master, enforced by a database constraint; `is_master` unsettable through any
/// API payload; the Master immutable except its own `bound_ips`; the Master undeletable.
#[tokio::test]
async fn s5_master_is_unique_unsettable_immutable_and_undeletable() {
    let (db, app) = setup().await;
    let (master_id, master) = key(&db, "Master", true, ALL_ADMIN_SCOPES).await;

    // Uniqueness is a schema invariant, and §5 requires it be proven by an **adversarial write**:
    // a direct insert setting `is_master` with the marker absent. Raw SQL rather than an
    // `ActiveModel`, deliberately — an `ActiveModel` cannot name `master_marker` (the field is not on
    // the entity), so it would demonstrate the constraint only for writers that happen to be built
    // from our own entity definitions. The statement below is what an operator at a `psql` prompt, a
    // restored backup, or a future migration would issue, and it is the exact statement that was
    // **accepted** against the previous application-maintained marker.
    assert!(
        adversarial_master_insert(&db, "Usurper", "usurper1")
            .await
            .is_err(),
        "an insert setting is_master with master_marker absent must be refused by the engine; \
         accepting it is how this codebase came to hold two masters while every test passed"
    );

    // `is_master` is unsettable and unclearable, from every caller including the master.
    for value in [true, false] {
        let req = signed(
            peer(
                Request::builder()
                    .method("POST")
                    .uri("/api/keys")
                    .header("X-API-Key", &master)
                    .header("Content-Type", "application/json"),
            ),
            if value { 1 } else { 2 },
            json!({ "name": format!("carries-{value}"), "is_master": value }).to_string(),
        );
        assert_eq!(
            send(&app, req).await.0,
            StatusCode::BAD_REQUEST,
            "no payload may carry is_master ({value})"
        );
    }

    // `bound_ips` is the one editable field.
    let req = signed(
        peer(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/keys/{master_id}"))
                .header("X-API-Key", &master)
                .header("Content-Type", "application/json"),
        ),
        3,
        json!({ "bound_ips": "10.0.0.0/8" }).to_string(),
    );
    assert_eq!(
        send(&app, req).await.0,
        StatusCode::OK,
        "the master may edit its own bound_ips"
    );

    for (n, body) in [
        json!({ "name": "Renamed" }),
        json!({ "can_manage_keys": false }),
    ]
    .into_iter()
    .enumerate()
    {
        let req = signed(
            peer(
                Request::builder()
                    .method("PUT")
                    .uri(format!("/api/keys/{master_id}"))
                    .header("X-API-Key", &master)
                    .header("Content-Type", "application/json"),
            ),
            10 + i64::try_from(n).unwrap(),
            body.to_string(),
        );
        assert_eq!(
            send(&app, req).await.0,
            StatusCode::FORBIDDEN,
            "and nothing else"
        );
    }

    assert_master_cannot_be_rotated_or_deleted(&app, &db, master_id, &master).await;
}

async fn assert_master_cannot_be_rotated_or_deleted(
    app: &axum::Router,
    db: &DatabaseConnection,
    master_id: Uuid,
    master: &str,
) {
    // Rotation and deletion are outside the API surface entirely.
    for (n, path) in [
        format!("/api/keys/{master_id}/rotate"),
        format!("/api/keys/{master_id}/rotate-secret"),
    ]
    .into_iter()
    .enumerate()
    {
        let req = signed(
            peer(
                Request::builder()
                    .method("POST")
                    .uri(path)
                    .header("X-API-Key", master),
            ),
            20 + i64::try_from(n).unwrap(),
            "",
        );
        assert_eq!(send(app, req).await.0, StatusCode::FORBIDDEN);
    }

    let req = signed(
        peer(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/keys/{master_id}"))
                .header("X-API-Key", master),
        ),
        30,
        "",
    );
    assert_eq!(
        send(app, req).await.0,
        StatusCode::FORBIDDEN,
        "the master cannot be deleted"
    );
    assert!(
        simply_ip_vault::entities::prelude::ApiKey::find_by_id(master_id)
            .one(db)
            .await
            .unwrap()
            .is_some()
    );
}

/// **§5.** ADVERSARIAL(§5) — the marker column is unwritable by *any* client, not merely unwritten by
/// ours.
///
/// Distinct from the uniqueness assertion, and not implied by it. Uniqueness says two markers cannot
/// coexist; this says nobody chooses what the marker is. A schema could satisfy the first and fail
/// the second — that is exactly what `m20260807_000007` did — and the failure mode is silent, because
/// a writer that supplies the right value looks identical to one that cannot supply a wrong one.
///
/// Both write verbs are tried. `UPDATE` matters independently of `INSERT`: a generated column that
/// somehow accepted an update could be desynchronised from `is_master` *after* the row passed every
/// check, which is the one ordering no insert-time constraint can catch.
#[tokio::test]
async fn s5_the_derived_marker_is_unwritable_by_any_client() {
    use sea_orm::ConnectionTrait;

    let (db, _app) = setup().await;
    let (master_id, _master) = key(&db, "Master", true, ALL_ADMIN_SCOPES).await;

    let attempt = |sql: String| {
        let db = db.clone();
        async move {
            db.execute_raw(sea_orm::Statement::from_string(
                db.get_database_backend(),
                sql,
            ))
            .await
        }
    };

    // Setting the marker while claiming master status — the cooperative shape the old schema
    // *required*, and which must now be refused outright rather than honoured.
    let err = attempt(format!(
        "INSERT INTO api_keys (id, name, key_hash, prefix, is_master, master_marker, \
         can_manage_keys, can_manage_webhooks, can_create_groups, created_at, updated_at) \
         VALUES (x'{}', 'Forger', 'forged-hash', 'forger01', true, 1, true, true, true, \
          '2026-08-08 00:00:00', '2026-08-08 00:00:00')",
        Uuid::new_v4().simple()
    ))
    .await
    .expect_err("a generated column must refuse an INSERT that names it");
    assert!(
        format!("{err:?}").to_lowercase().contains("generated"),
        "the refusal must come from the column being generated, not from something incidental: \
         {err:?}"
    );

    // Clearing the marker on the sitting Master — the shape that would free the unique index for a
    // second master while leaving `is_master` true on both.
    attempt(format!(
        "UPDATE api_keys SET master_marker = NULL WHERE id = x'{}'",
        master_id.simple()
    ))
    .await
    .expect_err("a generated column must refuse an UPDATE that names it");

    // And the marker still says what `is_master` says.
    let rows = db
        .query_all_raw(sea_orm::Statement::from_string(
            db.get_database_backend(),
            "SELECT master_marker FROM api_keys WHERE is_master = true".to_owned(),
        ))
        .await
        .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].try_get::<Option<i32>>("", "master_marker").unwrap(),
        Some(1),
        "the marker must remain derived from is_master after both attempts"
    );
}

/// **§5.** ADVERSARIAL(§5) — `is_master` is refused by the payload **type**, not by a handler check.
///
/// §5: "Removing the field from the payload type is required; rejecting it at the handler is not
/// sufficient, since a later handler can reintroduce the path." A status assertion alone cannot tell
/// the two apart — both spell `400` — so this asserts on *where the refusal came from*: serde's own
/// ``unknown field `is_master` `` names the field it could not deserialize, which no handler-side
/// guard produces.
///
/// The second half is what keeps that assertion honest. An unrelated unknown field must be refused
/// the same way, proving the rejection is `deny_unknown_fields` covering the whole struct rather than
/// a special case for one name that a future edit could carve an exception into.
#[tokio::test]
async fn s5_is_master_is_refused_by_the_payload_type_not_by_a_handler() {
    let (db, app) = setup().await;
    let (_master_id, master) = key(&db, "Master", true, ALL_ADMIN_SCOPES).await;

    let mut nonce = 0i64;
    let mut post = |uri: &str, method: &str, body: String| {
        nonce += 1;
        signed(
            peer(
                Request::builder()
                    .method(method)
                    .uri(uri.to_owned())
                    .header("X-API-Key", &master)
                    .header("Content-Type", "application/json"),
            ),
            nonce,
            body,
        )
    };

    for (label, body) in [
        ("is_master true", json!({ "name": "n", "is_master": true })),
        (
            "is_master false",
            json!({ "name": "n", "is_master": false }),
        ),
        (
            "an unrelated unknown field",
            json!({ "name": "n", "can_do_anything": true }),
        ),
    ] {
        let (status, text) = send(&app, post("/api/keys", "POST", body.to_string())).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{label} must be refused");
        assert!(
            text.contains("unknown field"),
            "{label} must be refused by deserialization, not by a handler guard — a handler-side \
             check produces the same status and is one deleted line from not existing: {text}"
        );
    }

    // The update payload is the other half of "no key-creation or key-update payload may carry it",
    // and it is a separate struct with its own attribute.
    let (_daughter_id, _daughter) = key(&db, "Daughter", false, NO_ADMIN_SCOPES).await;
    let target = simply_ip_vault::entities::prelude::ApiKey::find()
        .filter(simply_ip_vault::entities::api_key::Column::Name.eq("Daughter"))
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    let (status, text) = send(
        &app,
        post(
            &format!("/api/keys/{}", target.id),
            "PUT",
            json!({ "is_master": true }).to_string(),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        text.contains("unknown field"),
        "the update payload must refuse it in the type too: {text}"
    );
}

/// **§5.** ADVERSARIAL(§5) — the Master's immutability holds **per row**, not because there happens to
/// be only one master.
///
/// §5: "The Master key cannot be deleted through the API, and that guarantee must not rest on the
/// uniqueness constraint holding." Those are two independent controls, and a suite that only ever
/// sees one master cannot tell whether the second one exists. If `guard_master_immutable` were ever
/// rewritten as "refuse when the target is *the* master" — a count, a lookup of "the" master row —
/// every existing test would still pass, and the guarantee would quietly become a corollary of the
/// constraint it is supposed to be independent of.
///
/// So this test removes the constraint at runtime and builds the state §5 says must never exist, in
/// order to prove the *other* guarantee survives it. Dropping the index is the point, not a shortcut.
#[tokio::test]
async fn s5_master_immutability_does_not_rest_on_the_uniqueness_constraint() {
    use sea_orm::ConnectionTrait;

    let (db, app) = setup().await;
    let (master_id, master) = key(&db, "Master", true, ALL_ADMIN_SCOPES).await;

    // One authenticated request *before* any tampering, which pins the master exactly as a real boot
    // would (`main.rs` pins before binding the listener). The ordering is not incidental to this
    // test — it is the threat model. An attacker edits a database that is already running, so the
    // pin is always established first; a test that tampered first would be checking a state
    // production cannot reach, and would silently pass for the wrong reason once the demotion in
    // `middleware.rs` started firing.
    let req = signed(
        peer(
            Request::builder()
                .uri("/api/auth/me")
                .header("X-API-Key", &master),
        ),
        0,
        "",
    );
    assert_eq!(
        send(&app, req).await.0,
        StatusCode::OK,
        "the master is master before tampering"
    );

    // Take the constraint away, then build the forbidden state underneath the application.
    db.execute_raw(sea_orm::Statement::from_string(
        db.get_database_backend(),
        "DROP INDEX \"idx-api_keys-master_marker\"".to_owned(),
    ))
    .await
    .unwrap();
    adversarial_master_insert(&db, "Second Master", "second01")
        .await
        .expect("without the unique index the second master is accepted — that is the premise");
    let second_id = simply_ip_vault::entities::prelude::ApiKey::find()
        .filter(simply_ip_vault::entities::api_key::Column::Name.eq("Second Master"))
        .one(&db)
        .await
        .unwrap()
        .unwrap()
        .id;

    // Every mutating operation §5 names, against *both* masters, from a master caller.
    let mut nonce = 0i64;
    for target in [master_id, second_id] {
        for (method, path, body) in [
            ("DELETE", format!("/api/keys/{target}"), String::new()),
            ("POST", format!("/api/keys/{target}/rotate"), String::new()),
            (
                "POST",
                format!("/api/keys/{target}/rotate-secret"),
                String::new(),
            ),
            (
                "PUT",
                format!("/api/keys/{target}"),
                json!({ "name": "Renamed" }).to_string(),
            ),
        ] {
            nonce += 1;
            let req = signed(
                peer(
                    Request::builder()
                        .method(method)
                        .uri(path.clone())
                        .header("X-API-Key", &master)
                        .header("Content-Type", "application/json"),
                ),
                nonce,
                body,
            );
            assert_eq!(
                send(&app, req).await.0,
                StatusCode::FORBIDDEN,
                "{method} {path} must be refused on the target's own is_master, with no regard for \
                 how many masters exist"
            );
        }
    }

    // Both rows survive: the refusals were refusals, not deletions that happened to error late.
    let masters = simply_ip_vault::entities::prelude::ApiKey::find()
        .filter(simply_ip_vault::entities::api_key::Column::IsMaster.eq(true))
        .all(&db)
        .await
        .unwrap();
    assert_eq!(
        masters.len(),
        2,
        "the test's own premise must still hold at the end"
    );
}

// ─────────────────────────────────────────────────────────────
// §6 — Cascade deletion & pre-flight inventory
// ─────────────────────────────────────────────────────────────

/// **§6.** The subtree cascade, the pre-flight inventory over the *whole* subtree, the refusal, the
/// complete-map requirement, and "data is never destroyed implicitly".
///
/// The owned resource sits two levels below the key being deleted, which is the case an
/// inventory that inspects only the target gets wrong.
#[tokio::test]
async fn s6_cascade_requires_a_complete_pre_flight_resolution_map() {
    let (db, app) = setup().await;
    let (_master_id, master) = key(&db, "Master", true, ALL_ADMIN_SCOPES).await;
    let (root_id, _r) = key(&db, "Root", false, KEYS_SCOPE).await;
    let (child_id, _c) = key(&db, "Child", false, NO_ADMIN_SCOPES).await;
    let (grandchild_id, _g) = key(&db, "Grandchild", false, NO_ADMIN_SCOPES).await;
    set_parent(&db, child_id, Some(root_id)).await;
    set_parent(&db, grandchild_id, Some(child_id)).await;

    let owned = group(&db, "s6-owned", Some(grandchild_id)).await;
    let (survivor_id, _s) = key(&db, "Survivor", false, NO_ADMIN_SCOPES).await;

    // 1. Unresolved inventory refuses, and the payload carries §6's four fields.
    let req = signed(
        peer(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/keys/{root_id}"))
                .header("X-API-Key", &master),
        ),
        1,
        "",
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "an unresolved inventory refuses"
    );
    let payload: serde_json::Value = serde_json::from_str(&body).unwrap();
    let entities = payload["owned_entities"].as_array().unwrap();
    assert_eq!(
        entities.len(),
        1,
        "the inventory walks the whole subtree: {body}"
    );
    for field in ["entity_type", "id", "name", "owner_key_id"] {
        assert!(entities[0].get(field).is_some(), "§6 requires '{field}'");
    }
    assert_eq!(
        entities[0]["owner_key_id"],
        grandchild_id.to_string(),
        "two levels down"
    );

    // 2. Nothing happened.
    for id in [root_id, child_id, grandchild_id] {
        assert!(
            simply_ip_vault::entities::prelude::ApiKey::find_by_id(id)
                .one(&db)
                .await
                .unwrap()
                .is_some()
        );
    }

    // 3. A complete map executes; `reassign` moves rather than destroys; the subtree cascades.
    let req = signed(
        peer(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/keys/{root_id}"))
                .header("X-API-Key", &master)
                .header("Content-Type", "application/json"),
        ),
        2,
        json!({
            "resolutions": [{
                "entity_type": "group",
                "id": owned.to_string(),
                "action": "reassign",
                "owner_key_id": survivor_id.to_string()
            }]
        })
        .to_string(),
    );
    assert_eq!(send(&app, req).await.0, StatusCode::NO_CONTENT);

    for (id, label) in [
        (root_id, "root"),
        (child_id, "child"),
        (grandchild_id, "grandchild"),
    ] {
        assert!(
            simply_ip_vault::entities::prelude::ApiKey::find_by_id(id)
                .one(&db)
                .await
                .unwrap()
                .is_none(),
            "the {label} key must have cascaded"
        );
    }
    let surviving = simply_ip_vault::entities::prelude::IpGroup::find_by_id(owned)
        .one(&db)
        .await
        .unwrap()
        .expect("data is never destroyed implicitly");
    assert_eq!(
        surviving.owner_key_id,
        Some(survivor_id),
        "reassign moved it"
    );
}

// ─────────────────────────────────────────────────────────────
// §7 — Database constraints & indexing
// ─────────────────────────────────────────────────────────────

/// **§7.** ADVERSARIAL(§7) — "A database-level constraint guaranteeing Master uniqueness, per §5.
/// Indexes on `parent_key_id`, `owner_key_id`, the key-hash lookup column, and the permission-table
/// join columns — every column the authenticated hot paths search on."
///
/// Asserted against the live schema rather than against the migration source: a migration that was
/// edited after being applied, or one whose `create_index` silently no-ops, would still read
/// correctly in the file. `sqlite_master` is queried directly, which makes this test SQLite-specific
/// — and SQLite is the backend every test in this repository runs on, so a §7 regression would show
/// up here first regardless.
#[tokio::test]
async fn s7_the_schema_carries_the_required_constraints_and_indexes() {
    use sea_orm::ConnectionTrait;

    let (db, _app) = setup().await;

    let rows = db
        .query_all_raw(sea_orm::Statement::from_string(
            db.get_database_backend(),
            "SELECT name, sql FROM sqlite_master WHERE type = 'index'".to_owned(),
        ))
        .await
        .unwrap();
    let indexes: Vec<(String, String)> = rows
        .iter()
        .map(|r| {
            (
                r.try_get::<String>("", "name").unwrap_or_default(),
                r.try_get::<Option<String>>("", "sql")
                    .unwrap_or_default()
                    .unwrap_or_default(),
            )
        })
        .collect();
    let named = |needle: &str| indexes.iter().any(|(n, _)| n == needle);

    for required in [
        "idx-api_keys-parent_key_id",
        "idx-ip_groups-owner_key_id",
        "idx-webhook_configs-owner_key_id",
        "idx-akgp-group_id",
        "idx-akgp-api_key_id-group_id",
    ] {
        assert!(
            named(required),
            "§7 requires an index named '{required}': {indexes:?}"
        );
    }

    // The key-hash lookup column and the master-uniqueness constraint are both backed by *unique*
    // indexes, which SQLite may name automatically when they come from a column constraint — so these
    // two are asserted by the column they cover rather than by name.
    let unique_over = |column: &str| {
        indexes.iter().any(|(name, sql)| {
            (sql.to_lowercase().contains("unique") && sql.contains(column))
                || (sql.is_empty() && name.contains("autoindex"))
        })
    };
    assert!(
        unique_over("key_hash") || named("idx-api_keys-key_hash"),
        "§7 requires the key-hash lookup column to be indexed: {indexes:?}"
    );
    assert!(
        unique_over("master_marker"),
        "§5/§7 require a database-level constraint guaranteeing master uniqueness: {indexes:?}"
    );

    // The marker must be *engine-derived*, asserted against the table's own DDL. This is the
    // assertion whose absence let a bypassable constraint pass for six phases: every check above is
    // satisfied by a plain nullable column under a unique index, which is exactly what was there.
    let table = db
        .query_all_raw(sea_orm::Statement::from_string(
            db.get_database_backend(),
            "SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'api_keys'".to_owned(),
        ))
        .await
        .unwrap();
    let ddl = table[0].try_get::<String>("", "sql").unwrap();
    assert!(
        ddl.contains("GENERATED ALWAYS AS") && ddl.contains("master_marker"),
        "§5 requires the marker be derived by the engine from is_master, not maintained by the \
         application — an assignable marker can be left NULL, and NULLs do not collide: {ddl}"
    );

    // And the constraint actually bites, against an **adversarial** writer — an index that exists but
    // is not unique would satisfy every name check above, and a marker the writer supplies would
    // satisfy even a behavioural check while leaving the bypass wide open.
    let (_id, _plain) = key(&db, "First master", true, ALL_ADMIN_SCOPES).await;
    assert!(
        adversarial_master_insert(&db, "Second master", "second01")
            .await
            .is_err(),
        "the uniqueness constraint must refuse a second master written directly at the table"
    );
}

/// **§7.** ADVERSARIAL(§7) — where the engine cannot express a constraint in DDL, the application's
/// substitute is real, and the invariant it stands in for actually holds in the data.
///
/// §7: "Where a target engine cannot express a constraint in DDL (for example SQLite's lack of
/// `ALTER TABLE ADD CONSTRAINT` for foreign keys), the application-level equivalent must be covered by
/// a test that runs in CI. A constraint that holds only in production is one CI never checks."
///
/// `parent_key_id` and both `owner_key_id` columns were added by `ALTER TABLE` and therefore carry no
/// foreign key on SQLite. Every reference they hold is kept honest by handler code, which is the
/// arrangement most likely to be quietly correct in review and quietly wrong at runtime — nothing
/// fails loudly when it drifts, the rows simply start pointing at keys that are gone.
///
/// Three claims, in the order they can fail:
///
/// 1. **The premise.** There is genuinely no DDL foreign key here. If one appeared, the rest of this
///    test would be asserting against belt *and* braces while claiming to test the belt.
/// 2. **The write path refuses a dangling reference** — asserted through the API, since that is the
///    only writer that is supposed to check.
/// 3. **The data has no orphans after a cascade**, asserted by anti-join in raw SQL rather than by
///    re-reading through the entities. An ORM query that joins on the reference cannot see a row
///    whose reference is broken; only asking the table directly can.
#[tokio::test]
async fn s7_referential_integrity_holds_where_ddl_cannot_express_it() {
    use sea_orm::ConnectionTrait;

    let (db, app) = setup().await;
    let (_master_id, master) = key(&db, "Master", true, ALL_ADMIN_SCOPES).await;

    // 1. The premise: these columns really are unconstrained at the schema level.
    for table in ["api_keys", "ip_groups", "webhook_configs"] {
        let fks = db
            .query_all_raw(sea_orm::Statement::from_string(
                db.get_database_backend(),
                format!("PRAGMA foreign_key_list('{table}')"),
            ))
            .await
            .unwrap();
        let referencing: Vec<String> = fks
            .iter()
            .filter_map(|r| r.try_get::<String>("", "from").ok())
            .filter(|c| c == "parent_key_id" || c == "owner_key_id")
            .collect();
        assert!(
            referencing.is_empty(),
            "{table} gained a DDL foreign key on {referencing:?} — good, but this test and the \
             application-side checks it covers now need revisiting rather than silently duplicating it"
        );
    }

    // 2. The write path refuses a reference to a key that does not exist. This is the substitute for
    // the missing `REFERENCES api_keys(id)`, so it is the thing under test.
    let orphan_group = group(&db, "s7-group", None).await;
    let ghost = Uuid::new_v4();
    let req = signed(
        peer(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/groups/{orphan_group}/owner"))
                .header("X-API-Key", &master)
                .header("Content-Type", "application/json"),
        ),
        1,
        json!({ "owner_key_id": ghost.to_string() }).to_string(),
    );
    let (status, body) = send(&app, req).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "assigning ownership to a nonexistent key must be refused by the application, because the \
         schema will not: {body}"
    );

    // 3. No orphans after a real cascade. The subtree is built with lineage, given an owned resource,
    // and deleted with a complete resolution map — the path that rewrites the most references at once.
    let (root_id, _r) = key(&db, "s7-root", false, KEYS_SCOPE).await;
    let (child_id, _c) = key(&db, "s7-child", false, NO_ADMIN_SCOPES).await;
    set_parent(&db, child_id, Some(root_id)).await;
    let owned = group(&db, "s7-owned", Some(child_id)).await;

    let req = signed(
        peer(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/keys/{root_id}"))
                .header("X-API-Key", &master)
                .header("Content-Type", "application/json"),
        ),
        2,
        json!({
            "resolutions": [{
                "entity_type": "group",
                "id": owned.to_string(),
                "action": "delete"
            }]
        })
        .to_string(),
    );
    assert_eq!(send(&app, req).await.0, StatusCode::NO_CONTENT);

    // The anti-joins. `IS NOT NULL` matters: a NULL reference is "unowned", which is a legitimate
    // state, not a dangling pointer.
    for (table, column) in [
        ("api_keys", "parent_key_id"),
        ("ip_groups", "owner_key_id"),
        ("webhook_configs", "owner_key_id"),
    ] {
        let orphans = db
            .query_all_raw(sea_orm::Statement::from_string(
                db.get_database_backend(),
                format!(
                    "SELECT t.id FROM {table} t LEFT JOIN api_keys k ON t.{column} = k.id \
                     WHERE t.{column} IS NOT NULL AND k.id IS NULL"
                ),
            ))
            .await
            .unwrap();
        assert!(
            orphans.is_empty(),
            "{table}.{column} has {} row(s) referencing a key that no longer exists; with no DDL \
             foreign key, nothing else would have noticed",
            orphans.len()
        );
    }
}
