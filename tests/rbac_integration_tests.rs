use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, ColumnTrait, Database, DatabaseConnection, EntityTrait, QueryFilter};
use sea_orm_migration::MigratorTrait;
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

use simply_ip_vault::{create_app, migration, state::AppState};

async fn setup_test_db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migration::Migrator::up(&db, None).await.unwrap();
    db
}

fn inject_connect_info(req: axum::http::request::Builder) -> axum::http::request::Builder {
    req.extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 8080))))
}

/// Builds an `AppState` that trusts `127.0.0.1` — the peer address [`inject_connect_info`]
/// simulates — as a reverse proxy, so `X-Forwarded-For` and `X-Real-IP` are honoured.
///
/// Needed by every test that uses a forwarding header to stand in for a client address. Since
/// `TRUSTED_PROXIES` is now empty by default, `AppState::new` ignores those headers entirely, and a
/// test written against the old always-trusting behaviour would silently start asserting the peer
/// address instead of the forwarded one. Tests of the *spoofing* case deliberately do **not** use
/// this — see `test_spoofed_forwarded_for_from_an_untrusted_peer_cannot_bypass_bound_ips`.
fn proxied_state(
    db: &DatabaseConnection,
    webhook_tx: tokio::sync::mpsc::Sender<simply_ip_vault::state::WebhookEvent>,
) -> AppState {
    AppState::with_trusted_proxies(
        db.clone(),
        webhook_tx,
        simply_ip_vault::config::parse_trusted_proxies("127.0.0.1")
            .expect("the loopback literal is a valid entry"),
    )
}

// ─────────────────────────────────────────────────────────────
// HMAC request signing helpers
//
// Every `/api/*` request now needs `X-Timestamp` and an `X-Signature-256` over
// `METHOD + PATH + TIMESTAMP + RAW_BODY`. Rather than thread a second credential through each of
// the ~100 request-building sites below, keys seeded directly into the database follow a fixed
// convention (see `test_signing_secret`) that lets `signed()` recover the right secret from the
// request's own `X-API-Key` header.
// ─────────────────────────────────────────────────────────────

/// Test-only convention: a database-seeded key's signing secret is derived from its plaintext API
/// key, so [`signed`] can rediscover it from the `X-API-Key` header alone.
///
/// Only valid for keys inserted by these tests. Keys minted through `POST /api/keys` (or rotated via
/// `POST /api/keys/{id}/rotate`) get a server-generated random secret returned in the response body,
/// and must be signed with [`signed_with`] instead.
fn test_signing_secret(api_key: &str) -> String {
    format!("signing-secret-for-{api_key}")
}

/// The same secret in the shape the database actually stores.
///
/// `SecretCipher::open` is strictly fail-closed as of the 2026-08-02 hardening pass: a stored value
/// with no recognized prefix is a `MalformedCiphertext` error rather than a bare secret returned
/// verbatim. Seeded rows must therefore carry a real storage prefix, exactly as `SecretCipher::seal`
/// would have written it in the zero-config plaintext mode these suites run in.
fn stored_signing_secret(api_key: &str) -> String {
    format!("v1.plain.{}", hex::encode(test_signing_secret(api_key)))
}

/// Builds a signed request, deriving the signing secret from the builder's own `X-API-Key` header.
///
/// A builder carrying no `X-API-Key` still gets an `X-Timestamp` but no signature — exactly what the
/// "missing key is rejected" cases need, since they must fail on authentication rather than on a
/// missing timestamp.
fn signed(builder: axum::http::request::Builder, body: impl Into<String>) -> Request<Body> {
    let derived = builder
        .headers_ref()
        .and_then(|h| h.get("X-API-Key"))
        .and_then(|v| v.to_str().ok())
        .map(test_signing_secret);
    build_signed(builder, derived.as_deref(), body.into())
}

/// Like [`signed`], but stamped `offset_secs` into the future.
///
/// Exists because of the anti-replay guard. A signature covers method, target, timestamp and body —
/// and nothing else — so **repeating a call unchanged within the same wall-clock second produces the
/// identical signature, which is by definition a replay** and is now refused with `401`. Real
/// clients never trip this: a retry, a poll, or a second ban of the same address lands on a later
/// timestamp because time has actually passed. An in-process test issues both halves microseconds
/// apart, so the elapsed second has to be stated rather than waited for.
///
/// Using this is therefore not a workaround for the guard — it is how a test models the passage of
/// time that a real caller gets for free. `offset_secs` stays far inside the ±300s window, so the
/// freshness check is unaffected and the request is exactly as valid as a genuine later one.
fn signed_later(
    builder: axum::http::request::Builder,
    offset_secs: i64,
    body: impl Into<String>,
) -> Request<Body> {
    let derived = builder
        .headers_ref()
        .and_then(|h| h.get("X-API-Key"))
        .and_then(|v| v.to_str().ok())
        .map(test_signing_secret);
    let timestamp = (chrono::Utc::now().timestamp() + offset_secs).to_string();
    build_signed_at(builder, derived.as_deref(), timestamp, body.into())
}

/// Builds a signed request using an explicitly supplied signing secret, for keys whose secret was
/// generated server-side and read back out of a `POST /api/keys` or `/rotate` response.
fn signed_with(
    builder: axum::http::request::Builder,
    signing_secret: &str,
    body: impl Into<String>,
) -> Request<Body> {
    build_signed(builder, Some(signing_secret), body.into())
}

/// [`signed_with`] plus [`signed_later`]'s explicit clock offset — for a server-minted key that also
/// needs to issue several requests inside one wall-clock second without tripping the replay guard.
fn signed_later_with(
    builder: axum::http::request::Builder,
    signing_secret: &str,
    offset_secs: i64,
    body: impl Into<String>,
) -> Request<Body> {
    let timestamp = (chrono::Utc::now().timestamp() + offset_secs).to_string();
    build_signed_at(builder, Some(signing_secret), timestamp, body.into())
}

/// Builds a request signed at an explicit `X-Timestamp`, for exercising the anti-replay window.
///
/// The signature is computed over the same (possibly stale) timestamp that is sent, so these
/// requests are cryptographically valid and can only be rejected by the freshness check itself —
/// which is precisely what makes them a test of the anti-replay guard rather than of the HMAC.
fn signed_at(
    builder: axum::http::request::Builder,
    signing_secret: &str,
    timestamp: i64,
    body: impl Into<String>,
) -> Request<Body> {
    build_signed_at(builder, Some(signing_secret), timestamp.to_string(), body.into())
}

/// Attaches `X-Timestamp` (and, when a secret is available, `X-Signature-256`) and finishes the
/// request. The timestamp is always "now", so these requests sit comfortably inside the server's
/// 300-second anti-replay window.
fn build_signed(
    builder: axum::http::request::Builder,
    signing_secret: Option<&str>,
    body: String,
) -> Request<Body> {
    let timestamp = chrono::Utc::now().timestamp().to_string();
    build_signed_at(builder, signing_secret, timestamp, body)
}

/// Shared implementation behind [`build_signed`] and [`signed_at`].
fn build_signed_at(
    builder: axum::http::request::Builder,
    signing_secret: Option<&str>,
    timestamp: String,
    body: String,
) -> Request<Body> {
    // Read method and target back off the builder so the signature always matches what is actually
    // sent. The **full target** is signed, query string included, mirroring
    // `crypto::verify_signature` — a helper that stripped the query would make every
    // query-tampering test pass for the wrong reason.
    let method = builder
        .method_ref()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| "GET".to_owned());
    let target = builder
        .uri_ref()
        .map(|u| {
            u.path_and_query()
                .map(|pq| pq.as_str().to_owned())
                .unwrap_or_else(|| u.path().to_owned())
        })
        .unwrap_or_else(|| "/".to_owned());

    let mut builder = builder.header("X-Timestamp", &timestamp);
    if let Some(secret) = signing_secret {
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

/// `ALLOW_PRIVATE_WEBHOOKS` and `VAULT_ENCRYPTION_KEY` are process-wide global state. Any test that
/// mutates it must hold this lock for the duration, so two such tests running on different libtest
/// threads can never interleave their `set_var` calls (which is itself a data race, hence why
/// `set_var` is `unsafe`).
///
/// Tests that mint a key through `POST /api/keys` (or `/rotate`) and then authenticate as it must
/// hold this lock too, even though they set nothing themselves: whether that key's signing secret
/// gets sealed is decided by `VAULT_ENCRYPTION_KEY` *at creation time*, so a concurrent test
/// clearing the variable in between would leave them unable to decrypt their own secret.
static ENV_MUTATION_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

#[tokio::test]
async fn test_auth_and_cidr_rejection() {
    let db = setup_test_db().await;
    let (webhook_tx, _) = tokio::sync::mpsc::channel(100);
    let state = proxied_state(&db, webhook_tx);
    let app = create_app(state);

    let key_id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    let hash = simply_ip_vault::api::hash_key(&plaintext);

    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(key_id),
        key_hash: Set(hash),
        signing_secret: Set(Some(stored_signing_secret(&plaintext))),
        name: Set("Test Key".to_owned()),
        bound_ips: Set(Some("192.168.1.1/32".to_owned())),
        is_master: Set(false),
        can_manage_keys: Set(false),
        can_manage_webhooks: Set(false),
        can_create_groups: Set(false),
        parent_key_id: Set(None),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    // 1. Missing Key -> 401
    let req = signed(inject_connect_info(Request::builder().uri("/api/ips")), "");
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // 2. Invalid CIDR -> 403 (Client IP matches 127.0.0.1 from ConnectInfo, not 192.168.1.1)
    let req = signed(inject_connect_info(Request::builder().uri("/api/ips").header("X-API-Key", &plaintext)), "");
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);

    // 3. Valid CIDR (simulated via X-Forwarded-For) -> 200
    // Signed a second later: only the *headers* differ from case 2, and headers are not signed, so
    // an identical timestamp would make this the same signature — a replay, not a new request.
    let req = signed_later(inject_connect_info(Request::builder().uri("/api/ips").header("X-API-Key", &plaintext).header("X-Forwarded-For", "192.168.1.1")), 1, "");
    let response = app.clone().oneshot(req).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_tenant_isolation_mn_rbac() {
    let db = setup_test_db().await;
    let (webhook_tx, _) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    // Create a group
    let group_a_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_a_id),
        name: Set("Group A".to_owned()),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }.insert(&db).await.unwrap();

    let key_id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    let hash = simply_ip_vault::api::hash_key(&plaintext);

    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(key_id),
        key_hash: Set(hash),
        signing_secret: Set(Some(stored_signing_secret(&plaintext))),
        name: Set("Tenant Key".to_owned()),
        bound_ips: Set(Some("0.0.0.0/0".to_owned())),
        is_master: Set(false),
        can_manage_keys: Set(false),
        can_manage_webhooks: Set(false),
        can_create_groups: Set(false),
        parent_key_id: Set(None),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }.insert(&db).await.unwrap();

    // Key has NO explicit junction mapping yet.
    
    // Attempt POST to Group A without permissions -> 403
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({ "target_address": "8.8.8.8", "group_name": "Group A" }).to_string());
    
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);

    // Assign M:N Read/Write permissions
    simply_ip_vault::entities::api_key_group_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(key_id),
        group_id: Set(group_a_id),
        can_read: Set(true),
        can_write: Set(true),
        can_delete: Set(false),
        can_manage: Set(false),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }.insert(&db).await.unwrap();

    // POST to Group A -> Should Work. Byte-identical to the denied attempt above, so it is signed
    // a second later — the shape a real client retrying after being granted access produces.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), 1, json!({ "target_address": "8.8.8.8", "group_name": "Group A" }).to_string());
    
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn test_auto_provisioning_on_group_creation() {
    let db = setup_test_db().await;
    let (webhook_tx, _) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let key_id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    let hash = simply_ip_vault::api::hash_key(&plaintext);

    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(key_id),
        key_hash: Set(hash),
        signing_secret: Set(Some(stored_signing_secret(&plaintext))),
        name: Set("Creator Key".to_owned()),
        bound_ips: Set(Some("0.0.0.0/0".to_owned())),
        is_master: Set(false),
        can_manage_keys: Set(false),
        can_manage_webhooks: Set(false),
        can_create_groups: Set(true), // CAN CREATE GROUPS
        parent_key_id: Set(None),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }.insert(&db).await.unwrap();

    // Post to an completely new group
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({ "target_address": "4.4.4.4", "group_name": "Dynamic Group" }).to_string());
    
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Verify it automatically gave us 'can_delete' in the M:N binding
    let perms = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .all(&db).await.unwrap();
    
    assert_eq!(perms.len(), 1);
    assert_eq!(perms[0].api_key_id, key_id);
    assert!(perms[0].can_read);
    assert!(perms[0].can_write);
    assert!(perms[0].can_delete);
}

/// Same auto-provisioning guarantee as `test_auto_provisioning_on_group_creation`, but exercised
/// via the EXPLICIT `POST /api/groups` endpoint rather than an implicit ban/white auto-create —
/// AGENT.MD's rule ("When an API Key creates a new IpGroup...") applies to both paths, and only
/// the implicit one had coverage before this test.
#[tokio::test]
async fn test_explicit_group_creation_grants_full_permissions_to_creator() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (key_id, plaintext) = insert_key(&db, "Group Creator", false, false, false, true).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/groups")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({ "name": "explicitly-created-group" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let group_id = Uuid::parse_str(created["id"].as_str().unwrap()).unwrap();

    let perm = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .filter(simply_ip_vault::entities::api_key_group_permission::Column::ApiKeyId.eq(key_id))
        .filter(simply_ip_vault::entities::api_key_group_permission::Column::GroupId.eq(group_id))
        .one(&db)
        .await
        .unwrap()
        .expect("creator should have an auto-granted permission row on the group it just created");

    assert!(perm.can_read);
    assert!(perm.can_write);
    assert!(perm.can_delete);
}

/// RBAC must be checked BEFORE group-type validation: a key with no permission mapping at all on
/// an existing (whitelist-typed) group must get 403, never 400 — a caller with no access to a
/// group shouldn't learn anything about it, including its type, and should get the same denial
/// it would get for any other group it can't touch.
#[tokio::test]
async fn test_rbac_denial_precedes_group_type_validation() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (_key_b_id, key_b) = insert_key(&db, "No-Access Key", false, false, false, false).await;

    // Master creates a whitelist-typed group.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/white")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "target_address": "203.0.113.9", "group_name": "precedence-whitelist" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // key_b has NO permission mapping at all on this group — must get 403, not 400, even though
    // the group is also the "wrong" type for a ban.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &key_b)
        .header("Content-Type", "application/json")), json!({ "target_address": "198.51.100.5", "group_name": "precedence-whitelist" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(json["error"].as_str().unwrap().contains("Permission denied"));
}

/// Once RBAC clears a key for write access, group-type mismatches are still rejected — in both
/// directions — with the exact, actionable message naming the group and pointing at the correct
/// endpoint/group type.
#[tokio::test]
async fn test_group_type_mismatch_rejected_with_exact_message_for_authorized_key() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (key_b_id, key_b) = insert_key(&db, "Key_B", false, false, false, false).await;

    // Master creates a whitelist group and a banlist group, each seeded with an address.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/white")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "target_address": "203.0.113.10", "group_name": "type-check-whitelist" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "target_address": "203.0.113.11", "group_name": "type-check-banlist" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Grant Key_B full read+write on BOTH groups.
    for group_name in ["type-check-whitelist", "type-check-banlist"] {
        let req = signed(inject_connect_info(Request::builder()
            .method("POST")
            .uri(format!("/api/keys/{key_b_id}/groups"))
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json")), json!({
                "group_name": group_name,
                "can_read": true,
                "can_write": true,
                "can_delete": false
            }).to_string());
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
    }

    // Banning into the whitelist group is rejected with the exact specified message.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &key_b)
        .header("Content-Type", "application/json")), json!({ "target_address": "198.51.100.20", "group_name": "type-check-whitelist" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["error"],
        "Cannot ban IP into group 'type-check-whitelist': group type is 'whitelist'. Use /api/white or target a banlist group."
    );

    // Whitelisting into the banlist group is rejected with the exact specified (reverse) message.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/white")
        .header("X-API-Key", &key_b)
        .header("Content-Type", "application/json")), json!({ "target_address": "198.51.100.21", "group_name": "type-check-banlist" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        json["error"],
        "Cannot whitelist IP into group 'type-check-banlist': group type is 'banlist'. Use /api/ban or target a whitelist group."
    );
}

#[tokio::test]
async fn test_explicit_key_group_manipulation() {
    let db = setup_test_db().await;
    let (webhook_tx, _) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let master_id = Uuid::new_v4();
    let master_plaintext = simply_ip_vault::api::generate_random_key();
    let master_hash = simply_ip_vault::api::hash_key(&master_plaintext);

    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(master_id),
        key_hash: Set(master_hash),
        signing_secret: Set(Some(stored_signing_secret(&master_plaintext))),
        name: Set("System Master".to_owned()),
        bound_ips: Set(Some("0.0.0.0/0".to_owned())),
        is_master: Set(true), // CAN MANAGE KEYS
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_create_groups: Set(true),
        parent_key_id: Set(None),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let target_id = Uuid::new_v4();
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(target_id),
        key_hash: Set(simply_ip_vault::api::hash_key("dummy")),
        signing_secret: Set(Some(stored_signing_secret("dummy"))),
        name: Set("Target Sub-Key".to_owned()),
        bound_ips: Set(Some("192.168.1.1/32".to_owned())),
        is_master: Set(false),
        can_manage_keys: Set(false),
        can_manage_webhooks: Set(false),
        can_create_groups: Set(false),
        parent_key_id: Set(None),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{}/groups", target_id))
        .header("X-API-Key", &master_plaintext)
        .header("Content-Type", "application/json")), json!({
            "group_name": "Dynamic Access Hub",
            "can_read": true,
            "can_write": false,
            "can_delete": false
        }).to_string());

    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let perms = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .all(&db)
        .await
        .unwrap();

    assert_eq!(perms.len(), 1);
    assert_eq!(perms[0].api_key_id, target_id);
    assert!(perms[0].can_read);
    assert!(!perms[0].can_write);
}

/// AGENT.MD mandates verifying multi-group and temporal (`max_age`/`since`) query filtering on
/// `GET /api/v1/ips`.
#[tokio::test]
async fn test_multi_group_and_temporal_filtering() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let key_id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    let hash = simply_ip_vault::api::hash_key(&plaintext);
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(key_id),
        key_hash: Set(hash),
        signing_secret: Set(Some(stored_signing_secret(&plaintext))),
        name: Set("Master".to_owned()),
        bound_ips: Set(None),
        is_master: Set(true),
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_create_groups: Set(true),
        parent_key_id: Set(None),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    // A fresh record, created "now" through the API, in "group-fresh".
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({ "target_address": "9.9.9.9", "group_name": "group-fresh" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // A stale record inserted directly with an old `last_seen_at`, in "group-old".
    let old_group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(old_group_id),
        name: Set("group-old".to_owned()),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let old_record_id = Uuid::new_v4();
    let old_time = chrono::Utc::now().naive_utc() - chrono::Duration::hours(2);
    simply_ip_vault::entities::ip_record::ActiveModel {
        id: Set(old_record_id),
        target_address: Set("8.8.4.4".to_owned()),
        cause: Set(None),
        is_locked: Set(false),
        created_at: Set(old_time),
        updated_at: Set(old_time),
        last_seen_at: Set(old_time),
        is_deleted: Set(false),
        deleted_at: Set(None),
        deleted_by: Set(None),
    }
    .insert(&db)
    .await
    .unwrap();

    // The membership must be aged the same as the record — `since` now reads the membership's own
    // `updated_at` (`m20260926_120000`), so a membership stamped "now" would look fresh regardless
    // of how stale the record it points at is.
    simply_ip_vault::entities::ip_record_group_membership::ActiveModel {
        ip_record_id: Set(old_record_id),
        group_id: Set(old_group_id),
        created_at: Set(old_time),
        updated_at: Set(old_time),
    }
    .insert(&db)
    .await
    .unwrap();

    // `groups` filter: only the fresh record's group should be returned.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/ips?groups=group-fresh")
        .header("X-API-Key", &plaintext)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["target_address"], "9.9.9.9");

    // `max_age` filter: a 60-second window must exclude the 2-hour-old record but keep the
    // fresh one, and the exclusion must happen in the query (not just be truncated by paging).
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/ips?max_age=60")
        .header("X-API-Key", &plaintext)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert!(items.iter().any(|i| i["target_address"] == "9.9.9.9"));
    assert!(items.iter().all(|i| i["target_address"] != "8.8.4.4"));

    // `since` filter: a very recent Unix timestamp must also exclude the stale record.
    let since_ts = (chrono::Utc::now() - chrono::Duration::minutes(5)).timestamp();
    let req = signed(inject_connect_info(Request::builder()
        .uri(format!("/api/ips?since={since_ts}"))
        .header("X-API-Key", &plaintext)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert!(items.iter().any(|i| i["target_address"] == "9.9.9.9"));
    assert!(items.iter().all(|i| i["target_address"] != "8.8.4.4"));
}

/// AGENT.MD mandates verifying webhook payload delivery and HMAC `X-Signature-256` validity via
/// a mock HTTP endpoint.
///
/// Also the one place in the suite that proves execution history end to end: not by calling
/// `dispatch::log_execution` or the retry loop directly (`dispatch.rs`'s own unit tests already do
/// that), and not by hand-inserting a `webhook_executions` row and checking a listing endpoint
/// reads it back (`s4_webhook_executions_are_scoped_to_ownership_not_can_manage_keys` does that) —
/// but by driving the *entire* real path: `POST /api/ban` enqueues a real event, the real
/// `run_webhook_worker` dispatches it over a real HTTP call to the mock receiver above, and only
/// then is `GET /api/webhooks/executions` asked whether it saw a row. Every other execution-history
/// test could pass while the wiring between the worker and `log_execution` was silently broken
/// (wrong `db`, wrong `webhook_id`, a dropped `.await`) — this is the one that would catch it.
#[tokio::test]
async fn test_webhook_hmac_signature_and_delivery() {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;
    use std::sync::{Arc, Mutex};

    let _env_guard = ENV_MUTATION_LOCK.lock().await;

    #[derive(Default)]
    struct Captured {
        body: Option<String>,
        signature: Option<String>,
    }

    let captured: Arc<Mutex<Captured>> = Arc::new(Mutex::new(Captured::default()));
    let captured_for_handler = captured.clone();

    let hook_app = axum::Router::new().route(
        "/hook",
        axum::routing::post(move |headers: axum::http::HeaderMap, body: String| {
            let captured = captured_for_handler.clone();
            async move {
                let sig = headers
                    .get("X-Signature-256")
                    .and_then(|h| h.to_str().ok())
                    .map(|s| s.to_owned());
                let mut c = captured.lock().unwrap();
                c.body = Some(body);
                c.signature = sig;
                StatusCode::OK
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hook_addr = listener.local_addr().unwrap();
    let _hook_server = tokio::spawn(async move {
        axum::serve(listener, hook_app).await.unwrap();
    });

    // The mock hook above lives on loopback, which SSRF protection blocks by default; this test
    // explicitly opts in to private targets to exercise the signing/delivery path.
    unsafe {
        std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "true");
    }

    let db = setup_test_db().await;
    let (webhook_tx, webhook_rx) = tokio::sync::mpsc::channel(100);
    let db_for_worker = db.clone();
    let _worker_handle = tokio::spawn(async move {
        simply_ip_vault::dispatch::run_webhook_worker(db_for_worker, webhook_rx).await;
    });

    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let key_id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    let hash = simply_ip_vault::api::hash_key(&plaintext);
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(key_id),
        key_hash: Set(hash),
        signing_secret: Set(Some(stored_signing_secret(&plaintext))),
        name: Set("Webhook Tester".to_owned()),
        bound_ips: Set(None),
        is_master: Set(true),
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_create_groups: Set(true),
        parent_key_id: Set(None),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_id),
        name: Set("hook-group".to_owned()),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let secret = "top-secret-webhook-key";
    let hook_url = format!("http://{hook_addr}/hook");
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/webhooks")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({
            "name": "Test Hook",
            "target_url": hook_url,
            "secret_token": secret,
            "payload_template": "{\"ip\":\"$target_address\"}",
            "group_id": group_id.to_string(),
            // Explicit since `auth_mode` now defaults to CANONICAL_V1; this test asserts the
            // GitHub-style `sha256=<hex over body>` shape specifically.
            "auth_mode": "BODY_ONLY",
        }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let created: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    let webhook_id = created["id"].as_str().unwrap().to_owned();

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({ "target_address": "5.5.5.5", "group_name": "hook-group" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Dispatch is async (channel + background worker + spawned HTTP task); poll for delivery.
    let mut delivered = None;
    for _ in 0..40 {
        {
            let c = captured.lock().unwrap();
            if c.body.is_some() {
                delivered = Some((c.body.clone().unwrap(), c.signature.clone()));
            }
        }
        if delivered.is_some() {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    unsafe {
        std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "false");
    }

    let (body, signature) = delivered.expect("webhook was not delivered within timeout");
    let signature = signature.expect("missing X-Signature-256 header");

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(body.as_bytes());
    let expected = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
    assert_eq!(signature, expected);
    assert!(body.contains("5.5.5.5"));

    // The mock receiver capturing the request only proves the HTTP call happened — it says nothing
    // about whether `dispatch_with_retries_config` went on to call `log_execution` afterward. Poll
    // the real listing endpoint (not the table directly) so this also proves
    // `GET /api/webhooks/executions` itself surfaces what the worker just wrote, end to end.
    let mut execution_row = None;
    for i in 0..40 {
        // A distinct offset per poll, not `signed()`'s bare "now": two signed requests inside the
        // same wall-clock second produce the identical signature, which the anti-replay guard
        // correctly refuses as a replay — see `signed_later`'s own doc comment. `100 +` keeps this
        // clear of the earlier `signed()` calls above in this same test.
        let req = signed_later(inject_connect_info(Request::builder()
            .uri("/api/webhooks/executions")
            .header("X-API-Key", &plaintext)), 100 + i, "");
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let rows: Vec<serde_json::Value> = serde_json::from_slice(
            &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
        )
        .unwrap();
        if let Some(row) = rows.into_iter().find(|r| r["webhook_id"] == webhook_id) {
            execution_row = Some(row);
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }

    let row = execution_row.expect("the real dispatch that just delivered must appear in the execution history within the timeout");
    assert_eq!(row["event_type"], "IP_ADD", "the ban that triggered this dispatch is an IP_ADD event");
    assert_eq!(row["is_success"], true, "the mock receiver answered 200");
    assert_eq!(row["status_code"], 200);
    assert!(row["duration_ms"].as_i64().unwrap() >= 0);
}

/// A webhook scoped to `events: "IP_ADD"` must fire for a genuinely new address (`IP_ADD`) but
/// must be skipped for a re-registration of that same address (`IP_UPDATE`) and for its deletion
/// (`IP_DELETE`) — the dispatcher's per-config event allowlist in `run_webhook_worker`.
#[tokio::test]
async fn test_webhook_event_filtering_skips_non_matching_actions() {
    use std::sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    };

    let _env_guard = ENV_MUTATION_LOCK.lock().await;

    let hit_count = Arc::new(AtomicUsize::new(0));
    let hit_count_for_handler = hit_count.clone();

    let hook_app = axum::Router::new().route(
        "/hook",
        axum::routing::post(move || {
            let hit_count = hit_count_for_handler.clone();
            async move {
                hit_count.fetch_add(1, Ordering::SeqCst);
                StatusCode::OK
            }
        }),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let hook_addr = listener.local_addr().unwrap();
    let _hook_server = tokio::spawn(async move {
        axum::serve(listener, hook_app).await.unwrap();
    });

    unsafe {
        std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "true");
    }

    let db = setup_test_db().await;
    let (webhook_tx, webhook_rx) = tokio::sync::mpsc::channel(100);
    let db_for_worker = db.clone();
    let _worker_handle = tokio::spawn(async move {
        simply_ip_vault::dispatch::run_webhook_worker(db_for_worker, webhook_rx).await;
    });

    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let key_id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    let hash = simply_ip_vault::api::hash_key(&plaintext);
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(key_id),
        key_hash: Set(hash),
        signing_secret: Set(Some(stored_signing_secret(&plaintext))),
        name: Set("Event Filter Tester".to_owned()),
        bound_ips: Set(None),
        is_master: Set(true),
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_create_groups: Set(true),
        parent_key_id: Set(None),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_id),
        name: Set("event-filter-group".to_owned()),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let hook_url = format!("http://{hook_addr}/hook");
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/webhooks")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({
            "name": "Add-Only Hook",
            "target_url": hook_url,
            "secret_token": "irrelevant-for-this-test",
            "payload_template": "{\"ip\":\"$target_address\"}",
            "group_id": group_id.to_string(),
            "events": "IP_ADD",
        }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // A brand-new address is an IP_ADD — the webhook IS subscribed to this, so it must fire.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({ "target_address": "9.9.9.9", "group_name": "event-filter-group" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let mut saw_add_delivery = false;
    for _ in 0..40 {
        if hit_count.load(Ordering::SeqCst) >= 1 {
            saw_add_delivery = true;
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    assert!(saw_add_delivery, "IP_ADD should have been delivered to the events:\"IP_ADD\" webhook");
    assert_eq!(hit_count.load(Ordering::SeqCst), 1, "exactly one delivery so far");

    // Re-registering the SAME address in the SAME group is an IP_UPDATE — not subscribed, must
    // be skipped. There's no "it happened" signal to poll for here, so wait a fixed, generous
    // window (dispatch to a local loopback listener normally completes in low single-digit ms)
    // and confirm the hit count did NOT advance.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({ "target_address": "9.9.9.9", "group_name": "event-filter-group", "cause": "updated" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    assert_eq!(hit_count.load(Ordering::SeqCst), 1, "IP_UPDATE must NOT be delivered to an events:\"IP_ADD\"-only webhook");

    // Deleting it is an IP_DELETE — also not subscribed, must also be skipped.
    let req = signed(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri("/api/ips?target_address=9.9.9.9&group_name=event-filter-group")
        .header("X-API-Key", &plaintext)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NO_CONTENT);
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    unsafe {
        std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "false");
    }

    assert_eq!(hit_count.load(Ordering::SeqCst), 1, "IP_DELETE must NOT be delivered to an events:\"IP_ADD\"-only webhook");
}

/// Regression test for a bug found by manual exploratory testing: re-banning an address into a
/// group it already belongs to used `Entity::insert(..).on_conflict(..).do_nothing().exec(db)`
/// for the membership row, which raises `DbErr::RecordNotInserted` ("None of the records are
/// inserted") whenever the `DO NOTHING` branch actually fires, turning AGENT.MD's mandatory
/// "re-registering an existing IP updates `last_seen_at` rather than failing" behavior into a
/// 500 on the single most common real-world firewall operation. The fix uses
/// `exec_without_returning`, which doesn't require a row back.
#[tokio::test]
async fn test_reban_into_same_group_does_not_500() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let key_id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    let hash = simply_ip_vault::api::hash_key(&plaintext);
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(key_id),
        key_hash: Set(hash),
        signing_secret: Set(Some(stored_signing_secret(&plaintext))),
        name: Set("Master".to_owned()),
        bound_ips: Set(None),
        is_master: Set(true),
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_create_groups: Set(true),
        parent_key_id: Set(None),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let ban = |cause: &'static str| {
        json!({ "target_address": "77.77.77.77", "group_name": "reban-group", "cause": cause }).to_string()
    };

    // First ban: creates the record and the membership row (no conflict).
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), ban("first offense"));
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Second ban into the SAME group: the membership insert hits the conflict path. Must still
    // return 200, not 500.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), ban("second offense"));
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Exactly one record and one membership row must exist, with the cause updated.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/ips?groups=reban-group")
        .header("X-API-Key", &plaintext)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["cause"], "second offense");
}

/// Regression test for a bug found by manual exploratory testing: `POST /api/webhooks` accepted
/// any string as `target_url`, including "not a url", creating a webhook that could never
/// possibly be delivered with no feedback to the caller (it would only ever fail silently, once
/// per matching event, at dispatch time). `create_webhook` now validates the URL eagerly.
#[tokio::test]
async fn test_create_webhook_rejects_invalid_url() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let key_id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    let hash = simply_ip_vault::api::hash_key(&plaintext);
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(key_id),
        key_hash: Set(hash),
        signing_secret: Set(Some(stored_signing_secret(&plaintext))),
        name: Set("Master".to_owned()),
        bound_ips: Set(None),
        is_master: Set(true),
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_create_groups: Set(true),
        parent_key_id: Set(None),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_id),
        name: Set("webhook-validation-group".to_owned()),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let make_req = |url: &str| {
        signed(inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/webhooks")
            .header("X-API-Key", &plaintext)
            .header("Content-Type", "application/json")), json!({
                "name": "Test",
                "target_url": url,
                "secret_token": "s",
                "payload_template": "{}",
                "group_id": group_id.to_string(),
            }).to_string())
    };

    let res = app.clone().oneshot(make_req("not a url")).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let res = app.clone().oneshot(make_req("ftp://example.com/hook")).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    let res = app.clone().oneshot(make_req("https://example.com/hook")).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

// ─────────────────────────────────────────────────────────────
// API Key lifecycle & RBAC permission enforcement
// ─────────────────────────────────────────────────────────────

async fn insert_key(
    db: &DatabaseConnection,
    name: &str,
    is_master: bool,
    can_manage_keys: bool,
    can_manage_webhooks: bool,
    can_create_groups: bool,
) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    let hash = simply_ip_vault::api::hash_key(&plaintext);
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(id),
        key_hash: Set(hash),
        signing_secret: Set(Some(stored_signing_secret(&plaintext))),
        name: Set(name.to_owned()),
        bound_ips: Set(None),
        is_master: Set(is_master),
        can_manage_keys: Set(can_manage_keys),
        can_manage_webhooks: Set(can_manage_webhooks),
        can_create_groups: Set(can_create_groups),
        parent_key_id: Set(None),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(db)
    .await
    .unwrap();
    (id, plaintext)
}

/// Covers: a master key can create a new API key with specific global flags and `bound_ips`; a
/// non-privileged key gets `403 Forbidden` attempting the same.
#[tokio::test]
async fn test_key_creation_lifecycle() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/keys")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "name": "CI Bot",
            "bound_ips": "10.0.0.0/8",
            "can_manage_keys": true,
            "can_manage_webhooks": true
        }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(created["plaintext_key"].as_str().is_some_and(|s| !s.is_empty()));
    assert_eq!(created["bound_ips"], "10.0.0.0/8");
    let new_key_id = created["id"].as_str().unwrap();

    // Confirm the persisted flags actually match what was requested (not just the create
    // response echoing the input back).
    let stored = simply_ip_vault::entities::api_key::Entity::find_by_id(Uuid::parse_str(new_key_id).unwrap())
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert!(stored.can_manage_keys);
    assert!(stored.can_manage_webhooks);
    assert!(!stored.can_create_groups);
    assert_eq!(stored.bound_ips.as_deref(), Some("10.0.0.0/8"));

    // A non-privileged key (no is_master, no can_manage_keys) must be forbidden from creating keys.
    let (_plain_id, plain_key) = insert_key(&db, "Plain", false, false, false, false).await;
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/keys")
        .header("X-API-Key", &plain_key)
        .header("Content-Type", "application/json")), json!({ "name": "Should Not Exist" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
}

/// Covers: a key with zero global rights, scoped only via `ApiKeyGroupPermission`, is correctly
/// gated by `can_read`/`can_write` independently, and a live permission upgrade takes effect
/// immediately on the next request (no caching/staleness).
#[tokio::test]
async fn test_group_permission_assignment_boundaries() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (key_b_id, key_b) = insert_key(&db, "Key_B", false, false, false, false).await;

    // Master grants Key_B read-only rights on "Group_X" (auto-provisions the group).
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_b_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "group_name": "Group_X",
            "can_read": true,
            "can_write": false,
            "can_delete": false
        }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Master seeds an address into Group_X so there is something for Key_B to read.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "target_address": "203.0.113.1", "group_name": "Group_X" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Key_B can read Group_X.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/ips?groups=Group_X")
        .header("X-API-Key", &key_b)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["target_address"], "203.0.113.1");

    // Key_B cannot write to Group_X yet.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &key_b)
        .header("Content-Type", "application/json")), json!({ "target_address": "203.0.113.2", "group_name": "Group_X" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);

    // Master upgrades Key_B to can_write = true.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_b_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "group_name": "Group_X",
            "can_read": true,
            "can_write": true,
            "can_delete": false
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Key_B can now write to Group_X. Same request as the denied one above, retried a second later.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &key_b)
        .header("Content-Type", "application/json")), 1, json!({ "target_address": "203.0.113.2", "group_name": "Group_X" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
}

/// Covers: deleting an API key immediately invalidates it (`401` on next use, not just "no longer
/// listed"), and the FK `ON DELETE CASCADE` on `api_key_group_permissions.api_key_id` leaves no
/// orphaned permission rows behind.
#[tokio::test]
async fn test_key_deletion_revokes_access_and_cascades_permissions() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (key_b_id, key_b) = insert_key(&db, "Key_B", false, false, false, false).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_b_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "group_name": "Group_X",
            "can_read": true,
            "can_write": true,
            "can_delete": false
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Sanity check: Key_B actually works before deletion.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &key_b)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let perms_before = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .filter(simply_ip_vault::entities::api_key_group_permission::Column::ApiKeyId.eq(key_b_id))
        .all(&db)
        .await
        .unwrap();
    assert_eq!(perms_before.len(), 1);

    // Master deletes Key_B.
    let req = signed(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri(format!("/api/keys/{key_b_id}"))
        .header("X-API-Key", &master_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);

    // Immediately, any request using Key_B's header must be rejected as unauthorized.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &key_b)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/ips?groups=Group_X")
        .header("X-API-Key", &key_b)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // No orphaned api_key_group_permissions rows survive the deleted key.
    let perms_after = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .filter(simply_ip_vault::entities::api_key_group_permission::Column::ApiKeyId.eq(key_b_id))
        .all(&db)
        .await
        .unwrap();
    assert!(perms_after.is_empty());
}

// ─────────────────────────────────────────────────────────────
// Concurrency, reverse-proxy security, and CIDR boundary tests
// ─────────────────────────────────────────────────────────────

async fn insert_key_with_bound_ips(db: &DatabaseConnection, name: &str, bound_ips: &str) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    let hash = simply_ip_vault::api::hash_key(&plaintext);
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(id),
        key_hash: Set(hash),
        signing_secret: Set(Some(stored_signing_secret(&plaintext))),
        name: Set(name.to_owned()),
        bound_ips: Set(Some(bound_ips.to_owned())),
        is_master: Set(false),
        can_manage_keys: Set(false),
        can_manage_webhooks: Set(false),
        can_create_groups: Set(false),
        parent_key_id: Set(None),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(db)
    .await
    .unwrap();
    (id, plaintext)
}

/// Fail2ban-style simulation: 10 concurrent tasks re-ban the exact same address into the exact
/// same group at once. SeaORM's SQLite driver forces a single-connection pool by default (there is
/// no `cache=shared` in play here — without that forced serialization, concurrent connections to
/// `sqlite::memory:` would each see their own empty database), so this also doubles as a
/// concurrency-level regression test for the `exec_without_returning` fix: under real contention,
/// several of these requests *will* hit the `ON CONFLICT DO NOTHING` branch for the membership
/// insert at the same moment.
#[tokio::test]
async fn test_concurrent_burst_ban_requests() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    // Each task signs at a distinct second. Ten byte-identical signed requests would be ten copies
    // of one signature, which the anti-replay guard refuses by design — and refusing them would
    // make this a test of the guard rather than of the write race it exists to cover. Spreading the
    // timestamps keeps every request cryptographically distinct while leaving them simultaneous on
    // the wire, which is exactly the contention this test is about: ten writers, one
    // (address, group) pair, no duplicate rows and no 500s.
    let mut handles = Vec::with_capacity(10);
    for offset in 0..10 {
        let app = app.clone();
        let master_key = master_key.clone();
        handles.push(tokio::spawn(async move {
            let req = signed_later(inject_connect_info(Request::builder()
                .method("POST")
                .uri("/api/ban")
                .header("X-API-Key", &master_key)
                .header("Content-Type", "application/json")), offset, json!({
                    "target_address": "44.44.44.44",
                    "group_name": "burst-group",
                    "cause": "fail2ban burst"
                }).to_string());
            app.oneshot(req).await.unwrap().status()
        }));
    }

    let mut ok_count = 0;
    for handle in handles {
        // A per-task timeout turns a hang/deadlock into a clear test failure instead of an
        // indefinitely stuck `cargo test` run.
        let status = tokio::time::timeout(std::time::Duration::from_secs(10), handle)
            .await
            .expect("task did not complete in time (possible deadlock)")
            .unwrap();
        if status == StatusCode::OK {
            ok_count += 1;
        }
    }
    assert_eq!(ok_count, 10, "all 10 concurrent re-bans of the same address/group must return 200 OK");

    // Exactly one record must exist in exactly one membership row — no duplicates, no partial
    // failures, despite 10 simultaneous writers targeting the same (address, group) pair.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/ips?groups=burst-group")
        .header("X-API-Key", &master_key)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["target_address"], "44.44.44.44");

    // last_seen_at must reflect one of the concurrent requests, not be stale/missing.
    let last_seen: chrono::NaiveDateTime = serde_json::from_value(items[0]["last_seen_at"].clone()).unwrap();
    let age = chrono::Utc::now().naive_utc() - last_seen;
    assert!(age < chrono::Duration::seconds(30), "last_seen_at should have just been updated, age was {age}");
}

/// Security regression test: a forged `X-Forwarded-For` prefix must not bypass `bound_ips`. Only
/// the rightmost hop (the one *your own* reverse proxy appended) is trustworthy — anything to its
/// left is attacker-supplied and must be ignored, per AGENT.MD's "Resilient IP Extraction" rule.
#[tokio::test]
async fn test_reverse_proxy_xff_extracts_rightmost_trusted_hop() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = proxied_state(&db, webhook_tx);
    let app = create_app(state);

    const FORGED_CLAIM: &str = "8.8.8.8";
    const TRUSTED_HOP: &str = "10.0.0.1";
    let xff_header = format!("{FORGED_CLAIM}, {TRUSTED_HOP}");

    // A key bound to the rightmost (trusted-proxy-appended) address must be let through.
    let (_id, key_trusted) = insert_key_with_bound_ips(&db, "trusted-hop", "10.0.0.1/32").await;
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &key_trusted)
        .header("X-Forwarded-For", &xff_header)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // A key bound to the leftmost, client-forgeable claim must NOT be let through: if it were,
    // any client could bypass CIDR restriction just by prepending an allowed address to the
    // header.
    let (_id2, key_forged) = insert_key_with_bound_ips(&db, "forged-claim", "8.8.8.8/32").await;
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &key_forged)
        .header("X-Forwarded-For", &xff_header)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);
}

/// `POST /api/ban` must reject malformed CIDRs with `400` and accept valid IPv6 CIDRs cleanly.
#[tokio::test]
async fn test_cidr_and_ipv6_boundary_validation() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    let ban = |addr: &str| {
        signed(inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/ban")
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json")), json!({ "target_address": addr, "group_name": "cidr-boundary-group" }).to_string())
    };

    // Octet out of range (> 255).
    let res = app.clone().oneshot(ban("256.0.0.1/32")).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Prefix length out of range for an IPv4 address (max is /32).
    let res = app.clone().oneshot(ban("10.0.0.1/35")).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Free-form garbage.
    let res = app.clone().oneshot(ban("definitely-not-an-ip")).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // A valid, non-private IPv6 CIDR must parse and be accepted.
    let res = app.clone().oneshot(ban("2001:db8::/32")).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

/// `normalize_ip_or_cidr` strips a single-host CIDR suffix (`/32`, `/128`) down to the plain
/// address, **masks host bits off a genuine subnet**, and passes unparseable input through unchanged
/// rather than erroring: it is a normalization helper, not a validator.
///
/// The masking half changed in Session 55. This test previously asserted that
/// `188.190.74.130/24` survived verbatim; it now canonicalises to `188.190.74.0/24`, so that two
/// clients naming the same network with different host bits address one record rather than two.
#[tokio::test]
async fn test_normalize_ip_or_cidr_strips_single_host_prefixes_only() {
    use simply_ip_vault::api::normalize_ip_or_cidr;

    assert_eq!(normalize_ip_or_cidr("188.190.74.128/32"), "188.190.74.128");
    assert_eq!(normalize_ip_or_cidr("188.190.74.128"), "188.190.74.128");
    assert_eq!(normalize_ip_or_cidr("::1/128"), "::1");
    assert_eq!(normalize_ip_or_cidr("2001:db8::1"), "2001:db8::1");

    // Genuine subnets keep their prefix and are masked down to the network address.
    assert_eq!(normalize_ip_or_cidr("10.0.0.0/24"), "10.0.0.0/24", "already canonical");
    assert_eq!(normalize_ip_or_cidr("188.190.74.130/24"), "188.190.74.0/24", "host bits masked");
    assert_eq!(normalize_ip_or_cidr("2001:db8::/64"), "2001:db8::/64");
    assert_eq!(normalize_ip_or_cidr("2001:db8::fe/64"), "2001:db8::/64", "v6 host bits masked");
    // Masking follows the prefix length, not the octet boundary.
    assert_eq!(normalize_ip_or_cidr("192.168.1.130/25"), "192.168.1.128/25");
    assert_eq!(normalize_ip_or_cidr("192.168.1.126/25"), "192.168.1.0/25");

    // Unparseable input (garbage, or a genuine partial substring fragment as used by the
    // /api/ips filter) passes through unchanged rather than being rejected.
    assert_eq!(normalize_ip_or_cidr("not-an-ip"), "not-an-ip");
    assert_eq!(normalize_ip_or_cidr("74.128"), "74.128");
}

/// End-to-end proof that canonicalization actually prevents the duplicate-storage bug it exists
/// to fix: banning the same address once as "X/32" and once as bare "X" must produce exactly one
/// stored record (not two), in canonical (bare) form — and DELETE must find and remove a record
/// regardless of which representation it was originally created with vs. looked up by.
#[tokio::test]
async fn test_ban_deduplicates_slash_32_and_bare_ip_representations() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    // Ban the /32 form first.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "target_address": "188.190.74.128/32", "group_name": "canon-group" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Ban the bare form of the SAME address — must update the same row, not create a second one.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "target_address": "188.190.74.128", "group_name": "canon-group", "cause": "re-banned bare" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/ips?groups=canon-group")
        .header("X-API-Key", &master_key)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(items.len(), 1, "the /32 and bare forms must be treated as the SAME address, not two records");
    assert_eq!(items[0]["target_address"], "188.190.74.128", "stored in canonical (bare) form");
    assert_eq!(items[0]["cause"], "re-banned bare", "the second call updated the same row");

    // Deleting via the bare form must find and remove the record, even though nothing was ever
    // literally stored or requested with that exact string until now — canonicalization, not
    // string luck, is what makes this work.
    let req = signed(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri("/api/ips?target_address=188.190.74.128&group_name=canon-group")
        .header("X-API-Key", &master_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);

    // And deleting via the /32 form of an address that was actually stored bare must ALSO work.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "target_address": "203.0.113.77", "group_name": "canon-group" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = signed(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri("/api/ips?target_address=203.0.113.77/32&group_name=canon-group")
        .header("X-API-Key", &master_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);
}

/// Proves webhook dispatch is genuinely non-blocking: `POST /api/ban` must return almost
/// immediately even when the only registered webhook for that group targets an endpoint that
/// takes several seconds to respond. The handler only ever hands the event off over an mpsc
/// channel (`state.webhook_tx.send(event).await`, capacity 100, effectively never full here) — the
/// slow HTTP dispatch itself happens later, in the separate `run_webhook_worker` background task.
#[tokio::test]
async fn test_webhook_dispatch_does_not_block_api_response() {
    let _env_guard = ENV_MUTATION_LOCK.lock().await;

    let slow_app = axum::Router::new().route(
        "/slow-hook",
        axum::routing::post(|| async {
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
            StatusCode::OK
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let slow_addr = listener.local_addr().unwrap();
    let _slow_server = tokio::spawn(async move {
        axum::serve(listener, slow_app).await.unwrap();
    });

    // The slow mock above lives on loopback, which SSRF protection blocks unless explicitly
    // allowed; opt in so the dispatch genuinely reaches (and hangs on) the slow endpoint rather
    // than being short-circuited immediately.
    unsafe {
        std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "true");
    }

    let db = setup_test_db().await;
    let (webhook_tx, webhook_rx) = tokio::sync::mpsc::channel(100);
    let db_for_worker = db.clone();
    let _worker_handle = tokio::spawn(async move {
        simply_ip_vault::dispatch::run_webhook_worker(db_for_worker, webhook_rx).await;
    });

    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    let group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_id),
        name: Set("slow-hook-group".to_owned()),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/webhooks")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "name": "Slow Hook",
            "target_url": format!("http://{slow_addr}/slow-hook"),
            "secret_token": "s",
            "payload_template": "{}",
            "group_id": group_id.to_string(),
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let start = std::time::Instant::now();
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "target_address": "66.66.66.66", "group_name": "slow-hook-group" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    let elapsed = start.elapsed();

    unsafe {
        std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "false");
    }

    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        elapsed < std::time::Duration::from_millis(50),
        "expected POST /api/ban to return in under 50ms regardless of webhook speed, took {elapsed:?}"
    );
}

// ─────────────────────────────────────────────────────────────
// Unified group identification, flexible DELETE, key rotation/update,
// permission revocation, and audit log querying
// ─────────────────────────────────────────────────────────────

/// `DELETE /api/ips` must accept `target_address`/`group_name` from the URL query string (the
/// original, documented shape) as well as from a JSON request body (previously a guaranteed
/// deserialization failure, since `Query<DeleteIpQuery>` only ever looked at the URL).
#[tokio::test]
async fn test_delete_ip_accepts_query_or_json_body() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    for addr in ["55.55.55.1", "55.55.55.2"] {
        let req = signed(inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/ban")
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json")), json!({ "target_address": addr, "group_name": "delete-shape-group" }).to_string());
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
    }

    // Delete via URL query string.
    let req = signed(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri("/api/ips?target_address=55.55.55.1&group_name=delete-shape-group")
        .header("X-API-Key", &master_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);

    // Delete via JSON body instead — previously this failed before the handler even ran.
    let req = signed(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri("/api/ips")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "target_address": "55.55.55.2", "group_name": "delete-shape-group" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);

    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/ips?groups=delete-shape-group")
        .header("X-API-Key", &master_key)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert!(items.is_empty(), "both records should be gone: {items:?}");
}

/// A group granted/looked-up by `group_id` and one looked up by `group_name` must be the same
/// group and behave identically. Also covers the required-exactly-one-of validation and that an
/// unknown `group_id` 404s rather than silently auto-creating (unlike an unknown `group_name`).
#[tokio::test]
async fn test_group_identification_by_id_and_name_are_interchangeable() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (key_c_id, key_c) = insert_key(&db, "Key_C", false, false, false, false).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "target_address": "77.1.1.1", "group_name": "interop-group" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let group_id = simply_ip_vault::entities::ip_group::Entity::find()
        .filter(simply_ip_vault::entities::ip_group::Column::Name.eq("interop-group"))
        .one(&db).await.unwrap().unwrap().id;

    // Grant Key_C rights on the group BY ID.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_c_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "group_id": group_id, "can_read": true, "can_write": true, "can_delete": false }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Key_C bans an address identifying the group BY NAME...
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &key_c)
        .header("Content-Type", "application/json")), json!({ "target_address": "77.1.1.2", "group_name": "interop-group" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // ...and another identifying it BY ID.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &key_c)
        .header("Content-Type", "application/json")), json!({ "target_address": "77.1.1.3", "group_id": group_id }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Supplying both is rejected.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &key_c)
        .header("Content-Type", "application/json")), json!({ "target_address": "77.1.1.4", "group_id": group_id, "group_name": "interop-group" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::BAD_REQUEST);

    // Supplying neither is rejected.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &key_c)
        .header("Content-Type", "application/json")), json!({ "target_address": "77.1.1.5" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::BAD_REQUEST);

    // An unknown group_id is 404 — unlike group_name, an ID is never auto-creatable.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "target_address": "77.1.1.6", "group_id": Uuid::new_v4() }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NOT_FOUND);
}

/// `POST /api/keys/{id}/rotate` must generate a new secret and immediately invalidate the old one.
#[tokio::test]
async fn test_key_rotation_invalidates_old_secret() {
    // Serialized against the VAULT_ENCRYPTION_KEY test: this key's secret is sealed (or not)
    // according to the variable's value at creation time. See ENV_MUTATION_LOCK.
    let _guard = ENV_MUTATION_LOCK.lock().await;
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (rotate_id, old_secret) = insert_key(&db, "Rotate_Me", false, false, false, false).await;

    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &old_secret)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{rotate_id}/rotate"))
        .header("X-API-Key", &master_key)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let new_secret = parsed["plaintext_key"].as_str().unwrap().to_owned();
    assert_ne!(new_secret, old_secret);
    // Rotation mints a fresh signing secret alongside the key; it is returned exactly once, here.
    // From now on this key must be signed with `signed_with`, since its secret is server-generated
    // rather than following the seeded-key convention.
    let new_signing_secret = parsed["signing_secret"].as_str().unwrap().to_owned();
    assert_ne!(new_signing_secret, test_signing_secret(&old_secret));

    // Old secret immediately stops working.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &old_secret)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // The old *signing* secret is invalidated too: presenting the new key with the pre-rotation
    // secret must fail, or rotation would leave a working credential behind after a compromise.
    let req = signed_with(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &new_secret)), &test_signing_secret(&old_secret), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // New secret works.
    let req = signed_with(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &new_secret)), &new_signing_secret, "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // A non-privileged key cannot rotate someone else's key.
    let (other_id, _) = insert_key(&db, "Other", false, false, false, false).await;
    let req = signed_with(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{other_id}/rotate"))
        .header("X-API-Key", &new_secret)), &new_signing_secret, "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);
}

/// `PUT /api/keys/{id}` updates name/bound_ips/global scopes in place, and the change is visible
/// on the next request using that key (permission enforcement isn't cached).
#[tokio::test]
async fn test_update_api_key_changes_take_effect_immediately() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (target_id, target_key) = insert_key(&db, "Before", false, false, false, false).await;

    // Not yet allowed to manage webhooks.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/webhooks")
        .header("X-API-Key", &target_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);

    let req = signed(inject_connect_info(Request::builder()
        .method("PUT")
        .uri(format!("/api/keys/{target_id}"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "name": "After",
            "bound_ips": "0.0.0.0/0",
            "can_manage_webhooks": true
        }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let updated: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(updated["name"], "After");
    assert_eq!(updated["bound_ips"], "0.0.0.0/0");
    assert_eq!(updated["can_manage_webhooks"], true);

    // Now allowed, immediately, with the same (unrotated) secret — retried a second later, since
    // the denied attempt above was byte-identical.
    let req = signed_later(inject_connect_info(Request::builder()
        .uri("/api/webhooks")
        .header("X-API-Key", &target_key)), 1, "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
}

/// `DELETE /api/keys/{id}/permissions/{group_identifier}` removes exactly the targeted grant,
/// accepts either a group name or a group ID as the identifier, and 404s on a second attempt.
#[tokio::test]
async fn test_revoke_group_permission_by_name_and_by_id() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (key_id, key_plain) = insert_key(&db, "Key_D", false, false, false, false).await;

    for group_name in ["revoke-by-name-group", "revoke-by-id-group"] {
        let req = signed(inject_connect_info(Request::builder()
            .method("POST")
            .uri(format!("/api/keys/{key_id}/permissions"))
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json")), json!({ "group_name": group_name, "can_read": true, "can_write": true, "can_delete": true }).to_string());
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
    }

    let group_id_2 = simply_ip_vault::entities::ip_group::Entity::find()
        .filter(simply_ip_vault::entities::ip_group::Column::Name.eq("revoke-by-id-group"))
        .one(&db).await.unwrap().unwrap().id;

    // Revoke the first by name.
    let req = signed(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri("/api/keys/".to_owned() + &key_id.to_string() + "/permissions/revoke-by-name-group")
        .header("X-API-Key", &master_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);

    // Revoke the second by ID.
    let req = signed(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri(format!("/api/keys/{key_id}/permissions/{group_id_2}"))
        .header("X-API-Key", &master_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);

    // Revoking again is 404 — the grant is already gone. Identical to the first revoke, so it is
    // signed a second later rather than being refused as a replay before it reaches the handler.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri("/api/keys/".to_owned() + &key_id.to_string() + "/permissions/revoke-by-name-group")
        .header("X-API-Key", &master_key)), 1, "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NOT_FOUND);

    // The key can no longer read either group.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/ips?groups=revoke-by-name-group,revoke-by-id-group")
        .header("X-API-Key", &key_plain)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert!(items.is_empty());
}

/// Revocation is bounded by the caller's own group access, exactly as granting is.
///
/// `guard_delegated_group_grant` has always stopped a non-master key manager from *handing out*
/// access to a group it does not itself hold. The 2026-08-02 cross-audit found the mirror image
/// unguarded: `revoke_key_group_permission` checked only `can_manage_keys` and then deleted the
/// junction row, so the same caller could *strip* any key's access to any group in the system —
/// including groups belonging to tenants it can neither read nor name.
///
/// That asymmetry is worth stating plainly, because "revocation only removes authority" is a
/// tempting reason to leave it ungated and it is wrong here. Removing authority is exactly the
/// attack: this service exists to keep `fail2ban`-style automation in sync, so quietly revoking the
/// key that writes another tenant's banlist is a denial-of-service against that tenant's blocking,
/// and it is invisible until someone notices bans have stopped landing.
///
/// Both halves are asserted together so neither can regress into the other's shape.
#[tokio::test]
async fn a_key_manager_cannot_revoke_access_to_a_group_it_does_not_manage() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    // The attacker: a legitimate key manager, scoped to its own tenant and nothing else.
    let (attacker_id, attacker_key) = insert_key(&db, "Tenant A manager", false, true, false, false).await;
    // The victim: another tenant's worker key.
    let (victim_id, _victim_key) = insert_key(&db, "Tenant B worker", false, false, false, false).await;

    // Master grants each key access to its own group. Only the attacker gets `can_manage`, which is
    // R2's second half — with `can_manage_keys` it makes the attacker a genuine manager of
    // `tenant-a-group`, so the refusal below is about *which* group it reaches rather than about it
    // having no administrative standing at all.
    for (holder, group_name, manage) in [
        (attacker_id, "tenant-a-group", true),
        (victim_id, "tenant-b-group", false),
    ] {
        let req = signed_later(inject_connect_info(Request::builder()
            .method("POST")
            .uri(format!("/api/keys/{holder}/permissions"))
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json")), 1, json!({
                "group_name": group_name, "can_read": true, "can_write": true, "can_delete": true,
                "can_manage": manage
            }).to_string());
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
    }

    // The attack: strip the victim's access to a group the attacker has no relationship with.
    let req = signed(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri(format!("/api/keys/{victim_id}/permissions/tenant-b-group"))
        .header("X-API-Key", &attacker_key)), "");
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "a key manager with no access to 'tenant-b-group' must not be able to revoke another key's"
    );

    // The grant is genuinely still there — the 403 refused the write rather than merely reporting one.
    let surviving = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .filter(simply_ip_vault::entities::api_key_group_permission::Column::ApiKeyId.eq(victim_id))
        .all(&db)
        .await
        .unwrap();
    assert_eq!(surviving.len(), 1, "the victim's grant must survive the refused revocation");

    // ...while revocation inside the attacker's *own* group still works, so the guard bounds the
    // operation rather than disabling delegated key management.
    let (peer_id, _peer_key) = insert_key(&db, "Tenant A worker", false, false, false, false).await;
    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{peer_id}/permissions"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), 2, json!({
            "group_name": "tenant-a-group", "can_read": true, "can_write": true, "can_delete": true
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = signed_later(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri(format!("/api/keys/{peer_id}/permissions/tenant-a-group"))
        .header("X-API-Key", &attacker_key)), 3, "");
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::NO_CONTENT,
        "revoking within a group the caller does manage must still succeed"
    );

    // A master is unaffected by the guard and can still revoke anything.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri(format!("/api/keys/{victim_id}/permissions/tenant-b-group"))
        .header("X-API-Key", &master_key)), 4, "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);
}

/// Managing a group confers authority to remove **any** verb from it, held or not.
///
/// This is the converged rule, matching `simply_hook_executor`, and it replaces a stricter one that
/// required the caller to hold each verb it removed. The distinction it rests on: guarding a *grant*
/// per verb stops authority being manufactured, while removing a verb manufactures nothing — nobody,
/// the caller included, ends up with more access than before. What removal actually threatens is
/// another tenant's automation, and that is answered by *which groups* the caller can reach — the
/// entry gate asserted in `a_key_manager_cannot_revoke_access_to_a_group_it_does_not_manage`.
///
/// Both spellings of "reduce" are asserted here, because they used to disagree: the dedicated revoke
/// endpoint refused what an update-to-a-lower-value allowed.
#[tokio::test]
async fn a_group_manager_may_remove_verbs_it_does_not_hold_itself() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    // Read-only on the group, but a key manager: under the old rule this could not strip a verb it
    // did not hold, which made a grant it was trusted to create one it was forbidden to undo.
    let (manager_id, manager_key) = insert_key(&db, "Reader manager", false, true, false, false).await;
    let (worker_id, _worker_key) = insert_key(&db, "Worker", false, false, false, false).await;

    let grant = |holder: Uuid, verbs: serde_json::Value, nth: i64| {
        let (app, master_key) = (app.clone(), master_key.clone());
        async move {
            let req = signed_later(inject_connect_info(Request::builder()
                .method("POST")
                .uri(format!("/api/keys/{holder}/permissions"))
                .header("X-API-Key", &master_key)
                .header("Content-Type", "application/json")), nth, verbs.to_string());
            app.oneshot(req).await.unwrap().status()
        }
    };

    assert_eq!(
        grant(manager_id, json!({
            "group_name": "shared-group", "can_read": true, "can_write": false, "can_delete": false,
            // R2's resource half. Read-only on the group's *data*, administrative over its grants —
            // which is exactly what makes "removes a verb it does not hold" a real assertion.
            "can_manage": true
        }), 1).await,
        StatusCode::OK
    );
    assert_eq!(
        grant(worker_id, json!({
            "group_name": "shared-group", "can_read": true, "can_write": true, "can_delete": true
        }), 2).await,
        StatusCode::OK
    );

    // Spelling one: reduce the worker's row through the general update endpoint. This path already
    // permitted it — `over_grants` only inspects verbs being set to true — and is the behaviour the
    // revoke path is now aligned with.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{worker_id}/permissions"))
        .header("X-API-Key", &manager_key)
        .header("Content-Type", "application/json")), 3, json!({
            "group_name": "shared-group", "can_read": true, "can_write": false, "can_delete": false
        }).to_string());
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK,
        "a read-only manager may strip write/delete by updating the row to a lower value"
    );

    let reduced = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .filter(simply_ip_vault::entities::api_key_group_permission::Column::ApiKeyId.eq(worker_id))
        .one(&db)
        .await
        .unwrap()
        .expect("the worker's row survives, reduced");
    assert!(reduced.can_read, "the verb the manager holds is untouched");
    assert!(!reduced.can_write && !reduced.can_delete, "the verbs it does not hold were removed");

    // Spelling two: the dedicated revoke endpoint, on a row that still carried delete. Under the old
    // rule this was the 403 that made the two paths disagree.
    assert_eq!(
        grant(worker_id, json!({
            "group_name": "shared-group", "can_read": true, "can_write": true, "can_delete": true
        }), 4).await,
        StatusCode::OK
    );
    let req = signed_later(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri(format!("/api/keys/{worker_id}/permissions/shared-group"))
        .header("X-API-Key", &manager_key)), 5, "");
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::NO_CONTENT,
        "the same removal must succeed through the dedicated endpoint too"
    );

    // **Endpoint parity, in the one shape that distinguishes it.** R6: a reduction reached through
    // the general update endpoint is classified as a revocation "regardless of which endpoint it
    // arrives at". Every reduction so far has also been within the caller's own verbs, so routing it
    // through the grant path by mistake would produce the same answer and no test would notice.
    //
    // This one is not: the worker keeps `can_write`, which the manager does **not** hold, while
    // losing `can_delete`. It adds no verb, so it is a revocation and must succeed — but under the
    // grant path the surviving `can_write` trips the per-verb ceiling and it would be refused.
    assert_eq!(
        grant(worker_id, json!({
            "group_name": "shared-group", "can_read": true, "can_write": true, "can_delete": true
        }), 6).await,
        StatusCode::OK
    );
    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{worker_id}/permissions"))
        .header("X-API-Key", &manager_key)
        .header("Content-Type", "application/json")), 7, json!({
            "group_name": "shared-group", "can_read": true, "can_write": true, "can_delete": false
        }).to_string());
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK,
        "dropping one verb while leaving another the caller does not hold is still a revocation"
    );

    let partial = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .filter(simply_ip_vault::entities::api_key_group_permission::Column::ApiKeyId.eq(worker_id))
        .one(&db)
        .await
        .unwrap()
        .expect("the worker's row survives the partial reduction");
    assert!(
        partial.can_read && partial.can_write && !partial.can_delete,
        "only the dropped verb changed: {partial:?}"
    );

    // Granting is still bounded per verb — the relaxation is one-directional, and a test that did
    // not assert this would be consistent with the guard having been deleted outright.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{worker_id}/permissions"))
        .header("X-API-Key", &manager_key)
        .header("Content-Type", "application/json")), 8, json!({
            "group_name": "shared-group", "can_read": true, "can_write": true, "can_delete": true
        }).to_string());
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "a read-only manager still cannot confer can_delete it does not hold"
    );
}

/// A manager may revoke its **own** access to a group it manages.
///
/// The block this replaces existed to prevent a ratchet — grant yourself what you already hold, then
/// widen from the fresh row. The ratchet was never reachable: `guard_delegated_group_grant` compares
/// a self-directed request against the caller's own row, which is the row being written, so the
/// result can never exceed what was already held. All the block achieved was making the
/// least-privilege action — dropping your own access — require a master.
///
/// Asserted through both endpoints, and the escalation direction is asserted to still fail, so this
/// cannot pass by self-targeting having become unguarded rather than bounded.
#[tokio::test]
async fn a_group_manager_may_revoke_and_reduce_its_own_access() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (manager_id, manager_key) = insert_key(&db, "Manager", false, true, false, false).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{manager_id}/permissions"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "group_name": "self-revoke-group", "can_read": true, "can_write": true,
            "can_delete": true, "can_manage": true
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Self-reduction through the update endpoint: drop your own delete. `can_manage` is re-submitted
    // rather than omitted — omitting it would *also* be a valid reduction (dropping the
    // administrative right in the same call), but it would strip the very authority the later
    // assertions test, and the interesting case is reducing one verb while keeping the role.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{manager_id}/permissions"))
        .header("X-API-Key", &manager_key)
        .header("Content-Type", "application/json")), 1, json!({
            "group_name": "self-revoke-group", "can_read": true, "can_write": true,
            "can_delete": false, "can_manage": true
        }).to_string());
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK,
        "a manager may reduce its own row on a group it manages"
    );

    // ...but not widen it back. This is the bound that makes self-targeting safe to allow at all.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{manager_id}/permissions"))
        .header("X-API-Key", &manager_key)
        .header("Content-Type", "application/json")), 2, json!({
            "group_name": "self-revoke-group", "can_read": true, "can_write": true,
            "can_delete": true, "can_manage": true
        }).to_string());
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "a manager must not restore a verb it just dropped — self-targeting is bounded, not free"
    );

    // Self-revocation through the dedicated endpoint: surrender the group entirely.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri(format!("/api/keys/{manager_id}/permissions/self-revoke-group"))
        .header("X-API-Key", &manager_key)), 3, "");
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::NO_CONTENT,
        "a manager may drop its own access to a group it manages"
    );

    let remaining = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .filter(simply_ip_vault::entities::api_key_group_permission::Column::ApiKeyId.eq(manager_id))
        .all(&db)
        .await
        .unwrap();
    assert!(remaining.is_empty(), "the row is genuinely gone, not merely reported as removed");

    // Having surrendered the group, the manager is now outside the entry gate like anyone else.
    let (other_id, _other_key) = insert_key(&db, "Other", false, false, false, false).await;
    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{other_id}/permissions"))
        .header("X-API-Key", &manager_key)
        .header("Content-Type", "application/json")), 4, json!({
            "group_name": "self-revoke-group", "can_read": true, "can_write": false, "can_delete": false
        }).to_string());
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "self-revocation is a one-way door: the manager cannot re-grant itself back in"
    );
}

/// A group with no permission rows at all must stay visible and manageable by a master.
///
/// This is the counterpart safeguard to self-revocation. Now that the last manager of a group can
/// drop its own access, a group can reach a state where **no key holds any row on it**. If a
/// master's view were assembled from `api_key_group_permissions`, such a group would vanish from
/// every endpoint at that moment — recoverable only by someone with direct database access, which
/// is precisely the situation an admin API exists to avoid.
///
/// It does not vanish, because every read path branches on `is_master` *before* consulting the
/// permission table rather than filtering by a row the master never has. This asserts that end to
/// end, through the state the new revoke rule makes reachable.
#[tokio::test]
async fn a_group_left_ungoverned_by_self_revocation_stays_visible_to_a_master() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (manager_id, manager_key) = insert_key(&db, "Sole manager", false, true, false, false).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{manager_id}/permissions"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "group_name": "orphaned-group", "can_read": true, "can_write": true,
            "can_delete": true, "can_manage": true
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Put an address in it, so "view" has something to be wrong about.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &manager_key)
        .header("Content-Type", "application/json")), 1, json!({
            "target_address": "203.0.113.77", "group_name": "orphaned-group", "cause": "before orphaning"
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // The last manager surrenders the group. Nothing governs it now.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri(format!("/api/keys/{manager_id}/permissions/orphaned-group"))
        .header("X-API-Key", &manager_key)), 2, "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);

    let rows = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .all(&db)
        .await
        .unwrap();
    assert!(rows.is_empty(), "precondition: the group is genuinely ungoverned");

    // 1. The master can still LIST it.
    let req = signed_later(inject_connect_info(Request::builder()
        .uri("/api/groups")
        .header("X-API-Key", &master_key)), 3, "");
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let groups: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    let listed: Vec<&str> =
        groups.as_array().unwrap().iter().filter_map(|g| g["name"].as_str()).collect();
    assert!(
        listed.contains(&"orphaned-group"),
        "an ungoverned group must not disappear from the master's listing: {listed:?}"
    );

    // 2. The master can still VIEW its contents.
    let req = signed_later(inject_connect_info(Request::builder()
        .uri("/api/ips?group_name=orphaned-group")
        .header("X-API-Key", &master_key)), 4, "");
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ips: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    let addresses: Vec<&str> =
        ips.as_array().unwrap().iter().filter_map(|r| r["target_address"].as_str()).collect();
    assert!(
        addresses.contains(&"203.0.113.77"),
        "the master must still see the ungoverned group's records: {addresses:?}"
    );

    // 3. The master can still RE-GRANT on it, so the group is recoverable through the API.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{manager_id}/permissions"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), 5, json!({
            "group_name": "orphaned-group", "can_read": true, "can_write": true,
            "can_delete": true, "can_manage": true
        }).to_string());
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK,
        "a master must be able to put a group back under management"
    );

    // ...and the re-grant is real: the manager can reach the group again.
    let req = signed_later(inject_connect_info(Request::builder()
        .uri("/api/ips?group_name=orphaned-group")
        .header("X-API-Key", &manager_key)), 6, "");
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ips: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    assert_eq!(ips.as_array().unwrap().len(), 1, "the restored manager sees the group again");
}

/// Inserts a permission row directly, including the administrative flag.
///
/// Bypasses the API on purpose: several tests below need a caller holding **only** per-group
/// `can_manage` and no global scope, which is precisely the state the grant endpoint refuses to
/// create for a non-`can_manage_keys` caller. Seeding it directly is what lets the tests assert what
/// that state can and cannot do, rather than asserting how it is reached.
async fn grant_perm(
    db: &DatabaseConnection,
    key_id: Uuid,
    group_id: Uuid,
    read: bool,
    write: bool,
    del: bool,
    manage: bool,
) {
    simply_ip_vault::entities::api_key_group_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(key_id),
        group_id: Set(group_id),
        can_read: Set(read),
        can_write: Set(write),
        can_delete: Set(del),
        can_manage: Set(manage),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(db)
    .await
    .unwrap();
}

/// Creates a named group directly and returns its id.
async fn insert_group_row(db: &DatabaseConnection, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(id),
        name: Set(name.to_owned()),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(db)
    .await
    .unwrap();
    id
}

/// **R2 — neither half of the conjunction is sufficient alone.**
///
/// `RBAC_MODEL.md` R2: "Managing a specific resource requires holding both global `can_manage_keys`
/// AND a `can_manage = true` row for that specific resource. Neither alone is sufficient.
/// `can_manage_keys` is never a global bypass of per-resource RBAC."
///
/// This asserts the resource half in isolation, which is the half that used to be enough: a steward
/// holding `can_manage = true` and **no global scope whatsoever** could revoke, on the reasoning that
/// removing a verb raises nobody's authority. That reasoning is about escalation, and revocation is
/// not an escalation problem — it is an integrity one. §1 draws the tier boundary instead: a Daughter
/// key (no `can_manage_keys`) "may never" manage resources, in either direction.
///
/// The control at the end is what stops this passing for the wrong reason: the identical operation,
/// from a caller that holds *both* halves, succeeds.
#[tokio::test]
async fn per_group_can_manage_alone_confers_no_authority() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    // No global scopes whatsoever — not even can_manage_keys. Its entire authority is the row.
    let (steward_id, steward_key) = insert_key(&db, "Group steward", false, false, false, false).await;
    let (worker_id, _worker_key) = insert_key(&db, "Worker", false, false, false, false).await;

    let group_id = insert_group_row(&db, "stewarded-group").await;
    grant_perm(&db, steward_id, group_id, true, true, true, true).await;
    grant_perm(&db, worker_id, group_id, true, true, true, false).await;

    // REVOKE — refused. This is the assertion that inverted under R2.
    let req = signed(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri(format!("/api/keys/{worker_id}/permissions/stewarded-group"))
        .header("X-API-Key", &steward_key)), "");
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "can_manage without can_manage_keys must not permit revoking"
    );

    // GRANT — refused too, so the refusal is not direction-specific.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{worker_id}/permissions"))
        .header("X-API-Key", &steward_key)
        .header("Content-Type", "application/json")), 1, json!({
            "group_name": "stewarded-group", "can_read": true, "can_write": true, "can_delete": true
        }).to_string());
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "can_manage without can_manage_keys must not permit granting either"
    );

    // Lowering a row through the update endpoint is a revocation reached by another route (R6), and
    // is refused on exactly the same terms — the classification decides which *extra* rule applies,
    // never whether R2 applies at all.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{worker_id}/permissions"))
        .header("X-API-Key", &steward_key)
        .header("Content-Type", "application/json")), 2, json!({
            "group_name": "stewarded-group", "can_read": false, "can_write": false, "can_delete": false
        }).to_string());
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "a reduction through the update endpoint is governed by R2 like any other reduction"
    );

    let untouched = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .filter(simply_ip_vault::entities::api_key_group_permission::Column::ApiKeyId.eq(worker_id))
        .one(&db)
        .await
        .unwrap()
        .expect("the worker's row survives every refused attempt");
    assert!(
        untouched.can_read && untouched.can_write && untouched.can_delete,
        "the refusals blocked the writes rather than merely reporting a failure"
    );

    // Control: the same steward, with the missing half added, may do both. Without this the test
    // would pass just as well against a build where revocation had been disabled outright.
    let mut promoted: simply_ip_vault::entities::api_key::ActiveModel =
        simply_ip_vault::entities::prelude::ApiKey::find_by_id(steward_id)
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .into();
    promoted.can_manage_keys = Set(true);
    promoted.update(&db).await.unwrap();

    let req = signed_later(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri(format!("/api/keys/{worker_id}/permissions/stewarded-group"))
        .header("X-API-Key", &steward_key)), 3, "");
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::NO_CONTENT,
        "both halves together are the authority; the row alone was never the missing piece"
    );
}

/// **R2 across all four caller classes, side by side**, so the conjunction cannot regress into
/// either of its halves.
///
/// A test that only exercised the "holds both" case would pass just as well against a build that had
/// dropped one half of the check. Each class below is refused (or admitted) for a different reason,
/// and the two middle rows are the ones R2 changed: each holds exactly one half and was previously
/// admitted to at least one direction.
///
/// | Class | `can_manage_keys` | `can_manage` row | Grant | Revoke |
/// | :--- | :--- | :--- | :--- | :--- |
/// | Global-only | ✅ | ❌ | ❌ | ❌ |
/// | Scoped-only | ❌ | ✅ | ❌ | ❌ |
/// | Both | ✅ | ✅ | ✅ (verb-bounded) | ✅ |
/// | Neither | ❌ | ❌ | ❌ | ❌ |
#[tokio::test]
async fn grant_and_revoke_authority_requires_both_halves_of_the_conjunction() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let group_id = insert_group_row(&db, "classes-group").await;

    // Class 1: global `can_manage_keys` and a row on the group, but the row lacks `can_manage`. This
    // was the original grant path in full, and R2 refuses it — `can_manage_keys` is never a global
    // bypass of per-resource RBAC.
    let (global_id, global_key) = insert_key(&db, "Global manager", false, true, false, false).await;
    grant_perm(&db, global_id, group_id, true, true, true, false).await;

    // Class 2: per-group `can_manage`, no global scope. This was the revoke path.
    let (scoped_id, scoped_key) = insert_key(&db, "Scoped manager", false, false, false, false).await;
    grant_perm(&db, scoped_id, group_id, true, true, true, true).await;

    // Class 3: both halves. The only class that may act.
    let (full_id, full_key) = insert_key(&db, "Full manager", false, true, false, false).await;
    grant_perm(&db, full_id, group_id, true, true, true, true).await;

    // Class 4: neither. Ordinary access to the group and no administrative right at all.
    let (plain_id, plain_key) = insert_key(&db, "Plain holder", false, false, false, false).await;
    grant_perm(&db, plain_id, group_id, true, true, true, false).await;

    let (victim_id, _victim_key) = insert_key(&db, "Victim", false, false, false, false).await;

    // `write` selects whether the payload genuinely widens the victim's row. That distinction is the
    // whole subject of the classification: it is by *effect*, so re-submitting a row's existing
    // values is a no-op rather than a grant, and asserting "X cannot grant" against a no-op would
    // pass for the wrong reason (it did, on the first draft of this test).
    let grant_as = |caller: String, nth: i64, write: bool| {
        let app = app.clone();
        async move {
            let req = signed_later(inject_connect_info(Request::builder()
                .method("POST")
                .uri(format!("/api/keys/{victim_id}/permissions"))
                .header("X-API-Key", &caller)
                .header("Content-Type", "application/json")), nth, json!({
                    "group_name": "classes-group", "can_read": true, "can_write": write, "can_delete": false
                }).to_string());
            app.oneshot(req).await.unwrap().status()
        }
    };
    let revoke_as = |caller: String, nth: i64| {
        let app = app.clone();
        async move {
            let req = signed_later(inject_connect_info(Request::builder()
                .method("DELETE")
                .uri(format!("/api/keys/{victim_id}/permissions/classes-group"))
                .header("X-API-Key", &caller)), nth, "");
            app.oneshot(req).await.unwrap().status()
        }
    };

    // Every refusal is asserted first, while no row exists for the victim, so a grant refusal cannot
    // be mistaken for a 404 on a missing row.
    assert_eq!(grant_as(plain_key.clone(), 1, false).await, StatusCode::FORBIDDEN, "neither half: no grant");
    assert_eq!(grant_as(global_key.clone(), 2, false).await, StatusCode::FORBIDDEN, "can_manage_keys alone: no grant");
    assert_eq!(grant_as(scoped_key.clone(), 3, false).await, StatusCode::FORBIDDEN, "can_manage alone: no grant");

    // Class 3 grants. Creates the victim's row as read-only.
    assert_eq!(grant_as(full_key.clone(), 4, false).await, StatusCode::OK, "both halves grant");

    // Now that a row exists, every class is asked to revoke it.
    assert_eq!(revoke_as(plain_key, 5).await, StatusCode::FORBIDDEN, "neither half: no revoke");
    assert_eq!(revoke_as(global_key.clone(), 6).await, StatusCode::FORBIDDEN, "can_manage_keys alone: no revoke");
    assert_eq!(revoke_as(scoped_key.clone(), 7).await, StatusCode::FORBIDDEN, "can_manage alone: no revoke");

    // Widening is refused for the same two classes, so the refusal is not specific to row creation.
    assert_eq!(grant_as(global_key, 8, true).await, StatusCode::FORBIDDEN, "can_manage_keys alone: no widening");
    assert_eq!(grant_as(scoped_key, 9, true).await, StatusCode::FORBIDDEN, "can_manage alone: no widening");

    // The row survived every refusal, so the 403s blocked writes rather than reporting them.
    let survived = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .filter(simply_ip_vault::entities::api_key_group_permission::Column::ApiKeyId.eq(victim_id))
        .one(&db)
        .await
        .unwrap()
        .expect("the victim's row is still there");
    assert!(survived.can_read && !survived.can_write, "unchanged since class 3 created it");

    // Class 3 widens and then revokes, so neither direction was disabled outright.
    assert_eq!(grant_as(full_key.clone(), 10, true).await, StatusCode::OK, "both halves widen");
    assert_eq!(revoke_as(full_key, 11).await, StatusCode::NO_CONTENT, "both halves revoke");
    assert!(
        simply_ip_vault::entities::api_key_group_permission::Entity::find()
            .filter(simply_ip_vault::entities::api_key_group_permission::Column::ApiKeyId.eq(victim_id))
            .one(&db)
            .await
            .unwrap()
            .is_none(),
        "and the revocation genuinely removed the row"
    );
    let _ = (full_id, scoped_id, global_id, plain_id);
}

/// `can_manage` is itself a verb, so it cannot be conferred by someone who does not hold it.
///
/// Without this the flag would spread: any `can_manage_keys` holder with a row on a group could mint
/// group administrators, and the scoping would describe who *currently* holds the right rather than
/// who a master decided should.
#[tokio::test]
async fn can_manage_cannot_be_conferred_by_a_caller_who_lacks_it() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let group_id = insert_group_row(&db, "manage-verb-group").await;

    // A full key manager, with every read/write/delete verb — but not the administrative one.
    let (mgr_id, mgr_key) = insert_key(&db, "Manager", false, true, false, false).await;
    grant_perm(&db, mgr_id, group_id, true, true, true, false).await;
    let (target_id, _target_key) = insert_key(&db, "Target", false, false, false, false).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{target_id}/permissions"))
        .header("X-API-Key", &mgr_key)
        .header("Content-Type", "application/json")), json!({
            "group_name": "manage-verb-group",
            "can_read": true, "can_write": false, "can_delete": false, "can_manage": true
        }).to_string());
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "a caller without can_manage must not be able to confer it"
    );

    // A master can, and the flag lands as requested.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{target_id}/permissions"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), 1, json!({
            "group_name": "manage-verb-group",
            "can_read": true, "can_write": false, "can_delete": false, "can_manage": true
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let landed = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .filter(simply_ip_vault::entities::api_key_group_permission::Column::ApiKeyId.eq(target_id))
        .one(&db)
        .await
        .unwrap()
        .expect("the grant landed");
    assert!(landed.can_manage, "a master may confer the administrative flag");

    // Omitting the field entirely means "no administrative right", not "leave it alone" — the
    // serde default has to be false, or every legacy client silently starts granting it.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{target_id}/permissions"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), 2, json!({
            "group_name": "manage-verb-group", "can_read": true, "can_write": false, "can_delete": false
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let after = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .filter(simply_ip_vault::entities::api_key_group_permission::Column::ApiKeyId.eq(target_id))
        .one(&db)
        .await
        .unwrap()
        .expect("the row survives");
    assert!(!after.can_manage, "a payload omitting can_manage confers none");
}

/// A group left ungoverned via the dedicated revoke route stays visible to a master.
///
/// The other ungoverned-group test reaches that state by lowering a row through the *update*
/// endpoint. This one reaches it through `DELETE .../permissions/{group}`, because R6 requires the
/// two routes to be governed identically and a master's view must not depend on which one got there.
#[tokio::test]
async fn a_group_left_ungoverned_via_per_group_manage_stays_visible_to_a_master() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    // R2's conjunction: `can_manage_keys` plus the `can_manage` row granted below. Before R2 this
    // fixture held no global scope at all, which is exactly the case R2 closed.
    let (steward_id, steward_key) = insert_key(&db, "Sole steward", false, true, false, false).await;

    let group_id = insert_group_row(&db, "steward-orphaned").await;
    grant_perm(&db, steward_id, group_id, true, true, true, true).await;

    // Something to look at once the group is ungoverned.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &steward_key)
        .header("Content-Type", "application/json")), json!({
            "target_address": "203.0.113.91", "group_name": "steward-orphaned", "cause": "pre-orphan"
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Self-revocation through the scoped gate, with no global scope anywhere in play.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri(format!("/api/keys/{steward_id}/permissions/steward-orphaned"))
        .header("X-API-Key", &steward_key)), 1, "");
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::NO_CONTENT,
        "a manager may surrender its own row through the dedicated route"
    );

    let rows = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .all(&db)
        .await
        .unwrap();
    assert!(rows.is_empty(), "precondition: the group is genuinely ungoverned");

    // The master still sees it, can read its records, and can put it back under management.
    let req = signed_later(inject_connect_info(Request::builder()
        .uri("/api/groups")
        .header("X-API-Key", &master_key)), 2, "");
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let groups: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    let listed: Vec<&str> =
        groups.as_array().unwrap().iter().filter_map(|g| g["name"].as_str()).collect();
    assert!(listed.contains(&"steward-orphaned"), "still listed for a master: {listed:?}");

    let req = signed_later(inject_connect_info(Request::builder()
        .uri("/api/ips?group_name=steward-orphaned")
        .header("X-API-Key", &master_key)), 3, "");
    let resp = app.clone().oneshot(req).await.unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    let ips: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(resp.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    assert_eq!(ips.as_array().unwrap().len(), 1, "the master still sees the records");

    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{steward_id}/permissions"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), 4, json!({
            "group_name": "steward-orphaned",
            "can_read": true, "can_write": true, "can_delete": true, "can_manage": true
        }).to_string());
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK,
        "a master can restore a group orphaned through the scoped path"
    );
}

/// `GET /api/audit-logs` is master-only and returns populated entries after mutations, filterable
/// by action.
#[tokio::test]
async fn test_audit_log_query_returns_entries_after_mutations() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (_sub_id, sub_key) = insert_key(&db, "Sub", false, false, false, false).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "target_address": "88.1.1.1", "group_name": "audit-check-group" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Non-master keys cannot view audit logs, even with other broad global scopes.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/audit-logs")
        .header("X-API-Key", &sub_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);

    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/audit-logs?action=IP_ADD")
        .header("X-API-Key", &master_key)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["action"], "IP_ADD");
    assert_eq!(items[0]["target_address"], "88.1.1.1");
    assert_eq!(items[0]["group_names"], "audit-check-group");
}

// ─────────────────────────────────────────────────────────────
// Regression tests: duplicate group creation, flexible group_id,
// and the write/delete-requires-read invariant
// ─────────────────────────────────────────────────────────────

/// `POST /api/groups` must not `500` on a duplicate name — the raw `UNIQUE constraint failed`
/// `DbErr` should be caught and turned into a clean `409 Conflict`.
#[tokio::test]
async fn test_create_duplicate_group_returns_conflict_not_500() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    // `offset` makes the second attempt a distinct signed request rather than a replay of the
    // first. What is under test is a duplicate group *name*, which is unchanged.
    let make_req = |offset: i64| {
        signed_later(inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/groups")
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json")), offset, json!({ "name": "duplicate-group-test" }).to_string())
    };

    let res = app.clone().oneshot(make_req(0)).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let res = app.clone().oneshot(make_req(1)).await.unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT, "duplicate group name must be 409, not 500");

    // Only one row actually exists — the failed second attempt didn't leave anything behind.
    let count = simply_ip_vault::entities::ip_group::Entity::find()
        .filter(simply_ip_vault::entities::ip_group::Column::Name.eq("duplicate-group-test"))
        .all(&db)
        .await
        .unwrap()
        .len();
    assert_eq!(count, 1);
}

/// `POST /api/keys/{id}/groups` (and its `/permissions` alias) must accept a group's UUID *or*
/// its literal name in the `group_id` field — previously `group_id` was strictly typed as `Uuid`,
/// so a name-shaped string there failed Axum's deserialization with `422` before the handler ran.
#[tokio::test]
async fn test_group_permission_assignment_accepts_uuid_or_name_in_group_id_field() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (key_e_id, _key_e) = insert_key(&db, "Key_E", false, false, false, false).await;
    let (key_f_id, _key_f) = insert_key(&db, "Key_F", false, false, false, false).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/groups")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({ "name": "flex-id-group" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let group_uuid = created["id"].as_str().unwrap().to_owned();

    // A NAME string in the group_id field — previously a guaranteed 422.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_e_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "group_id": "flex-id-group",
            "can_read": true,
            "can_write": false,
            "can_delete": false
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // An actual UUID string in the group_id field, via the /permissions alias.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_f_id}/permissions"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "group_id": group_uuid,
            "can_read": true,
            "can_write": true,
            "can_delete": false
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Both grants landed on the exact same group.
    let perms = simply_ip_vault::entities::api_key_group_permission::Entity::find().all(&db).await.unwrap();
    let group_ids: std::collections::HashSet<String> = perms.iter().map(|p| p.group_id.to_string()).collect();
    assert_eq!(group_ids.len(), 1);
    assert_eq!(group_ids.into_iter().next().unwrap(), group_uuid);
}

/// `can_write`/`can_delete` without `can_read` violates AGENT.MD's least-privilege rule and must
/// be rejected with `400`, not silently persisted as a nonsensical grant.
#[tokio::test]
async fn test_group_permission_write_or_delete_requires_read() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (key_id, _key_plain) = insert_key(&db, "Key_G", false, false, false, false).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "group_name": "no-read-group",
            "can_read": false,
            "can_write": true,
            "can_delete": false
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::BAD_REQUEST);

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "group_name": "no-read-group",
            "can_read": false,
            "can_write": false,
            "can_delete": true
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::BAD_REQUEST);

    // can_read alone, or read+write together, are both fine.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{key_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "group_name": "no-read-group",
            "can_read": true,
            "can_write": true,
            "can_delete": false
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
}

// ─────────────────────────────────────────────────────────────
// Conflict detection, group_name assignment, audit log pagination,
// and a dedicated strict bound-IP rejection scenario
// ─────────────────────────────────────────────────────────────

/// The same address can legitimately belong to a `banlist` group and a `whitelist` group at
/// once; `GET /api/ips` must expose both memberships as separate rows (one per group), each
/// carrying its own `group_type`, so the dashboard's client-side conflict indicator
/// (`findConflictingAddresses` in `static/app.js`) has the data it needs to flag it. A response
/// that deduplicated/merged the two memberships into one row would silently break that feature.
#[tokio::test]
async fn test_multi_group_overlap_exposes_both_memberships_for_conflict_detection() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "target_address": "192.0.2.200",
            "group_name": "conflict-banlist",
            "cause": "flagged as hostile"
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/white")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "target_address": "192.0.2.200",
            "group_name": "conflict-whitelist",
            "cause": "also a trusted partner"
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/ips?ip=192.0.2.200")
        .header("X-API-Key", &master_key)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();

    assert_eq!(items.len(), 2, "both memberships must be exposed as separate rows: {items:?}");
    assert!(items.iter().all(|i| i["target_address"] == "192.0.2.200"));
    let mut group_types: Vec<&str> = items.iter().map(|i| i["group_type"].as_str().unwrap()).collect();
    group_types.sort_unstable();
    assert_eq!(group_types, vec!["banlist", "whitelist"]);
}

/// Assigning group rights via a literal `group_name` (e.g. a realistic fail2ban jail name) must
/// work exactly as well as via `group_id`, including when both are used to grant different keys
/// access to the very same group in the same test.
#[tokio::test]
async fn test_group_permission_assignment_via_group_name_alongside_uuid() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (name_key_id, name_key) = insert_key(&db, "fail2ban-nginx-name-grant", false, false, false, false).await;
    let (uuid_key_id, uuid_key) = insert_key(&db, "fail2ban-nginx-uuid-grant", false, false, false, false).await;

    // Seed the group into existence via a normal ban, using a realistic fail2ban-style name.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "target_address": "198.51.100.77",
            "group_name": "fail2ban_nginx",
            "cause": "nginx probing"
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/groups")
        .header("X-API-Key", &master_key)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let groups: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
    let group_id = groups.iter().find(|g| g["name"] == "fail2ban_nginx").unwrap()["id"].as_str().unwrap().to_owned();

    // Grant via the literal group_name field.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{name_key_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "group_name": "fail2ban_nginx",
            "can_read": true,
            "can_write": true,
            "can_delete": false
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Grant a DIFFERENT key on the SAME group via its UUID, seamlessly alongside the name grant.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{uuid_key_id}/groups"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), json!({
            "group_id": group_id,
            "can_read": true,
            "can_write": false,
            "can_delete": false
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Both keys can now read the group, and both grants reference the identical group id.
    for key in [&name_key, &uuid_key] {
        let req = signed(inject_connect_info(Request::builder()
            .uri("/api/ips?group_name=fail2ban_nginx")
            .header("X-API-Key", key)), "");
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(items.len(), 1);
    }

    let perms = simply_ip_vault::entities::api_key_group_permission::Entity::find().all(&db).await.unwrap();
    let group_ids: std::collections::HashSet<String> = perms.iter().map(|p| p.group_id.to_string()).collect();
    assert_eq!(group_ids.len(), 1, "the name-grant and the uuid-grant must reference the same group");
    assert_eq!(group_ids.into_iter().next().unwrap(), group_id);
}

/// `GET /api/audit-logs` pagination (`limit`/`offset`) must actually advance the window: two
/// consecutive pages of the same filtered query must return disjoint sets of entries.
#[tokio::test]
async fn test_audit_log_pagination() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    // Six distinct GROUP_CREATE audit entries, so two limit=3 pages fully partition them.
    for i in 0..6 {
        let req = signed(inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/groups")
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json")), json!({ "name": format!("pagination-group-{i}") }).to_string());
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
    }

    let fetch_page = |offset: u64| {
        let app = app.clone();
        let master_key = master_key.clone();
        async move {
            let req = signed(inject_connect_info(Request::builder()
                .uri(format!("/api/audit-logs?action=GROUP_CREATE&limit=3&offset={offset}"))
                .header("X-API-Key", &master_key)), "");
            let res = app.oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            serde_json::from_slice::<Vec<serde_json::Value>>(&body).unwrap()
        }
    };

    let page1 = fetch_page(0).await;
    let page2 = fetch_page(3).await;

    assert_eq!(page1.len(), 3, "page 1 (offset=0) must have exactly `limit` entries: {page1:?}");
    assert_eq!(page2.len(), 3, "page 2 (offset=3) must have exactly `limit` entries: {page2:?}");

    let page1_ids: std::collections::HashSet<&str> = page1.iter().map(|e| e["id"].as_str().unwrap()).collect();
    let page2_ids: std::collections::HashSet<&str> = page2.iter().map(|e| e["id"].as_str().unwrap()).collect();
    assert!(page1_ids.is_disjoint(&page2_ids), "page 1 and page 2 must not overlap: {page1_ids:?} vs {page2_ids:?}");
    assert_eq!(page1_ids.union(&page2_ids).count(), 6, "together the two pages cover all 6 entries exactly once");
}

/// Dedicated strict scenario: a key bound to `127.0.0.1/32` must be rejected — with exactly the
/// `403 Client IP not allowed` the middleware documents — when the (proxy-supplied) client
/// address is `203.0.113.50`, nowhere near the bound range.
#[tokio::test]
async fn test_bound_ip_strictly_rejects_out_of_cidr_forwarded_address() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = proxied_state(&db, webhook_tx);
    let app = create_app(state);

    let (_id, restricted_key) = insert_key_with_bound_ips(&db, "loopback-only", "127.0.0.1/32").await;

    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &restricted_key)
        .header("X-Forwarded-For", "203.0.113.50")), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::FORBIDDEN);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["error"], "Client IP not allowed");

    // Sanity check: the same key from the bound address itself is let through. Only the unsigned
    // X-Forwarded-For header differs from the rejected call above, so this is stamped a second later.
    let req = signed_later(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &restricted_key)
        .header("X-Forwarded-For", "127.0.0.1")), 1, "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
}

/// `GET /api/ips?format=iplist` (and its `mode=iplist` synonym) returns `{"ip_list": [...]}` —
/// just the addresses, de-duplicated, not full records. The same address banned into two
/// different groups must appear exactly once in the list, even though it matches two separate
/// `ip_record_group_membership` rows.
#[tokio::test]
async fn test_list_ips_iplist_format_returns_deduplicated_address_list() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    let ban = |addr: &'static str, group: &'static str| {
        signed(inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/ban")
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json")), json!({ "target_address": addr, "group_name": group }).to_string())
    };

    assert_eq!(app.clone().oneshot(ban("198.51.100.1", "iplist-group-a")).await.unwrap().status(), StatusCode::OK);
    assert_eq!(app.clone().oneshot(ban("198.51.100.2", "iplist-group-a")).await.unwrap().status(), StatusCode::OK);
    // Same address as the first, but in a SECOND group — must still only appear once in ip_list.
    assert_eq!(app.clone().oneshot(ban("198.51.100.1", "iplist-group-b")).await.unwrap().status(), StatusCode::OK);

    for query in ["format=iplist", "mode=iplist"] {
        let req = signed(inject_connect_info(Request::builder()
            .uri(format!("/api/ips?groups=iplist-group-a,iplist-group-b&{query}"))
            .header("X-API-Key", &master_key)), "");
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK, "query string was `{query}`");
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let ip_list = parsed["ip_list"].as_array().expect("ip_list must be an array");
        let addresses: Vec<&str> = ip_list.iter().map(|v| v.as_str().unwrap()).collect();
        assert_eq!(addresses.len(), 2, "query string was `{query}`: expected exactly 2 unique addresses, got {addresses:?}");
        assert!(addresses.contains(&"198.51.100.1"));
        assert!(addresses.contains(&"198.51.100.2"));
        // No other fields (id, cause, group_name, ...) leak into the lightweight response.
        assert!(parsed.get("id").is_none() && parsed.as_object().unwrap().len() == 1);
    }
}

/// `GET /api/ips` without `include_total` must keep returning the bare root array — the
/// historical contract every existing exporter/sync worker parses. `include_total` is opt-in
/// precisely so this shape never changes underneath a client that never asked for the envelope.
#[tokio::test]
async fn test_list_ips_without_include_total_returns_bare_array() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    let ban = |addr: &'static str| {
        signed(inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/ban")
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json")), json!({ "target_address": addr, "group_name": "no-envelope-group" }).to_string())
    };
    assert_eq!(app.clone().oneshot(ban("203.0.113.10")).await.unwrap().status(), StatusCode::OK);

    // Omitted entirely.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/ips?groups=no-envelope-group")
        .header("X-API-Key", &master_key)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(parsed.is_array(), "expected a bare array with include_total omitted, got {parsed:?}");
    assert_eq!(parsed.as_array().unwrap().len(), 1);

    // Explicit `false` behaves identically to omission.
    let req = signed_later(inject_connect_info(Request::builder()
        .uri("/api/ips?groups=no-envelope-group&include_total=false")
        .header("X-API-Key", &master_key)), 1, "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert!(parsed.is_array(), "expected a bare array with include_total=false, got {parsed:?}");
}

/// `GET /api/ips?include_total=true` wraps the response in `{data, total, limit, offset,
/// total_pages}`, with `total`/`total_pages` computed across every page, not just the one
/// returned — a page of 3 out of 7 records must still report the full 7.
#[tokio::test]
async fn test_list_ips_include_total_returns_accurate_envelope() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    for i in 0..7u8 {
        let req = signed_later(inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/ban")
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json")),
            i as i64,
            json!({ "target_address": format!("203.0.114.{i}"), "group_name": "envelope-group" }).to_string());
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
    }

    let req = signed_later(inject_connect_info(Request::builder()
        .uri("/api/ips?groups=envelope-group&limit=3&offset=0&include_total=true")
        .header("X-API-Key", &master_key)), 100, "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(parsed["data"].as_array().unwrap().len(), 3, "page size should be respected: {parsed:?}");
    assert_eq!(parsed["total"], 7);
    assert_eq!(parsed["limit"], 3);
    assert_eq!(parsed["offset"], 0);
    assert_eq!(parsed["total_pages"], 3, "ceil(7 / 3) == 3");
    // The envelope's `data` entries are otherwise full `IpRecordResponse` rows, not a stripped shape.
    assert!(parsed["data"][0].get("target_address").is_some());
    assert!(parsed["data"][0].get("group_name").is_some());

    // A page that starts past the end still reports the same total, with an empty `data`.
    let req = signed_later(inject_connect_info(Request::builder()
        .uri("/api/ips?groups=envelope-group&limit=3&offset=6&include_total=true")
        .header("X-API-Key", &master_key)), 101, "");
    let res = app.clone().oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["data"].as_array().unwrap().len(), 1, "record #7 is the only one at offset 6");
    assert_eq!(parsed["total"], 7);
    assert_eq!(parsed["total_pages"], 3);
}

/// `total` under `include_total=true` must respect the same RBAC group-read scoping as `data` —
/// a non-master key counts only the records in groups it holds `can_read` on, never records in a
/// group it cannot see, even though those records genuinely exist in the database.
#[tokio::test]
async fn test_list_ips_include_total_respects_rbac_group_scoping() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (restricted_id, restricted_key) = insert_key(&db, "Restricted", false, false, false, false).await;

    let visible_group = insert_group_row(&db, "rbac-total-visible").await;
    let _hidden_group = insert_group_row(&db, "rbac-total-hidden").await;
    grant_perm(&db, restricted_id, visible_group, true, false, false, false).await;
    // Deliberately no permission row at all for `hidden_group` — the restricted key has no
    // access to it whatsoever, matching §4's "not a member" case rather than "read-denied".

    let ban = |addr: &'static str, group: &'static str| {
        signed(inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/ban")
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json")), json!({ "target_address": addr, "group_name": group }).to_string())
    };
    assert_eq!(app.clone().oneshot(ban("203.0.115.1", "rbac-total-visible")).await.unwrap().status(), StatusCode::OK);
    assert_eq!(app.clone().oneshot(ban("203.0.115.2", "rbac-total-visible")).await.unwrap().status(), StatusCode::OK);
    assert_eq!(app.clone().oneshot(ban("203.0.115.3", "rbac-total-hidden")).await.unwrap().status(), StatusCode::OK);
    assert_eq!(app.clone().oneshot(ban("203.0.115.4", "rbac-total-hidden")).await.unwrap().status(), StatusCode::OK);
    assert_eq!(app.clone().oneshot(ban("203.0.115.5", "rbac-total-hidden")).await.unwrap().status(), StatusCode::OK);

    // Master sees all 5 across both groups.
    let req = signed_later(inject_connect_info(Request::builder()
        .uri("/api/ips?groups=rbac-total-visible,rbac-total-hidden&include_total=true")
        .header("X-API-Key", &master_key)), 1, "");
    let res = app.clone().oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["total"], 5, "master should count both groups: {parsed:?}");

    // The restricted key, asking for the same two groups by name, sees only the 2 it can read —
    // never an error and never the hidden group's 3, matching §4 oracle discipline.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/ips?groups=rbac-total-visible,rbac-total-hidden&include_total=true")
        .header("X-API-Key", &restricted_key)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["total"], 2, "restricted key must not count the hidden group's records: {parsed:?}");
    assert_eq!(parsed["data"].as_array().unwrap().len(), 2);

    // A restricted key with no readable groups at all still gets `200` with an empty, zeroed
    // envelope, not an error — the same early-return path `format=iplist` and the bare array take.
    let (_isolated_id, isolated_key) = insert_key(&db, "Isolated", false, false, false, false).await;
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/ips?include_total=true")
        .header("X-API-Key", &isolated_key)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["total"], 0);
    assert_eq!(parsed["total_pages"], 0);
    assert_eq!(parsed["data"].as_array().unwrap().len(), 0);
}

/// `GET /api/ips` must order results by `updated_at DESC` — the most recently added or
/// re-registered record always sorts first, regardless of insertion order.
#[tokio::test]
async fn test_list_ips_orders_by_updated_at_descending() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    // Both closures take a timestamp offset: this test issues the same ban twice and the same
    // listing twice, and a repeat with an unchanged timestamp is a byte-identical signature that
    // the anti-replay guard refuses. A real client re-registering an address gets the later
    // timestamp from the clock; here it is stated explicitly.
    let ban = |addr: &'static str, offset: i64| {
        signed_later(inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/ban")
            .header("X-API-Key", &master_key)
            .header("Content-Type", "application/json")), offset, json!({ "target_address": addr, "group_name": "ordering-group" }).to_string())
    };

    // Created in order A, B, C — freshly created, so C (most recent) should sort first.
    for addr in ["203.0.113.101", "203.0.113.102", "203.0.113.103"] {
        assert_eq!(app.clone().oneshot(ban(addr, 0)).await.unwrap().status(), StatusCode::OK);
    }

    let list = |app: &axum::Router, master_key: &str, offset: i64| {
        let app = app.clone();
        let master_key = master_key.to_owned();
        async move {
            let req = signed_later(inject_connect_info(Request::builder()
                .uri("/api/ips?groups=ordering-group")
                .header("X-API-Key", &master_key)), offset, "");
            let res = app.oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            let items: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
            items.into_iter().map(|i| i["target_address"].as_str().unwrap().to_owned()).collect::<Vec<_>>()
        }
    };

    let addresses = list(&app, &master_key, 0).await;
    assert_eq!(addresses, vec!["203.0.113.103", "203.0.113.102", "203.0.113.101"], "most recently created sorts first");

    // Re-register the OLDEST one (.101) — it must now jump to the front, since its updated_at is
    // now the most recent of the three.
    assert_eq!(app.clone().oneshot(ban("203.0.113.101", 1)).await.unwrap().status(), StatusCode::OK);

    let addresses = list(&app, &master_key, 1).await;
    assert_eq!(addresses, vec!["203.0.113.101", "203.0.113.103", "203.0.113.102"], "re-registered record jumps to the front");
}

// ─────────────────────────────────────────────────────────────
// HMAC-SHA256 authentication & anti-replay guard
// ─────────────────────────────────────────────────────────────

/// Every one of the three auth headers is individually mandatory: dropping any single one must
/// produce `401`, so no combination of two can ever authenticate a request on its own.
#[tokio::test]
async fn test_each_auth_header_is_individually_required() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_id, key) = insert_key(&db, "Signer", true, true, true, true).await;
    let secret = test_signing_secret(&key);

    // Control: all three headers present and correct.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let now = chrono::Utc::now().timestamp().to_string();
    let signature = simply_ip_vault::crypto::compute_signature(
        &secret, "GET", "/api/auth/me", &now, b"",
    ).unwrap();

    // Missing X-API-Key (timestamp + signature present).
    let req = inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-Timestamp", &now)
        .header("X-Signature-256", &signature))
        .body(Body::empty()).unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // Missing X-Timestamp (key + signature present).
    let req = inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &key)
        .header("X-Signature-256", &signature))
        .body(Body::empty()).unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // Missing X-Signature-256 (key + timestamp present) — i.e. exactly the pre-HMAC request shape,
    // which must no longer be sufficient.
    let req = inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &key)
        .header("X-Timestamp", &now))
        .body(Body::empty()).unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // A malformed (non-numeric) timestamp is rejected rather than treated as 0 or as "now".
    let req = inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &key)
        .header("X-Timestamp", "not-a-number")
        .header("X-Signature-256", &signature))
        .body(Body::empty()).unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
}

/// The anti-replay window is +/- 300 seconds and symmetric: a captured request replayed later is
/// rejected, and so is one timestamped in the future (which is what a replay attacker would forge
/// to extend a captured request's usable lifetime).
#[tokio::test]
async fn test_anti_replay_timestamp_window_is_enforced_in_both_directions() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_id, key) = insert_key(&db, "Replay", true, true, true, true).await;
    let secret = test_signing_secret(&key);

    // The clock is read *per call*, not once up front. Reading it once made every offset drift
    // toward "stale" by however long the preceding calls took, so under a loaded `cargo test` the
    // -290 case could arrive at -300 (the boundary) and the +301 case at +300 (inside the window) —
    // a real intermittent failure, observed rather than theorised.
    let call = |offset: i64| {
        let app = app.clone();
        let key = key.clone();
        let secret = secret.clone();
        async move {
            let ts = chrono::Utc::now().timestamp() + offset;
            let req = signed_at(inject_connect_info(Request::builder()
                .uri("/api/auth/me")
                .header("X-API-Key", &key)), &secret, ts, "");
            app.oneshot(req).await.unwrap().status()
        }
    };

    // Comfortably inside the window, in both directions, is accepted.
    assert_eq!(call(0).await, StatusCode::OK);
    assert_eq!(call(-290).await, StatusCode::OK, "290s stale is within the 300s window");
    assert_eq!(call(290).await, StatusCode::OK, "290s ahead is within the 300s window");

    // Outside it, in both directions, is rejected — with a correct signature, proving the
    // rejection comes from the freshness check and not from the HMAC.
    assert_eq!(call(-301).await, StatusCode::UNAUTHORIZED, "stale request is a replay");
    assert_eq!(call(301).await, StatusCode::UNAUTHORIZED, "future-dated request is rejected");
    assert_eq!(call(-86_400).await, StatusCode::UNAUTHORIZED, "day-old capture is rejected");
}

/// The signature must genuinely bind method, path and body — not merely prove key possession.
/// Each case below replays an *authentic* signature against a different request.
#[tokio::test]
async fn test_signature_binds_method_path_and_body() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_id, key) = insert_key(&db, "Binder", true, true, true, true).await;
    let secret = test_signing_secret(&key);
    let now = chrono::Utc::now().timestamp().to_string();

    let body = json!({ "target_address": "51.51.51.51", "group_name": "sig-bind-group" }).to_string();
    let authentic = simply_ip_vault::crypto::compute_signature(
        &secret, "POST", "/api/ban", &now, body.as_bytes(),
    ).unwrap();

    // Sanity: the authentic signature works for the exact request it was made for.
    let req = inject_connect_info(Request::builder()
        .method("POST").uri("/api/ban")
        .header("X-API-Key", &key)
        .header("Content-Type", "application/json")
        .header("X-Timestamp", &now)
        .header("X-Signature-256", &authentic))
        .body(Body::from(body.clone())).unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // Same signature, tampered body: an attacker swapping the target address is caught.
    let tampered = json!({ "target_address": "9.9.9.9", "group_name": "sig-bind-group" }).to_string();
    let req = inject_connect_info(Request::builder()
        .method("POST").uri("/api/ban")
        .header("X-API-Key", &key)
        .header("Content-Type", "application/json")
        .header("X-Timestamp", &now)
        .header("X-Signature-256", &authentic))
        .body(Body::from(tampered)).unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // Same signature, different path: a POST /api/ban signature cannot be replayed onto
    // /api/white, which would flip a ban into a whitelist entry.
    let req = inject_connect_info(Request::builder()
        .method("POST").uri("/api/white")
        .header("X-API-Key", &key)
        .header("Content-Type", "application/json")
        .header("X-Timestamp", &now)
        .header("X-Signature-256", &authentic))
        .body(Body::from(body.clone())).unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // Garbage and empty signatures fail closed rather than erroring out.
    for bogus in ["", "not-hex", "deadbeef"] {
        let req = inject_connect_info(Request::builder()
            .method("POST").uri("/api/ban")
            .header("X-API-Key", &key)
            .header("Content-Type", "application/json")
            .header("X-Timestamp", &now)
            .header("X-Signature-256", bogus))
            .body(Body::from(body.clone())).unwrap();
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "bogus signature {bogus:?} must be rejected"
        );
    }
}

/// A key signed with the *wrong* key's secret must not authenticate, even though both keys exist
/// and both secrets are individually valid. Guards against the signature ever being verified
/// against something other than the looked-up key's own secret.
#[tokio::test]
async fn test_signature_must_match_the_looked_up_key() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    // Deliberately *not* masters. Nothing here depends on scope — `/api/auth/me` authenticates and
    // returns the caller's own identity — and only one master may exist per database now that
    // `api_keys.master_marker` carries a unique index (RBAC_MODEL.md §5), so a fixture that mints two
    // is refused by the schema before the test can even start.
    let (_a_id, key_a) = insert_key(&db, "Key A", false, false, false, false).await;
    let (_b_id, key_b) = insert_key(&db, "Key B", false, false, false, false).await;

    let req = signed_with(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &key_a)), &test_signing_secret(&key_b), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
}

/// A key row predating the `signing_secret` column (NULL) cannot authenticate at all — it fails
/// closed rather than skipping signature verification.
#[tokio::test]
async fn test_key_without_signing_secret_cannot_authenticate() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let plaintext = simply_ip_vault::api::generate_random_key();
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        key_hash: Set(simply_ip_vault::api::hash_key(&plaintext)),
        signing_secret: Set(None), // as left by the additive migration on a pre-existing row
        name: Set("Legacy Key".to_owned()),
        bound_ips: Set(None),
        is_master: Set(true),
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_create_groups: Set(true),
        parent_key_id: Set(None),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }.insert(&db).await.unwrap();

    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &plaintext)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
}

/// End-to-end credential lifecycle: a key minted through `POST /api/keys` comes back with a
/// signing secret that actually works for signing subsequent requests.
#[tokio::test]
async fn test_created_key_returns_a_usable_signing_secret() {
    // Serialized against the VAULT_ENCRYPTION_KEY test: this key's secret is sealed (or not)
    // according to the variable's value at creation time. See ENV_MUTATION_LOCK.
    let _guard = ENV_MUTATION_LOCK.lock().await;
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST").uri("/api/keys")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")),
        json!({ "name": "minted", "bound_ips": "0.0.0.0/0" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let new_key = created["plaintext_key"].as_str().unwrap().to_owned();
    let new_signing_secret = created["signing_secret"].as_str().unwrap().to_owned();
    assert!(!new_signing_secret.is_empty(), "creation must return a signing secret");
    assert_ne!(new_signing_secret, new_key, "the two credentials must be independent values");

    // The returned secret authenticates...
    let req = signed_with(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &new_key)), &new_signing_secret, "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // ...and nothing else does.
    let req = signed_with(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &new_key)), "guessed-secret", "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);
}

/// The signing secret must never appear in any read endpoint's output — only in the one-shot
/// create/rotate responses. `GET /api/keys` and `GET /api/auth/me` are the two that expose key
/// metadata and are therefore the realistic leak paths.
#[tokio::test]
async fn test_signing_secret_is_never_exposed_by_read_endpoints() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_id, key) = insert_key(&db, "Master", true, true, true, true).await;
    let secret = test_signing_secret(&key);

    for path in ["/api/auth/me", "/api/keys"] {
        let req = signed(inject_connect_info(Request::builder()
            .uri(path)
            .header("X-API-Key", &key)), "");
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(!text.contains(&secret), "{path} leaked the signing secret");
        assert!(!text.contains("signing_secret"), "{path} exposed a signing_secret field");
    }
}

/// With an encrypting cipher configured, a key created through the API stores its signing secret
/// encrypted at rest, yet still authenticates — proving the seal/open round trip is wired into the
/// real request path, not just the crypto unit tests.
///
/// The cipher is now handed to `AppState` explicitly rather than read from the environment on every
/// seal and open, so this test no longer needs `ENV_MUTATION_LOCK`: nothing here is process-global,
/// and two cipher modes can be exercised concurrently in one process without racing.
#[tokio::test]
async fn test_signing_secret_is_encrypted_at_rest_when_vault_key_is_set() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let cipher = simply_ip_vault::crypto::SecretCipher::from_hex_key(
        "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
    )
    .expect("a 64-hex-character key is valid");
    let state = AppState::with_parts(db.clone(), webhook_tx, Vec::new(), cipher);
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST").uri("/api/keys")
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")),
        json!({ "name": "sealed", "bound_ips": "0.0.0.0/0" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let new_key = created["plaintext_key"].as_str().unwrap().to_owned();
    let new_signing_secret = created["signing_secret"].as_str().unwrap().to_owned();

    // What landed in the database is ciphertext, not the secret the caller was handed.
    let stored = simply_ip_vault::entities::prelude::ApiKey::find()
        .filter(simply_ip_vault::entities::api_key::Column::KeyHash
            .eq(simply_ip_vault::api::hash_key(&new_key)))
        .one(&db).await.unwrap().unwrap()
        .signing_secret.unwrap();
    assert!(
        stored.starts_with("v1.xchacha20poly1305."),
        "stored secret must be sealed with XChaCha20-Poly1305, got {stored}"
    );
    assert!(!stored.contains(&new_signing_secret), "plaintext secret must not survive in the DB");

    // And it still authenticates, so decryption happens transparently in the middleware.
    let req = signed_with(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &new_key)), &new_signing_secret, "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
}

// ─────────────────────────────────────────────────────────────
// Webhook auth modes (CANONICAL_V1 / BODY_ONLY / API_KEY_ONLY / NONE)
// ─────────────────────────────────────────────────────────────

/// What a mock webhook receiver captured from a single dispatch.
#[derive(Default, Clone)]
struct CapturedHook {
    path: Option<String>,
    body: Option<String>,
    signature: Option<String>,
    timestamp: Option<String>,
    api_key: Option<String>,
    /// A signature arriving under a caller-configured header name rather than the default.
    custom_signature: Option<String>,
}

/// Spawns a loopback mock receiver on an ephemeral port, returning its base URL and the shared slot
/// it records into. Used by the auth-mode tests below in place of the ad-hoc receiver that the
/// older webhook tests each built inline.
///
/// A `fallback` rather than a fixed route, so a test can point `target_url` at any path it likes and
/// still be recorded — which is exactly what the custom-`hmac_template` cases need.
async fn spawn_capturing_receiver() -> (String, std::sync::Arc<std::sync::Mutex<CapturedHook>>) {
    use std::sync::{Arc, Mutex};

    let captured: Arc<Mutex<CapturedHook>> = Arc::new(Mutex::new(CapturedHook::default()));
    let for_handler = captured.clone();

    let hook_app = axum::Router::new().fallback(
        move |uri: axum::http::Uri, headers: axum::http::HeaderMap, body: String| {
            let captured = for_handler.clone();
            async move {
                let header = |name: &str| {
                    headers.get(name).and_then(|h| h.to_str().ok()).map(|s| s.to_owned())
                };
                let mut c = captured.lock().unwrap();
                c.path = Some(uri.path().to_owned());
                c.signature = header("X-Signature-256");
                c.timestamp = header("X-Timestamp");
                c.api_key = header("X-API-Key");
                c.custom_signature = header("X-Hub-Signature-256");
                c.body = Some(body);
                StatusCode::OK
            }
        },
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, hook_app).await.unwrap();
    });

    (format!("http://{addr}"), captured)
}

/// Polls until the receiver records a dispatch, or gives up. Dispatch is asynchronous (channel →
/// background worker → spawned HTTP task), so there is nothing to await directly.
async fn await_dispatch(
    captured: &std::sync::Arc<std::sync::Mutex<CapturedHook>>,
) -> Option<CapturedHook> {
    for _ in 0..40 {
        {
            let c = captured.lock().unwrap();
            if c.body.is_some() {
                return Some(c.clone());
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    None
}

/// Boilerplate shared by the signature-mode tests: a master key, a group, and a running webhook
/// worker wired to the app.
async fn setup_webhook_fixture(
    group_name: &str,
) -> (axum::Router, DatabaseConnection, String, Uuid) {
    let db = setup_test_db().await;
    let (webhook_tx, webhook_rx) = tokio::sync::mpsc::channel(100);
    let db_for_worker = db.clone();
    tokio::spawn(async move {
        simply_ip_vault::dispatch::run_webhook_worker(db_for_worker, webhook_rx).await;
    });

    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_key_id, plaintext) = insert_key(&db, "Webhook Tester", true, true, true, true).await;

    let group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_id),
        name: Set(group_name.to_owned()),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    (app, db, plaintext, group_id)
}

/// A `CANONICAL_V1` webhook must send **both** `X-Signature-256` and `X-Timestamp`, with the
/// signature computed over `POST\n<path>\n<timestamp>\n<body>` — the exact construction the inbound
/// API middleware verifies, which is what makes vault-to-vault dispatch work.
#[tokio::test]
async fn test_canonical_v1_webhook_sends_timestamp_and_canonical_signature() {
    let _env_guard = ENV_MUTATION_LOCK.lock().await;
    unsafe { std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "true") };

    let (base_url, captured) = spawn_capturing_receiver().await;
    let (app, _db, plaintext, group_id) = setup_webhook_fixture("canonical-hook-group").await;

    let secret = "canonical-webhook-secret";
    let hook_url = format!("{base_url}/hook");
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/webhooks")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({
            "name": "Canonical Hook",
            "target_url": hook_url,
            "secret_token": secret,
            "payload_template": "{\"ip\":\"$target_address\"}",
            "group_id": group_id.to_string(),
            "auth_mode": "CANONICAL_V1",
        }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(created["auth_mode"], "CANONICAL_V1", "creation echoes the stored mode");

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")),
        json!({ "target_address": "5.5.5.5", "group_name": "canonical-hook-group" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let hit = await_dispatch(&captured).await.expect("webhook was not delivered within timeout");
    unsafe { std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "false") };

    let delivered_body = hit.body.expect("body");
    let signature = hit.signature.expect("CANONICAL_V1 dispatch must send X-Signature-256");
    let timestamp = hit.timestamp.expect("CANONICAL_V1 dispatch must send X-Timestamp");
    assert!(hit.api_key.is_none(), "no api_key configured means no X-API-Key header at all");

    // The timestamp must be a plausible current epoch, not a placeholder — a receiver's anti-replay
    // window would reject anything else.
    let parsed: i64 = timestamp.parse().expect("X-Timestamp must be an integer epoch");
    let skew = (chrono::Utc::now().timestamp() - parsed).abs();
    assert!(skew < 300, "X-Timestamp should be current, was {skew}s off");

    // `sha256=`-prefixed, byte-identical to what `compute_signature` produces and to what the
    // inbound middleware now requires — which is what makes vault-to-vault dispatch work at all.
    assert!(
        signature.starts_with(simply_ip_vault::crypto::SIGNATURE_PREFIX),
        "CANONICAL_V1 must send the mandatory sha256= prefix, got {signature}"
    );

    let expected = simply_ip_vault::crypto::compute_signature(
        secret, "POST", "/hook", &timestamp, delivered_body.as_bytes(),
    ).unwrap();
    assert_eq!(signature, expected, "signature must cover POST\\npath\\ntimestamp\\nbody");
    assert!(delivered_body.contains("5.5.5.5"));

    // The receiving end of the contract: the same bytes verify through the shared helper, which is
    // literally the function the inbound middleware calls.
    assert!(simply_ip_vault::crypto::verify_signature(
        secret, "POST", "/hook", &timestamp, delivered_body.as_bytes(), &signature,
    ).is_some());
}

/// `HMAC_ONLY` must keep the legacy `BODY_ONLY` behaviour exactly: body-only HMAC, `sha256=` prefix,
/// and **no**
/// `X-Timestamp` or `X-API-Key` header. Guards third-party receivers against a silent change.
#[tokio::test]
async fn test_hmac_only_signs_the_payload_alone_and_sends_neither_timestamp_nor_key() {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    let _env_guard = ENV_MUTATION_LOCK.lock().await;
    unsafe { std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "true") };

    let (base_url, captured) = spawn_capturing_receiver().await;
    let (app, _db, plaintext, group_id) = setup_webhook_fixture("legacy-hook-group").await;

    let secret = "legacy-webhook-secret";
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/webhooks")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({
            "name": "Legacy Hook",
            "target_url": format!("{base_url}/hook"),
            "secret_token": secret,
            "payload_template": "{\"ip\":\"$target_address\"}",
            "group_id": group_id.to_string(),
            // Spelled with the deprecated `signature_mode` alias on purpose: callers written
            // against the previous field must keep working unchanged.
            "signature_mode": "BODY_ONLY",
        }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&body).unwrap();
    // The request used the deprecated `signature_mode: "BODY_ONLY"` spelling and the service
    // normalises it to the current name — which is how a client's stored configuration migrates
    // itself on the next round-trip rather than needing a coordinated edit.
    assert_eq!(created["auth_mode"], "HMAC_ONLY", "the legacy alias still selects the mode");

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")),
        json!({ "target_address": "6.6.6.6", "group_name": "legacy-hook-group" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let hit = await_dispatch(&captured).await.expect("webhook was not delivered within timeout");
    unsafe { std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "false") };

    let delivered_body = hit.body.expect("body");
    let signature = hit.signature.expect("missing X-Signature-256");
    assert!(hit.timestamp.is_none(), "HMAC_ONLY must not send X-Timestamp");
    assert!(
        hit.api_key.is_none(),
        "HMAC_ONLY must send no key header at all — that is the property the mode is named for"
    );

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(delivered_body.as_bytes());
    assert_eq!(signature, format!("sha256={}", hex::encode(mac.finalize().into_bytes())));
}

/// `auth_mode` is validated at the API boundary rather than silently defaulted, and the stored
/// value is surfaced by `GET /api/webhooks` so the UI can display it.
#[tokio::test]
async fn test_auth_mode_is_validated_and_exposed_in_listings() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_key_id, plaintext) = insert_key(&db, "Master", true, true, true, true).await;

    let group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_id),
        name: Set("mode-group".to_owned()),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }.insert(&db).await.unwrap();

    let make = |mode: serde_json::Value, name: &str| {
        let mut payload = json!({
            "name": name,
            "target_url": "https://example.com/hook",
            "secret_token": "s3cret",
            "payload_template": "{}",
            "group_id": group_id.to_string(),
        });
        if !mode.is_null() {
            payload["auth_mode"] = mode;
        }
        signed(inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/webhooks")
            .header("X-API-Key", &plaintext)
            .header("Content-Type", "application/json")), payload.to_string())
    };

    // A typo must be a 400, not a silent downgrade to HMAC_ONLY: a caller who believes they enabled
    // canonical signing would otherwise ship a receiver that rejects every dispatch.
    let res = app.clone().oneshot(make(json!("CANONICAL_V2"), "typo")).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
    let res = app.clone().oneshot(make(json!("nonsense"), "nonsense")).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);

    // Casing is normalized rather than rejected — the value is an enum, not a password.
    let res = app.clone().oneshot(make(json!("canonical_v1"), "lowercase")).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let res = app.clone().oneshot(make(json!("BODY_ONLY"), "explicit-legacy")).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // An omitted mode is the new default rather than an error — but it is CANONICAL_V1 now.
    let res = app.clone().oneshot(make(json!(null), "defaulted")).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/webhooks")
        .header("X-API-Key", &plaintext)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let listed: serde_json::Value = serde_json::from_slice(&body).unwrap();

    let row = |name: &str| -> serde_json::Value {
        listed.as_array().unwrap().iter()
            .find(|w| w["name"] == name).unwrap().clone()
    };
    assert_eq!(row("lowercase")["auth_mode"], "CANONICAL_V1", "casing is normalized on the way in");
    // Accepted on input, reported under the current name. Both halves matter: refusing the legacy
    // spelling would break stored automation, and echoing it back would leave two names in
    // circulation forever.
    assert_eq!(row("explicit-legacy")["auth_mode"], "HMAC_ONLY");
    assert_eq!(row("defaulted")["auth_mode"], "CANONICAL_V1", "omitted mode defaults to CANONICAL_V1");

    // An unset hmac_template reports the effective default, not null — the dashboard renders this
    // straight into an input, and a literal "null" there would be signed on the next save.
    assert_eq!(
        row("defaulted")["hmac_template"],
        r"{method}\n{path}\n{timestamp}\n{body}"
    );
    assert_eq!(row("defaulted")["has_api_key"], false);

    // The listing must still never leak the HMAC key itself.
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(!text.contains("s3cret"), "GET /api/webhooks leaked secret_token");
}

/// The new modes' per-mode preconditions are enforced when the webhook is *configured*, not left to
/// fail silently inside the background worker on every future dispatch.
#[tokio::test]
async fn test_auth_mode_preconditions_are_enforced_at_creation() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_key_id, plaintext) = insert_key(&db, "Master", true, true, true, true).await;

    let group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_id),
        name: Set("precondition-group".to_owned()),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }.insert(&db).await.unwrap();

    let post = |mut payload: serde_json::Value, name: &str| {
        payload["name"] = json!(name);
        payload["target_url"] = json!("https://example.com/hook");
        payload["payload_template"] = json!("{}");
        payload["group_id"] = json!(group_id.to_string());
        signed(inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/webhooks")
            .header("X-API-Key", &plaintext)
            .header("Content-Type", "application/json")), payload.to_string())
    };
    let status = |req: Request<Body>| async { app.clone().oneshot(req).await.unwrap().status() };

    // A signing mode with no key to sign with would produce an HMAC over the empty secret — a
    // signature anyone can forge, which is worse than none because it looks authenticated.
    assert_eq!(status(post(json!({ "auth_mode": "CANONICAL_V1" }), "no-secret")).await, StatusCode::BAD_REQUEST);
    assert_eq!(status(post(json!({ "auth_mode": "BODY_ONLY", "secret_token": "" }), "blank-secret")).await, StatusCode::BAD_REQUEST);

    // API_KEY_ONLY without a key sends no credential at all — i.e. silently becomes NONE.
    assert_eq!(status(post(json!({ "auth_mode": "API_KEY_ONLY" }), "no-key")).await, StatusCode::BAD_REQUEST);
    assert_eq!(status(post(json!({ "auth_mode": "API_KEY_ONLY", "api_key": "   " }), "blank-key")).await, StatusCode::BAD_REQUEST);

    // A template that never interpolates the body signs a constant: replayable against any payload.
    assert_eq!(
        status(post(json!({
            "auth_mode": "CANONICAL_V1",
            "secret_token": "s",
            "hmac_template": r"{method}\n{path}\n{timestamp}",
        }), "bodyless-template")).await,
        StatusCode::BAD_REQUEST
    );

    // The unsigned modes legitimately need no secret at all.
    assert_eq!(status(post(json!({ "auth_mode": "NONE" }), "none-mode")).await, StatusCode::OK);
    assert_eq!(status(post(json!({ "auth_mode": "API_KEY_ONLY", "api_key": "remote-key" }), "key-mode")).await, StatusCode::OK);

    // ...and the key they carry is never handed back out.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/webhooks")
        .header("X-API-Key", &plaintext)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(!text.contains("remote-key"), "GET /api/webhooks leaked the webhook's api_key");
    let listed: serde_json::Value = serde_json::from_str(&text).unwrap();
    let key_row = listed.as_array().unwrap().iter().find(|w| w["name"] == "key-mode").unwrap();
    assert_eq!(key_row["has_api_key"], true, "presence is reported even though the value is not");
}

/// The `auth_mode` migration replaces `signature_mode` rather than adding beside it, so it must
/// carry existing rows across without rewriting them to the new `CANONICAL_V1` default — that would
/// silently re-sign live third-party webhooks under a scheme their receivers reject.
///
/// Raw SQL is deliberate here and confined to this test: the point is to inspect the *physical*
/// columns before and after, which the entity (fixed to the post-migration shape) cannot see. The
/// statements are plain ANSI, so the SQL-agnosticism rule in `AGENT.MD` still holds.
#[tokio::test]
async fn test_auth_mode_migration_preserves_existing_rows_and_reverses_cleanly() {
    use sea_orm::{ConnectionTrait, Statement};

    let db = setup_test_db().await;
    let backend = db.get_database_backend();
    let exec = |sql: &str| db.execute_raw(Statement::from_string(backend, sql.to_owned()));

    exec("INSERT INTO ip_groups (id, name, group_type, created_at) \
          VALUES ('g', 'migration-group', 'banlist', '2026-01-01 00:00:00')").await.unwrap();
    exec("INSERT INTO webhook_configs \
          (id, name, target_url, secret_token, auth_mode, payload_template, group_id, is_active, created_at) \
          VALUES ('w', 'legacy', 'https://example.com/hook', 's', 'BODY_ONLY', '{}', 'g', 1, '2026-01-01 00:00:00')")
        .await.unwrap();

    // Reverse *back through* the auth-mode migration. The step count is derived from the registry
    // rather than hardcoded: `down` always unwinds from the newest migration, so every migration
    // added after this one shifts how far back the auth-mode change sits. Computing it here means
    // adding a migration cannot silently turn this into a test of something else.
    let all = migration::Migrator::migrations();
    let auth_mode_index = all
        .iter()
        .position(|m| m.name().contains("add_webhook_auth_modes"))
        .expect("the auth-mode migration must be registered");
    let steps = (all.len() - auth_mode_index) as u32;

    migration::Migrator::down(&db, Some(steps)).await.unwrap();
    let row = db.query_one_raw(Statement::from_string(backend,
        "SELECT signature_mode FROM webhook_configs WHERE id = 'w'".to_owned())).await.unwrap().unwrap();
    // Unwound past `m20260811_000012`, so the column holds the pre-rename spelling again — the
    // `down` path rewrites the data, not just the schema.
    assert_eq!(row.try_get::<String>("", "signature_mode").unwrap(), "BODY_ONLY");

    // Re-apply it: the backfill — not the column default — decides what the existing row gets.
    migration::Migrator::up(&db, None).await.unwrap();
    let row = db.query_one_raw(Statement::from_string(backend,
        "SELECT auth_mode, api_key, hmac_template FROM webhook_configs WHERE id = 'w'".to_owned()))
        .await.unwrap().unwrap();
    assert_eq!(
        row.try_get::<String>("", "auth_mode").unwrap(), "HMAC_ONLY",
        "an existing webhook must keep its *mode* — re-applying the chain renames BODY_ONLY to \
         HMAC_ONLY without letting it inherit the CANONICAL_V1 column default, which would silently \
         change what the receiver is sent"
    );
    assert_eq!(row.try_get::<Option<String>>("", "api_key").unwrap(), None);
    assert_eq!(
        row.try_get::<Option<String>>("", "hmac_template").unwrap().as_deref(),
        Some(r"{method}\n{path}\n{timestamp}\n{body}")
    );
}

/// `CANONICAL_V1` with a custom template: a literal path baked into the template must override the
/// one derived from `target_url`, and `api_key` must ride along as `X-API-Key`.
///
/// This is the reverse-proxy case — the vault posts to `https://proxy/hooks/42` while the receiver
/// behind it sees, and signs over, `/api/hooks/42/execute`.
#[tokio::test]
async fn test_canonical_v1_custom_template_overrides_path_and_sends_api_key() {
    let _env_guard = ENV_MUTATION_LOCK.lock().await;
    unsafe { std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "true") };

    let (base_url, captured) = spawn_capturing_receiver().await;
    let (app, _db, plaintext, group_id) = setup_webhook_fixture("templated-hook-group").await;

    let secret = "templated-webhook-secret";
    let template = r"{method}\n/api/hooks/42/execute\n{timestamp}\n{body}";
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/webhooks")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({
            "name": "Templated Hook",
            "target_url": format!("{base_url}/proxied/path"),
            "secret_token": secret,
            "payload_template": "{\"ip\":\"$target_address\"}",
            "group_id": group_id.to_string(),
            "auth_mode": "CANONICAL_V1",
            "api_key": "downstream-key",
            "hmac_template": template,
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")),
        json!({ "target_address": "7.7.7.7", "group_name": "templated-hook-group" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let hit = await_dispatch(&captured).await.expect("webhook was not delivered within timeout");
    unsafe { std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "false") };

    let delivered_body = hit.body.expect("body");
    let signature = hit.signature.expect("CANONICAL_V1 dispatch must send X-Signature-256");
    let timestamp = hit.timestamp.expect("CANONICAL_V1 dispatch must send X-Timestamp");

    assert_eq!(hit.api_key.as_deref(), Some("downstream-key"), "api_key must be sent as X-API-Key");
    assert_eq!(hit.path.as_deref(), Some("/proxied/path"), "the request still goes to target_url");

    // Signed over the hardcoded path, NOT /proxied/path.
    let expected = simply_ip_vault::crypto::compute_signature(
        secret, "POST", "/api/hooks/42/execute", &timestamp, delivered_body.as_bytes(),
    ).unwrap();
    assert_eq!(signature, expected, "the literal path in the template must win over target_url's");

    // And the URL-derived path must NOT produce a matching signature, or the assertion above would
    // pass for the wrong reason.
    let from_url = simply_ip_vault::crypto::compute_signature(
        secret, "POST", "/proxied/path", &timestamp, delivered_body.as_bytes(),
    ).unwrap();
    assert_ne!(signature, from_url);
}

/// `API_KEY_ONLY` sends the key and nothing else; `NONE` sends no auth headers at all. Both still
/// deliver the templated payload.
#[tokio::test]
async fn test_api_key_only_and_none_modes_send_the_expected_headers() {
    let _env_guard = ENV_MUTATION_LOCK.lock().await;
    unsafe { std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "true") };

    for (mode, group, address, expected_key) in [
        ("API_KEY_ONLY", "keyonly-hook-group", "8.8.8.8", Some("downstream-key")),
        ("NONE", "nomode-hook-group", "9.9.9.9", None),
    ] {
        let (base_url, captured) = spawn_capturing_receiver().await;
        let (app, _db, plaintext, group_id) = setup_webhook_fixture(group).await;

        let req = signed(inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/webhooks")
            .header("X-API-Key", &plaintext)
            .header("Content-Type", "application/json")), json!({
                "name": format!("{mode} Hook"),
                "target_url": format!("{base_url}/hook"),
                "payload_template": "{\"ip\":\"$target_address\"}",
                "group_id": group_id.to_string(),
                "auth_mode": mode,
                // Set in both cases on purpose: NONE must ignore it rather than send it.
                "api_key": "downstream-key",
            }).to_string());
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK, "creating {mode} hook");

        let req = signed(inject_connect_info(Request::builder()
            .method("POST")
            .uri("/api/ban")
            .header("X-API-Key", &plaintext)
            .header("Content-Type", "application/json")),
            json!({ "target_address": address, "group_name": group }).to_string());
        assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

        let hit = await_dispatch(&captured).await.unwrap_or_else(|| panic!("{mode} webhook was not delivered"));
        assert_eq!(hit.api_key.as_deref(), expected_key, "{mode} X-API-Key header");
        assert!(hit.signature.is_none(), "{mode} must not send X-Signature-256");
        assert!(hit.timestamp.is_none(), "{mode} must not send X-Timestamp");
        assert!(hit.body.expect("body").contains(address), "{mode} must still deliver the payload");
    }

    unsafe { std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "false") };
}

// ─────────────────────────────────────────────────────────────
// POST /api/keys/{id}/rotate-secret
// ─────────────────────────────────────────────────────────────

/// Rotating the signing secret invalidates the old one, activates the new one, and leaves the API
/// key itself — plus name, scopes and per-group grants — completely untouched.
#[tokio::test]
async fn test_rotate_secret_swaps_only_the_signing_secret() {
    // Serialized against the VAULT_ENCRYPTION_KEY test: whether the new secret is sealed is decided
    // by that variable at rotation time. See ENV_MUTATION_LOCK.
    let _guard = ENV_MUTATION_LOCK.lock().await;

    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (target_id, target_key) = insert_key(&db, "Worker Bot", false, false, true, true).await;

    // Give the target a per-group grant, so we can prove rotation doesn't disturb RBAC.
    let group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_id),
        name: Set("rotate-secret-group".to_owned()),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }.insert(&db).await.unwrap();
    simply_ip_vault::entities::api_key_group_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(target_id),
        group_id: Set(group_id),
        can_read: Set(true),
        can_write: Set(true),
        can_delete: Set(true),
        can_manage: Set(false),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }.insert(&db).await.unwrap();

    let old_secret = test_signing_secret(&target_key);

    // Baseline: the original secret works.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &target_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{target_id}/rotate-secret"))
        .header("X-API-Key", &master_key)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let rotated: serde_json::Value = serde_json::from_slice(&body).unwrap();

    assert_eq!(rotated["id"], target_id.to_string(), "the key id is preserved");
    assert_eq!(rotated["name"], "Worker Bot", "the key name is preserved");
    let new_secret = rotated["signing_secret"].as_str().unwrap().to_owned();
    assert!(!new_secret.is_empty());
    assert_ne!(new_secret, old_secret, "a genuinely new secret is issued");
    // The response must not hand back a new API key — that is `/rotate`'s job, not this one's.
    assert!(rotated.get("plaintext_key").is_none(), "rotate-secret must not reissue the API key");

    // The old signing secret is dead...
    let req = signed_with(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &target_key)), &old_secret, "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // ...and the new one works with the *same, unchanged* API key.
    let req = signed_with(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &target_key)), &new_secret, "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    // Identity and RBAC survived intact.
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let me: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(me["id"], target_id.to_string());
    assert_eq!(me["name"], "Worker Bot");
    assert_eq!(me["can_manage_webhooks"], true);
    assert_eq!(me["can_create_groups"], true);
    assert_eq!(me["is_master"], false);
    let perms = me["group_permissions"].as_array().unwrap();
    assert_eq!(perms.len(), 1, "the per-group grant is untouched");
    assert_eq!(perms[0]["group_name"], "rotate-secret-group");
    assert_eq!(perms[0]["can_write"], true);
    assert_eq!(perms[0]["can_delete"], true);
}

/// A key whose `signing_secret` is `NULL` (a row predating HMAC auth) is recoverable through
/// `rotate-secret` — the documented upgrade path — without reissuing its API key.
#[tokio::test]
async fn test_rotate_secret_recovers_a_key_with_no_signing_secret() {
    let _guard = ENV_MUTATION_LOCK.lock().await;

    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;

    let legacy_id = Uuid::new_v4();
    let legacy_key = simply_ip_vault::api::generate_random_key();
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(legacy_id),
        key_hash: Set(simply_ip_vault::api::hash_key(&legacy_key)),
        signing_secret: Set(None),
        name: Set("Legacy".to_owned()),
        bound_ips: Set(None),
        is_master: Set(false),
        can_manage_keys: Set(false),
        can_manage_webhooks: Set(false),
        can_create_groups: Set(false),
        parent_key_id: Set(None),
        prefix: Set("dummy123".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }.insert(&db).await.unwrap();

    // Before: unusable.
    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &legacy_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{legacy_id}/rotate-secret"))
        .header("X-API-Key", &master_key)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let rotated: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let new_secret = rotated["signing_secret"].as_str().unwrap().to_owned();

    // After: the same API key now authenticates.
    let req = signed_with(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &legacy_key)), &new_secret, "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
}

/// `rotate-secret` is master/`can_manage_keys`-only, 404s for unknown keys, and writes an audit
/// entry naming the key it re-keyed.
#[tokio::test]
async fn test_rotate_secret_authorization_and_audit_trail() {
    let _guard = ENV_MUTATION_LOCK.lock().await;

    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (victim_id, _victim_key) = insert_key(&db, "Victim", false, false, false, false).await;
    let (_low_id, low_key) = insert_key(&db, "Lowly", false, false, false, false).await;

    // A key without can_manage_keys cannot re-key anyone — including itself.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{victim_id}/rotate-secret"))
        .header("X-API-Key", &low_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);

    // Unauthenticated is rejected before authorization.
    let req = inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{victim_id}/rotate-secret")))
        .body(Body::empty()).unwrap();
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::UNAUTHORIZED);

    // An unknown key id is a 404, not a silently-created key.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{}/rotate-secret", Uuid::new_v4()))
        .header("X-API-Key", &master_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NOT_FOUND);

    // The successful path writes a readable audit entry.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/keys/{victim_id}/rotate-secret"))
        .header("X-API-Key", &master_key)), "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = signed(inject_connect_info(Request::builder()
        .uri("/api/audit-logs?action=KEY_SECRET_ROTATE&limit=1")
        .header("X-API-Key", &master_key)), "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let logs: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let entry = &logs.as_array().unwrap()[0];
    assert_eq!(entry["action"], "KEY_SECRET_ROTATE");
    let details = entry["details"].as_str().unwrap();
    assert!(details.contains("'Victim'"), "audit details should name the key, got {details}");
    // The secret itself must never reach the audit trail.
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(!text.contains("signing_secret"), "audit log leaked a signing secret field");
}

// ─────────────────────────────────────────────────────────────
// RBAC_MODEL.md §3 — lineage, ownership and lifecycle authority
// ─────────────────────────────────────────────────────────────

/// **R3 — parentage confers no authority.** A daughter of the Master key is an ordinary daughter key.
///
/// `RBAC_MODEL.md` R3: "`parent_key_id` exists solely for cascading deletion and visibility scoping.
/// A daughter of the Master key is an ordinary daughter key with no elevated standing. Rights are
/// never derived from key lineage."
///
/// The failure this guards against is subtle and tempting: once lineage exists, "the master's own
/// children are trusted" reads like common sense, and it would make `parent_key_id` a second,
/// undeclared permission column.
///
/// # Why three keys and not two, and why they are set up so precisely
///
/// This is a **three-way differential**: a child of the Master, a child of an ordinary parent, and a
/// key with no parent at all. Two arms would miss the most likely mutation — a guard keyed on
/// `parent_key_id.is_some()` rather than on who the parent is — because both children would be
/// elevated together and still agree.
///
/// All three then hold **identical** scopes and **identical** grants, so lineage is the only variable
/// left. The grants are shaped so that every probe below is decided by `guard_group_manage` rather
/// than by the cheaper pre-gate in front of it: each key manages `lineage-home` (satisfying "does
/// this caller administer anything?") while holding only a plain row on `lineage-target`, which is
/// what the probes attack. A lineage-sensitive branch anywhere in that path moves one arm and breaks
/// the equality; without the two-group setup the pre-gate would refuse first and mask it — which it
/// did, on the first draft of this test, and which mutation testing is how that was found.
#[tokio::test]
async fn r3_lineage_confers_no_authority_on_a_daughter_of_the_master() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (parent_id, parent_key) = insert_key(&db, "Ordinary parent", false, true, false, false).await;

    // Two keys created through the API, so lineage is recorded by the handler rather than the fixture.
    let create_via = |caller: String, name: &'static str, nth: i64| {
        let app = app.clone();
        async move {
            let req = signed_later(inject_connect_info(Request::builder()
                .method("POST")
                .uri("/api/keys")
                .header("X-API-Key", &caller)
                .header("Content-Type", "application/json")), nth, json!({ "name": name }).to_string());
            let res = app.oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
            )
            .unwrap();
            (
                Uuid::parse_str(body["id"].as_str().unwrap()).unwrap(),
                body["plaintext_key"].as_str().unwrap().to_owned(),
                body["signing_secret"].as_str().unwrap().to_owned(),
            )
        }
    };

    let (royal_id, royal_key, royal_secret) = create_via(master_key.clone(), "Master's child", 1).await;
    let (commoner_id, commoner_key, commoner_secret) =
        create_via(parent_key.clone(), "Parent's child", 2).await;
    // The third arm: no parent at all, seeded directly.
    let (orphan_id, orphan_plain) = insert_key(&db, "Orphan", false, false, false, false).await;
    let orphan_secret = test_signing_secret(&orphan_plain);

    // Precondition: the lineages really are three different things. Without this the test could pass
    // because every key looks the same to begin with.
    let lineage = |id: Uuid| {
        let db = db.clone();
        async move {
            simply_ip_vault::entities::prelude::ApiKey::find_by_id(id)
                .one(&db).await.unwrap().unwrap().parent_key_id
        }
    };
    assert_eq!(lineage(royal_id).await, Some(master_id), "the master's child records the master");
    assert_eq!(lineage(commoner_id).await, Some(parent_id), "the parent's child records the parent");
    assert_eq!(lineage(orphan_id).await, None, "the seeded key records no parent");

    // Identical scopes across all three, applied directly so the differential is exact — R4 would not
    // let the ordinary parent grant `can_manage_keys` through the API, and an arm that differed in
    // scope would prove nothing about lineage.
    for id in [royal_id, commoner_id, orphan_id] {
        let mut active: simply_ip_vault::entities::api_key::ActiveModel =
            simply_ip_vault::entities::prelude::ApiKey::find_by_id(id)
                .one(&db).await.unwrap().unwrap().into();
        active.can_manage_keys = Set(true);
        active.update(&db).await.unwrap();
    }

    // Identical grants: `can_manage` on one group, a plain row on the group the probes attack. The
    // first satisfies the pre-gate; the second is what `guard_group_manage` must refuse.
    let home = insert_group_row(&db, "lineage-home").await;
    let target = insert_group_row(&db, "lineage-target").await;
    for id in [royal_id, commoner_id, orphan_id] {
        grant_perm(&db, id, home, true, true, true, true).await;
        grant_perm(&db, id, target, true, true, true, false).await;
    }

    let (victim_id, _victim_key) = insert_key(&db, "Victim", false, false, false, false).await;
    grant_perm(&db, victim_id, target, true, false, false, false).await;

    let probe = |plaintext: String, secret: String, nth: i64| {
        let app = app.clone();
        async move {
            let mut statuses = Vec::new();

            // 1. Grant on `lineage-target`, where the caller holds a row but not `can_manage`. R2
            //    refuses; lineage must not supply the missing half.
            let req = signed_later_with(inject_connect_info(Request::builder()
                .method("POST")
                .uri(format!("/api/keys/{victim_id}/permissions"))
                .header("X-API-Key", &plaintext)
                .header("Content-Type", "application/json")), &secret, nth, json!({
                    "group_name": "lineage-target", "can_read": true, "can_write": true, "can_delete": false
                }).to_string());
            statuses.push(app.clone().oneshot(req).await.unwrap().status());

            // 2. Revoke on the same group, same reasoning.
            let req = signed_later_with(inject_connect_info(Request::builder()
                .method("DELETE")
                .uri(format!("/api/keys/{victim_id}/permissions/lineage-target"))
                .header("X-API-Key", &plaintext)), &secret, nth + 1, "");
            statuses.push(app.clone().oneshot(req).await.unwrap().status());

            // 3. The audit log — master-only, and descent from the master is not mastery.
            let req = signed_later_with(inject_connect_info(Request::builder()
                .uri("/api/audit-logs")
                .header("X-API-Key", &plaintext)), &secret, nth + 2, "");
            statuses.push(app.clone().oneshot(req).await.unwrap().status());

            // 4. Deleting an unowned group — §3 lifecycle authority, which lineage also must not supply.
            let req = signed_later_with(inject_connect_info(Request::builder()
                .method("DELETE")
                .uri(format!("/api/groups/{target}"))
                .header("X-API-Key", &plaintext)), &secret, nth + 3, "");
            statuses.push(app.clone().oneshot(req).await.unwrap().status());

            statuses
        }
    };

    let royal_answers = probe(royal_key, royal_secret, 10).await;
    let commoner_answers = probe(commoner_key, commoner_secret, 20).await;
    let orphan_answers = probe(orphan_plain, orphan_secret, 30).await;

    assert_eq!(
        royal_answers, commoner_answers,
        "descent from the master must change nothing: royal={royal_answers:?} commoner={commoner_answers:?}"
    );
    assert_eq!(
        royal_answers, orphan_answers,
        "having a parent at all must change nothing: royal={royal_answers:?} orphan={orphan_answers:?}"
    );
    assert!(
        royal_answers.iter().all(|s| *s == StatusCode::FORBIDDEN),
        "and the shared answer must be refusal, not three matching successes: {royal_answers:?}"
    );

    // The victim's row survived, so those were refusals and not silent no-ops.
    assert!(
        simply_ip_vault::entities::api_key_group_permission::Entity::find()
            .filter(simply_ip_vault::entities::api_key_group_permission::Column::ApiKeyId.eq(victim_id))
            .one(&db).await.unwrap().is_some()
    );
}

/// **§3 — lifecycle authority belongs to Master and the owner, and to nobody else.**
///
/// The clause under test is the second sentence: "Holding manage rights or any operational verb
/// confers no lifecycle authority: a parent that merely uses a resource must not be able to delete
/// it." So the caller refused below is not a bystander — it is the most privileged non-owner the
/// model allows: `can_manage_keys` globally, and `can_read`/`can_write`/`can_delete`/`can_manage` on
/// the group itself. Every verb, and still no authority over the group's existence.
#[tokio::test]
async fn s3_group_deletion_is_restricted_to_master_and_the_owner() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (owner_id, owner_key) = insert_key(&db, "Owner", false, false, false, true).await;
    let (user_id, user_key) = insert_key(&db, "Privileged user", false, true, false, false).await;

    // The owner creates the group through the API, so ownership is recorded by the handler.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/groups")
        .header("X-API-Key", &owner_key)
        .header("Content-Type", "application/json")), json!({ "name": "owned-group" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    let group_id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();

    let stored = simply_ip_vault::entities::prelude::IpGroup::find_by_id(group_id)
        .one(&db).await.unwrap().unwrap();
    assert_eq!(stored.owner_key_id, Some(owner_id), "the creator is recorded as the owner");

    // Every verb the model can give a non-owner.
    grant_perm(&db, user_id, group_id, true, true, true, true).await;

    // Fixture keys derive their signing secret from their plaintext, so `signed_later` finds it from
    // the header — no explicit secret needed for any caller here.
    let delete_as = |plaintext: String, nth: i64| {
        let app = app.clone();
        async move {
            let req = signed_later(inject_connect_info(Request::builder()
                .method("DELETE")
                .uri(format!("/api/groups/{group_id}"))
                .header("X-API-Key", &plaintext)), nth, "");
            app.oneshot(req).await.unwrap().status()
        }
    };

    assert_eq!(
        delete_as(user_key, 1).await,
        StatusCode::FORBIDDEN,
        "read+write+delete+can_manage on a group confers no authority over the group itself"
    );
    assert!(
        simply_ip_vault::entities::prelude::IpGroup::find_by_id(group_id)
            .one(&db).await.unwrap().is_some(),
        "the refusal blocked the delete rather than reporting one"
    );

    // The owner may. This is the half that changed: deletion used to be master-only.
    assert_eq!(
        delete_as(owner_key, 2).await,
        StatusCode::NO_CONTENT,
        "the owner may delete its own group"
    );

    // And a master may delete a group it does not own.
    let unowned = insert_group_row(&db, "unowned-group").await;
    let req = signed_later(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri(format!("/api/groups/{unowned}"))
        .header("X-API-Key", &master_key)), 3, "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);
}

/// **§3 — "Master may reassign `owner_key_id` on any resource or dispatch target at any time."**
///
/// Also the recovery path for the `NULL` backfill: every group and webhook that predates the
/// ownership column arrives unowned, which reads as master-only, and this is how it stops being so.
/// Reassignment is master-only and *not* delegable to the current owner — ownership is the authority
/// to destroy the resource, and a transferable owner flag would let a tenant pass that on without the
/// master who granted it ever seeing the transfer.
#[tokio::test]
async fn s3_only_a_master_may_reassign_ownership() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (alice_id, alice_key) = insert_key(&db, "Alice", false, true, true, true).await;
    let (bob_id, bob_key) = insert_key(&db, "Bob", false, true, true, true).await;

    // An unowned group, exactly as the backfill leaves every pre-migration row.
    let group_id = insert_group_row(&db, "legacy-group").await;
    assert_eq!(
        simply_ip_vault::entities::prelude::IpGroup::find_by_id(group_id)
            .one(&db).await.unwrap().unwrap().owner_key_id,
        None,
        "precondition: unowned, as the backfill leaves it"
    );

    let reassign_as = |plaintext: String, to: Option<Uuid>, nth: i64| {
        let app = app.clone();
        async move {
            let body = json!({ "owner_key_id": to });
            let req = signed_later(inject_connect_info(Request::builder()
                .method("PUT")
                .uri(format!("/api/groups/{group_id}/owner"))
                .header("X-API-Key", &plaintext)
                .header("Content-Type", "application/json")), nth, body.to_string());
            app.oneshot(req).await.unwrap().status()
        }
    };

    // A non-master cannot claim an unowned resource for itself.
    assert_eq!(
        reassign_as(alice_key.clone(), Some(alice_id), 1).await,
        StatusCode::FORBIDDEN,
        "an unowned resource cannot be claimed by whoever asks first"
    );

    // The master assigns it.
    assert_eq!(
        reassign_as(master_key.clone(), Some(alice_id), 2).await,
        StatusCode::OK
    );
    assert_eq!(
        simply_ip_vault::entities::prelude::IpGroup::find_by_id(group_id)
            .one(&db).await.unwrap().unwrap().owner_key_id,
        Some(alice_id)
    );

    // Alice now owns it — and still cannot pass it on. Ownership is granted, never traded.
    assert_eq!(
        reassign_as(alice_key, Some(bob_id), 3).await,
        StatusCode::FORBIDDEN,
        "the owner may not transfer ownership; only a master reassigns"
    );

    // Nor may Bob take it.
    assert_eq!(
        reassign_as(bob_key, Some(bob_id), 4).await,
        StatusCode::FORBIDDEN
    );

    // The master can clear it back to unowned, which is master-only authority again.
    assert_eq!(
        reassign_as(master_key.clone(), None, 5).await,
        StatusCode::OK
    );
    assert_eq!(
        simply_ip_vault::entities::prelude::IpGroup::find_by_id(group_id)
            .one(&db).await.unwrap().unwrap().owner_key_id,
        None
    );

    // The master key itself is refused as an owner: ownership is a tenancy relationship, and `NULL`
    // already means "master only". Two spellings of the same state invite guards that check one.
    let master_row = simply_ip_vault::entities::prelude::ApiKey::find()
        .filter(simply_ip_vault::entities::api_key::Column::IsMaster.eq(true))
        .one(&db).await.unwrap().unwrap();
    assert_eq!(
        reassign_as(master_key.clone(), Some(master_row.id), 6).await,
        StatusCode::BAD_REQUEST,
        "the master cannot be recorded as an owner"
    );

    // A nonexistent key is refused rather than written as a dangling reference — the check that
    // stands in for the foreign key SQLite will not let this schema declare.
    assert_eq!(
        reassign_as(master_key.clone(), Some(Uuid::new_v4()), 7).await,
        StatusCode::BAD_REQUEST,
        "a dangling owner_key_id must not be writable"
    );
}

/// **§3/§4 — a webhook belongs to its creator, and lifecycle follows ownership rather than the group.**
///
/// Before this, `update_webhook` and `delete_webhook` scoped by *group readability*: any
/// `can_manage_webhooks` holder with `can_read` on a group could edit or delete another tenant's
/// integration in it. That is the shared-resource rule §4 explicitly forbids applying to a dispatch
/// target — "visible exclusively to their creator and Master … never exposed by the shared-resource
/// rule".
#[tokio::test]
async fn s3_webhook_lifecycle_follows_its_owner_not_its_group() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (owner_id, owner_key) = insert_key(&db, "Webhook owner", false, false, true, false).await;
    let (peer_id, peer_key) = insert_key(&db, "Group peer", false, false, true, false).await;

    // Both keys can read the same group. Under the old rule that alone made the webhook theirs.
    let group_id = insert_group_row(&db, "shared-webhook-group").await;
    grant_perm(&db, owner_id, group_id, true, true, true, false).await;
    grant_perm(&db, peer_id, group_id, true, true, true, false).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/webhooks")
        .header("X-API-Key", &owner_key)
        .header("Content-Type", "application/json")), json!({
            "name": "owned-hook",
            "target_url": "https://example.com/hook",
            "secret_token": "s3cr3t",
            "payload_template": "{}",
            "group_id": group_id.to_string()
        }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    let webhook_id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();

    assert_eq!(
        simply_ip_vault::entities::prelude::WebhookConfig::find_by_id(webhook_id)
            .one(&db).await.unwrap().unwrap().owner_key_id,
        Some(owner_id),
        "the creator is recorded as the owner"
    );

    // The peer shares the group and holds `can_manage_webhooks`. It gets a `404`, not a `403`: a
    // dispatch target outside the caller's scope must be indistinguishable from one that never
    // existed.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri(format!("/api/webhooks/{webhook_id}"))
        .header("X-API-Key", &peer_key)), 1, "");
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::NOT_FOUND,
        "sharing the group is not owning the webhook"
    );

    let req = signed_later(inject_connect_info(Request::builder()
        .method("PUT")
        .uri(format!("/api/webhooks/{webhook_id}"))
        .header("X-API-Key", &peer_key)
        .header("Content-Type", "application/json")), 2, json!({ "name": "hijacked" }).to_string());
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::NOT_FOUND,
        "nor may it rename one"
    );

    assert!(
        simply_ip_vault::entities::prelude::WebhookConfig::find_by_id(webhook_id)
            .one(&db).await.unwrap().is_some(),
        "the webhook survived both refusals"
    );

    // The owner may, and so may a master.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("PUT")
        .uri(format!("/api/webhooks/{webhook_id}"))
        .header("X-API-Key", &owner_key)
        .header("Content-Type", "application/json")), 3, json!({ "name": "renamed-by-owner" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = signed_later(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri(format!("/api/webhooks/{webhook_id}"))
        .header("X-API-Key", &master_key)), 4, "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NO_CONTENT);
}

/// **`POST /api/webhooks/{id}/test` carries the same ownership rule as every other webhook
/// endpoint, and a successful test genuinely reaches a real receiver.**
///
/// Ownership half mirrors [`s3_webhook_lifecycle_follows_its_owner_not_its_group`] exactly — a group
/// peer with `can_manage_webhooks` gets `404`, not `403`, the same oracle-discipline reason as
/// delete/update. The dispatch half is the new behaviour: the owner's test request must actually
/// reach a live loopback receiver (with `ALLOW_PRIVATE_WEBHOOKS` opted in, the same escape hatch
/// `test_webhook_hmac_signature_and_delivery` uses) and report success, and it must do so without
/// requiring any live traffic — nothing is ever posted to `/api/ban` or `/api/white` in this test, so
/// a passing result proves the endpoint dispatches on its own rather than merely being reachable.
#[tokio::test]
async fn s4_webhook_test_endpoint_follows_ownership_and_genuinely_dispatches() {
    let _env_guard = ENV_MUTATION_LOCK.lock().await;

    let receiver = axum::Router::new().route(
        "/hook",
        axum::routing::post(|| async { StatusCode::OK }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let receiver_addr = listener.local_addr().unwrap();
    let _receiver = tokio::spawn(async move {
        axum::serve(listener, receiver).await.unwrap();
    });
    unsafe { std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "true") };

    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (owner_id, owner_key) = insert_key(&db, "Webhook owner", false, false, true, false).await;
    let (peer_id, peer_key) = insert_key(&db, "Group peer", false, false, true, false).await;
    let (_stranger_id, stranger_key) = insert_key(&db, "No manage rights", false, false, false, false).await;

    let group_id = insert_group_row(&db, "test-endpoint-group").await;
    grant_perm(&db, owner_id, group_id, true, true, true, false).await;
    grant_perm(&db, peer_id, group_id, true, true, true, false).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/webhooks")
        .header("X-API-Key", &owner_key)
        .header("Content-Type", "application/json")), json!({
            "name": "test-endpoint-hook",
            "target_url": format!("http://{receiver_addr}/hook"),
            "auth_mode": "NONE",
            "payload_template": "{}",
            "group_id": group_id.to_string()
        }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    let webhook_id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();

    // A key with no `can_manage_webhooks` at all: refused outright, `403` — it never had standing to
    // ask about any webhook, owned or not.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/webhooks/{webhook_id}/test"))
        .header("X-API-Key", &stranger_key)), 1, "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);

    // A group peer with `can_manage_webhooks` but no ownership: `404`, matching delete/update — this
    // webhook is not in the set that peer's `GET /api/webhooks` would ever list.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/webhooks/{webhook_id}/test"))
        .header("X-API-Key", &peer_key)), 2, "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NOT_FOUND);

    // The owner may test its own webhook, and the live receiver actually answers.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/webhooks/{webhook_id}/test"))
        .header("X-API-Key", &owner_key)), 3, "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let result: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    assert_eq!(result["success"], true, "the live receiver answered 200: {result}");
    assert_eq!(result["status"], 200);

    // A master may test any webhook, ownership notwithstanding.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/webhooks/{webhook_id}/test"))
        .header("X-API-Key", &master_key)), 4, "");
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    unsafe { std::env::remove_var("ALLOW_PRIVATE_WEBHOOKS") };
}

/// **`GET /api/webhooks/executions` — Master sees every execution; a non-master key sees only its
/// own webhooks', and `can_manage_keys` grants neither.**
///
/// This is the core RBAC contract Task 3 asks for, spelled out against two webhooks owned by two
/// different keys so "sees its own" and "does not see the other's" are both actually exercised
/// (a test with only one owned webhook could pass by accident if the scoping filter were missing
/// entirely and the handler merely happened to return the right rows for that one caller).
#[tokio::test]
async fn s4_webhook_executions_are_scoped_to_ownership_not_can_manage_keys() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (owner_a_id, owner_a_key) = insert_key(&db, "Owner A", false, false, true, false).await;
    let (owner_b_id, owner_b_key) = insert_key(&db, "Owner B", false, false, true, false).await;
    // Holds `can_manage_keys` — the exact scope the brief says must NOT grant execution read
    // access — and nothing else.
    let (_parent_id, parent_only_key) = insert_key(&db, "Parent (manage_keys only)", false, true, false, false).await;
    let (_stranger_id, stranger_key) = insert_key(&db, "No webhook rights", false, false, false, false).await;

    let group_id = insert_group_row(&db, "executions-rbac-group").await;
    grant_perm(&db, owner_a_id, group_id, true, true, true, false).await;
    grant_perm(&db, owner_b_id, group_id, true, true, true, false).await;

    let seed_webhook = |owner: Uuid| {
        let db = db.clone();
        async move {
            let webhook_id = Uuid::new_v4();
            simply_ip_vault::entities::webhook_config::ActiveModel {
                id: Set(webhook_id),
                name: Set(format!("hook-{webhook_id}")),
                target_url: Set("https://example.com/hook".to_owned()),
                secret_token: Set(String::new()),
                auth_mode: Set("NONE".to_owned()),
                api_key: Set(None),
                hmac_template: Set(None),
                signature_header: Set(None),
                signature_prefix: Set(None),
                headers_json: Set(None),
                payload_template: Set("{}".to_owned()),
                group_id: Set(group_id),
                is_active: Set(true),
                events: Set(None),
                owner_key_id: Set(Some(owner)),
                created_at: Set(chrono::Utc::now().naive_utc()),
            }
            .insert(&db)
            .await
            .unwrap();
            webhook_id
        }
    };
    let seed_execution = |webhook_id: Uuid| {
        let db = db.clone();
        async move {
            simply_ip_vault::entities::webhook_execution::ActiveModel {
                id: Set(Uuid::new_v4()),
                webhook_id: Set(webhook_id),
                event_type: Set("IP_ADD".to_owned()),
                status_code: Set(Some(200)),
                is_success: Set(true),
                duration_ms: Set(5),
                response_body: Set(None),
                resolved_target_url: Set(None),
                target_address: Set(None),
                cause: Set(None),
                created_at: Set(chrono::Utc::now().naive_utc()),
            }
            .insert(&db)
            .await
            .unwrap();
        }
    };

    let webhook_a = seed_webhook(owner_a_id).await;
    let webhook_b = seed_webhook(owner_b_id).await;
    seed_execution(webhook_a).await;
    seed_execution(webhook_b).await;

    let list = |key: &str, ts: i64| {
        let app = app.clone();
        let key = key.to_owned();
        async move {
            let req = signed_later(inject_connect_info(Request::builder()
                .method("GET")
                .uri("/api/webhooks/executions")
                .header("X-API-Key", &key)), ts, "");
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
            )
            .unwrap_or(serde_json::Value::Null);
            (status, body)
        }
    };

    // `can_manage_keys` alone: refused outright, per the brief's explicit note.
    let (status, _) = list(&parent_only_key, 1).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "can_manage_keys must not grant execution read access");

    // No webhook rights at all: refused outright too.
    let (status, _) = list(&stranger_key, 2).await;
    assert_eq!(status, StatusCode::FORBIDDEN);

    // Owner A sees only its own webhook's execution, never Owner B's.
    let (status, body) = list(&owner_a_key, 3).await;
    assert_eq!(status, StatusCode::OK);
    let rows = body.as_array().expect("a JSON array");
    assert_eq!(rows.len(), 1, "Owner A sees exactly its own webhook's execution: {body}");
    assert_eq!(rows[0]["webhook_id"], webhook_a.to_string());

    // Owner B, symmetrically, sees only its own.
    let (status, body) = list(&owner_b_key, 4).await;
    assert_eq!(status, StatusCode::OK);
    let rows = body.as_array().expect("a JSON array");
    assert_eq!(rows.len(), 1, "Owner B sees exactly its own webhook's execution: {body}");
    assert_eq!(rows[0]["webhook_id"], webhook_b.to_string());

    // Master sees both, across both owners.
    let (status, body) = list(&master_key, 5).await;
    assert_eq!(status, StatusCode::OK);
    let rows = body.as_array().expect("a JSON array");
    assert_eq!(rows.len(), 2, "Master sees every webhook's executions: {body}");
}

/// **`GET /api/webhooks/executions`'s query contract**: `webhook_id`/`event_type`/`is_success`
/// each narrow the result set (not merely accepted and ignored), `limit`/`offset` paginate, and an
/// unrecognized parameter is refused with `400` rather than silently dropped.
///
/// The ownership/permission scoping has its own test above; this one is deliberately scoped to a
/// single owner so every assertion is about the *query parameters themselves* — a filter that
/// silently no-ops would still pass every RBAC test (the rows it returns are all ones the caller may
/// see, just not narrowed further), which is exactly the failure mode this test exists to catch.
#[tokio::test]
async fn s4_webhook_executions_endpoint_filters_paginates_and_rejects_unknown_fields() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let group_id = insert_group_row(&db, "executions-query-contract-group").await;

    let seed_webhook = || {
        let db = db.clone();
        async move {
            let webhook_id = Uuid::new_v4();
            simply_ip_vault::entities::webhook_config::ActiveModel {
                id: Set(webhook_id),
                name: Set(format!("hook-{webhook_id}")),
                target_url: Set("https://example.com/hook".to_owned()),
                secret_token: Set(String::new()),
                auth_mode: Set("NONE".to_owned()),
                api_key: Set(None),
                hmac_template: Set(None),
                signature_header: Set(None),
                signature_prefix: Set(None),
                headers_json: Set(None),
                payload_template: Set("{}".to_owned()),
                group_id: Set(group_id),
                is_active: Set(true),
                events: Set(None),
                owner_key_id: Set(None),
                created_at: Set(chrono::Utc::now().naive_utc()),
            }
            .insert(&db)
            .await
            .unwrap();
            webhook_id
        }
    };
    let seed_execution = |webhook_id: Uuid, event_type: &'static str, is_success: bool| {
        let db = db.clone();
        async move {
            simply_ip_vault::entities::webhook_execution::ActiveModel {
                id: Set(Uuid::new_v4()),
                webhook_id: Set(webhook_id),
                event_type: Set(event_type.to_owned()),
                status_code: Set(Some(if is_success { 200 } else { 500 })),
                is_success: Set(is_success),
                duration_ms: Set(5),
                response_body: Set(None),
                resolved_target_url: Set(None),
                target_address: Set(None),
                cause: Set(None),
                created_at: Set(chrono::Utc::now().naive_utc()),
            }
            .insert(&db)
            .await
            .unwrap();
        }
    };

    let webhook = seed_webhook().await;
    let other_webhook = seed_webhook().await; // never gets an execution — the webhook_id-filter control.
    seed_execution(webhook, "IP_ADD", true).await;
    seed_execution(webhook, "IP_ADD", false).await;
    seed_execution(webhook, "TEST", true).await;

    let query = |qs: String, ts: i64| {
        let app = app.clone();
        let master_key = master_key.clone();
        async move {
            let req = signed_later(inject_connect_info(Request::builder()
                .uri(format!("/api/webhooks/executions{qs}"))
                .header("X-API-Key", &master_key)), ts, "");
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
            )
            .unwrap_or(serde_json::Value::Null);
            (status, body)
        }
    };

    // No filter: all three rows for `webhook`, none for `other_webhook`.
    let (status, body) = query("".to_owned(), 1).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 3, "no filter returns every row: {body}");

    // `webhook_id` narrows to one webhook — proven by a second webhook with zero matching rows,
    // not merely by re-checking the same one the ownership test already covers.
    let (status, body) = query(format!("?webhook_id={other_webhook}"), 2).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 0, "the other webhook has no executions: {body}");

    // `event_type` narrows.
    let (status, body) = query("?event_type=TEST".to_owned(), 3).await;
    assert_eq!(status, StatusCode::OK);
    let rows = body.as_array().unwrap();
    assert_eq!(rows.len(), 1, "exactly the one TEST-type row: {body}");
    assert_eq!(rows[0]["event_type"], "TEST");

    // `is_success` narrows.
    let (status, body) = query("?is_success=false".to_owned(), 4).await;
    assert_eq!(status, StatusCode::OK);
    let rows = body.as_array().unwrap();
    assert_eq!(rows.len(), 1, "exactly the one failed row: {body}");
    assert_eq!(rows[0]["is_success"], false);

    // Filters combine with AND, not OR.
    let (status, body) = query("?event_type=IP_ADD&is_success=true".to_owned(), 5).await;
    assert_eq!(status, StatusCode::OK);
    let rows = body.as_array().unwrap();
    assert_eq!(rows.len(), 1, "only the row matching both filters: {body}");

    // `limit`/`offset` paginate: three separate one-row pages across the three seeded rows, no
    // row repeated and none skipped.
    let mut paged_ids = std::collections::HashSet::new();
    for offset in 0..3 {
        let (status, body) = query(format!("?limit=1&offset={offset}"), 6 + offset).await;
        assert_eq!(status, StatusCode::OK);
        let rows = body.as_array().unwrap();
        assert_eq!(rows.len(), 1, "limit=1 returns exactly one row at offset {offset}: {body}");
        paged_ids.insert(rows[0]["id"].as_str().unwrap().to_owned());
    }
    assert_eq!(paged_ids.len(), 3, "three pages of one row each covered all three rows with none repeated");

    // An unrecognized query parameter is refused, not silently ignored.
    let (status, body) = query("?not_a_real_filter=1".to_owned(), 9).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "an unknown query parameter must be a 400: {body}");
}

/// **`GET /api/webhooks/executions`'s newer filters**: `status` (success/failed/a numeric code),
/// `group_id`, `ip`, `search` (webhook name / address / cause), and `from_date`/`to_date` each
/// narrow the result set on their own, the way `webhook_id`/`event_type`/`is_success` already do —
/// exercised separately from that test so a regression in one of these five is not masked by the
/// others still passing.
#[tokio::test]
async fn s4_webhook_executions_endpoint_supports_rich_filters() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let group_a = insert_group_row(&db, "rich-filter-group-a").await;
    let group_b = insert_group_row(&db, "rich-filter-group-b").await;

    let seed_webhook = |name: &'static str, group_id: Uuid| {
        let db = db.clone();
        async move {
            let webhook_id = Uuid::new_v4();
            simply_ip_vault::entities::webhook_config::ActiveModel {
                id: Set(webhook_id),
                name: Set(name.to_owned()),
                target_url: Set("https://example.com/hook".to_owned()),
                secret_token: Set(String::new()),
                auth_mode: Set("NONE".to_owned()),
                api_key: Set(None),
                hmac_template: Set(None),
                signature_header: Set(None),
                signature_prefix: Set(None),
                headers_json: Set(None),
                payload_template: Set("{}".to_owned()),
                group_id: Set(group_id),
                is_active: Set(true),
                events: Set(None),
                owner_key_id: Set(None),
                created_at: Set(chrono::Utc::now().naive_utc()),
            }
            .insert(&db)
            .await
            .unwrap();
            webhook_id
        }
    };
    #[allow(clippy::too_many_arguments)]
    let seed_execution = |webhook_id: Uuid,
                          status_code: i32,
                          is_success: bool,
                          target_address: &'static str,
                          cause: &'static str,
                          age_hours: i64| {
        let db = db.clone();
        async move {
            let created_at =
                (chrono::Utc::now() - chrono::Duration::hours(age_hours)).naive_utc();
            simply_ip_vault::entities::webhook_execution::ActiveModel {
                id: Set(Uuid::new_v4()),
                webhook_id: Set(webhook_id),
                event_type: Set("IP_ADD".to_owned()),
                status_code: Set(Some(status_code)),
                is_success: Set(is_success),
                duration_ms: Set(5),
                response_body: Set(None),
                resolved_target_url: Set(Some(format!("https://receiver.example/{target_address}"))),
                target_address: Set(Some(target_address.to_owned())),
                cause: Set(Some(cause.to_owned())),
                created_at: Set(created_at),
            }
            .insert(&db)
            .await
            .unwrap();
        }
    };

    let hook_a = seed_webhook("alerting-hook", group_a).await;
    let hook_b = seed_webhook("other-hook", group_b).await;
    // hook_a: a success and a 503, both "recent" (0h old), one address/cause each.
    seed_execution(hook_a, 200, true, "203.0.113.10", "first sighting", 0).await;
    seed_execution(hook_a, 503, false, "203.0.113.11", "port scan", 0).await;
    // hook_b: one success, deliberately old (200h) so the date-range filter has something to exclude.
    seed_execution(hook_b, 200, true, "198.51.100.5", "unrelated", 200).await;

    let query = |qs: String, ts: i64| {
        let app = app.clone();
        let master_key = master_key.clone();
        async move {
            let req = signed_later(inject_connect_info(Request::builder()
                .uri(format!("/api/webhooks/executions{qs}"))
                .header("X-API-Key", &master_key)), ts, "");
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
            )
            .unwrap_or(serde_json::Value::Null);
            (status, body)
        }
    };

    // `status=success` / `status=failed`.
    let (status, body) = query("?status=success".to_owned(), 1).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 2, "both successes, across both webhooks: {body}");

    let (status, body) = query("?status=failed".to_owned(), 2).await;
    assert_eq!(status, StatusCode::OK);
    let rows = body.as_array().unwrap();
    assert_eq!(rows.len(), 1, "exactly the one failed row: {body}");
    assert_eq!(rows[0]["status_code"], 503);

    // `status=<numeric code>` narrows to that exact status.
    let (status, body) = query("?status=503".to_owned(), 3).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 1, "the numeric-code form matches status_code exactly: {body}");

    // An unparseable, non-keyword status is a 400, not a silent no-op.
    let (status, body) = query("?status=not-a-status".to_owned(), 4).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "an invalid status filter must be refused: {body}");

    // `group_id` narrows to the webhook currently targeting that group.
    let (status, body) = query(format!("?group_id={group_b}"), 5).await;
    assert_eq!(status, StatusCode::OK);
    let rows = body.as_array().unwrap();
    assert_eq!(rows.len(), 1, "only hook_b's execution, via its group: {body}");
    assert_eq!(rows[0]["webhook_id"], hook_b.to_string());

    // `ip` substring-matches the triggering event's address.
    let (status, body) = query("?ip=203.0.113".to_owned(), 6).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 2, "both hook_a rows share the 203.0.113.x prefix: {body}");

    // `search` matches webhook name, address, or cause — tried one at a time so a match on the
    // wrong field can't hide a broken one.
    let (status, body) = query("?search=alerting-hook".to_owned(), 7).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 2, "search matches by webhook name: {body}");

    let (status, body) = query("?search=port+scan".to_owned(), 8).await;
    assert_eq!(status, StatusCode::OK);
    let rows = body.as_array().unwrap();
    assert_eq!(rows.len(), 1, "search matches by cause: {body}");
    assert_eq!(rows[0]["cause"], "port scan");

    let (status, body) = query("?search=198.51.100.5".to_owned(), 9).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 1, "search matches by address: {body}");

    // `from_date` excludes the 200-hour-old row; a cutoff of "now minus 1 hour" as a Unix timestamp
    // keeps only the two rows seeded at age 0.
    let recent_cutoff = (chrono::Utc::now() - chrono::Duration::hours(1)).timestamp();
    let (status, body) = query(format!("?from_date={recent_cutoff}"), 10).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 2, "from_date excludes the old row: {body}");

    // `to_date` is the mirror image: a cutoff before the two recent rows keeps only the old one.
    let old_cutoff = (chrono::Utc::now() - chrono::Duration::hours(100)).timestamp();
    let (status, body) = query(format!("?to_date={old_cutoff}"), 11).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 1, "to_date excludes the two recent rows: {body}");
}

/// **`DELETE /api/webhooks/executions/{id}`**: master may delete any execution row; a non-master may
/// delete only one belonging to a webhook it owns, and gets `404` — not `403` — for one it does not,
/// matching every other handler's oracle discipline in this file. A successful delete actually
/// removes the row, not just reports success.
#[tokio::test]
async fn s4_webhook_execution_delete_is_scoped_to_ownership() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (owner_id, owner_key) = insert_key(&db, "Owner", false, false, true, false).await;
    let (_stranger_id, stranger_key) = insert_key(&db, "Stranger", false, false, true, false).await;
    let group_id = insert_group_row(&db, "execution-delete-group").await;
    grant_perm(&db, owner_id, group_id, true, true, true, false).await;

    let webhook_id = Uuid::new_v4();
    simply_ip_vault::entities::webhook_config::ActiveModel {
        id: Set(webhook_id),
        name: Set("owned-hook".to_owned()),
        target_url: Set("https://example.com/hook".to_owned()),
        secret_token: Set(String::new()),
        auth_mode: Set("NONE".to_owned()),
        api_key: Set(None),
        hmac_template: Set(None),
        signature_header: Set(None),
        signature_prefix: Set(None),
        headers_json: Set(None),
        payload_template: Set("{}".to_owned()),
        group_id: Set(group_id),
        is_active: Set(true),
        events: Set(None),
        owner_key_id: Set(Some(owner_id)),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let seed_execution = || {
        let db = db.clone();
        async move {
            let id = Uuid::new_v4();
            simply_ip_vault::entities::webhook_execution::ActiveModel {
                id: Set(id),
                webhook_id: Set(webhook_id),
                event_type: Set("IP_ADD".to_owned()),
                status_code: Set(Some(200)),
                is_success: Set(true),
                duration_ms: Set(5),
                response_body: Set(None),
                resolved_target_url: Set(None),
                target_address: Set(None),
                cause: Set(None),
                created_at: Set(chrono::Utc::now().naive_utc()),
            }
            .insert(&db)
            .await
            .unwrap();
            id
        }
    };

    let delete = |key: &str, id: Uuid, ts: i64| {
        let app = app.clone();
        let key = key.to_owned();
        async move {
            let req = signed_later(inject_connect_info(Request::builder()
                .method("DELETE")
                .uri(format!("/api/webhooks/executions/{id}"))
                .header("X-API-Key", &key)), ts, "");
            app.oneshot(req).await.unwrap().status()
        }
    };

    // A stranger — no relationship to the owning webhook at all — gets 404, not 403: the row's
    // existence is not confirmable from outside the owner's own scope.
    let exec_for_stranger_check = seed_execution().await;
    assert_eq!(
        delete(&stranger_key, exec_for_stranger_check, 1).await,
        StatusCode::NOT_FOUND,
        "a caller with no relationship to the owning webhook must not be able to delete its executions"
    );
    assert!(
        simply_ip_vault::entities::webhook_execution::Entity::find_by_id(exec_for_stranger_check)
            .one(&db)
            .await
            .unwrap()
            .is_some(),
        "the refused delete must not have removed the row"
    );

    // The owner may delete its own execution, and the row is actually gone afterward.
    let exec_for_owner = seed_execution().await;
    assert_eq!(delete(&owner_key, exec_for_owner, 2).await, StatusCode::NO_CONTENT);
    assert!(
        simply_ip_vault::entities::webhook_execution::Entity::find_by_id(exec_for_owner)
            .one(&db)
            .await
            .unwrap()
            .is_none(),
        "a successful delete must actually remove the row, not just report success"
    );

    // Deleting the same id again is a 404 — it is genuinely gone, not merely hidden.
    assert_eq!(delete(&owner_key, exec_for_owner, 3).await, StatusCode::NOT_FOUND);

    // Master may delete any execution, owner or not.
    let exec_for_master = seed_execution().await;
    assert_eq!(delete(&master_key, exec_for_master, 4).await, StatusCode::NO_CONTENT);

    // A nonexistent id is a 404 for everyone, master included.
    assert_eq!(delete(&master_key, Uuid::new_v4(), 5).await, StatusCode::NOT_FOUND);
}

// ─────────────────────────────────────────────────────────────
// RBAC_MODEL.md §4 — visibility scopes and oracle discipline
// ─────────────────────────────────────────────────────────────

/// **§4 — the three visibility scopes, asserted in one listing.**
///
/// A parent sees its own subtree "in full, minus raw secrets", and sees a key that merely shares a
/// resource it manages "in minimal form only: id, name, and that key's rights on that resource alone.
/// Global flags, bound IPs, and unrelated resource memberships remain hidden. A single shared resource
/// must never become a keyhole into another parent's whole configuration."
///
/// The stranger — a key with no relationship to the caller at all — must not appear. What this
/// replaced returned **every key in the system in full** to any `can_manage_keys` holder, which is the
/// keyhole sentence's opposite and did not even require a shared resource.
#[tokio::test]
async fn s4_key_listing_shows_own_subtree_in_full_and_shared_keys_minimally() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (caller_id, caller_key) = insert_key(&db, "Caller", false, true, false, false).await;

    // A daughter, created through the API so the handler records the lineage.
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/keys")
        .header("X-API-Key", &caller_key)
        .header("Content-Type", "application/json")), json!({
            "name": "Own daughter", "bound_ips": "10.0.0.0/8"
        }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    let daughter_id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();

    // A group the caller manages (R2's conjunction: it already holds can_manage_keys).
    let shared = insert_group_row(&db, "shared-group").await;
    grant_perm(&db, caller_id, shared, true, true, true, true).await;

    // A peer belonging to someone else, sharing that one group — and holding a private group and
    // global scopes that must not leak through it.
    let (peer_id, _peer_key) = insert_key(&db, "Other tenant", false, true, true, true).await;
    let private = insert_group_row(&db, "other-tenants-private-group").await;
    grant_perm(&db, peer_id, shared, true, true, false, false).await;
    grant_perm(&db, peer_id, private, true, true, true, true).await;

    // A stranger with no relationship to the caller at all.
    let (stranger_id, _stranger_key) = insert_key(&db, "Stranger", false, true, true, true).await;

    let req = signed_later(inject_connect_info(Request::builder()
        .uri("/api/keys")
        .header("X-API-Key", &caller_key)), 1, "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let listing: Vec<serde_json::Value> = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();

    let by_id = |id: Uuid| listing.iter().find(|k| k["id"] == id.to_string());

    // Scope 3: the stranger is absent entirely.
    assert!(by_id(stranger_id).is_none(), "a key with no relationship to the caller must not appear");

    // Scope 1: own subtree, in full. The caller itself is the root of its own subtree.
    for (id, label) in [(caller_id, "the caller"), (daughter_id, "its daughter")] {
        let entry = by_id(id).unwrap_or_else(|| panic!("{label} must be listed"));
        assert_eq!(entry["view"], "full", "{label} is in the caller's own subtree");
        assert!(entry.get("can_manage_keys").is_some(), "{label}: global flags are visible in full view");
        assert!(entry.get("prefix").is_some(), "{label}: prefix is visible in full view");
    }
    assert_eq!(
        by_id(daughter_id).unwrap()["bound_ips"], "10.0.0.0/8",
        "§4: a parent sees its daughters' bound IPs"
    );

    // Scope 2: the peer, minimally. This is the assertion that matters.
    let peer = by_id(peer_id).expect("a key sharing a managed group must be listed");
    assert_eq!(peer["view"], "minimal");
    for withheld in ["bound_ips", "is_master", "can_manage_keys", "can_manage_webhooks", "can_create_groups", "prefix", "parent_key_id"] {
        assert!(
            peer.get(withheld).is_none(),
            "§4: '{withheld}' must not leak through a shared resource, got {peer}"
        );
    }
    let peer_groups = peer["group_permissions"].as_array().unwrap();
    assert_eq!(peer_groups.len(), 1, "only the shared group, not every membership: {peer}");
    assert_eq!(peer_groups[0]["group_name"], "shared-group");
    assert_eq!(peer_groups[0]["can_read"], true);
    assert_eq!(peer_groups[0]["can_delete"], false, "the shared row's real rights are shown");

    // The peer's *own* private group must be nowhere in the response at all — not merely absent from
    // its entry. Serialised whole so a leak through any other field is caught too.
    let rendered = serde_json::to_string(&listing).unwrap();
    assert!(
        !rendered.contains("other-tenants-private-group"),
        "a shared resource must not become a keyhole into another parent's configuration: {rendered}"
    );
    assert!(!rendered.contains(&stranger_id.to_string()), "the stranger leaked somewhere: {rendered}");

    // Control: a master still sees everything, in full — the scoping narrowed delegated callers, not
    // the endpoint.
    let req = signed_later(inject_connect_info(Request::builder()
        .uri("/api/keys")
        .header("X-API-Key", &master_key)), 2, "");
    let res = app.clone().oneshot(req).await.unwrap();
    let master_listing: Vec<serde_json::Value> = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    assert_eq!(master_listing.len(), 5, "master sees every key: {master_listing:?}");
    assert!(master_listing.iter().all(|k| k["view"] == "full"));
}

/// **`GET /api/keys` carries the exact `parent_key_id` chain the dashboard's Key Lineage view
/// reconstructs client-side** — multiple siblings under one parent, correctly distinguishable, and
/// a grandchild one level further down.
///
/// The existing view-scoping test above already covers *one* parent/daughter pair; it does not
/// prove that two daughters of the *same* parent come back individually attributable, which is
/// exactly what the lineage view's `apiKeys.filter(k => k.parent_key_id === id)` (one level of
/// children) depends on — a listing that accidentally coalesced or mis-attributed siblings would
/// pass every existing RBAC test (visibility scoping is unaffected) while silently breaking the
/// lineage UI.
#[tokio::test]
async fn s4_api_key_listing_carries_the_parent_child_chain_a_lineage_view_needs() {
    let _env_guard = ENV_MUTATION_LOCK.lock().await;

    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (parent_id, parent_key) = insert_key(&db, "Parent", false, true, false, false).await;

    // Mints a key through the real API (server-generated credentials, exactly like a real client
    // would get) and returns `(id, plaintext_key, signing_secret)` for signing that key's own
    // subsequent requests.
    let mint_child = |name: &'static str, creator_key: String, ts: i64| {
        let app = app.clone();
        async move {
            let req = signed_later(inject_connect_info(Request::builder()
                .method("POST")
                .uri("/api/keys")
                .header("X-API-Key", &creator_key)
                .header("Content-Type", "application/json")), ts, json!({ "name": name }).to_string());
            let res = app.clone().oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
            )
            .unwrap();
            let id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();
            let plaintext = body["plaintext_key"].as_str().unwrap().to_owned();
            let secret = body["signing_secret"].as_str().unwrap().to_owned();
            (id, plaintext, secret)
        }
    };

    let (child_a, child_a_plaintext, child_a_secret) = mint_child("Child A", parent_key.clone(), 1).await;
    let (child_b, _, _) = mint_child("Child B", parent_key.clone(), 2).await;

    // A grandchild needs `can_manage_keys` granted to Child A first — Master is the only one who
    // may grant it (R4), so this goes through master rather than self-granting.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("PUT")
        .uri(format!("/api/keys/{child_a}"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), 3, json!({
            "can_manage_keys": true
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = signed_later_with(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/keys")
        .header("X-API-Key", &child_a_plaintext)
        .header("Content-Type", "application/json")), &child_a_secret, 4, json!({ "name": "Grandchild" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    let grandchild_id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();

    // Parent's own listing (its "own subtree", §4) must carry the whole chain.
    let req = signed_later(inject_connect_info(Request::builder()
        .uri("/api/keys")
        .header("X-API-Key", &parent_key)), 5, "");
    let res = app.clone().oneshot(req).await.unwrap();
    let listing: Vec<serde_json::Value> = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    let by_id = |id: Uuid| listing.iter().find(|k| k["id"] == id.to_string()).unwrap();

    // Both children individually attribute their parent correctly — not merged, not swapped.
    assert_eq!(by_id(child_a)["parent_key_id"], parent_id.to_string());
    assert_eq!(by_id(child_b)["parent_key_id"], parent_id.to_string());
    assert_ne!(child_a, child_b, "sanity: two distinct children exist");

    // "One level of children" from Parent's perspective is exactly {Child A, Child B} — the
    // grandchild must not appear as a direct child of Parent, only of Child A.
    let direct_children_of_parent: Vec<&serde_json::Value> = listing
        .iter()
        .filter(|k| k["parent_key_id"] == parent_id.to_string())
        .collect();
    assert_eq!(direct_children_of_parent.len(), 2, "exactly Child A and Child B: {listing:?}");

    assert_eq!(
        by_id(grandchild_id)["parent_key_id"], child_a.to_string(),
        "the grandchild's immediate parent is Child A, not Parent"
    );
}

/// **§4 — dispatch targets are visible to their creator and Master, and to nobody else.**
///
/// The listing used to be scoped by group readability, which is the shared-resource rule §4 forbids
/// applying here — so a `can_manage_webhooks` holder saw every other tenant's integration in any group
/// it could read, target URL and headers included.
#[tokio::test]
async fn s4_webhook_listing_is_creator_private() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (alice_id, alice_key) = insert_key(&db, "Alice", false, false, true, false).await;
    let (bob_id, bob_key) = insert_key(&db, "Bob", false, false, true, false).await;

    // One group, read by both. Under the old rule that alone made each other's webhooks visible.
    let group_id = insert_group_row(&db, "shared-hook-group").await;
    grant_perm(&db, alice_id, group_id, true, true, true, false).await;
    grant_perm(&db, bob_id, group_id, true, true, true, false).await;

    let create_hook = |caller: String, name: &'static str, nth: i64| {
        let app = app.clone();
        async move {
            let req = signed_later(inject_connect_info(Request::builder()
                .method("POST")
                .uri("/api/webhooks")
                .header("X-API-Key", &caller)
                .header("Content-Type", "application/json")), nth, json!({
                    "name": name,
                    "target_url": "https://example.com/hook",
                    "secret_token": "s3cr3t",
                    "payload_template": "{}",
                    "group_id": group_id.to_string()
                }).to_string());
            assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::OK);
        }
    };
    create_hook(alice_key.clone(), "alice-hook", 1).await;
    create_hook(bob_key.clone(), "bob-hook", 2).await;

    let list_as = |caller: String, nth: i64| {
        let app = app.clone();
        async move {
            let req = signed_later(inject_connect_info(Request::builder()
                .uri("/api/webhooks")
                .header("X-API-Key", &caller)), nth, "");
            let res = app.oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            let hooks: Vec<serde_json::Value> = serde_json::from_slice(
                &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
            )
            .unwrap();
            hooks.iter().filter_map(|h| h["name"].as_str().map(str::to_owned)).collect::<Vec<_>>()
        }
    };

    assert_eq!(list_as(alice_key, 3).await, vec!["alice-hook"], "Alice sees only her own");
    assert_eq!(list_as(bob_key, 4).await, vec!["bob-hook"], "Bob sees only his own");

    let mut master_sees = list_as(master_key, 5).await;
    master_sees.sort();
    assert_eq!(master_sees, vec!["alice-hook", "bob-hook"], "the master sees both");
}

/// **`POST /api/webhooks/{id}/clone` duplicates every configuration property, assigns the caller as
/// owner, and mints a fresh signing secret rather than copying the source's.**
///
/// Exercises a `CANONICAL_V1` webhook carrying every optional field this endpoint is asked to
/// duplicate — custom headers, a non-default `hmac_template`, `signature_header`/`signature_prefix`,
/// a restricted `events` subset, `is_active: false` — so a field silently dropped by the clone would
/// show up as a mismatch here rather than passing by accident on an all-defaults fixture.
#[tokio::test]
async fn clone_webhook_duplicates_configuration_under_a_fresh_secret_and_owner() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (owner_id, owner_key) = insert_key(&db, "Webhook owner", false, false, true, false).await;
    let group_id = insert_group_row(&db, "clone-source-group").await;
    grant_perm(&db, owner_id, group_id, true, true, true, false).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/webhooks")
        .header("X-API-Key", &owner_key)
        .header("Content-Type", "application/json")), json!({
            "name": "source-hook",
            "target_url": "https://example.com/hook",
            "secret_token": "source-secret",
            "payload_template": "{\"ip\":\"$target_address\"}",
            "group_id": group_id.to_string(),
            "auth_mode": "CANONICAL_V1",
            "hmac_template": "{method}\\n/fixed/path\\n{timestamp}\\n{body}",
            "signature_header": "X-Hub-Signature-256",
            "signature_prefix": "",
            "headers_json": "{\"X-Custom\":\"yes\"}",
            "events": "IP_ADD,IP_DELETE",
            "is_active": false,
        }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    let source_id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();

    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/webhooks/{source_id}/clone"))
        .header("X-API-Key", &owner_key)
        .header("Content-Type", "application/json")), 1, json!({
            "name": "cloned-hook",
        }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "clone returns 201 Created");
    let cloned_body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    let cloned_id = Uuid::parse_str(cloned_body["id"].as_str().unwrap()).unwrap();
    assert_ne!(cloned_id, source_id, "the clone is a new row, not the same one");
    assert_eq!(cloned_body["name"], "cloned-hook");
    assert_eq!(cloned_body["target_url"], "https://example.com/hook");
    assert_eq!(cloned_body["auth_mode"], "CANONICAL_V1");
    assert_eq!(cloned_body["hmac_template"], "{method}\\n/fixed/path\\n{timestamp}\\n{body}");
    assert_eq!(cloned_body["signature_header"], "X-Hub-Signature-256");
    assert_eq!(cloned_body["signature_prefix"], "");
    assert_eq!(cloned_body["headers_json"], "{\"X-Custom\":\"yes\"}");
    assert_eq!(cloned_body["events"], "IP_ADD,IP_DELETE");
    assert_eq!(cloned_body["is_active"], false, "is_active is duplicated, not reset to the default");
    assert_eq!(cloned_body["group_id"], group_id.to_string());

    let generated_secret =
        cloned_body["secret_token"].as_str().expect("CANONICAL_V1 requires a secret, so one is generated");
    assert!(!generated_secret.is_empty());

    // The row itself: owned by the caller, not by the source's owner (trivially the same key here,
    // but the field must be populated by `resource_owner(&caller)` rather than copied), and its
    // stored secret must differ from the source's — never copied, per the handler's own doc comment.
    let source_row = simply_ip_vault::entities::prelude::WebhookConfig::find_by_id(source_id)
        .one(&db).await.unwrap().unwrap();
    let cloned_row = simply_ip_vault::entities::prelude::WebhookConfig::find_by_id(cloned_id)
        .one(&db).await.unwrap().unwrap();
    assert_eq!(cloned_row.owner_key_id, Some(owner_id));
    assert_ne!(
        cloned_row.secret_token, source_row.secret_token,
        "cloning must mint a fresh secret, never reuse the source's"
    );
    assert_eq!(cloned_row.api_key, None, "neither webhook here ever set api_key");
}

/// **Cloning follows the same §4 ownership rule as every other webhook endpoint: a group peer with
/// `can_manage_webhooks` gets `404`, not `403`, and the owner (or master) may proceed.**
#[tokio::test]
async fn clone_webhook_requires_ownership_or_master() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (_master_id, master_key) = insert_key(&db, "Master", true, true, true, true).await;
    let (owner_id, owner_key) = insert_key(&db, "Webhook owner", false, false, true, false).await;
    let (peer_id, peer_key) = insert_key(&db, "Group peer", false, false, true, false).await;

    let group_id = insert_group_row(&db, "clone-ownership-group").await;
    grant_perm(&db, owner_id, group_id, true, true, true, false).await;
    grant_perm(&db, peer_id, group_id, true, true, true, false).await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/webhooks")
        .header("X-API-Key", &owner_key)
        .header("Content-Type", "application/json")), json!({
            "name": "owned-for-cloning",
            "target_url": "https://example.com/hook",
            "secret_token": "s3cr3t",
            "payload_template": "{}",
            "group_id": group_id.to_string()
        }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    let webhook_id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();

    // Sharing the group (and holding `can_manage_webhooks`) is not owning the webhook.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/webhooks/{webhook_id}/clone"))
        .header("X-API-Key", &peer_key)
        .header("Content-Type", "application/json")), 1, json!({ "name": "hijack-clone" }).to_string());
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::NOT_FOUND,
        "a non-owner must not learn the webhook exists, let alone clone it"
    );

    // A random id that was never a webhook at all answers identically.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/webhooks/{}/clone", Uuid::new_v4()))
        .header("X-API-Key", &owner_key)
        .header("Content-Type", "application/json")), 2, json!({ "name": "nope" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::NOT_FOUND);

    // The owner may clone its own webhook.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/webhooks/{webhook_id}/clone"))
        .header("X-API-Key", &owner_key)
        .header("Content-Type", "application/json")), 3, json!({ "name": "owner-clone" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::CREATED);

    // So may a master, ownership notwithstanding.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri(format!("/api/webhooks/{webhook_id}/clone"))
        .header("X-API-Key", &master_key)
        .header("Content-Type", "application/json")), 4, json!({ "name": "master-clone" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::CREATED);
}

/// **§4 oracle discipline — an out-of-scope id answers exactly as a nonexistent one.**
///
/// "Any key, resource, or dispatch target outside the caller's visibility scope must return the
/// identical status and body the service would return if that id did not exist."
///
/// Both halves are asserted: the status *and* the body. A `404` whose body differs is still an oracle,
/// just a quieter one.
///
/// Named for the control it covers, because there are two and they are easy to conflate — see
/// `s4_authenticate_then_authorize_ordering_is_not_regressed_by_oracle_discipline`, which covers the
/// other one.
#[tokio::test]
async fn s4_oracle_discipline_an_invisible_key_is_indistinguishable_from_a_missing_one() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (master_id, _master_key) = insert_key(&db, "Master", true, true, true, true).await;
    // Holds both administrative scopes, so every refusal below comes from the *visibility* check
    // rather than from a missing scope — a caller lacking `can_manage_webhooks` is refused uniformly
    // for every id and reveals nothing, which is a different (and also correct) shape, asserted
    // separately at the end.
    let (_caller_id, caller_key) = insert_key(&db, "Caller", false, true, true, false).await;
    // A real key the caller has no relationship with, and a real webhook it did not create.
    let (stranger_id, _stranger_key) = insert_key(&db, "Stranger", false, false, false, false).await;
    let (owner_id, _owner_key) = insert_key(&db, "Hook owner", false, false, true, false).await;

    let group_id = insert_group_row(&db, "hook-group").await;
    grant_perm(&db, owner_id, group_id, true, true, true, false).await;
    let hook_id = Uuid::new_v4();
    simply_ip_vault::entities::webhook_config::ActiveModel {
        id: Set(hook_id),
        name: Set("someone-elses-hook".to_owned()),
        target_url: Set("https://example.com/h".to_owned()),
        secret_token: Set("s".to_owned()),
        auth_mode: Set("BODY_ONLY".to_owned()),
        api_key: Set(None),
        hmac_template: Set(None),
        signature_header: Set(None),
        signature_prefix: Set(None),
        headers_json: Set(None),
        payload_template: Set("{}".to_owned()),
        group_id: Set(group_id),
        owner_key_id: Set(Some(owner_id)),
        is_active: Set(true),
        events: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let absent_key = Uuid::new_v4();
    let absent_hook = Uuid::new_v4();

    let probe = |method: &'static str, path: String, nth: i64| {
        let (app, caller_key) = (app.clone(), caller_key.clone());
        async move {
            let req = signed_later(inject_connect_info(Request::builder()
                .method(method)
                .uri(path)
                .header("X-API-Key", &caller_key)), nth, "");
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            (status, String::from_utf8(body.to_vec()).unwrap())
        }
    };

    // A key outside the caller's subtree, against a key that does not exist, on every
    // credential-level operation.
    for (n, (method, suffix)) in [
        ("DELETE", ""),
        ("POST", "/rotate"),
        ("POST", "/rotate-secret"),
    ]
    .into_iter()
    .enumerate()
    {
        let n = n as i64 * 10;
        let invisible = probe(method, format!("/api/keys/{stranger_id}{suffix}"), n + 1).await;
        let missing = probe(method, format!("/api/keys/{absent_key}{suffix}"), n + 2).await;
        assert_eq!(invisible.0, StatusCode::NOT_FOUND, "{method} {suffix}: invisible must be 404");
        assert_eq!(
            invisible, missing,
            "{method} {suffix}: an invisible key must answer identically to a missing one"
        );

        // The master key specifically — the most valuable id to be able to confirm.
        let master_probe = probe(method, format!("/api/keys/{master_id}{suffix}"), n + 3).await;
        assert_eq!(
            master_probe, missing,
            "{method} {suffix}: the master key must not be enumerable through a distinct status"
        );
    }

    // A dispatch target the caller did not create.
    let invisible = probe("DELETE", format!("/api/webhooks/{hook_id}"), 100).await;
    let missing = probe("DELETE", format!("/api/webhooks/{absent_hook}"), 101).await;
    assert_eq!(invisible.0, StatusCode::NOT_FOUND);
    assert_eq!(invisible, missing, "an invisible webhook must answer identically to a missing one");

    // Nothing was actually deleted by any of the probes.
    assert!(
        simply_ip_vault::entities::prelude::ApiKey::find_by_id(stranger_id)
            .one(&db).await.unwrap().is_some()
    );
    assert!(
        simply_ip_vault::entities::prelude::WebhookConfig::find_by_id(hook_id)
            .one(&db).await.unwrap().is_some()
    );

    // The other correct shape, for contrast. A caller lacking `can_manage_webhooks` is refused
    // `403` for *every* webhook id — existing, invisible, or invented — so the refusal is a property
    // of the caller and discloses nothing about the target. Oracle discipline is about answers that
    // vary with the id, not about every refusal becoming a `404`.
    let (_scopeless_id, scopeless_key) = insert_key(&db, "No webhook scope", false, true, false, false).await;
    let scopeless_probe = |target: Uuid, nth: i64| {
        let (app, scopeless_key) = (app.clone(), scopeless_key.clone());
        async move {
            let req = signed_later(inject_connect_info(Request::builder()
                .method("DELETE")
                .uri(format!("/api/webhooks/{target}"))
                .header("X-API-Key", &scopeless_key)), nth, "");
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            (status, String::from_utf8(body.to_vec()).unwrap())
        }
    };
    let real = scopeless_probe(hook_id, 200).await;
    let invented = scopeless_probe(absent_hook, 201).await;
    assert_eq!(real.0, StatusCode::FORBIDDEN);
    assert_eq!(real, invented, "a scope refusal must be identical for every id, real or not");
}

/// **The other control: authenticate, then authorize — `401` before `403`, for unauthenticated callers.**
///
/// §4 is explicit that these are two distinct rules and that neither may be satisfied by regressing
/// the other: oracle discipline "governs *authenticated* callers distinguishing absent from invisible.
/// It is a distinct control from the authenticate-then-authorize ordering rule, which governs
/// *unauthenticated* callers probing key bindings via 401-vs-403. Both hold simultaneously."
///
/// The regression this guards against is specific: making everything `404` in pursuit of the first
/// rule would also turn a CIDR rejection into a `404`, which tells an unauthenticated attacker that
/// the key it guessed does not exist — the exact inference the ordering rule exists to prevent. A
/// caller that cannot prove possession of the signing secret must get `401` whatever else is wrong.
#[tokio::test]
async fn s4_authenticate_then_authorize_ordering_is_not_regressed_by_oracle_discipline() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    // Bound to a network the test requests do not come from.
    let (bound_id, bound_key) = insert_key(&db, "Bound", false, false, false, false).await;
    let mut active: simply_ip_vault::entities::api_key::ActiveModel =
        simply_ip_vault::entities::prelude::ApiKey::find_by_id(bound_id)
            .one(&db).await.unwrap().unwrap().into();
    active.bound_ips = Set(Some("203.0.113.0/24".to_owned()));
    active.update(&db).await.unwrap();

    // A real key, wrong signature: `401`, and it must not reveal that the key exists by any other
    // status.
    let req = signed_with(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &bound_key)), "not-the-right-secret", "");
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED,
        "an unproven caller gets 401 before any authorization question is asked"
    );

    // A key that does not exist, also wrong signature: the same `401`. Indistinguishable.
    let req = signed_with(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", "0000000000000000000000000000000000000000000000000000000000000000")),
        "not-the-right-secret", "");
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED,
        "a nonexistent key gets the same 401 — the two must not be distinguishable"
    );

    // Correct signature, wrong network: `403`, **not** `404`. This is the assertion that would break
    // if oracle discipline were implemented by turning every refusal into a 404: the caller has
    // proven possession of the signing secret, so there is nothing left to hide from it, and a `404`
    // here would make the CIDR check itself a probe.
    let req = signed_later(inject_connect_info(Request::builder()
        .uri("/api/auth/me")
        .header("X-API-Key", &bound_key)), 1, "");
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "a proven caller outside its CIDR gets 403; collapsing this to 404 would regress the ordering rule"
    );
}

// ─────────────────────────────────────────────────────────────
// RBAC_MODEL.md §6 — cascade deletion & pre-flight inventory
// ─────────────────────────────────────────────────────────────

/// Builds a three-level lineage under one manager, with resources owned at the deepest level.
///
/// Returns `(manager_key, parent_id, child_id, grandchild_id, group_id, webhook_id)`. The group and
/// webhook are owned by the **grandchild** on purpose: §6 requires the inventory to walk "the entire
/// subtree being deleted", and a walk that only inspects the target key would miss them entirely — at
/// which point deleting the parent takes a webhook with it silently, which is precisely what §6
/// forbids.
async fn nested_ownership_fixture(
    db: &DatabaseConnection,
    app: &axum::Router,
) -> (String, Uuid, Uuid, Uuid, Uuid, Uuid) {
    let (_master_id, master_key) = insert_key(db, "Master", true, true, true, true).await;
    let (manager_id, manager_key) = insert_key(db, "Manager", false, true, false, false).await;

    // Three generations, each created by the one above so the handler records the lineage.
    let mint = |caller: String, name: &'static str, nth: i64| {
        let app = app.clone();
        async move {
            let req = signed_later(inject_connect_info(Request::builder()
                .method("POST")
                .uri("/api/keys")
                .header("X-API-Key", &caller)
                .header("Content-Type", "application/json")), nth,
                json!({ "name": name, "can_manage_webhooks": false }).to_string());
            let res = app.oneshot(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK, "minting {name}");
            let body: serde_json::Value = serde_json::from_slice(
                &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
            )
            .unwrap();
            (
                Uuid::parse_str(body["id"].as_str().unwrap()).unwrap(),
                body["plaintext_key"].as_str().unwrap().to_owned(),
                body["signing_secret"].as_str().unwrap().to_owned(),
            )
        }
    };

    let (parent_id, _parent_key, _ps) = mint(manager_key.clone(), "Parent", 1).await;
    // `can_manage_keys` is master-only (R4), so the intermediate keys are promoted directly — the
    // subject here is the *shape of the tree*, not how it came to be.
    for id in [parent_id] {
        let mut active: simply_ip_vault::entities::api_key::ActiveModel =
            simply_ip_vault::entities::prelude::ApiKey::find_by_id(id)
                .one(db).await.unwrap().unwrap().into();
        active.can_manage_keys = Set(true);
        active.update(db).await.unwrap();
    }
    let (child_id, child_key, _cs) = mint(master_key.clone(), "Child", 2).await;
    let (grandchild_id, grandchild_key, grandchild_secret) =
        mint(master_key.clone(), "Grandchild", 3).await;

    // Re-parent so the tree is manager → parent → child → grandchild, regardless of who minted what.
    for (id, parent) in [(parent_id, manager_id), (child_id, parent_id), (grandchild_id, child_id)] {
        let mut active: simply_ip_vault::entities::api_key::ActiveModel =
            simply_ip_vault::entities::prelude::ApiKey::find_by_id(id)
                .one(db).await.unwrap().unwrap().into();
        active.parent_key_id = Set(Some(parent));
        active.update(db).await.unwrap();
    }

    // The grandchild owns a group and a webhook — two levels below the key that gets deleted.
    let group_id = insert_group_row(db, "deep-group").await;
    let mut active: simply_ip_vault::entities::ip_group::ActiveModel =
        simply_ip_vault::entities::prelude::IpGroup::find_by_id(group_id)
            .one(db).await.unwrap().unwrap().into();
    active.owner_key_id = Set(Some(grandchild_id));
    active.update(db).await.unwrap();

    grant_perm(db, grandchild_id, group_id, true, true, true, false).await;
    let mut active: simply_ip_vault::entities::api_key::ActiveModel =
        simply_ip_vault::entities::prelude::ApiKey::find_by_id(grandchild_id)
            .one(db).await.unwrap().unwrap().into();
    active.can_manage_webhooks = Set(true);
    active.update(db).await.unwrap();

    let req = signed_later_with(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/webhooks")
        .header("X-API-Key", &grandchild_key)
        .header("Content-Type", "application/json")), &grandchild_secret, 4, json!({
            "name": "deep-hook",
            "target_url": "https://example.com/hook",
            "secret_token": "s3cr3t",
            "payload_template": "{}",
            "group_id": group_id.to_string()
        }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    let webhook_id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();

    let _ = child_key;
    (manager_key, parent_id, child_id, grandchild_id, group_id, webhook_id)
}

/// **§6 — the pre-flight inventory walks the entire subtree, and an unresolved inventory refuses.**
///
/// "Before any key deletion, the service walks the entire subtree being deleted and collects every
/// resource and dispatch target owned by any key within it. If that inventory is non-empty, the
/// deletion is refused and returns a structured payload enumerating each owned entity with enough
/// detail to decide its fate: type, id, name, and current owner."
///
/// The fixture puts the resources **two levels below** the key being deleted, which is the case a
/// naive implementation gets wrong: inspecting only the target key finds nothing, reports no conflict,
/// and takes a webhook with it.
#[tokio::test]
async fn s6_pre_flight_inventory_walks_the_whole_subtree_and_refuses_deletion() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (manager_key, parent_id, _child_id, grandchild_id, group_id, webhook_id) =
        nested_ownership_fixture(&db, &app).await;

    let req = signed_later(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri(format!("/api/keys/{parent_id}"))
        .header("X-API-Key", &manager_key)), 10, "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT, "an unresolved inventory must refuse the deletion");

    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    let owned = body["owned_entities"].as_array().expect("the payload enumerates owned entities");
    assert_eq!(owned.len(), 2, "both the group and the webhook, from two levels down: {body}");

    // §6's four required fields, on every entry.
    for entry in owned {
        for field in ["entity_type", "id", "name", "owner_key_id", "owner_name"] {
            assert!(entry.get(field).is_some(), "§6 requires '{field}' on each entity: {entry}");
        }
        assert_eq!(
            entry["owner_key_id"], grandchild_id.to_string(),
            "the owner named is the grandchild, not the key being deleted"
        );
    }
    let types: Vec<&str> = owned.iter().filter_map(|e| e["entity_type"].as_str()).collect();
    assert!(types.contains(&"group") && types.contains(&"webhook"), "{types:?}");
    assert_eq!(body["subtree_key_count"], 3, "parent + child + grandchild");

    // Nothing happened. Not the keys, not the resources.
    for id in [parent_id, grandchild_id] {
        assert!(
            simply_ip_vault::entities::prelude::ApiKey::find_by_id(id)
                .one(&db).await.unwrap().is_some(),
            "the refusal must not have deleted any key"
        );
    }
    assert!(
        simply_ip_vault::entities::prelude::IpGroup::find_by_id(group_id)
            .one(&db).await.unwrap().is_some()
    );
    assert!(
        simply_ip_vault::entities::prelude::WebhookConfig::find_by_id(webhook_id)
            .one(&db).await.unwrap().is_some()
    );
}

/// **§6 — "Deletion executes only when every entity in the inventory carries an explicit resolution;
/// partial maps are refused."**
///
/// A partial map is the dangerous case: it looks like compliance, and applying the resolutions it does
/// carry before discovering the gap would destroy data the caller never decided about. So the check
/// runs before a single write, and the response names what is still unresolved.
#[tokio::test]
async fn s6_a_partial_resolution_map_is_refused_and_applies_nothing() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (manager_key, parent_id, _child_id, _grandchild_id, group_id, webhook_id) =
        nested_ownership_fixture(&db, &app).await;

    // Resolves the group, says nothing about the webhook.
    let partial = json!({
        "resolutions": [ { "entity_type": "group", "id": group_id.to_string(), "action": "delete" } ]
    })
    .to_string();
    let req = signed_later(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri(format!("/api/keys/{parent_id}"))
        .header("X-API-Key", &manager_key)
        .header("Content-Type", "application/json")), 10, partial);
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CONFLICT, "a partial map must be refused");
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    let unresolved = body["unresolved"].as_array().expect("the response names what is missing");
    assert_eq!(unresolved.len(), 1);
    assert_eq!(unresolved[0]["id"], webhook_id.to_string());

    // **The half it did carry was not applied.** This is the assertion that matters: the group was
    // marked for deletion and is still here.
    assert!(
        simply_ip_vault::entities::prelude::IpGroup::find_by_id(group_id)
            .one(&db).await.unwrap().is_some(),
        "a refused partial map must apply none of its resolutions"
    );
    assert!(
        simply_ip_vault::entities::prelude::ApiKey::find_by_id(parent_id)
            .one(&db).await.unwrap().is_some()
    );

    // A map naming something outside the inventory is refused too — otherwise "resolve everything"
    // could be satisfied by resolving the wrong things.
    let stray = json!({
        "resolutions": [
            { "entity_type": "group", "id": group_id.to_string(), "action": "delete" },
            { "entity_type": "webhook", "id": webhook_id.to_string(), "action": "delete" },
            { "entity_type": "group", "id": Uuid::new_v4().to_string(), "action": "delete" }
        ]
    })
    .to_string();
    let req = signed_later(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri(format!("/api/keys/{parent_id}"))
        .header("X-API-Key", &manager_key)
        .header("Content-Type", "application/json")), 11, stray);
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::BAD_REQUEST,
        "a resolution naming an entity outside the inventory is refused"
    );
    assert!(
        simply_ip_vault::entities::prelude::IpGroup::find_by_id(group_id)
            .one(&db).await.unwrap().is_some(),
        "and again, nothing was applied"
    );
}

/// **§6 — a complete map executes: the subtree cascades, and resolutions are honoured exactly.**
///
/// Reassignment must *move* ownership, not destroy — §6's "data is never destroyed implicitly" cuts
/// both ways, and a `reassign` that quietly deleted would be the worst possible reading of it. So one
/// entity is reassigned and one is deleted in the same request, and both outcomes are asserted
/// against the database rather than against the status code.
#[tokio::test]
async fn s6_a_complete_resolution_map_cascades_the_subtree_and_honours_each_resolution() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (manager_key, parent_id, child_id, grandchild_id, group_id, webhook_id) =
        nested_ownership_fixture(&db, &app).await;

    // A survivor outside the doomed subtree to receive the group.
    let (survivor_id, _survivor_key) = insert_key(&db, "Survivor", false, false, false, false).await;

    // Some IP data in the group, to prove reassignment moves the container without touching contents.
    let record_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_record::ActiveModel {
        id: Set(record_id),
        target_address: Set("203.0.113.5".to_owned()),
        cause: Set(Some("pre-cascade".to_owned())),
        is_locked: Set(false),
        is_deleted: Set(false),
        deleted_at: Set(None),
        deleted_by: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
        last_seen_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();
    simply_ip_vault::entities::ip_record_group_membership::ActiveModel {
        ip_record_id: Set(record_id),
        group_id: Set(group_id),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let complete = json!({
        "resolutions": [
            { "entity_type": "group", "id": group_id.to_string(),
              "action": "reassign", "owner_key_id": survivor_id.to_string() },
            { "entity_type": "webhook", "id": webhook_id.to_string(), "action": "delete" }
        ]
    })
    .to_string();
    let req = signed_later(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri(format!("/api/keys/{parent_id}"))
        .header("X-API-Key", &manager_key)
        .header("Content-Type", "application/json")), 10, complete);
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::NO_CONTENT,
        "a complete map executes"
    );

    // The cascade reached every generation, not just the target.
    for (id, label) in [(parent_id, "parent"), (child_id, "child"), (grandchild_id, "grandchild")] {
        assert!(
            simply_ip_vault::entities::prelude::ApiKey::find_by_id(id)
                .one(&db).await.unwrap().is_none(),
            "the {label} key must be gone — §6 cascades recursively through the subtree"
        );
    }
    assert!(
        simply_ip_vault::entities::prelude::ApiKey::find_by_id(survivor_id)
            .one(&db).await.unwrap().is_some(),
        "a key outside the subtree is untouched"
    );

    // `reassign` moved the group; it did not destroy it.
    let group = simply_ip_vault::entities::prelude::IpGroup::find_by_id(group_id)
        .one(&db).await.unwrap()
        .expect("a reassigned group survives");
    assert_eq!(group.owner_key_id, Some(survivor_id), "and it has the new owner");

    // `delete` removed the webhook.
    assert!(
        simply_ip_vault::entities::prelude::WebhookConfig::find_by_id(webhook_id)
            .one(&db).await.unwrap().is_none()
    );

    // §6: "Data is never destroyed implicitly." The IP record inside the reassigned group is
    // untouched, and so is its membership.
    let record = simply_ip_vault::entities::prelude::IpRecord::find_by_id(record_id)
        .one(&db).await.unwrap()
        .expect("resource data must survive a key cascade");
    assert!(!record.is_deleted, "and it was not soft-deleted either");
    assert_eq!(
        simply_ip_vault::entities::ip_record_group_membership::Entity::find()
            .filter(simply_ip_vault::entities::ip_record_group_membership::Column::GroupId.eq(group_id))
            .all(&db).await.unwrap().len(),
        1,
        "the record is still in the group it was reassigned with"
    );
}

/// **§6 — a key owning nothing deletes without ceremony, and reassigning into the doomed subtree is
/// refused.**
///
/// The first half keeps the inventory from becoming a tax on the common case: most keys own nothing,
/// and requiring a resolution map for them would make routine credential hygiene a two-request dance
/// for no benefit.
///
/// The second half closes the obvious way to satisfy the map while defeating it. Reassigning an entity
/// to a key that is *itself* inside the subtree being deleted reads as a rescue and is a deferred
/// orphaning: the new owner disappears microseconds later, leaving the entity unowned and master-only.
#[tokio::test]
async fn s6_an_empty_inventory_deletes_directly_and_a_doomed_reassignment_target_is_refused() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    // The fixture seeds this database's one master (§5 permits no second), so it is built first and
    // its manager is reused for the barren-key half below.
    let (manager_key, parent_id, child_id, _grandchild_id, group_id, webhook_id) =
        nested_ownership_fixture(&db, &app).await;

    // A key owning nothing: no body, no inventory, straight through.
    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/keys")
        .header("X-API-Key", &manager_key)
        .header("Content-Type", "application/json")), 5,
        json!({ "name": "Owns nothing" }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    let barren_id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();

    let req = signed_later(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri(format!("/api/keys/{barren_id}"))
        .header("X-API-Key", &manager_key)), 6, "");
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::NO_CONTENT,
        "a key owning nothing needs no resolution map"
    );

    let doomed = json!({
        "resolutions": [
            // `child_id` is inside the subtree being deleted.
            { "entity_type": "group", "id": group_id.to_string(),
              "action": "reassign", "owner_key_id": child_id.to_string() },
            { "entity_type": "webhook", "id": webhook_id.to_string(), "action": "delete" }
        ]
    })
    .to_string();
    let req = signed_later(inject_connect_info(Request::builder()
        .method("DELETE")
        .uri(format!("/api/keys/{parent_id}"))
        .header("X-API-Key", &manager_key)
        .header("Content-Type", "application/json")), 10, doomed);
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::BAD_REQUEST,
        "reassigning to a key inside the doomed subtree is a deferred orphaning, not a rescue"
    );

    // And again: nothing applied. The webhook was marked for deletion in the same refused request.
    assert!(
        simply_ip_vault::entities::prelude::WebhookConfig::find_by_id(webhook_id)
            .one(&db).await.unwrap().is_some(),
        "the validated-before-written ordering holds for this refusal too"
    );
    assert!(
        simply_ip_vault::entities::prelude::ApiKey::find_by_id(parent_id)
            .one(&db).await.unwrap().is_some()
    );
}


/// `HMAC_ONLY` withholds `X-API-Key` **even when the row has one**, and honours a custom signature
/// header and prefix.
///
/// The first half is the property the mode is named for and the reason it was renamed from
/// `BODY_ONLY`. The existing dispatch test creates a webhook with no `api_key` at all, so it cannot
/// distinguish "withheld" from "there was nothing to send" — this one populates the column and
/// asserts the header still never appears. A receiver that chose signature-only authentication must
/// not be handed a reusable bearer credential it never asked for.
///
/// The second half covers the configurable transport added alongside the rename: GitHub-style
/// receivers expect `X-Hub-Signature-256`, and some expect a bare digest with no `sha256=` prefix.
#[tokio::test]
async fn hmac_only_withholds_a_configured_api_key_and_honours_a_custom_signature_header() {
    use hmac::{Hmac, KeyInit, Mac};
    use sha2::Sha256;

    let _env_guard = ENV_MUTATION_LOCK.lock().await;
    unsafe { std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "true") };

    let (base_url, captured) = spawn_capturing_receiver().await;
    let (app, _db, plaintext, group_id) = setup_webhook_fixture("hmac-only-group").await;

    let secret = "hmac-only-secret";
    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/webhooks")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({
            "name": "Hmac Only Hook",
            "target_url": format!("{base_url}/hook"),
            "secret_token": secret,
            "payload_template": "{\"ip\":\"$target_address\"}",
            "group_id": group_id.to_string(),
            "auth_mode": "HMAC_ONLY",
            // Deliberately populated. The mode must ignore it rather than "not have one to send".
            "api_key": "a-credential-the-receiver-never-asked-for",
            "signature_header": "X-Hub-Signature-256",
            // Empty string, not omitted: a bare digest is a real choice, and treating "" as unset
            // would make it unreachable through the API.
            "signature_prefix": "",
        }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let created: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    assert_eq!(created["auth_mode"], "HMAC_ONLY");

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/ban")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")),
        json!({ "target_address": "7.7.7.7", "group_name": "hmac-only-group" }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let hit = await_dispatch(&captured).await.expect("webhook was not delivered within timeout");
    unsafe { std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "false") };

    assert!(
        hit.api_key.is_none(),
        "HMAC_ONLY must withhold X-API-Key even when the row carries one — the receiver chose \
         signature-only authentication and must not be handed a reusable secret"
    );
    assert!(hit.timestamp.is_none(), "HMAC_ONLY sends no timestamp");
    assert!(
        hit.signature.is_none(),
        "with a custom header configured, nothing may still arrive under the default name"
    );

    let signature = hit.custom_signature.expect("missing X-Hub-Signature-256");
    assert!(
        !signature.starts_with("sha256="),
        "an explicitly empty signature_prefix must produce a bare digest, got {signature:?}"
    );

    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).unwrap();
    mac.update(hit.body.expect("body").as_bytes());
    assert_eq!(
        signature,
        hex::encode(mac.finalize().into_bytes()),
        "the digest is still HMAC-SHA256 over the body alone — only its transport is configurable"
    );
}


// ═════════════════════════════════════════════════════════════
// POST /api/records/batch
// ═════════════════════════════════════════════════════════════

/// Builds an app plus a master key, for the batch tests below.
async fn batch_fixture() -> (axum::Router, DatabaseConnection, String) {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));
    let (_id, plaintext) = insert_key(&db, "Batch Tester", true, true, true, true).await;
    (app, db, plaintext)
}

/// Reads one record straight from the database, bypassing every read endpoint.
///
/// The assertions below are about columns — `created_at` preserved, `deleted_by` populated — and a
/// listing endpoint applies its own projection and scoping. Going to the row is the only way to see
/// what was actually written.
async fn raw_record_by_address(
    db: &DatabaseConnection,
    address: &str,
) -> Option<simply_ip_vault::entities::ip_record::Model> {
    simply_ip_vault::entities::ip_record::Entity::find()
        .filter(simply_ip_vault::entities::ip_record::Column::TargetAddress.eq(address.to_owned()))
        .one(db)
        .await
        .unwrap()
}

/// Re-registering an address advances `last_seen_at` and `updated_at` but never `created_at`.
///
/// `created_at` records when this service first saw the address. A sync that reports it again is not
/// a creation, and letting a client overwrite that field would make the column mean "when the
/// exporter last ran" — losing the only record of first appearance, which is what an operator asks
/// for when investigating how long something has been blocked.
#[tokio::test]
async fn batch_preserves_created_at_while_advancing_last_seen_at() {
    let (app, db, key) = batch_fixture().await;

    let post = |body: String, tick: i64| {
        let (app, key) = (app.clone(), key.clone());
        async move {
            let req = signed_later(
                inject_connect_info(
                    Request::builder()
                        .method("POST")
                        .uri("/api/records/batch")
                        .header("X-API-Key", &key)
                        .header("Content-Type", "application/json"),
                ),
                tick,
                &body,
            );
            app.oneshot(req).await.unwrap()
        }
    };

    // First sync: an explicit, old creation timestamp.
    let res = post(
        json!({
            "group_name": "batch-group",
            "records": [{
                "target_address": "203.0.113.10",
                "cause": "initial",
                "created_at": "2020-01-01T00:00:00",
                "last_seen_at": "2020-01-01T00:00:00",
            }],
        })
        .to_string(),
        1,
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let summary: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(summary["created"], 1);
    assert_eq!(summary["linked"], 1);

    let first = raw_record_by_address(&db, "203.0.113.10").await.expect("record exists");
    assert_eq!(first.created_at.to_string(), "2020-01-01 00:00:00");

    // Second sync: same address, newer activity.
    let res = post(
        json!({
            "group_name": "batch-group",
            "records": [{
                "target_address": "203.0.113.10",
                "created_at": "1999-01-01T00:00:00",
                "last_seen_at": "2026-06-01T12:00:00",
            }],
        })
        .to_string(),
        2,
    )
    .await;
    assert_eq!(res.status(), StatusCode::OK);
    let summary: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(summary["created"], 0, "the address already existed");
    assert_eq!(summary["updated"], 1);

    let second = raw_record_by_address(&db, "203.0.113.10").await.expect("record still exists");
    assert_eq!(
        second.created_at, first.created_at,
        "created_at must survive a re-sync — even one that supplies an earlier value"
    );
    assert_eq!(second.last_seen_at.to_string(), "2026-06-01 12:00:00");
    assert!(second.updated_at > first.updated_at, "updated_at advances");
    assert_eq!(second.cause.as_deref(), Some("initial"), "an omitted cause does not clear it");
}

/// A locked record is skipped, counted, and left byte-for-byte as it was.
///
/// `is_locked` is an administrative hold. A bulk sync from an external source is exactly the traffic
/// it exists to withstand — otherwise the lock protects a record only from callers who were not going
/// to touch it anyway.
#[tokio::test]
async fn batch_skips_locked_records_without_modifying_them() {
    let (app, db, key) = batch_fixture().await;
    let group_id = insert_group_row(&db, "locked-group").await;

    // A locked record, placed in the group directly.
    let record_id = Uuid::new_v4();
    let original = chrono::NaiveDateTime::parse_from_str("2021-03-04 05:06:07", "%Y-%m-%d %H:%M:%S").unwrap();
    simply_ip_vault::entities::ip_record::ActiveModel {
        id: Set(record_id),
        target_address: Set("203.0.113.20".to_owned()),
        cause: Set(Some("hands off".to_owned())),
        is_locked: Set(true),
        created_at: Set(original),
        updated_at: Set(original),
        last_seen_at: Set(original),
        is_deleted: Set(false),
        deleted_at: Set(None),
        deleted_by: Set(None),
    }
    .insert(&db)
    .await
    .unwrap();
    simply_ip_vault::entities::ip_record_group_membership::ActiveModel {
        ip_record_id: Set(record_id),
        group_id: Set(group_id),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let body = json!({
        "group_name": "locked-group",
        "records": [{
            "target_address": "203.0.113.20",
            "cause": "overwritten by the sync",
            "is_deleted": true,
        }],
    })
    .to_string();
    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/records/batch")
                .header("X-API-Key", &key)
                .header("Content-Type", "application/json"),
        ),
        body,
    );
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let summary: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(summary["locked_skipped"], 1);
    assert_eq!(summary["updated"], 0);
    assert_eq!(summary["created"], 0);

    let row = raw_record_by_address(&db, "203.0.113.20").await.expect("still there");
    assert!(row.is_locked, "the lock survives");
    assert!(!row.is_deleted, "a locked record is not soft-deleted by a batch that asks for it");
    assert_eq!(row.cause.as_deref(), Some("hands off"), "its cause is untouched");
    assert_eq!(row.updated_at, original, "not even updated_at moves");
}

/// `full_replace` soft-deletes the active records the batch omits, attributing each to the caller.
///
/// Also asserts the two exemptions, because a sweep that took everything would be a very different
/// feature: an already-deleted record is not re-deleted, and a **locked** one is never swept at all.
#[tokio::test]
async fn full_replace_soft_deletes_omitted_records_and_records_who_did_it() {
    let (app, db, key) = batch_fixture().await;
    let group_id = insert_group_row(&db, "replace-group").await;
    let key_id = simply_ip_vault::entities::api_key::Entity::find()
        .filter(simply_ip_vault::entities::api_key::Column::IsMaster.eq(true))
        .one(&db)
        .await
        .unwrap()
        .unwrap()
        .id;

    let seed = |address: &'static str, locked: bool| {
        let db = db.clone();
        async move {
            let id = Uuid::new_v4();
            let now = chrono::Utc::now().naive_utc();
            simply_ip_vault::entities::ip_record::ActiveModel {
                id: Set(id),
                target_address: Set(address.to_owned()),
                cause: Set(None),
                is_locked: Set(locked),
                created_at: Set(now),
                updated_at: Set(now),
                last_seen_at: Set(now),
                is_deleted: Set(false),
                deleted_at: Set(None),
                deleted_by: Set(None),
            }
            .insert(&db)
            .await
            .unwrap();
            simply_ip_vault::entities::ip_record_group_membership::ActiveModel {
                ip_record_id: Set(id),
                group_id: Set(group_id),
                created_at: Set(now),
                updated_at: Set(now),
            }
            .insert(&db)
            .await
            .unwrap();
        }
    };
    seed("203.0.113.31", false).await; // kept — the batch lists it
    seed("203.0.113.32", false).await; // omitted — must be swept
    seed("203.0.113.33", true).await;  // omitted but locked — must survive

    let body = json!({
        "group_name": "replace-group",
        "mode": "full_replace",
        "records": [{ "target_address": "203.0.113.31" }],
    })
    .to_string();
    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/records/batch")
                .header("X-API-Key", &key)
                .header("Content-Type", "application/json"),
        ),
        body,
    );
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let summary: serde_json::Value =
        serde_json::from_slice(&axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap())
            .unwrap();
    assert_eq!(summary["soft_deleted"], 1, "exactly the omitted unlocked record");

    let kept = raw_record_by_address(&db, "203.0.113.31").await.unwrap();
    assert!(!kept.is_deleted, "a listed record stays live");

    let swept = raw_record_by_address(&db, "203.0.113.32").await.unwrap();
    assert!(swept.is_deleted, "an omitted record is soft-deleted");
    assert!(swept.deleted_at.is_some(), "and stamped");
    assert_eq!(
        swept.deleted_by.as_deref(),
        Some(key_id.to_string().as_str()),
        "deleted_by attributes the acting key by raw id — no FK, so the attribution survives the \
         key being deleted later"
    );

    let locked = raw_record_by_address(&db, "203.0.113.33").await.unwrap();
    assert!(
        !locked.is_deleted,
        "a locked record is exempt from the sweep — an administrative hold a remote sync could \
         clear would not be a hold"
    );
}

/// `deleted_by` holds a raw key id with no foreign key, so attribution outlives the key.
///
/// The column is `Text`, not a `UUID` FK, and deliberately: a cascade or `SET NULL` on key deletion
/// would erase the record of who removed an address. This asserts both halves — the value is the
/// key's id, and deleting that key leaves it in place.
#[tokio::test]
async fn deleted_by_survives_the_deletion_of_the_key_it_names() {
    let (app, db, key) = batch_fixture().await;
    let key_id = simply_ip_vault::entities::api_key::Entity::find()
        .filter(simply_ip_vault::entities::api_key::Column::IsMaster.eq(true))
        .one(&db)
        .await
        .unwrap()
        .unwrap()
        .id;

    let body = json!({
        "group_name": "attrib-group",
        "records": [{ "target_address": "203.0.113.40", "is_deleted": true }],
    })
    .to_string();
    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/records/batch")
                .header("X-API-Key", &key)
                .header("Content-Type", "application/json"),
        ),
        body,
    );
    assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::OK);

    let row = raw_record_by_address(&db, "203.0.113.40").await.unwrap();
    assert!(row.is_deleted);
    assert_eq!(row.deleted_by.as_deref(), Some(key_id.to_string().as_str()));

    // Remove the key directly — the API refuses to delete a master, and this is about the column.
    simply_ip_vault::entities::api_key::Entity::delete_by_id(key_id).exec(&db).await.unwrap();

    let after = raw_record_by_address(&db, "203.0.113.40").await.unwrap();
    assert_eq!(
        after.deleted_by.as_deref(),
        Some(key_id.to_string().as_str()),
        "no FK means no cascade: the attribution survives the key, which is the whole point of \
         storing it as text"
    );
}

/// **`full_replace` requires `can_delete`, not merely `can_write`.**
///
/// The security property of this endpoint. `full_replace` soft-deletes every unlisted record, so a
/// key holding only `can_write` could otherwise empty a group by sending an empty batch — deletion
/// reached through a write verb. `RBAC_MODEL.md` keeps operational verbs distinct precisely so that
/// holding one never confers another, and a bulk endpoint is where that boundary erodes quietly.
///
/// Asserted in both directions: refused without `can_delete`, and permitted with it.
#[tokio::test]
async fn full_replace_requires_delete_rights_while_upsert_needs_only_write() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let group_id = insert_group_row(&db, "verbs-group").await;
    let (writer_id, writer) = insert_key(&db, "Writer", false, false, false, false).await;
    grant_perm(&db, writer_id, group_id, true, true, false, false).await; // read+write, no delete

    let call = |mode: &'static str, tick: i64, api_key: String| {
        let app = app.clone();
        async move {
            let body = json!({
                "group_name": "verbs-group",
                "mode": mode,
                "records": [{ "target_address": "203.0.113.50" }],
            })
            .to_string();
            let req = signed_later(
                inject_connect_info(
                    Request::builder()
                        .method("POST")
                        .uri("/api/records/batch")
                        .header("X-API-Key", &api_key)
                        .header("Content-Type", "application/json"),
                ),
                tick,
                &body,
            );
            app.oneshot(req).await.unwrap().status()
        }
    };

    assert_eq!(
        call("upsert", 1, writer.clone()).await,
        StatusCode::OK,
        "can_write is enough to upsert"
    );
    assert_eq!(
        call("full_replace", 2, writer.clone()).await,
        StatusCode::FORBIDDEN,
        "can_write alone must not reach a mode that deletes"
    );

    // Grant delete and the same request goes through — so the refusal was the verb, not something
    // incidental about the payload.
    grant_perm(&db, writer_id, insert_group_row(&db, "unused").await, true, true, true, false).await;
    simply_ip_vault::entities::api_key_group_permission::Entity::update_many()
        .col_expr(simply_ip_vault::entities::api_key_group_permission::Column::CanDelete, sea_orm::sea_query::Expr::value(true))
        .filter(simply_ip_vault::entities::api_key_group_permission::Column::ApiKeyId.eq(writer_id))
        .filter(simply_ip_vault::entities::api_key_group_permission::Column::GroupId.eq(group_id))
        .exec(&db)
        .await
        .unwrap();

    assert_eq!(
        call("full_replace", 3, writer).await,
        StatusCode::OK,
        "with can_delete the same request succeeds"
    );
}

/// A batch cannot insert what `POST /api/ban` refuses, and duplicates are rejected.
///
/// Both are bypass checks. A second write path that skips the validation the first enforces is not a
/// feature, it is a hole — and duplicate addresses after canonicalisation would make the result
/// depend on payload order.
#[tokio::test]
async fn batch_enforces_address_validation_and_rejects_duplicates() {
    let (app, _db, key) = batch_fixture().await;

    let call = |records: serde_json::Value, tick: i64| {
        let (app, key) = (app.clone(), key.clone());
        async move {
            let body =
                json!({ "group_name": "validation-group", "records": records }).to_string();
            let req = signed_later(
                inject_connect_info(
                    Request::builder()
                        .method("POST")
                        .uri("/api/records/batch")
                        .header("X-API-Key", &key)
                        .header("Content-Type", "application/json"),
                ),
                tick,
                &body,
            );
            app.oneshot(req).await.unwrap().status()
        }
    };

    assert_eq!(
        call(json!([{ "target_address": "not-an-ip" }]), 1).await,
        StatusCode::BAD_REQUEST,
        "malformed addresses are refused"
    );
    assert_eq!(
        call(json!([{ "target_address": "127.0.0.1" }]), 2).await,
        StatusCode::BAD_REQUEST,
        "a batch must not ban loopback — the same guard POST /api/ban applies"
    );
    assert_eq!(
        call(json!([{ "target_address": "10.0.0.1" }]), 3).await,
        StatusCode::BAD_REQUEST,
        "nor private space"
    );
    assert_eq!(
        call(
            json!([{ "target_address": "203.0.113.60" }, { "target_address": "203.0.113.60/32" }]),
            4
        )
        .await,
        StatusCode::BAD_REQUEST,
        "two spellings of one address canonicalise to a duplicate and are refused rather than \
         resolved by payload order"
    );
}

/// **`skip_webhooks: true` on `POST /api/records/batch` suppresses dispatch entirely** — the record
/// itself and the audit trail are written exactly as they would be otherwise; only the notification
/// side effect is gated. Waits out the full `await_dispatch` window to confirm the *absence* of a
/// call, and additionally checks `webhook_executions` directly — a receiver simply not being hit
/// could mean "never dispatched" or "dispatched to the wrong place", and only the row count rules the
/// second one out.
#[tokio::test]
async fn batch_skip_webhooks_true_suppresses_dispatch() {
    let _env_guard = ENV_MUTATION_LOCK.lock().await;
    unsafe { std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "true") };

    let (base_url, captured) = spawn_capturing_receiver().await;
    let (app, db, plaintext, group_id) = setup_webhook_fixture("batch-skip-group").await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/webhooks")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({
            "name": "batch-skip-hook",
            "target_url": format!("{base_url}/hook"),
            "auth_mode": "NONE",
            "payload_template": "{}",
            "group_id": group_id.to_string(),
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/records/batch")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), 1, json!({
            "group_name": "batch-skip-group",
            "skip_webhooks": true,
            "records": [{ "target_address": "198.51.100.20" }],
        }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let summary: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    assert_eq!(summary["created"], 1, "the record itself is written regardless of skip_webhooks");
    assert_eq!(
        raw_record_by_address(&db, "198.51.100.20").await.map(|r| r.target_address),
        Some("198.51.100.20".to_owned())
    );

    assert!(
        await_dispatch(&captured).await.is_none(),
        "skip_webhooks: true must not enqueue any event, so the receiver is never reached"
    );
    assert_eq!(
        simply_ip_vault::entities::webhook_execution::Entity::find().all(&db).await.unwrap().len(),
        0,
        "no execution row at all — not merely a receiver that missed the call"
    );

    unsafe { std::env::remove_var("ALLOW_PRIVATE_WEBHOOKS") };
}

/// **`skip_webhooks: false`, or the field omitted entirely, dispatches exactly as `POST /api/ban`
/// would** — one `IP_ADD` event for a batch that links a brand-new record into the group, reaching a
/// live receiver and recording a `webhook_executions` row.
#[tokio::test]
async fn batch_skip_webhooks_false_or_omitted_dispatches_normally() {
    let _env_guard = ENV_MUTATION_LOCK.lock().await;
    unsafe { std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "true") };

    let (base_url, captured) = spawn_capturing_receiver().await;
    let (app, db, plaintext, group_id) = setup_webhook_fixture("batch-dispatch-group").await;

    let req = signed(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/webhooks")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), json!({
            "name": "batch-dispatch-hook",
            "target_url": format!("{base_url}/hook"),
            "auth_mode": "NONE",
            "payload_template": "{\"ip\":\"$target_address\",\"action\":\"$action\"}",
            "group_id": group_id.to_string(),
        }).to_string());
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // `skip_webhooks` is omitted entirely — the documented default is "dispatch normally", not
    // "suppress".
    let req = signed_later(inject_connect_info(Request::builder()
        .method("POST")
        .uri("/api/records/batch")
        .header("X-API-Key", &plaintext)
        .header("Content-Type", "application/json")), 1, json!({
            "group_name": "batch-dispatch-group",
            "records": [{ "target_address": "198.51.100.30" }],
        }).to_string());
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let hit = await_dispatch(&captured)
        .await
        .expect("a batch-created record must dispatch when skip_webhooks is omitted");
    let delivered_body = hit.body.expect("body");
    assert!(delivered_body.contains("198.51.100.30"));
    assert!(
        delivered_body.contains("IP_ADD"),
        "a brand-new record/membership is classified IP_ADD, matching handle_ip_upsert's own rule: \
         got {delivered_body}"
    );

    assert_eq!(
        simply_ip_vault::entities::webhook_execution::Entity::find().all(&db).await.unwrap().len(),
        1,
        "one dispatch attempt recorded"
    );

    unsafe { std::env::remove_var("ALLOW_PRIVATE_WEBHOOKS") };
}


// ═════════════════════════════════════════════════════════════
// Batch performance and concurrent readability
// ═════════════════════════════════════════════════════════════

/// A file-backed app built through the production connection path.
///
/// The rest of this suite uses `sqlite::memory:` via `Database::connect`, which applies none of the
/// pool's pragmas — an in-memory database cannot use WAL at all. A test about lock behaviour has to
/// use the pool `main.rs` actually builds, or it measures something that is never deployed.
async fn perf_fixture() -> (axum::Router, DatabaseConnection, String, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!("vault_perf_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let url = format!("sqlite://{}", dir.join("v.db").display());

    simply_ip_vault::db::run_migrations_isolated(&url)
        .await
        .expect("migrations apply on the isolated pool");
    let db = simply_ip_vault::db::connect(&url).await.expect("file-backed pool opens");

    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state.clone());
    let (_id, plaintext) = insert_key(&db, "Perf Tester", true, true, true, true).await;
    state.master_pin.pin_at_boot(&db).await.expect("master pins");

    (app, db, plaintext, dir)
}

/// The pool's durability settings are what make a large write cheap, so they are asserted here too.
///
/// `src/db.rs` already unit-tests all four pragmas; this re-checks the two that govern write cost
/// against the very connection the benchmark below runs on. A benchmark whose fixture silently lost
/// WAL would report a number nobody could interpret.
#[tokio::test]
async fn the_benchmark_pool_really_has_wal_and_synchronous_normal() {
    use sea_orm::{ConnectionTrait, Statement};

    let (_app, db, _key, dir) = perf_fixture().await;
    let backend = db.get_database_backend();

    let read = |sql: &'static str, col: &'static str| {
        let db = db.clone();
        async move {
            db.query_one_raw(Statement::from_string(backend, sql.to_owned()))
                .await
                .unwrap()
                .unwrap()
                .try_get::<String>("", col)
                .unwrap_or_else(|_| {
                    "non-string".to_owned()
                })
        }
    };

    assert_eq!(read("PRAGMA journal_mode;", "journal_mode").await, "wal");

    let sync: i32 = db
        .query_one_raw(Statement::from_string(backend, "PRAGMA synchronous;".to_owned()))
        .await
        .unwrap()
        .unwrap()
        .try_get("", "synchronous")
        .unwrap();
    assert_eq!(sync, 1, "synchronous must be NORMAL (1), the standard companion to WAL");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A 2 000-record `upsert` followed by a 2 000-record `full_replace`, timed, with readiness probes
/// running against the same pool throughout.
///
/// # What this does and does not assert
///
/// The **timing bound is generous on purpose and is not a performance contract.** These tests build
/// in debug, on whatever machine happens to run them, alongside every other test in the suite; a
/// tight threshold would fail for reasons that have nothing to do with the code under test, and a
/// benchmark that cries wolf gets deleted rather than investigated. The bound here is wide enough to
/// be a *regression* signal — an accidental O(n²) or a per-record transaction would blow through it
/// by an order of magnitude — and nothing narrower should be read into it.
///
/// The **concurrency assertion is the real content**, and it is worth being precise about what it
/// shows. `SQLITE_MEMORY_MAX_CONNECTIONS` is 1, so a probe issued *during* the batch does not demonstrate
/// WAL reader/writer separation — it would queue on the pool regardless. What it does demonstrate is
/// the property an operator actually cares about: the batch holds the connection for a bounded time
/// and the service answers normally on either side of it, rather than the transaction wedging the
/// pool for the life of the request.
#[tokio::test]
async fn a_large_batch_completes_promptly_and_leaves_the_service_responsive() {
    use std::time::Instant;

    const RECORDS: usize = 2_000;
    /// Wide enough to be a regression signal, not a performance contract — see the doc comment.
    const BUDGET: std::time::Duration = std::time::Duration::from_secs(20);

    let (app, db, key, dir) = perf_fixture().await;

    // 198.51.100.0/22 gives 1 024 hosts per /24; four /24s cover 2 000 without touching private or
    // loopback space, which `guard_bannable_address` would refuse.
    let addresses: Vec<String> = (0..RECORDS)
        .map(|i| format!("198.51.{}.{}", 100 + (i / 250), 1 + (i % 250)))
        .collect();
    assert_eq!(
        addresses.iter().collect::<std::collections::HashSet<_>>().len(),
        RECORDS,
        "the generated addresses must be distinct, or the batch would be refused as duplicated"
    );

    let batch = |mode: &'static str, records: Vec<String>, tick: i64| {
        let (app, key) = (app.clone(), key.clone());
        async move {
            let body = json!({
                "group_name": "perf-group",
                "mode": mode,
                "records": records
                    .iter()
                    .map(|a| json!({ "target_address": a, "cause": "bulk sync" }))
                    .collect::<Vec<_>>(),
            })
            .to_string();
            let req = signed_later(
                inject_connect_info(
                    Request::builder()
                        .method("POST")
                        .uri("/api/records/batch")
                        .header("X-API-Key", &key)
                        .header("Content-Type", "application/json"),
                ),
                tick,
                &body,
            );
            let started = Instant::now();
            let res = app.oneshot(req).await.unwrap();
            let elapsed = started.elapsed();
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            (status, serde_json::from_slice::<serde_json::Value>(&bytes).unwrap(), elapsed)
        }
    };

    // ── Probes before the write ──────────────────────────────────────────────
    let probe = |path: &'static str| {
        let app = app.clone();
        async move {
            let started = Instant::now();
            let req = Request::builder().uri(path).body(Body::empty()).unwrap();
            let status = app.oneshot(req).await.unwrap().status();
            (status, started.elapsed())
        }
    };
    for path in ["/health", "/ready"] {
        let (status, took) = probe(path).await;
        assert_eq!(status, StatusCode::OK, "{path} must be healthy before the batch");
        assert!(took < BUDGET, "{path} took {took:?} before any load");
    }

    // ── The upsert ───────────────────────────────────────────────────────────
    let (status, summary, upsert_time) = batch("upsert", addresses.clone(), 1).await;
    assert_eq!(status, StatusCode::OK, "the batch must succeed: {summary}");
    assert_eq!(summary["created"], RECORDS as u64, "every record is new the first time");
    assert!(
        upsert_time < BUDGET,
        "a {RECORDS}-record upsert took {upsert_time:?}, over the {BUDGET:?} regression budget — \
         suspect a per-record transaction or a missing index rather than a slow machine"
    );

    // ── Readiness immediately afterwards ─────────────────────────────────────
    // The transaction has committed, so the pool's single connection is free again. A batch that
    // wedged it would show up here as a hang, not a slow number.
    for path in ["/health", "/ready"] {
        let (status, took) = probe(path).await;
        assert_eq!(status, StatusCode::OK, "{path} must answer after a large write");
        assert!(
            took < BUDGET,
            "{path} took {took:?} after the batch — the write held the pool longer than it should"
        );
    }

    // ── full_replace over the same set ───────────────────────────────────────
    let (status, summary, replace_time) = batch("full_replace", addresses.clone(), 2).await;
    assert_eq!(status, StatusCode::OK, "full_replace must succeed: {summary}");
    assert_eq!(summary["updated"], RECORDS as u64, "every record already existed");
    assert_eq!(
        summary["soft_deleted"], 0,
        "the batch listed every member, so full_replace has nothing to sweep"
    );
    assert!(
        replace_time < BUDGET,
        "a {RECORDS}-record full_replace took {replace_time:?}, over the {BUDGET:?} budget"
    );

    // ── full_replace with a smaller set actually sweeps ──────────────────────
    let (status, summary, _) = batch("full_replace", addresses[..10].to_vec(), 3).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        summary["soft_deleted"],
        (RECORDS - 10) as u64,
        "everything the shorter batch omitted is swept in one transaction"
    );

    // Every row is accounted for: nothing was lost, and the sweep was scoped.
    let live = simply_ip_vault::entities::ip_record::Entity::find()
        .filter(simply_ip_vault::entities::ip_record::Column::IsDeleted.eq(false))
        .all(&db)
        .await
        .unwrap()
        .len();
    assert_eq!(live, 10, "exactly the listed records remain live");

    eprintln!(
        "batch timings — upsert({RECORDS}): {upsert_time:?}, full_replace({RECORDS}): {replace_time:?}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}


// ═════════════════════════════════════════════════════════════
// Differential sync: tombstones must survive the `since` filter
// ═════════════════════════════════════════════════════════════

/// A record soft-deleted after `since` is returned as a tombstone, even though its `last_seen_at`
/// predates the cutoff.
///
/// # The bug this pins
///
/// Soft delete writes `is_deleted`, `deleted_at`, `deleted_by` and `updated_at` — but deliberately
/// **not** `last_seen_at`, which records when the address was last *observed*, not when the row was
/// last touched. Conflating the two would corrupt the field's meaning.
///
/// The `since` filter, however, tested `last_seen_at` alone. So an address last seen at T0 and
/// deleted at T1 was invisible to every `?since=` query with a cutoff after T0: the deletion had
/// happened, the tombstone existed in the database, and no differential consumer could ever learn of
/// it. Exporters and sync workers kept the entry in memory forever, and the divergence was permanent
/// rather than self-correcting — a later poll could not surface it either, because `last_seen_at`
/// only ever moves forward on re-registration, which by definition never happens to a deleted record.
///
/// # Why the four assertions
///
/// A fix that simply widened the filter would satisfy the first assertion and break the rest. The
/// tombstone must appear **only** under `include_deleted`, must disappear once the client has caught
/// up past the deletion, and must not drag in deletions older than the cutoff — otherwise every poll
/// re-delivers the whole trash and the "differential" part is lost.
#[tokio::test]
async fn test_differential_sync_includes_recently_deleted_ips() {
    let (app, db, key, dir) = perf_fixture().await;

    let group_id = insert_group_row(&db, "sync-group").await;

    // T0 — an hour ago. Seeded directly so the timestamp is exact; the deletion below still goes
    // through the real endpoint, so the code path that writes the tombstone is the deployed one.
    let t0 = chrono::Utc::now().naive_utc() - chrono::Duration::hours(1);
    let record_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_record::ActiveModel {
        id: Set(record_id),
        target_address: Set("198.51.100.77".to_owned()),
        cause: Set(Some("seeded at T0".to_owned())),
        is_locked: Set(false),
        created_at: Set(t0),
        updated_at: Set(t0),
        last_seen_at: Set(t0),
        is_deleted: Set(false),
        deleted_at: Set(None),
        deleted_by: Set(None),
    }
    .insert(&db)
    .await
    .unwrap();
    simply_ip_vault::entities::ip_record_group_membership::ActiveModel {
        ip_record_id: Set(record_id),
        group_id: Set(group_id),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let get = |path: String, tick: i64| {
        let (app, key) = (app.clone(), key.clone());
        async move {
            let req = signed_later(
                inject_connect_info(Request::builder().uri(&path).header("X-API-Key", &key)),
                tick,
                "",
            );
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            (status, String::from_utf8(bytes.to_vec()).unwrap())
        }
    };

    // T1 — delete through the API, so `deleted_at` is written by production code.
    let req = signed_later(
        inject_connect_info(
            Request::builder().method("DELETE").uri(format!("/api/ips/{record_id}")).header("X-API-Key", &key),
        ),
        1,
        "",
    );
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let row = simply_ip_vault::entities::ip_record::Entity::find_by_id(record_id)
        .one(&db)
        .await
        .unwrap()
        .expect("the row survives a soft delete");
    assert!(row.is_deleted, "the delete was soft");
    let t1 = row.deleted_at.expect("deleted_at is stamped");
    assert_eq!(row.last_seen_at, t0, "last_seen_at must NOT move on delete — that is the premise");

    let t1_epoch = t1.and_utc().timestamp();

    // 1. since = T1 → the tombstone must be delivered.
    let (status, body) = get(format!("/api/ips?since={t1_epoch}&include_deleted=true"), 2).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("198.51.100.77"),
        "a record deleted at or after `since` must reach a differential consumer even though its \
         last_seen_at predates the cutoff — otherwise the deletion is never replicated: {body}"
    );
    let items: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(
        items[0]["is_deleted"], true,
        "and it must arrive flagged as a tombstone, not as a live record"
    );

    // 2. Without the flag it stays hidden — the fix must not leak trash into ordinary listings.
    let (_, body) = get(format!("/api/ips?since={t1_epoch}"), 3).await;
    assert!(
        !body.contains("198.51.100.77"),
        "include_deleted is still what opts a caller into tombstones: {body}"
    );

    // 3. since = T2 > T1 → already replicated, must not be re-sent.
    let t2_epoch = t1_epoch + 60;
    let (_, body) = get(format!("/api/ips?since={t2_epoch}&include_deleted=true"), 4).await;
    assert!(
        !body.contains("198.51.100.77"),
        "a client that has caught up past the deletion must not receive it again, or every poll \
         re-delivers the entire trash: {body}"
    );

    // 4. A live record whose last_seen_at predates the cutoff stays excluded, so the new clause
    //    widened the filter for tombstones only and not for everything.
    let quiet_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_record::ActiveModel {
        id: Set(quiet_id),
        target_address: Set("198.51.100.88".to_owned()),
        cause: Set(None),
        is_locked: Set(false),
        created_at: Set(t0),
        updated_at: Set(t0),
        last_seen_at: Set(t0),
        is_deleted: Set(false),
        deleted_at: Set(None),
        deleted_by: Set(None),
    }
    .insert(&db)
    .await
    .unwrap();
    // Aged the same as the record — `since`'s primary arm now reads the membership's own
    // `updated_at` (`m20260926_120000`), so a membership stamped "now" would look freshly touched
    // regardless of how quiet the record it points at actually was.
    simply_ip_vault::entities::ip_record_group_membership::ActiveModel {
        ip_record_id: Set(quiet_id),
        group_id: Set(group_id),
        created_at: Set(t0),
        updated_at: Set(t0),
    }
    .insert(&db)
    .await
    .unwrap();

    let (_, body) = get(format!("/api/ips?since={t1_epoch}&include_deleted=true"), 5).await;
    assert!(
        !body.contains("198.51.100.88"),
        "a live record last seen before the cutoff is still out of scope — the deletion clause must \
         not become a second way to match everything: {body}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}


/// A batch carrying the same address twice is **refused with `400`**, never a raw database error.
///
/// # Why refusal rather than last-wins
///
/// `target_address` is UNIQUE, so a batch containing `1.2.3.4` twice — or `1.2.3.4` and
/// `1.2.3.4/32`, which canonicalise to one string — has no single correct outcome. Three were
/// available:
///
/// | Option | Why not |
/// | :--- | :--- |
/// | Let it reach the database | A `500` from a constraint violation, with the whole transaction lost and nothing said about which entry caused it |
/// | Last-wins | The result depends on **payload order**, so the same set of records syncs differently depending on how the client happened to serialise it |
/// | Refuse with `400` | Deterministic, names the offending address, and the client's own view is what needs fixing |
///
/// The client sending duplicates has an inconsistent picture of its own state — two `cause` values
/// for one address is not something the vault can reconcile on its behalf. Silently picking one would
/// hide that.
///
/// The assertion that matters most is the *negative* one: no `5xx`. A constraint violation escaping
/// to the caller would be the vault reporting its own schema as the client's problem.
#[tokio::test]
async fn test_batch_payload_internal_duplicates() {
    let (app, db, key) = batch_fixture().await;

    let post = |records: serde_json::Value, tick: i64| {
        let (app, key) = (app.clone(), key.clone());
        async move {
            let body = json!({ "group_name": "dupe-group", "records": records }).to_string();
            let req = signed_later(
                inject_connect_info(
                    Request::builder()
                        .method("POST")
                        .uri("/api/records/batch")
                        .header("X-API-Key", &key)
                        .header("Content-Type", "application/json"),
                ),
                tick,
                &body,
            );
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            (status, String::from_utf8(bytes.to_vec()).unwrap())
        }
    };

    // Identical spelling, conflicting causes — the shape the brief describes.
    let (status, body) = post(
        json!([
            { "target_address": "203.0.113.90", "cause": "first" },
            { "target_address": "203.0.113.90", "cause": "second, contradicting the first" },
        ]),
        1,
    )
    .await;

    assert!(
        !status.is_server_error(),
        "an intra-batch duplicate must never surface as a database error — the vault's UNIQUE \
         constraint is not the caller's problem to interpret (got {status}: {body})"
    );
    assert_eq!(status, StatusCode::BAD_REQUEST, "it is a malformed request: {body}");
    assert!(
        body.contains("203.0.113.90"),
        "the refusal must name the offending address so the client can fix its own view: {body}"
    );
    assert!(body.contains("uplicate"), "and say what was wrong with it: {body}");

    // Different spellings of one address collide the same way, because the check runs *after*
    // canonicalisation — otherwise the constraint would catch it instead, as a 500.
    let (status, body) = post(
        json!([
            { "target_address": "203.0.113.91", "cause": "plain" },
            { "target_address": "203.0.113.91/32", "cause": "same host, /32 spelling" },
        ]),
        2,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "two spellings of one host are a duplicate too: {body}"
    );

    // Nothing was written. The refusal happens before the transaction opens, so a rejected batch
    // leaves the database exactly as it found it — no partial application to reconcile.
    let stored = simply_ip_vault::entities::ip_record::Entity::find().all(&db).await.unwrap();
    assert!(
        stored.is_empty(),
        "a refused batch must write nothing at all, got {} row(s)",
        stored.len()
    );

    // The control: the same batch without the duplicate succeeds, so the refusal was the duplicate
    // and not something incidental about the payload.
    let (status, body) = post(
        json!([
            { "target_address": "203.0.113.90", "cause": "first" },
            { "target_address": "203.0.113.92", "cause": "distinct" },
        ]),
        3,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "distinct addresses are accepted: {body}");
}

/// A `since` far older than the retention window succeeds and returns whatever still exists.
///
/// # What is actually being checked
///
/// `since` is a *filter*, not a cursor into a log, so there is no such thing as a value that is "too
/// old" for it — a timestamp before every row simply matches every row. The failure mode worth
/// excluding is the opposite of an error: that a client resuming after a long outage silently gets an
/// empty page, or a `400`, and concludes the vault is empty.
///
/// The retention boundary is where the honest limitation lies, and it is a limitation of the *data*
/// rather than of the query. `run_retention_worker` purges soft-deleted records after
/// `IP_RETENTION_DAYS` (92 by default), so a tombstone older than that is gone from the database
/// entirely. A consumer that has been offline longer than the retention window cannot learn about
/// those deletions from any `since` value, because the rows no longer exist to be returned — it needs
/// a full resync, and no header or status code can substitute for that.
///
/// This test pins three things: the query succeeds and returns the records that *did* change inside
/// the window, a record untouched for longer than the cutoff is still excluded (so an old `since` does
/// not quietly degrade into "return everything"), and a tombstone purged by retention is
/// unrecoverable by any cutoff.
#[tokio::test]
async fn test_sync_since_older_than_retention_period() {
    let (app, db, key, dir) = perf_fixture().await;
    let group_id = insert_group_row(&db, "retention-sync").await;

    let long_ago = chrono::Utc::now().naive_utc() - chrono::Duration::days(200);
    let within_window = chrono::Utc::now().naive_utc() - chrono::Duration::days(50);
    let recent = chrono::Utc::now().naive_utc() - chrono::Duration::days(1);

    let seed = |address: &'static str, last_seen: chrono::NaiveDateTime, deleted: Option<chrono::NaiveDateTime>| {
        let db = db.clone();
        async move {
            let id = Uuid::new_v4();
            simply_ip_vault::entities::ip_record::ActiveModel {
                id: Set(id),
                target_address: Set(address.to_owned()),
                cause: Set(None),
                is_locked: Set(false),
                created_at: Set(last_seen),
                updated_at: Set(last_seen),
                last_seen_at: Set(last_seen),
                is_deleted: Set(deleted.is_some()),
                deleted_at: Set(deleted),
                deleted_by: Set(None),
            }
            .insert(&db)
            .await
            .unwrap();
            // Aged the same as `last_seen` — `since`'s primary arm now reads the membership's own
            // `updated_at` (`m20260926_120000`), so this closure's whole "how long ago" parameter
            // would be silently ignored by the filter under test if the membership stayed "now".
            simply_ip_vault::entities::ip_record_group_membership::ActiveModel {
                ip_record_id: Set(id),
                group_id: Set(group_id),
                created_at: Set(last_seen),
                updated_at: Set(last_seen),
            }
            .insert(&db)
            .await
            .unwrap();
        }
    };

    // Live, last seen 50 days ago — inside the 100-day window, so it must be returned.
    seed("198.51.100.201", within_window, None).await;
    // A recent tombstone, well inside the 92-day retention window.
    seed("198.51.100.202", recent, Some(recent)).await;
    // Live, but untouched for 200 days — *outside* the window and correctly excluded. Seeded so the
    // test distinguishes "the query works" from "the query returns everything", which an
    // over-broad filter would also satisfy.
    seed("198.51.100.203", long_ago, None).await;

    // 100 days back: older than the retention boundary, and a perfectly ordinary filter value.
    let since = (chrono::Utc::now() - chrono::Duration::days(100)).timestamp();
    let req = signed_later(
        inject_connect_info(
            Request::builder()
                .uri(format!("/api/ips?since={since}&include_deleted=true&limit=100"))
                .header("X-API-Key", &key),
        ),
        1,
        "",
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "a `since` predating the retention window is a valid filter, not an error"
    );
    let body = String::from_utf8(
        axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap().to_vec(),
    )
    .unwrap();

    assert!(
        body.contains("198.51.100.201"),
        "a live record changed inside the window is returned, so a client resuming after a long \
         outage gets data rather than an empty page: {body}"
    );
    assert!(
        body.contains("198.51.100.202"),
        "and a tombstone inside the retention window is delivered as usual: {body}"
    );
    assert!(
        !body.contains("198.51.100.203"),
        "a record untouched for longer than the cutoff is still excluded — `since` remains a \
         differential filter and does not degrade into 'return everything' just because the cutoff \
         is old: {body}"
    );

    // The boundary is a property of the data, not of the query: a tombstone purged by retention is
    // simply absent, and no `since` value can recover it. Asserted by deleting the row the way the
    // retention worker would and re-running the identical request.
    simply_ip_vault::entities::ip_record::Entity::delete_many()
        .filter(simply_ip_vault::entities::ip_record::Column::TargetAddress.eq("198.51.100.202"))
        .exec(&db)
        .await
        .unwrap();

    let req = signed_later(
        inject_connect_info(
            Request::builder()
                .uri(format!("/api/ips?since={since}&include_deleted=true&limit=100"))
                .header("X-API-Key", &key),
        ),
        2,
        "",
    );
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK, "still a successful query");
    let body = String::from_utf8(
        axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap().to_vec(),
    )
    .unwrap();
    assert!(
        !body.contains("198.51.100.202"),
        "a purged tombstone cannot be returned by any `since` — the consumer needs a full resync, \
         which is the documented limit of differential sync: {body}"
    );
    assert!(body.contains("198.51.100.201"), "the in-window live record is unaffected: {body}");

    let _ = std::fs::remove_dir_all(&dir);
}

// ─────────────────────────────────────────────────────────────
// Task 1 & 2 — GET /api/groups RBAC: read-scoped filtering for
// non-master and daughter keys
// ─────────────────────────────────────────────────────────────

/// A non-master key with `can_read` on Group A and **no access** to Group B calls
/// `GET /api/groups`. The response must be `200 OK` and contain only Group A — Group B is
/// invisible, not an error.
///
/// This is the canonical `simply_ip_exporter` use-case: a scoped API key should discover
/// exactly the groups it is entitled to read, without any `403 Forbidden` interrupting it.
#[tokio::test]
async fn test_non_master_group_listing_read_scoped() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let group_a_id = insert_group_row(&db, "group-alpha").await;
    let _group_b_id = insert_group_row(&db, "group-beta").await;

    // Non-master, no global scopes — only `can_read` on Group A.
    let (key_id, key) = insert_key(&db, "exporter-key", false, false, false, false).await;
    grant_perm(&db, key_id, group_a_id, true, false, false, false).await;

    let req = signed(
        inject_connect_info(
            Request::builder()
                .uri("/api/groups")
                .header("X-API-Key", &key),
        ),
        "",
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK, "non-master with can_read must receive 200 OK");

    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let groups: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = groups.as_array().expect("response must be an array");

    assert_eq!(arr.len(), 1, "only one group should be returned, not both");
    assert_eq!(
        arr[0]["name"].as_str().unwrap(),
        "group-alpha",
        "the returned group must be the one the key can read"
    );
}

/// A daughter key (created with a `parent_key_id`) with `can_read` on Group A calls
/// `GET /api/groups`. The response must be `200 OK` with only Group A — parentage
/// confers no elevated authority (RBAC_MODEL.md R3) and the filter is by permission row, not
/// lineage.
#[tokio::test]
async fn test_daughter_key_group_listing_is_filtered_to_readable_groups() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let group_a_id = insert_group_row(&db, "group-alpha-daughter").await;
    let _group_b_id = insert_group_row(&db, "group-beta-daughter").await;

    // "Parent" key — has can_manage_keys but does not make the daughter privileged (R3).
    let (parent_id, _parent_key) = insert_key(&db, "parent-key", false, true, false, false).await;

    // Daughter key: a non-master key whose parent_key_id is set.
    let daughter_id = Uuid::new_v4();
    let daughter_plaintext = simply_ip_vault::api::generate_random_key();
    let daughter_hash = simply_ip_vault::api::hash_key(&daughter_plaintext);
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(daughter_id),
        key_hash: Set(daughter_hash),
        signing_secret: Set(Some(stored_signing_secret(&daughter_plaintext))),
        name: Set("daughter-key".to_owned()),
        bound_ips: Set(None),
        is_master: Set(false),
        can_manage_keys: Set(false),
        can_manage_webhooks: Set(false),
        can_create_groups: Set(false),
        parent_key_id: Set(Some(parent_id)),
        prefix: Set("daught12".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    // Grant only Group A to the daughter key.
    grant_perm(&db, daughter_id, group_a_id, true, false, false, false).await;

    let req = signed(
        inject_connect_info(
            Request::builder()
                .uri("/api/groups")
                .header("X-API-Key", &daughter_plaintext),
        ),
        "",
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK, "daughter key with can_read must receive 200 OK");

    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let groups: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = groups.as_array().expect("response must be an array");

    assert_eq!(arr.len(), 1, "daughter key must see only Group A, not the parent's full scope");
    assert_eq!(arr[0]["name"].as_str().unwrap(), "group-alpha-daughter");
}

/// A non-master key with **no group permission rows** calls `GET /api/groups`. The response
/// must be `200 OK` with an empty array `[]` — never `403 Forbidden`. This is the baseline that
/// the `simply_ip_exporter` service must never regress to a 403 on, even before groups are
/// assigned to the key.
#[tokio::test]
async fn test_key_with_zero_assigned_groups_returns_empty_list() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    // Two groups exist in the system, but the key holds no rows.
    let _group_a_id = insert_group_row(&db, "group-alpha-zero").await;
    let _group_b_id = insert_group_row(&db, "group-beta-zero").await;

    let (_key_id, key) = insert_key(&db, "zero-access-key", false, false, false, false).await;

    let req = signed(
        inject_connect_info(
            Request::builder()
                .uri("/api/groups")
                .header("X-API-Key", &key),
        ),
        "",
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "a key with no groups must receive 200 OK, not 403"
    );

    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let groups: serde_json::Value = serde_json::from_slice(&body).unwrap();
    let arr = groups.as_array().expect("response body must be a JSON array");
    assert!(arr.is_empty(), "a key with no group rows must receive an empty list []");
}

/// `GET /api/ip_groups` is a route alias for `GET /api/groups`. Both routes must produce
/// byte-identical responses for the same authenticated caller, ensuring the companion exporter
/// (`simply_ip_exporter`) and any client hitting the canonical path see the same data.
#[tokio::test]
async fn test_ip_groups_alias_returns_same_result_as_groups() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let group_a_id = insert_group_row(&db, "group-alias-alpha").await;
    let _group_b_id = insert_group_row(&db, "group-alias-beta").await;

    let (key_id, key) = insert_key(&db, "alias-test-key", false, false, false, false).await;
    grant_perm(&db, key_id, group_a_id, true, false, false, false).await;

    let req_canonical = signed(
        inject_connect_info(
            Request::builder()
                .uri("/api/groups")
                .header("X-API-Key", &key),
        ),
        "",
    );
    let req_alias = signed_later(
        inject_connect_info(
            Request::builder()
                .uri("/api/ip_groups")
                .header("X-API-Key", &key),
        ),
        1,
        "",
    );

    let res_canonical = app.clone().oneshot(req_canonical).await.unwrap();
    let res_alias = app.clone().oneshot(req_alias).await.unwrap();

    assert_eq!(res_canonical.status(), StatusCode::OK);
    assert_eq!(res_alias.status(), StatusCode::OK, "/api/ip_groups must return 200 OK");

    let body_canonical = axum::body::to_bytes(res_canonical.into_body(), usize::MAX).await.unwrap();
    let body_alias = axum::body::to_bytes(res_alias.into_body(), usize::MAX).await.unwrap();

    let canonical: serde_json::Value = serde_json::from_slice(&body_canonical).unwrap();
    let alias: serde_json::Value = serde_json::from_slice(&body_alias).unwrap();

    assert_eq!(
        canonical, alias,
        "/api/ip_groups and /api/groups must return identical JSON for the same key"
    );
}
