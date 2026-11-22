//! Races and interface contracts — properties that hold by construction today and that nothing
//! currently proves.
//!
//! Adapted from `simply_hook_executor`'s suite of the same name during the Session 56 reference
//! audit. The filename is deliberately identical: the two services already share
//! `rbac_model_compliance.rs` and `source_hygiene.rs`, and a reader moving between them should not
//! have to learn a second vocabulary for the same idea.
//!
//! # Why races need their own file
//!
//! Every sequential test in this repository exercises one request at a time, which cannot distinguish
//! "this check is atomic" from "this check has a window nobody has hit yet". The anti-replay ledger is
//! the clearest case: `ReplayGuard::check_and_record` holds one lock across both the lookup and the
//! insert, so the property holds — but a future refactor splitting that into a read-lock followed by
//! a write-lock would pass all 284 existing tests and silently accept every duplicate signature that
//! arrived inside the gap. These tests fail on that change.
//!
//! # And why contracts do
//!
//! A `400` is not a contract; a `400` with a body a client can parse is. The tests here map the shape
//! actually returned for each way a request can be malformed, across every extractor and across every
//! domain module — the envelope is only a contract if it holds with no exceptions, so it is asserted
//! that way rather than on one representative route.

use std::sync::Arc;

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sea_orm::{
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, Database, DatabaseConnection, EntityTrait,
    QueryFilter,
};
use simply_ip_vault::migration::MigratorTrait;
use tower::ServiceExt;
use uuid::Uuid;

use simply_ip_vault::{create_app, crypto, migration, state::AppState};

// ─────────────────────────────────────────────────────────────
// Harness
// ─────────────────────────────────────────────────────────────
//
// Self-contained, matching the convention every other suite here follows: a refactor of one suite's
// fixtures can never silently weaken another's. The peer factored these into `tests/common/mod.rs`;
// that is cleaner in the abstract and is recorded as a recommendation in `AGENT_NOTES.MD` rather than
// applied, because consolidating six suites is mechanical churn across 284 passing tests with no
// behavioural gain.

async fn setup_test_db() -> DatabaseConnection {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migration::Migrator::up(&db, None).await.unwrap();
    db
}

fn inject_connect_info(req: axum::http::request::Builder) -> axum::http::request::Builder {
    req.extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
        [127, 0, 0, 1],
        8080,
    ))))
}

fn test_signing_secret(api_key: &str) -> String {
    format!("signing-secret-for-{api_key}")
}

/// The same secret in the shape the database actually stores.
///
/// `SecretCipher::open` is strictly fail-closed: a stored value with no recognised prefix is a
/// `MalformedCiphertext` error rather than a bare secret returned verbatim. Seeding the raw string
/// makes every request 500 — which is exactly what the first run of this file did.
fn stored_signing_secret(api_key: &str) -> String {
    format!("v1.plain.{}", hex::encode(test_signing_secret(api_key)))
}

/// Builds a signed request at an explicit timestamp.
///
/// The timestamp is a parameter rather than `now()` because the replay test needs **two requests
/// whose signatures are byte-identical**, which is only true if they sign the same instant.
fn signed_at(
    builder: axum::http::request::Builder,
    secret: &str,
    timestamp: i64,
    body: &str,
) -> Request<Body> {
    let method = builder
        .method_ref()
        .expect("a method is set")
        .as_str()
        .to_owned();
    let target = builder
        .uri_ref()
        .map(|u| {
            u.path_and_query()
                .map_or_else(|| u.path().to_owned(), |pq| pq.as_str().to_owned())
        })
        .expect("a uri is set");
    let ts = timestamp.to_string();
    let signature = crypto::compute_signature(secret, &method, &target, &ts, body.as_bytes())
        .expect("the signature computes");

    builder
        .header("X-Timestamp", ts)
        .header("X-Signature-256", signature)
        .body(Body::from(body.to_owned()))
        .expect("the request builds")
}

async fn insert_master_key(db: &DatabaseConnection, name: &str) -> String {
    insert_test_key(db, name, true).await.1
}

async fn insert_test_key(db: &DatabaseConnection, name: &str, is_master: bool) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(id),
        key_hash: Set(simply_ip_vault::api::hash_key(&plaintext)),
        signing_secret: Set(Some(stored_signing_secret(&plaintext))),
        name: Set(name.to_owned()),
        bound_ips: Set(None),
        is_master: Set(is_master),
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_create_groups: Set(true),
        parent_key_id: Set(None),
        prefix: Set(plaintext.chars().take(8).collect()),
        created_at: Set(simply_ip_vault::time_serde::now_utc()),
        updated_at: Set(simply_ip_vault::time_serde::now_utc()),
    }
    .insert(db)
    .await
    .unwrap();
    (id, plaintext)
}

async fn insert_group(db: &DatabaseConnection, name: &str) -> Uuid {
    let id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(id),
        name: Set(name.to_owned()),
        allow_private_ips: Set(false),
        group_type: Set("banlist".to_owned()),
        description: Set(None),
        owner_key_id: Set(None),
        created_at: Set(simply_ip_vault::time_serde::now_utc()),
    }
    .insert(db)
    .await
    .unwrap();
    id
}

/// Inserts an address and a live, unlocked membership of it in `group_id`. Returns the address id.
async fn insert_ip_record(db: &DatabaseConnection, address: &str, group_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let now = simply_ip_vault::time_serde::now_utc();
    simply_ip_vault::entities::ip_record::ActiveModel {
        id: Set(id),
        target_address: Set(address.to_owned()),
        created_at: Set(now),
    }
    .insert(db)
    .await
    .unwrap();
    simply_ip_vault::entities::ip_record_group_membership::ActiveModel {
        id: Set(Uuid::new_v4()),
        ip_record_id: Set(id),
        group_id: Set(group_id),
        is_locked: Set(false),
        created_at: Set(now),
        last_seen_at: Set(now),
        is_deleted: Set(false),
        deleted_at: Set(None),
        deleted_by: Set(None),
    }
    .insert(db)
    .await
    .unwrap();
    id
}

/// Sends a request and returns `(status, body)`.
async fn send(app: &axum::Router, request: Request<Body>) -> (StatusCode, String) {
    let res = app.clone().oneshot(request).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX)
        .await
        .unwrap();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

// ─────────────────────────────────────────────────────────────
// Races
// ─────────────────────────────────────────────────────────────

/// **Two byte-identical signed requests, dispatched concurrently: exactly one is honoured.**
///
/// # What this proves, and what it does not
///
/// It proves the end-to-end outcome: two identical signatures in flight at once yield one `200` and
/// one `401`. That is the property a caller observes.
///
/// It does **not** prove `ReplayGuard::check_and_record` is atomic, and it cannot. Planting a
/// deliberate check-then-insert window in the guard — lock released between the lookup and the
/// insert, widened with a 50 ms sleep — leaves this test passing, on a multi-threaded runtime, every
/// time. The reason is structural: `auth_middleware` performs a database lookup *before* reaching the
/// replay guard, and `SQLITE_MEMORY_MAX_CONNECTIONS` is 1, so the two requests serialise on the pool long
/// before they ever contend for the ledger. The guard is simply never raced in this configuration.
///
/// That is worth knowing rather than papering over — it means the SQLite deployment gets replay
/// safety partly from the connection pool, which is not where anyone would look for it, and a future
/// move to PostgreSQL with a real pool removes that accidental serialisation.
///
/// Atomicity is therefore asserted directly against the guard in
/// [`the_replay_ledger_admits_one_winner_under_real_thread_contention`], which does catch the planted
/// window. This test covers the wiring; that one covers the invariant.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_concurrent_identical_signed_requests_only_one_succeeds() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = Arc::new(create_app(state.clone()));

    let master = insert_master_key(&db, "Racer").await;
    let secret = test_signing_secret(&master);
    state
        .master_pin
        .pin_at_boot(&db)
        .await
        .expect("the master pins");

    // One timestamp, so both signatures are the same bytes. That is what makes the second a replay
    // rather than merely a second request.
    let timestamp = time::OffsetDateTime::now_utc().unix_timestamp();
    let build = || {
        signed_at(
            inject_connect_info(
                Request::builder()
                    .uri("/api/ips")
                    .header("X-API-Key", &master),
            ),
            &secret,
            timestamp,
            "",
        )
    };

    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..2 {
        let app = Arc::clone(&app);
        let request = build();
        tasks.spawn(async move { send(&app, request).await.0 });
    }

    let mut statuses = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        statuses.push(joined.expect("neither task may panic"));
    }

    let accepted = statuses.iter().filter(|s| **s == StatusCode::OK).count();
    let refused = statuses
        .iter()
        .filter(|s| **s == StatusCode::UNAUTHORIZED)
        .count();

    assert_eq!(
        accepted, 1,
        "exactly one of two identical signatures may be honoured, got {statuses:?}. Two successes \
         mean the ledger checks and then inserts with a window in between — the replay window an \
         attacker resending a captured request is aiming at"
    );
    assert_eq!(
        refused, 1,
        "the loser is refused with 401, got {statuses:?}"
    );
}

/// **Two concurrent deletes of one record leave it soft-deleted exactly once.**
///
/// Our contract differs from the peer's here, and the test says so rather than copying its assertion.
/// `delete_ip_record` is *deliberately idempotent*: a record already in the trash reports success
/// without moving `deleted_at`, so that a client retrying after a timeout is not told its own earlier
/// delete failed. Two concurrent successes are therefore allowed.
///
/// What is not allowed is the row ending up inconsistent — deleted without a timestamp, timestamped
/// twice, or duplicated. Those are what a lost update or a torn read-modify-write would produce, and
/// they are what this asserts.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_concurrent_deletes_of_the_same_record_are_idempotent() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = Arc::new(create_app(state.clone()));

    let master = insert_master_key(&db, "Deleter").await;
    let secret = test_signing_secret(&master);
    state
        .master_pin
        .pin_at_boot(&db)
        .await
        .expect("the master pins");

    let group = insert_group(&db, "race-group").await;
    let record = insert_ip_record(&db, "198.51.100.150", group).await;
    // The delete addresses the membership by (address, group), per `DELETE /api/ips`.
    let body = format!(r#"{{"target_address":"198.51.100.150","group_id":"{group}"}}"#);

    let mut tasks = tokio::task::JoinSet::new();
    for offset in 0..2 {
        let app = Arc::clone(&app);
        // Distinct timestamps: two identical DELETEs would otherwise be a replay, and this test is
        // about the delete path rather than about the ledger.
        let request = signed_at(
            inject_connect_info(
                Request::builder()
                    .method("DELETE")
                    .uri("/api/ips")
                    .header("X-API-Key", &master)
                    .header("Content-Type", "application/json"),
            ),
            &secret,
            time::OffsetDateTime::now_utc().unix_timestamp() + offset,
            &body,
        );
        tasks.spawn(async move { send(&app, request).await });
    }

    let mut statuses = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        let (status, body) = joined.expect("neither delete task may panic");
        assert!(
            !status.is_server_error(),
            "a concurrent delete must not surface as a server error: {status} {body}"
        );
        statuses.push(status);
    }
    assert!(
        statuses.iter().all(axum::http::StatusCode::is_success),
        "both deletes report success, because the endpoint is idempotent by contract: {statuses:?}"
    );

    // The membership is intact and deleted exactly once.
    let rows = simply_ip_vault::entities::ip_record_group_membership::Entity::find()
        .filter(
            simply_ip_vault::entities::ip_record_group_membership::Column::IpRecordId.eq(record),
        )
        .filter(simply_ip_vault::entities::ip_record_group_membership::Column::GroupId.eq(group))
        .all(&db)
        .await
        .unwrap();
    assert_eq!(
        rows.len(),
        1,
        "no duplicate membership was produced by the race"
    );
    assert!(rows[0].is_deleted, "the record is soft-deleted");
    assert!(
        rows[0].deleted_at.is_some(),
        "and stamped — deleted without a timestamp is the torn state this test exists to exclude"
    );
    assert!(rows[0].deleted_by.is_some(), "and attributed");
}

// ─────────────────────────────────────────────────────────────
// Contracts
// ─────────────────────────────────────────────────────────────

/// **Every way a request can be malformed is refused with `400` — and every refusal is JSON.**
///
/// This maps the shape actually returned for each malformed input.
///
/// `error.rs` renders every `AppError` as `{"error": "..."}`, and `FILE_MAP.MD` describes that as the
/// contract these routes honour. It used to have two exceptions: axum's built-in `Path<Uuid>` and
/// `Query<T>` rejections are emitted by axum itself, before any handler runs, as `text/plain`, and no
/// handler in the crate had a chance to translate them. `src/extract.rs`'s `StrictPath` and
/// `StrictQuery` close that — every handler in `src/api/` now takes them instead of the bare axum
/// extractors, converging on the same wrapper `simply_hook_executor` already used.
///
/// | Request | Status | Body |
/// | :--- | :--- | :--- |
/// | `DELETE /api/ips/not-a-uuid` | `400` | `{"error": "Invalid URL: Cannot parse …"}` — JSON, via `StrictPath` |
/// | `GET /api/ips?limit=abc` | `400` | `{"error": "Failed to deserialize query string: …"}` — JSON, via `StrictQuery` |
/// | `GET /api/ips?since=<out of range>` | `400` | `{"error": "Invalid \`since\` timestamp"}` — JSON, handler-level |
/// | malformed JSON body | `400` | `{"error": "..."}` — JSON, via `StrictJson` |
///
/// A client doing `response.json().error` now gets a message on every row above, at the same status.
/// The two extractor-level rows and the two handler-level rows are still worth telling apart in the
/// assertions below — same envelope, different origin — since a regression that reintroduces a bare
/// `Path`/`Query` anywhere in `src/api/` would otherwise only show up as a missing `error` field on
/// whichever route it was left on, easy to miss in a suite of hundreds of assertions.
#[tokio::test]
async fn malformed_input_is_refused_on_every_extractor() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state.clone());

    let master = insert_master_key(&db, "Fuzzer").await;
    let secret = test_signing_secret(&master);
    state
        .master_pin
        .pin_at_boot(&db)
        .await
        .expect("the master pins");

    let mut tick = 0i64;
    let mut call = |method: &'static str, uri: String, body: &'static str| {
        tick += 1;
        let builder = inject_connect_info(
            Request::builder()
                .method(method)
                .uri(&uri)
                .header("X-API-Key", &master),
        );
        let builder = if body.is_empty() {
            builder
        } else {
            builder.header("Content-Type", "application/json")
        };
        let request = signed_at(
            builder,
            &secret,
            time::OffsetDateTime::now_utc().unix_timestamp() + tick,
            body,
        );
        let app = app.clone();
        async move { send(&app, request).await }
    };

    // 1. A body that is not JSON at all. Routed through `StrictJson`, so it keeps the JSON shape.
    let (status, body) = call("POST", "/api/records/batch".to_owned(), "{not json").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a non-JSON body is a 400: {body}"
    );
    assert!(
        body.contains("\"error\""),
        "`StrictJson` keeps the documented envelope: {body}"
    );

    // 2. Valid JSON, wrong shape. `deny_unknown_fields` refuses it in the type.
    let (status, body) = call(
        "POST",
        "/api/records/batch".to_owned(),
        r#"{"group_name":"g","records":[],"nope":1}"#,
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unknown field is a 400: {body}"
    );
    assert!(body.contains("\"error\""), "and stays JSON: {body}");
    assert!(
        body.contains("nope"),
        "and names the offending field: {body}"
    );

    // 3. An unparseable UUID path parameter — routed through `StrictPath`, so it keeps the JSON
    //    shape even though axum itself rejects it before any handler runs. `DELETE /api/ips/{id}` no
    //    longer exists, so the path-parameter case is exercised on a route that still takes one.
    let (status, body) = call("DELETE", "/api/groups/not-a-uuid".to_owned(), "").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unparseable path id is a 400: {body}"
    );
    assert!(
        body.contains("\"error\""),
        "`StrictPath` wraps axum's own rejection in the documented envelope: {body}"
    );

    // 4. A non-numeric query parameter — routed through `StrictQuery`, likewise wrapped.
    let (status, body) = call("GET", "/api/ips?limit=abc".to_owned(), "").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a non-numeric limit is a 400: {body}"
    );
    assert!(
        body.contains("\"error\""),
        "`StrictQuery` wraps axum's own rejection in the documented envelope: {body}"
    );

    // 5. A query parameter that parses but is out of range reaches our handler, so it *is* JSON.
    //    The contrast with 4 is the whole finding: same status, same endpoint, two body shapes,
    //    decided by whether the value failed to parse or failed to validate.
    let (status, body) = call("GET", "/api/ips?since=99999999999999".to_owned(), "").await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an out-of-range timestamp is a 400: {body}"
    );
    assert!(
        body.contains("\"error\""),
        "a handler-level refusal keeps the envelope, unlike the extractor-level one above: {body}"
    );

    // 6. The control: a well-formed request on the same routes succeeds, so the refusals above are
    //    the malformed input and not something incidental about the harness.
    let (status, body) = call("GET", "/api/ips?limit=10".to_owned(), "").await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a well-formed request still works: {body}"
    );
}

/// **`#[serde(deny_unknown_fields)]` refuses an unrecognized field on every domain payload, not just
/// the key-administration ones §5 names explicitly.**
///
/// `rbac_model_compliance.rs` already pins this for `CreateApiKeyPayload`/`UpdateApiKeyPayload`,
/// where it is a named RBAC §5 control (`is_master` must be unreachable, not merely rejected at a
/// handler). This test covers the same property on the payloads that carry no such named control but
/// would have exactly the same silent-drop failure mode if the annotation were ever removed: an IP
/// group, a ban, a whitelist entry, and a webhook — one caller-supplied unrecognized field each,
/// asserted refused with `400` and the field named in the JSON envelope, not silently accepted and
/// dropped.
#[tokio::test]
async fn unknown_fields_are_refused_across_every_domain_payload() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state.clone());

    let master = insert_master_key(&db, "Strictness Fuzzer").await;
    let secret = test_signing_secret(&master);
    state
        .master_pin
        .pin_at_boot(&db)
        .await
        .expect("the master pins");
    let group_id = insert_group(&db, "strictness-fuzzer-group").await;

    let mut tick = 0i64;
    let mut post = |uri: &'static str, body: String| {
        tick += 1;
        let builder = api_request("POST", uri, &master).header("Content-Type", "application/json");
        let request = signed_at(
            builder,
            &secret,
            time::OffsetDateTime::now_utc().unix_timestamp() + tick,
            &body,
        );
        let app = app.clone();
        async move { send(&app, request).await }
    };

    // Otherwise well-formed groups payload, plus one field CreateIpGroupPayload does not declare.
    let (status, body) = post(
        "/api/groups",
        r#"{"name":"strictness-test-group","group_type":"banlist","not_a_real_field":true}"#
            .to_owned(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unknown field on group creation is a 400: {body}"
    );
    assert!(
        body.contains("\"error\""),
        "and keeps the JSON envelope: {body}"
    );
    assert!(
        body.contains("not_a_real_field"),
        "and names the offending field: {body}"
    );

    // Ban: otherwise well-formed BanWhitePayload, plus an unrecognized field.
    let (status, body) = post(
        "/api/ban",
        format!(
            r#"{{"target_address":"203.0.113.50","group_id":"{group_id}","cause":"test","admin_override":true}}"#
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unknown field on /api/ban is a 400: {body}"
    );
    assert!(
        body.contains("\"error\""),
        "and keeps the JSON envelope: {body}"
    );
    assert!(
        body.contains("admin_override"),
        "and names the offending field: {body}"
    );

    // Whitelist: same struct, same control, different route — proving the annotation is on
    // `BanWhitePayload` itself rather than duplicated (and potentially missed) at one call site.
    let (status, body) = post(
        "/api/white",
        format!(
            r#"{{"target_address":"203.0.113.60","group_id":"{group_id}","cause":"test","admin_override":true}}"#
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unknown field on /api/white is a 400: {body}"
    );
    assert!(
        body.contains("\"error\""),
        "and keeps the JSON envelope: {body}"
    );
    assert!(
        body.contains("admin_override"),
        "and names the offending field: {body}"
    );

    assert_webhook_schema_is_strict(post, group_id).await;
}

async fn assert_webhook_schema_is_strict(
    mut post: impl AsyncFnMut(&'static str, String) -> (StatusCode, String),
    group_id: Uuid,
) {
    // Webhook: otherwise well-formed CreateWebhookPayload, plus an unrecognized field.
    let (status, body) = post(
        "/api/webhooks",
        format!(
            r#"{{"name":"strictness-test-hook","target_url":"https://example.invalid/hook",
                "payload_template":"{{}}","group_id":"{group_id}","not_a_real_field":true}}"#
        ),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "an unknown field on webhook creation is a 400: {body}"
    );
    assert!(
        body.contains("\"error\""),
        "and keeps the JSON envelope: {body}"
    );
    assert!(
        body.contains("not_a_real_field"),
        "and names the offending field: {body}"
    );

    // The control: the same four payloads, well-formed, all succeed — so the refusals above are the
    // unrecognized field and not something incidental about the request shape.
    let (status, body) = post(
        "/api/groups",
        r#"{"name":"strictness-control-group","group_type":"banlist"}"#.to_owned(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the well-formed control request must still work: {body}"
    );
}

/// **The replay ledger admits exactly one winner when genuinely contended.**
///
/// Asserted against [`simply_ip_vault::replay::ReplayGuard`] directly, with OS threads and a barrier,
/// rather than through HTTP. The end-to-end test above cannot reach this property: the request path
/// takes a database connection first, and the SQLite pool holds one, so two requests never contend
/// for the ledger at all.
///
/// Removing the middle layer is what makes the test able to fail. A check-then-insert split — lock
/// released between the lookup and the insert, which is the natural shape of a "fast path" refactor
/// since the common case is a miss — lets several threads all observe the digest as unseen and all
/// return `true`. Verified by planting exactly that: this assertion fails, while every other test in
/// the repository, including the HTTP one above, still passes.
///
/// `THREADS` is deliberately larger than two. A two-way race can be lost by scheduling; sixteen
/// threads released from one barrier will interleave.
#[test]
fn the_replay_ledger_admits_one_winner_under_real_thread_contention() {
    use simply_ip_vault::replay::ReplayGuard;
    use std::sync::{Arc, Barrier};

    const THREADS: usize = 16;
    const ROUNDS: usize = 25;

    for round in 0..ROUNDS {
        let guard = Arc::new(ReplayGuard::default());
        let barrier = Arc::new(Barrier::new(THREADS));
        let key_id = Uuid::new_v4();
        // A fresh digest each round: one accepted signature per round is the whole point, so reusing
        // a digest across rounds would make every round after the first trivially refuse.
        let digest = format!("digest-{round}").into_bytes();

        let winners: Vec<bool> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..THREADS)
                .map(|_| {
                    let guard = Arc::clone(&guard);
                    let barrier = Arc::clone(&barrier);
                    let digest = digest.clone();
                    scope.spawn(move || {
                        // Every thread blocks here and is released together, so they reach
                        // `check_and_record` at genuinely the same moment.
                        barrier.wait();
                        guard.check_and_record(key_id, &digest)
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("no thread may panic"))
                .collect()
        });

        let accepted = winners.iter().filter(|w| **w).count();
        assert_eq!(
            accepted, 1,
            "round {round}: {THREADS} threads raced one digest and {accepted} were accepted. \
             More than one means the ledger checks and then inserts with a window in between — the \
             exact window an attacker resending a captured request aims at. Exactly zero means the \
             guard is refusing a first-time signature."
        );
    }
}

/// A distinct digest, or a distinct key, is not a replay — the ledger keys on both.
///
/// The companion to the test above: a guard that refused *everything* under contention would satisfy
/// "exactly one winner" for one digest while breaking the service entirely. This pins that the
/// refusal is scoped to the identical (key, digest) pair.
#[test]
fn the_replay_ledger_scopes_its_refusal_to_one_key_and_digest() {
    use simply_ip_vault::replay::ReplayGuard;

    let guard = ReplayGuard::default();
    let key_a = Uuid::new_v4();
    let key_b = Uuid::new_v4();

    assert!(
        guard.check_and_record(key_a, b"one"),
        "a first-time signature is accepted"
    );
    assert!(
        !guard.check_and_record(key_a, b"one"),
        "the identical pair is a replay"
    );
    assert!(
        guard.check_and_record(key_a, b"two"),
        "a different digest under the same key is new"
    );
    assert!(
        guard.check_and_record(key_b, b"one"),
        "the same digest under a different key is new — the ledger is keyed on both, so one key \
         cannot exhaust another's signature space"
    );
}

fn api_request(
    method: &str,
    uri: impl AsRef<str>,
    key: impl AsRef<str>,
) -> axum::http::request::Builder {
    inject_connect_info(
        Request::builder()
            .method(method)
            .uri(uri.as_ref())
            .header("X-API-Key", key.as_ref()),
    )
}

struct BanPolicyApi {
    app: axum::Router,
    db: DatabaseConnection,
    key: String,
    timestamp: i64,
}

impl BanPolicyApi {
    async fn new(normalize_ipv6: bool) -> Self {
        let db = setup_test_db().await;
        let key = insert_master_key(&db, "Policy administrator").await;
        let (webhook_tx, _rx) = tokio::sync::mpsc::channel(32);
        let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new())
            .with_ipv6_48_normalization(normalize_ipv6);
        Self {
            app: create_app(state),
            db,
            key,
            timestamp: time::OffsetDateTime::now_utc().unix_timestamp(),
        }
    }

    async fn call(
        &mut self,
        method: &str,
        path: &str,
        body: serde_json::Value,
        expected: StatusCode,
    ) -> serde_json::Value {
        self.timestamp += 1;
        let body = if body.is_null() {
            String::new()
        } else {
            body.to_string()
        };
        let request = signed_at(
            inject_connect_info(Request::builder().method(method).uri(path))
                .header("X-API-Key", &self.key)
                .header("Content-Type", "application/json"),
            &test_signing_secret(&self.key),
            self.timestamp,
            &body,
        );
        let (status, body) = send(&self.app, request).await;
        assert_eq!(status, expected, "{method} {path}\n{body}");
        if body.is_empty() {
            serde_json::Value::Null
        } else {
            serde_json::from_str(&body).unwrap()
        }
    }

    async fn group(&mut self, name: &str, group_type: &str) -> serde_json::Value {
        self.call(
            "POST",
            "/api/groups",
            serde_json::json!({ "name": name, "group_type": group_type }),
            StatusCode::OK,
        )
        .await
    }

    async fn record(
        &mut self,
        path: &str,
        group: &str,
        address: &str,
        status: StatusCode,
    ) -> serde_json::Value {
        let method = if path == "/api/ips" { "DELETE" } else { "POST" };
        self.call(
            method,
            path,
            serde_json::json!({
                "group_name": group, "target_address": address
            }),
            status,
        )
        .await
    }
}

#[tokio::test]
async fn private_bans_require_opt_in_on_single_batch_and_restore() {
    use serde_json::{Value, json};
    let mut api = BanPolicyApi::new(false).await;
    api.record("/api/ban", "missing", "10.0.0.1", StatusCode::BAD_REQUEST)
        .await;
    assert_eq!(
        api.call("GET", "/api/groups", Value::Null, StatusCode::OK)
            .await,
        json!([])
    );
    let group = api.group("internal", "banlist").await;
    assert_eq!(group["allow_private_ips"], false);
    let update = format!("/api/ip_groups/{}", group["id"].as_str().unwrap());
    api.record("/api/ban", "internal", "10.0.0.1", StatusCode::BAD_REQUEST)
        .await;
    let batch = json!({"group_name":"internal", "records":[{"target_address":"100.64.0.1"}, {"target_address":"fd00::/64"}]});
    api.call(
        "POST",
        "/api/records/batch",
        batch.clone(),
        StatusCode::BAD_REQUEST,
    )
    .await;

    let response = api
        .call(
            "PUT",
            &update,
            json!({"allow_private_ips": true}),
            StatusCode::OK,
        )
        .await;
    assert_eq!(response["allow_private_ips"], true);
    api.record("/api/ban", "internal", "10.0.0.1", StatusCode::OK)
        .await;
    let response = api
        .call("POST", "/api/records/batch", batch, StatusCode::OK)
        .await;
    assert_eq!(response["linked"], 2);
    assert_eq!(response["skipped_excluded"], 0);
    for address in [
        "127.0.0.1",
        "169.254.5.5",
        "ff02::1",
        "192.0.2.3",
        "::ffff:127.0.0.0/104",
    ] {
        api.record("/api/ban", "internal", address, StatusCode::BAD_REQUEST)
            .await;
    }
    api.record("/api/ips", "internal", "10.0.0.1", StatusCode::NO_CONTENT)
        .await;
    api.call(
        "PUT",
        &update,
        json!({"allow_private_ips": false}),
        StatusCode::OK,
    )
    .await;
    api.record(
        "/api/ips/restore",
        "internal",
        "10.0.0.1",
        StatusCode::BAD_REQUEST,
    )
    .await;
    api.call(
        "PUT",
        &update,
        json!({"allow_private_ips": true}),
        StatusCode::OK,
    )
    .await;
    api.record("/api/ips/restore", "internal", "10.0.0.1", StatusCode::OK)
        .await;
}

#[tokio::test]
async fn group_policy_rejects_invalid_configuration() {
    use serde_json::json;

    let mut api = BanPolicyApi::new(false).await;
    let white = api.group("trusted", "whitelist").await;
    let other = api.group("another", "banlist").await;
    let white_id = &white["id"];
    let missing = Uuid::new_v4();
    for payload in [
        json!({"group_type":"whitelist", "allow_private_ips":true}),
        json!({"group_type":"whitelist", "excluded_whitelist_ids":[white_id]}),
        json!({"excluded_whitelist_ids":[missing]}),
        json!({"excluded_whitelist_ids":[other["id"]]}),
    ] {
        let mut payload = payload;
        payload["name"] = json!("invalid");
        api.call("POST", "/api/groups", payload, StatusCode::BAD_REQUEST)
            .await;
    }

    let ban = api
        .call(
            "POST",
            "/api/groups",
            json!({
                "name":"guarded", "excluded_whitelist_ids":[white_id, white_id]
            }),
            StatusCode::OK,
        )
        .await;
    assert_eq!(ban["excluded_whitelist_ids"], json!([white_id]));
    assert_eq!(ban["excluded_whitelist_names"], json!(["trusted"]));
    assert!(ban["description"].is_null());
    assert!(ban["owner_key_id"].is_null());
    assert!(ban["created_at"].is_string());
    let ban_id = ban["id"].as_str().unwrap();
    let update = format!("/api/groups/{ban_id}");
    let white_path = format!("/api/groups/{}", white_id.as_str().unwrap());

    for payload in [
        json!({"excluded_whitelist_ids":[ban_id]}),
        json!({"excluded_whitelist_ids":[other["id"]]}),
        json!({"excluded_whitelist_ids":[white_id, missing]}),
        json!({"group_type":"whitelist"}),
    ] {
        api.call("PUT", &update, payload, StatusCode::BAD_REQUEST)
            .await;
    }
    api.call(
        "PUT",
        &white_path,
        json!({"allow_private_ips":true}),
        StatusCode::BAD_REQUEST,
    )
    .await;
    api.call(
        "PUT",
        &white_path,
        json!({"excluded_whitelist_ids":[white_id]}),
        StatusCode::BAD_REQUEST,
    )
    .await;
    api.call(
        "PUT",
        &update,
        json!({"name":"another", "excluded_whitelist_ids":[]}),
        StatusCode::CONFLICT,
    )
    .await;
}

#[tokio::test]
async fn group_policy_replaces_exclusions_and_cascades() {
    use serde_json::{Value, json};
    use simply_ip_vault::entities::{audit_log, ip_group_exclusion};

    let mut api = BanPolicyApi::new(false).await;
    let white = api.group("trusted", "whitelist").await;
    let white_id = &white["id"];
    let ban = api
        .call(
            "POST",
            "/api/groups",
            json!({
                "name":"guarded", "excluded_whitelist_ids":[white_id]
            }),
            StatusCode::OK,
        )
        .await;
    let ban_id = ban["id"].as_str().unwrap();
    let update = format!("/api/groups/{ban_id}");
    let white_path = format!("/api/groups/{}", white_id.as_str().unwrap());

    let response = api
        .call("PUT", &update, json!({"name":"renamed"}), StatusCode::OK)
        .await;
    assert_eq!(response["excluded_whitelist_ids"], json!([white_id]));
    assert_eq!(response["name"], "renamed");
    let response = api
        .call(
            "PUT",
            &update,
            json!({"excluded_whitelist_ids":[]}),
            StatusCode::OK,
        )
        .await;
    assert_eq!(response["excluded_whitelist_ids"], json!([]));
    api.call(
        "PUT",
        &update,
        json!({"excluded_whitelist_ids":[white_id, white_id]}),
        StatusCode::OK,
    )
    .await;
    let listed = api
        .call("GET", "/api/groups", Value::Null, StatusCode::OK)
        .await;
    let group = listed
        .as_array()
        .unwrap()
        .iter()
        .find(|g| g["id"] == ban_id)
        .unwrap();
    assert_eq!(group["excluded_whitelist_names"], json!(["trusted"]));
    assert_eq!(
        ip_group_exclusion::Entity::find()
            .all(&api.db)
            .await
            .unwrap()
            .len(),
        1
    );
    api.call("DELETE", &white_path, Value::Null, StatusCode::NO_CONTENT)
        .await;
    assert!(
        ip_group_exclusion::Entity::find()
            .all(&api.db)
            .await
            .unwrap()
            .is_empty()
    );
    let updates = audit_log::Entity::find()
        .filter(audit_log::Column::Action.eq("GROUP_UPDATE"))
        .all(&api.db)
        .await
        .unwrap();
    assert_eq!(updates.len(), 3);
}

#[tokio::test]
async fn exclusions_cover_both_cidr_directions_and_ipv6_storage() {
    use serde_json::json;
    let mut api = BanPolicyApi::new(true).await;
    let white = api.group("trusted", "whitelist").await;
    let second = api.group("trusted-v6", "whitelist").await;
    api.call(
        "POST",
        "/api/groups",
        json!({
            "name":"protected", "excluded_whitelist_ids":[white["id"], second["id"]]
        }),
        StatusCode::OK,
    )
    .await;

    for address in ["8.8.8.0/24", "9.9.9.9", "2606:4700:1111:2::/64"] {
        api.record("/api/white", "trusted", address, StatusCode::OK)
            .await;
    }
    api.record(
        "/api/white",
        "trusted-v6",
        "2606:4700:1111:3::/64",
        StatusCode::OK,
    )
    .await;
    for address in [
        "8.8.8.8",
        "9.9.9.0/24",
        "2606:4700:1111:2::1",
        "2606:4700:1111:4::1",
    ] {
        let response = api
            .record("/api/ban", "protected", address, StatusCode::CONFLICT)
            .await;
        let error = response["error"].as_str().unwrap();
        assert!(error.contains("trusted"));
        if address.contains(':') {
            assert!(error.contains("trusted-v6"));
        }
    }
    api.record("/api/ips", "trusted", "8.8.8.0/24", StatusCode::NO_CONTENT)
        .await;
    api.record("/api/ban", "protected", "8.8.8.8", StatusCode::OK)
        .await;
    api.record("/api/ips", "protected", "8.8.8.8", StatusCode::NO_CONTENT)
        .await;
    api.record("/api/ips/restore", "trusted", "8.8.8.0/24", StatusCode::OK)
        .await;
    api.record(
        "/api/ips/restore",
        "protected",
        "8.8.8.8",
        StatusCode::CONFLICT,
    )
    .await;
}

#[tokio::test]
async fn full_replace_excludes_protected_bans_and_keeps_processing_the_batch() {
    use serde_json::json;
    use simply_ip_vault::entities::audit_log;
    let mut api = BanPolicyApi::new(false).await;
    let white = api.group("trusted", "whitelist").await;
    api.call(
        "POST",
        "/api/groups",
        json!({
            "name":"protected", "excluded_whitelist_ids":[white["id"]]
        }),
        StatusCode::OK,
    )
    .await;
    api.record("/api/ban", "protected", "8.8.8.8", StatusCode::OK)
        .await;
    api.record("/api/white", "trusted", "8.8.8.0/24", StatusCode::OK)
        .await;
    let summary = api
        .call(
            "POST",
            "/api/records/batch",
            json!({
                "group_name":"protected", "mode":"full_replace",
                "records":[{"target_address":"8.8.8.8"}, {"target_address":"1.1.1.1"}]
            }),
            StatusCode::OK,
        )
        .await;
    assert_eq!(summary["skipped_excluded"], 1);
    assert_eq!(summary["linked"], 1);
    assert_eq!(summary["soft_deleted"], 1);
    let logs = audit_log::Entity::find()
        .filter(audit_log::Column::Action.eq("batch_records_updated"))
        .all(&api.db)
        .await
        .unwrap();
    assert_eq!(logs.len(), 1);
    assert!(
        logs[0]
            .details
            .as_deref()
            .unwrap()
            .contains("skipped_excluded=1")
    );
}

#[tokio::test]
async fn updating_group_policy_requires_authentication_and_lifecycle_authority() {
    use serde_json::json;

    let mut api = BanPolicyApi::new(false).await;
    let group = api.group("owned", "banlist").await;
    let path = format!("/api/groups/{}", group["id"].as_str().unwrap());
    let request = inject_connect_info(Request::builder().method("PUT").uri(&path))
        .header("Content-Type", "application/json")
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(send(&api.app, request).await.0, StatusCode::UNAUTHORIZED);

    let (owner_id, owner_key) = insert_test_key(&api.db, "Group owner", false).await;
    let request = signed_at(
        inject_connect_info(Request::builder().method("PUT").uri(&path))
            .header("Content-Type", "application/json")
            .header("X-API-Key", &owner_key),
        &test_signing_secret(&owner_key),
        api.timestamp,
        r#"{"allow_private_ips":true}"#,
    );
    assert_eq!(send(&api.app, request).await.0, StatusCode::FORBIDDEN);
    api.call(
        "PUT",
        &format!("{path}/owner"),
        json!({"owner_key_id":owner_id}),
        StatusCode::OK,
    )
    .await;
    api.key = owner_key;
    let group = api
        .call(
            "PUT",
            &path,
            json!({"allow_private_ips":true}),
            StatusCode::OK,
        )
        .await;
    assert_eq!(group["allow_private_ips"], true);
    assert_eq!(group["owner_key_id"], owner_id.to_string());
}
