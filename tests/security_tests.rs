//! Security regression suite — adversarial tests for the HMAC authentication and webhook
//! signing paths.
//!
//! Where `rbac_integration_tests.rs` asks "does the feature work?", every test here asks "can it be
//! made to *not* work?" and asserts the attack fails. Each one is named for the attack it replays,
//! so a failure reads as "this vulnerability is now open" rather than "this test broke".
//!
//! Deliberately self-contained: it duplicates a small amount of harness setup from the RBAC suite
//! rather than sharing it, so that a refactor of the functional tests can never silently weaken the
//! security ones.

use axum::{
    body::Body,
    http::{Request, StatusCode},
};
use sea_orm::{
    ConnectionTrait,
    ActiveModelTrait, ActiveValue::Set, ColumnTrait, Database, DatabaseConnection, EntityTrait,
    QueryFilter,
};
use sea_orm_migration::MigratorTrait;
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

use simply_ip_vault::{create_app, crypto, migration, state::AppState};

/// `ALLOW_PRIVATE_WEBHOOKS` is process-wide, and the dispatcher reads it once at worker startup.
/// Tests that flip it must not overlap.
static ENV_MUTATION_LOCK: std::sync::LazyLock<tokio::sync::Mutex<()>> =
    std::sync::LazyLock::new(|| tokio::sync::Mutex::new(()));

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

/// Injects an explicit TCP peer address, standing in for what the kernel reports.
///
/// This is the value an attacker **cannot** control. Everything the spoofing tests turn on is the
/// difference between it and the headers a client writes freely.
fn connect_from(req: axum::http::request::Builder, peer: &str) -> axum::http::request::Builder {
    let ip: std::net::IpAddr = peer.parse().expect("test peer literal parses");
    req.extension(axum::extract::ConnectInfo(std::net::SocketAddr::new(ip, 40000)))
}

/// Parses a `TRUSTED_PROXIES`-style string into the matcher list `AppState` carries.
fn trusted(entries: &str) -> Vec<simply_ip_vault::config::ProxyMatcher> {
    simply_ip_vault::config::parse_trusted_proxies(entries)
        .expect("test fixture must use valid proxy entries")
}

/// Test-only convention mirroring the RBAC suite: a seeded key's signing secret is derived from its
/// plaintext API key.
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

/// Seeds an API key with explicit scopes and an optional `bound_ips`, returning `(id, plaintext)`.
#[allow(clippy::too_many_arguments)]
async fn insert_key(
    db: &DatabaseConnection,
    name: &str,
    is_master: bool,
    can_manage_keys: bool,
    can_manage_webhooks: bool,
    can_create_groups: bool,
    bound_ips: Option<&str>,
) -> (Uuid, String) {
    let id = Uuid::new_v4();
    let plaintext = simply_ip_vault::api::generate_random_key();
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(id),
        key_hash: Set(simply_ip_vault::api::hash_key(&plaintext)),
        signing_secret: Set(Some(stored_signing_secret(&plaintext))),
        name: Set(name.to_owned()),
        bound_ips: Set(bound_ips.map(str::to_owned)),
        is_master: Set(is_master),
        can_manage_keys: Set(can_manage_keys),
        can_manage_webhooks: Set(can_manage_webhooks),
        can_create_groups: Set(can_create_groups),
        parent_key_id: Set(None),
        prefix: Set("sectest2".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(db)
    .await
    .unwrap();
    (id, plaintext)
}

/// Seeds an IP group and returns its id.
async fn insert_group(db: &DatabaseConnection, name: &str) -> Uuid {
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

/// Grants a key explicit read/write/delete on a group.
async fn grant(
    db: &DatabaseConnection,
    key_id: Uuid,
    group_id: Uuid,
    read: bool,
    write: bool,
    del: bool,
) {
    simply_ip_vault::entities::api_key_group_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(key_id),
        group_id: Set(group_id),
        can_read: Set(read),
        can_write: Set(write),
        can_delete: Set(del),
        // The administrative flag is off unless a test asks for it explicitly — the security suite
        // is about the read/write/delete surface.
        can_manage: Set(false),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(db)
    .await
    .unwrap();
}

/// Grants a key read/write/delete **and** the administrative `can_manage` flag on a group.
///
/// R2 makes `can_manage` half of the authority to touch a group's permission rows at all, so any
/// fixture whose caller is expected to grant or revoke needs this rather than [`grant`].
async fn grant_manager(
    db: &DatabaseConnection,
    key_id: Uuid,
    group_id: Uuid,
    read: bool,
    write: bool,
    del: bool,
) {
    simply_ip_vault::entities::api_key_group_permission::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(key_id),
        group_id: Set(group_id),
        can_read: Set(read),
        can_write: Set(write),
        can_delete: Set(del),
        can_manage: Set(true),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(db)
    .await
    .unwrap();
}

/// Records `parent` as `child`'s creator, so a seeded fixture lands inside a caller's subtree.
///
/// §4 scopes credential-level operations to the caller's own subtree, and `insert_key` seeds keys with
/// no lineage at all — which puts them outside everyone's. A test about *authority* has to place its
/// target inside the caller's scope first, or it measures visibility instead.
async fn set_parent(db: &DatabaseConnection, child: Uuid, parent: Uuid) {
    let mut active: simply_ip_vault::entities::api_key::ActiveModel =
        simply_ip_vault::entities::prelude::ApiKey::find_by_id(child)
            .one(db)
            .await
            .unwrap()
            .unwrap()
            .into();
    active.parent_key_id = Set(Some(parent));
    active.update(db).await.unwrap();
}

/// Seeds a master API key directly into the database and returns its plaintext form.
async fn insert_master_key(db: &DatabaseConnection, name: &str) -> String {
    let plaintext = simply_ip_vault::api::generate_random_key();
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        key_hash: Set(simply_ip_vault::api::hash_key(&plaintext)),
        signing_secret: Set(Some(stored_signing_secret(&plaintext))),
        name: Set(name.to_owned()),
        bound_ips: Set(None),
        is_master: Set(true),
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_create_groups: Set(true),
        parent_key_id: Set(None),
        prefix: Set("sectest1".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(db)
    .await
    .unwrap();
    plaintext
}

/// Builds a fully-signed request at an explicit timestamp. The signature always covers the exact
/// timestamp that is sent, so a rejection can only come from the freshness check — never from a
/// mismatched HMAC.
fn signed_at(
    builder: axum::http::request::Builder,
    secret: &str,
    timestamp: i64,
    body: &str,
) -> Request<Body> {
    let method = builder
        .method_ref()
        .map(|m| m.as_str().to_owned())
        .unwrap_or_else(|| "GET".to_owned());
    // The **full** target, query string included — signing the bare path here would make the
    // query-tampering tests below pass without proving anything.
    let target = builder
        .uri_ref()
        .map(|u| {
            u.path_and_query()
                .map(|pq| pq.as_str().to_owned())
                .unwrap_or_else(|| u.path().to_owned())
        })
        .unwrap_or_else(|| "/".to_owned());
    let ts = timestamp.to_string();
    let signature = crypto::compute_signature(secret, &method, &target, &ts, body.as_bytes()).unwrap();
    builder
        .header("X-Timestamp", &ts)
        .header("X-Signature-256", &signature)
        .body(Body::from(body.to_owned()))
        .unwrap()
}

/// Builds a signed request stamped "now".
fn signed(builder: axum::http::request::Builder, secret: &str, body: &str) -> Request<Body> {
    signed_at(builder, secret, chrono::Utc::now().timestamp(), body)
}

/// Builds a signed request stamped `offset_secs` into the future.
///
/// A signature covers method, target, timestamp and body and nothing else, so repeating a call
/// unchanged inside the same wall-clock second yields the identical signature — a replay, which the
/// guard now refuses. Real callers never hit this because their second attempt lands on a later
/// timestamp; a test issuing both microseconds apart has to say so explicitly. The offset stays far
/// inside the ±300s window, so the request is exactly as fresh as a genuine later one.
fn signed_later(
    builder: axum::http::request::Builder,
    secret: &str,
    offset_secs: i64,
    body: &str,
) -> Request<Body> {
    signed_at(builder, secret, chrono::Utc::now().timestamp() + offset_secs, body)
}

// ─────────────────────────────────────────────────────────────
// Attack 1 — Timestamp forgery (anti-replay)
// ─────────────────────────────────────────────────────────────

/// A captured-and-held request must not become usable by back- or forward-dating `X-Timestamp`.
///
/// Both probes carry a **cryptographically valid** signature over the stale timestamp they send:
/// the attacker is assumed to hold the signing secret's output for that moment (a replayed
/// capture), so the HMAC check passes and only the freshness window can stop them. A test that sent
/// a bad signature here would pass for the wrong reason and would keep passing even if the entire
/// anti-replay check were deleted.
#[tokio::test]
async fn attack_timestamp_forgery_outside_the_window_is_rejected_both_directions() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let key = insert_master_key(&db, "Replay Attacker").await;
    let secret = test_signing_secret(&key);

    // The clock is read **inside** each probe, and only after waiting clear of a second boundary.
    //
    // Both details are load-bearing, and this test was intermittently red without them. It used to
    // capture `now` once and derive every offset from it, but the middleware reads `Utc::now()` again
    // when the request arrives — so the effective skew is `offset - elapsed`, where `elapsed` is
    // however long the *previous* probes took. One second of accumulated runtime turned `probe(301)`
    // into a skew of exactly 300, which is inside the inclusive window and answers `200`. It passed
    // whenever the suite ran fast and failed under load, which is the worst way for a security test
    // to behave: the failure looks like the control it guards has broken.
    //
    // Reading the clock per probe collapses `elapsed` to microseconds. The `sleep` then removes the
    // remaining sub-second race — landing a few microseconds before a tick would reintroduce exactly
    // the same off-by-one — by starting each probe at least 200 ms into a second, leaving ~800 ms of
    // margin against a boundary that is otherwise invisible.
    let probe = |offset: i64| {
        let (app, key, secret) = (app.clone(), key.clone(), secret.clone());
        async move {
            let subsec = u64::from(chrono::Utc::now().timestamp_subsec_millis());
            if subsec > 800 {
                tokio::time::sleep(std::time::Duration::from_millis(1_200 - subsec)).await;
            }
            let req = signed_at(
                inject_connect_info(
                    Request::builder().uri("/api/auth/me").header("X-API-Key", &key),
                ),
                &secret,
                chrono::Utc::now().timestamp() + offset,
                "",
            );
            app.oneshot(req).await.unwrap().status()
        }
    };

    // Control: the identical request at the current time authenticates. Without this, a blanket
    // 401 (e.g. from a broken fixture) would make the assertions below meaningless.
    assert_eq!(probe(0).await, StatusCode::OK, "a fresh, correctly signed request must succeed");

    // 301 seconds — one second past the 300s window, in both directions.
    assert_eq!(
        probe(-301).await,
        StatusCode::UNAUTHORIZED,
        "a 301s-stale timestamp is a replay and must be rejected"
    );
    assert_eq!(
        probe(301).await,
        StatusCode::UNAUTHORIZED,
        "a 301s-future timestamp must be rejected — allowing it would let a captured request be \
         held and replayed later"
    );

    // The boundary itself is inclusive, so 301 really is the first rejected value and the test
    // above is pinned to the edge rather than to an arbitrarily distant offset.
    assert_eq!(probe(-300).await, StatusCode::OK, "exactly 300s stale is still inside the window");
    assert_eq!(probe(300).await, StatusCode::OK, "exactly 300s ahead is still inside the window");

    // A long-held capture must never come back.
    assert_eq!(probe(-86_400).await, StatusCode::UNAUTHORIZED, "a day-old capture is rejected");
}

/// `X-Timestamp` must be *mandatory*, not merely validated when present. A middleware that skipped
/// the check on a missing header would leave every signature replayable forever, since the
/// signature alone carries no notion of time.
#[tokio::test]
async fn attack_omitting_the_timestamp_header_does_not_skip_the_replay_check() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let key = insert_master_key(&db, "No Timestamp").await;
    let secret = test_signing_secret(&key);
    let now = chrono::Utc::now().timestamp().to_string();

    // An otherwise perfect request: correct key, correct signature over the current time — with the
    // timestamp header simply left off.
    let signature = crypto::compute_signature(&secret, "GET", "/api/auth/me", &now, b"").unwrap();
    let req = inject_connect_info(
        Request::builder()
            .uri("/api/auth/me")
            .header("X-API-Key", &key)
            .header("X-Signature-256", &signature),
    )
    .body(Body::empty())
    .unwrap();
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED,
        "a missing X-Timestamp must fail closed, not bypass the freshness check"
    );

    // A non-numeric timestamp must not be coerced into something that happens to fall in-window
    // (e.g. parsed-as-zero-then-compared).
    for malformed in ["", "not-a-number", "NaN", "1e9", " ", "+", "999999999999999999999999"] {
        let req = inject_connect_info(
            Request::builder()
                .uri("/api/auth/me")
                .header("X-API-Key", &key)
                .header("X-Timestamp", malformed)
                .header("X-Signature-256", &signature),
        )
        .body(Body::empty())
        .unwrap();
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::UNAUTHORIZED,
            "malformed X-Timestamp {malformed:?} must be rejected"
        );
    }
}

// ─────────────────────────────────────────────────────────────
// Attack 2 — Signature forgery
// ─────────────────────────────────────────────────────────────

/// Flips the final hex digit of a signature, keeping it valid hex of the correct length.
///
/// Staying valid hex is the point: a signature mangled into non-hex would be thrown out by
/// `hex::decode` before the MAC is ever consulted, so the test would pass without the constant-time
/// comparison being exercised at all. This forces the rejection to come from `Mac::verify_slice`.
fn flip_last_hex_digit(signature: &str) -> String {
    let mut chars: Vec<char> = signature.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == '0' { '1' } else { '0' };
    chars.into_iter().collect()
}

/// A single-character change to an otherwise authentic signature must be rejected.
///
/// This is the canonical probe for a truncated or prefix-only comparison: an implementation that
/// compared, say, the first 8 bytes, or that used a short-circuiting `==` on a partially-copied
/// buffer, would accept a signature differing only in its last nibble.
#[tokio::test]
async fn attack_signature_forgery_by_last_character_flip_is_rejected() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let key = insert_master_key(&db, "Forger").await;
    let secret = test_signing_secret(&key);
    let now = chrono::Utc::now().timestamp().to_string();

    let authentic = crypto::compute_signature(&secret, "GET", "/api/auth/me", &now, b"").unwrap();
    // Mutations are applied to the digest and re-tagged, so every case below reaches the MAC
    // comparison instead of being turned away by the `sha256=` format check — which would make the
    // whole test pass for a reason that has nothing to do with what it is probing.
    let digest = authentic
        .strip_prefix(crypto::SIGNATURE_PREFIX)
        .expect("compute_signature emits the mandatory tag")
        .to_owned();
    assert_eq!(digest.len(), 64, "HMAC-SHA256 hex is 64 characters");
    let tagged = |digest: &str| format!("{}{digest}", crypto::SIGNATURE_PREFIX);

    let send = |sig: String| {
        let (app, key, now) = (app.clone(), key.clone(), now.clone());
        async move {
            let req = inject_connect_info(
                Request::builder()
                    .uri("/api/auth/me")
                    .header("X-API-Key", &key)
                    .header("X-Timestamp", &now)
                    .header("X-Signature-256", &sig),
            )
            .body(Body::empty())
            .unwrap();
            app.oneshot(req).await.unwrap().status()
        }
    };

    // Control: unmodified, it authenticates.
    assert_eq!(send(authentic.clone()).await, StatusCode::OK);

    // The attack: exactly one character different, still 64 valid hex digits.
    let forged = flip_last_hex_digit(&digest);
    assert_ne!(forged, digest);
    assert_eq!(forged.len(), digest.len());
    assert_eq!(forged[..63], digest[..63], "the forgery must differ *only* in the final character");
    assert_eq!(
        send(tagged(&forged)).await,
        StatusCode::UNAUTHORIZED,
        "a signature differing by one trailing character must be rejected"
    );

    // The same must hold at the other end and in the middle — no position is unchecked.
    for pos in [0usize, 1, 31, 32, 62] {
        let mut chars: Vec<char> = digest.chars().collect();
        chars[pos] = if chars[pos] == '0' { '1' } else { '0' };
        let mutated: String = chars.into_iter().collect();
        assert_eq!(
            send(tagged(&mutated)).await,
            StatusCode::UNAUTHORIZED,
            "a signature differing at index {pos} must be rejected"
        );
    }

    // A correct-prefix-but-truncated signature must not be accepted by a length-agnostic compare.
    assert_eq!(
        send(tagged(&digest[..32])).await,
        StatusCode::UNAUTHORIZED,
        "a truncated signature sharing a valid prefix must be rejected"
    );
    // ...nor an over-long one that merely starts with the correct value.
    assert_eq!(
        send(tagged(&format!("{digest}00"))).await,
        StatusCode::UNAUTHORIZED,
        "an over-long signature with a valid prefix must be rejected"
    );

    // And the digest sent bare — correct bytes, missing tag — is refused over HTTP with 401, not
    // merely inside `verify_signature`. This is the mandated end-to-end check on the format rule.
    //
    // It must be a signature that has **never been accepted**, which is why it is signed over a
    // fresh timestamp rather than reusing `digest`. Reusing it would make the replay guard the thing
    // doing the rejecting — the control request at the top of this test already consumed that
    // digest — and the check would then report 401 just as loudly with the format rule deleted.
    // Verified by mutation: with both the `crypto` and middleware checks removed, this fails.
    let unused_now = (chrono::Utc::now().timestamp() - 7).to_string();
    let unused = crypto::compute_signature(&secret, "GET", "/api/auth/me", &unused_now, b"").unwrap();
    let unused_digest = unused
        .strip_prefix(crypto::SIGNATURE_PREFIX)
        .expect("compute_signature emits the mandatory tag")
        .to_owned();

    let send_at = |sig: String, ts: String| {
        let (app, key) = (app.clone(), key.clone());
        async move {
            let req = inject_connect_info(
                Request::builder()
                    .uri("/api/auth/me")
                    .header("X-API-Key", &key)
                    .header("X-Timestamp", &ts)
                    .header("X-Signature-256", &sig),
            )
            .body(Body::empty())
            .unwrap();
            app.oneshot(req).await.unwrap().status()
        }
    };

    assert_eq!(
        send_at(unused_digest, unused_now.clone()).await,
        StatusCode::UNAUTHORIZED,
        "a valid hex signature missing the sha256= prefix must be rejected with 401"
    );
    // Control: the very same signature *with* the tag is accepted, proving the rejection above is
    // the missing prefix and not a stale timestamp or an exhausted key.
    assert_eq!(
        send_at(unused, unused_now).await,
        StatusCode::OK,
        "the same signature with its sha256= tag must authenticate"
    );
}

/// The library-level equivalent, asserting the same property directly on `verify_signature` so a
/// regression is localized to `crypto` rather than only surfacing through the HTTP stack.
///
/// # Why bits and not characters
///
/// An earlier version of this test mutated hex *characters*, which is a coarser instrument than it
/// looks: it replaced each position with one of four fixed digits, so it never distinguished the two
/// nibbles of a byte and never covered the other eleven values a nibble can take. This sweeps the
/// **decoded tag**: all 32 bytes × 8 bits = 256 single-bit forgeries, each one re-encoded and sent
/// through the real entry point. Every one must fail.
///
/// That is the exhaustive statement of what a constant-time comparison buys. A comparison that
/// short-circuits, that compares a prefix, that stops at a word boundary, or that folds bytes
/// together before comparing would each accept *some* single-bit change — and each would still pass
/// a spot-check of the first, middle, and last positions.
///
/// The wrong-length cases are the other half. `Mac::verify_slice` rejects a mismatched width before
/// comparing anything, which is correct and leaks only the digest width (a public constant); this
/// asserts it happens rather than assuming it, across every length from empty to double.
#[test]
fn attack_single_bit_signature_mutations_never_verify() {
    let (secret, method, path, ts, body) = ("s3cret", "POST", "/api/ban", "1700000000", b"payload");
    let authentic = crypto::compute_signature(secret, method, path, ts, body).unwrap();
    let tag = hex::decode(
        authentic.strip_prefix(crypto::SIGNATURE_PREFIX).expect("the mandatory tag is present"),
    )
    .expect("the digest is hex");

    assert_eq!(tag.len(), 32, "HMAC-SHA256 produces a 32-byte tag");
    assert!(
        crypto::verify_signature(secret, method, path, ts, body, &authentic).is_some(),
        "control: the unmodified signature verifies"
    );

    let verify = |tag: &[u8]| {
        let framed = format!("{}{}", crypto::SIGNATURE_PREFIX, hex::encode(tag));
        crypto::verify_signature(secret, method, path, ts, body, &framed)
    };

    // All 256 single-bit forgeries.
    for byte in 0..tag.len() {
        for bit in 0..8u32 {
            let mut forged = tag.clone();
            forged[byte] ^= 1 << bit;
            assert!(
                verify(&forged).is_none(),
                "flipping bit {bit} of byte {byte} must not verify"
            );
        }
    }

    // Every wrong width, including the empty tag and the doubled one. A truncation that happens to
    // share a prefix with the real tag is the case a length-agnostic compare would accept.
    for len in (0..=64).filter(|len| *len != 32) {
        let mut wrong = tag.clone();
        wrong.resize(len, 0);
        assert!(verify(&wrong).is_none(), "a {len}-byte tag must be rejected on width alone");
    }

    // ...and the untruncated tag with trailing bytes appended, which shares all 32 correct bytes.
    let mut extended = tag.clone();
    extended.extend_from_slice(&[0u8; 8]);
    assert!(verify(&extended).is_none(), "a tag that merely starts correct must be rejected");
}

// ─────────────────────────────────────────────────────────────
// Attack 3 — Webhook HMAC template injection
// ─────────────────────────────────────────────────────────────

/// What the mock receiver recorded from a dispatch.
#[derive(Clone, Default)]
struct CapturedHook {
    path: Option<String>,
    body: Option<String>,
    signature: Option<String>,
    timestamp: Option<String>,
}

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

/// A caller who controls part of the webhook payload must not be able to forge canonical-string
/// field boundaries in the signature the dispatcher produces.
///
/// The attack surface is concrete: `cause` travels from a `POST /api/ban` body, through
/// `payload_template`'s `$cause` substitution, into the dispatched payload — and the payload is the
/// `{body}` field of the signed canonical string. If the resolver rescanned substituted values, an
/// attacker could submit `cause` containing newlines and placeholder syntax to make the receiver
/// verify a *different* method, path, and timestamp than the ones actually dispatched.
#[tokio::test]
async fn attack_hmac_template_injection_via_payload_body_cannot_forge_canonical_fields() {
    let _env_guard = ENV_MUTATION_LOCK.lock().await;
    unsafe { std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "true") };

    let (base_url, captured) = spawn_capturing_receiver().await;

    let db = setup_test_db().await;
    let (webhook_tx, webhook_rx) = tokio::sync::mpsc::channel(100);
    let db_for_worker = db.clone();
    tokio::spawn(async move {
        simply_ip_vault::dispatch::run_webhook_worker(db_for_worker, webhook_rx).await;
    });
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let key = insert_master_key(&db, "Injection Tester").await;
    let secret = test_signing_secret(&key);

    let group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_id),
        name: Set("injection-group".to_owned()),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    // A CANONICAL_V1 webhook on the **default** template — the injection must fail against the
    // shipped configuration, not just against a hardened custom one.
    let hook_secret = "injection-webhook-secret";
    let hook_url = format!("{base_url}/hook");
    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/webhooks")
                .header("X-API-Key", &key)
                .header("Content-Type", "application/json"),
        ),
        &secret,
        &json!({
            "name": "Injection Hook",
            "target_url": hook_url,
            "secret_token": hook_secret,
            "payload_template": r#"{"malicious":"$cause"}"#,
            "group_id": group_id.to_string(),
            "auth_mode": "CANONICAL_V1",
            "events": "IP_ADD",
        })
        .to_string(),
    );
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    // The hostile value: real newlines plus a complete fake canonical prefix. If these were ever
    // treated as separators, the receiver would authenticate `POST /api/fake` at timestamp 123456.
    let hostile_cause = "value\nPOST\n/api/fake\n123456";
    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/ban")
                .header("X-API-Key", &key)
                .header("Content-Type", "application/json"),
        ),
        &secret,
        &json!({
            "target_address": "203.0.113.42",
            "group_name": "injection-group",
            "cause": hostile_cause,
        })
        .to_string(),
    );
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);

    let hit = await_dispatch(&captured).await.expect("webhook was not delivered within timeout");
    unsafe { std::env::set_var("ALLOW_PRIVATE_WEBHOOKS", "false") };

    let delivered_body = hit.body.expect("dispatch must carry a body");
    let signature = hit.signature.expect("CANONICAL_V1 must send X-Signature-256");
    let timestamp = hit.timestamp.expect("CANONICAL_V1 must send X-Timestamp");

    // The injection really did reach the payload — otherwise this test proves nothing.
    assert!(
        delivered_body.contains(hostile_cause),
        "the hostile cause must survive into the dispatched payload verbatim, got {delivered_body:?}"
    );
    assert!(delivered_body.contains('\n'), "the payload must contain real newlines");

    // ── The core assertion ──────────────────────────────────────────────────
    // The signature is the HMAC over `POST\n<real path>\n<real timestamp>\n<entire body>`, with the
    // body — newlines and all — as one opaque trailing field.
    let expected = crypto::compute_signature(
        hook_secret,
        "POST",
        "/hook",
        &timestamp,
        delivered_body.as_bytes(),
    )
    .unwrap();
    assert_eq!(
        signature, expected,
        "the dispatcher must sign the real method/path/timestamp with the body as one opaque field"
    );

    // ── The forgeries that must NOT verify ──────────────────────────────────
    // Each is what a receiver would compute if it (or the dispatcher) had let the injected newlines
    // act as canonical separators.
    let injected_tail = delivered_body
        .split_once("value\n")
        .map(|(_, tail)| tail.to_owned())
        .expect("the injected marker is present");
    for (method, path, ts, body) in [
        ("POST", "/api/fake", "123456", injected_tail.as_str()),
        ("POST", "/api/fake", "123456", delivered_body.as_str()),
        ("POST", "/api/fake", timestamp.as_str(), delivered_body.as_str()),
    ] {
        assert!(
            crypto::verify_signature(hook_secret, method, path, ts, body.as_bytes(), &signature)
                .is_none(),
            "the injected fields ({method} {path} @{ts}) must not verify against the real signature"
        );
    }

    // The receiver's contract holds: verifying with the true fields succeeds.
    assert!(
        crypto::verify_signature(
            hook_secret,
            "POST",
            "/hook",
            &timestamp,
            delivered_body.as_bytes(),
            &signature,
        )
        .is_some(),
        "the genuine canonical fields must verify"
    );

    // And the path actually requested is the one signed — not the injected `/api/fake`.
    assert_eq!(hit.path.as_deref(), Some("/hook"));
}

/// The same property at the unit level, isolated from HTTP and timing: a body carrying placeholder
/// syntax and escape sequences lands in the signed string byte-for-byte, and the canonical fields
/// remain recoverable by a receiver splitting into exactly four parts.
#[test]
fn attack_template_resolution_never_rescans_substituted_values() {
    use simply_ip_vault::{
        entities::webhook_config::DEFAULT_HMAC_TEMPLATE, dispatch::resolve_hmac_template,
    };

    // Both flavours of the attack: real newline characters, and literal backslash-n escapes.
    for hostile_body in [
        "{\"malicious\": \"value\nPOST\n/api/fake\n123456\"}",
        r#"{"malicious": "value\nPOST\n/api/fake\n123456"}"#,
        r"{path}\n{timestamp}\n{body}",
        r"{method}{path}{timestamp}{body}",
        "\\\\n{body}",
    ] {
        let resolved =
            resolve_hmac_template(DEFAULT_HMAC_TEMPLATE, "POST", "/real/path", "1700000000", hostile_body);

        // The signed string is exactly the three real fields plus the body appended verbatim.
        assert_eq!(
            resolved,
            format!("POST\n/real/path\n1700000000\n{hostile_body}"),
            "substituted values must never be rescanned for placeholders or escapes"
        );

        // A receiver splitting into four fields recovers the true method, path and timestamp — the
        // injected content stays entirely inside the fourth.
        let mut fields = resolved.splitn(4, '\n');
        assert_eq!(fields.next(), Some("POST"));
        assert_eq!(fields.next(), Some("/real/path"));
        assert_eq!(fields.next(), Some("1700000000"));
        assert_eq!(fields.next(), Some(hostile_body));
    }
}

// ─────────────────────────────────────────────────────────────
// Attack 4 — Invalid auth-mode configuration
// ─────────────────────────────────────────────────────────────

/// A signing mode with no secret must be refused at creation.
///
/// Accepting it would key the HMAC with the empty string — a signature *anyone* can compute, which
/// is strictly worse than sending none at all because the receiver sees a well-formed
/// `X-Signature-256` and concludes the request is authenticated.
#[tokio::test]
async fn attack_canonical_v1_webhook_without_a_secret_is_rejected() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let key = insert_master_key(&db, "Webhook Admin").await;
    let secret = test_signing_secret(&key);

    let group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_id),
        name: Set("authmode-group".to_owned()),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let create = |mut payload: serde_json::Value, name: &str| {
        payload["name"] = json!(name);
        payload["target_url"] = json!("https://example.com/hook");
        payload["payload_template"] = json!("{}");
        payload["group_id"] = json!(group_id.to_string());
        signed(
            inject_connect_info(
                Request::builder()
                    .method("POST")
                    .uri("/api/webhooks")
                    .header("X-API-Key", &key)
                    .header("Content-Type", "application/json"),
            ),
            &secret,
            &payload.to_string(),
        )
    };
    let status = |req: Request<Body>| {
        let app = app.clone();
        async move { app.oneshot(req).await.unwrap().status() }
    };

    // The headline case: CANONICAL_V1 with an explicitly empty secret_token.
    assert_eq!(
        status(create(json!({ "auth_mode": "CANONICAL_V1", "secret_token": "" }), "empty-secret")).await,
        StatusCode::BAD_REQUEST,
        "CANONICAL_V1 with an empty secret_token must be rejected"
    );

    // ...and the equivalent shapes a client can produce for "no secret".
    assert_eq!(
        status(create(json!({ "auth_mode": "CANONICAL_V1" }), "omitted-secret")).await,
        StatusCode::BAD_REQUEST,
        "CANONICAL_V1 with an omitted secret_token must be rejected"
    );
    assert_eq!(
        status(create(json!({ "auth_mode": "CANONICAL_V1", "secret_token": null }), "null-secret")).await,
        StatusCode::BAD_REQUEST,
        "CANONICAL_V1 with a null secret_token must be rejected"
    );
    // Case-insensitive parsing must not become a way around the precondition.
    assert_eq!(
        status(create(json!({ "auth_mode": "canonical_v1", "secret_token": "" }), "lowercase-mode")).await,
        StatusCode::BAD_REQUEST,
        "the precondition must apply regardless of auth_mode casing"
    );
    // The deprecated alias reaches the same validation path.
    assert_eq!(
        status(create(json!({ "signature_mode": "CANONICAL_V1", "secret_token": "" }), "alias-mode")).await,
        StatusCode::BAD_REQUEST,
        "the deprecated signature_mode alias must not bypass the secret precondition"
    );
    // BODY_ONLY is the other signing mode and needs the same guarantee.
    assert_eq!(
        status(create(json!({ "auth_mode": "BODY_ONLY", "secret_token": "" }), "body-only-empty")).await,
        StatusCode::BAD_REQUEST,
        "BODY_ONLY with an empty secret_token must be rejected"
    );

    // An unknown mode must be refused outright rather than silently defaulted to something weaker.
    assert_eq!(
        status(create(json!({ "auth_mode": "PLAINTEXT", "secret_token": "s" }), "bogus-mode")).await,
        StatusCode::BAD_REQUEST,
        "an unrecognized auth_mode must be rejected, not defaulted"
    );

    // A template that never interpolates {body} signs a constant — replayable against any payload.
    assert_eq!(
        status(create(
            json!({
                "auth_mode": "CANONICAL_V1",
                "secret_token": "s",
                "hmac_template": r"{method}\n{path}\n{timestamp}",
            }),
            "bodyless-template"
        ))
        .await,
        StatusCode::BAD_REQUEST,
        "an hmac_template that omits {{body}} authenticates nothing and must be rejected"
    );

    // Control: with a real secret, the same request succeeds — proving the rejections above come
    // from the precondition and not from something incidental in the fixture.
    assert_eq!(
        status(create(
            json!({ "auth_mode": "CANONICAL_V1", "secret_token": "a-real-secret" }),
            "valid-canonical"
        ))
        .await,
        StatusCode::OK,
        "a CANONICAL_V1 webhook with a secret must still be creatable"
    );
}

/// The `secret_token` must never be readable back out of the API. A reader who can list webhooks
/// and recover the secret can forge `X-Signature-256` for every dispatch that webhook makes.
#[tokio::test]
async fn attack_webhook_secret_is_not_recoverable_from_read_endpoints() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let key = insert_master_key(&db, "Reader").await;
    let secret = test_signing_secret(&key);

    let group_id = Uuid::new_v4();
    simply_ip_vault::entities::ip_group::ActiveModel {
        id: Set(group_id),
        name: Set("leak-group".to_owned()),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
        description: Set(None),
        created_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let hook_secret = "super-secret-hmac-key-do-not-leak";
    let downstream_key = "downstream-api-key-do-not-leak";
    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/webhooks")
                .header("X-API-Key", &key)
                .header("Content-Type", "application/json"),
        ),
        &secret,
        &json!({
            "name": "Leak Check",
            "target_url": "https://example.com/hook",
            "secret_token": hook_secret,
            "api_key": downstream_key,
            "payload_template": "{}",
            "group_id": group_id.to_string(),
            "auth_mode": "CANONICAL_V1",
        })
        .to_string(),
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let created = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created = String::from_utf8(created.to_vec()).unwrap();
    assert!(!created.contains(hook_secret), "creation response leaked secret_token");
    assert!(!created.contains(downstream_key), "creation response leaked api_key");

    let req = signed(
        inject_connect_info(Request::builder().uri("/api/webhooks").header("X-API-Key", &key)),
        &secret,
        "",
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let listing = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let listing = String::from_utf8(listing.to_vec()).unwrap();
    assert!(!listing.contains(hook_secret), "GET /api/webhooks leaked secret_token");
    assert!(!listing.contains(downstream_key), "GET /api/webhooks leaked api_key");
}

// ─────────────────────────────────────────────────────────────
// Attack 5 — X-Forwarded-For spoofing against bound_ips
// ─────────────────────────────────────────────────────────────

/// The headline IP-spoofing attack: a key restricted to a CIDR must not be usable from outside it
/// merely by claiming an allowed address in a header.
///
/// `X-Forwarded-For` is an ordinary request header — anyone can send any value. Honouring it from
/// an arbitrary peer turns `bound_ips` from a network restriction into a self-asserted one, i.e.
/// into no restriction at all. The peer address in `connect_from` is the part the attacker cannot
/// forge, and it is the only thing that may decide whether the header is believed.
#[tokio::test]
async fn attack_spoofed_forwarded_for_from_an_untrusted_peer_cannot_bypass_bound_ips() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    // A proxy IS configured — but not the attacker's. The check is per-peer, not
    // "is anything configured at all".
    let app = create_app(AppState::with_trusted_proxies(
        db.clone(),
        webhook_tx,
        trusted("10.0.0.0/8"),
    ));

    let (_id, key) = insert_key(&db, "Bound", false, false, false, false, Some("192.168.1.0/24")).await;
    let secret = test_signing_secret(&key);

    // Every call below repeats the same signed request with only unsigned headers (or nothing)
    // varying, which would otherwise reproduce one signature and be refused as a replay. The
    // counter stands in for the seconds a real caller would have spent between attempts.
    let tick = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));
    let probe = |peer: &'static str, xff: Option<&'static str>, real_ip: Option<&'static str>| {
        let (app, key, secret, tick) = (app.clone(), key.clone(), secret.clone(), tick.clone());
        async move {
            let mut builder =
                connect_from(Request::builder().uri("/api/auth/me").header("X-API-Key", &key), peer);
            if let Some(v) = xff {
                builder = builder.header("X-Forwarded-For", v);
            }
            if let Some(v) = real_ip {
                builder = builder.header("X-Real-IP", v);
            }
            let offset = tick.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            app.oneshot(signed_later(builder, &secret, offset, "")).await.unwrap().status()
        }
    };

    // Control: from an address genuinely inside the bound CIDR, with no headers at all, it works.
    // Without this the assertions below could all be passing for an unrelated reason.
    assert_eq!(probe("192.168.1.50", None, None).await, StatusCode::OK);

    // The attack: an untrusted peer claiming to be inside the bound CIDR.
    assert_eq!(
        probe("203.0.113.9", Some("192.168.1.50"), None).await,
        StatusCode::FORBIDDEN,
        "a spoofed X-Forwarded-For from an untrusted peer must not satisfy bound_ips"
    );
    assert_eq!(
        probe("203.0.113.9", None, Some("192.168.1.50")).await,
        StatusCode::FORBIDDEN,
        "a spoofed X-Real-IP from an untrusted peer must not satisfy bound_ips"
    );
    assert_eq!(
        probe("203.0.113.9", Some("192.168.1.50"), Some("192.168.1.50")).await,
        StatusCode::FORBIDDEN,
        "sending both spoofed headers must not satisfy bound_ips either"
    );

    // Claiming to *be* the trusted proxy does not make the claim believable — trust is decided by
    // the peer address, never by the header's contents.
    assert_eq!(
        probe("203.0.113.9", Some("10.0.0.1, 192.168.1.50"), None).await,
        StatusCode::FORBIDDEN,
        "impersonating a trusted proxy inside the header must not bootstrap trust"
    );

    // A multi-hop chain forged entirely by the client is equally inert.
    assert_eq!(
        probe("203.0.113.9", Some("192.168.1.50, 192.168.1.51, 192.168.1.52"), None).await,
        StatusCode::FORBIDDEN,
        "a fully forged proxy chain must not satisfy bound_ips"
    );
}

/// The other half of the contract: from a peer that genuinely *is* a configured proxy, the header
/// is honoured — otherwise the fix would simply have broken every proxied deployment.
#[tokio::test]
async fn forwarded_for_is_honoured_from_a_configured_trusted_proxy() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(
        db.clone(),
        webhook_tx,
        trusted("10.0.0.0/8"),
    ));

    let (_id, key) = insert_key(&db, "Proxied", false, false, false, false, Some("192.168.1.0/24")).await;
    let secret = test_signing_secret(&key);

    // Repeated calls below differ only in unsigned headers, so each needs its own timestamp or the
    // second would reproduce the first's signature and be refused as a replay.
    let tick = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));
    let probe = |peer: &'static str, xff: &'static str| {
        let (app, key, secret, tick) = (app.clone(), key.clone(), secret.clone(), tick.clone());
        async move {
            let req = signed_later(
                connect_from(
                    Request::builder().uri("/api/auth/me").header("X-API-Key", &key),
                    peer,
                )
                .header("X-Forwarded-For", xff),
                &secret,
                tick.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                "",
            );
            app.oneshot(req).await.unwrap().status()
        }
    };

    // The trusted proxy declares an in-CIDR client.
    assert_eq!(probe("10.0.0.1", "192.168.1.50").await, StatusCode::OK);

    // A client-supplied prefix is ignored in favour of the proxy-appended rightmost entry, so a
    // client behind the proxy still cannot forge its way in.
    assert_eq!(
        probe("10.0.0.1", "192.168.1.50, 203.0.113.9").await,
        StatusCode::FORBIDDEN,
        "the rightmost (proxy-appended) hop wins over a client-supplied prefix"
    );

    // ...and the reverse ordering resolves to the real client.
    assert_eq!(probe("10.0.0.1", "203.0.113.9, 192.168.1.50").await, StatusCode::OK);

    // A chained trusted hop is skipped, exposing the genuine client behind it.
    assert_eq!(probe("10.0.0.1", "192.168.1.50, 10.0.0.2").await, StatusCode::OK);
}

/// A master key with a configured `bound_ips` must be held to it like any other key.
///
/// The previous `!key.is_master` bypass made the single most powerful credential in the system the
/// only one whose network restriction was decorative — and silently ignored a restriction an
/// operator had explicitly set, which is worse than not offering the field at all.
#[tokio::test]
async fn attack_master_key_is_not_exempt_from_its_bound_ips() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (_id, bound_master) =
        insert_key(&db, "Bound Master", true, true, true, true, Some("192.168.1.0/24")).await;
    let bound_secret = test_signing_secret(&bound_master);

    // Repeated calls below differ only in unsigned headers, so each needs its own timestamp or the
    // second would reproduce the first's signature and be refused as a replay.
    let tick = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));
    let call = |key: String, secret: String, peer: &'static str| {
        let (app, tick) = (app.clone(), tick.clone());
        async move {
            let req = signed_later(
                connect_from(
                    Request::builder().uri("/api/auth/me").header("X-API-Key", &key),
                    peer,
                ),
                &secret,
                tick.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                "",
            );
            app.oneshot(req).await.unwrap().status()
        }
    };

    // From inside its bound network the master key works normally.
    assert_eq!(
        call(bound_master.clone(), bound_secret.clone(), "192.168.1.50").await,
        StatusCode::OK
    );

    // From outside it, master status is no longer an exemption.
    assert_eq!(
        call(bound_master.clone(), bound_secret.clone(), "203.0.113.9").await,
        StatusCode::FORBIDDEN,
        "a master key with bound_ips set must be rejected outside that CIDR"
    );

    // A key with *no* bound_ips is still unrestricted — an empty column means "no restriction
    // configured", not "restrict to nothing".
    //
    // Not a second master: `api_keys.master_marker` carries a unique index now (RBAC_MODEL.md §5),
    // so one database holds one master and this fixture cannot mint another. Nothing is lost — the
    // property under test is a property of `bound_ips`, not of master status, and the master-specific
    // half of this test (no CIDR exemption) is already proven by the two assertions above.
    let (_id2, free_key) = insert_key(&db, "Free Key", false, false, false, false, None).await;
    assert_eq!(
        call(free_key.clone(), test_signing_secret(&free_key), "203.0.113.9").await,
        StatusCode::OK,
        "a key without bound_ips stays unrestricted"
    );
}

// ─────────────────────────────────────────────────────────────
// Attack 6 — Master privilege escalation via key administration
// ─────────────────────────────────────────────────────────────

/// Builds a `can_manage_keys` (but non-master) caller plus a master victim, and returns the app.
async fn escalation_fixture(
    db: &DatabaseConnection,
) -> (axum::Router, String, String, Uuid, Uuid) {
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (manager_id, manager) = insert_key(db, "Key Manager", false, true, true, true, None).await;
    let (victim_id, _victim) = insert_key(db, "Master Victim", true, true, true, true, None).await;

    let secret = test_signing_secret(&manager);
    (app, manager, secret, manager_id, victim_id)
}

/// `can_manage_keys` must not be a route to `is_master`.
///
/// Minting a master key returns its plaintext in the very same response, so accepting
/// `is_master: true` from a non-master was a single-request escalation from a delegated scope to
/// full control of the system.
///
/// The refusal moved from `403` to `400` when `RBAC_MODEL.md` §5 took master status out of the API
/// surface entirely: it is no longer a scope the caller lacks authority for, it is a field no
/// payload may carry — from *any* caller, master included. `attack_a_master_cannot_mint_a_second_master`
/// covers the other half of that, and the count assertion below is unchanged and still the point:
/// whatever the status code, no second master row appears.
#[tokio::test]
async fn attack_non_master_cannot_mint_a_master_key() {
    let db = setup_test_db().await;
    let (app, manager, secret, _mid, _vid) = escalation_fixture(&db).await;

    let create = |body: serde_json::Value| {
        let (app, manager, secret) = (app.clone(), manager.clone(), secret.clone());
        async move {
            let req = signed(
                inject_connect_info(
                    Request::builder()
                        .method("POST")
                        .uri("/api/keys")
                        .header("X-API-Key", &manager)
                        .header("Content-Type", "application/json"),
                ),
                &secret,
                &body.to_string(),
            );
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            (status, String::from_utf8(body.to_vec()).unwrap())
        }
    };

    let (status, body) = create(json!({ "name": "escalated", "is_master": true })).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "a non-master must not be able to create a master key (got body {body})"
    );
    assert!(
        body.contains("is_master"),
        "the refusal must name the offending field so the caller knows what to remove: {body}"
    );

    // Clearing it is refused on the same terms. §5 says "settable or clearable", and a payload that
    // carries the field is asserting authority over it in either direction.
    let (status, _) = create(json!({ "name": "explicitly-not-master", "is_master": false })).await;
    assert_eq!(
        status,
        StatusCode::BAD_REQUEST,
        "`is_master: false` is refused too — the field may not appear at all"
    );

    // Nothing was written — the rejection happens before the insert, so no orphan key is left over.
    let masters = simply_ip_vault::entities::prelude::ApiKey::find()
        .filter(simply_ip_vault::entities::api_key::Column::IsMaster.eq(true))
        .all(&db)
        .await
        .unwrap();
    assert_eq!(masters.len(), 1, "only the pre-seeded master victim should exist");

    // The other two master-only scopes are each a path *back to* master authority — one mints
    // co-administrators, the other mints groups whose creator is auto-granted full access — so a
    // non-master cannot hand either out.
    for scope in ["can_manage_keys", "can_create_groups", "can_manage_webhooks"] {
        let (status, _) = create(json!({ "name": format!("escalated-{scope}"), scope: true })).await;
        assert_eq!(
            status,
            StatusCode::FORBIDDEN,
            "a non-master must not be able to grant '{scope}'"
        );
    }

    // `can_manage_webhooks` joined the master-only set under R4. It was previously delegable on the
    // reasoning that it "confers no authority over keys or groups", which was too narrow: a webhook is
    // a standing export of everything happening in a group to a URL its creator picks, and the scope
    // was freely amplifiable — a parent that did not hold it could hand it out, R1's plainest
    // violation. §1 puts resource-creation rights at the same tier as `can_manage_keys`.
    let (status, _) = create(json!({ "name": "webhook-minter", "can_manage_webhooks": true })).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "a non-master cannot grant can_manage_webhooks");

    // Control: the same caller can still create an ordinary key, so the guards bound key
    // administration rather than having disabled it.
    let (status, _) = create(json!({ "name": "ordinary" })).await;
    assert_eq!(status, StatusCode::OK, "a non-master may still create unscoped keys");

    // An explicit `false` on the master-only *scopes* is not treated as a request for elevation.
    // `is_master` is absent here on purpose: it is no longer a scope with a permissive `false`
    // branch, it is a field the payload may not carry at all, which the assertion further up
    // establishes separately.
    let (status, _) = create(json!({
        "name": "explicitly-unscoped",
        "can_manage_keys": false,
        "can_create_groups": false,
        "can_manage_webhooks": false,
    }))
    .await;
    assert_eq!(status, StatusCode::OK);
}

/// The same restriction on the update path: a non-master cannot elevate an *existing* key into the
/// master-only scopes either, which would otherwise be a two-step version of the same escalation.
#[tokio::test]
async fn attack_non_master_cannot_elevate_an_existing_key_into_master_scopes() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (mid, manager) = insert_key(&db, "Manager", false, true, true, false, None).await;
    let secret = test_signing_secret(&manager);
    let (victim_id, _victim) = insert_key(&db, "Ordinary", false, false, false, false, None).await;
    // Inside the manager's subtree, so every refusal below is R4 refusing an elevation rather than §4
    // refusing to admit the key exists.
    set_parent(&db, victim_id, mid).await;

    // Some calls below repeat verbatim, so each takes its own timestamp — an identical repeat
    // inside one second is the same signature, which is exactly what a replay is.
    let tick = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));
    let update = |body: serde_json::Value| {
        let (app, manager, secret, tick) =
            (app.clone(), manager.clone(), secret.clone(), tick.clone());
        async move {
            let req = signed_later(
                inject_connect_info(
                    Request::builder()
                        .method("PUT")
                        .uri(format!("/api/keys/{victim_id}"))
                        .header("X-API-Key", &manager)
                        .header("Content-Type", "application/json"),
                ),
                &secret,
                tick.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                &body.to_string(),
            );
            app.oneshot(req).await.unwrap().status()
        }
    };

    // Every global scope is master-only under R4 — `can_manage_webhooks` included, as of Phase 1.
    for scope in ["can_manage_keys", "can_create_groups", "can_manage_webhooks"] {
        assert_eq!(
            update(json!({ scope: true })).await,
            StatusCode::FORBIDDEN,
            "a non-master must not elevate another key into '{scope}'"
        );
    }

    // Ordinary fields still update normally, so the guard bounds elevation rather than freezing the
    // endpoint.
    assert_eq!(update(json!({ "name": "Renamed" })).await, StatusCode::OK);

    // Lowering a scope is never an elevation, so a non-master may still take one away.
    assert_eq!(update(json!({ "can_manage_webhooks": false })).await, StatusCode::OK);

    let after = simply_ip_vault::entities::prelude::ApiKey::find_by_id(victim_id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert!(!after.is_master && !after.can_manage_keys && !after.can_create_groups);
    assert!(!after.can_manage_webhooks, "no scope was granted");
    assert_eq!(after.name, "Renamed", "the non-scope field did land");
}

// ─────────────────────────────────────────────────────────────
// Attack 6b — Master uniqueness and immutability (RBAC_MODEL.md §5)
// ─────────────────────────────────────────────────────────────

/// Master uniqueness is a **schema** invariant, not an application convention.
///
/// `RBAC_MODEL.md` §5 is explicit that it must be "enforced by a database constraint rather than by
/// application logic alone", and the reason is that application logic has a gap by construction:
/// `bootstrap_master_key` checks for an existing master and then inserts, which two processes
/// starting together both pass. This test bypasses every guard in `src/api.rs` and writes straight to
/// the table, which is the only way to distinguish "the handlers refuse it" from "the database
/// refuses it".
#[tokio::test]
async fn attack_a_second_master_cannot_be_written_even_bypassing_the_api() {
    let db = setup_test_db().await;

    let _first = insert_master_key(&db, "The Master").await;

    let plaintext = simply_ip_vault::api::generate_random_key();
    let second = simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        key_hash: Set(simply_ip_vault::api::hash_key(&plaintext)),
        signing_secret: Set(Some(stored_signing_secret(&plaintext))),
        name: Set("Usurper".to_owned()),
        bound_ips: Set(None),
        is_master: Set(true),
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_create_groups: Set(true),
        parent_key_id: Set(None),
        prefix: Set("usurper1".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await;

    // Note what this insert does *not* contain: `master_marker`. It cannot — the field is not on the
    // entity, because the column is engine-generated. That absence is what makes this an adversarial
    // write rather than a cooperative one, and it is the exact shape that used to be accepted.
    let err = second
        .expect_err("the unique index over the derived master_marker must refuse a second master");
    assert!(
        format!("{err:?}").to_lowercase().contains("unique"),
        "the refusal must come from the uniqueness constraint, not from something incidental: {err:?}"
    );

    let masters = simply_ip_vault::entities::prelude::ApiKey::find()
        .filter(simply_ip_vault::entities::api_key::Column::IsMaster.eq(true))
        .all(&db)
        .await
        .unwrap();
    assert_eq!(masters.len(), 1, "exactly one master survives the attempt");
}

/// The upgrade path: a database that predates §5 comes out the far side with its existing master
/// carrying the derived marker, and every other key carrying `NULL`.
///
/// Nothing backfills this — that is the point. The value is produced by the engine from `is_master`
/// the instant the generated column exists, so the assertion is about what the *schema* computes for
/// rows that were written long before it, not about what any migration remembered to write.
///
/// Migrations 1–6 run first, two keys are seeded as they would have existed before §5, then the rest
/// of the chain runs.
#[tokio::test]
async fn the_master_marker_migration_derives_the_marker_for_pre_existing_rows() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migration::Migrator::up(&db, Some(6)).await.unwrap();

    for (name, prefix, is_master) in
        [("Legacy Master", "legacy01", true), ("Legacy Daughter", "legacy02", false)]
    {
        let plaintext = simply_ip_vault::api::generate_random_key();
        db.execute_unprepared(&format!(
            // `x'...'` rather than a quoted string: SeaORM stores `Uuid` as a 16-byte BLOB on
            // SQLite, and a 36-character hyphenated literal fails to decode on read.
            "INSERT INTO api_keys (id, name, key_hash, prefix, bound_ips, is_master, \
             can_manage_keys, can_manage_webhooks, can_create_groups, created_at, updated_at) \
             VALUES (x'{}', '{name}', '{}', '{prefix}', NULL, {is_master}, true, true, true, \
              '2026-01-01 00:00:00', '2026-01-01 00:00:00')",
            Uuid::new_v4().simple(),
            simply_ip_vault::api::hash_key(&plaintext),
        ))
        .await
        .unwrap();
    }

    migration::Migrator::up(&db, None).await.unwrap();

    // Read through raw SQL: the column is absent from `api_key::Model` by design, so the entity
    // cannot see it. That is the same reason no `INSERT` can name it.
    let rows = db
        .query_all_raw(sea_orm::Statement::from_string(
            db.get_database_backend(),
            "SELECT name, master_marker FROM api_keys ORDER BY prefix".to_owned(),
        ))
        .await
        .unwrap();
    let derived: Vec<(String, Option<i32>)> = rows
        .iter()
        .map(|r| {
            (r.try_get::<String>("", "name").unwrap(), r.try_get("", "master_marker").unwrap())
        })
        .collect();
    assert_eq!(
        derived,
        vec![
            ("Legacy Master".to_owned(), Some(1)),
            ("Legacy Daughter".to_owned(), None)
        ],
        "the engine must derive 1 for the pre-existing master and NULL for everyone else — the NULL \
         half is what lets every non-master row coexist under the unique index"
    );
}

/// A database that already holds two masters stops the migration rather than being silently
/// resolved.
///
/// Demoting a key would strip an operator's authority without asking, and picking the "oldest" is a
/// guess dressed as a policy. Failing names the ids and the `UPDATE` that fixes it, which is
/// recoverable in one command — and the migration leaves the schema untouched, so a retry after the
/// fix starts from a clean state rather than a half-applied one.
#[tokio::test]
async fn the_master_marker_migration_refuses_a_database_with_two_masters() {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migration::Migrator::up(&db, Some(6)).await.unwrap();

    for name in ["Master A", "Master B"] {
        let plaintext = simply_ip_vault::api::generate_random_key();
        db.execute_unprepared(&format!(
            "INSERT INTO api_keys (id, name, key_hash, prefix, bound_ips, is_master, \
             can_manage_keys, can_manage_webhooks, can_create_groups, created_at, updated_at) \
             VALUES (x'{}', '{name}', '{}', 'legacy01', NULL, true, true, true, true, \
              '2026-01-01 00:00:00', '2026-01-01 00:00:00')",
            Uuid::new_v4().simple(),
            simply_ip_vault::api::hash_key(&plaintext),
        ))
        .await
        .unwrap();
    }

    let err = migration::Migrator::up(&db, None)
        .await
        .expect_err("two masters must stop the migration");
    let message = format!("{err}");
    assert!(
        message.contains("RBAC_MODEL.md §5") && message.contains("UPDATE api_keys"),
        "the failure must say what is wrong and how to fix it: {message}"
    );
    assert!(
        !message.contains("<unreadable id>"),
        "the offending ids must be legible — they are what the operator's UPDATE targets: {message}"
    );

    // Left exactly as found: the column was never added, so a retry after the operator's `UPDATE`
    // starts clean instead of hitting a half-applied schema.
    assert!(
        db.execute_unprepared("SELECT master_marker FROM api_keys").await.is_err(),
        "the column must not have been added before the check refused"
    );
}

/// The upgrade that has to cope with the damage: a database that reached `m20260807_000008` while
/// holding **two** masters must stop at `m20260808_000009` rather than crash into the unique index.
///
/// This state is not hypothetical, and that is why the test builds it the hard way instead of seeding
/// it. `m20260807_000007`'s marker was application-maintained, so any writer could set
/// `is_master = true` and leave the marker NULL — NULLs do not collide — and the second master was
/// accepted. Every deployment that ran the old chain could be sitting on exactly this today.
///
/// What the migration owes such an operator is a legible refusal: both rows named, and the `UPDATE`
/// that resolves it. Letting `CREATE UNIQUE INDEX` fail instead would surface a driver-level
/// constraint error naming an index, not the rows, and would do it after the column had already been
/// swapped — a half-applied schema on top of an ambiguous database.
#[tokio::test]
async fn the_derived_marker_migration_refuses_a_database_the_old_marker_let_through() {
    let db = Database::connect("sqlite::memory:").await.unwrap();

    // Through 000008 — the old, bypassable regime — with one legitimate master.
    migration::Migrator::up(&db, Some(6)).await.unwrap();
    let seed = |name: &str, prefix: &str| {
        format!(
            "INSERT INTO api_keys (id, name, key_hash, prefix, bound_ips, is_master, \
             can_manage_keys, can_manage_webhooks, can_create_groups, created_at, updated_at) \
             VALUES (x'{}', '{name}', '{}', '{prefix}', NULL, true, true, true, true, \
              '2026-01-01 00:00:00', '2026-01-01 00:00:00')",
            Uuid::new_v4().simple(),
            simply_ip_vault::api::hash_key(&simply_ip_vault::api::generate_random_key()),
        )
    };
    db.execute_unprepared(&seed("Legitimate Master", "legit001")).await.unwrap();
    // `Some(2)` is two *further* migrations, not "up to number 2": `up` counts pending ones. That
    // lands exactly on 000008 — the last state before the marker became engine-derived.
    migration::Migrator::up(&db, Some(2)).await.unwrap();

    // The bypass itself, replayed: `is_master = true`, marker omitted. Under the old schema this is
    // simply accepted, which is the defect `m20260808_000009` exists to close.
    db.execute_unprepared(&seed("Usurper", "usurper1"))
        .await
        .expect("the old application-maintained marker accepts this — that is the bug");

    let err = migration::Migrator::up(&db, None)
        .await
        .expect_err("two masters must stop the migration rather than fail on the index");
    let message = format!("{err}");
    for expected in ["RBAC_MODEL.md §5", "UPDATE api_keys", "Legitimate Master", "Usurper"] {
        assert!(
            message.contains(expected),
            "the refusal must name both offending rows and the fix, missing {expected:?}: {message}"
        );
    }
    assert!(
        !message.contains("<unreadable id>"),
        "the offending ids must be legible — they are what the operator's UPDATE targets: {message}"
    );

    // Left as found: still the old plain column, not a half-swapped generated one. A retry after the
    // operator's `UPDATE` therefore starts from a coherent schema.
    let ddl = db
        .query_all_raw(sea_orm::Statement::from_string(
            db.get_database_backend(),
            "SELECT sql FROM sqlite_master WHERE name = 'api_keys'".to_owned(),
        ))
        .await
        .unwrap();
    let ddl = ddl[0].try_get::<String>("", "sql").unwrap();
    assert!(
        !ddl.contains("GENERATED"),
        "the schema must be untouched when the migration refuses: {ddl}"
    );
}

/// Even the Master cannot mint a second Master through the API.
///
/// `attack_non_master_cannot_mint_a_master_key` covers the delegated caller. This covers the one
/// caller that used to be allowed: before §5, `guard_scope_elevation` returned `Ok` early for a
/// master, so `POST /api/keys` with `is_master: true` from the master produced a second master and
/// returned its plaintext in the response body.
#[tokio::test]
async fn attack_a_master_cannot_mint_a_second_master() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let master = insert_master_key(&db, "The Master").await;
    let secret = test_signing_secret(&master);

    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/keys")
                .header("X-API-Key", &master)
                .header("Content-Type", "application/json"),
        ),
        &secret,
        &json!({ "name": "Co-Master", "is_master": true }).to_string(),
    );
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::BAD_REQUEST,
        "master status is bootstrap-only; no payload may carry the field, from any caller"
    );

    let masters = simply_ip_vault::entities::prelude::ApiKey::find()
        .filter(simply_ip_vault::entities::api_key::Column::IsMaster.eq(true))
        .all(&db)
        .await
        .unwrap();
    assert_eq!(masters.len(), 1, "no second master row was written");
}

/// The Master key cannot be deleted through the API — by itself or by anyone else.
///
/// `RBAC_MODEL.md` §5: "The Master key cannot be deleted through the API. Regeneration is: delete the
/// row directly in the database; the service re-mints at next boot." The previous guards were both
/// *relative* — "not yourself" and "not by a non-master" — which together left the master deletable
/// by any other master, and the whole point of §5 is that there is no other master.
#[tokio::test]
async fn attack_the_master_key_cannot_be_deleted_through_the_api() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let master = insert_master_key(&db, "The Master").await;
    let secret = test_signing_secret(&master);
    let master_id = simply_ip_vault::entities::prelude::ApiKey::find()
        .filter(simply_ip_vault::entities::api_key::Column::IsMaster.eq(true))
        .one(&db)
        .await
        .unwrap()
        .unwrap()
        .id;

    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/keys/{master_id}"))
                .header("X-API-Key", &master),
        ),
        &secret,
        "",
    );
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "the master key must not be deletable through the API"
    );

    assert!(
        simply_ip_vault::entities::prelude::ApiKey::find_by_id(master_id)
            .one(&db)
            .await
            .unwrap()
            .is_some(),
        "the row is still there"
    );
}

/// `bound_ips` is the Master's *only* API-editable field, and every other one is refused.
///
/// §5 draws the line here rather than at "immutable" outright because a master locked to a network it
/// can no longer reach is unrecoverable without database access, and relocating an operator's own
/// admin network is a routine, non-escalating change. Renaming and re-scoping are neither routine nor
/// non-escalating, and rotation hands back a working master credential in the response body — so all
/// three are outside the API surface entirely.
#[tokio::test]
async fn master_may_edit_only_its_own_bound_ips() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let master = insert_master_key(&db, "The Master").await;
    let secret = test_signing_secret(&master);
    let master_id = simply_ip_vault::entities::prelude::ApiKey::find()
        .filter(simply_ip_vault::entities::api_key::Column::IsMaster.eq(true))
        .one(&db)
        .await
        .unwrap()
        .unwrap()
        .id;

    // Repeats below differ only in body, and two identical bodies inside one second would produce
    // the same signature — which the replay guard refuses for reasons unrelated to this test.
    let tick = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));
    let call = |method: &'static str, path: String, body: String| {
        let (app, master, secret, tick) =
            (app.clone(), master.clone(), secret.clone(), tick.clone());
        async move {
            let req = signed_later(
                inject_connect_info(
                    Request::builder()
                        .method(method)
                        .uri(path)
                        .header("X-API-Key", &master)
                        .header("Content-Type", "application/json"),
                ),
                &secret,
                tick.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                &body,
            );
            app.oneshot(req).await.unwrap().status()
        }
    };

    let put = |body: serde_json::Value| call("PUT", format!("/api/keys/{master_id}"), body.to_string());

    // The permitted edit.
    assert_eq!(
        put(json!({ "bound_ips": "10.0.0.0/8" })).await,
        StatusCode::OK,
        "the master may edit its own bound_ips"
    );
    let after = simply_ip_vault::entities::prelude::ApiKey::find_by_id(master_id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(after.bound_ips.as_deref(), Some("10.0.0.0/8"), "and the edit landed");

    // Everything else on the same endpoint.
    for field in ["name", "can_manage_keys", "can_manage_webhooks", "can_create_groups"] {
        let value = if field == "name" { json!("Renamed") } else { json!(false) };
        assert_eq!(
            put(json!({ field: value })).await,
            StatusCode::FORBIDDEN,
            "the master's '{field}' must not be editable through the API"
        );
    }

    // A payload mixing the one permitted field with a forbidden one is refused whole rather than
    // partially applied — otherwise "edit bound_ips" would become a carrier for the rest.
    assert_eq!(
        put(json!({ "bound_ips": "192.0.2.0/24", "name": "Sneaky" })).await,
        StatusCode::FORBIDDEN
    );

    // Both rotation endpoints, which §5 names explicitly.
    assert_eq!(
        call("POST", format!("/api/keys/{master_id}/rotate"), String::new()).await,
        StatusCode::FORBIDDEN,
        "rotating the master would return a working master credential in the response body"
    );
    assert_eq!(
        call("POST", format!("/api/keys/{master_id}/rotate-secret"), String::new()).await,
        StatusCode::FORBIDDEN,
        "re-keying the master's HMAC secret is equally out of the API surface"
    );

    // Nothing leaked through: the master is exactly as it was except for the one permitted field.
    let final_state = simply_ip_vault::entities::prelude::ApiKey::find_by_id(master_id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(final_state.name, "The Master", "the name never changed");
    assert!(final_state.can_manage_keys && final_state.can_manage_webhooks);
    assert_eq!(final_state.key_hash, after.key_hash, "the credential never rotated");
    assert_eq!(
        final_state.bound_ips.as_deref(),
        Some("10.0.0.0/8"),
        "the rejected mixed payload did not apply its bound_ips half either"
    );
}

/// Rotating a key returns fresh credentials for it. Allowing that against a *master* key handed a
/// non-master complete, immediate takeover of the master credential — the single most direct
/// escalation path in the system.
///
/// The refusal moved from `403` to `404` when §4's visibility scoping landed, and that is a
/// **strengthening, not a regression**. `403` confirmed the id named a real key; the master is in no
/// non-master's subtree, so §4 requires it to answer exactly as a nonexistent id would. A `403` on
/// `POST /keys/{id}/rotate` was a way to enumerate the master key, which is precisely the oracle §4
/// closes. The credential-leak assertions below are unchanged and remain the point of the test.
#[tokio::test]
async fn attack_non_master_cannot_rotate_or_destroy_a_master_key() {
    let db = setup_test_db().await;
    let (app, manager, secret, manager_id, victim_id) = escalation_fixture(&db).await;

    let call = |method: &'static str, path: String, body: &'static str| {
        let (app, manager, secret) = (app.clone(), manager.clone(), secret.clone());
        async move {
            let req = signed(
                inject_connect_info(
                    Request::builder()
                        .method(method)
                        .uri(&path)
                        .header("X-API-Key", &manager)
                        .header("Content-Type", "application/json"),
                ),
                &secret,
                body,
            );
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            (status, String::from_utf8(bytes.to_vec()).unwrap())
        }
    };

    // Full rotation — would have returned a working master API key *and* signing secret.
    let (status, body) = call("POST", format!("/api/keys/{victim_id}/rotate"), "").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "non-master rotated a master key");
    assert!(
        !body.contains("plaintext_key") && !body.contains("signing_secret"),
        "the rejection must not leak credentials, got {body}"
    );

    // Signing-secret-only rotation — same takeover, narrower blast radius.
    let (status, body) = call("POST", format!("/api/keys/{victim_id}/rotate-secret"), "").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "non-master rotated a master key's signing secret");
    assert!(!body.contains("signing_secret"), "the rejection must not leak a secret, got {body}");

    // Relocating a master key's network binding to the attacker's own range.
    let (status, _) = call(
        "PUT",
        format!("/api/keys/{victim_id}"),
        r#"{"bound_ips":"203.0.113.0/24"}"#,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "non-master rewrote a master key's bound_ips");

    // Removing the master keys that would otherwise contain the incident.
    let (status, _) = call("DELETE", format!("/api/keys/{victim_id}"), "").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "non-master deleted a master key");

    // The victim is untouched: still master, still holding its original signing secret.
    let victim = simply_ip_vault::entities::prelude::ApiKey::find_by_id(victim_id)
        .one(&db)
        .await
        .unwrap()
        .expect("the master key must still exist");
    assert!(victim.is_master);

    // Control: the same operations against a *non-master* target still succeed, so the guard is
    // scoped to master targets rather than having disabled key administration outright.
    let (other_id, _other) = insert_key(&db, "Ordinary", false, false, false, false, None).await;
    set_parent(&db, other_id, manager_id).await;
    let (status, _) = call("POST", format!("/api/keys/{other_id}/rotate"), "").await;
    assert_eq!(status, StatusCode::OK, "rotating a non-master key must still work");
    let (status, _) = call("DELETE", format!("/api/keys/{other_id}"), "").await;
    assert_eq!(status, StatusCode::NO_CONTENT, "deleting a non-master key must still work");

    // ...and the caller can still rotate itself.
    let (status, _) = call("POST", format!("/api/keys/{manager_id}/rotate-secret"), "").await;
    assert_eq!(status, StatusCode::OK, "a key may still re-key itself");
}

/// A key must not be able to widen its own global scopes through the generic update endpoint.
#[tokio::test]
async fn attack_non_master_cannot_widen_its_own_scopes() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    // Holds only `can_manage_keys`.
    let (self_id, key) = insert_key(&db, "Self Escalator", false, true, false, false, None).await;
    let secret = test_signing_secret(&key);

    let update = |target: Uuid, body: String| {
        let (app, key, secret) = (app.clone(), key.clone(), secret.clone());
        async move {
            let req = signed(
                inject_connect_info(
                    Request::builder()
                        .method("PUT")
                        .uri(format!("/api/keys/{target}"))
                        .header("X-API-Key", &key)
                        .header("Content-Type", "application/json"),
                ),
                &secret,
                &body,
            );
            app.oneshot(req).await.unwrap().status()
        }
    };

    assert_eq!(
        update(self_id, r#"{"can_manage_webhooks":true}"#.to_owned()).await,
        StatusCode::FORBIDDEN,
        "a key must not grant itself can_manage_webhooks"
    );
    assert_eq!(
        update(self_id, r#"{"can_create_groups":true}"#.to_owned()).await,
        StatusCode::FORBIDDEN,
        "a key must not grant itself can_create_groups"
    );

    // Narrowing its own scopes is not an escalation and stays allowed.
    assert_eq!(
        update(self_id, r#"{"can_manage_keys":false}"#.to_owned()).await,
        StatusCode::OK,
        "dropping a scope you already hold is not an escalation"
    );

    let after = simply_ip_vault::entities::prelude::ApiKey::find_by_id(self_id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert!(!after.can_manage_webhooks && !after.can_create_groups, "no scope was widened");
}

// ─────────────────────────────────────────────────────────────
// Attack 7 — Self-granting and over-granting group permissions
// ─────────────────────────────────────────────────────────────

/// A caller must not be able to widen its own group access, nor hand out access it does not hold.
///
/// Without this, per-group RBAC was advisory: any `can_manage_keys` holder could grant itself — or a
/// second key it controls — full read/write/delete over every group in the system.
#[tokio::test]
async fn attack_cannot_self_grant_or_over_grant_group_permissions() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (caller_id, caller) = insert_key(&db, "Granter", false, true, false, false, None).await;
    let (accomplice_id, _accomplice) = insert_key(&db, "Accomplice", false, false, false, false, None).await;
    let secret = test_signing_secret(&caller);

    let own_group = insert_group(&db, "own-group").await;
    let foreign_group = insert_group(&db, "foreign-group").await;
    // The caller can read and write its own group, but cannot delete in it — and it administers the
    // group, which under R2 is what admits it to the grant path at all. Without `can_manage` every
    // assertion below would pass on the admission check rather than on the per-verb ceiling this test
    // is about, and the control at the end would fail.
    grant_manager(&db, caller_id, own_group, true, true, false).await;

    // `group_id` is a plain string (it doubles as a name), and all three verbs are required fields.
    let post = |target: Uuid, group: Uuid, read: bool, write: bool, del: bool| {
        let (app, caller, secret) = (app.clone(), caller.clone(), secret.clone());
        async move {
            let body = json!({
                "group_id": group.to_string(),
                "can_read": read,
                "can_write": write,
                "can_delete": del,
            });
            let req = signed(
                inject_connect_info(
                    Request::builder()
                        .method("POST")
                        .uri(format!("/api/keys/{target}/permissions"))
                        .header("X-API-Key", &caller)
                        .header("Content-Type", "application/json"),
                ),
                &secret,
                &body.to_string(),
            );
            app.oneshot(req).await.unwrap().status()
        }
    };

    // Self-targeting is bounded rather than blocked: the request is compared against the caller's
    // own row, which is the row being written, so it can never widen. Asking for `can_delete` — the
    // one verb the caller does not hold on its own group — is the escalation direction and fails.
    assert_eq!(
        post(caller_id, own_group, true, true, true).await,
        StatusCode::FORBIDDEN,
        "a key must not widen its own group permissions"
    );
    assert_eq!(
        post(caller_id, foreign_group, true, false, false).await,
        StatusCode::FORBIDDEN,
        "a key must not grant itself access to a group it cannot reach"
    );

    // Granting a third party access to a group the caller cannot reach is refused too — otherwise
    // the accomplice becomes a trivial proxy around the self-grant rule.
    assert_eq!(
        post(accomplice_id, foreign_group, true, false, false).await,
        StatusCode::FORBIDDEN,
        "a key must not delegate access to a group it has none on"
    );

    // Nor may it delegate a verb it does not hold on a group it *can* reach.
    assert_eq!(
        post(accomplice_id, own_group, true, true, true).await,
        StatusCode::FORBIDDEN,
        "a key holding read+write must not grant delete"
    );

    // Control: delegating exactly what it does hold is legitimate and still works.
    assert_eq!(
        post(accomplice_id, own_group, true, true, false).await,
        StatusCode::OK,
        "delegating permissions the caller holds must still work"
    );

    // The accomplice ended up with precisely the delegated verbs and nothing more.
    let perms = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .filter(
            simply_ip_vault::entities::api_key_group_permission::Column::ApiKeyId.eq(accomplice_id),
        )
        .all(&db)
        .await
        .unwrap();
    assert_eq!(perms.len(), 1, "only the one legitimate grant landed");
    assert!(perms[0].can_read && perms[0].can_write && !perms[0].can_delete);

    // Last, because it mutates the caller's own row and everything above depends on it: reducing
    // your own access is permitted. It is the same authority the dedicated revoke endpoint confers,
    // reached through this one, and removing a verb cannot raise anyone above where they already
    // were — the caller least of all.
    assert_eq!(
        post(caller_id, own_group, true, false, false).await,
        StatusCode::OK,
        "a key may drop a verb from its own row on a group it manages"
    );
    let own = simply_ip_vault::entities::api_key_group_permission::Entity::find()
        .filter(simply_ip_vault::entities::api_key_group_permission::Column::ApiKeyId.eq(caller_id))
        .one(&db)
        .await
        .unwrap()
        .expect("the caller still has a row");
    assert!(own.can_read && !own.can_write, "the self-directed change was a genuine reduction");
}

// ─────────────────────────────────────────────────────────────
// Attack 8 — Webhook hijacking by repointing
// ─────────────────────────────────────────────────────────────

/// Repointing a webhook must invalidate the secret it signs with.
///
/// `secret_token` is write-only — no endpoint returns it — so an editor cannot read the secret
/// directly. The hijack is indirect: point the webhook at a server you control and wait, and the
/// next dispatch arrives at your endpoint carrying a valid `X-Signature-256` over a payload you
/// influenced, which is a working forgery oracle for the receiver's shared secret. Forcing rotation
/// on repoint means a secret is only ever usable against the destination it was configured for.
#[tokio::test]
async fn attack_repointing_a_webhook_forces_its_secret_to_rotate() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let key = insert_master_key(&db, "Hook Admin").await;
    let secret = test_signing_secret(&key);
    let group_id = insert_group(&db, "hijack-group").await;

    let original_secret = "original-webhook-secret-do-not-leak";
    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/webhooks")
                .header("X-API-Key", &key)
                .header("Content-Type", "application/json"),
        ),
        &secret,
        &json!({
            "name": "Hijack Target",
            "target_url": "https://legitimate.example.com/hook",
            "secret_token": original_secret,
            "payload_template": "{}",
            "group_id": group_id.to_string(),
            "auth_mode": "CANONICAL_V1",
        })
        .to_string(),
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let created = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&created).unwrap();
    let hook_id = created["id"].as_str().unwrap().to_owned();

    let put = |body: serde_json::Value| {
        let (app, key, secret, hook_id) =
            (app.clone(), key.clone(), secret.clone(), hook_id.clone());
        async move {
            let req = signed(
                inject_connect_info(
                    Request::builder()
                        .method("PUT")
                        .uri(format!("/api/webhooks/{hook_id}"))
                        .header("X-API-Key", &key)
                        .header("Content-Type", "application/json"),
                ),
                &secret,
                &body.to_string(),
            );
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));
            (status, parsed)
        }
    };

    let stored_secret = |db: DatabaseConnection, hook_id: String| async move {
        let id: Uuid = hook_id.parse().unwrap();
        simply_ip_vault::entities::prelude::WebhookConfig::find_by_id(id)
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .secret_token
    };

    // A rename touches neither the URL nor the template, so the secret is left alone.
    let (status, body) = put(json!({ "name": "Renamed" })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["secret_rotated"], false, "a rename must not churn the secret");
    assert_eq!(
        stored_secret(db.clone(), hook_id.clone()).await,
        original_secret,
        "the secret survives an unrelated edit"
    );

    // Re-submitting the identical URL is not a repoint — an idempotent PUT must not rotate.
    let (status, body) = put(json!({ "target_url": "https://legitimate.example.com/hook" })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["secret_rotated"], false, "re-submitting the same URL is not a repoint");
    assert_eq!(stored_secret(db.clone(), hook_id.clone()).await, original_secret);

    // ── The attack: repoint at an attacker-controlled server. ──────────────
    let (status, body) = put(json!({ "target_url": "https://attacker.example.net/collect" })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["secret_rotated"], true, "repointing must rotate the secret");

    let after_repoint = stored_secret(db.clone(), hook_id.clone()).await;
    assert_ne!(after_repoint, original_secret, "the old secret must not survive a repoint");
    assert_eq!(after_repoint.len(), 64, "the replacement is a full-width generated secret");

    // The new secret is disclosed exactly once, to the caller that caused the rotation...
    assert_eq!(
        body["secret_token"].as_str(),
        Some(after_repoint.as_str()),
        "the generated secret is returned once so the operator can reconfigure the receiver"
    );
    // ...and the *old* one is never echoed anywhere in that response.
    assert!(
        !body.to_string().contains(original_secret),
        "the pre-rotation secret must never appear in a response"
    );

    // Rewriting the template is treated the same way: it decides which bytes the signature covers,
    // so a caller who can rewrite it can make the existing secret vouch for content it never saw.
    let before_template_edit = stored_secret(db.clone(), hook_id.clone()).await;
    let (status, body) = put(json!({ "hmac_template": r"{method}\n{path}\n{timestamp}\n{body}\nx" })).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["secret_rotated"], true, "rewriting hmac_template must rotate the secret");
    assert_ne!(stored_secret(db.clone(), hook_id.clone()).await, before_template_edit);

    // A template that does not cover the body is still refused outright, rotation or not.
    let (status, _) = put(json!({ "hmac_template": r"{method}\n{path}\n{timestamp}" })).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "a bodyless template is rejected on update too");

    // A caller supplying its own replacement gets no generated value echoed back.
    let (status, body) =
        put(json!({ "target_url": "https://elsewhere.example.com/h", "secret_token": "chosen-by-caller" }))
            .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["secret_rotated"], true);
    assert!(body["secret_token"].is_null(), "a caller-supplied secret is not echoed back");
    assert_eq!(stored_secret(db.clone(), hook_id.clone()).await, "chosen-by-caller");

    // No read endpoint ever discloses the secret, before or after rotation.
    let req = signed(
        inject_connect_info(Request::builder().uri("/api/webhooks").header("X-API-Key", &key)),
        &secret,
        "",
    );
    let res = app.clone().oneshot(req).await.unwrap();
    let listing = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let listing = String::from_utf8(listing.to_vec()).unwrap();
    assert!(!listing.contains(original_secret) && !listing.contains("chosen-by-caller"));
}

/// Webhook administration must be bounded by the caller's own group access.
///
/// A webhook is a standing export of everything that happens in its group, to a URL the creator
/// chooses. `can_manage_webhooks` alone let a key scoped to one group subscribe to *every* group's
/// events and stream them to a server it controls.
#[tokio::test]
async fn attack_webhook_admin_cannot_reach_groups_it_has_no_access_to() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let master = insert_master_key(&db, "Owner").await;
    let master_secret = test_signing_secret(&master);
    let (tenant_id, tenant) = insert_key(&db, "Tenant", false, false, true, false, None).await;
    let tenant_secret = test_signing_secret(&tenant);

    let own_group = insert_group(&db, "tenant-group").await;
    let foreign_group = insert_group(&db, "other-tenant-group").await;
    grant(&db, tenant_id, own_group, true, true, true).await;

    // The master seeds a webhook on the group the tenant cannot see.
    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/webhooks")
                .header("X-API-Key", &master)
                .header("Content-Type", "application/json"),
        ),
        &master_secret,
        &json!({
            "name": "Foreign Hook",
            "target_url": "https://foreign.example.com/hook",
            "secret_token": "foreign-secret",
            "payload_template": "{}",
            "group_id": foreign_group.to_string(),
            "auth_mode": "CANONICAL_V1",
        })
        .to_string(),
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let created = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&created).unwrap();
    let foreign_hook_id = created["id"].as_str().unwrap().to_owned();

    let as_tenant = |method: &'static str, path: String, body: String| {
        let (app, tenant, tenant_secret) = (app.clone(), tenant.clone(), tenant_secret.clone());
        async move {
            let req = signed(
                inject_connect_info(
                    Request::builder()
                        .method(method)
                        .uri(&path)
                        .header("X-API-Key", &tenant)
                        .header("Content-Type", "application/json"),
                ),
                &tenant_secret,
                &body,
            );
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            (status, String::from_utf8(bytes.to_vec()).unwrap())
        }
    };

    // Subscribing to a group it cannot read is refused.
    let exfil = json!({
        "name": "Exfiltrator",
        "target_url": "https://attacker.example.net/collect",
        "secret_token": "s",
        "payload_template": "{\"ip\":\"$target_address\"}",
        "group_id": foreign_group.to_string(),
        "auth_mode": "CANONICAL_V1",
    })
    .to_string();
    let (status, _) = as_tenant("POST", "/api/webhooks".to_owned(), exfil).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a tenant must not subscribe a webhook to another tenant's group"
    );

    // The foreign webhook is invisible in its listing...
    let (status, body) = as_tenant("GET", "/api/webhooks".to_owned(), String::new()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(!body.contains("Foreign Hook"), "listing leaked another group's webhook: {body}");
    assert!(!body.contains("foreign.example.com"), "listing leaked another group's target URL");

    // ...and neither editable nor deletable, reported as absent rather than forbidden.
    let (status, _) = as_tenant(
        "PUT",
        format!("/api/webhooks/{foreign_hook_id}"),
        r#"{"target_url":"https://attacker.example.net/collect"}"#.to_owned(),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a tenant must not repoint another group's webhook");

    let (status, _) =
        as_tenant("DELETE", format!("/api/webhooks/{foreign_hook_id}"), String::new()).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "a tenant must not delete another group's webhook");

    // Control: on its own group everything still works.
    let own = json!({
        "name": "Own Hook",
        "target_url": "https://tenant.example.com/hook",
        "secret_token": "s",
        "payload_template": "{}",
        "group_id": own_group.to_string(),
        "auth_mode": "CANONICAL_V1",
    })
    .to_string();
    let (status, _) = as_tenant("POST", "/api/webhooks".to_owned(), own).await;
    assert_eq!(status, StatusCode::OK, "a tenant may still manage webhooks on its own group");
}

/// Editing an already-privileged webhook's `auth_mode` or `api_key` is master-only, extending the
/// same gate that already covers `target_url`/`hmac_template`. Changing either one achieves the same
/// hijack a repoint would: an `auth_mode` change can downgrade the receiver's verification (e.g. to
/// `NONE`, so no signature is checked at all), and an `api_key` change swaps out the credential the
/// receiver trusts — neither is undone by the secret rotation a repoint alone triggers.
#[tokio::test]
async fn attack_editing_a_privileged_webhooks_auth_mode_or_api_key_is_master_only() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let master = insert_master_key(&db, "Owner").await;
    let master_secret = test_signing_secret(&master);
    let (owner_id, owner_key) = insert_key(&db, "Webhook Owner", false, false, true, false, None).await;
    let owner_secret = test_signing_secret(&owner_key);
    let group_id = insert_group(&db, "priv-group").await;
    grant(&db, owner_id, group_id, true, true, true).await;

    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/webhooks")
                .header("X-API-Key", &owner_key)
                .header("Content-Type", "application/json"),
        ),
        &owner_secret,
        &json!({
            "name": "Privileged Hook",
            "target_url": "https://legitimate.example.com/hook",
            "secret_token": "s",
            "api_key": "downstream-credential",
            "payload_template": "{}",
            "group_id": group_id.to_string(),
            "auth_mode": "CANONICAL_V1",
        })
        .to_string(),
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let created = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&created).unwrap();
    let hook_id = created["id"].as_str().unwrap().to_owned();

    let put = |key: String, secret: String, body: serde_json::Value| {
        let (app, hook_id) = (app.clone(), hook_id.clone());
        async move {
            let req = signed(
                inject_connect_info(
                    Request::builder()
                        .method("PUT")
                        .uri(format!("/api/webhooks/{hook_id}"))
                        .header("X-API-Key", &key)
                        .header("Content-Type", "application/json"),
                ),
                &secret,
                &body.to_string(),
            );
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));
            (status, parsed)
        }
    };

    // The owner (non-master) may not weaken auth_mode on its own privileged webhook...
    let (status, _) = put(owner_key.clone(), owner_secret.clone(), json!({ "auth_mode": "NONE" })).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a non-master cannot change auth_mode on a privileged webhook"
    );

    // ...nor swap out the api_key credential itself.
    let (status, _) =
        put(owner_key.clone(), owner_secret.clone(), json!({ "api_key": "attacker-supplied-key" })).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "a non-master cannot change api_key on a privileged webhook"
    );

    // Non-identity fields remain freely editable by the owner.
    let (status, _) =
        put(owner_key.clone(), owner_secret.clone(), json!({ "name": "Renamed Privileged" })).await;
    assert_eq!(status, StatusCode::OK, "a non-master may still rename a privileged webhook");

    // A master may change either.
    let (status, body) = put(master.clone(), master_secret.clone(), json!({ "auth_mode": "NONE" })).await;
    assert_eq!(status, StatusCode::OK, "a master may change auth_mode on a privileged webhook");
    assert_eq!(body["auth_mode"], "NONE");

    let (status, body) =
        put(master.clone(), master_secret.clone(), json!({ "api_key": "master-rotated-key" })).await;
    assert_eq!(status, StatusCode::OK, "a master may change api_key on a privileged webhook");
    assert_eq!(body["has_api_key"], true);
}

/// **Cloning a privileged webhook (one carrying a non-empty `api_key`) is master-only**, even for the
/// webhook's own non-master owner. Cloning duplicates every configuration property, including
/// `api_key` — so an unrestricted clone would be an easy way to fan a receiver-trusted credential out
/// to a *second*, independently-editable dispatch target, which is a strictly larger exposure than
/// `PUT`-editing the original in place (the concern
/// [`attack_editing_a_privileged_webhooks_auth_mode_or_api_key_is_master_only`] already covers).
#[tokio::test]
async fn attack_cloning_a_privileged_webhook_is_master_only() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let master = insert_master_key(&db, "Owner").await;
    let master_secret = test_signing_secret(&master);
    let (owner_id, owner_key) = insert_key(&db, "Webhook Owner", false, false, true, false, None).await;
    let owner_secret = test_signing_secret(&owner_key);
    let group_id = insert_group(&db, "priv-clone-group").await;
    grant(&db, owner_id, group_id, true, true, true).await;

    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/webhooks")
                .header("X-API-Key", &owner_key)
                .header("Content-Type", "application/json"),
        ),
        &owner_secret,
        &json!({
            "name": "Privileged Hook",
            "target_url": "https://legitimate.example.com/hook",
            "secret_token": "s",
            "api_key": "downstream-credential",
            "payload_template": "{}",
            "group_id": group_id.to_string(),
            "auth_mode": "CANONICAL_V1",
        })
        .to_string(),
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let created = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&created).unwrap();
    let hook_id = created["id"].as_str().unwrap().to_owned();

    // The webhook's own non-master owner may not clone it — owning a privileged webhook is not the
    // same authority as being trusted to fan its credential out to a new target.
    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri(format!("/api/webhooks/{hook_id}/clone"))
                .header("X-API-Key", &owner_key)
                .header("Content-Type", "application/json"),
        ),
        &owner_secret,
        &json!({ "name": "owner-attempted-clone" }).to_string(),
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        res.status(),
        StatusCode::FORBIDDEN,
        "a non-master cannot clone a privileged webhook, even one it owns"
    );

    // No row was created by the refused attempt.
    let count = simply_ip_vault::entities::webhook_config::Entity::find().all(&db).await.unwrap().len();
    assert_eq!(count, 1, "the refused clone must not have inserted anything");

    // A master may clone it.
    let req = signed_later(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri(format!("/api/webhooks/{hook_id}/clone"))
                .header("X-API-Key", &master)
                .header("Content-Type", "application/json"),
        ),
        &master_secret,
        1,
        &json!({ "name": "master-cloned" }).to_string(),
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::CREATED, "a master may clone a privileged webhook");
    let cloned: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    assert_eq!(cloned["name"], "master-cloned");

    let cloned_id = Uuid::parse_str(cloned["id"].as_str().unwrap()).unwrap();
    let cloned_row = simply_ip_vault::entities::prelude::WebhookConfig::find_by_id(cloned_id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        cloned_row.api_key.as_deref(),
        Some("downstream-credential"),
        "a master's clone does duplicate api_key — the gate is about who may clone, not whether the \
         field is copied once permitted"
    );
}

/// Retargeting a webhook onto a different group is scoped by the same `can_read` check
/// `create_webhook` applies to the group a webhook is created against — and, unlike
/// `target_url`/`hmac_template`/`auth_mode`/`api_key`, is **not** gated by the privileged-webhook
/// rule: it changes which events trigger dispatch, not where a credential is sent or what is signed.
#[tokio::test]
async fn update_webhook_group_id_change_is_scoped_by_can_read_not_by_the_privileged_gate() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (owner_id, owner_key) = insert_key(&db, "Owner", false, false, true, false, None).await;
    let owner_secret = test_signing_secret(&owner_key);
    let origin_group = insert_group(&db, "origin-group").await;
    let readable_group = insert_group(&db, "readable-group").await;
    let unreadable_group = insert_group(&db, "unreadable-group").await;
    grant(&db, owner_id, origin_group, true, true, true).await;
    grant(&db, owner_id, readable_group, true, true, true).await;
    // Deliberately no grant on unreadable_group.

    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/webhooks")
                .header("X-API-Key", &owner_key)
                .header("Content-Type", "application/json"),
        ),
        &owner_secret,
        &json!({
            "name": "Privileged Regroup Hook",
            "target_url": "https://legitimate.example.com/hook",
            "secret_token": "s",
            "api_key": "downstream-credential",
            "payload_template": "{}",
            "group_id": origin_group.to_string(),
            "auth_mode": "CANONICAL_V1",
        })
        .to_string(),
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let created = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&created).unwrap();
    let hook_id = created["id"].as_str().unwrap().to_owned();

    let put = |body: serde_json::Value| {
        let (app, owner_key, owner_secret, hook_id) =
            (app.clone(), owner_key.clone(), owner_secret.clone(), hook_id.clone());
        async move {
            let req = signed(
                inject_connect_info(
                    Request::builder()
                        .method("PUT")
                        .uri(format!("/api/webhooks/{hook_id}"))
                        .header("X-API-Key", &owner_key)
                        .header("Content-Type", "application/json"),
                ),
                &owner_secret,
                &body.to_string(),
            );
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or(json!(null));
            (status, parsed)
        }
    };

    // Retargeting onto a group the owner cannot read is refused...
    let (status, _) = put(json!({ "group_id": unreadable_group.to_string() })).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "retargeting onto an unreadable group must be refused");

    // ...but onto one it can read succeeds, even though the webhook is privileged — group_id is not
    // part of the privileged-webhook gate.
    let (status, body) = put(json!({ "group_id": readable_group.to_string() })).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a non-master owner may retarget a privileged webhook's group when it can read the destination"
    );
    assert_eq!(body["group_id"], readable_group.to_string());
}

/// Changing `auth_mode` into a signing mode is treated the same as a repoint: the secret a webhook
/// holds must never be inherited silently into a new signing use. A webhook created in `NONE` mode
/// (so its `secret_token` is an empty string) transitioning into `CANONICAL_V1` without supplying a
/// secret must get a freshly generated one, not ship with an empty signing key.
#[tokio::test]
async fn attack_changing_auth_mode_into_a_signing_mode_forces_secret_rotation() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let key = insert_master_key(&db, "Hook Admin").await;
    let secret = test_signing_secret(&key);
    let group_id = insert_group(&db, "mode-change-group").await;

    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/webhooks")
                .header("X-API-Key", &key)
                .header("Content-Type", "application/json"),
        ),
        &secret,
        &json!({
            "name": "Mode Change Hook",
            "target_url": "https://legitimate.example.com/hook",
            "payload_template": "{}",
            "group_id": group_id.to_string(),
            "auth_mode": "NONE",
        })
        .to_string(),
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let created = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&created).unwrap();
    let hook_id = created["id"].as_str().unwrap().to_owned();

    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/webhooks/{hook_id}"))
                .header("X-API-Key", &key)
                .header("Content-Type", "application/json"),
        ),
        &secret,
        &json!({ "auth_mode": "CANONICAL_V1" }).to_string(),
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(
        body["secret_rotated"], true,
        "transitioning into a signing mode must rotate the secret"
    );
    assert!(
        body["secret_token"].as_str().is_some_and(|s| s.len() == 64),
        "a fresh secret is generated and returned"
    );
}

/// Transitioning an existing webhook into `API_KEY_ONLY` without ever having (or now supplying) an
/// `api_key` is refused up front — the same precondition `create_webhook` enforces, checked here
/// against the *effective* post-update state rather than the payload alone.
#[tokio::test]
async fn update_webhook_rejects_api_key_only_transition_without_a_key() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let key = insert_master_key(&db, "Hook Admin").await;
    let secret = test_signing_secret(&key);
    let group_id = insert_group(&db, "api-key-transition-group").await;

    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/webhooks")
                .header("X-API-Key", &key)
                .header("Content-Type", "application/json"),
        ),
        &secret,
        &json!({
            "name": "No Key Hook",
            "target_url": "https://legitimate.example.com/hook",
            "secret_token": "s",
            "payload_template": "{}",
            "group_id": group_id.to_string(),
            "auth_mode": "CANONICAL_V1",
        })
        .to_string(),
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let created = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let created: serde_json::Value = serde_json::from_slice(&created).unwrap();
    let hook_id = created["id"].as_str().unwrap().to_owned();

    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/webhooks/{hook_id}"))
                .header("X-API-Key", &key)
                .header("Content-Type", "application/json"),
        ),
        &secret,
        &json!({ "auth_mode": "API_KEY_ONLY" }).to_string(),
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        res.status(),
        StatusCode::BAD_REQUEST,
        "no api_key exists to satisfy API_KEY_ONLY"
    );

    // Supplying one alongside the mode change succeeds.
    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("PUT")
                .uri(format!("/api/webhooks/{hook_id}"))
                .header("X-API-Key", &key)
                .header("Content-Type", "application/json"),
        ),
        &secret,
        &json!({ "auth_mode": "API_KEY_ONLY", "api_key": "remote-credential" }).to_string(),
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "supplying api_key alongside the mode change satisfies the precondition"
    );
}

// ─────────────────────────────────────────────────────────────
// IP record soft delete, restore, hard delete, and 92-day purge
// ─────────────────────────────────────────────────────────────

/// Seeds an IP record in a group and returns its id.
async fn insert_ip_record(db: &DatabaseConnection, address: &str, group_id: Uuid) -> Uuid {
    let id = Uuid::new_v4();
    let now = chrono::Utc::now().naive_utc();
    simply_ip_vault::entities::ip_record::ActiveModel {
        id: Set(id),
        target_address: Set(address.to_owned()),
        cause: Set(Some("seeded".to_owned())),
        is_locked: Set(false),
        created_at: Set(now),
        updated_at: Set(now),
        last_seen_at: Set(now),
        is_deleted: Set(false),
        deleted_at: Set(None),
        deleted_by: Set(None),
    }
    .insert(db)
    .await
    .unwrap();

    simply_ip_vault::entities::ip_record_group_membership::ActiveModel {
        ip_record_id: Set(id),
        group_id: Set(group_id),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(db)
    .await
    .unwrap();

    id
}

/// Reads a record straight from the database, bypassing every API-level filter.
async fn raw_record(
    db: &DatabaseConnection,
    id: Uuid,
) -> Option<simply_ip_vault::entities::ip_record::Model> {
    simply_ip_vault::entities::prelude::IpRecord::find_by_id(id).one(db).await.unwrap()
}

/// A non-master's delete must hide the record without destroying it.
///
/// The two halves are equally important and are asserted separately: the API must stop returning
/// it (otherwise "delete" did nothing observable) *and* the row must survive with its attribution
/// intact (otherwise it is an ordinary delete wearing a different name, and nothing is recoverable).
#[tokio::test]
async fn non_master_delete_is_soft_and_hides_the_record_without_dropping_the_row() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (deleter_id, deleter) = insert_key(&db, "Deleter", false, false, false, false, None).await;
    let secret = test_signing_secret(&deleter);
    let group_id = insert_group(&db, "soft-delete-group").await;
    grant(&db, deleter_id, group_id, true, true, true).await;

    let record_id = insert_ip_record(&db, "198.51.100.10", group_id).await;

    // Visible before the delete.
    let req = signed(
        inject_connect_info(Request::builder().uri("/api/ips").header("X-API-Key", &deleter)),
        &secret,
        "",
    );
    let res = app.clone().oneshot(req).await.unwrap();
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    assert!(String::from_utf8(body.to_vec()).unwrap().contains("198.51.100.10"));

    // Delete.
    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/ips/{record_id}"))
                .header("X-API-Key", &deleter),
        ),
        &secret,
        "",
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let parsed: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(parsed["deleted"], "soft", "a non-master delete must be soft");

    // Half one: the row is still there, flagged and attributed.
    let row = raw_record(&db, record_id).await.expect("the row must survive a soft delete");
    assert!(row.is_deleted, "is_deleted must be set");
    assert!(row.deleted_at.is_some(), "deleted_at must be stamped");
    assert_eq!(
        row.deleted_by.as_deref(),
        Some(deleter_id.to_string().as_str()),
        "deleted_by must attribute the acting key"
    );
    assert_eq!(row.target_address, "198.51.100.10", "the record's data is untouched");

    // Half two: it is gone from every *ordinary* read. Each listing gets its own timestamp — the
    // paths differ, but the loop also runs after earlier calls in this test and a repeat would
    // otherwise collide with one of them.
    //
    // `?include_deleted=true` is deliberately **not** in this list. It used to be, back when the flag
    // was master-only; it is now open to any caller and scoped by group instead, so a key reading a
    // group it may read *should* see that group's tombstones — that is what a delta-sync consumer
    // replicates. What must not change is that the tombstone stays out of the default listing and out
    // of the address export, which is what this loop still pins. The group scoping itself is covered
    // by `include_deleted_is_scoped_to_readable_groups_for_a_non_master`.
    for (offset, path) in ["/api/ips", "/api/ips?format=iplist"].iter().enumerate() {
        let req = signed_later(
            inject_connect_info(Request::builder().uri(*path).header("X-API-Key", &deleter)),
            &secret,
            // +1: the plain `/api/ips` listing was already issued above, before the delete.
            offset as i64 + 1,
            "",
        );
        let res = app.clone().oneshot(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            !text.contains("198.51.100.10"),
            "{path} must not expose a soft-deleted record without an explicit opt-in (got {text})"
        );
    }

    // And the opt-in does surface it — for this caller, in this group. Asserted here rather than
    // merely removed from the loop above, so the change of policy is pinned rather than implied.
    let req = signed_later(
        inject_connect_info(
            Request::builder().uri("/api/ips?include_deleted=true").header("X-API-Key", &deleter),
        ),
        &secret,
        3,
        "",
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let text = String::from_utf8(
        axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap().to_vec(),
    )
    .unwrap();
    assert!(
        text.contains("198.51.100.10"),
        "include_deleted must surface a tombstone in a group the caller can read: {text}"
    );
    assert!(
        !text.contains("deleted_by"),
        "but never the id of the key that deleted it — that is master-only: {text}"
    );

    // A non-master cannot escalate to a hard delete by asking for one.
    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/ips/{record_id}?hard=true"))
                .header("X-API-Key", &deleter),
        ),
        &secret,
        "",
    );
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "hard delete must be master-only"
    );
    assert!(raw_record(&db, record_id).await.is_some(), "the row must still be there");
}

/// A key with no delete permission on any of the record's groups cannot delete it at all.
#[tokio::test]
async fn deleting_a_record_requires_delete_permission_on_one_of_its_groups() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (reader_id, reader) = insert_key(&db, "Reader", false, false, false, false, None).await;
    let secret = test_signing_secret(&reader);
    let group_id = insert_group(&db, "read-only-group").await;
    // Read and write, but explicitly NOT delete.
    grant(&db, reader_id, group_id, true, true, false).await;

    let record_id = insert_ip_record(&db, "198.51.100.20", group_id).await;

    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/ips/{record_id}"))
                .header("X-API-Key", &reader),
        ),
        &secret,
        "",
    );
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::FORBIDDEN);

    let row = raw_record(&db, record_id).await.expect("row survives");
    assert!(!row.is_deleted, "a rejected delete must not have flagged the record");
}

/// The master's side of the trash: see it, restore it, or destroy it for good.
#[tokio::test]
async fn master_can_view_restore_and_hard_delete_soft_deleted_records() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let master = insert_master_key(&db, "Trash Admin").await;
    let secret = test_signing_secret(&master);
    let group_id = insert_group(&db, "trash-group").await;
    let record_id = insert_ip_record(&db, "198.51.100.30", group_id).await;

    // Some calls below repeat verbatim, so each takes its own timestamp — an identical repeat
    // inside one second is the same signature, which is exactly what a replay is.
    let tick = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));
    let call = |method: &'static str, path: String| {
        let (app, master, secret, tick) =
            (app.clone(), master.clone(), secret.clone(), tick.clone());
        async move {
            let req = signed_later(
                inject_connect_info(
                    Request::builder().method(method).uri(&path).header("X-API-Key", &master),
                ),
                &secret,
                tick.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                "",
            );
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            (status, String::from_utf8(bytes.to_vec()).unwrap())
        }
    };

    let (status, _) = call("DELETE", format!("/api/ips/{record_id}")).await;
    assert_eq!(status, StatusCode::OK);

    // Hidden from the default listing even for a master — the trash is opt-in, so a master's
    // ordinary view is not silently different from everyone else's.
    let (_, body) = call("GET", "/api/ips".to_owned()).await;
    assert!(!body.contains("198.51.100.30"), "the default listing hides deleted records");

    // ...and visible with the explicit flag.
    let (status, body) = call("GET", "/api/ips?include_deleted=true".to_owned()).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("198.51.100.30"), "include_deleted must surface the trash");
    let listed: serde_json::Value = serde_json::from_str(&body).unwrap();
    let row = listed.as_array().unwrap().iter().find(|r| r["target_address"] == "198.51.100.30").unwrap();
    assert_eq!(row["is_deleted"], true, "the trash view reports the flag");
    assert!(row["deleted_at"].is_string(), "and when it happened");

    // Restore.
    let (status, body) = call("POST", format!("/api/ips/{record_id}/restore")).await;
    assert_eq!(status, StatusCode::OK, "master restore must succeed");
    assert!(body.contains("\"restored\":true"));

    let row = raw_record(&db, record_id).await.expect("row exists");
    assert!(!row.is_deleted, "restore clears the flag");
    assert!(row.deleted_at.is_none(), "restore clears deleted_at");
    assert!(row.deleted_by.is_none(), "restore clears deleted_by");

    // Back in the normal listing.
    let (_, body) = call("GET", "/api/ips".to_owned()).await;
    assert!(body.contains("198.51.100.30"), "a restored record is visible again");

    // Restoring a live record is a no-op error, not a silent success.
    let (status, _) = call("POST", format!("/api/ips/{record_id}/restore")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "nothing to restore");

    // Hard delete really removes the row.
    let (status, body) = call("DELETE", format!("/api/ips/{record_id}?hard=true")).await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.contains("permanent"));
    assert!(raw_record(&db, record_id).await.is_none(), "hard delete drops the row");
}

/// Restore is master-only: recovering from a careless or compromised key must not depend on that
/// same key's authority.
#[tokio::test]
async fn restore_and_purge_are_master_only() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    // Every delegated scope short of master.
    let (id, delegated) = insert_key(&db, "Delegated", false, true, true, true, None).await;
    let secret = test_signing_secret(&delegated);
    let group_id = insert_group(&db, "perm-group").await;
    grant(&db, id, group_id, true, true, true).await;
    let record_id = insert_ip_record(&db, "198.51.100.40", group_id).await;

    let post = |path: String| {
        let (app, delegated, secret) = (app.clone(), delegated.clone(), secret.clone());
        async move {
            let req = signed(
                inject_connect_info(
                    Request::builder()
                        .method("POST")
                        .uri(&path)
                        .header("X-API-Key", &delegated)
                        .header("Content-Type", "application/json"),
                ),
                &secret,
                "",
            );
            app.oneshot(req).await.unwrap().status()
        }
    };

    assert_eq!(post(format!("/api/ips/{record_id}/restore")).await, StatusCode::FORBIDDEN);
    assert_eq!(post("/api/system/purge-ips".to_owned()).await, StatusCode::FORBIDDEN);
}

/// The purge drops records past the retention window and keeps everything else.
///
/// Three records with deliberately chosen ages pin the boundary: one well past 92 days (purged),
/// one just inside it (kept), and one live-but-old (kept, because it was never deleted). The last
/// is the important one — a purge that filtered on `deleted_at` alone without also checking
/// `is_deleted` would destroy restored records that kept an old timestamp.
#[tokio::test]
async fn purge_removes_only_records_past_the_92_day_retention_window() {
    use simply_ip_vault::retention::{purge_expired_ip_records, DEFAULT_RETENTION_DAYS};

    let db = setup_test_db().await;
    let group_id = insert_group(&db, "purge-group").await;

    let expired = insert_ip_record(&db, "203.0.113.1", group_id).await;
    let recent = insert_ip_record(&db, "203.0.113.2", group_id).await;
    let live = insert_ip_record(&db, "203.0.113.3", group_id).await;

    let age = |days: i64| (chrono::Utc::now() - chrono::Duration::days(days)).naive_utc();

    let mark_deleted = |id: Uuid, at: chrono::NaiveDateTime, deleted: bool| {
        let db = db.clone();
        async move {
            let record = raw_record(&db, id).await.unwrap();
            let mut active: simply_ip_vault::entities::ip_record::ActiveModel = record.into();
            active.is_deleted = Set(deleted);
            active.deleted_at = Set(Some(at));
            active.update(&db).await.unwrap();
        }
    };

    mark_deleted(expired, age(DEFAULT_RETENTION_DAYS + 1), true).await;
    mark_deleted(recent, age(DEFAULT_RETENTION_DAYS - 1), true).await;
    // Deleted long ago, then restored: `is_deleted` is false but the stale timestamp remains.
    mark_deleted(live, age(DEFAULT_RETENTION_DAYS + 365), false).await;

    let purged = purge_expired_ip_records(&db, DEFAULT_RETENTION_DAYS).await.unwrap();
    assert_eq!(purged, 1, "exactly the one aged-out record is purged");

    assert!(raw_record(&db, expired).await.is_none(), "the aged-out record is gone");
    assert!(raw_record(&db, recent).await.is_some(), "a record inside the window is kept");
    assert!(
        raw_record(&db, live).await.is_some(),
        "a restored record must survive regardless of its stale deleted_at"
    );

    // Cascade: the purged record's group membership went with it, leaving no orphan junction row.
    let orphans = simply_ip_vault::entities::prelude::IpRecordGroupMembership::find()
        .filter(
            simply_ip_vault::entities::ip_record_group_membership::Column::IpRecordId.eq(expired),
        )
        .all(&db)
        .await
        .unwrap();
    assert!(orphans.is_empty(), "cascade removed the membership rows");

    // A retention window of 0 disables purging entirely rather than meaning "purge everything".
    assert_eq!(purge_expired_ip_records(&db, 0).await.unwrap(), 0);
    assert_eq!(purge_expired_ip_records(&db, -1).await.unwrap(), 0);
    assert!(raw_record(&db, recent).await.is_some(), "nothing was destroyed by the disabled sweep");
}

/// **Successful and failed `webhook_executions` rows are purged on independent windows** — 24h for
/// successes, 7 days (168h) for failures — and each threshold disables independently at `0`,
/// mirroring `purge_removes_only_records_past_the_92_day_retention_window`'s coverage of the same
/// properties for IP records.
///
/// Four rows pin every boundary that matters: a success old enough to purge, a success just inside
/// its window, a failure old enough to purge under the *failure* window but not the (much shorter)
/// success one, and a failure well inside its own window. If the two outcomes shared one threshold,
/// this test would catch it — the "old failure" row would either survive when it shouldn't (proving
/// the windows are genuinely independent) or the "old success" row's purge would also destroy it.
#[tokio::test]
async fn webhook_execution_retention_purges_each_outcome_on_its_own_window() {
    use simply_ip_vault::retention::{
        purge_expired_webhook_executions, DEFAULT_EXECUTION_RETENTION_FAILURE_HOURS,
        DEFAULT_EXECUTION_RETENTION_SUCCESS_HOURS,
    };
    use simply_ip_vault::entities::{webhook_config, webhook_execution};

    let db = setup_test_db().await;
    let group_id = insert_group(&db, "exec-retention-group").await;

    let webhook_id = Uuid::new_v4();
    webhook_config::ActiveModel {
        id: Set(webhook_id),
        name: Set("retention-test-hook".to_owned()),
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

    let age_hours = |hours: i64| (chrono::Utc::now() - chrono::Duration::hours(hours)).naive_utc();
    let insert_execution = |is_success: bool, hours_old: i64| {
        let db = db.clone();
        async move {
            let id = Uuid::new_v4();
            webhook_execution::ActiveModel {
                id: Set(id),
                webhook_id: Set(webhook_id),
                event_type: Set("TEST".to_owned()),
                status_code: Set(Some(if is_success { 200 } else { 500 })),
                is_success: Set(is_success),
                duration_ms: Set(10),
                response_body: Set(None),
                resolved_target_url: Set(None),
                target_address: Set(None),
                cause: Set(None),
                created_at: Set(age_hours(hours_old)),
            }
            .insert(&db)
            .await
            .unwrap();
            id
        }
    };

    let old_success = insert_execution(true, DEFAULT_EXECUTION_RETENTION_SUCCESS_HOURS + 1).await;
    let recent_success = insert_execution(true, DEFAULT_EXECUTION_RETENTION_SUCCESS_HOURS - 1).await;
    // Older than the success window, but well inside the (much longer) failure window — must
    // survive, proving the two thresholds are genuinely independent rather than one shared minimum.
    let old_failure_recent_by_its_own_window =
        insert_execution(false, DEFAULT_EXECUTION_RETENTION_SUCCESS_HOURS + 1).await;
    let expired_failure = insert_execution(false, DEFAULT_EXECUTION_RETENTION_FAILURE_HOURS + 1).await;

    let purged = purge_expired_webhook_executions(
        &db,
        DEFAULT_EXECUTION_RETENTION_SUCCESS_HOURS,
        DEFAULT_EXECUTION_RETENTION_FAILURE_HOURS,
    )
    .await
    .unwrap();
    assert_eq!(purged, 2, "the one aged-out success and the one aged-out failure, nothing else");

    let exists = |id: Uuid| {
        let db = db.clone();
        async move { webhook_execution::Entity::find_by_id(id).one(&db).await.unwrap().is_some() }
    };
    assert!(!exists(old_success).await, "a success past its 24h window is purged");
    assert!(exists(recent_success).await, "a success inside its window is kept");
    assert!(
        exists(old_failure_recent_by_its_own_window).await,
        "a failure past the *success* window but inside its own 7-day window must survive — the \
         two outcomes do not share a threshold"
    );
    assert!(!exists(expired_failure).await, "a failure past its 7-day window is purged");

    // Each threshold disables independently at 0, mirroring `purge_expired_ip_records`'s contract.
    assert_eq!(purge_expired_webhook_executions(&db, 0, 0).await.unwrap(), 0);
    assert!(exists(recent_success).await, "nothing was destroyed by the fully-disabled sweep");
    assert!(
        exists(old_failure_recent_by_its_own_window).await,
        "nothing was destroyed by the fully-disabled sweep"
    );
}

/// The master-only purge endpoint runs the same sweep and reports what it removed.
#[tokio::test]
async fn purge_endpoint_reports_the_number_of_records_removed() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let master = insert_master_key(&db, "Purger").await;
    let secret = test_signing_secret(&master);
    let group_id = insert_group(&db, "endpoint-purge-group").await;
    let old = insert_ip_record(&db, "203.0.113.50", group_id).await;

    let record = raw_record(&db, old).await.unwrap();
    let mut active: simply_ip_vault::entities::ip_record::ActiveModel = record.into();
    active.is_deleted = Set(true);
    active.deleted_at = Set(Some((chrono::Utc::now() - chrono::Duration::days(200)).naive_utc()));
    active.update(&db).await.unwrap();

    // Some calls below repeat verbatim, so each takes its own timestamp — an identical repeat
    // inside one second is the same signature, which is exactly what a replay is.
    let tick = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));
    let purge = |body: &'static str| {
        let (app, master, secret, tick) =
            (app.clone(), master.clone(), secret.clone(), tick.clone());
        async move {
            let req = signed_later(
                inject_connect_info(
                    Request::builder()
                        .method("POST")
                        .uri("/api/system/purge-ips")
                        .header("X-API-Key", &master)
                        .header("Content-Type", "application/json"),
                ),
                &secret,
                tick.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                body,
            );
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            (status, String::from_utf8(bytes.to_vec()).unwrap())
        }
    };

    // `older_than_days: 0` would read as "purge everything" — rejected rather than obeyed, because
    // the destructive reading must never be what a typo selects.
    let (status, _) = purge(r#"{"older_than_days":0}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _) = purge(r#"{"older_than_days":-5}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(raw_record(&db, old).await.is_some(), "the rejected purges destroyed nothing");

    // An empty body uses the configured 92-day default.
    let (status, body) = purge("").await;
    assert_eq!(status, StatusCode::OK);
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["purged"], 1);
    assert_eq!(parsed["retention_days"], 92, "the default window is 92 days");
    assert!(raw_record(&db, old).await.is_none());

    // A second sweep finds nothing left.
    let (_, body) = purge("").await;
    let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(parsed["purged"], 0);
}

/// Re-banning a soft-deleted address must resurrect it rather than colliding with the unique
/// index. Otherwise an address someone deleted could never be banned again until a master emptied
/// the trash — a delete would be a denial of service on that address.
#[tokio::test]
async fn re_registering_a_soft_deleted_address_restores_it() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let master = insert_master_key(&db, "Rebanner").await;
    let secret = test_signing_secret(&master);
    let group_id = insert_group(&db, "reban-group").await;
    let record_id = insert_ip_record(&db, "203.0.113.77", group_id).await;

    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("DELETE")
                .uri(format!("/api/ips/{record_id}"))
                .header("X-API-Key", &master),
        ),
        &secret,
        "",
    );
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
    assert!(raw_record(&db, record_id).await.unwrap().is_deleted);

    // Ban the same address again.
    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/ban")
                .header("X-API-Key", &master)
                .header("Content-Type", "application/json"),
        ),
        &secret,
        &json!({
            "target_address": "203.0.113.77",
            "group_name": "reban-group",
            "cause": "seen again",
        })
        .to_string(),
    );
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK,
        "re-banning a soft-deleted address must succeed, not collide with the unique index"
    );

    let row = raw_record(&db, record_id).await.expect("the same row is reused");
    assert!(!row.is_deleted, "re-registration clears the deleted flag");
    assert!(row.deleted_at.is_none(), "...and the retention clock");
    assert!(row.deleted_by.is_none(), "...and the attribution");
    assert_eq!(row.cause.as_deref(), Some("seen again"), "the new cause was applied");
}

// ─────────────────────────────────────────────────────────────
// Convergence — anti-replay, pipeline ordering, full-URI signing, memory bounds
//
// These cover the arbitrated decisions of the cross-service convergence pass. Each one exists
// because the property it asserts is invisible in normal use and would regress silently.
// ─────────────────────────────────────────────────────────────

/// **Replay.** An intercepted, validly-signed request resent verbatim inside the freshness window
/// must be rejected.
///
/// This is the gap a timestamp check alone cannot close. The window bounds how *long* a captured
/// request stays usable; it says nothing about using it *twice*. Every field the signature covers —
/// method, target, timestamp, body — is unchanged in a replay, so the HMAC verifies perfectly and
/// the freshness check passes. Only a record of what has already been accepted can tell the two
/// apart.
///
/// The scenario is concrete rather than theoretical: `simply_ip_vault` is normally reached over
/// plain HTTP on a LAN, so an authentic `POST /api/ban` is readable by anything on the path, and
/// replaying it repeats the side effect for the next 300 seconds.
#[tokio::test]
async fn an_intercepted_signed_request_cannot_be_replayed_within_the_window() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (_id, master) = insert_key(&db, "Master", true, true, true, true, None).await;
    let secret = test_signing_secret(&master);

    // One authentic request, captured on the wire. Building it once and cloning the parts is the
    // point: the attacker resends the *same bytes*, not a re-signed equivalent.
    let timestamp = chrono::Utc::now().timestamp();
    let body = json!({ "target_address": "203.0.113.200", "group_name": "replay-group" }).to_string();
    let build = || {
        signed_at(
            inject_connect_info(
                Request::builder()
                    .method("POST")
                    .uri("/api/ban")
                    .header("X-API-Key", &master)
                    .header("Content-Type", "application/json"),
            ),
            &secret,
            timestamp,
            &body,
        )
    };

    assert_eq!(
        app.clone().oneshot(build()).await.unwrap().status(),
        StatusCode::OK,
        "the genuine request must succeed"
    );

    let res = app.clone().oneshot(build()).await.unwrap();
    assert_eq!(
        res.status(),
        StatusCode::UNAUTHORIZED,
        "a byte-identical resend inside the window is a replay and must be refused"
    );
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    let text = String::from_utf8(bytes.to_vec()).unwrap();
    assert!(
        text.contains("already been used"),
        "the rejection must name replay, not look like a signature failure: {text}"
    );

    // A third attempt is refused too — the guard is not a one-shot latch that clears itself.
    assert_eq!(
        app.clone().oneshot(build()).await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );

    // ...while a *freshly signed* request from the same key is unaffected, so the guard rejects
    // replays rather than simply breaking the key after one use.
    let fresh = signed_at(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/ban")
                .header("X-API-Key", &master)
                .header("Content-Type", "application/json"),
        ),
        &secret,
        timestamp + 1,
        &body,
    );
    assert_eq!(app.clone().oneshot(fresh).await.unwrap().status(), StatusCode::OK);
}

/// A replay of one key's request must not consume another key's identical signature, and vice
/// versa — the guard is keyed per API key, not globally.
#[tokio::test]
async fn replay_tracking_is_scoped_per_key() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    // Ordinary keys: replay tracking is keyed on identity, not on scope, and only one master may
    // exist per database (RBAC_MODEL.md §5). `GET /api/ips` answers `200` with an empty list for a
    // key holding no grants, which is all this test needs from it.
    let (_a, first) = insert_key(&db, "First", false, false, false, false, None).await;
    let (_b, second) = insert_key(&db, "Second", false, false, false, false, None).await;
    let timestamp = chrono::Utc::now().timestamp();

    for key in [&first, &second] {
        let req = signed_at(
            inject_connect_info(Request::builder().uri("/api/ips").header("X-API-Key", key)),
            &test_signing_secret(key),
            timestamp,
            "",
        );
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::OK,
            "each key's first use of its own signature must succeed"
        );
    }
}

/// **Auth before authz.** A caller that cannot prove possession of the signing secret must not be
/// able to tell "this key does not exist" from "this key exists but your address is not allowed".
///
/// If `bound_ips` were checked before the HMAC, the `403`-vs-`401` split would turn key guessing
/// into key *mapping*: an attacker could enumerate identifiers and learn which ones are real, and
/// even which networks they are pinned to, without ever holding a secret. Both shapes must return
/// `401` until the signature verifies.
#[tokio::test]
async fn an_unauthenticated_caller_cannot_distinguish_a_missing_key_from_a_blocked_address() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    // A key that genuinely exists, bound to a network the test connection is *not* in.
    let (_id, bound) =
        insert_key(&db, "Bound", true, true, true, true, Some("10.99.0.0/16")).await;

    let probe = |key: String, offset: i64| {
        let app = app.clone();
        async move {
            // Deliberately the *wrong* secret: this models an attacker holding (or guessing) an
            // identifier but not the secret behind it.
            let req = signed_later(
                inject_connect_info(Request::builder().uri("/api/auth/me").header("X-API-Key", &key)),
                "not-the-real-signing-secret",
                offset,
                "",
            );
            app.oneshot(req).await.unwrap().status()
        }
    };

    let nonexistent = probe("this-key-does-not-exist-at-all".to_owned(), 0).await;
    let real_but_out_of_range = probe(bound.clone(), 1).await;

    assert_eq!(nonexistent, StatusCode::UNAUTHORIZED);
    assert_eq!(
        real_but_out_of_range,
        StatusCode::UNAUTHORIZED,
        "a real key whose CIDR excludes the caller must also be 401 while the signature is unproven \
         — a 403 here would confirm the key exists"
    );
    assert_eq!(nonexistent, real_but_out_of_range, "the two must be indistinguishable");

    // ...and once the signature *does* verify, the CIDR check runs and reports 403, proving the
    // ordering is a deliberate sequence rather than the network check having been dropped.
    let authenticated = signed(
        inject_connect_info(Request::builder().uri("/api/auth/me").header("X-API-Key", &bound)),
        &test_signing_secret(&bound),
        "",
    );
    assert_eq!(
        app.clone().oneshot(authenticated).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "an authenticated caller outside its bound network gets 403"
    );
}

/// **Full-URI signing.** Rewriting the query string of an otherwise-valid signed request must
/// invalidate it.
///
/// The concrete attack: `?hard=true` turns a reversible soft delete into an irreversible purge, and
/// `?include_deleted=true` widens a listing to the trash view. While the query sat outside the
/// signed material, an on-path attacker who could not forge a signature could still rewrite a
/// captured request into either — no secret required.
#[tokio::test]
async fn tampering_with_the_query_string_invalidates_the_signature() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (_id, master) = insert_key(&db, "Master", true, true, true, true, None).await;
    let secret = test_signing_secret(&master);
    let group_id = insert_group(&db, "tamper-group").await;
    let record_id = insert_ip_record(&db, "198.51.100.77", group_id).await;
    let timestamp = chrono::Utc::now().timestamp();

    // Signed for the plain path...
    let honest = crypto::compute_signature(
        &secret,
        "DELETE",
        &format!("/api/ips/{record_id}"),
        &timestamp.to_string(),
        b"",
    )
    .expect("signing succeeds");

    // ...but sent with `?hard=true` bolted on, exactly as a proxy-level attacker would.
    let tampered = inject_connect_info(
        Request::builder()
            .method("DELETE")
            .uri(format!("/api/ips/{record_id}?hard=true"))
            .header("X-API-Key", &master)
            .header("X-Timestamp", timestamp.to_string())
            .header("X-Signature-256", &honest),
    )
    .body(Body::empty())
    .expect("request builds");

    assert_eq!(
        app.clone().oneshot(tampered).await.unwrap().status(),
        StatusCode::UNAUTHORIZED,
        "a query string appended after signing must break the signature"
    );
    assert!(
        raw_record(&db, record_id).await.is_some(),
        "the record must survive the rejected escalation"
    );

    // The honest request still works, so the rejection above is about the tampering and not about
    // the route being broken.
    let honest_req = inject_connect_info(
        Request::builder()
            .method("DELETE")
            .uri(format!("/api/ips/{record_id}"))
            .header("X-API-Key", &master)
            .header("X-Timestamp", timestamp.to_string())
            .header("X-Signature-256", &honest),
    )
    .body(Body::empty())
    .expect("request builds");
    assert_eq!(app.clone().oneshot(honest_req).await.unwrap().status(), StatusCode::OK);

    // Symmetrically: a signature computed *with* the query is not valid without it, so an attacker
    // cannot strip a parameter either.
    let with_query = crypto::compute_signature(
        &secret,
        "GET",
        "/api/ips?include_deleted=true",
        &timestamp.to_string(),
        b"",
    )
    .expect("signing succeeds");
    let stripped = inject_connect_info(
        Request::builder()
            .uri("/api/ips")
            .header("X-API-Key", &master)
            .header("X-Timestamp", timestamp.to_string())
            .header("X-Signature-256", &with_query),
    )
    .body(Body::empty())
    .expect("request builds");
    assert_eq!(
        app.clone().oneshot(stripped).await.unwrap().status(),
        StatusCode::UNAUTHORIZED,
        "removing a signed query parameter must also break the signature"
    );
}

/// A legitimate request that *carries* a query string still authenticates, so the change above did
/// not simply break every filtered read.
#[tokio::test]
async fn a_correctly_signed_query_string_authenticates() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (_id, master) = insert_key(&db, "Master", true, true, true, true, None).await;
    let secret = test_signing_secret(&master);

    for (offset, path) in [
        "/api/ips?limit=5",
        "/api/ips?groups=a,b&limit=10&offset=0",
        "/api/ips?include_deleted=true",
        "/api/ips?ip=203.0&cause=ssh",
    ]
    .iter()
    .enumerate()
    {
        let req = signed_later(
            inject_connect_info(Request::builder().uri(*path).header("X-API-Key", &master)),
            &secret,
            offset as i64,
            "",
        );
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::OK,
            "{path} signed over its full target must authenticate"
        );
    }
}

/// **Memory bound.** The router-wide limit and the middleware's signature buffer are the same
/// number, so no body size is accepted by one layer and refused by the other.
///
/// Asserted on the resolver rather than by pushing a payload through the stack: the property that
/// matters is that the two cannot drift, and a size-based test would pass just as well with two
/// independently-chosen values that happen to agree today.
///
/// This used to assert the literal `3 * 1024 * 1024`, which made it a test of *the number* rather
/// than of the invariant its own doc comment describes — so raising the default to 10 MiB for the
/// batch endpoint broke it while the invariant it was meant to protect was never in danger. It now
/// checks what it always claimed to.
#[test]
fn the_body_limit_and_the_signature_buffer_are_one_constant() {
    // Both layers call this one function: `create_app`'s `DefaultBodyLimit::max(...)` and
    // `auth_middleware`'s `to_bytes(body, ...)`. There is no second value to disagree with.
    let resolved = simply_ip_vault::config::max_body_bytes();

    assert_eq!(
        resolved,
        simply_ip_vault::MAX_REQUEST_BODY_BYTES,
        "with MAX_BODY_SIZE_MIB unset, the resolver must return the compiled-in default"
    );
    assert_eq!(
        simply_ip_vault::MAX_REQUEST_BODY_BYTES,
        simply_ip_vault::config::DEFAULT_MAX_BODY_MIB * 1024 * 1024,
        "the constant is the named default in bytes, not a second hand-written literal"
    );
    assert!(
        resolved >= 1024 * 1024,
        "the floor keeps a misconfiguration from rejecting ordinary payloads and presenting as a \
         broken API rather than as a bad setting"
    );
}

/// A body over the router-wide limit is refused before it can be buffered.
#[tokio::test]
async fn an_oversized_body_is_rejected_rather_than_buffered() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (_id, master) = insert_key(&db, "Master", true, true, true, true, None).await;
    let secret = test_signing_secret(&master);

    let oversized = "x".repeat(simply_ip_vault::MAX_REQUEST_BODY_BYTES + 1024);
    let req = signed(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/ban")
                .header("X-API-Key", &master)
                .header("Content-Type", "application/json"),
        ),
        &secret,
        &oversized,
    );

    let status = app.clone().oneshot(req).await.unwrap().status();
    assert!(
        status == StatusCode::PAYLOAD_TOO_LARGE || status == StatusCode::BAD_REQUEST,
        "an over-limit body must be refused, got {status}"
    );
}

/// **Pragma resilience.** `apply_sqlite_pragmas` must never be able to stop the service, whatever
/// the database says.
///
/// An in-memory database is the case that actually occurs — it reports `journal_mode=memory` and
/// declines WAL silently — and it is what the entire test suite runs on. A version of this function
/// that propagated the outcome would take down every deployment on a read-only mount or a
/// filesystem without shared-memory support, trading a real outage for a concurrency setting that
/// did not apply.
#[tokio::test]
async fn sqlite_pragma_failures_never_stop_the_service() {
    let db = setup_test_db().await;

    // Returns unit: there is no error channel to propagate, by construction. Calling it twice also
    // proves it is idempotent, since it runs before migrations on every boot.
    simply_ip_vault::db::apply_sqlite_pragmas(&db).await.expect("pragmas are never fatal");
    simply_ip_vault::db::apply_sqlite_pragmas(&db).await.expect("pragmas are never fatal");

    // The database is still fully usable afterwards.
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));
    let (_id, master) = insert_key(&db, "Master", true, true, true, true, None).await;
    let req = signed(
        inject_connect_info(Request::builder().uri("/api/ips").header("X-API-Key", &master)),
        &test_signing_secret(&master),
        "",
    );
    assert_eq!(app.clone().oneshot(req).await.unwrap().status(), StatusCode::OK);
}

/// **WAL actually engages, and persists.** The pragma resilience test above proves only that a
/// failure is survivable — and it runs on `sqlite::memory:`, where WAL legitimately *cannot* engage.
/// So on its own it would pass unchanged if `apply_sqlite_pragmas` stopped issuing the pragma
/// altogether, which is exactly the regression it looks like it is guarding against.
///
/// This one uses a real file, which is the only place the setting can take effect, and asserts the
/// two properties the production reasoning depends on:
///
/// 1. `journal_mode` is genuinely `wal` and `busy_timeout` is genuinely the configured value after
///    the call.
/// 2. **WAL survives reconnection.** It is recorded in the database file header rather than being
///    connection state, which is what makes applying it once at startup sufficient for every
///    connection the pool opens later — and for every subsequent run of the service. If that were
///    not true, a single pooled connection would be the only one benefiting and the whole
///    "apply once at boot" design would be wrong.
#[tokio::test]
async fn wal_engages_on_a_file_backed_database_and_survives_reconnection() {
    use sea_orm::{ConnectionTrait, Database, DatabaseBackend, Statement};

    async fn pragma<T>(db: &sea_orm::DatabaseConnection, sql: &str, column: &str) -> T
    where
        T: sea_orm::TryGetable,
    {
        db.query_one_raw(Statement::from_string(DatabaseBackend::Sqlite, sql.to_owned()))
            .await
            .expect("pragma query succeeds")
            .expect("pragma returns a row")
            .try_get::<T>("", column)
            .expect("pragma column has the expected type")
    }

    // `tempfile` rather than a fixed path: the suite runs tests in parallel, and two of them sharing
    // one database file would produce exactly the lock contention this pragma exists to avoid.
    let dir = tempfile::tempdir().expect("temp dir is creatable");
    let path = dir.path().join("wal_probe.db");
    let url = format!("sqlite://{}?mode=rwc", path.display());

    let db = Database::connect(&url).await.expect("file-backed sqlite opens");
    simply_ip_vault::db::apply_sqlite_pragmas(&db).await.expect("pragmas are never fatal");

    let mode: String = pragma(&db, "PRAGMA journal_mode;", "journal_mode").await;
    assert_eq!(
        mode.to_ascii_lowercase(),
        "wal",
        "WAL must be in force on a file-backed database, got {mode:?}"
    );

    let timeout: i32 = pragma(&db, "PRAGMA busy_timeout;", "timeout").await;
    assert_eq!(
        timeout,
        simply_ip_vault::db::SQLITE_BUSY_TIMEOUT_MS as i32,
        "the busy timeout must be the configured value"
    );

    // Migrations still run against the WAL database, so the setting is not merely reported but
    // actually usable for the writes the service performs at boot.
    simply_ip_vault::migration::Migrator::up(&db, None).await.expect("migrations run under WAL");

    // Reconnect with a completely fresh pool. Nothing re-applies the pragma here — if WAL were
    // connection state rather than file state, this would come back `delete`.
    drop(db);
    let reopened = Database::connect(&url).await.expect("file-backed sqlite reopens");
    let inherited: String = pragma(&reopened, "PRAGMA journal_mode;", "journal_mode").await;
    assert_eq!(
        inherited.to_ascii_lowercase(),
        "wal",
        "WAL is written to the file header and must survive reconnection, got {inherited:?}"
    );

    drop(reopened);
}

/// **Stored secrets are opened strictly, or not at all.** A value carrying no recognized prefix is a
/// `MalformedCiphertext` error, never a bare secret handed back verbatim.
///
/// The removed fallback looked like backward compatibility and behaved like a silent failure. "No
/// recognized prefix" is not evidence of a pre-prefix row; it is evidence of nothing, and the other
/// causes are all worse. A `v1.plain.` value whose prefix was lost to a botched migration or a
/// truncated column would have had its surviving hex text used as HMAC key material — turning a
/// damaged row into a fleet of `401`s that point at the client instead of at the database.
#[test]
fn a_stored_secret_without_a_recognized_prefix_is_refused() {
    use simply_ip_vault::crypto::{CryptoError, SecretCipher};

    let key = "00".repeat(32);
    for cipher in [
        SecretCipher::Plaintext,
        SecretCipher::from_hex_key(&key).expect("a 64-hex key is valid"),
    ] {
        for unprefixed in [
            "signing-secret-for-legacy-key",       // the shape the old fallback accepted
            "",                                    // an empty column
            "deadbeef",                            // bare hex, indistinguishable from a stripped body
            "v1.plain",                            // the prefix, truncated just short of its dot
            "v1.xchacha20poly1305",                // likewise
            "V1.PLAIN.6162",                       // prefixes are matched exactly, not case-folded
            // The retired AES-GCM shape, spelled exactly as the old writer produced it: a 12-byte
            // hex nonce followed by hex ciphertext‖tag. Reinstating the read path would make this
            // value open again, which is the regression this entry exists to catch.
            "aesgcm256:000102030405060708090a0b1122334455667788990011223344556677",
            "aesgcm256",                           // and the bare prefix
        ] {
            assert!(
                matches!(cipher.open(unprefixed), Err(CryptoError::MalformedCiphertext)),
                "{unprefixed:?} must be refused rather than returned as a signing secret"
            );
        }

        // ...while a correctly-prefixed value still round-trips, so the loop above is not passing
        // simply because `open` rejects everything.
        let sealed = cipher.seal("real-secret").expect("sealing succeeds");
        assert_eq!(cipher.open(&sealed).expect("opening succeeds"), "real-secret");
    }
}

/// The end-to-end consequence of the rule above: a key whose stored secret is unreadable cannot
/// authenticate, and fails as an operator problem (`500`) rather than as a caller problem (`401`).
///
/// The distinction matters operationally. `401` tells an operator to go and look at the client, which
/// is the one place the fault is not. `500` plus the row's prefix in the log points at the database.
#[tokio::test]
async fn a_key_whose_stored_secret_is_unreadable_cannot_authenticate() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (id, plaintext) = insert_key(&db, "Damaged", true, true, true, true, None).await;

    // Simulate a row whose storage prefix was lost — a truncated column, a bad restore, a migration
    // that rewrote the value without re-sealing it.
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(id),
        signing_secret: Set(Some(test_signing_secret(&plaintext))),
        ..Default::default()
    }
    .update(&db)
    .await
    .expect("row updates");

    let req = signed(
        inject_connect_info(Request::builder().uri("/api/ips").header("X-API-Key", &plaintext)),
        &test_signing_secret(&plaintext),
        "",
    );
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::INTERNAL_SERVER_ERROR,
        "an unreadable stored secret is an operator fault, not a failed authentication attempt"
    );
}

/// **Cipher fail-closed.** A malformed encryption key must abort startup rather than silently
/// downgrading to storing signing secrets in the clear.
///
/// The old behaviour accepted any string and SHA-256'd it, so `VAULT_ENCRYPTION_KEY=password`
/// produced a 32-byte key with the entropy of "password" and no signal that anything was wrong.
/// Refusing is the only honest option: an operator who set the variable believes their secrets are
/// encrypted.
#[test]
fn a_malformed_encryption_key_fails_closed_instead_of_degrading() {
    use simply_ip_vault::crypto::{CryptoError, SecretCipher};

    for bad in ["password", "", "deadbeef", "not hex at all", &"00".repeat(31), &"00".repeat(33)] {
        assert!(
            matches!(SecretCipher::from_hex_key(bad), Err(CryptoError::InvalidKey)),
            "{bad:?} must be refused, never accepted as key material"
        );
    }

    // A real key is accepted and actually encrypts.
    let good = SecretCipher::from_hex_key(&"ab".repeat(32)).expect("64 hex characters are valid");
    assert!(good.is_encrypting());
    let sealed = good.seal("round-trip").expect("sealing succeeds");
    assert!(sealed.starts_with("v1.xchacha20poly1305."), "got {sealed}");
    assert!(!sealed.contains("round-trip"), "the plaintext must not survive");
    assert_eq!(good.open(&sealed).expect("opening succeeds"), "round-trip");
}

// ═════════════════════════════════════════════════════════════
// Master key pinning — identity, not just uniqueness
// ═════════════════════════════════════════════════════════════

/// The attack §5's uniqueness constraint cannot see: **swap** the master rather than add one.
///
/// The derived `master_marker` guarantees at most one row carries `is_master`. An attacker with
/// database access does not need two. Demoting the legitimate master and promoting itself leaves the
/// count at exactly one, the unique index perfectly satisfied, and — before the key was pinned at
/// startup — the attacker holding every master-only power in the service.
///
/// No index is dropped here and no constraint is violated. That is the point: this sequence is
/// available on a fully compliant §5 database, which is why uniqueness and identity have to be
/// defended separately.
#[tokio::test]
async fn attack_promoting_a_key_in_a_live_database_does_not_make_it_master() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state.clone());

    let real_master = insert_master_key(&db, "The Master").await;
    let (impostor_id, impostor) =
        insert_key(&db, "Impostor", false, false, false, false, None).await;

    // Boot: the service pins the master before serving anything. `main.rs` does this explicitly;
    // here it is the same call, and it is what makes everything below a no-op for the attacker.
    let pinned = state.master_pin.pin_at_boot(&state.db).await.expect("exactly one master exists at boot");

    // The attacker, holding a database prompt, performs the swap.
    let demote: simply_ip_vault::entities::api_key::ActiveModel =
        simply_ip_vault::entities::prelude::ApiKey::find()
            .filter(simply_ip_vault::entities::api_key::Column::Id.eq(pinned))
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .into();
    let mut demote = demote;
    demote.is_master = Set(false);
    demote.update(&db).await.unwrap();

    let promote: simply_ip_vault::entities::api_key::ActiveModel =
        simply_ip_vault::entities::prelude::ApiKey::find_by_id(impostor_id)
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .into();
    let mut promote = promote;
    promote.is_master = Set(true);
    promote.update(&db).await.unwrap();

    // The database now says the impostor is master, and says so legally — one master, marker derived,
    // index satisfied. Confirmed rather than assumed, because if this write had failed the rest of
    // the test would pass for the wrong reason.
    let row = simply_ip_vault::entities::prelude::ApiKey::find_by_id(impostor_id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert!(row.is_master, "the premise: the database really does call the impostor master");

    // The service does not. `/auth/me` reports what the request actually carries, and the impostor
    // arrives demoted.
    let req = signed(
        inject_connect_info(Request::builder().uri("/api/auth/me").header("X-API-Key", &impostor)),
        &test_signing_secret(&impostor),
        "",
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK, "the impostor is still a valid key");
    let body: serde_json::Value = serde_json::from_slice(
        &axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap(),
    )
    .unwrap();
    assert_eq!(
        body["is_master"],
        serde_json::json!(false),
        "a key promoted after boot must not be reported as master: {body}"
    );

    // And master-only authority is genuinely absent, not merely mislabelled. The audit log is
    // master-only, so a 403 here is the whole guarantee in one status code.
    let req = signed_later(
        inject_connect_info(Request::builder().uri("/api/audit-logs").header("X-API-Key", &impostor)),
        &test_signing_secret(&impostor),
        1,
        "",
    );
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "the impostor must not reach a master-only endpoint"
    );

    // The pin is immovable for the life of the process, even though the row it names no longer
    // claims to be master. Re-resolving would hand the attacker exactly what pinning denies.
    assert_eq!(
        state.master_pin.pin_at_boot(&state.db).await.unwrap(),
        pinned,
        "the pin must not move once set"
    );

    // The real master is now demoted in the database, so it is not master either — the conjunction
    // cuts both ways, and neither key inherits the authority.
    let req = signed_later(
        inject_connect_info(Request::builder().uri("/api/audit-logs").header("X-API-Key", &real_master)),
        &test_signing_secret(&real_master),
        2,
        "",
    );
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "a demoted master is not master either; is_master AND pinned-id, both required"
    );
}

/// Startup refuses a database holding more than one master, rather than picking one.
///
/// Only reachable if the §5 uniqueness index was dropped, which is why the index is dropped here.
/// The service cannot know which of the two rows an operator intended, and choosing by row order
/// would make the most powerful credential in the system a function of physical layout.
#[tokio::test]
async fn startup_refuses_to_pin_a_master_when_the_database_holds_two() {
    use sea_orm::ConnectionTrait;

    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());

    let _first = insert_master_key(&db, "Master A").await;
    db.execute_unprepared("DROP INDEX \"idx-api_keys-master_marker\"").await.unwrap();
    let _second = insert_master_key(&db, "Master B").await;

    let err = state.master_pin.pin_at_boot(&state.db).await.expect_err("two masters must refuse to pin");
    let message = format!("{err}");
    assert!(
        message.contains("2 keys have is_master = true"),
        "the refusal must say how many and which: {message}"
    );
    assert!(
        message.contains("RBAC_MODEL.md §5"),
        "the refusal must name the rule it is enforcing: {message}"
    );

    // Fail closed while unpinned: no caller is master, rather than every caller being one.
    assert_eq!(state.master_pin.resolve(&state.db).await, None);
}

/// Startup refuses a database with no master at all.
///
/// Distinct from the two-master case and reported separately, because the remedies have nothing in
/// common: this one means the bootstrap never ran or the row was deleted, and starting anyway would
/// leave every master-only operation permanently unreachable with no way to recover through the API.
#[tokio::test]
async fn startup_refuses_to_pin_a_master_when_the_database_holds_none() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());

    let _ordinary = insert_key(&db, "Just a key", false, true, false, false, None).await;

    let err = state.master_pin.pin_at_boot(&state.db).await.expect_err("no master must refuse to pin");
    assert!(
        format!("{err}").contains("No master key exists"),
        "the refusal must distinguish 'none' from 'several': {err}"
    );
    assert_eq!(state.master_pin.resolve(&state.db).await, None);
}

/// Startup refuses when §5's uniqueness index is missing, even though exactly one master exists.
///
/// Checked *after* the master count. Two masters is only reachable once this index is gone, so
/// checking the index first made `MultipleMasters` unreportable — the operator would be told to
/// recreate an index while two masters sat in the table unmentioned. This case is what remains once
/// the count is unambiguous: one master today, and nothing stopping a second tomorrow.
#[tokio::test]
async fn startup_refuses_to_pin_a_master_without_the_uniqueness_index() {
    use sea_orm::ConnectionTrait;

    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());

    let _only = insert_master_key(&db, "The Master").await;
    db.execute_unprepared("DROP INDEX \"idx-api_keys-master_marker\"").await.unwrap();

    let err = state.master_pin.pin_at_boot(&state.db).await.expect_err("a missing index must refuse to pin");
    assert!(
        format!("{err}").contains("idx-api_keys-master_marker"),
        "the refusal must name the missing index: {err}"
    );
    assert_eq!(state.master_pin.resolve(&state.db).await, None);
}

/// R4 through the pin: a Parent key cannot grant a Master-only scope on create **or** update.
///
/// `guard_scope_elevation` short-circuits on `caller.is_master`, so its correctness now rests on the
/// caller's flag being trustworthy — which is exactly what the middleware's demotion provides. Both
/// verbs are covered because they are separate handlers reading separate payload types, and a fix
/// applied to one has been forgotten on the other before.
#[tokio::test]
async fn a_parent_key_cannot_grant_master_only_scopes_on_create_or_update() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let _master = insert_master_key(&db, "The Master").await;
    let (parent_id, parent) =
        insert_key(&db, "Parent", false, true, false, false, None).await;
    let (daughter_id, _daughter) =
        insert_key(&db, "Daughter", false, false, false, false, None).await;

    // Lineage matters, and its absence is what this test got wrong first time round. `insert_key`
    // leaves `parent_key_id` null, so the daughter sat outside the parent's subtree and `PUT` came
    // back 404 rather than 403 — correct §4 oracle discipline, and useless as evidence about R4. A
    // 404 would have proved only that the parent could not see the key. Making it a real daughter is
    // what puts the request in front of `guard_scope_elevation`.
    let mut adopt: simply_ip_vault::entities::api_key::ActiveModel =
        simply_ip_vault::entities::prelude::ApiKey::find_by_id(daughter_id)
            .one(&db)
            .await
            .unwrap()
            .unwrap()
            .into();
    adopt.parent_key_id = Set(Some(parent_id));
    adopt.update(&db).await.unwrap();

    let mut nonce = 0i64;
    for scope in ["can_manage_keys", "can_create_groups", "can_manage_webhooks"] {
        nonce += 1;
        let req = signed_later(
            inject_connect_info(Request::builder().method("POST").uri("/api/keys").header("X-API-Key", &parent))
                .header("Content-Type", "application/json"),
            &test_signing_secret(&parent),
            nonce,
            &json!({ "name": format!("escalated-via-{scope}"), scope: true }).to_string(),
        );
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::FORBIDDEN,
            "R4: a parent must not mint a key holding '{scope}'"
        );

        nonce += 1;
        let req = signed_later(
            inject_connect_info(Request::builder().method("PUT").uri(format!("/api/keys/{daughter_id}")).header("X-API-Key", &parent))
                .header("Content-Type", "application/json"),
            &test_signing_secret(&parent),
            nonce,
            &json!({ scope: true }).to_string(),
        );
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::FORBIDDEN,
            "R4: a parent must not grant '{scope}' to an existing key"
        );
    }

    // Nothing leaked through: the daughter is exactly as it was created.
    let after = simply_ip_vault::entities::prelude::ApiKey::find_by_id(daughter_id)
        .one(&db)
        .await
        .unwrap()
        .unwrap();
    assert!(!after.can_manage_keys && !after.can_create_groups && !after.can_manage_webhooks);
}


// ─────────────────────────────────────────────────────────────
// Liveness and readiness probes
// ─────────────────────────────────────────────────────────────
//
// These endpoints are the only two in the service that answer an *unauthenticated* caller, so every
// test below sends no `X-API-Key`, no `X-Timestamp`, and no `X-Signature-256`. That is the property
// under test, not an omission: a probe that needed a credential could not be called by Docker's
// `HEALTHCHECK` or a Kubernetes readiness gate, which is what these exist for.
//
// Note also that none of them calls `inject_connect_info`. Every authenticated test in this file
// must, because `auth_middleware` extracts `ConnectInfo` to resolve the client address — so a probe
// that succeeds *without* it is direct evidence the middleware never ran.

/// `GET /health` answers `200` with no credentials, no headers, and no connect-info extension.
#[tokio::test]
async fn health_check_answers_an_unauthenticated_caller() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db, webhook_tx, Vec::new()));

    let req = Request::builder().uri("/health").body(Body::empty()).unwrap();
    let res = app.oneshot(req).await.unwrap();

    assert_eq!(res.status(), StatusCode::OK, "liveness must not require a credential");

    let body = axum::body::to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ok");
    assert_eq!(json["service"], "simply_ip_vault");
    // No version string. It told an anonymous caller which build is deployed — the first thing
    // worth knowing before looking up what that build is vulnerable to — on a route designed to be
    // polled by machines. Asserted as *absent* so it cannot be reintroduced as a convenience.
    assert!(json.get("version").is_none(), "a public probe must not disclose the build: {json}");
    assert_eq!(
        json.as_object().map(serde_json::Map::len),
        Some(2),
        "the liveness body is exactly two constant fields; anything varying with runtime state \
         can leak it: {json}"
    );
}

/// `GET /health` does not depend on the database — the distinction that keeps a database outage
/// from becoming a crash loop.
///
/// An orchestrator restarts a container whose *liveness* probe fails. If liveness checked the
/// database, a service whose database had gone away would be killed and restarted repeatedly, each
/// new process failing the same probe — turning a recoverable dependency outage into an unbounded
/// restart loop while the service itself was fine. Readiness is where a dependency belongs, and the
/// test below asserts that half.
///
/// Closing the connection is the direct way to prove liveness is not consulting it.
#[tokio::test]
async fn health_check_still_answers_when_the_database_is_gone() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    db.close().await.expect("the connection closes");

    let req = Request::builder().uri("/health").body(Body::empty()).unwrap();
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::OK,
        "liveness must stay green while the database is unreachable, or a dependency outage \
         becomes a restart loop"
    );
}

/// `GET /ready` answers `200` without credentials once the master identity is pinned.
#[tokio::test]
async fn readiness_check_answers_an_unauthenticated_caller_when_the_service_can_serve() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state.clone());

    insert_master_key(&db, "The Master").await;
    state.master_pin.pin_at_boot(&state.db).await.expect("the master pins");

    let req = Request::builder().uri("/ready").body(Body::empty()).unwrap();
    let res = app.oneshot(req).await.unwrap();

    assert_eq!(res.status(), StatusCode::OK, "readiness must not require a credential");

    let body = axum::body::to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "ready");
    assert_eq!(json["database"], "up");
}

/// `GET /ready` answers `503` while no master identity is pinned.
///
/// Unreachable in production — `main.rs` pins before binding the listener — which is exactly why it
/// is worth asserting. That ordering is a convention held up by one line, and an edit that bound the
/// listener first would otherwise produce a service reporting itself ready while every master-only
/// route quietly refused. Here the state is built and never pinned, which is that regression.
#[tokio::test]
async fn readiness_check_refuses_while_no_master_is_pinned() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db, webhook_tx, Vec::new()));

    let req = Request::builder().uri("/ready").body(Body::empty()).unwrap();
    let res = app.oneshot(req).await.unwrap();

    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);

    let body = axum::body::to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(json["status"], "unavailable");
    // The body reports the *database* dimension only. An unpinned master leaves it "up" — honest,
    // and it does not tell an anonymous caller which internal check refused.
    assert_eq!(json["database"], "up");
    assert!(
        json.get("reason").is_none(),
        "a failing public probe must not name the check that failed: {json}"
    );
}

/// `GET /ready` answers `503` when the database is unreachable, and leaks nothing about why.
///
/// The response names *which* check failed and never the underlying error. A database URL, a file
/// path, or a driver message in the body of an endpoint that answers anonymous callers is an
/// information leak, and this endpoint is reachable by anyone who can open a socket.
#[tokio::test]
async fn readiness_check_refuses_when_the_database_is_unreachable_without_leaking_detail() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state);

    db.close().await.expect("the connection closes");

    let req = Request::builder().uri("/ready").body(Body::empty()).unwrap();
    let res = app.oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);

    let body = axum::body::to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let text = String::from_utf8(body.to_vec()).unwrap();
    assert!(text.contains("\"database\":\"down\""), "the database dimension is reported: {text}");
    assert!(
        !text.contains("sqlite") && !text.contains("Connection") && !text.contains("pool"),
        "the underlying error must stay in the log, not the response body: {text}"
    );
}

/// The probes are outside `auth_middleware`, and an authenticated route is inside it.
///
/// Asserted as a pair in one test on purpose. Either half alone is satisfiable by a mistake: a
/// service with no authentication at all would pass the first two assertions, and a service that
/// never mounted the probes would pass the third. Together they say the boundary is where it was
/// meant to be — and that a bogus credential changes nothing about a probe, since an endpoint that
/// merely *tolerated* a missing header might still branch on a present one.
#[tokio::test]
async fn the_probes_bypass_authentication_and_nothing_else_does() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state.clone());

    insert_master_key(&db, "The Master").await;
    state.master_pin.pin_at_boot(&state.db).await.expect("the master pins");

    // All four spellings, including the Kubernetes-idiomatic `z` aliases that mirror the peer.
    for path in ["/health", "/ready", "/healthz", "/readyz"] {
        let req = Request::builder()
            .uri(path)
            .header("X-API-Key", "not-a-real-key")
            .header("X-Timestamp", "0")
            .header("X-Signature-256", "sha256=deadbeef")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::OK,
            "{path} must ignore a forged credential rather than reject it — it never authenticates"
        );

        // And the alias is the same handler, not a stub that merely returns 200.
        let req = Request::builder().uri(path).body(Body::empty()).unwrap();
        let res = app.clone().oneshot(req).await.unwrap();
        let body = axum::body::to_bytes(res.into_body(), 64 * 1024).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let expected = if path.starts_with("/health") { "ok" } else { "ready" };
        assert_eq!(json["status"], expected, "{path} answers with the real handler's body");
    }

    let req = inject_connect_info(Request::builder().uri("/api/audit-logs"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::UNAUTHORIZED,
        "every other route still demands a signed request; the probes are the exception, not a hole"
    );
}

// ─────────────────────────────────────────────────────────────
// The pinned-master negative path
// ─────────────────────────────────────────────────────────────

/// **ADVERSARIAL(§5).** A key that is the sole, legitimate master in the database is still refused
/// when this process pinned a *different* identity.
///
/// The complement of `attack_promoting_a_key_in_a_live_database_does_not_make_it_master`, and it
/// isolates a property that test cannot. There, the attacker performs a swap and the pin is what the
/// service resolved for itself. Here the database is perfectly §5-compliant — exactly one master, the
/// index intact, nothing tampered with — and the *process* holds a pin from before. That is the state
/// after a restore rolls the database back to a moment when a different key was master, and it cannot
/// be constructed through `pin_at_boot`, which by definition only ever pins the row that really is
/// the sole master.
///
/// `MasterPin::pinned_to` exists for precisely this. Without it the only way to reach the state is to
/// drop the §5 index and write a second master row — which tests two failures at once and cannot
/// distinguish "the pin held" from "the missing index was noticed".
#[tokio::test]
async fn a_legitimate_master_is_refused_when_this_process_pinned_another_identity() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);

    let master = insert_master_key(&db, "The Master").await;

    // Pin an id that belongs to no row at all: the process booted against a different database
    // state, and nothing since has moved the pin.
    let stale_pin = Uuid::new_v4();
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new())
        .with_pinned_master(stale_pin);
    let app = create_app(state.clone());

    assert_eq!(state.master_pin.get(), Some(stale_pin), "the pin is fixed without a query");

    let req = signed_later(
        inject_connect_info(Request::builder().uri("/api/audit-logs").header("X-API-Key", &master)),
        &test_signing_secret(&master),
        1,
        "",
    );
    assert_eq!(
        app.clone().oneshot(req).await.unwrap().status(),
        StatusCode::FORBIDDEN,
        "is_master is authoritative only for the pinned id — a real master that this process did \
         not pin is an ordinary key"
    );

    // The pin did not move to accommodate the row it found, which is the whole guarantee.
    assert_eq!(
        state.master_pin.get(),
        Some(stale_pin),
        "resolving a request must never re-resolve the pin"
    );

    // And the demotion is a demotion, not a rejection: the key still authenticates and reaches
    // routes its own scopes allow. §5 makes master status a property of one key, not a credential.
    let req = signed_later(
        inject_connect_info(Request::builder().uri("/api/keys").header("X-API-Key", &master)),
        &test_signing_secret(&master),
        2,
        "",
    );
    assert_eq!(
        app.oneshot(req).await.unwrap().status(),
        StatusCode::OK,
        "the key is demoted, not revoked — it keeps every scope it legitimately holds"
    );
}


// ─────────────────────────────────────────────────────────────
// include_deleted: scoped, not master-gated
// ─────────────────────────────────────────────────────────────
//
// `?include_deleted=true` used to be refused to every non-master. That gate bought nothing — the
// group-scoping filter already confines a non-master to the groups it holds `can_read` on — while
// making the trash view unusable by the delta-sync consumers that need it: a replica which cannot
// see deletions diverges from its source silently and never recovers.
//
// The flag is now open to everyone and the *rows* are what remain scoped. These tests pin that the
// scoping is real, that widening the flag did not widen anything else, and that the §4 oracle is
// still closed.

/// A scoped key sees soft-deleted records **in its own readable group**, and nothing from elsewhere.
///
/// The two halves are asserted in one test on purpose. Either alone is satisfiable by a mistake: a
/// service that ignored `include_deleted` entirely would pass the second, and one that ignored group
/// scoping would pass the first.
#[tokio::test]
async fn include_deleted_is_scoped_to_readable_groups_for_a_non_master() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let master = insert_master_key(&db, "Master").await;
    let (reader_id, reader) = insert_key(&db, "Reader", false, false, false, false, None).await;

    let mine = insert_group(&db, "mine").await;
    let theirs = insert_group(&db, "theirs").await;
    let my_record = insert_ip_record(&db, "198.51.100.61", mine).await;
    let their_record = insert_ip_record(&db, "198.51.100.62", theirs).await;

    // Read *and* delete on my group; nothing at all on the other one.
    grant(&db, reader_id, mine, true, false, true).await;

    let tick = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));
    let call = |api_key: String, method: &'static str, path: String| {
        let (app, tick) = (app.clone(), tick.clone());
        async move {
            let secret = test_signing_secret(&api_key);
            let req = signed_later(
                inject_connect_info(
                    Request::builder().method(method).uri(&path).header("X-API-Key", &api_key),
                ),
                &secret,
                tick.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                "",
            );
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            (status, String::from_utf8(bytes.to_vec()).unwrap())
        }
    };

    // The master soft-deletes the record in the other group, so there is something to leak.
    let (status, _) = call(master.clone(), "DELETE", format!("/api/ips/{their_record}")).await;
    assert_eq!(status, StatusCode::OK);
    // The reader soft-deletes its own.
    let (status, _) = call(reader.clone(), "DELETE", format!("/api/ips/{my_record}")).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = call(reader.clone(), "GET", "/api/ips?include_deleted=true".to_owned()).await;
    assert_eq!(status, StatusCode::OK, "a can_read key may ask for the trash");
    assert!(
        body.contains("198.51.100.61"),
        "a scoped key must see soft-deleted records in a group it can read: {body}"
    );
    assert!(
        !body.contains("198.51.100.62"),
        "a soft-deleted record in an unreadable group must stay invisible — widening the flag must \
         not widen the scope: {body}"
    );

    // And the default listing still hides its own deleted row, so the flag is what did the work.
    let (_, body) = call(reader, "GET", "/api/ips".to_owned()).await;
    assert!(!body.contains("198.51.100.61"), "the default listing still hides the trash: {body}");
}

/// `deleted_by` is Master-only, and widening `include_deleted` did not smuggle it out.
///
/// The column holds a raw key id. `RBAC_MODEL.md` §4 limits what one key may learn about another to
/// id, name and rights *on a shared resource*; nothing entitles a group reader to the identity of an
/// unrelated key. This is the field most likely to leak as a side effect of the change above, so it
/// gets its own test rather than an assertion tacked onto one.
#[tokio::test]
async fn deleted_by_is_visible_to_master_and_withheld_from_everyone_else() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let master = insert_master_key(&db, "Master").await;
    let (reader_id, reader) = insert_key(&db, "Reader", false, false, false, false, None).await;
    let group = insert_group(&db, "shared").await;
    let record = insert_ip_record(&db, "198.51.100.63", group).await;
    grant(&db, reader_id, group, true, false, true).await;

    let tick = std::sync::Arc::new(std::sync::atomic::AtomicI64::new(0));
    let call = |api_key: String, method: &'static str, path: String| {
        let (app, tick) = (app.clone(), tick.clone());
        async move {
            let secret = test_signing_secret(&api_key);
            let req = signed_later(
                inject_connect_info(
                    Request::builder().method(method).uri(&path).header("X-API-Key", &api_key),
                ),
                &secret,
                tick.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
                "",
            );
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            (status, String::from_utf8(bytes.to_vec()).unwrap())
        }
    };

    let (status, _) = call(reader.clone(), "DELETE", format!("/api/ips/{record}")).await;
    assert_eq!(status, StatusCode::OK);

    let (_, seen_by_reader) = call(reader, "GET", "/api/ips?include_deleted=true".to_owned()).await;
    assert!(seen_by_reader.contains("198.51.100.63"), "the record is in scope: {seen_by_reader}");
    assert!(
        !seen_by_reader.contains("deleted_by"),
        "a non-master must not learn which key performed the deletion: {seen_by_reader}"
    );
    // The control: the field is genuinely populated, so its absence above is suppression rather
    // than there being nothing to suppress.
    let (_, seen_by_master) =
        call(master, "GET", "/api/ips?include_deleted=true".to_owned()).await;
    assert!(
        seen_by_master.contains("deleted_by"),
        "master must still see the attribution: {seen_by_master}"
    );
}

/// Naming an unreadable group is not an error — §4 oracle discipline.
///
/// Refusing here would tell an unauthorised caller that the group exists, which is exactly the
/// distinction §4 forbids: an out-of-scope name must be indistinguishable from one that names
/// nothing at all.
#[tokio::test]
async fn requesting_an_unreadable_group_is_indistinguishable_from_requesting_a_nonexistent_one() {
    let db = setup_test_db().await;
    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let app = create_app(AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new()));

    let (reader_id, reader) = insert_key(&db, "Reader", false, false, false, false, None).await;
    let mine = insert_group(&db, "mine").await;
    let secret_group = insert_group(&db, "secret").await;
    insert_ip_record(&db, "198.51.100.64", secret_group).await;
    grant(&db, reader_id, mine, true, false, false).await;

    let call = |path: String, offset: i64| {
        let (app, reader) = (app.clone(), reader.clone());
        async move {
            let secret = test_signing_secret(&reader);
            let req = signed_later(
                inject_connect_info(
                    Request::builder().uri(&path).header("X-API-Key", &reader),
                ),
                &secret,
                offset,
                "",
            );
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            (status, String::from_utf8(bytes.to_vec()).unwrap())
        }
    };

    let (existing_status, existing_body) =
        call("/api/ips?include_deleted=true&groups=secret".to_owned(), 1).await;
    let (absent_status, absent_body) =
        call("/api/ips?include_deleted=true&groups=no-such-group-anywhere".to_owned(), 2).await;

    assert_eq!(
        (existing_status, existing_body.as_str()),
        (absent_status, absent_body.as_str()),
        "a group the caller cannot read must answer byte-identically to one that does not exist"
    );
    assert!(!existing_body.contains("198.51.100.64"), "and it leaks no rows: {existing_body}");
}


// ─────────────────────────────────────────────────────────────
// Backpressure and concurrency
// ─────────────────────────────────────────────────────────────

/// **A saturated webhook queue drops events; it never blocks the request that produced one.**
///
/// # The failure this exists to prevent
///
/// Handlers used to `webhook_tx.send(event).await`. That is harmless while the dispatcher drains as
/// fast as events arrive — and stopped being harmless when dispatch became throttled. At the default
/// pace four workers handle eighty events per second between them, so a large enough bulk operation
/// can still fill the queue faster than that, and every subsequent `send().await` parks the Axum
/// handler until a slot frees. A firewall API that stops answering because a *notification* queue
/// backed up has its priorities inverted: the ban is the product, the webhook is a courtesy.
///
/// # Why a tiny channel instead of 4 096 real events
///
/// The production capacity comes from `WEBHOOK_QUEUE_CAPACITY` through a `OnceLock`, so it is fixed
/// for the process and cannot be varied per test. Generating 4 096 genuine events would also mean
/// 4 096 signed HTTP round trips — minutes of runtime to demonstrate a property that is about the
/// channel, not about volume.
///
/// So the state is built with a **deliberately tiny channel whose receiver is dropped immediately**.
/// That is a strictly harsher condition than saturation: capacity 1 with no consumer at all. If
/// `enqueue_webhook` can block, it blocks here.
///
/// The whole test is wrapped in a timeout, because the failure mode is a *hang* rather than a wrong
/// answer — and an assertion cannot catch a future that never returns.
#[tokio::test]
async fn test_webhook_queue_overflow_non_blocking() {
    let db = setup_test_db().await;

    // Capacity 1, and the receiver is dropped on the next line: every send after the first faces a
    // full-or-closed channel.
    let (webhook_tx, webhook_rx) = tokio::sync::mpsc::channel(1);
    drop(webhook_rx);

    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = create_app(state.clone());

    let master = insert_master_key(&db, "Flood Master").await;
    let secret = test_signing_secret(&master);
    let group_id = insert_group(&db, "flood-group").await;

    // Enqueue far past capacity directly. `enqueue_webhook` is the function under test; going
    // through handlers would measure HTTP overhead instead of the queue's behaviour.
    let flood = tokio::time::timeout(std::time::Duration::from_secs(5), async {
        for i in 0..2_000 {
            state.enqueue_webhook(simply_ip_vault::state::WebhookEvent {
                action: "IP_ADD".to_owned(),
                address: format!("198.51.100.{}", i % 250),
                is_whitelist: false,
                group_id: Some(group_id),
                group_name: None,
                cause: None,
            });
        }
    })
    .await;
    assert!(
        flood.is_ok(),
        "enqueueing 2 000 events into a capacity-1 channel with no consumer must not block — if \
         this times out, `enqueue_webhook` is awaiting a slot and a bulk operation can stall the API"
    );

    // And the service still answers. The point is not that one request works in isolation but that
    // the flood left nothing wedged: the same state, the same process, immediately afterwards.
    let started = std::time::Instant::now();
    let req = signed_later(
        inject_connect_info(
            Request::builder().uri("/api/ips").header("X-API-Key", &master),
        ),
        &secret,
        1,
        "",
    );
    let res = tokio::time::timeout(std::time::Duration::from_secs(5), app.clone().oneshot(req))
        .await
        .expect("the API must answer after a queue flood, not hang")
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "an authenticated read still succeeds");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "and promptly: {:?}",
        started.elapsed()
    );

    // A write path, which is what actually enqueues, is equally unaffected.
    let body = json!({ "target_address": "203.0.113.200", "group_name": "flood-group" }).to_string();
    let req = signed_later(
        inject_connect_info(
            Request::builder()
                .method("POST")
                .uri("/api/ban")
                .header("X-API-Key", &master)
                .header("Content-Type", "application/json"),
        ),
        &secret,
        2,
        &body,
    );
    let res = tokio::time::timeout(std::time::Duration::from_secs(5), app.oneshot(req))
        .await
        .expect("a write that enqueues a webhook must not block on the queue")
        .unwrap();
    assert_eq!(
        res.status(),
        StatusCode::OK,
        "the ban is recorded even though its notification could not be queued — dropping the \
         courtesy is correct, failing the product is not"
    );

    // The ban really landed, so the dropped notification cost nothing but the notification.
    let stored = simply_ip_vault::entities::ip_record::Entity::find()
        .filter(
            simply_ip_vault::entities::ip_record::Column::TargetAddress.eq("203.0.113.200"),
        )
        .one(&db)
        .await
        .unwrap();
    assert!(stored.is_some(), "the record was written despite the webhook being dropped");
}

/// Concurrent batch writes all succeed, with no `SQLITE_BUSY`, corruption, or lost rows.
///
/// # What this actually demonstrates
///
/// Not WAL reader/writer concurrency. `SQLITE_MEMORY_MAX_CONNECTIONS` is **1** — SQLite permits a single
/// writer, and a DDL sequence spread across connections does not survive — so these transactions do
/// not race inside SQLite at all: they queue on the pool and execute one at a time. That is the
/// design, not a limitation being worked around.
///
/// What it demonstrates is that the queueing is *correct and bounded*: every task completes, none
/// returns `SQLITE_BUSY` or a lock error, and the final row count is exactly the union of what the
/// tasks wrote. A serialisation bug would show up here as a failed request or a missing row, and
/// `db::SQLITE_BUSY_TIMEOUT_MS` is what keeps a queued writer waiting rather than erroring.
///
/// The tasks write **overlapping** address ranges deliberately. Disjoint sets would exercise only
/// insertion; the overlap forces the same rows to be contended, which is where a lost update or a
/// double insert on a UNIQUE column would surface.
#[tokio::test]
async fn test_concurrent_batch_writes_under_wal() {
    use std::sync::Arc;

    const TASKS: usize = 8;
    const PER_TASK: usize = 60;
    /// Each task starts 30 addresses into the previous one's range, so half of every batch collides.
    const STRIDE: usize = 30;

    // File-backed through `db::connect`: the in-memory fixture the rest of this suite uses has no
    // WAL and no busy_timeout, so it would not exercise the pool this test is about.
    let dir = std::env::temp_dir().join(format!("vault_conc_{}", Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let url = format!("sqlite://{}", dir.join("v.db").display());
    simply_ip_vault::db::run_migrations_isolated(&url)
        .await
        .expect("migrations apply on the isolated pool");
    let db = simply_ip_vault::db::connect(&url).await.expect("file-backed pool opens");

    let (webhook_tx, _rx) = tokio::sync::mpsc::channel(100);
    let state = AppState::with_trusted_proxies(db.clone(), webhook_tx, Vec::new());
    let app = Arc::new(create_app(state.clone()));
    let master = insert_master_key(&db, "Concurrency Master").await;
    state.master_pin.pin_at_boot(&db).await.expect("master pins");

    let mut tasks = tokio::task::JoinSet::new();
    for task in 0..TASKS {
        let app = app.clone();
        let master = master.clone();
        tasks.spawn(async move {
            let records: Vec<serde_json::Value> = (0..PER_TASK)
                .map(|i| {
                    let n = task * STRIDE + i;
                    json!({
                        "target_address": format!("198.51.{}.{}", 100 + (n / 250), 1 + (n % 250)),
                        "cause": format!("task {task}"),
                    })
                })
                .collect();
            let body = json!({ "group_name": "conc-group", "records": records }).to_string();
            let req = signed_later(
                inject_connect_info(
                    Request::builder()
                        .method("POST")
                        .uri("/api/records/batch")
                        .header("X-API-Key", &master)
                        .header("Content-Type", "application/json"),
                ),
                &test_signing_secret(&master),
                // A distinct timestamp per task: identical signed requests inside one second are
                // replays, which the anti-replay guard would reject for the right reason and make
                // this test fail for the wrong one.
                task as i64 + 1,
                &body,
            );
            let res = (*app).clone().oneshot(req).await.unwrap();
            let status = res.status();
            let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
            (task, status, String::from_utf8(bytes.to_vec()).unwrap())
        });
    }

    let mut completed = 0;
    while let Some(joined) = tasks.join_next().await {
        let (task, status, body) = joined.expect("no task may panic — a poisoned lock or an \
                                                 unhandled DB error would surface here");
        assert_eq!(
            status,
            StatusCode::OK,
            "task {task} failed with {status}: {body}\n\
             SQLITE_BUSY or a lock error here means a queued writer gave up instead of waiting; \
             busy_timeout is what prevents that"
        );
        // Matched against the specific engine messages, not on the bare word "locked" — the success
        // body carries a `locked_skipped` counter, and a substring check for "locked" flagged every
        // healthy response. Naming the actual error strings is both narrower and clearer about what
        // is being excluded.
        let lowered = body.to_lowercase();
        for signal in ["database is locked", "sqlite_busy", "database table is locked"] {
            assert!(
                !lowered.contains(signal),
                "task {task} reported {signal:?}: {body}"
            );
        }
        assert!(
            !body.contains("\"error\""),
            "task {task} returned an error payload: {body}"
        );
        completed += 1;
    }
    assert_eq!(completed, TASKS, "every concurrent batch completed");

    // The union of eight overlapping ranges, counted exactly. A lost update would leave this short;
    // a double insert would have violated the UNIQUE constraint and failed a task above.
    let expected = (TASKS - 1) * STRIDE + PER_TASK;
    let stored = simply_ip_vault::entities::ip_record::Entity::find().all(&db).await.unwrap();
    assert_eq!(
        stored.len(),
        expected,
        "expected the exact union of the overlapping ranges ({expected} rows), found {}",
        stored.len()
    );
    assert!(
        stored.iter().all(|r| !r.is_deleted && !r.target_address.is_empty()),
        "every row is intact — no partially written or corrupted record"
    );

    // The service is still healthy afterwards, so nothing was left holding the pool.
    let res = (*app).clone()
        .oneshot(Request::builder().uri("/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(res.status(), StatusCode::OK, "readiness survives concurrent write pressure");

    let _ = std::fs::remove_dir_all(&dir);
}
