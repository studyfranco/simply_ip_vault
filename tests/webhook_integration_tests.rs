//! Webhook dispatch isolation: a mutation in one group must never produce a dispatch event for
//! another group, even when the same address is a member of both.
//!
//! These tests inspect the event stream the HTTP handlers hand to the dispatcher. That is the
//! boundary the group-scoping decision is made at: the dispatcher selects webhook configurations by
//! the event's `group_id`, so an event carrying the wrong group is the only way a receiver of
//! another group can be notified.

use axum::{body::Body, http::Request};
use sea_orm::{ActiveModelTrait, ActiveValue::Set, Database, DatabaseConnection, EntityTrait};
use sea_orm_migration::MigratorTrait;
use serde_json::json;
use tower::ServiceExt;
use uuid::Uuid;

use simply_ip_vault::{create_app, migration, state::{AppState, WebhookEvent}};

const MASTER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000002";

async fn setup() -> (DatabaseConnection, axum::Router, tokio::sync::mpsc::Receiver<WebhookEvent>) {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migration::Migrator::up(&db, None).await.unwrap();

    let secret = format!("signing-secret-for-{MASTER_KEY}");
    simply_ip_vault::entities::api_key::ActiveModel {
        id: Set(Uuid::new_v4()),
        key_hash: Set(simply_ip_vault::api::hash_key(MASTER_KEY)),
        signing_secret: Set(Some(format!("v1.plain.{}", hex::encode(&secret)))),
        name: Set("Master".to_owned()),
        bound_ips: Set(None),
        is_master: Set(true),
        can_manage_keys: Set(true),
        can_manage_webhooks: Set(true),
        can_create_groups: Set(true),
        parent_key_id: Set(None),
        prefix: Set("00000000".to_owned()),
        created_at: Set(chrono::Utc::now().naive_utc()),
        updated_at: Set(chrono::Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let (tx, rx) = tokio::sync::mpsc::channel(256);
    let state = AppState::with_trusted_proxies(db.clone(), tx, Vec::new());
    (db, create_app(state), rx)
}

fn signed_request(method: &str, uri: &str, body: String, offset: i64) -> Request<Body> {
    let secret = format!("signing-secret-for-{MASTER_KEY}");
    let ts = (chrono::Utc::now().timestamp() + offset).to_string();
    let sig = simply_ip_vault::crypto::compute_signature(&secret, method, uri, &ts, body.as_bytes()).unwrap();
    Request::builder()
        .method(method)
        .uri(uri)
        .header("X-API-Key", MASTER_KEY)
        .header("X-Timestamp", ts)
        .header("X-Signature-256", sig)
        .header("Content-Type", "application/json")
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 8080))))
        .body(Body::from(body))
        .unwrap()
}

fn drain(rx: &mut tokio::sync::mpsc::Receiver<WebhookEvent>) -> Vec<WebhookEvent> {
    let mut out = Vec::new();
    while let Ok(ev) = rx.try_recv() {
        out.push(ev);
    }
    out
}

/// Creates a group-scoped webhook the way an operator does, so the configuration under test is the
/// real one and not a hand-built row.
async fn create_webhook(app: &axum::Router, db: &DatabaseConnection, group: &str, offset: i64) {
    let group_id = group_id_of(db, group).await;
    let body = json!({
        "name": format!("hook-{group}"),
        "target_url": "https://receiver.example.com/hook",
        "secret_token": "receiver-secret",
        "group_id": group_id,
        "payload_template": "{\"ip\":\"$target_address\",\"action\":\"$action\"}",
    })
    .to_string();
    let res = app.clone().oneshot(signed_request("POST", "/api/webhooks", body, offset)).await.unwrap();
    let status = res.status();
    let bytes = axum::body::to_bytes(res.into_body(), usize::MAX).await.unwrap();
    assert_eq!(status, axum::http::StatusCode::OK, "webhook creation for {group} must succeed: {}", String::from_utf8_lossy(&bytes));
}

async fn group_id_of(db: &DatabaseConnection, name: &str) -> Uuid {
    simply_ip_vault::entities::ip_group::Entity::find()
        .all(db)
        .await
        .unwrap()
        .into_iter()
        .find(|g| g.name == name)
        .expect("the group exists")
        .id
}

async fn ban(app: &axum::Router, address: &str, group: &str, offset: i64) {
    let body = json!({ "target_address": address, "group_name": group, "cause": "isolation probe" }).to_string();
    let res = app.clone().oneshot(signed_request("POST", "/api/ban", body, offset)).await.unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK, "ban of {address} into {group} must succeed");
}

/// **The reported defect.** An address already present in Group A is added to Group B. Only Group B
/// may be notified. The event this produces must carry Group B's identity and nothing else.
#[tokio::test]
async fn adding_an_address_to_group_b_never_emits_an_event_for_group_a() {
    let (_db, app, mut rx) = setup().await;

    ban(&app, "203.0.113.10", "group-a", 0).await;
    let group_a_events = drain(&mut rx);
    assert_eq!(group_a_events.len(), 1, "the first ban produces exactly one event");
    let group_a_id = group_a_events[0].group_id.expect("the event names its group");

    ban(&app, "203.0.113.10", "group-b", 1).await;
    let events = drain(&mut rx);
    assert_eq!(events.len(), 1, "adding to group B produces exactly one event, for group B");
    assert_ne!(
        events[0].group_id,
        Some(group_a_id),
        "an add into group B must not be attributed to group A's webhooks"
    );
    assert_eq!(events[0].group_name.as_deref(), Some("group-b"));
}

/// The same property observed through the configuration the dispatcher actually consults: a
/// webhook on Group A is registered, and an add into Group B must not select it.
#[tokio::test]
async fn group_a_webhook_is_not_selected_for_a_group_b_mutation() {
    let (db, app, mut rx) = setup().await;

    ban(&app, "203.0.113.20", "group-a", 0).await;
    create_webhook(&app, &db, "group-a", 1).await;
    let _ = drain(&mut rx);
    ban(&app, "203.0.113.20", "group-b", 2).await;
    let events = drain(&mut rx);

    let group_a = simply_ip_vault::entities::ip_group::Entity::find()
        .all(&db)
        .await
        .unwrap()
        .into_iter()
        .find(|g| g.name == "group-a")
        .expect("group-a exists");

    let b_events: Vec<_> = events.iter().filter(|e| e.group_name.as_deref() == Some("group-b")).collect();
    assert_eq!(b_events.len(), 1, "group B's add is reported once");
    assert!(
        b_events.iter().all(|e| e.group_id != Some(group_a.id)),
        "the group B event must not carry group A's id, or A's webhook would be selected for it"
    );
}
