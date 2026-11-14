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

#[tokio::test]
async fn ban_normalizes_ipv6_to_48_in_db_while_dispatching_full_ipv6_in_webhooks() {
    let (db, app, mut rx) = setup().await;

    ban(&app, "2001:db8:1234:5678::1", "Seedbox_Ban", 0).await;
    let first_events = drain(&mut rx);
    assert_eq!(first_events.len(), 1);
    assert_eq!(first_events[0].action, "IP_ADD");
    assert_eq!(first_events[0].address, "2001:db8:1234:5678::1");
    assert!(!first_events[0].is_whitelist);

    // Banning a second host IP in the same /48 updates the existing /48 record (IP_UPDATE)
    // while still emitting the new triggering host IP in the webhook event.
    ban(&app, "2001:db8:1234:9999::2", "Seedbox_Ban", 1).await;
    let second_events = drain(&mut rx);
    assert_eq!(second_events.len(), 1);
    assert_eq!(second_events[0].action, "IP_UPDATE");
    assert_eq!(second_events[0].address, "2001:db8:1234:9999::2");

    // Database contains a single normalized /48 record.
    let records = simply_ip_vault::entities::ip_record::Entity::find()
        .all(&db)
        .await
        .unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].target_address, "2001:db8:1234::/48");
}

#[tokio::test]
async fn whitelist_does_not_normalize_ipv6_to_48() {
    let (db, app, mut rx) = setup().await;

    let body = json!({
        "target_address": "2001:db8:1234:5678::1",
        "group_name": "Allowed_Hosts",
        "cause": "trusted operator"
    })
    .to_string();
    let res = app
        .clone()
        .oneshot(signed_request("POST", "/api/white", body, 0))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);

    let events = drain(&mut rx);
    assert_eq!(events.len(), 1);
    assert!(events[0].is_whitelist);
    assert_eq!(events[0].address, "2001:db8:1234:5678::1");

    let records = simply_ip_vault::entities::ip_record::Entity::find()
        .all(&db)
        .await
        .unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].target_address, "2001:db8:1234:5678::1");
}

#[tokio::test]
async fn batch_ban_normalizes_ipv6_to_48_and_dispatches_full_ips() {
    let (db, app, mut rx) = setup().await;

    let body = json!({
        "group_name": "Seedbox_Ban",
        "mode": "upsert",
        "records": [
            { "target_address": "2001:db8:abcd:0001::10", "cause": "ssh brute" },
            { "target_address": "2001:db8:abcd:0002::20", "cause": "port scan" }
        ]
    })
    .to_string();
    let res = app
        .clone()
        .oneshot(signed_request("POST", "/api/records/batch", body, 0))
        .await
        .unwrap();
    assert_eq!(res.status(), axum::http::StatusCode::OK);

    let records = simply_ip_vault::entities::ip_record::Entity::find()
        .all(&db)
        .await
        .unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].target_address, "2001:db8:abcd::/48");

    let events = drain(&mut rx);
    assert_eq!(events.len(), 2);
    assert_eq!(events[0].action, "IP_ADD");
    assert_eq!(events[0].address, "2001:db8:abcd:1::10");
    assert_eq!(events[1].action, "IP_UPDATE");
    assert_eq!(events[1].address, "2001:db8:abcd:2::20");
}

#[tokio::test]
async fn delete_and_restore_by_host_ipv6_resolve_stored_48_membership() {
    let (db, app, mut rx) = setup().await;

    ban(&app, "2001:db8:face:1111::42", "Seedbox_Ban", 0).await;
    let _ = drain(&mut rx);

    // Soft-delete using another host IP inside the same /48 resolves the /48 record and
    // emits IP_DELETE with the stored /48 prefix.
    let del_res = app
        .clone()
        .oneshot(signed_request(
            "DELETE",
            "/api/ips?target_address=2001:db8:face:2222::99&group_name=Seedbox_Ban",
            String::new(),
            1,
        ))
        .await
        .unwrap();
    assert_eq!(del_res.status(), axum::http::StatusCode::NO_CONTENT);

    let del_events = drain(&mut rx);
    assert_eq!(del_events.len(), 1);
    assert_eq!(del_events[0].action, "IP_DELETE");
    assert_eq!(del_events[0].address, "2001:db8:face::/48");

    // Restore using the original bare host IPv6 also resolves the stored /48 membership.
    let restore_body = json!({
        "target_address": "2001:db8:face:1111::42",
        "group_name": "Seedbox_Ban"
    })
    .to_string();
    let restore_res = app
        .clone()
        .oneshot(signed_request("POST", "/api/ips/restore", restore_body, 2))
        .await
        .unwrap();
    assert_eq!(restore_res.status(), axum::http::StatusCode::OK);

    let memberships = simply_ip_vault::entities::ip_record_group_membership::Entity::find()
        .all(&db)
        .await
        .unwrap();
    assert_eq!(memberships.len(), 1);
    assert!(!memberships[0].is_deleted);
}

#[tokio::test]
async fn disabling_ipv6_48_normalization_via_api_stores_exact_host_ipv6() {
    let (db, app, mut rx) = setup().await;

    // Disable normalization at runtime via PUT /api/settings
    let put_body = json!({ "normalize_ipv6_to_48": false }).to_string();
    let put_res = app
        .clone()
        .oneshot(signed_request("PUT", "/api/settings", put_body, 0))
        .await
        .unwrap();
    assert_eq!(put_res.status(), axum::http::StatusCode::OK);

    ban(&app, "2001:db8:9999:aaaa::1", "Seedbox_Ban", 1).await;
    let events = drain(&mut rx);
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].address, "2001:db8:9999:aaaa::1");

    let records = simply_ip_vault::entities::ip_record::Entity::find()
        .all(&db)
        .await
        .unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].target_address, "2001:db8:9999:aaaa::1");
}
