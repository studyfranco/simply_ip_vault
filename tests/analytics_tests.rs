//! Integration tests for Ban Analytics and Recidivism endpoints:
//! `GET /api/stats/analytics`
//! `GET /api/stats/intersection`

use axum::{body::Body, http::Request, http::StatusCode};
use chrono::Utc;
use sea_orm::{ActiveModelTrait, ActiveValue::Set, Database, DatabaseConnection};
use sea_orm_migration::MigratorTrait;
use serde_json::Value;
use tower::ServiceExt;
use uuid::Uuid;

use simply_ip_vault::{
    create_app,
    entities::{api_key, ip_group, ip_record, ip_record_cause, ip_record_group_membership},
    migration,
    state::{AppState, WebhookEvent},
};

const MASTER_KEY: &str = "0000000000000000000000000000000000000000000000000000000000000002";

async fn setup() -> (DatabaseConnection, axum::Router) {
    let db = Database::connect("sqlite::memory:").await.unwrap();
    migration::Migrator::up(&db, None).await.unwrap();

    let secret = format!("signing-secret-for-{MASTER_KEY}");
    api_key::ActiveModel {
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
        created_at: Set(Utc::now().naive_utc()),
        updated_at: Set(Utc::now().naive_utc()),
    }
    .insert(&db)
    .await
    .unwrap();

    let (tx, _rx) = tokio::sync::mpsc::channel::<WebhookEvent>(256);
    let state = AppState::with_trusted_proxies(db.clone(), tx, Vec::new());
    (db, create_app(state))
}

fn signed_request(method: &str, uri: &str, body: &str) -> Request<Body> {
    let secret = format!("signing-secret-for-{MASTER_KEY}");
    let ts = Utc::now().timestamp().to_string();
    let sig = simply_ip_vault::crypto::compute_signature(&secret, method, uri, &ts, body.as_bytes()).unwrap();
    Request::builder()
        .method(method)
        .uri(uri)
        .header("X-API-Key", MASTER_KEY)
        .header("X-Timestamp", ts)
        .header("X-Signature-256", sig)
        .header("Content-Type", "application/json")
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from(([127, 0, 0, 1], 8080))))
        .body(Body::from(body.to_owned()))
        .unwrap()
}

#[tokio::test]
async fn test_analytics_and_intersection_endpoints() {
    let (db, app) = setup().await;
    let now = Utc::now().naive_utc();

    // Create 2 groups: GroupA and GroupB
    let group_a_id = Uuid::new_v4();
    ip_group::ActiveModel {
        id: Set(group_a_id),
        name: Set("Fail2ban".to_owned()),
        description: Set(Some("Host bans".to_owned())),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
        created_at: Set(now),
    }
    .insert(&db)
    .await
    .unwrap();

    let group_b_id = Uuid::new_v4();
    ip_group::ActiveModel {
        id: Set(group_b_id),
        name: Set("Seedbox_Ban".to_owned()),
        description: Set(Some("Torrent bans".to_owned())),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
        created_at: Set(now),
    }
    .insert(&db)
    .await
    .unwrap();

    // Create 3 IPs:
    // IP 1: 192.168.1.1 (Only in Fail2ban)
    let ip1_id = Uuid::new_v4();
    ip_record::ActiveModel {
        id: Set(ip1_id),
        target_address: Set("192.168.1.1".to_owned()),
        created_at: Set(now),
    }
    .insert(&db)
    .await
    .unwrap();

    let m1_id = Uuid::new_v4();
    ip_record_group_membership::ActiveModel {
        id: Set(m1_id),
        ip_record_id: Set(ip1_id),
        group_id: Set(group_a_id),
        is_locked: Set(false),
        created_at: Set(now),
        last_seen_at: Set(now),
        is_deleted: Set(false),
        deleted_at: Set(None),
        deleted_by: Set(None),
    }
    .insert(&db)
    .await
    .unwrap();

    ip_record_cause::ActiveModel {
        id: Set(Uuid::new_v4()),
        membership_id: Set(m1_id),
        cause: Set("ssh-bruteforce".to_owned()),
        created_at: Set(now),
    }
    .insert(&db)
    .await
    .unwrap();

    // IP 2: 10.0.0.2 (Only in Seedbox_Ban)
    let ip2_id = Uuid::new_v4();
    ip_record::ActiveModel {
        id: Set(ip2_id),
        target_address: Set("10.0.0.2".to_owned()),
        created_at: Set(now),
    }
    .insert(&db)
    .await
    .unwrap();

    let m2_id = Uuid::new_v4();
    ip_record_group_membership::ActiveModel {
        id: Set(m2_id),
        ip_record_id: Set(ip2_id),
        group_id: Set(group_b_id),
        is_locked: Set(false),
        created_at: Set(now),
        last_seen_at: Set(now),
        is_deleted: Set(false),
        deleted_at: Set(None),
        deleted_by: Set(None),
    }
    .insert(&db)
    .await
    .unwrap();

    ip_record_cause::ActiveModel {
        id: Set(Uuid::new_v4()),
        membership_id: Set(m2_id),
        cause: Set("torrent-ratio-cheat".to_owned()),
        created_at: Set(now),
    }
    .insert(&db)
    .await
    .unwrap();

    // IP 3: 172.16.0.3 (In BOTH Fail2ban and Seedbox_Ban -> Recidivist!)
    let ip3_id = Uuid::new_v4();
    ip_record::ActiveModel {
        id: Set(ip3_id),
        target_address: Set("172.16.0.3".to_owned()),
        created_at: Set(now),
    }
    .insert(&db)
    .await
    .unwrap();

    let m3a_id = Uuid::new_v4();
    ip_record_group_membership::ActiveModel {
        id: Set(m3a_id),
        ip_record_id: Set(ip3_id),
        group_id: Set(group_a_id),
        is_locked: Set(false),
        created_at: Set(now),
        last_seen_at: Set(now),
        is_deleted: Set(false),
        deleted_at: Set(None),
        deleted_by: Set(None),
    }
    .insert(&db)
    .await
    .unwrap();

    ip_record_cause::ActiveModel {
        id: Set(Uuid::new_v4()),
        membership_id: Set(m3a_id),
        cause: Set("ssh-bruteforce".to_owned()),
        created_at: Set(now),
    }
    .insert(&db)
    .await
    .unwrap();

    let m3b_id = Uuid::new_v4();
    ip_record_group_membership::ActiveModel {
        id: Set(m3b_id),
        ip_record_id: Set(ip3_id),
        group_id: Set(group_b_id),
        is_locked: Set(false),
        created_at: Set(now),
        last_seen_at: Set(now),
        is_deleted: Set(false),
        deleted_at: Set(None),
        deleted_by: Set(None),
    }
    .insert(&db)
    .await
    .unwrap();

    ip_record_cause::ActiveModel {
        id: Set(Uuid::new_v4()),
        membership_id: Set(m3b_id),
        cause: Set("torrent-ratio-cheat".to_owned()),
        created_at: Set(now),
    }
    .insert(&db)
    .await
    .unwrap();

    // IP 4: 1.1.1.1 (Deleted in Seedbox_Ban, active in Fail2ban -> Not a recidivist)
    let ip4_id = Uuid::new_v4();
    ip_record::ActiveModel {
        id: Set(ip4_id),
        target_address: Set("1.1.1.1".to_owned()),
        created_at: Set(now),
    }
    .insert(&db)
    .await
    .unwrap();

    let m4a_id = Uuid::new_v4();
    ip_record_group_membership::ActiveModel {
        id: Set(m4a_id),
        ip_record_id: Set(ip4_id),
        group_id: Set(group_a_id),
        is_locked: Set(false),
        created_at: Set(now),
        last_seen_at: Set(now),
        is_deleted: Set(false),
        deleted_at: Set(None),
        deleted_by: Set(None),
    }
    .insert(&db)
    .await
    .unwrap();

    ip_record_cause::ActiveModel {
        id: Set(Uuid::new_v4()),
        membership_id: Set(m4a_id),
        cause: Set("port-scan".to_owned()),
        created_at: Set(now),
    }
    .insert(&db)
    .await
    .unwrap();

    let m4b_id = Uuid::new_v4();
    ip_record_group_membership::ActiveModel {
        id: Set(m4b_id),
        ip_record_id: Set(ip4_id),
        group_id: Set(group_b_id),
        is_locked: Set(false),
        created_at: Set(now),
        last_seen_at: Set(now),
        is_deleted: Set(true),
        deleted_at: Set(Some(now)),
        deleted_by: Set(Some("admin".to_owned())),
    }
    .insert(&db)
    .await
    .unwrap();

    ip_record_cause::ActiveModel {
        id: Set(Uuid::new_v4()),
        membership_id: Set(m4b_id),
        cause: Set("old-violation".to_owned()),
        created_at: Set(now),
    }
    .insert(&db)
    .await
    .unwrap();

    // Test 1: GET /api/stats/analytics
    let req = signed_request("GET", "/api/stats/analytics", "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();

    // Total active IPs = 4 (IP1, IP2, IP3, IP4)
    assert_eq!(body["total_active_ips"], 4);
    // Recidivist IPs = 1 (IP3)
    assert_eq!(body["recidivist_ips_count"], 1);
    // Recidivism rate = 25.0% (1 / 4)
    let rate = body["recidivism_rate_pct"].as_f64().unwrap();
    assert!((rate - 25.0).abs() < 0.01);

    // Check groups
    let groups = body["groups"].as_array().unwrap();
    assert_eq!(groups.len(), 2);

    // Fail2ban has 3 active (IP1, IP3, IP4), shared = 1 (IP3)
    let f2b = groups.iter().find(|g| g["group_name"] == "Fail2ban").unwrap();
    assert_eq!(f2b["active_count"], 3);
    assert_eq!(f2b["shared_count"], 1);

    // Seedbox_Ban has 2 active (IP2, IP3), shared = 1 (IP3)
    let sb = groups.iter().find(|g| g["group_name"] == "Seedbox_Ban").unwrap();
    assert_eq!(sb["active_count"], 2);
    assert_eq!(sb["shared_count"], 1);

    // Check top causes
    let causes = body["top_causes"].as_array().unwrap();
    let ssh = causes.iter().find(|c| c["cause"] == "ssh-bruteforce").unwrap();
    assert_eq!(ssh["count"], 2);

    // Check top recidivists
    let recidivists = body["top_recidivists"].as_array().unwrap();
    assert_eq!(recidivists.len(), 1);
    assert_eq!(recidivists[0]["target_address"], "172.16.0.3");
    assert_eq!(recidivists[0]["group_count"], 2);

    // Check CIDR breakdown
    let cidrs = body["cidr_breakdown"].as_array().unwrap();
    assert_eq!(cidrs.len(), 4);

    // Check locked breakdown
    let locked = &body["locked_breakdown"];
    assert_eq!(locked["total_active"], 5);
    assert_eq!(locked["locked_count"], 0);
    assert_eq!(locked["dynamic_count"], 5);

    // Check velocity breakdown
    let v24 = &body["velocity_24h"];
    assert_eq!(v24["active_added_or_seen"], 5);
    assert_eq!(v24["soft_deleted"], 1);

    let v7d = &body["velocity_7d"];
    assert_eq!(v7d["active_added_or_seen"], 5);
    assert_eq!(v7d["soft_deleted"], 1);

    // Test 2: GET /api/stats/intersection?group_a=Fail2ban&group_b=Seedbox_Ban
    let req = signed_request("GET", "/api/stats/intersection?group_a=Fail2ban&group_b=Seedbox_Ban", "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let isect: Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(isect["group_a_name"], "Fail2ban");
    assert_eq!(isect["group_b_name"], "Seedbox_Ban");
    assert_eq!(isect["total_overlap"], 1);

    let items = isect["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["target_address"], "172.16.0.3");

    // Test 3: Non-existent group returns 404
    let req = signed_request("GET", "/api/stats/intersection?group_a=Fail2ban&group_b=NoSuchGroup", "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    // Test 4: 4-Group Intersection
    // Create GroupC and GroupD
    let group_c_id = Uuid::new_v4();
    ip_group::ActiveModel {
        id: Set(group_c_id),
        name: Set("Spamhaus".to_owned()),
        description: Set(Some("Spam blacklist".to_owned())),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
        created_at: Set(now),
    }
    .insert(&db)
    .await
    .unwrap();

    let group_d_id = Uuid::new_v4();
    ip_group::ActiveModel {
        id: Set(group_d_id),
        name: Set("TorExit".to_owned()),
        description: Set(Some("Tor exit nodes".to_owned())),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
        created_at: Set(now),
    }
    .insert(&db)
    .await
    .unwrap();

    // Add IP3 into GroupC and GroupD (IP3 is now in Fail2ban, Seedbox_Ban, Spamhaus, TorExit)
    ip_record_group_membership::ActiveModel {
        id: Set(Uuid::new_v4()),
        ip_record_id: Set(ip3_id),
        group_id: Set(group_c_id),
        is_locked: Set(false),
        created_at: Set(now),
        last_seen_at: Set(now),
        is_deleted: Set(false),
        deleted_at: Set(None),
        deleted_by: Set(None),
    }
    .insert(&db)
    .await
    .unwrap();

    ip_record_group_membership::ActiveModel {
        id: Set(Uuid::new_v4()),
        ip_record_id: Set(ip3_id),
        group_id: Set(group_d_id),
        is_locked: Set(false),
        created_at: Set(now),
        last_seen_at: Set(now),
        is_deleted: Set(false),
        deleted_at: Set(None),
        deleted_by: Set(None),
    }
    .insert(&db)
    .await
    .unwrap();

    // Add IP2 into GroupC (IP2 is now in Seedbox_Ban and Spamhaus)
    ip_record_group_membership::ActiveModel {
        id: Set(Uuid::new_v4()),
        ip_record_id: Set(ip2_id),
        group_id: Set(group_c_id),
        is_locked: Set(false),
        created_at: Set(now),
        last_seen_at: Set(now),
        is_deleted: Set(false),
        deleted_at: Set(None),
        deleted_by: Set(None),
    }
    .insert(&db)
    .await
    .unwrap();

    // Query 4 groups: Fail2ban, Seedbox_Ban, Spamhaus, TorExit
    let req = signed_request("GET", "/api/stats/intersection?groups=Fail2ban,Seedbox_Ban,Spamhaus,TorExit", "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let isect4: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(isect4["total_overlap"], 1);
    assert_eq!(isect4["groups"].as_array().unwrap().len(), 4);
    assert_eq!(isect4["items"][0]["target_address"], "172.16.0.3");
    let gls = &isect4["items"][0]["group_last_seen"];
    assert!(gls["Fail2ban"].is_string());
    assert!(gls["Seedbox_Ban"].is_string());
    assert!(gls["Spamhaus"].is_string());
    assert!(gls["TorExit"].is_string());

    // Query 2 groups via `groups` parameter: Seedbox_Ban, Spamhaus -> Overlap is 2 (IP2 and IP3)
    let req = signed_request("GET", "/api/stats/intersection?groups=Seedbox_Ban,Spamhaus", "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let isect2: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(isect2["total_overlap"], 2);

    // Query with single group should fail (400 Bad Request)
    let req = signed_request("GET", "/api/stats/intersection?groups=Fail2ban", "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

async fn add_test_ip(db: &DatabaseConnection, ip_str: &str, now: chrono::NaiveDateTime) -> Uuid {
    let ip_id = Uuid::new_v4();
    ip_record::ActiveModel {
        id: Set(ip_id),
        target_address: Set(ip_str.to_owned()),
        created_at: Set(now),
    }
    .insert(db)
    .await
    .unwrap();
    ip_id
}

async fn add_test_membership(
    db: &DatabaseConnection,
    ip_id: Uuid,
    grp_id: Uuid,
    is_locked: bool,
    created: chrono::NaiveDateTime,
    seen: chrono::NaiveDateTime,
    deleted: Option<chrono::NaiveDateTime>,
) -> Uuid {
    let m_id = Uuid::new_v4();
    ip_record_group_membership::ActiveModel {
        id: Set(m_id),
        ip_record_id: Set(ip_id),
        group_id: Set(grp_id),
        is_locked: Set(is_locked),
        created_at: Set(created),
        last_seen_at: Set(seen),
        is_deleted: Set(deleted.is_some()),
        deleted_at: Set(deleted),
        deleted_by: Set(deleted.map(|_| "admin".to_owned())),
    }
    .insert(db)
    .await
    .unwrap();
    m_id
}

#[tokio::test]
async fn test_analytics_new_statistics_and_pagination() {
    let (db, app) = setup().await;
    let now = Utc::now().naive_utc();
    let two_days_ago = now - chrono::Duration::days(2);
    let ten_days_ago = now - chrono::Duration::days(10);

    // Create 3 groups: Alpha, Beta, Gamma
    let g1_id = Uuid::new_v4();
    ip_group::ActiveModel {
        id: Set(g1_id),
        name: Set("Alpha".to_owned()),
        description: Set(None),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
        created_at: Set(now),
    }
    .insert(&db)
    .await
    .unwrap();

    let g2_id = Uuid::new_v4();
    ip_group::ActiveModel {
        id: Set(g2_id),
        name: Set("Beta".to_owned()),
        description: Set(None),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
        created_at: Set(now),
    }
    .insert(&db)
    .await
    .unwrap();

    let g3_id = Uuid::new_v4();
    ip_group::ActiveModel {
        id: Set(g3_id),
        name: Set("Gamma".to_owned()),
        description: Set(None),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
        created_at: Set(now),
    }
    .insert(&db)
    .await
    .unwrap();

    let ip1 = add_test_ip(&db, "192.168.10.1", now).await;
    let ip2 = add_test_ip(&db, "192.168.10.2", now).await;
    let ip3 = add_test_ip(&db, "192.168.10.3", now).await;
    let ip4 = add_test_ip(&db, "10.50.0.1", now).await;
    let ip5 = add_test_ip(&db, "10.50.0.2", now).await;
    let ip6 = add_test_ip(&db, "2001:db8:beef::1", now).await;
    let ip7 = add_test_ip(&db, "2001:db8:beef::2", now).await;
    let ip8 = add_test_ip(&db, "2001:db8:cafe::/48", now).await;

    // Memberships:
    // ip1 in Alpha (locked, now) AND in Beta (dynamic, now) AND in Gamma (dynamic, now) -> 3 groups (top recidivist!)
    add_test_membership(&db, ip1, g1_id, true, now, now, None).await;
    add_test_membership(&db, ip1, g2_id, false, now, now, None).await;
    add_test_membership(&db, ip1, g3_id, false, now, now, None).await;

    // ip2 in Alpha (locked, now) AND in Beta (dynamic, now) -> 2 groups
    add_test_membership(&db, ip2, g1_id, true, now, now, None).await;
    add_test_membership(&db, ip2, g2_id, false, now, now, None).await;

    // ip3 in Alpha (locked, two_days_ago) -> 1 group
    add_test_membership(&db, ip3, g1_id, true, two_days_ago, two_days_ago, None).await;

    // ip4 in Beta (locked, two_days_ago) -> 1 group
    add_test_membership(&db, ip4, g2_id, true, two_days_ago, two_days_ago, None).await;

    // ip5 in Gamma (dynamic, ten_days_ago) -> 1 group
    add_test_membership(&db, ip5, g3_id, false, ten_days_ago, ten_days_ago, None).await;

    // ip6 in Alpha (dynamic, now)
    add_test_membership(&db, ip6, g1_id, false, now, now, None).await;

    // ip7 in Alpha (dynamic, now)
    add_test_membership(&db, ip7, g1_id, false, now, now, None).await;

    // ip8 in Beta (dynamic, now)
    add_test_membership(&db, ip8, g2_id, false, now, now, None).await;

    // Soft-deleted memberships:
    // ip3 deleted in Beta recently (within 24h)
    add_test_membership(&db, ip3, g2_id, false, now, now, Some(now)).await;
    // ip4 deleted in Gamma 2 days ago (within 7d)
    add_test_membership(
        &db,
        ip4,
        g3_id,
        false,
        two_days_ago,
        two_days_ago,
        Some(two_days_ago),
    )
    .await;
    // ip5 deleted in Alpha 10 days ago (outside 7d)
    add_test_membership(
        &db,
        ip5,
        g1_id,
        false,
        ten_days_ago,
        ten_days_ago,
        Some(ten_days_ago),
    )
    .await;

    // Test GET /api/stats/analytics
    let req = signed_request("GET", "/api/stats/analytics", "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let body: Value = serde_json::from_slice(&bytes).unwrap();

    // 8 active IPs total (ip1..ip8)
    assert_eq!(body["total_active_ips"], 8);
    // Recidivists: ip1 (3 groups) and ip2 (2 groups) = 2
    assert_eq!(body["recidivist_ips_count"], 2);
    // Recidivism rate: 2 / 8 = 25.0%
    let rate = body["recidivism_rate_pct"].as_f64().unwrap();
    assert!((rate - 25.0).abs() < 0.01);

    // Top recidivists: ip1 should be first because it has 3 groups, ip2 second (2 groups)
    let top_rec = body["top_recidivists"].as_array().unwrap();
    assert_eq!(top_rec.len(), 2);
    assert_eq!(top_rec[0]["target_address"], "192.168.10.1");
    assert_eq!(top_rec[0]["group_count"], 3);
    assert_eq!(top_rec[1]["target_address"], "192.168.10.2");
    assert_eq!(top_rec[1]["group_count"], 2);

    // Groups breakdown shared count:
    // Alpha has active: ip1, ip2, ip3, ip6, ip7 = 5. Shared: ip1, ip2 = 2.
    // Beta has active: ip1, ip2, ip4, ip8 = 4. Shared: ip1, ip2 = 2.
    // Gamma has active: ip1, ip5 = 2. Shared: ip1 = 1.
    let groups = body["groups"].as_array().unwrap();
    let alpha = groups.iter().find(|g| g["group_name"] == "Alpha").unwrap();
    assert_eq!(alpha["active_count"], 5);
    assert_eq!(alpha["shared_count"], 2);

    let beta = groups.iter().find(|g| g["group_name"] == "Beta").unwrap();
    assert_eq!(beta["active_count"], 4);
    assert_eq!(beta["shared_count"], 2);

    let gamma = groups.iter().find(|g| g["group_name"] == "Gamma").unwrap();
    assert_eq!(gamma["active_count"], 2);
    assert_eq!(gamma["shared_count"], 1);

    // CIDR breakdown:
    // 192.168.10.0/24: 3 IPs (ip1, ip2, ip3)
    // 2001:db8:beef::/64: 2 IPs (ip6, ip7)
    // 10.50.0.0/24: 2 IPs (ip4, ip5)
    // 2001:db8:cafe::/48: 1 IP (ip8)
    let cidrs = body["cidr_breakdown"].as_array().unwrap();
    assert_eq!(cidrs.len(), 4);
    assert_eq!(cidrs[0]["subnet"], "192.168.10.0/24");
    assert_eq!(cidrs[0]["active_count"], 3);

    // Locked breakdown:
    // Total active = 11 memberships. Locked = 4, Dynamic = 7.
    let locked = &body["locked_breakdown"];
    assert_eq!(locked["total_active"], 11);
    assert_eq!(locked["locked_count"], 4);
    assert_eq!(locked["dynamic_count"], 7);

    // Velocity breakdown:
    // Active added/seen:
    // In 24h: 8 active.
    // In 7d: 8 + 2 = 10 active.
    // Soft-deleted:
    // In 24h: 1 soft-deleted.
    // In 7d: 1 + 1 = 2 soft-deleted.
    let v24 = &body["velocity_24h"];
    assert_eq!(v24["active_added_or_seen"], 8);
    assert_eq!(v24["soft_deleted"], 1);

    let v7d = &body["velocity_7d"];
    assert_eq!(v7d["active_added_or_seen"], 10);
    assert_eq!(v7d["soft_deleted"], 2);

    // Intersection pagination tests between Alpha and Beta:
    // Common IPs in Alpha and Beta: ip1 and ip2 (total overlap = 2)
    // Page limit 1, offset 0 -> 1 item
    let req = signed_request(
        "GET",
        "/api/stats/intersection?groups=Alpha,Beta&limit=1&offset=0",
        "",
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let isect: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(isect["total_overlap"], 2);
    assert_eq!(isect["items"].as_array().unwrap().len(), 1);

    // Page limit 1, offset 1 -> 1 item
    let req = signed_request(
        "GET",
        "/api/stats/intersection?groups=Alpha,Beta&limit=1&offset=1",
        "",
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let isect: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(isect["total_overlap"], 2);
    assert_eq!(isect["items"].as_array().unwrap().len(), 1);

    // Page offset past total_overlap -> 0 items
    let req = signed_request(
        "GET",
        "/api/stats/intersection?groups=Alpha,Beta&limit=1&offset=10",
        "",
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let isect: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(isect["total_overlap"], 2);
    assert_eq!(isect["items"].as_array().unwrap().len(), 0);

    // 3-Group intersection: Alpha, Beta, Gamma (only ip1 is in all three)
    let req = signed_request(
        "GET",
        "/api/stats/intersection?groups=Alpha,Beta,Gamma",
        "",
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let isect3: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(isect3["total_overlap"], 1);
    assert_eq!(isect3["items"].as_array().unwrap().len(), 1);
    assert_eq!(isect3["items"][0]["target_address"], "192.168.10.1");
    let gls = &isect3["items"][0]["group_last_seen"];
    assert!(gls["Alpha"].is_string());
    assert!(gls["Beta"].is_string());
    assert!(gls["Gamma"].is_string());

    // Create an empty group Delta
    let g4_id = Uuid::new_v4();
    ip_group::ActiveModel {
        id: Set(g4_id),
        name: Set("Delta".to_owned()),
        description: Set(None),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
        created_at: Set(now),
    }
    .insert(&db)
    .await
    .unwrap();

    // Intersection with Delta should return total_overlap = 0 and empty items
    let req = signed_request(
        "GET",
        "/api/stats/intersection?groups=Alpha,Delta",
        "",
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024).await.unwrap();
    let isect_empty: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(isect_empty["total_overlap"], 0);
    assert_eq!(isect_empty["items"].as_array().unwrap().len(), 0);
}
