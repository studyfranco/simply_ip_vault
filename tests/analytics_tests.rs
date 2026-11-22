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
    let sig =
        simply_ip_vault::crypto::compute_signature(&secret, method, uri, &ts, body.as_bytes())
            .unwrap();
    Request::builder()
        .method(method)
        .uri(uri)
        .header("X-API-Key", MASTER_KEY)
        .header("X-Timestamp", ts)
        .header("X-Signature-256", sig)
        .header("Content-Type", "application/json")
        .extension(axum::extract::ConnectInfo(std::net::SocketAddr::from((
            [127, 0, 0, 1],
            8080,
        ))))
        .body(Body::from(body.to_owned()))
        .unwrap()
}

#[tokio::test]
async fn test_analytics_and_intersection_endpoints() {
    let (db, app) = setup().await;
    let now = Utc::now().naive_utc();

    let (ip2_id, ip3_id) = seed_analytics_fixture(&db, now).await;
    // Test 1: GET /api/stats/analytics
    let req = signed_request("GET", "/api/stats/analytics", "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
        .await
        .unwrap();
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
    let f2b = groups
        .iter()
        .find(|g| g["group_name"] == "Fail2ban")
        .unwrap();
    assert_eq!(f2b["active_count"], 3);
    assert_eq!(f2b["shared_count"], 1);

    // Seedbox_Ban has 2 active (IP2, IP3), shared = 1 (IP3)
    let sb = groups
        .iter()
        .find(|g| g["group_name"] == "Seedbox_Ban")
        .unwrap();
    assert_eq!(sb["active_count"], 2);
    assert_eq!(sb["shared_count"], 1);

    // Check top causes
    let causes = body["top_causes"].as_array().unwrap();
    let ssh = causes
        .iter()
        .find(|c| c["cause"] == "ssh-bruteforce")
        .unwrap();
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
    let req = signed_request(
        "GET",
        "/api/stats/intersection?group_a=Fail2ban&group_b=Seedbox_Ban",
        "",
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
        .await
        .unwrap();
    let isect: Value = serde_json::from_slice(&bytes).unwrap();

    assert_eq!(isect["group_a_name"], "Fail2ban");
    assert_eq!(isect["group_b_name"], "Seedbox_Ban");
    assert_eq!(isect["total_overlap"], 1);

    let items = isect["items"].as_array().unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["target_address"], "172.16.0.3");

    // Test 3: Non-existent group returns 404
    let req = signed_request(
        "GET",
        "/api/stats/intersection?group_a=Fail2ban&group_b=NoSuchGroup",
        "",
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::NOT_FOUND);

    assert_multi_group_intersection(db, app, now, ip2_id, ip3_id).await;
}

async fn seed_analytics_fixture(
    db: &DatabaseConnection,
    now: chrono::NaiveDateTime,
) -> (Uuid, Uuid) {
    // Create 2 groups: GroupA and GroupB
    let fail2ban = add_test_group(db, "Fail2ban", Some("Host bans"), now).await;

    let seedbox = add_test_group(db, "Seedbox_Ban", Some("Torrent bans"), now).await;

    // Create 3 IPs:
    // IP 1: 192.168.1.1 (Only in Fail2ban)
    let ip1_id = add_test_ip(db, "192.168.1.1", now).await;

    let m1_id = add_test_membership(db, ip1_id, fail2ban, false, now, now, None).await;

    ip_record_cause::ActiveModel {
        id: Set(Uuid::new_v4()),
        membership_id: Set(m1_id),
        cause: Set("ssh-bruteforce".to_owned()),
        created_at: Set(now),
    }
    .insert(db)
    .await
    .unwrap();

    // IP 2: 10.0.0.2 (Only in Seedbox_Ban)
    let ip2_id = add_test_ip(db, "10.0.0.2", now).await;

    let m2_id = add_test_membership(db, ip2_id, seedbox, false, now, now, None).await;

    ip_record_cause::ActiveModel {
        id: Set(Uuid::new_v4()),
        membership_id: Set(m2_id),
        cause: Set("torrent-ratio-cheat".to_owned()),
        created_at: Set(now),
    }
    .insert(db)
    .await
    .unwrap();

    // IP 3: 172.16.0.3 (In BOTH Fail2ban and Seedbox_Ban -> Recidivist!)
    let ip3_id = add_test_ip(db, "172.16.0.3", now).await;

    let recidivist_host_membership =
        add_test_membership(db, ip3_id, fail2ban, false, now, now, None).await;

    ip_record_cause::ActiveModel {
        id: Set(Uuid::new_v4()),
        membership_id: Set(recidivist_host_membership),
        cause: Set("ssh-bruteforce".to_owned()),
        created_at: Set(now),
    }
    .insert(db)
    .await
    .unwrap();

    let recidivist_torrent_membership =
        add_test_membership(db, ip3_id, seedbox, false, now, now, None).await;

    ip_record_cause::ActiveModel {
        id: Set(Uuid::new_v4()),
        membership_id: Set(recidivist_torrent_membership),
        cause: Set("torrent-ratio-cheat".to_owned()),
        created_at: Set(now),
    }
    .insert(db)
    .await
    .unwrap();

    // IP 4: 1.1.1.1 (Deleted in Seedbox_Ban, active in Fail2ban -> Not a recidivist)
    let ip4_id = add_test_ip(db, "1.1.1.1", now).await;

    let live_membership = add_test_membership(db, ip4_id, fail2ban, false, now, now, None).await;

    ip_record_cause::ActiveModel {
        id: Set(Uuid::new_v4()),
        membership_id: Set(live_membership),
        cause: Set("port-scan".to_owned()),
        created_at: Set(now),
    }
    .insert(db)
    .await
    .unwrap();

    let deleted_membership = Uuid::new_v4();
    ip_record_group_membership::ActiveModel {
        id: Set(deleted_membership),
        ip_record_id: Set(ip4_id),
        group_id: Set(seedbox),
        is_locked: Set(false),
        created_at: Set(now),
        last_seen_at: Set(now),
        is_deleted: Set(true),
        deleted_at: Set(Some(now)),
        deleted_by: Set(Some("admin".to_owned())),
    }
    .insert(db)
    .await
    .unwrap();

    ip_record_cause::ActiveModel {
        id: Set(Uuid::new_v4()),
        membership_id: Set(deleted_membership),
        cause: Set("old-violation".to_owned()),
        created_at: Set(now),
    }
    .insert(db)
    .await
    .unwrap();
    (ip2_id, ip3_id)
}

async fn assert_multi_group_intersection(
    db: DatabaseConnection,
    app: axum::Router,
    now: chrono::NaiveDateTime,
    ip2_id: Uuid,
    ip3_id: Uuid,
) {
    // Test 4: 4-Group Intersection
    // Create GroupC and GroupD
    let spamhaus = add_test_group(&db, "Spamhaus", Some("Spam blacklist"), now).await;

    let tor_exit = add_test_group(&db, "TorExit", Some("Tor exit nodes"), now).await;

    // Add IP3 into GroupC and GroupD (IP3 is now in Fail2ban, Seedbox_Ban, Spamhaus, TorExit)
    add_test_membership(&db, ip3_id, spamhaus, false, now, now, None).await;

    add_test_membership(&db, ip3_id, tor_exit, false, now, now, None).await;

    // Add IP2 into GroupC (IP2 is now in Seedbox_Ban and Spamhaus)
    add_test_membership(&db, ip2_id, spamhaus, false, now, now, None).await;

    // Query 4 groups: Fail2ban, Seedbox_Ban, Spamhaus, TorExit
    let req = signed_request(
        "GET",
        "/api/stats/intersection?groups=Fail2ban,Seedbox_Ban,Spamhaus,TorExit",
        "",
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
        .await
        .unwrap();
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
    let req = signed_request(
        "GET",
        "/api/stats/intersection?groups=Seedbox_Ban,Spamhaus",
        "",
    );
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
        .await
        .unwrap();
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
    seed_pagination_fixture(&db, now).await;
    // Test GET /api/stats/analytics
    let req = signed_request("GET", "/api/stats/analytics", "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);

    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
        .await
        .unwrap();
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

    assert_intersection_pagination(db, app, now).await;
}

async fn seed_pagination_fixture(db: &DatabaseConnection, now: chrono::NaiveDateTime) {
    let two_days_ago = now - chrono::Duration::days(2);
    let ten_days_ago = now - chrono::Duration::days(10);

    // Create 3 groups: Alpha, Beta, Gamma
    let g1_id = add_test_group(db, "Alpha", None, now).await;

    let g2_id = add_test_group(db, "Beta", None, now).await;

    let g3_id = add_test_group(db, "Gamma", None, now).await;

    let ip1 = add_test_ip(db, "192.168.10.1", now).await;
    let ip2 = add_test_ip(db, "192.168.10.2", now).await;
    let ip3 = add_test_ip(db, "192.168.10.3", now).await;
    let ip4 = add_test_ip(db, "10.50.0.1", now).await;
    let ip5 = add_test_ip(db, "10.50.0.2", now).await;
    let ip6 = add_test_ip(db, "2001:db8:beef::1", now).await;
    let ip7 = add_test_ip(db, "2001:db8:beef::2", now).await;
    let ip8 = add_test_ip(db, "2001:db8:cafe::/48", now).await;

    // Memberships:
    // ip1 in Alpha (locked, now) AND in Beta (dynamic, now) AND in Gamma (dynamic, now) -> 3 groups (top recidivist!)
    add_test_membership(db, ip1, g1_id, true, now, now, None).await;
    add_test_membership(db, ip1, g2_id, false, now, now, None).await;
    add_test_membership(db, ip1, g3_id, false, now, now, None).await;

    // ip2 in Alpha (locked, now) AND in Beta (dynamic, now) -> 2 groups
    add_test_membership(db, ip2, g1_id, true, now, now, None).await;
    add_test_membership(db, ip2, g2_id, false, now, now, None).await;

    // ip3 in Alpha (locked, two_days_ago) -> 1 group
    add_test_membership(db, ip3, g1_id, true, two_days_ago, two_days_ago, None).await;

    // ip4 in Beta (locked, two_days_ago) -> 1 group
    add_test_membership(db, ip4, g2_id, true, two_days_ago, two_days_ago, None).await;

    // ip5 in Gamma (dynamic, ten_days_ago) -> 1 group
    add_test_membership(db, ip5, g3_id, false, ten_days_ago, ten_days_ago, None).await;

    // ip6 in Alpha (dynamic, now)
    add_test_membership(db, ip6, g1_id, false, now, now, None).await;

    // ip7 in Alpha (dynamic, now)
    add_test_membership(db, ip7, g1_id, false, now, now, None).await;

    // ip8 in Beta (dynamic, now)
    add_test_membership(db, ip8, g2_id, false, now, now, None).await;

    // Soft-deleted memberships:
    // ip3 deleted in Beta recently (within 24h)
    add_test_membership(db, ip3, g2_id, false, now, now, Some(now)).await;
    // ip4 deleted in Gamma 2 days ago (within 7d)
    add_test_membership(
        db,
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
        db,
        ip5,
        g1_id,
        false,
        ten_days_ago,
        ten_days_ago,
        Some(ten_days_ago),
    )
    .await;
}

async fn assert_intersection_pagination(
    db: DatabaseConnection,
    app: axum::Router,
    now: chrono::NaiveDateTime,
) {
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
    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
        .await
        .unwrap();
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
    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
        .await
        .unwrap();
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
    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
        .await
        .unwrap();
    let isect: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(isect["total_overlap"], 2);
    assert_eq!(isect["items"].as_array().unwrap().len(), 0);

    // 3-Group intersection: Alpha, Beta, Gamma (only ip1 is in all three)
    let req = signed_request("GET", "/api/stats/intersection?groups=Alpha,Beta,Gamma", "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
        .await
        .unwrap();
    let isect3: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(isect3["total_overlap"], 1);
    assert_eq!(isect3["items"].as_array().unwrap().len(), 1);
    assert_eq!(isect3["items"][0]["target_address"], "192.168.10.1");
    let gls = &isect3["items"][0]["group_last_seen"];
    assert!(gls["Alpha"].is_string());
    assert!(gls["Beta"].is_string());
    assert!(gls["Gamma"].is_string());

    // Create an empty group Delta
    let _empty_group = add_test_group(&db, "Delta", None, now).await;

    // Intersection with Delta should return total_overlap = 0 and empty items
    let req = signed_request("GET", "/api/stats/intersection?groups=Alpha,Delta", "");
    let res = app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(res.into_body(), 64 * 1024)
        .await
        .unwrap();
    let isect_empty: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(isect_empty["total_overlap"], 0);
    assert_eq!(isect_empty["items"].as_array().unwrap().len(), 0);
}

async fn add_test_group(
    db: &DatabaseConnection,
    name: &str,
    description: Option<&str>,
    now: chrono::NaiveDateTime,
) -> Uuid {
    let id = Uuid::new_v4();
    ip_group::ActiveModel {
        id: Set(id),
        name: Set(name.to_owned()),
        description: Set(description.map(str::to_owned)),
        allow_private_ips: Set(false),
        group_type: Set("banlist".to_owned()),
        owner_key_id: Set(None),
        created_at: Set(now),
    }
    .insert(db)
    .await
    .unwrap();
    id
}

async fn seed_listing_benchmark(db: &DatabaseConnection, base: i64) -> Vec<Uuid> {
    use sea_orm::EntityTrait as _;

    let groups: Vec<_> = (1..=4).map(Uuid::from_u128).collect();
    let stamp = |seconds| {
        chrono::DateTime::from_timestamp(base + seconds, 0)
            .unwrap()
            .naive_utc()
    };
    for (index, &id) in groups.iter().enumerate() {
        ip_group::ActiveModel {
            id: Set(id),
            name: Set(format!("benchmark-{index}")),
            group_type: Set("banlist".to_owned()),
            created_at: Set(stamp(0)),
            ..Default::default()
        }
        .insert(db)
        .await
        .unwrap();
    }

    for start in (0..4096).step_by(128) {
        let fixture = (start..start + 128).map(|i| {
            let seen = stamp(i64::from(i));
            let record = Uuid::from_u128(u128::from(i + 100_u32));
            let deleted = i % 5 == 0;
            let address = ip_record::ActiveModel {
                id: Set(record),
                target_address: Set(format!("45.200.{}.{}", i / 256, i % 256)),
                created_at: Set(seen),
            };
            let membership = ip_record_group_membership::ActiveModel {
                id: Set(Uuid::from_u128(u128::from(i + 5000))),
                ip_record_id: Set(record),
                group_id: Set(groups[i as usize % groups.len()]),
                is_locked: Set(false),
                created_at: Set(seen),
                last_seen_at: Set(seen),
                is_deleted: Set(deleted),
                deleted_at: Set(deleted.then_some(seen)),
                deleted_by: Set(None),
            };
            (address, membership)
        });
        let (addresses, memberships): (Vec<_>, Vec<_>) = fixture.unzip();
        ip_record::Entity::insert_many(addresses)
            .exec(db)
            .await
            .unwrap();
        ip_record_group_membership::Entity::insert_many(memberships)
            .exec(db)
            .await
            .unwrap();
    }
    groups
}

async fn timed_listing(app: &axum::Router, label: &str, query: &str) -> Value {
    let request = signed_request("GET", &format!("/api/ips?{query}"), "");
    let started = std::time::Instant::now();
    let response = app.clone().oneshot(request).await.unwrap();
    let time = started.elapsed();
    eprintln!("{label}: {:.3} ms", time.as_secs_f64() * 1000.0);
    assert!(
        time < std::time::Duration::from_millis(250),
        "{label}: {time:?}"
    );
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 256 * 1024)
        .await
        .unwrap();
    serde_json::from_slice(&bytes).unwrap()
}

fn assert_listing(body: &Value, expected: Vec<u32>, limit: usize) {
    assert_eq!(body["total"], expected.len());
    let addresses: Vec<_> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .map(|row| row["target_address"].as_str().unwrap())
        .collect();
    let expected: Vec<_> = expected
        .into_iter()
        .take(limit)
        .map(|i| format!("45.200.{}.{}", i / 256, i % 256))
        .collect();
    assert_eq!(addresses, expected);
}

#[tokio::test]
async fn benchmark_membership_count_global_group_and_address_search() {
    let (db, app) = setup().await;
    let base = 1_700_000_000;
    let groups = seed_listing_benchmark(&db, base).await;
    let active = (0..4096).rev().filter(|i| i % 5 != 0);
    let envelope = "include_total=true&format=minimal";

    let body = timed_listing(
        &app,
        "scoped membership count with blank filters",
        &format!("{envelope}&groups=benchmark-1,benchmark-3&limit=0&ip=%20%20&cause=%20"),
    )
    .await;
    assert_listing(&body, active.clone().filter(|i| i % 2 == 1).collect(), 0);

    let since = base + 4000;
    let body = timed_listing(
        &app,
        "global recent page",
        &format!("{envelope}&limit=10&since={since}"),
    )
    .await;
    assert_listing(&body, active.clone().filter(|&i| i >= 4000).collect(), 10);

    let body = timed_listing(
        &app,
        "group recent page",
        &format!("{envelope}&group_id={}&limit=10&since={since}", groups[1]),
    )
    .await;
    assert_listing(
        &body,
        active
            .clone()
            .filter(|&i| i >= 4000 && i % 4 == 1)
            .collect(),
        10,
    );

    let body = timed_listing(
        &app,
        "address prefix page",
        &format!("{envelope}&ip=45.200.15.&limit=10"),
    )
    .await;
    assert_listing(&body, active.clone().filter(|&i| i >= 3840).collect(), 10);

    let body = timed_listing(
        &app,
        "exact address page",
        &format!("{envelope}&ip=45.200.15.23&limit=10"),
    )
    .await;
    assert_listing(&body, vec![3863], 10);

    let body = timed_listing(
        &app,
        "address infix fallback",
        &format!("{envelope}&ip=.15.23&limit=10"),
    )
    .await;
    assert_listing(
        &body,
        active
            .filter(|i| i / 256 == 15 && (i % 256).to_string().starts_with("23"))
            .collect(),
        10,
    );
}

#[tokio::test]
async fn cached_membership_count_is_invalidated_by_soft_delete() {
    let (db, app) = setup().await;
    let now = Utc::now().naive_utc();
    seed_analytics_fixture(&db, now).await;

    let before = timed_listing(
        &app,
        "count before soft delete",
        "groups=Fail2ban&limit=0&include_total=true",
    )
    .await;
    assert_eq!(before["total"], 3);
    let address = timed_listing(
        &app,
        "active membership before soft delete",
        "groups=Fail2ban&limit=1&include_total=true",
    )
    .await["data"][0]["target_address"]
        .as_str()
        .unwrap()
        .to_owned();
    let request = signed_request(
        "DELETE",
        &format!("/api/ips?group_name=Fail2ban&target_address={address}"),
        "",
    );
    assert_eq!(
        app.clone().oneshot(request).await.unwrap().status(),
        StatusCode::NO_CONTENT
    );

    let after = timed_listing(
        &app,
        "count after soft delete",
        "include_total=true&groups=Fail2ban&limit=0",
    )
    .await;
    assert_eq!(after["total"], 2);
}
