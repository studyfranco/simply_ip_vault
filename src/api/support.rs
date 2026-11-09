//! Shared plumbing every handler module leans on.
//!
//! This module exists because a handful of helpers are used by *three or more* of the handler
//! domains each — hashing a credential, normalising an address, writing an audit row, resolving a
//! group by id-or-name, formatting a reference for a log line. Pushing any of them into a domain
//! module would make every other domain depend on that one; leaving them in [`super`] made
//! `api/mod.rs` a 267-line file that was declarations, router surface, and a utility drawer at once.
//!
//! **Nothing here makes an authorization decision.** That is the boundary against [`super::guards`],
//! and it is testable rather than stylistic: no function in this file inspects *who* is calling or
//! returns a refusal that depends on the caller. A helper that starts deciding belongs in `guards`
//! instead — otherwise that module comes to mean "guards, plus everything else that happened to be
//! shared", which is the monolith problem again one level down.

use chrono::Utc;
use ipnet::IpNet;
use rand::RngExt;
use sea_orm::{ActiveValue::Set, ColumnTrait, EntityTrait, QueryFilter, sea_query::OnConflict};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::entities::{api_key, audit_log, ip_group};
use crate::error::AppError;

/// The three webhook-filterable IP mutation actions, in the vocabulary shared by
/// `audit_log::Model::action` and `webhook_config::Model::events`.
pub(crate) const IP_EVENT_ACTIONS: [&str; 3] = ["IP_ADD", "IP_UPDATE", "IP_DELETE"];

// `MASTER_MARKER` used to live beside these: the string `bootstrap_master_key` wrote into
// `api_keys.master_marker` to claim the unique index. It is gone because the column is now
// `GENERATED ALWAYS AS (CASE WHEN is_master THEN 1 ELSE NULL END)` and no client may write it
// (`RBAC_MODEL.md` §5, `migration::m20260808_000009_derive_master_marker`). Application code holding
// a constant for a value the engine derives is the arrangement that let a writer set `is_master`
// and leave the marker NULL. There is nothing here to keep in step any more.

// ─────────────────────────────────────────────────────────────
// Credential primitives
// ─────────────────────────────────────────────────────────────
//
// `pub` rather than `pub(crate)` because the integration suites mint keys directly against the
// database — a test hashes a plaintext exactly as the service would, which is the only way to seed a
// key whose secret the test already knows.

/// Generates a random 32-byte hex key for API authentication
pub fn generate_random_key() -> String {
    let bytes: [u8; 32] = rand::rng().random();
    hex::encode(bytes)
}

/// Hashes an API key using SHA-256 for secure storage
pub fn hash_key(key: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(key.as_bytes());
    hex::encode(hasher.finalize())
}

// ─────────────────────────────────────────────────────────────
// Address normalization
// ─────────────────────────────────────────────────────────────

/// Canonicalizes an IP address or CIDR string so the same target always has exactly one string
/// representation, regardless of how the caller wrote it.
///
/// `ip_records.target_address` is UNIQUE, so this function is what decides whether two spellings are
/// one rule or two. That makes it a schema concern as much as a formatting one.
///
/// Two normalisations, and they pull in opposite directions on purpose:
///
/// | Input | Output | Why |
/// | :--- | :--- | :--- |
/// | `1.2.3.4/32`, `2001:db8::1/128` | `1.2.3.4`, `2001:db8::1` | A prefix covering exactly one host says nothing the address does not. Dropping it stops `X/32` and `X` being two rows for one host |
/// | `192.168.1.50/24` | `192.168.1.0/24` | **Host bits are masked off.** `…50/24` and `…100/24` name the *same network*, and a network rule is about the network |
/// | `2001:db8::fe/64` | `2001:db8::/64` | Same rule, v6 |
/// | `192.168.1.130/25` | `192.168.1.128/25` | Masking is by prefix length, not by octet boundary |
///
/// # Why host bits are masked
///
/// A subnet ban is a statement about a range. Two clients writing `10.0.0.5/8` and `10.9.9.9/8` mean
/// the identical rule, and storing them separately produced two rows with independent lifecycles:
/// banning through one and unbanning through the other left the range still blocked, with nothing in
/// the API to show why. Masking makes the UNIQUE constraint do the deduplication instead of leaving
/// it to whoever typed the address.
///
/// This **changed** in Session 55. Host bits were previously preserved, and the reasoning recorded at
/// the time — that `IpNetwork::ip()` returns the address as parsed, so a rule stayed exactly as
/// written — described the mechanism rather than defending the outcome. Existing rows written in
/// non-masked form are not rewritten by this change; migrating them is an administrative step.
///
/// # Infallible by design
///
/// Input that does not parse as an address or CIDR is returned unchanged. This function normalises,
/// it does not validate — callers that must reject malformed input parse it themselves (see
/// [`super::records::guard_bannable_address`] and the batch endpoint, which both do), and callers
/// using it for a best-effort match need a bare fragment like `"74.128"` to pass through untouched.
/// Parses a string as either a CIDR network or a bare IP address, promoting bare addresses
/// to `/32` or `/128`.
pub fn parse_cidr_or_ip(raw: &str) -> Result<IpNet, ()> {
    let trimmed = raw.trim();
    if let Ok(net) = trimmed.parse::<IpNet>() {
        return Ok(net);
    }
    if let Ok(addr) = trimmed.parse::<std::net::IpAddr>() {
        return Ok(IpNet::from(addr));
    }
    Err(())
}

/// Normalizes a bare IP address or CIDR subnet to a canonical string form (`/32`/`/128` singles
/// stored without a prefix, everything else keeps its prefix length and masks host bits).
pub fn normalize_ip_or_cidr(input: &str) -> String {
    let trimmed = input.trim();
    if let Ok(net) = trimmed.parse::<IpNet>() {
        let is_single_host = (net.addr().is_ipv4() && net.prefix_len() == 32)
            || (net.addr().is_ipv6() && net.prefix_len() == 128);
        if is_single_host {
            net.addr().to_string()
        } else {
            format!("{}/{}", net.network(), net.prefix_len())
        }
    } else if let Ok(ip) = trimmed.parse::<std::net::IpAddr>() {
        ip.to_string()
    } else {
        input.to_owned()
    }
}

// ─────────────────────────────────────────────────────────────
// Audit trail
// ─────────────────────────────────────────────────────────────

/// Formats a target API key for a human-readable audit log `details` string, e.g.
/// `"'worker_bot' (65cf11ce...)"` — pairs the name (what an operator actually recognizes) with a
/// truncated id (for unambiguous cross-referencing against a `GET /api/keys` listing) instead of
/// a bare UUID, which was cryptic on its own.
///
/// Lived in [`super::guards`] until the structural audit: it decides nothing and refuses nobody, it
/// just renders a string, and five of its seven call sites are outside that module.
pub(crate) fn format_key_reference(name: &str, id: Uuid) -> String {
    let id_str = id.to_string();
    format!("'{name}' ({}...)", &id_str[..8])
}

/// Helper to insert an audit log entry. `key` denormalizes the acting key's name/prefix into the
/// row so the audit trail stays legible even after that key is later deleted (its `api_key_id` FK
/// is `ON DELETE SET NULL`, per `SCHEMA.MD`, but the name/prefix survive as a point-in-time
/// snapshot rather than a live join). `client_ip` is the resolved caller address from
/// [`crate::middleware::ClientIp`].
///
/// # Attribution is required, not defaulted
///
/// `key` and `client_ip` are taken **by value rather than as `Option`**, and that is the control
/// rather than an ergonomic preference. `m20260811_000010` made the three attribution columns
/// `NOT NULL`; the obvious way to satisfy that would have been to keep the `Option`s and substitute
/// `"anonymous"` / `"unknown"` when they are `None`. That would be strictly worse. A fallback string
/// makes an unattributed write *succeed*, so the first caller that has no key — a future background
/// job, a system event, a handler mounted outside `auth_middleware` — silently produces rows that
/// satisfy the constraint and attribute nothing. The column would be `NOT NULL` and the audit trail
/// would still have holes in it.
///
/// Taking them by value makes that call impossible to write instead. Every audited route already
/// runs behind [`crate::middleware::auth_middleware`], which resolves both before a handler sees the
/// request, so all twenty call sites satisfy this today with no fallback needed — the `Option`s were
/// never `None` in practice, only in the type.
///
/// The fallback exists exactly once, in the migration's backfill, where it is genuinely needed for
/// rows written before the constraint. A future system-event writer should get its own function with
/// its own explicit actor, not a `None` threaded through this one.
///
/// # Generic over the connection
///
/// Takes any [`ConnectionTrait`](sea_orm::ConnectionTrait), so it can be called with a
/// `DatabaseTransaction` as readily as with the pool. That matters for the batch endpoint — and, as
/// of the concurrent-write-load tuning pass, `handle_ip_upsert`/`delete_ip` too: an audit row
/// written outside the transaction it describes would survive a rollback and claim an operation
/// that never happened, which is worse than no row at all — a trail that lies is not a trail.
///
/// # Deliberately not backgrounded
///
/// Production logs once showed `INSERT INTO audit_logs` itself taking 1-2s under write contention,
/// which reads like an argument for moving the write off the request's own critical path (a spawned
/// task, a channel to a dedicated writer). That was rejected: a caller who receives `200 OK` before
/// their audit row is confirmed durable has no way to know whether it ever will be — a crash between
/// responding and the background write landing loses the record silently, and (worse, for the
/// endpoints this row now shares a transaction with) a background write is definitionally outside
/// whatever transaction the operation it describes runs in, reopening exactly the "trail that lies"
/// problem above. The actual measured cause was three separate write-lock acquisitions per logical
/// request (the record write, the membership write, and this one, each its own implicit
/// transaction), not slow disk I/O on this statement specifically — see `handle_ip_upsert`'s and
/// `delete_ip`'s own comments for the fix that follows from that: one `Immediate` transaction
/// instead of three deferred ones, which cuts the lock-acquisition count without cutting the
/// durability guarantee.
pub(crate) async fn create_audit_log<C: sea_orm::ConnectionTrait>(
    db: &C,
    key: &api_key::Model,
    client_ip: std::net::IpAddr,
    action: &str,
    target_address: Option<String>,
    group_names: Option<String>,
    details: Option<String>,
) -> Result<(), AppError> {
    let log = audit_log::ActiveModel {
        id: Set(Uuid::new_v4()),
        api_key_id: Set(Some(key.id)),
        api_key_name: Set(key.name.clone()),
        api_key_prefix: Set(key.prefix.clone()),
        client_ip: Set(client_ip.to_string()),
        action: Set(action.to_owned()),
        target_address: Set(target_address),
        group_names: Set(group_names),
        details: Set(details),
        timestamp: Set(Utc::now().naive_utc()),
    };
    audit_log::Entity::insert(log).exec(db).await?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────
// Group resolution
// ─────────────────────────────────────────────────────────────

/// Fetches an `IpGroup` by name, creating it with `default_group_type` if it doesn't exist yet.
///
/// Concurrency-safe: naively doing a `find` followed by a plain `insert` races when two requests
/// both observe the group as missing and both try to create it — `ip_groups.name` is unique, so
/// the loser gets a raw constraint-violation `500` instead of just using the winner's row. This
/// uses `on_conflict(...).do_nothing()` for the insert and always re-reads by name afterwards, so
/// either outcome (we created it, or a concurrent request beat us to it) converges on the same
/// canonical row.
///
/// `owner` becomes the group's `owner_key_id` when this call is the one that creates it, per §3.
/// When a concurrent request wins the race the existing row's owner is left alone — ownership belongs
/// to whoever actually created the resource, and the loser of a race did not.
pub(crate) async fn get_or_create_group(
    db: &sea_orm::DatabaseConnection,
    name: &str,
    default_group_type: &str,
    owner: Option<Uuid>,
) -> Result<ip_group::Model, AppError> {
    let new_group = ip_group::ActiveModel {
        id: Set(Uuid::new_v4()),
        name: Set(name.to_owned()),
        group_type: Set(default_group_type.to_owned()),
        description: Set(None),
        owner_key_id: Set(owner),
        created_at: Set(Utc::now().naive_utc()),
    };
    ip_group::Entity::insert(new_group)
        .on_conflict(OnConflict::column(ip_group::Column::Name).do_nothing().to_owned())
        .exec_without_returning(db)
        .await?;

    ip_group::Entity::find()
        .filter(ip_group::Column::Name.eq(name))
        .one(db)
        .await?
        .ok_or(AppError::Internal)
}

/// Resolves a group given an optional `group_id` and/or `group_name`; exactly one must be
/// supplied. Returns `Ok(None)` if the identifier doesn't match any existing group — the caller
/// decides whether that means "404" (for `group_id`, which is never client-inventable) or
/// "auto-create it" (for `group_name`, the only identifier a client can pick with permission).
pub(crate) async fn resolve_group_ref(
    db: &sea_orm::DatabaseConnection,
    group_id: Option<Uuid>,
    group_name: Option<&str>,
) -> Result<Option<ip_group::Model>, AppError> {
    match (group_id, group_name) {
        (Some(_), Some(_)) => Err(AppError::InvalidInput(
            "Provide either group_id or group_name, not both".to_owned(),
        )),
        (None, None) => Err(AppError::InvalidInput(
            "Either group_id or group_name is required".to_owned(),
        )),
        (Some(gid), None) => Ok(ip_group::Entity::find_by_id(gid).one(db).await?),
        (None, Some(name)) => Ok(ip_group::Entity::find()
            .filter(ip_group::Column::Name.eq(name))
            .one(db)
            .await?),
    }
}

/// Resolves a group from a single path segment that may be either a UUID or a literal name —
/// used for the `DELETE .../permissions/{group_identifier}` route, where REST path conventions
/// only allow one placeholder rather than separate `group_id`/`group_name` fields.
pub(crate) async fn resolve_group_by_identifier(
    db: &sea_orm::DatabaseConnection,
    identifier: &str,
) -> Result<Option<ip_group::Model>, AppError> {
    if let Ok(id) = Uuid::parse_str(identifier)
        && let Some(g) = ip_group::Entity::find_by_id(id).one(db).await?
    {
        return Ok(Some(g));
    }
    Ok(ip_group::Entity::find()
        .filter(ip_group::Column::Name.eq(identifier))
        .one(db)
        .await?)
}

/// Resolves a group given an optional flexible `group_id` and/or `group_name`; exactly one must
/// be supplied. Unlike [`resolve_group_ref`], `group_id` here is a plain string rather than a
/// strictly-typed UUID: a client that passes a group's name into the `group_id` field (or a UUID
/// into it, which also works) gets a correct lookup instead of Axum rejecting the request with a
/// `422` before this code ever runs. Never auto-creates via `group_id`, matching
/// [`resolve_group_by_identifier`]'s semantics — only `group_name` can create.
pub(crate) async fn resolve_group_ref_flexible(
    db: &sea_orm::DatabaseConnection,
    group_id: Option<&str>,
    group_name: Option<&str>,
) -> Result<Option<ip_group::Model>, AppError> {
    match (group_id, group_name) {
        (Some(_), Some(_)) => Err(AppError::InvalidInput(
            "Provide either group_id or group_name, not both".to_owned(),
        )),
        (None, None) => Err(AppError::InvalidInput(
            "Either group_id or group_name is required".to_owned(),
        )),
        (Some(identifier), None) => resolve_group_by_identifier(db, identifier).await,
        (None, Some(name)) => Ok(ip_group::Entity::find()
            .filter(ip_group::Column::Name.eq(name))
            .one(db)
            .await?),
    }
}

// ─────────────────────────────────────────────────────────────
// Shared payloads
// ─────────────────────────────────────────────────────────────

/// Payload for reassigning a resource's owner. `owner_key_id: null` clears ownership, returning the
/// resource to Master-only lifecycle authority.
///
/// Shared rather than duplicated: `PUT /groups/{id}/owner` and `PUT /webhooks/{id}/owner` live in
/// different domain modules and must accept exactly the same body, and two copies of a payload
/// struct are two things to keep `deny_unknown_fields` in step across.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReassignOwnerPayload {
    /// The key to make the new owner, or `null` to leave the resource unowned.
    pub owner_key_id: Option<Uuid>,
}
