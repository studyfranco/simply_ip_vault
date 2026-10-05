# `simply_ip_vault` — Exhaustive `src/` File Map

An index of every file under `src/`, its size, and its exact purpose. Written for future agents: read
this before searching the tree, and update it when you add, remove, or repurpose a file.

**Revision:** `22d9aa4` (plus this session's uncommitted changes) · **Generated:** 2026-08-19, line counts refreshed 2026-09-28 · **Files indexed:** 50 · **Total:** ~16,330 lines. Line counts below are refreshed only for files this session or previous ones touched (`config.rs`, `db.rs`, `dispatch.rs`, `error.rs`, `groups.rs`, `lib.rs`, `main.rs`, `records.rs`, `retention.rs`, `state.rs`, `webhooks.rs`, `webhook_config.rs`, `webhook_execution.rs`, `ip_record_group_membership.rs`, the five new migrations); the rest are as of `2026-08-19` and have drifted somewhat since — treat other rows' line counts as approximate.

---

## Top-level modules

| File | Lines | Purpose |
| :--- | ---: | :--- |
| `lib.rs` | 177 | Crate root. Assembles the axum router, declares module visibility, and exposes `create_app` / `setup_state` — the two entry points integration tests build against. `/api/ip_groups` is registered as a full alias of `/api/groups` (GET/POST/DELETE plus `/{id}/owner`) for companion agents that spell it that way; both live inside `api_routes`, ahead of `.layer(auth_middleware)`, so the alias is authenticated exactly like the canonical path. |
| `main.rs` | 494 | Process entry point and nothing else. The boot sequence in strict order: connect → pragmas → migrate → bootstrap Master → **verify the encryption key opens a real sealed secret** → pin Master → build state → start workers → bind → serve → graceful shutdown. The only writer of `is_master = true` in the service. `verify_encryption_key` refuses to start rather than deferring a `VAULT_ENCRYPTION_KEY` mismatch to the first authenticated request's `500`; carries its own `#[cfg(test)]` integration tests against a real in-memory database. |
| `config.rs` | 1,792 | All environment reads, each `OnceLock`-cached and fail-soft with a warning, plus the client-IP resolution policy (trusted proxies, `X-Forwarded-For` handling). Also holds fatal validators for bootstrap credentials. Pool tuning is two-tiered: PostgreSQL/MySQL (`database_max_connections` &c., default 50/10) and file-backed SQLite (`sqlite_file_max_connections` &c., default 10/2, hard-ceilinged at 10) share the same four env var names with independent defaults. Webhook dispatch tuning (`webhook_workers` default 4, `webhook_dispatch_interval` default 50ms, `webhook_queue_capacity` default 4,096, `webhook_max_retries` default 3, `webhook_retry_backoff_ms` default 1,000) lives here too. |
| `crypto.rs` | 928 | Two responsibilities: `CANONICAL_V1` request signing (HMAC-SHA256, constant-time verification, 300 s skew window) and signing-secret encryption at rest (XChaCha20-Poly1305 via `SecretCipher`). Also `check_key_canary` — a pure, boot-time check that a configured `SecretCipher` actually opens a given stored secret, called from `main.rs::verify_encryption_key`. |
| `db.rs` | 750 | Connection pool construction, SQLite session pragmas (WAL, `synchronous=NORMAL`, `foreign_keys=ON`, `busy_timeout=10000`, `temp_store=MEMORY`), migration runner, and a dialect-aware `has_index` used by migrations. **Two-phase startup**: `run_migrations_isolated` runs every migration on a dedicated single-connection pool (every backend) that closes before `connect`'s application pool ever opens, so that pool can never witness DDL. SQLite is then two tiers: `sqlite::memory:` stays pinned to one connection unconditionally (`is_in_memory_sqlite` detects it); a file-backed URL is sized by `config::sqlite_file_max_connections`. |
| `error.rs` | 251 | `AppError` and its `IntoResponse` mapping. The single definition of the `{"error": "…"}` envelope and of which internal failures are redacted before reaching a client. `is_transient_lock_error` (private) decides `500` vs `503` for a `DbError` — lock/pool contention (SQLite `SQLITE_BUSY`/`SQLITE_LOCKED`, any extended-code variant via `& 0xFF` masking; Postgres `lock_not_available`/`serialization_failure`/`deadlock_detected`; pool timeout) is `503` with a retry-hint body, decided once here so every route gets the distinction automatically. Inline `#[cfg(test)]` unit tests reproduce a genuine busy error (a stale-snapshot write conflict via `db::connect`, not a synthetic one) rather than asserting against the enum shape alone. |
| `extract.rs` | 208 | Strict request extractors (`StrictJson`, `OptionalStrictJson`, `StrictPath`, `StrictQuery`). Makes rejection a property of the *type* rather than of a handler, so no endpoint can accidentally emit axum's default plain-text rejection. `StrictPath`/`StrictQuery` pass through axum's own rejection status (`400` for a malformed segment, `500` only for a route/handler mismatch) rather than hardcoding one — converged with `simply_hook_executor`'s wrapper of the same name. Every handler in `src/api/` uses these, never the bare axum extractors. |
| `master.rs` | 322 | Boot-time pinning of the Master key **identity** (`MasterPin`), and the per-request demotion that enforces it. Distinct from the database's uniqueness constraint, which governs *cardinality* — an attacker with DB write access does not need two Masters, only to promote itself. |
| `middleware.rs` | 328 | Authentication middleware: key lookup by hash, signature verification, timestamp validation, replay rejection, and `bound_ips` CIDR enforcement — in that order, so an unauthenticated caller cannot probe key bindings via 401-vs-403. |
| `replay.rs` | 440 | `ReplayGuard`: the single-use ledger for `CANONICAL_V1` signatures. Fails closed on a poisoned lock, and prunes only genuinely expired entries — never wholesale, which would let every live signature replay at once. |
| `state.rs` | 213 | `AppState`: the database handle, the webhook dispatch channel, and the three security singletons (`MasterPin`, `ReplayGuard`, `SecretCipher`). Carries `for_tests` so integration tests can build state without environment reads. `WebhookEvent` (the channel's payload) carries `group_name` alongside `group_id` — resolved by the caller at event-construction time, since `dispatch::prepare_dispatch` is deliberately synchronous and DB-free — so `$group_name` template substitution never needs a lookup mid-dispatch. |
| `dispatch.rs` | 1,893 | The outbound webhook dispatcher — the background worker pool that actually sends notifications, with rate limiting and the four authentication modes. Request construction (`prepare_dispatch`) is shared between the real dispatch path and `send_test_dispatch` (the live "Test Webhook" endpoint's backend), so a test exercises the exact bytes a real event would send. `target_url` and `payload_template` share one templating evaluator (`resolve_event_variables`/`substitute_placeholders`) supporting `$target_address`/`$ip`/`$action`/`$event`/`$cause`/`$group_name`/`$group_id`/`$timestamp`, single-pass with no rescanning; `CANONICAL_V1`'s signed path is derived from the resolved URL. Delivery retries transient failures (network errors, `5xx`) with exponential backoff up to `config::webhook_max_retries`; a `4xx` fails on the first attempt (`attempt_delivery`'s classification, `dispatch_with_retries_config`). **Every HTTP attempt, including retried ones, is persisted as its own `webhook_executions` row** (`log_execution`, taking a `DispatchContext`) — the delivery history behind the dashboard's Executions tab, now including the resolved target URL and the triggering event's address/cause. |
| `maintenance.rs` | 51 | Twelve-hourly SQLite housekeeping: `incremental_vacuum(1000)` then `wal_checkpoint(TRUNCATE)`, with the same shutdown-channel pattern as the retention workers. Spawned from `main.rs`. |
| `retention.rs` | 284 | Two independent background retention workers, each its own task with its own shutdown channel: `run_retention_worker` permanently drops soft-deleted IP records once they age past the configured window, and `run_webhook_execution_retention_worker` purges `webhook_executions` rows — successes after 24h, failures after 7 days, independently configurable and independently disable-able. |

## `src/api/` — HTTP handlers

| File | Lines | Purpose |
| :--- | ---: | :--- |
| `mod.rs` | 69 | Module declarations and the re-export surface the router binds against. |
| `guards.rs` | 457 | **The single place a permission decision is made.** Holds `guard_resource_lifecycle`, `guard_group_manage`, `guard_may_administer_any_group`, `guard_delegated_group_grant`, `guard_scope_elevation`, `guard_master_target`, `guard_master_immutable`. Read this before touching any authorization logic. |
| `support.rs` | 312 | Shared handler plumbing: `hash_key`, `key_prefix`, `generate_random_key`, `normalize_ip_or_cidr` (masks CIDR host bits at ingestion), and `create_audit_log` — which takes its actor **by value, not `Option`**, so an unattributed write is unrepresentable. |
| `keys.rs` | 1,374 | API key endpoints: identity (`/auth/me`), creation, listing, lifecycle, rotation, and per-group grants. Implements the §6 cascade with pre-flight inventory and resolution map. The largest handler module. |
| `records.rs` | 1,770 | IP record endpoints: ban/whitelist upsert, listing with delta (`since`) support, batch upsert/full-replace, soft delete, restore, and hard purge. `handle_ip_upsert` and `delete_ip` each combine their record write, membership write, and audit log write into one `Immediate` SQLite transaction (a concurrent-write-load tuning pass — see `AGENT.MD`'s SQLite bullets) instead of three separate implicit ones. The `WebhookEvent`s enqueued from here carry `group_name` (from the same `resolved_group_name`/`group.name` already used for audit logging) alongside `group_id`, so `dispatch::resolve_event_variables`'s `$group_name` needs no lookup of its own. `batch_records` now dispatches too — one event per record outcome, classified the same way `handle_ip_upsert` classifies its own (membership-newness, not row-newness) — unless `skip_webhooks: true` is set in the payload, buffered and enqueued only after the transaction commits. `list_ips` builds every filter into one `Condition` (every `group_id` source — RBAC scoping, `groups`/`group_name`/`group_id`, `status` — intersected in Rust into one `.is_in(...)` instead of several ANDed `IN` clauses, short-circuiting to an empty response with no query when the intersection is empty) so the same condition applies identically to the data query and, under `include_total=true`, a `{data, total, limit, offset, total_pages}` envelope's count query — a direct `.select_only()` + typed-tuple count (no subquery, no column projection), sharing one transaction with the data fetch for snapshot consistency. See `AGENT_NOTES.MD` Addendum 13 for what was verified real vs. already-false in the brief that prompted this. Since `m20260926_120000` (Addendum 14), `handle_ip_upsert`/`batch_records` **upsert** the membership row (`ON CONFLICT ... DO UPDATE SET updated_at`, `created_at` untouched on conflict) instead of only inserting it, determining `IP_ADD`/`IP_UPDATE` via an explicit pre-check read rather than an affected-row-count trick that an upsert can no longer supply; `list_ips`'s `ORDER BY` and its `since` filter's primary arm now read the membership's own `updated_at` instead of the shared `ip_records.updated_at`, and `IpRecordResponse.created_at`/`.updated_at` are populated from the membership row too — closing a bug where an address's membership in one group looked "changed" to every other group it also belonged to. |
| `groups.rs` | 214 | IP Group endpoints: creation, listing, deletion, owner reassignment. `list_ip_groups` is readable by **any** authenticated key — no `is_master`/`can_manage_keys` gate, and never has had one: Master branches on `is_master` before consulting permissions (so a group whose last manager revoked itself stays listable), and every other key is filtered to groups where it holds `can_read`, `can_write`, `can_delete` **or** `can_manage`. The `can_manage` arm is the load-bearing one — a `can_manage`-only row (`can_read: false`) is reachable via the grant API, and such a key must be able to list the group it administers. Zero accessible groups is `200 []`, never `403`. |
| `webhooks.rs` | 1,199 | Webhook config endpoints: creation, listing, update (every stored field editable, including `group_id`/`auth_mode`/`api_key`/`signature_header`/`signature_prefix` — the privileged-webhook master-only gate extends to `auth_mode`/`api_key` changes on an already-privileged webhook), deletion, owner reassignment, the four auth modes, `POST /{id}/test` (`test_webhook`), `POST /{id}/clone` (`clone_webhook` — duplicates every configuration property except `owner_key_id` (caller, not source) and `secret_token` (always freshly generated), gated by ownership plus the same privileged-webhook master-only rule `update_webhook` applies), `GET /executions` (`list_webhook_executions` — `webhook_id`/`event_type`/`is_success`/`status`/`search`/`group_id`/`ip`/`from_date`/`to_date`, all `AND`-combined with ownership scoping), and `DELETE /executions/{id}` (`delete_webhook_execution`), gated the same way as the listing. |
| `audit.rs` | 58 | Audit log query endpoint. Master-only. |
| `health.rs` | 121 | Unauthenticated liveness (`/health`, `/healthz`) and readiness (`/ready`, `/readyz`) probes. Liveness deliberately does not touch the database, so an outage cannot become a restart loop. |

## `src/entities/` — SeaORM models

| File | Lines | Purpose |
| :--- | ---: | :--- |
| `mod.rs` | 19 | Entity module declarations, mirroring the tables in `SCHEMA.MD`. |
| `prelude.rs` | 16 | Convenience re-exports of every entity type. |
| `api_key.rs` | 119 | `api_keys`: authentication tokens, global rights, CIDR bindings, lineage (`parent_key_id`), and the engine-derived `master_marker`. `signing_secret`'s doc names the actual read path (`AppState::cipher`'s `SecretCipher::open`) and cipher (XChaCha20-Poly1305). |
| `ip_record.rs` | 76 | `ip_records`: banned/whitelisted addresses and subnets, with soft-delete columns. |
| `ip_group.rs` | 87 | `ip_groups`: named collections of IP rules (`fail2ban`, `sshd`, …), each with an `owner_key_id`. |
| `webhook_config.rs` | 247 | `webhook_configs`: downstream HTTP endpoints notified on IP events, including auth mode and templating. |
| `webhook_execution.rs` | 78 | `webhook_executions`: one row per outbound HTTP attempt a webhook dispatch makes, including retries. `ON DELETE CASCADE` from `webhook_configs` — see the migration for why, unlike `audit_logs`, this table cannot use `SET NULL`. Also carries `resolved_target_url`/`target_address`/`cause` — the per-attempt event data a `target_url` template resolves against, not derivable from `webhook_configs` alone once the template can vary per event. |
| `audit_log.rs` | 66 | `audit_logs`: the mutating-operation audit trail. Attribution columns are `NOT NULL` by migration. |
| `api_key_group_permission.rs` | 70 | `api_key_group_permissions` M:N junction: per-group read/write/delete/manage rights. The table R2's conjunction is evaluated against. |
| `ip_record_group_membership.rs` | 66 | `ip_record_group_memberships` M:N junction associating records with groups. Carries its own `created_at`/`updated_at` since `m20260926_120000` — this table's own history for one (record, group) pairing, distinct from the shared `ip_records` row's own timestamps. |

## `src/migration/` — versioned DDL

| File | Lines | Purpose |
| :--- | ---: | :--- |
| `mod.rs` | 38 | Migration registry. Migrations run automatically at startup. |
| `m20230101_000001_initial_schema.rs` | 340 | Base schema: all core tables, `key_hash` declared `unique_key()` (which implies its index). |
| `m20260729_000002_add_api_key_signing_secret.rs` | 54 | Adds `api_keys.signing_secret`, the per-key HMAC secret behind `X-Signature-256`. |
| `m20260730_000003_add_webhook_signature_mode.rs` | 57 | Adds `webhook_configs.signature_mode`. |
| `m20260730_000004_add_webhook_auth_modes.rs` | 165 | Generalizes signature mode into a four-valued `auth_mode` and adds its supporting columns. |
| `m20260801_000005_add_ip_record_soft_delete.rs` | 114 | Adds `is_deleted`, `deleted_at`, `deleted_by` to `ip_records`. |
| `m20260804_000006_add_group_permission_can_manage.rs` | 66 | Adds `api_key_group_permissions.can_manage` — the per-resource half of R2's conjunction. |
| `m20260807_000007_add_api_key_master_marker.rs` | 159 | Adds `master_marker` as an **application-maintained** column. **Superseded** — retained only so the history replays. |
| `m20260807_000008_add_lineage_and_ownership.rs` | 262 | Adds `parent_key_id` and `owner_key_id`, plus the §7 hot-path indexes. |
| `m20260808_000009_derive_master_marker.rs` | 260 | Replaces the hand-maintained marker with one the **engine derives** (`GENERATED ALWAYS AS`, `STORED` on Postgres / `VIRTUAL` elsewhere). This is what satisfies `RBAC_MODEL.md` §5. |
| `m20260811_000010_audit_attribution_not_null.rs` | 287 | Makes `api_key_name`, `api_key_prefix`, `client_ip` `NOT NULL` — structurally forbidding an unattributed audit row. No peer service has an equivalent. **Backfills the `UNRECORDED` sentinel before tightening nullability**, and carries the SQLite table-rebuild path (no `ALTER COLUMN` there). The `NOT NULL` strings coexist with `api_key_id`'s `ON DELETE SET NULL` because they are different columns — denormalized copies survive the cascade. **Reference implementation for the rebuild pattern**; see `AGENT.MD` § SeaORM Migration Standards. |
| `m20260811_000011_index_ip_record_delta_columns.rs` | 72 | Indexes `ip_records.updated_at` so delta (`since`) queries do not table-scan. |
| `m20260811_000012_webhook_hmac_only_mode.rs` | 105 | Renames the `BODY_ONLY` auth mode to `HMAC_ONLY` and makes the signature header configurable. |
| `m20260824_093000_add_webhook_executions.rs` | 142 | Adds `webhook_executions` (one row per HTTP delivery attempt) with `webhook_id` `ON DELETE CASCADE` — deliberately not `SET NULL` like `audit_logs.api_key_id`, since this table has no denormalized name to fall back on and visibility is entirely join-derived through `webhook_id`. Indexes `webhook_id`, `created_at`, and a composite `(is_success, created_at)` for the retention sweep. |
| `m20260824_110000_webhook_execution_response_body.rs` | 54 | Renames `webhook_executions.error_message` -> `response_body` — the column always meant "whatever the receiver said back", not just on failure; the rename re-scopes it to match what `dispatch.rs` now actually populates it with on every attempt. |
| `m20260824_140000_webhook_execution_event_context.rs` | 83 | Adds `webhook_executions.resolved_target_url`/`target_address`/`cause` — the per-attempt event data a `target_url` template resolves against, needed once `target_url` itself became templatable. Three separate `alter_table` calls, one column each — SQLite allows only one `ADD COLUMN` per statement. |
| `m20260824_150000_add_query_performance_indexes.rs` | 134 | Adds `idx_ip_records_deleted_updated` (composite, `is_deleted`+`updated_at DESC`) and `idx_group_memberships_lookup` (composite, `group_id`+`ip_record_id`) — both verified missing via `EXPLAIN QUERY PLAN` against the query shapes production logs named as slow, and both verified to eliminate the specific plan lines (`USE TEMP B-TREE FOR ORDER BY`, `SCAN ip_record_group_memberships`) that were the actual cause. Deliberately does *not* add a bare `ip_records(updated_at)` or `audit_logs(timestamp)` index — both already exist (`m20260811_000011`, `m20230101_000001`) and a duplicate would cost every future write for no query the planner would ever prefer it over its twin for. `idx_ip_records_deleted_updated` was later dropped by `m20260926_120000` as dead weight once its one consumer moved to a different table's column — see that migration. |
| `m20260926_120000_add_membership_timestamps.rs` | 361 | Adds `created_at`/`updated_at` (`NOT NULL`) to `ip_record_group_memberships`, backfilled per-row from the referenced `ip_records` row (a full SQLite table rebuild, since a per-row-computed `NOT NULL` column can't be added with `ADD COLUMN` alone; `ALTER COLUMN`/`MODIFY COLUMN` directly on Postgres/MySQL). Drops `idx_ip_records_deleted_updated` (now unused — see above) and adds `idx_membership_group_updated` (`group_id`, `updated_at DESC`). Closes the bug where `ip_records.updated_at` being shared across every group an address belongs to made a re-ban in one group look like a change in all the others to `GET /api/ips`'s `since`/`ORDER BY`. See `AGENT_NOTES.MD` Addendum 14, including the accepted trade-off for the one query shape (a master browsing with no `group_id` filter) that still needs a temp b-tree sort. |

---

## `tests/` — what each suite is responsible for

`src/` is the subject of this map, but the suites are where its guarantees are pinned, and knowing
which file owns which property saves adding a test to the wrong one.

| File | Owns |
| :--- | :--- |
| `rbac_model_compliance.rs` | One test per `RBAC_MODEL.md` rule and section (`r1_`–`r7_`, `s3_`–`s7_`). Five are marked `ADVERSARIAL(§N)` and bypass the application layer with raw SQL. `scripts/verify_convergence.sh` fails if a rule loses its test |
| `security_tests.rs` | Named attacks, each asserting the attack fails. HMAC forgery, replay, proxy spoofing, master promotion, the unauthenticated probes. Also owns both retention sweeps' unit-level coverage (`purge_expired_ip_records`, `purge_expired_webhook_executions`) — not an attack, but the closest existing home for a pure-function DB test that needs no router |
| `schema_integrity_tests.rs` | What the **engine** does — foreign-key cascades, orphan refusal, address canonicalisation against the UNIQUE constraint, and everything `m20260811_000010`'s/`m20260926_120000`'s table rebuilds had to carry across. File-backed, opened through `db::connect`, because `PRAGMA foreign_keys` is per-connection. `upgrading_a_populated_database_backfills_every_membership_including_multi_group_ones` upgrades a database seeded with real pre-migration data — including one address linked into *two* groups at once — through `m20260926_120000`, and asserts both memberships backfill identically from the shared record, nothing is lost or duplicated, and `ON DELETE CASCADE` still functions afterward |
| `rbac_integration_tests.rs` | The features working, end to end through the router. Includes `GET /api/webhooks/executions`'s ownership scoping (`can_manage_keys` grants nothing; two different owners each see only their own webhook's executions; Master sees both) and the `parent_key_id` chain a multi-key listing carries for the dashboard's Key Lineage view |
| `source_hygiene.rs` | Properties of the source tree: no raw SQL and no hand-written DML in `src/`, outside two startup-only exemptions. Carries a meta-test proving the scanner can see a violation |
| `concurrency_and_contracts.rs` | Races and interface contracts. Replay-ledger atomicity under real thread contention, concurrent-delete idempotency, a map of the response shape returned for every kind of malformed input across every extractor (`StrictJson`/`StrictPath`/`StrictQuery`, all in the `{"error": …}` envelope), and `deny_unknown_fields` refused across every domain payload (groups, ban, white, webhooks). Name shared with the peer's suite of the same purpose |
| `frontend_syntax_test.rs` | `static/app.js` parses. Nothing else compiles or executes it |

**`source_hygiene.rs` deliberately duplicates `verify_convergence.sh::check_no_raw_sql`**, and the two
are not interchangeable. The shell gate has to be *run*; the Rust test runs on every `cargo test`, in
CI and in an IDE. More to the point, two successive versions of the shell gate were silently broken —
one used a gawk extension that is an always-false variable under `mawk`, the other exempted anything
near the word "pragma" — and each reported CLEAN against a deliberately planted violation. Both
failures were invisible because neither had a meta-test. This file has one.

---

## `static/` and `scripts/` — outside this map's `src/` scope, noted briefly

This map indexes `src/`; the dashboard (`static/index.html`, `app.js`, `style.css`, ~5,600 lines)
and the E2E harness (`scripts/test_e2e.sh`, ~3,600+ lines / 629 checks) are large enough to deserve
their own maps if they keep growing, but do not have one yet. Four things worth knowing without
reading either in full:

- **`PagedCache` (`app.js`) is the one generic paginator behind IP Records, Audit Logs, and now
  Executions** — server-fetched 100 rows at a time, paginated locally 15 at a time, with background
  prefetch. A new paginated tab needs only a `fetchChunk` function and the four
  render/pagination-update boilerplate calls (`loadFirstChunk`/`currentPageItems`/`hasNextPage`/
  `hasPrevPage`); it does not need a new pagination implementation. `executionsCache` is the
  reference example to copy for the next one. `fetchChunk` may optionally return
  `{items, total}` instead of a bare array when its endpoint can report an exact server-side
  count (`fetchIpsChunk` does, via `GET /api/ips?include_total=true`); `PagedCache._absorbChunk`
  normalizes either shape and remembers `serverTotal` for accurate pagination-footer display. A
  fetcher that just returns an array (`fetchAuditLogsChunk`, `fetchExecutionsChunk`) needs no
  changes — `serverTotal` simply stays `null` and the old "N+" estimate keeps rendering.
- **The Webhooks tab's create form and its Edit modal each own a separate custom-headers editor.**
  `app.js`'s `renderHeaderRows`/`addHeaderRow`/`headerMap` back the always-visible create form
  (`webhookHeaders` state, `#webhook-headers-list`); `renderEditHeaderRows`/`addEditHeaderRow`/
  `editHeaderMap` are their near-identical twin for the Edit Webhook modal (`editWebhookHeaders`
  state, `#edit-webhook-headers-list`) — kept separate rather than parametrized because the create
  form is always present in the DOM while the modal only overlays it, so a shared array would let
  opening one for editing clobber whatever the create form had half-typed.

- **A flex container blockifies every element child, not only the ones meant to occupy their own
  line.** `static/style.css`'s `.auth-mode-hint` is `display: flex; flex-direction: column` so its
  two intended lines stack; an unwrapped `<strong>`/`<code>` sitting as a *direct* child gets the
  same treatment as the `<em>` line and lands on its own line too, fragmenting a sentence one word
  at a time. `static/app.js`'s `AUTH_MODE_HINTS` wraps everything but the trailing `<em>` in one
  `<span class="hint-lead">` for exactly this reason — do the same for any future hint added there.
- **`scripts/test_e2e.sh` §31 builds and boots a real `example/simply_hook_executor`** as a second
  live service, not a capture script — the one section in the suite that proves a sibling service
  actually *accepts* what the vault sends, rather than only capturing the bytes. Degrades to a
  warning + skip if that checkout is absent, matching §13's `python3` soft-dependency pattern.
- **`.container`'s width is fluid up to an 1800px cap** (`max-width: 1800px; padding: 2rem
  clamp(1rem, 3vw, 4rem)`), converged with `simply_hook_executor` — a fixed `1280px` previously
  left several hundred pixels of dead margin on anything wider than a laptop screen.
- **`SearchableSelect.openMenu()` (`app.js`) repositions itself, it does not just toggle
  visibility.** A combobox can sit anywhere on a scrollable page — "Manage Group Rights" in the
  API Keys tab is often the last control before the fold — and the menu used to always open
  downward at a fixed 220px with no check for whether that fit. `positionMenu()` measures the
  actual room above/below the input each time the menu opens and flips to whichever side has more
  (via a `.combobox-menu-above` class swapping `top`/`bottom`), capping `max-height` inline to
  whatever is actually available rather than the fixed value. Applies to every `SearchableSelect`
  instance (group filters, webhook target-group pickers, "Manage Group Rights") with no per-caller
  changes needed.

## Reading order for a new agent

1. `RBAC_MODEL.md` — the normative rules everything below implements.
2. `SCHEMA.MD` — the tables those rules are enforced against.
3. `src/api/guards.rs` — where every permission decision is actually made.
4. `src/middleware.rs` — how a request is authenticated before any guard runs.
5. `src/master.rs` — why Master identity and Master cardinality are separate properties.
6. The handler module for whatever you are changing.

`API_REFERENCE.md` (repository root) catalogs every HTTP endpoint — path, aliases, RBAC guard, query
parameters, request DTO, and response schema — derived from `src/lib.rs`'s router and the handlers
under `src/api/`. It is the fastest way to see the whole surface at once, and the right file to
update in the same commit as any route change.

## Migration conventions

Full standards live in `AGENT.MD` § *SeaORM Migration Standards*. The two that cause damage if missed:

- **Never rename an applied migration.** `#[derive(DeriveMigrationName)]` derives identity from the
  file name and SeaORM stores it in `seaql_migrations`. A rename makes an applied migration look
  unapplied and it re-runs on next boot.
- **The existing 12 files use a six-digit sequence** (`_000010_`), not `HHMMSS`. They are grandfathered.
  New migrations use `mYYYYMMDD_HHMMSS_name.rs`.

## Invariants that are easy to break

- **`create_audit_log` takes its actor by value.** Do not make it `Option`; an unattributed write must stay unrepresentable.
- **`master_marker` is engine-derived and must never become settable** on any entity, fixture, or test helper (`RBAC_MODEL.md` §5).
- **Migrations run only through `db::run_migrations_isolated`, on a single-connection pool, closed before `db::connect`'s application pool ever opens.** A file-backed SQLite application pool may legitimately hold more than one connection now (`config::sqlite_file_max_connections`) — that is safe *because* migration isolation guarantees it never sees DDL, not because the pool is capped at one. `sqlite::memory:` is the one tier still pinned to exactly one connection unconditionally (a second in-memory connection is a second, empty database). Do not add a second `run_migrations` call against the wide application pool "for safety" — see `src/db.rs`'s module header for why that would reintroduce the race it exists to prevent.
- **An explicit transaction that reads before it writes needs `SqliteTransactionMode::Immediate`, not a plain `.begin()`.** Now that a file-backed SQLite pool can hold more than one connection, a `BEGIN DEFERRED` transaction (the default) that does a `SELECT` before its first write can have its read snapshot go stale if another connection commits in between — and SQLite refuses the write-lock upgrade with `SQLITE_BUSY` *immediately*, without the `busy_timeout` handler ever retrying. `api::records::batch_records` hit exactly this while the pool was being widened; see `AGENT.MD`'s database section for the fix and when it applies.
- **Guards live in `guards.rs`.** An inline permission check in a handler is drift, and it is what separates the converged peers from the diverging one.
- **Every handler takes `StrictJson`/`StrictPath`/`StrictQuery`, never the bare axum extractor.** A single bare `Path<Uuid>` left in a new handler is one route where a malformed input answers `text/plain` instead of `{"error": …}` — `tests/concurrency_and_contracts.rs::malformed_input_is_refused_on_every_extractor` asserts this across the whole crate for exactly that reason.
- **New request-payload structs need `#[serde(deny_unknown_fields)]`.** The one exception is a struct with a `#[serde(flatten)]` field — serde refuses to compile the two together; put the annotation on the flattened type instead (see `keys.rs`'s `Resolution`/`ResolutionEntry`).
