[Project goals and onboarding](GOALS.md)

# simply_ip_vault

Simply efficient. A homelab firewall.

`simply_ip_vault` is a small, self-hosted API and dashboard for centrally managing IP ban/whitelist
rules across your infrastructure. It's the single source of truth for "is this address allowed?",
and can notify other systems (or other `simply_ip_vault` instances) of changes via signed,
templated webhooks.

- **Backend:** Rust, Axum, SeaORM (SQLite by default, zero config).
- **Frontend:** a single-page dashboard in `static/` — vanilla HTML/CSS/JS, no build step, no
  external dependencies.
- **Access control:** every API key can be a full master key, or scoped with fine-grained
  per-group read/write/delete rights plus a handful of global privileges (manage keys, manage
  webhooks, create groups).

## Features

- Ban or whitelist single IPs or CIDR ranges (IPv4 and IPv6), organized into named groups.
- Re-registering an address just refreshes its `last_seen_at` — safe to call repeatedly (e.g. from
  fail2ban) without creating duplicates or erroring.
- An address can belong to multiple groups at once, including simultaneously to a `banlist` and a
  `whitelist` group; the dashboard flags that as a conflict.
- Query IPs by group, address/cause substring, ban-vs-whitelist status, or recency (`max_age`/
  `since`).
- Multi-tenant RBAC: API keys can be scoped to exactly the groups (and read/write/delete rights)
  they need.
- Webhooks: HMAC-SHA256-signed (`X-Signature-256`), templated JSON payloads, custom headers, with
  SSRF protection against private/loopback targets by default. Four auth modes — canonical signing
  (which can authenticate straight into another instance's API, with a fully customizable signed
  string), generic body-only signing, API-key-only, and unauthenticated.
- Every mutating action is recorded in an audit log.

## Getting Started

### Prerequisites

- A recent stable Rust toolchain (edition 2024).
- No database server to install — SQLite is used out of the box.

### Run it

```bash
cargo run
```

On first boot, `simply_ip_vault`:

1. Connects to the database (creating the SQLite file if needed) and runs all pending migrations
   automatically.
2. Checks whether any API key with master rights exists. If not — which is always true on a brand
   new database, and also true again if every master key is ever deleted later — it generates one
   and prints it **once**, to stdout, in a boxed banner:

   ```
   ╔══════════════════════════════════════════════════════════════════════════════════╗
   ║ BOOTSTRAP: Master API Key Generated                                              ║
   ╠══════════════════════════════════════════════════════════════════════════════════╣
   ║ X-API-Key      : <64 hex characters>                                             ║
   ║ Signing secret : <64 hex characters>                                             ║
   ║ Bound IPs      : 0.0.0.0/0                                                       ║
   ║                                                                                  ║
   ║ Both values are needed to sign requests (X-Timestamp + X-Signature-256).         ║
   ║ They will NOT be shown again — store them securely!                              ║
   ╚══════════════════════════════════════════════════════════════════════════════════╝
   ```

   Copy **both** values immediately. Only the key's SHA-256 hash is stored, and the signing secret
   is stored encrypted (or, without `VAULT_ENCRYPTION_KEY`, raw) but never echoed back — neither can
   be recovered from the API afterwards. If you lose every master credential, delete the
   corresponding rows from `api_keys` (or the whole database, for a fresh start) and restart; a new
   pair will be generated the same way.
3. Starts listening on `0.0.0.0:3000` and serves the dashboard from `static/` at `/`.

Open `http://localhost:3000` and paste **both** the key and the signing secret into the login
screen, or drive the API directly with `curl` (see below).

> **Note:** the dashboard prefers the browser's Web Crypto API, which is only exposed in a secure
> context (HTTPS or `http://localhost`). Over plain HTTP to a LAN address it transparently falls back
> to a built-in pure-JS HMAC-SHA256, so the dashboard works either way — but that fallback is not
> constant-time and your traffic is unencrypted, so TLS is still recommended.

> **Behind a reverse proxy:** the dashboard sends requests relative to wherever it is served, so a
> mount at `https://host/vault/` needs no configuration to *reach* the API. Signatures are a
> different matter — they cover the path the vault process itself sees. If your proxy strips the
> prefix (`/vault/api/ips` → `/api/ips`), leave the login screen's **API Base Path Override** blank.
> If it forwards the prefix untouched, set the override to `/vault/api`. Getting it wrong produces a
> `401` on every request, including the first.

### Configuration

All configuration is via environment variables (a `.env` file in the working directory is loaded
automatically if present):

| Variable | Default | Purpose |
| :--- | :--- | :--- |
| `DATABASE_URL` | `sqlite://simply_ip_vault.db?mode=rwc` | SeaORM connection string. |
| `BIND_HOST` / `HOST` | `0.0.0.0` | Address to bind. `BIND_HOST` wins if both are set. |
| `PORT` | `3000` | Port to bind. |
| `VAULT_ENCRYPTION_KEY` | *(unset)* | **Exactly 64 hex characters** (32 bytes) — generate with `openssl rand -hex 32`. Encrypts each API key's HMAC `signing_secret` at rest with **XChaCha20-Poly1305**. A malformed value **aborts startup** rather than degrading to plaintext. **Unset means signing secrets are stored in plaintext** — the zero-config development default, warned about at startup. Keep it: losing it makes every existing key unauthenticatable. |
| `SIGNING_SECRET_KEY` | *(unset)* | Accepted alias for the above, matching the name `simply_hook_executor` uses so one provisioning system can supply both. `VAULT_ENCRYPTION_KEY` wins when both are set. |
| `TRUSTED_PROXIES` | *(empty)* | Comma-separated CIDRs and/or hostnames permitted to set `X-Forwarded-For`/`X-Real-IP`. **Empty means no proxy is trusted** and forwarding headers are ignored entirely. A malformed entry aborts startup. Behind a reverse proxy this **must** be set, or every request resolves to the proxy's own address. |
| `BOOTSTRAP_SUBNET` | `0.0.0.0/0,::/0` | `bound_ips` assigned to the auto-generated master key. Both families by default: an IPv4-only value locks you out of a dual-stack deployment on the first request. |
| `INITIAL_MASTER_KEY` | *(unset)* | Deterministic bootstrap master key, for test/CI only. **Must be exactly 64 hex characters**; anything else aborts startup. Unset is the correct production setting — the service generates a random 256-bit key and prints it once. |
| `INITIAL_MASTER_SIGNING_SECRET` | *(unset)* | The bootstrap key's HMAC signing secret. Test/CI only, same as above. |
| `ALLOW_PRIVATE_WEBHOOKS` | `false` | Set to `true` to allow webhook targets on private/loopback/link-local addresses (useful for local testing; leave `false` in production to keep SSRF protection active). |
| `MAX_BODY_SIZE_MIB` | `10` | Largest request body accepted, in MiB. Raised from 3 for `POST /api/records/batch` — ten thousand records exceed 3 MiB comfortably. Applied to the router **and** to the middleware's signature buffer through one resolver, so the two cannot disagree. Over the limit answers `413`. Floor of 1 MiB. |
| `WEBHOOK_WORKERS` | `1` | Parallel webhook dispatch workers. Clamped to at least 1 — `0` would leave nothing draining the queue while the service looked healthy. |
| `WEBHOOK_DISPATCH_INTERVAL_MS` | `500` | Pause each worker takes **after** finishing an event. `0` disables throttling. Paces events per worker, so the aggregate ceiling is `WEBHOOK_WORKERS / interval` events per second. |
| `WEBHOOK_QUEUE_CAPACITY` | `1024` | Depth of the in-memory webhook queue. When full, events are **dropped with a warning** rather than stalling the request that produced them — see below. |
| `IP_RETENTION_DAYS` | `92` | How long a soft-deleted IP record is kept before the purge worker removes it. |
| `IP_RETENTION_SWEEP_SECONDS` | `3600` | Interval between purge sweeps. |
| `RUST_LOG` | `info` | Standard `tracing-subscriber` env filter, e.g. `debug`, `simply_ip_vault=debug`. |

Three of these abort startup rather than falling back when malformed — `VAULT_ENCRYPTION_KEY`,
`TRUSTED_PROXIES`, and `INITIAL_MASTER_KEY`. Each configures a security boundary, and the only
alternative to refusing is silently applying a boundary different from the one you wrote down. The
operational tuning variables above fail *soft* by contrast: a malformed number logs a warning and uses
the default, because throttling a notification queue wrongly is a performance choice, not a boundary.

### Webhook delivery is best-effort

The dispatch queue is bounded and **drops events when it is full**, logging each at `warn` with the
address and the configured capacity. That is deliberate. A firewall API that stops answering because a
*notification* queue backed up has its priorities inverted — the ban is the product, the webhook is a
courtesy — so the request never waits on the queue.

Throttling makes a full queue much likelier than it used to be: at the default pace one worker drains
two events per second, so a bulk operation can outrun it. If you see the warning, raise
`WEBHOOK_QUEUE_CAPACITY` or `WEBHOOK_WORKERS`, or lower `WEBHOOK_DISPATCH_INTERVAL_MS`. A consumer that
cannot tolerate loss should poll `GET /api/ips?since=…&include_deleted=true` instead — the webhook
stream has always been best-effort, and now says so.

### Docker

A `Dockerfile` and `docker-compose.yml` are included:

```bash
docker compose up --build
```

This persists the database under `./data` and exposes port `3000`. The container declares a
`HEALTHCHECK` against `GET /ready`, so `docker compose ps` reports real health and
`depends_on: condition: service_healthy` works against it.

## API Reference

### Health & readiness

Two routes sit **outside** `/api` and take no credentials at all — the only unauthenticated
endpoints in the service:

| Route | Meaning |
| :--- | :--- |
| `GET /health` (`/healthz`) | **Liveness.** `200` whenever the process is answering. Touches no dependency. |
| `GET /ready` (`/readyz`) | **Readiness.** `200` when the database answers *and* the Master identity is pinned; `503` otherwise. |

The `z` spellings are the Kubernetes-idiomatic aliases and are the same handlers, matching
`simply_hook_executor` so one set of manifests works against both services.

They are unauthenticated because the callers — Docker's `HEALTHCHECK`, a Kubernetes probe, a load
balancer — cannot compute an HMAC over a body with a rolling timestamp, and minting a long-lived key
for the platform to hold would be the worse trade. Requiring a credential would also make the probe
fail exactly when the credential store is what broke.

Because they are public they disclose as little as possible: no data, no counts, no names, **no build
version**, and never the underlying error. A failing `/ready` reports `"database":"down"` and nothing
more; the driver message goes to the log, where an operator can read it and an anonymous caller
cannot.

Keep them apart when wiring an orchestrator. A liveness probe that checked the database would make a
dependency outage trigger repeated container *restarts* — replacing a partial outage with a crash
loop. The bundled `Dockerfile` and `docker-compose.yml` probe `/ready`.

```bash
curl -s http://127.0.0.1:3000/health   # {"status":"ok","service":"simply_ip_vault"}
curl -s http://127.0.0.1:3000/ready    # {"status":"ready","database":"up"}
```

### Authenticated routes

Every route below is nested under `/api` and requires **three** headers — an API key alone is not
enough:

| Header | Value |
| :--- | :--- |
| `X-API-Key` | The plaintext key. Identifies which key record to look up. |
| `X-Timestamp` | Current UTC Unix time in seconds. Rejected if more than **300s** from the server's clock, in either direction (anti-replay). |
| `X-Signature-256` | `sha256=<hex>` — HMAC-SHA256 of the **CANONICAL_V1** string `METHOD\nTARGET\nTIMESTAMP\nRAW_BODY`, the four fields joined by single newlines with no trailing newline, keyed with the key's **signing secret**. `TARGET` is the full request target, **query string included**. The `sha256=` prefix is mandatory: a bare hex digest is rejected with `401`. |

The signing secret is issued alongside the key by `POST /api/keys` and `POST /api/keys/{id}/rotate`
and is shown **once** — it is never returned by any read endpoint. See the `call()` helper under
[Examples](#examples) for a copy-pasteable signing implementation.

Missing/invalid credentials or a stale timestamp get `401`; keys whose `bound_ips` CIDRs don't cover
the caller's (proxy-aware) source address get `403`. Master keys bypass all group/CIDR checks.

| Method | Path | Purpose |
| :--- | :--- | :--- |
| `GET` | `/api/auth/me` | Identity + effective RBAC permissions for the calling key. |
| `POST` | `/api/ban` | Add/refresh an address in a `banlist` group. |
| `POST` | `/api/white` | Add/refresh an address in a `whitelist` group. |
| `GET` | `/api/ips` | List IP records (see filters below). |
| `DELETE` | `/api/ips` | Remove an address from a group. |
| `POST` / `GET` | `/api/keys` | Create / list API keys (requires `is_master` or `can_manage_keys`). |
| `DELETE` | `/api/keys/{id}` | Delete an API key. |
| `POST` | `/api/keys/{id}/rotate` | Reissue **both** the API key and its signing secret. |
| `POST` | `/api/keys/{id}/rotate-secret` | Reissue **only** the signing secret; id, name, and permissions are unchanged. |
| `POST` | `/api/keys/{id}/groups` | Grant/update a key's read/write/delete rights on a group. |
| `POST` / `GET` | `/api/groups` | Create / list IP groups. |
| `DELETE` | `/api/groups/{id}` | Delete a group (cascades its memberships and permissions). |
| `POST` / `GET` | `/api/webhooks` | Create / list webhook configs. |
| `DELETE` | `/api/webhooks/{id}` | Delete a webhook config. |

### Webhook auth modes

Each webhook chooses how it authenticates to its receiver, via `auth_mode` on `POST /api/webhooks`
(also a dropdown in the dashboard's Webhooks tab):

| Mode | Signed message | Headers sent | Use for |
| :--- | :--- | :--- | :--- |
| `CANONICAL_V1` *(default)* | the resolved `hmac_template` | `X-Signature-256: sha256=<hex>`, `X-Timestamp`, and `X-API-Key` if set | Another `simply_ip_vault` instance, or `simply_hook_executor`. |
| `BODY_ONLY` | the raw body | `X-Signature-256: sha256=<hex>` | Generic third-party receivers (GitHub-style consumers). |
| `API_KEY_ONLY` | *(none)* | `X-API-Key` | APIs whose only credential is a bearer-style key. |
| `NONE` | *(none)* | *(none)* | Receivers authenticated by network position, or by something in `headers_json`. |

`CANONICAL_V1` with the default template uses exactly the same construction as the inbound API, which
is what makes **instance chaining** work end to end: create a key on the receiving instance, then on
the sending instance set `secret_token` to that key's signing secret, `api_key` to the key itself, and
point `target_url` at the receiver's `/api/ban`. The dispatch arrives as an ordinary signed,
timestamped API request and passes the receiver's anti-replay check.

An unrecognized `auth_mode` is rejected with `400` rather than silently downgraded, as is a mode whose
preconditions aren't met (a signing mode with no `secret_token`, `API_KEY_ONLY` with no `api_key`).
The older field name `signature_mode` is still accepted as an alias.

#### HMAC templates

In `CANONICAL_V1` mode, `hmac_template` is the exact string that gets signed. It defaults to
`{method}\n{path}\n{timestamp}\n{body}`, where `\n` is a two-character escape (expanded at dispatch
time, so the field is editable in a single-line input) and `{path}` comes from `target_url`.

Hardcoding a path in the template overrides `{path}` with no extra configuration — the case that
matters behind a reverse proxy that rewrites paths:

```
{method}\n/api/hooks/42/execute\n{timestamp}\n{body}
```

The request still goes to `target_url`, but the signature covers `/api/hooks/42/execute` — the path
the receiver actually sees, and therefore the one it will verify against. `{body}` is mandatory.

`GET /api/ips` query parameters: `groups=fail2ban,sshd` (or singular `group_name=`), `ip=<substring>`,
`cause=<substring>`, `status=ban|white`, `max_age=<seconds>`, `since=<unix timestamp>`, `limit`,
`offset`. All filters combine with AND semantics and are always narrowed by the caller's own group
permissions first.

### Examples

Requests must be signed, so these examples go through a small helper. Drop it into your shell
(requires `openssl`):

```bash
KEY="<PLAINTEXT_API_KEY>"
SECRET="<SIGNING_SECRET>"     # shown once, when the key is created or rotated

# call METHOD PATH [JSON_BODY]
call() {
  local method="$1" path="$2" body="${3:-}"
  local ts; ts=$(date -u +%s)
  # CANONICAL_V1: real newlines between the four fields, none at the end.
  # The FULL path is signed, query string included — do not strip it.
  local sig; sig=$(printf '%s\n%s\n%s\n%s' "$method" "$path" "$ts" "$body" \
                   | openssl dgst -sha256 -hmac "$SECRET" | sed 's/^.*= //')
  curl -sS -X "$method" \
    -H "X-API-Key: $KEY" -H "X-Timestamp: $ts" -H "X-Signature-256: sha256=$sig" \
    ${body:+-H "Content-Type: application/json" -d "$body"} \
    "http://localhost:3000$path"
}
```

```bash
# Who am I / what can I do?
call GET /api/auth/me

# Ban an address into the "fail2ban" group
call POST /api/ban \
  '{"target_address": "192.168.1.100", "group_name": "fail2ban", "cause": "SSH brute force"}'

# Whitelist a CIDR range
call POST /api/white '{"target_address": "10.0.0.0/24", "group_name": "vpn"}'

# List recently-seen banned IPs in specific groups
call GET "/api/ips?groups=fail2ban,sshd&status=ban&max_age=3600"

# Remove an address from a group
call DELETE "/api/ips?target_address=192.168.1.100&group_name=fail2ban"

# Create a scoped API key (returns both plaintext_key and signing_secret — copy both)
call POST /api/keys '{"name": "ci-bot", "bound_ips": "10.0.0.0/8", "can_create_groups": true}'
```

## Project structure

```
src/
├── main.rs              process entry point: startup order, graceful shutdown, master bootstrap
├── lib.rs               router assembly (create_app), state wiring, body-limit constant
├── db.rs                pool construction, SQLite session pragmas, migration execution
├── state.rs             AppState and WebhookEvent — shared, built once at startup
├── master.rs            MasterPin: boot-time Master identity, and the demotion that enforces it
├── middleware.rs        authentication: HMAC, anti-replay, bound_ips, Master-pin enforcement
├── crypto.rs            at-rest cipher (XChaCha20-Poly1305) and CANONICAL_V1 request signing
├── config.rs            env parsing, trusted proxies, X-Forwarded-For chain walk
├── replay.rs            anti-replay guard (monotonic expiry)
├── extract.rs           StrictJson / OptionalStrictJson — body rejections as typed API errors
├── error.rs             AppError and its HTTP rendering
├── dispatch.rs          outbound webhook dispatch worker (the sender)
├── retention.rs         background purge of expired soft-deleted records
├── api/                 HTTP handlers, split by domain, re-exported flat
│   ├── mod.rs           module wiring and flat re-exports — no executable code
│   ├── support.rs       plumbing used by three or more domains; decides nothing
│   ├── guards.rs        every authorization decision, and nothing else
│   ├── health.rs        unauthenticated /health and /ready probes
│   ├── keys.rs          API key identity, lifecycle, rotation, permission grants
│   ├── records.rs       ban/whitelist, listing, soft delete, restore, purge
│   ├── groups.rs        IP Group CRUD and owner reassignment
│   ├── webhooks.rs      webhook config CRUD (the configuration surface)
│   └── audit.rs         audit log listing (master-only)
├── entities/            SeaORM models, one per table
└── migration/           ordered schema migrations (immutable once applied)
```

Three pairs of names are worth disambiguating before reading:

- **`src/dispatch.rs` vs `src/api/webhooks.rs`** — the first is the background worker that *sends*
  webhooks; the second is the CRUD surface that *configures* them. The worker was `src/webhooks.rs`
  until the two names sitting one directory apart proved to be a reliable source of wrong imports.
- **`src/middleware.rs` vs `src/api/guards.rs`** — the first answers "who is calling, and may they
  call at all"; the second answers "may this caller touch *this* resource".
- **`src/api/support.rs` vs `src/api/guards.rs`** — the boundary is testable, not stylistic: nothing
  in `support.rs` inspects who is calling or returns a refusal that depends on the caller. A helper
  that starts deciding belongs in `guards.rs`.

`FILE_MAP.MD` documents every file's role, its primary exports, and the reasoning behind its
boundaries — including what each file must deliberately *not* contain.

## Development

```bash
cargo check --all-targets            # compile everything, including tests
cargo test                           # integration tests, run against sqlite::memory:
cargo clippy --all-targets -- -D warnings
```

Integration tests live in `tests/` and spin up a fresh in-memory SQLite database per test — no
external services required.

See `AGENT.MD` for the full architectural/security ruleset this project is built and audited
against, `FILE_MAP.MD` for a file-by-file map of `src/`, `SCHEMA.MD` for the database schema,
`RBAC_MODEL.md` for the normative authorization specification (shared byte-identically with
`simply_hook_executor`), [the in-repo agent skill](.agents/skills/use-ip-vault/SKILL.md) for API
operation recipes, and `AGENT_NOTES.MD` for the running audit worklog.

## License

GPLv3 — see [LICENSE](LICENSE).
