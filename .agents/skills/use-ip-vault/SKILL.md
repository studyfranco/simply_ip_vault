---
name: use-ip-vault
description: Operate and integrate with simply_ip_vault — CANONICAL_V1 HMAC-SHA256 request signing, reverse-proxy OriginalUri path handling, Master vs Scoped RBAC, IP records/groups/banlists/webhooks cookbook, and isolate/ext network boundaries.
---

# Using `simply_ip_vault`

`simply_ip_vault` is the central source of truth for IP addresses, CIDR ranges, group memberships (`banlist` / `whitelist`), observation timestamps, causes, and webhook event dispatch.

## 1. Network & Trust Boundaries (`isolate` vs `ext`)

- **`isolate` (default):** Attach `simply_ip_vault` to the internal `isolate` network. Companion services (`simply_ip_sync`, `simply_ip_exporter`) and the reverse proxy reach `/api/*` over `isolate`; keep the vault's own listener internal.
- **`ext` (egress only when needed):** Attach `ext` only if outbound webhooks or remote peering must reach external destinations (for example, `hooks.example.test`).
- **Reverse proxy (`TRUSTED_PROXIES`):** Empty by default (forwarding headers ignored). Behind a proxy, set `TRUSTED_PROXIES` to the proxy's CIDR or hostname so `X-Forwarded-For` / `X-Real-IP` resolve the real client IP for `bound_ips` and audit logs.

## 2. Authentication (`CANONICAL_V1` HMAC-SHA256)

Every `/api/*` endpoint requires three headers (health probes `/health`, `/ready`, `/healthz`, `/readyz` are unauthenticated):

| Header | Format | Notes |
| :--- | :--- | :--- |
| `X-API-Key` | 64-char hex plaintext key | Used to look up the key by SHA-256 hash. |
| `X-Timestamp` | UTC Unix seconds (integer string) | Must be within `MAX_TIMESTAMP_SKEW_SECS` (300s) of server time. |
| `X-Signature-256` | `sha256=<hex>` | `sha256=` prefix is required; bare hex is rejected. |

Canonical string signed with the key's `signing_secret` (`HMAC-SHA256`):

```text
METHOD\nTARGET\nTIMESTAMP\nRAW_BODY
```

- `METHOD`: Uppercase HTTP verb (`GET`, `POST`, `PUT`, `DELETE`).
- `TARGET`: Full request path **plus** query string if present (for example `/api/ips?group=fail2ban`).
- `TIMESTAMP`: Exact raw `X-Timestamp` header string.
- `RAW_BODY`: Exact request body bytes (empty string `""` for bodyless `GET`/`DELETE`).
- **Anti-replay:** `ReplayGuard` enforces single-use signatures within the timestamp window; reusing a signature returns `401 Unauthorized`.

### Reverse-Proxy `OriginalUri` Subpath Rule

`auth_middleware` derives `TARGET` from Axum's `OriginalUri` (the URI seen by the vault process):

- If the proxy **strips** the mount prefix (`/vault/api/ips` → `/api/ips`), sign `/api/ips` (leave dashboard **API Base Path Override** blank).
- If the proxy **forwards** the prefix untouched (`/vault/api/ips` → `/vault/api/ips`), sign `/vault/api/ips` (set dashboard **API Base Path Override** to `/vault/api`).

### Example Signed `curl` Request

```bash
METHOD="POST"
TARGET="/api/ban"
TS="$(date -u +%s)"
BODY='{"address":"198.51.100.42","group_name":"fail2ban","cause":"ssh-bruteforce"}'
SIG=$(printf '%s\n%s\n%s\n%s' "$METHOD" "$TARGET" "$TS" "$BODY" \
  | openssl dgst -sha256 -hmac "$SIGNING_SECRET" -hex | awk '{print $NF}')

curl -sS -X "$METHOD" "https://vault.example.test${TARGET}" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: ${API_KEY}" \
  -H "X-Timestamp: ${TS}" \
  -H "X-Signature-256: sha256=${SIG}" \
  -d "$BODY"
```

## 3. RBAC Model (Master vs Scoped)

- **Master key:** Exactly one `is_master` key is pinned at boot (`MasterPin`). Holds all global and per-group rights, including group/webhook ownership reassignment (`PUT /api/groups/{id}/owner`, `PUT /api/webhooks/{id}/owner`) and purge (`POST /api/system/purge-ips`).
- **Scoped keys:** Governed by global flags (`can_manage_keys`, `can_manage_webhooks`, `can_create_groups`) and per-group grants (`can_read`, `can_write`, `can_delete`, `can_manage`).
- **Lifecycle ownership:** Deleting or renaming a group or webhook is restricted to Master or its `owner_key_id`.
- **Source network binding:** `bound_ips` (comma-separated CIDRs, for example `192.0.2.0/24,2001:db8::/32`) is enforced after HMAC verification for every key, including Master.

## 4. API Cookbook

### IP Records, Bans, Whitelists & Batch Sync

- `POST /api/ban` — Upsert an IP/CIDR (for example `198.51.100.42`, `2001:db8:1::/48`) into a `banlist` group with optional `cause`. Re-registering refreshes `last_seen_at`.
- `POST /api/white` — Upsert an IP/CIDR into a `whitelist` group.
- `POST /api/records/batch` — Transactional bulk sync (supports `full_replace` mode for `simply_ip_sync`).
- `GET /api/ips` — Query active records (filter by group, substring, ban/whitelist type, `since` / `max_age`).
- `DELETE /api/ips` — Soft-delete a membership by address and group.
- `POST /api/ips/restore` — Restore a soft-deleted membership.
- `POST /api/system/purge-ips` — Master-only immediate purge of soft-deleted records.

### Groups & Permissions

- `GET /api/groups` / `POST /api/groups` (aliases: `/api/ip_groups`) — List or create groups (`group_type`: `"banlist"` or `"whitelist"`). Banlist groups support `allow_private_ips` (opt-in for RFC1918/CGNAT/ULA) and `excluded_whitelist_ids` (list of whitelist group IDs whose active ranges cannot be banned in that banlist).
- `PUT /api/groups/{id}` / `DELETE /api/groups/{id}` — Update or delete a group (Master or `owner_key_id`). Updating `excluded_whitelist_ids` on a banlist—as well as adding, batch-upserting, or restoring an IP/CIDR on a linked whitelist—automatically and retroactively soft-deletes any overlapping active bans in linked banlists and emits `IP_DELETE` webhooks (`cause`: `"Excluded by whitelist <name>"`, respecting `skip_webhooks` on batch).
- `PUT /api/groups/{id}/owner` — Reassign group ownership (Master only).
- `POST /api/keys/{id}/permissions` (legacy alias: `/api/keys/{id}/groups`) — Grant/update per-group `can_read`/`can_write`/`can_delete`/`can_manage`.
- `DELETE /api/keys/{id}/permissions/{group_identifier}` — Revoke a key's grant on a group.

### API Keys & Secret Rotation

- `GET /api/auth/me` — Inspect the calling key's identity and effective permissions.
- `GET /api/keys` / `POST /api/keys` — List or create scoped API keys (returns `plaintext_key` and `signing_secret` once).
- `PUT /api/keys/{id}` / `DELETE /api/keys/{id}` — Update metadata/scopes or delete a key.
- `POST /api/keys/{id}/rotate` — Rotate the API key (`X-API-Key`).
- `POST /api/keys/{id}/rotate-secret` — Rotate only the HMAC `signing_secret`.

### Webhooks & Delivery History

- `GET /api/webhooks` / `POST /api/webhooks` — List or create group-scoped webhooks.
  - Auth modes: `CANONICAL_V1` (default, customizable `hmac_template`), `HMAC_ONLY`, `API_KEY_ONLY`, `NONE`.
  - SSRF protection blocks private/loopback/link-local targets unless `ALLOW_PRIVATE_WEBHOOKS=true` (local testing only).
- `PUT /api/webhooks/{id}` / `DELETE /api/webhooks/{id}` — Update or delete a webhook.
- `POST /api/webhooks/{id}/test` — Send a test dispatch.
- `POST /api/webhooks/{id}/clone` — Clone an existing webhook configuration.
- `GET /api/webhooks/executions` / `DELETE /api/webhooks/executions/{id}` — Inspect or delete delivery history.

### Audit & Analytics

- `GET /api/audit-logs` — Query the mutating-operation audit trail.
- `GET /api/stats/analytics` / `GET /api/stats/intersection` — Group analytics and banlist/whitelist overlap stats.

## 5. Safety Guardrails

- **Never** commit, log, or paste real `X-API-Key`, `signing_secret`, `VAULT_ENCRYPTION_KEY`, or production IPs/domains. Use RFC 5737 (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), RFC 3849 (`2001:db8::/32`), and RFC 2606 (`*.example.test`) in examples and tests.
- Keep `VAULT_ENCRYPTION_KEY` (64 hex chars) backed up; losing it makes sealed `signing_secret` rows unauthenticatable at startup.
- Keep `ALLOW_PRIVATE_WEBHOOKS=false` in production.
