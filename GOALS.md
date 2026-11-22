# Simply IP Vault goals

`simply_ip_vault` is the internal source of truth for IP addresses and networks, their group memberships, observation times, causes, and lifecycle state. It gives operators and companion services an authenticated API for managing and reading that state, with scoped permissions and an audit trail.

## The six services

| Service | Responsibility |
| --- | --- |
| `simply_ip_vault` | Stores canonical IP and group state, enforces access, and dispatches group-scoped webhook events. |
| `simply_ip_sync` | Synchronizes records between configured sources and vaults through the vault API. |
| `simply_ip_exporter` | Reads scoped vault data and produces exports for downstream consumers. |
| `simply_fw_rules_manager` | Manages firewall rules and applies network enforcement. |
| `simply_white_list` | Owns allowlist decisions and exceptions for its consumers. |
| `simply_hook_executor` | Receives authenticated hooks and runs configured actions. |

Firewall enforcement, allowlist decision-making, peer reconciliation, export pipelines, and arbitrary hook execution belong to the companion services. The vault owns storage, access control, and event publication. Webhook delivery is best effort.

## Docker networks

Attach the vault to `isolate` by default. The sync service, exporter, and reverse proxy reach the internal vault API over that network. Publish operator access through the reverse proxy and keep the vault's own listener internal.

Attach the vault to `ext` only if outbound webhooks or remote peering require egress from the vault container. For example, a vault at `vault.example.test` can serve a local sync client over `isolate` and reach a remote receiver at `hooks.example.test` only when that receiver requires external routing.

## Security invariants

- Sign authenticated requests using CANONICAL_V1 HMAC-SHA256. The single-use replay guard rejects reuse of an accepted signature within its validity window.
- Seal secrets at rest with XChaCha20-Poly1305.
- Enforce scoped permissions and lifecycle ownership as specified in [the RBAC model](RBAC_MODEL.md).
- Apply SSRF protection to outbound webhook requests.
- Build database queries with SeaORM and SeaQuery, with zero raw SQL apart from the existing constant readiness probe.
- Forbid unsafe Rust and require `cargo audit --deny warnings` with zero ignored advisories.
