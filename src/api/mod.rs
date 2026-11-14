//! API endpoints and business logic.
//!
//! Every handler here runs behind [`crate::middleware::auth_middleware`], so it can rely on an
//! authenticated [`crate::entities::api_key::Model`] and a resolved [`crate::middleware::ClientIp`]
//! being present in the request extensions. The two exceptions are in [`health`], which is mounted
//! outside that layer on purpose. Authorization, by contrast, is per-handler and explicit — see
//! [`guards`].
//!
//! # Layout
//!
//! This was one 3,674-line file until the split recorded in `AGENT_NOTES.MD`. It is divided by
//! *domain*, with two modules that exist for structural reasons rather than domain ones:
//!
//! | Module | Holds |
//! | :--- | :--- |
//! | [`support`] | Shared plumbing used by three or more handler domains. Decides nothing |
//! | [`guards`] | Every authorization decision. Writes nothing |
//! | [`keys`] | Key CRUD, `GET /api/auth/me`, per-group grants, the §6 cascade |
//! | [`records`] | IP records: upsert, listing, trash/restore/purge |
//! | [`groups`] | IP group lifecycle and ownership reassignment |
//! | [`webhooks`] | Webhook *configuration* — the dispatcher itself is [`crate::dispatch`] |
//! | [`audit`] | Audit log reads |
//! | [`health`] | Unauthenticated liveness and readiness probes. **The only unauthenticated routes** |
//!
//! **`guards` is one module rather than one per domain on purpose.** The rules in `RBAC_MODEL.md`
//! are cross-cutting: R2's conjunction governs groups, records and webhooks alike, and §3's
//! ownership test is consulted from three domains. Splitting guards by caller would put one sentence
//! of the specification in three files and invite the copies to drift — precisely the failure the
//! compliance suite exists to catch, so it should not be designed in.
//!
//! **`support` is not a junk drawer**, and the boundary is testable: nothing in it makes an
//! authorization decision or returns a refusal that depends on *who* is calling. A helper that
//! starts deciding belongs in [`guards`].
//!
//! # Re-exports
//!
//! Every handler is re-exported flat, so `api::create_api_key` resolves exactly as it did when this
//! was one file — `src/lib.rs`'s router, every integration test, and `scripts/` needed no changes.
//! That is what makes the split reviewable as a move rather than a rewrite. The paths are the API;
//! the files are an implementation detail.

mod audit;
mod groups;
mod guards;
mod health;
mod keys;
mod records;
mod settings;
mod stats;
mod support;
mod webhooks;

// `pub(crate)` rather than `pub` for the two internal modules: every item in `guards` is internal,
// so a `pub` glob would re-export nothing and clippy says so, and most of `support` is the same. The
// guards are deliberately not part of the crate's public surface — they are the enforcement, not the
// API.
pub(crate) use guards::*;
pub(crate) use support::*;

pub use audit::*;
pub use groups::*;
pub use health::*;
pub use keys::*;
pub use records::*;
pub use settings::*;
pub use stats::*;
pub use webhooks::*;

// The credential primitives and the shared owner payload are public because the integration suites
// mint keys directly against the database — a test hashes a plaintext exactly as the service would,
// which is the only way to seed a key whose secret the test already knows. Named explicitly rather
// than left to the glob above, which caps them at `pub(crate)`.
pub use support::{
    ReassignOwnerPayload, generate_random_key, hash_key, normalize_ip_or_cidr,
    normalize_ipv6_ban_storage,
};
