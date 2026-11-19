//! Boot-time pinning of the Master key **identity**, and the demotion that enforces it.
//!
//! # The attack this closes
//!
//! `api_keys.is_master` is a column, and every authorization guard in `src/api/` branches on it.
//! Anyone who reaches the database — a restored backup, a stray migration, an operator with a
//! sqlite3 prompt, a second process sharing the file — needs one statement to become Master:
//!
//! ```sql
//! UPDATE api_keys SET is_master = true WHERE id = '<attacker key>';
//! ```
//!
//! `RBAC_MODEL.md` §5's uniqueness index does not close that, and the reason is worth stating
//! precisely because it is the whole justification for this module. The index guarantees *at most
//! one* row carries `is_master`. It says nothing about **which** row. An attacker does not need two
//! masters: demoting the real one and promoting itself keeps the count at exactly one and leaves
//! every constraint satisfied. **Uniqueness and identity are different properties**, and the index
//! only defends the first.
//!
//! So the identity is resolved **once**, at startup, from a database whose §5 invariants are checked
//! at that moment, and then held for the life of the process. Afterwards `is_master` on any other row
//! is inert — noticed, logged loudly, and ignored. Making it mean something again requires a restart,
//! which is an event an operator can see and which re-runs every assertion below.
//!
//! # What this does not claim
//!
//! It is not a defence against an attacker who can write the database *and* restart the service, nor
//! against one who repoints an existing Master row's `key_hash` at a credential they hold. Nothing at
//! this layer could be. It closes the cheap, silent, otherwise invisible escalation of flipping a
//! boolean on a row you already control.

use std::sync::OnceLock;

use sea_orm::{ColumnTrait, DatabaseConnection, EntityTrait, QueryFilter, QuerySelect};
use uuid::Uuid;

use crate::entities::api_key;

/// The unique index over the engine-derived `master_marker`, created by
/// `migration::m20260808_000009_derive_master_marker`.
///
/// Named here as well as there because this is the one place that checks it still exists at
/// *runtime*: a migration proves the index was created once, and this proves nobody has dropped it
/// since.
pub const MASTER_MARKER_INDEX: &str = "idx-api_keys-master_marker";

/// The table the index above belongs to.
const API_KEYS_TABLE: &str = "api_keys";

/// Why [`MasterPin::pin_at_boot`] refused to let the service start.
///
/// Every variant is a database state that makes "the Master key" ambiguous or absent. None is
/// recoverable by retrying, and none should be papered over at runtime: a service that starts without
/// knowing which key is Master is a service whose most powerful credential is decided by whichever
/// row a query happens to return first.
///
/// They are distinguished rather than collapsed into one "startup failed" because the operator
/// response differs sharply between them — one means the bootstrap never ran, another means somebody
/// must decide which key is legitimate, and a third is a schema repair.
#[derive(Debug, thiserror::Error)]
pub enum MasterPinError {
    /// The `api_keys` table holds no row with `is_master = true`.
    #[error(
        "No master key exists. The service mints one at first boot; if this database was restored \
         or edited, delete nothing and investigate — starting without a master would leave every \
         master-only operation permanently unreachable."
    )]
    NoMaster,

    /// More than one row claims `is_master`, so there is no single answer to pin.
    #[error(
        "{} keys have is_master = true ({}), but RBAC_MODEL.md §5 requires exactly one. This is \
         only reachable if the uniqueness constraint was dropped or bypassed. Decide which key is \
         legitimate and demote the others, then restart. Refusing to start rather than guessing.",
        .0.len(),
        .0.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")
    )]
    MultipleMasters(Vec<Uuid>),

    /// The unique index backing §5 is absent from the live schema.
    #[error(
        "The master-uniqueness index '{MASTER_MARKER_INDEX}' is missing from {API_KEYS_TABLE}. \
         RBAC_MODEL.md §5 requires master uniqueness to be enforced by the database rather than by \
         application logic; without it a second master can be written at any time. Note that \
         re-running migrations will NOT restore it — m20260808_000009_derive_master_marker is \
         already recorded as applied and will be skipped. Recreate {MASTER_MARKER_INDEX} as a \
         unique index on the master_marker column of {API_KEYS_TABLE}."
    )]
    MissingUniquenessIndex,

    /// The schema or key lookup itself failed.
    #[error("Could not read the database while pinning the master key: {0}")]
    Query(#[from] sea_orm::DbErr),
}

/// The id of the one key permitted to act as Master, resolved once and then immutable.
///
/// # Why `OnceLock` rather than a plain `Uuid`
///
/// Write-once is the property being bought, not laziness. A plain field would be assignable by any
/// code holding `&mut` access, and "the master is whoever we last decided it was" is exactly the
/// mutable state this module exists to rule out. [`OnceLock`] makes a second assignment impossible
/// rather than merely discouraged, so the pin cannot drift under a running process even by accident.
///
/// Held behind an [`Arc`](std::sync::Arc) on [`crate::state::AppState`] so every clone of the state
/// observes the same pin; a per-clone cell would let each handler resolve its own, which is the bug
/// this type exists to prevent, reintroduced one `#[derive(Clone)]` at a time.
#[derive(Debug, Default)]
pub struct MasterPin {
    cell: OnceLock<Uuid>,
}

impl MasterPin {
    /// An unresolved pin.
    #[must_use]
    pub fn new() -> Self {
        Self {
            cell: OnceLock::new(),
        }
    }

    /// A pin fixed to a known id, without consulting the database.
    ///
    /// For tests that need to assert the *negative*: what a key does when it claims mastery and is
    /// not the pinned identity. Reaching that situation through [`Self::pin_at_boot`] is impossible
    /// by construction — resolution only ever pins a row that really is the sole Master — so the
    /// alternative is dropping the §5 index and writing a second master row, which tests a different
    /// failure at the same time.
    #[must_use]
    pub fn pinned_to(id: Uuid) -> Self {
        let cell = OnceLock::new();
        let _ = cell.set(id);
        Self { cell }
    }

    /// The pinned id, if one has been established. Never queries.
    pub fn get(&self) -> Option<Uuid> {
        self.cell.get().copied()
    }

    /// Establishes which key is Master, once, and refuses to return anything else afterwards.
    ///
    /// Called by `main.rs` **before the listener is bound**, so the pin is in place before a single
    /// request can be served. Three checks, in the order that gives the most useful error:
    ///
    /// 1. Exactly one row has `is_master = true`. Zero and many are both fatal and are reported
    ///    differently, because the remedies have nothing in common.
    /// 2. The §5 uniqueness index still exists. A migration proves it was created once; this proves
    ///    nobody has dropped it since.
    /// 3. That row's id becomes the pin.
    ///
    /// # Idempotent by construction
    ///
    /// Calling it twice returns the already-pinned id and does not re-query. That is not a
    /// convenience: it is what makes the guarantee hold. If a second call could re-resolve, then
    /// anything able to trigger one — a reconnect, a reload, a future admin endpoint — could move the
    /// pin, and "fixed at boot" would be true only until the first such event.
    ///
    /// # Errors
    ///
    /// Returns an error if the stored master credential cannot be loaded.
    pub async fn pin_at_boot(&self, db: &DatabaseConnection) -> Result<Uuid, MasterPinError> {
        if let Some(pinned) = self.cell.get() {
            return Ok(*pinned);
        }

        let pinned = Self::sole_master(db).await?;

        // The index check comes *after* the count, and the ordering was the other way round until a
        // test showed why it should not be. Two masters is only reachable once the index is gone, so
        // checking the index first meant `MultipleMasters` could never be reported — the operator was
        // told to recreate an index while two masters sat in the table unmentioned. Counting first
        // surfaces the more urgent fact; the index error is then reported on the next start, once the
        // ambiguity the service cannot resolve for itself has been resolved.
        // `crate::db::has_index` rather than `SchemaManager::has_index`. The latter selects its
        // catalog query behind cargo feature gates that this crate does not enable for PostgreSQL, so
        // it answered `BackendNotSupported` there and **the service could not start on Postgres at
        // all** — against a database whose index was present and correct. See `db::has_index`.
        if !crate::db::has_index(db, API_KEYS_TABLE, MASTER_MARKER_INDEX).await? {
            return Err(MasterPinError::MissingUniquenessIndex);
        }

        // `set` losing a race is not an error: two callers resolving concurrently necessarily read
        // the same single row, so the winner's value is the loser's value.
        let _ = self.cell.set(pinned);
        Ok(pinned)
    }

    /// The pinned id, resolving it on first use if [`Self::pin_at_boot`] has not already run.
    ///
    /// **Fail-closed.** Returns `None` — meaning *no key is Master* — whenever the identity cannot be
    /// established: no master row, several, a missing index, or an unreadable database. `None` is
    /// strictly more restrictive than any answer it replaces, so a failure here removes authority
    /// rather than granting it, and it leaves the cell unset so a later call can still succeed once
    /// an operator has fixed the row.
    ///
    /// The lazy path exists for tests, which build their state before seeding any key and would
    /// otherwise have to be rewritten around a startup sequence they are not testing. It is
    /// unreachable in production: `main.rs` pins before binding the listener, so by the time any
    /// request arrives this is a load with no query behind it.
    ///
    /// Both paths run **the same resolution**. That matters more than the timing: if the lazily
    /// resolved test build and the boot-pinned production build differed, the property under test
    /// would not be the property deployed.
    pub async fn resolve(&self, db: &DatabaseConnection) -> Option<Uuid> {
        match self.pin_at_boot(db).await {
            Ok(id) => Some(id),
            Err(e) => {
                tracing::error!(
                    "Master identity is unresolvable, so no caller will be treated as Master: {e}"
                );
                None
            }
        }
    }

    /// Applies the pin to a freshly authenticated key record, clearing `is_master` on an impostor.
    ///
    /// This is the **single choke point** for the whole guarantee, and it is a mutation of the
    /// principal rather than a check sprinkled through the handlers. That is the entire design: there
    /// are dozens of `key.is_master` reads across `src/api/`, and any scheme requiring each of them
    /// to also compare an id would be one forgotten call site away from worthless — including every
    /// call site added later, by someone who never read this module.
    ///
    /// Instead the record handed to handlers is the *effective* principal. Downstream code keeps
    /// reading `key.is_master` and is automatically correct, because a key that is not the pinned
    /// Master no longer says it is.
    ///
    /// # Demoted, not rejected
    ///
    /// §5 makes master status a property of one specific key, not a credential in its own right. A
    /// key whose `is_master` column was flipped is still a valid key with whatever scopes it
    /// legitimately holds, and it keeps exactly those. Returning `401` would also make the flag
    /// observable to the caller, which is the sort of oracle §4 spends considerable effort closing
    /// elsewhere.
    ///
    /// Only keys *claiming* master pay for the lookup, and after the first resolution the pin is a
    /// [`OnceLock`] read — so the common path costs one boolean test.
    pub async fn authenticate(&self, db: &DatabaseConnection, key: &mut api_key::Model) {
        if !key.is_master {
            return;
        }

        // Loud, and at error level: reaching either arm means a row was promoted in the database
        // behind the service's back, which is either an intrusion or an operator editing production
        // by hand. Both are worth waking someone up for.
        match self.resolve(db).await {
            Some(pinned) if pinned == key.id => {}
            Some(pinned) => {
                tracing::error!(
                    key = %key.prefix,
                    claimed_id = %key.id,
                    pinned_master = %pinned,
                    "TAMPER: a key carries is_master = true but is not the master this process \
                     pinned at startup. Treating it as an ordinary key. The database was modified \
                     outside the service — see RBAC_MODEL.md §5."
                );
                key.is_master = false;
            }
            None => {
                tracing::error!(
                    key = %key.prefix,
                    claimed_id = %key.id,
                    "A key carries is_master = true but this process has no pinned master (the \
                     database does not contain exactly one). Treating it as an ordinary key."
                );
                key.is_master = false;
            }
        }
    }

    /// Reads the sole Master row's id, or explains why there isn't one.
    ///
    /// `select_only` + one column: the master row carries a signing secret, and there is no reason
    /// for a startup check to pull a credential into memory to count to one.
    async fn sole_master(db: &DatabaseConnection) -> Result<Uuid, MasterPinError> {
        let masters: Vec<Uuid> = crate::entities::prelude::ApiKey::find()
            .select_only()
            .column(api_key::Column::Id)
            .filter(api_key::Column::IsMaster.eq(true))
            .into_tuple()
            .all(db)
            .await?;

        match masters.as_slice() {
            [only] => Ok(*only),
            [] => Err(MasterPinError::NoMaster),
            many => Err(MasterPinError::MultipleMasters(many.to_vec())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_pinned_cell_reports_its_id_without_a_database() {
        let id = Uuid::new_v4();
        assert_eq!(MasterPin::pinned_to(id).get(), Some(id));
    }

    #[test]
    fn a_fresh_pin_is_unresolved() {
        assert_eq!(MasterPin::new().get(), None);
    }

    /// The error text is operator-facing and names the remedy; a bare "startup failed" would not.
    /// Each of these strings is the only instruction an operator gets at 3am, so each is asserted.
    #[test]
    fn every_failure_explains_what_to_do_about_it() {
        assert!(MasterPinError::NoMaster.to_string().contains("investigate"));

        let dupes = MasterPinError::MultipleMasters(vec![Uuid::nil(), Uuid::max()]);
        let text = dupes.to_string();
        assert!(text.contains("2 keys"), "the count is stated: {text}");
        assert!(
            text.contains(&Uuid::nil().to_string()),
            "the offending ids are named: {text}"
        );
        assert!(text.contains("Refusing to start rather than guessing"));

        // The index error must not say "re-run migrations": `m20260808_000009` is already recorded
        // as applied and would be skipped, so that advice sends an operator in a circle.
        let missing = MasterPinError::MissingUniquenessIndex.to_string();
        assert!(missing.contains(MASTER_MARKER_INDEX));
        assert!(
            missing.contains("unique index on the master_marker column"),
            "the remedy is spelled out: {missing}"
        );
        assert!(
            missing.contains("will NOT restore it"),
            "the useless remedy is ruled out explicitly: {missing}"
        );
    }
}
