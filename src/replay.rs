//! Single-use enforcement for `CANONICAL_V1` request signatures.
//!
//! The timestamp window in [`crate::middleware`] bounds *how long* a captured request stays useful;
//! it does nothing about that request being used more than once inside the window. Those are
//! different properties, and only the second one is replay protection in the sense an attacker
//! cares about: anyone who observes one authentic signed request — a mirrored packet on a
//! plain-HTTP LAN link, a reverse-proxy access log, a debug trace — can resend those exact bytes
//! for the rest of the window. Every field the signature covers is unchanged, so the HMAC verifies
//! and the freshness check passes. For `POST /api/ban` that is a duplicate row; for anything
//! non-idempotent it is a repeated side effect the caller never asked for.
//!
//! [`ReplayGuard`] closes that by remembering which signatures have already been accepted and
//! refusing a second use. A signature is only ever recorded **after** it has been verified, which is
//! what keeps this from becoming a memory-exhaustion target: filling the map requires producing
//! valid HMACs, which requires the signing secret.
//!
//! This module was extracted from `crate::state` and rebuilt during the 2026-08-02 cross-audit
//! follow-up. Three properties changed, each closing a defect the audit found:
//!
//! - **Monotonic expiry.** Entries expire against [`tokio::time::Instant`] rather than
//!   `chrono::Utc::now()`. The previous wall-clock arithmetic (`(now - ts).abs() <= window`) evicted
//!   still-valid entries whenever the system clock stepped in *either* direction, which is precisely
//!   the moment — an NTP correction — when an operator is least likely to connect the two events.
//! - **Amortized sweeping.** Pruning runs on an interval instead of scanning the whole map on every
//!   request while holding the global lock every request must take.
//! - **Graceful saturation.** Reaching the ceiling triggers a sweep and a warning, never a
//!   `clear()`. Flushing the map would make every signature accepted in the current window
//!   replayable at once — and because the map is process-global, one key's burst would have
//!   disabled the guard for every other key.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::Duration;

use tokio::time::Instant;
use uuid::Uuid;

/// How often expired entries are swept out, as a fraction of the replay window.
///
/// Pruning on every insertion is O(n) per request inside the lock every authenticated request must
/// take; pruning never lets the map hold every signature since boot. Sweeping once per
/// window-quarter bounds the map at roughly the signatures accepted in 1.25 windows while keeping
/// the amortized cost per request negligible.
const PRUNE_INTERVAL_DIVISOR: u32 = 4;

/// Minimum spacing between two *capacity-triggered* sweeps, as a fraction of the replay window.
///
/// A capacity sweep deliberately bypasses the routine interval so the ceiling is enforced promptly.
/// Without a floor on how often that may happen, a map saturated with entries that are all still
/// live would sweep on every single request — freeing nothing and reinstating exactly the
/// per-request O(n) scan this module exists to remove. Backing off to a sixteenth of the window
/// (≈18s at the default 300s) keeps the response prompt while bounding the wasted work.
const CAPACITY_BACKOFF_DIVISOR: u32 = 16;

/// Hard ceiling on tracked signatures, past which the guard sweeps early and complains.
///
/// Only reachable by callers that legitimately hold signing secrets and are issuing signed requests
/// faster than the window expires them — better than 333/s sustained at the default 300s window —
/// so this is a runaway-client alarm rather than an attack control. At 32 bytes of digest plus map
/// overhead, 100k entries is a few tens of MiB.
///
/// Passing it does **not** disable the guard. The map is allowed to grow beyond this point rather
/// than be flushed: over-retention costs memory, whereas under-retention costs the security
/// property, and only one of those is recoverable by adding hardware.
const MAX_TRACKED_SIGNATURES: usize = 100_000;

/// Identifies one accepted signature.
///
/// Keyed by the API key as well as the digest so two keys cannot collide, even though an HMAC
/// collision across distinct secrets is not something an attacker can arrange — the property costs
/// nothing to guarantee directly and does not then depend on collision resistance.
///
/// The digest is stored as **raw bytes**, exactly as [`crate::crypto::verify_signature`] decoded
/// them, rather than as the header's hex text. That is what makes `sha256=AB…` and `sha256=ab…` —
/// the same signature, differently spelled — impossible to present as two distinct single uses. The
/// previous implementation achieved the same result by lowercasing the header string, which was
/// correct only because `hex::decode` had already rejected non-canonical spellings upstream; here
/// the property holds by construction instead of at a distance.
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
struct SignatureId {
    /// The key that signed the request.
    key_id: Uuid,
    /// The raw HMAC-SHA256 digest.
    digest: Vec<u8>,
}

/// When the next routine and capacity-triggered sweeps become due.
///
/// Both live under one lock so a sweep decision is atomic: two threads arriving together must not
/// each conclude they are the one that should sweep.
#[derive(Debug)]
struct PruneSchedule {
    /// Next routine sweep.
    next: Instant,
    /// Earliest instant at which a capacity-triggered sweep may run again.
    next_capacity: Instant,
}

/// Rejects a validly-signed request whose signature has already been seen inside the window.
///
/// Shared through [`crate::state::AppState`] behind an [`std::sync::Arc`], so every handler sees one
/// set of accepted signatures. A per-clone guard would accept a replay on any request that happened
/// to be served through a different clone — which is to say most of them.
///
/// # Ordering
///
/// [`ReplayGuard::check_and_record`] must be consulted **after** the HMAC verifies, never before.
/// Recording unverified digests would let an unauthenticated caller fill the map with garbage (a
/// memory-exhaustion path needing no credentials) and, worse, pre-insert a signature it had merely
/// observed a legitimate client preparing to send — turning replay protection into a
/// denial-of-service primitive aimed at the client it exists to protect.
#[derive(Debug)]
pub struct ReplayGuard {
    /// Accepted signatures mapped to the instant they stop being remembered.
    ///
    /// A [`std::sync::Mutex`] rather than a `tokio` one: every operation is a hash lookup and an
    /// occasional retain, the lock is never held across an `.await`, and an async mutex would add a
    /// scheduling round-trip to a critical section measured in nanoseconds.
    seen: Mutex<HashMap<SignatureId, Instant>>,
    /// When sweeps are next due.
    schedule: Mutex<PruneSchedule>,
    /// How long a signature stays remembered.
    ///
    /// Mirrors the timestamp window: once a signature's timestamp is too old to pass
    /// [`crate::middleware`], the freshness check owns the rejection and there is nothing left for
    /// this to remember.
    window: Duration,
    /// Routine sweep interval, precomputed from [`ReplayGuard::window`].
    prune_interval: Duration,
    /// Floor on the spacing between capacity-triggered sweeps.
    capacity_backoff: Duration,
}

impl Default for ReplayGuard {
    /// Builds a guard whose memory matches the service's fixed anti-replay window.
    fn default() -> Self {
        Self::new(crate::crypto::MAX_TIMESTAMP_SKEW_SECS)
    }
}

impl ReplayGuard {
    /// Builds a guard remembering signatures for `window_seconds`.
    ///
    /// Private: [`ReplayGuard::default`] is the only production constructor, and it supplies the
    /// fixed [`crate::crypto::MAX_TIMESTAMP_SKEW_SECS`]. The window is still clamped into
    /// `[1, 3600]` rather than trusted — the clamp is dormant at that call site, but it costs
    /// nothing and keeps a future caller from switching the guard off, or turning the map into an
    /// unbounded allocation, by passing a nonsensical window.
    fn new(window_seconds: i64) -> Self {
        let window = Duration::from_secs(window_seconds.clamp(1, 3600) as u64);
        let prune_interval = window / PRUNE_INTERVAL_DIVISOR;
        let capacity_backoff = window / CAPACITY_BACKOFF_DIVISOR;
        let now = Instant::now();
        Self {
            seen: Mutex::new(HashMap::new()),
            schedule: Mutex::new(PruneSchedule {
                next: now + prune_interval,
                // Deliberately `now`, not `now + backoff`: the very first time the ceiling is
                // reached the sweep must be immediate, not deferred by a window the guard has not
                // yet had occasion to use.
                next_capacity: now,
            }),
            window,
            prune_interval,
            capacity_backoff,
        }
    }

    /// Records a verified signature, reporting whether it had already been used.
    ///
    /// Returns `true` when this is the signature's first use — the request may proceed — and `false`
    /// when it has been seen inside the window, which the caller must reject with `401`.
    ///
    /// Call this **only after** the signature has been verified; see the type-level note on
    /// ordering.
    ///
    /// A poisoned lock fails **closed**: the request is treated as a replay and rejected. A guard
    /// that cannot prove a signature is fresh must not claim that it is, and a poisoned mutex means
    /// a thread panicked while holding the map — not a state to keep authenticating through.
    pub fn check_and_record(&self, key_id: Uuid, digest: &[u8]) -> bool {
        let now = Instant::now();
        self.prune_if_due(now);

        let Ok(mut seen) = self.seen.lock() else {
            tracing::error!(
                "Replay guard mutex is poisoned; rejecting the request rather than authenticating \
                 without replay protection."
            );
            return false;
        };

        let id = SignatureId { key_id, digest: digest.to_vec() };
        match seen.get(&id) {
            // An entry that has outlived the window is stale bookkeeping the sweep has not reached
            // yet, not a replay — its timestamp could no longer pass the freshness check anyway.
            Some(expires_at) if *expires_at > now => false,
            _ => {
                seen.insert(id, now + self.window);
                true
            }
        }
    }

    /// Removes a recorded signature digest so that a transiently failed request (e.g. 503 Service
    /// Unavailable due to SQLite database locking or connection pool exhaustion) can be retried by
    /// the caller with the same signature without being falsely rejected as a replay.
    pub fn unrecord(&self, key_id: Uuid, digest: &[u8]) {
        if let Ok(mut seen) = self.seen.lock() {
            let id = SignatureId {
                key_id,
                digest: digest.to_vec(),
            };
            seen.remove(&id);
        }
    }

    /// How many signatures are currently remembered.
    ///
    /// Test-only, so a suite can assert that expired entries are actually *released* rather than
    /// merely stopped from being honoured. Nothing in the request path needs it, so it is compiled
    /// out of release builds rather than left as public surface no caller uses.
    #[cfg(test)]
    fn tracked(&self) -> usize {
        self.seen.lock().map(|seen| seen.len()).unwrap_or(0)
    }

    /// Drops expired entries when a sweep is due, or when the map has reached its ceiling.
    ///
    /// Amortized O(1) per request: the O(n) retain runs at most once per [`PRUNE_INTERVAL_DIVISOR`]
    /// fraction of the window, or once per [`CAPACITY_BACKOFF_DIVISOR`] fraction while saturated.
    ///
    /// The two locks are taken strictly one after the other, never nested, so this cannot deadlock
    /// against [`ReplayGuard::check_and_record`].
    fn prune_if_due(&self, now: Instant) {
        let over_capacity =
            self.seen.lock().is_ok_and(|seen| seen.len() >= MAX_TRACKED_SIGNATURES);

        {
            let Ok(mut schedule) = self.schedule.lock() else {
                // A poisoned schedule costs pruning, not correctness: entries still expire on read
                // via the `expires_at > now` comparison above, so nothing stale is ever honoured.
                return;
            };
            let routine_due = now >= schedule.next;
            let capacity_due = over_capacity && now >= schedule.next_capacity;
            if !routine_due && !capacity_due {
                return;
            }
            schedule.next = now + self.prune_interval;
            if capacity_due {
                schedule.next_capacity = now + self.capacity_backoff;
            }
        }

        let Ok(mut seen) = self.seen.lock() else {
            return;
        };
        seen.retain(|_, expires_at| *expires_at > now);

        if seen.len() >= MAX_TRACKED_SIGNATURES {
            tracing::warn!(
                tracked = seen.len(),
                ceiling = MAX_TRACKED_SIGNATURES,
                "Replay guard is at capacity even after sweeping expired entries: a client is \
                 issuing signed requests faster than the anti-replay window expires them. Replay \
                 protection is STILL ENFORCED — the map is allowed to grow rather than be flushed, \
                 since flushing it would make every signature accepted in this window replayable."
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A distinct 32-byte digest, shaped like the real thing.
    fn digest(byte: u8) -> Vec<u8> {
        vec![byte; 32]
    }

    #[tokio::test]
    async fn a_signature_is_accepted_once_and_refused_afterwards() {
        let guard = ReplayGuard::default();
        let key = Uuid::new_v4();

        assert!(guard.check_and_record(key, &digest(1)), "the first use is the legitimate request");
        assert!(!guard.check_and_record(key, &digest(1)), "the same signature is a replay");
        assert!(!guard.check_and_record(key, &digest(1)), "...and stays one on every later attempt");

        // Unrecord allows retrying the request after a transient failure
        guard.unrecord(key, &digest(1));
        assert!(guard.check_and_record(key, &digest(1)), "unrecorded signature can be used again");
        assert!(!guard.check_and_record(key, &digest(1)), "and is protected against replays once again");
    }

    #[tokio::test]
    async fn distinct_signatures_and_distinct_keys_do_not_collide() {
        let guard = ReplayGuard::default();
        let (key, other_key) = (Uuid::new_v4(), Uuid::new_v4());

        assert!(guard.check_and_record(key, &digest(1)));
        assert!(guard.check_and_record(key, &digest(2)), "a different signature is not a replay");
        // The same digest under a different key must not read as reuse — otherwise one tenant's
        // traffic could deny another's.
        assert!(guard.check_and_record(other_key, &digest(1)));
    }

    /// Byte-level keying: two digests differing in one bit are two signatures, and a digest is
    /// compared in full rather than by any prefix.
    #[tokio::test]
    async fn digests_are_distinguished_across_their_whole_length() {
        let guard = ReplayGuard::default();
        let key = Uuid::new_v4();

        let base = digest(0xAA);
        assert!(guard.check_and_record(key, &base));

        for position in 0..base.len() {
            let mut mutated = base.clone();
            mutated[position] ^= 0x01;
            assert!(
                guard.check_and_record(key, &mutated),
                "a digest differing at byte {position} is a different signature"
            );
        }
        // ...and the original is still remembered, so the loop above did not simply evict it.
        assert!(!guard.check_and_record(key, &base));
    }

    /// Expiry runs on the monotonic clock, so the tokio test clock can drive it exactly. This is the
    /// property that wall-clock arithmetic got wrong: an NTP step used to evict live entries.
    #[tokio::test(start_paused = true)]
    async fn an_entry_expires_once_its_window_elapses() {
        let guard = ReplayGuard::new(300);
        let key = Uuid::new_v4();

        assert!(guard.check_and_record(key, &digest(1)));
        assert!(!guard.check_and_record(key, &digest(1)), "still inside the window");

        tokio::time::advance(Duration::from_secs(301)).await;

        assert!(
            guard.check_and_record(key, &digest(1)),
            "past the window the freshness check owns the rejection, so this is not a replay"
        );
    }

    /// The sweep must actually release memory, not merely stop honouring entries.
    #[tokio::test(start_paused = true)]
    async fn expired_entries_are_released_by_the_sweep() {
        let guard = ReplayGuard::new(300);
        let key = Uuid::new_v4();

        for byte in 0..50u8 {
            assert!(guard.check_and_record(key, &digest(byte)));
        }
        assert_eq!(guard.tracked(), 50);

        // Past the window *and* past the routine sweep interval (300 / 4 = 75s).
        tokio::time::advance(Duration::from_secs(301)).await;
        assert!(guard.check_and_record(key, &digest(200)));

        assert_eq!(guard.tracked(), 1, "the sweep released the expired entries rather than stacking");
    }

    /// Amortization: inside one interval the map is not rescanned, so expired entries linger in
    /// memory without ever being *honoured*. Both halves matter — the first is the performance
    /// property, the second is the security one.
    #[tokio::test(start_paused = true)]
    async fn sweeping_is_amortized_but_stale_entries_are_never_honoured() {
        let guard = ReplayGuard::new(300);
        let key = Uuid::new_v4();

        assert!(guard.check_and_record(key, &digest(1)));

        // Past the entry's own window, but short of the 75s sweep interval.
        tokio::time::advance(Duration::from_secs(60)).await;
        assert_eq!(guard.tracked(), 1, "no sweep has run yet");

        // Not a replay: the expiry comparison is per-entry and does not wait for the sweep.
        assert!(guard.check_and_record(key, &digest(2)));
    }

    /// A misconfigured window must not be able to disable the guard or make the map unbounded.
    #[tokio::test]
    async fn a_nonsensical_window_is_clamped_rather_than_honoured() {
        let key = Uuid::new_v4();
        for window in [0, -1, i64::MIN, i64::MAX] {
            let guard = ReplayGuard::new(window);
            assert!(guard.check_and_record(key, &digest(7)));
            assert!(
                !guard.check_and_record(key, &digest(7)),
                "window {window} must still enforce single use"
            );
        }
    }

    /// Saturation must never flush the map. The previous implementation called `seen.clear()` here,
    /// which made every signature accepted in the current window replayable at once — and because
    /// the map is process-global, one key's burst disabled the guard for every other key.
    #[tokio::test(start_paused = true)]
    async fn reaching_capacity_sweeps_and_warns_but_never_flushes() {
        let guard = ReplayGuard::new(300);
        let key = Uuid::new_v4();

        // Fill to the ceiling with entries that are all still live.
        {
            let mut seen = guard.seen.lock().expect("fresh mutex is not poisoned");
            let expires_at = Instant::now() + Duration::from_secs(300);
            for n in 0..MAX_TRACKED_SIGNATURES {
                seen.insert(
                    SignatureId { key_id: key, digest: n.to_le_bytes().to_vec() },
                    expires_at,
                );
            }
        }
        assert_eq!(guard.tracked(), MAX_TRACKED_SIGNATURES);

        // A brand-new signature is still accepted...
        assert!(guard.check_and_record(key, &digest(0xFF)));
        // ...the map grew rather than being flushed...
        assert!(
            guard.tracked() > MAX_TRACKED_SIGNATURES,
            "a saturated guard must retain its entries, not clear them"
        );
        // ...and, decisively, every pre-existing entry is still enforced.
        assert!(
            !guard.check_and_record(key, 0usize.to_le_bytes().as_ref()),
            "capacity pressure must never make an already-used signature replayable"
        );
        assert!(!guard.check_and_record(key, &digest(0xFF)), "the new entry is enforced too");
    }

    /// The other half of the capacity contract: once entries genuinely expire, the sweep reclaims
    /// them and the map returns to a normal size on its own.
    #[tokio::test(start_paused = true)]
    async fn a_saturated_guard_recovers_once_its_entries_expire() {
        let guard = ReplayGuard::new(300);
        let key = Uuid::new_v4();

        {
            let mut seen = guard.seen.lock().expect("fresh mutex is not poisoned");
            let expires_at = Instant::now() + Duration::from_secs(300);
            for n in 0..MAX_TRACKED_SIGNATURES {
                seen.insert(
                    SignatureId { key_id: key, digest: n.to_le_bytes().to_vec() },
                    expires_at,
                );
            }
        }

        tokio::time::advance(Duration::from_secs(301)).await;
        assert!(guard.check_and_record(key, &digest(1)));

        assert_eq!(guard.tracked(), 1, "the sweep reclaimed the whole saturated map");
    }
}
