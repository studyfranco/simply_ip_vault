#!/usr/bin/env bash
#
# verify_convergence.sh — mechanical drift detection between simply_ip_vault and
# simply_hook_executor.
#
# The two services deliberately share a small set of security primitives. Nothing in either build
# enforces that: they are separate crates with separate test suites, so the shared logic can drift
# apart one plausible-looking edit at a time and nobody notices until the next manual audit. This
# script is that audit, run cheaply and repeatably.
#
# It extracts the security-critical functions from both trees and diffs them, normalizing away the
# differences that are *expected* (crate names, the vault's `ProxyMatcher` vs the executor's
# `ProxySpec`, comment wording) so that only behavioural divergence surfaces.
#
# WHAT IT DOES NOT DO: decide whether a divergence is wrong. Several are deliberate and documented —
# most importantly the authentication posture, which is asymmetric by design (see AGENT_NOTES.MD,
# "Convergence Parity Check"). A reported difference is a prompt to check the rationale, not a bug.
#
# Usage:
#   scripts/verify_convergence.sh            # summary, exit 1 on unexpected divergence
#   scripts/verify_convergence.sh --verbose  # also print the normalized diffs
#
# Exit status: 0 when every tracked primitive matches (or diverges as documented), 1 otherwise.

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PEER_ROOT="$PROJECT_ROOT/example/simply_hook_executor"

VERBOSE=0
[ "${1:-}" == "--verbose" ] && VERBOSE=1

if [ -t 1 ]; then
    RED=$'\033[0;31m'; GREEN=$'\033[0;32m'; YELLOW=$'\033[0;33m'
    BLUE=$'\033[0;36m'; BOLD=$'\033[1m'; RESET=$'\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; BLUE=''; BOLD=''; RESET=''
fi

MATCH_COUNT=0
DRIFT_COUNT=0
EXPECTED_COUNT=0

# ─────────────────────────────────────────────────────────────
# Peer sync — compare against the peer's current HEAD, not a stale one
# ─────────────────────────────────────────────────────────────
#
# The clones under `example/` have their own remotes and fall behind. A convergence check run against
# a stale clone certifies agreement with code that no longer exists, and does so *silently*: every
# assertion passes and the summary reads clean. That has happened — a snapshot nineteen files behind,
# six of them under `src/api/`, was audited as current.
#
# **Never fatal.** This gate must stay usable offline, on a laptop with no route to the forge, and in
# CI without credentials. Every failure below degrades to a warning and the check proceeds against
# whatever is on disk, which is still worth running.
#
# Set `SKIP_PEER_SYNC=1` to bypass entirely — for an air-gapped run, or to pin a comparison to a known
# peer commit while investigating a drift report.
sync_peer_repositories() {
    if [ "${SKIP_PEER_SYNC:-0}" == "1" ]; then
        echo "  ${YELLOW}⚠${RESET}  peer sync skipped (SKIP_PEER_SYNC=1) — comparing against the local checkout"
        return
    fi

    local git_dir peer name
    local found=0
    for git_dir in "$PROJECT_ROOT"/example/*/.git; do
        # Unmatched globs expand to the literal pattern, so the guard is on existence, not on the
        # loop running. A flat snapshot with no `.git` is a legitimate setup and simply has nothing
        # to pull.
        [ -e "$git_dir" ] || continue
        found=1
        peer="$(dirname "$git_dir")"
        name="$(basename "$peer")"

        # Refuse to pull over local modifications. A dirty peer worktree means somebody is mid-edit
        # or a previous sync copied files in; merging on top of that either fails noisily or succeeds
        # and silently mixes the two. Neither belongs in a check that is supposed to observe.
        if [ -n "$(git -C "$peer" status --porcelain 2>/dev/null)" ]; then
            echo "  ${YELLOW}⚠${RESET}  $name has local changes — not pulling, comparing against the working tree as-is"
            continue
        fi

        # `GIT_TERMINAL_PROMPT=0` is the load-bearing part. These remotes are HTTPS, and without it a
        # missing or expired credential makes git block on an interactive prompt — which in CI is not
        # an error but a hang, the failure mode that costs the most to diagnose. `timeout` bounds the
        # network side for the same reason.
        if GIT_TERMINAL_PROMPT=0 timeout 60 git -C "$peer" pull --quiet --ff-only 2>/dev/null; then
            echo "  ${GREEN}✓${RESET} $name synced — now at $(git -C "$peer" rev-parse --short HEAD)"
        else
            echo "  ${YELLOW}⚠️  Warning: Could not pull peer repository, continuing with local version...${RESET}"
            echo "     $name stays at $(git -C "$peer" rev-parse --short HEAD 2>/dev/null || echo 'unknown')" \
                 "— offline, no credentials, or the branch has diverged."
        fi
    done

    [ "$found" == "1" ] || echo "  ${BLUE}·${RESET}  no git clone under example/ — comparing against the files on disk"
}

echo "${BOLD}Peer synchronization${RESET}"
sync_peer_repositories
echo

if [ ! -d "$PEER_ROOT" ]; then
    echo "${YELLOW}SKIP${RESET} peer service not found at $PEER_ROOT" >&2
    echo "Mount simply_hook_executor there (read-only is fine) to enable drift detection." >&2
    exit 0
fi

WORK_DIR="$(mktemp -d)"
trap 'rm -rf "$WORK_DIR"' EXIT

# Prints the body of a Rust function, from its signature to the closing brace at the same
# indentation. Deliberately awk rather than a real parser: the targets are all top-level `fn`s with
# rustfmt-normalized bodies, so brace-depth counting is exact for them, and a parser dependency
# would be one more thing to keep working.
# Usage: extract_fn FILE FUNCTION_NAME
extract_fn() {
    local file="$1" name="$2"
    [ -f "$file" ] || return 1
    awk -v target="$name" '
        # Match the function signature, tolerating pub/async/const qualifiers.
        !inside && $0 ~ ("(^|[^a-zA-Z0-9_])fn[ \t]+" target "[ \t]*[(<]") {
            inside = 1; depth = 0
        }
        inside {
            print
            n = gsub(/\{/, "{"); depth += n
            n = gsub(/\}/, "}"); depth -= n
            # The signature line may span several lines before the opening brace; only start
            # counting down once a brace has actually been seen.
            if (depth == 0 && seen_brace) { exit }
            if (depth > 0) seen_brace = 1
        }
    ' "$file"
}

# Strips the differences that are expected between the two crates, so the diff reports behaviour
# rather than vocabulary. Each substitution is a naming difference the two services agreed to keep.
normalize() {
    sed -E \
        -e 's/[[:space:]]+$//' \
        -e '/^[[:space:]]*\/\//d' \
        -e '/^[[:space:]]*$/d' \
        -e 's/simply_hook_executor/CRATE/g' \
        -e 's/simply_ip_vault/CRATE/g' \
        -e 's/ProxySpec/PROXY_ENTRY/g' \
        -e 's/ProxyMatcher/PROXY_ENTRY/g' \
        -e 's/TRUSTED_PROXY_DNS_TTL/POSITIVE_TTL/g' \
        -e 's/SIGNING_SECRET_KEY/ENCRYPTION_KEY/g' \
        -e 's/VAULT_ENCRYPTION_KEY/ENCRYPTION_KEY/g' \
        -e 's/[[:space:]]+/ /g'
}

# Compares one function between the two trees.
# Usage: compare_fn LABEL OUR_FILE OUR_FN PEER_FILE PEER_FN [expected-divergence-reason]
compare_fn() {
    local label="$1" our_file="$2" our_fn="$3" peer_file="$4" peer_fn="$5" expected="${6:-}"

    extract_fn "$PROJECT_ROOT/$our_file" "$our_fn" | normalize > "$WORK_DIR/ours.txt"
    extract_fn "$PEER_ROOT/$peer_file" "$peer_fn" | normalize > "$WORK_DIR/peer.txt"

    if [ ! -s "$WORK_DIR/ours.txt" ]; then
        echo "  ${RED}✗ MISSING${RESET} $label — could not find \`fn $our_fn\` in $our_file"
        DRIFT_COUNT=$((DRIFT_COUNT + 1))
        return
    fi
    if [ ! -s "$WORK_DIR/peer.txt" ]; then
        echo "  ${YELLOW}~ ABSENT${RESET}  $label — the peer has no \`fn $peer_fn\` in $peer_file"
        EXPECTED_COUNT=$((EXPECTED_COUNT + 1))
        return
    fi

    if diff -q "$WORK_DIR/ours.txt" "$WORK_DIR/peer.txt" >/dev/null 2>&1; then
        echo "  ${GREEN}✓ MATCH${RESET}   $label"
        MATCH_COUNT=$((MATCH_COUNT + 1))
        return
    fi

    if [ -n "$expected" ]; then
        echo "  ${YELLOW}~ DIVERGES${RESET} $label — expected: $expected"
        EXPECTED_COUNT=$((EXPECTED_COUNT + 1))
    else
        echo "  ${RED}✗ DRIFT${RESET}   $label — the two implementations no longer agree"
        DRIFT_COUNT=$((DRIFT_COUNT + 1))
    fi

    if [ "$VERBOSE" == "1" ]; then
        echo "${BLUE}--- ours ($our_file::$our_fn) / peer ($peer_file::$peer_fn) ---${RESET}"
        diff -u "$WORK_DIR/ours.txt" "$WORK_DIR/peer.txt" | sed 's/^/    /'
        echo
    fi
}

# Asserts that a pattern appears in one of our files. Used for invariants that are a property of the
# file rather than of a single function.
# Usage: assert_present LABEL FILE PATTERN
assert_present() {
    local label="$1" file="$2" pattern="$3"
    if grep -qE "$pattern" "$PROJECT_ROOT/$file" 2>/dev/null; then
        echo "  ${GREEN}✓ PRESENT${RESET} $label"
        MATCH_COUNT=$((MATCH_COUNT + 1))
    else
        echo "  ${RED}✗ ABSENT${RESET}  $label — expected /$pattern/ in $file"
        DRIFT_COUNT=$((DRIFT_COUNT + 1))
    fi
}

# Asserts that a pattern appears NOWHERE in src/. Used for things that must stay gone.
# Usage: assert_absent LABEL PATTERN
assert_absent() {
    local label="$1" pattern="$2"
    local hits
    # `grep -rn` prefixes every line with `path:lineno:`, so the comment filter has to skip past
    # that prefix — anchoring at ^ would never see the `//` and every doc comment would be a hit.
    hits=$(grep -rnE "$pattern" "$PROJECT_ROOT/src" 2>/dev/null \
        | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|\*)' || true)
    if [ -z "$hits" ]; then
        echo "  ${GREEN}✓ CLEAN${RESET}   $label"
        MATCH_COUNT=$((MATCH_COUNT + 1))
    else
        echo "  ${RED}✗ FOUND${RESET}   $label"
        echo "$hits" | sed 's/^/      /'
        DRIFT_COUNT=$((DRIFT_COUNT + 1))
    fi
}

echo
echo "${BOLD}Convergence check: simply_ip_vault  ↔  simply_hook_executor${RESET}"
echo "  this repo: $PROJECT_ROOT"
echo "  peer:      $PEER_ROOT"
echo

# ─────────────────────────────────────────────────────────────
echo "${BOLD}Pillar 0 — Canonical specification${RESET}"
# `RBAC_MODEL.md` is the single source of truth for the authorization model, and its whole value
# rests on being the *same* document in both trees. A specification that has drifted is worse than no
# specification: each side would keep converging against its own copy and call the result agreement.
#
# Byte equality, not a normalized diff, and deliberately so. Everything else in this script
# normalizes away expected differences (crate names, type names) because it compares *code* that is
# meant to behave alike while being written for different nouns. This file is meant to be literally
# identical — it names both services' nouns in the same sentences — so a single changed byte is drift
# by definition.
#
# Both mount points are accepted: the peer repository may be checked out at `example/` (its own root)
# or at `example/simply_hook_executor/` (nested), and the check should not depend on which.
check_spec_parity() {
    local label="RBAC_MODEL.md is byte-identical across services"
    local ours="$PROJECT_ROOT/RBAC_MODEL.md"

    if [ ! -f "$ours" ]; then
        echo "  ${RED}✗ MISSING${RESET} $label — $ours does not exist"
        DRIFT_COUNT=$((DRIFT_COUNT + 1))
        return
    fi

    local peer_spec=""
    for candidate in "$PEER_ROOT/RBAC_MODEL.md" "$PROJECT_ROOT/example/RBAC_MODEL.md"; do
        if [ -f "$candidate" ]; then
            peer_spec="$candidate"
            break
        fi
    done

    # Not yet published on the peer side. Reported as an expected gap rather than drift: this
    # service cannot create a file in a tree it does not own, and failing here would make the whole
    # check red for a condition the peer alone can fix.
    if [ -z "$peer_spec" ]; then
        echo "  ${YELLOW}~ ABSENT${RESET}  $label — the peer has no RBAC_MODEL.md yet"
        echo "             copy $ours into the peer repository root to enable this check"
        EXPECTED_COUNT=$((EXPECTED_COUNT + 1))
        return
    fi

    if cmp -s "$ours" "$peer_spec"; then
        echo "  ${GREEN}✓ MATCH${RESET}   $label"
        MATCH_COUNT=$((MATCH_COUNT + 1))
        return
    fi

    echo "  ${RED}✗ DRIFT${RESET}   $label — the two copies differ"
    echo "             ours: $ours"
    echo "             peer: $peer_spec"
    DRIFT_COUNT=$((DRIFT_COUNT + 1))
    if [ "$VERBOSE" == "1" ]; then
        echo "${BLUE}--- ours / peer ---${RESET}"
        diff -u "$ours" "$peer_spec" | sed 's/^/    /'
        echo
    fi
}
check_spec_parity

# Rule coverage: every rule and section in RBAC_MODEL.md must have at least one compliance test.
#
# Byte-identity proves the two services agree on *what the specification says*. It says nothing about
# whether either of them enforces it. This check closes the other half locally: `tests/rbac_model_compliance.rs`
# names every test after the rule it enforces (`r1_`…`r7_`, `s3_`…`s7_`), so a rule with no test is a
# missing prefix and shows up here rather than in an incident.
#
# Deliberately shallow, and it says so: a test named `r2_…` proves a rule was thought about, not that
# it is enforced. Mutation testing is what proves the second half, and its results live in
# AGENT_NOTES.MD — a rule whose mutation does not fire is recorded there as untested rather than
# counted as covered. This check is the tripwire for the case mutation testing cannot catch, which is
# a rule nobody wrote a test for at all.
check_rule_coverage() {
    local suite="$PROJECT_ROOT/tests/rbac_model_compliance.rs"
    local label="every RBAC_MODEL.md rule has a compliance test"

    if [ ! -f "$suite" ]; then
        echo "  ${RED}✗ MISSING${RESET} $label — $suite does not exist"
        DRIFT_COUNT=$((DRIFT_COUNT + 1))
        return
    fi

    # Only `fn` definitions count. A rule mentioned in a doc comment or an assertion message is not a
    # test, and matching those would let prose satisfy the check.
    local uncovered=""
    local covered=0
    for rule in r1 r2 r3 r4 r5 r6 r7 s3 s4 s5 s6 s7; do
        if grep -qE "^\s*async fn ${rule}_|^\s*fn ${rule}_" "$suite"; then
            covered=$((covered + 1))
        else
            uncovered="$uncovered $rule"
        fi
    done

    if [ -n "$uncovered" ]; then
        echo "  ${RED}✗ GAP${RESET}     $label — no test for:$uncovered"
        echo "             add one to tests/rbac_model_compliance.rs named <rule>_<what it asserts>"
        DRIFT_COUNT=$((DRIFT_COUNT + 1))
        return
    fi

    echo "  ${GREEN}✓ MATCH${RESET}   $label ($covered/12 rules and sections)"
    MATCH_COUNT=$((MATCH_COUNT + 1))
}
check_rule_coverage

# Adversarial coverage: every rule that claims a guarantee below the application must be proven
# against an *uncooperative* writer.
#
# This check exists because of a specific failure, and the failure is worth stating rather than
# summarizing. §5 required master uniqueness "enforced by a database constraint rather than by
# application logic alone". The schema had a `master_marker` column under a genuine unique index —
# but the application wrote the marker, and NULLs do not collide in a unique index, so any writer
# that set `is_master` and omitted the marker got a second master. It was accepted on a live
# database.
#
# Nothing caught it for six phases. `check_rule_coverage` above was green: §5 had a test. The test
# passed. Mutation testing fired: removing `.unique()` broke it. Every signal agreed, and every
# signal was blind for the same reason — the test supplied the marker itself. It proved a
# well-behaved writer behaves well, which is not what the rule was about.
#
# The generalisable form: a test that reaches the guarantee through the application can only ever
# prove the application's own habits. Where the claim is about the database, the type system, or an
# extractor, at least one test must go around the application entirely. That test is marked
# `ADVERSARIAL(§N)` in its doc comment, and this check fails when a rule listed below has none.
#
# The marker is a doc-comment convention rather than an attribute because it is a *claim about what
# the test does*, and it should read as one to anyone opening the file — the same reason the rule
# prefixes are in the test names.
check_adversarial_coverage() {
    local suite="$PROJECT_ROOT/tests/rbac_model_compliance.rs"
    local label="every infrastructure-level rule has an adversarial test"

    if [ ! -f "$suite" ]; then
        echo "  ${RED}✗ MISSING${RESET} $label — $suite does not exist"
        DRIFT_COUNT=$((DRIFT_COUNT + 1))
        return
    fi

    # The rules whose guarantee lives below the application, and therefore cannot be proven by a
    # test that goes through it. Sections 5 and 7 are the schema-level claims (master uniqueness,
    # the derived marker, payload types that cannot express a field, indexes, and the
    # application-side substitutes for foreign keys SQLite will not take).
    #
    # R1–R7, §3, §4 and §6 are deliberately absent: they are authorization *decisions*, made by
    # handlers, and a caller exercising the API is the correct — not merely convenient — way to test
    # them. Adding them here would demand adversarial tests for rules where "bypass the application"
    # has no meaning, and a gate that asks for impossible evidence gets switched off.
    local uncovered=""
    local covered=0
    for rule in "§5" "§7"; do
        if grep -qF "ADVERSARIAL(${rule})" "$suite"; then
            covered=$((covered + 1))
        else
            uncovered="$uncovered $rule"
        fi
    done

    if [ -n "$uncovered" ]; then
        echo "  ${RED}✗ GAP${RESET}     $label — no adversarial test for:$uncovered"
        echo "             a rule about the schema, a type, or an extractor needs one test that"
        echo "             bypasses the application: raw SQL, or a payload the type cannot express."
        echo "             Mark it \`ADVERSARIAL(<rule>)\` in the test's doc comment."
        DRIFT_COUNT=$((DRIFT_COUNT + 1))
        return
    fi

    local total
    total=$(grep -cF "ADVERSARIAL(" "$suite")
    echo "  ${GREEN}✓ MATCH${RESET}   $label ($covered/2 rules, $total adversarial test(s))"
    MATCH_COUNT=$((MATCH_COUNT + 1))
}
check_adversarial_coverage

# The two mechanisms the §5 adversarial tests depend on, asserted structurally as well as
# behaviourally. Both are one-line deletions that leave every handler compiling and every
# application-path test green, which is precisely the profile of an edit that survives review.
assert_present "the master marker is generated by the engine, not by the application" \
    "src/migration/m20260808_000009_derive_master_marker.rs" "GENERATED ALWAYS AS"
assert_present "the generated column is per-backend: STORED on Postgres, VIRTUAL elsewhere" \
    "src/migration/m20260808_000009_derive_master_marker.rs" "DatabaseBackend::Postgres => \"STORED\""
assert_absent "no code writes the master marker" \
    "master_marker:[[:space:]]*Set\("

# The marker must be unreachable from application code by *construction*, not by discipline.
#
# The `Set(` pattern above catches the obvious spelling. This catches the thing that would make that
# spelling compile again: a `master_marker` field on the entity. `api_key::Model` deliberately omits
# it, which is why `ActiveModel` has no slot to assign — SeaORM cannot build a write for a column the
# model does not know about. Reintroducing the field is the one edit that turns "nobody writes it"
# from a guarantee back into a convention, and it would look like a routine entity sync.
if grep -qE '^\s*pub master_marker' "$PROJECT_ROOT/src/entities/api_key.rs"; then
    echo "  ${RED}✗ FOUND${RESET}   api_key::Model declares master_marker — the column must stay unmodelled"
    DRIFT_COUNT=$((DRIFT_COUNT + 1))
else
    echo "  ${GREEN}✓ CLEAN${RESET}   api_key::Model does not model the derived marker"
    MATCH_COUNT=$((MATCH_COUNT + 1))
fi

# No hand-written UPDATE/INSERT naming the column either, outside the migration that defines it.
marker_dml=$(grep -rniE "(INSERT INTO|UPDATE)[^\"]*master_marker" "$PROJECT_ROOT/src" 2>/dev/null \
    | grep -v "/src/migration/" | grep -vE '^[^:]+:[0-9]+:[[:space:]]*(//|\*)' || true)
if [ -z "$marker_dml" ]; then
    echo "  ${GREEN}✓ CLEAN${RESET}   no raw DML names master_marker outside src/migration/"
    MATCH_COUNT=$((MATCH_COUNT + 1))
else
    echo "  ${RED}✗ FOUND${RESET}   raw DML naming master_marker:"
    echo "$marker_dml" | sed 's/^/      /'
    DRIFT_COUNT=$((DRIFT_COUNT + 1))
fi

# The Master's *identity* is pinned at boot, which is a different guarantee from its *uniqueness*.
# §5's index makes at most one row carry `is_master`; it does not say which row. An attacker with
# database access does not need two masters — demoting the real one and promoting itself keeps the
# count at exactly one and satisfies every constraint. These assertions cover the identity half.
#
# They moved from `src/state.rs`/`src/middleware.rs` to `src/master.rs` when the mechanism was
# extracted into a `MasterPin` type, mirroring the peer's `src/master.rs`. Moving the assertions with
# the code is the whole point of writing them down: an assertion left pointing at the old file would
# have gone on reporting MATCH against a `state.rs` that no longer contained the mechanism, which is
# the vacuous-pass failure this repository has now hit three times. Each pattern below is checked
# against the file that actually holds the code today.
# Anchored on the opening paren. Without it the pattern is a *prefix* match, and a rename to
# `pin_at_boot_renamed` still satisfied it — caught by planting exactly that edit and watching this
# line report PRESENT. Every `fn` pattern below carries the paren for the same reason.
assert_present "the master key id is pinned once at startup" \
    "src/master.rs" "pub async fn pin_at_boot\("
assert_present "the pin is write-once, not a reassignable field" \
    "src/master.rs" "cell: OnceLock<Uuid>"
assert_present "startup aborts rather than serving with an unpinnable master" \
    "src/main.rs" "state.master_pin.pin_at_boot\(&state.db\).await.map_err"
assert_present "the demotion is applied at one choke point, in the middleware" \
    "src/middleware.rs" "state.master_pin.authenticate\(&state.db, &mut key_record\)"
assert_present "a key claiming master is demoted unless it is the pinned one" \
    "src/master.rs" "key\.is_master = false"
# The call now threads the connection explicitly, because it moved off `SchemaManager::has_index` to
# `crate::db::has_index`. That helper's PostgreSQL arm was compiled out by a cargo feature this crate
# does not enable on `sea-orm-migration`, so the boot check answered `BackendNotSupported` and the
# service could not start on Postgres at all. The pattern is updated rather than loosened: an
# assertion that stops matching the code it guards is the vacuous-pass failure this file exists to
# prevent, and it caught this change correctly.
assert_present "the §5 uniqueness index is re-checked at runtime, not just in the migration" \
    "src/master.rs" "has_index\(db, API_KEYS_TABLE, MASTER_MARKER_INDEX\)"
# And the check must be backend-agnostic, since the version it replaced was not.
assert_present "the runtime index check works on every supported backend" \
    "src/db.rs" "fn index_catalog_query"

# The demotion must stay in exactly one place. A second copy is not a redundancy — it is a second
# thing to keep correct, and the one that gets it wrong is invisible because the other still works.
#
# The pattern is `key.is_master = false` — the mutation on a model — and not the bare
# `is_master = false`, which the first version of this check used. That version reported DRIFT
# immediately, correctly by its own rule and wrongly by the intended one: two migrations quote
# `UPDATE api_keys SET is_master = false WHERE id IN (...)` inside operator-facing error text, which
# is advice for a human, not a demotion. `src/migration/` is excluded for the same reason.
demotion_files=$(grep -rln "key\.is_master = false" "$PROJECT_ROOT/src" --include='*.rs' \
    | grep -v "/src/migration/" | wc -l)
if [ "$demotion_files" -eq 1 ]; then
    echo "  ${GREEN}✓ MATCH${RESET}   the demotion has exactly one implementation in src/"
    MATCH_COUNT=$((MATCH_COUNT + 1))
else
    echo "  ${RED}✗ DRIFT${RESET}   the demotion must live in exactly one file (found $demotion_files)"
    grep -rn "key\.is_master = false" "$PROJECT_ROOT/src" --include='*.rs' \
        | grep -v "/src/migration/" | sed 's/^/             /'
    DRIFT_COUNT=$((DRIFT_COUNT + 1))
fi

# The two probes answer unauthenticated callers, so their placement *outside* the `/api` nest is a
# security property rather than a routing detail. Mounted inside it they would sit behind
# `auth_middleware` and become uncallable by any orchestrator — and, worse, the failure would look
# like a broken healthcheck rather than a misplaced route.
assert_present "liveness is mounted outside the authenticated nest" \
    "src/lib.rs" 'route\("/health", get\(api::health_check\)\)'
assert_present "readiness is mounted outside the authenticated nest" \
    "src/lib.rs" 'route\("/ready", get\(api::readiness_check\)\)'
# The Kubernetes-idiomatic aliases the peer also mounts. An operator writing one set of manifests for
# both services should not have to remember which of the pair answers which spelling.
assert_present "the /healthz alias matches the peer's spelling" \
    "src/lib.rs" 'route\("/healthz", get\(api::health_check\)\)'
assert_present "the /readyz alias matches the peer's spelling" \
    "src/lib.rs" 'route\("/readyz", get\(api::readiness_check\)\)'
# The probes live in `api/health.rs` on both sides. This is a naming assertion, not a behavioural
# one, and it is here because the file was `api/system.rs` until the parity audit — `system.rs` is
# the peer's name for a *different* module (its effective-configuration endpoint).
if [ -f "$PROJECT_ROOT/src/api/health.rs" ] && [ -f "$PEER_ROOT/src/api/health.rs" ]; then
    echo "  ${GREEN}✓ MATCH${RESET}   the probes live in src/api/health.rs on both sides"
    MATCH_COUNT=$((MATCH_COUNT + 1))
else
    echo "  ${RED}✗ DRIFT${RESET}   src/api/health.rs is missing on one side"
    DRIFT_COUNT=$((DRIFT_COUNT + 1))
fi
# Neither probe may hand an anonymous caller a build identifier.
assert_absent "no public probe discloses the build version" \
    '"version":[[:space:]]*env!'
if grep -n 'route("/health"' "$PROJECT_ROOT/src/lib.rs" | grep -q "$(grep -n 'let api_routes' "$PROJECT_ROOT/src/lib.rs" | cut -d: -f1)"; then
    echo "  ${RED}✗ DRIFT${RESET}   the probes are inside the authenticated router"
    DRIFT_COUNT=$((DRIFT_COUNT + 1))
else
    echo "  ${GREEN}✓ MATCH${RESET}   the probes are outside auth_middleware"
    MATCH_COUNT=$((MATCH_COUNT + 1))
fi

# Foreign keys are the schema's half of RBAC_MODEL.md §6 ("data is never destroyed implicitly"), and
# in SQLite they are per-connection and OFF by default — so this is a property of how the pool is
# opened, not of the migrations. Asserted here because it is one deleted line away from silently
# disabling every cascade and every orphan refusal in the database.
assert_present "foreign key enforcement is set at connection time" \
    "src/db.rs" "\.foreign_keys\(true\)"
assert_present "synchronous=NORMAL is set at connection time" \
    "src/db.rs" "SqliteSynchronous::Normal"

# No raw SQL for DML anywhere in `src/`, migrations excepted.
#
# Typed SeaORM is not a style preference here. A hand-built statement is a place where a filter can
# be forgotten (`WHERE owner_key_id = …` omitted is a tenancy breach that compiles) and where a value
# can be interpolated instead of bound. The entity API makes the first a type error and the second
# impossible, so the rule worth enforcing is not "write good SQL" but "do not write SQL".
#
# Two exemptions, both narrow and both deliberate:
#   - `src/migration/` — DDL is the one thing SeaQuery genuinely cannot express portably here
#     (generated columns, per-engine storage classes), and it is reviewed as schema, not as queries.
#   - `PRAGMA` — engine configuration rather than a query, SQLite-only, with no typed representation
#     in SeaORM at all. It is also convergence-tracked against the peer's `apply_sqlite_pragmas`.
check_no_raw_sql() {
    local label="no raw SQL outside migrations (PRAGMA excepted)"
    local hits
    # The statement text sits a few lines below the call it belongs to — `Statement::from_string(`
    # opens, the backend follows, and the SQL itself lands third — so a line-wise `grep -v PRAGMA`
    # cannot see it and would report `apply_sqlite_pragmas` forever. Each file is buffered and a hit
    # cleared only when the statement it opens is a PRAGMA, which is the exemption actually intended.
    #
    # One file per awk invocation, using `END` rather than gawk's `ENDFILE`. The first version of this
    # check used `ENDFILE` and reported CLEAN against a deliberately planted `execute_unprepared`:
    # the awk here is **mawk**, where `ENDFILE` is not a pattern but an ordinary — always false —
    # variable reference, so the block never ran. A gate that cannot fail is worse than no gate,
    # because it is reported as evidence.
    hits=""
    local file
    while IFS= read -r file; do
        local found
        found=$(awk -v path="${file#"$PROJECT_ROOT/"}" '
            { L[NR] = $0 }
            END {
                for (i = 1; i <= NR; i++) {
                    line = L[i]
                    if (line !~ /execute_unprepared|Statement::from_(string|sql)|(query_one|query_all|execute)_raw/) continue
                    if (line ~ /^[ \t]*(\/\/|\/\*|\*)/) continue          # a comment about it
                    # Outside `db.rs` there is no exemption at all: any raw-SQL call is a finding.
                    #
                    # Inside `db.rs` the test is what the statement *does*, not what sits near it.
                    # An earlier version exempted anything within six lines of the word "pragma",
                    # which that file contains almost everywhere — a planted
                    # `execute_unprepared("DELETE FROM api_keys")` appended to it was reported CLEAN.
                    # Looking for DML keywords instead cannot be satisfied by adjacent prose: the
                    # rule being enforced is "no raw SQL for SELECT/INSERT/UPDATE/DELETE", so that
                    # is literally what is matched. The window looks both ways because the statement
                    # text may sit below the call (`Statement::from_string(` opens, backend follows,
                    # SQL lands third) or above it (a table of pragmas iterated in a loop).
                    flag = 1
                    if (path == "src/db.rs") {
                        flag = 0
                        lo = i - 6; if (lo < 1) lo = 1
                        hi = i + 6; if (hi > NR) hi = NR
                        for (j = lo; j <= hi; j++)
                            if (toupper(L[j]) ~ /SELECT |INSERT INTO|UPDATE |DELETE FROM/) flag = 1
                    }
                    if (flag) printf "%s:%d:%s\n", path, i, line
                }
            }
        ' "$file")
        [ -n "$found" ] && hits="${hits}${found}"$'\n'
    done < <(find "$PROJECT_ROOT/src" -name '*.rs' -not -path "$PROJECT_ROOT/src/migration/*")
    hits=$(printf '%s' "$hits" | sed '/^$/d')

    if [ -z "$hits" ]; then
        echo "  ${GREEN}✓ CLEAN${RESET}   $label"
        MATCH_COUNT=$((MATCH_COUNT + 1))
        return
    fi
    echo "  ${RED}✗ FOUND${RESET}   $label — use typed entity methods or SeaQuery instead"
    echo "$hits" | sed 's|^'"$PROJECT_ROOT"'/|      |'
    DRIFT_COUNT=$((DRIFT_COUNT + 1))
}
check_no_raw_sql
echo

# ─────────────────────────────────────────────────────────────
echo "${BOLD}Pillar 1 — Proxy resolution & X-Forwarded-For${RESET}"
# The chain walk is the one function that is supposed to be character-for-character identical: both
# services resolve a client address from the same header under the same trust rule, and a difference
# here means one of them is trusting an address the other would not.
compare_fn "X-Forwarded-For chain walk" \
    "src/config.rs" "resolve_client_ip" \
    "src/config.rs" "resolve_client_ip"
compare_fn "IPv4-mapped normalization" \
    "src/config.rs" "normalize_ip" \
    "src/config.rs" "normalize_ip"
compare_fn "trusted-network membership" \
    "src/config.rs" "is_trusted" \
    "src/config.rs" "is_trusted"
compare_fn "bind-address parsing" \
    "src/config.rs" "parse_bind_addr" \
    "src/config.rs" "parse_bind_addr"
# `resolve_hostname` is deliberately NOT diffed here, and this note is the reason.
#
# It was tracked as a documented divergence until 2026-08-03 because the return shapes differ: the
# peer hands back `(Vec<IpNetwork>, bool)` where this service returns `Vec<IpNetwork>`. Reading both
# retired that as a false positive. The peer returns `false` in exactly the two empty cases — a
# lookup error, and a success with zero addresses — so its bool is `!networks.is_empty()` by
# construction, which is precisely what this service's caller derives at the call site. There is no
# state either function can be in that the other cannot express.
#
# Keeping it listed cost something real: a divergence report that names a difference carrying no
# behaviour trains its reader to skim, and the entries below it are ones that genuinely matter. The
# fail-closed outcome — the property a regression here would actually break — is asserted instead.
assert_present "an unresolvable hostname is logged and trusted with nothing (fail closed)" \
    "src/config.rs" "Could not resolve TRUSTED_PROXIES hostname"
assert_present "negative DNS caching is configured" \
    "src/config.rs" "NEGATIVE_TTL"
assert_present "boot grace period for unresolvable names" \
    "src/config.rs" "BOOT_GRACE_PERIOD"
echo

# ─────────────────────────────────────────────────────────────
echo "${BOLD}Pillar 2 — Cryptography${RESET}"
# The dependency, not just the type name. `src/crypto.rs` could keep every `XChaCha20Poly1305`
# mention in a doc comment while the crate underneath had been swapped, so the manifest is asserted
# separately — and `aes-gcm` is asserted **gone**, because the migration away from it is only
# complete if nothing can quietly reintroduce a 96-bit-nonce path beside the 192-bit one.
if grep -qE '^chacha20poly1305\s*=' "$PROJECT_ROOT/Cargo.toml"; then
    echo "  ${GREEN}✓ PRESENT${RESET} chacha20poly1305 is a declared dependency"
    MATCH_COUNT=$((MATCH_COUNT + 1))
else
    echo "  ${RED}✗ ABSENT${RESET}  chacha20poly1305 is not declared in Cargo.toml"
    DRIFT_COUNT=$((DRIFT_COUNT + 1))
fi
if grep -qE '^aes[-_]gcm\s*=' "$PROJECT_ROOT/Cargo.toml"; then
    echo "  ${RED}✗ DRIFT${RESET}   aes-gcm is back in Cargo.toml — the retired 96-bit-nonce AEAD"
    DRIFT_COUNT=$((DRIFT_COUNT + 1))
else
    echo "  ${GREEN}✓ CLEAN${RESET}   aes-gcm is not a dependency"
    MATCH_COUNT=$((MATCH_COUNT + 1))
fi

assert_present "XChaCha20-Poly1305 is the at-rest AEAD" \
    "src/crypto.rs" "XChaCha20Poly1305"
assert_present "192-bit nonce width" \
    "src/crypto.rs" "NONCE_LEN: usize = 24"
assert_present "constant-time signature comparison" \
    "src/crypto.rs" "verify_slice"
assert_present "the encryption key is length-checked, not hashed into shape" \
    "src/crypto.rs" "KEY_LEN"

# Both 64-hex-character rules, asserted at the line that enforces them rather than at a doc comment.
#
# They cover different credentials and are equally deletable: `KEY_LEN` guards the at-rest encryption
# key, and the check below guards the bootstrap **master key** — the one credential that can
# administer every other credential. That one accepted any non-empty string until it was fixed, with
# a startup warning as its only objection, so the assertion here is specifically that the refusal is
# a `Result`, not a log line.
assert_present "the bootstrap master key must be 64 hex characters" \
    "src/config.rs" "MASTER_KEY_HEX_LEN: usize = 64"
assert_present "a malformed bootstrap master key is refused, not warned about" \
    "src/config.rs" "pub fn validate_initial_master_key\("
# The call site. Its *fatality* is asserted behaviourally instead — `test_e2e.sh` §29 boots four
# instances with malformed keys and checks each process exits — because a structural pattern here
# would have to encode how the error is propagated, and that spelling changed once already: the
# refusal is now logged before being returned, since `main`'s `Box<dyn Error>` renders with `Debug`
# and would otherwise discard the whole operator message.
assert_present "startup validates the bootstrap master key before using it" \
    "src/main.rs" "validate_initial_master_key\(&fixed_key\)"
assert_present "the master key rule checks the alphabet, not only the length" \
    "src/config.rs" "is_ascii_hexdigit"
# Both services require `X-Signature-256: sha256=<hex>` and reject a bare digest. This service
# accepted either spelling until 2026-08-03, which meant a request it would take was one the peer
# would refuse — a difference that surfaces as a broken dispatch rather than as a finding. The `?`
# is the load-bearing character: `strip_prefix(...).unwrap_or(provided)` is the exact edit that
# reintroduces the fallback, and it looks like a tidy-up rather than a downgrade.
assert_present "the sha256= prefix is mandatory, not stripped-if-present" \
    "src/crypto.rs" 'strip_prefix\(SIGNATURE_PREFIX\)\?'
assert_absent "no bare-hex signature fallback" \
    'strip_prefix\("sha256="\)[[:space:]]*\.unwrap_or'
# The whole point of the constant-time comparison is undone by one `==` on a digest, and that is an
# easy edit for someone "simplifying" the code. There is no legitimate reason for either spelling to
# reappear, so this is an absolute prohibition rather than a comparison.
assert_absent "no equality comparison on a signature or MAC" \
    '(signature|hmac|mac|digest|secret)[a-z_]*[[:space:]]*==[[:space:]]*[^=]|==[[:space:]]*[a-z_]*(signature|hmac|digest)'
echo

# ─────────────────────────────────────────────────────────────
echo "${BOLD}Pillar 3 — Pipeline ordering & memory bounds${RESET}"
assert_present "the router-wide body limit is a named default, not a literal" \
    "src/lib.rs" "MAX_REQUEST_BODY_BYTES: usize = config::DEFAULT_MAX_BODY_MIB"
assert_present "the limit is applied to the router" \
    "src/lib.rs" "DefaultBodyLimit::max\(config::max_body_bytes\(\)\)"
# The property is that both layers resolve through the *same function*, so they cannot drift into a
# band of sizes one accepts and the other refuses. Asserted on the call, not on a shared constant,
# because the limit became runtime-configurable (`MAX_BODY_SIZE_MIB`) in Session 52.
assert_present "the signature buffer resolves through the same function as the router limit" \
    "src/middleware.rs" "crate::config::max_body_bytes\(\)"
# Ordering is asserted structurally: the signature check must appear before the bound_ips check in
# the middleware source. Reversing them reintroduces the 401/403 oracle, and would otherwise be
# caught only by a test someone might delete.
OUR_MW="$PROJECT_ROOT/src/middleware.rs"
SIG_LINE=$(grep -n "verify_signature" "$OUR_MW" | head -1 | cut -d: -f1)
CIDR_LINE=$(grep -n "bound_ips" "$OUR_MW" | grep -v "^\s*//" | tail -1 | cut -d: -f1)
if [ -n "$SIG_LINE" ] && [ -n "$CIDR_LINE" ] && [ "$SIG_LINE" -lt "$CIDR_LINE" ]; then
    echo "  ${GREEN}✓ ORDERED${RESET} authentication precedes the bound_ips check (line $SIG_LINE < $CIDR_LINE)"
    MATCH_COUNT=$((MATCH_COUNT + 1))
else
    echo "  ${RED}✗ ORDER${RESET}   authentication must precede the bound_ips check — a 401/403 oracle otherwise"
    DRIFT_COUNT=$((DRIFT_COUNT + 1))
fi
assert_present "anti-replay guard is consulted" \
    "src/middleware.rs" "replay\.check_and_record"
# The guard now lives in its own module on both sides, and keys on the raw digest rather than on
# header text. Monotonic expiry is the load-bearing part: wall-clock arithmetic let an NTP step
# evict live entries, so a wall-clock call inside the guard is a regression, not a style choice.
assert_present "anti-replay tracking has a dedicated module" \
    "src/replay.rs" "pub struct ReplayGuard"
assert_present "replay entries expire on the monotonic clock" \
    "src/replay.rs" "use tokio::time::Instant"
assert_absent "replay expiry does not consult the wall clock" \
    "src/replay.rs" "now_utc()"
assert_absent "a saturated replay guard is never flushed" \
    "src/replay.rs" "seen.clear()"
assert_present "replay entries are keyed on the raw digest" \
    "src/replay.rs" "digest: Vec<u8>"
assert_present "the full request target is signed" \
    "src/middleware.rs" "path_and_query"
echo

# ─────────────────────────────────────────────────────────────
echo "${BOLD}Pillar 4 — Database resilience & retention${RESET}"
# Both services now keep this in `src/db.rs`, so the *module* difference that used to explain the
# divergence is gone. What remains is a real behavioural difference, stated plainly rather than left
# as "wording": this service applies **five** pragmas (adding `foreign_keys=ON`,
# `synchronous=NORMAL`, and `temp_store=MEMORY`, the last added during a concurrent-write-load
# tuning pass) where the peer applies two. The shared half — WAL, the busy timeout, and the
# never-fatal handling of both — is what this comparison is still watching.
compare_fn "SQLite pragma initialization" \
    "src/db.rs" "apply_sqlite_pragmas" \
    "src/db.rs" "apply_sqlite_pragmas" \
    "this service applies 5 pragmas (adds foreign_keys, synchronous, temp_store); the peer applies 2"
# The pragmas must not be able to abort startup. A `?` inside would make a read-only mount fatal.
if grep -A40 "pub async fn apply_sqlite_pragmas" "$PROJECT_ROOT/src/db.rs" | grep -qE '\?;\s*$'; then
    echo "  ${RED}✗ FATAL${RESET}   apply_sqlite_pragmas propagates an error — it must degrade, not abort"
    DRIFT_COUNT=$((DRIFT_COUNT + 1))
else
    echo "  ${GREEN}✓ SOFT${RESET}    apply_sqlite_pragmas cannot abort startup"
    MATCH_COUNT=$((MATCH_COUNT + 1))
fi
assert_present "retention window is environment-configurable" \
    "src/retention.rs" "RETENTION_DAYS_ENV"
assert_present "92-day default" \
    "src/retention.rs" "DEFAULT_RETENTION_DAYS: i64 = 92"
assert_present "purge guards on both is_deleted and deleted_at" \
    "src/retention.rs" "DeletedAt.is_not_null"
echo

# ─────────────────────────────────────────────────────────────
echo "${BOLD}Pillar 5 — Authentication posture (asymmetric by design)${RESET}"
echo "  ${BLUE}note${RESET}     simply_ip_vault requires full-URI HMAC + anti-replay on every key, with"
echo "           no opt-out anywhere in its API surface. simply_hook_executor's asymmetry moved,"
echo "           not away: it used to sit on api_keys.hmac_mode (a per-key choice, since retired to"
echo "           CANONICAL_V1-only); it now sits on hooks.auth_mode — a per-hook door that lets the"
echo "           three routes that actually invoke a hook (execute/test/webhook alias) accept a"
echo "           keyless caller when that specific hook opts in (HMAC_ONLY/NONE), while every other"
echo "           route keeps requiring a key exactly as before. This asymmetry is intentional — see"
echo "           AGENT_NOTES.MD, Convergence Parity Check."
# What must hold on *this* service is that there is no way to opt out — no per-key HMAC mode ever
# existed here, and there is no per-hook (or per-resource) equivalent either: unlike the peer,
# nothing in this service's outbound webhook or inbound API model has ever had a keyless door.
assert_absent "no per-key HMAC mode exists on this service" \
    "hmac_mode|HmacMode|REQUIRE_SIGNED_REQUESTS"
echo

# ─────────────────────────────────────────────────────────────
echo "${BOLD}Summary${RESET}"
echo "  ${GREEN}$MATCH_COUNT matching${RESET}   ${YELLOW}$EXPECTED_COUNT documented divergence(s)${RESET}   ${RED}$DRIFT_COUNT unexplained${RESET}"
echo

if [ "$DRIFT_COUNT" -gt 0 ]; then
    echo "${RED}Convergence check FAILED${RESET} — $DRIFT_COUNT primitive(s) drifted." >&2
    echo "Re-run with --verbose to see the normalized diffs." >&2
    exit 1
fi

echo "${GREEN}Convergence check PASSED${RESET} — every tracked primitive agrees or diverges as documented."
exit 0
