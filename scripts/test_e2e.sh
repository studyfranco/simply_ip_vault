#!/usr/bin/env bash
#
# End-to-end test suite for simply_ip_vault.
#
# Builds the project, boots a fresh instance against a throwaway SQLite database with a
# deterministic bootstrap master key (via INITIAL_MASTER_KEY — no log-scraping), and drives the
# whole HTTP API with curl + jq: RBAC across a multi-key permission matrix, IP add/list/filter/
# update/delete across multiple groups (including banlist/whitelist overlap, and deletion via
# both query-string params and a JSON body), key lifecycle (create/update/rotate/delete), bound-IP
# CIDR enforcement, audit log generation + pagination + enrichment (client IP, API key name/
# prefix), webhook lifecycle (create/list/delete, with the mandatory `name` field) and per-webhook
# event filtering (events=IP_ADD/IP_UPDATE/IP_DELETE), RBAC-before-group-type-validation precedence
# and strict banlist/whitelist type enforcement on /api/ban and /api/white, auto-granted creator
# permissions on both explicit (POST /api/groups) and implicit (ban/white auto-create) group
# creation, explicit group_type selection on group creation (with a lenient default-to-banlist
# fallback for an omitted/invalid value), IP/CIDR canonicalization (a bare address and its /32 or
# /128 form are the same stored record, while genuine subnets keep their notation), latest-
# activity-first ordering on GET /api/ips, a lightweight format=iplist/mode=iplist response mode,
# human-readable target-key names in audit log details (instead of a bare UUID), and the
# group-identification bug fixes (duplicate-name 409, flexible group_id/group_name). Every request
# is logged with a timestamp, method, full URL, color-coded status, and jq-formatted body.
#
# Usage: ./scripts/test_e2e.sh
# Requires: curl, jq. Needs port 3000 free, or BASE_URL pointed at a free one (BIND_HOST/PORT
# configure the listen address;
# this suite uses the default and boots its throwaway instances on higher ports).
# Optional: python3 (only for live webhook-delivery verification in §13; that one section degrades
# to a skip + warning without it, everything else is unaffected). Optional: a vendored checkout of
# simply_hook_executor at ../example/simply_hook_executor, built and booted as a second live
# service by §31, which drives the full webhook auth-mode matrix against a real sibling receiver
# rather than a capture script. Degrades to a skip + warning if the checkout is absent, its build
# fails, or it does not come up — everything else is unaffected.
# Exit code: 0 if every check passed, 1 otherwise.

set -uo pipefail
# Not using `set -e`: assertions on purpose expect non-2xx responses (401/403/404/409), so a
# non-zero curl/jq exit inside a check must not abort the whole run.

# ── Configuration ────────────────────────────────────────────────────────────

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
# 127.0.0.1 rather than "localhost": avoids any IPv6 (::1) resolution first-try delay against a
# server that only ever binds the IPv4 wildcard address.
BASE_URL="${BASE_URL:-http://127.0.0.1:3000}"
# The port the main instance listens on, derived from BASE_URL so the two can never disagree.
#
# This used to be the literal 3000 in three unrelated places — the preflight check, the throwaway
# instances below, and nothing at all in the server's own environment, which simply took the default.
# The header above has always documented `PORT` as configurable, so the promise was there and only
# the plumbing was missing: overriding BASE_URL pointed curl at a new port while the server stayed on
# 3000. Deriving it once here makes `BASE_URL=http://127.0.0.1:3300 ./scripts/test_e2e.sh` work, which
# is what lets this suite run beside a `simply_hook_executor` already holding 3000.
#
# Adopted from `simply_hook_executor` in the Session 56 reference audit: the port is now *chosen*
# rather than assumed. An explicitly requested one is honoured and a conflict on it is fatal —
# silently moving would defeat the point of pinning it — while the default walks up from 3000 to the
# first free port. That is a direct fix for a real collision: this suite could not run at all while a
# `simply_hook_executor` instance held 3000, and the previous behaviour was to abort with advice to
# stop it.
REQUESTED_PORT=""
if [ -n "${BASE_URL_EXPLICIT:-}" ] || [ -n "${PORT:-}" ]; then
    REQUESTED_PORT="${PORT:-$(printf '%s' "$BASE_URL" | sed -n 's|.*:\([0-9]\{1,5\}\)$|\1|p')}"
elif [ -n "${BASE_URL+x}" ] && [ "$BASE_URL" != "http://127.0.0.1:3000" ]; then
    REQUESTED_PORT="$(printf '%s' "$BASE_URL" | sed -n 's|.*:\([0-9]\{1,5\}\)$|\1|p')"
fi

# True when something is listening. The subshell's exit status is the connect result, and the
# descriptor it opens dies with it, so nothing leaks into the caller's shell.
port_in_use() {
    (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null
}

pick_port() {
    if [ -n "$REQUESTED_PORT" ]; then
        if port_in_use "$REQUESTED_PORT"; then
            err "PORT=$REQUESTED_PORT was requested but something is already listening on it."
            exit 1
        fi
        VAULT_PORT="$REQUESTED_PORT"
        return
    fi

    local candidate
    for candidate in $(seq 3000 3100); do
        if ! port_in_use "$candidate"; then
            VAULT_PORT="$candidate"
            [ "$candidate" -ne 3000 ] && log "Port 3000 is busy; using the next free port $VAULT_PORT"
            BASE_URL="http://127.0.0.1:$VAULT_PORT"
            return
        fi
    done
    err "No free port between 3000 and 3100."
    exit 1
}
VAULT_PORT=3000
# Deterministic bootstrap secret: passed to the server as INITIAL_MASTER_KEY so this script never
# needs to scrape the master key back out of the (buffered, redirected) server log.
MASTER_KEY="e2eaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
# Its HMAC counterpart, passed as INITIAL_MASTER_SIGNING_SECRET for the same reason: every request
# must now carry an X-Signature-256, so the script needs the bootstrap key's signing secret up front.
MASTER_SIGNING_SECRET="e2e_master_signing_secret_for_testing_987654321"

# Maps a plaintext API key -> its HMAC signing secret, so api_call() can sign on behalf of whichever
# key a check happens to use without every call site having to pass a second credential.
# register_key_secret() populates it as keys are minted during the run.
declare -A SIGNING_SECRETS=()
SIGNING_SECRETS["$MASTER_KEY"]="$MASTER_SIGNING_SECRET"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/simply_ip_vault_e2e.XXXXXX")"
DB_PATH="$WORK_DIR/e2e.db"
SERVER_LOG="$WORK_DIR/server.log"
RESP_BODY_FILE="$WORK_DIR/resp_body"
SERVER_PID=""
# Local loopback listener used only by the webhook event-filtering section to observe whether a
# dispatch actually happened; started lazily there, but declared here so `cleanup()` can always
# safely check it even if the script exits before that section runs.
RECEIVER_PORT="${RECEIVER_PORT:-18763}"
RECEIVER_LOG="$WORK_DIR/receiver_hits.log"
RECEIVER_PID=""

# A second, real sibling service used only by §31 as a live webhook receiver, not a stand-in like
# the Python capture server above. Declared here, same reasoning as RECEIVER_PID: cleanup() must be
# able to check it regardless of where the script exits.
HOOK_EXECUTOR_PORT="${HOOK_EXECUTOR_PORT:-18771}"
HOOK_EXECUTOR_PID=""

PASS_COUNT=0
FAIL_COUNT=0

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
DIM='\033[2m'
BOLD='\033[1m'
RESET='\033[0m'

# ── Helpers ──────────────────────────────────────────────────────────────────
#
# Every diagnostic/progress function below writes to STDERR, never STDOUT. This is deliberate,
# not cosmetic: helper functions like `create_scoped_key` (further down) need to hand a real
# value back to the caller via plain global variables, and several `check_jq` calls parse
# `$RESP_BODY` via `$(...)` command substitution elsewhere in the script. Command/process
# substitution captures *only* stdout, so if timestamps/status lines/PASS-FAIL/response-body
# output went to stdout too, they'd contaminate any captured value (an early version of this
# script had exactly that bug, traced to a `mapfile < <(...)` capturing a helper function's log
# lines instead of its actual return value). Keeping stdout pristine and routing everything else
# to stderr is the robust fix — a terminal shows both streams interleaved anyway, so a normal run
# of this script looks identical either way.

ts() { date +"%H:%M:%S.%3N"; }

log() { echo -e "$(ts) ${CYAN}[INFO]${RESET} $*" >&2; }
warn() { echo -e "$(ts) ${YELLOW}[WARN]${RESET} $*" >&2; }
err() { echo -e "$(ts) ${RED}[ERROR]${RESET} $*" >&2; }

log_section() {
    echo "" >&2
    echo -e "$(ts) ${BOLD}${MAGENTA}=== $* ===${RESET}" >&2
}

status_color() {
    case "$1" in
        2??) echo -n "$GREEN" ;;
        401|403|404|409|422) echo -n "$YELLOW" ;;
        4??) echo -n "$YELLOW" ;;
        5??) echo -n "$RED" ;;
        *) echo -n "$RESET" ;;
    esac
}

# Pretty-prints $RESP_BODY (JSON via jq when possible, indented under the request line above).
print_response_body() {
    if [ -z "$RESP_BODY" ]; then
        echo -e "$(ts)          ${DIM}(empty body)${RESET}" >&2
        return
    fi
    local formatted
    if formatted=$(echo "$RESP_BODY" | jq . 2>/dev/null); then
        while IFS= read -r line; do
            echo -e "$(ts)          ${DIM}${line}${RESET}" >&2
        done <<< "$formatted"
    else
        echo -e "$(ts)          ${DIM}${RESP_BODY}${RESET}" >&2
    fi
}

# Computes the full X-Signature-256 header value the server expects — `sha256=<hex>` over the
# CANONICAL_V1 string METHOD\nPATH\nTIMESTAMP\nRAW_BODY (the four fields joined by single LFs, no
# trailing newline).
#
# The `sha256=` prefix is part of the return value rather than something each call site appends,
# because the server now *requires* it and a helper that returned a bare digest would put a
# 401-producing footgun behind every one of the several hundred checks below.
#
# `printf` with an explicit `%s\n%s\n%s\n%s` format (rather than `echo`, or interpolating "\n" into
# a single string) is what makes the delimiters real newlines and keeps the message byte-exact:
# no trailing newline, and no mangling of JSON bodies containing backslashes or leading dashes.
# Usage: hmac_sign SECRET METHOD PATH TIMESTAMP BODY
hmac_sign() {
    local secret="$1" method="$2" target="$3" timestamp="$4" body="${5:-}"
    # CANONICAL_V1 signs the **full request target**, query string included. Stripping it here (as
    # this helper used to) would leave `?hard=true` and `?include_deleted=true` rewritable on an
    # otherwise-valid signed request — and would make the tampering checks below pass vacuously.
    printf 'sha256=%s' "$(printf '%s\n%s\n%s\n%s' "$method" "$target" "$timestamp" "$body" \
        | openssl dgst -sha256 -hmac "$secret" \
        | sed 's/^.*= //')"
}

# Last X-Timestamp used per distinct request identity, so a repeated identical call gets a fresh
# one rather than reproducing a signature the server has already accepted.
declare -A LAST_SIGNED_AT

# Returns an X-Timestamp for a request, guaranteed to differ from the last one used for the same
# request identity.
#
# A signature covers method, target, timestamp and body and nothing else, so **issuing the same call
# twice inside one wall-clock second reproduces the same signature**, which the server refuses as a
# replay. That is correct behaviour and this suite must not disable it — but the script fires
# hundreds of checks in a few seconds and legitimately repeats calls (list, mutate, list again), and
# several checks differ only in an *unsigned* header such as X-Forwarded-For. So the timestamp is
# advanced by one second per repeat of an identical call, which is exactly what elapsed time would
# have given a real caller. Distinct calls are untouched, so the clock never drifts far from now and
# the ±300s freshness window is unaffected.
# The result is left in $SIGNED_TS rather than printed: `$(next_timestamp ...)` would run the
# function in a subshell, where the update to LAST_SIGNED_AT is discarded the moment it returns —
# which silently reduces this to a plain `date +%s` and lets every repeat collide again.
# Usage: next_timestamp IDENTITY  ->  $SIGNED_TS
next_timestamp() {
    local identity="$1"
    local now; now=$(date -u +%s)
    local previous="${LAST_SIGNED_AT[$identity]:-0}"
    if [ "$now" -le "$previous" ]; then
        now=$((previous + 1))
    fi
    LAST_SIGNED_AT["$identity"]=$now
    SIGNED_TS=$now
}

# Records the signing secret for a freshly minted key so subsequent api_call invocations using that
# key can sign with it. Call immediately after any response carrying .plaintext_key/.signing_secret.
# Usage: register_key_secret PLAINTEXT_KEY SIGNING_SECRET
register_key_secret() {
    local key="$1" secret="$2"
    if [ -z "$key" ] || [ "$key" == "null" ] || [ -z "$secret" ] || [ "$secret" == "null" ]; then
        err "register_key_secret called with an empty key/secret — the API response was malformed"
        return 1
    fi
    SIGNING_SECRETS["$key"]="$secret"
}

# Performs an HTTP request and leaves the outcome in $RESP_STATUS / $RESP_BODY. Every call prints
# a timestamped, colored "[STATUS] METHOD /path" line followed by the jq-formatted response body.
# Usage: api_call METHOD PATH [API_KEY] [JSON_BODY] [X_FORWARDED_FOR]
api_call() {
    local method="$1" path="$2" api_key="${3:-}" data="${4:-}" xff="${5:-}"
    local args=(-s -o "$RESP_BODY_FILE" -w "%{http_code}" -X "$method")

    # Anti-replay timestamp: always sent, even for the deliberately-unauthenticated checks, so those
    # still fail on the credential under test rather than on a missing X-Timestamp.
    #
    # A signature covers method, target, timestamp and body and nothing else, so **issuing the same
    # call twice inside one wall-clock second reproduces the same signature**, which the server now
    # refuses as a replay. That is correct behaviour and this suite must not disable it — but this
    # script fires hundreds of checks in a few seconds and legitimately repeats calls (list, mutate,
    # list again). So the timestamp is advanced by one second per *repeat of an identical call*,
    # which is precisely what elapsed time would have given a real caller. Distinct calls are
    # untouched, so the clock never drifts far from now and the ±300s freshness window is unaffected.
    next_timestamp "$method|$path|$api_key|$data"
    local timestamp="$SIGNED_TS"
    args+=(-H "X-Timestamp: $timestamp")

    if [ -n "$api_key" ]; then
        args+=(-H "X-API-Key: $api_key")
        # An unknown key (the "invalid key is rejected" checks) has no registered secret; sign with a
        # placeholder so the request is still well-formed and gets rejected at key lookup, which is
        # the failure those checks are actually asserting.
        local secret="${SIGNING_SECRETS[$api_key]:-unregistered-key-has-no-signing-secret}"
        args+=(-H "X-Signature-256: $(hmac_sign "$secret" "$method" "$path" "$timestamp" "$data")")
    fi

    [ -n "$xff" ] && args+=(-H "X-Forwarded-For: $xff")
    if [ -n "$data" ]; then
        args+=(-H "Content-Type: application/json" -d "$data")
    fi
    RESP_STATUS=$(curl "${args[@]}" "$BASE_URL$path")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    local color; color=$(status_color "$RESP_STATUS")
    printf "%s ${color}[%s]${RESET} %-6s %s\n" "$(ts)" "$RESP_STATUS" "$method" "$BASE_URL$path" >&2
    print_response_body
}

# Usage: check EXPECTED_STATUS "description"
check() {
    local expected="$1" description="$2"
    if [ "$RESP_STATUS" == "$expected" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description (expected $expected, got $RESP_STATUS)" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (expected $expected, got $RESP_STATUS)" >&2
    fi
}

# Usage: check_jq '.some.jq.filter' "expected value" "description"
check_jq() {
    local filter="$1" expected="$2" description="$3"
    local actual
    actual=$(echo "$RESP_BODY" | jq -r "$filter" 2>/dev/null)
    if [ "$actual" == "$expected" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description (got '$actual')" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (expected '$expected', got '$actual')" >&2
    fi
}

# Compares two locally-computed values, for assertions that are not about an HTTP response at all —
# a process exit status, a log line, the presence of a file. Usage:
#   check_local ACTUAL EXPECTED "description"
# Asserts the last response body does NOT contain a needle.
#
# The empty-needle guard is the part worth copying: `""` is a substring of every string, so an
# assertion with an empty needle can never fail and would sit in the suite forever reporting PASS.
# Adopted from `simply_hook_executor`.
check_not_contains() {
    local needle="$1" description="$2"
    if [ -z "$needle" ]; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (empty needle — the assertion is vacuous)" >&2
        return
    fi
    if [[ "$RESP_BODY" == *"$needle"* ]]; then
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (the body contains it)" >&2
    else
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description" >&2
    fi
}

check_local() {
    local actual="$1" expected="$2" description="$3"
    if [ "$actual" == "$expected" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (expected '$expected', got '$actual')" >&2
    fi
}

# Usage: check_true "jq boolean expression producing true/false" "description"
check_true() {
    local expr="$1" description="$2"
    local actual
    actual=$(echo "$RESP_BODY" | jq -e "$expr" 2>/dev/null)
    if [ "$actual" == "true" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $description" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} $description (jq expr '$expr' was not true)" >&2
    fi
}

cleanup() {
    if [ -n "$SERVER_PID" ] && kill -0 "$SERVER_PID" 2>/dev/null; then
        log "Stopping server (pid $SERVER_PID)..."
        kill "$SERVER_PID" 2>/dev/null || true
        wait "$SERVER_PID" 2>/dev/null || true
    fi
    if [ -n "$RECEIVER_PID" ] && kill -0 "$RECEIVER_PID" 2>/dev/null; then
        log "Stopping local webhook receiver (pid $RECEIVER_PID)..."
        kill "$RECEIVER_PID" 2>/dev/null || true
        wait "$RECEIVER_PID" 2>/dev/null || true
    fi
    if [ -n "$HOOK_EXECUTOR_PID" ] && kill -0 "$HOOK_EXECUTOR_PID" 2>/dev/null; then
        log "Stopping simply_hook_executor (pid $HOOK_EXECUTOR_PID)..."
        kill "$HOOK_EXECUTOR_PID" 2>/dev/null || true
        wait "$HOOK_EXECUTOR_PID" 2>/dev/null || true
    fi
    rm -rf "$WORK_DIR"
}
trap cleanup EXIT INT TERM

# ── Preflight ────────────────────────────────────────────────────────────────

log_section "Preflight"

for bin in curl jq cargo openssl; do
    if ! command -v "$bin" >/dev/null 2>&1; then
        err "$bin is required but not found on PATH"
        exit 1
    fi
    log "Found $bin: $(command -v "$bin")"
done

pick_port
log "Main instance will listen on port $VAULT_PORT ($BASE_URL)"

# python3 is a *soft* dependency: only the live webhook-delivery verification (§13) needs a local
# HTTP listener to observe whether a dispatch actually happened. Its absence — or the receiver
# port being busy — degrades that one section to a warning + skip rather than failing the suite,
# since every other check (including the events-field API contract itself) needs only curl/jq.
if command -v python3 >/dev/null 2>&1; then
    log "Found python3: $(command -v python3) (used for live webhook-delivery verification)"
else
    warn "python3 not found — live webhook-delivery verification (§13) will be skipped."
fi

# ── Build & start ────────────────────────────────────────────────────────────

log_section "Build"
log "Running cargo build in $PROJECT_ROOT ..."
if ! (cd "$PROJECT_ROOT" && cargo build --quiet 2>"$WORK_DIR/build.log"); then
    err "Build failed:"
    cat "$WORK_DIR/build.log" >&2
    exit 1
fi
log "Build succeeded."

log_section "Boot"
# 64 hex characters, as `openssl rand -hex 32` would produce. Fixed rather than random so a failed
# run leaves a database the operator can still open with the same value.
E2E_ENCRYPTION_KEY="0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"

log "Starting server against a fresh database at $DB_PATH"
log "Using INITIAL_MASTER_KEY + INITIAL_MASTER_SIGNING_SECRET for deterministic bootstrap (no log-scraping needed)"
# ALLOW_PRIVATE_WEBHOOKS=true: §13 targets a webhook at a loopback receiver to observe deliveries,
# which SSRF protection would otherwise block by default. Every other webhook test in this script
# targets a real public host, so this doesn't loosen anything they depend on.
# VAULT_ENCRYPTION_KEY is set so the run exercises the XChaCha20-Poly1305 seal/open path for
# signing secrets end to end, rather than the plaintext development fallback. It MUST be exactly 64
# hex characters: a malformed key now aborts startup instead of silently degrading to plaintext, and
# §26 asserts exactly that by booting a throwaway instance with a bad one.
# TRUSTED_PROXIES=localhost: curl connects over loopback, so declaring it a trusted proxy is what
# lets the CIDR checks below use X-Forwarded-For to stand in for a client address — exactly as a
# real reverse proxy would. Spelled as a *hostname* rather than 127.0.0.1 on purpose: that exercises
# the dynamic DNS resolution path (the Docker/Traefik case) end to end against a real resolver,
# rather than only the literal-CIDR path the unit tests cover. It resolves to 127.0.0.1 and
# deliberately NOT to 127.0.0.2, which §6b connects from to exercise the untrusted-peer path.
DATABASE_URL="sqlite://$DB_PATH?mode=rwc" RUST_LOG=info INITIAL_MASTER_KEY="$MASTER_KEY" \
    INITIAL_MASTER_SIGNING_SECRET="$MASTER_SIGNING_SECRET" \
    VAULT_ENCRYPTION_KEY="$E2E_ENCRYPTION_KEY" \
    ALLOW_PRIVATE_WEBHOOKS=true \
    TRUSTED_PROXIES="localhost" \
    PORT="$VAULT_PORT" \
    "$PROJECT_ROOT/target/debug/simply_ip_vault" >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!

log "Waiting for the server to become ready (pid $SERVER_PID)..."
READY=0
for _ in $(seq 1 60); do
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
        err "Server process exited during startup. Log:"
        cat "$SERVER_LOG" >&2
        exit 1
    fi
    # Readiness is decided purely by whether the HTTP listener answers on a real API route —
    # never by log content, which may be buffered and lag behind the process actually being
    # ready to serve. `/api/groups` sits behind auth middleware, so an unauthenticated probe
    # never returns a plain connection failure once the server is up; any of 200/401/404 proves
    # the listener is live and axum is routing requests (curl's own exit code, not `-f`, is what
    # actually distinguishes "no HTTP response yet" from "got a response").
    STATUS_CODE=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/groups" 2>/dev/null)
    case "$STATUS_CODE" in
        200|401|404)
            READY=1
            break
            ;;
    esac
    sleep 0.5
done
if [ "$READY" -ne 1 ]; then
    err "Server did not become ready in time. Log:"
    cat "$SERVER_LOG" >&2
    exit 1
fi
log "Server is up."

api_call GET "/api/auth/me" "$MASTER_KEY"
check "200" "the deterministic INITIAL_MASTER_KEY authenticates"
check_jq ".is_master" "true" "it reports is_master=true"
# The one master in this installation, and now the only one there can ever be — RBAC_MODEL.md §5
# makes master status bootstrap-only and a unique index on api_keys.master_marker enforces it. Every
# later section that needs a master *target* uses this id, because no second one can be minted.
MASTER_ID=$(echo "$RESP_BODY" | jq -r '.id')

# ── 1. Basic auth ────────────────────────────────────────────────────────────

log_section "1. Basic Authentication"

api_call GET "/api/auth/me"
check "401" "no X-API-Key header is rejected"

api_call GET "/api/auth/me" "not-a-real-key"
check "401" "an invalid key is rejected"

# ── 1b. HMAC signing & anti-replay guard ────────────────────────────────────
#
# These checks bypass api_call() and drive curl directly: they need to send deliberately malformed
# or omitted auth headers, which api_call() exists precisely to get right.

log_section "1b. HMAC Signing & Anti-Replay Guard"

# Usage: raw_call METHOD PATH [curl args...] — same $RESP_STATUS/$RESP_BODY contract as api_call.
raw_call() {
    local method="$1" path="$2"; shift 2
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X "$method" "$@" "$BASE_URL$path")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    local color; color=$(status_color "$RESP_STATUS")
    printf "%s ${color}[%s]${RESET} %-6s %s\n" "$(ts)" "$RESP_STATUS" "$method" "$BASE_URL$path" >&2
    print_response_body
}

# Routed through the shared clock: `GET /api/auth/me` as the master key has already been issued
# earlier in this run, and an identical repeat within the same second is a replay by definition.
next_timestamp "GET|/api/auth/me|$MASTER_KEY|"
NOW_TS="$SIGNED_TS"
VALID_SIG=$(hmac_sign "$MASTER_SIGNING_SECRET" "GET" "/api/auth/me" "$NOW_TS" "")

# Control: the three headers together authenticate.
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $NOW_TS" -H "X-Signature-256: $VALID_SIG"
check "200" "X-API-Key + X-Timestamp + X-Signature-256 authenticates"

# Each header is individually mandatory.
raw_call GET "/api/auth/me" -H "X-Timestamp: $NOW_TS" -H "X-Signature-256: $VALID_SIG"
check "401" "missing X-API-Key is rejected"

raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Signature-256: $VALID_SIG"
check "401" "missing X-Timestamp is rejected"

# This is exactly the pre-HMAC request shape — it must no longer be sufficient.
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $NOW_TS"
check "401" "missing X-Signature-256 is rejected (a bare API key no longer authenticates)"

raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: not-a-number" -H "X-Signature-256: $VALID_SIG"
check "401" "a malformed X-Timestamp is rejected"

raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $NOW_TS" -H "X-Signature-256: deadbeef"
check "401" "a wrong signature is rejected"

# Anti-replay window: +/-300s, symmetric. Each of these carries a *correct* signature for the
# timestamp it sends, so only the freshness check can reject it.
#
# The two directions need different margins, because elapsed wall-clock time moves them oppositely:
# a stale timestamp only gets staler while the script runs, so it can never drift back inside the
# window. A *future* timestamp decays toward it — at NOW+301, one second of elapsed time between
# capturing NOW_TS and the server reading its own clock leaves a skew of 300, which is inside the
# window and legitimately returns 200. Hence a fresh capture immediately before the call plus a
# margin comfortably clear of the boundary.
#
# The exact ±300/±301 edge is pinned deterministically in
# `tests/security_tests.rs::attack_timestamp_forgery_outside_the_window_is_rejected_both_directions`,
# where the request is handled in-process microseconds after the timestamp is chosen. E2E asserts
# the behaviour, not the boundary.
# Captured fresh rather than derived from NOW_TS: `next_timestamp` may have pushed NOW_TS a second
# or two ahead of the real clock to avoid a replay collision, and subtracting from an inflated base
# would land inside the window and pass for the wrong reason.
STALE_TS=$(( $(date -u +%s) - 360 ))
STALE_SIG=$(hmac_sign "$MASTER_SIGNING_SECRET" "GET" "/api/auth/me" "$STALE_TS" "")
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $STALE_TS" -H "X-Signature-256: $STALE_SIG"
check "401" "a 301s-stale timestamp is rejected as a replay"

FUTURE_TS=$(( $(date -u +%s) + 360 ))
FUTURE_SIG=$(hmac_sign "$MASTER_SIGNING_SECRET" "GET" "/api/auth/me" "$FUTURE_TS" "")
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $FUTURE_TS" -H "X-Signature-256: $FUTURE_SIG"
check "401" "a future-dated timestamp beyond the window is rejected"

EDGE_TS=$((NOW_TS - 290))
EDGE_SIG=$(hmac_sign "$MASTER_SIGNING_SECRET" "GET" "/api/auth/me" "$EDGE_TS" "")
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $EDGE_TS" -H "X-Signature-256: $EDGE_SIG"
check "200" "a 290s-old timestamp is still inside the 300s window"

# The signature binds the body: replaying an authentic signature over different content fails.
BIND_BODY='{"target_address":"198.51.100.77","group_name":"Group-Sig","cause":"signed"}'
BIND_TS=$(date -u +%s)
BIND_SIG=$(hmac_sign "$MASTER_SIGNING_SECRET" "POST" "/api/ban" "$BIND_TS" "$BIND_BODY")
raw_call POST "/api/ban" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $BIND_TS" \
    -H "X-Signature-256: $BIND_SIG" -H "Content-Type: application/json" -d "$BIND_BODY"
check "200" "a correctly signed body is accepted"

raw_call POST "/api/ban" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $BIND_TS" \
    -H "X-Signature-256: $BIND_SIG" -H "Content-Type: application/json" \
    -d '{"target_address":"9.9.9.9","group_name":"Group-Sig","cause":"tampered"}'
check "401" "the same signature over a tampered body is rejected"

# ...and the path: a /api/ban signature cannot be replayed onto /api/white.
raw_call POST "/api/white" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $BIND_TS" \
    -H "X-Signature-256: $BIND_SIG" -H "Content-Type: application/json" -d "$BIND_BODY"
check "401" "a /api/ban signature replayed onto /api/white is rejected"

# ── CANONICAL_V1 adversarial probes ─────────────────────────────────────────
# Each of these carries an otherwise *perfect* request — correct key, correct signature over the
# exact bytes sent — and changes one thing. A 200 here means the corresponding control is not
# actually being enforced. Mirrors tests/security_tests.rs at the HTTP boundary.

# X-Timestamp must be mandatory, not merely validated when present. If a missing header skipped the
# freshness check, every captured signature would stay replayable forever, since the signature
# itself encodes no notion of time.
STRIP_TS=$(date -u +%s)
STRIP_BODY='{"target_address":"198.51.100.91","group_name":"Group-Sig","cause":"no-timestamp"}'
STRIP_SIG=$(hmac_sign "$MASTER_SIGNING_SECRET" "POST" "/api/ban" "$STRIP_TS" "$STRIP_BODY")
raw_call POST "/api/ban" -H "X-API-Key: $MASTER_KEY" \
    -H "X-Signature-256: $STRIP_SIG" -H "Content-Type: application/json" -d "$STRIP_BODY"
check "401" "CANONICAL_V1: omitting X-Timestamp on an otherwise valid signed request is rejected"

# The same, on a GET with no body, so the rejection cannot be attributed to body handling.
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Signature-256: $VALID_SIG"
check "401" "CANONICAL_V1: omitting X-Timestamp on a signed GET is rejected"

# An empty X-Timestamp must not be treated as absent-and-therefore-skipped, nor parsed as 0.
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp;" -H "X-Signature-256: $VALID_SIG"
check "401" "CANONICAL_V1: an empty X-Timestamp is rejected"

# The digest alone, without the mandatory `sha256=` tag. Every mutation below is applied to this and
# re-tagged, so each one tests the digest comparison rather than accidentally tripping the format
# check — a distinction that matters now that an untagged value is refused outright.
VALID_HEX="${VALID_SIG#sha256=}"

# Signature forgery: flip only the final hex digit, keeping 64 valid hex characters so the request
# reaches the constant-time MAC comparison instead of failing early in hex decoding.
FORGED_HEX="${VALID_HEX%?}"
case "${VALID_HEX: -1}" in
    0) FORGED_HEX="${FORGED_HEX}1" ;;
    *) FORGED_HEX="${FORGED_HEX}0" ;;
esac
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $NOW_TS" -H "X-Signature-256: sha256=$FORGED_HEX"
check "401" "a signature differing only in its last character is rejected"

# ...and the first character, so no position of the digest goes uncompared.
FIRST_FLIPPED="0${VALID_HEX:1}"
[ "${VALID_HEX:0:1}" == "0" ] && FIRST_FLIPPED="1${VALID_HEX:1}"
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $NOW_TS" -H "X-Signature-256: sha256=$FIRST_FLIPPED"
check "401" "a signature differing only in its first character is rejected"

# A truncated signature sharing a valid prefix must not pass a length-agnostic comparison.
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $NOW_TS" -H "X-Signature-256: sha256=${VALID_HEX:0:32}"
check "401" "a truncated signature with a valid prefix is rejected"

raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $NOW_TS" -H "X-Signature-256: sha256=${VALID_HEX}00"
check "401" "an over-long signature with a valid prefix is rejected"

# The `sha256=` tag is mandatory, so the *correct* digest sent bare must still be refused. This is
# the one check where the HMAC is genuinely valid and only the framing is wrong: it fails only if
# the bare-hex fallback comes back, which no digest-mutation check above could ever detect.
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $NOW_TS" -H "X-Signature-256: $VALID_HEX"
check "401" "a valid digest without the sha256= prefix is rejected"

# Neither may a different algorithm tag be honoured over the same digest.
raw_call GET "/api/auth/me" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $NOW_TS" -H "X-Signature-256: sha512=$VALID_HEX"
check "401" "a signature tagged with a different algorithm is rejected"

# The signing secret must never come back from a read endpoint.
api_call GET "/api/keys" "$MASTER_KEY"
check "200" "list keys"
if echo "$RESP_BODY" | grep -q "signing_secret"; then
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} GET /api/keys must not expose signing_secret" >&2
else
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} GET /api/keys does not expose signing_secret" >&2
fi

# ── 2. Multi-key permission matrix ──────────────────────────────────────────

log_section "2. Multi-Key Permission Matrix (Group A)"

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"Group-A"}'
check "200" "Group A is created"
GROUP_A_ID=$(echo "$RESP_BODY" | jq -r '.id')
log "Group A id: $GROUP_A_ID"

# Creates a key and leaves its plaintext/id in $CREATED_KEY / $CREATED_ID. Deliberately does NOT
# run in a subshell (no `$(...)`/`<(...)` around the whole function) — those globals need to
# propagate back to the calling scope, which a subshell would prevent.
create_scoped_key() {
    local name="$1"
    api_call POST "/api/keys" "$MASTER_KEY" "{\"name\":\"$name\",\"bound_ips\":\"0.0.0.0/0\"}"
    check "200" "create scoped key '$name'"
    CREATED_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
    CREATED_SIGNING_SECRET=$(echo "$RESP_BODY" | jq -r '.signing_secret')
    register_key_secret "$CREATED_KEY" "$CREATED_SIGNING_SECRET"
    CREATED_ID=$(echo "$RESP_BODY" | jq -r '.id')
}

log "Creating Read-Only Key..."
create_scoped_key "Read-Only Key"
READONLY_KEY="$CREATED_KEY"; READONLY_ID="$CREATED_ID"

log "Creating Write-Only Key..."
create_scoped_key "Write-Only Key"
WRITEONLY_KEY="$CREATED_KEY"; WRITEONLY_ID="$CREATED_ID"

log "Creating No-Access Key..."
create_scoped_key "No-Access Key"
NOACCESS_KEY="$CREATED_KEY"; NOACCESS_ID="$CREATED_ID"

# Read-Only: can_read only.
api_call POST "/api/keys/$READONLY_ID/groups" "$MASTER_KEY" \
    "{\"group_id\":\"$GROUP_A_ID\",\"can_read\":true,\"can_write\":false,\"can_delete\":false}"
check "200" "grant Read-Only Key read-only rights on Group A (by group_id)"

# Write-Only: can_read + can_write (can_write requires can_read, per AGENT.MD least-privilege).
api_call POST "/api/keys/$WRITEONLY_ID/groups" "$MASTER_KEY" \
    "{\"group_id\":\"$GROUP_A_ID\",\"can_read\":true,\"can_write\":true,\"can_delete\":false}"
check "200" "grant Write-Only Key read+write rights on Group A"

# No-Access Key: no grant at all — left as-is.

log "Seeding Group A with an address as master..."
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"198.51.100.50","group_name":"Group-A","cause":"seed"}'
check "200" "master seeds an address into Group A"

log "-- Read-Only Key --"
api_call GET "/api/ips?group_id=$GROUP_A_ID" "$READONLY_KEY"
check "200" "Read-Only Key can list Group A"
api_call POST "/api/ban" "$READONLY_KEY" '{"target_address":"198.51.100.51","group_name":"Group-A"}'
check "403" "Read-Only Key cannot write to Group A"

log "-- Write-Only Key --"
api_call GET "/api/ips?group_id=$GROUP_A_ID" "$WRITEONLY_KEY"
check "200" "Write-Only Key can list Group A"
api_call POST "/api/ban" "$WRITEONLY_KEY" '{"target_address":"198.51.100.52","group_name":"Group-A"}'
check "200" "Write-Only Key can write to Group A"
api_call DELETE "/api/ips?target_address=198.51.100.52&group_name=Group-A" "$WRITEONLY_KEY"
check "403" "Write-Only Key cannot delete from Group A (no can_delete)"

log "-- No-Access Key --"
api_call GET "/api/ips?group_id=$GROUP_A_ID" "$NOACCESS_KEY"
check "200" "No-Access Key's list call still succeeds..."
check_jq "length" "0" "...but returns zero rows (RBAC-filtered, not a 403)"
api_call POST "/api/ban" "$NOACCESS_KEY" '{"target_address":"198.51.100.53","group_name":"Group-A"}'
check "403" "No-Access Key cannot write to Group A"

# ── 3. IP management across multiple groups ─────────────────────────────────

log_section "3. IP Add / List / Filter / Update / Delete Across Groups"

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"Group-B"}'
check "200" "Group B is created"

api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"203.0.113.10","group_name":"Group-B","cause":"initial-cause"}'
check "200" "add an address to Group B"

# A group's type (banlist/whitelist) is fixed at creation and doesn't change per-membership, so
# the whitelist example needs its OWN group rather than reusing Group B — /white auto-creates it
# as type=whitelist since it doesn't exist yet.
api_call POST "/api/white" "$MASTER_KEY" '{"target_address":"203.0.113.11","group_name":"Group-C"}'
check "200" "whitelist an address into a fresh whitelist group (Group C)"

api_call GET "/api/ips?groups=Group-A,Group-B,Group-C" "$MASTER_KEY"
check "200" "list across multiple groups at once"
check_jq "length" "4" "sees all 4 addresses across Group A + Group B + Group C"

api_call GET "/api/ips?ip=203.0.113.10" "$MASTER_KEY"
check "200" "filter by IP substring"
check_jq "length" "1" "IP substring filter narrows to exactly one record"

api_call GET "/api/ips?status=white" "$MASTER_KEY"
check "200" "filter by status=white"
check_jq ".[0].target_address" "203.0.113.11" "status filter finds the whitelisted address"

log "Updating (re-registering) 203.0.113.10 with a new cause..."
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"203.0.113.10","group_name":"Group-B","cause":"updated-cause"}'
check "200" "re-registering an existing address updates it rather than failing"
api_call GET "/api/ips?ip=203.0.113.10" "$MASTER_KEY"
check_jq ".[0].cause" "updated-cause" "the cause was actually updated"
check_jq "length" "1" "still exactly one row — no duplicate created"

log "Deleting 203.0.113.10 from Group B via query-string parameters..."
api_call DELETE "/api/ips?target_address=203.0.113.10&group_name=Group-B" "$MASTER_KEY"
check "204" "delete via query string succeeds"
api_call GET "/api/ips?ip=203.0.113.10" "$MASTER_KEY"
check_jq "length" "0" "the query-string-deleted address is gone"

log "Adding 203.0.113.20 to Group B, then deleting it via a JSON request body instead..."
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"203.0.113.20","group_name":"Group-B","cause":"json-body-delete-test"}'
check "200" "add 203.0.113.20 to Group B for the JSON-body delete test"
api_call DELETE "/api/ips" "$MASTER_KEY" '{"target_address":"203.0.113.20","group_name":"Group-B"}'
check "204" "delete via JSON body (no query string at all) succeeds"
api_call GET "/api/ips?ip=203.0.113.20" "$MASTER_KEY"
check_jq "length" "0" "the JSON-body-deleted address is gone"

# ── 4. Multi-group overlap / conflict detection ─────────────────────────────

log_section "4. Multi-Group Overlap (Banlist + Whitelist) Conflict Detection"

log "Adding the SAME address to both a banlist group and a whitelist group..."
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"192.0.2.200","group_name":"Group-B","cause":"flagged as hostile"}'
check "200" "address added to banlist Group B"
api_call POST "/api/white" "$MASTER_KEY" '{"target_address":"192.0.2.200","group_name":"Group-C","cause":"also a trusted partner"}'
check "200" "the SAME address added to whitelist Group C"

api_call GET "/api/ips?ip=192.0.2.200" "$MASTER_KEY"
check "200" "list the overlapping address"
check_jq "length" "2" "GET /api/ips exposes BOTH memberships (one row per group), not a single merged/deduped row"
check_true '[.[].group_type] | sort == ["banlist","whitelist"]' "the two rows carry the two different group_types the UI conflict indicator diffs on"
check_true '[.[].target_address] | unique == ["192.0.2.200"]' "both rows are unambiguously the same address"

# ── 5. Key lifecycle: update + rotate ───────────────────────────────────────

log_section "5. Key Lifecycle (Update + Rotate)"

api_call PUT "/api/keys/$READONLY_ID" "$MASTER_KEY" '{"name":"Read-Only Key (renamed)","can_manage_webhooks":true}'
check "200" "PUT updates the key"
check_jq ".name" "Read-Only Key (renamed)" "the name was actually updated"
check_jq ".can_manage_webhooks" "true" "the new scope was actually granted"

api_call GET "/api/webhooks" "$READONLY_KEY"
check "200" "the updated scope takes effect immediately, with the same secret"

log "Rotating the Read-Only Key's secret..."
api_call POST "/api/keys/$READONLY_ID/rotate" "$MASTER_KEY"
check "200" "rotate succeeds"
NEW_READONLY_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
register_key_secret "$NEW_READONLY_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

api_call GET "/api/auth/me" "$READONLY_KEY"
check "401" "the OLD secret is rejected immediately after rotation"

api_call GET "/api/auth/me" "$NEW_READONLY_KEY"
check "200" "the NEW secret works"
READONLY_KEY="$NEW_READONLY_KEY"

# ── 6. Bound IP (CIDR) restrictions ─────────────────────────────────────────

log_section "6. Bound IP / CIDR Restrictions"

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"CIDR-Restricted Key","bound_ips":"203.0.113.0/24"}'
check "200" "create a key bound to 203.0.113.0/24"
RESTRICTED_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
register_key_secret "$RESTRICTED_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

api_call GET "/api/auth/me" "$RESTRICTED_KEY" "" "203.0.113.99"
check "200" "an X-Forwarded-For address inside the bound CIDR is allowed"

api_call GET "/api/auth/me" "$RESTRICTED_KEY" "" "8.8.8.8"
check "403" "an X-Forwarded-For address outside the bound CIDR is rejected"

api_call GET "/api/auth/me" "$RESTRICTED_KEY" "" "8.8.8.8, 203.0.113.42"
check "200" "only the rightmost (trusted-proxy) hop of X-Forwarded-For is honored"

log "Dedicated strict scenario: bound_ips=127.0.0.1/32, request claims to be from 203.0.113.50..."
api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Loopback-Only Key","bound_ips":"127.0.0.1/32"}'
check "200" "create a key bound to 127.0.0.1/32"
LOOPBACK_ONLY_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
register_key_secret "$LOOPBACK_ONLY_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

api_call GET "/api/auth/me" "$LOOPBACK_ONLY_KEY" "" "203.0.113.50"
check "403" "an out-of-CIDR X-Forwarded-For is strictly rejected"
check_jq ".error" "Client IP not allowed" "the error message is exactly 'Client IP not allowed'"

# ── 6b. X-Forwarded-For spoofing from an UNTRUSTED peer ─────────────────────
#
# Everything above connects from 127.0.0.1, which this run declares a trusted proxy, so the header
# is honoured. The attack is the opposite case: a client that is NOT a configured proxy must not be
# able to satisfy bound_ips by writing an allowed address into a header it controls.
#
# 127.0.0.2 is a loopback address that is NOT in TRUSTED_PROXIES, so binding curl's source address
# to it reproduces an untrusted peer without needing a second machine. Guarded, because
# `--interface` against a 127/8 alias is Linux-specific.

log_section "6b. X-Forwarded-For Spoofing From an Untrusted Peer"

# Signs and sends a request from an explicit source address. Mirrors api_call's signing, but adds
# --interface so the server sees a different TCP peer.
call_from_interface() {
    local iface="$1" method="$2" path="$3" api_key="$4" xff="$5"
    # Same clock as api_call: these probes differ only in the (unsigned) X-Forwarded-For header, so
    # without it the second would reproduce the first's signature and be refused as a replay.
    # Deliberately the *same* identity key as api_call: --interface changes which source address
    # curl binds, not a single byte of the signed material, so a call_from_interface and an
    # api_call for the same method/path/key produce the same signature and must share one clock.
    next_timestamp "$method|$path|$api_key|"
    local timestamp="$SIGNED_TS"
    local secret="${SIGNING_SECRETS[$api_key]:-unregistered-key-has-no-signing-secret}"
    local args=(-s -o "$RESP_BODY_FILE" -w "%{http_code}" -X "$method" --interface "$iface")
    args+=(-H "X-API-Key: $api_key" -H "X-Timestamp: $timestamp")
    args+=(-H "X-Signature-256: $(hmac_sign "$secret" "$method" "$path" "$timestamp" "")")
    [ -n "$xff" ] && args+=(-H "X-Forwarded-For: $xff")
    RESP_STATUS=$(curl "${args[@]}" "$BASE_URL$path")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    local color; color=$(status_color "$RESP_STATUS")
    printf "%s ${color}[%s]${RESET} %-6s %s (from %s)\n" "$(ts)" "$RESP_STATUS" "$method" "$BASE_URL$path" "$iface" >&2
    print_response_body
}

if curl -s -o /dev/null --interface 127.0.0.2 --max-time 5 "$BASE_URL/api/auth/me" 2>/dev/null; then
    api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Spoof-Target Key","bound_ips":"203.0.113.0/24"}'
    check "200" "create a key bound to 203.0.113.0/24 for the spoofing test"
    SPOOF_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
    register_key_secret "$SPOOF_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

    # The attack: an untrusted peer claiming an address inside the bound CIDR.
    call_from_interface "127.0.0.2" GET "/api/auth/me" "$SPOOF_KEY" "203.0.113.99"
    check "403" "a spoofed X-Forwarded-For from an untrusted peer does NOT satisfy bound_ips"
    check_jq ".error" "Client IP not allowed" "the spoofing rejection is the CIDR check, not an auth error"

    # Impersonating the trusted proxy inside the header must not bootstrap trust either.
    call_from_interface "127.0.0.2" GET "/api/auth/me" "$SPOOF_KEY" "127.0.0.1, 203.0.113.99"
    check "403" "naming the trusted proxy inside X-Forwarded-For does not bootstrap trust"

    # TRUSTED_PROXIES is spelled as the hostname "localhost" for this run, so the control below
    # passing proves the dynamic DNS resolution path works against a real resolver — the same
    # mechanism a Docker/Traefik deployment relies on to keep trusting a container whose IP moves.

    # Control: the identical header from the trusted peer (127.0.0.1) IS honoured, proving the
    # difference is the peer address and not something incidental about the request.
    api_call GET "/api/auth/me" "$SPOOF_KEY" "" "203.0.113.99"
    check "200" "the same X-Forwarded-For from the trusted proxy IS honored"

    # A master key with bound_ips is subject to them like any other key — no exemption.
    #
    # This used to mint a second master to test against. It cannot any more (RBAC_MODEL.md §5), so it
    # narrows the real one instead — which doubles as the positive case for §5's single exception:
    # bound_ips is the one field the master may edit about itself.
    #
    # Loopback stays in the set on purpose. Without it, the restore below would be sent from
    # 127.0.0.1, land outside the master's own CIDR, and be refused — locking the suite out of its
    # only master with ~1500 checks still to run. 8.8.8.8 is outside either way, which is what the
    # "no exemption" assertion actually turns on.
    api_call PUT "/api/keys/$MASTER_ID" "$MASTER_KEY" '{"bound_ips":"203.0.113.0/24,127.0.0.1/32,::1/128"}'
    check "200" "the master may edit its OWN bound_ips (the one field §5 leaves editable)"

    api_call GET "/api/auth/me" "$MASTER_KEY" "" "203.0.113.99"
    check "200" "a bound master key works from inside its CIDR"

    api_call GET "/api/auth/me" "$MASTER_KEY" "" "8.8.8.8"
    check "403" "a bound MASTER key is rejected outside its CIDR (no master exemption)"

    # Everything else about the master is refused on the same endpoint that just accepted bound_ips,
    # so the difference is the field and not the caller.
    api_call PUT "/api/keys/$MASTER_ID" "$MASTER_KEY" '{"name":"Renamed Master"}'
    check "403" "the master cannot be renamed through the API"

    api_call POST "/api/keys/$MASTER_ID/rotate" "$MASTER_KEY"
    check "403" "the master cannot be rotated through the API"

    api_call POST "/api/keys/$MASTER_ID/rotate-secret" "$MASTER_KEY"
    check "403" "the master's signing secret cannot be re-keyed through the API"

    api_call DELETE "/api/keys/$MASTER_ID" "$MASTER_KEY"
    check "403" "the master cannot be deleted through the API"

    # Restore, or every remaining master call in this suite is a 403.
    api_call PUT "/api/keys/$MASTER_ID" "$MASTER_KEY" '{"bound_ips":"0.0.0.0/0,::/0"}'
    check "200" "restore the master's original binding"
else
    warn "curl --interface 127.0.0.2 unavailable — skipping untrusted-peer spoofing checks."
fi

# ── 7. Audit log generation & pagination ────────────────────────────────────

log_section "7. Audit Log Generation & Pagination"

api_call GET "/api/audit-logs" "$READONLY_KEY"
check "403" "a non-master key cannot read audit logs"

api_call GET "/api/audit-logs?action=IP_ADD&limit=50" "$MASTER_KEY"
check "200" "master can read audit logs"
IP_ADD_COUNT=$(echo "$RESP_BODY" | jq 'length')
if [ "${IP_ADD_COUNT:-0}" -ge 1 ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} at least one IP_ADD audit entry exists (found $IP_ADD_COUNT)" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} expected at least one IP_ADD audit entry, found $IP_ADD_COUNT" >&2
fi

api_call GET "/api/audit-logs?action=KEY_ROTATE" "$MASTER_KEY"
check_jq "length" "1" "exactly one KEY_ROTATE audit entry exists (from step 5)"

log "Generating a deterministic run of mutating actions for pagination testing..."
for i in 1 2 3 4 5 6; do
    api_call POST "/api/groups" "$MASTER_KEY" "{\"name\":\"pagination-group-$i\"}"
    check "200" "create pagination-group-$i (audit entry #$i)"
done

api_call GET "/api/audit-logs?action=GROUP_CREATE&limit=3&offset=0" "$MASTER_KEY"
check "200" "page 1 of GROUP_CREATE audit logs (limit=3, offset=0)"
check_jq "length" "3" "page 1 has exactly 3 entries"
PAGE1_IDS=$(echo "$RESP_BODY" | jq -c '[.[].id]')

api_call GET "/api/audit-logs?action=GROUP_CREATE&limit=3&offset=3" "$MASTER_KEY"
check "200" "page 2 of GROUP_CREATE audit logs (limit=3, offset=3)"
check_jq "length" "3" "page 2 has exactly 3 entries"
PAGE2_IDS=$(echo "$RESP_BODY" | jq -c '[.[].id]')

if [ "$PAGE1_IDS" != "$PAGE2_IDS" ]; then
    OVERLAP=$(jq -n --argjson a "$PAGE1_IDS" --argjson b "$PAGE2_IDS" '[$a[] | select(. as $x | $b | index($x))] | length')
    if [ "$OVERLAP" == "0" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} page 1 and page 2 contain disjoint entries (no overlap)" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} page 1 and page 2 overlap by $OVERLAP entr(ies)" >&2
    fi
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} page 1 and page 2 are identical — offset is not advancing the window" >&2
fi

# ── 8. Group identification & least-privilege regressions ──────────────────

log_section "8. Regression: Duplicate Group Name, Flexible group_id, and group_name"

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"Group-A"}'
check "409" "creating a group with a name that already exists returns 409, not 500"

api_call POST "/api/keys/$NOACCESS_ID/groups" "$MASTER_KEY" \
    "{\"group_id\":\"Group-B\",\"can_read\":true,\"can_write\":false,\"can_delete\":false}"
check "200" "a literal NAME in the group_id field is accepted (no 422)"

api_call POST "/api/keys/$NOACCESS_ID/groups" "$MASTER_KEY" \
    "{\"group_id\":\"$GROUP_A_ID\",\"can_read\":false,\"can_write\":true,\"can_delete\":false}"
check "400" "can_write without can_read is rejected (least-privilege rule)"

log "Assigning rights via a literal group_name ('fail2ban_nginx') alongside a UUID-based grant..."
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"198.51.100.77","group_name":"fail2ban_nginx","cause":"nginx probing"}'
check "200" "seed the fail2ban_nginx group into existence"
api_call GET "/api/groups" "$MASTER_KEY"
check "200" "list groups to find fail2ban_nginx's id"
FAIL2BAN_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.[] | select(.name=="fail2ban_nginx") | .id')
log "fail2ban_nginx group id: $FAIL2BAN_GROUP_ID"

api_call POST "/api/keys/$NOACCESS_ID/permissions" "$MASTER_KEY" \
    '{"group_name":"fail2ban_nginx","can_read":true,"can_write":true,"can_delete":false}'
check "200" "grant rights via the literal group_name field"

create_scoped_key "fail2ban_nginx UUID-grant key"
FAIL2BAN_UUID_KEY_ID="$CREATED_ID"
api_call POST "/api/keys/$FAIL2BAN_UUID_KEY_ID/permissions" "$MASTER_KEY" \
    "{\"group_id\":\"$FAIL2BAN_GROUP_ID\",\"can_read\":true,\"can_write\":false,\"can_delete\":false}"
check "200" "grant rights on the SAME group via its UUID, seamlessly alongside the group_name grant"

api_call GET "/api/ips?group_name=fail2ban_nginx" "$NOACCESS_KEY"
check "200" "the group_name-granted key can read fail2ban_nginx"
check_jq "length" "1" "and sees the seeded address"

# ── 9. Webhook lifecycle ─────────────────────────────────────────────────────

log_section "9. Webhook Lifecycle (Create / List / Delete)"

log "Omitting the mandatory 'name' field is refused in the standard JSON envelope..."
api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"target_url\":\"https://webhook.site/e2e-missing-name\",\"secret_token\":\"whsec_e2e\",\"payload_template\":\"{}\",\"group_id\":\"$GROUP_A_ID\"}"
# Was 422 (axum's bare `Json<T>` default) before `create_webhook` moved onto `StrictJson`. 400 is
# now correct and consistent: it is what every other `StrictJson`-covered endpoint in this service
# already answers for the identical "well-formed JSON, wrong shape" failure — see
# `src/extract.rs`'s `StrictJson` doc for why that remap is deliberate rather than axum's default.
check "400" "creating a webhook without 'name' is rejected with 400 (missing required field, StrictJson envelope)"
check_jq '.error != null' "true" "and the refusal carries the standard error field"

log "Creating a webhook with the correct payload shape (name/target_url/secret_token/payload_template/group_id)..."
api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"slack_alert\",\"target_url\":\"https://webhook.site/e2e-test-endpoint\",\"secret_token\":\"whsec_e2e_test_secret\",\"payload_template\":\"{\\\"ip\\\":\\\"{{target_address}}\\\"}\",\"group_id\":\"$GROUP_A_ID\"}"
check "200" "create the webhook"
WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')
log "Webhook id: $WEBHOOK_ID"

api_call GET "/api/webhooks" "$MASTER_KEY"
check "200" "list webhooks"
check_true "any(.[]; .id == \"$WEBHOOK_ID\" and .name == \"slack_alert\")" "the created webhook appears in the list with the right name"
check_true 'all(.[]; has("secret_token") | not)' "no listed webhook ever exposes its secret_token"

api_call DELETE "/api/webhooks/$WEBHOOK_ID" "$MASTER_KEY"
check "204" "delete the webhook"

api_call GET "/api/webhooks" "$MASTER_KEY"
check_true "all(.[]; .id != \"$WEBHOOK_ID\")" "the deleted webhook no longer appears in the list"

api_call DELETE "/api/webhooks/$WEBHOOK_ID" "$MASTER_KEY"
check "404" "deleting an already-deleted webhook returns 404, not another 204"

# ── 10. Key deletion ─────────────────────────────────────────────────────────

log_section "10. Key Deletion"

log "Creating a disposable key to delete..."
create_scoped_key "Disposable Key"
DISPOSABLE_KEY="$CREATED_KEY"; DISPOSABLE_ID="$CREATED_ID"

api_call GET "/api/auth/me" "$DISPOSABLE_KEY"
check "200" "the disposable key authenticates before deletion"

api_call DELETE "/api/keys/$WRITEONLY_ID" "$NOACCESS_KEY"
check "403" "a key without can_manage_keys cannot delete other keys"

api_call DELETE "/api/keys/$DISPOSABLE_ID" "$MASTER_KEY"
check "204" "master deletes the disposable key"

api_call GET "/api/auth/me" "$DISPOSABLE_KEY"
check "401" "the deleted key's secret is rejected immediately after deletion"

api_call DELETE "/api/keys/$DISPOSABLE_ID" "$MASTER_KEY"
check "404" "deleting an already-deleted key returns 404, not another 204"

# ── 11. Invalid input validation ────────────────────────────────────────────

log_section "11. Invalid Input Validation"

api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"999.999.999.999","group_name":"Group-A","cause":"malformed"}'
check "400" "banning a malformed address (999.999.999.999) is rejected with 400 Bad Request"

# ── 12. Group deletion cascade ───────────────────────────────────────────────

log_section "12. Group Deletion Cascade"

log "Creating a temporary group, then attaching an IP record and a key permission to it..."
api_call POST "/api/groups" "$MASTER_KEY" '{"name":"cascade-test-group"}'
check "200" "create the temporary cascade-test-group"
CASCADE_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"198.51.100.90","group_name":"cascade-test-group","cause":"cascade delete test"}'
check "200" "add an IP record into the temporary group"

create_scoped_key "Cascade Test Key"
CASCADE_KEY_ID="$CREATED_ID"
api_call POST "/api/keys/$CASCADE_KEY_ID/groups" "$MASTER_KEY" \
    "{\"group_id\":\"$CASCADE_GROUP_ID\",\"can_read\":true,\"can_write\":true,\"can_delete\":false}"
check "200" "grant a key permission on the temporary group"

log "Deleting the group while it still owns an IP record and a key permission..."
api_call DELETE "/api/groups/$CASCADE_GROUP_ID" "$MASTER_KEY"
check "204" "the group with attached records/permissions is removed cleanly, with no FK error"

api_call GET "/api/groups" "$MASTER_KEY"
check_true "all(.[]; .id != \"$CASCADE_GROUP_ID\")" "the deleted group no longer appears in the group list"

api_call GET "/api/ips?ip=198.51.100.90" "$MASTER_KEY"
check_jq "length" "0" "its IP record's membership was cascade-deleted along with the group"

api_call POST "/api/keys/$CASCADE_KEY_ID/groups" "$MASTER_KEY" \
    "{\"group_id\":\"$CASCADE_GROUP_ID\",\"can_read\":true,\"can_write\":false,\"can_delete\":false}"
check "404" "re-granting a permission against the now-deleted group id fails (group no longer resolvable)"

# ── 13. Webhook event filtering ─────────────────────────────────────────────

log_section "13. Webhook Event Filtering"

api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"bad-events-hook\",\"target_url\":\"https://webhook.site/e2e-bad-events\",\"secret_token\":\"x\",\"payload_template\":\"{}\",\"group_id\":\"$GROUP_A_ID\",\"events\":\"NOT_A_REAL_EVENT\"}"
check "400" "creating a webhook with an unrecognized events entry is rejected with 400"

WEBHOOK_RECEIVER_AVAILABLE=0
if command -v python3 >/dev/null 2>&1; then
    if command -v fuser >/dev/null 2>&1 && fuser "$RECEIVER_PORT/tcp" >/dev/null 2>&1; then
        warn "Port $RECEIVER_PORT is already in use; skipping live webhook-delivery verification."
    else
        cat > "$WORK_DIR/receiver.py" <<'PYEOF'
import http.server
import json
import sys

port = int(sys.argv[1])
log_path = sys.argv[2]

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(length).decode('utf-8', 'replace')
        # One JSON object per line: still exactly one line per delivery (so the existing
        # `wc -l` hit-counting checks are unaffected), but now carrying everything the
        # auth-mode checks need to verify each of the four dispatch shapes.
        with open(log_path, 'a') as f:
            f.write(json.dumps({
                'path': self.path,
                'signature': self.headers.get('X-Signature-256'),
                'timestamp': self.headers.get('X-Timestamp'),
                'api_key': self.headers.get('X-API-Key'),
                'body': body,
            }) + '\n')
        self.send_response(200)
        self.end_headers()

    def log_message(self, format, *args):
        pass

http.server.HTTPServer(('127.0.0.1', port), Handler).serve_forever()
PYEOF
        : > "$RECEIVER_LOG"
        python3 "$WORK_DIR/receiver.py" "$RECEIVER_PORT" "$RECEIVER_LOG" &
        RECEIVER_PID=$!
        sleep 0.3
        if kill -0 "$RECEIVER_PID" 2>/dev/null; then
            WEBHOOK_RECEIVER_AVAILABLE=1
            log "Local webhook receiver listening on 127.0.0.1:$RECEIVER_PORT (pid $RECEIVER_PID)"
        else
            warn "Local webhook receiver failed to start; skipping live webhook-delivery verification."
        fi
    fi
else
    warn "python3 not found; skipping live webhook-delivery verification."
fi

count_receiver_hits() {
    wc -l < "$RECEIVER_LOG" 2>/dev/null | tr -d ' '
}

if [ "$WEBHOOK_RECEIVER_AVAILABLE" -eq 1 ]; then
    api_call POST "/api/groups" "$MASTER_KEY" '{"name":"event-filter-group"}'
    check "200" "create a dedicated group for event-filtering tests"
    EVENT_FILTER_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/webhooks" "$MASTER_KEY" \
        "{\"name\":\"add-only-hook\",\"target_url\":\"http://127.0.0.1:$RECEIVER_PORT/hook\",\"secret_token\":\"x\",\"payload_template\":\"{}\",\"group_id\":\"$EVENT_FILTER_GROUP_ID\",\"events\":\"IP_ADD\"}"
    check "200" "create a webhook restricted to events=IP_ADD"
    EVENT_FILTER_WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call GET "/api/webhooks" "$MASTER_KEY"
    check_true "any(.[]; .id == \"$EVENT_FILTER_WEBHOOK_ID\" and .events == \"IP_ADD\")" "the events field round-trips and is visible when listing webhooks"

    log "Banning a brand-new address (IP_ADD) — the events:\"IP_ADD\" webhook should fire..."
    api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"192.0.2.250","group_name":"event-filter-group","cause":"event filter test"}'
    check "200" "add the address (IP_ADD)"

    HITS=0
    for _ in $(seq 1 20); do
        HITS=$(count_receiver_hits)
        [ "${HITS:-0}" -ge 1 ] && break
        sleep 0.2
    done
    if [ "${HITS:-0}" == "1" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} IP_ADD was delivered to the events:\"IP_ADD\" webhook (1 hit)" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} expected exactly 1 delivery after IP_ADD, got ${HITS:-0}" >&2
    fi

    # The mock receiver capturing the hit above proves the HTTP call happened; it says nothing about
    # whether the real background worker went on to record it in `webhook_executions`. Poll the real
    # listing endpoint — against the live binary, not a Rust test process — so this is genuinely the
    # whole path end to end: POST /api/ban -> real worker -> real HTTP dispatch -> a row visible
    # through GET /api/webhooks/executions.
    log "Polling GET /api/webhooks/executions for the row that dispatch must have recorded..."
    EXEC_FOUND=0
    for _ in $(seq 1 20); do
        api_call GET "/api/webhooks/executions" "$MASTER_KEY"
        if [ "$RESP_STATUS" == "200" ] && echo "$RESP_BODY" | jq -e --arg wid "$EVENT_FILTER_WEBHOOK_ID" \
            'any(.[]; .webhook_id == $wid and .event_type == "IP_ADD" and .is_success == true and .status_code == 200)' \
            >/dev/null 2>&1
        then
            EXEC_FOUND=1
            break
        fi
        sleep 0.2
    done
    check_local "$EXEC_FOUND" "1" \
        "the real dispatch above produced a matching webhook_executions row (event_type=IP_ADD, is_success=true, status_code=200)"

    log "Re-registering the same address (IP_UPDATE) — must NOT fire (not subscribed)..."
    api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"192.0.2.250","group_name":"event-filter-group","cause":"updated"}'
    check "200" "re-register the address (IP_UPDATE)"
    sleep 1
    HITS=$(count_receiver_hits)
    if [ "${HITS:-0}" == "1" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} IP_UPDATE was correctly skipped (still 1 hit)" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} expected delivery count to stay at 1 after IP_UPDATE, got ${HITS:-0}" >&2
    fi

    log "Deleting the address (IP_DELETE) — must also NOT fire..."
    api_call DELETE "/api/ips?target_address=192.0.2.250&group_name=event-filter-group" "$MASTER_KEY"
    check "204" "delete the address (IP_DELETE)"
    sleep 1
    HITS=$(count_receiver_hits)
    if [ "${HITS:-0}" == "1" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} IP_DELETE was correctly skipped (still 1 hit)" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} expected delivery count to stay at 1 after IP_DELETE, got ${HITS:-0}" >&2
    fi
else
    warn "Live webhook-delivery verification skipped (see above); the events-field API contract check above still ran."
fi

# ── 14. Audit log enrichment (client IP, API key name/prefix) ──────────────

log_section "14. Audit Log Enrichment (Client IP, API Key Name/Prefix)"

api_call GET "/api/audit-logs?action=GROUP_CREATE&limit=1" "$MASTER_KEY"
check "200" "fetch the most recent GROUP_CREATE audit entry to inspect enrichment fields"
check_jq ".[0].client_ip" "127.0.0.1" "the audit entry's client_ip is populated with the real caller address"
check_jq ".[0].api_key_name" "System Master" "the audit entry's api_key_name is denormalized from the acting key"
check_true '(.[0].api_key_prefix | length) == 8' "the audit entry's api_key_prefix is present and 8 characters"

# ── 15. RBAC precedence & strict group-type validation ──────────────────────

log_section "15. RBAC Precedence & Strict Group Type Validation"

log "Master creates a whitelist group and a banlist group for the type-validation scenarios..."
api_call POST "/api/white" "$MASTER_KEY" '{"target_address":"203.0.113.60","group_name":"rbac-precedence-whitelist","cause":"seed"}'
check "200" "seed the whitelist group"
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"203.0.113.61","group_name":"rbac-precedence-banlist","cause":"seed"}'
check "200" "seed the banlist group"

log "A key with NO permission mapping on the whitelist group attempts to ban into it..."
api_call POST "/api/ban" "$NOACCESS_KEY" '{"target_address":"198.51.100.30","group_name":"rbac-precedence-whitelist"}'
check "403" "no-access key gets 403 (RBAC), not 400 (type mismatch) — permission is checked first"
check_true '.error | contains("Permission denied")' "the 403 body is a genuine permission-denied error, not a type-validation one"

log "Granting a dedicated key full read+write on both groups..."
create_scoped_key "Type Validation Key"
TYPE_CHECK_KEY="$CREATED_KEY"; TYPE_CHECK_ID="$CREATED_ID"
api_call POST "/api/keys/$TYPE_CHECK_ID/groups" "$MASTER_KEY" \
    '{"group_name":"rbac-precedence-whitelist","can_read":true,"can_write":true,"can_delete":false}'
check "200" "grant the type-validation key rights on the whitelist group"
api_call POST "/api/keys/$TYPE_CHECK_ID/groups" "$MASTER_KEY" \
    '{"group_name":"rbac-precedence-banlist","can_read":true,"can_write":true,"can_delete":false}'
check "200" "grant the type-validation key rights on the banlist group"

log "Now authorized: banning into the whitelist group is rejected with the exact 400 message..."
api_call POST "/api/ban" "$TYPE_CHECK_KEY" '{"target_address":"198.51.100.31","group_name":"rbac-precedence-whitelist"}'
check "400" "banning into a whitelist group is rejected with 400, not 200 or 403"
check_jq ".error" "Cannot ban IP into group 'rbac-precedence-whitelist': group type is 'whitelist'. Use /api/white or target a banlist group." \
    "the error message exactly matches the spec"

log "Whitelisting into the banlist group is rejected with the exact reverse 400 message..."
api_call POST "/api/white" "$TYPE_CHECK_KEY" '{"target_address":"198.51.100.32","group_name":"rbac-precedence-banlist"}'
check "400" "whitelisting into a banlist group is rejected with 400, not 200 or 403"
check_jq ".error" "Cannot whitelist IP into group 'rbac-precedence-banlist': group type is 'banlist'. Use /api/ban or target a whitelist group." \
    "the error message exactly matches the reverse spec"

# ── 16. Auto-grant full permissions on group creation ───────────────────────

log_section "16. Auto-Grant Full Permissions on Group Creation"

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Group Creator Key","bound_ips":"0.0.0.0/0","can_create_groups":true}'
check "200" "create a key with can_create_groups=true"
GROUP_CREATOR_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
register_key_secret "$GROUP_CREATOR_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

log "Explicit creation via POST /api/groups..."
api_call POST "/api/groups" "$GROUP_CREATOR_KEY" '{"name":"explicit-creator-group"}'
check "200" "the can_create_groups key creates a new group via POST /api/groups"
EXPLICIT_CREATOR_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call GET "/api/auth/me" "$GROUP_CREATOR_KEY"
check "200" "fetch the creator key's own profile to inspect its granted permissions"
check_true "[.group_permissions[] | select(.group_id == \"$EXPLICIT_CREATOR_GROUP_ID\")] | length == 1" \
    "the creator has exactly one permission record on the group it just created"
check_true "[.group_permissions[] | select(.group_id == \"$EXPLICIT_CREATOR_GROUP_ID\")][0] | .can_read and .can_write and .can_delete" \
    "that permission record grants full can_read/can_write/can_delete"

log "Implicit creation via POST /api/ban (auto-create-on-first-use)..."
api_call POST "/api/ban" "$GROUP_CREATOR_KEY" '{"target_address":"198.51.100.240","group_name":"implicit-creator-group","cause":"testing implicit auto-grant"}'
check "200" "the can_create_groups key implicitly creates a new group via POST /api/ban"

api_call GET "/api/groups" "$MASTER_KEY"
IMPLICIT_CREATOR_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.[] | select(.name=="implicit-creator-group") | .id')

api_call GET "/api/auth/me" "$GROUP_CREATOR_KEY"
check "200" "fetch the creator key's profile again after implicit group creation"
check_true "[.group_permissions[] | select(.group_id == \"$IMPLICIT_CREATOR_GROUP_ID\")][0] | .can_read and .can_write and .can_delete" \
    "the implicitly-created group also grants full can_read/can_write/can_delete"

# ── 17. Group type creation & display ───────────────────────────────────────

log_section "17. Group Type Creation & Display"

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"explicit-whitelist-group","group_type":"whitelist"}'
check "200" "create a group with an explicit group_type=whitelist"
check_jq ".group_type" "whitelist" "the response reports group_type=whitelist"

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"explicit-banlist-group","group_type":"banlist"}'
check "200" "create a group with an explicit group_type=banlist"
check_jq ".group_type" "banlist" "the response reports group_type=banlist"

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"default-type-group"}'
check "200" "create a group omitting group_type entirely"
check_jq ".group_type" "banlist" "an omitted group_type defaults to banlist"

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"invalid-type-group","group_type":"not-a-real-type"}'
check "200" "an invalid group_type value is NOT rejected with 400..."
check_jq ".group_type" "banlist" "...it silently falls back to the banlist default instead"

api_call GET "/api/groups" "$MASTER_KEY"
check "200" "list groups to confirm the whitelist group's type persisted"
check_true '[.[] | select(.name=="explicit-whitelist-group")][0].group_type == "whitelist"' \
    "GET /api/groups shows the persisted whitelist type, not just the create response"

# ── 18. IP address canonicalization (/32, /128 stripping) ───────────────────

log_section "18. IP Address Canonicalization"

log "Banning the same address once as '/32' and once bare must produce exactly ONE record..."
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"188.190.74.128/32","group_name":"canon-e2e-group","cause":"first as /32"}'
check "200" "ban the /32 form"
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"188.190.74.128","group_name":"canon-e2e-group","cause":"second as bare"}'
check "200" "ban the bare form of the SAME address"

api_call GET "/api/ips?groups=canon-e2e-group" "$MASTER_KEY"
check "200" "list the canonicalization test group"
check_jq "length" "1" "the /32 and bare forms collapsed into exactly one stored record"
check_jq ".[0].target_address" "188.190.74.128" "stored in canonical (bare) form, not '.../32'"
check_jq ".[0].cause" "second as bare" "the second call updated the same row (proving it was a re-registration, not a duplicate insert)"

log "Deleting via the /32 form must remove a record that is actually stored bare..."
api_call DELETE "/api/ips?target_address=188.190.74.128/32&group_name=canon-e2e-group" "$MASTER_KEY"
check "204" "delete succeeds even though the stored value has no '/32' suffix"
api_call GET "/api/ips?groups=canon-e2e-group" "$MASTER_KEY"
check_jq "length" "0" "the record is actually gone"

log "A genuine subnet (not a single-host CIDR) must keep its CIDR notation unchanged..."
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"203.0.113.0/24","group_name":"canon-e2e-group","cause":"real subnet"}'
check "200" "ban a /24 subnet"
api_call GET "/api/ips?groups=canon-e2e-group" "$MASTER_KEY"
check_jq ".[0].target_address" "203.0.113.0/24" "a /24 keeps its CIDR notation (already the network address; host bits would be masked)"

# ── 19. Latest-activity-first ordering & lightweight iplist format ──────────

log_section "19. Latest-Activity-First Ordering & Lightweight iplist Format"

log "Banning 3 addresses in sequence — GET /api/ips must return them most-recent-first..."
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"198.51.100.201","group_name":"ordering-e2e-group"}'
check "200" "ban address 1"
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"198.51.100.202","group_name":"ordering-e2e-group"}'
check "200" "ban address 2"
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"198.51.100.203","group_name":"ordering-e2e-group"}'
check "200" "ban address 3"

api_call GET "/api/ips?groups=ordering-e2e-group" "$MASTER_KEY"
check "200" "list the ordering test group"
check_jq ".[0].target_address" "198.51.100.203" "the most recently created record sorts first"
check_jq ".[2].target_address" "198.51.100.201" "the oldest record sorts last"

log "Re-banning the oldest address must move it back to the front..."
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"198.51.100.201","group_name":"ordering-e2e-group","cause":"renewed"}'
check "200" "re-ban address 1"
api_call GET "/api/ips?groups=ordering-e2e-group" "$MASTER_KEY"
check_jq ".[0].target_address" "198.51.100.201" "the re-registered record jumps back to the front"

log "GET /api/ips?format=iplist returns a lightweight, deduplicated address list..."
api_call GET "/api/ips?groups=ordering-e2e-group&format=iplist" "$MASTER_KEY"
check "200" "iplist format request succeeds"
check_true '(.ip_list | type) == "array"' "the response has an ip_list array"
check_jq "(.ip_list | length)" "3" "all 3 addresses are present"
check_true '.ip_list | contains(["198.51.100.201","198.51.100.202","198.51.100.203"])' "the exact addresses are present"

log "mode=iplist is accepted as a synonym for format=iplist..."
api_call GET "/api/ips?groups=ordering-e2e-group&mode=iplist" "$MASTER_KEY"
check "200" "mode=iplist request succeeds"
check_jq "(.ip_list | length)" "3" "same result via the mode= synonym"

# ── 19b. include_total pagination envelope ──────────────────────────────────

log_section "19b. GET /api/ips?include_total=true Pagination Envelope"

log "Seeding 5 records in a dedicated group..."
for n in 1 2 3 4 5; do
    api_call POST "/api/ban" "$MASTER_KEY" "{\"target_address\":\"198.51.100.21${n}\",\"group_name\":\"include-total-e2e-group\"}"
    check "200" "seed record #$n"
done

log "Without include_total, the response is still the bare root array..."
api_call GET "/api/ips?groups=include-total-e2e-group" "$MASTER_KEY"
check "200" "list without include_total"
check_true '(. | type) == "array"' "the response is a bare array"
check_jq "(. | length)" "5" "all 5 records are present"

log "include_total=true wraps the same page in a {data,total,limit,offset,total_pages} envelope..."
api_call GET "/api/ips?groups=include-total-e2e-group&limit=2&offset=0&include_total=true" "$MASTER_KEY"
check "200" "list with include_total=true, page 1"
check_true '(.data | type) == "array"' "the envelope's data field is an array"
check_jq "(.data | length)" "2" "the page respects limit=2"
check_jq ".total" "5" "total counts across every page, not just this one"
check_jq ".limit" "2" "limit is echoed back"
check_jq ".offset" "0" "offset is echoed back"
check_jq ".total_pages" "3" "ceil(5 / 2) == 3"

log "The last, partial page still reports the same total..."
api_call GET "/api/ips?groups=include-total-e2e-group&limit=2&offset=4&include_total=true" "$MASTER_KEY"
check "200" "list with include_total=true, last page"
check_jq "(.data | length)" "1" "only 1 record remains at offset 4"
check_jq ".total" "5" "total is unchanged by which page was requested"
check_jq ".total_pages" "3" "total_pages is unchanged by which page was requested"

log "A key with no readable groups at all gets a zeroed envelope, not an error..."
api_call POST "/api/keys" "$MASTER_KEY" '{"name":"include_total_isolated_key","bound_ips":"0.0.0.0/0"}'
check "200" "create a key with zero group grants"
register_key_secret "$(echo "$RESP_BODY" | jq -r '.plaintext_key')" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"
ISOLATED_TOTAL_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
api_call GET "/api/ips?include_total=true" "$ISOLATED_TOTAL_KEY"
check "200" "an isolated key still gets 200, never 403 (RBAC_MODEL.md §4 oracle discipline)"
check_jq ".total" "0" "an isolated key counts nothing, including the 5 records seeded above"
check_jq ".total_pages" "0" "total_pages is 0, not 1, when total is 0"
check_jq "(.data | length)" "0" "data is an empty array, not omitted"

# ── 20. Readable audit log details (human-readable key names) ──────────────

log_section "20. Readable Audit Log Details"

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"readable_logs_key","bound_ips":"0.0.0.0/0"}'
check "200" "create a dedicated key to exercise KEY_ROTATE/KEY_PERM_UPDATE/KEY_DELETE logging"
READABLE_LOGS_KEY_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/keys/$READABLE_LOGS_KEY_ID/rotate" "$MASTER_KEY"
check "200" "rotate its secret"
api_call GET "/api/audit-logs?action=KEY_ROTATE&limit=1" "$MASTER_KEY"
check "200" "fetch the most recent KEY_ROTATE entry"
check_true '(.[0].details | contains("readable_logs_key")) and (.[0].details | contains("Rotated secret for key"))' \
    "the details string names the key by name, not just its raw UUID"

api_call POST "/api/keys/$READABLE_LOGS_KEY_ID/groups" "$MASTER_KEY" \
    '{"group_name":"readable-logs-group","can_read":true,"can_write":false,"can_delete":false}'
check "200" "grant it a group permission"
api_call GET "/api/audit-logs?action=KEY_PERM_UPDATE&limit=1" "$MASTER_KEY"
check "200" "fetch the most recent KEY_PERM_UPDATE entry"
check_jq ".[0].details" "Updated permissions for key 'readable_logs_key' (${READABLE_LOGS_KEY_ID:0:8}...)" \
    "the details string exactly matches the spec's example format"

api_call DELETE "/api/keys/$READABLE_LOGS_KEY_ID" "$MASTER_KEY"
check "204" "delete the key"
api_call GET "/api/audit-logs?action=KEY_DELETE&limit=1" "$MASTER_KEY"
check "200" "fetch the most recent KEY_DELETE entry"
check_true '.[0].details | contains("readable_logs_key")' "the delete log also names the key by name, even though it no longer exists"

# ── 21. API key signing-secret rotation ─────────────────────────────────────

log_section "21. Signing Secret Rotation (POST /api/keys/{id}/rotate-secret)"

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"rotate_secret_key","bound_ips":"0.0.0.0/0","can_create_groups":true}'
check "200" "create a key to rotate the secret of"
ROTATE_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
ROTATE_KEY_ID=$(echo "$RESP_BODY" | jq -r '.id')
ROTATE_OLD_SECRET=$(echo "$RESP_BODY" | jq -r '.signing_secret')
register_key_secret "$ROTATE_KEY" "$ROTATE_OLD_SECRET"

api_call GET "/api/auth/me" "$ROTATE_KEY"
check "200" "the key authenticates with its original signing secret"

api_call POST "/api/keys/$ROTATE_KEY_ID/rotate-secret" "$MASTER_KEY"
check "200" "rotate the signing secret"
check_true '.id != null' "the response carries the key id"
check_true '.name == "rotate_secret_key"' "the key name is preserved"
check_true '.signing_secret != null and (.signing_secret | length) > 0' "a new signing secret is returned"
check_true '.plaintext_key == null' "rotate-secret does NOT reissue the API key"
ROTATE_NEW_SECRET=$(echo "$RESP_BODY" | jq -r '.signing_secret')

if [ "$ROTATE_NEW_SECRET" != "$ROTATE_OLD_SECRET" ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} the new signing secret differs from the old one" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} rotate-secret returned the same signing secret" >&2
fi

# The old secret is dead: sign with it explicitly (the same API key, the previous secret).
NOW_TS=$(date -u +%s)
OLD_SIG=$(hmac_sign "$ROTATE_OLD_SECRET" "GET" "/api/auth/me" "$NOW_TS" "")
raw_call GET "/api/auth/me" -H "X-API-Key: $ROTATE_KEY" -H "X-Timestamp: $NOW_TS" -H "X-Signature-256: $OLD_SIG"
check "401" "the OLD signing secret no longer authenticates"

# The same, unchanged API key works with the new secret.
register_key_secret "$ROTATE_KEY" "$ROTATE_NEW_SECRET"
api_call GET "/api/auth/me" "$ROTATE_KEY"
check "200" "the SAME API key authenticates with the new signing secret"
check_true ".id == \"$ROTATE_KEY_ID\"" "identity is unchanged after rotation"
check_true '.can_create_groups == true' "global scopes survive rotation"

api_call GET "/api/audit-logs?action=KEY_SECRET_ROTATE&limit=1" "$MASTER_KEY"
check "200" "fetch the KEY_SECRET_ROTATE audit entry"
check_true '.[0].details | contains("rotate_secret_key")' "the audit entry names the rotated key"

api_call POST "/api/keys/00000000-0000-0000-0000-000000000000/rotate-secret" "$MASTER_KEY"
check "404" "rotating an unknown key id is a 404"

api_call POST "/api/keys/$ROTATE_KEY_ID/rotate-secret" "$NOACCESS_KEY"
check "403" "a key without can_manage_keys cannot rotate secrets"

api_call DELETE "/api/keys/$ROTATE_KEY_ID" "$MASTER_KEY"
check "204" "clean up the rotation test key"

# ── 22. Webhook auth modes ──────────────────────────────────────────────────

log_section "22. Webhook Auth Modes (CANONICAL_V1 / HMAC_ONLY / API_KEY_ONLY / NONE)"

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"SigMode-Group"}'
check "200" "create a group for auth-mode webhooks"
SIGMODE_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

# Validation happens at the API boundary rather than silently downgrading.
api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"bad-mode\",\"target_url\":\"https://example.com/h\",\"secret_token\":\"s\",\"payload_template\":\"{}\",\"group_id\":\"$SIGMODE_GROUP_ID\",\"auth_mode\":\"CANONICAL_V2\"}"
check "400" "an unknown auth_mode is rejected"

# Per-mode preconditions: a signing mode with no key signs with the empty secret (forgeable), and
# API_KEY_ONLY with no key sends no credential at all (silently equivalent to NONE).
api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"no-secret\",\"target_url\":\"https://example.com/h\",\"payload_template\":\"{}\",\"group_id\":\"$SIGMODE_GROUP_ID\",\"auth_mode\":\"CANONICAL_V1\"}"
check "400" "a signing auth_mode without a secret_token is rejected"

# The explicitly-blank variant, which is what an untouched HTML form field actually posts — it must
# not slip past a check that only looks for an absent field.
api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"empty-secret\",\"target_url\":\"https://example.com/h\",\"secret_token\":\"\",\"payload_template\":\"{}\",\"group_id\":\"$SIGMODE_GROUP_ID\",\"auth_mode\":\"CANONICAL_V1\"}"
check "400" "CANONICAL_V1 with an empty secret_token is rejected"

# Case-insensitive mode parsing must not become a route around the precondition.
api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"lowercase-mode\",\"target_url\":\"https://example.com/h\",\"secret_token\":\"\",\"payload_template\":\"{}\",\"group_id\":\"$SIGMODE_GROUP_ID\",\"auth_mode\":\"canonical_v1\"}"
check "400" "a lowercase canonical_v1 with an empty secret_token is rejected"

# ...nor may the deprecated alias reach a different validation path.
api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"alias-mode\",\"target_url\":\"https://example.com/h\",\"secret_token\":\"\",\"payload_template\":\"{}\",\"group_id\":\"$SIGMODE_GROUP_ID\",\"signature_mode\":\"CANONICAL_V1\"}"
check "400" "the deprecated signature_mode alias enforces the same secret precondition"

api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"no-key\",\"target_url\":\"https://example.com/h\",\"payload_template\":\"{}\",\"group_id\":\"$SIGMODE_GROUP_ID\",\"auth_mode\":\"API_KEY_ONLY\"}"
check "400" "API_KEY_ONLY without an api_key is rejected"

api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"bodyless-template\",\"target_url\":\"https://example.com/h\",\"secret_token\":\"s\",\"payload_template\":\"{}\",\"group_id\":\"$SIGMODE_GROUP_ID\",\"auth_mode\":\"CANONICAL_V1\",\"hmac_template\":\"{method}\\\\n{path}\\\\n{timestamp}\"}"
check "400" "an hmac_template that omits {body} is rejected"

api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"default-mode\",\"target_url\":\"https://example.com/h\",\"secret_token\":\"s\",\"payload_template\":\"{}\",\"group_id\":\"$SIGMODE_GROUP_ID\"}"
check "200" "omitting auth_mode is accepted"
check_true '.auth_mode == "CANONICAL_V1"' "an omitted auth_mode defaults to CANONICAL_V1"
DEFAULT_MODE_WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

# The previous field name still selects a mode, so existing callers keep working.
api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"alias-mode\",\"target_url\":\"https://example.com/h\",\"secret_token\":\"s\",\"payload_template\":\"{}\",\"group_id\":\"$SIGMODE_GROUP_ID\",\"signature_mode\":\"BODY_ONLY\"}"
check "200" "the deprecated signature_mode alias is still accepted"
# The request sent the deprecated `signature_mode: BODY_ONLY`; the service accepts it and reports the
# current name back. Both halves matter — refusing the old spelling would break stored automation,
# and echoing it back would leave two names for one mode in circulation indefinitely.
check_true '.auth_mode == "HMAC_ONLY"' "the legacy alias is accepted and normalised to HMAC_ONLY"
ALIAS_MODE_WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call GET "/api/webhooks" "$MASTER_KEY"
check "200" "list webhooks"
check_true "[.[] | select(.id == \"$DEFAULT_MODE_WEBHOOK_ID\")] | length == 1" "the webhook appears in the listing"
check_true "[.[] | select(.id == \"$DEFAULT_MODE_WEBHOOK_ID\") | .auth_mode == \"CANONICAL_V1\"] | all" "the listing exposes auth_mode"
check_true "[.[] | select(.id == \"$DEFAULT_MODE_WEBHOOK_ID\") | .hmac_template == \"{method}\\\\n{path}\\\\n{timestamp}\\\\n{body}\"] | all" "the listing resolves hmac_template to the effective default"
check_true "[.[] | select(.id == \"$DEFAULT_MODE_WEBHOOK_ID\") | .has_api_key == false] | all" "the listing reports api_key presence, not its value"
check_true 'all(.[]; has("api_key") | not)' "no listed webhook ever exposes its api_key"

api_call DELETE "/api/webhooks/$ALIAS_MODE_WEBHOOK_ID" "$MASTER_KEY"
check "204" "delete the alias-mode webhook"

api_call DELETE "/api/webhooks/$DEFAULT_MODE_WEBHOOK_ID" "$MASTER_KEY"
check "204" "delete the default-mode webhook"

# Live CANONICAL_V1 dispatch verification needs the local receiver from §13.
if [ "${WEBHOOK_RECEIVER_AVAILABLE:-0}" -eq 1 ]; then
    CANON_SECRET="canonical-e2e-secret"
    : > "$RECEIVER_LOG"

    api_call POST "/api/webhooks" "$MASTER_KEY" \
        "{\"name\":\"canonical-hook\",\"target_url\":\"http://127.0.0.1:$RECEIVER_PORT/canon\",\"secret_token\":\"$CANON_SECRET\",\"payload_template\":\"{\\\"ip\\\":\\\"\$target_address\\\"}\",\"group_id\":\"$SIGMODE_GROUP_ID\",\"auth_mode\":\"CANONICAL_V1\",\"events\":\"IP_ADD\"}"
    check "200" "create a CANONICAL_V1 webhook"
    check_true '.auth_mode == "CANONICAL_V1"' "creation echoes CANONICAL_V1"
    CANON_WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/ban" "$MASTER_KEY" "{\"target_address\":\"198.51.100.222\",\"group_name\":\"SigMode-Group\",\"cause\":\"canonical dispatch\"}"
    check "200" "ban an address to trigger the canonical dispatch"

    # Dispatch is asynchronous; poll for the delivery line.
    for _ in $(seq 1 40); do
        [ -s "$RECEIVER_LOG" ] && break
        sleep 0.25
    done

    if [ -s "$RECEIVER_LOG" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} the CANONICAL_V1 webhook was delivered" >&2

        HIT=$(head -n 1 "$RECEIVER_LOG")
        HOOK_SIG=$(echo "$HIT" | jq -r '.signature // empty')
        HOOK_TS=$(echo "$HIT" | jq -r '.timestamp // empty')
        HOOK_BODY=$(echo "$HIT" | jq -r '.body // empty')
        HOOK_PATH=$(echo "$HIT" | jq -r '.path // empty')
        log "Captured dispatch: path=$HOOK_PATH ts=$HOOK_TS sig=${HOOK_SIG:0:16}..."

        if [ -n "$HOOK_TS" ]; then
            PASS_COUNT=$((PASS_COUNT + 1))
            echo -e "$(ts)   ${GREEN}✓ PASS${RESET} the dispatch carries an X-Timestamp header" >&2
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
            echo -e "$(ts)   ${RED}✗ FAIL${RESET} CANONICAL_V1 dispatch is missing X-Timestamp" >&2
        fi

        # Recompute the signature exactly as the server should have: POST\npath\nts\nbody.
        EXPECTED_SIG=$(hmac_sign "$CANON_SECRET" "POST" "$HOOK_PATH" "$HOOK_TS" "$HOOK_BODY")
        if [ -n "$HOOK_SIG" ] && [ "$HOOK_SIG" == "$EXPECTED_SIG" ]; then
            PASS_COUNT=$((PASS_COUNT + 1))
            echo -e "$(ts)   ${GREEN}✓ PASS${RESET} X-Signature-256 matches HMAC(POST\\npath\\ntimestamp\\nbody)" >&2
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
            echo -e "$(ts)   ${RED}✗ FAIL${RESET} canonical signature mismatch (got '$HOOK_SIG', expected '$EXPECTED_SIG')" >&2
        fi

        # `sha256=`-prefixed, exactly like HMAC_ONLY and exactly like what the API itself now
        # requires inbound. This is the property that lets a dispatch authenticate directly against
        # another instance's /api/* route: a bare digest would be refused with 401 there.
        case "$HOOK_SIG" in
            sha256=*)
                PASS_COUNT=$((PASS_COUNT + 1))
                echo -e "$(ts)   ${GREEN}✓ PASS${RESET} CANONICAL_V1 sends a sha256=-prefixed signature" >&2
                ;;
            *)
                FAIL_COUNT=$((FAIL_COUNT + 1))
                echo -e "$(ts)   ${RED}✗ FAIL${RESET} CANONICAL_V1 signature must carry the mandatory sha256= prefix" >&2
                ;;
        esac
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} CANONICAL_V1 webhook was never delivered" >&2
    fi

    api_call DELETE "/api/webhooks/$CANON_WEBHOOK_ID" "$MASTER_KEY"
    check "204" "delete the canonical webhook"

    # And the legacy mode, through the same receiver, must still be `sha256=`-prefixed with no
    # timestamp — the regression guard for third-party consumers.
    : > "$RECEIVER_LOG"
    api_call POST "/api/webhooks" "$MASTER_KEY" \
        "{\"name\":\"legacy-hook\",\"target_url\":\"http://127.0.0.1:$RECEIVER_PORT/legacy\",\"secret_token\":\"$CANON_SECRET\",\"payload_template\":\"{\\\"ip\\\":\\\"\$target_address\\\"}\",\"group_id\":\"$SIGMODE_GROUP_ID\",\"auth_mode\":\"HMAC_ONLY\",\"events\":\"IP_ADD\"}"
    check "200" "create an HMAC_ONLY webhook on the same receiver"
    LEGACY_WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/ban" "$MASTER_KEY" "{\"target_address\":\"198.51.100.223\",\"group_name\":\"SigMode-Group\"}"
    check "200" "ban an address to trigger the legacy dispatch"

    for _ in $(seq 1 40); do
        [ -s "$RECEIVER_LOG" ] && break
        sleep 0.25
    done

    if [ -s "$RECEIVER_LOG" ]; then
        HIT=$(head -n 1 "$RECEIVER_LOG")
        LEGACY_SIG=$(echo "$HIT" | jq -r '.signature // empty')
        LEGACY_TS=$(echo "$HIT" | jq -r '.timestamp // empty')
        LEGACY_BODY=$(echo "$HIT" | jq -r '.body // empty')
        LEGACY_EXPECTED="sha256=$(printf '%s' "$LEGACY_BODY" | openssl dgst -sha256 -hmac "$CANON_SECRET" | sed 's/^.*= //')"

        if [ -z "$LEGACY_TS" ]; then
            PASS_COUNT=$((PASS_COUNT + 1))
            echo -e "$(ts)   ${GREEN}✓ PASS${RESET} HMAC_ONLY sends no X-Timestamp header" >&2
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
            echo -e "$(ts)   ${RED}✗ FAIL${RESET} HMAC_ONLY unexpectedly sent X-Timestamp: $LEGACY_TS" >&2
        fi

        if [ "$LEGACY_SIG" == "$LEGACY_EXPECTED" ]; then
            PASS_COUNT=$((PASS_COUNT + 1))
            echo -e "$(ts)   ${GREEN}✓ PASS${RESET} HMAC_ONLY signature is sha256=HMAC(body) — unchanged legacy format" >&2
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
            echo -e "$(ts)   ${RED}✗ FAIL${RESET} HMAC_ONLY signature mismatch (got '$LEGACY_SIG', expected '$LEGACY_EXPECTED')" >&2
        fi
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} HMAC_ONLY webhook was never delivered" >&2
    fi

    api_call DELETE "/api/webhooks/$LEGACY_WEBHOOK_ID" "$MASTER_KEY"
    check "204" "delete the legacy webhook"
else
    warn "Local webhook receiver unavailable — skipping live CANONICAL_V1/HMAC_ONLY dispatch verification."
fi

# ── 23. Dynamic HMAC templates & key-based dispatch ─────────────────────────

log_section "23. Dynamic HMAC Templates, API_KEY_ONLY and NONE Dispatch"

if [ "${WEBHOOK_RECEIVER_AVAILABLE:-0}" -eq 1 ]; then
    TEMPLATE_SECRET="template-e2e-secret"
    DOWNSTREAM_KEY="downstream-e2e-key"
    # The simply_hook_executor shape: the vault POSTs to whatever URL the proxy exposes, while the
    # receiver behind it signs over the path IT sees. Hardcoding that path in the template is the
    # whole mechanism — no extra column, no proxy-awareness in the dispatcher.
    EXECUTOR_PATH="/api/hooks/42/execute"
    ESCAPED_TEMPLATE="{method}\\\\n$EXECUTOR_PATH\\\\n{timestamp}\\\\n{body}"
    : > "$RECEIVER_LOG"

    api_call POST "/api/webhooks" "$MASTER_KEY" \
        "{\"name\":\"executor-hook\",\"target_url\":\"http://127.0.0.1:$RECEIVER_PORT/proxied/path\",\"secret_token\":\"$TEMPLATE_SECRET\",\"payload_template\":\"{\\\"ip\\\":\\\"\$target_address\\\"}\",\"group_id\":\"$SIGMODE_GROUP_ID\",\"auth_mode\":\"CANONICAL_V1\",\"api_key\":\"$DOWNSTREAM_KEY\",\"hmac_template\":\"$ESCAPED_TEMPLATE\",\"events\":\"IP_ADD\"}"
    check "200" "create a CANONICAL_V1 webhook with a hardcoded-path hmac_template"
    TEMPLATE_WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/ban" "$MASTER_KEY" "{\"target_address\":\"198.51.100.224\",\"group_name\":\"SigMode-Group\",\"cause\":\"templated dispatch\"}"
    check "200" "ban an address to trigger the templated dispatch"

    for _ in $(seq 1 40); do
        [ -s "$RECEIVER_LOG" ] && break
        sleep 0.25
    done

    if [ -s "$RECEIVER_LOG" ]; then
        HIT=$(head -n 1 "$RECEIVER_LOG")
        T_SIG=$(echo "$HIT" | jq -r '.signature // empty')
        T_TS=$(echo "$HIT" | jq -r '.timestamp // empty')
        T_BODY=$(echo "$HIT" | jq -r '.body // empty')
        T_PATH=$(echo "$HIT" | jq -r '.path // empty')
        T_KEY=$(echo "$HIT" | jq -r '.api_key // empty')

        if [ "$T_PATH" == "/proxied/path" ]; then
            PASS_COUNT=$((PASS_COUNT + 1))
            echo -e "$(ts)   ${GREEN}✓ PASS${RESET} the request is still sent to target_url's path" >&2
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
            echo -e "$(ts)   ${RED}✗ FAIL${RESET} expected delivery to /proxied/path, got '$T_PATH'" >&2
        fi

        if [ "$T_KEY" == "$DOWNSTREAM_KEY" ]; then
            PASS_COUNT=$((PASS_COUNT + 1))
            echo -e "$(ts)   ${GREEN}✓ PASS${RESET} CANONICAL_V1 sends the configured api_key as X-API-Key" >&2
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
            echo -e "$(ts)   ${RED}✗ FAIL${RESET} expected X-API-Key '$DOWNSTREAM_KEY', got '$T_KEY'" >&2
        fi

        # Signed over the template's hardcoded path...
        TEMPLATE_EXPECTED=$(hmac_sign "$TEMPLATE_SECRET" "POST" "$EXECUTOR_PATH" "$T_TS" "$T_BODY")
        if [ -n "$T_SIG" ] && [ "$T_SIG" == "$TEMPLATE_EXPECTED" ]; then
            PASS_COUNT=$((PASS_COUNT + 1))
            echo -e "$(ts)   ${GREEN}✓ PASS${RESET} the signature covers the template's hardcoded path, not target_url's" >&2
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
            echo -e "$(ts)   ${RED}✗ FAIL${RESET} templated signature mismatch (got '$T_SIG', expected '$TEMPLATE_EXPECTED')" >&2
        fi

        # ...and NOT over the URL-derived one, or the check above would pass for the wrong reason.
        URL_DERIVED=$(hmac_sign "$TEMPLATE_SECRET" "POST" "/proxied/path" "$T_TS" "$T_BODY")
        if [ "$T_SIG" != "$URL_DERIVED" ]; then
            PASS_COUNT=$((PASS_COUNT + 1))
            echo -e "$(ts)   ${GREEN}✓ PASS${RESET} the URL-derived path does not produce a matching signature" >&2
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
            echo -e "$(ts)   ${RED}✗ FAIL${RESET} the template's path did not override the URL-derived one" >&2
        fi
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} the templated webhook was never delivered" >&2
    fi

    api_call DELETE "/api/webhooks/$TEMPLATE_WEBHOOK_ID" "$MASTER_KEY"
    check "204" "delete the templated webhook"

    # The two unsigned modes, back to back through the same receiver.
    for MODE_SPEC in "API_KEY_ONLY:198.51.100.225:$DOWNSTREAM_KEY" "NONE:198.51.100.226:"; do
        MODE="${MODE_SPEC%%:*}"
        REST="${MODE_SPEC#*:}"
        MODE_ADDR="${REST%%:*}"
        EXPECT_KEY="${REST#*:}"
        : > "$RECEIVER_LOG"

        api_call POST "/api/webhooks" "$MASTER_KEY" \
            "{\"name\":\"${MODE}-hook\",\"target_url\":\"http://127.0.0.1:$RECEIVER_PORT/unsigned\",\"payload_template\":\"{\\\"ip\\\":\\\"\$target_address\\\"}\",\"group_id\":\"$SIGMODE_GROUP_ID\",\"auth_mode\":\"$MODE\",\"api_key\":\"$DOWNSTREAM_KEY\",\"events\":\"IP_ADD\"}"
        check "200" "create a $MODE webhook (no secret_token required)"
        UNSIGNED_WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

        api_call POST "/api/ban" "$MASTER_KEY" "{\"target_address\":\"$MODE_ADDR\",\"group_name\":\"SigMode-Group\"}"
        check "200" "ban an address to trigger the $MODE dispatch"

        for _ in $(seq 1 40); do
            [ -s "$RECEIVER_LOG" ] && break
            sleep 0.25
        done

        if [ -s "$RECEIVER_LOG" ]; then
            HIT=$(head -n 1 "$RECEIVER_LOG")
            U_SIG=$(echo "$HIT" | jq -r '.signature // empty')
            U_TS=$(echo "$HIT" | jq -r '.timestamp // empty')
            U_KEY=$(echo "$HIT" | jq -r '.api_key // empty')
            U_BODY=$(echo "$HIT" | jq -r '.body // empty')

            if [ -z "$U_SIG" ] && [ -z "$U_TS" ]; then
                PASS_COUNT=$((PASS_COUNT + 1))
                echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $MODE sends neither X-Signature-256 nor X-Timestamp" >&2
            else
                FAIL_COUNT=$((FAIL_COUNT + 1))
                echo -e "$(ts)   ${RED}✗ FAIL${RESET} $MODE unexpectedly sent sig='$U_SIG' ts='$U_TS'" >&2
            fi

            if [ "$U_KEY" == "$EXPECT_KEY" ]; then
                PASS_COUNT=$((PASS_COUNT + 1))
                echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $MODE X-API-Key header is as expected ('$EXPECT_KEY')" >&2
            else
                FAIL_COUNT=$((FAIL_COUNT + 1))
                echo -e "$(ts)   ${RED}✗ FAIL${RESET} $MODE expected X-API-Key '$EXPECT_KEY', got '$U_KEY'" >&2
            fi

            case "$U_BODY" in
                *"$MODE_ADDR"*)
                    PASS_COUNT=$((PASS_COUNT + 1))
                    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} $MODE still delivers the templated payload" >&2
                    ;;
                *)
                    FAIL_COUNT=$((FAIL_COUNT + 1))
                    echo -e "$(ts)   ${RED}✗ FAIL${RESET} $MODE payload did not contain $MODE_ADDR (got '$U_BODY')" >&2
                    ;;
            esac
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
            echo -e "$(ts)   ${RED}✗ FAIL${RESET} the $MODE webhook was never delivered" >&2
        fi

        api_call DELETE "/api/webhooks/$UNSIGNED_WEBHOOK_ID" "$MASTER_KEY"
        check "204" "delete the $MODE webhook"
    done
else
    warn "Local webhook receiver unavailable — skipping live template/API_KEY_ONLY/NONE dispatch verification."
fi

# ── Summary ──────────────────────────────────────────────────────────────────

log_section "24. IP Soft Delete, Restore, Hard Delete & 92-Day Purge"

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"softdelete-group"}'
check "200" "create a group for the soft-delete checks"
SOFTDEL_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

# A delegated key with full group rights but no master status — the one whose deletes must be soft.
api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Soft Deleter"}'
check "200" "create a non-master deleter key"
SOFTDEL_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
SOFTDEL_KEY_ID=$(echo "$RESP_BODY" | jq -r '.id')
register_key_secret "$SOFTDEL_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

api_call POST "/api/keys/$SOFTDEL_KEY_ID/permissions" "$MASTER_KEY" \
    "{\"group_id\":\"$SOFTDEL_GROUP_ID\",\"can_read\":true,\"can_write\":true,\"can_delete\":true}"
check "200" "grant the deleter full rights on the group"

api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"198.51.100.201","group_name":"softdelete-group","cause":"soft delete test"}'
check "200" "ban an address to soft-delete"

api_call GET "/api/ips?groups=softdelete-group" "$MASTER_KEY"
check "200" "list the group before deletion"

# A non-master delete must be soft: hidden from reads, row retained.
api_call DELETE "/api/ips" "$SOFTDEL_KEY" '{"target_address":"198.51.100.201","group_name":"softdelete-group"}'
check "204" "a non-master DELETE /api/ips (by address and group) succeeds"

api_call GET "/api/ips?groups=softdelete-group" "$SOFTDEL_KEY"
check "200" "the deleter lists the group after deleting"
check_true '[.[] | select(.target_address == "198.51.100.201")] | length == 0' \
    "the soft-deleted record is hidden from the non-master listing"

api_call GET "/api/ips?groups=softdelete-group&format=iplist" "$SOFTDEL_KEY"
check "200" "the iplist export also runs after deletion"
check_true '[.ip_list[] | select(. == "198.51.100.201")] | length == 0' \
    "the soft-deleted record is excluded from the iplist export too"

# A non-master cannot escalate to a permanent delete.
api_call DELETE "/api/ips?hard=true" "$SOFTDEL_KEY" '{"target_address":"198.51.100.201","group_name":"softdelete-group"}'
check "403" "a non-master cannot hard-delete a record"

# The master trash view sees it, with its attribution.
api_call GET "/api/ips?include_deleted=true&groups=softdelete-group" "$MASTER_KEY"
check "200" "master lists the trash with include_deleted=true"
check_true '[.[] | select(.target_address == "198.51.100.201" and .is_deleted == true)] | length == 1' \
    "the master trash view exposes the soft-deleted record"
check_true "[.[] | select(.target_address == \"198.51.100.201\") | .deleted_by == \"$SOFTDEL_KEY_ID\"] | all" \
    "deleted_by attributes the key that issued the delete"

# The master's DEFAULT listing still hides it — the trash is opt-in, not a master-only default view.
api_call GET "/api/ips?groups=softdelete-group" "$MASTER_KEY"
check "200" "master lists the group without include_deleted"
check_true '[.[] | select(.target_address == "198.51.100.201")] | length == 0' \
    "the trash stays hidden unless include_deleted is explicitly requested"

# Restore.
api_call POST "/api/ips/restore" "$SOFTDEL_KEY" '{"target_address":"198.51.100.201","group_name":"softdelete-group"}'
check "403" "a non-master cannot restore a deleted record"

api_call POST "/api/ips/restore" "$MASTER_KEY" '{"target_address":"198.51.100.201","group_name":"softdelete-group"}'
check "200" "master restores the soft-deleted record"
check_true '.restored == true' "the restore is reported"

api_call GET "/api/ips?groups=softdelete-group" "$SOFTDEL_KEY"
check "200" "list the group after restoration"
check_true '[.[] | select(.target_address == "198.51.100.201")] | length == 1' \
    "the restored record is visible again"

api_call POST "/api/ips/restore" "$MASTER_KEY" '{"target_address":"198.51.100.201","group_name":"softdelete-group"}'
check "400" "restoring an already-live record is rejected"

# Re-banning a soft-deleted address must resurrect it rather than collide with the unique index.
api_call DELETE "/api/ips" "$SOFTDEL_KEY" '{"target_address":"198.51.100.201","group_name":"softdelete-group"}'
check "204" "soft-delete the record again"
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"198.51.100.201","group_name":"softdelete-group","cause":"seen again"}'
check "200" "re-banning a soft-deleted address succeeds instead of colliding"
api_call GET "/api/ips?groups=softdelete-group" "$MASTER_KEY"
check_true '[.[] | select(.target_address == "198.51.100.201")] | length == 1' \
    "re-registration resurrected the record"

# Purge: master-only, and the window cannot be set to a destructive zero.
api_call POST "/api/system/purge-ips" "$SOFTDEL_KEY"
check "403" "a non-master cannot purge deleted records"

api_call POST "/api/system/purge-ips" "$MASTER_KEY" '{"older_than_days":0}'
check "400" "older_than_days=0 is rejected rather than treated as 'purge everything'"

api_call POST "/api/system/purge-ips" "$MASTER_KEY" '{"older_than_days":-5}'
check "400" "a negative older_than_days is rejected"

api_call POST "/api/system/purge-ips" "$MASTER_KEY"
check "200" "master runs the purge with the default window"
check_true '.retention_days == 92' "the default retention window is 92 days"
check_true '.purged == 0' "nothing is purged: the only deleted record is far younger than 92 days"

api_call GET "/api/ips?groups=softdelete-group" "$MASTER_KEY"
check_true '[.[] | select(.target_address == "198.51.100.201")] | length == 1' \
    "the live record survived the purge"

# Master hard delete really drops the row.
api_call DELETE "/api/ips?hard=true" "$MASTER_KEY" '{"target_address":"198.51.100.201","group_name":"softdelete-group"}'
check "204" "master hard-deletes the record"

api_call GET "/api/ips?include_deleted=true&groups=softdelete-group" "$MASTER_KEY"
check_true '[.[] | select(.target_address == "198.51.100.201")] | length == 0' \
    "a hard-deleted record is gone even from the trash view"

log_section "24c. Whitelist Parity: Update, Soft Delete, Restore, Hard Delete"

# §3/§24 above exhaustively cover a *banlist* record's full lifecycle — create, re-register,
# permission-gated soft delete, trash visibility, restore, re-registration-after-delete, and hard
# delete. This section is not a second pass at proving the mechanism (group-type is not a branch
# any of that code takes); it exists because a whitelist record had never actually been pushed
# through any of it — created once (§3) and never touched again. A regression scoped to
# `group_type == "whitelist"` specifically — for example a filter that assumed "banlist" — would
# have passed every check above without ever being exercised.

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"softdelete-whitelist-group","group_type":"whitelist"}'
check "200" "create a whitelist group for the whitelist-parity checks"
SOFTDEL_WHITE_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/white" "$MASTER_KEY" '{"target_address":"203.0.113.201","group_name":"softdelete-whitelist-group","cause":"first registration"}'
check "200" "whitelist an address"

api_call GET "/api/ips?groups=softdelete-whitelist-group" "$MASTER_KEY"
check "200" "list the whitelist group before any update"
check_jq ".[0].cause" "first registration" "the initial cause is recorded"
SOFTDEL_WHITE_RECORD_ID=$(echo "$RESP_BODY" | jq -r '.[0].id')

# Update: re-registering the same address must update the existing row, not collide or duplicate —
# the whitelist mirror of §3's banlist "re-registering an existing address updates it" check.
api_call POST "/api/white" "$MASTER_KEY" '{"target_address":"203.0.113.201","group_name":"softdelete-whitelist-group","cause":"updated-cause"}'
check "200" "re-registering the same whitelisted address succeeds"
api_call GET "/api/ips?groups=softdelete-whitelist-group" "$MASTER_KEY"
check_true "length == 1" "still exactly one record — the re-registration updated it, not duplicated it"
check_jq ".[0].cause" "updated-cause" "the cause was updated by the re-registration"
check_jq ".[0].id" "$SOFTDEL_WHITE_RECORD_ID" "same row, same id — a genuine update, not a delete+recreate"

# Soft delete + trash visibility.
api_call DELETE "/api/ips" "$MASTER_KEY" '{"target_address":"203.0.113.201","group_name":"softdelete-whitelist-group"}'
check "204" "soft-delete the whitelisted record"

api_call GET "/api/ips?groups=softdelete-whitelist-group" "$MASTER_KEY"
check_true '[.[] | select(.target_address == "203.0.113.201")] | length == 0' \
    "the soft-deleted whitelist record is hidden from the default listing"

api_call GET "/api/ips?include_deleted=true&groups=softdelete-whitelist-group" "$MASTER_KEY"
check_true '[.[] | select(.target_address == "203.0.113.201" and .is_deleted == true)] | length == 1' \
    "the trash view exposes the soft-deleted whitelist record, same as a banlist one"

# Restore.
api_call POST "/api/ips/restore" "$MASTER_KEY" '{"target_address":"203.0.113.201","group_name":"softdelete-whitelist-group"}'
check "200" "restore the soft-deleted whitelist record"
check_true '.restored == true' "the restore is reported"
api_call GET "/api/ips?groups=softdelete-whitelist-group" "$MASTER_KEY"
check_true '[.[] | select(.target_address == "203.0.113.201")] | length == 1' \
    "the restored whitelist record is visible again"

# Hard delete really drops the row.
api_call DELETE "/api/ips?hard=true" "$MASTER_KEY" '{"target_address":"203.0.113.201","group_name":"softdelete-whitelist-group"}'
check "204" "hard-delete the whitelist record"
api_call GET "/api/ips?include_deleted=true&groups=softdelete-whitelist-group" "$MASTER_KEY"
check_true '[.[] | select(.target_address == "203.0.113.201")] | length == 0' \
    "a hard-deleted whitelist record is gone even from the trash view"

# ── SQLite concurrency pragmas ──────────────────────────────────────────────
# Asserted from the startup log rather than by querying, because the pragma is applied once at
# connection setup and this is the only place its actual effect is reported.

log_section "24b. SQLite Session PRAGMAs"

# The four pragmas `src/db.rs` applies. These greps track the log wording in `apply_sqlite_pragmas`;
# if that wording changes, update these rather than deleting them — the point is that a real boot
# reports what actually took effect, which no unit test on `sqlite::memory:` can show (an in-memory
# database legitimately cannot use WAL).
if grep -q "SQLite journal mode: WAL" "$SERVER_LOG"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} SQLite journal_mode=WAL is enabled at startup" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} SQLite WAL mode was not reported at startup" >&2
fi

if grep -q "busy_timeout=10000ms" "$SERVER_LOG"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} SQLite busy_timeout is set to 10000ms" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} SQLite busy_timeout was not reported at startup" >&2
fi

if grep -q "temp_store=MEMORY" "$SERVER_LOG"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} SQLite temp_store=MEMORY is reported at startup" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} SQLite temp_store=MEMORY was not reported at startup" >&2
fi

if grep -q "foreign_keys=ON" "$SERVER_LOG"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} SQLite foreign_keys=ON is reported at startup" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} SQLite foreign_keys was not reported at startup" >&2
fi

if grep -q "synchronous=NORMAL" "$SERVER_LOG"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} SQLite synchronous=NORMAL is reported at startup" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} SQLite synchronous was not reported at startup" >&2
fi

# WAL leaves a -wal sidecar next to the database file while connections are open.
if [ -f "$DB_PATH-wal" ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} the WAL sidecar file exists alongside the database" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} no -wal sidecar found at $DB_PATH-wal" >&2
fi

# The retention worker must have started with the 92-day window.
if grep -q "IP retention worker started" "$SERVER_LOG"; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} the IP retention worker started" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} the IP retention worker did not start" >&2
fi

log_section "25. RBAC Privilege Escalation & Webhook Hijacking"

# A delegated key manager: full can_manage_keys, but NOT master. Everything below asks whether that
# scope can be turned into master authority.
api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Delegated Key Manager","can_manage_keys":true,"can_manage_webhooks":true}'
check "200" "create a non-master key manager"
MANAGER_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
MANAGER_ID=$(echo "$RESP_BODY" | jq -r '.id')
register_key_secret "$MANAGER_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

# An ordinary key for the scope-elevation checks to target. Created BY the manager, so it lands
# inside the manager's subtree — §4 scopes credential operations there, and a target outside it would
# answer 404 for visibility reasons rather than 403 for the R4 reason under test.

# The master key it will attack. Previously a purpose-built second master; RBAC_MODEL.md §5 makes
# that impossible, so the target is the real one — which is a strictly stronger test, since it is the
# credential that actually matters.
VICTIM_ID="$MASTER_ID"

# 1. Minting a master key would return its plaintext in this very response. The refusal is now a
#    `400` rather than a `403`: master status left the API surface entirely, so this is not a scope
#    the caller lacks authority over, it is a field no payload may carry.
api_call POST "/api/keys" "$MANAGER_KEY" '{"name":"Self-Promoted Master","is_master":true}'
check "400" "a non-master cannot mint a master key"

# 1b. Nor can the master itself, and nor does an explicit `false` slip through — §5 says "settable or
#     clearable", so the field is refused in both directions from every caller.
api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Co-Master","is_master":true}'
check "400" "not even a master can mint a second master"

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Explicitly Not Master","is_master":false}'
check "400" "is_master:false is refused too — the field may not appear at all"

api_call GET "/api/keys" "$MASTER_KEY"
check_true '[.[] | select(.is_master == true)] | length == 1' "exactly one master key exists"

# 2-4. Rotating, repointing or deleting the master. Each answers `404`, not `403`, since §4 scopes
#      credential operations to the caller's own subtree and the master is in nobody's. That is
#      stronger than the `403` it replaced: `403` confirmed the id named a real key, which made
#      `POST /keys/{id}/rotate` a way to enumerate the master.
api_call POST "/api/keys/$VICTIM_ID/rotate" "$MANAGER_KEY"
check "404" "a non-master cannot rotate a master key"

api_call POST "/api/keys/$VICTIM_ID/rotate-secret" "$MANAGER_KEY"
check "404" "a non-master cannot rotate a master key's signing secret"

api_call PUT "/api/keys/$VICTIM_ID" "$MANAGER_KEY" '{"bound_ips":"203.0.113.0/24"}'
check "404" "a non-master cannot rewrite a master key's bound_ips"

api_call DELETE "/api/keys/$VICTIM_ID" "$MANAGER_KEY"
check "404" "a non-master cannot delete a master key"

# ...and the answer is byte-identical to the one a genuinely nonexistent id produces. §4: "must
# return the identical status and body the service would return if that id did not exist."
api_call DELETE "/api/keys/$VICTIM_ID" "$MANAGER_KEY"
MASTER_PROBE_BODY="$RESP_BODY"
api_call DELETE "/api/keys/11111111-2222-3333-4444-555555555555" "$MANAGER_KEY"
check "404" "#4 a nonexistent key answers 404 too"
check_local "$RESP_BODY" "$MASTER_PROBE_BODY" \
    "#4 oracle discipline: an invisible key is byte-identical to a nonexistent one"

# 5. Widening its own scopes through the generic update endpoint.
api_call PUT "/api/keys/$MANAGER_ID" "$MANAGER_KEY" '{"can_create_groups":true}'
check "403" "a key cannot grant itself additional scopes"

# The master-only scopes cannot be handed to ANY key by a non-master, not just to itself: each is a
# path back to master authority (co-administrators, or groups whose creator is auto-granted access).
api_call POST "/api/keys" "$MANAGER_KEY" '{"name":"Escalated Manager","can_manage_keys":true}'
check "403" "a non-master cannot grant can_manage_keys"

api_call POST "/api/keys" "$MANAGER_KEY" '{"name":"Escalated Groups","can_create_groups":true}'
check "403" "a non-master cannot grant can_create_groups"

# R4/R1: can_manage_webhooks is a resource-creation right and joined the master-only set. It was
# previously freely delegable — a parent that did not hold it could hand it out, which is the
# plainest possible non-amplification violation.
api_call POST "/api/keys" "$MANAGER_KEY" '{"name":"Escalated Webhooks","can_manage_keys":false,"can_manage_webhooks":true}'
check "403" "a non-master cannot grant can_manage_webhooks"

api_call POST "/api/keys" "$MANAGER_KEY" '{"name":"Scope Elevation Target"}'
check "200" "create a daughter key to attempt scope elevation against"
VICTIM_NONMASTER_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call PUT "/api/keys/$VICTIM_NONMASTER_ID" "$MANAGER_KEY" '{"can_manage_webhooks":true}'
check "403" "nor elevate an existing key into can_manage_webhooks"

# Lowering a scope is never an elevation, so the guard bounds direction rather than the field.
api_call PUT "/api/keys/$VICTIM_NONMASTER_ID" "$MANAGER_KEY" '{"can_manage_webhooks":false}'
check "200" "but it may still take can_manage_webhooks away"

# Controls: the delegated scope still works against non-master targets, so the guards are scoped to
# master escalation rather than having disabled key administration.
api_call POST "/api/keys" "$MANAGER_KEY" '{"name":"Ordinary Delegated Key"}'
check "200" "a non-master can still create ordinary keys"
ORDINARY_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/keys/$ORDINARY_ID/rotate" "$MANAGER_KEY"
check "200" "a non-master can still rotate a non-master key"

api_call DELETE "/api/keys/$ORDINARY_ID" "$MANAGER_KEY"
check "204" "a non-master can still delete a non-master key"

# Webhook hijacking: repointing a webhook must invalidate the secret it signs with, since
# secret_token is write-only and the attacker's route to it is to redirect a signed dispatch to a
# server they control.
api_call POST "/api/groups" "$MASTER_KEY" '{"name":"hijack-group"}'
check "200" "create a group for the webhook hijacking checks"
HIJACK_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"hijack-target\",\"target_url\":\"https://legitimate.example.com/hook\",\"secret_token\":\"original-e2e-secret\",\"payload_template\":\"{}\",\"group_id\":\"$HIJACK_GROUP_ID\",\"auth_mode\":\"CANONICAL_V1\"}"
check "200" "create a webhook to attempt to hijack"
HIJACK_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

# An unrelated edit must not churn the secret.
api_call PUT "/api/webhooks/$HIJACK_HOOK_ID" "$MASTER_KEY" '{"name":"hijack-target-renamed"}'
check "200" "renaming a webhook succeeds"
check_true '.secret_rotated == false' "a rename does not rotate the secret"

# Re-submitting the identical URL is not a repoint, so an idempotent save must not rotate either.
api_call PUT "/api/webhooks/$HIJACK_HOOK_ID" "$MASTER_KEY" '{"target_url":"https://legitimate.example.com/hook"}'
check "200" "re-submitting the same target_url succeeds"
check_true '.secret_rotated == false' "re-submitting the same URL is not a repoint"

# The attack: repoint at an attacker-controlled server.
api_call PUT "/api/webhooks/$HIJACK_HOOK_ID" "$MASTER_KEY" '{"target_url":"https://attacker.example.net/collect"}'
check "200" "repointing a webhook succeeds"
check_true '.secret_rotated == true' "repointing a webhook FORCES its secret_token to rotate"
check_true '.secret_token != null and (.secret_token | length) == 64' "the replacement secret is returned once, full width"
if echo "$RESP_BODY" | grep -q "original-e2e-secret"; then
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} the pre-rotation secret leaked in the update response" >&2
else
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} the pre-rotation secret never appears in the response" >&2
fi

# Rewriting the template decides which bytes the signature covers, so it rotates too.
api_call PUT "/api/webhooks/$HIJACK_HOOK_ID" "$MASTER_KEY" '{"hmac_template":"{method}\\n{path}\\n{timestamp}\\n{body}\\nx"}'
check "200" "rewriting hmac_template succeeds"
check_true '.secret_rotated == true' "rewriting hmac_template also forces rotation"

# A template that never covers the body is refused on update as it is on create.
api_call PUT "/api/webhooks/$HIJACK_HOOK_ID" "$MASTER_KEY" '{"hmac_template":"{method}\\n{path}\\n{timestamp}"}'
check "400" "an hmac_template omitting {body} is rejected on update"

# A caller supplying its own replacement gets no generated value echoed back.
api_call PUT "/api/webhooks/$HIJACK_HOOK_ID" "$MASTER_KEY" '{"target_url":"https://elsewhere.example.com/h","secret_token":"caller-chosen-secret"}'
check "200" "repointing with a caller-supplied secret succeeds"
check_true '.secret_rotated == true' "a caller-supplied secret still counts as a rotation"
check_true '.secret_token == null' "a caller-supplied secret is not echoed back"

# No read endpoint ever discloses either secret.
api_call GET "/api/webhooks" "$MASTER_KEY"
check "200" "list webhooks after the rotations"
if echo "$RESP_BODY" | grep -qE "original-e2e-secret|caller-chosen-secret"; then
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} GET /api/webhooks leaked a secret_token" >&2
else
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} no secret_token is exposed by the webhook listing" >&2
fi

# A webhook that carries an api_key is *privileged*: its dispatches authenticate as a real caller on
# the receiving system (instance chaining), and that credential belongs to the remote system so
# rotation cannot invalidate it. Repointing one is therefore master-only.
#
# The manager is created FIRST and creates the privileged webhook itself, so it is the recorded
# `owner_key_id`. That ordering matters as of RBAC_MODEL.md §3/§4: a webhook is a creator-private
# dispatch target, so a non-owner now gets `404` for every operation on it and never reaches the
# privileged-field guard at all. Owning it is what puts this caller inside the visibility scope, which
# is the only position from which "may rename, may not repoint" is a distinction that can be observed.
api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Webhook Manager","can_manage_webhooks":true}'
check "200" "create a non-master webhook manager"
WHM_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
WHM_KEY_ID=$(echo "$RESP_BODY" | jq -r '.id')
register_key_secret "$WHM_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

api_call POST "/api/keys/$WHM_KEY_ID/permissions" "$MASTER_KEY" \
    "{\"group_id\":\"$HIJACK_GROUP_ID\",\"can_read\":true,\"can_write\":true,\"can_delete\":true}"
check "200" "grant the webhook manager access to the hijack group"

api_call POST "/api/webhooks" "$WHM_KEY" \
    "{\"name\":\"privileged-hook\",\"target_url\":\"https://legitimate.example.com/hook\",\"secret_token\":\"s\",\"api_key\":\"downstream-credential\",\"payload_template\":\"{}\",\"group_id\":\"$HIJACK_GROUP_ID\",\"auth_mode\":\"CANONICAL_V1\"}"
check "200" "create a privileged webhook that carries an api_key"
PRIV_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call PUT "/api/webhooks/$PRIV_HOOK_ID" "$WHM_KEY" '{"target_url":"https://attacker.example.net/collect"}'
check "403" "a non-master cannot repoint a privileged (api_key-bearing) webhook"

# A second webhook manager, sharing the same group, cannot see it at all — the §4 rule that replaced
# group-scoped webhook visibility. `404`, not `403`: outside the scope is indistinguishable from
# nonexistent.
api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Other Webhook Manager","can_manage_webhooks":true}'
check "200" "create a second webhook manager in the same group"
WHM2_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
WHM2_KEY_ID=$(echo "$RESP_BODY" | jq -r '.id')
register_key_secret "$WHM2_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

api_call POST "/api/keys/$WHM2_KEY_ID/permissions" "$MASTER_KEY" \
    "{\"group_id\":\"$HIJACK_GROUP_ID\",\"can_read\":true,\"can_write\":true,\"can_delete\":true}"
check "200" "grant it the same group access as the owner"

api_call PUT "/api/webhooks/$PRIV_HOOK_ID" "$WHM2_KEY" '{"name":"stolen"}'
check "404" "#3 sharing the group is not owning the webhook — a dispatch target is creator-private"

api_call DELETE "/api/webhooks/$PRIV_HOOK_ID" "$WHM2_KEY"
check "404" "#3 nor may a group peer delete it"

api_call PUT "/api/webhooks/$PRIV_HOOK_ID" "$WHM_KEY" '{"hmac_template":"{method}\\n{path}\\n{timestamp}\\n{body}\\nx"}'
check "403" "a non-master cannot rewrite a privileged webhook's hmac_template"

# Non-critical fields stay editable by the delegated manager.
api_call PUT "/api/webhooks/$PRIV_HOOK_ID" "$WHM_KEY" '{"name":"privileged-hook-renamed"}'
check "200" "a non-master can still rename a privileged webhook"

# ...and a master may repoint it, which still forces the secret to rotate.
api_call PUT "/api/webhooks/$PRIV_HOOK_ID" "$MASTER_KEY" '{"target_url":"https://elsewhere.example.com/h"}'
check "200" "a master can repoint a privileged webhook"
check_true '.secret_rotated == true' "repointing a privileged webhook still rotates its secret"

api_call DELETE "/api/webhooks/$PRIV_HOOK_ID" "$MASTER_KEY"
check "204" "delete the privileged webhook"

api_call DELETE "/api/webhooks/$HIJACK_HOOK_ID" "$MASTER_KEY"
check "204" "delete the hijack-target webhook"

log_section "25a. Every Webhook Field Is Editable"

# `UpdateWebhookPayload` used to carry only name/target_url/hmac_template/secret_token/
# headers_json/payload_template/events/is_active — group_id, auth_mode, api_key,
# signature_header, and signature_prefix were fixed at creation. This section proves each of
# those five is now genuinely settable through `PUT /api/webhooks/{id}`, and that the
# privileged-webhook master-only gate (§25 above, previously scoped to target_url/hmac_template
# only) now also covers auth_mode and api_key changes on an already-privileged webhook.

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"editfields-group-a"}'
check "200" "#25a create the webhook's starting group"
EDITFIELDS_GROUP_A=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"editfields-group-b"}'
check "200" "#25a create a second group to retarget onto"
EDITFIELDS_GROUP_B=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"editfields-hook\",\"target_url\":\"https://editfields.example.com/hook\",\"payload_template\":\"{}\",\"group_id\":\"$EDITFIELDS_GROUP_A\",\"auth_mode\":\"NONE\"}"
check "200" "#25a create a non-privileged webhook with no auth"
EDITFIELDS_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

# group_id: retargeting a non-privileged webhook onto another readable group is a plain edit.
api_call PUT "/api/webhooks/$EDITFIELDS_HOOK_ID" "$MASTER_KEY" \
    "{\"group_id\":\"$EDITFIELDS_GROUP_B\"}"
check "200" "#25a group_id is editable"
check_jq ".group_id" "$EDITFIELDS_GROUP_B" "#25a the webhook now reports the new group_id"

# auth_mode: NONE -> HMAC_ONLY needs a secret; omitting one still works because the transition
# itself forces a rotation, exactly like a repoint does.
api_call PUT "/api/webhooks/$EDITFIELDS_HOOK_ID" "$MASTER_KEY" '{"auth_mode":"HMAC_ONLY"}'
check "200" "#25a auth_mode is editable, and a transition into a signing mode is accepted without an explicit secret"
check_jq ".auth_mode" "HMAC_ONLY" "#25a the webhook now reports the new auth_mode"
check_true '.secret_rotated == true' "#25a transitioning into a signing mode rotates the secret, same as a repoint"

# signature_header / signature_prefix: freely editable, not gated by anything.
api_call PUT "/api/webhooks/$EDITFIELDS_HOOK_ID" "$MASTER_KEY" \
    '{"signature_header":"X-Custom-Sig","signature_prefix":""}'
check "200" "#25a signature_header and signature_prefix are editable"
check_jq ".signature_header" "X-Custom-Sig" "#25a the webhook now reports the new signature_header"
check_jq ".signature_prefix" "" "#25a an explicit empty signature_prefix (bare digest) is honoured, not treated as absent"

# API_KEY_ONLY transition validation: refused without a key (mirrors create_webhook's own
# precondition), accepted once one is supplied in the same request.
api_call PUT "/api/webhooks/$EDITFIELDS_HOOK_ID" "$MASTER_KEY" '{"auth_mode":"API_KEY_ONLY"}'
check "400" "#25a transitioning into API_KEY_ONLY without ever having (or now supplying) an api_key is refused"

api_call PUT "/api/webhooks/$EDITFIELDS_HOOK_ID" "$MASTER_KEY" \
    '{"auth_mode":"API_KEY_ONLY","api_key":"editfields-downstream-key"}'
check "200" "#25a supplying api_key alongside the mode change satisfies the precondition"
check_jq ".auth_mode" "API_KEY_ONLY" "#25a the webhook now reports API_KEY_ONLY"
check_true '.has_api_key == true' "#25a has_api_key now reports true, without disclosing the key itself"

api_call DELETE "/api/webhooks/$EDITFIELDS_HOOK_ID" "$MASTER_KEY"
check "204" "#25a delete the editfields webhook"

# The privileged-webhook gate, extended: a webhook that already carries a non-empty api_key is
# master-only to edit on target_url/hmac_template/auth_mode/api_key alike — §25 above already
# proved the first two; this proves the extension covers the latter two the same way, using the
# same "manager creates its own webhook, so it is the owner" pattern §25 established.
api_call POST "/api/keys/$WHM_KEY_ID/permissions" "$MASTER_KEY" \
    "{\"group_id\":\"$EDITFIELDS_GROUP_A\",\"can_read\":true,\"can_write\":true,\"can_delete\":true}"
check "200" "#25a grant the existing webhook manager access to the editfields group too"

api_call POST "/api/webhooks" "$WHM_KEY" \
    "{\"name\":\"editfields-privileged-hook\",\"target_url\":\"https://legitimate.example.com/hook\",\"secret_token\":\"s\",\"api_key\":\"downstream-credential\",\"payload_template\":\"{}\",\"group_id\":\"$EDITFIELDS_GROUP_A\",\"auth_mode\":\"CANONICAL_V1\"}"
check "200" "#25a the manager creates its own privileged webhook"
EDITFIELDS_PRIV_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call PUT "/api/webhooks/$EDITFIELDS_PRIV_HOOK_ID" "$WHM_KEY" '{"auth_mode":"NONE"}'
check "403" "#25a a non-master cannot change auth_mode on a privileged webhook"

api_call PUT "/api/webhooks/$EDITFIELDS_PRIV_HOOK_ID" "$WHM_KEY" '{"api_key":"attacker-supplied-key"}'
check "403" "#25a a non-master cannot change api_key on a privileged webhook"

# group_id is deliberately NOT part of that gate — it only changes which events trigger dispatch,
# not where a credential is sent or what is signed — so the same non-master owner may still
# retarget it, as long as it can read the destination group.
api_call PUT "/api/webhooks/$EDITFIELDS_PRIV_HOOK_ID" "$WHM_KEY" \
    "{\"group_id\":\"$HIJACK_GROUP_ID\"}"
check "200" "#25a a non-master owner may retarget a privileged webhook's group when it can read the destination"

api_call PUT "/api/webhooks/$EDITFIELDS_PRIV_HOOK_ID" "$WHM_KEY" \
    '{"group_id":"00000000-0000-0000-0000-000000000000"}'
check "403" "#25a ...but not onto a group it has no read access to"

api_call PUT "/api/webhooks/$EDITFIELDS_PRIV_HOOK_ID" "$MASTER_KEY" '{"auth_mode":"NONE"}'
check "200" "#25a a master may change auth_mode on a privileged webhook"
check_jq ".auth_mode" "NONE" "#25a the privileged webhook now reports auth_mode NONE"

api_call DELETE "/api/webhooks/$EDITFIELDS_PRIV_HOOK_ID" "$MASTER_KEY"
check "204" "#25a delete the editfields privileged webhook"

log_section "25b. An Edited Webhook's New Config Actually Takes Effect"

# Every PUT check above (renames, repoints, template rewrites, RBAC refusals) verifies only the
# PUT's own HTTP response — `secret_rotated`, a status code, an error body. None of them re-fires a
# real event afterward to prove the *edited* config is what a live dispatch actually uses. A PUT
# handler that accepted a new `target_url` or `events` list but silently kept dispatching against
# the old one would pass every check above. This section closes that gap against the real local
# receiver §13 started (still running, since nothing stops it until final cleanup) — one webhook,
# edited twice, each edit proven by an actual delivery rather than by re-reading the PUT response.
if [ "${WEBHOOK_RECEIVER_AVAILABLE:-0}" -eq 1 ]; then
    # `grep -o | wc -l` rather than `grep -c ... || echo 0`: `grep -c` exits 1 on zero matches
    # while still printing "0", so the `||` fallback would ALSO fire and print a second "0" on the
    # next line — corrupting the very "0" this is meant to report cleanly. `wc -l` always exits 0.
    count_receiver_hits_for_path() {
        grep -o "\"path\": \"$1\"" "$RECEIVER_LOG" 2>/dev/null | wc -l | tr -d ' '
    }

    api_call POST "/api/groups" "$MASTER_KEY" '{"name":"edit-verify-group"}'
    check "200" "create the group backing the edit-verification webhook"
    EDITVERIFY_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/webhooks" "$MASTER_KEY" \
        "{\"name\":\"edit-verify-hook\",\"target_url\":\"http://127.0.0.1:$RECEIVER_PORT/before-edit\",\"payload_template\":\"{}\",\"group_id\":\"$EDITVERIFY_GROUP_ID\",\"auth_mode\":\"NONE\",\"events\":\"IP_ADD\"}"
    check "200" "create a webhook targeting /before-edit, subscribed to IP_ADD only"
    EDITVERIFY_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

    log "Before any edit: banning a new address must reach /before-edit..."
    api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"192.0.2.150","group_name":"edit-verify-group","cause":"pre-edit"}'
    check "200" "IP_ADD before editing the webhook"
    BEFORE_HITS=0
    for _ in $(seq 1 20); do
        BEFORE_HITS=$(count_receiver_hits_for_path "/before-edit")
        [ "${BEFORE_HITS:-0}" -ge 1 ] && break
        sleep 0.2
    done
    check_local "$BEFORE_HITS" "1" "the pre-edit config delivered to /before-edit"

    # The edit: repoint target_url AND narrow events to IP_DELETE only, in one PUT.
    api_call PUT "/api/webhooks/$EDITVERIFY_HOOK_ID" "$MASTER_KEY" \
        "{\"target_url\":\"http://127.0.0.1:$RECEIVER_PORT/after-edit\",\"events\":\"IP_DELETE\"}"
    check "200" "edit the webhook: repoint target_url and change events to IP_DELETE only"
    # UpdateWebhookResponse flattens `webhook: WebhookSummary` into the top level (`#[serde(flatten)]`),
    # so these fields are read directly rather than under a `.webhook` key.
    check_jq ".target_url" "http://127.0.0.1:$RECEIVER_PORT/after-edit" "the PUT response reports the new target_url"
    check_jq ".events" "IP_DELETE" "the PUT response reports the new events filter"

    log "After the edit: an IP_ADD on a fresh address must fire on NEITHER path — events no longer includes IP_ADD..."
    api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"192.0.2.151","group_name":"edit-verify-group","cause":"post-edit, wrong event"}'
    check "200" "IP_ADD after editing the webhook (the ban itself still succeeds; only dispatch is filtered)"
    sleep 1
    check_local "$(count_receiver_hits_for_path "/before-edit")" "1" \
        "still exactly 1 — the old URL received nothing more after the repoint"
    check_local "$(count_receiver_hits_for_path "/after-edit")" "0" \
        "the new URL received nothing either — IP_ADD is no longer a subscribed event"

    log "Deleting that same address (IP_DELETE) must now reach /after-edit — proving both edits together..."
    api_call DELETE "/api/ips?target_address=192.0.2.151&group_name=edit-verify-group" "$MASTER_KEY"
    check "204" "IP_DELETE after editing the webhook"
    AFTER_HITS=0
    for _ in $(seq 1 20); do
        AFTER_HITS=$(count_receiver_hits_for_path "/after-edit")
        [ "${AFTER_HITS:-0}" -ge 1 ] && break
        sleep 0.2
    done
    check_local "$AFTER_HITS" "1" \
        "the edited target_url received the IP_DELETE dispatch — the edit genuinely took effect, not just the API response"
    check_local "$(count_receiver_hits_for_path "/before-edit")" "1" \
        "the old URL still shows exactly the one pre-edit hit — delivery moved, it did not duplicate"
else
    warn "Edit-verification checks skipped (no local webhook receiver — see §13)."
fi

log_section "25c. Target URL Templating & the Executions Endpoint's Rich Filters/Delete"

# `target_url` gained the same `$variable` templating `payload_template` already had — proven here
# against the real local receiver: a webhook whose target_url contains `$action` must dial the
# resolved path, not the literal template, and the resulting `webhook_executions` row must record
# that resolved URL alongside the triggering event's address and cause.
if [ "${WEBHOOK_RECEIVER_AVAILABLE:-0}" -eq 1 ]; then
    api_call POST "/api/groups" "$MASTER_KEY" '{"name":"tmpl-url-group"}'
    check "200" "#25c create the group backing the templated-URL webhook"
    TMPLURL_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/webhooks" "$MASTER_KEY" \
        "{\"name\":\"tmpl-url-hook\",\"target_url\":\"http://127.0.0.1:$RECEIVER_PORT/tmpl-hooks/\$action\",\"payload_template\":\"{}\",\"group_id\":\"$TMPLURL_GROUP_ID\",\"auth_mode\":\"NONE\"}"
    check "200" "#25c create a webhook whose target_url contains \$action"
    TMPLURL_HOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/ban" "$MASTER_KEY" \
        '{"target_address":"192.0.2.170","group_name":"tmpl-url-group","cause":"templating-e2e-cause"}'
    check "200" "#25c IP_ADD to trigger the templated webhook"

    TMPLURL_HITS=0
    for _ in $(seq 1 20); do
        TMPLURL_HITS=$(count_receiver_hits_for_path "/tmpl-hooks/IP_ADD")
        [ "${TMPLURL_HITS:-0}" -ge 1 ] && break
        sleep 0.2
    done
    check_local "$TMPLURL_HITS" "1" \
        "the receiver was hit at the \$action-resolved path /tmpl-hooks/IP_ADD, not the literal template"

    # The execution row must record the resolved URL and the triggering event's own address/cause —
    # not just the webhook's (unresolved) target_url template.
    EXEC_WAIT=0
    for _ in $(seq 1 20); do
        api_call GET "/api/webhooks/executions?webhook_id=$TMPLURL_HOOK_ID" "$MASTER_KEY"
        EXEC_WAIT=$(echo "$RESP_BODY" | jq 'length')
        [ "${EXEC_WAIT:-0}" -ge 1 ] && break
        sleep 0.2
    done
    check "200" "#25c list this webhook's executions"
    check_jq ".[0].resolved_target_url" "http://127.0.0.1:$RECEIVER_PORT/tmpl-hooks/IP_ADD" \
        "the execution row's resolved_target_url has \$action already expanded"
    check_jq ".[0].target_address" "192.0.2.170" "the execution row records the triggering event's address"
    check_jq ".[0].cause" "templating-e2e-cause" "the execution row records the triggering event's cause"
    TMPLURL_EXEC_ID=$(echo "$RESP_BODY" | jq -r '.[0].id')

    # Rich filters, each proven to actually narrow (not merely accepted) against this real row.
    api_call GET "/api/webhooks/executions?status=success" "$MASTER_KEY"
    check_true '[.[] | select(.id == "'"$TMPLURL_EXEC_ID"'")] | length == 1' \
        "#25c status=success includes the templated hook's successful delivery"

    api_call GET "/api/webhooks/executions?search=templating-e2e-cause" "$MASTER_KEY"
    check_true 'length == 1 and .[0].id == "'"$TMPLURL_EXEC_ID"'"' \
        "#25c search matches by cause and returns exactly this row"

    api_call GET "/api/webhooks/executions?ip=192.0.2.170" "$MASTER_KEY"
    check_true 'length == 1 and .[0].id == "'"$TMPLURL_EXEC_ID"'"' \
        "#25c ip filter matches the triggering event's address"

    api_call GET "/api/webhooks/executions?group_id=$TMPLURL_GROUP_ID" "$MASTER_KEY"
    check_true '[.[] | select(.id == "'"$TMPLURL_EXEC_ID"'")] | length == 1' \
        "#25c group_id filter matches via the webhook's current group"

    FUTURE_CUTOFF=$(( $(date +%s) + 3600 ))
    api_call GET "/api/webhooks/executions?from_date=$FUTURE_CUTOFF" "$MASTER_KEY"
    check_true '[.[] | select(.id == "'"$TMPLURL_EXEC_ID"'")] | length == 0' \
        "#25c from_date an hour in the future excludes a row created now"

    api_call GET "/api/webhooks/executions?status=bogus-status" "$MASTER_KEY"
    check "400" "#25c an unrecognized status filter value is refused, not silently ignored"

    # DELETE /api/webhooks/executions/{id} — the row is actually gone afterward, not just reported
    # as deleted.
    api_call DELETE "/api/webhooks/executions/$TMPLURL_EXEC_ID" "$MASTER_KEY"
    check "204" "#25c delete the templated hook's execution row"
    api_call GET "/api/webhooks/executions?webhook_id=$TMPLURL_HOOK_ID" "$MASTER_KEY"
    check_true '[.[] | select(.id == "'"$TMPLURL_EXEC_ID"'")] | length == 0' \
        "#25c the deleted execution row no longer appears in the listing"
    api_call DELETE "/api/webhooks/executions/$TMPLURL_EXEC_ID" "$MASTER_KEY"
    check "404" "#25c deleting the same execution id again is a 404 — it is genuinely gone"

    api_call DELETE "/api/webhooks/$TMPLURL_HOOK_ID" "$MASTER_KEY"
    check "204" "#25c delete the templated-URL webhook"
else
    warn "Target URL templating / executions rich-filter checks skipped (no local webhook receiver — see §13)."
fi

# ─────────────────────────────────────────────────────────────
log_section "26. Convergence — Full-URI Signing, Anti-Replay & Fail-Closed Crypto"
# ─────────────────────────────────────────────────────────────
#
# The three arbitrated decisions of the cross-service convergence pass, asserted against a live
# server rather than in-process, because each one lives in the request pipeline where a unit test
# cannot see the whole path.

# --- Full-URI signature coverage -------------------------------------------------------------
#
# The query string is part of the signed target. Before it was, an on-path attacker who could not
# forge a signature could still append `?hard=true` to a captured `DELETE /api/ips` and turn a
# reversible soft delete into an irreversible purge — no secret required.

api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"198.51.100.240","group_name":"convergence-group","cause":"full-uri signing"}'
check "200" "#26 seed a record for the query-tampering checks"

api_call GET "/api/ips?groups=convergence-group" "$MASTER_KEY"
check "200" "#26 read the seeded record back"

# Sign the bare path, send it with `?hard=true` bolted on — exactly the rewrite a proxy-level
# attacker performs.
next_timestamp "TAMPER|convergence"
TAMPER_TS="$SIGNED_TS"
TAMPER_BODY='{"target_address":"198.51.100.240","group_name":"convergence-group"}'
TAMPER_SIG=$(hmac_sign "$MASTER_SIGNING_SECRET" "DELETE" "/api/ips" "$TAMPER_TS" "$TAMPER_BODY")
raw_call DELETE "/api/ips?hard=true" \
    -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $TAMPER_TS" -H "X-Signature-256: $TAMPER_SIG" \
    -H "Content-Type: application/json" -d "$TAMPER_BODY"
check "401" "#26 a query string appended after signing breaks the signature"

api_call GET "/api/ips?groups=convergence-group" "$MASTER_KEY"
check_true '[.[] | select(.target_address == "198.51.100.240")] | length == 1' \
    "#26 the record survived the rejected escalation"

# The mirror image: a signature computed *with* a query is not valid without it, so a parameter
# cannot be stripped either.
next_timestamp "STRIPQ|convergence"
STRIPQ_TS="$SIGNED_TS"
STRIPQ_SIG=$(hmac_sign "$MASTER_SIGNING_SECRET" "GET" "/api/ips?include_deleted=true" "$STRIPQ_TS" "")
raw_call GET "/api/ips" \
    -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $STRIPQ_TS" -H "X-Signature-256: $STRIPQ_SIG"
check "401" "#26 removing a signed query parameter also breaks the signature"

# ...and a correctly signed query still authenticates, so the change did not simply break every
# filtered read.
api_call GET "/api/ips?groups=convergence-group&limit=5" "$MASTER_KEY"
check "200" "#26 a correctly signed query string authenticates normally"

# --- Anti-replay: signature reuse inside the window -------------------------------------------
#
# A freshness window bounds how *long* a captured request stays usable; it says nothing about using
# it *twice*. Every field the signature covers is unchanged in a replay, so the HMAC verifies and
# the timestamp check passes — only a record of what has already been accepted separates them.
# `simply_ip_vault` is normally reached over plain HTTP on a LAN, so an authentic POST is readable
# by anything on the path.

next_timestamp "REPLAY|convergence"
REPLAY_TS="$SIGNED_TS"
REPLAY_BODY='{"target_address":"198.51.100.241","group_name":"convergence-group","cause":"replay probe"}'
REPLAY_SIG=$(hmac_sign "$MASTER_SIGNING_SECRET" "POST" "/api/ban" "$REPLAY_TS" "$REPLAY_BODY")

raw_call POST "/api/ban" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $REPLAY_TS" \
    -H "X-Signature-256: $REPLAY_SIG" -H "Content-Type: application/json" -d "$REPLAY_BODY"
check "200" "#26 the genuine signed request succeeds"

# The identical bytes, resent. This is the intercepted-and-replayed request.
raw_call POST "/api/ban" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $REPLAY_TS" \
    -H "X-Signature-256: $REPLAY_SIG" -H "Content-Type: application/json" -d "$REPLAY_BODY"
check "401" "#26 a byte-identical replay inside the window is rejected"
check_true '.error | test("already been used")' \
    "#26 the rejection names replay rather than looking like a signature failure"

# A third attempt is refused too: the guard is not a one-shot latch that clears itself.
raw_call POST "/api/ban" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $REPLAY_TS" \
    -H "X-Signature-256: $REPLAY_SIG" -H "Content-Type: application/json" -d "$REPLAY_BODY"
check "401" "#26 the replay stays rejected on further attempts"

# ...while a freshly signed request from the same key is unaffected, proving the guard rejects
# replays rather than simply burning the key after one use.
api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"198.51.100.242","group_name":"convergence-group","cause":"fresh after replay"}'
check "200" "#26 a freshly signed request from the same key still works"

# --- Fail-closed cipher initialization --------------------------------------------------------
#
# A malformed VAULT_ENCRYPTION_KEY must abort startup, never degrade to writing signing secrets in
# the clear. The previous implementation accepted any string and SHA-256'd it, so
# `VAULT_ENCRYPTION_KEY=password` produced a key with the entropy of "password" and no signal that
# anything was wrong. Booting a throwaway instance is the only way to assert a startup decision.

BADKEY_PORT=$((VAULT_PORT + 61))
BADKEY_DB="$WORK_DIR/badkey.db"
BADKEY_LOG="$WORK_DIR/badkey_server.log"

log "Booting a throwaway instance with a malformed VAULT_ENCRYPTION_KEY (expected to refuse)..."
DATABASE_URL="sqlite://$BADKEY_DB?mode=rwc" RUST_LOG=info \
    VAULT_ENCRYPTION_KEY="not-a-64-hex-character-key" \
    PORT="$BADKEY_PORT" \
    "$PROJECT_ROOT/target/debug/simply_ip_vault" >"$BADKEY_LOG" 2>&1 &
BADKEY_PID=$!

# It must exit on its own, and quickly — the cipher is built before the listener binds.
BADKEY_EXITED=0
for _ in $(seq 1 40); do
    if ! kill -0 "$BADKEY_PID" 2>/dev/null; then BADKEY_EXITED=1; break; fi
    sleep 0.25
done
if [ "$BADKEY_EXITED" != "1" ]; then
    kill "$BADKEY_PID" 2>/dev/null || true
fi
wait "$BADKEY_PID" 2>/dev/null || true

check_local "$BADKEY_EXITED" "1" "#26 a malformed VAULT_ENCRYPTION_KEY aborts startup instead of degrading"
if grep -qi "InvalidKey\|hex characters" "$BADKEY_LOG" 2>/dev/null; then
    check_local "named" "named" "#26 the startup failure names the key as the reason"
else
    check_local "$(head -c 200 "$BADKEY_LOG" 2>/dev/null)" "named" "#26 the startup failure names the key as the reason"
fi
check_local "$([ -s "$BADKEY_DB" ] && echo created || echo absent)" "absent" \
    "#26 no database is provisioned when the cipher is refused"

# --- Negative DNS caching survives a dead hostname --------------------------------------------
#
# An unresolvable TRUSTED_PROXIES entry disables that entry only — never the service — and is
# retried on a short negative TTL rather than re-queried per request. The live instance is already
# proof of the first half in the healthy direction; this asserts the failing one.

DEADNS_PORT=$((VAULT_PORT + 62))
DEADNS_DB="$WORK_DIR/deadns.db"
DEADNS_LOG="$WORK_DIR/deadns_server.log"
DEADNS_MASTER="deadbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"

log "Booting an instance whose TRUSTED_PROXIES names an unresolvable host alongside a good one..."
DATABASE_URL="sqlite://$DEADNS_DB?mode=rwc" RUST_LOG=info INITIAL_MASTER_KEY="$DEADNS_MASTER" \
    INITIAL_MASTER_SIGNING_SECRET="$MASTER_SIGNING_SECRET" \
    TRUSTED_PROXIES="this-host-does-not-exist.invalid,127.0.0.1" \
    PORT="$DEADNS_PORT" \
    "$PROJECT_ROOT/target/debug/simply_ip_vault" >"$DEADNS_LOG" 2>&1 &
DEADNS_PID=$!

DEADNS_READY=0
for _ in $(seq 1 60); do
    if ! kill -0 "$DEADNS_PID" 2>/dev/null; then break; fi
    SC=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$DEADNS_PORT/api/ips" 2>/dev/null)
    case "$SC" in 200|401|403|404) DEADNS_READY=1; break ;; esac
    sleep 0.5
done

check_local "$DEADNS_READY" "1" "#26 an unresolvable TRUSTED_PROXIES entry does not stop the service"

if [ "$DEADNS_READY" == "1" ]; then
    # The good entry still works: 127.0.0.1 is trusted, so its forwarding header is honoured.
    next_timestamp "DEADNS|auth"
    DEADNS_TS="$SIGNED_TS"
    DEADNS_SIG=$(hmac_sign "$MASTER_SIGNING_SECRET" "GET" "/api/auth/me" "$DEADNS_TS" "")
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" \
        -H "X-API-Key: $DEADNS_MASTER" -H "X-Timestamp: $DEADNS_TS" \
        -H "X-Signature-256: $DEADNS_SIG" \
        "http://127.0.0.1:$DEADNS_PORT/api/auth/me")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "200" "#26 the surviving TRUSTED_PROXIES entries keep working"

    if grep -q "did not resolve at startup" "$DEADNS_LOG" 2>/dev/null; then
        check_local "logged" "logged" "#26 the unresolvable entry is reported by name at startup"
    else
        check_local "missing" "logged" "#26 the unresolvable entry is reported by name at startup"
    fi
fi

kill "$DEADNS_PID" 2>/dev/null || true
wait "$DEADNS_PID" 2>/dev/null || true

# --- ...but a malformed TRUSTED_PROXIES entry aborts startup ----------------------------------
#
# The exact counterpart of the block above, and the reason the two sit together: an *unresolvable*
# name is transient and must not stop the service, while a *syntactically impossible* one can never
# become valid and must. Dropping it silently would leave the set of peers allowed to rewrite the
# client address different from the set the operator wrote down — and the symptom is a 403 on a
# CIDR-bound key, hours later, with one warn line as the only evidence.
#
# `10.0.0.0/99` is the archetype: one character from a valid CIDR, impossible as a DNS name.

BADPROXY_PORT=$((VAULT_PORT + 63))
BADPROXY_DB="$WORK_DIR/badproxy.db"
BADPROXY_LOG="$WORK_DIR/badproxy_server.log"

log "Booting a throwaway instance with a malformed TRUSTED_PROXIES entry (expected to refuse)..."
DATABASE_URL="sqlite://$BADPROXY_DB?mode=rwc" RUST_LOG=info \
    TRUSTED_PROXIES="127.0.0.1,10.0.0.0/99,proxy." \
    PORT="$BADPROXY_PORT" \
    "$PROJECT_ROOT/target/debug/simply_ip_vault" >"$BADPROXY_LOG" 2>&1 &
BADPROXY_PID=$!

BADPROXY_EXITED=0
for _ in $(seq 1 40); do
    if ! kill -0 "$BADPROXY_PID" 2>/dev/null; then BADPROXY_EXITED=1; break; fi
    sleep 0.25
done
if [ "$BADPROXY_EXITED" != "1" ]; then
    kill "$BADPROXY_PID" 2>/dev/null || true
fi
wait "$BADPROXY_PID" 2>/dev/null || true

check_local "$BADPROXY_EXITED" "1" "#26 a malformed TRUSTED_PROXIES entry aborts startup"
if grep -q "FATAL: TRUSTED_PROXIES entry '10.0.0.0/99'" "$BADPROXY_LOG" 2>/dev/null; then
    check_local "named" "named" "#26 the refusal names the offending entry"
else
    check_local "$(head -c 300 "$BADPROXY_LOG" 2>/dev/null)" "named" "#26 the refusal names the offending entry"
fi
# Both bad entries, not just the first: one restart has to surface every typo in the list.
if grep -q "FATAL: TRUSTED_PROXIES entry 'proxy.'" "$BADPROXY_LOG" 2>/dev/null; then
    check_local "both" "both" "#26 every malformed entry is reported, not just the first"
else
    check_local "first-only" "both" "#26 every malformed entry is reported, not just the first"
fi
# The abort must precede everything else — no database, no listener, no DNS.
check_local "$([ -s "$BADPROXY_DB" ] && echo created || echo absent)" "absent" \
    "#26 no database is provisioned when the trust boundary is ambiguous"


# ─────────────────────────────────────────────────────────────
log_section "27. Hardening — Monotonic Replay Guard, RBAC Revocation & Strict Decryption"
# ─────────────────────────────────────────────────────────────
#
# The four changes from the 2026-08-02 cross-audit follow-up, each asserted against the live server.

# --- 27a. The replay guard keys on the decoded digest, not on header text ---------------------
#
# `ReplayGuard` now stores the raw bytes `verify_signature` decoded, rather than a token re-derived
# from the header. That closes a spelling bypass: `sha256=AB…` and `ab…` are the *same* signature,
# and a guard keyed on the header string could be made to record them as two distinct single uses.

next_timestamp "SPELL|convergence"
SPELL_TS="$SIGNED_TS"
SPELL_BODY='{"target_address":"198.51.100.243","group_name":"convergence-group","cause":"digest keying"}'
SPELL_SIG=$(hmac_sign "$MASTER_SIGNING_SECRET" "POST" "/api/ban" "$SPELL_TS" "$SPELL_BODY")

raw_call POST "/api/ban" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $SPELL_TS" \
    -H "X-Signature-256: $SPELL_SIG" -H "Content-Type: application/json" -d "$SPELL_BODY"
check "200" "#27 the genuine signed request succeeds"

# The identical signature with its **digest** uppercased. Hex decoding is case-insensitive, so this
# is byte-for-byte the same digest — and must be refused as the replay it is.
#
# The `sha256=` tag is left alone deliberately. It is a fixed literal matched case-sensitively (as on
# the peer service), so uppercasing it too would be refused for its format before the replay guard
# ever ran, and this check would pass while proving nothing about digest keying.
SPELL_SIG_UPPER="sha256=$(printf '%s' "${SPELL_SIG#sha256=}" | tr '[:lower:]' '[:upper:]')"
raw_call POST "/api/ban" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $SPELL_TS" \
    -H "X-Signature-256: $SPELL_SIG_UPPER" -H "Content-Type: application/json" -d "$SPELL_BODY"
check "401" "#27 an uppercased respelling of a used signature is still a replay"
check_true '.error | test("already been used")' \
    "#27 the respelled replay is named as a replay, not as a bad signature"

# ...and with the optional `sha256=` prefix bolted on, which the server strips before decoding.
raw_call POST "/api/ban" -H "X-API-Key: $MASTER_KEY" -H "X-Timestamp: $SPELL_TS" \
    -H "X-Signature-256: sha256=$SPELL_SIG" -H "Content-Type: application/json" -d "$SPELL_BODY"
check "401" "#27 a sha256=-prefixed respelling is still the same digest and still a replay"

# --- 27b. Replay tracking is per key, and saturation never flushes it -------------------------
#
# Entries are keyed on (key_id, digest). One key's traffic must never consume another's entry —
# previously the ceiling was handled with a global `seen.clear()`, so any key's burst would have
# disabled the guard for every other key at once.

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Replay Isolation A","can_create_groups":true}'
check "200" "#27 create the first replay-isolation key"
RPL_A_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
RPL_A_SECRET=$(echo "$RESP_BODY" | jq -r '.signing_secret')
register_key_secret "$RPL_A_KEY" "$RPL_A_SECRET"

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Replay Isolation B","can_create_groups":true}'
check "200" "#27 create the second replay-isolation key"
RPL_B_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
RPL_B_SECRET=$(echo "$RESP_BODY" | jq -r '.signing_secret')
register_key_secret "$RPL_B_KEY" "$RPL_B_SECRET"

# Both keys issue the same request at the same timestamp. Different secrets mean different digests,
# so neither may be mistaken for the other's replay.
next_timestamp "RPLISO|shared"
RPL_TS="$SIGNED_TS"
RPL_PATH="/api/auth/me"
RPL_A_SIG=$(hmac_sign "$RPL_A_SECRET" "GET" "$RPL_PATH" "$RPL_TS" "")
RPL_B_SIG=$(hmac_sign "$RPL_B_SECRET" "GET" "$RPL_PATH" "$RPL_TS" "")

raw_call GET "$RPL_PATH" -H "X-API-Key: $RPL_A_KEY" -H "X-Timestamp: $RPL_TS" -H "X-Signature-256: $RPL_A_SIG"
check "200" "#27 key A's first use is accepted"
raw_call GET "$RPL_PATH" -H "X-API-Key: $RPL_B_KEY" -H "X-Timestamp: $RPL_TS" -H "X-Signature-256: $RPL_B_SIG"
check "200" "#27 key B is unaffected by key A's recorded signature"
raw_call GET "$RPL_PATH" -H "X-API-Key: $RPL_A_KEY" -H "X-Timestamp: $RPL_TS" -H "X-Signature-256: $RPL_A_SIG"
check "401" "#27 key A's own replay is still refused after key B's traffic"
raw_call GET "$RPL_PATH" -H "X-API-Key: $RPL_B_KEY" -H "X-Timestamp: $RPL_TS" -H "X-Signature-256: $RPL_B_SIG"
check "401" "#27 key B's own replay is refused too"

# --- 27c. Revocation is bounded by the group, not by the verb ---------------------------------
#
# Managing a group is the whole authority test for removing permissions on it: a caller that manages
# the group may remove any verb from any key's row, including its own, without holding the verbs it
# removes. Matches `simply_hook_executor`, where `can_manage` over a hook confers exactly this.
#
# The bound that remains is *which groups* the caller can reach, and it is the one that matters:
# removing authority raises nobody, but revoking the key that maintains another tenant's banlist
# stops that tenant's blocking, and presents as "bans stopped landing" rather than as a permission
# error. That is an integrity concern, answered by the entry gate below.

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Tenant A Manager","can_manage_keys":true}'
check "200" "#27 create a delegated key manager"
REVK_MGR_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
REVK_MGR_ID=$(echo "$RESP_BODY" | jq -r '.id')
register_key_secret "$REVK_MGR_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Tenant B Worker"}'
check "200" "#27 create another tenant's worker key"
REVK_VICTIM_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Tenant A Worker"}'
check "200" "#27 create a worker inside the manager's own tenant"
REVK_PEER_ID=$(echo "$RESP_BODY" | jq -r '.id')
# Its own credentials are needed further down, to prove a master's re-grant genuinely restores access
# rather than merely returning 200.
REVK_PEER_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
register_key_secret "$REVK_PEER_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

# `can_manage` is R2's resource half. With the manager's global `can_manage_keys` it is what admits
# it to this group's permission rows at all; the tenant-mate below deliberately does NOT get it, so
# the refusals further down are about which group is reachable, not about standing in general.
api_call POST "/api/keys/$REVK_MGR_ID/permissions" "$MASTER_KEY" \
    '{"group_name":"revguard-tenant-a","can_read":true,"can_write":true,"can_delete":true,"can_manage":true}'
check "200" "#27 grant the manager full rights on its own group"
api_call POST "/api/keys/$REVK_PEER_ID/permissions" "$MASTER_KEY" \
    '{"group_name":"revguard-tenant-a","can_read":true,"can_write":true,"can_delete":true}'
check "200" "#27 grant its tenant-mate the same group"
api_call POST "/api/keys/$REVK_VICTIM_ID/permissions" "$MASTER_KEY" \
    '{"group_name":"revguard-tenant-b","can_read":true,"can_write":true,"can_delete":true}'
check "200" "#27 grant the other tenant's worker its own group"

# The attack: strip a group the manager has no relationship with.
api_call DELETE "/api/keys/$REVK_VICTIM_ID/permissions/revguard-tenant-b" "$REVK_MGR_KEY"
check "403" "#27 a key manager cannot revoke access to a group it does not manage"

# The grant genuinely survived — the 403 refused the write rather than merely reporting one.
api_call GET "/api/keys" "$MASTER_KEY"
check "200" "#27 re-read the key list after the refused revocation"

# ...while revoking inside a group it *does* manage works, so the guard bounds delegated key
# management rather than disabling it.
api_call DELETE "/api/keys/$REVK_PEER_ID/permissions/revguard-tenant-a" "$REVK_MGR_KEY"
check "204" "#27 revoking within a managed group still succeeds"

# A master is unaffected by the guard.
api_call DELETE "/api/keys/$REVK_VICTIM_ID/permissions/revguard-tenant-b" "$MASTER_KEY"
check "204" "#27 a master key can still revoke anything"

# Self-revocation is permitted: a manager may surrender its own access to a group it manages. The
# block this replaces stopped only the least-privilege action, since the widening direction is
# refused by the per-verb grant check regardless of who the target is.
# `can_manage` is re-submitted rather than omitted: omitting it would also be a valid reduction
# (surrendering the administrative role in the same call), but it would strip the authority the next
# assertion needs. Reducing one verb while keeping the role is the interesting case.
api_call POST "/api/keys/$REVK_MGR_ID/permissions" "$REVK_MGR_KEY" \
    '{"group_name":"revguard-tenant-a","can_read":true,"can_write":true,"can_delete":false,"can_manage":true}'
check "200" "#27 a manager may reduce its own row on a group it manages"

api_call DELETE "/api/keys/$REVK_MGR_ID/permissions/revguard-tenant-a" "$REVK_MGR_KEY"
check "204" "#27 a manager may revoke its own group access"

# ...and having surrendered it, the manager is outside the entry gate like anyone else. This is what
# keeps self-revocation a one-way door rather than a way to re-enter on your own authority.
api_call POST "/api/keys/$REVK_PEER_ID/permissions" "$REVK_MGR_KEY" \
    '{"group_name":"revguard-tenant-a","can_read":true,"can_write":false,"can_delete":false}'
check "403" "#27 a manager cannot re-grant itself into a group it surrendered"

# --- 27c-bis. An ungoverned group stays visible and recoverable by a master --------------------
#
# `revguard-tenant-a` now has no permission rows at all: the peer's was revoked and the manager
# surrendered its own. That state is only reachable because self-revocation is allowed, and it is
# the counterpart safeguard — a master's view must never be assembled from a table the master has no
# rows in, or the group would vanish at exactly this moment and be recoverable only by hand.

api_call GET "/api/groups" "$MASTER_KEY"
check "200" "#27 a master can still list groups after the last manager left"
check_true '[.[] | select(.name == "revguard-tenant-a")] | length == 1' \
    "#27 the ungoverned group is still listed for a master"

api_call GET "/api/ips?group_name=revguard-tenant-a" "$MASTER_KEY"
check "200" "#27 a master can still view an ungoverned group's records"

api_call POST "/api/keys/$REVK_PEER_ID/permissions" "$MASTER_KEY" \
    '{"group_name":"revguard-tenant-a","can_read":true,"can_write":true,"can_delete":true}'
check "200" "#27 a master can put an ungoverned group back under management"

api_call GET "/api/ips?group_name=revguard-tenant-a" "$REVK_PEER_KEY"
check "200" "#27 the restored manager can reach the group again"

# --- 27c-ter. R2: neither half of the conjunction is sufficient alone -------------------------
#
# RBAC_MODEL.md R2 requires BOTH global can_manage_keys AND can_manage = true on the specific
# resource, and says plainly that neither alone is sufficient. Both halves used to be sufficient on
# their own for at least one direction: can_manage_keys + any row was the grant path, and can_manage
# alone was the revoke path. Each is asserted here in isolation, then together as the control.

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"conjunction-group"}'
check "200" "#27 create a group for the R2 conjunction checks"

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Global Half","can_manage_keys":true}'
check "200" "#27 create a caller holding only the global half"
CONJ_GLOBAL_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
CONJ_GLOBAL_ID=$(echo "$RESP_BODY" | jq -r '.id')
register_key_secret "$CONJ_GLOBAL_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Scoped Half"}'
check "200" "#27 create a caller holding only the resource half"
CONJ_SCOPED_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
CONJ_SCOPED_ID=$(echo "$RESP_BODY" | jq -r '.id')
register_key_secret "$CONJ_SCOPED_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Conjunction Victim"}'
check "200" "#27 create a target for the conjunction checks"
CONJ_VICTIM_ID=$(echo "$RESP_BODY" | jq -r '.id')

# A row on the group, but WITHOUT can_manage.
api_call POST "/api/keys/$CONJ_GLOBAL_ID/permissions" "$MASTER_KEY" \
    '{"group_name":"conjunction-group","can_read":true,"can_write":true,"can_delete":true}'
check "200" "#27 give the global-half caller ordinary access to the group"

# can_manage on the group, but NO global scope.
api_call POST "/api/keys/$CONJ_SCOPED_ID/permissions" "$MASTER_KEY" \
    '{"group_name":"conjunction-group","can_read":true,"can_write":true,"can_delete":true,"can_manage":true}'
check "200" "#27 give the scoped-half caller can_manage on the group"

api_call POST "/api/keys/$CONJ_VICTIM_ID/permissions" "$MASTER_KEY" \
    '{"group_name":"conjunction-group","can_read":true,"can_write":false,"can_delete":false}'
check "200" "#27 give the victim a row to be attacked"

api_call POST "/api/keys/$CONJ_VICTIM_ID/permissions" "$CONJ_GLOBAL_KEY" \
    '{"group_name":"conjunction-group","can_read":true,"can_write":true,"can_delete":false}'
check "403" "#27 can_manage_keys plus a row, without can_manage, cannot grant"

api_call DELETE "/api/keys/$CONJ_VICTIM_ID/permissions/conjunction-group" "$CONJ_GLOBAL_KEY"
check "403" "#27 ...nor revoke"

api_call POST "/api/keys/$CONJ_VICTIM_ID/permissions" "$CONJ_SCOPED_KEY" \
    '{"group_name":"conjunction-group","can_read":true,"can_write":true,"can_delete":false}'
check "403" "#27 can_manage without can_manage_keys cannot grant"

api_call DELETE "/api/keys/$CONJ_VICTIM_ID/permissions/conjunction-group" "$CONJ_SCOPED_KEY"
check "403" "#27 ...nor revoke"

# The victim's row survived every refusal, so those 403s blocked writes rather than reporting them.
api_call GET "/api/keys" "$MASTER_KEY"
check_true "[.[] | select(.id == \"$CONJ_VICTIM_ID\") | .group_permissions[] | select(.group_name == \"conjunction-group\")] | length == 1" \
    "#27 the victim's row survived every refused attempt"

# Control: give the scoped caller the missing global half, and the identical calls succeed.
api_call PUT "/api/keys/$CONJ_SCOPED_ID" "$MASTER_KEY" '{"can_manage_keys":true}'
check "200" "#27 a master adds the missing half"

api_call POST "/api/keys/$CONJ_VICTIM_ID/permissions" "$CONJ_SCOPED_KEY" \
    '{"group_name":"conjunction-group","can_read":true,"can_write":true,"can_delete":false}'
check "200" "#27 both halves together grant"

api_call DELETE "/api/keys/$CONJ_VICTIM_ID/permissions/conjunction-group" "$CONJ_SCOPED_KEY"
check "204" "#27 both halves together revoke"

# --- 27c-quater. §3 lifecycle authority: Master and owner, and nobody else -------------------
#
# RBAC_MODEL.md §3: "Resource lifecycle actions — deleting or renaming the entity itself — are
# restricted exclusively to Master and the designated owner_key_id. Holding manage rights or any
# operational verb confers no lifecycle authority: a parent that merely uses a resource must not be
# able to delete it."

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Group Owner","can_create_groups":true}'
check "200" "#3 create a key that will own a group"
OWNER_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
OWNER_ID=$(echo "$RESP_BODY" | jq -r '.id')
register_key_secret "$OWNER_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

api_call POST "/api/groups" "$OWNER_KEY" '{"name":"owned-lifecycle-group"}'
check "200" "#3 the owner creates its group"
OWNED_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

# The most privileged non-owner the model allows: can_manage_keys globally, and every verb including
# can_manage on the group itself.
api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Privileged Non-Owner","can_manage_keys":true}'
check "200" "#3 create a fully-privileged non-owner"
NONOWNER_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
NONOWNER_ID=$(echo "$RESP_BODY" | jq -r '.id')
register_key_secret "$NONOWNER_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

api_call POST "/api/keys/$NONOWNER_ID/permissions" "$MASTER_KEY" \
    "{\"group_id\":\"$OWNED_GROUP_ID\",\"can_read\":true,\"can_write\":true,\"can_delete\":true,\"can_manage\":true}"
check "200" "#3 give the non-owner every verb the model has, can_manage included"

api_call DELETE "/api/groups/$OWNED_GROUP_ID" "$NONOWNER_KEY"
check "403" "#3 every verb on a group confers no authority over the group itself"

api_call GET "/api/groups" "$MASTER_KEY"
check_true '[.[] | select(.name == "owned-lifecycle-group")] | length == 1' \
    "#3 the refusal blocked the delete rather than reporting one"

# Ownership reassignment is master-only, and not delegable to the current owner.
api_call PUT "/api/groups/$OWNED_GROUP_ID/owner" "$OWNER_KEY" "{\"owner_key_id\":\"$NONOWNER_ID\"}"
check "403" "#3 the owner may not hand ownership on; only a master reassigns"

api_call PUT "/api/groups/$OWNED_GROUP_ID/owner" "$MASTER_KEY" "{\"owner_key_id\":\"$NONOWNER_ID\"}"
check "200" "#3 a master reassigns ownership"

api_call DELETE "/api/groups/$OWNED_GROUP_ID" "$OWNER_KEY"
check "403" "#3 the previous owner lost lifecycle authority with the reassignment"

api_call DELETE "/api/groups/$OWNED_GROUP_ID" "$NONOWNER_KEY"
check "204" "#3 and the new owner gained it"

# A dangling or master owner_key_id is refused rather than written — the check standing in for the
# foreign key SQLite will not let this schema declare.
api_call POST "/api/groups" "$MASTER_KEY" '{"name":"owner-validation-group"}'
check "200" "#3 create a group for the owner-validation checks"
OWNERVAL_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call PUT "/api/groups/$OWNERVAL_GROUP_ID/owner" "$MASTER_KEY" '{"owner_key_id":"00000000-0000-0000-0000-000000000000"}'
check "400" "#3 a nonexistent key cannot be recorded as an owner"

api_call PUT "/api/groups/$OWNERVAL_GROUP_ID/owner" "$MASTER_KEY" "{\"owner_key_id\":\"$MASTER_ID\"}"
check "400" "#3 nor can the master — null already means master-only"

api_call PUT "/api/groups/$OWNERVAL_GROUP_ID/owner" "$MASTER_KEY" '{"owner_key_id":null}'
check "200" "#3 clearing ownership returns the group to master-only"

api_call DELETE "/api/groups/$OWNERVAL_GROUP_ID" "$MASTER_KEY"
check "204" "#3 clean up the validation group"

# --- 27c-quinquies. §6 cascade deletion & pre-flight inventory --------------------------------
#
# RBAC_MODEL.md §6: deleting a key cascades recursively through its daughter subtree, but only after a
# pre-flight inventory of every resource owned by ANY key in that subtree — and the deletion is
# refused until each one carries an explicit resolution. "Data is never destroyed implicitly."

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Cascade Root","can_manage_keys":true,"can_create_groups":true,"can_manage_webhooks":true}'
check "200" "#6 create the root of a subtree to delete"
CASC_ROOT_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
CASC_ROOT_ID=$(echo "$RESP_BODY" | jq -r '.id')
register_key_secret "$CASC_ROOT_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

api_call POST "/api/keys" "$CASC_ROOT_KEY" '{"name":"Cascade Daughter"}'
check "200" "#6 the root mints a daughter"
CASC_CHILD_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
CASC_CHILD_ID=$(echo "$RESP_BODY" | jq -r '.id')
register_key_secret "$CASC_CHILD_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

# The daughter owns a group, so the inventory has to walk past the key actually being deleted.
api_call PUT "/api/keys/$CASC_CHILD_ID" "$MASTER_KEY" '{"can_create_groups":true}'
check "200" "#6 let the daughter create a group"
api_call POST "/api/groups" "$CASC_CHILD_KEY" '{"name":"cascade-owned-group"}'
check "200" "#6 the daughter creates a group it owns"
CASC_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

# An IP inside it, to prove the cascade never destroys resource data.
api_call POST "/api/ban" "$CASC_CHILD_KEY" '{"target_address":"203.0.113.211","group_name":"cascade-owned-group","cause":"pre-cascade"}'
check "200" "#6 put a record in the owned group"

# Deleting the root refuses, and hands back the inventory.
api_call DELETE "/api/keys/$CASC_ROOT_ID" "$MASTER_KEY"
check "409" "#6 an unresolved inventory refuses the deletion"
check_true '.owned_entities | length == 1' "#6 the payload enumerates the owned entity"
check_true '.owned_entities[0].entity_type == "group"' "#6 ...with its type"
check_true '.owned_entities[0].name == "cascade-owned-group"' "#6 ...its name"
check_true ".owned_entities[0].owner_key_id == \"$CASC_CHILD_ID\"" \
    "#6 ...and the owner, which is the DAUGHTER, not the key being deleted"
check_true '.subtree_key_count == 2' "#6 the subtree count covers root plus daughter"

# Nothing was touched.
api_call GET "/api/auth/me" "$CASC_CHILD_KEY"
check "200" "#6 the refusal deleted no key"

# A partial map — here, an empty one carried alongside a valid JSON body — is refused too.
api_call DELETE "/api/keys/$CASC_ROOT_ID" "$MASTER_KEY" '{"resolutions":[]}'
check "409" "#6 an empty resolutions array is still an unresolved inventory"

# A resolution naming something outside the inventory is refused.
api_call DELETE "/api/keys/$CASC_ROOT_ID" "$MASTER_KEY" \
    '{"resolutions":[{"entity_type":"group","id":"00000000-0000-0000-0000-000000000000","action":"delete"}]}'
check "409" "#6 a map that resolves the wrong entity leaves the real one unresolved"

# Reassigning into the doomed subtree is a deferred orphaning, not a rescue.
api_call DELETE "/api/keys/$CASC_ROOT_ID" "$MASTER_KEY" \
    "{\"resolutions\":[{\"entity_type\":\"group\",\"id\":\"$CASC_GROUP_ID\",\"action\":\"reassign\",\"owner_key_id\":\"$CASC_CHILD_ID\"}]}"
check "400" "#6 cannot reassign to a key inside the subtree being deleted"

# A complete map executes: the group is reassigned to a survivor, and the whole subtree cascades.
api_call POST "/api/keys" "$MASTER_KEY" '{"name":"Cascade Survivor"}'
check "200" "#6 create a survivor to receive the group"
CASC_SURVIVOR_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call DELETE "/api/keys/$CASC_ROOT_ID" "$MASTER_KEY" \
    "{\"resolutions\":[{\"entity_type\":\"group\",\"id\":\"$CASC_GROUP_ID\",\"action\":\"reassign\",\"owner_key_id\":\"$CASC_SURVIVOR_ID\"}]}"
check "204" "#6 a complete resolution map executes the cascade"

# Both generations are gone...
api_call GET "/api/auth/me" "$CASC_ROOT_KEY"
check "401" "#6 the root key no longer authenticates"
api_call GET "/api/auth/me" "$CASC_CHILD_KEY"
check "401" "#6 the daughter cascaded with it"

# ...while the group and its contents survived, under the new owner.
api_call GET "/api/groups" "$MASTER_KEY"
check_true '[.[] | select(.name == "cascade-owned-group")] | length == 1' \
    "#6 the reassigned group survived the cascade"
check_true "[.[] | select(.name == \"cascade-owned-group\") | select(.owner_key_id == \"$CASC_SURVIVOR_ID\")] | length == 1" \
    "#6 ...with the new owner"

api_call GET "/api/ips?group_name=cascade-owned-group" "$MASTER_KEY"
check "200" "#6 read the reassigned group's records"
check_true '[.[] | select(.target_address == "203.0.113.211")] | length == 1' \
    "#6 resource data is never destroyed implicitly (§6)"

# --- 27d. A wrong-but-well-formed encryption key refuses startup, not just a request -----------
#
# `SecretCipher::open` refuses any value without a recognized storage prefix, and any sealed value
# it cannot authenticate. §26 above covers a *malformed* key (wrong length/hex); this covers a key
# that is syntactically fine but is not the one the data at rest was actually sealed under — the
# shape a botched key rotation or a restored-from-the-wrong-vault deployment actually produces.
#
# `verify_encryption_key`'s boot-time canary (`src/main.rs`) opens one stored `signing_secret`
# before the listener binds specifically so this case is caught here rather than on the first
# authenticated request. Before the canary existed, this instance would start cleanly, report ready,
# and only fail — as a `500` — the moment a real client tried to authenticate; every credential in
# the database would silently stop working the instant it did. Asserted the same way §26 asserts a
# malformed key: the process must exit on its own before ever binding a listener.

STRICT_PORT=$((VAULT_PORT + 63))
STRICT_DB="$WORK_DIR/strict.db"
STRICT_LOG_A="$WORK_DIR/strict_server_a.log"
STRICT_LOG_B="$WORK_DIR/strict_server_b.log"
STRICT_MASTER="5717c7cccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
STRICT_KEY_1="00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
STRICT_KEY_2="ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"

log "Booting an instance that seals its signing secrets under one encryption key..."
DATABASE_URL="sqlite://$STRICT_DB?mode=rwc" RUST_LOG=info INITIAL_MASTER_KEY="$STRICT_MASTER" \
    INITIAL_MASTER_SIGNING_SECRET="$MASTER_SIGNING_SECRET" \
    VAULT_ENCRYPTION_KEY="$STRICT_KEY_1" PORT="$STRICT_PORT" \
    "$PROJECT_ROOT/target/debug/simply_ip_vault" >"$STRICT_LOG_A" 2>&1 &
STRICT_PID=$!

STRICT_READY=0
for _ in $(seq 1 60); do
    if ! kill -0 "$STRICT_PID" 2>/dev/null; then break; fi
    SC=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$STRICT_PORT/api/ips" 2>/dev/null)
    case "$SC" in 200|401|403|404) STRICT_READY=1; break ;; esac
    sleep 0.5
done
check_local "$STRICT_READY" "1" "#27 the sealing instance starts"

if [ "$STRICT_READY" == "1" ]; then
    next_timestamp "STRICT|A"
    STRICT_TS="$SIGNED_TS"
    STRICT_SIG=$(hmac_sign "$MASTER_SIGNING_SECRET" "GET" "/api/auth/me" "$STRICT_TS" "")
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" \
        -H "X-API-Key: $STRICT_MASTER" -H "X-Timestamp: $STRICT_TS" -H "X-Signature-256: $STRICT_SIG" \
        "http://127.0.0.1:$STRICT_PORT/api/auth/me")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "200" "#27 a sealed signing secret authenticates under the key that wrote it"

    # The raw secret must not be a substring of the database file — that is what sealing buys.
    if grep -aq "$MASTER_SIGNING_SECRET" "$STRICT_DB" 2>/dev/null; then
        check_local "present" "absent" "#27 the sealed secret is not readable in the database file"
    else
        check_local "absent" "absent" "#27 the sealed secret is not readable in the database file"
    fi
fi

kill "$STRICT_PID" 2>/dev/null || true
wait "$STRICT_PID" 2>/dev/null || true

log "Re-opening the same database under a different VAULT_ENCRYPTION_KEY (expected to refuse to start)..."
DATABASE_URL="sqlite://$STRICT_DB?mode=rwc" RUST_LOG=info \
    VAULT_ENCRYPTION_KEY="$STRICT_KEY_2" PORT="$STRICT_PORT" \
    "$PROJECT_ROOT/target/debug/simply_ip_vault" >"$STRICT_LOG_B" 2>&1 &
STRICT_PID_B=$!

# It must exit on its own, and before ever answering a request — the canary runs after migrations
# and before `TcpListener::bind`, so a caller can never race it. Same wait shape as §26's malformed
# -key check: watch the PID, not the port.
STRICT_EXITED_B=0
for _ in $(seq 1 40); do
    if ! kill -0 "$STRICT_PID_B" 2>/dev/null; then STRICT_EXITED_B=1; break; fi
    sleep 0.25
done
if [ "$STRICT_EXITED_B" != "1" ]; then
    kill "$STRICT_PID_B" 2>/dev/null || true
fi
wait "$STRICT_PID_B" 2>/dev/null || true

check_local "$STRICT_EXITED_B" "1" \
    "#27 a wrong-but-well-formed encryption key aborts startup instead of starting and failing later"
if grep -qi "could not be decrypted" "$STRICT_LOG_B" 2>/dev/null; then
    check_local "named" "named" "#27 the startup refusal names the key mismatch as the reason"
else
    check_local "$(head -c 200 "$STRICT_LOG_B" 2>/dev/null)" "named" \
        "#27 the startup refusal names the key mismatch as the reason"
fi

# --- 27e. WAL is written to the file header and survives reconnection --------------------------
#
# The startup-log check in §24b proves the pragma was issued. This proves it took effect *and* is
# persistent, which is what makes applying it once at boot sufficient for every connection the pool
# opens afterwards. Read straight from the file: SQLite records the write format version at byte
# offset 18, where `2` means WAL and `1` means the rollback journal.

journal_format_byte() {
    dd if="$1" bs=1 skip=18 count=1 2>/dev/null | od -An -tu1 | tr -d ' \n'
}

check_local "$([ -f "${DB_PATH}-wal" ] && echo present || echo absent)" "present" \
    "#27 the live database has a -wal sidecar, so WAL is genuinely engaged"
check_local "$(journal_format_byte "$DB_PATH")" "2" \
    "#27 the database file header records WAL as the write format"

# The throwaway instance from 27d was started, stopped, restarted and stopped again — all without
# anything re-applying the pragma on the second boot. Its header must still say WAL.
check_local "$(journal_format_byte "$STRICT_DB")" "2" \
    "#27 WAL persists in the file header across a full restart of the service"


log_section "28. Liveness & readiness probes (unauthenticated)"

# The only two endpoints that answer without a credential, checked here against the *real binary*
# rather than a `oneshot` router. That distinction matters more than it usually would: the Rust tests
# drive the router directly, so they cannot see a mistake in how the layers are composed at startup —
# and "is this route inside or outside `auth_middleware`?" is exactly a composition question. A curl
# with no headers at all is the same call Docker's HEALTHCHECK makes.

RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" "$BASE_URL/health")
RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
check "200" "#28 GET /health answers with no credential at all"
check_local "$(echo "$RESP_BODY" | jq -r '.status // "missing"')" "ok" \
    "#28 /health reports status=ok"
check_local "$(echo "$RESP_BODY" | jq -r '.service // "missing"')" "simply_ip_vault" \
    "#28 /health names the service"
# Asserted *absent*: a version string tells an anonymous caller which build is deployed, which is
# the first thing worth knowing before looking up what that build is vulnerable to.
check_local "$(echo "$RESP_BODY" | jq -r 'if .version then "present" else "absent" end')" "absent" \
    "#28 /health discloses no build version"
check_local "$(echo "$RESP_BODY" | jq -r 'keys | length')" "2" \
    "#28 the liveness body is exactly two constant fields"

RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" "$BASE_URL/ready")
RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
check "200" "#28 GET /ready answers with no credential at all"
check_local "$(echo "$RESP_BODY" | jq -r '.status // "missing"')" "ready" \
    "#28 /ready reports status=ready once the master is pinned"
check_local "$(echo "$RESP_BODY" | jq -r '.database // "missing"')" "up" \
    "#28 /ready confirms the database answered"

# A forged credential must be *ignored*, not rejected. An endpoint that merely tolerated a missing
# header could still branch on a present one, which would put it back behind authentication for
# exactly the callers most likely to send stale credentials.
for probe_path in /health /ready /healthz /readyz; do
    RESP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" \
        -H "X-API-Key: not-a-real-key" -H "X-Timestamp: 0" -H "X-Signature-256: sha256=deadbeef" \
        "$BASE_URL$probe_path")
    check "200" "#28 $probe_path ignores a forged credential rather than rejecting it"
done

# The Kubernetes-idiomatic aliases must be the *same handler*, not stubs that happen to answer 200.
# Matching the peer's spellings means one set of manifests works against both services.
for probe_path in /healthz /readyz; do
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" "$BASE_URL$probe_path")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "200" "#28 $probe_path answers"
    if [ "$probe_path" == "/healthz" ]; then EXPECT="ok"; else EXPECT="ready"; fi
    check_local "$(echo "$RESP_BODY" | jq -r '.status // "missing"')" "$EXPECT" \
        "#28 $probe_path returns the real handler's body, not a stub"
done

# The complement: the probes are the exception, not a hole in the wall. An unsigned request to any
# other route must still be refused.
RESP_STATUS=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/api/auth/me")
check "401" "#28 every other route still demands a signed request"

# Neither probe may leak operational detail to an anonymous caller.
RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" "$BASE_URL/ready")
RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
if echo "$RESP_BODY" | grep -qiE "sqlite|\.db|/tmp/|password|secret"; then
    check_local "leaked" "clean" "#28 /ready leaks no path, driver, or credential detail"
else
    check_local "clean" "clean" "#28 /ready leaks no path, driver, or credential detail"
fi


log_section "29. A weak INITIAL_MASTER_KEY is refused at startup"

# The master key is the one credential that can administer every other credential. The variable used
# to accept any non-empty string with only a log line objecting — a safeguard that read like one and
# stopped nothing, since nobody reads a startup warning about the value they just set on purpose.
#
# Booted as a throwaway instance on its own port and database, so a refusal here cannot affect the
# main run. Each case asserts the process **exits**, not merely that it logs.
WEAKKEY_PORT=$((VAULT_PORT + 64))
WEAKKEY_DB="$WORK_DIR/weakkey.db"
WEAKKEY_LOG="$WORK_DIR/weakkey_server.log"

for BAD_KEY in "changeme" "e2e_master_secret_key_for_testing_123456789" "$(printf 'a%.0s' $(seq 1 63))" "$(printf 'a%.0s' $(seq 1 63))g"; do
    rm -f "$WEAKKEY_DB"
    DATABASE_URL="sqlite://$WEAKKEY_DB?mode=rwc" RUST_LOG=info \
        INITIAL_MASTER_KEY="$BAD_KEY" \
        PORT="$WEAKKEY_PORT" \
        "$PROJECT_ROOT/target/debug/simply_ip_vault" >"$WEAKKEY_LOG" 2>&1 &
    WEAK_PID=$!
    WEAK_EXITED=0
    for _ in $(seq 1 40); do
        if ! kill -0 "$WEAK_PID" 2>/dev/null; then WEAK_EXITED=1; break; fi
        sleep 0.25
    done
    if [ "$WEAK_EXITED" -ne 1 ]; then kill "$WEAK_PID" 2>/dev/null; wait "$WEAK_PID" 2>/dev/null; fi
    check_local "$WEAK_EXITED" "1" "#29 a ${#BAD_KEY}-char INITIAL_MASTER_KEY aborts startup"
done

# The refusal has to be actionable: an operator reading only this log must know the shape required
# and how to produce one.
if grep -q "64 hexadecimal characters" "$WEAKKEY_LOG" && grep -q "openssl rand -hex 32" "$WEAKKEY_LOG"; then
    check_local "actionable" "actionable" "#29 the refusal states the requirement and the remedy"
else
    check_local "unclear" "actionable" "#29 the refusal states the requirement and the remedy"
fi

# And the control: a well-formed 64-hex key still boots. Without this the section above would pass
# for a binary that refused every key, including valid ones.
rm -f "$WEAKKEY_DB"
GOOD_KEY="abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
DATABASE_URL="sqlite://$WEAKKEY_DB?mode=rwc" RUST_LOG=info \
    INITIAL_MASTER_KEY="$GOOD_KEY" \
    PORT="$WEAKKEY_PORT" \
    "$PROJECT_ROOT/target/debug/simply_ip_vault" >"$WEAKKEY_LOG" 2>&1 &
GOOD_PID=$!
GOOD_READY=0
for _ in $(seq 1 60); do
    if ! kill -0 "$GOOD_PID" 2>/dev/null; then break; fi
    SC=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$WEAKKEY_PORT/health" 2>/dev/null)
    if [ "$SC" == "200" ]; then GOOD_READY=1; break; fi
    sleep 0.5
done
check_local "$GOOD_READY" "1" "#29 a well-formed 64-hex INITIAL_MASTER_KEY still boots"
kill "$GOOD_PID" 2>/dev/null; wait "$GOOD_PID" 2>/dev/null

log_section "29b. Database pool tuning environment variables"

# `DATABASE_MAX_CONNECTIONS`/`DATABASE_MIN_CONNECTIONS` now feed **two** tiers, not one: the
# PostgreSQL/MySQL tier (`config::database_max_connections`, unreachable from this harness — it has
# no live Postgres/MySQL to boot against) and, since the two-phase/tiered SQLite work, the
# file-backed SQLite tier (`config::sqlite_file_max_connections`), which this harness boots against
# on every run. `DATABASE_IDLE_TIMEOUT_SECS`/`DATABASE_ACQUIRE_TIMEOUT_SECS` remain PostgreSQL/MySQL-
# only — the file-backed SQLite tier reuses `config::database_idle_timeout`/`database_acquire_timeout`
# directly rather than having its own, so those two are read but not re-derived here. What this
# section proves on SQLite: the variables are accepted without affecting startup (valid values), and
# a garbled `DATABASE_MAX_CONNECTIONS` fails soft with a warning rather than aborting boot — visibly,
# now, because the file-backed tier actually reads it (matching `numeric_env`'s documented "all fail
# soft" contract — real unit coverage of the parsing/clamping logic itself lives in `src/config.rs`'s
# own test module, which can exercise multiple values in one process; an env-driven `OnceLock`
# cannot).
POOLENV_PORT=$((VAULT_PORT + 65))
POOLENV_DB="$WORK_DIR/poolenv.db"
POOLENV_LOG="$WORK_DIR/poolenv_server.log"

rm -f "$POOLENV_DB"
DATABASE_URL="sqlite://$POOLENV_DB?mode=rwc" RUST_LOG=info \
    INITIAL_MASTER_KEY="$MASTER_KEY" \
    DATABASE_MAX_CONNECTIONS=25 DATABASE_MIN_CONNECTIONS=5 \
    DATABASE_IDLE_TIMEOUT_SECS=120 DATABASE_ACQUIRE_TIMEOUT_SECS=3 \
    PORT="$POOLENV_PORT" \
    "$PROJECT_ROOT/target/debug/simply_ip_vault" >"$POOLENV_LOG" 2>&1 &
POOLENV_PID=$!
POOLENV_READY=0
for _ in $(seq 1 60); do
    if ! kill -0 "$POOLENV_PID" 2>/dev/null; then break; fi
    SC=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$POOLENV_PORT/health" 2>/dev/null)
    if [ "$SC" == "200" ]; then POOLENV_READY=1; break; fi
    sleep 0.5
done
check_local "$POOLENV_READY" "1" "#29b valid DATABASE_* pool settings do not prevent startup on SQLite"
kill "$POOLENV_PID" 2>/dev/null; wait "$POOLENV_PID" 2>/dev/null

rm -f "$POOLENV_DB"
DATABASE_URL="sqlite://$POOLENV_DB?mode=rwc" RUST_LOG=info \
    INITIAL_MASTER_KEY="$MASTER_KEY" \
    DATABASE_MAX_CONNECTIONS="not-a-number" \
    PORT="$POOLENV_PORT" \
    "$PROJECT_ROOT/target/debug/simply_ip_vault" >"$POOLENV_LOG" 2>&1 &
GARBLED_PID=$!
GARBLED_READY=0
for _ in $(seq 1 60); do
    if ! kill -0 "$GARBLED_PID" 2>/dev/null; then break; fi
    SC=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:$POOLENV_PORT/health" 2>/dev/null)
    if [ "$SC" == "200" ]; then GARBLED_READY=1; break; fi
    sleep 0.5
done
check_local "$GARBLED_READY" "1" "#29b a malformed DATABASE_MAX_CONNECTIONS does not abort startup on SQLite"
kill "$GARBLED_PID" 2>/dev/null; wait "$GARBLED_PID" 2>/dev/null

# Tolerated, and now *visibly* so. Before the tiered SQLite pool this was silence: `db::connect`
# called `config::database_max_connections` (where `numeric_env`'s "not a valid number" warning
# fires) only on the non-SQLite branch, and this harness only ever boots against SQLite, so nothing
# ever read the value at all. That is no longer true — this harness's file-backed database now goes
# through `config::sqlite_file_max_connections`, which calls the very same `numeric_env` parser on
# the very same `DATABASE_MAX_CONNECTIONS`, so a garbled value is read, warned about, and clamped to
# a floor of 1 exactly the way the PostgreSQL/MySQL tier always has been. The warning is the proof
# the file-backed tier is genuinely consulting the environment rather than merely accepting the
# ceiling's default. The parse-and-clamp behaviour itself is unit-tested directly in `src/config.rs`,
# which can drive `numeric_env`/`clamp_sqlite_file_max` with several inputs in one process; an
# env-driven `OnceLock` cached once per boot cannot be re-exercised that way from outside.
check_local "$([ -s "$POOLENV_LOG" ] && grep -qi "not a valid number" "$POOLENV_LOG" && echo warned || echo silent)" \
    "warned" "#29b on SQLite the file-backed tier reads the value and warns rather than ignoring it"


log_section "30. Edge cases: intra-batch duplicates and IPv6 canonicalisation"

# Light CLI cover for two properties the Rust suites pin in depth. Worth repeating here because these
# run against the **real binary over HTTP**: canonicalisation happens on a string that has travelled
# through JSON, a URL query and SeaORM's parameter binding, and a mismatch anywhere in that path
# would leave the unit-level assertions true and the deployed behaviour wrong.

api_call POST "/api/groups" "$MASTER_KEY" \
    "{\"name\":\"edge-group\",\"group_type\":\"banlist\"}"
check "200" "#30 create the edge-case group"
EDGE_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

# ── Intra-batch duplicates ──────────────────────────────────────────────────
# Two entries for one address, with conflicting causes. Must be a clean 400 naming the address —
# never a 500 from the UNIQUE constraint, and never a silent last-wins that depends on payload order.
api_call POST "/api/records/batch" "$MASTER_KEY" \
    "{\"group_name\":\"edge-group\",\"records\":[{\"target_address\":\"203.0.113.240\",\"cause\":\"first\"},{\"target_address\":\"203.0.113.240\",\"cause\":\"second\"}]}"
check "400" "#30 an intra-batch duplicate is refused, not surfaced as a database error"
check_true '.error | test("uplicate")' "#30 the refusal says what was wrong"
check_true '.error | test("203.0.113.240")' "#30 and names the offending address"

# Different spellings of one host collide the same way, because the check runs after canonicalisation.
api_call POST "/api/records/batch" "$MASTER_KEY" \
    "{\"group_name\":\"edge-group\",\"records\":[{\"target_address\":\"203.0.113.241\"},{\"target_address\":\"203.0.113.241/32\"}]}"
check "400" "#30 two spellings of one host are a duplicate after canonicalisation"

# The control: the same shape without the duplicate succeeds, so the refusals above were the
# duplicate and not something incidental about batch payloads.
api_call POST "/api/records/batch" "$MASTER_KEY" \
    "{\"group_name\":\"edge-group\",\"records\":[{\"target_address\":\"203.0.113.242\"},{\"target_address\":\"203.0.113.243\"}]}"
check "200" "#30 a batch of distinct addresses is accepted"
check_true '.created == 2' "#30 both records were created"

# ── CIDR host-bit masking over the wire ─────────────────────────────────────
# A subnet submitted with host bits set must be stored as the network address. Checked over HTTP
# because canonicalisation runs on a string that has crossed JSON, a URL query and SeaORM's parameter
# binding — a mismatch anywhere on that path leaves the Rust assertions true and the deployment wrong.
#
# Its own group and a range no other section touches. `target_address` is globally UNIQUE, so a
# record created by an earlier section is the *same row* here — an earlier draft of this block reused
# 203.0.113.0/24, which §16 already bans, and the `.created == 1` assertion failed because the batch
# correctly reported `updated` instead. The isolation is what makes "created" mean what it says.
api_call POST "/api/groups" "$MASTER_KEY" \
    "{\"name\":\"cidr-group\",\"group_type\":\"banlist\"}"
check "200" "#30 create the CIDR-canonicalisation group"
api_call POST "/api/records/batch" "$MASTER_KEY" \
    "{\"group_name\":\"cidr-group\",\"records\":[{\"target_address\":\"93.184.216.50/24\",\"cause\":\"host bits set\"}]}"
check "200" "#30 a CIDR with host bits set is accepted"
check_true '.created == 1' "#30 and stored as a new record"

api_call GET "/api/ips?groups=cidr-group&limit=100" "$MASTER_KEY"
check_true '[.[] | select(.target_address == "93.184.216.0/24")] | length == 1' \
    "#30 the CIDR is stored masked to its network address"
check_true '[.[] | select(.target_address == "93.184.216.50/24")] | length == 0' \
    "#30 and the as-typed form is not stored"

# A different host inside the same /24 must update that one record, not create a second.
api_call POST "/api/records/batch" "$MASTER_KEY" \
    "{\"group_name\":\"cidr-group\",\"records\":[{\"target_address\":\"93.184.216.200/24\",\"cause\":\"different host bits\"}]}"
check "200" "#30 a different host inside the same network is accepted"
check_true '.created == 0 and .updated == 1' \
    "#30 and deduplicates onto the existing network record"

api_call GET "/api/ips?groups=cidr-group&ip=93.184.216.0&limit=100" "$MASTER_KEY"
check_true 'length == 1' "#30 exactly one row exists for the /24, whatever host bits were typed"
check_true '.[0].cause == "different host bits"' "#30 and the second write updated it"

# A single host keeps its exact address — masking applies to networks, not to /32.
api_call POST "/api/records/batch" "$MASTER_KEY" \
    "{\"group_name\":\"cidr-group\",\"records\":[{\"target_address\":\"93.184.216.77/32\"}]}"
check "200" "#30 a /32 single host is accepted"
api_call GET "/api/ips?groups=cidr-group&ip=93.184.216.77&limit=100" "$MASTER_KEY"
check_true '[.[] | select(.target_address == "93.184.216.77")] | length == 1' \
    "#30 a /32 is stored as the bare host address, never masked"

# IPv6 subnets follow the same rule.
api_call POST "/api/records/batch" "$MASTER_KEY" \
    "{\"group_name\":\"cidr-group\",\"records\":[{\"target_address\":\"2001:db8:beef::fe/64\"}]}"
check "200" "#30 an IPv6 CIDR with host bits set is accepted"
api_call GET "/api/ips?groups=cidr-group&ip=2001:db8:beef&limit=100" "$MASTER_KEY"
check_true '[.[] | select(.target_address == "2001:db8:beef::/64")] | length == 1' \
    "#30 the IPv6 CIDR is stored masked to its network address"

# ── IPv6 canonicalisation over the wire ─────────────────────────────────────
# Fully expanded, with a redundant /128. Must be stored compressed and without the prefix.
api_call POST "/api/records/batch" "$MASTER_KEY" \
    "{\"group_name\":\"edge-group\",\"records\":[{\"target_address\":\"2001:0db8:0000:0000:0000:0000:0000:00ff/128\",\"cause\":\"expanded form\"}]}"
check "200" "#30 an expanded IPv6 address with /128 is accepted"
check_true '.created == 1' "#30 and stored as a new record"

api_call GET "/api/ips?groups=edge-group&limit=100" "$MASTER_KEY"
check "200" "#30 list the edge-case group"
check_true '[.[] | select(.target_address == "2001:db8::ff")] | length == 1' \
    "#30 the expanded IPv6 form is stored in canonical compressed notation"

# Re-submitting a *different* spelling of the same address must update that one record rather than
# create a second — the property the UNIQUE index exists to guarantee.
api_call POST "/api/records/batch" "$MASTER_KEY" \
    "{\"group_name\":\"edge-group\",\"records\":[{\"target_address\":\"2001:DB8::00FF\",\"cause\":\"mixed case, compressed\"}]}"
check "200" "#30 a different spelling of the same IPv6 host is accepted"
check_true '.created == 0 and .updated == 1' \
    "#30 and matches the existing record instead of creating a duplicate"

# Filtered on the full canonical address, not the `2001:db8` prefix. The looser form worked only
# while this was the sole documentation-prefix record in the group; it is a substring match, so any
# later 2001:db8 address would join the result and this assertion would fail for an unrelated reason.
api_call GET "/api/ips?groups=edge-group&ip=2001:db8::ff&limit=100" "$MASTER_KEY"
check_true 'length == 1' "#30 exactly one row exists for the IPv6 host, whatever the spelling"
check_true '.[0].cause == "mixed case, compressed"' "#30 and the re-submission updated it"



# ── 31. Webhook Integration via simply_hook_executor (live receiver) ────────
#
# Every check up to this point proves what the vault *sends* — §22/§23 capture the raw bytes with a
# Python receiver that verifies nothing. This section proves the other half: that a real sibling
# service, built from source and driven independently, actually *accepts* those bytes and does
# something with them. `simply_hook_executor` is the natural receiver for that — it is the gold-
# standard peer this project converges with (`AGENT.MD`), and unlike the capture script it performs
# its own authentication and executes a real command as a result.
#
# ## All four real auth modes are genuinely end-to-end testable, with exactly two hooks and two keys
#
# An earlier version of this section concluded HMAC_ONLY and NONE could never authenticate against
# the executor, because at the time `X-API-Key` was mandatory on every route, unconditionally.
# `example/simply_hook_executor` has since grown a second, keyless authentication path
# (`middleware::invocation_auth_middleware`, `src/entities/hook.rs::AuthMode`) that applies only to
# the three routes that actually invoke a hook. Re-read from current source before writing anything
# below each time this section changes, since a prior conclusion reached against an older checkout
# does not necessarily hold — this is the second time it hasn't.
#
# - A **keyed** caller (`X-API-Key` present) authenticates exactly as before, on every route,
#   regardless of the target hook's own `auth_mode` — that field "only ever *adds* a way in for a
#   keyless caller; it never removes the always-available keyed path" (`hook.rs`'s own doc). This is
#   proven directly below rather than only asserted: the CANONICAL_V1 and API_KEY_ONLY blocks target
#   the *keyless* HMAC_ONLY and NONE hooks respectively, and succeed anyway.
# - A **keyless** caller (no `X-API-Key`) is judged entirely by the target *hook's* `auth_mode`:
#   `CanonicalV1`/`ApiKeyOnly` still refuse it (a key is required for those); `HmacOnly` accepts it
#   if the configured header carries a valid HMAC-SHA256 over the raw body against the **hook's
#   own** `hmac_secret` (never a key's) — no timestamp, no key, the exact shape the vault's
#   `HMAC_ONLY` mode sends; `NoAuth` accepts it outright, provided the deployment-wide
#   `REQUIRE_SIGNED_REQUESTS` is `false` (the default) and no stray signature material is present.
#
# Because a keyed caller never consults the target hook's `auth_mode`, only **two** hooks are
# provisioned below (`HmacOnly`, `NoAuth`) rather than one per mode — a `CanonicalV1`- or
# `ApiKeyOnly`-auth_mode hook would behave identically to any other hook for every keyed caller,
# so a dedicated one would prove nothing a shared one does not. The distinction that *does* need
# two of something is the **key**: this session's peer update added
# `CreateApiKeyPayload::generate_signing_secret` (default `true`), which — set to `false` — mints a
# bearer credential with no `key_id`/`signing_secret` at all, structurally incapable of signing
# rather than merely a signing-capable key that happens not to be asked to. `TRIGGER_KEY` (default,
# signing-capable) drives CANONICAL_V1 ("API Key + Hmac"); `BEARERONLY_KEY`
# (`generate_signing_secret: false`) drives API_KEY_ONLY ("API Key only"). Both are granted
# `can_execute` on both hooks, so which hook each keyed test happens to target is a free choice, not
# a constraint.
#
# ## Four real modes, not five
#
# `hook::AuthMode` has exactly four variants — `CanonicalV1`, `ApiKeyOnly`, `HmacOnly`, `NoAuth`
# ("NONE") — confirmed directly from the enum in `src/entities/hook.rs`. There is no `BODY_ONLY`
# among them: it was retired as an *api_keys* `hmac_mode` value in `m20260819_141730` (SCHEMA.MD),
# and the keyless third-party-webhook use case it used to serve is exactly what a hook's own
# `HmacOnly` `auth_mode` now provides. This mirrors the vault's own side precisely — `BODY_ONLY` is
# likewise a retired, input-only alias for `HMAC_ONLY` there (`m20260811_000012`), not a fifth live
# mode — so there is no fifth hook to provision; a hook named for `BODY_ONLY` would have nowhere to
# point that `HMAC_ONLY`'s hook does not already cover identically.
#
# ## Body-only HMAC is a *signing-content* choice, not a mode — proven both with and without a key
#
# `BODY_ONLY` is not a fifth mode; it is what happens when the signed material is reduced to just
# the payload. That reduction is reachable two structurally different ways, and both are proven
# below rather than only the one `HMAC_ONLY`'s name suggests:
#
# - **Without an API key** — `AuthMode::HmacOnly`/`BODY_ONLY_LEGACY` on the vault's side, `HmacOnly`
#   on a *hook* on the executor's side. No key header at all; the executor identifies which secret
#   to verify against from the hook the request path names, not from any credential. This is the
#   keyless HMAC_ONLY/BODY_ONLY block already described above.
# - **With an API key** — a `CANONICAL_V1` webhook whose `hmac_template` is reduced to exactly
#   `{body}` (the only requirement is that it *contain* `{body}`; nothing requires the other three
#   placeholders too), paired on the executor's side with an ordinary key whose own
#   `canonical_template` override carries no format requirement either. `X-API-Key` and
#   `X-Timestamp` are both still sent — CANONICAL_V1 always adds them — but the signature itself
#   covers the body alone, identically to the keyless case, just attributable to a real credential
#   this time. Proven in its own block below, wire shape first (contrasted directly against the
#   keyless capture) and then against the live executor.
#
# ## What "custom HMAC template" coverage this can and cannot add
#
# An earlier version of this comment claimed the executor's CANONICAL_V1 verification format is
# fixed with no per-key customization. That was wrong even at the time it was written — re-reading
# `src/api/keys.rs` while building the "keyed body-only HMAC" block below found
# `api_keys.canonical_template`: an ordinary (non-`can_manage_keys`) key can override the string it
# signs over with no format requirement at all, and the block below relies on exactly that to prove
# a keyed, body-only signature against a live executor. §23's path-override edge case could
# therefore also be proven against the executor now, by setting the matching key's
# `canonical_template` to the same hardcoded path — left where §23 already proves it, against the
# raw capture receiver, since that coverage is adequate and duplicating it against a second receiver
# would only be a slower copy of the same assertion.
#
# A *body-excluding* template was going to be tested the same way — until running it once showed
# `src/api/webhooks.rs` refuses any `hmac_template` omitting `{body}` at the API layer, on both
# create and update ("a signature that does not cover the payload authenticates nothing"). There is
# therefore no receiver, real or captured, that a body-excluding template can ever reach: the
# refusal is unconditional and precedes dispatch entirely. That refusal is what gets tested below,
# in place of the live delivery this section originally assumed was reachable.
#
# "Single-pass escape resolution" (a value containing a literal `\n` substring must not be
# corrupted) is already proven at the Rust level by `cargo test` — see
# `dispatch::tests::resolve_hmac_template` and its adversarial "hostile body" case — so it is not
# duplicated here; re-proving a property `cargo test` already pins on every run would only be a
# slower, shell-shaped copy of the same assertion.

log_section "31. Webhook Integration via simply_hook_executor (live receiver)"

HOOK_EXECUTOR_DIR="$PROJECT_ROOT/example/simply_hook_executor"
HOOK_EXECUTOR_AVAILABLE=0

if [ ! -d "$HOOK_EXECUTOR_DIR" ]; then
    warn "example/simply_hook_executor not found — skipping §31 (live webhook integration)."
elif ! command -v cargo >/dev/null 2>&1; then
    warn "cargo not found — skipping §31 (live webhook integration)."
else
    log "Building simply_hook_executor from $HOOK_EXECUTOR_DIR ..."
    if ! (cd "$HOOK_EXECUTOR_DIR" && cargo build --quiet 2>"$WORK_DIR/hook_executor_build.log"); then
        warn "simply_hook_executor failed to build — skipping §31. Build log:"
        cat "$WORK_DIR/hook_executor_build.log" >&2
    elif [ ! -x "$HOOK_EXECUTOR_DIR/target/debug/simply_hook_executor" ]; then
        warn "simply_hook_executor binary not found after build — skipping §31."
    elif command -v fuser >/dev/null 2>&1 && fuser "$HOOK_EXECUTOR_PORT/tcp" >/dev/null 2>&1; then
        warn "Port $HOOK_EXECUTOR_PORT is already in use — skipping §31."
    else
        HOOK_EXECUTOR_AVAILABLE=1
    fi
fi

if [ "$HOOK_EXECUTOR_AVAILABLE" -eq 1 ]; then
    HOOK_EXECUTOR_BASE="http://127.0.0.1:$HOOK_EXECUTOR_PORT"
    HOOK_EXECUTOR_DB="$WORK_DIR/hook_executor.db"
    HOOK_EXECUTOR_LOG="$WORK_DIR/hook_executor_server.log"
    HOOK_EXECUTOR_MASTER_KEY="b33fb33fb33fb33fb33fb33fb33fb33fb33fb33fb33fb33fb33fb33fb33fb33f"
    HOOK_SCRIPT_DIR="$WORK_DIR/hook_scripts"
    mkdir -p "$HOOK_SCRIPT_DIR"
    # Canonicalized so it matches exactly what ALLOWED_SCRIPT_ROOTS below is compared against — on
    # a platform where $TMPDIR resolves through a symlink, the literal and physical forms would
    # otherwise differ and the executor's containment check would refuse the hook for the wrong
    # reason. Same fix simply_hook_executor's own e2e suite applies to its own hook directory.
    HOOK_SCRIPT_DIR="$(cd "$HOOK_SCRIPT_DIR" && pwd -P)"

    # Echoes the one parameter every trigger below supplies, so a successful execution's stdout
    # names exactly which banned address reached it — the difference between "got a 200" and "the
    # right event actually flowed through the whole pipeline".
    HOOK_ECHO_SCRIPT="$HOOK_SCRIPT_DIR/vault_trigger.sh"
    printf '#!/bin/sh\necho "vault-triggered:${HOOK_PARAM_TARGET}"\n' > "$HOOK_ECHO_SCRIPT"
    chmod 755 "$HOOK_ECHO_SCRIPT"

    log "Starting simply_hook_executor on port $HOOK_EXECUTOR_PORT ..."
    DATABASE_URL="sqlite://$HOOK_EXECUTOR_DB?mode=rwc" RUST_LOG=info \
        INITIAL_MASTER_KEY="$HOOK_EXECUTOR_MASTER_KEY" \
        ALLOWED_SCRIPT_ROOTS="$HOOK_SCRIPT_DIR" \
        BIND_HOST="127.0.0.1" PORT="$HOOK_EXECUTOR_PORT" \
        "$HOOK_EXECUTOR_DIR/target/debug/simply_hook_executor" >"$HOOK_EXECUTOR_LOG" 2>&1 &
    HOOK_EXECUTOR_PID=$!

    HOOK_EXECUTOR_READY=0
    for _ in $(seq 1 60); do
        if ! kill -0 "$HOOK_EXECUTOR_PID" 2>/dev/null; then break; fi
        SC=$(curl -s -o /dev/null -w "%{http_code}" "$HOOK_EXECUTOR_BASE/health" 2>/dev/null)
        [ "$SC" == "200" ] && { HOOK_EXECUTOR_READY=1; break; }
        sleep 0.25
    done

    if [ "$HOOK_EXECUTOR_READY" -ne 1 ]; then
        warn "simply_hook_executor did not become ready — skipping §31. Server log:"
        cat "$HOOK_EXECUTOR_LOG" >&2
        HOOK_EXECUTOR_AVAILABLE=0
    else
        log "simply_hook_executor is up (pid $HOOK_EXECUTOR_PID)."
    fi
fi

if [ "$HOOK_EXECUTOR_AVAILABLE" -eq 1 ]; then
    # A tiny local helper mirroring api_call(), targeting the executor's own base URL instead of
    # the vault's. Bare X-API-Key, no signing: the executor's own auth is signature-optional by
    # default (see the module comment above), so administrative calls here need nothing more than
    # every unsigned call in the executor's *own* e2e suite uses for the same purpose.
    hook_api_call() {
        local method="$1" path="$2" api_key="${3:-}" data="${4:-}"
        local args=(-s -o "$RESP_BODY_FILE" -w "%{http_code}" -X "$method")
        [ -n "$api_key" ] && args+=(-H "X-API-Key: $api_key")
        if [ -n "$data" ]; then
            args+=(-H "Content-Type: application/json" -d "$data")
        fi
        RESP_STATUS=$(curl "${args[@]}" "$HOOK_EXECUTOR_BASE$path")
        RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    }

    # Two hooks, one per *keyless* auth_mode, both pointed at the same echo script — the mode is a
    # property of the hook row, not the script. `CANONICAL_V1` and `API_KEY_ONLY` do not get their
    # own dedicated hooks: `auth_mode` only ever adds a keyless door, never removes the always-
    # available keyed path (`hook.rs`'s own doc), so a keyed caller authenticates identically
    # against either hook below regardless of what its own `auth_mode` says. Proven directly, not
    # just asserted: the CANONICAL_V1 block targets the HMAC_ONLY hook, and API_KEY_ONLY targets the
    # NONE hook — each hook is exercised by both its own keyless door and an unrelated keyed caller.
    HOOK_HMAC_SECRET="executor-hook-own-hmac-secret-not-a-key-secret"

    hook_api_call POST "/api/hooks" "$HOOK_EXECUTOR_MASTER_KEY" \
        "{\"name\":\"vault_trigger_hmaconly\",\"script_path\":\"$HOOK_ECHO_SCRIPT\",\"default_timeout_seconds\":10,\"auth_mode\":\"HMAC_ONLY\",\"hmac_secret\":\"$HOOK_HMAC_SECRET\",\"parameters\":[{\"param_key\":\"target\",\"is_required\":true}]}"
    check "200" "create the HMAC_ONLY hook — keyless, verified against the hook's own hmac_secret"
    HOOK_HMACONLY_ID=$(echo "$RESP_BODY" | jq -r '.id')

    hook_api_call POST "/api/hooks" "$HOOK_EXECUTOR_MASTER_KEY" \
        "{\"name\":\"vault_trigger_noauth\",\"script_path\":\"$HOOK_ECHO_SCRIPT\",\"default_timeout_seconds\":10,\"auth_mode\":\"NONE\",\"parameters\":[{\"param_key\":\"target\",\"is_required\":true}]}"
    check "200" "create the NONE hook — keyless, unauthenticated (REQUIRE_SIGNED_REQUESTS defaults to false)"
    HOOK_NOAUTH_ID=$(echo "$RESP_BODY" | jq -r '.id')

    # Two keys, one per *keyed* connection method. `generate_signing_secret` (new on the executor
    # this session — re-pulled and re-read before writing any of this, per AGENT.MD's mandatory-pull
    # rule) is what makes "API Key only" a real, structural property of a credential rather than a
    # signing-capable key that simply happens not to be asked to sign: a caller minted with
    # `generate_signing_secret: false` has no `signing_secret` to sign with at all.
    hook_api_call POST "/api/keys" "$HOOK_EXECUTOR_MASTER_KEY" '{"name":"vault-dispatcher-canonical"}'
    check "200" "create the API-Key-plus-HMAC key (default generate_signing_secret: true)"
    TRIGGER_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
    TRIGGER_KEY_ID=$(echo "$RESP_BODY" | jq -r '.id')
    TRIGGER_SECRET=$(echo "$RESP_BODY" | jq -r '.signing_secret')
    check_true '.key_id != null' "and it was minted with a key_id (signing-capable)"

    hook_api_call POST "/api/keys" "$HOOK_EXECUTOR_MASTER_KEY" \
        '{"name":"vault-dispatcher-apikeyonly","generate_signing_secret":false}'
    check "200" "create the API-Key-only key (generate_signing_secret: false — no signing secret exists)"
    BEARERONLY_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
    BEARERONLY_KEY_ID=$(echo "$RESP_BODY" | jq -r '.id')
    check_true '.key_id == null' "and no key_id was minted for it"
    check_true '.signing_secret == null' "and no signing_secret was minted for it either"

    # Both keys get execute rights on both hooks — not because both combinations are meaningful
    # (only the two used below are), but because the grant matrix being complete is what makes "the
    # hook's own auth_mode does not gate a keyed caller" a fact this suite exercises rather than one
    # it merely asserts in a comment.
    for GRANT_KEY_ID in "$TRIGGER_KEY_ID" "$BEARERONLY_KEY_ID"; do
        for GRANT_HOOK_ID in "$HOOK_HMACONLY_ID" "$HOOK_NOAUTH_ID"; do
            hook_api_call POST "/api/keys/$GRANT_KEY_ID/permissions" "$HOOK_EXECUTOR_MASTER_KEY" \
                "{\"hook_id\":\"$GRANT_HOOK_ID\",\"can_execute\":true,\"can_manage\":false}"
            check "200" "grant key $GRANT_KEY_ID execute rights on hook $GRANT_HOOK_ID"
        done
    done

    # Successful executions recorded against one hook so far, so each mode below can assert its own
    # *delta* rather than an absolute count that would be wrong the second time this loop runs.
    executor_success_count() {
        local hook_id="$1"
        hook_api_call GET "/api/executions?hook=$hook_id&status=SUCCESS&limit=1000" "$HOOK_EXECUTOR_MASTER_KEY"
        echo "$RESP_BODY" | jq -r 'length' 2>/dev/null || echo 0
    }

    api_call POST "/api/groups" "$MASTER_KEY" '{"name":"hook-executor-group"}'
    check "200" "create the vault-side group backing the live-integration webhooks"
    HOOKEXEC_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

    # ── CANONICAL_V1 ("API Key + Hmac"): keyed, fully signed, against the HMAC_ONLY hook ────────
    BEFORE=$(executor_success_count "$HOOK_HMACONLY_ID")
    api_call POST "/api/webhooks" "$MASTER_KEY" \
        "{\"name\":\"canonical-to-executor\",\"target_url\":\"$HOOK_EXECUTOR_BASE/webhook/vault_trigger_hmaconly\",\"secret_token\":\"$TRIGGER_SECRET\",\"api_key\":\"$TRIGGER_KEY\",\"payload_template\":\"{\\\"target\\\":\\\"\$target_address\\\"}\",\"group_id\":\"$HOOKEXEC_GROUP_ID\",\"auth_mode\":\"CANONICAL_V1\",\"events\":\"IP_ADD\"}"
    check "200" "create a CANONICAL_V1 webhook targeting the live executor's HMAC_ONLY hook"
    CANON_EXEC_WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"203.0.113.31","group_name":"hook-executor-group","cause":"canonical live dispatch"}'
    check "200" "ban an address to trigger the CANONICAL_V1 dispatch"

    AFTER=0
    for _ in $(seq 1 40); do
        AFTER=$(executor_success_count "$HOOK_HMACONLY_ID")
        [ "$AFTER" -gt "$BEFORE" ] 2>/dev/null && break
        sleep 0.25
    done
    check_local "$AFTER" "$((BEFORE + 1))" "CANONICAL_V1: exactly one new successful execution was recorded"

    hook_api_call GET "/api/executions?hook=$HOOK_HMACONLY_ID&status=SUCCESS&limit=1" "$HOOK_EXECUTOR_MASTER_KEY"
    check_true '.[0].stdout | contains("vault-triggered:203.0.113.31")' \
        "CANONICAL_V1: the executed script actually saw the banned address, end to end"
    check_true '.[0].api_key_id != null' \
        "CANONICAL_V1: the execution is attributed to the presenting key, even though the target hook's own auth_mode is HMAC_ONLY"

    api_call DELETE "/api/webhooks/$CANON_EXEC_WEBHOOK_ID" "$MASTER_KEY"
    check "204" "delete the CANONICAL_V1 executor webhook"

    # ── API_KEY_ONLY ("API Key only"): keyed, unsigned, against the NONE hook ───────────────────
    #
    # `BEARERONLY_KEY` has no `signing_secret` at all — this is not merely a dispatch that omits a
    # signature it could have sent, it is a credential that structurally cannot sign.
    BEFORE=$(executor_success_count "$HOOK_NOAUTH_ID")
    api_call POST "/api/webhooks" "$MASTER_KEY" \
        "{\"name\":\"apikeyonly-to-executor\",\"target_url\":\"$HOOK_EXECUTOR_BASE/webhook/vault_trigger_noauth\",\"api_key\":\"$BEARERONLY_KEY\",\"payload_template\":\"{\\\"target\\\":\\\"\$target_address\\\"}\",\"group_id\":\"$HOOKEXEC_GROUP_ID\",\"auth_mode\":\"API_KEY_ONLY\",\"events\":\"IP_ADD\"}"
    check "200" "create an API_KEY_ONLY webhook targeting the live executor's NONE hook"
    APIKEY_EXEC_WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"203.0.113.32","group_name":"hook-executor-group","cause":"api-key-only live dispatch"}'
    check "200" "ban an address to trigger the API_KEY_ONLY dispatch"

    AFTER=0
    for _ in $(seq 1 40); do
        AFTER=$(executor_success_count "$HOOK_NOAUTH_ID")
        [ "$AFTER" -gt "$BEFORE" ] 2>/dev/null && break
        sleep 0.25
    done
    check_local "$AFTER" "$((BEFORE + 1))" "API_KEY_ONLY: exactly one new successful execution was recorded"

    hook_api_call GET "/api/executions?hook=$HOOK_NOAUTH_ID&status=SUCCESS&limit=1" "$HOOK_EXECUTOR_MASTER_KEY"
    check_true '.[0].stdout | contains("vault-triggered:203.0.113.32")' \
        "API_KEY_ONLY: the bearer-only, non-signing key's dispatch still executed with the correct payload"
    check_true '.[0].api_key_id != null' \
        "API_KEY_ONLY: attributed to the bearer-only key, even though the target hook's own auth_mode is NONE"

    api_call DELETE "/api/webhooks/$APIKEY_EXEC_WEBHOOK_ID" "$MASTER_KEY"
    check "204" "delete the API_KEY_ONLY executor webhook"

    # ── HMAC_ONLY ("hmac only", configured on the hook): keyless ────────────────────────────────
    #
    # No X-API-Key, no X-Timestamp — matching AuthMode::HmacOnly's wire shape exactly (already
    # proven at the byte level against the Python receiver in §22). The vault's secret_token must
    # equal the *hook's* hmac_secret, not any key's, since the executor verifies this keyless path
    # against the hook row alone.
    BEFORE=$(executor_success_count "$HOOK_HMACONLY_ID")
    api_call POST "/api/webhooks" "$MASTER_KEY" \
        "{\"name\":\"hmaconly-to-executor\",\"target_url\":\"$HOOK_EXECUTOR_BASE/webhook/vault_trigger_hmaconly\",\"secret_token\":\"$HOOK_HMAC_SECRET\",\"payload_template\":\"{\\\"target\\\":\\\"\$target_address\\\"}\",\"group_id\":\"$HOOKEXEC_GROUP_ID\",\"auth_mode\":\"HMAC_ONLY\",\"events\":\"IP_ADD\"}"
    check "200" "create an HMAC_ONLY webhook targeting the live executor's keyless HMAC_ONLY hook"
    HMACONLY_EXEC_WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"203.0.113.33","group_name":"hook-executor-group","cause":"hmac-only live dispatch"}'
    check "200" "ban an address to trigger the HMAC_ONLY dispatch"

    AFTER=0
    for _ in $(seq 1 40); do
        AFTER=$(executor_success_count "$HOOK_HMACONLY_ID")
        [ "$AFTER" -gt "$BEFORE" ] 2>/dev/null && break
        sleep 0.25
    done
    check_local "$AFTER" "$((BEFORE + 1))" "HMAC_ONLY: exactly one new successful execution was recorded, keyless"

    hook_api_call GET "/api/executions?hook=$HOOK_HMACONLY_ID&status=SUCCESS&limit=1" "$HOOK_EXECUTOR_MASTER_KEY"
    check_true '.[0].stdout | contains("vault-triggered:203.0.113.33")' \
        "HMAC_ONLY: the keyless dispatch still executed with the correct payload, end to end"
    check_true '.[0].api_key_id == null' \
        "HMAC_ONLY: the execution is recorded as keyless (no api_key_id), unlike either keyed case above"

    api_call DELETE "/api/webhooks/$HMACONLY_EXEC_WEBHOOK_ID" "$MASTER_KEY"
    check "204" "delete the HMAC_ONLY executor webhook"

    # A wrong secret must still be refused on this same keyless path — the point of it accepting no
    # key at all is not that it accepts anything.
    HMACONLY_TAMPERED_BODY='{"target":"tampered-hmac-only-probe"}'
    HMACONLY_TAMPERED_SIG="sha256=$(printf '%s' "$HMACONLY_TAMPERED_BODY" \
        | openssl dgst -sha256 -hmac "definitely-not-the-hook-secret" | sed 's/^.*= //')"
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X POST \
        -H "X-Signature-256: $HMACONLY_TAMPERED_SIG" -H "Content-Type: application/json" \
        -d "$HMACONLY_TAMPERED_BODY" "$HOOK_EXECUTOR_BASE/webhook/vault_trigger_hmaconly")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "401" "a keyless HMAC_ONLY request signed with the wrong secret is refused, not accepted"

    # ── BODY_ONLY: the legacy input alias for HMAC_ONLY, proven at the wire and live ────────────
    #
    # `AuthMode::BODY_ONLY_LEGACY` (`src/entities/webhook_config.rs`) is not a distinct mode — it is
    # accepted on input and immediately normalised to `HMAC_ONLY`; the stored row and every byte the
    # dispatcher later sends are identical to a webhook created with `"HMAC_ONLY"` directly. §22
    # already proves the alias round-trips for the *deprecated field name* (`signature_mode:
    # "BODY_ONLY"`, against a URL that is never actually dispatched to). What has not been proven
    # anywhere yet is the *current* field spelled the *legacy* way — `"auth_mode": "BODY_ONLY"` —
    # carried all the way through a live dispatch. Two receivers, same webhook creation call: the
    # local capture script for the exact wire shape, then the live executor for genuine verification
    # and execution — the same split used for CANONICAL_V1/HMAC_ONLY above.
    if [ "${WEBHOOK_RECEIVER_AVAILABLE:-0}" -eq 1 ]; then
        BODYONLY_SECRET="body-only-legacy-alias-secret"
        : > "$RECEIVER_LOG"

        api_call POST "/api/webhooks" "$MASTER_KEY" \
            "{\"name\":\"bodyonly-wire-capture\",\"target_url\":\"http://127.0.0.1:$RECEIVER_PORT/bodyonly-legacy\",\"secret_token\":\"$BODYONLY_SECRET\",\"payload_template\":\"{\\\"ip\\\":\\\"\$target_address\\\"}\",\"group_id\":\"$HOOKEXEC_GROUP_ID\",\"auth_mode\":\"BODY_ONLY\",\"events\":\"IP_ADD\"}"
        check "200" "create a webhook using the legacy 'auth_mode':'BODY_ONLY' input spelling"
        check_true '.auth_mode == "HMAC_ONLY"' \
            "and it is normalised to HMAC_ONLY in the response, identically to the canonical spelling"
        BODYONLY_CAPTURE_WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

        api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"203.0.113.38","group_name":"hook-executor-group","cause":"body-only wire capture"}'
        check "200" "ban an address to trigger the BODY_ONLY-labelled dispatch"

        for _ in $(seq 1 40); do
            [ -s "$RECEIVER_LOG" ] && break
            sleep 0.25
        done

        if [ -s "$RECEIVER_LOG" ]; then
            HIT=$(head -n 1 "$RECEIVER_LOG")
            BO_SIG=$(echo "$HIT" | jq -r '.signature // empty')
            BO_TS=$(echo "$HIT" | jq -r '.timestamp // empty')
            BO_KEY=$(echo "$HIT" | jq -r '.api_key // empty')
            BO_BODY=$(echo "$HIT" | jq -r '.body // empty')
            BO_EXPECTED="sha256=$(printf '%s' "$BO_BODY" | openssl dgst -sha256 -hmac "$BODYONLY_SECRET" | sed 's/^.*= //')"

            if [ -n "$BO_SIG" ] && [ "$BO_SIG" == "$BO_EXPECTED" ]; then
                PASS_COUNT=$((PASS_COUNT + 1))
                echo -e "$(ts)   ${GREEN}✓ PASS${RESET} BODY_ONLY: X-Signature-256 is sha256=HMAC(RAW_BODY), computed strictly over the body" >&2
            else
                FAIL_COUNT=$((FAIL_COUNT + 1))
                echo -e "$(ts)   ${RED}✗ FAIL${RESET} BODY_ONLY: signature mismatch (got '$BO_SIG', expected '$BO_EXPECTED')" >&2
            fi

            if [ -z "$BO_TS" ]; then
                PASS_COUNT=$((PASS_COUNT + 1))
                echo -e "$(ts)   ${GREEN}✓ PASS${RESET} BODY_ONLY: X-Timestamp is absent" >&2
            else
                FAIL_COUNT=$((FAIL_COUNT + 1))
                echo -e "$(ts)   ${RED}✗ FAIL${RESET} BODY_ONLY: unexpectedly sent X-Timestamp: $BO_TS" >&2
            fi

            if [ -z "$BO_KEY" ]; then
                PASS_COUNT=$((PASS_COUNT + 1))
                echo -e "$(ts)   ${GREEN}✓ PASS${RESET} BODY_ONLY: X-API-Key is absent, same as HMAC_ONLY" >&2
            else
                FAIL_COUNT=$((FAIL_COUNT + 1))
                echo -e "$(ts)   ${RED}✗ FAIL${RESET} BODY_ONLY: unexpectedly sent X-API-Key: $BO_KEY" >&2
            fi
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
            echo -e "$(ts)   ${RED}✗ FAIL${RESET} the BODY_ONLY-labelled webhook was never delivered" >&2
        fi

        api_call DELETE "/api/webhooks/$BODYONLY_CAPTURE_WEBHOOK_ID" "$MASTER_KEY"
        check "204" "delete the BODY_ONLY wire-capture webhook"
    else
        warn "Local webhook receiver unavailable — skipping the BODY_ONLY wire-shape capture."
    fi

    # Same alias, now against the live executor's HmacOnly hook — proving simply_hook_executor
    # actually validates the signature and executes, not merely that the vault sent well-formed
    # bytes. Reuses the same hook/secret as the HMAC_ONLY block above: the wire format is identical,
    # so the executor cannot tell these two webhooks apart, which is the entire point of the alias.
    BEFORE=$(executor_success_count "$HOOK_HMACONLY_ID")
    api_call POST "/api/webhooks" "$MASTER_KEY" \
        "{\"name\":\"bodyonly-to-executor\",\"target_url\":\"$HOOK_EXECUTOR_BASE/webhook/vault_trigger_hmaconly\",\"secret_token\":\"$HOOK_HMAC_SECRET\",\"payload_template\":\"{\\\"target\\\":\\\"\$target_address\\\"}\",\"group_id\":\"$HOOKEXEC_GROUP_ID\",\"auth_mode\":\"BODY_ONLY\",\"events\":\"IP_ADD\"}"
    check "200" "create a BODY_ONLY-labelled webhook targeting the live executor's HmacOnly hook"
    check_true '.auth_mode == "HMAC_ONLY"' "and its stored auth_mode is HMAC_ONLY, not BODY_ONLY"
    BODYONLY_EXEC_WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"203.0.113.39","group_name":"hook-executor-group","cause":"body-only live dispatch"}'
    check "200" "ban an address to trigger the BODY_ONLY-labelled live dispatch"

    AFTER=0
    for _ in $(seq 1 40); do
        AFTER=$(executor_success_count "$HOOK_HMACONLY_ID")
        [ "$AFTER" -gt "$BEFORE" ] 2>/dev/null && break
        sleep 0.25
    done
    check_local "$AFTER" "$((BEFORE + 1))" \
        "BODY_ONLY: exactly one new successful execution was recorded on the live executor"

    hook_api_call GET "/api/executions?hook=$HOOK_HMACONLY_ID&status=SUCCESS&limit=1" "$HOOK_EXECUTOR_MASTER_KEY"
    check_true '.[0].stdout | contains("vault-triggered:203.0.113.39")' \
        "BODY_ONLY: simply_hook_executor validated the signature and executed with the correct payload"

    api_call DELETE "/api/webhooks/$BODYONLY_EXEC_WEBHOOK_ID" "$MASTER_KEY"
    check "204" "delete the BODY_ONLY executor webhook"

    # ── Body-only HMAC, WITH an API key ─────────────────────────────────────
    #
    # HMAC_ONLY/BODY_ONLY above are body-only *and* keyless — that pairing is what the mode exists
    # for, but it is not the only way to get a body-only signature. `hmac_template` only has to
    # *contain* `{body}`; nothing requires the other three placeholders, so a CANONICAL_V1 webhook
    # (which still sends X-API-Key and X-Timestamp) can be pointed at a template of exactly
    # `"{body}"` and sign nothing else. The executor mirrors this on the keyed side: an ordinary
    # key's `canonical_template` override has no format requirement at all (only a
    # can_manage_keys-holding key is pinned to the service-wide default), so a dedicated key set to
    # `"{body}"` verifies the identical, minimal signature. Two independent customization surfaces,
    # same resulting wire shape, each checked from its own side of the connection: the vault's
    # "must contain {body}" rule below, the executor's "no format requirement for an ordinary key"
    # above.
    hook_api_call POST "/api/keys" "$HOOK_EXECUTOR_MASTER_KEY" \
        '{"name":"vault-dispatcher-body-only-template","canonical_template":"{body}"}'
    check "200" "create a third executor key whose own canonical_template is just {body}"
    BODYKEYED_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
    BODYKEYED_KEY_ID=$(echo "$RESP_BODY" | jq -r '.id')
    BODYKEYED_SECRET=$(echo "$RESP_BODY" | jq -r '.signing_secret')

    hook_api_call POST "/api/keys/$BODYKEYED_KEY_ID/permissions" "$HOOK_EXECUTOR_MASTER_KEY" \
        "{\"hook_id\":\"$HOOK_HMACONLY_ID\",\"can_execute\":true,\"can_manage\":false}"
    check "200" "grant the body-only-template key execute rights on the HMAC_ONLY hook"

    # Wire capture first, against the local receiver: X-API-Key and X-Timestamp both present (this
    # is still nominally a CANONICAL_V1 dispatch — the key is sent and the header is always added in
    # that branch) but the signature covers the body alone, contrasting directly with the keyless
    # BODY_ONLY capture above.
    if [ "${WEBHOOK_RECEIVER_AVAILABLE:-0}" -eq 1 ]; then
        : > "$RECEIVER_LOG"
        api_call POST "/api/webhooks" "$MASTER_KEY" \
            "{\"name\":\"keyed-body-only-wire-capture\",\"target_url\":\"http://127.0.0.1:$RECEIVER_PORT/keyed-body-only\",\"secret_token\":\"$BODYKEYED_SECRET\",\"api_key\":\"$BODYKEYED_KEY\",\"payload_template\":\"{\\\"ip\\\":\\\"\$target_address\\\"}\",\"group_id\":\"$HOOKEXEC_GROUP_ID\",\"auth_mode\":\"CANONICAL_V1\",\"hmac_template\":\"{body}\",\"events\":\"IP_ADD\"}"
        check "200" "create a CANONICAL_V1 webhook whose hmac_template is exactly {body}"
        KEYEDBODY_CAPTURE_WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

        api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"203.0.113.40","group_name":"hook-executor-group","cause":"keyed body-only wire capture"}'
        check "200" "ban an address to trigger the keyed body-only dispatch"

        for _ in $(seq 1 40); do
            [ -s "$RECEIVER_LOG" ] && break
            sleep 0.25
        done

        if [ -s "$RECEIVER_LOG" ]; then
            HIT=$(head -n 1 "$RECEIVER_LOG")
            KB_SIG=$(echo "$HIT" | jq -r '.signature // empty')
            KB_TS=$(echo "$HIT" | jq -r '.timestamp // empty')
            KB_KEY=$(echo "$HIT" | jq -r '.api_key // empty')
            KB_BODY=$(echo "$HIT" | jq -r '.body // empty')
            KB_EXPECTED="sha256=$(printf '%s' "$KB_BODY" | openssl dgst -sha256 -hmac "$BODYKEYED_SECRET" | sed 's/^.*= //')"

            if [ "$KB_KEY" == "$BODYKEYED_KEY" ]; then
                PASS_COUNT=$((PASS_COUNT + 1))
                echo -e "$(ts)   ${GREEN}✓ PASS${RESET} keyed body-only: X-API-Key is present, unlike the keyless BODY_ONLY case" >&2
            else
                FAIL_COUNT=$((FAIL_COUNT + 1))
                echo -e "$(ts)   ${RED}✗ FAIL${RESET} keyed body-only: expected X-API-Key '$BODYKEYED_KEY', got '$KB_KEY'" >&2
            fi

            if [ -n "$KB_TS" ]; then
                PASS_COUNT=$((PASS_COUNT + 1))
                echo -e "$(ts)   ${GREEN}✓ PASS${RESET} keyed body-only: X-Timestamp is present — CANONICAL_V1 always sends it, regardless of what the template signs" >&2
            else
                FAIL_COUNT=$((FAIL_COUNT + 1))
                echo -e "$(ts)   ${RED}✗ FAIL${RESET} keyed body-only: X-Timestamp is unexpectedly absent" >&2
            fi

            if [ -n "$KB_SIG" ] && [ "$KB_SIG" == "$KB_EXPECTED" ]; then
                PASS_COUNT=$((PASS_COUNT + 1))
                echo -e "$(ts)   ${GREEN}✓ PASS${RESET} keyed body-only: the signature covers the body alone, ignoring the timestamp it is sent alongside" >&2
            else
                FAIL_COUNT=$((FAIL_COUNT + 1))
                echo -e "$(ts)   ${RED}✗ FAIL${RESET} keyed body-only: signature mismatch (got '$KB_SIG', expected '$KB_EXPECTED')" >&2
            fi
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
            echo -e "$(ts)   ${RED}✗ FAIL${RESET} the keyed body-only webhook was never delivered" >&2
        fi

        api_call DELETE "/api/webhooks/$KEYEDBODY_CAPTURE_WEBHOOK_ID" "$MASTER_KEY"
        check "204" "delete the keyed body-only wire-capture webhook"
    else
        warn "Local webhook receiver unavailable — skipping the keyed body-only wire-shape capture."
    fi

    # Now the live executor: the dedicated key's own canonical_template ({body}) must independently
    # arrive at the same signature the vault computed, and actually execute.
    BEFORE=$(executor_success_count "$HOOK_HMACONLY_ID")
    api_call POST "/api/webhooks" "$MASTER_KEY" \
        "{\"name\":\"keyed-body-only-to-executor\",\"target_url\":\"$HOOK_EXECUTOR_BASE/webhook/vault_trigger_hmaconly\",\"secret_token\":\"$BODYKEYED_SECRET\",\"api_key\":\"$BODYKEYED_KEY\",\"payload_template\":\"{\\\"target\\\":\\\"\$target_address\\\"}\",\"group_id\":\"$HOOKEXEC_GROUP_ID\",\"auth_mode\":\"CANONICAL_V1\",\"hmac_template\":\"{body}\",\"events\":\"IP_ADD\"}"
    check "200" "create the keyed body-only webhook targeting the live executor"
    KEYEDBODY_EXEC_WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"203.0.113.41","group_name":"hook-executor-group","cause":"keyed body-only live dispatch"}'
    check "200" "ban an address to trigger the keyed body-only live dispatch"

    AFTER=0
    for _ in $(seq 1 40); do
        AFTER=$(executor_success_count "$HOOK_HMACONLY_ID")
        [ "$AFTER" -gt "$BEFORE" ] 2>/dev/null && break
        sleep 0.25
    done
    check_local "$AFTER" "$((BEFORE + 1))" \
        "keyed body-only: exactly one new successful execution was recorded, with an API key present"

    hook_api_call GET "/api/executions?hook=$HOOK_HMACONLY_ID&status=SUCCESS&limit=1" "$HOOK_EXECUTOR_MASTER_KEY"
    check_true '.[0].stdout | contains("vault-triggered:203.0.113.41")' \
        "keyed body-only: the executor verified the body-only signature against the key's own canonical_template and executed"
    check_true '.[0].api_key_id != null' \
        "keyed body-only: the execution IS attributed to the presenting key, unlike the keyless HMAC_ONLY/BODY_ONLY cases above"

    api_call DELETE "/api/webhooks/$KEYEDBODY_EXEC_WEBHOOK_ID" "$MASTER_KEY"
    check "204" "delete the keyed body-only executor webhook"

    # ── NONE ("No authentification"): keyless, zero headers ─────────────────
    BEFORE=$(executor_success_count "$HOOK_NOAUTH_ID")
    api_call POST "/api/webhooks" "$MASTER_KEY" \
        "{\"name\":\"none-to-executor\",\"target_url\":\"$HOOK_EXECUTOR_BASE/webhook/vault_trigger_noauth\",\"payload_template\":\"{\\\"target\\\":\\\"\$target_address\\\"}\",\"group_id\":\"$HOOKEXEC_GROUP_ID\",\"auth_mode\":\"NONE\",\"events\":\"IP_ADD\"}"
    check "200" "create a NONE webhook targeting the live executor's keyless NONE hook"
    NONE_EXEC_WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"203.0.113.34","group_name":"hook-executor-group","cause":"none live dispatch"}'
    check "200" "ban an address to trigger the NONE dispatch"

    AFTER=0
    for _ in $(seq 1 40); do
        AFTER=$(executor_success_count "$HOOK_NOAUTH_ID")
        [ "$AFTER" -gt "$BEFORE" ] 2>/dev/null && break
        sleep 0.25
    done
    check_local "$AFTER" "$((BEFORE + 1))" "NONE: exactly one new successful execution was recorded, with zero authentication headers"

    hook_api_call GET "/api/executions?hook=$HOOK_NOAUTH_ID&status=SUCCESS&limit=1" "$HOOK_EXECUTOR_MASTER_KEY"
    check_true '.[0].stdout | contains("vault-triggered:203.0.113.34")' \
        "NONE: the fully unauthenticated dispatch still executed with the correct payload"
    check_true '.[0].api_key_id == null' \
        "NONE: recorded as keyless too, same as HMAC_ONLY, distinct from both keyed cases above"

    api_call DELETE "/api/webhooks/$NONE_EXEC_WEBHOOK_ID" "$MASTER_KEY"
    check "204" "delete the NONE executor webhook"

    # Stray signature material against a NONE hook must be refused outright, not silently ignored —
    # `signature_material_present`'s own doc names this as the gap it exists to close.
    RESP_STATUS=$(curl -s -o "$RESP_BODY_FILE" -w "%{http_code}" -X POST \
        -H "X-Signature-256: sha256=0000000000000000000000000000000000000000000000000000000000000000" \
        -H "Content-Type: application/json" -d '{"target":"stray-signature-on-noauth-probe"}' \
        "$HOOK_EXECUTOR_BASE/webhook/vault_trigger_noauth")
    RESP_BODY=$(cat "$RESP_BODY_FILE" 2>/dev/null || true)
    check "401" "a NONE hook refuses a keyless request that carries stray signature material"

    # ── Proactive: a tampered secret is refused, not silently accepted ─────
    #
    # Same shape as the executor's own e2e suite's "definitely-not-the-secret" check, applied here
    # to prove the *vault's* dispatch of a CANONICAL_V1 webhook is meaningfully verified on arrival
    # rather than merely well-formed.
    BEFORE=$(executor_success_count "$HOOK_HMACONLY_ID")
    api_call POST "/api/webhooks" "$MASTER_KEY" \
        "{\"name\":\"tampered-secret-to-executor\",\"target_url\":\"$HOOK_EXECUTOR_BASE/webhook/vault_trigger_hmaconly\",\"secret_token\":\"definitely-not-the-registered-secret\",\"api_key\":\"$TRIGGER_KEY\",\"payload_template\":\"{\\\"target\\\":\\\"\$target_address\\\"}\",\"group_id\":\"$HOOKEXEC_GROUP_ID\",\"auth_mode\":\"CANONICAL_V1\",\"events\":\"IP_ADD\"}"
    check "200" "create a CANONICAL_V1 webhook signed with the wrong secret"
    TAMPERED_EXEC_WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"203.0.113.35","group_name":"hook-executor-group","cause":"tampered secret dispatch"}'
    check "200" "ban an address to trigger the mis-signed dispatch"
    sleep 2
    AFTER=$(executor_success_count "$HOOK_HMACONLY_ID")
    check_local "$AFTER" "$BEFORE" "a dispatch signed with the wrong secret is rejected, not silently accepted"

    api_call DELETE "/api/webhooks/$TAMPERED_EXEC_WEBHOOK_ID" "$MASTER_KEY"
    check "204" "delete the tampered-secret webhook"

    # ── Proactive: an authenticated request to a hook that does not exist ──
    #
    # The credential is genuine (the registered worker key/secret); only the target hook name is
    # wrong. This exercises the dispatcher's handling of an authenticated-but-unexpected receiver
    # response (404) rather than an auth failure, and proves it does not wedge the worker: the
    # vault must still answer normally afterward.
    api_call POST "/api/webhooks" "$MASTER_KEY" \
        "{\"name\":\"missing-hook-to-executor\",\"target_url\":\"$HOOK_EXECUTOR_BASE/webhook/does_not_exist\",\"secret_token\":\"$TRIGGER_SECRET\",\"api_key\":\"$TRIGGER_KEY\",\"payload_template\":\"{\\\"target\\\":\\\"\$target_address\\\"}\",\"group_id\":\"$HOOKEXEC_GROUP_ID\",\"auth_mode\":\"CANONICAL_V1\",\"events\":\"IP_ADD\"}"
    check "200" "create a correctly-signed webhook targeting a hook name that does not exist"
    MISSING_HOOK_WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/ban" "$MASTER_KEY" '{"target_address":"203.0.113.36","group_name":"hook-executor-group","cause":"unexpected 404 dispatch"}'
    check "200" "ban an address to trigger a dispatch the executor will 404"
    sleep 1

    api_call GET "/health"
    check "200" "the vault itself is unaffected by a receiver's unexpected 404 (worker did not wedge)"

    api_call DELETE "/api/webhooks/$MISSING_HOOK_WEBHOOK_ID" "$MASTER_KEY"
    check "204" "delete the missing-hook webhook"

    api_call DELETE "/api/groups/$HOOKEXEC_GROUP_ID" "$MASTER_KEY"
    check "204" "clean up the hook-executor integration group"

    # ── Custom HMAC template excluding {body}: refused, not silently accepted ──────────────────
    #
    # This was drafted as a live-delivery test (create a body-excluding template, trigger it,
    # prove the signature is body-content-independent) before actually running it. It failed
    # immediately, and correctly: `src/api/webhooks.rs` refuses any `hmac_template` that omits
    # `{body}` at both creation and update, with the message below — "a signature that does not
    # cover the payload authenticates nothing". There is therefore no way, through the API, for a
    # body-excluding template to ever reach a live webhook row, on this route or any other; the
    # right test is that the refusal holds, not a delivery that can never happen.
    api_call POST "/api/groups" "$MASTER_KEY" '{"name":"nobody-template-group"}'
    check "200" "create a group for the body-excluding template check"
    NOBODY_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call POST "/api/webhooks" "$MASTER_KEY" \
        "{\"name\":\"nobody-template-hook\",\"target_url\":\"https://example.invalid/nobody\",\"secret_token\":\"no-body-in-template-secret\",\"payload_template\":\"{}\",\"group_id\":\"$NOBODY_GROUP_ID\",\"auth_mode\":\"CANONICAL_V1\",\"hmac_template\":\"{method}\\\\n{path}\\\\n{timestamp}\",\"events\":\"IP_ADD\"}"
    check "400" "creating a CANONICAL_V1 webhook whose template omits {body} is refused"
    check_jq ".error" "hmac_template must contain {body}: a signature that does not cover the payload authenticates nothing" \
        "and refused for exactly this reason — a signature that never covers the payload authenticates nothing"

    # The same refusal on the update path, not just at creation: a webhook created with the
    # default template must not be repointable onto a body-excluding one after the fact either.
    api_call POST "/api/webhooks" "$MASTER_KEY" \
        "{\"name\":\"retemplate-target-hook\",\"target_url\":\"https://example.invalid/retarget\",\"secret_token\":\"retarget-secret\",\"payload_template\":\"{}\",\"group_id\":\"$NOBODY_GROUP_ID\",\"auth_mode\":\"CANONICAL_V1\",\"events\":\"IP_ADD\"}"
    check "200" "create a webhook with the default (body-inclusive) template"
    RETEMPLATE_WEBHOOK_ID=$(echo "$RESP_BODY" | jq -r '.id')

    api_call PUT "/api/webhooks/$RETEMPLATE_WEBHOOK_ID" "$MASTER_KEY" \
        '{"hmac_template":"{method}\n{path}\n{timestamp}"}'
    check "400" "updating an existing webhook onto a body-excluding template is refused the same way"
    check_jq ".error" "hmac_template must contain {body}: a signature that does not cover the payload authenticates nothing" \
        "and the update path names the identical reason"

    api_call DELETE "/api/webhooks/$RETEMPLATE_WEBHOOK_ID" "$MASTER_KEY"
    check "204" "delete the retemplate-target webhook"
    api_call DELETE "/api/groups/$NOBODY_GROUP_ID" "$MASTER_KEY"
    check "204" "clean up the body-excluding template group"

    log "Stopping simply_hook_executor (pid $HOOK_EXECUTOR_PID)..."
    kill "$HOOK_EXECUTOR_PID" 2>/dev/null || true
    wait "$HOOK_EXECUTOR_PID" 2>/dev/null || true
    HOOK_EXECUTOR_PID=""
else
    warn "simply_hook_executor unavailable — skipping §31 entirely."
fi


log_section "32. Webhook Cloning (POST /api/webhooks/{id}/clone)"

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"clone-e2e-group","group_type":"banlist"}'
check "200" "#32 create the clone-source group"
CLONE_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"clone-source-hook\",\"target_url\":\"https://example.invalid/clone-source\",\"secret_token\":\"clone-source-secret\",\"payload_template\":\"{\\\"ip\\\":\\\"\$target_address\\\"}\",\"group_id\":\"$CLONE_GROUP_ID\",\"auth_mode\":\"CANONICAL_V1\",\"events\":\"IP_ADD,IP_DELETE\",\"is_active\":false}"
check "200" "#32 create the source webhook"
CLONE_SOURCE_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/webhooks/$CLONE_SOURCE_ID/clone" "$MASTER_KEY" '{"name":"cloned-hook"}'
check "201" "#32 clone the webhook — 201 Created"
check_jq ".name" "cloned-hook" "#32 the clone carries the requested name"
check_jq ".target_url" "https://example.invalid/clone-source" "#32 target_url is duplicated"
check_jq ".auth_mode" "CANONICAL_V1" "#32 auth_mode is duplicated"
check_jq ".events" "IP_ADD,IP_DELETE" "#32 events is duplicated"
check_true '.is_active == false' "#32 is_active is duplicated, not reset to the default"
check_true '(.secret_token | length) > 0' "#32 a fresh signing secret is generated and returned once"
CLONE_GENERATED_SECRET=$(echo "$RESP_BODY" | jq -r '.secret_token')
if [ "$CLONE_GENERATED_SECRET" != "clone-source-secret" ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} #32 the generated secret differs from the source's, never copied" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} #32 the clone must mint a fresh secret, not reuse the source's" >&2
fi
CLONE_TARGET_ID=$(echo "$RESP_BODY" | jq -r '.id')
if [ "$CLONE_TARGET_ID" != "$CLONE_SOURCE_ID" ] && [ -n "$CLONE_TARGET_ID" ] && [ "$CLONE_TARGET_ID" != "null" ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} #32 the clone is a new row with a fresh id, not the source" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} #32 clone id ('$CLONE_TARGET_ID') must be new and distinct from the source" >&2
fi

# The clone is a fully independent row: deleting the source must not affect it.
api_call DELETE "/api/webhooks/$CLONE_SOURCE_ID" "$MASTER_KEY"
check "204" "#32 delete the source webhook"
api_call GET "/api/webhooks" "$MASTER_KEY"
check_true "[.[] | select(.id == \"$CLONE_TARGET_ID\")] | length == 1" \
    "#32 the clone survives its source's deletion"

api_call DELETE "/api/webhooks/$CLONE_TARGET_ID" "$MASTER_KEY"
check "204" "#32 clean up the cloned webhook"
api_call DELETE "/api/groups/$CLONE_GROUP_ID" "$MASTER_KEY"
check "204" "#32 clean up the clone-source group"

# Cloning a nonexistent webhook is a 404, matching every other webhook endpoint's oracle discipline —
# indistinguishable from cloning one the caller cannot see.
api_call POST "/api/webhooks/00000000-0000-0000-0000-000000000000/clone" "$MASTER_KEY" '{"name":"nope"}'
check "404" "#32 cloning a nonexistent webhook id answers 404"

# A key holding can_manage_webhooks but no relationship to the webhook at all — neither owner nor
# even sharing its group — must not be able to clone it either.
api_call POST "/api/groups" "$MASTER_KEY" '{"name":"clone-peer-group","group_type":"banlist"}'
check "200" "#32 create a second group for the non-owner clone check"
CLONE_PEER_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')
api_call POST "/api/webhooks" "$MASTER_KEY" \
    "{\"name\":\"clone-peer-source-hook\",\"target_url\":\"https://example.invalid/peer-source\",\"payload_template\":\"{}\",\"group_id\":\"$CLONE_PEER_GROUP_ID\",\"auth_mode\":\"NONE\",\"events\":\"IP_ADD\"}"
check "200" "#32 create a second webhook, owned by master"
CLONE_PEER_SOURCE_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/keys" "$MASTER_KEY" \
    '{"name":"clone-peer","can_manage_webhooks":true,"bound_ips":"0.0.0.0/0,::/0"}'
check "200" "#32 create a peer key holding can_manage_webhooks"
CLONE_PEER_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
register_key_secret "$CLONE_PEER_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"
CLONE_PEER_KEY_ID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/webhooks/$CLONE_PEER_SOURCE_ID/clone" "$CLONE_PEER_KEY" '{"name":"peer-attempted-clone"}'
check "404" "#32 a non-owner with can_manage_webhooks cannot clone another tenant's webhook"

api_call DELETE "/api/keys/$CLONE_PEER_KEY_ID" "$MASTER_KEY"
check "204" "#32 clean up the peer key"
api_call DELETE "/api/webhooks/$CLONE_PEER_SOURCE_ID" "$MASTER_KEY"
check "204" "#32 clean up the second source webhook"
api_call DELETE "/api/groups/$CLONE_PEER_GROUP_ID" "$MASTER_KEY"
check "204" "#32 clean up the second group"


log_section "33. Batch Webhook Suppression (POST /api/records/batch skip_webhooks)"

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"batch-skip-e2e-group","group_type":"banlist"}'
check "200" "#33 create the batch-skip group"
BATCH_SKIP_GROUP_ID=$(echo "$RESP_BODY" | jq -r '.id')

if [ "${WEBHOOK_RECEIVER_AVAILABLE:-0}" -eq 1 ]; then
    api_call POST "/api/webhooks" "$MASTER_KEY" \
        "{\"name\":\"batch-skip-hook\",\"target_url\":\"http://127.0.0.1:$RECEIVER_PORT/batch-skip\",\"payload_template\":\"{\\\"ip\\\":\\\"\$target_address\\\"}\",\"group_id\":\"$BATCH_SKIP_GROUP_ID\",\"auth_mode\":\"NONE\",\"events\":\"IP_ADD\"}"
    check "200" "#33 create a webhook on the batch-skip group"

    # skip_webhooks: true — the record is written, but the receiver must never be reached.
    : > "$RECEIVER_LOG"
    api_call POST "/api/records/batch" "$MASTER_KEY" \
        "{\"group_name\":\"batch-skip-e2e-group\",\"skip_webhooks\":true,\"records\":[{\"target_address\":\"203.0.113.90\"}]}"
    check "200" "#33 batch with skip_webhooks: true succeeds"
    check_true '.created == 1' "#33 and the record is written regardless of skip_webhooks"

    # Give the (should-be-empty) dispatch queue every chance to have fired if it were going to.
    sleep 1
    if [ ! -s "$RECEIVER_LOG" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} #33 skip_webhooks: true suppressed dispatch — the receiver was never reached" >&2
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} #33 skip_webhooks: true must not dispatch, but the receiver was hit" >&2
    fi

    # skip_webhooks omitted — the documented default is "dispatch normally", not "suppress".
    : > "$RECEIVER_LOG"
    api_call POST "/api/records/batch" "$MASTER_KEY" \
        "{\"group_name\":\"batch-skip-e2e-group\",\"records\":[{\"target_address\":\"203.0.113.91\"}]}"
    check "200" "#33 batch with skip_webhooks omitted succeeds"
    check_true '.created == 1' "#33 and the record is written"

    for _ in $(seq 1 40); do
        [ -s "$RECEIVER_LOG" ] && break
        sleep 0.25
    done
    if [ -s "$RECEIVER_LOG" ]; then
        PASS_COUNT=$((PASS_COUNT + 1))
        echo -e "$(ts)   ${GREEN}✓ PASS${RESET} #33 skip_webhooks omitted dispatches normally — the receiver was reached" >&2
        HIT=$(head -n 1 "$RECEIVER_LOG")
        HOOK_BODY=$(echo "$HIT" | jq -r '.body // empty')
        if [[ "$HOOK_BODY" == *"203.0.113.91"* ]]; then
            PASS_COUNT=$((PASS_COUNT + 1))
            echo -e "$(ts)   ${GREEN}✓ PASS${RESET} #33 the dispatched payload names the batch-created address" >&2
        else
            FAIL_COUNT=$((FAIL_COUNT + 1))
            echo -e "$(ts)   ${RED}✗ FAIL${RESET} #33 dispatched body does not mention the batch-created address (got: $HOOK_BODY)" >&2
        fi
    else
        FAIL_COUNT=$((FAIL_COUNT + 1))
        echo -e "$(ts)   ${RED}✗ FAIL${RESET} #33 skip_webhooks omitted did not dispatch within the timeout" >&2
    fi

    api_call DELETE "/api/groups/$BATCH_SKIP_GROUP_ID" "$MASTER_KEY"
    check "204" "#33 clean up the batch-skip group"
else
    warn "Local webhook receiver unavailable — §33 checks only the record-level effect of skip_webhooks."
    api_call POST "/api/records/batch" "$MASTER_KEY" \
        "{\"group_name\":\"batch-skip-e2e-group\",\"skip_webhooks\":true,\"records\":[{\"target_address\":\"203.0.113.90\"}]}"
    check "200" "#33 batch with skip_webhooks: true still succeeds without a receiver"
    check_true '.created == 1' "#33 and the record is written regardless of skip_webhooks"
fi

# ── 34. Non-master / daughter key group listing (simply_ip_exporter workflow) ──
#
# Exercises the behaviour `simply_ip_exporter` depends on: a scoped API key calling
# GET /api/groups (or the /api/ip_groups alias) must receive 200 OK with exactly the groups
# it holds at least can_read on, no 403 Forbidden even when the group list is empty.
#
# Three sub-scenarios:
#   34a. Non-master key with can_read on one group: sees only that group.
#   34b. Daughter key (parent_key_id set) with can_read on same group: sees only that group.
#   34c. Non-master key with zero group permissions: sees empty list [], not 403.
#   34d. GET /api/ip_groups returns identical JSON to GET /api/groups for the same key.

log_section "34. Non-master / daughter key group listing (simply_ip_exporter workflow)"

# Set up two groups for this section.
api_call POST "/api/groups" "$MASTER_KEY" '{"name":"exporter-group-visible"}'
check "200" "#34 create the visible group"
EXPORTER_VISIBLE_GID=$(echo "$RESP_BODY" | jq -r '.id')

api_call POST "/api/groups" "$MASTER_KEY" '{"name":"exporter-group-hidden"}'
check "200" "#34 create a second group that the exporter key must NOT see"

# ── 34a. Non-master key filtered to its readable group ────────────────────────

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"exporter-nonmaster-key"}'
check "200" "#34a create the non-master exporter key"
EXPORTER_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
EXPORTER_KEY_ID=$(echo "$RESP_BODY" | jq -r '.id')
register_key_secret "$EXPORTER_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

# Grant only the visible group.
api_call POST "/api/keys/$EXPORTER_KEY_ID/permissions" "$MASTER_KEY" \
    "{\"group_id\":\"$EXPORTER_VISIBLE_GID\",\"can_read\":true,\"can_write\":false,\"can_delete\":false}"
check "200" "#34a grant can_read on the visible group to the non-master key"

api_call GET "/api/groups" "$EXPORTER_KEY"
check "200" "#34a non-master key receives 200 OK on GET /api/groups"
check_true "length == 1" "#34a response contains exactly one group (not two)"
check_jq ".[0].name" "exporter-group-visible" "#34a the returned group is the one the key can read"

# ── 34b. Daughter key (parent_key_id set) — same expectation ─────────────────

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"exporter-daughter-key"}'
check "200" "#34b create a daughter key"
DAUGHTER_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
DAUGHTER_KEY_ID=$(echo "$RESP_BODY" | jq -r '.id')
register_key_secret "$DAUGHTER_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

# Grant only the visible group to the daughter key too.
api_call POST "/api/keys/$DAUGHTER_KEY_ID/permissions" "$MASTER_KEY" \
    "{\"group_id\":\"$EXPORTER_VISIBLE_GID\",\"can_read\":true,\"can_write\":false,\"can_delete\":false}"
check "200" "#34b grant can_read on the visible group to the daughter key"

api_call GET "/api/groups" "$DAUGHTER_KEY"
check "200" "#34b daughter key receives 200 OK on GET /api/groups"
check_true "length == 1" "#34b daughter key sees only its own readable group, not both"
check_jq ".[0].name" "exporter-group-visible" "#34b the returned group is correct"

# ── 34c. Key with zero permissions: empty list, never 403 ────────────────────

api_call POST "/api/keys" "$MASTER_KEY" '{"name":"exporter-zero-key"}'
check "200" "#34c create a key with no group grants"
ZERO_KEY=$(echo "$RESP_BODY" | jq -r '.plaintext_key')
register_key_secret "$ZERO_KEY" "$(echo "$RESP_BODY" | jq -r '.signing_secret')"

api_call GET "/api/groups" "$ZERO_KEY"
check "200" "#34c key with zero group permissions receives 200 OK, not 403"
check_true "length == 0" "#34c response is an empty list []"

# ── 34d. GET /api/ip_groups alias returns identical JSON ─────────────────────

api_call GET "/api/groups" "$EXPORTER_KEY"
check "200" "#34d GET /api/groups baseline for alias comparison"
GROUPS_CANONICAL="$RESP_BODY"

api_call GET "/api/ip_groups" "$EXPORTER_KEY"
check "200" "#34d GET /api/ip_groups returns 200 OK"
GROUPS_ALIAS="$RESP_BODY"

CANONICAL_NAMES=$(echo "$GROUPS_CANONICAL" | jq -c '[.[].name] | sort')
ALIAS_NAMES=$(echo "$GROUPS_ALIAS" | jq -c '[.[].name] | sort')
if [ "$CANONICAL_NAMES" = "$ALIAS_NAMES" ]; then
    PASS_COUNT=$((PASS_COUNT + 1))
    echo -e "$(ts)   ${GREEN}✓ PASS${RESET} #34d /api/ip_groups and /api/groups return identical group names" >&2
else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    echo -e "$(ts)   ${RED}✗ FAIL${RESET} #34d /api/ip_groups returned different names: canonical=$CANONICAL_NAMES alias=$ALIAS_NAMES" >&2
fi

# ── 35. Stateful memberships: per-group state, cause history, restore, totals ─────────────────
#
# The address row is canonical; lock, soft delete and last observation belong to the membership in one
# group. These checks exercise that split through the wire, against the refactored schema.

ADDR_M="198.51.100.231"
GROUP_MA="membership-a"
GROUP_MB="membership-b"
DEL_A="{\"target_address\":\"$ADDR_M\",\"group_name\":\"$GROUP_MA\"}"

api_call POST "/api/ban" "$MASTER_KEY" "{\"target_address\":\"$ADDR_M\",\"group_name\":\"$GROUP_MA\",\"cause\":\"first cause\"}"
check "200" "#35 ban the address into membership-a with a cause"
api_call POST "/api/ban" "$MASTER_KEY" "{\"target_address\":\"$ADDR_M\",\"group_name\":\"$GROUP_MB\",\"cause\":\"b cause\"}"
check "200" "#35 the same address into membership-b (a second membership, same canonical row)"

api_call GET "/api/ips?groups=$GROUP_MA" "$MASTER_KEY"
check "200" "#35 list membership-a"
check_true "[.[] | select(.target_address == \"$ADDR_M\")] | length == 1" \
    "#35 the address appears once in membership-a"
check_true "[.[] | select(.target_address == \"$ADDR_M\") | has(\"updated_at\") | not] | all" \
    "#35 the response carries no updated_at (last_seen_at is the single timestamp)"
check_true "[.[] | select(.target_address == \"$ADDR_M\") | has(\"ip_record_id\") and has(\"id\")] | all" \
    "#35 each item exposes the membership id and the canonical ip_record_id"

# Cause history: the latest cause wins; a re-report without a cause writes no row and keeps it.
api_call POST "/api/ban" "$MASTER_KEY" "{\"target_address\":\"$ADDR_M\",\"group_name\":\"$GROUP_MA\",\"cause\":\"second cause\"}"
check "200" "#35 re-report into membership-a with a new cause"
api_call POST "/api/ban" "$MASTER_KEY" "{\"target_address\":\"$ADDR_M\",\"group_name\":\"$GROUP_MA\"}"
check "200" "#35 re-report into membership-a with no cause"
api_call GET "/api/ips?groups=$GROUP_MA" "$MASTER_KEY"
check_true "[.[] | select(.target_address == \"$ADDR_M\") | .cause] == [\"second cause\"]" \
    "#35 the reported cause is the latest one, and a cause-less re-report does not clear it"

api_call GET "/api/ips?groups=$GROUP_MA&cause=first" "$MASTER_KEY"
check_true "[.[] | select(.target_address == \"$ADDR_M\")] | length == 1" \
    "#35 cause filter matches an older cause in the membership history"

# Per-group state: soft-deleting membership-a must not touch membership-b.
api_call DELETE "/api/ips" "$MASTER_KEY" "$DEL_A"
check "204" "#35 soft-delete the address from membership-a by address and group"
api_call GET "/api/ips?groups=$GROUP_MA" "$MASTER_KEY"
check_true "[.[] | select(.target_address == \"$ADDR_M\")] | length == 0" \
    "#35 the soft-deleted membership is hidden from membership-a"
api_call GET "/api/ips?groups=$GROUP_MB" "$MASTER_KEY"
check_true "[.[] | select(.target_address == \"$ADDR_M\")] | length == 1" \
    "#35 the same address in membership-b is unaffected by the membership-a delete"

api_call GET "/api/ips?include_deleted=true&groups=$GROUP_MA" "$MASTER_KEY"
check_true "[.[] | select(.target_address == \"$ADDR_M\" and .is_deleted == true)] | length == 1" \
    "#35 include_deleted exposes the soft-deleted membership with its deleted state"

# The route that addressed a record by id is gone: restore and delete must go by address and group.
api_call DELETE "/api/ips/00000000-0000-0000-0000-000000000000" "$MASTER_KEY"
check "405" "#35 DELETE /api/ips/{id} is no longer served (405: the path exists for other methods only)"

# Restore by address and group.
api_call POST "/api/ips/restore" "$MASTER_KEY" "$DEL_A"
check "200" "#35 master restores the membership by address and group"
api_call GET "/api/ips?groups=$GROUP_MA" "$MASTER_KEY"
check_true "[.[] | select(.target_address == \"$ADDR_M\")] | length == 1" \
    "#35 the restored membership is visible in membership-a again"
api_call POST "/api/ips/restore" "$MASTER_KEY" "$DEL_A"
check "400" "#35 restoring a live membership is rejected"

# Totals and freshness, scoped per membership.
api_call GET "/api/ips?groups=$GROUP_MB&include_total=true&limit=1" "$MASTER_KEY"
check "200" "#35 include_total envelope for membership-b"
check_true '(.total >= 1) and (.data | length == 1) and (.total_pages >= 1)' \
    "#35 include_total reports a total across pages, not just the page size"
api_call GET "/api/ips?groups=$GROUP_MB&max_age=3600" "$MASTER_KEY"
check_true "[.[] | select(.target_address == \"$ADDR_M\")] | length == 1" \
    "#35 max_age keeps a membership observed within the window"

# Hard delete removes only this membership; the address stays because membership-b still holds it.
api_call DELETE "/api/ips?hard=true" "$MASTER_KEY" "$DEL_A"
check "204" "#35 master hard-deletes the membership in membership-a"
api_call GET "/api/ips?groups=$GROUP_MB" "$MASTER_KEY"
check_true "[.[] | select(.target_address == \"$ADDR_M\")] | length == 1" \
    "#35 the address survives a hard delete while another group still holds it"

log_section "Summary"
echo -e "$(ts) ${GREEN}Passed: $PASS_COUNT${RESET}   ${RED}Failed: $FAIL_COUNT${RESET}" >&2

if [ "$FAIL_COUNT" -gt 0 ]; then
    err "E2E suite FAILED ($FAIL_COUNT failing check(s))."
    exit 1
fi

log "E2E suite PASSED — all $PASS_COUNT checks succeeded."
exit 0
