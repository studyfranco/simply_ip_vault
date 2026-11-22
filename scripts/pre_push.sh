#!/usr/bin/env bash
set -euo pipefail

cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.."

rustc --version
cargo clippy --version

cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings

test_log=$(mktemp)
trap 'rm -f -- "$test_log"' EXIT
cargo test --workspace --verbose --color never 2>&1 | tee "$test_log"
if ! grep -Eq '^test result: ok\.' "$test_log" ||
    grep -E '^test result:' "$test_log" | grep -Ev '0 failed; 0 ignored;'; then
    echo "Every test suite must pass with zero failed and zero ignored tests." >&2
    exit 1
fi

cargo audit --deny warnings
bash -n scripts/test_e2e.sh
