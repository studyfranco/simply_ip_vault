//! Parses the dashboard's JavaScript and fails the build on any syntax error.
//!
//! # Why this exists
//!
//! `static/` is served straight off disk by `ServeDir` (`lib.rs`) and is never compiled, linted, or
//! executed by anything else in this repository. That leaves a gap nothing else can cover: a syntax
//! error in `app.js` is invisible to `cargo check`, `cargo clippy`, `cargo test` and the entire
//! `test_e2e.sh` suite, all of which exercise the HTTP API and never parse the file they are serving.
//!
//! That is not hypothetical. Commit `4bdadf0` shipped an `app.js` that could not be parsed at all —
//! a stray backtick inside a template literal terminated the string early — and every one of those
//! gates passed. The dashboard was completely dead in the browser; the first thing to notice was a
//! human opening it.
//!
//! # Why a parser and not an engine
//!
//! `oxc_parser` parses without executing. Running the file instead would immediately fail on
//! `document`, `localStorage` and `crypto.subtle`, none of which exist outside a browser, and
//! distinguishing "this is not valid JavaScript" from "this needs a DOM" would mean pattern-matching
//! on error text. Parsing answers exactly the question worth asking here.
//!
//! # Scope
//!
//! Syntax only. This says nothing about whether the code *works* — a typo'd identifier, a wrong
//! selector, or a broken event wiring all parse cleanly. It closes the "the file cannot load at all"
//! class of failure, which is the one that takes the whole dashboard down at once.

use std::path::{Path, PathBuf};

use oxc_allocator::Allocator;
use oxc_parser::Parser;
use oxc_span::SourceType;

/// Resolves a path relative to the crate root, so the test is independent of the working directory
/// `cargo test` happens to be invoked from.
fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

/// Parses one file and returns its syntax errors, each rendered as `path:line:col message`.
fn syntax_errors(relative: &str) -> Vec<String> {
    let path = repo_path(relative);
    let source = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{relative} must be readable: {e}"));

    let allocator = Allocator::default();
    // `cjs` rather than `mjs`: `app.js` is loaded with a plain <script> tag, so it is a classic
    // script. The distinction is not cosmetic — module source would silently accept `import`/`export`
    // that the browser would reject in this context.
    let parsed = Parser::new(&allocator, &source, SourceType::cjs()).parse();

    // `diagnostics` in oxc >= 0.9x; the field was called `errors` in earlier releases. Named here
    // rather than destructured so a future rename fails to compile instead of silently reporting
    // "no syntax errors" against a list this test never looked at.
    parsed
        .diagnostics
        .iter()
        .map(|err| {
            // `labels` is a plain slice in current oxc (it was `Option<Vec<_>>` in older releases).
            // A diagnostic without a label falls back to offset 0 rather than being dropped: a
            // reported error with an unknown position is still a reported error.
            // `offset()` is a `u32` in current oxc; widened once here so the slicing below stays in
            // `usize` and cannot silently truncate on a large file.
            let offset = (err.labels.first().map_or(0, oxc_span::LabeledSpan::offset) as usize)
                .min(source.len());
            let line = source[..offset].matches('\n').count() + 1;
            let column = offset - source[..offset].rfind('\n').map_or(0, |i| i + 1) + 1;
            format!("{relative}:{line}:{column}  {}", err.message)
        })
        .collect()
}

/// `static/app.js` must parse as valid ECMAScript.
#[test]
fn app_js_has_no_syntax_errors() {
    let errors = syntax_errors("static/app.js");
    assert_eq!(
        errors,
        [] as [String; 0],
        "static/app.js has {} syntax error(s) and will not load in a browser:\n  {}",
        errors.len(),
        errors.join("\n  ")
    );
}

/// The check is only worth having if it actually rejects broken input, so this feeds it the exact
/// defect that got shipped — a backtick inside a template literal, which ends the template early and
/// leaves the following word as a bare identifier.
///
/// Without this, a future refactor could neuter `app_js_has_no_syntax_errors` (wrong path, swallowed
/// errors, an `is_ok()` that is always true) and it would keep passing silently. A guard that has
/// never been shown to fail is not evidence of anything.
#[test]
fn the_syntax_check_rejects_the_defect_it_exists_to_catch() {
    let allocator = Allocator::default();
    let broken = r#"
        function render(rows) {
            return rows.map(r => `
                <td>
                    <!-- `title` carries the full value -->
                    <span title="${r.address}">${r.address}</span>
                </td>
            `).join('');
        }
    "#;

    let parsed = Parser::new(&allocator, broken, SourceType::cjs()).parse();
    assert!(
        !parsed.diagnostics.is_empty(),
        "a backtick inside a template literal must be reported as a syntax error — if this passes, \
         the parser is not actually checking anything"
    );
}

/// A file that does not exist would make `syntax_errors` panic rather than silently report success,
/// but the panic message should name the file. Cheap insurance against the check being pointed at a
/// path that no longer exists after a reorganization.
#[test]
fn the_checked_file_is_where_the_test_thinks_it_is() {
    assert!(
        repo_path("static/app.js").is_file(),
        "static/app.js not found — the syntax check is pointed at a path that does not exist"
    );
}
