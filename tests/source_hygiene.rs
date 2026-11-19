//! Static policy checks for the Rust sources, Cargo manifest, and browser dashboard.

use std::collections::{BTreeMap, HashSet};
use std::path::{Path, PathBuf};

use oxc_allocator::Allocator;
use oxc_parser::{Parser, config::TokensParserConfig};
use oxc_span::{LabeledSpan, SourceType};

fn repo_path(relative: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(relative)
}

fn read(relative: &str) -> String {
    std::fs::read_to_string(repo_path(relative))
        .unwrap_or_else(|error| panic!("{relative} must be readable: {error}"))
}

fn files(dir: &str, extensions: &[&str], recursive: bool) -> Vec<String> {
    let mut paths = Vec::new();
    collect_files(&repo_path(dir), extensions, recursive, &mut paths);
    paths.sort();
    paths
}

fn collect_files(dir: &Path, extensions: &[&str], recursive: bool, paths: &mut Vec<String>) {
    for entry in dir
        .read_dir()
        .unwrap_or_else(|error| panic!("{}: {error}", dir.display()))
    {
        let entry = entry.expect("directory entry must be readable");
        let path = entry.path();
        if recursive
            && entry
                .file_type()
                .expect("file type must be readable")
                .is_dir()
        {
            collect_files(&path, extensions, recursive, paths);
        } else if path
            .extension()
            .and_then(|ext| ext.to_str())
            .is_some_and(|ext| extensions.contains(&ext))
        {
            paths.push(
                path.strip_prefix(repo_path(""))
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
}

fn src_files() -> Vec<String> {
    files("src", &["rs"], true)
}

fn line_at(source: &str, offset: usize) -> usize {
    source[..offset]
        .bytes()
        .filter(|&byte| byte == b'\n')
        .count()
        + 1
}

#[derive(Clone, Copy)]
struct Token<'a> {
    text: &'a str,
    offset: usize,
}

fn words<'a>(tokens: &[Token<'a>]) -> Vec<&'a str> {
    tokens
        .iter()
        .map(|token| {
            token
                .text
                .strip_prefix("r#")
                .filter(|name| name.starts_with(ident_char))
                .unwrap_or(token.text)
        })
        .collect()
}

fn has_sequence(tokens: &[&str], sequence: &[&str]) -> bool {
    tokens
        .windows(sequence.len())
        .any(|window| window == sequence)
}

fn ident_char(ch: char) -> bool {
    ch.is_alphanumeric() || ch == '_'
}

fn quoted_end(source: &str, quote: char, escapes: bool) -> Option<usize> {
    let mut chars = source.char_indices();
    chars.next();
    while let Some((index, ch)) = chars.next() {
        if ch == quote {
            return Some(index + ch.len_utf8());
        }
        if ch == '\\' && escapes {
            chars.next();
        }
    }
    None
}

fn block_comment_end(source: &str) -> usize {
    let mut offset = 2;
    let mut depth = 1;
    while let Some(index) = source[offset..].find(['/', '*']) {
        offset += index;
        if source[offset..].starts_with("/*") {
            depth += 1;
            offset += 2;
        } else if source[offset..].starts_with("*/") {
            depth -= 1;
            offset += 2;
            if depth == 0 {
                return offset;
            }
        } else {
            offset += 1;
        }
    }
    source.len()
}

fn rust_string(source: &str) -> Option<(usize, &str)> {
    let prefix = usize::from(source.starts_with(['b', 'c']));
    let body = &source[prefix..];
    if let Some(content) = body.strip_prefix('"') {
        return Some(match quoted_end(body, '"', true) {
            Some(end) => (prefix + end, &body[1..end - 1]),
            None => (source.len(), content),
        });
    }
    let raw = body.strip_prefix('r')?;
    let hashes = raw.bytes().take_while(|&byte| byte == b'#').count();
    let content = raw[hashes..].strip_prefix('"')?;
    let closing = format!("\"{}", "#".repeat(hashes));
    let end = content.find(&closing).unwrap_or(content.len());
    Some((
        (prefix + 2 + hashes + end + closing.len()).min(source.len()),
        &content[..end],
    ))
}

fn rust_char_end(source: &str) -> Option<usize> {
    let prefix = usize::from(source.starts_with('b'));
    let content = source[prefix..].strip_prefix('\'')?;
    if content.starts_with('\\') {
        return quoted_end(&source[prefix..], '\'', true).map(|end| prefix + end);
    }
    let width = content.chars().next()?.len_utf8();
    content[width..]
        .starts_with('\'')
        .then_some(prefix + width + 2)
}

fn rust_tokens(source: &str) -> Vec<Token<'_>> {
    let mut tokens = Vec::new();
    let mut offset = 0;
    while let Some(ch) = source[offset..].chars().next() {
        let rest = &source[offset..];
        if ch.is_whitespace() {
            offset += ch.len_utf8();
            continue;
        }
        if rest.starts_with("//") {
            offset += rest.find('\n').unwrap_or(rest.len());
            continue;
        }
        if rest.starts_with("/*") {
            offset += block_comment_end(rest);
            continue;
        }
        let width = if let Some((width, _)) = rust_string(rest) {
            width
        } else if let Some(width) = rust_char_end(rest) {
            width
        } else if let Some(identifier) = rest.strip_prefix("r#")
            && identifier.starts_with(ident_char)
        {
            2 + identifier
                .find(|ch| !ident_char(ch))
                .unwrap_or(identifier.len())
        } else if ident_char(ch) {
            rest.find(|ch| !ident_char(ch)).unwrap_or(rest.len())
        } else {
            ch.len_utf8()
        };
        tokens.push(Token {
            text: &rest[..width],
            offset,
        });
        offset += width;
    }
    tokens
}

/// Returns the index of a closing delimiter, including nested occurrences of the same pair.
fn closing_token(tokens: &[&str], start: usize, open: &str, close: &str) -> Option<usize> {
    let mut depth = 0;
    for (index, &token) in tokens.iter().enumerate().skip(start) {
        if token == open {
            depth += 1;
        } else if token == close {
            depth -= 1;
            if depth == 0 {
                return Some(index);
            }
        }
    }
    None
}

fn is_ignore_attribute(tokens: &[&str]) -> bool {
    match tokens {
        ["ignore", ..] => true,
        ["cfg_attr", "(", arguments @ .., ")"] => split_arguments(arguments)
            .into_iter()
            .skip(1)
            .any(is_ignore_attribute),
        _ => false,
    }
}

fn ignored_test_offsets(tokens: &[Token<'_>]) -> Vec<usize> {
    let code = words(tokens);
    code.iter()
        .enumerate()
        .filter_map(|(index, &token)| {
            if token != "#" {
                return None;
            }
            let tail = &code[index + 1..];
            let tail = tail.strip_prefix(&["!"]).unwrap_or(tail);
            if !tail.starts_with(&["["]) {
                return None;
            }
            let end = closing_token(tail, 0, "[", "]")?;
            is_ignore_attribute(&tail[1..end]).then_some(tokens[index].offset)
        })
        .collect()
}

#[test]
fn rust_sources_never_ignore_tests() {
    for path in src_files().into_iter().chain(files("tests", &["rs"], true)) {
        let source = read(&path);
        let lines: Vec<_> = ignored_test_offsets(&rust_tokens(&source))
            .into_iter()
            .map(|offset| line_at(&source, offset))
            .collect();
        assert!(lines.is_empty(), "{path} ignores tests on lines {lines:?}");
    }
}

#[test]
fn the_ignore_check_finds_direct_and_nested_conditional_attributes() {
    let fixture = r###"
        #[ignore]
        # /* comment */ [r#ignore = "reason"]
        #[cfg_attr(any(test, feature = "slow"), allow(dead_code), ignore)]
        #[cfg_attr(all(), cfg_attr(any(), ignore = "reason"),)]
        #![cfg_attr(test, ignore)]
        #[cfg_attr(ignore, allow(dead_code))]
        #[cfg_attr(test, allow(ignore), doc = "ignore")]
        #[doc = r##"#[ignore]"##]
        // #[ignore]
        /* #[cfg_attr(test, ignore)] */
    "###;
    let lines: Vec<_> = ignored_test_offsets(&rust_tokens(fixture))
        .into_iter()
        .map(|offset| line_at(fixture, offset))
        .collect();
    assert_eq!(lines, [2, 3, 4, 5, 6]);
}

fn test_module_bounds(tokens: &[&str]) -> Option<(usize, usize)> {
    let mut depth = 0;
    for (index, &token) in tokens.iter().enumerate() {
        if depth == 0
            && let Some(mut tail) = tokens[index..].strip_prefix(&["#", "[", "cfg", "(", "test"])
        {
            tail = tail.strip_prefix(&[","]).unwrap_or(tail);
            if let Some(mut item) = tail.strip_prefix(&[")", "]"]) {
                while item.starts_with(&["#", "["]) {
                    let end = closing_token(item, 1, "[", "]")?;
                    item = &item[end + 1..];
                }
                if item.starts_with(&["mod", "tests", "{"]) {
                    return Some((index, tokens.len() - item.len() + 2));
                }
            }
        }
        depth += nesting_change(token);
    }
    None
}

fn test_module_offset(tokens: &[Token<'_>]) -> Option<usize> {
    test_module_bounds(&words(tokens)).map(|(index, _)| tokens[index].offset)
}

fn test_module_is_last(tokens: &[&str]) -> bool {
    test_module_bounds(tokens)
        .is_none_or(|(_, open)| closing_token(tokens, open, "{", "}") == Some(tokens.len() - 1))
}

#[test]
fn every_source_file_places_its_test_module_last() {
    for path in src_files() {
        assert!(
            test_module_is_last(&words(&rust_tokens(&read(&path)))),
            "{path} has code after its test module"
        );
    }
}

#[test]
fn the_test_module_check_rejects_production_code_after_the_module() {
    let module = r#"
        // #[cfg(test)] mod tests {}
        #[cfg(test)] fn helper() {}
        mod sibling { #[cfg(test)] mod tests {} }
        fn production() {}
        #[cfg(test)]
        #[doc = "Fixture module"]
        mod tests { fn check() { let _ = "}"; /* } */ } }
    "#;
    let tokens = rust_tokens(module);
    let offset = test_module_offset(&tokens).unwrap();
    assert!(module[offset..].starts_with("#[cfg(test)]\n        #[doc = \"Fixture module\"]"));
    assert!(test_module_is_last(&words(&tokens)));
    let misplaced = format!("{module} fn hidden() {{}}");
    assert!(!test_module_is_last(&words(&rust_tokens(&misplaced))));
}

fn production_tokens<'s, 'a>(tokens: &'s [Token<'a>]) -> &'s [Token<'a>] {
    let end = test_module_offset(tokens).map_or(tokens.len(), |offset| {
        tokens.partition_point(|token| token.offset < offset)
    });
    &tokens[..end]
}

const FORBIDDEN_PRODUCTION: &[&[&str]] = &[
    &[".", "unwrap", "("],
    &[".", "expect", "("],
    &["panic", "!", "("],
    &["unreachable", "!", "("],
    &["assert", "!", "("],
    &["assert_eq", "!", "("],
    &["assert_ne", "!", "("],
    &["debug_assert", "!", "("],
    &["debug_assert_eq", "!", "("],
    &["debug_assert_ne", "!", "("],
    &["todo", "!", "("],
    &["unimplemented", "!", "("],
    &["dbg", "!", "("],
    &["unsafe", "{"],
    &["unsafe", "fn"],
    &["unsafe", "impl"],
    &["unsafe", "extern"],
    &["unsafe", "trait"],
];

fn forbidden_production_offsets(tokens: &[Token<'_>]) -> Vec<usize> {
    let code = words(production_tokens(tokens));
    code.windows(2)
        .enumerate()
        .filter_map(|(index, pair)| {
            let macro_delimiter =
                pair[1] == "!" && matches!(code.get(index + 2), Some(&("(" | "[" | "{")));
            FORBIDDEN_PRODUCTION
                .iter()
                .any(|pattern| {
                    code[index..].starts_with(pattern)
                        || (macro_delimiter && pattern.len() == 3 && pattern.starts_with(pair))
                })
                .then_some(tokens[index].offset)
        })
        .collect()
}

#[test]
fn no_unwrap_or_expect_in_production_code() {
    for path in src_files() {
        let source = read(&path);
        let lines: Vec<_> = forbidden_production_offsets(&rust_tokens(&source))
            .into_iter()
            .map(|offset| line_at(&source, offset))
            .collect();
        assert!(
            lines.is_empty(),
            "{path} uses forbidden production constructs on lines {lines:?}"
        );
    }
}

#[test]
fn the_production_check_rejects_forbidden_code_and_ignores_literals_and_comments() {
    let fixture = r###"
        // bad.unwrap()
        /* outer /* nested */ panic!() */
        let _ = ("escaped \" .unwrap(", r##"todo!() " unsafe {"##, '}', b'"');
        let _ = x. /* comment */ unwrap ();
        x.r#expect("bad");
        panic!("bad"); todo!{} unimplemented![]; dbg!(x);
        unsafe { f(); } unsafe fn f() {} unsafe impl Trait for T {}
        #[cfg(test)] mod tests { fn allowed() { x.unwrap(); } }
    "###;
    assert_eq!(forbidden_production_offsets(&rust_tokens(fixture)).len(), 9);
}

/// APIs that mean "this line executes raw SQL", per `AGENT.MD`: "Never write vendor-specific raw
/// SQL queries. Zero raw SQL for DML in `src/`." `Expr::cust` is included even though it sits
/// inside the query builder: it splices an uninterpreted fragment into a statement, so it carries
/// exactly the injection risk the builder otherwise removes.
///
/// Ported and strengthened from `example/simply_ip_vault`'s `tests/source_hygiene.rs` (2026-08-17
/// peer test-harness audit — see `AGENT_NOTES.MD`): the original version here matched only the
/// bare marker list. Vault's version additionally scans for the *shape* of hand-written DML inside
/// string literals (below) and pins the allowlist to a documented, freshness-checked reason per
/// entry, after its own predecessors shipped broken twice — see vault's module doc comment.
const RAW_SQL_MARKERS: &[&str] = &[
    "Statement::from_",
    "from_raw_sql",
    "execute_raw",
    "query_raw",
    "query_one_raw",
    "query_all_raw",
    "execute_unprepared",
    "Expr::cust",
    "AssertSqlSafe",
    "raw_sql",
];

/// The **shape** of a DML statement: a leading keyword and the structural word that must follow
/// it. Matching the pair rather than the bare keyword is what makes this usable — a bare-keyword
/// version flags ordinary English error messages ("Cannot delete this endpoint", "no delete
/// access") as violations; a statement has a grammar English almost never reproduces by accident.
const DML_SHAPES: &[(&str, &str)] = &[
    ("SELECT ", " FROM "),
    ("INSERT ", " INTO "),
    ("UPDATE ", " SET "),
    ("DELETE ", " FROM "),
];

fn sql_marker_offsets(tokens: &[Token<'_>]) -> Vec<usize> {
    let code = words(tokens);
    let patterns: Vec<_> = RAW_SQL_MARKERS
        .iter()
        .map(|marker| words(&rust_tokens(marker)))
        .collect();
    code.iter()
        .enumerate()
        .filter_map(|(index, _)| {
            patterns
                .iter()
                .any(|pattern| {
                    code[index..].starts_with(pattern)
                        || (matches!(pattern.as_slice(), ["Expr" | "Statement", ":", ":", _])
                            && code[index..].starts_with(&pattern[..3])
                            && code
                                .get(index + 3)
                                .is_some_and(|name| name.starts_with(pattern[3])))
                })
                .then_some(tokens[index].offset)
        })
        .collect()
}

fn dml_offsets(tokens: &[Token<'_>]) -> Vec<usize> {
    let mut offsets = Vec::new();
    for token in tokens {
        let Some((_, literal)) = rust_string(token.text) else {
            continue;
        };
        let normalized = literal
            .replace("\\n", "\n")
            .replace("\\r", "\r")
            .replace("\\t", "\t")
            .split_whitespace()
            .filter(|word| *word != "\\")
            .collect::<Vec<_>>()
            .join(" ");
        if literal == "SELECT 1" {
            continue;
        }
        let normalized = normalized.to_ascii_uppercase();
        let padded = format!(" {} ", normalized.trim_end_matches(';'));
        let sql_prefixes = [
            "SELECT ",
            "PRAGMA ",
            "VACUUM ",
            "CREATE TABLE ",
            "CREATE INDEX ",
            "CREATE UNIQUE INDEX ",
            "ALTER TABLE ",
            "DROP TABLE ",
            "DROP INDEX ",
            "TRUNCATE TABLE ",
            "REPLACE INTO ",
        ];
        if sql_prefixes
            .iter()
            .any(|prefix| padded[1..].starts_with(prefix))
            || DML_SHAPES.iter().any(|(verb, follower)| {
                padded.match_indices(verb).any(|(index, _)| {
                    index > 0
                        && padded.as_bytes()[index - 1].is_ascii_whitespace()
                        && padded[index..].contains(follower)
                })
            })
        {
            offsets.push(token.offset);
        }
    }
    offsets
}

fn raw_sql_lines(source: &str) -> Vec<usize> {
    let tokens = rust_tokens(source);
    let mut lines: Vec<_> = sql_marker_offsets(&tokens)
        .into_iter()
        .chain(dml_offsets(&tokens))
        .map(|offset| line_at(source, offset))
        .collect();
    lines.sort_unstable();
    lines.dedup();
    lines
}

#[test]
fn no_raw_sql_in_rust_sources_including_migrations() {
    for path in src_files() {
        let lines = raw_sql_lines(&read(&path));
        assert!(
            lines.is_empty(),
            "{path} contains raw SQL on lines {lines:?}"
        );
    }
}

#[test]
fn the_raw_sql_scanner_detects_what_it_is_looking_for() {
    for raw_sql in [
        r#"db.execute_unprepared("DROP TABLE api_keys").await?;"#,
        "db.query_raw(statement).await?;",
        r#"let sql = "SELECT 2";"#,
        r#"let sql = "PRAGMA foreign_keys = OFF";"#,
        r#"let sql = "VACUUM;";"#,
        r#"let sql = "ALTER TABLE api_keys DROP COLUMN name";"#,
        r#"let sql = "DELETE\nFROM api_keys";"#,
        "db.query_one_raw(statement).await?;",
        "db.query_all_raw(statement).await?;",
        "db.execute_raw(statement).await?;",
        "Statement :: from_other(sql);",
        "Expr :: cust_with_values(expr, values);",
        "Key::find().from_raw_sql /* gap */ (statement);",
        r#"let sql = format!("DELETE FROM api_keys WHERE id = {id}");"#,
        r#"let sql = "update api_keys set is_master = 1";"#,
        "let sql = \"DELETE\nFROM api_keys\";",
    ] {
        assert!(!raw_sql_lines(raw_sql).is_empty(), "missed {raw_sql}");
    }
    for prose in [
        r#"let ping = "SELECT 1";"#,
        r#"return Err(AppError::Forbidden("Cannot delete yourself".to_owned()));"#,
        r#""The Master key cannot be deleted through the API".to_owned(),"#,
        r#"let msg = "Deleted the endpoint";"#,
        r#"// db.execute_unprepared("DELETE FROM api_keys");"#,
    ] {
        assert!(raw_sql_lines(prose).is_empty(), "flagged {prose}");
    }
}

/// Parses one file and returns its syntax errors, each rendered as `path:line:col message`.
fn js_syntax_errors(relative: &str, source: &str) -> Vec<String> {
    let allocator = Allocator::default();
    // `cjs`, not `mjs`: app.js is loaded with a plain <script> tag (a classic script), and module
    // source would silently accept `import`/`export` that the browser would reject in this context.
    let parsed = Parser::new(&allocator, source, SourceType::cjs()).parse();

    parsed
        .diagnostics
        .iter()
        .map(|err| {
            let offset =
                (err.labels.first().map_or(0, LabeledSpan::offset) as usize).min(source.len());
            let line = source[..offset].matches('\n').count() + 1;
            let column = offset - source[..offset].rfind('\n').map_or(0, |i| i + 1) + 1;
            format!("{relative}:{line}:{column}  {}", err.message)
        })
        .collect()
}

#[test]
fn app_js_has_no_syntax_errors() {
    let errors = js_syntax_errors("static/app.js", &read("static/app.js"));
    assert!(
        errors.is_empty(),
        "static/app.js has {} syntax error(s) and will not load in a browser:\n  {}",
        errors.len(),
        errors.join("\n  ")
    );
}

/// A syntax check that has never been shown to fail is not evidence of anything: this feeds it a
/// deliberately broken fixture (an unterminated template literal) and asserts it is caught.
#[test]
fn the_syntax_check_rejects_broken_javascript() {
    let broken = r#"
        function render(rows) {
            return rows.map(r => `
                <span title="${r.address}">${r.address}
            `).join('');
        }
        const x = ;
    "#;
    assert!(!js_syntax_errors("broken.js", broken).is_empty());
}

fn literal(token: &str) -> Option<&str> {
    let quote = token.chars().next()?;
    if !matches!(quote, '\'' | '"' | '`') || token.len() < 2 {
        return None;
    }
    token[1..].strip_suffix(quote)
}

// Cargo policy only needs table names, assignments, strings, arrays and inline tables.
fn manifest_tokens(source: &str) -> Vec<&str> {
    let mut tokens = Vec::new();
    let mut rest = source;
    while let Some(ch) = rest.chars().next() {
        let width = match ch {
            '#' => rest.find('\n').unwrap_or(rest.len()),
            '\'' | '"' => {
                let delimiter = if rest.starts_with("'''") {
                    "'''"
                } else if rest.starts_with("\"\"\"") {
                    "\"\"\""
                } else {
                    ""
                };
                if delimiter.is_empty() {
                    quoted_end(rest, ch, ch == '"').unwrap_or(rest.len())
                } else {
                    rest[3..].find(delimiter).map_or(rest.len(), |end| end + 6)
                }
            }
            '\n' | '[' | ']' | '{' | '}' | '=' | '.' | ',' => 1,
            c if c.is_whitespace() => c.len_utf8(),
            _ => rest
                .find(|c: char| c.is_whitespace() || "#[]{}=.,'\"".contains(c))
                .unwrap_or(rest.len()),
        };
        if ch == '\n' || !(ch.is_whitespace() || ch == '#') {
            tokens.push(&rest[..width]);
        }
        rest = &rest[width..];
    }
    tokens
}

fn key_path(tokens: &[&str]) -> String {
    tokens
        .iter()
        .map(|token| literal(token).unwrap_or(token))
        .collect()
}

fn manifest_assignments(source: &str) -> BTreeMap<String, Vec<&str>> {
    let tokens = manifest_tokens(source);
    let mut assignments = BTreeMap::new();
    let mut section = String::new();
    let mut statement = Vec::new();
    let mut depth = 0;
    for token in tokens.into_iter().chain(["\n"]) {
        match token {
            "[" | "{" => depth += 1,
            "]" | "}" => depth -= 1,
            "\n" if depth == 0 => {
                if statement.first() == Some(&"[") {
                    section = key_path(&statement[1..statement.len() - 1]);
                } else if let Some(equals) = statement.iter().position(|&part| part == "=") {
                    let key = key_path(&statement[..equals]);
                    let name = if section.is_empty() {
                        key
                    } else {
                        format!("{section}.{key}")
                    };
                    assignments.insert(name, statement[equals + 1..].to_vec());
                }
                statement.clear();
            }
            _ => {}
        }
        if token != "\n" {
            statement.push(token);
        }
    }
    assignments
}

fn manifest_field<'a>(
    assignments: &BTreeMap<String, Vec<&'a str>>,
    path: &str,
) -> Option<Vec<&'a str>> {
    if let Some(value) = assignments.get(path) {
        return Some(value.clone());
    }
    let (table, key) = path.rsplit_once('.')?;
    let parent = manifest_field(assignments, table)?;
    let fields = parent.strip_prefix(&["{"])?.strip_suffix(&["}"])?;
    split_arguments(fields).into_iter().find_map(|field| {
        let equals = field.iter().position(|&token| token == "=")?;
        (key_path(&field[..equals]) == key).then(|| field[equals + 1..].to_vec())
    })
}

fn check_manifest(source: &str) -> Vec<String> {
    let assignments = manifest_assignments(source);
    let field = |path: &str| manifest_field(&assignments, path);
    let level = |path: &str| {
        field(&format!("{path}.level"))
            .or_else(|| field(path))
            .filter(|value| value.len() == 1)
            .and_then(|value| literal(value[0]))
    };
    let mut violations = Vec::new();
    for (path, expected) in [
        ("package.edition", "2024"),
        ("lints.rust.unsafe_code", "forbid"),
        ("lints.clippy.all", "warn"),
        ("lints.clippy.pedantic", "warn"),
    ] {
        if level(path) != Some(expected) {
            violations.push(format!("{path} must be {expected:?}"));
        }
    }
    for (lint, priority) in [("all", "-2"), ("pedantic", "-1")] {
        let path = format!("lints.clippy.{lint}.priority");
        if field(&path).is_none_or(|value| value.concat() != priority) {
            violations.push(format!("{path} must be {priority}"));
        }
    }
    if field("package.rust-version").is_some() {
        violations.push("package.rust-version must be absent".to_owned());
    }
    let mut clippy_keys = HashSet::new();
    for path in assignments
        .keys()
        .filter_map(|path| path.strip_prefix("lints.clippy."))
    {
        clippy_keys.insert(path.split('.').next().unwrap().to_owned());
    }
    if let Some(clippy) = field("lints.clippy")
        && let Some(body) = clippy
            .strip_prefix(&["{"])
            .and_then(|body| body.strip_suffix(&["}"]))
    {
        for entry in split_arguments(body) {
            if let Some(key) = entry.first() {
                clippy_keys.insert(literal(key).unwrap_or(key).to_string());
            }
        }
    }
    for key in clippy_keys {
        let path = format!("lints.clippy.{key}");
        if level(&path) == Some("allow") {
            violations.push(format!("{path} may not be allow"));
        }
    }
    let sqlx_features = |dependency: &str| -> HashSet<&str> {
        field(&format!("dependencies.{dependency}.features"))
            .into_iter()
            .flatten()
            .filter_map(literal)
            .filter(|feature| feature.starts_with("sqlx-"))
            .collect()
    };
    let orm = sqlx_features("sea-orm");
    let migration = sqlx_features("sea-orm-migration");
    for feature in orm.difference(&migration) {
        violations.push(format!("sea-orm-migration is missing {feature:?}"));
    }
    for feature in migration.difference(&orm) {
        violations.push(format!("sea-orm is missing {feature:?}"));
    }
    violations.sort();
    violations
}

#[test]
fn cargo_manifest_follows_the_lint_and_database_feature_policy() {
    let violations = check_manifest(&read("Cargo.toml"));
    assert!(
        violations.is_empty(),
        "Cargo.toml policy violations: {violations:#?}"
    );
}

#[test]
fn the_manifest_check_rejects_policy_regressions() {
    let good = r#"
        [package]
        edition = '2024' # rust-version = "ignore this"
        [lints.rust]
        unsafe_code = "forbid"
        [lints.clippy]
        all = { priority = -2, level = "warn" }
        pedantic = { level = "warn", priority = -1 }
        [dependencies]
        sea-orm = {features = ["sqlx-sqlite", "sqlx-postgres"]}
        [dependencies.sea-orm-migration]
        features = [
            "sqlx-postgres", # another backend
            'sqlx-sqlite',
        ]
    "#;
    assert!(check_manifest(good).is_empty());
    let bad = good
        .replace("'2024'", "\"2021\"\nrust-version = '1.85'")
        .replace("\"forbid\"", "\"warn\"")
        .replace(
            "pedantic = { level = \"warn\", priority = -1 }",
            "pedantic = 'allow'\nother = { level = \"allow\" }",
        )
        .replace("\"sqlx-postgres\", # another backend", "");
    let violations = check_manifest(&bad);
    assert_eq!(violations.len(), 8, "{violations:#?}");
}

fn model_expectation(code: &[&str], start: usize, end: usize) -> bool {
    let attribute = &code[start..=end];
    let Some(body) = attribute
        .strip_prefix(&[
            "#",
            "[",
            "expect",
            "(",
            "clippy",
            ":",
            ":",
            "struct_excessive_bools",
            ",",
            "reason",
            "=",
        ])
        .and_then(|body| body.strip_suffix(&[")", "]"]))
    else {
        return false;
    };
    let ([reason] | [reason, ","]) = body else {
        return false;
    };
    if literal(reason)
        != Some("SeaORM DeriveEntityModel requires flat 1:1 fields for SQL BOOLEAN columns")
    {
        return false;
    }

    // Attributes on either side of the expectation belong to the same item.
    let mut first = start;
    while first > 0 && code[first - 1] == "]" {
        let Some(previous) = code[..first].iter().rposition(|&token| token == "#") else {
            break;
        };
        if code.get(previous + 1) != Some(&"[")
            || closing_token(code, previous + 1, "[", "]") != Some(first - 1)
        {
            break;
        }
        first = previous;
    }
    let mut next = first;
    let mut derives_entity = false;
    while code[next..].starts_with(&["#", "["]) {
        let Some(close) = closing_token(code, next + 1, "[", "]") else {
            return false;
        };
        let body = &code[next + 2..close];
        if let Some(derives) = body
            .strip_prefix(&["derive", "("])
            .and_then(|body| body.strip_suffix(&[")"]))
        {
            derives_entity |= split_arguments(derives)
                .iter()
                .any(|path| path.last() == Some(&"DeriveEntityModel"));
        }
        next = close + 1;
    }
    if code.get(next) != Some(&"pub") {
        return false;
    }
    next += 1;
    if !derives_entity || !code[next..].starts_with(&["struct", "Model", "{"]) {
        return false;
    }
    closing_token(code, next + 2, "{", "}").is_some_and(|close| {
        split_arguments(&code[next + 3..close])
            .iter()
            .filter(|field| field.ends_with(&[":", "bool"]))
            .count()
            >= 4
    })
}

fn lint_attribute_offsets(path: &str, tokens: &[Token<'_>]) -> Vec<usize> {
    let code = words(tokens);
    let mut violations = Vec::new();
    for (start, _) in code.iter().enumerate().filter(|(_, token)| **token == "#") {
        let inner = code.get(start + 1) == Some(&"!");
        let bracket = start + 1 + usize::from(inner);
        if code.get(bracket) != Some(&"[") {
            continue;
        }
        let Some(end) = closing_token(&code, bracket, "[", "]") else {
            continue;
        };
        let lint_attribute = code[bracket + 1..end]
            .windows(2)
            .any(|pair| matches!(pair, ["allow" | "expect" | "warn" | "deny" | "forbid", "("]));
        let entity = path
            .strip_prefix("src/entities/")
            .is_some_and(|name| !name.contains('/'));
        if lint_attribute && !(entity && model_expectation(&code, start, end)) {
            violations.push(tokens[start].offset);
        }
    }
    violations
}

#[test]
fn rust_files_only_use_lint_attributes_for_derived_models_with_many_bools() {
    for path in src_files().into_iter().chain(files("tests", &["rs"], true)) {
        let source = read(&path);
        let lines: Vec<_> = lint_attribute_offsets(&path, &rust_tokens(&source))
            .into_iter()
            .map(|offset| line_at(&source, offset))
            .collect();
        assert!(
            lines.is_empty(),
            "{path} has lint attributes on lines {lines:?}"
        );
    }
}

#[test]
fn the_clippy_check_rejects_suppressions_outside_the_model_exception() {
    let model = concat!(
        "#[derive(sea_orm::DeriveEntityModel)]\n",
        "#[expect(",
        "clippy::struct_excessive_bools, reason = \"SeaORM DeriveEntityModel requires flat 1:1 fields for SQL BOOLEAN columns\")]\n",
        "pub struct Model { a: bool, b: bool, c: bool, d: bool }"
    );
    let violations =
        |source: &str| lint_attribute_offsets("src/entities/demo.rs", &rust_tokens(source)).len();
    assert_eq!(violations(model), 0);
    assert_eq!(
        lint_attribute_offsets("src/api/demo.rs", &rust_tokens(model)).len(),
        1
    );
    for forbidden in [
        concat!("#[ allow(", "clippy :: too_many_lines)] fn f() {}").to_owned(),
        concat!("#![allow(", "clippy::all)]").to_owned(),
        concat!(
            "#![expect(",
            "clippy::struct_excessive_bools, reason = \"no\")]"
        )
        .to_owned(),
        concat!(
            "#[cfg_attr(test, allow(dead_code, ",
            "clippy::all))] fn f() {}"
        )
        .to_owned(),
        concat!("#![warn(", "missing_docs)]").to_owned(),
        model.replace("d: bool", "d: u32"),
        model.replace("struct Model", "struct Settings"),
        model.replace("DeriveEntityModel", "Clone"),
        model.replace("reason = \"SeaORM DeriveEntityModel requires flat 1:1 fields for SQL BOOLEAN columns\"", "reason = \"\""),
        model.replace("pub struct", "fn intervening() {} pub struct"),
    ] {
        assert_eq!(violations(&forbidden), 1, "missed {forbidden}");
    }
    let ignored = format!("/* {model} */ let _ = r###\"{model}\"###;");
    assert_eq!(violations(&ignored), 0);
}

// Oxc tokens distinguish real calls from comments, quoted examples and regex literals.
fn js_tokens(source: &str) -> Vec<Token<'_>> {
    let allocator = Allocator::default();
    Parser::new(&allocator, source, SourceType::mjs())
        .with_config(TokensParserConfig)
        .parse()
        .tokens
        .iter()
        .filter(|token| token.start() < token.end())
        .map(|token| Token {
            text: &source[token.start() as usize..token.end() as usize],
            offset: token.start() as usize,
        })
        .collect()
}

fn nesting_change(token: &str) -> i32 {
    match token {
        "(" | "[" | "{" => 1,
        ")" | "]" | "}" => -1,
        _ if token.starts_with('`') && token.ends_with("${") => 1,
        _ if token.starts_with('}') && token.ends_with('`') => -1,
        _ => 0,
    }
}

fn top_level_separator(tokens: &[&str], separators: &[&str]) -> Option<usize> {
    let mut depth = 0;
    for (index, &token) in tokens.iter().enumerate() {
        if depth == 0 && separators.contains(&token) {
            return Some(index);
        }
        depth += nesting_change(token);
    }
    None
}

fn split_arguments<'s, 'a>(mut tokens: &'s [&'a str]) -> Vec<&'s [&'a str]> {
    let mut arguments = Vec::new();
    while let Some(comma) = top_level_separator(tokens, &[","]) {
        arguments.push(&tokens[..comma]);
        tokens = &tokens[comma + 1..];
    }
    if !tokens.is_empty() {
        arguments.push(tokens);
    }
    arguments
}

fn calls<'s, 'a>(
    tokens: &'s [&'a str],
    names: &'s [&str],
) -> impl Iterator<Item = (usize, &'s [&'a str])> {
    tokens
        .windows(2)
        .enumerate()
        .filter_map(move |(index, pair)| {
            if pair[1] != "(" || !names.contains(&pair[0]) {
                return None;
            }
            let end = top_level_separator(&tokens[index + 2..], &[")"])? + index + 2;
            Some((index, &tokens[index + 2..end]))
        })
}

fn html_tags(mut source: &str) -> impl Iterator<Item = &str> {
    std::iter::from_fn(move || {
        while let Some((_, after)) = source.split_once('<') {
            source = after;
            if let Some(comment) = source.strip_prefix("!--") {
                source = comment.split_once("-->").map_or("", |(_, rest)| rest);
                continue;
            }
            if !source
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
            {
                continue;
            }
            let mut chars = source.char_indices();
            while let Some((index, ch)) = chars.next() {
                if ch == '>' {
                    let tag = &source[..index];
                    source = &source[index + 1..];
                    return Some(tag);
                }
                if matches!(ch, '\'' | '"') {
                    let quote = ch;
                    for (_, ch) in chars.by_ref() {
                        if ch == quote {
                            break;
                        }
                    }
                }
            }
        }
        None
    })
}

fn html_attributes(tag: &str) -> impl Iterator<Item = (&str, Option<&str>)> {
    let mut rest = tag.trim_start_matches(|ch: char| !ch.is_whitespace());
    std::iter::from_fn(move || {
        rest = rest.trim_start();
        if rest.is_empty() || rest == "/" {
            return None;
        }
        let end = rest
            .find(|ch: char| ch.is_whitespace() || ch == '=')
            .unwrap_or(rest.len());
        let name = &rest[..end];
        rest = rest[end..].trim_start();
        let value = rest.strip_prefix('=').map(|after| {
            rest = after.trim_start();
            if let Some(quote) = rest.chars().next().filter(|&ch| matches!(ch, '\'' | '"')) {
                let end = quoted_end(rest, quote, false).unwrap_or(rest.len());
                let value = &rest[1..end.saturating_sub(1).max(1)];
                rest = &rest[end..];
                value
            } else {
                let end = rest.find(char::is_whitespace).unwrap_or(rest.len());
                let value = &rest[..end];
                rest = &rest[end..];
                value
            }
        });
        Some((name, value))
    })
}

fn html_values<'a>(source: &'a str, attribute: &'a str) -> impl Iterator<Item = &'a str> {
    html_tags(source)
        .flat_map(html_attributes)
        .filter_map(move |(name, value)| {
            name.eq_ignore_ascii_case(attribute)
                .then_some(value)
                .flatten()
        })
}

fn extract_el_ids(source: &str) -> Vec<&str> {
    let tokens = words(&js_tokens(source));
    calls(&tokens, &["el", "getElementById"])
        .filter_map(|(_, args)| literal(args.first()?))
        .filter(|id| !id.contains("${"))
        .collect()
}

fn missing_dom_ids<'a>(js: &'a str, html: &'a str) -> Vec<&'a str> {
    let code = words(&js_tokens(js));
    let markup = code
        .iter()
        .filter_map(|token| literal_start(token).or_else(|| token.strip_prefix('}')));
    let assigned_ids = code.windows(4).filter_map(|window| match window {
        [".", "id", "=", value] => literal(value),
        _ => None,
    });
    let set_attributes = calls(&code, &["setAttribute"]).filter_map(|(_, args)| match args {
        [name, ",", value] if literal(name) == Some("id") => literal(value),
        _ => None,
    });
    let defined: HashSet<_> = html_values(html, "id")
        .chain(markup.flat_map(|markup| html_values(markup, "id")))
        .chain(assigned_ids)
        .chain(set_attributes)
        .collect();
    extract_el_ids(js)
        .into_iter()
        .filter(|id| !defined.contains(id))
        .collect()
}

fn missing_tab_panels(html: &str) -> Vec<&str> {
    let ids: HashSet<_> = html_values(html, "id").collect();
    html_values(html, "data-tab")
        .filter(|tab| !ids.contains(format!("tab-{tab}").as_str()))
        .collect()
}

#[test]
fn dashboard_assets_exist() {
    for path in ["static/app.js", "static/index.html", "static/style.css"] {
        assert!(repo_path(path).is_file(), "{path} must exist");
    }
}

#[test]
fn every_dom_id_referenced_in_app_js_exists_in_index_html() {
    let js = read("static/app.js");
    let html = read("static/index.html");
    assert!(
        !extract_el_ids(&js).is_empty(),
        "expected dashboard DOM lookups"
    );
    let missing = missing_dom_ids(&js, &html);
    assert!(
        missing.is_empty(),
        "DOM lookups reference missing IDs: {missing:?}"
    );
    let missing = missing_tab_panels(&html);
    assert!(
        missing.is_empty(),
        "data-tab values without a matching tab panel: {missing:?}"
    );
}

#[test]
fn the_dom_id_check_rejects_a_reference_to_a_nonexistent_id() {
    let js = r#"
        el('single'); el ("double");
        document.getElementById('native-single');
        document.getElementById("native-double");
        otherel('ignore'); el(`tab-${name}`); el('injected');
        target.innerHTML = '<div id="injected"></div>';
        target.id = 'assigned'; el('assigned');
        target.setAttribute("id", "attribute"); el("attribute");
    "#;
    let html = r#"<div data-tab="missing"></div><div data-tab="present" id="tab-present"></div>"#;
    assert_eq!(
        missing_dom_ids(js, html),
        ["single", "double", "native-single", "native-double"]
    );
    assert_eq!(missing_tab_panels(html), ["missing"]);
}

fn literal_start(token: &str) -> Option<&str> {
    if let Some(content) = literal(token) {
        return Some(content);
    }
    token.strip_prefix('`')?.strip_suffix("${")
}

fn hardcoded_absolute_fetch_calls(source: &str) -> Vec<usize> {
    let tokens = js_tokens(source);
    let code = words(&tokens);
    calls(&code, &["fetch"])
        .filter_map(|(index, args)| {
            literal_start(args.first()?).filter(|arg| arg.starts_with('/'))?;
            Some(line_at(source, tokens[index].offset))
        })
        .collect()
}

#[test]
fn no_hardcoded_absolute_path_bypasses_the_subpath_request_base() {
    let violations = hardcoded_absolute_fetch_calls(&read("static/app.js"));
    assert!(
        violations.is_empty(),
        "hardcoded absolute fetch paths on lines {violations:?}"
    );
}

#[test]
fn the_hardcoded_fetch_check_rejects_a_literal_absolute_path() {
    let js = "fetch('/one');\nfetch \n (\n \"/two\");\nfetch (`/three/${id}`);\nfetch(requestUrl);";
    assert_eq!(hardcoded_absolute_fetch_calls(js), [1, 2, 5]);
}

fn statement_expression<'s, 'a>(tokens: &'s [&'a str]) -> &'s [&'a str] {
    let end = top_level_separator(tokens, &[";", "}"]).unwrap_or(tokens.len());
    &tokens[..end]
}

fn initializer<'s, 'a>(tokens: &'s [&'a str], name: &str) -> Option<&'s [&'a str]> {
    tokens
        .windows(3)
        .position(|window| {
            matches!(window[0], "const" | "let" | "var" | ".") && window[1..] == [name, "="]
        })
        .map(|index| statement_expression(&tokens[index + 3..]))
}

fn function_body<'s, 'a>(tokens: &'s [&'a str], name: &str) -> Option<&'s [&'a str]> {
    let names = [name];
    let (start, params) = calls(tokens, &names).find(|(index, _)| {
        index
            .checked_sub(1)
            .is_some_and(|index| matches!(tokens[index], "function" | "async" | "static"))
    })?;
    let open = start + params.len() + 3;
    if tokens.get(open) != Some(&"{") {
        return None;
    }
    let end = closing_token(tokens, open, "{", "}")?;
    Some(&tokens[open + 1..end])
}

fn has_optional_api_base(html: &str) -> bool {
    html_tags(html)
        .filter(|tag| {
            tag.split_whitespace()
                .next()
                .is_some_and(|name| name.eq_ignore_ascii_case("input"))
        })
        .any(|tag| {
            let attrs: Vec<_> = html_attributes(tag).collect();
            attrs.iter().any(|(name, value)| {
                name.eq_ignore_ascii_case("id") && *value == Some("login-api-base")
            }) && !attrs
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("required"))
        })
}

fn subpath_policy_violations(js: &str, html: &str) -> Vec<&'static str> {
    let tokens = js_tokens(js);
    let code = words(&tokens);
    let pathname = ["window", ".", "location", ".", "pathname"];
    let request_base = ["REQUEST_BASE", "requestBase"].into_iter().find(|name| {
        initializer(&code, name).is_some_and(|expr| {
            has_sequence(expr, &pathname)
                || calls(expr, &["deriveRequestBase"]).any(|_| {
                    function_body(&code, "deriveRequestBase")
                        .is_some_and(|body| has_sequence(body, &pathname))
                })
        })
    });
    let api = function_body(&code, "apiFetch").unwrap_or_default();
    let request_routed = request_base.is_some_and(|base| {
        calls(api, &["fetch"]).any(|(_, args)| {
            let end = top_level_separator(args, &[","]).unwrap_or(args.len());
            let url = &args[..end];
            let target = match url {
                [name] => initializer(api, name).unwrap_or(url),
                _ => url,
            };
            target.contains(&base)
        })
    });
    let signed_with_override = calls(api, &["signRequest"]).any(|(_, args)| {
        let arguments = split_arguments(args);
        let Some(target) = arguments.get(1) else {
            return false;
        };
        let target = if let [name] = **target {
            initializer(api, name).unwrap_or(target)
        } else {
            target
        };
        let uses_request_base = |expr: &[&str]| {
            expr.iter()
                .any(|token| matches!(*token, "REQUEST_BASE" | "requestBase"))
        };
        !uses_request_base(target)
            && ["apiBaseOverride", "signingBase"].iter().any(|base| {
                target.contains(base)
                    && initializer(api, base)
                        .or_else(|| initializer(&code, base))
                        .is_none_or(|expr| !uses_request_base(expr))
            })
    });
    let reads_override_input = |expression: &[&str]| {
        calls(expression, &["el", "getElementById"]).any(|(index, args)| {
            matches!(args, [id] if literal(id) == Some("login-api-base"))
                && expression[index + args.len() + 3..].starts_with(&[".", "value"])
        })
    };
    let override_configurable = calls(&code, &["setApiBaseOverride", "setSigningBase"])
        .any(|(_, args)| reads_override_input(args))
        || code.windows(2).enumerate().any(|(index, window)| {
            matches!(window, ["apiBaseOverride" | "signingBase", "="])
                && reads_override_input(statement_expression(&code[index + 2..]))
        });
    let canonical_v1 = function_body(&code, "signRequest").is_some_and(|body| {
        initializer(body, "message").is_some_and(|message| {
            message.concat() == r"encoder.encode(`${method}\n${path}\n${timestamp}\n${body}`)"
        })
    });
    let mut violations = Vec::new();
    if !request_routed {
        violations.push("fetch must use a request base derived from window.location.pathname");
    }
    if !signed_with_override || !override_configurable || !canonical_v1 {
        violations
            .push("CANONICAL_V1 signing must use the independently configurable signing base");
    }
    if !has_optional_api_base(html) {
        violations.push("index.html must expose an optional login-api-base input");
    }
    violations
}

#[test]
fn dashboard_routes_requests_and_signs_with_independent_bases() {
    let js = read("static/app.js");
    let html = read("static/index.html");
    let violations = subpath_policy_violations(&js, &html);
    assert!(violations.is_empty(), "{violations:#?}");
}

#[test]
fn the_subpath_check_rejects_a_shared_signing_base_and_a_required_override() {
    let js = r#"
        const requestBase = window.location.pathname;
        let signingBase = '';
        function save() { signingBase = el("login-api-base").value; }
        function signRequest(method, path, timestamp, body) {
            const message = encoder.encode(`${method}\n${path}\n${timestamp}\n${body}`);
            return hmac(secret, textToBytes(message));
        }
        function apiFetch(path) {
            const target = `${signingBase}${path}`;
            const signature = signRequest(method, target, timestamp, body);
            return fetch(`${requestBase}${path}`, { headers: { signature } });
        }
    "#;
    let html = r#"<input id="login-api-base">"#;
    assert!(subpath_policy_violations(js, html).is_empty());
    let shared = js.replace("${signingBase}", "${requestBase}");
    let required = html.replace("<input", "<input REQUIRED");
    assert_eq!(subpath_policy_violations(&shared, &required).len(), 2);
    let no_override = js.replace("signingBase = el", "unused = el");
    assert_eq!(subpath_policy_violations(&no_override, html).len(), 1);
    let no_subpath = js.replace("window.location.pathname", "'/'");
    assert_eq!(subpath_policy_violations(&no_subpath, html).len(), 1);
}

fn key_route(tokens: &[&str]) -> bool {
    tokens
        .iter()
        .filter_map(|token| literal_start(token).or_else(|| token.strip_prefix('}')))
        .any(|part| {
            ["/api/keys", "/keys"].into_iter().any(|prefix| {
                let Some(start) = part.find(prefix) else {
                    return false;
                };
                let tail = &part[start + prefix.len()..];
                tail.is_empty() || tail.starts_with(['/', '?', '`'])
            })
        })
}

fn visibly_assigned<'s, 'a>(
    code: &'s [&'a str],
    before: usize,
    name: &'s str,
) -> impl Iterator<Item = (usize, &'s [&'a str])> {
    code[..before]
        .windows(2)
        .enumerate()
        .filter_map(move |(index, window)| {
            if window != [name, "="] || !visible_at(code, index, before) {
                return None;
            }
            Some((index, statement_expression(&code[index + 2..before])))
        })
}

fn visible_at(code: &[&str], definition: usize, use_at: usize) -> bool {
    // An initializer or field assignment in a sibling block cannot reach this call.
    let mut depth = 0;
    for &token in &code[definition..use_at] {
        match token {
            "{" => depth += 1,
            "}" if depth == 0 => return false,
            "}" => depth -= 1,
            _ => {}
        }
    }
    true
}

fn is_master_field(token: &str) -> bool {
    literal(token).unwrap_or(token) == "is_master"
}

fn contains_master_payload_field(expression: &[&str]) -> bool {
    let mut nesting = Vec::new();
    for (index, &token) in expression.iter().enumerate() {
        if is_master_field(token) && index > 0 {
            let previous = expression[index - 1];
            let next = expression.get(index + 1);
            let ordinary = nesting.last() == Some(&"{")
                && matches!(previous, "{" | ",")
                && matches!(next, Some(&(":" | "," | "}")));
            let computed = nesting.ends_with(&["{", "["])
                && previous == "["
                && expression[index + 1..].starts_with(&["]", ":"]);
            if ordinary || computed {
                return true;
            }
        }
        match nesting_change(token) {
            1 => nesting.push(token),
            -1 => {
                nesting.pop();
            }
            _ => {}
        }
    }
    false
}

fn payload_has_master(code: &[&str], before: usize, expression: &[&str]) -> bool {
    if contains_master_payload_field(expression) {
        return true;
    }
    let references = expression.iter().enumerate().filter_map(|(index, &token)| {
        let previous = index.checked_sub(1).and_then(|index| expression.get(index));
        let identifier = token
            .chars()
            .next()
            .is_some_and(|ch| ch.is_alphabetic() || ch == '_');
        (identifier
            && !matches!(previous, Some(&("." | "?.")))
            && !matches!(expression.get(index + 1), Some(&(":" | "." | "?." | "["))))
        .then_some(token)
    });
    for name in references {
        if visibly_assigned(code, before, name)
            .any(|(at, value)| payload_has_master(code, at, value))
        {
            return true;
        }
        if code[..before]
            .windows(5)
            .enumerate()
            .any(|(index, window)| {
                window[0] == name
                    && visible_at(code, index, before)
                    && ((window[1] == "." && is_master_field(window[2]) && window[3] == "=")
                        || (window[1] == "["
                            && is_master_field(window[2])
                            && window[3..] == ["]", "="]))
            })
        {
            return true;
        }
    }
    false
}

fn key_payloads_with_master(source: &str) -> Vec<usize> {
    let tokens = js_tokens(source);
    let code = words(&tokens);
    calls(&code, &["apiCall", "apiFetch", "fetch"]).filter_map(|(index, args)| {
        let args = split_arguments(args);
        let (route, payload) = match (code[index], args.as_slice()) {
            ("apiCall", [method, route, payload, ..])
                if method.first().and_then(|token| literal(token)).is_some_and(|method| matches!(method, "POST" | "PUT" | "PATCH")) =>
            {
                (*route, *payload)
            }
            ("fetch" | "apiFetch", [route, options, ..]) => (*route, *options),
            _ => return None,
        };
        let is_key_route = key_route(route) || matches!(route, [name] if visibly_assigned(&code, index, name).any(|(_, value)| key_route(value)));
        (is_key_route && payload_has_master(&code, index, payload)).then(|| line_at(source, tokens[index].offset))
    }).collect()
}

#[test]
fn the_dashboard_never_sends_is_master_in_a_key_payload() {
    let violations = key_payloads_with_master(&read("static/app.js"));
    assert!(
        violations.is_empty(),
        "key payloads send is_master on lines {violations:?}"
    );
}

#[test]
fn the_key_payload_check_rejects_is_master_fields_but_permits_reads() {
    let js = r#"
apiCall('POST', '/api/keys', { is_master: true });
const flags = { 'is_master': true };
const payload = { name: 'example', ...flags };
apiCall("PUT", `/api/keys/${key.id}`, payload);
const changed = {};
changed["is_master"] = localFlag;
apiCall("PATCH", "/api/keys/42", changed);
fetch('/api/keys', {method: 'POST', body: JSON.stringify({is_master})});
apiCall('POST', '/api/settings', { is_master: true });
apiCall('POST', '/api/keys', { name: k.is_master ? 'master' : 'regular' });
if (me.is_master) render();
const row = { is_master: true };
apiCall('POST', '/api/keys', { name: row.is_master ? 'master' : 'regular' });
"#;
    assert_eq!(key_payloads_with_master(js), [2, 5, 8, 9]);
    let dashboard_call = r#"this.apiFetch(`/keys/${id}`, { method: "PUT", body: JSON.stringify({ "is_master": true }) });"#;
    assert_eq!(key_payloads_with_master(dashboard_call), [1]);
}

const FORBIDDEN_ASSET_MARKERS: &[&str] = &[
    "fonts.googleapis",
    "fonts.gstatic",
    "cdn.jsdelivr",
    "unpkg.com",
    "cdnjs.cloudflare",
    "data:image/svg+xml",
];

fn external_url(value: &str) -> bool {
    let value = value.trim_start().to_ascii_lowercase();
    ["http://", "https://", "//", "ws://", "wss://"]
        .iter()
        .any(|scheme| value.starts_with(scheme))
}

fn css_asset_violations(source: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    let lower = source.to_ascii_lowercase();
    let mut rest = lower.as_str();
    while let Some(ch) = rest.chars().next() {
        if let Some(comment) = rest.strip_prefix("/*") {
            rest = comment.split_once("*/").map_or("", |(_, rest)| rest);
        } else if matches!(ch, '\'' | '"') {
            rest = &rest[quoted_end(rest, ch, true).unwrap_or(rest.len())..];
        } else if ch == '@'
            && rest
                .strip_prefix("@import")
                .is_some_and(|after| !after.starts_with(|ch| ident_char(ch) || ch == '-'))
        {
            violations.push("CSS @import");
            rest = &rest["@import".len()..];
        } else if ident_char(ch) || ch == '-' {
            let end = rest
                .find(|ch| !(ident_char(ch) || ch == '-'))
                .unwrap_or(rest.len());
            if &rest[..end] == "url"
                && let Some(value) = rest[end..].trim_start().strip_prefix('(')
            {
                let value = value
                    .trim_start()
                    .trim_start_matches(['\'', '"'])
                    .trim_start();
                if external_url(value) {
                    violations.push("external CSS url()");
                }
            }
            rest = &rest[end..];
        } else {
            rest = &rest[ch.len_utf8()..];
        }
    }
    violations
}

fn html_asset_violations(source: &str) -> Vec<&'static str> {
    let mut violations = Vec::new();
    for tag in html_tags(source) {
        let name = tag
            .split_whitespace()
            .next()
            .unwrap_or_default()
            .to_ascii_lowercase();
        for (attribute, value) in html_attributes(tag) {
            let Some(value) = value else { continue };
            let attr = attribute.to_ascii_lowercase();
            if attr == "style" {
                violations.extend(css_asset_violations(value));
            }
            if matches!(attr.as_str(), "src" | "poster" | "background")
                || (attr == "data" && name == "object")
                || (matches!(attr.as_str(), "href" | "xlink:href")
                    && matches!(
                        name.as_str(),
                        "link" | "script" | "use" | "image" | "feimage" | "base"
                    ))
            {
                if external_url(value) {
                    violations.push("external HTML resource");
                }
            } else if matches!(attr.as_str(), "srcset" | "imagesrcset")
                && value.split(',').any(external_url)
            {
                violations.push("external HTML source set");
            }
        }
    }
    violations
}

fn js_asset_violations(source: &str) -> Vec<&'static str> {
    let code = words(&js_tokens(source));
    let is_external = |token| literal_start(token).is_some_and(external_url);
    let mut violations = Vec::new();
    for (_, args) in calls(
        &code,
        &[
            "fetch",
            "WebSocket",
            "EventSource",
            "import",
            "importScripts",
            "setAttribute",
        ],
    ) {
        let external_argument = args.first().is_some_and(|&token| is_external(token));
        let external_attribute = matches!(args, [name, ",", value, ..]
            if matches!(literal(name), Some("src" | "href")) && is_external(value));
        if external_argument || external_attribute {
            violations.push("external JavaScript call");
        }
    }
    for window in code.windows(3) {
        if (matches!(literal(window[0]).unwrap_or(window[0]), "src" | "href")
            && matches!(window[1], "=" | ":")
            && is_external(window[2]))
            || (window[0] == "from" && is_external(window[1]))
            || (window[0] == "import" && is_external(window[1]))
        {
            violations.push("external JavaScript resource");
        }
    }
    for window in code.windows(5) {
        if matches!(window, ["[", name, "]", "=" | ":", value]
            if matches!(literal(name), Some("src" | "href")) && is_external(value))
        {
            violations.push("external JavaScript resource");
        }
    }
    for token in code {
        if let Some(markup) = literal_start(token).or_else(|| token.strip_prefix('}')) {
            violations.extend(html_asset_violations(markup));
        }
    }
    violations
}

fn asset_violations(path: &str, source: &str) -> Vec<&'static str> {
    let lower = source.to_ascii_lowercase();
    let mut violations: Vec<_> = FORBIDDEN_ASSET_MARKERS
        .iter()
        .copied()
        .filter(|marker| lower.contains(marker))
        .collect();
    let extension = Path::new(path).extension().and_then(|ext| ext.to_str());
    if extension == Some("css") {
        violations.extend(css_asset_violations(source));
    } else if extension == Some("js") {
        violations.extend(js_asset_violations(source));
    } else if extension == Some("html") {
        violations.extend(html_asset_violations(source));
        for (tag, close) in [("style", "</style"), ("script", "</script")] {
            for (start, _) in lower.match_indices(&format!("<{tag}")) {
                if let Some((head, body)) = source[start + 1..].split_once('>')
                    && head
                        .split_whitespace()
                        .next()
                        .is_some_and(|name| name.eq_ignore_ascii_case(tag))
                    && let Some(end) = lower[source.len() - body.len()..].find(close)
                {
                    if tag == "style" {
                        violations.extend(css_asset_violations(&body[..end]));
                    } else {
                        violations.extend(js_asset_violations(&body[..end]));
                    }
                }
            }
        }
    }
    violations
}

#[test]
fn frontend_has_no_external_assets_or_svg_data_uris() {
    for path in files("static", &["html", "css", "js"], false) {
        let violations = asset_violations(&path, &read(&path));
        assert!(
            violations.is_empty(),
            "{path} contains forbidden assets: {violations:?}"
        );
    }
}

#[test]
fn the_offline_asset_check_rejects_external_resources_and_svg_data_uris() {
    for (path, input) in [
        ("bad.css", "@IMPORT 'local.css';"),
        (
            "bad.css",
            ".x { background: URL( '//example.org/bg.png' ); }",
        ),
        ("bad.css", ".x { src: url(HTTPS://example.org/font); }"),
        (
            "bad.html",
            r#"<script async src = "//example.org/js"></script>"#,
        ),
        ("bad.html", "<link href='http://example.org/css'>"),
        (
            "bad.html",
            r#"<img srcset="local.png 1x, https://example.org/large.png 2x">"#,
        ),
        (
            "bad.html",
            "<style> .x { background: url(https://example.org/bg) } </style>",
        ),
        (
            "bad.html",
            "<script> const s = new WebSocket('wss://example.org/stream'); </script>",
        ),
        ("bad.js", "fetch (\n 'https://example.org/api');"),
        (
            "bad.js",
            "new EventSource(`https://example.org/events/${id}`);",
        ),
        ("bad.js", "import x from 'https://example.org/js';"),
        ("bad.js", "import('https://example.org/js');"),
        ("bad.js", "script.src = 'https://example.org/js';"),
        ("bad.js", "link['href'] = 'http://example.org/css';"),
        (
            "bad.js",
            r#"target.innerHTML = '<img src="https://example.org/image">';"#,
        ),
        ("bad.js", "const image = 'data:image/svg+xml,<svg></svg>';"),
    ] {
        assert!(!asset_violations(path, input).is_empty(), "missed {input}");
    }
    for marker in FORBIDDEN_ASSET_MARKERS {
        assert!(!asset_violations("bad.css", marker).is_empty());
    }
    for (path, input) in [
        (
            "good.css",
            "/* @import 'old.css'; */ .x {background: url('local.png')}",
        ),
        (
            "good.html",
            r#"<link rel="icon" href="favicon.svg"><script src="app.js"></script>"#,
        ),
        (
            "good.js",
            "fetch(requestUrl); /* fetch('https://example.org'); */",
        ),
        (
            "good.js",
            "const prose = 'Open over https:// for a secure context';",
        ),
    ] {
        assert!(asset_violations(path, input).is_empty(), "flagged {input}");
    }
}
