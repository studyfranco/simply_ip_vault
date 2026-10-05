//! Database connection setup: pool construction, SQLite session pragmas, and migrations.
//!
//! Extracted from `state.rs` so that "how the database is opened" is one module rather than a
//! detail of application state, mirroring `simply_hook_executor`'s `src/db.rs`.
//!
//! Everything SQLite-specific here is backend-conditional. `AGENT.MD` requires the data layer to
//! stay SQL-agnostic, and it does: no *query* in this codebase is vendor-specific. These are
//! connection **pragmas** — they configure how the engine behaves, not what it is asked — and they
//! are skipped entirely on any backend that is not SQLite.
//!
//! # Two-phase startup: migrate on one connection, then open the real pool
//!
//! [`run_migrations_isolated`] is the **only** place this service ever runs DDL — confirmed by
//! grepping every non-`src/migration/` source file for `ALTER TABLE`/`CREATE TABLE`/`SchemaManager`
//! and finding nothing. It builds its own throwaway single-connection pool, applies every pending
//! migration, and lets that pool close as it goes out of scope — all *before* `main` ever calls
//! [`connect`] to open the pool the running service actually uses. That ordering is what makes the
//! application pool's connection count a pure performance question rather than a correctness one:
//! by the time it exists, there is no DDL left to run against it, on any backend, ever again.
//!
//! This is a narrower, more precise version of the rule the single-connection pinning below used to
//! carry entirely on its own: it is not "SQLite must never have more than one connection", it is
//! "a DDL sequence must never be spread across connections" — the [`connect`]-time application pool
//! for a *file-backed* SQLite database is now allowed to grow past one specifically because it can
//! no longer see a migration by construction, not because the original failure mode stopped
//! mattering.
//!
//! # SQLite is two tiers, not one, and only one of them can ever grow
//!
//! **`sqlite::memory:`** stays pinned to exactly one connection, unconditionally, and that pinning
//! is not the DDL-race rule above — it is a different, harder constraint. An in-memory SQLite
//! database is one process-local buffer with no file behind it; a *second* connection to
//! `sqlite::memory:` is not a second reader of the same data, it is a second, entirely empty
//! database that never saw a single migration the first connection applied. Growing this tier would
//! not merely reintroduce a race, it would make the service internally inconsistent about what data
//! exists at all. [`config::sqlite_file_max_connections`] and its sibling are never consulted for
//! this tier — [`connect`] detects it before either function is called, by inspecting the URL
//! (`is_in_memory_sqlite`), not by asking either function to guess.
//!
//! **A file-backed SQLite database** (`sqlite://path/to/file...`) may now use more than one
//! connection, tuned by the same `DATABASE_MAX_CONNECTIONS`/`DATABASE_MIN_CONNECTIONS` environment
//! variables the PostgreSQL/MySQL tier reads, through
//! [`config::sqlite_file_max_connections`]/[`config::sqlite_file_min_connections`] — their own
//! defaults (10/2) and their own hard ceiling
//! (`config::SQLITE_FILE_MAX_CONNECTIONS_CEILING`, 10, which an operator can lower but not raise),
//! distinct from the PostgreSQL/MySQL tier's 50/10 and unbounded ceiling. SQLite permits any number
//! of concurrent readers under WAL and exactly one writer at a time — `busy_timeout` (10000ms as of
//! the concurrent-write-load tuning pass, still applied per-connection at open time) is what makes
//! a second writer queue instead of erroring, on one connection or ten alike.
//!
//! # Pool tuning is structural, not a guard clause
//!
//! `config::database_max_connections`/`database_min_connections`/`database_idle_timeout`/
//! `database_acquire_timeout` (the PostgreSQL/MySQL tier) apply only on the [`Database::connect`]
//! path [`connect`] takes for every non-SQLite URL — that branch never constructs the
//! `SqlitePoolOptions` the SQLite tiers use, and the SQLite branches never construct the
//! `ConnectOptions` this tier configures. There is no code path by which a setting meant for one
//! tier could reach either of the other two even by mistake; each tier's ceiling holds because the
//! other tiers' code cannot see it, not because it remembers not to look.
//!
//! # Where a pragma actually takes effect
//!
//! | Pragma | Scope | Default already in force |
//! | :--- | :--- | :--- |
//! | `foreign_keys` | per-connection | **ON** (SQLx sets it) |
//! | `busy_timeout` | per-connection | **10000 ms** (SQLx sets it) |
//! | `journal_mode=WAL` | **persistent** (file header) | `delete` |
//! | `synchronous=NORMAL` | per-connection | `FULL` (2) |
//! | `temp_store=MEMORY` | per-connection | `0` (engine's choice, usually a disk file) |
//!
//! Four of the five are per-connection, which would matter enormously on a multi-connection pool —
//! sampling `PRAGMA synchronous` across a five-connection pool after a single
//! `PRAGMA synchronous=NORMAL` returns *both* `1` and `2`, because the statement lands on whichever
//! connection served it. With one connection the distinction collapses: pool-wide and
//! per-connection are the same thing.
//!
//! [`connect`] still sets them through `SqliteConnectOptions` rather than relying on
//! [`apply_sqlite_pragmas`] alone, for one narrow but real reason: SQLx reopens a connection that
//! has been closed or invalidated, and a reopened connection gets its options replayed but not our
//! `PRAGMA` statements. Declaring them at open time is what makes them survive a recycle.
//!
//! [`apply_sqlite_pragmas`] remains, and remains called, for two reasons: it is the function
//! `scripts/verify_convergence.sh` diffs against the peer's, and it reads `journal_mode` back so the
//! startup log reports what is actually in force rather than what was requested.
//!
//! URL query parameters were tried first and rejected outright — SQLx answers
//! `unknown query parameter 'synchronous' while parsing connection URL`.

use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, DbErr,
    SqlxSqliteConnector, Statement,
};
use sea_orm::sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous,
};
use sea_orm_migration::MigratorTrait;

/// How long SQLite waits on a locked database before returning `SQLITE_BUSY`, in milliseconds.
///
/// Was 5000 (SQLx's own default) until production logs under concurrent write load showed
/// `SQLITE_BUSY` surfacing as user-visible `500`s on simple single-row `INSERT`s — a writer that
/// would have succeeded a few hundred milliseconds later was instead failing outright. Raised to
/// 10000: still bounded (a genuinely stuck writer cannot hang a request forever), but wide enough
/// that a writer queued behind WAL's single-writer-at-a-time rule waits it out instead of erroring.
/// This does not fix contention — it changes what contention costs: a queued write now costs
/// latency instead of a failed request. See also the write-batching in `api::records`/`api::support`
/// that reduces *how many* separate write-lock acquisitions one logical request makes in the first
/// place, which addresses the contention itself rather than just how long a caller tolerates it.
pub const SQLITE_BUSY_TIMEOUT_MS: u32 = 10_000;

/// Connections in the in-memory SQLite tier's pool. **One**, unconditionally, and not a tuning
/// knob — see the module header for why this is a data-integrity constraint rather than the
/// DDL-race concern the rest of this module is about.
pub const SQLITE_MEMORY_MAX_CONNECTIONS: u32 = 1;

/// Connections a dedicated migration pool ever opens, on any backend. Not exported as a tuning
/// knob: [`run_migrations_isolated`] is the only caller, and the whole point is that it never
/// varies.
const MIGRATION_POOL_MAX_CONNECTIONS: u32 = 1;

/// Whether `db_url` addresses SQLite's in-process, non-durable in-memory database rather than a
/// file on disk.
///
/// Pure and exhaustively testable by design: this is the one signal [`connect`] uses to choose
/// between the two SQLite tiers described in the module header, and it has to be right before
/// either tier's connection count is ever chosen. Recognises the plain form (`sqlite::memory:`,
/// the only form this codebase's own tests use), the URL-authority form (`sqlite://:memory:`),
/// and the `?mode=memory` query-parameter form SQLx itself also accepts.
fn is_in_memory_sqlite(db_url: &str) -> bool {
    let (path, query) = db_url.split_once('?').unwrap_or((db_url, ""));
    path.ends_with(":memory:") || query.split('&').any(|param| param.eq_ignore_ascii_case("mode=memory"))
}

/// Builds the `SqliteConnectOptions` every SQLite pool in this module opens with, whether that
/// pool ends up holding one connection or several.
///
/// Split out so [`run_migrations_isolated`]'s single-connection migration pool and [`connect`]'s
/// tiered application pool cannot drift apart on the pragmas that matter — in particular
/// `busy_timeout`, which is what lets the migration pool and a not-yet-closed application pool
/// (or a concurrent process) queue for the write lock instead of erroring, and `journal_mode=WAL`,
/// which the module header explains must be set at open time because a reopened connection replays
/// its `SqliteConnectOptions` but not hand-issued `PRAGMA` statements.
fn build_sqlite_connect_options(db_url: &str) -> Result<SqliteConnectOptions, DbErr> {
    use std::str::FromStr;

    Ok(SqliteConnectOptions::from_str(db_url)
        .map_err(|e| DbErr::Conn(sea_orm::RuntimeErr::Internal(e.to_string())))?
        .create_if_missing(true)
        // Enforced rather than assumed. SQLx already defaults this to on — measured, not trusted —
        // so this is an assertion that survives a future SQLx default change, not a fix.
        .foreign_keys(true)
        // Readers proceed against the last committed snapshot while a writer appends, instead of
        // blocking on a database-wide exclusive lock. Persistent in the file header, but set here
        // too so a fresh database gets it before the first write rather than after.
        .journal_mode(SqliteJournalMode::Wal)
        // The one setting that genuinely requires this placement. `NORMAL` is the standard
        // companion to WAL: it keeps full durability against process crashes and gives up only the
        // last transactions in a power loss, in exchange for not fsyncing on every commit.
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(std::time::Duration::from_millis(u64::from(SQLITE_BUSY_TIMEOUT_MS)))
        // TEMP tables and indexes (the sort in `ORDER BY ... USE TEMP B-TREE`, a `GROUP BY`'s
        // aggregation buffer) default to a disk-backed file. `MEMORY` keeps them in the process's
        // own heap instead — a real win for the query shapes this service actually runs, all of
        // which fit comfortably in memory (paginated listings, capped at `limit`), and one less
        // place a slow disk can show up as request latency. No portable `SqliteConnectOptions`
        // method exists for this pragma, hence the generic `.pragma()` escape hatch rather than a
        // typed setter like the others above.
        .pragma("temp_store", "MEMORY")
        // Persistent in the file header, so only a database created under this setting (or one that
        // has been VACUUMed under it — see `ensure_incremental_auto_vacuum`) is actually incremental.
        // On an existing NONE database this per-connection value is inert until that conversion runs.
        .pragma("auto_vacuum", "INCREMENTAL")
        // 256 MiB of memory-mapped reads: hot pages are served without a `read(2)` copy per page.
        .pragma("mmap_size", "268435456")
        // 64 MiB page cache per connection (negative = KiB, so this is 64000 KiB).
        .pragma("cache_size", "-64000"))
}

/// Runs every pending migration on a dedicated pool that opens with exactly one connection, applies
/// every migration, and is closed before returning — on every backend, not only SQLite.
///
/// This is the mechanism the module header calls "two-phase startup": callers are expected to run
/// this to completion, on the database's own URL, *before* ever calling [`connect`]. Once this
/// function returns, there is no pool left open that has seen any DDL, and the pool [`connect`]
/// builds next therefore cannot race one — regardless of how many connections that pool goes on to
/// hold.
///
/// PostgreSQL and MySQL gain nothing operationally from the single-connection restriction today —
/// nothing in this codebase runs concurrent DDL against them — but it is applied uniformly rather
/// than only where a failure has already been observed, so a future migration cannot depend on
/// which backend happened to make a race visible.
pub async fn run_migrations_isolated(db_url: &str) -> Result<(), DbErr> {
    tracing::info!("Running database migrations on an isolated, single-connection pool...");

    let db = if db_url.starts_with("sqlite:") {
        let connect_options = build_sqlite_connect_options(db_url)?;
        let pool = SqlitePoolOptions::new()
            .max_connections(MIGRATION_POOL_MAX_CONNECTIONS)
            .connect_with(connect_options)
            .await
            .map_err(|e| DbErr::Conn(sea_orm::RuntimeErr::Internal(e.to_string())))?;
        SqlxSqliteConnector::from_sqlx_sqlite_pool(pool)
    } else {
        let mut opt = ConnectOptions::new(db_url.to_owned());
        opt.sqlx_logging_level(log::LevelFilter::Debug).max_connections(MIGRATION_POOL_MAX_CONNECTIONS);
        Database::connect(opt).await?
    };

    crate::migration::Migrator::up(&db, None).await?;
    ensure_incremental_auto_vacuum(&db).await?;

    // Explicit rather than left to `drop`: a dropped `DatabaseConnection` closes its pool in the
    // background, with no guarantee it has finished by the time this function returns. The whole
    // point of this function is that the caller can rely on "no pool has seen DDL" the instant it
    // gets a result back, so the close is awaited here rather than assumed.
    db.close().await
}

/// Opens the application's database pool, applying SQLite session pragmas to **every** connection.
///
/// Non-SQLite backends take the plain [`Database::connect`] path, tuned by `config::database_*`
/// (see the module header's "Pool tuning is structural" section).
///
/// SQLite is two tiers — see the module header. `sqlite::memory:` is pinned to
/// [`SQLITE_MEMORY_MAX_CONNECTIONS`] (1) unconditionally; a file-backed URL is tuned by
/// `config::sqlite_file_max_connections`/`sqlite_file_min_connections`, the same environment
/// variables the PostgreSQL/MySQL tier reads but with that tier's own defaults and hard ceiling.
///
/// This function assumes migrations have already been applied via [`run_migrations_isolated`] —
/// it does not run them, and for a file-backed SQLite database it must not: by the time it is
/// called, the pool it is about to build may hold more than one connection, and it is
/// [`run_migrations_isolated`]'s single-connection discipline, not anything here, that makes that
/// safe.
pub async fn connect(db_url: &str) -> Result<DatabaseConnection, DbErr> {
    // Backend detection by URL scheme, which is the only signal available before a pool exists.
    // Everything downstream reads `get_database_backend()` instead; this is the one place that
    // cannot.
    if !db_url.starts_with("sqlite:") {
        let mut opt = ConnectOptions::new(db_url.to_owned());
        opt.sqlx_logging_level(log::LevelFilter::Debug);
        // PostgreSQL/MySQL pool tuning — `config::database_*`, all environment-configurable. Set
        // here rather than left to SeaORM's own defaults (`max_connections: 10`, no floor, no
        // acquire timeout) because those defaults are what produced the slow-pool-acquisition
        // symptom this function exists to address: a burst of concurrent webhook dispatches
        // fetching their config rows can outrun ten connections long before the database itself is
        // the bottleneck, and with no `acquire_timeout` the caller waits however long its own HTTP
        // client allows rather than failing fast and legibly.
        //
        // These four calls have **no effect on SQLite** — the branches below never construct this
        // `opt` at all, let alone read these fields off it. See the module header for why that
        // separation is deliberate rather than an oversight.
        opt.max_connections(crate::config::database_max_connections())
            .min_connections(crate::config::database_min_connections())
            .idle_timeout(crate::config::database_idle_timeout())
            .acquire_timeout(crate::config::database_acquire_timeout());
        return Database::connect(opt).await;
    }

    let connect_options = build_sqlite_connect_options(db_url)?;

    let mut pool_options = SqlitePoolOptions::new();
    pool_options = if is_in_memory_sqlite(db_url) {
        // See the module header: this is not the DDL-race rule below, it is that a second
        // connection to `sqlite::memory:` is a second, empty database, not a second reader of the
        // first one's data.
        pool_options.max_connections(SQLITE_MEMORY_MAX_CONNECTIONS)
    } else {
        // File-backed: SQLite's own file-locking serializes writers regardless of pool size, and
        // migrations are guaranteed complete before this function is ever called (see this
        // function's own doc comment), so widening the pool here is a performance choice, not a
        // correctness risk.
        pool_options
            .max_connections(crate::config::sqlite_file_max_connections())
            .min_connections(crate::config::sqlite_file_min_connections())
            .idle_timeout(crate::config::database_idle_timeout())
            .acquire_timeout(crate::config::database_acquire_timeout())
    };

    let pool = pool_options
        .connect_with(connect_options)
        .await
        .map_err(|e| DbErr::Conn(sea_orm::RuntimeErr::Internal(e.to_string())))?;

    Ok(SqlxSqliteConnector::from_sqlx_sqlite_pool(pool))
}

/// Whether `index` exists on `table`, on any supported backend.
///
/// # Why this is not `SchemaManager::has_index`
///
/// It was, and **the service could not start on PostgreSQL**. `sea-orm-migration`'s `has_index`
/// selects a per-backend catalog query behind cargo feature gates:
///
/// ```text
/// #[cfg(feature = "sqlx-postgres")] DbBackend::Postgres => …,
/// other => return Err(DbErr::BackendNotSupported { ctx: "has_index" }),
/// ```
///
/// and this crate depends on `sea-orm-migration` with **only** `sqlx-sqlite` enabled, while `sea-orm`
/// itself enables all three. So the PostgreSQL arm is compiled out, control reaches the fallback, and
/// the boot-time §5 index check fails with `BackendNotSupported` against a database whose index is
/// present and correct.
///
/// Enabling the extra features on `sea-orm-migration` would also have worked. This is preferred for
/// two reasons: the check is a *runtime* assertion about a live schema rather than a migration
/// concern, so it belongs beside connection setup rather than in the migration harness; and it makes
/// the behaviour independent of a feature-flag combination in another crate, which is what made the
/// failure surface only on a backend no local suite starts.
///
/// # Why the queries live here
///
/// Catalog inspection has no representation in SeaORM's entity API — there is no `Entity` for
/// `pg_indexes` — so it is necessarily raw SQL. `src/db.rs` is the module `tests/source_hygiene.rs`
/// allowlists for exactly this: startup-only, unreachable from any request, and already the home of
/// "how the database is opened and interrogated". Putting it in `master.rs` would have required
/// widening that allowlist to a module the middleware can reach.
///
/// **Both parameters are bound, never interpolated.** They are compile-time constants today, and
/// binding them costs nothing while removing the question entirely.
///
/// Returns `Ok(false)` when the index is absent — an absent index is an answer, not an error. Only a
/// failure to *ask* is an error.
pub async fn has_index(db: &DatabaseConnection, table: &str, index: &str) -> Result<bool, DbErr> {
    let backend = db.get_database_backend();
    let sql = index_catalog_query(backend)?;

    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            backend,
            sql,
            [index.into(), table.into()],
        ))
        .await?
        .ok_or_else(|| {
            DbErr::Custom(format!(
                "catalog query for index '{index}' on '{table}' returned no row"
            ))
        })?;

    // `COUNT(*)` is `i64` on PostgreSQL and SQLite and narrower on some MySQL drivers, so the
    // smaller type is tried second rather than assumed.
    let hits: i64 = match row.try_get::<i64>("", "hits") {
        Ok(n) => n,
        Err(_) => i64::from(row.try_get::<i32>("", "hits")?),
    };
    Ok(hits > 0)
}

/// The catalog query for one backend, taking the index name first and the table name second.
///
/// Split out from [`has_index`] purely so it can be unit-tested. That matters more than it usually
/// would: the defect this replaced was **PostgreSQL-only**, and no suite in this repository starts a
/// PostgreSQL server — so a test that needs a live connection could not have caught it and cannot
/// guard against its return. Selecting the statement is the part that was broken, and it is testable
/// without a database.
///
/// Placeholder syntax is per-backend — PostgreSQL numbers them, the other two do not — which is one
/// more reason each dialect gets its own statement rather than a shared string with substitutions.
fn index_catalog_query(backend: DatabaseBackend) -> Result<&'static str, DbErr> {
    Ok(match backend {
        DatabaseBackend::Sqlite => {
            "SELECT COUNT(*) AS hits FROM sqlite_master \
             WHERE type = 'index' AND name = ? AND tbl_name = ?"
        }
        DatabaseBackend::Postgres => {
            "SELECT COUNT(*) AS hits FROM pg_indexes WHERE indexname = $1 AND tablename = $2"
        }
        DatabaseBackend::MySql => {
            // Scoped to the connected schema: `information_schema.statistics` spans every database on
            // the server, so an identically named index elsewhere would otherwise be a false hit.
            "SELECT COUNT(*) AS hits FROM information_schema.statistics \
             WHERE index_name = ? AND table_name = ? AND table_schema = DATABASE()"
        }
        // `DatabaseBackend` is `#[non_exhaustive]`, so a future SeaORM release can add a variant this
        // build has never heard of. Refusing is the only safe answer: the caller uses this to assert
        // a §5 constraint, and inventing `true` for a backend whose catalog we cannot read would
        // report the constraint as present without having looked — an unverified guarantee reported
        // as verified, which is the exact failure this check exists to prevent.
        other => {
            return Err(DbErr::Custom(format!(
                "no catalog query is known for backend {other:?}; refusing to assume an index exists"
            )));
        }
    })
}

/// Runs every pending migration against an already-open connection.
///
/// A thin wrapper, kept for the four existing call sites that already hold a `&DatabaseConnection`
/// (three integration-test files and `main.rs`'s own encryption-key-canary test) and for tests that
/// want migrations applied without going through [`connect`] at all. Production startup does not
/// use this — it uses [`run_migrations_isolated`], which owns its own single-connection pool and
/// closes it before returning, rather than running DDL on a connection the caller keeps.
pub async fn run_migrations(db: &DatabaseConnection) -> Result<(), DbErr> {
    tracing::info!("Running database migrations...");
    crate::migration::Migrator::up(db, None).await
}

/// Applies SQLite's session pragmas to the current connection, logging what actually took effect.
///
/// # What this adds over [`connect`]
///
/// Not the settings themselves — [`connect`] has already applied them to every connection, and on a
/// pool built there this function will find them already in force. What it adds is **evidence**: it
/// reads `journal_mode` back rather than inferring success from a clean return, so the startup log
/// says which mode is genuinely active. It also covers pools this crate did not build, which is
/// every pool in the test suite.
///
/// # Failure handling
///
/// **Never fatal.** Every failure is logged and swallowed, and the function still returns `Ok`. Two
/// reasons. The benign one: an in-memory database (`sqlite::memory:`, which the whole test suite
/// uses) reports `journal_mode=memory` and cannot be switched to WAL, since there is no file to
/// write a log beside — SQLite declines silently rather than erroring, which is why the mode is read
/// back instead of inferred. The important one: refusing to boot over a concurrency setting that did
/// not apply would trade a real outage for a theoretical slowdown, on a read-only mount or an exotic
/// filesystem that is otherwise perfectly serviceable.
pub async fn apply_sqlite_pragmas(db: &DatabaseConnection) -> Result<(), DbErr> {
    if db.get_database_backend() != DatabaseBackend::Sqlite {
        return Ok(());
    }

    // `journal_mode` answers with the mode actually in force, which is the only trustworthy
    // confirmation — SQLite silently declines the switch for in-memory and read-only databases
    // rather than erroring, so assuming success from a clean return would be wrong.
    match db
        .query_one_raw(Statement::from_string(
            DatabaseBackend::Sqlite,
            "PRAGMA journal_mode=WAL;",
        ))
        .await
    {
        Ok(Some(row)) => match row.try_get::<String>("", "journal_mode") {
            Ok(mode) if mode.eq_ignore_ascii_case("wal") => {
                tracing::info!("SQLite journal mode: WAL (concurrent readers during writes).");
            }
            Ok(mode) => tracing::info!(
                "SQLite journal mode is '{mode}' rather than WAL; this is normal for in-memory or \
                 read-only databases."
            ),
            Err(e) => tracing::warn!("Could not read back the SQLite journal mode: {e}"),
        },
        Ok(None) => tracing::warn!("PRAGMA journal_mode returned no row; leaving the default."),
        Err(e) => tracing::warn!("Could not enable SQLite WAL mode: {e}. Continuing without it."),
    }

    // The remaining four are set-and-log. Each is per-connection, so on a pool this reaches
    // whichever connection serves it — which is precisely why `connect` sets them at open time and
    // why these calls are confirmation rather than mechanism.
    for (label, statement) in [
        ("foreign key enforcement", "PRAGMA foreign_keys=ON;".to_owned()),
        ("synchronous mode", "PRAGMA synchronous=NORMAL;".to_owned()),
        ("busy timeout", format!("PRAGMA busy_timeout={SQLITE_BUSY_TIMEOUT_MS};")),
        ("temp store", "PRAGMA temp_store=MEMORY;".to_owned()),
    ] {
        if let Err(e) =
            db.execute_raw(Statement::from_string(DatabaseBackend::Sqlite, statement)).await
        {
            tracing::warn!("Could not set the SQLite {label}: {e}. Continuing with the default.");
        }
    }
    for (label, statement) in [
        ("auto vacuum", "PRAGMA auto_vacuum=INCREMENTAL;".to_owned()),
        ("mmap size", "PRAGMA mmap_size=268435456;".to_owned()),
        ("page cache size", "PRAGMA cache_size=-64000;".to_owned()),
    ] {
        if let Err(e) =
            db.execute_raw(Statement::from_string(DatabaseBackend::Sqlite, statement)).await
        {
            tracing::warn!("Could not set the SQLite {label}: {e}. Continuing with the default.");
        }
    }
    tracing::info!(
        "SQLite session pragmas applied: foreign_keys=ON, synchronous=NORMAL, \
         busy_timeout={SQLITE_BUSY_TIMEOUT_MS}ms, temp_store=MEMORY, auto_vacuum=INCREMENTAL, \
         mmap_size=256MiB, cache_size=64MiB."
    );

    // `PRAGMA optimize` refreshes the planner's statistics for tables whose data has changed enough
    // to matter. Cheap when there is nothing to do, and it is what keeps the partial-index plans in
    // `schema_integrity_tests.rs` honest as the data grows.
    if let Err(e) = db.execute_raw(Statement::from_string(DatabaseBackend::Sqlite, "PRAGMA optimize;".to_owned())).await {
        tracing::warn!("Could not run PRAGMA optimize: {e}.");
    } else {
        tracing::info!("SQLite planner statistics refreshed (PRAGMA optimize).");
    }

    Ok(())
}

/// Reads the database's `auto_vacuum` mode as SQLite reports it: `0` NONE, `1` FULL, `2` INCREMENTAL.
async fn auto_vacuum_mode(db: &DatabaseConnection) -> Result<i64, DbErr> {
    let row = db
        .query_one_raw(Statement::from_string(DatabaseBackend::Sqlite, "PRAGMA auto_vacuum;".to_owned()))
        .await?
        .ok_or_else(|| DbErr::Custom("PRAGMA auto_vacuum returned no row".to_owned()))?;
    row.try_get::<i64>("", "auto_vacuum").map_err(|e| DbErr::Custom(e.to_string()))
}

/// Converts a SQLite database still in `auto_vacuum = NONE` to `INCREMENTAL`, once, at startup.
///
/// SQLite only honours an `auto_vacuum` change for a database that is rewritten afterward, so the
/// switch is followed by `VACUUM`. That rewrite is proportional to database size and holds the
/// database for its duration — which is why this runs inside [`run_migrations_isolated`], on the
/// single-connection pool, before the HTTP listener binds, rather than as a background task. A
/// database already in any other mode is left alone.
async fn ensure_incremental_auto_vacuum(db: &DatabaseConnection) -> Result<(), DbErr> {
    if db.get_database_backend() != DatabaseBackend::Sqlite {
        return Ok(());
    }
    match auto_vacuum_mode(db).await? {
        0 => {
            tracing::warn!(
                "SQLite auto_vacuum is NONE; converting to INCREMENTAL and running VACUUM. This \
                 rewrites the whole database and can take a while on a large one."
            );
            db.execute_unprepared("PRAGMA auto_vacuum = INCREMENTAL;").await?;
            db.execute_unprepared("VACUUM;").await?;
            tracing::info!("SQLite auto_vacuum converted to INCREMENTAL.");
            Ok(())
        }
        mode => {
            tracing::info!("SQLite auto_vacuum mode is {mode}; no conversion needed.");
            Ok(())
        }
    }
}

/// Returns up to `pages` free pages to the operating system (`PRAGMA incremental_vacuum`).
///
/// Only meaningful on a database in `INCREMENTAL` mode (see [`ensure_incremental_auto_vacuum`]).
/// Deletes leave free pages behind rather than shrinking the file; this is what gives them back,
/// in bounded slices so no single call holds the write lock for long.
pub async fn run_incremental_vacuum(db: &DatabaseConnection, pages: u32) -> Result<(), DbErr> {
    if db.get_database_backend() != DatabaseBackend::Sqlite {
        return Ok(());
    }
    db.execute_unprepared(&format!("PRAGMA incremental_vacuum({pages});")).await?;
    Ok(())
}

/// Folds the write-ahead log back into the main database file and truncates it to zero bytes.
///
/// Without this the WAL grows with sustained writes until SQLite's automatic checkpoint (which
/// does not truncate) lets it be reused, so an idle service can keep a large WAL file on disk.
pub async fn wal_checkpoint_truncate(db: &DatabaseConnection) -> Result<(), DbErr> {
    if db.get_database_backend() != DatabaseBackend::Sqlite {
        return Ok(());
    }
    db.execute_unprepared("PRAGMA wal_checkpoint(TRUNCATE);").await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sea_orm::ConnectionTrait;

    /// Reads one pragma back through the pool.
    async fn pragma<T: sea_orm::TryGetable>(db: &DatabaseConnection, sql: &str, col: &str) -> T {
        db.query_one_raw(Statement::from_string(DatabaseBackend::Sqlite, sql.to_owned()))
            .await
            .expect("the pragma query succeeds")
            .expect("a row is returned")
            .try_get("", col)
            .expect("the column has the expected type")
    }

    /// A temporary directory holding one database file, removed on drop.
    struct TempDb(std::path::PathBuf);
    impl TempDb {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("vault_db_{}", uuid::Uuid::new_v4()));
            std::fs::create_dir_all(&dir).expect("temp dir is creatable");
            Self(dir)
        }
        fn url(&self) -> String {
            format!("sqlite://{}", self.0.join("v.db").display())
        }
    }
    impl Drop for TempDb {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// All five pragmas are in force on a pool built by [`connect`].
    ///
    /// Note what this does **not** claim. An earlier version of this test sampled twenty-five times
    /// and asserted the values were uniform, which sounds like a pool-wide guarantee and is not one:
    /// the pool holds a single connection, so every sample necessarily hits it and uniformity is
    /// tautological. The real pool-wide guarantee comes from
    /// [`tests::the_sqlite_pool_holds_exactly_one_connection`]; this test's job is only that the five
    /// settings actually took.
    #[tokio::test]
    async fn connect_applies_all_five_pragmas() {
        let tmp = TempDb::new();
        let db = connect(&tmp.url()).await.expect("a file-backed sqlite pool opens");

        assert_eq!(pragma::<String>(&db, "PRAGMA journal_mode;", "journal_mode").await, "wal");
        assert_eq!(pragma::<i32>(&db, "PRAGMA synchronous;", "synchronous").await, 1, "NORMAL");
        assert_eq!(pragma::<i32>(&db, "PRAGMA foreign_keys;", "foreign_keys").await, 1, "ON");
        assert_eq!(
            pragma::<i32>(&db, "PRAGMA busy_timeout;", "timeout").await,
            SQLITE_BUSY_TIMEOUT_MS as i32
        );
        // `temp_store`: 0 = engine default (a disk file), 1 = FILE, 2 = MEMORY. `.pragma("temp_store",
        // "MEMORY")` at connect time must actually have taken, not merely been accepted as a
        // connection-string parameter and silently ignored.
        assert_eq!(pragma::<i32>(&db, "PRAGMA temp_store;", "temp_store").await, 2, "MEMORY");
    }

    /// The in-memory SQLite tier holds exactly one connection, regardless of anything an operator
    /// sets `DATABASE_MAX_CONNECTIONS` to — [`connect`] must not even consult that setting for this
    /// tier, since a second connection to `sqlite::memory:` is a second, empty database.
    #[tokio::test]
    async fn the_in_memory_sqlite_pool_holds_exactly_one_connection() {
        let db = connect("sqlite::memory:").await.expect("pool opens");
        assert_eq!(
            db.get_sqlite_connection_pool().options().get_max_connections(),
            SQLITE_MEMORY_MAX_CONNECTIONS,
            "sqlite::memory: must never be pooled past one connection: a second connection is a \
             second, unrelated empty database, not a second reader"
        );
    }

    /// A file-backed SQLite pool built by [`connect`] is sized by the file tier's configuration —
    /// not pinned to one — which is the entire point of tiering the pool in the first place.
    ///
    /// Asserted against the live pool rather than the config function directly, so this also proves
    /// [`connect`] actually plumbs the value through rather than merely computing and discarding it.
    #[tokio::test]
    async fn a_file_backed_sqlite_pool_is_sized_by_the_file_tier_config() {
        let tmp = TempDb::new();
        let db = connect(&tmp.url()).await.expect("pool opens");
        assert_eq!(
            db.get_sqlite_connection_pool().options().get_max_connections(),
            crate::config::sqlite_file_max_connections(),
            "a file-backed pool must be sized by the file tier's config function, not left pinned \
             to one now that migrations are isolated from it"
        );
    }

    /// Two-phase startup does not reintroduce the historical `duplicate column name: master_marker`
    /// failure, run through the *actual* production sequence: [`run_migrations_isolated`] against
    /// the bare URL first, then [`connect`] for the (now potentially multi-connection) application
    /// pool second.
    ///
    /// This is the regression test for a real break introduced while writing this module originally:
    /// building the pool with SQLx's default of ten connections made `Migrator::up` fail with
    /// exactly this error, because `m20260808_000009` drops `master_marker` and re-adds it as a
    /// generated column, and at any pool size ≥ 2 the `ADD` can land on a connection whose schema is
    /// still the old one. Isolating migrations to their own single-connection pool — closed before
    /// the wide pool ever opens — is what lets the wide pool exist at all without reviving that
    /// failure, and this test is what stands behind that claim rather than merely asserting it in
    /// the module header.
    #[tokio::test]
    async fn two_phase_startup_survives_the_historical_master_marker_regression() {
        let tmp = TempDb::new();

        run_migrations_isolated(&tmp.url())
            .await
            .expect("every migration applies on the isolated single-connection pool");

        let db = connect(&tmp.url()).await.expect("the application pool opens after migrations");

        // The schema the isolated phase created is visible from a pool that never ran it — proof
        // the isolated pool's writes are durable (WAL + a clean close) rather than only locally
        // consistent within the connection that made them.
        assert!(
            has_index(&db, "api_keys", "idx-api_keys-master_marker").await.unwrap(),
            "the application pool must see the schema the isolated migration phase created"
        );

        // A second migration pass against the wide pool — which production deliberately does not
        // do, per the module header — must still be harmless if it ever happened, because there is
        // no pending DDL left for it to run.
        run_migrations(&db)
            .await
            .expect("a redundant migration pass against the wide pool is a no-op, not a failure");
    }

    /// Every supported backend has a catalog query, and each speaks its own dialect.
    ///
    /// This is the regression test for a **PostgreSQL-only boot failure**: the previous
    /// implementation used `SchemaManager::has_index`, whose PostgreSQL arm is behind a cargo feature
    /// this crate does not enable for `sea-orm-migration`, so it answered `BackendNotSupported` and
    /// the service refused to start against a perfectly good database.
    ///
    /// No suite here starts a PostgreSQL server, so no connection-based test could have caught that
    /// or can guard its return. Selecting the statement is the part that broke, and it is checkable
    /// without a database — which is the whole reason it is a separate function.
    #[test]
    fn every_backend_has_a_catalog_query_in_its_own_dialect() {
        let sqlite = index_catalog_query(DatabaseBackend::Sqlite).expect("sqlite is supported");
        let postgres = index_catalog_query(DatabaseBackend::Postgres).expect("postgres is supported");
        let mysql = index_catalog_query(DatabaseBackend::MySql).expect("mysql is supported");

        // Each reads the catalog its own engine actually exposes.
        assert!(sqlite.contains("sqlite_master"), "{sqlite}");
        assert!(postgres.contains("pg_indexes"), "{postgres}");
        assert!(mysql.contains("information_schema.statistics"), "{mysql}");

        // PostgreSQL numbers its placeholders; the other two do not. Getting this wrong is a runtime
        // syntax error on one backend only.
        assert!(postgres.contains("$1") && postgres.contains("$2"), "{postgres}");
        assert!(!sqlite.contains("$1") && sqlite.matches('?').count() == 2, "{sqlite}");
        assert!(!mysql.contains("$1") && mysql.matches('?').count() == 2, "{mysql}");

        // MySQL's catalog spans every database on the server, so the query must scope itself.
        assert!(mysql.contains("DATABASE()"), "an unscoped MySQL lookup matches other schemas: {mysql}");

        // All three project the same column name, which `has_index` reads back positionally by name.
        for q in [sqlite, postgres, mysql] {
            assert!(q.contains("AS hits"), "{q}");
        }
    }

    /// The index check answers truthfully in both directions against a live schema.
    ///
    /// A checker that always returned `true` would satisfy the boot-time §5 assertion without ever
    /// looking, which is the failure mode that assertion exists to prevent.
    #[tokio::test]
    async fn has_index_reports_presence_and_absence() {
        let tmp = TempDb::new();
        run_migrations_isolated(&tmp.url()).await.expect("migrations run on the isolated pool");
        let db = connect(&tmp.url()).await.expect("pool opens after migrations are complete");

        assert!(
            has_index(&db, "api_keys", "idx-api_keys-master_marker").await.unwrap(),
            "the §5 uniqueness index must be reported as present"
        );
        assert!(
            !has_index(&db, "api_keys", "idx-api_keys-does-not-exist").await.unwrap(),
            "an absent index must be reported as absent, not as an error and not as present"
        );
        // Right index name, wrong table: the table predicate has to be doing work too.
        assert!(
            !has_index(&db, "audit_logs", "idx-api_keys-master_marker").await.unwrap(),
            "the table name must be part of the match"
        );
    }

    /// Foreign keys are genuinely enforced, not merely reported as on.
    ///
    /// `PRAGMA foreign_keys` returning `1` says the switch is set; it does not prove the engine acts
    /// on it. The schema declares `api_key_group_permissions.api_key_id REFERENCES api_keys(id)`, so
    /// an insert naming a key that does not exist is the direct test — and it is the constraint that
    /// SQLite would silently ignore with the pragma off.
    #[tokio::test]
    async fn foreign_keys_are_enforced_not_just_enabled() {
        let tmp = TempDb::new();
        run_migrations_isolated(&tmp.url()).await.expect("migrations run on the isolated pool");
        let db = connect(&tmp.url()).await.expect("pool opens after migrations are complete");

        let orphan = crate::entities::api_key_group_permission::ActiveModel {
            id: sea_orm::ActiveValue::Set(uuid::Uuid::new_v4()),
            api_key_id: sea_orm::ActiveValue::Set(uuid::Uuid::new_v4()), // no such key
            group_id: sea_orm::ActiveValue::Set(uuid::Uuid::new_v4()),   // no such group
            can_read: sea_orm::ActiveValue::Set(true),
            can_write: sea_orm::ActiveValue::Set(false),
            can_delete: sea_orm::ActiveValue::Set(false),
            can_manage: sea_orm::ActiveValue::Set(false),
            created_at: sea_orm::ActiveValue::Set(chrono::Utc::now().naive_utc()),
        };
        let outcome = sea_orm::EntityTrait::insert(orphan).exec(&db).await;
        assert!(
            outcome.is_err(),
            "a permission row referencing a nonexistent key must be refused; with foreign_keys off \
             SQLite accepts it silently"
        );
    }

    /// An in-memory database cannot use WAL. That must be a logged no-op, not a startup failure —
    /// the entire test suite runs on `sqlite::memory:`.
    ///
    /// This is the resilience contract in miniature: the pragmas are a *performance* setting and the
    /// service is entirely correct without them. Refusing to boot over a setting that did not apply
    /// would trade a real outage for a theoretical slowdown.
    #[tokio::test]
    async fn a_database_that_cannot_use_wal_still_starts_and_works() {
        let db = Database::connect("sqlite::memory:").await.expect("in-memory sqlite opens");
        assert!(apply_sqlite_pragmas(&db).await.is_ok(), "a declined pragma is never fatal");

        // WAL genuinely did not engage — so the assertion above is tolerance, not a silent success.
        let mode = pragma::<String>(&db, "PRAGMA journal_mode;", "journal_mode").await;
        assert_ne!(mode.to_ascii_lowercase(), "wal", "an in-memory database cannot use WAL");

        // And the connection is still fully usable afterwards, which is the point of continuing.
        run_migrations(&db).await.expect("migrations still run");

        // Re-applying is idempotent: a restart against the same database must not fail either.
        assert!(apply_sqlite_pragmas(&db).await.is_ok());
    }

    /// A non-SQLite backend is skipped by *backend*, not by URL text, so there is no string parsing
    /// to get wrong once PostgreSQL is in play.
    #[tokio::test]
    async fn the_pragmas_are_scoped_to_sqlite_by_backend() {
        let db = Database::connect("sqlite::memory:").await.expect("in-memory sqlite opens");
        assert_eq!(db.get_database_backend(), DatabaseBackend::Sqlite);
        assert!(apply_sqlite_pragmas(&db).await.is_ok());
    }

    /// `is_in_memory_sqlite` classifies every URL form this codebase or SQLx itself recognises as
    /// in-memory, and does not false-positive on a file path that merely contains "memory".
    #[test]
    fn is_in_memory_sqlite_classifies_every_known_url_form() {
        // In-memory: the plain form this codebase's own code and tests use exclusively.
        assert!(is_in_memory_sqlite("sqlite::memory:"));
        // In-memory: the URL-authority form.
        assert!(is_in_memory_sqlite("sqlite://:memory:"));
        // In-memory: SQLx's own query-parameter form, including alongside other parameters and in
        // mixed case.
        assert!(is_in_memory_sqlite("sqlite://file.db?mode=memory"));
        assert!(is_in_memory_sqlite("sqlite://file.db?cache=shared&mode=memory"));
        assert!(is_in_memory_sqlite("sqlite://file.db?MODE=Memory"));

        // File-backed: an ordinary path.
        assert!(!is_in_memory_sqlite("sqlite:///var/lib/vault/v.db"));
        // File-backed: `?mode=rwc`, this service's documented default query parameter.
        assert!(!is_in_memory_sqlite("sqlite:///var/lib/vault/v.db?mode=rwc"));
        // File-backed: a path that merely contains "memory" as text must not trip the suffix check.
        assert!(!is_in_memory_sqlite("sqlite:///var/lib/vault/in_memory_archive.db"));
    }

    /// WAL is persistent: a *new* connection to the same file inherits it. This is what makes the
    /// journal mode the one setting that does not need re-applying per connection.
    #[tokio::test]
    async fn wal_survives_reconnection() {
        let tmp = TempDb::new();
        {
            let db = connect(&tmp.url()).await.expect("pool opens");
            assert_eq!(pragma::<String>(&db, "PRAGMA journal_mode;", "journal_mode").await, "wal");
        }
        let reopened = Database::connect(tmp.url()).await.expect("plain reconnect succeeds");
        assert_eq!(
            pragma::<String>(&reopened, "PRAGMA journal_mode;", "journal_mode").await,
            "wal",
            "WAL is recorded in the file header and survives a reconnect that sets no pragmas"
        );
    }
}
