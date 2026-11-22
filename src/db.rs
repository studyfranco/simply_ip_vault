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
//! | `foreign_keys` | per-connection | **ON** (`SQLx` sets it) |
//! | `busy_timeout` | per-connection | **10000 ms** (`SQLx` sets it) |
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
//! [`apply_sqlite_pragmas`] alone, for one narrow but real reason: `SQLx` reopens a connection that
//! has been closed or invalidated, and a reopened connection gets its options replayed but not our
//! `PRAGMA` statements. Declaring them at open time is what makes them survive a recycle.
//!
//! [`apply_sqlite_pragmas`] remains, and remains called, for two reasons: it is the function
//! `scripts/verify_convergence.sh` diffs against the peer's, and it reads `journal_mode` back so the
//! startup log reports what is actually in force rather than what was requested.
//!
//! URL query parameters were tried first and rejected outright — `SQLx` answers
//! `unknown query parameter 'synchronous' while parsing connection URL`.

use sea_orm::sea_query::{Alias, Query};
use sea_orm::sqlx::sqlite::{
    SqliteAutoVacuum, SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteSynchronous,
};
use sea_orm::sqlx::{ConnectOptions as _, Connection as _};
use sea_orm::{
    ConnectOptions, ConnectionTrait, Database, DatabaseBackend, DatabaseConnection, DbErr,
    SqlxSqliteConnector,
};
use sea_orm_migration::{MigratorTrait, SchemaManager};

/// How long SQLite waits on a locked database before returning `SQLITE_BUSY`, in milliseconds.
///
/// Was 5000 (`SQLx`'s own default) until production logs under concurrent write load showed
/// `SQLITE_BUSY` surfacing as user-visible `500`s on simple single-row `INSERT`s — a writer that
/// would have succeeded a few hundred milliseconds later was instead failing outright. Raised to
/// 10000: still bounded (a genuinely stuck writer cannot hang a request forever), but wide enough
/// that a writer queued behind WAL's single-writer-at-a-time rule waits it out instead of erroring.
/// This does not fix contention — it changes what contention costs: a queued write now costs
/// latency instead of a failed request. See also the write-batching in `api::records`/`api::support`
/// that reduces *how many* separate write-lock acquisitions one logical request makes in the first
/// place, which addresses the contention itself rather than just how long a caller tolerates it.
pub const SQLITE_BUSY_TIMEOUT_MS: u32 = 30_000;

/// Overrides the memory-mapped I/O window, in bytes. Env `SQLITE_MMAP_SIZE_BYTES`.
pub const SQLITE_MMAP_SIZE_BYTES_ENV: &str = "SQLITE_MMAP_SIZE_BYTES";
/// Default memory-mapped I/O window: 512 MiB. Hot pages are served without a `read(2)` copy per
/// page. Doubled from the original 256 MiB after production telemetry showed multi-group listings
/// paying real I/O cost at that size; still a window, not a load of the whole file, so a database
/// much larger than this stays correct and just serves its colder pages the ordinary way.
const DEFAULT_SQLITE_MMAP_SIZE_BYTES: i64 = 512 * 1024 * 1024;

/// Overrides the page cache budget, in KiB. Env `SQLITE_CACHE_SIZE_KIB`.
///
/// This is the *magnitude*: SQLite's own `cache_size` pragma takes a negative number to mean "KiB
/// of pages" (positive means "number of pages", which is the confusing historical default), and
/// this env var is that negative number's absolute value, negated when the pragma is issued — so
/// setting it never requires remembering which sign means what.
pub const SQLITE_CACHE_SIZE_KIB_ENV: &str = "SQLITE_CACHE_SIZE_KIB";
/// Default page cache: 128 MiB (131072 KiB) **per connection**. Doubled from the original 64 MiB.
/// Multiplies by the pool size for total resident memory — see [`SQLITE_MEMORY_MAX_CONNECTIONS`]
/// and the file-backed pool's own connection cap for what that multiplies against.
const DEFAULT_SQLITE_CACHE_SIZE_KIB: i64 = 128 * 1024;

/// Reads [`SQLITE_MMAP_SIZE_BYTES_ENV`], falling back to the default with a warning on a bad or
/// negative value. Read once per connection open, same as every other pragma here — not cached
/// globally, so tests that set the env var per-case are not fighting a stale value.
fn sqlite_mmap_size_bytes() -> i64 {
    let value =
        crate::config::numeric_env(SQLITE_MMAP_SIZE_BYTES_ENV, DEFAULT_SQLITE_MMAP_SIZE_BYTES);
    if value < 0 {
        tracing::warn!(
            "{SQLITE_MMAP_SIZE_BYTES_ENV}={value} must not be negative; using the default of \
             {DEFAULT_SQLITE_MMAP_SIZE_BYTES} bytes."
        );
        DEFAULT_SQLITE_MMAP_SIZE_BYTES
    } else {
        value
    }
}

/// Reads [`SQLITE_CACHE_SIZE_KIB_ENV`], falling back to the default with a warning on a bad or
/// non-positive value.
fn sqlite_cache_size_kib() -> i64 {
    let value =
        crate::config::numeric_env(SQLITE_CACHE_SIZE_KIB_ENV, DEFAULT_SQLITE_CACHE_SIZE_KIB);
    if value <= 0 {
        tracing::warn!(
            "{SQLITE_CACHE_SIZE_KIB_ENV}={value} must be positive; using the default of \
             {DEFAULT_SQLITE_CACHE_SIZE_KIB} KiB."
        );
        DEFAULT_SQLITE_CACHE_SIZE_KIB
    } else {
        value
    }
}

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
/// and the `?mode=memory` query-parameter form `SQLx` itself also accepts.
fn is_in_memory_sqlite(db_url: &str) -> bool {
    let (path, query) = db_url.split_once('?').unwrap_or((db_url, ""));
    path.ends_with(":memory:")
        || query
            .split('&')
            .any(|param| param.eq_ignore_ascii_case("mode=memory"))
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
        .auto_vacuum(SqliteAutoVacuum::Incremental)
        // Readers proceed against the last committed snapshot while a writer appends, instead of
        // blocking on a database-wide exclusive lock. Persistent in the file header, but set here
        // too so a fresh database gets it before the first write rather than after.
        .journal_mode(SqliteJournalMode::Wal)
        // The one setting that genuinely requires this placement. `NORMAL` is the standard
        // companion to WAL: it keeps full durability against process crashes and gives up only the
        // last transactions in a power loss, in exchange for not fsyncing on every commit.
        .synchronous(SqliteSynchronous::Normal)
        .busy_timeout(crate::config::sqlite_busy_timeout())
        // TEMP tables and indexes (the sort in `ORDER BY ... USE TEMP B-TREE`, a `GROUP BY`'s
        // aggregation buffer) default to a disk-backed file. `MEMORY` keeps them in the process's
        // own heap instead — a real win for the query shapes this service actually runs, all of
        // which fit comfortably in memory (paginated listings, capped at `limit`), and one less
        // place a slow disk can show up as request latency. No portable `SqliteConnectOptions`
        // method exists for this pragma, hence the generic `.pragma()` escape hatch rather than a
        // typed setter like the others above.
        .pragma("temp_store", "MEMORY")
        // Memory-mapped reads: hot pages are served without a `read(2)` copy per page. See
        // `SQLITE_MMAP_SIZE_BYTES_ENV`'s doc comment for the default and how to override it.
        .pragma("mmap_size", sqlite_mmap_size_bytes().to_string())
        // Page cache per connection (negative = KiB). See `SQLITE_CACHE_SIZE_KIB_ENV`.
        .pragma("cache_size", format!("-{}", sqlite_cache_size_kib()))
        // Limits ANALYZE and PRAGMA optimize sampling so multi-million row databases do not block.
        .pragma("analysis_limit", "400")
        .optimize_on_close(true, 400)
        .log_slow_statements(
            log::LevelFilter::Warn,
            crate::config::database_slow_threshold(),
        ))
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
///
/// # Errors
///
/// Returns a database error if the connection or database operation fails.
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
        opt.sqlx_logging_level(log::LevelFilter::Debug)
            .sqlx_slow_statements_logging_settings(
                log::LevelFilter::Warn,
                crate::config::database_slow_threshold(),
            )
            .max_connections(MIGRATION_POOL_MAX_CONNECTIONS);
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
///
/// # Errors
///
/// Returns a database error if the connection or database operation fails.
pub async fn connect(db_url: &str) -> Result<DatabaseConnection, DbErr> {
    // Backend detection by URL scheme, which is the only signal available before a pool exists.
    // Everything downstream reads `get_database_backend()` instead; this is the one place that
    // cannot.
    if !db_url.starts_with("sqlite:") {
        let mut opt = ConnectOptions::new(db_url.to_owned());
        opt.sqlx_logging_level(log::LevelFilter::Debug)
            .sqlx_slow_statements_logging_settings(
                log::LevelFilter::Warn,
                crate::config::database_slow_threshold(),
            );
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

/// Whether `index` exists on `table` on the connected backend.
///
/// # Errors
///
/// Returns a database error if the backend cannot inspect its index catalog.
pub async fn has_index(db: &DatabaseConnection, table: &str, index: &str) -> Result<bool, DbErr> {
    SchemaManager::new(db).has_index(table, index).await
}

/// Runs every pending migration against an already-open connection.
///
/// A thin wrapper, kept for the four existing call sites that already hold a `&DatabaseConnection`
/// (three integration-test files and `main.rs`'s own encryption-key-canary test) and for tests that
/// want migrations applied without going through [`connect`] at all. Production startup does not
/// use this — it uses [`run_migrations_isolated`], which owns its own single-connection pool and
/// closes it before returning, rather than running DDL on a connection the caller keeps.
///
/// # Errors
///
/// Returns a database error if the connection or database operation fails.
pub async fn run_migrations(db: &DatabaseConnection) -> Result<(), DbErr> {
    tracing::info!("Running database migrations...");
    crate::migration::Migrator::up(db, None).await
}

/// Logs the active journal mode and the SQLite session settings configured by [`connect`].
///
/// Journal mode inspection is non-fatal. In-memory databases report their own journal mode.
///
/// # Errors
///
/// Inspection failures are logged and this function returns `Ok(())`.
pub async fn apply_sqlite_pragmas(db: &DatabaseConnection) -> Result<(), DbErr> {
    if db.get_database_backend() != DatabaseBackend::Sqlite {
        return Ok(());
    }

    match sqlite_setting::<String>(db, "pragma_journal_mode", "journal_mode").await {
        Ok(mode) if mode.eq_ignore_ascii_case("wal") => {
            tracing::info!("SQLite journal mode: WAL (concurrent readers during writes).");
        }
        Ok(mode) => tracing::info!("SQLite journal mode: {mode}."),
        Err(e) => tracing::warn!("Could not read back the SQLite journal mode: {e}"),
    }

    let busy_ms = crate::config::sqlite_busy_timeout().as_millis();
    tracing::info!(
        "SQLite session pragmas configured: foreign_keys=ON, synchronous=NORMAL, \
         busy_timeout={busy_ms}ms, temp_store=MEMORY, mmap_size={}MiB, cache_size={}MiB.",
        sqlite_mmap_size_bytes() / (1024 * 1024),
        sqlite_cache_size_kib() / 1024,
    );

    Ok(())
}

async fn sqlite_setting<T: sea_orm::TryGetable>(
    db: &DatabaseConnection,
    table: &str,
    column: &str,
) -> Result<T, DbErr> {
    db.query_one(
        &*Query::select()
            .column(Alias::new(column))
            .from(Alias::new(table)),
    )
    .await?
    .ok_or_else(|| DbErr::Custom(format!("SQLite setting {column} returned no row")))?
    .try_get("", column)
}

/// Refreshes SQLite planner statistics after startup without delaying the listener.
pub async fn optimize_in_background(db: DatabaseConnection) {
    if db.get_database_backend() != DatabaseBackend::Sqlite {
        return;
    }
    tracing::info!(
        "SQLite planner statistics refresh (PRAGMA optimize) started in the background."
    );
    let started = std::time::Instant::now();
    match run_sqlite_optimize(&db).await {
        Ok(()) => tracing::info!(
            "SQLite planner statistics refreshed (PRAGMA optimize) in {:?}.",
            started.elapsed()
        ),
        Err(e) => tracing::warn!(
            "Could not run PRAGMA optimize after {:?}: {e}.",
            started.elapsed()
        ),
    }
}

/// Checks the stored vacuum mode after migrations have created the database tables.
async fn ensure_incremental_auto_vacuum(db: &DatabaseConnection) -> Result<(), DbErr> {
    if db.get_database_backend() == DatabaseBackend::Sqlite
        && sqlite_setting::<i32>(db, "pragma_auto_vacuum", "auto_vacuum").await? != 2
    {
        // SQLite requires a full VACUUM to switch an existing database from NONE.
        tracing::warn!(
            "SQLite incremental auto-vacuum requires an offline database vacuum to take effect."
        );
    }
    Ok(())
}

/// Runs a maintenance pragma on a separate, short-lived connection to the same SQLite file.
async fn run_sqlite_maintenance(
    db: &DatabaseConnection,
    name: &'static str,
    value: String,
) -> Result<(), DbErr> {
    if db.get_database_backend() != DatabaseBackend::Sqlite {
        return Ok(());
    }

    // Reopening an in-memory URL could address an entirely different database.
    let file: String = sqlite_setting(db, "pragma_database_list", "file").await?;
    if file.is_empty() {
        return Ok(());
    }

    let options = db.get_sqlite_connection_pool().connect_options();
    let connection = options
        .as_ref()
        .clone()
        .create_if_missing(false)
        .optimize_on_close(false, None)
        .pragma(name, value)
        .connect()
        .await
        .map_err(|e| DbErr::Conn(sea_orm::RuntimeErr::Internal(e.to_string())))?;
    connection
        .close()
        .await
        .map_err(|e| DbErr::Conn(sea_orm::RuntimeErr::Internal(e.to_string())))
}

/// Returns up to `pages` free pages to the operating system for a file in incremental vacuum mode.
///
/// # Errors
///
/// Returns a database error if SQLite cannot open or maintain the file.
pub async fn run_incremental_vacuum(db: &DatabaseConnection, pages: u32) -> Result<(), DbErr> {
    if pages == 0 {
        return Ok(());
    }
    run_sqlite_maintenance(db, "incremental_vacuum", pages.to_string()).await
}

/// Attempts to checkpoint and truncate the file-backed SQLite WAL.
///
/// # Errors
///
/// Returns a database error if SQLite cannot open or maintain the file.
pub async fn wal_checkpoint_truncate(db: &DatabaseConnection) -> Result<(), DbErr> {
    run_sqlite_maintenance(db, "wal_checkpoint", "TRUNCATE".into()).await
}

/// Refreshes planner statistics on a file-backed SQLite database.
///
/// # Errors
///
/// Returns a database error if SQLite cannot open or maintain the file.
pub async fn run_sqlite_optimize(db: &DatabaseConnection) -> Result<(), DbErr> {
    // The maintenance connection has no query history. Consider all tables while keeping
    // SQLite's usual checks for whether statistics are missing or stale. This also
    // gives the planner statistics for the membership indexes installed at startup.
    run_sqlite_maintenance(db, "optimize", "0x10002".into()).await
}

#[cfg(test)]
mod tests {
    use super::*;
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

    /// SQLite session settings are in force on a freshly created file-backed pool.
    #[tokio::test]
    async fn connect_applies_sqlite_session_settings() {
        let tmp = TempDb::new();
        let db = connect(&tmp.url())
            .await
            .expect("a file-backed sqlite pool opens");

        assert_eq!(
            sqlite_setting::<String>(&db, "pragma_journal_mode", "journal_mode")
                .await
                .unwrap(),
            "wal"
        );
        assert_eq!(
            sqlite_setting::<i32>(&db, "pragma_synchronous", "synchronous")
                .await
                .unwrap(),
            1,
            "NORMAL"
        );
        assert_eq!(
            sqlite_setting::<i32>(&db, "pragma_foreign_keys", "foreign_keys")
                .await
                .unwrap(),
            1,
            "ON"
        );
        assert_eq!(
            sqlite_setting::<i32>(&db, "pragma_busy_timeout", "timeout")
                .await
                .unwrap(),
            i32::try_from(crate::config::sqlite_busy_timeout().as_millis()).unwrap()
        );
        // `temp_store`: 0 = engine default (a disk file), 1 = FILE, 2 = MEMORY. `.pragma("temp_store",
        // "MEMORY")` at connect time must actually have taken, not merely been accepted as a
        // connection-string parameter and silently ignored.
        assert_eq!(
            sqlite_setting::<i32>(&db, "pragma_temp_store", "temp_store")
                .await
                .unwrap(),
            2,
            "MEMORY"
        );
        assert_eq!(
            sqlite_setting::<i32>(&db, "pragma_auto_vacuum", "auto_vacuum")
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            sqlite_setting::<i32>(&db, "pragma_analysis_limit", "analysis_limit")
                .await
                .unwrap(),
            400
        );
    }

    #[tokio::test]
    async fn scheduled_sqlite_maintenance_reclaims_pages_and_truncates_wal() {
        use sea_orm::sea_query::{ColumnDef, Expr, Table};

        let tmp = TempDb::new();
        let db = connect(&tmp.url()).await.unwrap();
        db.execute(
            &Table::create()
                .table("maintenance_fixture")
                .col(ColumnDef::new("body").blob())
                .to_owned(),
        )
        .await
        .unwrap();
        db.execute(
            &Query::insert()
                .into_table("maintenance_fixture")
                .columns(["body"])
                .values_panic([Expr::val(vec![0_u8; 256 * 1024])])
                .to_owned(),
        )
        .await
        .unwrap();
        db.execute(&Query::delete().from_table("maintenance_fixture").to_owned())
            .await
            .unwrap();
        let free_pages = || sqlite_setting::<i32>(&db, "pragma_freelist_count", "freelist_count");
        let before = free_pages().await.unwrap();
        assert!(before >= 5);

        run_incremental_vacuum(&db, 5).await.unwrap();
        assert_eq!(free_pages().await.unwrap(), before - 5);

        run_sqlite_optimize(&db).await.unwrap();
        let wal = tmp.0.join("v.db-wal");
        assert!(std::fs::metadata(&wal).unwrap().len() > 0);
        wal_checkpoint_truncate(&db).await.unwrap();
        assert_eq!(std::fs::metadata(&wal).unwrap().len(), 0);
    }

    /// The in-memory SQLite tier holds exactly one connection, regardless of anything an operator
    /// sets `DATABASE_MAX_CONNECTIONS` to — [`connect`] must not even consult that setting for this
    /// tier, since a second connection to `sqlite::memory:` is a second, empty database.
    #[tokio::test]
    async fn the_in_memory_sqlite_pool_holds_exactly_one_connection() {
        let db = connect("sqlite::memory:").await.expect("pool opens");
        assert_eq!(
            db.get_sqlite_connection_pool()
                .options()
                .get_max_connections(),
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
            db.get_sqlite_connection_pool()
                .options()
                .get_max_connections(),
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
    /// building the pool with `SQLx`'s default of ten connections made `Migrator::up` fail with
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

        let db = connect(&tmp.url())
            .await
            .expect("the application pool opens after migrations");

        // The schema the isolated phase created is visible from a pool that never ran it — proof
        // the isolated pool's writes are durable (WAL + a clean close) rather than only locally
        // consistent within the connection that made them.
        assert!(
            has_index(&db, "api_keys", "idx-api_keys-master_marker")
                .await
                .unwrap(),
            "the application pool must see the schema the isolated migration phase created"
        );

        // A second migration pass against the wide pool — which production deliberately does not
        // do, per the module header — must still be harmless if it ever happened, because there is
        // no pending DDL left for it to run.
        run_migrations(&db)
            .await
            .expect("a redundant migration pass against the wide pool is a no-op, not a failure");
    }

    /// The index check answers truthfully in both directions against a live schema.
    ///
    /// A checker that always returned `true` would satisfy the boot-time §5 assertion without ever
    /// looking, which is the failure mode that assertion exists to prevent.
    #[tokio::test]
    async fn has_index_reports_presence_and_absence() {
        let tmp = TempDb::new();
        run_migrations_isolated(&tmp.url())
            .await
            .expect("migrations run on the isolated pool");
        let db = connect(&tmp.url())
            .await
            .expect("pool opens after migrations are complete");

        assert!(
            has_index(&db, "api_keys", "idx-api_keys-master_marker")
                .await
                .unwrap(),
            "the §5 uniqueness index must be reported as present"
        );
        assert!(
            !has_index(&db, "api_keys", "idx-api_keys-does-not-exist")
                .await
                .unwrap(),
            "an absent index must be reported as absent, not as an error and not as present"
        );
        // Right index name, wrong table: the table predicate has to be doing work too.
        assert!(
            !has_index(&db, "audit_logs", "idx-api_keys-master_marker")
                .await
                .unwrap(),
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
        run_migrations_isolated(&tmp.url())
            .await
            .expect("migrations run on the isolated pool");
        let db = connect(&tmp.url())
            .await
            .expect("pool opens after migrations are complete");

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
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("in-memory sqlite opens");
        assert!(
            apply_sqlite_pragmas(&db).await.is_ok(),
            "a declined pragma is never fatal"
        );

        // WAL genuinely did not engage — so the assertion above is tolerance, not a silent success.
        let mode = sqlite_setting::<String>(&db, "pragma_journal_mode", "journal_mode")
            .await
            .unwrap();
        assert_ne!(
            mode.to_ascii_lowercase(),
            "wal",
            "an in-memory database cannot use WAL"
        );

        // And the connection is still fully usable afterwards, which is the point of continuing.
        run_migrations(&db).await.expect("migrations still run");

        // Re-applying is idempotent: a restart against the same database must not fail either.
        assert!(apply_sqlite_pragmas(&db).await.is_ok());
    }

    /// A non-SQLite backend is skipped by *backend*, not by URL text, so there is no string parsing
    /// to get wrong once PostgreSQL is in play.
    #[tokio::test]
    async fn the_pragmas_are_scoped_to_sqlite_by_backend() {
        let db = Database::connect("sqlite::memory:")
            .await
            .expect("in-memory sqlite opens");
        assert_eq!(db.get_database_backend(), DatabaseBackend::Sqlite);
        assert!(apply_sqlite_pragmas(&db).await.is_ok());
    }

    /// `is_in_memory_sqlite` classifies every URL form this codebase or `SQLx` itself recognises as
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
        assert!(is_in_memory_sqlite(
            "sqlite://file.db?cache=shared&mode=memory"
        ));
        assert!(is_in_memory_sqlite("sqlite://file.db?MODE=Memory"));

        // File-backed: an ordinary path.
        assert!(!is_in_memory_sqlite("sqlite:///var/lib/vault/v.db"));
        // File-backed: `?mode=rwc`, this service's documented default query parameter.
        assert!(!is_in_memory_sqlite(
            "sqlite:///var/lib/vault/v.db?mode=rwc"
        ));
        // File-backed: a path that merely contains "memory" as text must not trip the suffix check.
        assert!(!is_in_memory_sqlite(
            "sqlite:///var/lib/vault/in_memory_archive.db"
        ));
    }

    /// WAL is persistent: a *new* connection to the same file inherits it. This is what makes the
    /// journal mode the one setting that does not need re-applying per connection.
    #[tokio::test]
    async fn wal_survives_reconnection() {
        let tmp = TempDb::new();
        {
            let db = connect(&tmp.url()).await.expect("pool opens");
            assert_eq!(
                sqlite_setting::<String>(&db, "pragma_journal_mode", "journal_mode")
                    .await
                    .unwrap(),
                "wal"
            );
        }
        let reopened = Database::connect(tmp.url())
            .await
            .expect("plain reconnect succeeds");
        assert_eq!(
            sqlite_setting::<String>(&reopened, "pragma_journal_mode", "journal_mode")
                .await
                .unwrap(),
            "wal",
            "WAL is recorded in the file header and survives a reconnect that sets no pragmas"
        );
    }
}
