//! Periodic SQLite housekeeping: incremental vacuum and WAL truncation, every 12 hours.
//!
//! Deleted rows return their pages to SQLite's free list rather than to the operating system, and
//! a busy WAL is never shrunk by the automatic checkpoint. Neither happens on its own in a
//! long-running service, so this worker does both on a fixed schedule. Both operations are no-ops
//! on other backends, so the worker is harmless if the store is ever changed.

use std::time::Duration;

use sea_orm::DatabaseConnection;
use tokio::sync::mpsc;

/// Seconds between maintenance passes. Twelve hours.
pub const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(12 * 60 * 60);

/// Free pages reclaimed per pass. Bounded so one pass never holds the write lock for long.
pub const VACUUM_PAGES_PER_PASS: u32 = 1000;

/// Runs one maintenance pass: reclaim up to [`VACUUM_PAGES_PER_PASS`] free pages, then truncate the
/// WAL. Failures are logged rather than returned, so one bad pass cannot stop the schedule.
pub async fn run_once(db: &DatabaseConnection) {
    if let Err(e) = crate::db::run_incremental_vacuum(db, VACUUM_PAGES_PER_PASS).await {
        tracing::error!("Maintenance: incremental vacuum failed: {e}");
    }
    if let Err(e) = crate::db::wal_checkpoint_truncate(db).await {
        tracing::error!("Maintenance: WAL checkpoint failed: {e}");
    }
}

/// Runs [`run_once`] every [`MAINTENANCE_INTERVAL`] until the shutdown channel closes.
///
/// The first pass is scheduled one interval after start, not immediately: boot already does the
/// schema work, and a pass at every restart would turn a crash loop into a maintenance loop.
pub async fn run_maintenance_worker(db: DatabaseConnection, mut shutdown: mpsc::Receiver<()>) {
    tracing::info!(
        interval_hours = MAINTENANCE_INTERVAL.as_secs() / 3600,
        "Maintenance worker started."
    );
    let mut ticker = tokio::time::interval_at(
        tokio::time::Instant::now() + MAINTENANCE_INTERVAL,
        MAINTENANCE_INTERVAL,
    );
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            _ = ticker.tick() => run_once(&db).await,
            _ = shutdown.recv() => break,
        }
    }
    tracing::info!("Maintenance worker shut down.");
}
