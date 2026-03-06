//! `ectoledger serve` — run the Observer dashboard without an agent.

use crate::pool;
use crate::server;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

/// Run the standalone Observer dashboard HTTP server (PostgreSQL backend).
///
/// Blocks until Ctrl-C is received or the cancellation token is triggered.
pub async fn run(
    pool: sqlx::PgPool,
    metrics: Arc<crate::metrics::Metrics>,
    cancel: CancellationToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    run_with_pool(pool::DatabasePool::Postgres(pool), metrics, cancel).await
}

/// Run the standalone Observer dashboard with any `DatabasePool` variant
/// (PostgreSQL **or** SQLite).
///
/// Called directly from `main.rs` when `DATABASE_URL` uses a `sqlite:` scheme,
/// or indirectly via `run()` for the Postgres path.
///
/// Blocks until the cancellation token is triggered (fired by the Ctrl-C
/// handler in `main.rs`).  Does **not** install its own signal handler to
/// avoid duplicate SIGINT listeners.
pub async fn run_with_pool(
    pool: pool::DatabasePool,
    metrics: Arc<crate::metrics::Metrics>,
    cancel: CancellationToken,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let bind_host = crate::config::bind_host();
    let bind_port = crate::config::bind_port();
    let bind_addr = format!("{}:{}", bind_host, bind_port);
    let listener = TcpListener::bind(&bind_addr).await?;
    let display_host = if bind_host == "0.0.0.0" {
        "localhost"
    } else {
        &bind_host
    };

    let db_kind = match &pool {
        pool::DatabasePool::Postgres(_) => "PostgreSQL",
        pool::DatabasePool::Sqlite(_) => {
            tracing::warn!(
                "SQLite is a single-instance backend. Do NOT run multiple \
                 EctoLedger processes against the same database file. \
                 Use PostgreSQL for multi-instance deployments. \
                 See docs/SCALING.md for details."
            );
            "SQLite"
        }
    };
    tracing::info!(
        "Observer dashboard: http://{}:{} ({})",
        display_host,
        bind_port,
        db_kind,
    );

    // ── One-time startup recovery ─────────────────────────────────────────
    // Recover sessions stuck in 'running' status from a previous server
    // lifetime (e.g. crash, kill -9) and mark dangling actions as failed.
    // This MUST run once at startup, NOT inside run_cognitive_loop — doing
    // it per-session would kill every other actively-running session.
    if let Some(pg) = pool.as_pg() {
        if let Err(e) = crate::wakeup::recover_zombie_sessions(pg).await {
            tracing::warn!("startup: failed to recover zombie sessions: {e}");
        }
        if let Err(e) = crate::wakeup::recover_incomplete_actions(pg).await {
            tracing::warn!("startup: failed to recover incomplete actions: {e}");
        }
    }

    let (made_router, task_tracker) = server::router(pool, metrics, cancel.clone());

    let server = axum::serve(
        listener,
        made_router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(cancel.clone().cancelled_owned());

    // Single await — the graceful_shutdown future observes the cancel token
    // that main.rs fires on Ctrl-C.  No duplicate signal handler needed.
    if let Err(e) = server.await {
        // Axum returns an error if the listener is closed unexpectedly.
        // During graceful shutdown this is expected; only log if unexpected.
        if !cancel.is_cancelled() {
            return Err(e.into());
        }
        tracing::debug!("Server exited during shutdown: {e}");
    }

    // ── Drain tracked cognitive-loop tasks ─────────────────────────────────
    // Close the tracker so no new tasks can be spawned, then wait for all
    // in-flight sessions to exit (they will observe `cancel.is_cancelled()`
    // at the top of their next loop iteration).
    task_tracker.close();
    tracing::info!(
        "Waiting for {} in-flight session(s) to drain…",
        task_tracker.len()
    );
    task_tracker.wait().await;
    tracing::info!("All session tasks drained.");

    Ok(())
}
