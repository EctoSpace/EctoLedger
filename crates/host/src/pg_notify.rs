//! PostgreSQL `LISTEN/NOTIFY` helpers for cross-instance SSE fanout.
//!
//! When multiple EctoLedger instances share a PostgreSQL database the
//! in-process `tokio::sync::broadcast` channel only wakes SSE clients
//! connected to the local instance.  This module bridges the gap:
//!
//! 1. **[`notify_new_event`]** — Called after each event append to issue
//!    `NOTIFY ectoledger_events`.  This is a no-op for SQLite.
//! 2. **[`spawn_pg_listener`]** — Spawns a background task that
//!    `LISTEN`s on the channel and calls [`crate::server::notify_sse_subscribers`]
//!    whenever a notification arrives from any instance (including self).
//!
//! # Wiring
//!
//! • Call `spawn_pg_listener(&pg_pool)` once during server startup.
//! • Call `notify_new_event(&pg_pool).await` after every successful
//!   `INSERT INTO agent_events`.
//!
//! See `docs/SCALING.md` for the full horizontal-scaling design.

use sqlx::PgPool;

/// The PostgreSQL channel name used for cross-instance event wakeups.
pub const CHANNEL: &str = "ectoledger_events";

/// Send a `NOTIFY` on the `ectoledger_events` channel.
///
/// This is intentionally fire-and-forget: a failed NOTIFY should not
/// block or error the event-append path.  The worst case is a slightly
/// delayed SSE update on other instances (they will catch up via their
/// periodic poll or on the next successful NOTIFY).
pub async fn notify_new_event(pool: &PgPool) {
    let result = sqlx::query(&format!("NOTIFY {}", CHANNEL))
        .execute(pool)
        .await;
    if let Err(e) = result {
        tracing::warn!("pg NOTIFY failed (non-fatal): {}", e);
    }
}

/// Spawn a long-lived background task that listens for PostgreSQL
/// notifications and wakes local SSE subscribers.
///
/// Returns a `tokio::task::JoinHandle` that can be used to cancel the
/// listener on shutdown.
pub fn spawn_pg_listener(pool: &PgPool) -> tokio::task::JoinHandle<()> {
    let pool = pool.clone();
    tokio::spawn(async move {
        // PgListener needs the raw connection options from the pool.
        let mut listener = match sqlx::postgres::PgListener::connect_with(&pool).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!(
                    "Failed to create PgListener: {}. Cross-instance SSE wakeups disabled.",
                    e
                );
                return;
            }
        };

        if let Err(e) = listener.listen(CHANNEL).await {
            tracing::error!(
                "LISTEN {} failed: {}. Cross-instance SSE wakeups disabled.",
                CHANNEL,
                e
            );
            return;
        }

        tracing::info!(
            "Listening on pg channel '{}' for cross-instance SSE wakeups",
            CHANNEL
        );

        loop {
            match listener.recv().await {
                Ok(_notification) => {
                    // Wake all local SSE subscribers — they will re-poll
                    // the DB and pick up any new events.
                    crate::server::notify_sse_subscribers();
                }
                Err(e) => {
                    // sqlx::PgListener reconnects automatically on
                    // transient errors.  Log and continue.
                    tracing::warn!("PgListener recv error (will retry): {}", e);
                }
            }
        }
    })
}
