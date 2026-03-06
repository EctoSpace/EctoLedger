pub mod agent;
pub mod approvals;
pub mod blocking; // Async wrappers for blocking crypto operations
pub mod certificate;
pub mod cloud_creds;
pub mod commands;
pub mod compensation;
pub mod config;
pub mod db_setup;
pub mod enclave;
pub mod error;
pub use ectoledger_compliance::evm_anchor;
pub mod executor;
pub mod guard;
pub mod guard_process;
#[cfg(feature = "keychain")]
pub mod keychain;
pub mod ledger;
pub mod llm;
pub mod metrics;
pub use ectoledger_llm::ollama_setup as ollama;
pub mod orchestrator;
pub use ectoledger_compliance::ots;
pub use ectoledger_sandbox::output;
pub mod output_scanner;
pub mod pg_notify;
pub mod policy;
pub mod pool;
pub mod red_team;
pub mod report;
pub use ectoledger_sandbox::sandbox;
pub mod schema;
pub mod secrets;
pub mod server;
pub mod signing;
pub mod snapshot;
#[cfg(feature = "sqlcipher")]
pub mod sqlcipher;
pub mod tripwire;
pub use ectoledger_compliance::verifiable_credential;
pub mod wakeup;
pub mod webhook;

// Re-export ectoledger_core's pure-logic modules into this crate's namespace.
// - `hash` / `merkle`: all `use crate::hash::*` and `use crate::merkle::*` calls resolve transparently.
// - `intent`: eliminates the wrapper file; `use crate::intent::ProposedIntent` etc. still work.
pub use ectoledger_core::hash;
pub use ectoledger_core::intent;
pub use ectoledger_core::merkle;

// ─── Convenience top-level API ────────────────────────────────────────────────
// These thin wrappers let `gui/src-tauri` and external integrators call
// `ectoledger::start_server(...)` / `::run_migrations(...)` without
// reaching into internal module paths.

use std::sync::Arc;

/// Start the Axum HTTP server on an already-bound `TcpListener`.
///
/// Blocks until the server shuts down (or the future is dropped/cancelled).
/// Intended to be called from inside a `tokio::spawn` task.
///
/// # Example
/// ```no_run
/// use std::net::SocketAddr;
/// use ectoledger::{pool, metrics::Metrics, start_server};
///
/// # tokio_test::block_on(async {
/// let p = pool::create_sqlite_pool(std::path::Path::new(":memory:")).await.unwrap();
/// let m = std::sync::Arc::new(Metrics::default());
/// let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
/// start_server(p, m, listener).await.unwrap();
/// # });
/// ```
pub async fn start_server(
    pool: pool::DatabasePool,
    metrics_handle: Arc<metrics::Metrics>,
    listener: tokio::net::TcpListener,
) -> Result<(), std::io::Error> {
    let cancel = tokio_util::sync::CancellationToken::new();
    let (made_router, _task_tracker) = server::router(pool, metrics_handle, cancel);
    axum::serve(
        listener,
        made_router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
}

/// Like [`start_server`] but accepts an LLM backend factory for dependency
/// injection (e.g. integration tests that need a stub backend without
/// requiring external services).
pub async fn start_server_with_llm(
    pool: pool::DatabasePool,
    metrics_handle: Arc<metrics::Metrics>,
    listener: tokio::net::TcpListener,
    llm_factory: Arc<dyn Fn() -> Box<dyn ectoledger_llm::LlmBackend> + Send + Sync>,
) -> Result<(), std::io::Error> {
    let cancel = tokio_util::sync::CancellationToken::new();
    let approval_state = Arc::new(approvals::ApprovalState::new());
    let (made_router, _task_tracker) = server::router_with_approval_state(
        pool,
        metrics_handle,
        approval_state,
        cancel,
        Some(llm_factory),
    );
    axum::serve(
        listener,
        made_router.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
}

/// Run the migration set appropriate for the given pool variant.
///
/// - `DatabasePool::Postgres` → runs `./migrations` (full Postgres schema).
/// - `DatabasePool::Sqlite`   → runs `./migrations/sqlite` (SQLite-compatible schema).
///
/// This is **idempotent**: migrations already applied are skipped automatically.
pub async fn run_migrations(pool: &pool::DatabasePool) -> Result<(), sqlx::migrate::MigrateError> {
    match pool {
        pool::DatabasePool::Postgres(pg) => sqlx::migrate!("./migrations").run(pg).await,
        pool::DatabasePool::Sqlite(sq) => sqlx::migrate!("./migrations/sqlite").run(sq).await,
    }
}
