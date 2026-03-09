// Embedded Axum backend — starts the EctoLedger host server in-process so the
// Tauri desktop app is fully self-contained (no separate CLI launch required).
//
// On startup we:
//   1. Resolve (or create) a local SQLite database in the app data directory.
//   2. Run migrations.
//   3. Build the Axum router from `ectoledger::server`.
//   4. Bind to `127.0.0.1:0` (OS-assigned ephemeral port).
//   5. Spawn the server on a background Tokio task.
//   6. Return the assigned port so that `commands.rs` can route IPC calls.
//
// The server is automatically shut down when the Tauri app exits (the Tokio
// runtime is dropped, cancelling all spawned tasks).

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};

use ectoledger::metrics::Metrics;
use ectoledger::pool;
use ectoledger::server;
use tauri::{Emitter, Manager};
use tokio::net::TcpListener;

/// Opaque handle stored in Tauri managed state **and** in a global `OnceLock`
/// so that `commands.rs` can resolve the base URL / auth token without
/// requiring `tauri::State` on every command signature.
#[derive(Clone)]
pub struct EmbeddedServer {
    /// The `127.0.0.1:<port>` the Axum server is listening on.
    pub port: u16,
    /// Bootstrap API token that the GUI uses for auth.  Generated once per
    /// launch so there is no need for the user to configure tokens manually.
    pub token: String,
}

/// Global singleton — initialised once in `start()`, read by `commands.rs`.
static INSTANCE: OnceLock<EmbeddedServer> = OnceLock::new();

/// Returns the embedded server info, if started.
pub fn instance() -> Option<&'static EmbeddedServer> {
    INSTANCE.get()
}

/// Resolve the SQLite database path inside the Tauri app-data directory.
///
/// Falls back to `$HOME/.ectoledger/ectoledger.db` when the Tauri path resolver
/// is not available (e.g. during tests).
fn db_path(app: &tauri::AppHandle) -> PathBuf {
    let base = app.path().app_data_dir().unwrap_or_else(|_| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".ectoledger")
    });
    std::fs::create_dir_all(&base).ok();
    base.join("ectoledger.db")
}

/// Start the embedded Axum backend and return the assigned port + bootstrap token.
///
/// This must be called from inside `tauri::Builder::setup` (which runs on the
/// Tokio runtime that Tauri owns).
pub async fn start(app: &tauri::AppHandle) -> Result<EmbeddedServer, Box<dyn std::error::Error>> {
    let path = db_path(app);
    tracing::info!("Embedded SQLite database: {}", path.display());

    // ── 0. Embedded-mode defaults ───────────────────────────────────────
    // The Tauri GUI ships without the guard-worker binary, so disable the
    // guard by default.  If the operator explicitly set GUARD_REQUIRED we
    // honour that, but the default must be "false" for the embedded mode.
    if std::env::var("GUARD_REQUIRED").is_err() {
        // SAFETY: called once at startup before any threads spawn.
        unsafe { std::env::set_var("GUARD_REQUIRED", "false") };
    }

    // ── 1. Create pool & run migrations ─────────────────────────────────
    let pool = pool::create_sqlite_pool(&path)
        .await
        .map_err(|e| -> Box<dyn std::error::Error> { e })?;

    // ── 2. Generate a one-time admin token ──────────────────────────────
    let raw: [u8; 32] = rand::random();
    let token = hex::encode(raw);
    let token_hash = {
        use sha2::Digest;
        hex::encode(sha2::Sha256::digest(token.as_bytes()))
    };
    // Use the pool's own method so it works for both PG and SQLite.
    pool.insert_token(&token_hash, "admin", Some("gui-bootstrap"), None)
        .await?;

    // If the launcher set OBSERVER_TOKEN (e.g. ectoledger-mac), register it
    // in the embedded DB too so requests authenticated with it succeed
    // even when ECTO_HOST isn't set.
    if let Ok(env_tok) = std::env::var("OBSERVER_TOKEN")
        && !env_tok.is_empty()
        && env_tok != token
    {
        let env_hash = {
            use sha2::Digest;
            hex::encode(sha2::Sha256::digest(env_tok.as_bytes()))
        };
        if let Err(e) = pool
            .insert_token(&env_hash, "admin", Some("env-observer-token"), None)
            .await
        {
            tracing::warn!(
                "Failed to register OBSERVER_TOKEN in embedded DB: {e}. Requests using this token may fail with 401."
            );
        }
        tracing::info!("Registered OBSERVER_TOKEN from environment in embedded DB.");
    }

    // ── 3. Build the Axum router ────────────────────────────────────────
    let metrics = Arc::new(Metrics::default());
    let cancel = tokio_util::sync::CancellationToken::new();
    let (router, _task_tracker) = server::router(pool, metrics, cancel);

    // ── 4. Bind to an ephemeral port on loopback ────────────────────────
    let listener = TcpListener::bind("127.0.0.1:0").await?;
    let addr: SocketAddr = listener.local_addr()?;
    let port = addr.port();
    tracing::info!("Embedded server listening on http://127.0.0.1:{port}");

    // Store in global OnceLock so commands.rs can resolve port/token.
    let srv = EmbeddedServer {
        port,
        token: token.clone(),
    };
    let _ = INSTANCE.set(srv.clone());

    // ── 5. Spawn the server and monitor for crashes ─────────────────
    let app_handle = app.clone();
    let server_handle = tokio::spawn(async move {
        if let Err(e) = axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        {
            tracing::error!("Embedded Axum server exited with error: {e}");
        }
    });

    // Spawn a watcher that emits a Tauri event if the backend dies.
    // Without this, a crashed server leaves the GUI visually functional
    // but every API call silently fails.
    tokio::spawn(async move {
        match server_handle.await {
            Ok(()) => {
                tracing::warn!("Embedded Axum server exited unexpectedly");
                let _ = app_handle.emit("backend-crash", "Server exited");
            }
            Err(e) => {
                tracing::error!("Embedded Axum server panicked: {e}");
                let _ = app_handle.emit("backend-crash", format!("Server panicked: {e}"));
            }
        }
    });

    Ok(srv)
}
