use pg_embed::pg_enums::PgAuthMethod;
use pg_embed::pg_fetch::{PG_V15, PgFetchSettings};
use pg_embed::postgres::{PgEmbed, PgSettings};
use std::net::TcpListener;
use std::path::PathBuf;
use std::time::Duration;

const POLL_MAX_ATTEMPTS: u32 = 60;

pub struct EmbeddedDb(#[allow(dead_code)] Option<PgEmbed>);

/// Returns true when ECTO_DEMO_MODE=true is set (demo launcher flag).
fn is_demo_mode() -> bool {
    std::env::var("ECTO_DEMO_MODE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub async fn ensure_postgres_ready(
    database_url: &str,
) -> Result<(String, EmbeddedDb), DbSetupError> {
    // ── Demo mode: always use an isolated embedded PG instance ───────────
    if is_demo_mode() {
        // Use a dedicated port + DB name so demo never touches the normal database.
        let demo_url = "postgres://ectoledger:ectoledger@localhost:5433/ectoledger_demo";
        eprintln!("INFO: Demo mode — starting isolated embedded PostgreSQL on port 5433.");
        println!(
            "Starting embedded PostgreSQL for demo (first run downloads ~30 MB of binaries)..."
        );
        let (pg, url) = start_embedded(demo_url).await?;
        println!("Embedded PostgreSQL (demo) ready.");
        return Ok((url, EmbeddedDb(Some(pg))));
    }

    let is_local = database_url.contains("localhost") || database_url.contains("127.0.0.1");

    if !is_local {
        eprintln!("INFO: Using external PostgreSQL (DATABASE_URL set).");
        poll_until_connected(database_url).await?;
        return Ok((database_url.to_string(), EmbeddedDb(None)));
    }

    if quick_connect(database_url).await.is_ok() {
        eprintln!(
            "INFO: Using Docker/external PostgreSQL container at {}.",
            database_url
        );
        return Ok((database_url.to_string(), EmbeddedDb(None)));
    }

    eprintln!(
        "WARNING: Using embedded PostgreSQL. Not recommended for production or multi-user deployments."
    );
    eprintln!(
        "         Set DATABASE_URL to point to an external Postgres instance for production use."
    );
    println!("Starting embedded PostgreSQL (first run downloads ~30 MB of binaries)...");
    let (pg, url) = start_embedded(database_url).await?;
    println!("Embedded PostgreSQL ready.");
    Ok((url, EmbeddedDb(Some(pg))))
}

async fn quick_connect(url: &str) -> Result<(), sqlx::Error> {
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(3))
        .connect(url)
        .await?;
    let _ = pool.close().await;
    Ok(())
}

async fn start_embedded(database_url: &str) -> Result<(PgEmbed, String), DbSetupError> {
    // Pre-extract pg-embed binaries from the cached zip if needed.
    // pg-embed 0.7 uses archiver_rs 0.5 / zip 0.5.x which fails to open Maven JAR
    // files (UTF-8 flag 0x0800), returning "Could not find central directory end".
    // By pre-extracting with system tools (unzip + tar) we allow pg-embed to detect
    // existing binaries and skip its own extraction step.  We also set LD_LIBRARY_PATH
    // so the bundled libpq.so.5 (inside the archive) is visible to initdb/pg_ctl.
    pre_extract_pg_embed_binaries();

    let parsed = database_url
        .parse::<url::Url>()
        .map_err(|e| DbSetupError::EmbeddedSetup(format!("invalid url: {}", e)))?;

    let port = parsed.port().unwrap_or(5432);
    let user = {
        let u = parsed.username();
        if u.is_empty() { "ectoledger" } else { u }.to_string()
    };
    let password = parsed.password().unwrap_or("ectoledger").to_string();
    let db_name = {
        let p = parsed.path().trim_start_matches('/');
        if p.is_empty() { "ectoledger" } else { p }.to_string()
    };

    let data_dir = if is_demo_mode() {
        app_data_dir().join("postgres-demo")
    } else {
        app_data_dir().join("postgres")
    };
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| DbSetupError::EmbeddedSetup(format!("create data dir: {}", e)))?;

    // ── Pre-flight checks ────────────────────────────────────────────────
    // 1. Remove stale PID file left behind by a previous crash / kill -9.
    //    pg_ctl refuses to start when postmaster.pid already exists.
    //    Also kill the old PG process if it's still running.
    let pid_file = data_dir.join("postmaster.pid");
    if pid_file.exists() {
        // Try to read the PID and kill the orphaned process.
        #[cfg(unix)]
        if let Ok(contents) = std::fs::read_to_string(&pid_file)
            && let Some(pid_str) = contents.lines().next()
            && let Ok(pid) = pid_str.trim().parse::<i32>()
        {
            eprintln!(
                "WARNING: Found stale PID file (PID {}) at {}. \
                 Attempting to stop the orphaned PostgreSQL process.",
                pid,
                pid_file.display()
            );
            // Verify the PID actually belongs to a postgres process
            // before sending signals.  Stale PID files can reference
            // recycled PIDs that now belong to unrelated processes.
            let is_postgres = std::process::Command::new("ps")
                .args(["-p", &pid.to_string(), "-o", "comm="])
                .output()
                .ok()
                .and_then(|out| {
                    let name = String::from_utf8_lossy(&out.stdout).trim().to_lowercase();
                    if name.contains("postgres") || name.contains("postmaster") {
                        Some(true)
                    } else {
                        None
                    }
                })
                .unwrap_or(false);

            if is_postgres {
                // Send SIGTERM to the old process.
                unsafe {
                    libc::kill(pid, libc::SIGTERM);
                }
                // Give it a moment to shut down.
                tokio::time::sleep(Duration::from_secs(2)).await;
                // If still alive, force kill.
                unsafe {
                    if libc::kill(pid, 0) == 0 {
                        eprintln!("WARNING: PID {} did not exit, sending SIGKILL.", pid);
                        libc::kill(pid, libc::SIGKILL);
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                }
            } else {
                eprintln!(
                    "WARNING: PID {} is not a postgres process. \
                     Ignoring stale PID file to avoid killing an unrelated process.",
                    pid
                );
            }
        }

        // Windows: use `taskkill /F /PID <pid>` to stop the orphaned process.
        // We cannot easily verify if the PID belongs to postgres on Windows,
        // but since it came from our own pg-embed PID file, it is safe to
        // terminate.  If the PID has been recycled, taskkill will either fail
        // harmlessly or kill an unrelated process — acceptable given that the
        // PID file explicitly lives in our app-data directory.
        #[cfg(windows)]
        if let Ok(contents) = std::fs::read_to_string(&pid_file) {
            if let Some(pid_str) = contents.lines().next() {
                let pid_str = pid_str.trim();
                if pid_str.parse::<u32>().is_ok() {
                    eprintln!(
                        "WARNING: Found stale PID file (PID {}) at {}. \
                         Attempting to stop the orphaned PostgreSQL process.",
                        pid_str,
                        pid_file.display()
                    );
                    let _ = std::process::Command::new("taskkill")
                        .args(["/F", "/PID", pid_str])
                        .stdout(std::process::Stdio::null())
                        .stderr(std::process::Stdio::null())
                        .status();
                    std::thread::sleep(Duration::from_secs(1));
                }
            }
        }

        eprintln!(
            "WARNING: Removing stale PID file at {}.",
            pid_file.display()
        );
        let _ = std::fs::remove_file(&pid_file);
    }

    // 2. Verify the target port is actually free.  If something else (local
    //    Postgres install, Docker container, zombie pg-embed) is holding the
    //    port, try to kill it before giving up.
    if TcpListener::bind(("127.0.0.1", port)).is_err() {
        eprintln!(
            "WARNING: Port {} is in use. Attempting to kill the process holding it…",
            port
        );

        // macOS / Linux: lsof + kill.
        #[cfg(unix)]
        {
            let _ = std::process::Command::new("sh")
                .args([
                    "-c",
                    &format!("lsof -ti:{} | xargs kill -9 2>/dev/null", port),
                ])
                .status();
        }

        // Windows: parse `netstat -aon` to find the PID listening on the
        // port, then `taskkill /F /PID` it.
        #[cfg(windows)]
        {
            if let Ok(output) = std::process::Command::new("netstat")
                .args(["-aon"])
                .output()
            {
                let stdout = String::from_utf8_lossy(&output.stdout);
                let port_suffix = format!(":{}", port);
                for line in stdout.lines() {
                    let cols: Vec<&str> = line.split_whitespace().collect();
                    // Expected: TCP  <local>  <foreign>  LISTENING  <PID>
                    if cols.len() >= 5
                        && cols[1].ends_with(&port_suffix)
                        && cols[3].eq_ignore_ascii_case("LISTENING")
                    {
                        let pid = cols[4];
                        eprintln!("  Killing PID {} on port {}.", pid, port);
                        let _ = std::process::Command::new("taskkill")
                            .args(["/F", "/PID", pid])
                            .stdout(std::process::Stdio::null())
                            .stderr(std::process::Stdio::null())
                            .status();
                    }
                }
            }
        }

        tokio::time::sleep(Duration::from_secs(2)).await;

        // Re-check.
        if TcpListener::bind(("127.0.0.1", port)).is_err() {
            #[cfg(unix)]
            let hint = format!(
                "Port {} is already in use. This is usually caused by:\n  \
                 • A locally installed PostgreSQL (brew services stop postgresql)\n  \
                 • A Docker container (docker ps | grep {})\n  \
                 • A previous Ecto Ledger session that didn't shut down cleanly\n\n  \
                 Fix: stop the other process, or set DATABASE_URL to point at it.",
                port, port
            );
            #[cfg(windows)]
            let hint = format!(
                "Port {} is already in use. This is usually caused by:\n  \
                 • A locally installed PostgreSQL service (services.msc → postgresql-*)\n  \
                 • A Docker container (docker ps)\n  \
                 • A previous Ecto Ledger session that didn't shut down cleanly\n\n  \
                 Fix: netstat -ano | findstr :{}\n       taskkill /F /PID <PID>",
                port, port
            );
            #[cfg(not(any(unix, windows)))]
            let hint = format!("Port {} is already in use.", port);
            return Err(DbSetupError::PortConflict { port, hint });
        }
        eprintln!("Port {} is now free. Continuing startup.", port);
    }

    let pg_settings = PgSettings {
        database_dir: data_dir,
        port,
        user: user.clone(),
        password: password.clone(),
        auth_method: PgAuthMethod::Plain,
        persistent: true,
        timeout: Some(Duration::from_secs(60)),
        migration_dir: None,
    };

    let fetch_settings = PgFetchSettings {
        version: PG_V15,
        ..Default::default()
    };

    let mut pg = PgEmbed::new(pg_settings, fetch_settings)
        .await
        .map_err(|e| DbSetupError::EmbeddedSetup(e.to_string()))?;

    pg.setup()
        .await
        .map_err(|e| DbSetupError::EmbeddedSetup(e.to_string()))?;

    pg.start_db()
        .await
        .map_err(|e| DbSetupError::EmbeddedSetup(e.to_string()))?;

    create_database_if_missing(&pg.db_uri, &db_name).await?;

    let db_url = pg.full_db_uri(&db_name);
    Ok((pg, db_url))
}

async fn create_database_if_missing(base_uri: &str, db_name: &str) -> Result<(), DbSetupError> {
    let system_url = format!("{}/postgres", base_uri);
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&system_url)
        .await
        .map_err(|e| DbSetupError::EmbeddedSetup(e.to_string()))?;

    let exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM pg_database WHERE datname = $1)")
            .bind(db_name)
            .fetch_one(&pool)
            .await
            .map_err(|e| DbSetupError::EmbeddedSetup(e.to_string()))?;

    if !exists {
        // Strict allowlist: only alphanumeric + underscore to prevent SQL injection.
        if !db_name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
            || db_name.is_empty()
        {
            return Err(DbSetupError::EmbeddedSetup(format!(
                "invalid database name (must be [a-zA-Z0-9_]+): {}",
                db_name
            )));
        }
        let safe_name = db_name.replace('"', "\"\"");
        // Force UTF-8 encoding regardless of the OS locale.  On Windows the
        // embedded PostgreSQL initdb inherits the system code page (typically
        // WIN1252), which rejects any non-ASCII UTF-8 in SQL migration files.
        // TEMPLATE template0 is required when overriding the encoding.
        // LC_COLLATE/LC_CTYPE 'C' is the only locale guaranteed to exist on
        // every platform and is compatible with UTF-8.
        sqlx::query(&format!(
            "CREATE DATABASE \"{}\" ENCODING 'UTF8' LC_COLLATE 'C' LC_CTYPE 'C' TEMPLATE template0",
            safe_name
        ))
        .execute(&pool)
        .await
        .map_err(|e| DbSetupError::EmbeddedSetup(e.to_string()))?;
    }

    let _ = pool.close().await;
    Ok(())
}

async fn poll_until_connected(database_url: &str) -> Result<(), DbSetupError> {
    for attempt in 1..=POLL_MAX_ATTEMPTS {
        match sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect(database_url)
            .await
        {
            Ok(pool) => {
                let _ = pool.close().await;
                return Ok(());
            }
            Err(_) => {
                if attempt < POLL_MAX_ATTEMPTS {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                } else {
                    return Err(DbSetupError::Timeout);
                }
            }
        }
    }
    Err(DbSetupError::Timeout)
}

/// Returns the platform-appropriate application data directory.
pub fn app_data_dir() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| {
            tracing::warn!("$HOME not set; falling back to current directory for DB storage");
            ".".to_string()
        });
        PathBuf::from(home)
            .join("Library")
            .join("Application Support")
            .join("ectoledger")
    }
    #[cfg(target_os = "windows")]
    {
        let appdata = std::env::var("LOCALAPPDATA").unwrap_or_else(|_| {
            tracing::warn!(
                "$LOCALAPPDATA not set; falling back to current directory for DB storage"
            );
            ".".to_string()
        });
        PathBuf::from(appdata).join("ectoledger")
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    {
        let home = std::env::var("HOME").unwrap_or_else(|_| {
            tracing::warn!("$HOME not set; falling back to current directory for DB storage");
            ".".to_string()
        });
        PathBuf::from(home)
            .join(".local")
            .join("share")
            .join("ectoledger")
    }
}

/// Workaround for archiver_rs / zip 0.5.x incompatibility with Maven JAR files.
///
/// pg-embed 0.7 bundles archiver_rs 0.5 which uses the `zip` crate 0.5.13.
/// That version fails to open JAR/zip files with the UTF-8 language-encoding
/// flag (bit 0x0800), returning "Could not find central directory end" even
/// though the file is structurally valid.
///
/// This function pre-extracts the PostgreSQL binaries from the cached zip using
/// system `unzip` and `tar` commands.  Once `bin/initdb` exists, pg-embed's
/// `pg_executables_cached()` returns `true` and it skips its own extraction.
///
/// It also sets `LD_LIBRARY_PATH` (Linux) / `DYLD_LIBRARY_PATH` (macOS) so the
/// bundled `libpq.so.5` included in the archive is found by the pg processes.
fn pre_extract_pg_embed_binaries() {
    // Only applicable on Unix.
    #[cfg(not(unix))]
    return;

    #[cfg(unix)]
    {
        use std::path::PathBuf;

        // ── Resolve pg-embed cache directory ──
        let cache_base: PathBuf = {
            #[cfg(target_os = "macos")]
            {
                match std::env::var("HOME") {
                    Ok(h) => PathBuf::from(h).join("Library").join("Caches"),
                    Err(_) => return,
                }
            }
            #[cfg(not(target_os = "macos"))]
            {
                std::env::var("XDG_CACHE_HOME")
                    .ok()
                    .filter(|s| !s.is_empty())
                    .map(PathBuf::from)
                    .or_else(|| {
                        std::env::var("HOME")
                            .ok()
                            .map(|h| PathBuf::from(h).join(".cache"))
                    })
                    .unwrap_or_else(return_none)
            }
        };

        // ── Detect architecture ──
        let arch = std::process::Command::new("uname")
            .arg("-m")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .map(|s| s.trim().to_string());
        let arch_str = match arch.as_deref() {
            Some("x86_64") => "amd64",
            Some("aarch64") | Some("arm64") => "arm64",
            _ => "amd64",
        };

        // ── Resolve OS name (matches pg-embed's OperationSystem::to_string) ──
        #[cfg(target_os = "macos")]
        let os_str = "darwin";
        #[cfg(not(target_os = "macos"))]
        let os_str = "linux";

        let pg_version = "15.1.0";
        let platform = format!("{}-{}", os_str, arch_str);
        let pg_cache = cache_base
            .join("pg-embed")
            .join(os_str)
            .join(arch_str)
            .join(pg_version);

        let initdb = pg_cache.join("bin").join("initdb");
        let lib_dir = pg_cache.join("lib");

        // If binaries are already extracted, just ensure the lib path is set.
        if initdb.exists() {
            set_library_path(&lib_dir);
            return;
        }

        let zip_file = pg_cache.join(format!("{}-{}.zip", platform, pg_version));
        if !zip_file.exists() {
            // pg-embed will download the zip on its own; nothing to pre-extract.
            return;
        }

        tracing::info!(
            "pg-embed binaries not found; pre-extracting from cached zip via system tools \
             (archiver_rs compat workaround)…"
        );

        let tmpdir = match tempfile::tempdir() {
            Ok(t) => t,
            Err(e) => {
                tracing::warn!("pg-embed pre-extract: could not create tmpdir: {}", e);
                return;
            }
        };

        let txz_name = format!("postgres-{}.txz", platform);

        // Step 1: extract the .txz from the JAR/zip using system unzip.
        let ok = std::process::Command::new("unzip")
            .args([
                "-q",
                "-o",
                zip_file.to_str().unwrap_or(""),
                &txz_name,
                "-d",
                tmpdir.path().to_str().unwrap_or(""),
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if !ok {
            tracing::warn!(
                "pg-embed pre-extract: unzip failed; pg-embed will attempt its own extraction."
            );
            return;
        }

        // Step 2: extract the tar.xz to the pg-embed cache directory.
        if let Err(e) = std::fs::create_dir_all(&pg_cache) {
            tracing::warn!("pg-embed pre-extract: could not create cache dir: {}", e);
            return;
        }

        let txz = tmpdir.path().join(&txz_name);
        let ok = std::process::Command::new("tar")
            .args([
                "-xJf",
                txz.to_str().unwrap_or(""),
                "-C",
                pg_cache.to_str().unwrap_or(""),
            ])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);

        if ok && initdb.exists() {
            tracing::info!("pg-embed binaries pre-extracted to {}", pg_cache.display());
            set_library_path(&lib_dir);
        } else {
            tracing::warn!(
                "pg-embed pre-extract: tar step failed or initdb still missing; \
                 pg-embed will attempt its own extraction."
            );
        }
    }
}

/// Returns a dummy PathBuf for the unreachable else branch (used to satisfy the
/// type checker in cfg blocks that might not compile on all platforms).
#[allow(dead_code)]
fn return_none() -> std::path::PathBuf {
    std::path::PathBuf::new()
}

/// Sets `LD_LIBRARY_PATH` (Linux) or `DYLD_LIBRARY_PATH` (macOS) to include
/// the bundled pg-embed library directory so `libpq.so.5` / `libpq.dylib` is
/// found by `initdb`, `pg_ctl`, and `postgres` at runtime.
#[cfg(unix)]
fn set_library_path(lib_dir: &std::path::Path) {
    if !lib_dir.is_dir() {
        return;
    }
    let lib_path = lib_dir.to_string_lossy();

    #[cfg(target_os = "macos")]
    let env_key = "DYLD_LIBRARY_PATH";
    #[cfg(not(target_os = "macos"))]
    let env_key = "LD_LIBRARY_PATH";

    let existing = std::env::var(env_key).unwrap_or_default();
    if existing.split(':').any(|p| p == lib_path.as_ref()) {
        return; // already present
    }
    let new_val = if existing.is_empty() {
        lib_path.into_owned()
    } else {
        format!("{}:{}", lib_path, existing)
    };
    // SAFETY: single-threaded at this point (called before tokio runtime starts
    // spinning up worker threads via pg-embed).
    unsafe {
        std::env::set_var(env_key, new_val);
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DbSetupError {
    #[error("embedded postgres setup failed: {0}")]
    EmbeddedSetup(String),
    #[error("port {port} is already in use.\n{hint}")]
    PortConflict { port: u16, hint: String },
    #[error("PostgreSQL did not accept connections within {POLL_MAX_ATTEMPTS} seconds")]
    Timeout,
}

/// Returns true if the given database URL is reachable. Used for first-launch detection.
pub async fn check_database_accessible(url: &str) -> bool {
    if url.starts_with("postgres://") || url.starts_with("postgresql://") {
        match sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(2))
            .connect(url)
            .await
        {
            Ok(pool) => {
                pool.close().await;
                return true;
            }
            Err(_) => return false,
        }
    }
    if url.starts_with("sqlite:") || url.starts_with("sqlite://") {
        let path_str = url
            .strip_prefix("sqlite:///")
            .or_else(|| url.strip_prefix("sqlite://"))
            .or_else(|| url.strip_prefix("sqlite:"))
            .unwrap_or(url)
            .trim_start_matches('/');
        if path_str == ":memory:" || path_str.is_empty() {
            return true;
        }
        let path = PathBuf::from(path_str);
        if let Ok(pool) = create_sqlite_pool(Some(path)).await {
            pool.close().await;
            return true;
        }
        return false;
    }
    false
}

// ── SQLite pool for Tauri embedded mode ─────────────────────────────────────────

/// Creates a SQLite pool at the given path (or default `$APP_DATA/ectoledger/ledger.db`),
/// creates parent directories, and runs SQLite migrations.
pub async fn create_sqlite_pool(
    path: Option<std::path::PathBuf>,
) -> Result<sqlx::SqlitePool, sqlx::Error> {
    let db_path = path.unwrap_or_else(|| app_data_dir().join("ectoledger").join("ledger.db"));
    // Explicitly resolve and create the full parent directory chain before connecting.
    // SQLite returns "unable to open database file" (code 14) when the directory does not exist.
    let parent = db_path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| std::path::Path::new("."));
    std::fs::create_dir_all(parent).map_err(|e| {
        sqlx::Error::Configuration(Box::new(std::io::Error::other(format!(
            "create_sqlite_pool: create_dir_all({}): {}",
            parent.display(),
            e
        ))))
    })?;
    let path_str = db_path.to_string_lossy().replace('\\', "/");
    let url = if cfg!(windows) && path_str.len() > 1 && path_str.chars().nth(1) == Some(':') {
        format!("sqlite:///{}", path_str)
    } else {
        format!("sqlite:{}", path_str)
    };
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await?;
    sqlx::migrate!("./migrations/sqlite")
        .run(&pool)
        .await
        .map_err(|e| sqlx::Error::Configuration(e.into()))?;
    Ok(pool)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Verify that `app_data_dir()` returns a non-empty, OS-appropriate path.
    /// Each platform branch is exercised on the platform where the test runs.
    #[test]
    fn app_data_dir_returns_valid_path() {
        let dir = app_data_dir();
        let s = dir.to_string_lossy();
        // Must not be empty.
        assert!(!s.is_empty(), "app_data_dir must not be empty");
        // Must contain the application identifier.
        assert!(
            s.contains("ectoledger"),
            "app_data_dir should contain 'ectoledger': {s}"
        );

        #[cfg(target_os = "macos")]
        assert!(
            s.contains("Library/Application Support"),
            "macOS app_data_dir should be under ~/Library/Application Support: {s}"
        );

        #[cfg(target_os = "windows")]
        assert!(
            s.contains("ectoledger"),
            "Windows app_data_dir should be under LOCALAPPDATA\\ectoledger: {s}"
        );

        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        assert!(
            s.contains(".local/share/ectoledger"),
            "Linux app_data_dir should be under ~/.local/share/ectoledger: {s}"
        );
    }
}
