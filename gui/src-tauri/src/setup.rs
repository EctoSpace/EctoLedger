// setup.rs — Tauri commands for the first-launch wizard (Track 3).
//
// Exposes: detect_system_state, check_setup_complete, mark_setup_complete,
//          initialize_database, install_ollama, pull_model.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tauri::{Emitter, Manager};

// ── Data structures ────────────────────────────────────────────────────────

/// System state returned to the frontend for the wizard's detection step.
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct SystemState {
    pub os: String,
    pub arch: String,
    pub ram_gb: Option<f64>,
    pub ollama_running: bool,
    pub ollama_installed: bool,
    pub existing_db_path: Option<String>,
    pub recommended_model: String,
}

// ── Helpers ────────────────────────────────────────────────────────────────

fn setup_complete_path(app: &tauri::AppHandle) -> PathBuf {
    let base = app
        .path()
        .app_data_dir()
        .unwrap_or_else(|_| PathBuf::from("."));
    base.join("setup_complete.json")
}

/// Try to read total RAM via /proc/meminfo (Linux) or sysctl (macOS/BSD).
/// Returns None if detection fails (non-fatal).
fn detect_ram_gb() -> Option<f64> {
    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string("/proc/meminfo").ok()?;
        for line in content.lines() {
            if line.starts_with("MemTotal:") {
                let kb: u64 = line.split_whitespace().nth(1)?.parse().ok()?;
                return Some(kb as f64 / 1_048_576.0);
            }
        }
        None
    }
    #[cfg(target_os = "macos")]
    {
        let out = std::process::Command::new("sysctl")
            .arg("-n")
            .arg("hw.memsize")
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout);
        let bytes: u64 = s.trim().parse().ok()?;
        Some(bytes as f64 / 1_073_741_824.0)
    }
    #[cfg(target_os = "windows")]
    {
        // Use PowerShell Get-CimInstance (wmic is deprecated on Windows 11+)
        let out = std::process::Command::new("powershell")
            .args([
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory",
            ])
            .output()
            .ok()?;
        let s = String::from_utf8_lossy(&out.stdout);
        let bytes: u64 = s.trim().parse().ok()?;
        Some(bytes as f64 / 1_073_741_824.0)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        None
    }
}

/// Detect if Ollama HTTP API is running on the default port.
async fn probe_ollama_http() -> bool {
    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(2))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    client
        .get("http://127.0.0.1:11434/api/tags")
        .send()
        .await
        .map(|r| r.status().is_success())
        .unwrap_or(false)
}

/// Check if `ollama` is on PATH.
fn ollama_installed() -> bool {
    #[cfg(target_os = "windows")]
    let cmd = "where";
    #[cfg(not(target_os = "windows"))]
    let cmd = "which";
    std::process::Command::new(cmd)
        .arg("ollama")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Pick a sensible default model based on available RAM.
fn recommended_model(ram_gb: Option<f64>) -> &'static str {
    match ram_gb {
        Some(r) if r >= 32.0 => "llama3.3:70b-instruct-q4_K_M",
        Some(r) if r >= 8.0 => "llama3.1:8b",
        _ => "llama3.2:3b",
    }
}

// ── Tauri commands ─────────────────────────────────────────────────────────

/// Detect system capabilities and return them to the wizard.
#[tauri::command]
pub async fn detect_system_state(app: tauri::AppHandle) -> Result<SystemState, String> {
    let os = std::env::consts::OS.to_string();
    let arch = std::env::consts::ARCH.to_string();
    let ram_gb = detect_ram_gb();

    let ollama_running = probe_ollama_http().await;
    let installed = ollama_installed();

    // Check if an existing SQLite DB already exists in the app data dir.
    let existing_db = {
        let base = app
            .path()
            .app_data_dir()
            .unwrap_or_else(|_| PathBuf::from("."));
        let db = base.join("ectoledger.db");
        if db.exists() {
            Some(db.to_string_lossy().into_owned())
        } else {
            None
        }
    };

    let model = recommended_model(ram_gb).to_string();

    Ok(SystemState {
        os,
        arch,
        ram_gb,
        ollama_running,
        ollama_installed: installed,
        existing_db_path: existing_db,
        recommended_model: model,
    })
}

/// Resolve the SQLite database path — same logic as `embedded::db_path`.
fn resolve_db_path(app: &tauri::AppHandle) -> PathBuf {
    let base = app.path().app_data_dir().unwrap_or_else(|_| {
        dirs::home_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join(".ectoledger")
    });
    base.join("ectoledger.db")
}

/// Explicitly run the SQLite migration set against the local database.
///
/// This command can be invoked from the setup wizard's provisioning step to
/// initialise (or upgrade) the schema before the first session is created.
/// It is fully idempotent — already-applied migrations are skipped.
#[tauri::command]
pub async fn initialize_database(app: tauri::AppHandle) -> Result<(), String> {
    let path = resolve_db_path(&app);
    tracing::info!("initialize_database: migrating {}", path.display());
    let pool = ectoledger::pool::create_sqlite_pool(&path)
        .await
        .map_err(|e| format!("Failed to open database: {e}"))?;
    ectoledger::run_migrations(&pool)
        .await
        .map_err(|e| format!("Migration error: {e}"))?;
    tracing::info!("initialize_database: migrations complete");
    Ok(())
}

/// Return true if the first-launch wizard has already been completed.
///
/// Also returns true (and auto-writes the marker) when Ollama is already
/// running on the default port — meaning the system is fully configured and
/// the wizard would be a no-op.  This prevents the wizard from appearing on
/// every launch for users who set up manually or via `ectoledger-mac`.
///
/// The env var `ECTO_FORCE_SETUP=1` suppresses the auto-detect so that
/// `./ectoledger-mac --setup` can force the wizard to appear even when Ollama
/// is running.
#[tauri::command]
pub async fn check_setup_complete(app: tauri::AppHandle) -> bool {
    // --setup path: the launcher sets this env var to prevent us from
    // auto-detecting a configured system and re-skipping the wizard.
    if std::env::var("ECTO_FORCE_SETUP")
        .map(|v| v == "1")
        .unwrap_or(false)
    {
        return false;
    }

    // Fast path: marker file already written.
    if setup_complete_path(&app).exists() {
        return true;
    }

    // Auto-detect: if Ollama is reachable the system is effectively configured.
    // Write the marker so the wizard never appears again.
    let ollama_ok = probe_ollama_http().await;

    // Also accept OpenAI-style setups: if OPENAI_API_KEY or LLM_BACKEND=openai
    // is set in the environment the user consciously chose a cloud backend.
    let openai_ok = std::env::var("OPENAI_API_KEY")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(false)
        || std::env::var("LLM_BACKEND")
            .map(|v| v.trim().eq_ignore_ascii_case("openai"))
            .unwrap_or(false);

    if ollama_ok || openai_ok {
        // Best-effort: write marker so future launches skip the wizard.
        if let Err(e) = mark_setup_complete(app).await {
            tracing::warn!(
                "Failed to write setup-complete marker: {e}. The setup wizard will re-appear on next launch."
            );
        }
        return true;
    }

    false
}

/// Persist a marker that tells the wizard to skip on next launch.
#[tauri::command]
pub async fn mark_setup_complete(app: tauri::AppHandle) -> Result<(), String> {
    let path = setup_complete_path(&app);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create app data dir: {e}"))?;
    }
    let content = serde_json::json!({
        "completed_at": chrono::Utc::now().to_rfc3339(),
        "version": env!("CARGO_PKG_VERSION")
    });
    std::fs::write(&path, serde_json::to_string_pretty(&content).unwrap())
        .map_err(|e| format!("Failed to write setup_complete.json: {e}"))
}

/// Install Ollama using the platform-appropriate method.
/// Emits "install_ollama_progress" events with { line: String }.
#[tauri::command]
pub async fn install_ollama(app: tauri::AppHandle) -> Result<(), String> {
    #[cfg(target_os = "windows")]
    let args: Vec<&str> = vec!["install", "Ollama.Ollama"];

    #[cfg(target_os = "windows")]
    let program = "winget";

    #[cfg(not(target_os = "windows"))]
    let program = "sh";

    #[cfg(not(target_os = "windows"))]
    let args: Vec<&str> = vec!["-c", "curl -fsSL https://ollama.com/install.sh | sh"];

    let mut child = std::process::Command::new(program)
        .args(&args)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to launch Ollama installer: {e}"))?;

    // Drain stdout/stderr and emit as Tauri events.
    use std::io::{BufRead, BufReader};
    if let Some(stdout) = child.stdout.take() {
        let app2 = app.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let _ = app2.emit(
                    "install_ollama_progress",
                    serde_json::json!({ "line": line }),
                );
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        let app3 = app.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let _ = app3.emit(
                    "install_ollama_progress",
                    serde_json::json!({ "line": line, "stderr": true }),
                );
            }
        });
    }

    let status = child
        .wait()
        .map_err(|e| format!("Ollama installer wait failed: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!("Ollama installer exited with status: {status}"))
    }
}

/// Pull an Ollama model, streaming progress via "pull_model_progress" events.
#[tauri::command]
pub async fn pull_model(app: tauri::AppHandle, model_name: String) -> Result<(), String> {
    let mut child = std::process::Command::new("ollama")
        .args(["pull", &model_name])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to run 'ollama pull {model_name}': {e}"))?;

    use std::io::{BufRead, BufReader};
    if let Some(stdout) = child.stdout.take() {
        let app2 = app.clone();
        let model = model_name.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                let _ = app2.emit(
                    "pull_model_progress",
                    serde_json::json!({ "model": model, "line": line }),
                );
            }
        });
    }
    if let Some(stderr) = child.stderr.take() {
        let app3 = app.clone();
        let model2 = model_name.clone();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let _ = app3.emit(
                    "pull_model_progress",
                    serde_json::json!({ "model": model2, "line": line, "stderr": true }),
                );
            }
        });
    }

    let status = child
        .wait()
        .map_err(|e| format!("ollama pull wait failed: {e}"))?;
    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "ollama pull '{model_name}' exited with status: {status}"
        ))
    }
}
