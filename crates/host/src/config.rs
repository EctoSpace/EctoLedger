use std::sync::OnceLock;

const DEFAULT_DATABASE_URL: &str = "postgres://ectoledger:ectoledger@localhost:5432/ectoledger";

static OBSERVER_TOKEN_CACHE: OnceLock<String> = OnceLock::new();

/// Returns true when ECTO_DEMO_MODE=true|1 is set (demo launcher flag).
pub fn is_demo_mode() -> bool {
    std::env::var("ECTO_DEMO_MODE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Returns true when the process is running in developer/test mode.
/// Production deployments should never set ECTO_DEV_MODE.
pub fn is_dev_mode() -> bool {
    std::env::var("ECTO_DEV_MODE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

pub fn database_url() -> Result<String, std::env::VarError> {
    match std::env::var("DATABASE_URL") {
        Ok(s) => Ok(s),
        Err(std::env::VarError::NotPresent) => {
            if is_dev_mode() {
                tracing::info!(
                    "DATABASE_URL not set — using default dev credentials (ECTO_DEV_MODE=true)."
                );
                Ok(DEFAULT_DATABASE_URL.to_string())
            } else {
                tracing::error!(
                    "DATABASE_URL not set. Set DATABASE_URL explicitly for production, \
                     or set ECTO_DEV_MODE=true to use default dev credentials."
                );
                Err(std::env::VarError::NotPresent)
            }
        }
        Err(e) => Err(e),
    }
}

pub fn ollama_base_url() -> String {
    std::env::var("OLLAMA_BASE_URL").unwrap_or_else(|_| "http://localhost:11434".to_string())
}

pub fn ollama_model() -> String {
    std::env::var("OLLAMA_MODEL").unwrap_or_else(|_| "mistral".to_string())
}

/// Number of steps between auto-snapshots. Env: AGENT_SNAPSHOT_INTERVAL, default 50.
pub fn snapshot_interval() -> u32 {
    std::env::var("AGENT_SNAPSHOT_INTERVAL")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(50)
}

/// LLM backend name: ollama, openai, or anthropic. Env: LLM_BACKEND, default ollama.
pub fn llm_backend() -> String {
    std::env::var("LLM_BACKEND").unwrap_or_else(|_| "ollama".to_string())
}

/// When true, guard is required and GUARD_LLM_BACKEND / GUARD_LLM_MODEL must be set.
/// Env: GUARD_REQUIRED, default TRUE. Set GUARD_REQUIRED=false only for development.
/// In production, a guard running the same model class as the primary is not a real guard.
pub fn guard_required() -> bool {
    std::env::var("GUARD_REQUIRED")
        .ok()
        .and_then(|s| match s.to_lowercase().as_str() {
            "0" | "false" | "no" => Some(false),
            _ => s.parse().ok(),
        })
        .unwrap_or(true)
}

/// Guard LLM backend (for guard-worker). Env: GUARD_LLM_BACKEND. Required when GUARD_REQUIRED=true.
pub fn guard_llm_backend() -> Option<String> {
    std::env::var("GUARD_LLM_BACKEND")
        .ok()
        .filter(|s| !s.is_empty())
}

/// Guard LLM model. Env: GUARD_LLM_MODEL. Required when GUARD_REQUIRED=true.
pub fn guard_llm_model() -> Option<String> {
    std::env::var("GUARD_LLM_MODEL")
        .ok()
        .filter(|s| !s.is_empty())
}

/// Returns an error if guard is required but GUARD_LLM_BACKEND or GUARD_LLM_MODEL are unset.
pub fn ensure_guard_config() -> Result<(), String> {
    if !guard_required() {
        return Ok(());
    }
    let missing: Vec<&str> = [
        guard_llm_backend().is_none().then_some("GUARD_LLM_BACKEND"),
        guard_llm_model().is_none().then_some("GUARD_LLM_MODEL"),
    ]
    .into_iter()
    .flatten()
    .collect();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "GUARD_REQUIRED is set but {} are unset. Set them for production mode.",
            missing.join(" and ")
        ))
    }
}

/// Token for Observer dashboard auth. Env: OBSERVER_TOKEN.
/// If unset, a 32-byte hex token is generated and printed to stdout for this process.
/// All dashboard/API requests must include it (Bearer header or ?token=).
pub fn observer_token() -> String {
    OBSERVER_TOKEN_CACHE
        .get_or_init(|| {
            std::env::var("OBSERVER_TOKEN")
                .ok()
                .filter(|s| !s.is_empty())
                .unwrap_or_else(|| {
                    let token = hex::encode(rand::random::<[u8; 32]>());
                    let host = bind_host();
                    let port = bind_port();
                    let display_host = if host == "0.0.0.0" {
                        "localhost".to_string()
                    } else {
                        host
                    };
                    println!(
                        "⚠️  No OBSERVER_TOKEN set. Generated token for this session: {}",
                        token
                    );
                    println!(
                        "    Dashboard: http://{}:{}?token={}",
                        display_host, port, token
                    );
                    token
                })
        })
        .clone()
}

/// Consecutive LLM errors before aborting the session. Env: AGENT_LLM_ERROR_LIMIT, default 5.
pub fn llm_error_limit() -> u32 {
    std::env::var("AGENT_LLM_ERROR_LIMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn database_url_default_and_override() {
        // database_url() requires ECTO_DEV_MODE to return the default when
        // DATABASE_URL is absent (production mode returns Err).
        unsafe { env::set_var("ECTO_DEV_MODE", "true") };
        unsafe { env::remove_var("DATABASE_URL") };
        assert_eq!(
            database_url().unwrap(),
            "postgres://ectoledger:ectoledger@localhost:5432/ectoledger"
        );
        unsafe { env::set_var("DATABASE_URL", "postgres://example") };
        assert_eq!(database_url().unwrap(), "postgres://example");
        // Clean up
        unsafe { env::remove_var("ECTO_DEV_MODE") };
    }

    #[test]
    fn guard_config_logic() {
        unsafe { env::remove_var("GUARD_REQUIRED") };
        unsafe { env::remove_var("GUARD_LLM_BACKEND") };
        unsafe { env::remove_var("GUARD_LLM_MODEL") };
        assert!(guard_required());
        assert!(ensure_guard_config().is_err());
        unsafe { env::set_var("GUARD_REQUIRED", "false") };
        assert!(!guard_required());
        assert!(ensure_guard_config().is_ok());
    }

    #[test]
    fn snapshot_interval_and_other_defaults() {
        unsafe { env::remove_var("AGENT_SNAPSHOT_INTERVAL") };
        assert_eq!(snapshot_interval(), 50);
        unsafe { env::set_var("AGENT_SNAPSHOT_INTERVAL", "123") };
        assert_eq!(snapshot_interval(), 123);
        unsafe { env::remove_var("OLLAMA_BASE_URL") };
        assert!(ollama_base_url().contains("localhost"));
        unsafe { env::remove_var("LLM_BACKEND") };
        assert_eq!(llm_backend(), "ollama");
    }
}

/// Consecutive Guard denials before aborting the session. Env: AGENT_GUARD_DENIAL_LIMIT, default 3.
pub fn guard_denial_limit() -> u32 {
    std::env::var("AGENT_GUARD_DENIAL_LIMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3)
}

/// Consecutive schema failures (missing/too-short justification) before aborting. Env: AGENT_JUSTIFICATION_FAILURE_LIMIT, default 3.
pub fn justification_failure_limit() -> u32 {
    std::env::var("AGENT_JUSTIFICATION_FAILURE_LIMIT")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3)
}

/// Directory for encrypted session key files. Env: ECTO_DATA_DIR, default `.ectoledger/keys`.
pub fn session_key_dir() -> std::path::PathBuf {
    let base = std::env::var("ECTO_DATA_DIR").unwrap_or_else(|_| ".ectoledger".to_string());
    std::path::PathBuf::from(base).join("keys")
}

/// Path to rollback rules TOML file. Env: ECTO_DATA_DIR, default `.ectoledger/rollback_rules.toml`.
pub fn rollback_rules_path() -> std::path::PathBuf {
    let base = std::env::var("ECTO_DATA_DIR").unwrap_or_else(|_| ".ectoledger".to_string());
    std::path::PathBuf::from(base).join("rollback_rules.toml")
}

/// Directory for user-editable policy files. Env: ECTO_DATA_DIR, default `.ectoledger/policies`.
pub fn policies_dir() -> std::path::PathBuf {
    let base = std::env::var("ECTO_DATA_DIR").unwrap_or_else(|_| ".ectoledger".to_string());
    std::path::PathBuf::from(base).join("policies")
}

/// Path to settings config file. Env: ECTO_DATA_DIR, default `.ectoledger/settings.json`.
pub fn settings_config_path() -> std::path::PathBuf {
    let base = std::env::var("ECTO_DATA_DIR").unwrap_or_else(|_| ".ectoledger".to_string());
    std::path::PathBuf::from(base).join("settings.json")
}

/// Settings override (persisted to file). When present, overrides env vars for display/API.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct SettingsConfig {
    pub database_url: Option<String>,
    pub llm_backend: Option<String>,
    pub ollama_base_url: Option<String>,
    pub ollama_model: Option<String>,
    pub guard_required: Option<bool>,
    pub guard_llm_backend: Option<String>,
    pub guard_llm_model: Option<String>,
    pub max_steps: Option<u32>,
    pub agent_allowed_domains: Option<Vec<String>>,
}

/// Load settings override from file. Returns None if file missing or invalid.
pub fn load_settings_config() -> Option<SettingsConfig> {
    let path = settings_config_path();
    let content = std::fs::read_to_string(&path).ok()?;
    serde_json::from_str::<SettingsConfig>(&content).ok()
}

/// Save settings override to file.
pub fn save_settings_config(cfg: &SettingsConfig) -> Result<(), String> {
    let path = settings_config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    std::fs::write(&path, json).map_err(|e| e.to_string())
}

/// Path to tripwire config file. Env: ECTO_DATA_DIR, default `.ectoledger/tripwire.json`.
pub fn tripwire_config_path() -> std::path::PathBuf {
    let base = std::env::var("ECTO_DATA_DIR").unwrap_or_else(|_| ".ectoledger".to_string());
    std::path::PathBuf::from(base).join("tripwire.json")
}

/// Tripwire configuration (persisted to file).
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct TripwireConfig {
    pub allowed_paths: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub banned_command_patterns: Vec<String>,
    /// Minimum justification length (chars) for non-complete actions. Default 5.
    #[serde(default = "default_min_justification_length")]
    pub min_justification_length: u32,
    /// Require HTTPS for http_get intents. Default true.
    #[serde(default = "default_require_https")]
    pub require_https: bool,
}

fn default_min_justification_length() -> u32 {
    5
}

fn default_require_https() -> bool {
    true
}

/// Load tripwire config from file. Falls back to defaults if file missing.
/// **Panics** if `tripwire.json` exists but contains invalid JSON — a broken
/// config must never be silently ignored.
pub fn load_tripwire_config() -> TripwireConfig {
    let path = tripwire_config_path();
    match std::fs::read_to_string(&path) {
        Ok(content) => match serde_json::from_str::<TripwireConfig>(&content) {
            Ok(cfg) => return cfg,
            Err(e) => panic!(
                "tripwire.json at '{}' has invalid JSON syntax: {}. \
                 Fix or delete the file to use defaults.",
                path.display(),
                e
            ),
        },
        Err(_) => { /* file missing — fall through to defaults */ }
    }
    let workspace = std::env::current_dir()
        .unwrap_or_else(|_| std::path::PathBuf::from("."))
        .to_string_lossy()
        .to_string();
    let allowed_domains: Vec<String> = std::env::var("AGENT_ALLOWED_DOMAINS")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();
    TripwireConfig {
        allowed_paths: vec![workspace],
        allowed_domains,
        banned_command_patterns: crate::tripwire::default_banned_command_patterns(),
        min_justification_length: 5,
        require_https: true,
    }
}

/// Save tripwire config to file (atomic write via tempfile + rename).
pub fn save_tripwire_config(cfg: &TripwireConfig) -> Result<(), String> {
    let path = tripwire_config_path();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let json = serde_json::to_string_pretty(cfg).map_err(|e| e.to_string())?;
    // Atomic write: write to temp file then rename to prevent torn configs on crash.
    let dir = path.parent().unwrap_or(std::path::Path::new("."));
    let mut tmp = tempfile::NamedTempFile::new_in(dir).map_err(|e| e.to_string())?;
    std::io::Write::write_all(&mut tmp, json.as_bytes()).map_err(|e| e.to_string())?;
    tmp.persist(&path).map_err(|e| e.to_string())?;
    Ok(())
}

/// Max approximate token budget per session (character count / 4 estimate).
/// Env: AGENT_TOKEN_BUDGET_MAX. Default: unlimited (None).
pub fn token_budget_max() -> Option<u64> {
    std::env::var("AGENT_TOKEN_BUDGET_MAX")
        .ok()
        .and_then(|s| s.parse().ok())
}

/// Max cognitive loop steps. Env: AGENT_MAX_STEPS, default 20.
pub fn max_steps() -> u32 {
    std::env::var("AGENT_MAX_STEPS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20)
}

// ── Webhook / SIEM egress ──────────────────────────────────────────────────────

/// Configuration for outbound webhook / SIEM egress.
/// Set `WEBHOOK_URL` to enable; `WEBHOOK_BEARER_TOKEN` and `SIEM_FORMAT` are optional.
#[derive(Clone, Debug)]
pub struct WebhookConfig {
    /// Full URL to POST security events to (e.g. Slack, Splunk HEC, custom SIEM endpoint).
    pub url: String,
    /// Optional `Authorization: Bearer <token>` header value.
    pub bearer_token: Option<String>,
    /// Output format: `json` (default), `cef` (ArcSight CEF), or `leef` (IBM LEEF).
    pub siem_format: String,
}

/// Returns `Some(WebhookConfig)` when `WEBHOOK_URL` is set, otherwise `None` (egress disabled).
pub fn webhook_config() -> Option<WebhookConfig> {
    let url = std::env::var("WEBHOOK_URL")
        .ok()
        .filter(|s| !s.is_empty())?;
    let bearer_token = std::env::var("WEBHOOK_BEARER_TOKEN")
        .ok()
        .filter(|s| !s.is_empty());
    let siem_format = std::env::var("SIEM_FORMAT")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "json".to_string());
    Some(WebhookConfig {
        url,
        bearer_token,
        siem_format,
    })
}

/// Number of cognitive-loop steps between automatic signing-key rotations.
/// Env: `AGENT_KEY_ROTATION_STEPS`. Default: `None` (rotation disabled).
///
/// Example: `AGENT_KEY_ROTATION_STEPS=50` rotates after every 50 agent steps.
pub fn key_rotation_interval_steps() -> Option<u32> {
    std::env::var("AGENT_KEY_ROTATION_STEPS")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .filter(|&n| n > 0)
}

// ── Observer dashboard network binding ───────────────────────────────────────

/// Host address for the Observer dashboard TCP listener.
/// Env: `ECTO_BIND_HOST`, default `"0.0.0.0"` (all interfaces).
/// Set to `"127.0.0.1"` to restrict to loopback only in hardened deployments.
pub fn bind_host() -> String {
    std::env::var("ECTO_BIND_HOST").unwrap_or_else(|_| "0.0.0.0".to_string())
}

/// Port for the Observer dashboard TCP listener.
/// Env: `ECTO_BIND_PORT`, default `3000`.
/// Set to `0` to let the OS assign a free port (useful in integration test suites).
///
/// **Panics** if `ECTO_BIND_PORT` is set but cannot be parsed as a `u16`.
pub fn bind_port() -> u16 {
    match std::env::var("ECTO_BIND_PORT") {
        Ok(s) => s.parse::<u16>().unwrap_or_else(|e| {
            panic!(
                "ECTO_BIND_PORT='{}' is not a valid u16 port number: {}",
                s, e
            )
        }),
        Err(_) => 3000,
    }
}

// ── Webhook HMAC signing ──────────────────────────────────────────────────────

/// HMAC-SHA256 secret for signing outbound webhook payloads.
/// When set, every webhook POST includes an `X-EctoLedger-Signature: sha256=<hex>` header
/// so receivers can verify authenticity (GitHub webhook signature convention).
/// Env: `WEBHOOK_HMAC_SECRET`. Default: `None` (signing disabled).
pub fn webhook_hmac_secret() -> Option<String> {
    std::env::var("WEBHOOK_HMAC_SECRET")
        .ok()
        .filter(|s| !s.is_empty())
}

/// Maximum outbound webhook deliveries per second, per target URL.
/// Env: `WEBHOOK_RATE_LIMIT_PER_SECOND`, default `10`.
pub fn webhook_rate_limit_per_second() -> u64 {
    std::env::var("WEBHOOK_RATE_LIMIT_PER_SECOND")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10)
}

/// Whether to forward `GuardDenial` events to the webhook egress worker.
/// Env: `WEBHOOK_INCLUDE_GUARD`, default `true`.
/// Set `false` (or `0`) to suppress guard-denial events from SIEM egress.
pub fn webhook_include_guard() -> bool {
    std::env::var("WEBHOOK_INCLUDE_GUARD")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true)
}

/// Whether to forward `TripwireRejection` events to the webhook egress worker.
/// Env: `WEBHOOK_INCLUDE_TRIPWIRE`, default `true`.
/// Set `false` (or `0`) to suppress tripwire-rejection events from SIEM egress.
pub fn webhook_include_tripwire() -> bool {
    std::env::var("WEBHOOK_INCLUDE_TRIPWIRE")
        .map(|v| v != "false" && v != "0")
        .unwrap_or(true)
}

/// Per-IP rate limit for `POST /api/sessions` (and `/api/chat`) — requests per second.
/// Env: `SESSION_RATE_LIMIT_PER_SECOND`, default `2`.
/// Set to a high value (e.g. `1000`) in integration-test environments.
pub fn session_rate_limit_per_second() -> u64 {
    std::env::var("SESSION_RATE_LIMIT_PER_SECOND")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2)
}

/// Burst allowance for the `POST /api/sessions` rate limiter.
/// Env: `SESSION_RATE_LIMIT_BURST`, default `5`.
pub fn session_rate_limit_burst() -> u32 {
    std::env::var("SESSION_RATE_LIMIT_BURST")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5)
}

/// SSE keep-alive interval (seconds). Env: `SSE_KEEPALIVE_SECS`, default `15`.
/// Lower this in integration-test environments so keepalive events arrive
/// before pytest's global timeout fires.
pub fn sse_keepalive_secs() -> u64 {
    std::env::var("SSE_KEEPALIVE_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(15)
}

/// Global per-IP API rate limit — requests per second.
/// Env: `API_RATE_LIMIT_PER_SECOND`, default `60`.
pub fn api_rate_limit_per_second() -> u64 {
    std::env::var("API_RATE_LIMIT_PER_SECOND")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(60)
}

/// Burst allowance for the global API rate limiter.
/// Env: `API_RATE_LIMIT_BURST`, default `120`.
pub fn api_rate_limit_burst() -> u32 {
    std::env::var("API_RATE_LIMIT_BURST")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(120)
}

/// Per-IP rate limit for the SSE `GET /api/stream` endpoint — connections per second.
/// Env: `SSE_RATE_LIMIT_PER_SECOND`, default `4`.
/// Set to a high value in integration-test environments.
pub fn sse_rate_limit_per_second() -> u64 {
    std::env::var("SSE_RATE_LIMIT_PER_SECOND")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(4)
}

/// Burst allowance for the SSE stream rate limiter.
/// Env: `SSE_RATE_LIMIT_BURST`, default `10`.
pub fn sse_rate_limit_burst() -> u32 {
    std::env::var("SSE_RATE_LIMIT_BURST")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10)
}

/// Database connection-pool size.
/// Env: `DATABASE_POOL_SIZE`. Default: `2 × CPU count`, clamped to `[5, 50]`.
/// The clamp is applied to the **final** value regardless of whether it came
/// from the environment variable or the CPU-based default.
pub fn database_pool_size() -> u32 {
    std::env::var("DATABASE_POOL_SIZE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| {
            let cpus = std::thread::available_parallelism()
                .map(|n| n.get() as u32)
                .unwrap_or(4);
            cpus * 2
        })
        .clamp(5, 50)
}
