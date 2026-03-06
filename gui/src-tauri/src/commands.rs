// Tauri commands — HTTP proxy to the embedded Axum server on localhost.
// Port and auth token are resolved from the embedded server's global OnceLock
// (populated in `embedded::start`).  Env var overrides are still honoured for
// development against a standalone server.

use serde::Deserialize;
// Used by `open_devtools` (debug builds only) for `app.get_webview_window()`.
use tauri::Emitter;
#[allow(unused_imports)]
use tauri::Manager;

use crate::embedded;

/// Shared HTTP client — reuses connection pool across all Tauri commands.
fn http_client() -> &'static reqwest::Client {
    static CLIENT: std::sync::OnceLock<reqwest::Client> = std::sync::OnceLock::new();
    CLIENT.get_or_init(|| {
        reqwest::Client::builder()
            .connect_timeout(std::time::Duration::from_secs(5))
            .timeout(std::time::Duration::from_secs(30))
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .expect("reqwest Client::builder() with plain timeouts always succeeds")
    })
}

fn base_url() -> String {
    // 1. Explicit override wins (useful for dev against standalone server).
    if let Ok(host) = std::env::var("ECTO_HOST") {
        return host;
    }
    // 2. Read from the embedded server global.
    if let Some(srv) = embedded::instance() {
        return format!("http://127.0.0.1:{}", srv.port);
    }
    // 3. Legacy fallback.
    let port = std::env::var("ECTO_BIND_PORT").unwrap_or_else(|_| "3000".to_string());
    format!("http://127.0.0.1:{}", port)
}

fn obs_token() -> Option<String> {
    // Env var override first.
    if let Ok(t) = std::env::var("OBSERVER_TOKEN")
        && !t.is_empty()
    {
        return Some(t);
    }
    // Then try the embedded server's bootstrap token.
    embedded::instance().map(|s| s.token.clone())
}

/// Expose the observer token to the Svelte frontend so it can construct
/// authenticated EventSource URLs for the SSE stream (EventSource does not
/// support custom headers, so the token must be passed as ?token=).
#[tauri::command]
pub async fn observer_token() -> String {
    obs_token().unwrap_or_default()
}

fn auth_headers() -> reqwest::header::HeaderMap {
    let mut headers = reqwest::header::HeaderMap::new();
    if let Some(token) = obs_token()
        && let Ok(value) = format!("Bearer {}", token).parse()
    {
        headers.insert(reqwest::header::AUTHORIZATION, value);
    }
    headers
}

/// Strip HTML tags from error response bodies so that styled HTML 404 pages
/// from wrong servers don't flood the GUI error display with raw markup.
fn sanitize_error_body(body: &str) -> String {
    if !body.contains('<') {
        return body.trim().to_string();
    }
    let mut result = String::new();
    let mut in_tag = false;
    for ch in body.chars() {
        match ch {
            '<' => in_tag = true,
            '>' => {
                in_tag = false;
                if !result.ends_with(' ') {
                    result.push(' ');
                }
            }
            _ if !in_tag => result.push(ch),
            _ => {}
        }
    }
    let cleaned: String = result.split_whitespace().collect::<Vec<_>>().join(" ");
    if cleaned.is_empty() {
        "(empty HTML response — the backend may not be running on the expected port)".to_string()
    } else {
        cleaned
    }
}

#[tauri::command]
pub async fn server_url() -> String {
    base_url()
}

#[tauri::command]
pub async fn is_demo_mode() -> bool {
    std::env::var("ECTO_DEMO_MODE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

#[tauri::command]
pub async fn reset_demo_data() -> Result<serde_json::Value, String> {
    let client = http_client();
    let res = client
        .post(format!("{}/api/admin/reset-demo", base_url()))
        .headers(auth_headers())
        .send()
        .await
        .map_err(|e| format!("Cannot reach backend: {e}"))?;
    if !res.status().is_success() {
        let msg = res.text().await.unwrap_or_default();
        return Err(format!("Reset failed: {}", sanitize_error_body(&msg)));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn open_devtools(app: tauri::AppHandle) -> Result<(), String> {
    #[cfg(debug_assertions)]
    {
        let window = app
            .get_webview_window("main")
            .ok_or("Main window not found")?;
        window.open_devtools();
        Ok(())
    }
    #[cfg(not(debug_assertions))]
    {
        let _ = app;
        Err("DevTools are disabled in release builds".to_string())
    }
}

/// Returns the full dashboard URL (without auth token) for "Open full dashboard" link.
/// Auth token is no longer appended as a query parameter to avoid leaking it in
/// Referrer headers, server logs, and the DOM. The iframe uses the Tauri proxy
/// commands instead.
#[tauri::command]
pub async fn dashboard_url() -> String {
    base_url()
}

#[tauri::command]
pub async fn get_events(session_id: Option<String>) -> Result<serde_json::Value, String> {
    let sid = session_id.ok_or("session_id required")?;
    let url = format!(
        "{}/api/events?session_id={}",
        base_url(),
        urlencoding::encode(&sid)
    );
    let client = http_client();
    let mut req = client.get(url);
    req = req.headers(auth_headers().clone());
    let res = req
        .send()
        .await
        .map_err(|e| format!("Cannot reach server: {e}"))?;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        return Err(match status.as_u16() {
            429 => "Rate limited — retrying automatically.".to_string(),
            404 => format!("Session {sid} not found."),
            _ => format!(
                "Failed to load events ({status}): {}",
                sanitize_error_body(&body)
            ),
        });
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| format!("Invalid events response: {e}"))
}

#[derive(Deserialize)]
pub struct RunPromptArgs {
    pub goal: String,
    pub llm_backend: Option<String>,
    pub llm_model: Option<String>,
}

#[tauri::command]
pub async fn run_prompt(args: RunPromptArgs) -> Result<serde_json::Value, String> {
    let client = http_client();
    let req = client
        .post(format!("{}/api/sessions", base_url()))
        .headers(auth_headers().clone())
        .json(&serde_json::json!({
            "goal": args.goal,
            "llm_backend": args.llm_backend.unwrap_or_else(|| "ollama".to_string()),
            "llm_model": args.llm_model.unwrap_or_else(|| "llama3".to_string()),
        }));
    let res = req
        .send()
        .await
        .map_err(|e| format!("Cannot reach backend: {e}"))?;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        let body = body.trim();
        // Prefer the server-provided body text (now includes real error
        // messages).  Fall back to the status reason phrase if the body is
        // empty (legacy server or network-level error).
        let detail = if body.is_empty() {
            format!("Server returned {status}")
        } else {
            body.to_string()
        };
        return Err(detail);
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

/// Direct one-shot LLM chat — no agent loop, no guard, no tripwire.
#[tauri::command]
pub async fn chat(message: String) -> Result<serde_json::Value, String> {
    let client = http_client();
    let req = client
        .post(format!("{}/api/chat", base_url()))
        .headers(auth_headers().clone())
        .json(&serde_json::json!({ "message": message }));
    let res = req
        .send()
        .await
        .map_err(|e| format!("Cannot reach server: {e}"))?;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        let body = body.trim();
        let detail = if body.is_empty() {
            format!("Server returned {status}")
        } else {
            body.to_string()
        };
        return Err(detail);
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| format!("Invalid chat response: {e}"))
}

#[tauri::command]
pub async fn get_metrics() -> Result<serde_json::Value, String> {
    let client = http_client();
    let mut req = client.get(format!("{}/api/metrics/security", base_url()));
    req = req.headers(auth_headers().clone());
    let res = req
        .send()
        .await
        .map_err(|e| format!("Cannot reach server: {e}"))?;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        let reason = status.canonical_reason().unwrap_or("").trim();
        return Err(match status.as_u16() {
            429 => "Server rate limit reached. Metrics will retry automatically.".to_string(),
            401 | 403 => format!("Authentication failed ({status}). Restart the application."),
            500..=599 => format!(
                "Server error ({status} {reason}): {}",
                sanitize_error_body(&body)
            ),
            _ => format!(
                "Metrics request failed: {status} {reason} {}",
                sanitize_error_body(&body)
            ),
        });
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| format!("Invalid metrics response: {e}"))
}

#[tauri::command]
pub async fn get_prometheus_metrics() -> Result<String, String> {
    let client = http_client();
    let mut req = client.get(format!("{}/metrics", base_url()));
    req = req.headers(auth_headers().clone());
    let res = req.send().await.map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("Metrics request failed: {}", res.status()));
    }
    res.text().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn export_certificate(session_id: String) -> Result<Vec<u8>, String> {
    let client = http_client();
    let mut req = client.get(format!(
        "{}/api/certificates/{}",
        base_url(),
        urlencoding::encode(&session_id)
    ));
    req = req.headers(auth_headers().clone());
    let res = req.send().await.map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("Certificate export failed: {}", res.status()));
    }
    let bytes = res.bytes().await.map_err(|e| e.to_string())?;
    Ok(bytes.to_vec())
}

#[tauri::command]
pub async fn get_policy_content(name: String) -> Result<String, String> {
    let client = http_client();
    let mut req = client.get(format!(
        "{}/api/policies/{}",
        base_url(),
        urlencoding::encode(&name)
    ));
    req = req.headers(auth_headers().clone());
    let res = req.send().await.map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("Policy not found: {}", name));
    }
    res.text().await.map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_config() -> Result<serde_json::Value, String> {
    let client = http_client();
    let mut req = client.get(format!("{}/api/config", base_url()));
    req = req.headers(auth_headers().clone());
    let res = req.send().await.map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let status = res.status();
        let msg = res.text().await.unwrap_or_else(|_| status.to_string());
        return Err(format!(
            "Failed to load config: {}",
            sanitize_error_body(&msg)
        ));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct ConfigPayload {
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

#[tauri::command]
pub async fn save_config(payload: ConfigPayload) -> Result<serde_json::Value, String> {
    let client = http_client();
    let res = client
        .put(format!("{}/api/config", base_url()))
        .headers(auth_headers().clone())
        .json(&payload)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let status = res.status();
        let msg = res.text().await.unwrap_or_else(|_| status.to_string());
        return Err(format!("Save failed: {}", sanitize_error_body(&msg)));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[derive(serde::Deserialize, Default)]
pub struct GetOllamaModelsArgs {
    #[serde(rename = "baseUrlOverride")]
    pub base_url_override: Option<String>,
}

#[tauri::command]
pub async fn get_ollama_models(args: GetOllamaModelsArgs) -> Result<serde_json::Value, String> {
    let has_override = args.base_url_override.is_some();
    let url = args
        .base_url_override
        .unwrap_or_else(|| {
            std::env::var("OLLAMA_BASE_URL")
                .unwrap_or_else(|_| "http://localhost:11434".to_string())
        })
        .trim_end_matches('/')
        .to_string();

    // SSRF protection: only allow requests to localhost / loopback addresses
    // when the URL comes from user input (base_url_override).
    if has_override {
        let parsed_url = url::Url::parse(&url).map_err(|_| "Invalid URL format".to_string())?;
        let host = parsed_url.host_str().unwrap_or("");
        let is_local =
            host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]";
        if !is_local {
            return Err(format!(
                "Ollama URL must point to localhost (got '{}'); set OLLAMA_BASE_URL env var for remote hosts",
                host
            ));
        }
    }

    let client = http_client();
    let res = client
        .get(format!("{}/api/tags", url))
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("Ollama not reachable at {}: {}", url, res.status()));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_tripwire_config() -> Result<serde_json::Value, String> {
    let client = http_client();
    let mut req = client.get(format!("{}/api/tripwire", base_url()));
    req = req.headers(auth_headers().clone());
    let res = req.send().await.map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let status = res.status();
        let msg = res.text().await.unwrap_or_else(|_| status.to_string());
        return Err(format!(
            "Failed to load tripwire config: {}",
            sanitize_error_body(&msg)
        ));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[derive(serde::Serialize, serde::Deserialize)]
pub struct TripwireConfigPayload {
    pub allowed_paths: Vec<String>,
    pub allowed_domains: Vec<String>,
    pub banned_command_patterns: Vec<String>,
    pub min_justification_length: Option<u32>,
    pub require_https: Option<bool>,
}

#[tauri::command]
pub async fn save_tripwire_config(
    payload: TripwireConfigPayload,
) -> Result<serde_json::Value, String> {
    let client = http_client();
    let res = client
        .put(format!("{}/api/tripwire", base_url()))
        .headers(auth_headers().clone())
        .json(&payload)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let status = res.status();
        let msg = res.text().await.unwrap_or_else(|_| status.to_string());
        return Err(format!("Save failed: {}", sanitize_error_body(&msg)));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_policies() -> Result<serde_json::Value, String> {
    let client = http_client();
    let mut req = client.get(format!("{}/api/policies", base_url()));
    req = req.headers(auth_headers().clone());
    let res = req.send().await.map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let status = res.status();
        let msg = res.text().await.unwrap_or_else(|_| status.to_string());
        return Err(format!(
            "Failed to load policies: {}",
            sanitize_error_body(&msg)
        ));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn save_policy(name: String, content: String) -> Result<String, String> {
    let client = http_client();
    let res = client
        .put(format!(
            "{}/api/policies/{}",
            base_url(),
            urlencoding::encode(&name)
        ))
        .headers(auth_headers().clone())
        .body(content)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("Save failed: {}", res.status()));
    }
    Ok(res.status().to_string())
}

#[tauri::command]
pub async fn delete_policy(name: String) -> Result<(), String> {
    let client = http_client();
    let res = client
        .delete(format!(
            "{}/api/policies/{}",
            base_url(),
            urlencoding::encode(&name)
        ))
        .headers(auth_headers().clone())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let status = res.status();
        let msg = res.text().await.unwrap_or_else(|_| status.to_string());
        return Err(if status.as_u16() == 403 {
            "Built-in policies cannot be deleted.".to_string()
        } else {
            format!("Delete failed: {}", sanitize_error_body(&msg))
        });
    }
    Ok(())
}

#[tauri::command]
pub async fn download_report(session_id: String) -> Result<Vec<u8>, String> {
    let client = http_client();
    let mut req = client.get(format!(
        "{}/api/reports/{}",
        base_url(),
        urlencoding::encode(&session_id)
    ));
    req = req.headers(auth_headers().clone());
    let res = req.send().await.map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        return Err(format!("Report download failed: {}", res.status()));
    }
    res.bytes()
        .await
        .map(|b| b.to_vec())
        .map_err(|e| e.to_string())
}

// ── Token management ─────────────────────────────────────────────────────────

#[tauri::command]
pub async fn get_tokens() -> Result<serde_json::Value, String> {
    let client = http_client();
    let res = client
        .get(format!("{}/api/tokens", base_url()))
        .headers(auth_headers())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let msg = res.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to list tokens: {}",
            sanitize_error_body(&msg)
        ));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn create_token(
    label: String,
    role: String,
    expiry_days: Option<u32>,
) -> Result<serde_json::Value, String> {
    // Validate role against known allowed values to prevent privilege escalation.
    const ALLOWED_ROLES: &[&str] = &["admin", "auditor", "agent"];
    if !ALLOWED_ROLES.contains(&role.as_str()) {
        return Err(format!(
            "Invalid role '{}'. Allowed: {:?}",
            role, ALLOWED_ROLES
        ));
    }
    let client = http_client();
    let body = serde_json::json!({ "label": label, "role": role, "expires_in_days": expiry_days });
    let res = client
        .post(format!("{}/api/tokens", base_url()))
        .headers(auth_headers())
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let msg = res.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to create token: {}",
            sanitize_error_body(&msg)
        ));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn delete_token(token_hash: String) -> Result<(), String> {
    let client = http_client();
    let res = client
        .delete(format!(
            "{}/api/tokens/{}",
            base_url(),
            urlencoding::encode(&token_hash)
        ))
        .headers(auth_headers())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let msg = res.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to revoke token: {}",
            sanitize_error_body(&msg)
        ));
    }
    Ok(())
}

// ── Webhook management ────────────────────────────────────────────────────────

#[tauri::command]
pub async fn get_sessions(
    status: Option<String>,
    limit: Option<u32>,
    offset: Option<u32>,
) -> Result<serde_json::Value, String> {
    let client = http_client();
    // build URL with optional query params
    let mut url = format!("{}/api/sessions", base_url());
    if status.is_some() || limit.is_some() || offset.is_some() {
        url.push('?');
        if let Some(s) = status {
            url.push_str(&format!("status={}&", urlencoding::encode(&s)));
        }
        if let Some(l) = limit {
            url.push_str(&format!("limit={}&", l));
        }
        if let Some(o) = offset {
            url.push_str(&format!("offset={}&", o));
        }
        // trim trailing '&' or '?'
        while url.ends_with('&') || url.ends_with('?') {
            url.pop();
        }
    }
    let res = client
        .get(url)
        .headers(auth_headers())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let msg = res.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to list sessions: {}",
            sanitize_error_body(&msg)
        ));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_session(session_id: String) -> Result<serde_json::Value, String> {
    let client = http_client();
    let res = client
        .get(format!(
            "{}/api/sessions/{}",
            base_url(),
            urlencoding::encode(&session_id)
        ))
        .headers(auth_headers())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let msg = res.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to fetch session: {}",
            sanitize_error_body(&msg)
        ));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_session_vc(session_id: String) -> Result<serde_json::Value, String> {
    let client = http_client();
    let res = client
        .get(format!(
            "{}/api/sessions/{}/vc",
            base_url(),
            urlencoding::encode(&session_id)
        ))
        .headers(auth_headers())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if res.status().as_u16() == 404 {
        return Err("No VC found for this session. Only completed Agent-mode sessions generate a Verifiable Credential. Run an audit via Agent mode first.".to_string());
    }
    if !res.status().is_success() {
        let msg = res.text().await.unwrap_or_default();
        return Err(format!("Failed to fetch VC: {}", sanitize_error_body(&msg)));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn get_webhooks() -> Result<serde_json::Value, String> {
    let client = http_client();
    let res = client
        .get(format!("{}/api/webhooks", base_url()))
        .headers(auth_headers())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let msg = res.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to list webhooks: {}",
            sanitize_error_body(&msg)
        ));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn create_webhook(
    label: String,
    url: String,
    bearer_token: Option<String>,
    siem_format: String,
    filter_kinds: Vec<String>,
    enabled: bool,
) -> Result<serde_json::Value, String> {
    let client = http_client();
    let body = serde_json::json!({
        "label": label,
        "url": url,
        "bearer_token": bearer_token,
        "siem_format": siem_format,
        "filter_kinds": filter_kinds,
        "enabled": enabled,
    });
    let res = client
        .post(format!("{}/api/webhooks", base_url()))
        .headers(auth_headers())
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let msg = res.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to create webhook: {}",
            sanitize_error_body(&msg)
        ));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

#[tauri::command]
pub async fn delete_webhook(webhook_id: String) -> Result<(), String> {
    let client = http_client();
    let res = client
        .delete(format!(
            "{}/api/webhooks/{}",
            base_url(),
            urlencoding::encode(&webhook_id)
        ))
        .headers(auth_headers())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let msg = res.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to delete webhook: {}",
            sanitize_error_body(&msg)
        ));
    }
    Ok(())
}

#[tauri::command]
pub async fn toggle_webhook(webhook_id: String, enabled: bool) -> Result<(), String> {
    let client = http_client();
    let body = serde_json::json!({ "enabled": enabled });
    let res = client
        .put(format!(
            "{}/api/webhooks/{}",
            base_url(),
            urlencoding::encode(&webhook_id)
        ))
        .headers(auth_headers())
        .json(&body)
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if !res.status().is_success() {
        let msg = res.text().await.unwrap_or_default();
        return Err(format!(
            "Failed to toggle webhook: {}",
            sanitize_error_body(&msg)
        ));
    }
    Ok(())
}

/// Call `GET /api/sessions/{id}/vc/verify` — returns the decoded VC payload plus a `valid` flag.
#[tauri::command]
pub async fn verify_session_vc(session_id: String) -> Result<serde_json::Value, String> {
    let client = http_client();
    let res = client
        .get(format!(
            "{}/api/sessions/{}/vc/verify",
            base_url(),
            urlencoding::encode(&session_id)
        ))
        .headers(auth_headers())
        .send()
        .await
        .map_err(|e| e.to_string())?;
    if res.status().as_u16() == 404 {
        return Err("No VC found for this session. Only completed Agent-mode sessions generate a Verifiable Credential.".to_string());
    }
    if !res.status().is_success() {
        let status = res.status();
        let msg = res.text().await.unwrap_or_default();
        let msg = msg.trim();
        return Err(if msg.is_empty() {
            format!("VC verification failed (HTTP {})", status.as_u16())
        } else {
            format!("VC verify failed: {}", sanitize_error_body(msg))
        });
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

// ── Approval gate ────────────────────────────────────────────────────────────

/// Poll `GET /api/approvals/{session_id}/pending` to check for a pending
/// human-approval gate.  Returns `null` when no gate is pending.
#[tauri::command]
pub async fn get_pending_approval(session_id: String) -> Result<serde_json::Value, String> {
    let client = http_client();
    let res = client
        .get(format!(
            "{}/api/approvals/{}/pending",
            base_url(),
            urlencoding::encode(&session_id)
        ))
        .headers(auth_headers())
        .send()
        .await
        .map_err(|e| format!("Cannot reach server: {e}"))?;
    if !res.status().is_success() {
        let status = res.status();
        let body = res.text().await.unwrap_or_default();
        return Err(format!(
            "Pending approval check failed ({status}): {}",
            sanitize_error_body(&body)
        ));
    }
    res.json::<serde_json::Value>()
        .await
        .map_err(|e| e.to_string())
}

/// Post `POST /api/approvals/{session_id}` with an approval decision.
/// `approved` = true → approve, false → deny.
#[tauri::command]
pub async fn post_approval_decision(
    session_id: String,
    gate_id: String,
    approved: bool,
    reason: Option<String>,
) -> Result<(), String> {
    let client = http_client();
    let body = serde_json::json!({
        "gate_id": gate_id,
        "approved": approved,
        "reason": reason,
    });
    let res = client
        .post(format!(
            "{}/api/approvals/{}",
            base_url(),
            urlencoding::encode(&session_id)
        ))
        .headers(auth_headers())
        .json(&body)
        .send()
        .await
        .map_err(|e| format!("Cannot reach server: {e}"))?;
    if !res.status().is_success() {
        let msg = res.text().await.unwrap_or_default();
        return Err(format!(
            "Approval decision failed: {}",
            sanitize_error_body(&msg)
        ));
    }
    Ok(())
}

// ── Developer Hub: run shell command and stream output ──────────────────────
// Security: only allowlisted commands are permitted to prevent RCE via compromised frontend.

const ALLOWED_DEV_COMMANDS: &[(&str, Option<&str>)] = &[
    (
        "python -m pip install -e \".[langchain,autogen]\" && python -m pytest tests/",
        Some("sdk/python"),
    ),
    ("npm ci && npm run build", Some("sdk/typescript")),
    ("cargo test -p ectoledger", None),
];

#[derive(serde::Deserialize)]
pub struct RunShellCommandArgs {
    pub cmd: String,
    pub cwd: Option<String>,
}

#[derive(serde::Serialize)]
pub struct RunShellCommandResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
}

#[tauri::command]
pub async fn run_shell_command(args: RunShellCommandArgs) -> Result<RunShellCommandResult, String> {
    let allowed = ALLOWED_DEV_COMMANDS
        .iter()
        .find(|(cmd, cwd)| *cmd == args.cmd && *cwd == args.cwd.as_deref());
    if allowed.is_none() {
        return Err("Command not in allowlist".to_string());
    }
    let (cmd, cwd) = (args.cmd, args.cwd);
    let result = tokio::task::spawn_blocking(move || {
        let mut builder = std::process::Command::new("sh");
        builder.arg("-c").arg(&cmd);
        builder
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped());
        if let Some(ref dir) = cwd {
            builder.current_dir(dir);
        }
        let output = builder
            .output()
            .map_err(|e| format!("Failed to run command: {}", e))?;
        let stdout = String::from_utf8_lossy(&output.stdout).to_string();
        let stderr = String::from_utf8_lossy(&output.stderr).to_string();
        let exit_code = output.status.code();
        Ok::<_, String>(RunShellCommandResult {
            stdout,
            stderr,
            exit_code,
        })
    })
    .await
    .map_err(|e| format!("run_shell_command task join: {}", e))??;
    Ok(result)
}

#[derive(Clone, serde::Serialize)]
pub struct ShellCommandStreamPayload {
    pub line: String,
    pub stream: String,
}

/// Runs an allowlisted shell command and streams stdout/stderr to the frontend via "shell-command-output" events.
#[tauri::command]
pub async fn run_shell_command_streaming(
    app: tauri::AppHandle,
    args: RunShellCommandArgs,
) -> Result<RunShellCommandResult, String> {
    let allowed = ALLOWED_DEV_COMMANDS
        .iter()
        .find(|(cmd, cwd)| *cmd == args.cmd && *cwd == args.cwd.as_deref());
    if allowed.is_none() {
        return Err("Command not in allowlist".to_string());
    }

    use std::process::Stdio;
    use tokio::io::AsyncBufReadExt;
    use tokio::process::Command;

    let mut builder = Command::new("sh");
    builder.arg("-c").arg(&args.cmd);
    builder.stdout(Stdio::piped()).stderr(Stdio::piped());
    if let Some(ref dir) = args.cwd {
        builder.current_dir(dir);
    }
    let mut child = builder
        .spawn()
        .map_err(|e| format!("Failed to run command: {}", e))?;

    let stdout = child.stdout.take().ok_or("no stdout")?;
    let stderr = child.stderr.take().ok_or("no stderr")?;

    let app_out = app.clone();
    let app_err = app.clone();

    let out_task = tokio::spawn(async move {
        let mut reader = tokio::io::BufReader::new(stdout).lines();
        let mut acc = String::new();
        while let Ok(Some(line)) = reader.next_line().await {
            acc.push_str(&line);
            acc.push('\n');
            let _ = app_out.emit(
                "shell-command-output",
                ShellCommandStreamPayload {
                    line,
                    stream: "stdout".to_string(),
                },
            );
        }
        acc
    });

    let err_task = tokio::spawn(async move {
        let mut reader = tokio::io::BufReader::new(stderr).lines();
        let mut acc = String::new();
        while let Ok(Some(line)) = reader.next_line().await {
            acc.push_str(&line);
            acc.push('\n');
            let _ = app_err.emit(
                "shell-command-output",
                ShellCommandStreamPayload {
                    line,
                    stream: "stderr".to_string(),
                },
            );
        }
        acc
    });

    let (out_res, err_res) = tokio::join!(out_task, err_task);
    let stdout_acc = out_res.map_err(|e| format!("stdout task: {}", e))?;
    let stderr_acc = err_res.map_err(|e| format!("stderr task: {}", e))?;

    let status = child
        .wait()
        .await
        .map_err(|e| format!("wait failed: {}", e))?;
    let exit_code = status.code();

    Ok(RunShellCommandResult {
        stdout: stdout_acc,
        stderr: stderr_acc,
        exit_code,
    })
}
