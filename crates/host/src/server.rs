use crate::agent;
use crate::approvals::{ApprovalDecisionRequest, ApprovalState, PendingApproval};
use crate::config;
use crate::guard::GuardExecutor;
use crate::guard_process::GuardProcess;
use crate::ledger;
use crate::llm;
use crate::pool::DatabasePool;
use crate::schema::{EventPayload, SessionRow};
use crate::tripwire;
use axum::Router;
use axum::extract::{ConnectInfo, Path, Query, Request, State};
use axum::http::StatusCode;
use axum::middleware::Next;
use axum::response::Html;
use axum::response::sse::{Event, Sse};
use axum::routing::{delete, get, post, put};
use regex_lite::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::sync::mpsc;
use tokio_stream::StreamExt;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;
use tower_governor::{
    GovernorLayer, governor::GovernorConfigBuilder, key_extractor::SmartIpKeyExtractor,
};
use tower_http::cors::CorsLayer;
use uuid::Uuid;

use crate::metrics::Metrics;

// ── Role-based access control ─────────────────────────────────────────────────

/// Roles injected into every authenticated request via the `require_auth` middleware.
/// Handlers that perform write or administrative operations extract this to enforce
/// per-route privilege requirements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// Full administrative access: create/delete tokens, manage webhooks, edit
    /// policies and config, approve agent actions.
    Admin,
    /// Read-only observer: may call all GET endpoints and the SSE stream.
    Auditor,
    /// Programmatic agent identity: may create sessions and submit approvals.
    Agent,
}

impl Role {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "admin" => Some(Role::Admin),
            "auditor" => Some(Role::Auditor),
            "agent" => Some(Role::Agent),
            _ => None,
        }
    }

    #[allow(dead_code)]
    fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Auditor => "auditor",
            Role::Agent => "agent",
        }
    }
}

const INDEX_HTML: &str = include_str!("index.html");

/// Global broadcast sender used to wake SSE clients when new ledger events are written.
/// Global SSE wakeup sender.  Set once during router construction.
/// Uses a plain `OnceLock<broadcast::Sender>` — no Mutex needed because
/// `broadcast::Sender` is already `Clone + Send + Sync` and `send()` is
/// wait-free.
static SSE_WAKEUP: OnceLock<broadcast::Sender<()>> = OnceLock::new();

/// Wake all SSE stream handlers. Called after any ledger event is appended.
/// Safe to call from any context; silently no-ops if the server is not running.
pub fn notify_sse_subscribers() {
    if let Some(tx) = SSE_WAKEUP.get() {
        let _ = tx.send(());
    }
}

#[derive(Clone)]
pub struct AppState {
    pub pool: DatabasePool,
    pub metrics: Arc<Metrics>,
    pub approval_state: Arc<ApprovalState>,
    /// Broadcast sender — cloned into SSE handlers for event-driven wakeup.
    pub sse_tx: broadcast::Sender<()>,
    /// Sender end of the single shared webhook egress worker.
    /// Cloned into each agent session instead of spawning a separate worker
    /// per session (which would exhaust the DB connection pool under load).
    pub egress_tx: mpsc::Sender<crate::webhook::EgressEvent>,
    /// Shared HTTP client — reused across all handlers to avoid per-session
    /// TLS/DNS/connection-pool exhaustion under concurrent load.
    pub http_client: reqwest::Client,
    /// Tracks all spawned cognitive-loop tasks so shutdown can await them.
    pub task_tracker: TaskTracker,
    /// Server-wide cancellation token — cancelled on shutdown to signal all
    /// REST-spawned cognitive loops to exit cooperatively.
    pub cancel: CancellationToken,
    /// Optional LLM backend factory — when set, handlers use this instead of
    /// `backend_from_env()`.  Used by integration tests to inject a stub
    /// without requiring mock.rs in production code.
    pub llm_factory: Option<Arc<dyn Fn() -> Box<dyn llm::LlmBackend> + Send + Sync>>,
}

// Compiled once, reused for every call to `redact_string`.
static REDACT_PATH_RE: OnceLock<Regex> = OnceLock::new();
static REDACT_CRED_RE: OnceLock<Regex> = OnceLock::new();
static REDACT_IPV4_RE: OnceLock<Regex> = OnceLock::new();
static REDACT_IPV6_RE: OnceLock<Regex> = OnceLock::new();

/// Redacts sensitive content in strings before streaming to the dashboard.
///
/// JSON input is parsed structurally so that only string-valued leaves are
/// examined, preventing the path regex from destroying numeric or boolean
/// fields.  Non-JSON text falls back to regex replacement.
fn redact_string(s: &str) -> String {
    // The path pattern is deliberately tightened: require the slash to be
    // preceded by a word boundary or start-of-string so that URL hosts
    // (e.g. "https://example.com/very-long-path") are still caught but
    // mid-token slashes in JSON keys are not.
    let path_re = REDACT_PATH_RE.get_or_init(|| Regex::new(r"(?:^|\s)/[^\s]{30,}").unwrap());
    let cred_re = REDACT_CRED_RE
        .get_or_init(|| Regex::new(r#"(?i)(api_key|password|secret|token)\s*[:=]\s*\S+"#).unwrap());
    let ipv4_re =
        REDACT_IPV4_RE.get_or_init(|| Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap());
    let ipv6_re = REDACT_IPV6_RE
        .get_or_init(|| Regex::new(r"\b(?:[0-9a-fA-F]{0,4}:){2,7}[0-9a-fA-F]{0,4}\b").unwrap());
    let mut out = s.to_string();
    out = path_re.replace_all(&out, "[REDACTED_PATH]").to_string();
    out = cred_re.replace_all(&out, "[REDACTED]").to_string();
    out = ipv4_re.replace_all(&out, "[REDACTED_IP]").to_string();
    out = ipv6_re.replace_all(&out, "[REDACTED_IP]").to_string();
    out
}

fn redact_for_stream(payload: &serde_json::Value) -> serde_json::Value {
    /// Keys whose *values* are redacted entirely, regardless of content.
    const SENSITIVE_KEYS: &[&str] = &[
        "password",
        "secret",
        "token",
        "api_key",
        "apikey",
        "authorization",
        "bearer",
        "credential",
        "private_key",
        "access_key",
        "secret_key",
        "session_token",
    ];

    fn is_sensitive_key(k: &str) -> bool {
        let lower = k.to_lowercase();
        SENSITIVE_KEYS.iter().any(|s| lower.contains(s))
    }

    match payload {
        serde_json::Value::String(s) => serde_json::Value::String(redact_string(s)),
        serde_json::Value::Array(arr) => {
            serde_json::Value::Array(arr.iter().map(redact_for_stream).collect())
        }
        serde_json::Value::Object(map) => {
            let redacted: serde_json::Map<String, serde_json::Value> = map
                .iter()
                .map(|(k, v)| {
                    if is_sensitive_key(k) {
                        (
                            k.clone(),
                            serde_json::Value::String("[REDACTED]".to_string()),
                        )
                    } else {
                        (k.clone(), redact_for_stream(v))
                    }
                })
                .collect();
            serde_json::Value::Object(redacted)
        }
        other => other.clone(),
    }
}

async fn require_auth(
    State(state): State<Arc<AppState>>,
    request: Request,
    next: Next,
) -> Result<axum::response::Response, (StatusCode, String)> {
    let (parts, body) = request.into_parts();

    // Extract the raw token from the Authorization header or ?token= query param.
    let bearer = parts
        .headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|s| s.to_string());
    let query_token = parts.uri.query().and_then(|q| {
        // Use proper form-urlencoded parsing so tokens that contain `+` or
        // `%xx` sequences are correctly decoded before the SHA-256 comparison.
        url::form_urlencoded::parse(q.as_bytes())
            .find(|(k, _)| k == "token")
            .map(|(_, v)| v.into_owned())
    });
    let Some(token) = bearer.or(query_token) else {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Missing authentication token".into(),
        ));
    };

    // Hash the raw token before the DB lookup so the raw credential is never
    // compared or stored beyond this function's stack frame.
    let token_hash = hex::encode(Sha256::digest(token.as_bytes()));

    let row = state.pool.find_token_role(&token_hash).await.map_err(|e| {
        tracing::error!("Token lookup failed: {e}");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Token lookup failed: {e}"),
        )
    })?;

    let role = match row {
        Some(ref s) => Role::from_str(s)
            .ok_or_else(|| (StatusCode::UNAUTHORIZED, format!("Unknown role: {s}")))?,
        None => return Err((StatusCode::UNAUTHORIZED, "Invalid or expired token".into())),
    };

    // Inject the resolved role into request extensions so individual handlers can
    // enforce their own minimum privilege requirements without splitting the router.
    let mut req = Request::from_parts(parts, body);
    req.extensions_mut().insert(role);
    Ok(next.run(req).await)
}

#[derive(Debug, Serialize)]
struct StreamEvent {
    id: i64,
    sequence: i64,
    previous_hash: String,
    content_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload: Option<serde_json::Value>,
    created_at: String,
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

#[derive(Debug, serde::Deserialize)]
struct StreamQuery {
    after: Option<i64>,
    /// Alias for `after` — clients can use `?since=<last_sequence>` to reconnect
    /// without replaying the full event history.
    since: Option<i64>,
    session_id: Option<Uuid>,
}

async fn stream_events(
    State(state): State<Arc<AppState>>,
    Query(q): Query<StreamQuery>,
    ConnectInfo(_addr): ConnectInfo<SocketAddr>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let pool = state.pool.clone();
    // `since` takes precedence over `after` for forwards-compat; both work.
    let mut last_id = q.since.or(q.after).unwrap_or(0);
    let session_id = q.session_id;
    // Subscribe before entering the loop so we don't miss a wakeup that races
    // with the initial fetch below.
    let mut rx = state.sse_tx.subscribe();

    let stream = async_stream::stream! {
        loop {
        let rows: Vec<crate::schema::LedgerEventRow> = {
                let query_result = pool.stream_events_since(last_id, session_id).await;
                match query_result {
                    Ok(rows) => rows,
                    Err(e) => {
                        tracing::error!("SSE DB poll failed: {}", e);
                        yield Ok(Event::default().event("error").data("db_error"));
                        break;
                    }
                }
            };

            for row in rows {
                last_id = row.id;
                let payload_value = serde_json::to_value(&row.payload).unwrap_or(serde_json::Value::Null);
                let payload_redacted = redact_for_stream(&payload_value);
                let ev = StreamEvent {
                    id: row.id,
                    sequence: row.sequence,
                    previous_hash: row.previous_hash.clone(),
                    content_hash: row.content_hash.clone(),
                    payload: Some(payload_redacted),
                    created_at: row.created_at.to_rfc3339(),
                };
                if let Ok(data) = serde_json::to_string(&ev) {
                    yield Ok(Event::default().event("event").id(row.id.to_string()).data(data));
                }
            }

            // Wait for a wakeup signal from the ledger writer, or a keep-alive timeout.
            // This replaces the unconditional 1-second sleep, avoiding unnecessary DB polls.
            tokio::select! {
                recv_result = rx.recv() => {
                    match recv_result {
                        Ok(_) => {
                            // Normal wakeup — drain accumulated signals before re-polling.
                            while rx.try_recv().is_ok() {}
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            // The receiver fell too far behind and some wakeup signals were
                            // dropped by the channel.  This is NOT a data-loss problem: we
                            // always re-query the DB using `last_id`, so all missed ledger
                            // events will be picked up on the next DB fetch above.
                            tracing::debug!("SSE client lagged by {} broadcast signals; catching up via DB", n);
                            while rx.try_recv().is_ok() {}
                        }
                        Err(broadcast::error::RecvError::Closed) => {
                            // The broadcast sender was dropped — server is shutting down.
                            tracing::debug!("SSE wakeup channel closed; terminating stream");
                            break;
                        }
                    }
                }
                _ = tokio::time::sleep(Duration::from_secs(30)) => {
                    // Fallback heartbeat — ensures we eventually detect if the sender is dropped.
                }
            }
        }
    };

    let stream = stream.map(|r| r.map_err(|_: Infallible| unreachable!()));
    Sse::new(stream).keep_alive(
        axum::response::sse::KeepAlive::new()
            .interval(Duration::from_secs(crate::config::sse_keepalive_secs()))
            .text("keep-alive"),
    )
}

#[derive(Deserialize)]
struct CreateSessionRequest {
    goal: String,
}

// ── Direct LLM chat (no agent loop, no guard, no tripwire) ────────────────────

#[derive(Deserialize)]
struct ChatRequest {
    message: String,
}

/// `POST /api/chat` — One-shot LLM chat.
///
/// Sends the user's message directly to the configured LLM backend and returns
/// the raw text response.  No session is created, no guard or tripwire checks
/// are applied.  This is the happy-path "just talk to the model" endpoint used
/// by the dashboard's Test Prompt panel.
async fn chat(
    State(state): State<Arc<AppState>>,
    axum::Extension(_role): axum::Extension<Role>,
    axum::Json(body): axum::Json<ChatRequest>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    let message = body.message.trim();
    if message.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Message must not be empty".into()));
    }

    let client = state.http_client.clone();

    // Always use the real LLM backend — demo mode auto-provisions a local
    // micro-model (e.g. qwen2.5:0.5b) via Ollama so the real pipeline works
    // without external API keys.
    let llm: Box<dyn llm::LlmBackend> = if let Some(factory) = &state.llm_factory {
        factory()
    } else {
        let primary = llm::backend_from_env(&client);
        match primary {
            Ok(backend) => match backend.ensure_ready(&client).await {
                Ok(()) => backend,
                Err(e) => {
                    tracing::error!("LLM not ready: {}", e);
                    return Err((
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!("LLM not ready: {e}. Is your LLM backend running?"),
                    ));
                }
            },
            Err(e) => {
                tracing::error!("LLM setup failed: {}", e);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("LLM setup failed: {e}"),
                ));
            }
        }
    };

    let system =
        "You are a helpful AI assistant. Respond naturally and concisely to the user's message.";

    // Log the user's message to the ledger so the observer can see it.
    if let Err(e) = state
        .pool
        .append_event(
            EventPayload::ChatMessage {
                role: "user".into(),
                content: message.to_string(),
                backend: None,
                model: None,
            },
            None,
            None,
            None,
        )
        .await
    {
        tracing::error!("Failed to append user chat event to audit ledger: {}", e);
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to log chat event: {e}"),
        ));
    }

    let reply = llm.raw_call(system, message).await.map_err(|e| {
        tracing::error!("LLM chat call failed: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("LLM call failed: {e}"),
        )
    })?;

    let backend_name = llm.backend_name().to_string();
    let model_name = llm.model_name().to_string();

    // Log the LLM's reply to the ledger.
    if let Err(e) = state
        .pool
        .append_event(
            EventPayload::ChatMessage {
                role: "assistant".into(),
                content: reply.clone(),
                backend: Some(backend_name.clone()),
                model: Some(model_name.clone()),
            },
            None,
            None,
            None,
        )
        .await
    {
        tracing::error!(
            "Failed to append assistant chat event to audit ledger: {}",
            e
        );
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to log chat reply: {e}"),
        ));
    }

    Ok(axum::Json(serde_json::json!({
        "reply": reply,
        "backend": backend_name,
        "model": model_name,
    })))
}

// ── Python SDK alias handlers ────────────────────────────────────────────────

/// `POST /api/sessions/{session_id}/chat` — Chat scoped to a specific session.
///
/// Appends the user's message as a `ChatMessage` event to the given session,
/// calls the LLM, and appends the assistant's reply to the same session.
async fn session_chat(
    State(state): State<Arc<AppState>>,
    axum::Extension(_role): axum::Extension<Role>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
    axum::Json(body): axum::Json<ChatRequest>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    let message = body.message.trim();
    if message.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Message must not be empty".into()));
    }

    let client = state.http_client.clone();

    let llm: Box<dyn llm::LlmBackend> = if let Some(factory) = &state.llm_factory {
        factory()
    } else {
        let primary = llm::backend_from_env(&client);
        match primary {
            Ok(backend) => match backend.ensure_ready(&client).await {
                Ok(()) => backend,
                Err(e) => {
                    return Err((
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!("LLM not ready: {e}. Is your LLM backend running?"),
                    ));
                }
            },
            Err(e) => {
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("LLM setup failed: {e}"),
                ));
            }
        }
    };

    let system =
        "You are a helpful AI assistant. Respond naturally and concisely to the user's message.";

    // Append user message to this session's ledger.
    if let Err(e) = state
        .pool
        .append_event(
            EventPayload::ChatMessage {
                role: "user".into(),
                content: message.to_string(),
                backend: None,
                model: None,
            },
            Some(session_id),
            None,
            None,
        )
        .await
    {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to log chat event: {e}"),
        ));
    }

    let reply = match llm.raw_call(system, message).await {
        Ok(r) => r,
        Err(e) => {
            return Err((StatusCode::BAD_GATEWAY, format!("LLM call failed: {e}")));
        }
    };

    let backend_name = llm.backend_name().to_string();
    let model_name = llm.model_name().to_string();

    if let Err(e) = state
        .pool
        .append_event(
            EventPayload::ChatMessage {
                role: "assistant".into(),
                content: reply.clone(),
                backend: Some(backend_name.clone()),
                model: Some(model_name.clone()),
            },
            Some(session_id),
            None,
            None,
        )
        .await
    {
        return Err((
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to log chat reply: {e}"),
        ));
    }

    Ok(axum::Json(serde_json::json!({
        "reply": reply,
        "backend": backend_name,
        "model": model_name,
    })))
}

/// `GET /api/sessions/{session_id}/events/stream` — SSE stream scoped to a session.
///
/// Alias for the generic `/api/stream?session_id=<id>` endpoint, used by the
/// Python SDK which encodes the session ID in the path instead of a query param.
async fn stream_events_by_session(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
) -> Sse<impl futures_util::Stream<Item = Result<Event, Infallible>>> {
    let query = StreamQuery {
        after: None,
        since: None,
        session_id: Some(session_id),
    };
    stream_events(State(state), Query(query), ConnectInfo(addr)).await
}

#[derive(serde::Deserialize, Default)]
struct ListSessionsQuery {
    status: Option<String>,
    #[serde(default)]
    limit: Option<i64>,
    #[serde(default)]
    offset: Option<i64>,
}

async fn list_sessions(
    State(state): State<Arc<AppState>>,
    axum::extract::Query(q): axum::extract::Query<ListSessionsQuery>,
) -> Result<axum::Json<Vec<SessionRow>>, StatusCode> {
    let limit = q.limit.unwrap_or(100).clamp(1, 500);
    let offset = q.offset.unwrap_or(0).max(0);
    let sessions = state
        .pool
        .list_sessions_filtered(q.status.as_deref(), limit, offset)
        .await
        .map_err(|e| {
            tracing::error!("list_sessions DB query failed: {}", e);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    Ok(axum::Json(sessions))
}

async fn get_session_by_id(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(session_id): axum::extract::Path<uuid::Uuid>,
) -> Result<axum::Json<SessionRow>, StatusCode> {
    let sessions = state
        .pool
        .list_sessions_filtered(None, 500, 0)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    sessions
        .into_iter()
        .find(|s| s.id == session_id)
        .map(axum::Json)
        .ok_or(StatusCode::NOT_FOUND)
}

async fn get_session_vc(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(session_id): axum::extract::Path<uuid::Uuid>,
) -> Result<axum::Json<serde_json::Value>, StatusCode> {
    use crate::verifiable_credential::decode_vc_payload;
    use ectoledger_core::merkle;
    let events = state
        .pool
        .get_events_by_session(session_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "get_events_by_session failed for session {}: {}",
                session_id,
                e
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    for ev in events.iter().rev() {
        if let EventPayload::VerifiableCredential { vc_jwt } = &ev.payload {
            let decoded = decode_vc_payload(vc_jwt);

            // ── Integrity-check fields expected by the GUI ────────────
            let event_count = events.len();

            // Merkle root over every event's content_hash
            let hashes: Vec<&str> = events.iter().map(|e| e.content_hash.as_str()).collect();
            let merkle_root = merkle::build_merkle_tree(&hashes)
                .ok()
                .and_then(|tree| merkle::root(&tree).ok());

            // Policy hash from the VC credential subject
            let policy_hash = decoded
                .as_ref()
                .and_then(|p| p.get("vc"))
                .and_then(|vc| vc.get("credentialSubject"))
                .and_then(|cs| cs.get("policyHash"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string());

            // The JWT has a real signature when it doesn't end with a trailing dot
            let has_signature = !vc_jwt.ends_with('.');

            return Ok(axum::Json(serde_json::json!({
                "vc_jwt": vc_jwt,
                "vc_payload": decoded,
                "merkle_root": merkle_root,
                "event_count": event_count,
                "policy_hash": policy_hash,
                "proof": has_signature,
            })));
        }
    }
    Err(StatusCode::NOT_FOUND)
}

/// `GET /api/sessions/{id}/vc/verify` — Verify the W3C VC-JWT for a completed session.
///
/// Resolves the VC stored for the session and checks:
/// - JWT structure (header.payload.signature)
/// - `exp` claim (credential lifetime)
/// - Ed25519 signature (when the session signing key is present in the store)
///
/// Returns JSON with `"valid": true/false` and a `"reason"` field on failure.
async fn verify_session_vc(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(session_id): axum::extract::Path<uuid::Uuid>,
) -> Result<axum::Json<serde_json::Value>, StatusCode> {
    use crate::verifiable_credential::{VcVerifyError, verify_vc_jwt};
    let events = state
        .pool
        .get_events_by_session(session_id)
        .await
        .map_err(|e| {
            tracing::error!(
                "get_events_by_session failed for session {}: {}",
                session_id,
                e
            );
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    // Try to load the session's verifying key so we can perform full Ed25519
    // verification instead of a structural-only check.
    let verifying_key = state.pool.load_session_verifying_key(session_id).await;
    for ev in events.iter().rev() {
        if let EventPayload::VerifiableCredential { vc_jwt } = &ev.payload {
            let result = verify_vc_jwt(vc_jwt, verifying_key.as_ref());
            return match result {
                Ok(payload) => {
                    let sig_verified = verifying_key.is_some();
                    Ok(axum::Json(serde_json::json!({
                        "valid": true,
                        "signature_verified": sig_verified,
                        "vc_jwt": vc_jwt,
                        "vc_payload": payload,
                    })))
                }
                Err(VcVerifyError::Expired) => Ok(axum::Json(serde_json::json!({
                    "valid": false,
                    "reason": "credential has expired",
                }))),
                Err(e) => Ok(axum::Json(serde_json::json!({
                    "valid": false,
                    "reason": e.to_string(),
                }))),
            };
        }
    }
    Err(StatusCode::NOT_FOUND)
}

async fn create_session(
    State(state): State<Arc<AppState>>,
    axum::Extension(role): axum::Extension<Role>,
    axum::Json(body): axum::Json<CreateSessionRequest>,
) -> Result<axum::Json<SessionRow>, (StatusCode, String)> {
    // Only Admin and Agent roles may create sessions.
    if role == Role::Auditor {
        return Err((
            StatusCode::FORBIDDEN,
            "Auditor role cannot create sessions".into(),
        ));
    }
    let goal = body.goal.trim();
    if goal.is_empty() {
        return Err((StatusCode::BAD_REQUEST, "Goal must not be empty".into()));
    }

    // Backpressure: probe the DB pool before spawning a new cognitive loop.
    // This prevents an authenticated caller from exhausting the connection
    // pool by rapidly creating sessions.
    if let Some(pg_pool) = state.pool.as_pg() {
        match tokio::time::timeout(std::time::Duration::from_secs(5), pg_pool.acquire()).await {
            Ok(Ok(_conn)) => { /* pool has capacity — connection dropped immediately */ }
            Ok(Err(e)) => {
                tracing::error!("create_session: pool acquire failed: {}", e);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("Database pool error: {e}"),
                ));
            }
            Err(_) => {
                tracing::warn!(
                    "create_session: pool acquire timed out — pool saturated, rejecting session"
                );
                return Err((
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Database pool saturated — try again later".into(),
                ));
            }
        }
    }

    let client = state.http_client.clone();

    // Always use the real LLM backend — demo mode auto-provisions a local
    // micro-model (e.g. qwen2.5:0.5b) via Ollama so the real pipeline works.
    let llm_backend: Box<dyn llm::LlmBackend> = if let Some(factory) = &state.llm_factory {
        factory()
    } else {
        let primary = llm::backend_from_env(&client);
        match primary {
            Ok(backend) => match backend.ensure_ready(&client).await {
                Ok(()) => backend,
                Err(e) => {
                    tracing::error!("LLM not ready: {}", e);
                    return Err((
                        StatusCode::SERVICE_UNAVAILABLE,
                        format!("LLM not ready: {e}. Is your LLM backend running?"),
                    ));
                }
            },
            Err(e) => {
                tracing::error!("LLM setup failed: {}", e);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("LLM setup failed: {e}"),
                ));
            }
        }
    };

    let (session, session_signing_key) = state
        .pool
        .create_session(
            goal,
            llm_backend.backend_name(),
            llm_backend.model_name(),
            {
                // Compute a policy hash from the default builtin compliance policy
                // (ISO 42001) so that every GUI-created session is bound to a
                // governance baseline.  The orchestrator path does the same for
                // its per-role policies.
                static DEFAULT_POLICY_HASH: std::sync::OnceLock<String> =
                    std::sync::OnceLock::new();
                let hash = DEFAULT_POLICY_HASH.get_or_init(|| {
                    let iso_content = BUILTIN_POLICIES
                        .iter()
                        .find(|(n, _)| *n == "iso42001")
                        .map(|(_, c)| *c)
                        .unwrap_or("");
                    ectoledger_core::policy::policy_hash_bytes(iso_content.as_bytes())
                });
                Some(hash.as_str())
            },
        )
        .await
        .map_err(|e| {
            tracing::error!("create_session failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to create session: {e}"),
            )
        })?;

    state.metrics.inc_sessions_created();
    let session_id = session.id;
    let session_signing_key = std::sync::Arc::new(session_signing_key);

    state
        .pool
        .append_event(
            EventPayload::PromptInput {
                content: goal.to_string(),
            },
            Some(session_id),
            Some(goal),
            Some(session_signing_key.as_ref()),
        )
        .await
        .map_err(|e| {
            tracing::error!("append_event failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to append prompt event: {e}"),
            )
        })?;

    let tw_cfg = config::load_tripwire_config();
    let allowed_paths: Vec<PathBuf> = tw_cfg
        .allowed_paths
        .iter()
        .map(|p| {
            match PathBuf::from(p).canonicalize() {
                Ok(canonical) => canonical,
                Err(err) => {
                    // Path doesn't exist yet (e.g. a work directory the agent will create).
                    // Symlink-escape detection for this path is degraded until it exists.
                    // Operators should pre-create all allowed_paths entries to avoid this.
                    tracing::warn!(
                        "allowed_paths entry '{}' could not be canonicalized ({}); \
                         using raw path — symlink-escape protection is reduced for this entry. \
                         Pre-create the directory to restore full protection.",
                        p,
                        err
                    );
                    PathBuf::from(p)
                }
            }
        })
        .collect();
    let tripwire = std::sync::Arc::new(tripwire::Tripwire::new(
        allowed_paths,
        tw_cfg.allowed_domains,
        tw_cfg.banned_command_patterns,
        tw_cfg.min_justification_length,
        tw_cfg.require_https,
    ));

    let guard: Option<Box<dyn GuardExecutor>> = if config::guard_required() {
        config::ensure_guard_config().map_err(|e| {
            tracing::error!("Guard config: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Guard configuration error: {e}. Set GUARD_REQUIRED=false to disable."),
            )
        })?;
        match GuardProcess::spawn() {
            Ok(g) => Some(Box::new(g)),
            Err(e) => {
                tracing::error!("Guard spawn failed: {}", e);
                return Err((
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!(
                        "Guard process failed to start: {e}. Set GUARD_REQUIRED=false to disable."
                    ),
                ));
            }
        }
    } else {
        None
    };

    let pool = state.pool.clone();
    let metrics = state.metrics.clone();
    let approval_state = state.approval_state.clone();
    // Clone the shared egress sender; no new worker is spawned per session.
    let egress_tx = state.egress_tx.clone();
    let goal_owned = goal.to_string();

    // Clone pool for the panic-recovery path (outside the AssertUnwindSafe boundary).
    let session_cancel = state.cancel.clone();
    let pool_for_panic = pool.clone();
    let approval_state_cleanup = approval_state.clone();
    state.task_tracker.spawn(async move {
        let pool_inner = pool.clone();
        let sid = session_id;
        let fut = std::panic::AssertUnwindSafe(async move {
            let agent_config = agent::AgentLoopConfig {
                llm: llm_backend,
                tripwire: &tripwire,
                max_steps: Some(config::max_steps()),
                session_id: Some(sid),
                session_goal: goal_owned,
                guard,
                policy: None,
                session_signing_key: Some(session_signing_key),
                metrics: Some(metrics),
                egress_tx: {
                    // Use the single shared egress worker started at server startup.
                    // This avoids spawning O(sessions) workers and exhausting the DB pool.
                    Some(egress_tx)
                },
                cloud_creds: crate::cloud_creds::load_cloud_creds().map(std::sync::Arc::new),
                interactive: false,
                approval_state: Some(approval_state),
                firecracker_config: crate::sandbox::FirecrackerConfig::from_env_opt(),
                docker_config: crate::sandbox::DockerConfig::from_env_opt(),
                key_rotation_interval_steps: config::key_rotation_interval_steps(),
                compensation: Some(crate::compensation::CompensationPlanner::load()),
                enclave: None,
                enclave_attestation: None,
                cancel: Some(session_cancel),
            };
            // run_cognitive_loop accepts &DatabasePool.  It internally
            // requires PostgreSQL; for SQLite-only mode sessions are managed
            // via the REST API only.
            match agent::run_cognitive_loop(&pool_inner, &client, agent_config).await {
                Ok(()) => {
                    if let Err(e) = pool_inner.finish_session(sid, "completed").await {
                        tracing::warn!("Failed to mark session {} as completed: {}", sid, e);
                    }
                    tracing::info!("Session {} completed", sid);
                }
                Err(agent::AgentError::Append(ledger::AppendError::GoalMismatch)) => {
                    if let Err(e) = pool_inner
                        .append_event(
                            EventPayload::Thought {
                                content: "Security: session goal mismatch; aborting."
                                    .to_string(),
                                },
                                Some(sid),
                                None,
                                None,
                            )
                            .await
                        {
                            tracing::error!("CRITICAL: failed to log security event (goal mismatch) for session {}: {}", sid, e);
                        }
                        if let Err(e) = pool_inner.finish_session(sid, "aborted").await {
                            tracing::error!("Failed to mark session {} as aborted: {}", sid, e);
                        }
                        tracing::warn!("Session {} aborted: goal mismatch", sid);
                    }
                    Err(agent::AgentError::Append(ledger::AppendError::UnverifiedEvidence(
                        msg,
                    ))) => {
                        if let Err(e) = pool_inner
                            .append_event(
                                EventPayload::Thought {
                                    content: format!(
                                        "Findings verification failed: {}; commit rejected.",
                                        msg
                                    ),
                                },
                                Some(sid),
                                None,
                                None,
                            )
                            .await
                        {
                            tracing::error!("CRITICAL: failed to log security event (unverified evidence) for session {}: {}", sid, e);
                        }
                        if let Err(e) = pool_inner.finish_session(sid, "failed").await {
                            tracing::error!("Failed to mark session {} as failed: {}", sid, e);
                        }
                        tracing::warn!("Session {} failed: {}", sid, msg);
                    }
                    Err(agent::AgentError::TripwireAbort(ref reason)) => {
                        // Prompt-level tripwire scan caught a dangerous pattern.
                        // The thought event was already appended inside the agent loop.
                        if let Err(e) = pool_inner.finish_session(sid, "aborted").await {
                            tracing::error!("Failed to mark session {} as aborted: {}", sid, e);
                        }
                        tracing::warn!("Session {} aborted (tripwire): {}", sid, reason);
                    }
                    Err(agent::AgentError::GuardAbort) => {
                        if let Err(e) = pool_inner.finish_session(sid, "aborted").await {
                            tracing::error!("Failed to mark session {} as aborted: {}", sid, e);
                        }
                        tracing::warn!("Session {} aborted (guard)", sid);
                    }
                    Err(agent::AgentError::CircuitBreaker) => {
                        if let Err(e) = pool_inner.finish_session(sid, "aborted").await {
                            tracing::error!("Failed to mark session {} as aborted: {}", sid, e);
                        }
                        tracing::warn!("Session {} aborted (circuit breaker)", sid);
                    }
                    Err(agent::AgentError::Cancelled) => {
                        if let Err(e) = pool_inner.finish_session(sid, "aborted").await {
                            tracing::error!("Failed to mark session {} as aborted: {}", sid, e);
                        }
                        tracing::info!("Session {} aborted (cancellation token)", sid);
                    }
                    Err(e) => {
                        if let Err(db_err) = pool_inner.finish_session(sid, "failed").await {
                            tracing::error!("Failed to mark session {} as failed: {}", sid, db_err);
                        }
                        tracing::error!("Session {} failed: {}", sid, e);
                    }
                }
        });
        // Catch panics in the cognitive loop so the session is marked failed
        // instead of becoming a permanent zombie.
        if let Err(panic) = futures_util::FutureExt::catch_unwind(fut).await {
            tracing::error!(session_id = %session_id, "cognitive loop panicked: {:?}", panic);
            if let Err(db_err) = pool_for_panic.finish_session(session_id, "failed").await {
                tracing::error!(
                    session_id = %session_id,
                    "CRITICAL: zombie session — failed to mark panicked session as failed: {}. \
                     Manual intervention required: UPDATE agent_sessions SET status='failed' WHERE id='{}'",
                    db_err,
                    session_id,
                );
            }
        }
        // Clean up in-memory approval state for this session to prevent unbounded growth.
        approval_state_cleanup.cleanup_session(session_id);
    });

    let row = SessionRow {
        id: session.id,
        goal: session.goal,
        goal_hash: session.goal_hash,
        status: session.status,
        llm_backend: session.llm_backend,
        llm_model: session.llm_model,
        created_at: session.created_at,
        finished_at: session.finished_at,
        policy_hash: session.policy_hash,
        session_public_key: session.session_public_key,
        session_did: session.session_did,
        enclave_attestation_json: None,
    };
    Ok(axum::Json(row))
}

// ── Policies API ───────────────────────────────────────────────────────────────

const BUILTIN_POLICIES: &[(&str, &str)] = &[
    ("soc2-audit", include_str!("../policies/soc2-audit.toml")),
    (
        "pci-dss-audit",
        include_str!("../policies/pci-dss-audit.toml"),
    ),
    ("owasp-top10", include_str!("../policies/owasp-top10.toml")),
    ("iso42001", include_str!("../policies/iso42001.toml")),
];

async fn list_policies() -> axum::Json<Vec<String>> {
    let mut names: Vec<String> = BUILTIN_POLICIES
        .iter()
        .map(|(n, _)| n.to_string())
        .collect();
    let dir = config::policies_dir();
    if dir.exists()
        && let Ok(entries) = std::fs::read_dir(&dir)
    {
        for e in entries.flatten() {
            if e.path().extension().is_some_and(|e| e == "toml")
                && let Some(stem) = e.path().file_stem()
            {
                let name = stem.to_string_lossy().to_string();
                if !names.contains(&name) {
                    names.push(name);
                }
            }
        }
    }
    names.sort();
    axum::Json(names)
}

async fn get_policy_content(Path(name): Path<String>) -> Result<String, StatusCode> {
    let name = name.trim();
    if name.is_empty() || name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err(StatusCode::BAD_REQUEST);
    }
    if let Some((_, content)) = BUILTIN_POLICIES.iter().find(|(n, _)| *n == name) {
        return Ok(content.to_string());
    }
    let path = config::policies_dir().join(format!("{}.toml", name));
    if path.exists() {
        std::fs::read_to_string(&path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

async fn save_policy(
    axum::Extension(role): axum::Extension<Role>,
    Path(name): Path<String>,
    body: String,
) -> Result<StatusCode, StatusCode> {
    if role != Role::Admin {
        return Err(StatusCode::FORBIDDEN);
    }
    let name = name.trim();
    if name.is_empty() || name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err(StatusCode::BAD_REQUEST);
    }
    if BUILTIN_POLICIES.iter().any(|(n, _)| *n == name) {
        return Err(StatusCode::FORBIDDEN);
    }
    let content = body;
    // Reject syntactically invalid TOML before touching the filesystem.
    if content.parse::<toml::Value>().is_err() {
        return Err(StatusCode::UNPROCESSABLE_ENTITY);
    }
    let dir = config::policies_dir();
    std::fs::create_dir_all(&dir).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let target = dir.join(format!("{}.toml", name));
    // Atomic write: write to a sibling temp file then rename into place.
    // This prevents a concurrent save from producing a torn/corrupted file.
    let mut tmp =
        tempfile::NamedTempFile::new_in(&dir).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    std::io::Write::write_all(&mut tmp, content.as_bytes())
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    tmp.persist(&target)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}

async fn delete_policy(
    axum::Extension(role): axum::Extension<Role>,
    Path(name): Path<String>,
) -> Result<StatusCode, StatusCode> {
    if role != Role::Admin {
        return Err(StatusCode::FORBIDDEN);
    }
    let name = name.trim();
    if name.is_empty() || name.contains("..") || name.contains('/') || name.contains('\\') {
        return Err(StatusCode::BAD_REQUEST);
    }
    if BUILTIN_POLICIES.iter().any(|(n, _)| *n == name) {
        return Err(StatusCode::FORBIDDEN);
    }
    let path = config::policies_dir().join(format!("{}.toml", name));
    if path.exists() {
        std::fs::remove_file(&path).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
        Ok(StatusCode::OK)
    } else {
        Err(StatusCode::NOT_FOUND)
    }
}

// ── Certificate API ───────────────────────────────────────────────────────────

async fn get_certificate(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<Uuid>,
) -> Result<axum::Json<crate::certificate::EctoLedgerCertificate>, StatusCode> {
    let pg = state.pool.as_pg().ok_or(StatusCode::NOT_IMPLEMENTED)?;
    let cert = crate::certificate::build_certificate(pg, session_id, None, false, None)
        .await
        .map_err(|e| {
            tracing::warn!("Certificate build failed for {}: {}", session_id, e);
            StatusCode::NOT_FOUND
        })?;
    Ok(axum::Json(cert))
}

// ── Reports API ───────────────────────────────────────────────────────────────

async fn get_report(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<Uuid>,
) -> Result<axum::Json<crate::report::AuditReport>, StatusCode> {
    let pg = state.pool.as_pg().ok_or(StatusCode::NOT_IMPLEMENTED)?;
    let report = crate::report::build_report(pg, session_id)
        .await
        .map_err(|e| {
            tracing::warn!("Report build failed for {}: {}", session_id, e);
            StatusCode::NOT_FOUND
        })?;
    Ok(axum::Json(report))
}

// ── Events JSON API (for GUI; /api/stream is SSE) ──────────────────────────────

#[derive(Debug, serde::Deserialize)]
struct EventsQuery {
    session_id: Option<Uuid>,
}

async fn get_events_json(
    State(state): State<Arc<AppState>>,
    Query(q): Query<EventsQuery>,
) -> Result<axum::Json<Vec<serde_json::Value>>, StatusCode> {
    let session_id = q.session_id.ok_or(StatusCode::BAD_REQUEST)?;
    let events = state
        .pool
        .get_events_by_session(session_id)
        .await
        .map_err(|e| {
            tracing::error!("get_events_json: session_id={session_id}: {e}");
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
    let out: Vec<serde_json::Value> = events
        .into_iter()
        .map(|e| {
            serde_json::json!({
                "id": e.id,
                "sequence": e.sequence,
                "previous_hash": e.previous_hash,
                "content_hash": e.content_hash,
                "payload": e.payload,
                "created_at": e.created_at.to_rfc3339(),
            })
        })
        .collect();
    Ok(axum::Json(out))
}

#[derive(serde::Serialize)]
struct PendingApprovalResponse {
    pending: Option<PendingApproval>,
}

async fn get_pending_approval(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
) -> axum::Json<PendingApprovalResponse> {
    let pending = state.approval_state.get_pending(session_id);
    axum::Json(PendingApprovalResponse { pending })
}

async fn post_approval_decision(
    State(state): State<Arc<AppState>>,
    axum::Extension(role): axum::Extension<Role>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
    axum::Json(body): axum::Json<ApprovalDecisionRequest>,
) -> Result<axum::Json<serde_json::Value>, StatusCode> {
    // Only Admin may approve or deny actions.
    if role != Role::Admin {
        return Err(StatusCode::FORBIDDEN);
    }
    if let Err(e) = state
        .pool
        .append_event(
            EventPayload::ApprovalDecision {
                gate_id: body.gate_id.clone(),
                approved: body.approved,
                reason: body.reason.clone(),
            },
            Some(session_id),
            None,
            None,
        )
        .await
    {
        tracing::warn!("Failed to append ApprovalDecision to ledger: {}", e);
        return Err(StatusCode::INTERNAL_SERVER_ERROR);
    }
    // Mutate in-memory state only after the DB write succeeds (TOCTOU fix).
    state
        .approval_state
        .record_decision(session_id, body.gate_id, body.approved, body.reason);
    Ok(axum::Json(serde_json::json!({ "ok": true })))
}

#[derive(serde::Serialize)]
struct ConfigResponse {
    database_url: String,
    llm_backend: String,
    ollama_base_url: String,
    ollama_model: String,
    guard_required: bool,
    guard_llm_backend: Option<String>,
    guard_llm_model: Option<String>,
    max_steps: u32,
    agent_allowed_domains: Vec<String>,
    /// "none" | "docker" | "firecracker"
    sandbox_mode: String,
    /// true when EVM_RPC_URL + EVM_CONTRACT_ADDRESS env vars are set
    evm_enabled: bool,
    /// true when ECTO_DEMO_MODE=true|1 — used by the GUI to display a "Demo" tag
    demo_mode: bool,
}

/// Returns `true` if `host` resolves to a private, loopback, link-local, or cloud
/// metadata address.  Covers the full RFC 1918 172.16.0.0/12 range (172.16–172.31),
/// IPv6 loopback, IPv4-mapped IPv6, and common metadata hostnames.
pub fn is_internal_host(host: &str) -> bool {
    let clean = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = clean.parse::<std::net::IpAddr>() {
        return match ip {
            std::net::IpAddr::V4(v4) => {
                v4.is_loopback()
                    || v4.is_private()       // covers 10.*, 172.16-31.*, 192.168.*
                    || v4.is_link_local()     // 169.254.*
                    || v4.is_unspecified() // 0.0.0.0
            }
            std::net::IpAddr::V6(v6) => {
                v6.is_loopback()             // ::1
                    || v6.is_unspecified()    // ::
                    || (v6.segments()[0] & 0xffc0) == 0xfe80  // link-local fe80::/10
                    || (v6.segments()[0] & 0xfe00) == 0xfc00  // ULA fc00::/7 (fd…/fc…)
                    || v6.to_ipv4_mapped().is_some_and(|v4| {
                        v4.is_loopback() || v4.is_private() || v4.is_link_local()
                    })
            }
        };
    }
    host == "localhost"
        || host == "metadata.google.internal"
        || host.ends_with(".internal")
        || host.ends_with(".local")
}

/// Redact the password (if any) from a database connection URL.
fn redact_db_url(url: &str) -> String {
    if let Ok(mut parsed) = url::Url::parse(url) {
        if parsed.password().is_some() {
            let _ = parsed.set_password(Some("****"));
        }
        parsed.to_string()
    } else {
        url.to_string()
    }
}

fn merged_config() -> ConfigResponse {
    let allowed_domains: Vec<String> = std::env::var("AGENT_ALLOWED_DOMAINS")
        .ok()
        .map(|s| {
            s.split(',')
                .map(|x| x.trim().to_string())
                .filter(|x| !x.is_empty())
                .collect()
        })
        .unwrap_or_default();
    let sandbox_mode = if std::env::var("ECTO_FC_BINARY").is_ok() {
        "firecracker".to_string()
    } else if std::env::var("ECTO_DOCKER_IMAGE").is_ok() {
        "docker".to_string()
    } else {
        "none".to_string()
    };
    let evm_enabled =
        std::env::var("EVM_RPC_URL").is_ok() && std::env::var("EVM_CONTRACT_ADDRESS").is_ok();
    let demo_mode = std::env::var("ECTO_DEMO_MODE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    let base = ConfigResponse {
        database_url: redact_db_url(&config::database_url().unwrap_or_default()),
        llm_backend: config::llm_backend(),
        ollama_base_url: config::ollama_base_url(),
        ollama_model: config::ollama_model(),
        guard_required: config::guard_required(),
        guard_llm_backend: config::guard_llm_backend(),
        guard_llm_model: config::guard_llm_model(),
        max_steps: config::max_steps(),
        agent_allowed_domains: allowed_domains,
        sandbox_mode: sandbox_mode.clone(),
        evm_enabled,
        demo_mode,
    };
    if let Some(ov) = config::load_settings_config() {
        ConfigResponse {
            database_url: ov.database_url.unwrap_or(base.database_url),
            llm_backend: ov.llm_backend.unwrap_or(base.llm_backend),
            ollama_base_url: ov.ollama_base_url.unwrap_or(base.ollama_base_url),
            ollama_model: ov.ollama_model.unwrap_or(base.ollama_model),
            guard_required: ov.guard_required.unwrap_or(base.guard_required),
            guard_llm_backend: ov.guard_llm_backend.or(base.guard_llm_backend),
            guard_llm_model: ov.guard_llm_model.or(base.guard_llm_model),
            max_steps: ov.max_steps.unwrap_or(base.max_steps),
            agent_allowed_domains: ov
                .agent_allowed_domains
                .unwrap_or(base.agent_allowed_domains),
            sandbox_mode,
            evm_enabled,
            demo_mode,
        }
    } else {
        base
    }
}

async fn get_config(
    axum::Extension(role): axum::Extension<Role>,
) -> Result<axum::Json<ConfigResponse>, StatusCode> {
    // Restrict to Admin — the response includes database_url which may contain credentials.
    if role != Role::Admin {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(axum::Json(merged_config()))
}

/// Lightweight public status endpoint — no auth required.
/// Only exposes non-sensitive information that the GUI needs on startup.
#[derive(Serialize)]
struct StatusResponse {
    demo_mode: bool,
    version: &'static str,
}

async fn get_status() -> axum::Json<StatusResponse> {
    let demo_mode = std::env::var("ECTO_DEMO_MODE")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false);
    axum::Json(StatusResponse {
        demo_mode,
        version: env!("CARGO_PKG_VERSION"),
    })
}

#[derive(serde::Deserialize)]
struct ConfigUpdate {
    database_url: Option<String>,
    llm_backend: Option<String>,
    ollama_base_url: Option<String>,
    ollama_model: Option<String>,
    guard_required: Option<bool>,
    guard_llm_backend: Option<String>,
    guard_llm_model: Option<String>,
    max_steps: Option<u32>,
    agent_allowed_domains: Option<Vec<String>>,
}

async fn put_config(
    axum::Extension(role): axum::Extension<Role>,
    axum::Json(body): axum::Json<ConfigUpdate>,
) -> Result<axum::Json<ConfigResponse>, StatusCode> {
    if role != Role::Admin {
        return Err(StatusCode::FORBIDDEN);
    }
    let current = config::load_settings_config().unwrap_or_default();
    let cfg = config::SettingsConfig {
        database_url: body.database_url.or(current.database_url),
        llm_backend: body.llm_backend.or(current.llm_backend),
        ollama_base_url: body.ollama_base_url.or(current.ollama_base_url),
        ollama_model: body.ollama_model.or(current.ollama_model),
        guard_required: body.guard_required.or(current.guard_required),
        guard_llm_backend: body.guard_llm_backend.or(current.guard_llm_backend),
        guard_llm_model: body.guard_llm_model.or(current.guard_llm_model),
        max_steps: body.max_steps.or(current.max_steps),
        agent_allowed_domains: body.agent_allowed_domains.or(current.agent_allowed_domains),
    };
    config::save_settings_config(&cfg).map_err(|e| {
        tracing::error!("save_settings_config: {}", e);
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok(axum::Json(merged_config()))
}

// ── Demo reset ─────────────────────────────────────────────────────────────────

/// `POST /api/admin/reset-demo`
///
/// Deletes all agent sessions, events, snapshots, and action-log rows.
/// Only available in demo mode and only to admins.
async fn reset_demo_data(
    State(state): State<Arc<AppState>>,
    axum::Extension(role): axum::Extension<Role>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    if role != Role::Admin {
        return Err((StatusCode::FORBIDDEN, "Admin role required".into()));
    }
    if !config::is_demo_mode() {
        return Err((
            StatusCode::FORBIDDEN,
            "Reset is only available in demo mode".into(),
        ));
    }
    state.pool.reset_demo_data().await.map_err(|e| {
        tracing::error!("reset_demo_data: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("Failed to reset demo data: {e}"),
        )
    })?;
    // Re-create the genesis event so the ledger chain is valid.
    if let Err(e) = state.pool.ensure_genesis().await {
        tracing::warn!("Failed to re-create genesis event after reset: {}", e);
    }
    tracing::info!("Demo data reset by admin");
    Ok(axum::Json(
        serde_json::json!({"ok": true, "message": "Demo database reset successfully"}),
    ))
}

async fn get_tripwire_config() -> axum::Json<config::TripwireConfig> {
    axum::Json(config::load_tripwire_config())
}

#[derive(serde::Deserialize)]
struct TripwireConfigUpdate {
    allowed_paths: Vec<String>,
    allowed_domains: Vec<String>,
    banned_command_patterns: Vec<String>,
    #[serde(default)]
    min_justification_length: Option<u32>,
    #[serde(default)]
    require_https: Option<bool>,
}

async fn put_tripwire_config(
    axum::Extension(role): axum::Extension<Role>,
    axum::Json(body): axum::Json<TripwireConfigUpdate>,
) -> Result<axum::Json<config::TripwireConfig>, (StatusCode, String)> {
    if role != Role::Admin {
        return Err((StatusCode::FORBIDDEN, "Admin role required".to_string()));
    }
    let current = config::load_tripwire_config();
    let cfg = config::TripwireConfig {
        allowed_paths: body.allowed_paths,
        allowed_domains: body.allowed_domains,
        banned_command_patterns: body.banned_command_patterns,
        min_justification_length: body
            .min_justification_length
            .unwrap_or(current.min_justification_length),
        require_https: body.require_https.unwrap_or(current.require_https),
    };
    config::save_tripwire_config(&cfg).map_err(|e| {
        tracing::error!("save_tripwire_config: {}", e);
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            "Failed to save tripwire configuration".to_string(),
        )
    })?;
    Ok(axum::Json(cfg))
}

#[derive(serde::Serialize)]
struct SecurityMetricsResponse {
    injection_attempts_detected_7d: u64,
    injection_attempts_by_layer: std::collections::HashMap<String, u64>,
    sessions_aborted_circuit_breaker: u64,
    chain_verification_failures: u64,
}

async fn security_metrics(
    State(state): State<Arc<AppState>>,
    axum::Extension(_role): axum::Extension<Role>,
) -> Result<axum::Json<SecurityMetricsResponse>, StatusCode> {
    // Read-only summary counters — accessible to any authenticated role.
    let m = &state.metrics;
    let mut by_layer = std::collections::HashMap::new();
    by_layer.insert(
        "tripwire".to_string(),
        m.tripwire_rejections
            .load(std::sync::atomic::Ordering::Relaxed),
    );
    by_layer.insert(
        "guard_llm".to_string(),
        m.guard_denials.load(std::sync::atomic::Ordering::Relaxed),
    );
    Ok(axum::Json(SecurityMetricsResponse {
        injection_attempts_detected_7d: m
            .tripwire_rejections
            .load(std::sync::atomic::Ordering::Relaxed)
            + m.guard_denials.load(std::sync::atomic::Ordering::Relaxed),
        injection_attempts_by_layer: by_layer,
        sessions_aborted_circuit_breaker: 0,
        chain_verification_failures: 0,
    }))
}

async fn metrics_handler(
    State(state): State<Arc<AppState>>,
    axum::Extension(role): axum::Extension<Role>,
    headers: axum::http::HeaderMap,
) -> Result<([(axum::http::header::HeaderName, &'static str); 1], String), StatusCode> {
    if role != Role::Admin {
        return Err(StatusCode::FORBIDDEN);
    }
    let body = state.metrics.prometheus_text();

    let wants_html = headers
        .get(axum::http::header::ACCEPT)
        .and_then(|v| v.to_str().ok())
        .map(|a| a.contains("text/html"))
        .unwrap_or(false);

    if wants_html {
        let html = format!(
            r#"<!DOCTYPE html><html lang="en"><head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Ecto Ledger — Metrics</title>
<style>
  body{{margin:0;background:#0d1117;color:#c9d1d9;font-family:"SF Mono","Fira Code",Consolas,monospace;font-size:13px;padding:16px;}}
  h2{{color:#58a6ff;font-size:14px;margin-bottom:12px;}}
  pre{{white-space:pre-wrap;word-break:break-all;background:#161b22;padding:16px;border-radius:4px;border:1px solid #21262d;}}
  a{{color:#58a6ff;font-size:12px;}}
</style>
</head><body>
<h2>Ecto Ledger — Prometheus Metrics</h2>
<pre>{}</pre>
<a href="/">&larr; Observer dashboard</a>
</body></html>"#,
            body
        );
        Ok((
            [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
            html,
        ))
    } else {
        Ok((
            [(
                axum::http::header::CONTENT_TYPE,
                "text/plain; charset=utf-8",
            )],
            body,
        ))
    }
}

// ── RBAC token management ─────────────────────────────────────────────────────

#[derive(Deserialize)]
struct CreateTokenRequest {
    label: Option<String>,
    /// "admin", "auditor", or "agent"
    role: String,
    /// Optional number of days until this token expires.
    expires_in_days: Option<u32>,
}

#[derive(Serialize)]
struct CreateTokenResponse {
    /// Raw token — shown exactly once; the server stores only its SHA-256 hex digest.
    token: String,
    token_hash: String,
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
}

#[derive(Serialize)]
struct TokenListRow {
    token_hash: String,
    role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    label: Option<String>,
    created_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<String>,
}

async fn create_token(
    axum::Extension(role): axum::Extension<Role>,
    State(state): State<Arc<AppState>>,
    axum::Json(body): axum::Json<CreateTokenRequest>,
) -> Result<axum::Json<CreateTokenResponse>, StatusCode> {
    if role != Role::Admin {
        return Err(StatusCode::FORBIDDEN);
    }
    let role_str = match body.role.as_str() {
        r @ ("admin" | "auditor" | "agent") => r.to_string(),
        _ => return Err(StatusCode::BAD_REQUEST),
    };
    let raw: [u8; 32] = rand::random();
    let token = hex::encode(raw);
    let token_hash = hex::encode(Sha256::digest(token.as_bytes()));
    let expires_at: Option<chrono::DateTime<chrono::Utc>> = body
        .expires_in_days
        .map(|d| chrono::Utc::now() + chrono::Duration::days(d as i64));
    state
        .pool
        .insert_token(&token_hash, &role_str, body.label.as_deref(), expires_at)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(axum::Json(CreateTokenResponse {
        token,
        token_hash,
        role: role_str,
        label: body.label,
    }))
}

async fn list_tokens(
    axum::Extension(role): axum::Extension<Role>,
    State(state): State<Arc<AppState>>,
) -> Result<axum::Json<Vec<TokenListRow>>, StatusCode> {
    if role != Role::Admin {
        return Err(StatusCode::FORBIDDEN);
    }
    let rows = state
        .pool
        .list_tokens()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(axum::Json(
        rows.into_iter()
            .map(|t| TokenListRow {
                token_hash: t.token_hash,
                role: t.role,
                label: t.label,
                created_at: t.created_at,
                expires_at: t.expires_at,
            })
            .collect(),
    ))
}

async fn delete_token(
    axum::Extension(role): axum::Extension<Role>,
    State(state): State<Arc<AppState>>,
    Path(hash): Path<String>,
) -> Result<StatusCode, StatusCode> {
    if role != Role::Admin {
        return Err(StatusCode::FORBIDDEN);
    }
    state
        .pool
        .delete_token(&hash)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

// ── Dynamic webhook config ────────────────────────────────────────────────────

#[derive(Serialize)]
struct WebhookListRow {
    id: Uuid,
    label: String,
    url: String,
    siem_format: String,
    filter_kinds: Vec<String>,
    enabled: bool,
    created_at: String,
}

fn default_siem_format() -> String {
    "json".to_string()
}
fn default_filter_kinds() -> Vec<String> {
    vec![
        "observation".to_string(),
        "guard_denial".to_string(),
        "tripwire_rejection".to_string(),
    ]
}
fn default_enabled() -> bool {
    true
}

#[derive(Deserialize)]
struct UpsertWebhookRequest {
    label: String,
    url: String,
    bearer_token: Option<String>,
    #[serde(default = "default_siem_format")]
    siem_format: String,
    #[serde(default = "default_filter_kinds")]
    filter_kinds: Vec<String>,
    #[serde(default = "default_enabled")]
    enabled: bool,
}

async fn list_webhooks(
    axum::Extension(role): axum::Extension<Role>,
    State(state): State<Arc<AppState>>,
) -> Result<axum::Json<Vec<WebhookListRow>>, StatusCode> {
    if role != Role::Admin {
        return Err(StatusCode::FORBIDDEN);
    }
    let rows = state
        .pool
        .list_webhooks()
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let mut webhook_rows = Vec::new();
    for w in rows {
        let id: Uuid = w.id.parse().map_err(|e| {
            tracing::error!("Webhook has invalid UUID '{}': {e}", w.id);
            StatusCode::INTERNAL_SERVER_ERROR
        })?;
        webhook_rows.push(WebhookListRow {
            id,
            label: w.label,
            url: w.url,
            siem_format: w.siem_format,
            filter_kinds: w
                .filter_kinds
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect(),
            enabled: w.enabled,
            created_at: w.created_at,
        });
    }
    Ok(axum::Json(webhook_rows))
}

async fn create_webhook(
    axum::Extension(role): axum::Extension<Role>,
    State(state): State<Arc<AppState>>,
    axum::Json(body): axum::Json<UpsertWebhookRequest>,
) -> Result<(StatusCode, axum::Json<WebhookListRow>), StatusCode> {
    if role != Role::Admin {
        return Err(StatusCode::FORBIDDEN);
    }
    if body.url.is_empty() || !matches!(body.siem_format.as_str(), "json" | "cef" | "leef") {
        return Err(StatusCode::BAD_REQUEST);
    }
    // Validate webhook URL scheme to prevent SSRF via file://, ftp://, etc.
    let parsed_url = body
        .url
        .parse::<url::Url>()
        .map_err(|_| StatusCode::BAD_REQUEST)?;
    if !matches!(parsed_url.scheme(), "http" | "https") {
        return Err(StatusCode::BAD_REQUEST);
    }
    // Block requests to internal/link-local addresses via async DNS resolution
    if let Some(host) = parsed_url.host_str() {
        let port = parsed_url
            .port()
            .unwrap_or(if parsed_url.scheme() == "https" {
                443
            } else {
                80
            });
        if let Ok(addrs) = tokio::net::lookup_host(format!("{}:{}", host, port)).await {
            for addr in addrs {
                let ip = addr.ip();
                let is_private = match ip {
                    std::net::IpAddr::V4(v4) => {
                        v4.is_loopback()
                            || v4.is_private()
                            || v4.is_link_local()
                            || v4.is_unspecified()
                    }
                    std::net::IpAddr::V6(v6) => {
                        v6.is_loopback()
                            || v6.is_unspecified()
                            || v6.to_ipv4_mapped().is_some_and(|v4| {
                                v4.is_loopback() || v4.is_private() || v4.is_link_local()
                            })
                    }
                };
                if is_private {
                    return Err(StatusCode::BAD_REQUEST); // Reject internal IP resolution
                }
            }
        }
        if is_internal_host(host) {
            // Catch localhost/metadata strings
            return Err(StatusCode::BAD_REQUEST);
        }
    }
    let id_str = state
        .pool
        .insert_webhook(
            &body.label,
            &body.url,
            body.bearer_token.as_deref(),
            &body.siem_format,
            &body.filter_kinds,
            body.enabled,
        )
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let id: Uuid = id_str.parse().map_err(|e| {
        tracing::error!("insert_webhook returned invalid UUID '{id_str}': {e}");
        StatusCode::INTERNAL_SERVER_ERROR
    })?;
    Ok((
        StatusCode::CREATED,
        axum::Json(WebhookListRow {
            id,
            label: body.label,
            url: body.url,
            siem_format: body.siem_format,
            filter_kinds: body.filter_kinds,
            enabled: body.enabled,
            created_at: chrono::Utc::now().to_rfc3339(),
        }),
    ))
}

async fn delete_webhook(
    axum::Extension(role): axum::Extension<Role>,
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
) -> Result<StatusCode, StatusCode> {
    if role != Role::Admin {
        return Err(StatusCode::FORBIDDEN);
    }
    state
        .pool
        .delete_webhook(&id.to_string())
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::NO_CONTENT)
}

/// Body accepted by `PUT /api/webhooks/{id}`.
#[derive(Deserialize)]
struct ToggleWebhookBody {
    /// Desired state: `true` to enable the webhook, `false` to disable it.
    enabled: bool,
}

/// Set a webhook's `enabled` flag to an explicit value (Admin only).
///
/// Uses SET semantics (`enabled = $2`) rather than a flip so that concurrent
/// requests from the GUI always converge to the caller's intent, regardless of
/// the current DB state.
async fn toggle_webhook(
    axum::Extension(role): axum::Extension<Role>,
    State(state): State<Arc<AppState>>,
    Path(id): Path<Uuid>,
    axum::Json(body): axum::Json<ToggleWebhookBody>,
) -> Result<StatusCode, StatusCode> {
    if role != Role::Admin {
        return Err(StatusCode::FORBIDDEN);
    }
    state
        .pool
        .toggle_webhook(&id.to_string(), body.enabled)
        .await
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    Ok(StatusCode::OK)
}

// ── SDK-facing REST endpoints ─────────────────────────────────────────────────

/// `POST /api/sessions/{id}/seal` — Seal (finish) a session.
async fn seal_session_handler(
    State(state): State<Arc<AppState>>,
    axum::Extension(role): axum::Extension<Role>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    if role == Role::Auditor {
        return Err((
            StatusCode::FORBIDDEN,
            "Auditor role cannot seal sessions".into(),
        ));
    }
    state
        .pool
        .finish_session(session_id, "completed")
        .await
        .map_err(|e| {
            tracing::error!("seal_session failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to seal session: {e}"),
            )
        })?;
    Ok(axum::Json(serde_json::json!({"ok": true})))
}

/// `POST /api/sessions/{id}/events` — Append a single event to a session.
///
/// Accepts an arbitrary JSON body.  If the body matches a known `EventPayload`
/// variant it is stored as-is; otherwise it is wrapped in `Observation { content }`.
async fn append_event_handler(
    State(state): State<Arc<AppState>>,
    axum::Extension(role): axum::Extension<Role>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
    axum::Json(body): axum::Json<serde_json::Value>,
) -> Result<(StatusCode, axum::Json<serde_json::Value>), (StatusCode, String)> {
    if role == Role::Auditor {
        return Err((
            StatusCode::FORBIDDEN,
            "Auditor role cannot append events".into(),
        ));
    }
    // Try to deserialize as a known EventPayload variant; fall back to Observation.
    let payload: EventPayload =
        serde_json::from_value(body.clone()).unwrap_or_else(|_| EventPayload::Observation {
            content: body.to_string(),
        });
    let result = state
        .pool
        .append_event(payload, Some(session_id), None, None)
        .await
        .map_err(|e| {
            tracing::error!("append_event failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Failed to append event: {e}"),
            )
        })?;
    state.metrics.inc_events_appended();
    Ok((
        StatusCode::CREATED,
        axum::Json(serde_json::json!({
            "id": result.id,
            "payload_hash": result.content_hash,
            "sequence": result.sequence,
        })),
    ))
}

/// `GET /api/sessions/{id}/verify` — Verify hash-chain integrity for a session.
async fn verify_chain_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    let ok = state
        .pool
        .verify_chain_for_session(session_id)
        .await
        .map_err(|e| {
            tracing::error!("verify_chain failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Chain verification failed: {e}"),
            )
        })?;
    Ok(axum::Json(serde_json::json!({"ok": ok})))
}

/// `GET /api/sessions/{id}/compliance` — Generate a compliance proof bundle.
async fn prove_compliance_handler(
    State(state): State<Arc<AppState>>,
    axum::extract::Path(session_id): axum::extract::Path<Uuid>,
) -> Result<axum::Json<serde_json::Value>, (StatusCode, String)> {
    let value = state
        .pool
        .prove_compliance_for_session(session_id)
        .await
        .map_err(|e| {
            tracing::error!("prove_compliance failed: {}", e);
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Compliance proof failed: {e}"),
            )
        })?;
    Ok(axum::Json(value))
}

/// `GET /api/metrics` — JSON metrics summary (total_sessions, total_events).
async fn metrics_json_handler(
    State(state): State<Arc<AppState>>,
    axum::Extension(_role): axum::Extension<Role>,
) -> axum::Json<serde_json::Value> {
    let m = &state.metrics;
    axum::Json(serde_json::json!({
        "total_sessions": m.sessions_created.load(std::sync::atomic::Ordering::Relaxed),
        "total_events": m.events_appended.load(std::sync::atomic::Ordering::Relaxed),
    }))
}

/// Build a router and return both the `Router` and the shared `ApprovalState` Arc so callers
/// (e.g. the `audit` command) can wire it into the `AgentLoopConfig`.
pub fn router_with_approval_state(
    pool: DatabasePool,
    metrics: Arc<crate::metrics::Metrics>,
    approval_state: Arc<ApprovalState>,
    cancel: CancellationToken,
    llm_factory: Option<Arc<dyn Fn() -> Box<dyn llm::LlmBackend> + Send + Sync>>,
) -> (Router, TaskTracker) {
    let task_tracker = TaskTracker::new();
    let (tx, _) = broadcast::channel::<()>(64);
    // Spin up exactly one egress worker for the lifetime of this router.  All
    // agent sessions share this single worker rather than each spawning their
    // own, preventing DB connection pool exhaustion under concurrent load.
    //
    // The egress worker requires PgPool (it queries webhooks with PG-specific
    // SQL).  When running in embedded SQLite mode we skip it and use a dummy
    // channel whose sender will never deliver.
    let egress_tx: mpsc::Sender<crate::webhook::EgressEvent> = if let Some(pg) = pool.as_pg() {
        let (etx, _handle) =
            crate::webhook::spawn_egress_worker(config::webhook_config(), pg.clone());
        etx
    } else {
        let (etx, mut rx) = mpsc::channel(16);
        // Drain the receiver so senders never block on a full channel.
        tokio::spawn(async move { while rx.recv().await.is_some() {} });
        tracing::info!("webhook egress worker disabled (no Postgres pool)");
        etx
    };

    // ── Zombie session reaper ────────────────────────────────────────────
    // A session that is still "running" after 60 minutes almost certainly hit an
    // unrecoverable panic or lost its DB connection.  Mark it "failed" so the
    // GUI never shows a permanently-spinning session.
    {
        let reaper_pool = pool.clone();
        tokio::spawn(async move {
            let interval = tokio::time::Duration::from_secs(5 * 60); // every 5 min
            loop {
                tokio::time::sleep(interval).await;
                let fut = std::panic::AssertUnwindSafe(reaper_pool.reap_zombie_sessions(60));
                match futures_util::FutureExt::catch_unwind(fut).await {
                    Ok(Ok(n)) if n > 0 => {
                        tracing::warn!(
                            count = n,
                            "zombie-session-reaper: marked {n} stale session(s) as failed"
                        );
                    }
                    Ok(Err(e)) => {
                        tracing::error!("zombie-session-reaper: query failed: {e}");
                    }
                    Err(e) => {
                        tracing::error!(
                            "zombie-session-reaper: panicked: {:?} — will retry next interval",
                            e
                        );
                    }
                    _ => {}
                }
            }
        });
    }

    // Store the SSE sender in the global so `notify_sse_subscribers()` can
    // wake SSE handlers from the ledger layer without threading state through.
    let _ = SSE_WAKEUP.set(tx.clone());
    let state = Arc::new(AppState {
        pool,
        metrics,
        approval_state,
        sse_tx: tx,
        egress_tx,
        http_client: reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(60))
            .build()
            .unwrap_or_else(|e| {
                tracing::warn!(
                    "reqwest Client::builder() failed ({e}); falling back to default client"
                );
                reqwest::Client::new()
            }),
        task_tracker: task_tracker.clone(),
        cancel,
        llm_factory,
    });

    // Global API rate limit: configurable via API_RATE_LIMIT_PER_SECOND and
    // API_RATE_LIMIT_BURST env vars (defaults: 60 req/s, burst 120).
    let api_governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_second(crate::config::api_rate_limit_per_second())
            .burst_size(crate::config::api_rate_limit_burst())
            .finish()
            .expect("GovernorConfigBuilder with valid per_second/burst_size must succeed"),
    );

    // Stricter rate limit for the SSE stream endpoint.  Override via
    // SSE_RATE_LIMIT_PER_SECOND / SSE_RATE_LIMIT_BURST env vars.
    let sse_governor_conf = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_second(crate::config::sse_rate_limit_per_second())
            .burst_size(crate::config::sse_rate_limit_burst())
            .finish()
            .expect("GovernorConfigBuilder with valid per_second/burst_size must succeed"),
    );

    // Per-IP limit on session *creation* only (POST).  Defaults to 2 req/s with
    // burst of 5 to prevent an authenticated caller from spinning up hundreds of
    // concurrent sessions and exhausting LLM quota / DB connections.  Override
    // via SESSION_RATE_LIMIT_PER_SECOND / SESSION_RATE_LIMIT_BURST env vars
    // (set both to high values in integration-test environments).
    let session_create_conf = Arc::new(
        GovernorConfigBuilder::default()
            .key_extractor(SmartIpKeyExtractor)
            .per_second(crate::config::session_rate_limit_per_second())
            .burst_size(crate::config::session_rate_limit_burst())
            .finish()
            .expect("GovernorConfigBuilder with valid per_second/burst_size must succeed"),
    );

    let stream_router = Router::new()
        .route("/api/stream", get(stream_events))
        .route_layer(GovernorLayer::new(sse_governor_conf));

    let session_create_router = Router::new()
        .route("/api/sessions", post(create_session))
        .route("/api/chat", post(chat))
        .route_layer(GovernorLayer::new(session_create_conf));

    let built_router = Router::new()
        .route("/api/sessions", get(list_sessions))
        .merge(session_create_router)
        .route("/api/sessions/{id}", get(get_session_by_id))
        .route("/api/sessions/{id}/seal", post(seal_session_handler))
        .route("/api/sessions/{id}/events", post(append_event_handler))
        .route("/api/sessions/{id}/verify", get(verify_chain_handler))
        .route(
            "/api/sessions/{id}/compliance",
            get(prove_compliance_handler),
        )
        .route("/api/events", get(get_events_json))
        .route("/api/policies", get(list_policies))
        .route(
            "/api/policies/{name}",
            get(get_policy_content)
                .put(save_policy)
                .delete(delete_policy),
        )
        .route("/api/certificates/{session_id}", get(get_certificate))
        .route("/api/reports/{session_id}", get(get_report))
        .route(
            "/api/approvals/{session_id}/pending",
            get(get_pending_approval),
        )
        .route("/api/approvals/{session_id}", post(post_approval_decision))
        .route("/metrics", get(metrics_handler))
        .route("/api/metrics", get(metrics_json_handler))
        .route("/api/metrics/security", get(security_metrics))
        .route("/api/config", get(get_config).put(put_config))
        .route("/api/admin/reset-demo", post(reset_demo_data))
        .route(
            "/api/tripwire",
            get(get_tripwire_config).put(put_tripwire_config),
        )
        .route("/api/sessions/{id}/vc", get(get_session_vc))
        .route("/api/sessions/{id}/vc/verify", get(verify_session_vc))
        .route("/api/tokens", get(list_tokens).post(create_token))
        .route("/api/tokens/{hash}", delete(delete_token))
        .route("/api/webhooks", get(list_webhooks).post(create_webhook))
        .route(
            "/api/webhooks/{id}",
            delete(delete_webhook).put(toggle_webhook),
        )
        // ── Python SDK alias routes ──────────────────────────────────────
        // The Python SDK uses slightly different endpoint paths.  These aliases
        // ensure both the TS and Python SDKs work against the same backend.
        .route(
            "/api/config/tripwire",
            get(get_tripwire_config).put(put_tripwire_config),
        )
        .route("/api/webhooks/{id}/toggle", put(toggle_webhook))
        .route(
            "/api/sessions/{session_id}/events/stream",
            get(stream_events_by_session),
        )
        .route("/api/sessions/{session_id}/chat", post(session_chat))
        .merge(stream_router)
        .route_layer(GovernorLayer::new(api_governor_conf))
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_auth,
        ))
        // Public routes — merged AFTER the auth route_layer so they are
        // accessible without a Bearer token (the index page is static HTML).
        .route("/", get(index))
        .route("/api/status", get(get_status))
        .layer(axum::extract::DefaultBodyLimit::max(1_048_576)) // 1 MiB
        // CORS: allow any origin so the Tauri webview (tauri://localhost or
        // http://localhost:1420 in dev) can reach the embedded Axum server.
        // The server binds only to 127.0.0.1 so this poses no external risk;
        // real security is enforced by the Bearer-token auth middleware above.
        .layer(CorsLayer::very_permissive())
        .with_state(state);

    (built_router, task_tracker)
}

pub fn router(
    pool: DatabasePool,
    metrics: Arc<crate::metrics::Metrics>,
    cancel: CancellationToken,
) -> (Router, TaskTracker) {
    router_with_approval_state(pool, metrics, Arc::new(ApprovalState::new()), cancel, None)
}
