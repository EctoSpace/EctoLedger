//! Integration tests for the five SDK-aligned routes:
//!
//!   POST /sessions/:id/seal
//!   POST /sessions/:id/events   (external append)
//!   GET  /sessions/:id/verify
//!   GET  /sessions/:id/compliance
//!   GET  /metrics/json
//!
//! Each test spins up the full Axum server on a random port with an
//! in-memory SQLite database.  No external services needed.

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use std::sync::Arc;

const TEST_TOKEN: &str = "test-token";

// ── Minimal LLM stub for tests (no mock.rs dependency) ──────────────────────

/// A zero-dependency LLM backend that always returns `complete`.
/// Lives in the test file so production code never ships a mock.
struct TestStubBackend;

#[async_trait]
impl ectoledger::llm::LlmBackend for TestStubBackend {
    async fn propose(
        &self,
        _system: &str,
        _user: &str,
    ) -> Result<ectoledger_core::intent::ProposedIntent, ectoledger::llm::LlmError> {
        Ok(ectoledger_core::intent::ProposedIntent {
            action: "complete".into(),
            params: serde_json::json!({ "findings": [] }),
            justification: "Test stub — completing immediately.".into(),
            reasoning: "Integration test stub.".into(),
        })
    }

    async fn raw_call(
        &self,
        _system: &str,
        _user: &str,
    ) -> Result<String, ectoledger::llm::LlmError> {
        Ok("test-stub response".into())
    }

    fn backend_name(&self) -> &str {
        "test-stub"
    }

    fn model_name(&self) -> &str {
        "test-stub-v1"
    }
}

/// Set GUARD_REQUIRED=false exactly once before any async runtime is spawned.
fn ensure_guard_disabled() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        // SAFETY: called exactly once, before any multi-threaded Tokio
        // runtime is active, so there is no concurrent env reader.
        unsafe {
            std::env::set_var("GUARD_REQUIRED", "false");
        }
    });
}

/// Spawn the EctoLedger server on a random port, return the base URL.
async fn spawn_server() -> String {
    ensure_guard_disabled();

    let pool = ectoledger::pool::create_sqlite_pool(std::path::Path::new(":memory:"))
        .await
        .expect("create in-memory SQLite pool");

    // Seed the test bearer token into api_tokens so the auth middleware accepts it.
    let token_hash = hex::encode(Sha256::digest(TEST_TOKEN.as_bytes()));
    pool.insert_token(&token_hash, "admin", Some("test"), None)
        .await
        .expect("seed test token");

    let metrics = Arc::new(ectoledger::metrics::Metrics::default());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");
    let base = format!("http://{addr}/api");

    let llm_factory: Arc<dyn Fn() -> Box<dyn ectoledger::llm::LlmBackend> + Send + Sync> =
        Arc::new(|| Box::new(TestStubBackend));

    tokio::spawn(async move {
        ectoledger::start_server_with_llm(pool, metrics, listener, llm_factory)
            .await
            .expect("server exited with error");
    });

    // Give the server a moment to start accepting connections
    tokio::time::sleep(std::time::Duration::from_millis(100)).await;

    base
}

fn auth() -> (&'static str, &'static str) {
    ("Authorization", "Bearer test-token")
}

/// Create a session and return its id.
async fn create_session(base: &str) -> String {
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/sessions"))
        .header(auth().0, auth().1)
        .json(&serde_json::json!({ "goal": "integration-test" }))
        .send()
        .await
        .expect("POST /sessions");
    assert!(
        resp.status().is_success(),
        "create session: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("json");
    body["id"].as_str().expect("id field").to_string()
}

// ── POST /sessions/:id/seal ──────────────────────────────────────

#[tokio::test]
async fn seal_session_sets_status_completed() {
    let base = spawn_server().await;
    let id = create_session(&base).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/sessions/{id}/seal"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "seal: {}", resp.status());

    let session: serde_json::Value = client
        .get(format!("{base}/sessions/{id}"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(session["status"].as_str().unwrap_or(""), "completed");
}

#[tokio::test]
async fn seal_session_is_idempotent() {
    let base = spawn_server().await;
    let id = create_session(&base).await;
    let client = reqwest::Client::new();

    let r1 = client
        .post(format!("{base}/sessions/{id}/seal"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap();
    assert!(r1.status().is_success());

    let r2 = client
        .post(format!("{base}/sessions/{id}/seal"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap();
    assert!(r2.status().is_success());
}

// ── POST /sessions/:id/events ────────────────────────────────────

#[tokio::test]
async fn append_event_succeeds() {
    let base = spawn_server().await;
    let id = create_session(&base).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("{base}/sessions/{id}/events"))
        .header(auth().0, auth().1)
        .json(&serde_json::json!({
            "event_type": "test_event",
            "payload": { "key": "value" }
        }))
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "append event: {}",
        resp.status()
    );

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body.get("id").is_some() || body.get("seq").is_some(),
        "response should contain id or seq: {body}"
    );
}

#[tokio::test]
async fn append_multiple_events_and_verify_chain() {
    let base = spawn_server().await;
    let id = create_session(&base).await;
    let client = reqwest::Client::new();

    for i in 0..3 {
        let resp = client
            .post(format!("{base}/sessions/{id}/events"))
            .header(auth().0, auth().1)
            .json(&serde_json::json!({
                "event_type": "step",
                "payload": { "index": i }
            }))
            .send()
            .await
            .unwrap();
        assert!(resp.status().is_success(), "append {i}: {}", resp.status());
    }

    // Verify chain integrity
    let resp = client
        .get(format!("{base}/sessions/{id}/verify"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "verify: {}", resp.status());
}

// ── GET /sessions/:id/verify ─────────────────────────────────────

#[tokio::test]
async fn verify_chain_valid() {
    let base = spawn_server().await;
    let id = create_session(&base).await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{base}/sessions/{id}/verify"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    let body: serde_json::Value = resp.json().await.unwrap();
    let valid = body["valid"]
        .as_bool()
        .or_else(|| body["ok"].as_bool())
        .or_else(|| body["verified"].as_bool());
    assert_eq!(valid, Some(true), "expected valid chain: {body}");
}

// ── GET /sessions/:id/compliance ─────────────────────────────────

#[tokio::test]
async fn prove_compliance_returns_bundle() {
    let base = spawn_server().await;
    let id = create_session(&base).await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{base}/sessions/{id}/compliance"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "compliance: {}", resp.status());

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(
        body.is_object() || body.is_array(),
        "compliance should be JSON object/array: {body}"
    );
}

// ── GET /metrics/json ────────────────────────────────────────────

#[tokio::test]
async fn metrics_json_returns_object() {
    let base = spawn_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{base}/metrics"))
        .header(auth().0, auth().1)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "metrics/json: {}",
        resp.status()
    );

    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body.is_object(), "metrics/json should be object: {body}");
}

// ── Cross-platform OS-specific tests ─────────────────────────────

#[cfg(target_os = "linux")]
mod linux_guards {
    use super::*;

    #[tokio::test]
    async fn event_with_sensitive_linux_path() {
        let base = spawn_server().await;
        let id = create_session(&base).await;
        let client = reqwest::Client::new();

        let resp = client
            .post(format!("{base}/sessions/{id}/events"))
            .header(auth().0, auth().1)
            .json(&serde_json::json!({
                "event_type": "file_access",
                "payload": { "path": "/etc/shadow" }
            }))
            .send()
            .await
            .unwrap();
        // Accepted (guard logs, not blocks by default) or 400
        assert!(
            resp.status().is_success() || resp.status().as_u16() == 400,
            "linux sensitive path: {}",
            resp.status()
        );
    }
}

#[cfg(target_os = "macos")]
mod macos_guards {
    use super::*;

    #[tokio::test]
    async fn event_with_keychain_path() {
        let base = spawn_server().await;
        let id = create_session(&base).await;
        let client = reqwest::Client::new();

        let resp = client
            .post(format!("{base}/sessions/{id}/events"))
            .header(auth().0, auth().1)
            .json(&serde_json::json!({
                "event_type": "file_access",
                "payload": { "path": "/Library/Keychains/System.keychain" }
            }))
            .send()
            .await
            .unwrap();
        assert!(
            resp.status().is_success() || resp.status().as_u16() == 400,
            "macos keychain path: {}",
            resp.status()
        );
    }
}

#[cfg(target_os = "windows")]
mod windows_guards {
    use super::*;

    #[tokio::test]
    async fn event_with_system32_path() {
        let base = spawn_server().await;
        let id = create_session(&base).await;
        let client = reqwest::Client::new();

        let resp = client
            .post(format!("{base}/sessions/{id}/events"))
            .header(auth().0, auth().1)
            .json(&serde_json::json!({
                "event_type": "file_access",
                "payload": { "path": "C:\\Windows\\System32\\config\\SAM" }
            }))
            .send()
            .await
            .unwrap();
        assert!(
            resp.status().is_success() || resp.status().as_u16() == 400,
            "windows system32 path: {}",
            resp.status()
        );
    }

    #[tokio::test]
    async fn event_with_unc_path() {
        let base = spawn_server().await;
        let id = create_session(&base).await;
        let client = reqwest::Client::new();

        let resp = client
            .post(format!("{base}/sessions/{id}/events"))
            .header(auth().0, auth().1)
            .json(&serde_json::json!({
                "event_type": "file_access",
                "payload": { "path": "\\\\server\\share\\secret.doc" }
            }))
            .send()
            .await
            .unwrap();
        assert!(
            resp.status().is_success() || resp.status().as_u16() == 400,
            "windows UNC path: {}",
            resp.status()
        );
    }
}
