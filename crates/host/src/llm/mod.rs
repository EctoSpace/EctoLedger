// Re-export everything from the standalone ectoledger-llm crate so that
// existing `crate::llm::*` paths resolve without changes across the host.
pub use ectoledger_llm::*;

use crate::schema::{EventPayload, RestoredState};
use async_trait::async_trait;
use serde_json::json;

pub fn state_to_prompt(state: &RestoredState, max_events: usize) -> String {
    let mut out = String::new();
    if let Some(obj) = state.snapshot_payload.as_object() {
        if let Some(c) = obj.get("event_count").and_then(|v| v.as_u64()) {
            out.push_str(&format!("Event count: {}\n", c));
        }
        if let Some(s) = obj.get("last_sequence").and_then(|v| v.as_i64()) {
            out.push_str(&format!("Last sequence: {}\n", s));
        }
    }
    out.push_str("\nRecent events:\n");
    let start = state.replayed_events.len().saturating_sub(max_events);
    for ev in state.replayed_events.iter().skip(start) {
        match &ev.payload {
            EventPayload::Genesis { message, .. } => {
                out.push_str(&format!("  [genesis] {}\n", message));
            }
            EventPayload::PromptInput { content } => {
                out.push_str(&format!("  [prompt] {}\n", content));
            }
            EventPayload::Thought { content } => {
                out.push_str(&format!("  [thought] {}\n", content));
            }
            EventPayload::SchemaError {
                message,
                attempt,
                max_attempts,
            } => {
                out.push_str(&format!(
                    "  [schema_error] ({}/{}) {}\n",
                    attempt, max_attempts, message
                ));
            }
            EventPayload::CircuitBreaker {
                reason,
                consecutive_failures,
            } => {
                out.push_str(&format!(
                    "  [circuit_breaker] ({} failures) {}\n",
                    consecutive_failures, reason
                ));
            }
            EventPayload::Action { name, params } => {
                out.push_str(&format!("  [action] {} {:?}\n", name, params));
            }
            EventPayload::Observation { content } => {
                let trunc = if content.len() > 200 {
                    let mut b = 200;
                    while b > 0 && !content.is_char_boundary(b) {
                        b -= 1;
                    }
                    format!("{}...", &content[..b])
                } else {
                    content.clone()
                };
                out.push_str(&format!("  [observation] {}\n", trunc));
            }
            EventPayload::ApprovalRequired { .. } | EventPayload::ApprovalDecision { .. } => {
                out.push_str("  [approval]\n");
            }
            EventPayload::CrossLedgerSeal { seal_hash, .. } => {
                out.push_str(&format!(
                    "  [cross_ledger_seal] {}\n",
                    &seal_hash[..16.min(seal_hash.len())]
                ));
            }
            EventPayload::Anchor {
                ledger_tip_hash, ..
            } => {
                out.push_str(&format!(
                    "  [anchor] tip {}\n",
                    &ledger_tip_hash[..16.min(ledger_tip_hash.len())]
                ));
            }
            EventPayload::KeyRotation {
                new_public_key,
                rotation_index,
            } => {
                out.push_str(&format!(
                    "  [key_rotation] index {} new_key {}\n",
                    rotation_index,
                    &new_public_key[..16.min(new_public_key.len())]
                ));
            }
            EventPayload::KeyRevocation {
                revoked_public_key,
                reason,
            } => {
                out.push_str(&format!(
                    "  [key_revocation] key {} reason: {}\n",
                    &revoked_public_key[..16.min(revoked_public_key.len())],
                    reason
                ));
            }
            EventPayload::VerifiableCredential { .. } => {
                out.push_str("  [verifiable_credential]\n");
            }
            EventPayload::ChatMessage { role, content, .. } => {
                out.push_str(&format!("  [chat:{}] {}\n", role, content));
            }
        }
    }
    out.push_str("\nPropose the next action as a single JSON object (action + params only).");
    out
}

// ── Local mock backend (for deterministic integration tests) ─────────────────

struct MockBackend;

#[async_trait]
impl LlmBackend for MockBackend {
    async fn propose(&self, _system: &str, _user: &str) -> Result<ectoledger_core::intent::ProposedIntent, LlmError> {
        Ok(ectoledger_core::intent::ProposedIntent {
            action: "complete".to_string(),
            params: json!({ "findings": [] }),
            justification: "Mock backend deterministic completion".to_string(),
            reasoning: "No external LLM available in this environment.".to_string(),
        })
    }

    async fn raw_call(&self, _system: &str, user: &str) -> Result<String, LlmError> {
        Ok(format!("mock: {}", user))
    }

    fn backend_name(&self) -> &str {
        "mock"
    }

    fn model_name(&self) -> &str {
        "mock-v1"
    }
}

// ── Factory functions (depend on host crate's config module) ──────────────────

pub fn backend_from_env(client: &reqwest::Client) -> Result<Box<dyn LlmBackend>, LlmError> {
    let name = crate::config::llm_backend();
    match name.as_str() {
        "mock" => Ok(Box::new(MockBackend)),
        "ollama" => Ok(Box::new(OllamaBackend::from_env(client))),
        "openai" => Ok(Box::new(OpenAiBackend::from_env(client))),
        "anthropic" => Ok(Box::new(AnthropicBackend::from_env(client))),
        _ => Err(LlmError::UnsupportedBackend(name)),
    }
}

/// Creates a Guard LLM backend from environment variables.
///
/// Reads `GUARD_LLM_BACKEND` (default: same as `LLM_BACKEND`) and
/// `GUARD_LLM_MODEL` to allow the guard to run on a separate, isolated model.
pub fn guard_backend_from_env(client: &reqwest::Client) -> Result<Box<dyn LlmBackend>, LlmError> {
    let name = crate::config::guard_llm_backend().unwrap_or_else(crate::config::llm_backend);
    let guard_model = crate::config::guard_llm_model();

    match name.as_str() {
        "mock" => Ok(Box::new(MockBackend)),
        "ollama" => {
            let mut backend = OllamaBackend::from_env(client);
            if let Some(model) = guard_model {
                backend.override_model(model);
            }
            Ok(Box::new(backend))
        }
        "openai" => {
            let mut backend = OpenAiBackend::from_env(client);
            if let Some(model) = guard_model {
                backend.override_model(model);
            }
            Ok(Box::new(backend))
        }
        "anthropic" => {
            let mut backend = AnthropicBackend::from_env(client);
            if let Some(model) = guard_model {
                backend.override_model(model);
            }
            Ok(Box::new(backend))
        }
        _ => Err(LlmError::UnsupportedBackend(name)),
    }
}
