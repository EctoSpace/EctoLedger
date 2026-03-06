//! LLM backend abstraction and provider implementations for EctoLedger.
//!
//! This crate defines the [`LlmBackend`] trait and concrete implementations for
//! Ollama, OpenAI, and Anthropic.  The host crate re-exports this module so
//! existing `crate::llm::*` paths continue to resolve.

mod anthropic;
mod ollama_backend;
pub mod ollama_setup;
mod openai;

pub use anthropic::AnthropicBackend;
pub use ollama_backend::OllamaBackend;
pub use ollama_setup::{OllamaSetupError, ensure_ollama_ready};
pub use openai::OpenAiBackend;

use async_trait::async_trait;
use ectoledger_core::intent::ProposedIntent;

// ── System prompt & few-shot examples ─────────────────────────────────────────

pub const DEFAULT_SYSTEM_PROMPT: &str = r#"You are a security-audit agent. Your response must be exactly one JSON object with no surrounding text.

Goal: Achieve the user's current goal (stated at the start of the user message).

Allowed actions and params:
- run_command: params.command (string) — run a single shell command
- read_file: params.path (string) — read a file path
- http_get: params.url (string) — fetch a URL
- complete: no params or empty params — finish the audit

Security rules:
- Propose only actions necessary for the stated goal.
- Do not run destructive or off-goal commands.

Anti-loop rule:
- Do not repeat the same action with the same parameters. If an action did not advance the goal, try a different action or complete with your findings.

Output format (JSON only — you MUST use this exact structure):
{"action": "<action>", "params": {...}, "justification": "<why this action is needed, at least 5 chars>", "reasoning": "<your step-by-step thinking>"}
Every response MUST include all four fields: "action", "params", "justification", and "reasoning". If "justification" is missing or shorter than 5 characters your response will be rejected.
When you complete, include in params an optional \"findings\" array. Each finding must have \"severity\", \"title\", \"evidence\", \"recommendation\", and for high/critical must include \"evidence_sequence\" (array of ledger sequence numbers of observations that support this finding) and \"evidence_quotes\" (array of exact substrings from those observations).

Example for step 1 (reading a file):
{\"action\": \"read_file\", \"params\": {\"path\": \"server_config.txt\"}, \"justification\": \"Reading the config file to identify misconfigurations.\", \"reasoning\": \"Reading config to inspect settings.\"}"#;

/// Few-shot examples injected during the first steps to anchor weaker models
/// and prevent them from producing off-format or looping output.
pub fn few_shot_examples() -> &'static str {
    r#"
--- FEW-SHOT EXAMPLES (follow this exact format) ---

Example 1 — reading a file:
User: "Current goal: Audit server_config.txt\n\nRecent events:\n  [genesis] initialized"
Assistant: {"action":"read_file","params":{"path":"server_config.txt"},"justification":"Need to inspect server configuration for audit findings.","reasoning":"The goal is to audit server_config.txt, so reading it is the first logical step."}

Example 2 — running a command:
User: "Current goal: Check open ports\n\nRecent events:\n  [observation] file contents: ..."
Assistant: {"action":"run_command","params":{"command":"ss -tlnp"},"justification":"Listing TCP listening ports to identify exposed services.","reasoning":"After reading config, enumerating listening ports confirms which services are active."}

Example 3 — completing the audit:
User: "Current goal: Audit server_config.txt\n\nRecent events:\n  [observation] port 22 open"
Assistant: {"action":"complete","params":{"findings":[{"severity":"medium","title":"SSH exposed","evidence":"port 22 open","recommendation":"Restrict SSH access via firewall rules."}]},"justification":"All planned checks done.","reasoning":"Sufficient evidence gathered to produce findings."}

--- END EXAMPLES ---
"#
}

// ── Helpers ───────────────────────────────────────────────────────────────────

pub fn strip_markdown_fences(s: &str) -> &str {
    let s = s.trim();
    if !s.starts_with("```") {
        return s;
    }
    let after_open = s.trim_start_matches('`');
    let after_lang = after_open
        .trim_start_matches("json")
        .trim_start_matches("JSON")
        .trim_start_matches('\n')
        .trim_start_matches('\r');
    match after_lang.rfind("```") {
        Some(end) => after_lang[..end].trim(),
        None => after_lang.trim(),
    }
}

// ── Trait ──────────────────────────────────────────────────────────────────────

#[async_trait]
pub trait LlmBackend: Send + Sync {
    async fn propose(&self, system: &str, user: &str) -> Result<ProposedIntent, LlmError>;
    async fn raw_call(&self, system: &str, user: &str) -> Result<String, LlmError>;
    fn backend_name(&self) -> &str;
    fn model_name(&self) -> &str;
    async fn ensure_ready(&self, client: &reqwest::Client) -> Result<(), LlmError> {
        let _ = client;
        Ok(())
    }
}

// ── Error ─────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum LlmError {
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
    #[error("http status {0}: {1}")]
    HttpStatus(u16, String),
    #[error("empty response")]
    EmptyResponse,
    #[error("invalid json: {0}")]
    InvalidJson(#[from] serde_json::Error),
    #[error("unsupported LLM backend: {0}")]
    UnsupportedBackend(String),
    #[error("setup: {0}")]
    Setup(String),
}
