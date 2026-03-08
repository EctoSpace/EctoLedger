//! # ledger-api
//!
//! Minimal, backend-agnostic trait surface for the Ecto Ledger cryptographic ledger.
//!
//! Consumers (agents, servers, tests) depend on *this* crate rather than directly on
//! any concrete backend.  The host crate ships two implementations behind the
//! `LedgerBackend` trait:
//!
//! - `ledger::postgres::PostgresLedger`  — production Postgres
//! - `ledger::sqlite::SqliteLedger`      — zero-config local SQLite
//!
//! ## Example
//! ```rust,ignore
//! use std::sync::Arc;
//! use ledger_api::{LedgerBackend, NewSession};
//!
//! async fn run(ledger: Arc<dyn LedgerBackend>) {
//!     let (session, _key) = ledger
//!         .create_session(NewSession { goal: "audit example.com".into(), ..Default::default() })
//!         .await
//!         .unwrap();
//!     println!("Session {} created", session.id);
//! }
//! ```

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

// ─── Error Types ───────────────────────────────────────────────────────────────

/// Errors that can occur when interacting with the ledger backend.
#[derive(Debug, thiserror::Error)]
pub enum LedgerError {
    #[error("database error: {0}")]
    Database(String),
    #[error("serialization error: {0}")]
    Serialize(String),
    #[error("session goal hash mismatch — possible prompt-injection redirect")]
    GoalMismatch,
    #[error("unverified evidence: {0}")]
    UnverifiedEvidence(String),
    #[error("chain integrity failure at sequence {0}")]
    ChainBroken(i64),
    #[error("backend not supported")]
    Unsupported,
}

// ─── Shared Value Types ─────────────────────────────────────────────────────────

/// Raw payload stored in an event.  Passed through as JSON so the trait stays
/// independent from the concrete `EventPayload` enum defined in the host crate.
pub type RawPayload = serde_json::Value;

/// A single ledger event row as returned from any backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LedgerEvent {
    pub id: i64,
    pub sequence: i64,
    pub previous_hash: String,
    pub content_hash: String,
    pub payload: RawPayload,
    pub created_at: DateTime<Utc>,
}

/// Session record returned from any backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub id: Uuid,
    pub goal: String,
    pub goal_hash: Option<String>,
    pub status: String,
    pub llm_backend: Option<String>,
    pub llm_model: Option<String>,
    pub created_at: DateTime<Utc>,
    pub finished_at: Option<DateTime<Utc>>,
    pub policy_hash: Option<String>,
    pub session_public_key: Option<String>,
    /// W3C Decentralized Identifier associated with this agent session (phase 1: stored as-is).
    pub session_did: Option<String>,
}

/// Parameters for creating a new session.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct NewSession {
    pub goal: String,
    pub llm_backend: String,
    pub llm_model: String,
    pub policy_hash: Option<String>,
    /// Optional DID to associate with this session.
    pub session_did: Option<String>,
}

/// Result of a successful event append.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppendResult {
    pub id: i64,
    pub sequence: i64,
    pub previous_hash: String,
    pub content_hash: String,
    pub created_at: DateTime<Utc>,
}

// ─── Core Trait ────────────────────────────────────────────────────────────────

/// Minimal, cursor-style backend interface for the Ecto Ledger cryptographic ledger.
///
/// All methods are async and return `Result<_, LedgerError>`.  Implementations
/// are expected to be `Send + Sync` so they can be wrapped in `Arc<dyn LedgerBackend>`.
///
/// Phase-1 surface covers the operations required for event appending, session
/// lifecycle, chain verification, and compliance sealing.  Further operations
/// (batch queries, metric snapshots, cross-ledger seals) may be added as new
/// methods with default no-op implementations to preserve backward compatibility.
#[async_trait]
pub trait LedgerBackend: Send + Sync {
    // ── Write path ──────────────────────────────────────────────────────────

    /// Append an arbitrary JSON payload to the chain.
    ///
    /// When `session_id` and `session_goal` are both provided the backend MUST
    /// verify that `session_goal` matches the stored `goal_hash` before writing.
    /// `signing_key_bytes` is the raw 32-byte seed of the session Ed25519 key; when
    /// present the backend signs the `content_hash` and stores the signature.
    async fn append_event(
        &self,
        payload: RawPayload,
        session_id: Option<Uuid>,
        session_goal: Option<&str>,
        signing_key_bytes: Option<&[u8]>,
    ) -> Result<AppendResult, LedgerError>;

    /// Create a new session record.  Returns the session row and the raw 32-byte
    /// Ed25519 signing-key seed so callers can sign subsequent events.
    async fn create_session(&self, params: NewSession) -> Result<(Session, Vec<u8>), LedgerError>;

    /// Seal (finish) a session with the given status string (`"completed"`, `"failed"`, etc.).
    async fn seal_session(&self, session_id: Uuid, status: &str) -> Result<(), LedgerError>;

    // ── Read path ───────────────────────────────────────────────────────────

    /// Return all events belonging to `session_id` in ascending sequence order.
    async fn get_events_by_session(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<LedgerEvent>, LedgerError>;

    /// Return all sessions, newest first.
    async fn list_sessions(&self) -> Result<Vec<Session>, LedgerError>;

    // ── Integrity ───────────────────────────────────────────────────────────

    /// Verify the hash-chain between two sequence numbers (inclusive).
    /// Returns `true` if every link is intact.
    async fn verify_chain(&self, from: i64, to: i64) -> Result<bool, LedgerError>;

    // ── Compliance ──────────────────────────────────────────────────────────

    /// Generate a compliance proof bundle (implementation-defined bytes — may be
    /// a Merkle proof, a signed JSON, a ZK receipt, or a simple digest).
    async fn prove_compliance(&self, session_id: Uuid) -> Result<Vec<u8>, LedgerError>;
}

// ─── Extended Admin Trait ──────────────────────────────────────────────────────

/// Extended administrative interface for ledger backends.
///
/// Covers operational methods beyond the core read/write/integrity surface:
/// event streaming, session maintenance, and initialization.
///
/// Separated from [`LedgerBackend`] so that minimal consumers (agents, tests)
/// need only the core trait, while the server and CLI can require the full
/// administrative surface.
#[async_trait]
pub trait LedgerAdmin: LedgerBackend {
    /// Return the latest event's `(sequence, content_hash)`.
    /// Returns `None` if the chain is empty.
    async fn get_latest(&self) -> Result<Option<(i64, String)>, LedgerError>;

    /// Ensure the genesis event exists, creating it if the chain is empty.
    /// Idempotent — returns the genesis event's metadata on every call.
    async fn ensure_genesis(&self) -> Result<AppendResult, LedgerError>;

    /// Return events with `id > after_id`, optionally filtered to a session.
    /// Results are ordered by `id ASC` and capped at an implementation-defined
    /// batch size (typically 100).  Used for SSE streaming.
    async fn stream_events_since(
        &self,
        after_id: i64,
        session_id: Option<Uuid>,
    ) -> Result<Vec<LedgerEvent>, LedgerError>;

    /// Mark sessions that have been `"running"` for longer than `max_age_minutes`
    /// as `"failed"`.  Returns the number of sessions reaped.
    async fn reap_zombie_sessions(&self, max_age_minutes: i64) -> Result<u64, LedgerError>;

    /// List sessions with optional status filter, pagination via `limit`/`offset`.
    /// Returns sessions in reverse chronological order.
    async fn list_sessions_filtered(
        &self,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Session>, LedgerError>;
}
