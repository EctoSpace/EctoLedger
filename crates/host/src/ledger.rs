// ledger — module root.
//
// Sub-backends:
//   ledger::postgres — PostgreSQL (production default)
//   ledger::sqlite   — SQLite (zero-config local dev)
//
// All existing call-sites continue to work via the wildcard re-export of `postgres`.

pub mod postgres;
pub mod sqlite;

// ─── Shared error type ────────────────────────────────────────────────────────
//
// `AppendError` is used by both the Postgres and SQLite backends.  Defining it
// at the module root avoids cross-module coupling (sqlite depending on postgres
// or vice-versa).  Both backends import it via `use super::AppendError;`.

/// Error type returned when appending an event to the ledger fails.
#[derive(Debug, thiserror::Error)]
pub enum AppendError {
    #[error("db: {0}")]
    Db(#[from] sqlx::Error),
    #[error("serialize: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("session goal mismatch (possible redirect)")]
    GoalMismatch,
    #[error("unverified evidence: {0}")]
    UnverifiedEvidence(String),
}

// Re-export the Postgres free-functions so all `crate::ledger::foo` call-sites
// continue to compile without changes.
pub use postgres::{
    PostgresLedger, append_event, create_session, create_session_with_did, ensure_genesis,
    find_cached_http_get, finish_session, get_dangling_actions, get_event_by_id, get_events,
    get_events_by_session, get_latest, get_session_did, list_sessions, list_sessions_filtered,
    mark_action_completed, mark_action_executing, mark_action_failed, store_enclave_attestation,
    verify_chain, verify_findings, verify_goal_hash, verify_session_signatures,
};

// Expose the trait-based backend for DI consumers.
pub use ledger_api::{LedgerAdmin, LedgerBackend};

// (Implementations live in ledger::postgres and ledger::sqlite)
