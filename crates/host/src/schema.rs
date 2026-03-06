use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use uuid::Uuid;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Running,
    Completed,
    Failed,
    Aborted,
}

impl SessionStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            SessionStatus::Running => "running",
            SessionStatus::Completed => "completed",
            SessionStatus::Failed => "failed",
            SessionStatus::Aborted => "aborted",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuditFinding {
    pub severity: FindingSeverity,
    pub title: String,
    pub evidence: String,
    pub recommendation: String,
    /// Ledger sequence numbers that support this finding. Required for high/critical.
    #[serde(default)]
    pub evidence_sequence: Vec<i64>,
    /// Exact substrings from those observations that support the evidence.
    #[serde(default)]
    pub evidence_quotes: Vec<String>,
}

#[derive(Clone, Debug, Serialize, FromRow)]
pub struct SessionRow {
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
    pub session_did: Option<String>,
    /// JSON-serialised `EnclaveAttestation` captured during the session, if any.
    pub enclave_attestation_json: Option<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EventPayload {
    Genesis {
        message: String,
        /// Random hex nonce ensuring each ledger's genesis event is unique (TM-2c).
        #[serde(default, skip_serializing_if = "Option::is_none")]
        nonce: Option<String>,
        /// Hex-encoded Ed25519 verifying key of the session that owns this ledger (TM-2c).
        /// Binds the genesis event to a specific signing key so it cannot be replayed
        /// into a different session with a different key.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        session_public_key: Option<String>,
    },
    /// The user's original prompt / audit goal.
    PromptInput {
        content: String,
    },
    Thought {
        content: String,
    },
    /// Schema validation error (e.g. missing justification).
    SchemaError {
        message: String,
        attempt: u32,
        max_attempts: u32,
    },
    /// Circuit breaker tripped: too many consecutive errors of the same kind.
    CircuitBreaker {
        reason: String,
        consecutive_failures: u32,
    },
    Action {
        name: String,
        params: serde_json::Value,
    },
    Observation {
        content: String,
    },
    /// Human-in-the-loop: approval requested for an action.
    ApprovalRequired {
        gate_id: String,
        action_name: String,
        action_params_summary: String,
    },
    /// Human-in-the-loop: decision recorded.
    ApprovalDecision {
        gate_id: String,
        approved: bool,
        reason: Option<String>,
    },
    /// Multi-agent: cross-ledger seal committing all sub-agent ledger tips.
    CrossLedgerSeal {
        seal_hash: String,
        session_ids: Vec<Uuid>,
        session_tip_hashes: Vec<String>,
    },
    /// OpenTimestamps anchor: the ledger tip was submitted to the Bitcoin timechain.
    Anchor {
        ledger_tip_hash: String,
        ots_proof_hex: String,
        /// Filled once the OTS stamp is confirmed on the blockchain.
        bitcoin_block_height: Option<u64>,
    },
    /// Automatic signing-key rotation: a new Ed25519 keypair has been generated.
    /// All events after this one are signed with `new_public_key`.
    /// Verifiers should use this event to determine which public key covers each
    /// segment of the audit trail (events before this rotation vs. after).
    KeyRotation {
        /// Hex-encoded Ed25519 public key that will be used from this point onward.
        new_public_key: String,
        /// Monotonically increasing rotation counter (1 = first rotation, 2 = second, …).
        rotation_index: u64,
    },
    /// Explicit revocation of an Ed25519 signing key (TM-3f).
    /// Once recorded, verifiers MUST reject any event signed by the revoked
    /// key that has a sequence number greater than this event's sequence.
    KeyRevocation {
        /// Hex-encoded Ed25519 public key being revoked.
        revoked_public_key: String,
        /// Human-readable reason for revocation (e.g. "key compromise", "rotation").
        reason: String,
    },
    /// W3C Verifiable Credential JWT issued when the session completes.
    /// The JWT is signed with the session Ed25519 key (EdDSA) and encodes goal,
    /// policy hash, DID, session ID, and completion timestamp.
    VerifiableCredential {
        /// The full JWT string: `header.payload.signature` (or `header.payload.` when unsigned).
        vc_jwt: String,
    },
    /// Direct LLM chat message (no agent loop). Logged so the observer can
    /// display user↔LLM interactions in real-time.
    ChatMessage {
        role: String,
        content: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        backend: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        model: Option<String>,
    },
}

#[derive(Clone, Debug)]
pub struct LedgerEventRow {
    pub id: i64,
    pub sequence: i64,
    pub previous_hash: String,
    pub content_hash: String,
    pub payload: EventPayload,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct AppendedEvent {
    pub id: i64,
    pub sequence: i64,
    pub previous_hash: String,
    pub content_hash: String,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct SnapshotRow {
    pub id: Uuid,
    pub sequence: i64,
    pub state_hash: String,
    pub payload: serde_json::Value,
    pub created_at: DateTime<Utc>,
}

#[derive(Clone, Debug)]
pub struct RestoredState {
    pub snapshot_sequence: i64,
    pub snapshot_payload: serde_json::Value,
    pub replayed_events: Vec<LedgerEventRow>,
}
