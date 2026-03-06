// Human-in-the-loop approval gates: in-memory state, types, and optional
// database persistence for horizontal-scaling readiness.
//
// The in-memory `ApprovalState` remains the fast path.  When running in
// multi-instance mode the companion `db_*` functions persist decisions to
// the `pending_approvals` table so that an approval submitted on one node
// can be picked up by the agent loop on another.
//
// See docs/SCALING.md § Approval State for the full design.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::RwLock;
use uuid::Uuid;

type DecisionMap = HashMap<(Uuid, String), (bool, Option<String>)>;

#[derive(Clone, Debug, Serialize)]
pub struct PendingApproval {
    pub gate_id: String,
    pub action_name: String,
    pub action_params_summary: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ApprovalDecisionRequest {
    pub gate_id: String,
    pub approved: bool,
    pub reason: Option<String>,
}

pub struct ApprovalState {
    pending: RwLock<HashMap<Uuid, PendingApproval>>,
    decisions: RwLock<DecisionMap>,
}

impl ApprovalState {
    pub fn new() -> Self {
        Self {
            pending: RwLock::new(HashMap::new()),
            decisions: RwLock::new(HashMap::new()),
        }
    }

    pub fn set_pending(&self, session_id: Uuid, approval: PendingApproval) {
        self.pending
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert(session_id, approval);
    }

    pub fn get_pending(&self, session_id: Uuid) -> Option<PendingApproval> {
        self.pending
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .get(&session_id)
            .cloned()
    }

    pub fn record_decision(
        &self,
        session_id: Uuid,
        gate_id: String,
        approved: bool,
        reason: Option<String>,
    ) {
        self.decisions
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .insert((session_id, gate_id), (approved, reason));
        self.pending
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&session_id);
    }

    pub fn take_decision(&self, session_id: Uuid, gate_id: &str) -> Option<(bool, Option<String>)> {
        self.decisions
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&(session_id, gate_id.to_string()))
    }

    /// Remove all pending approvals and decisions for a given session.
    /// Must be called when a session completes, aborts, or fails to prevent
    /// unbounded growth of the in-memory maps.
    pub fn cleanup_session(&self, session_id: Uuid) {
        self.pending
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .remove(&session_id);
        self.decisions
            .write()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|(sid, _), _| *sid != session_id);
    }
}

impl Default for ApprovalState {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Database-backed approval persistence ─────────────────────────────────────
//
// These async functions mirror the in-memory `ApprovalState` methods but
// operate on the `pending_approvals` table.  Call them **in addition to**
// the in-memory path to get write-through persistence; or call them
// **instead of** the in-memory path in a fully DB-backed deployment.

/// Insert a pending approval into the database.
pub async fn db_set_pending(
    pool: &sqlx::PgPool,
    session_id: Uuid,
    approval: &PendingApproval,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO pending_approvals (session_id, gate_id, action_name, action_params_summary, created_at)
         VALUES ($1, $2, $3, $4, $5)
         ON CONFLICT (session_id, gate_id) DO UPDATE
            SET action_name = EXCLUDED.action_name,
                action_params_summary = EXCLUDED.action_params_summary,
                approved = NULL,
                reason = NULL,
                decided_at = NULL",
    )
    .bind(session_id)
    .bind(&approval.gate_id)
    .bind(&approval.action_name)
    .bind(&approval.action_params_summary)
    .bind(approval.created_at)
    .execute(pool)
    .await?;
    Ok(())
}

/// Read the pending approval for a session from the database (if any
/// undecided row exists).
pub async fn db_get_pending(
    pool: &sqlx::PgPool,
    session_id: Uuid,
) -> Result<Option<PendingApproval>, sqlx::Error> {
    let row: Option<(String, String, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT gate_id, action_name, action_params_summary, created_at
         FROM pending_approvals
         WHERE session_id = $1 AND approved IS NULL
         ORDER BY created_at DESC
         LIMIT 1",
    )
    .bind(session_id)
    .fetch_optional(pool)
    .await?;

    Ok(row.map(
        |(gate_id, action_name, action_params_summary, created_at)| PendingApproval {
            gate_id,
            action_name,
            action_params_summary,
            created_at,
        },
    ))
}

/// Record an approval decision in the database.
pub async fn db_record_decision(
    pool: &sqlx::PgPool,
    session_id: Uuid,
    gate_id: &str,
    approved: bool,
    reason: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE pending_approvals
         SET approved = $1, reason = $2, decided_at = NOW()
         WHERE session_id = $3 AND gate_id = $4 AND approved IS NULL",
    )
    .bind(approved)
    .bind(reason)
    .bind(session_id)
    .bind(gate_id)
    .execute(pool)
    .await?;
    Ok(())
}

/// Fetch and consume a decided approval from the database.
/// Returns `Some((approved, reason))` if a decision exists, `None` otherwise.
pub async fn db_take_decision(
    pool: &sqlx::PgPool,
    session_id: Uuid,
    gate_id: &str,
) -> Result<Option<(bool, Option<String>)>, sqlx::Error> {
    // Use a CTE to atomically read + delete in one round trip.
    let row: Option<(bool, Option<String>)> = sqlx::query_as(
        "WITH taken AS (
             DELETE FROM pending_approvals
             WHERE session_id = $1 AND gate_id = $2 AND approved IS NOT NULL
             RETURNING approved, reason
         )
         SELECT approved, reason FROM taken LIMIT 1",
    )
    .bind(session_id)
    .bind(gate_id)
    .fetch_optional(pool)
    .await?;

    Ok(row)
}

/// Remove all approval rows for a session (cleanup on session end).
pub async fn db_cleanup_session(pool: &sqlx::PgPool, session_id: Uuid) -> Result<(), sqlx::Error> {
    sqlx::query("DELETE FROM pending_approvals WHERE session_id = $1")
        .bind(session_id)
        .execute(pool)
        .await?;
    Ok(())
}
