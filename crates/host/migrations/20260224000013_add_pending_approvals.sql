-- Persistent approval state for horizontal-scaling readiness.
-- Replaces (or supplements) the in-memory ApprovalState when running
-- multiple EctoLedger instances behind a load balancer.
--
-- See docs/SCALING.md for the full rationale.

CREATE TABLE IF NOT EXISTS pending_approvals (
    id          BIGSERIAL PRIMARY KEY,
    session_id  UUID        NOT NULL,
    gate_id     TEXT        NOT NULL,
    action_name TEXT        NOT NULL,
    action_params_summary TEXT NOT NULL DEFAULT '',
    -- NULL = pending, TRUE = approved, FALSE = denied
    approved    BOOLEAN,
    reason      TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    decided_at  TIMESTAMPTZ,
    -- Prevent duplicate pending records for the same gate in the same session.
    CONSTRAINT uq_pending_session_gate UNIQUE (session_id, gate_id)
);

-- Index for the agent-side poll: "any decided approvals for my session?"
CREATE INDEX IF NOT EXISTS idx_pending_approvals_session_decided
    ON pending_approvals (session_id)
    WHERE approved IS NOT NULL;
