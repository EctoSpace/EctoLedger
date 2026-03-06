-- Persistent approval state for horizontal-scaling readiness (SQLite variant).

CREATE TABLE IF NOT EXISTS pending_approvals (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT    NOT NULL,
    gate_id     TEXT    NOT NULL,
    action_name TEXT    NOT NULL,
    action_params_summary TEXT NOT NULL DEFAULT '',
    approved    INTEGER,        -- NULL = pending, 1 = approved, 0 = denied
    reason      TEXT,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    decided_at  TEXT,
    UNIQUE (session_id, gate_id)
);

CREATE INDEX IF NOT EXISTS idx_pending_approvals_session_decided
    ON pending_approvals (session_id)
    WHERE approved IS NOT NULL;
