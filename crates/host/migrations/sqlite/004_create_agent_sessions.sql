-- SQLite schema: agent_sessions + DID support
-- Combines Postgres migrations 004 + 006 + 007 + 008
CREATE TABLE IF NOT EXISTS agent_sessions (
    id                 TEXT    PRIMARY KEY,             -- UUID as text
    goal               TEXT    NOT NULL,
    goal_hash          TEXT,
    status             TEXT    NOT NULL DEFAULT 'running',
    llm_backend        TEXT,
    llm_model          TEXT,
    created_at         TEXT    NOT NULL DEFAULT (datetime('now')),
    finished_at        TEXT,
    policy_hash        TEXT,
    session_public_key TEXT,
    session_did        TEXT                             -- W3C DID (phase 1: plain string)
);
CREATE INDEX IF NOT EXISTS idx_sessions_status ON agent_sessions (status);

-- Event signatures table (migration 007 equivalent)
CREATE TABLE IF NOT EXISTS agent_event_signatures (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id     INTEGER NOT NULL REFERENCES agent_events(id),
    content_hash TEXT    NOT NULL,
    signature    TEXT    NOT NULL,
    public_key   TEXT    NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_event_sigs_event ON agent_event_signatures (event_id);
