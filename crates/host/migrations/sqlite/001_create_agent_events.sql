-- SQLite schema: agent_events
-- Mirrors Postgres migration 20250219000001 + 20250219000005 (session_id column)
CREATE TABLE IF NOT EXISTS agent_events (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    sequence      INTEGER NOT NULL UNIQUE,
    previous_hash TEXT    NOT NULL,
    content_hash  TEXT    NOT NULL,
    payload       TEXT    NOT NULL,          -- JSON stored as text
    created_at    TEXT    NOT NULL DEFAULT (datetime('now')),
    session_id    TEXT                       -- UUID stored as text
);
CREATE INDEX IF NOT EXISTS idx_agent_events_session ON agent_events (session_id);
CREATE INDEX IF NOT EXISTS idx_agent_events_sequence ON agent_events (sequence);
