-- SQLite schema: agent_action_log
-- Mirrors Postgres migration 20250219000003
CREATE TABLE IF NOT EXISTS agent_action_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id    INTEGER NOT NULL REFERENCES agent_events(id),
    status      TEXT    NOT NULL DEFAULT 'pending',
    started_at  TEXT    NOT NULL DEFAULT (datetime('now')),
    finished_at TEXT,
    error_msg   TEXT
);
CREATE INDEX IF NOT EXISTS idx_action_log_event ON agent_action_log (event_id);
CREATE INDEX IF NOT EXISTS idx_action_log_status ON agent_action_log (status);
