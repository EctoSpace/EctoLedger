-- SQLite schema: agent_snapshots
-- Mirrors Postgres migration 20250219000002
CREATE TABLE IF NOT EXISTS agent_snapshots (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    sequence     INTEGER NOT NULL UNIQUE,
    merkle_root  TEXT    NOT NULL,
    created_at   TEXT    NOT NULL DEFAULT (datetime('now'))
);
