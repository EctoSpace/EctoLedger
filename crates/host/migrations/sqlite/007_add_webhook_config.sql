-- Dynamic webhook / SIEM target configuration (SQLite).
--
-- Mirrors PostgreSQL migration 20260222000010_add_webhook_config.sql.
-- Replaces static env-var webhook configuration with a database-backed store
-- so targets can be managed at runtime via the API without a restart.
CREATE TABLE IF NOT EXISTS webhooks (
    id           TEXT PRIMARY KEY DEFAULT (lower(hex(randomblob(4)) || '-' || hex(randomblob(2)) || '-4' || substr(hex(randomblob(2)),2) || '-' || substr('89ab', abs(random()) % 4 + 1, 1) || substr(hex(randomblob(2)),2) || '-' || hex(randomblob(6)))),
    label        TEXT NOT NULL,
    url          TEXT NOT NULL,
    bearer_token TEXT,
    siem_format  TEXT NOT NULL DEFAULT 'json'
                      CHECK (siem_format IN ('json', 'cef', 'leef')),
    -- Comma-separated list of EgressKind strings (SQLite has no array type)
    filter_kinds TEXT NOT NULL DEFAULT 'observation,guard_denial,tripwire_rejection',
    enabled      INTEGER NOT NULL DEFAULT 1,
    created_at   TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at   TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS webhooks_enabled_idx ON webhooks (enabled);
