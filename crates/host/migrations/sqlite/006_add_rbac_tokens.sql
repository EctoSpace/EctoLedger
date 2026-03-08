-- RBAC token table (SQLite).
--
-- Mirrors PostgreSQL migration 20260222000009_add_rbac_tokens.sql.
-- Raw tokens are never stored; only their SHA-256 hex digest is kept so a DB
-- breach does not expose live credentials.
CREATE TABLE IF NOT EXISTS api_tokens (
    token_hash  TEXT PRIMARY KEY,
    role        TEXT NOT NULL CHECK (role IN ('admin', 'auditor', 'agent')),
    label       TEXT,
    created_at  TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at  TEXT
);

CREATE INDEX IF NOT EXISTS api_tokens_role_idx ON api_tokens (role);
