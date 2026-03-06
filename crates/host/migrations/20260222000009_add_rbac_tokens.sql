-- RBAC token table.
--
-- Raw tokens are never stored; only their SHA-256 hex digest is kept so a DB
-- breach does not expose live credentials.  The seeding of the legacy
-- OBSERVER_TOKEN as an admin entry is performed by the binary at startup.
CREATE TABLE IF NOT EXISTS api_tokens (
    token_hash  VARCHAR(64)  PRIMARY KEY,
    role        VARCHAR(16)  NOT NULL CHECK (role IN ('admin', 'auditor', 'agent')),
    label       TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT now(),
    expires_at  TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS api_tokens_role_idx ON api_tokens (role);
