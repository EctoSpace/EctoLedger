-- Dynamic webhook / SIEM target configuration.
--
-- Replaces static env-var webhook configuration with a database-backed store
-- so targets can be managed at runtime via the API without a restart.
-- The legacy WEBHOOK_URL env var remains supported as a fallback / bootstrap
-- mechanism handled in webhook.rs.
CREATE TABLE IF NOT EXISTS webhooks (
    id           UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    label        TEXT         NOT NULL,
    url          TEXT         NOT NULL,
    bearer_token TEXT,
    siem_format  VARCHAR(8)   NOT NULL DEFAULT 'json'
                              CHECK (siem_format IN ('json', 'cef', 'leef')),
    -- Array of EgressKind strings: observation, guard_denial, tripwire_rejection
    filter_kinds TEXT[]       NOT NULL DEFAULT '{observation,guard_denial,tripwire_rejection}',
    enabled      BOOLEAN      NOT NULL DEFAULT true,
    created_at   TIMESTAMPTZ  NOT NULL DEFAULT now(),
    updated_at   TIMESTAMPTZ  NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS webhooks_enabled_idx ON webhooks (enabled);
