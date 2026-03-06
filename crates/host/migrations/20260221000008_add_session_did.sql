-- Add DID support to agent sessions (enterprise-2026 / raptor-test)
-- session_did stores an optional W3C Decentralized Identifier for the agent.
-- Phase 1: stored as a plain string (did:key:, did:web:, etc.)
-- Phase 2: full SSI resolution + Verifiable Credential support planned.

ALTER TABLE agent_sessions ADD COLUMN IF NOT EXISTS session_did TEXT;
