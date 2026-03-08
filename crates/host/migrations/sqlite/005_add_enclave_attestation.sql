-- SQLite: store enclave attestation evidence on the session.
ALTER TABLE agent_sessions ADD COLUMN enclave_attestation_json TEXT;
