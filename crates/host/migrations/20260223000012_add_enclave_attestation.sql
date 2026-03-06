-- Store enclave attestation evidence on the session so that certificate
-- generation can embed it even when the original agent process has exited.
--
-- The column holds a JSON-serialised `EnclaveAttestation` struct:
--   { "level": "apple_hypervisor", "measurement_hash": "abc...", "raw_attestation": null }

ALTER TABLE agent_sessions
    ADD COLUMN enclave_attestation_json TEXT;
