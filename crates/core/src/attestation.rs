//! LLM Inference Attestation Interface
//!
//! This module defines the `LlmAttestationBackend` trait — an abstraction over
//! mechanisms that can cryptographically prove that a specific LLM produced a
//! specific response to a specific prompt.
//!
//! # Current implementations
//!
//! - [`NoopAttestation`]: passes through without generating any proof.  Used by
//!   default so the cognitive loop operates normally with zero overhead.
//!
//! - `Sp1ZkAttestation` (feature-gated via `--features zk` in the host crate):
//!   extends the existing SP1 ledger-chain proof to also commit to a
//!   SHA-256(prompt ++ response) value inside the guest program, making the
//!   entire inference step verifiable.
//!
//! # Future implementations
//!
//! - `NitroEnclaveAttestation`: runs inference inside an AWS Nitro Enclave and
//!   returns the AWS PCR-signed attestation document as the proof.
//!
//! - `TdxAttestation`: Intel TDX / AMD SEV-SNP equivalent for on-prem TEE
//!   deployments.
//!
//! Plugging in a new backend requires only implementing this trait and passing
//! the concrete type inside `AgentLoopConfig::attestation` (see the host crate).

// ── Proof and error types ─────────────────────────────────────────────────────

/// An opaque attestation proof that a specific LLM produced a specific response.
///
/// The proof is backend-specific; callers should treat it as an opaque blob and
/// pass it to the same backend's `verify` method for local verification, or
/// forward it to an external verifier.
#[derive(Debug, Clone)]
pub struct AttestationProof {
    /// The backend that produced this proof (e.g. `"noop"`, `"sp1_zk"`, `"nitro"`).
    pub backend: String,
    /// SHA-256(prompt || response) — the preimage commitment that the proof covers.
    pub inference_hash: String,
    /// Raw proof bytes (empty for `NoopAttestation`).
    pub proof_bytes: Vec<u8>,
}

/// Errors that can occur during attestation or verification.
#[derive(Debug, thiserror::Error)]
pub enum AttestationError {
    /// The backend is not compiled in (feature-gated).
    #[error("attestation not available: {0}")]
    NotAvailable(&'static str),
    /// Proof generation failed.
    #[error("prover error: {0}")]
    Prover(String),
    /// Proof verification failed.
    #[error("verification error: {0}")]
    Verification(String),
}

// ── Trait ─────────────────────────────────────────────────────────────────────

/// A backend that can attest that a given LLM produced a given response.
///
/// Implementations should be cheap to clone and send across thread boundaries.
/// The `attest` method is called once per cognitive-loop step.
pub trait LlmAttestationBackend: Send + Sync {
    /// Generate a proof that `response` was produced by the model for `prompt`.
    ///
    /// `step` and `session_id` are informational — they can be embedded in the
    /// proof to bind it to a specific ledger position.
    fn attest(
        &self,
        prompt: &str,
        response: &str,
        step: u32,
        session_id: &str,
    ) -> Result<AttestationProof, AttestationError>;

    /// Verify a proof previously produced by `attest`.
    fn verify(&self, proof: &AttestationProof) -> Result<bool, AttestationError>;

    /// Human-readable name of this backend (used in log output and ledger events).
    fn name(&self) -> &'static str;
}

// ── NoopAttestation ───────────────────────────────────────────────────────────

/// Default pass-through implementation.  Produces an empty proof and always
/// verifies as `true`.  Zero overhead; safe to use in production when full
/// inference attestation is not required.
#[derive(Debug, Clone, Default)]
pub struct NoopAttestation;

impl LlmAttestationBackend for NoopAttestation {
    fn attest(
        &self,
        prompt: &str,
        response: &str,
        _step: u32,
        _session_id: &str,
    ) -> Result<AttestationProof, AttestationError> {
        // Compute the inference hash even in the noop case; it is stored in the
        // proof struct so that callers can record it in the ledger without having
        // to hash the prompt/response themselves.
        let inference_hash = crate::hash::sha256_pair(prompt.as_bytes(), response.as_bytes());
        Ok(AttestationProof {
            backend: self.name().to_string(),
            inference_hash,
            proof_bytes: vec![],
        })
    }

    fn verify(&self, proof: &AttestationProof) -> Result<bool, AttestationError> {
        // Ensure the proof was actually produced by the noop backend.
        // Prevents a downgrade attack where a proof claiming "sp1_zk" or "nitro"
        // is silently accepted if the verifier has been switched to noop.
        if proof.backend != self.name() {
            return Err(AttestationError::Verification(format!(
                "proof backend '{}' does not match verifier '{}'",
                proof.backend,
                self.name()
            )));
        }
        Ok(true)
    }

    fn name(&self) -> &'static str {
        "noop"
    }
}

// ── Sp1ZkAttestation stub ─────────────────────────────────────────────────────

/// Zero-knowledge attestation using the SP1 RISC-V prover.
///
/// This type is compiled only when the host crate is built with `--features zk`.
/// The full implementation lives in `crates/host/src/attestation_zk.rs` so the
/// SP1 SDK (a large optional dependency) is not pulled into `ectoledger_core`.
///
/// The guest program commits to:
///   - The full event hash chain (existing behaviour, carried over from `prove-audit`)
///   - SHA-256(prompt || response) for each cognitive-loop step
///
/// This makes the entire reasoning trace — "the LLM received X and produced Y,
/// which caused ledger event Z" — mathematically provable without revealing the
/// raw prompt or response.
#[derive(Debug, Clone, Default)]
pub struct Sp1ZkAttestationStub;

impl LlmAttestationBackend for Sp1ZkAttestationStub {
    fn attest(
        &self,
        _prompt: &str,
        _response: &str,
        _step: u32,
        _session_id: &str,
    ) -> Result<AttestationProof, AttestationError> {
        Err(AttestationError::NotAvailable(
            "SP1 ZK inference attestation is not compiled in. \
             Rebuild with: cargo build --features zk\n\
             Requires the SP1 toolchain: https://docs.succinct.xyz/docs/getting-started/install\n\
             Note: SP1 proving is supported on x86_64 Linux and macOS; \
             ARM / Windows hosts should use the Succinct Network prover (SP1_PROVER=network).",
        ))
    }

    fn verify(&self, _proof: &AttestationProof) -> Result<bool, AttestationError> {
        Err(AttestationError::NotAvailable(
            "SP1 ZK inference attestation is not compiled in. \
             Rebuild with: cargo build --features zk\n\
             Requires the SP1 toolchain: https://docs.succinct.xyz/docs/getting-started/install",
        ))
    }

    fn name(&self) -> &'static str {
        "sp1_zk"
    }
}
