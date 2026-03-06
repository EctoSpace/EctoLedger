// Host-side policy module.
//
// All pure evaluation types and the PolicyEngine are defined in `ectoledger_core::policy`
// and re-exported here so that existing `use crate::policy::*` imports resolve unchanged.
//
// This module adds the TOML file-loading layer (`PolicyLoadError`, `load_policy_engine`)
// which requires std file I/O and is therefore kept out of the no-I/O-dependency core crate.

pub use ectoledger_core::policy::*;

use sha2::{Digest, Sha256};
use std::path::Path;

// ── Load error (host-only) ─────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum PolicyLoadError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("invalid regex in policy: {0}")]
    InvalidRegex(String),
    #[error("policy integrity check failed: expected hash {expected}, got {actual}")]
    IntegrityCheckFailed { expected: String, actual: String },
}

// ── File loader (host-only) ────────────────────────────────────────────────────

/// Parse an `AuditPolicy` from a TOML file and wrap it in a `PolicyEngine`.
///
/// The `PolicyEngine` itself lives in `ectoledger_core` (no file I/O).
/// This free function is the host-side entry point for loading policies from disk.
pub fn load_policy_engine(path: &Path) -> Result<PolicyEngine, PolicyLoadError> {
    load_policy_engine_with_integrity(path, None)
}

/// Parse an `AuditPolicy` from a TOML file, optionally verifying its SHA-256
/// hash against `expected_hash` before trusting the content (TM-5 hardening).
///
/// When `expected_hash` is `Some`, the raw file content is hashed and compared
/// to the expected value. A mismatch indicates policy file tampering and the
/// function returns `PolicyLoadError::IntegrityCheckFailed`.
///
/// Returns the `PolicyEngine` and the computed SHA-256 hash of the file (hex).
pub fn load_policy_engine_with_integrity(
    path: &Path,
    expected_hash: Option<&str>,
) -> Result<PolicyEngine, PolicyLoadError> {
    let s = std::fs::read_to_string(path).map_err(PolicyLoadError::Io)?;

    // Compute the SHA-256 hash of the raw policy file for integrity verification.
    let actual_hash = hex::encode(Sha256::digest(s.as_bytes()));

    if let Some(expected) = expected_hash
        && !constant_time_eq(expected.as_bytes(), actual_hash.as_bytes())
    {
        return Err(PolicyLoadError::IntegrityCheckFailed {
            expected: expected.to_string(),
            actual: actual_hash,
        });
    }

    let policy: AuditPolicy = toml::from_str(&s).map_err(PolicyLoadError::Toml)?;
    PolicyEngine::new(policy).map_err(|e| PolicyLoadError::InvalidRegex(e.0))
}

/// Compute the SHA-256 hash of a policy file without loading it as a
/// `PolicyEngine`. Useful for storing the expected hash at deployment time.
pub fn compute_policy_hash(path: &Path) -> Result<String, std::io::Error> {
    let s = std::fs::read_to_string(path)?;
    Ok(hex::encode(Sha256::digest(s.as_bytes())))
}

/// Constant-time byte comparison (prevents timing side-channels on hash checks).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}
