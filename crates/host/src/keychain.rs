//! OS keychain integration for Ed25519 signing-key storage (TM-3g).
//!
//! When the `keychain` feature is enabled, the signing key can be stored in
//! the OS-native credential store instead of an encrypted file on disk:
//!
//! - **macOS**: Keychain Access (via Security framework)
//! - **Windows**: Windows Credential Manager
//! - **Linux**: Secret Service (GNOME Keyring, KWallet)
//!
//! # Usage
//!
//! ```bash
//! cargo build --features keychain
//! ectoledger audit "..." --key-store keychain
//! ```
//!
//! The keychain entry is identified by the service name `ectoledger` and the
//! session UUID as the username. The raw 32-byte Ed25519 private key is stored
//! as a hex-encoded string.
//!
//! # Fallback
//!
//! If the `keychain` feature is not enabled, or if keychain access fails at
//! runtime (e.g., no D-Bus session on headless Linux), the system falls back
//! to the encrypted-file approach (`session-<uuid>.key`).

const SERVICE_NAME: &str = "ectoledger";

/// Error type for keychain operations.
#[derive(Debug, thiserror::Error)]
pub enum KeychainError {
    #[error("keychain backend error: {0}")]
    Backend(String),
    #[error("key not found in keychain for session {0}")]
    NotFound(String),
    #[error("invalid key data in keychain")]
    InvalidData,
}

/// Store a signing key's secret bytes in the OS keychain.
///
/// The key is stored as a hex-encoded string under the service `ectoledger`
/// with the session UUID as the username/account field.
#[cfg(feature = "keychain")]
pub fn store_key(session_id: uuid::Uuid, key_bytes: &[u8; 32]) -> Result<(), KeychainError> {
    let entry = keyring::Entry::new(SERVICE_NAME, &session_id.to_string())
        .map_err(|e| KeychainError::Backend(e.to_string()))?;
    let hex_key = hex::encode(key_bytes);
    entry
        .set_password(&hex_key)
        .map_err(|e| KeychainError::Backend(e.to_string()))?;
    tracing::info!(
        "Signing key stored in OS keychain for session {}",
        session_id
    );
    Ok(())
}

/// Retrieve a signing key's secret bytes from the OS keychain.
#[cfg(feature = "keychain")]
pub fn load_key(session_id: uuid::Uuid) -> Result<[u8; 32], KeychainError> {
    let entry = keyring::Entry::new(SERVICE_NAME, &session_id.to_string())
        .map_err(|e| KeychainError::Backend(e.to_string()))?;
    let hex_key = entry.get_password().map_err(|e| match e {
        keyring::Error::NoEntry => KeychainError::NotFound(session_id.to_string()),
        other => KeychainError::Backend(other.to_string()),
    })?;
    let bytes = hex::decode(&hex_key).map_err(|_| KeychainError::InvalidData)?;
    let arr: [u8; 32] = bytes.try_into().map_err(|_| KeychainError::InvalidData)?;
    Ok(arr)
}

/// Delete a signing key from the OS keychain.
#[cfg(feature = "keychain")]
pub fn delete_key(session_id: uuid::Uuid) -> Result<(), KeychainError> {
    let entry = keyring::Entry::new(SERVICE_NAME, &session_id.to_string())
        .map_err(|e| KeychainError::Backend(e.to_string()))?;
    entry
        .delete_credential()
        .map_err(|e| KeychainError::Backend(e.to_string()))?;
    tracing::info!(
        "Signing key removed from OS keychain for session {}",
        session_id
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    fn service_name_is_stable() {
        // This test is cross-platform and ensures the service name
        // doesn't accidentally change, which would orphan stored keys.
        assert_eq!(SERVICE_NAME, "ectoledger");
    }
}
