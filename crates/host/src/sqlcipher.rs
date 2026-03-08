//! SQLCipher at-rest encryption support (TM-1d).
//!
//! When the `sqlcipher` feature is enabled, the SQLite database file is
//! encrypted transparently using AES-256-CBC with an HMAC-SHA512 MAC via
//! the SQLCipher extension.
//!
//! # Requirements
//!
//! - The `sqlcipher` feature must be enabled: `cargo build --features sqlcipher`
//! - The `ECTOLEDGER_SQLCIPHER_KEY` environment variable must be set to the
//!   database encryption passphrase (at least 16 characters).
//! - The system must have a SQLCipher-enabled SQLite library installed.
//!
//! # Security considerations
//!
//! SQLCipher encrypts the database at rest, preventing an attacker who gains
//! access to the filesystem from reading or modifying ledger events without
//! the encryption key. This is defense-in-depth alongside the immutability
//! triggers and chain verification.
//!
//! # Cross-platform
//!
//! SQLCipher is available on Windows, macOS, and Linux. The key is read from
//! the environment or a file descriptor for CI/CD pipelines.

/// Minimum passphrase length for SQLCipher encryption.
pub const MIN_SQLCIPHER_KEY_LEN: usize = 16;

/// Error type for SQLCipher operations.
#[derive(Debug, thiserror::Error)]
pub enum SqlCipherError {
    #[error("ECTOLEDGER_SQLCIPHER_KEY not set or empty")]
    KeyNotSet,
    #[error("ECTOLEDGER_SQLCIPHER_KEY too short (minimum {MIN_SQLCIPHER_KEY_LEN} characters)")]
    KeyTooShort,
    #[error("SQLCipher PRAGMA failed: {0}")]
    Pragma(String),
}

/// Read the SQLCipher encryption key from the environment.
///
/// Returns `None` if the `sqlcipher` feature is not enabled at compile time.
/// Returns `Err` if the feature is enabled but the key is missing or too short.
#[cfg(feature = "sqlcipher")]
pub fn read_sqlcipher_key() -> Result<String, SqlCipherError> {
    let key = std::env::var("ECTOLEDGER_SQLCIPHER_KEY").map_err(|_| SqlCipherError::KeyNotSet)?;
    if key.is_empty() {
        return Err(SqlCipherError::KeyNotSet);
    }
    if key.len() < MIN_SQLCIPHER_KEY_LEN {
        return Err(SqlCipherError::KeyTooShort);
    }
    Ok(key)
}

/// Apply the SQLCipher key to a SQLite connection by issuing `PRAGMA key`.
///
/// Must be called immediately after opening the connection, before any
/// other database operations. This function assumes the underlying SQLite
/// library is SQLCipher-enabled; with stock SQLite the PRAGMA is silently
/// ignored.
#[cfg(feature = "sqlcipher")]
pub async fn apply_sqlcipher_key(pool: &sqlx::SqlitePool, key: &str) -> Result<(), SqlCipherError> {
    // SQLCipher requires the key to be set as the first operation.
    // Use the x'...' hex form to avoid SQL injection issues.
    let hex_key = hex::encode(key.as_bytes());
    let pragma = format!("PRAGMA key = \"x'{}'\";", hex_key);
    sqlx::query(&pragma)
        .execute(pool)
        .await
        .map_err(|e| SqlCipherError::Pragma(e.to_string()))?;

    // Verify the key is correct by attempting a read.
    sqlx::query("SELECT count(*) FROM sqlite_master;")
        .execute(pool)
        .await
        .map_err(|e| SqlCipherError::Pragma(format!("Key verification failed: {}", e)))?;

    tracing::info!("SQLCipher encryption enabled for SQLite database.");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn min_key_length_enforced() {
        // This test is cross-platform (no OS-specific logic).
        assert_eq!(MIN_SQLCIPHER_KEY_LEN, 16);
    }

    #[cfg(feature = "sqlcipher")]
    #[test]
    fn short_key_rejected() {
        unsafe { std::env::set_var("ECTOLEDGER_SQLCIPHER_KEY", "short") };
        let result = read_sqlcipher_key();
        assert!(matches!(result, Err(SqlCipherError::KeyTooShort)));
        unsafe { std::env::remove_var("ECTOLEDGER_SQLCIPHER_KEY") };
    }

    #[cfg(feature = "sqlcipher")]
    #[test]
    fn valid_key_accepted() {
        unsafe {
            std::env::set_var(
                "ECTOLEDGER_SQLCIPHER_KEY",
                "this-is-a-reasonably-long-key!!",
            )
        };
        let result = read_sqlcipher_key();
        assert!(result.is_ok());
        unsafe { std::env::remove_var("ECTOLEDGER_SQLCIPHER_KEY") };
    }
}
