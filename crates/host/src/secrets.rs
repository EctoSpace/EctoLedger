//! Secure memory management for sensitive values (API keys, private keys, tokens).
//!
//! Uses the `zeroize` crate to ensure that secret material is overwritten in memory
//! when it goes out of scope.  Wraps raw `String` values in a newtype that implements
//! `Drop` with zeroization, preventing secrets from lingering on the heap after use.
//!
//! # Design
//!
//! - **`SecretString`**: A `String` wrapper that zeroizes on drop.  Callers must
//!   explicitly call `.expose_secret()` to access the inner value, making secret
//!   usage grep-able and auditable.
//! - **`load_env_secret`**: Reads an environment variable into a `SecretString` and
//!   then **removes** the variable from the process environment to prevent
//!   `/proc/<pid>/environ` scraping on Linux.
//!
//! # Usage
//!
//! ```no_run
//! use ectoledger::secrets::load_env_secret;
//!
//! if let Some(key) = load_env_secret("EVM_PRIVATE_KEY") {
//!     // key is automatically zeroized when dropped
//!     let raw = key.expose_secret();
//!     // ... use the key ...
//! }
//! ```

use zeroize::Zeroize;

/// A string that is zeroized (overwritten with zeros) when dropped.
///
/// This prevents sensitive values like private keys and API tokens from
/// lingering in process memory after they are no longer needed.
#[derive(Clone)]
pub struct SecretString {
    inner: String,
}

impl SecretString {
    /// Wrap an existing `String` in a `SecretString`.
    ///
    /// The caller should avoid retaining the original `String` after this call.
    pub fn new(value: String) -> Self {
        Self { inner: value }
    }

    /// Temporarily expose the secret value for use.
    ///
    /// This method is intentionally named to make secret access grep-able
    /// and auditable in code review.
    #[inline]
    pub fn expose_secret(&self) -> &str {
        &self.inner
    }
}

impl Drop for SecretString {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

impl std::fmt::Debug for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

impl std::fmt::Display for SecretString {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("[REDACTED]")
    }
}

/// Load a secret from an environment variable and remove it from the process environment.
///
/// This two-step approach:
/// 1. Reads the value into a zeroize-on-drop `SecretString`
/// 2. Removes the variable from `std::env` so it cannot be scraped via
///    `/proc/<pid>/environ` (Linux) or `Get-Process` (Windows)
///
/// Returns `None` if the variable is not set.
pub fn load_env_secret(var_name: &str) -> Option<SecretString> {
    match std::env::var(var_name) {
        Ok(val) => {
            // Remove from process environment to prevent /proc/<pid>/environ scraping.
            // SAFETY: We are the only reader at this point during startup; the value
            // is captured in `val`. No other threads are reading this variable concurrently.
            unsafe { std::env::remove_var(var_name) };
            tracing::debug!(
                "Secret '{}' loaded and removed from process environment.",
                var_name
            );
            Some(SecretString::new(val))
        }
        Err(_) => None,
    }
}

/// Load a secret from an environment variable **without** removing it.
///
/// Use this for secrets that must remain in the environment for child processes
/// (e.g., cloud CLI credentials that are injected into child process env).
pub fn load_env_secret_persistent(var_name: &str) -> Option<SecretString> {
    std::env::var(var_name).ok().map(SecretString::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn secret_string_redacts_display() {
        let s = SecretString::new("hunter2".to_string());
        assert_eq!(format!("{}", s), "[REDACTED]");
        assert_eq!(format!("{:?}", s), "[REDACTED]");
    }

    #[test]
    fn expose_secret_returns_inner() {
        let s = SecretString::new("hunter2".to_string());
        assert_eq!(s.expose_secret(), "hunter2");
    }

    #[test]
    fn load_env_secret_removes_var() {
        // SAFETY: Test runs serially; no other thread reads this test-only variable.
        unsafe { std::env::set_var("_TEST_SECRET_REMOVE", "secret_value") };
        let s = load_env_secret("_TEST_SECRET_REMOVE");
        assert!(s.is_some());
        assert_eq!(s.unwrap().expose_secret(), "secret_value");
        assert!(std::env::var("_TEST_SECRET_REMOVE").is_err());
    }

    #[test]
    fn load_env_secret_missing_returns_none() {
        let s = load_env_secret("_NONEXISTENT_SECRET_VAR_12345");
        assert!(s.is_none());
    }
}
