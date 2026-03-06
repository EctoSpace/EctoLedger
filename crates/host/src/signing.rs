// Ed25519 signing of event content hashes for tamper-proof verification.
// Key persistence: the signing key is encrypted with AES-256-GCM using a key
// derived from a user-supplied password via Argon2id. The ciphertext is stored at
// <data_dir>/session-<session_id>.key so that a crash does not invalidate the
// cryptographic audit trail of an ongoing session.

use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng as AeadOsRng, Payload},
};
use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use uuid::Uuid;

pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

pub fn sign_content_hash(signing_key: &SigningKey, content_hash: &str) -> String {
    let sig = signing_key.sign(content_hash.as_bytes());
    hex::encode(sig.to_bytes())
}

pub fn verify_signature(
    public_key_hex: &str,
    content_hash: &str,
    signature_hex: &str,
) -> Result<(), SigningError> {
    let pk_bytes = hex::decode(public_key_hex).map_err(|_| SigningError::InvalidHex)?;
    let vk = VerifyingKey::from_bytes(
        pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SigningError::InvalidKey)?,
    )
    .map_err(|_| SigningError::InvalidKey)?;
    let sig_bytes = hex::decode(signature_hex).map_err(|_| SigningError::InvalidHex)?;
    let sig = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SigningError::InvalidSignature)?,
    );
    vk.verify(content_hash.as_bytes(), &sig)
        .map_err(|_| SigningError::VerificationFailed)
}

pub fn public_key_hex(verifying_key: &VerifyingKey) -> String {
    hex::encode(verifying_key.as_bytes())
}

/// Verify that `signature_hex` (hex-encoded Ed25519 signature) is a valid
/// signature of `content_hash` under `verifying_key`.
///
/// Returns `true` when verification succeeds, `false` on any decode or
/// cryptographic failure.
pub fn verify_content_hash(
    verifying_key: &VerifyingKey,
    content_hash: &str,
    signature_hex: &str,
) -> bool {
    let sig_bytes = match hex::decode(signature_hex) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let sig = match <[u8; 64]>::try_from(sig_bytes.as_slice()) {
        Ok(arr) => Signature::from_bytes(&arr),
        Err(_) => return false,
    };
    verifying_key.verify(content_hash.as_bytes(), &sig).is_ok()
}

// ── Encrypted key file ────────────────────────────────────────────────────────

/// On-disk representation of a password-encrypted Ed25519 signing key.
#[derive(Serialize, Deserialize)]
pub struct EncryptedKeyFile {
    /// Argon2id salt (base64-encoded, stored in the file for self-containment).
    pub salt: String,
    /// AES-256-GCM nonce, hex-encoded.
    pub nonce_hex: String,
    /// AES-256-GCM ciphertext (32-byte key), hex-encoded.
    pub ciphertext_hex: String,
    /// Session UUID this key belongs to.
    pub session_id: String,
}

/// Derive a 32-byte AES key from `password` and a 16-byte `salt` using Argon2id.
fn derive_key(password: &str, salt_str: &SaltString) -> Result<[u8; 32], SigningError> {
    let argon2 = Argon2::default();
    let hash = argon2
        .hash_password(password.as_bytes(), salt_str)
        .map_err(|e| SigningError::Kdf(e.to_string()))?;
    let hash_output = hash
        .hash
        .ok_or_else(|| SigningError::Kdf("no hash output".to_string()))?;
    let bytes = hash_output.as_bytes();
    if bytes.len() < 32 {
        return Err(SigningError::Kdf("hash output too short".to_string()));
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes[..32]);
    Ok(key)
}

/// Encrypt a `SigningKey` with `password` using Argon2id KDF + AES-256-GCM.
///
/// The `session_id` is bound as Additional Authenticated Data (AAD) so that
/// the JSON wrapper's `session_id` field cannot be swapped without failing
/// decryption (TM-3 hardening).
pub fn encrypt_signing_key(
    session_id: Uuid,
    key: &SigningKey,
    password: &str,
) -> Result<EncryptedKeyFile, SigningError> {
    let salt = SaltString::generate(&mut OsRng);
    let aes_key_bytes = derive_key(password, &salt)?;
    let aes_key = {
        #[allow(deprecated)]
        Key::<Aes256Gcm>::from_slice(&aes_key_bytes)
    };
    let cipher = Aes256Gcm::new(aes_key);
    let nonce = Aes256Gcm::generate_nonce(&mut AeadOsRng);
    let sid_str = session_id.to_string();
    let ciphertext = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: key.as_bytes().as_ref(),
                aad: sid_str.as_bytes(),
            },
        )
        .map_err(|e| SigningError::Encrypt(e.to_string()))?;
    Ok(EncryptedKeyFile {
        salt: salt.to_string(),
        nonce_hex: hex::encode(nonce),
        ciphertext_hex: hex::encode(ciphertext),
        session_id: sid_str,
    })
}

/// Decrypt an `EncryptedKeyFile` with `password` to recover the `SigningKey`.
///
/// The stored `session_id` is verified as GCM Additional Authenticated Data;
/// decryption fails if the wrapper metadata has been tampered with (TM-3).
pub fn decrypt_signing_key(
    enc: &EncryptedKeyFile,
    password: &str,
) -> Result<SigningKey, SigningError> {
    let salt = SaltString::from_b64(&enc.salt).map_err(|e| SigningError::Kdf(e.to_string()))?;
    let aes_key_bytes = derive_key(password, &salt)?;
    let aes_key = {
        #[allow(deprecated)]
        Key::<Aes256Gcm>::from_slice(&aes_key_bytes)
    };
    let cipher = Aes256Gcm::new(aes_key);
    let nonce_bytes = hex::decode(&enc.nonce_hex).map_err(|_| SigningError::InvalidHex)?;
    let nonce_arr: [u8; 12] = nonce_bytes
        .as_slice()
        .try_into()
        .map_err(|_| SigningError::InvalidKey)?;
    let nonce = Nonce::from(nonce_arr);
    let ct_bytes = hex::decode(&enc.ciphertext_hex).map_err(|_| SigningError::InvalidHex)?;
    let plaintext = cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ct_bytes.as_ref(),
                aad: enc.session_id.as_bytes(),
            },
        )
        .map_err(|_| SigningError::Decrypt)?;
    let key_bytes: [u8; 32] = plaintext.try_into().map_err(|_| SigningError::InvalidKey)?;
    Ok(SigningKey::from_bytes(&key_bytes))
}

fn key_file_path(key_dir: &Path, session_id: Uuid) -> PathBuf {
    key_dir.join(format!("session-{}.key", session_id))
}

/// Persist a `SigningKey` to disk encrypted with `password`.
///
/// The password must be at least `MIN_PASSWORD_LEN` characters long
/// (TM-3c hardening). Short passwords are rejected with `SigningError::PasswordTooShort`.
pub fn save_session_key(
    key_dir: &Path,
    session_id: Uuid,
    key: &SigningKey,
    password: &str,
) -> Result<(), SigningError> {
    if password.len() < MIN_PASSWORD_LEN {
        return Err(SigningError::PasswordTooShort);
    }
    std::fs::create_dir_all(key_dir).map_err(|e| SigningError::Io(e.to_string()))?;
    let enc = encrypt_signing_key(session_id, key, password)?;
    let json = serde_json::to_string_pretty(&enc).map_err(|e| SigningError::Io(e.to_string()))?;
    let path = key_file_path(key_dir, session_id);
    {
        use std::io::Write;
        let mut file = std::fs::File::create(&path).map_err(|e| SigningError::Io(e.to_string()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(std::fs::Permissions::from_mode(0o600))
                .map_err(|e| SigningError::Io(e.to_string()))?;
        }
        #[cfg(windows)]
        {
            // Restrict the key file to the current user only via icacls.
            // Disable inheritance, then grant Full access exclusively to %USERNAME%.
            // These operations are FATAL — leaving a key file world-readable is
            // a critical security violation (TM-3b hardening).
            let path_str = path.to_string_lossy();
            std::process::Command::new("icacls")
                .args([path_str.as_ref(), "/inheritance:r"])
                .output()
                .map_err(|e| {
                    SigningError::Io(format!(
                        "SECURITY: failed to remove inheritance on signing key file {}: {}. \
                         Refusing to leave key file with permissive ACL.",
                        path_str, e
                    ))
                })?;
            let user = std::env::var("USERNAME").map_err(|_| {
                SigningError::Io(
                    "SECURITY: USERNAME env var not set; cannot restrict key file ACL".into(),
                )
            })?;
            std::process::Command::new("icacls")
                .args([path_str.as_ref(), "/grant:r", &format!("{user}:F")])
                .output()
                .map_err(|e| {
                    SigningError::Io(format!(
                        "SECURITY: failed to restrict signing key file {} to user {}: {}. \
                         Refusing to leave key file with permissive ACL.",
                        path_str, user, e
                    ))
                })?;
        }
        file.write_all(json.as_bytes())
            .map_err(|e| SigningError::Io(e.to_string()))?;
    }
    Ok(())
}

/// Load and decrypt a `SigningKey` from disk using `password`.
/// Returns `SigningError::KeyFileNotFound` if the file does not exist (new session).
pub fn load_session_key(
    key_dir: &Path,
    session_id: Uuid,
    password: &str,
) -> Result<SigningKey, SigningError> {
    let path = key_file_path(key_dir, session_id);
    if !path.exists() {
        return Err(SigningError::KeyFileNotFound);
    }
    let json = std::fs::read_to_string(&path).map_err(|e| SigningError::Io(e.to_string()))?;
    let enc: EncryptedKeyFile =
        serde_json::from_str(&json).map_err(|e| SigningError::Io(e.to_string()))?;
    decrypt_signing_key(&enc, password)
}

/// Prompt the user for a key-protection password, or read it from
/// `ECTO_KEY_PASSWORD`. Returns `None` if the user enters an empty string
/// (key persistence is skipped) or if stdin is not a terminal.
///
/// **`ECTO_KEY_PASSWORD` is deprecated (TM-3c).** It remains functional for
/// non-interactive CI pipelines, but a loud deprecation warning is emitted.
/// Prefer `--key-password-fd` (reading from a file descriptor) in production.
pub fn prompt_or_env_password(prompt_msg: &str) -> Option<String> {
    if let Ok(pw) = std::env::var("ECTO_KEY_PASSWORD") {
        if !pw.is_empty() {
            // Emit a loud, unmissable deprecation + security warning.
            eprintln!("╔══════════════════════════════════════════════════════════════╗");
            eprintln!("║  DEPRECATED: ECTO_KEY_PASSWORD is set via env var           ║");
            eprintln!("║  This is INSECURE: the password is visible in process        ║");
            eprintln!("║  listings (/proc/self/environ, `ps auxe`, docker inspect).   ║");
            eprintln!("║  Use --key-password-fd or the interactive prompt instead.    ║");
            eprintln!("║  ECTO_KEY_PASSWORD will be REMOVED in a future release.      ║");
            eprintln!("╚══════════════════════════════════════════════════════════════╝");
            return Some(pw);
        }
        return None;
    }
    match rpassword::prompt_password(prompt_msg) {
        Ok(pw) if !pw.is_empty() => Some(pw),
        _ => None,
    }
}

/// Prompt the user to re-enter the password to unlock an existing session key.
pub fn prompt_or_env_password_for_resume(session_id: Uuid) -> Option<String> {
    let prompt = format!(
        "Enter password to unlock signing key for session {} (leave blank to skip): ",
        session_id
    );
    if let Ok(pw) = std::env::var("ECTO_KEY_PASSWORD") {
        if !pw.is_empty() {
            eprintln!("╔══════════════════════════════════════════════════════════════╗");
            eprintln!("║  DEPRECATED: ECTO_KEY_PASSWORD is set via env var           ║");
            eprintln!("║  This is INSECURE: the password is visible in process        ║");
            eprintln!("║  listings (/proc/self/environ, `ps auxe`, docker inspect).   ║");
            eprintln!("║  Use --key-password-fd or the interactive prompt instead.    ║");
            eprintln!("║  ECTO_KEY_PASSWORD will be REMOVED in a future release.      ║");
            eprintln!("╚══════════════════════════════════════════════════════════════╝");
            return Some(pw);
        }
        return None;
    }
    match rpassword::prompt_password(&prompt) {
        Ok(pw) if !pw.is_empty() => Some(pw),
        _ => None,
    }
}

/// Read a password from file descriptor `fd` (TM-3c hardening).
///
/// This avoids placing the password in environment variables or command-line
/// arguments, both of which are visible via `/proc` and `ps`. Typical usage:
///
/// ```bash
/// ectoledger audit "…" --key-password-fd 3   3< <(pass show ectoledger)
/// ```
///
/// The entire content of the FD is read (up to 1 KiB), trimmed of trailing
/// whitespace, and returned. Returns `None` on read failure.
pub fn read_password_from_fd(fd: i32) -> Option<String> {
    // Cross-platform: on Unix use FromRawFd; on Windows this path is not
    // reachable (the CLI validator rejects --key-password-fd on Windows).
    #[cfg(unix)]
    {
        use std::io::Read;
        use std::os::unix::io::FromRawFd;
        let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
        let mut buf = vec![0u8; 1024];
        match file.read(&mut buf) {
            Ok(n) => {
                let s = String::from_utf8_lossy(&buf[..n]).trim_end().to_string();
                if s.is_empty() { None } else { Some(s) }
            }
            Err(e) => {
                eprintln!("Failed to read password from fd {}: {}", fd, e);
                None
            }
        }
    }
    #[cfg(not(unix))]
    {
        let _ = fd;
        eprintln!("--key-password-fd is only supported on Unix platforms.");
        None
    }
}

// ── Signed checkpoint (TM-1c) ─────────────────────────────────────────────────

/// A signed checkpoint captures the chain tip hash at a point in time,
/// allowing offline verification of ledger integrity without replaying
/// the full chain.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SignedCheckpoint {
    /// ISO-8601 timestamp of when the checkpoint was created.
    pub created_at: String,
    /// Latest sequence number in the chain.
    pub sequence: i64,
    /// SHA-256 content hash of the latest event (the chain tip).
    pub chain_tip_hash: String,
    /// Hex-encoded Ed25519 signature over `"{sequence}:{chain_tip_hash}"`.
    pub signature: String,
    /// Hex-encoded Ed25519 public key for verification.
    pub public_key: String,
}

impl SignedCheckpoint {
    /// Create and sign a checkpoint for the given chain tip.
    pub fn create(sequence: i64, chain_tip_hash: &str, signing_key: &SigningKey) -> Self {
        let msg = format!("{}:{}", sequence, chain_tip_hash);
        let sig = signing_key.sign(msg.as_bytes());
        Self {
            created_at: chrono::Utc::now().to_rfc3339(),
            sequence,
            chain_tip_hash: chain_tip_hash.to_string(),
            signature: hex::encode(sig.to_bytes()),
            public_key: hex::encode(signing_key.verifying_key().to_bytes()),
        }
    }

    /// Verify this checkpoint's Ed25519 signature.
    pub fn verify(&self) -> Result<(), SigningError> {
        let pk_bytes = hex::decode(&self.public_key).map_err(|_| SigningError::InvalidHex)?;
        let pk_arr: [u8; 32] = pk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SigningError::InvalidKey)?;
        let verifying_key =
            VerifyingKey::from_bytes(&pk_arr).map_err(|_| SigningError::InvalidKey)?;
        let sig_bytes = hex::decode(&self.signature).map_err(|_| SigningError::InvalidHex)?;
        let sig_arr: [u8; 64] = sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| SigningError::InvalidSignature)?;
        let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
        let msg = format!("{}:{}", self.sequence, self.chain_tip_hash);
        verifying_key
            .verify_strict(msg.as_bytes(), &signature)
            .map_err(|_| SigningError::VerificationFailed)
    }

    /// Save the checkpoint to a JSON file.
    pub fn save(&self, path: &Path) -> Result<(), SigningError> {
        let json =
            serde_json::to_string_pretty(self).map_err(|e| SigningError::Io(e.to_string()))?;
        std::fs::write(path, json).map_err(|e| SigningError::Io(e.to_string()))
    }

    /// Load a checkpoint from a JSON file.
    pub fn load(path: &Path) -> Result<Self, SigningError> {
        let json = std::fs::read_to_string(path).map_err(|e| SigningError::Io(e.to_string()))?;
        serde_json::from_str(&json).map_err(|e| SigningError::Io(e.to_string()))
    }
}

// ── Error type ────────────────────────────────────────────────────────────────

/// Try to load the Ed25519 `VerifyingKey` for a session from its stored
/// `session_public_key` hex string in the database.  Returns `None` if the
/// session doesn't exist or has no stored key.
pub async fn load_session_verifying_key(
    pool: &sqlx::PgPool,
    session_id: Uuid,
) -> Option<VerifyingKey> {
    let pk_hex: Option<String> =
        sqlx::query_scalar("SELECT session_public_key FROM agent_sessions WHERE id = $1")
            .bind(session_id)
            .fetch_optional(pool)
            .await
            .ok()?
            .flatten();
    let pk_hex = pk_hex?;
    let pk_bytes = hex::decode(&pk_hex).ok()?;
    let arr: [u8; 32] = pk_bytes.as_slice().try_into().ok()?;
    VerifyingKey::from_bytes(&arr).ok()
}

#[derive(Debug, thiserror::Error)]
pub enum SigningError {
    #[error("invalid hex")]
    InvalidHex,
    #[error("invalid key bytes")]
    InvalidKey,
    #[error("invalid signature")]
    InvalidSignature,
    #[error("signature verification failed")]
    VerificationFailed,
    #[error("password too short (minimum {MIN_PASSWORD_LEN} characters)")]
    PasswordTooShort,
    #[error("KDF error: {0}")]
    Kdf(String),
    #[error("encryption error: {0}")]
    Encrypt(String),
    #[error("decryption failed (wrong password or corrupted key file)")]
    Decrypt,
    #[error("key file I/O error: {0}")]
    Io(String),
    #[error("key file not found (new session or key_dir not set)")]
    KeyFileNotFound,
}

/// Minimum password length for key encryption (TM-3c hardening).
pub const MIN_PASSWORD_LEN: usize = 12;
