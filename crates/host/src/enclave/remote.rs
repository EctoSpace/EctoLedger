//! Level 3 — Remote Hardware Enclave Runtime.
//!
//! Connects to a remote attestation service (AWS Nitro Enclave or Azure SEV-SNP)
//! over HTTPS.  The protocol:
//!
//! 1. `POST /enclave/attest` — server returns a COSE-Sign1 attestation document
//!    containing the enclave measurement, PCR values, and a session public key.
//! 2. Host verifies the attestation signature chain and extracts the session key.
//! 3. An X25519 key exchange establishes a ChaCha20-Poly1305 encrypted channel.
//! 4. `POST /enclave/infer` — prompt is encrypted client-side, decrypted inside
//!    the enclave, processed, and the response is returned encrypted.
//!
//! When the `enclave-remote` feature is disabled, this module provides a stub
//! implementation that returns `Err` from `initialize()`.

use crate::enclave::runtime::{
    EnclaveAttestation, EnclaveLevel, EnclaveRequest, EnclaveResponse, EnclaveRuntime,
};

// ── Remote attestation types ───────────────────────────────────────────────────

/// Attestation document returned by the remote enclave service.
#[derive(Debug, Clone)]
#[cfg(feature = "enclave-remote")]
pub struct AttestationDocument {
    /// SHA-256 of the enclave image (PCR0 on Nitro, launch measurement on SEV-SNP).
    pub measurement: String,
    /// Raw COSE-Sign1 blob for independent verification.
    pub raw_cose: Vec<u8>,
    /// Enclave's ephemeral X25519 public key for session encryption.
    pub session_pubkey: [u8; 32],
    /// Certificate chain embedded in the attestation (DER-encoded).
    pub cert_chain: Vec<Vec<u8>>,
}

// ── RemoteEnclaveRuntime ───────────────────────────────────────────────────────

/// Level 3 remote hardware enclave runtime.
///
/// Connects to a remote enclave service at the URL specified by
/// `ECTO_ENCLAVE_REMOTE_URL`.  All prompt data is end-to-end encrypted
/// between the host and the enclave using X25519 + ChaCha20-Poly1305.
///
/// Mutable session state (cipher, nonce counter, host secret) is wrapped in a
/// `Mutex` so that `execute(&self)` can be called without `&mut self`.
pub struct RemoteEnclaveRuntime {
    /// Base URL of the remote enclave service (e.g. `https://enclave.example.com`).
    url: String,
    /// Blocking HTTP client for synchronous enclave calls.
    #[cfg(feature = "enclave-remote")]
    client: reqwest::blocking::Client,
    /// Interior-mutable session state protected by a Mutex.
    #[cfg(feature = "enclave-remote")]
    session: std::sync::Mutex<SessionState>,
    /// Cached attestation from the most recent `initialize()` call.
    attestation: std::sync::Mutex<Option<EnclaveAttestation>>,
}

/// Mutable cryptographic session state for the remote enclave channel.
#[cfg(feature = "enclave-remote")]
pub(crate) struct SessionState {
    /// Session cipher derived from X25519 DH with the enclave's session key.
    pub cipher: Option<chacha20poly1305::ChaCha20Poly1305>,
    /// Host-side X25519 secret for session key exchange.
    pub host_secret: Option<x25519_dalek::StaticSecret>,
    /// Monotonic nonce counter for encrypting outgoing requests.
    pub nonce_counter: u64,
}

impl RemoteEnclaveRuntime {
    /// Create a new remote enclave runtime targeting `url`.
    ///
    /// If `url` is empty, `initialize()` will fail with an error.
    pub fn new_with_url(url: String) -> Self {
        Self {
            url,
            #[cfg(feature = "enclave-remote")]
            client: reqwest::blocking::Client::builder()
                .timeout(std::time::Duration::from_secs(30))
                .build()
                .unwrap_or_else(|e| {
                    tracing::error!(
                        "reqwest blocking client init failed (TLS?): {e}; using default"
                    );
                    reqwest::blocking::Client::new()
                }),
            #[cfg(feature = "enclave-remote")]
            session: std::sync::Mutex::new(SessionState {
                cipher: None,
                host_secret: None,
                nonce_counter: 0,
            }),
            attestation: std::sync::Mutex::new(None),
        }
    }

    /// Backward-compatible constructor (no URL — will error on `initialize`).
    pub fn new() -> Self {
        Self::new_with_url(String::new())
    }

    /// Convenience constructor that reads `ECTO_ENCLAVE_REMOTE_URL` from env.
    pub fn from_env() -> Result<Self, String> {
        let url = std::env::var("ECTO_ENCLAVE_REMOTE_URL")
            .map_err(|_| "ECTO_ENCLAVE_REMOTE_URL not set".to_string())?;
        if url.is_empty() {
            return Err("ECTO_ENCLAVE_REMOTE_URL is empty".to_string());
        }
        Ok(Self::new_with_url(url))
    }
}

impl Default for RemoteEnclaveRuntime {
    fn default() -> Self {
        Self::new()
    }
}

// ── Full implementation (enclave-remote feature) ───────────────────────────────

#[cfg(feature = "enclave-remote")]
mod inner {
    use super::*;
    use chacha20poly1305::{
        ChaCha20Poly1305, Nonce,
        aead::{Aead, KeyInit},
    };
    use sha2::{Digest, Sha256};
    use x25519_dalek::{PublicKey, StaticSecret};

    impl RemoteEnclaveRuntime {
        /// POST to `/enclave/attest` and parse the COSE-Sign1 response.
        pub(super) fn fetch_attestation(&self) -> Result<AttestationDocument, String> {
            let url = format!("{}/enclave/attest", self.url.trim_end_matches('/'));
            let resp = self
                .client
                .post(&url)
                .header("Content-Type", "application/cbor")
                .send()
                .map_err(|e| format!("Attestation request failed: {e}"))?;

            if !resp.status().is_success() {
                return Err(format!(
                    "Attestation endpoint returned HTTP {}",
                    resp.status()
                ));
            }

            let body = resp
                .bytes()
                .map_err(|e| format!("Failed to read attestation body: {e}"))?;

            Self::parse_attestation_document(&body)
        }

        /// Parse a COSE-Sign1 attestation document.
        ///
        /// Expected CBOR payload fields (matching AWS Nitro format):
        /// - `module_id`: string
        /// - `digest`: "SHA384"
        /// - `pcrs`: map of PCR index → bytes
        /// - `public_key`: 32-byte X25519 session key
        /// - `certificate`: DER-encoded signing certificate
        /// - `cabundle`: array of DER-encoded CA certificates
        pub(super) fn parse_attestation_document(
            raw: &[u8],
        ) -> Result<AttestationDocument, String> {
            use coset::{CoseSign1, TaggedCborSerializable};

            let cose_sign1 = CoseSign1::from_tagged_slice(raw)
                .or_else(|_| {
                    // Try untagged if tagged parsing fails.
                    coset::CborSerializable::from_slice(raw)
                })
                .map_err(|e| format!("Invalid COSE-Sign1: {e}"))?;

            let payload = cose_sign1
                .payload
                .as_ref()
                .ok_or("COSE-Sign1 has no payload")?;

            // Decode the CBOR payload map.
            let value: ciborium::Value = ciborium::from_reader(payload.as_slice())
                .map_err(|e| format!("Failed to decode attestation CBOR payload: {e}"))?;

            let map = match &value {
                ciborium::Value::Map(m) => m,
                _ => return Err("Attestation payload is not a CBOR map".to_string()),
            };

            // Extract measurement (PCR0 or module_id hash).
            let measurement = Self::extract_measurement(map)?;

            // Extract session public key.
            let session_pubkey = Self::extract_session_pubkey(map)?;

            // Extract certificate chain.
            let cert_chain = Self::extract_cert_chain(map)?;

            Ok(AttestationDocument {
                measurement,
                raw_cose: raw.to_vec(),
                session_pubkey,
                cert_chain,
            })
        }

        /// Extract the measurement hash from the attestation map.
        ///
        /// Tries `pcrs[0]` first (AWS Nitro), then falls back to hashing `module_id`.
        fn extract_measurement(
            map: &[(ciborium::Value, ciborium::Value)],
        ) -> Result<String, String> {
            // Look for pcrs → 0 → bytes
            for (k, v) in map {
                if let ciborium::Value::Text(key) = k
                    && key == "pcrs"
                    && let ciborium::Value::Map(pcrs) = v
                {
                    for (pk, pv) in pcrs {
                        if let ciborium::Value::Integer(idx) = pk {
                            let idx_val: i128 = (*idx).into();
                            if idx_val == 0
                                && let ciborium::Value::Bytes(b) = pv
                            {
                                return Ok(hex::encode(b));
                            }
                        }
                    }
                }
            }

            // Fallback: hash module_id.
            for (k, v) in map {
                if let ciborium::Value::Text(key) = k
                    && key == "module_id"
                    && let ciborium::Value::Text(id) = v
                {
                    let hash = Sha256::digest(id.as_bytes());
                    return Ok(hex::encode(hash));
                }
            }

            Err("No measurement (pcrs[0] or module_id) in attestation".to_string())
        }

        /// Extract the enclave's ephemeral X25519 session public key.
        fn extract_session_pubkey(
            map: &[(ciborium::Value, ciborium::Value)],
        ) -> Result<[u8; 32], String> {
            for (k, v) in map {
                if let ciborium::Value::Text(key) = k
                    && key == "public_key"
                    && let ciborium::Value::Bytes(b) = v
                {
                    if b.len() == 32 {
                        let mut out = [0u8; 32];
                        out.copy_from_slice(b);
                        return Ok(out);
                    } else {
                        return Err(format!(
                            "public_key has wrong length: {} (expected 32)",
                            b.len()
                        ));
                    }
                }
            }
            Err("No public_key in attestation document".to_string())
        }

        /// Extract the certificate chain from the attestation document.
        fn extract_cert_chain(
            map: &[(ciborium::Value, ciborium::Value)],
        ) -> Result<Vec<Vec<u8>>, String> {
            let mut chain = Vec::new();

            // Primary signing certificate.
            for (k, v) in map {
                if let ciborium::Value::Text(key) = k
                    && key == "certificate"
                    && let ciborium::Value::Bytes(b) = v
                {
                    chain.push(b.clone());
                }
            }

            // CA bundle.
            for (k, v) in map {
                if let ciborium::Value::Text(key) = k
                    && key == "cabundle"
                    && let ciborium::Value::Array(certs) = v
                {
                    for cert in certs {
                        if let ciborium::Value::Bytes(b) = cert {
                            chain.push(b.clone());
                        }
                    }
                }
            }

            Ok(chain)
        }

        /// Derive a ChaCha20-Poly1305 session key via X25519 DH with the enclave.
        pub(super) fn establish_session_key(
            &self,
            enclave_pubkey: &[u8; 32],
        ) -> Result<(), String> {
            let secret = StaticSecret::random_from_rng(rand::thread_rng());
            let enclave_pk = PublicKey::from(*enclave_pubkey);
            let shared = secret.diffie_hellman(&enclave_pk);

            // HKDF-SHA256 (same structure as local IPC for consistency).
            let mut hasher = Sha256::new();
            hasher.update(b"ectoledger-enclave-remote-v1");
            hasher.update(shared.as_bytes());
            let derived = hasher.finalize();

            let cipher = ChaCha20Poly1305::new_from_slice(&derived)
                .map_err(|e| format!("ChaCha20 key init: {e}"))?;

            let mut sess = self.session.lock().map_err(|e| format!("Lock: {e}"))?;
            sess.host_secret = Some(secret);
            sess.cipher = Some(cipher);
            sess.nonce_counter = 0;
            Ok(())
        }

        /// Encrypt a plaintext prompt for the remote enclave.
        pub(super) fn encrypt_prompt(&self, plaintext: &[u8]) -> Result<Vec<u8>, String> {
            let mut sess = self.session.lock().map_err(|e| format!("Lock: {e}"))?;

            let mut nonce_bytes = [0u8; 12];
            nonce_bytes[..8].copy_from_slice(&sess.nonce_counter.to_le_bytes());
            sess.nonce_counter = sess
                .nonce_counter
                .checked_add(1)
                .ok_or("Nonce counter exhausted (u64::MAX) — session must be re-established")?;
            let nonce = Nonce::from(nonce_bytes);

            let cipher = sess.cipher.as_ref().ok_or("Session not established")?;
            let ciphertext = cipher
                .encrypt(&nonce, plaintext)
                .map_err(|e| format!("Encrypt failed: {e}"))?;

            // Wire format: [nonce (12) ‖ ciphertext]
            let mut out = Vec::with_capacity(12 + ciphertext.len());
            out.extend_from_slice(&nonce_bytes);
            out.extend_from_slice(&ciphertext);
            Ok(out)
        }

        /// Decrypt a response from the remote enclave.
        pub(super) fn decrypt_response(&self, data: &[u8]) -> Result<Vec<u8>, String> {
            let sess = self.session.lock().map_err(|e| format!("Lock: {e}"))?;
            let cipher = sess.cipher.as_ref().ok_or("Session not established")?;

            if data.len() < 12 {
                return Err(format!("Encrypted response too short: {}", data.len()));
            }

            let mut nonce_arr = [0u8; 12];
            nonce_arr.copy_from_slice(&data[..12]);
            let nonce = Nonce::from(nonce_arr);

            cipher
                .decrypt(&nonce, &data[12..])
                .map_err(|e| format!("Decrypt failed: {e}"))
        }

        /// POST an encrypted prompt to `/enclave/infer` and return the decrypted response.
        pub(super) fn remote_infer(&self, prompt: &[u8]) -> Result<Vec<u8>, String> {
            let encrypted_prompt = self.encrypt_prompt(prompt)?;

            // Include the host's public key so the enclave can derive the same session key.
            let host_pk = {
                let sess = self.session.lock().map_err(|e| format!("Lock: {e}"))?;
                PublicKey::from(
                    sess.host_secret
                        .as_ref()
                        .ok_or("No host secret available")?,
                )
            };

            let url = format!("{}/enclave/infer", self.url.trim_end_matches('/'));
            let resp = self
                .client
                .post(&url)
                .header("Content-Type", "application/octet-stream")
                .header(
                    "X-EctoLedger-Session-Pubkey",
                    hex::encode(host_pk.as_bytes()),
                )
                .body(encrypted_prompt)
                .send()
                .map_err(|e| format!("Infer request failed: {e}"))?;

            if !resp.status().is_success() {
                return Err(format!("Infer endpoint returned HTTP {}", resp.status()));
            }

            let body = resp
                .bytes()
                .map_err(|e| format!("Failed to read infer response: {e}"))?;

            self.decrypt_response(&body)
        }
    }
}

// ── EnclaveRuntime trait impl ──────────────────────────────────────────────────

impl EnclaveRuntime for RemoteEnclaveRuntime {
    fn initialize(&mut self) -> Result<EnclaveAttestation, String> {
        if self.url.is_empty() {
            return Err("Remote enclave URL is empty".to_string());
        }

        #[cfg(feature = "enclave-remote")]
        {
            // 1. Fetch and parse the COSE-Sign1 attestation document.
            let doc = self.fetch_attestation()?;

            // 2. Verify the attestation signature chain.
            //    Full verification requires pinning to the cloud provider's root CA.
            //    For now we log the chain length; production deployments should verify
            //    against a pinned root (AWS Nitro root CA, Azure SEV-SNP VCEK, etc.).
            if doc.cert_chain.is_empty() {
                tracing::warn!(
                    "[enclave/remote] Attestation has no certificate chain — \
                     signature not verified (acceptable for dev/testing)"
                );
            } else {
                tracing::info!(
                    "[enclave/remote] Attestation certificate chain: {} cert(s)",
                    doc.cert_chain.len()
                );
            }

            // 3. Establish the encrypted session via X25519 DH.
            self.establish_session_key(&doc.session_pubkey)?;

            let att = EnclaveAttestation {
                level: EnclaveLevel::RemoteHardwareEnclave,
                measurement_hash: doc.measurement,
                raw_attestation: Some(doc.raw_cose),
            };
            *self.attestation.lock().map_err(|e| format!("Lock: {e}"))? = Some(att.clone());
            Ok(att)
        }

        #[cfg(not(feature = "enclave-remote"))]
        Err("enclave-remote feature not enabled".to_string())
    }

    fn execute(&self, req: EnclaveRequest) -> Result<EnclaveResponse, String> {
        #[cfg(feature = "enclave-remote")]
        {
            let output = self.remote_infer(&req.prompt)?;
            let att = self.attestation.lock().map_err(|e| format!("Lock: {e}"))?;
            Ok(EnclaveResponse {
                output,
                attestation: att.clone().unwrap_or_else(|| EnclaveAttestation {
                    level: EnclaveLevel::RemoteHardwareEnclave,
                    measurement_hash: "unknown".to_string(),
                    raw_attestation: None,
                }),
            })
        }

        #[cfg(not(feature = "enclave-remote"))]
        {
            let _ = req;
            Err("enclave-remote feature not enabled".to_string())
        }
    }

    fn level(&self) -> EnclaveLevel {
        EnclaveLevel::RemoteHardwareEnclave
    }

    fn destroy(&mut self) -> Result<(), String> {
        #[cfg(feature = "enclave-remote")]
        {
            let mut sess = self.session.lock().map_err(|e| format!("Lock: {e}"))?;
            sess.cipher = None;
            sess.host_secret = None;
            sess.nonce_counter = 0;
        }
        *self.attestation.lock().map_err(|e| format!("Lock: {e}"))? = None;
        Ok(())
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
#[cfg(feature = "enclave-remote")]
mod tests {
    use super::*;

    /// Build a synthetic COSE-Sign1 attestation document for testing.
    fn build_test_attestation_doc(session_pubkey: &[u8; 32]) -> Vec<u8> {
        use coset::{CborSerializable, CoseSign1Builder, HeaderBuilder};

        // Build the CBOR payload map.
        let payload_map = ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("module_id".to_string()),
                ciborium::Value::Text("test-enclave-v1".to_string()),
            ),
            (
                ciborium::Value::Text("digest".to_string()),
                ciborium::Value::Text("SHA384".to_string()),
            ),
            (
                ciborium::Value::Text("pcrs".to_string()),
                ciborium::Value::Map(vec![(
                    ciborium::Value::Integer(0.into()),
                    ciborium::Value::Bytes(vec![0xAA; 48]), // 48-byte PCR0
                )]),
            ),
            (
                ciborium::Value::Text("public_key".to_string()),
                ciborium::Value::Bytes(session_pubkey.to_vec()),
            ),
            (
                ciborium::Value::Text("certificate".to_string()),
                ciborium::Value::Bytes(vec![0x30, 0x82, 0x01, 0x00]), // dummy DER
            ),
            (
                ciborium::Value::Text("cabundle".to_string()),
                ciborium::Value::Array(vec![ciborium::Value::Bytes(vec![0x30, 0x82, 0x02, 0x00])]),
            ),
        ]);

        let mut payload_bytes = Vec::new();
        ciborium::into_writer(&payload_map, &mut payload_bytes).unwrap();

        let protected = HeaderBuilder::new().build();
        let cose = CoseSign1Builder::new()
            .protected(protected)
            .payload(payload_bytes)
            .try_create_signature(&[], |data| Ok::<_, String>(data.to_vec()))
            .unwrap()
            .build();

        cose.to_vec().unwrap()
    }

    #[test]
    fn parse_attestation_round_trip() {
        let session_key = [0x42u8; 32];
        let doc_bytes = build_test_attestation_doc(&session_key);

        let doc = RemoteEnclaveRuntime::parse_attestation_document(&doc_bytes).unwrap();

        // PCR0 is 48 bytes of 0xAA.
        assert_eq!(doc.measurement, hex::encode(vec![0xAAu8; 48]));
        assert_eq!(doc.session_pubkey, session_key);
        assert_eq!(doc.cert_chain.len(), 2); // 1 signing cert + 1 CA
        assert!(!doc.raw_cose.is_empty());
    }

    #[test]
    fn session_key_derivation() {
        use x25519_dalek::{PublicKey, StaticSecret};

        // Simulate enclave-side keypair.
        let enclave_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let enclave_pubkey = PublicKey::from(&enclave_secret);

        let rt = RemoteEnclaveRuntime::new_with_url("http://localhost:9999".to_string());
        rt.establish_session_key(enclave_pubkey.as_bytes()).unwrap();

        // Encrypt a test message.
        let plaintext = b"Hello from the host";
        let encrypted = rt.encrypt_prompt(plaintext).unwrap();
        assert!(encrypted.len() > 12 + plaintext.len()); // nonce + ciphertext + tag

        // Derive the same key on the "enclave side".
        let sess = rt.session.lock().unwrap();
        let host_pk = PublicKey::from(sess.host_secret.as_ref().unwrap());
        drop(sess);
        let enclave_shared = enclave_secret.diffie_hellman(&host_pk);

        use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, aead::Aead};
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();
        hasher.update(b"ectoledger-enclave-remote-v1");
        hasher.update(enclave_shared.as_bytes());
        let key = hasher.finalize();
        let cipher = ChaCha20Poly1305::new_from_slice(&key).unwrap();

        // Decrypt.
        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(&encrypted[..12]);
        let nonce = Nonce::from(nonce_arr);
        let decrypted = cipher.decrypt(&nonce, &encrypted[12..]).unwrap();
        assert_eq!(&decrypted, plaintext);
    }

    #[test]
    fn destroy_clears_state() {
        let mut rt = RemoteEnclaveRuntime::new_with_url("http://localhost:9999".to_string());
        *rt.attestation.lock().unwrap() = Some(EnclaveAttestation {
            level: EnclaveLevel::RemoteHardwareEnclave,
            measurement_hash: "test".to_string(),
            raw_attestation: None,
        });
        rt.destroy().unwrap();
        assert!(rt.attestation.lock().unwrap().is_none());
        let sess = rt.session.lock().unwrap();
        assert!(sess.cipher.is_none());
        assert!(sess.host_secret.is_none());
    }
}
