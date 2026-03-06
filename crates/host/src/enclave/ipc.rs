//! Encrypted IPC channel over a shared memory page.
//!
//! Layout of the 4 KiB shared memory page (guest physical address inside guest RAM):
//!
//! ```text
//! Offset   Size   Field
//! ──────   ────   ─────
//!   0       32    Host X25519 public key
//!  32       32    Guest X25519 public key
//!  64        1    Command byte (host → guest): 0x00 = idle, 0x01 = request ready
//!  65        1    Status byte  (guest → host): 0x00 = idle, 0x02 = response ready
//!  66        2    Reserved (alignment padding)
//!  68        4    Request length  (little-endian u32)
//!  72        4    Response length (little-endian u32)
//!  76        4    Reserved
//!  80       ..    Nonce (12 bytes) ‖ ciphertext (up to page end)
//! ```
//!
//! Protocol:
//! 1. Host writes its public key at offset 0.
//! 2. Host sets `command = 0x01` and boots the guest / resumes vCPU.
//! 3. Guest reads host pubkey, writes its own pubkey at offset 32, derives shared secret.
//! 4. Guest reads encrypted request from offset 80, decrypts, processes.
//! 5. Guest writes encrypted response at offset 80, sets response length, status = 0x02, HVC.
//! 6. Host reads response, decrypts.

#[cfg(feature = "enclave")]
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
#[cfg(feature = "enclave")]
use sha2::{Digest, Sha256};
#[cfg(feature = "enclave")]
use x25519_dalek::{PublicKey, StaticSecret};

/// Byte offsets within the shared memory page.
pub const OFF_HOST_PUBKEY: usize = 0;
pub const OFF_GUEST_PUBKEY: usize = 32;
pub const OFF_COMMAND: usize = 64;
pub const OFF_STATUS: usize = 65;
pub const OFF_REQ_LEN: usize = 68;
pub const OFF_RESP_LEN: usize = 72;
pub const OFF_PAYLOAD: usize = 80;

/// Maximum ciphertext size = page size − payload offset − nonce (12 bytes).
pub const MAX_CIPHERTEXT: usize = 4096 - OFF_PAYLOAD - 12;

/// Command byte values.
pub const CMD_IDLE: u8 = 0x00;
pub const CMD_REQUEST_READY: u8 = 0x01;

/// Status byte values.
pub const STATUS_IDLE: u8 = 0x00;
pub const STATUS_RESPONSE_READY: u8 = 0x02;

/// Host-side encrypted IPC channel.
///
/// The host holds a static X25519 secret and derives a symmetric ChaCha20-Poly1305 key
/// after reading the guest's public key from the shared page.
#[cfg(feature = "enclave")]
pub struct SharedMemoryChannel {
    secret: StaticSecret,
    host_pubkey: PublicKey,
    /// Derived after handshake.
    cipher: Option<ChaCha20Poly1305>,
    /// Monotonic nonce counter (96-bit, little-endian).  Incremented after every encrypt.
    nonce_counter: u64,
}

#[cfg(feature = "enclave")]
impl SharedMemoryChannel {
    /// Create a new channel.  Writes the host public key to `shared_page[0..32]`.
    pub fn new(shared_page: &mut [u8]) -> Self {
        let secret = StaticSecret::random_from_rng(rand::thread_rng());
        let host_pubkey = PublicKey::from(&secret);

        // Write host public key into the shared page.
        shared_page[OFF_HOST_PUBKEY..OFF_HOST_PUBKEY + 32].copy_from_slice(host_pubkey.as_bytes());

        Self {
            secret,
            host_pubkey,
            cipher: None,
            nonce_counter: 0,
        }
    }

    /// Return the host's public key bytes (for attestation embedding).
    pub fn host_pubkey_bytes(&self) -> [u8; 32] {
        *self.host_pubkey.as_bytes()
    }

    /// Complete the handshake: read the guest's public key from `shared_page[32..64]`,
    /// derive the ChaCha20-Poly1305 key via HKDF-SHA256(shared_secret).
    pub fn handshake(&mut self, shared_page: &[u8]) -> Result<(), String> {
        let mut guest_key_bytes = [0u8; 32];
        guest_key_bytes.copy_from_slice(&shared_page[OFF_GUEST_PUBKEY..OFF_GUEST_PUBKEY + 32]);

        // Reject the null public key (indicates the guest never wrote its key).
        if guest_key_bytes == [0u8; 32] {
            return Err("Guest public key is all-zero — handshake not completed".to_string());
        }

        let guest_pubkey = PublicKey::from(guest_key_bytes);
        let shared_secret = self.secret.diffie_hellman(&guest_pubkey);

        // HKDF-SHA256: extract + expand in one step (single hash for simplicity).
        let mut hasher = Sha256::new();
        hasher.update(b"ectoledger-enclave-ipc-v1");
        hasher.update(shared_secret.as_bytes());
        let derived_key = hasher.finalize();

        let cipher = ChaCha20Poly1305::new_from_slice(&derived_key)
            .map_err(|e| format!("ChaCha20 key init: {e}"))?;
        self.cipher = Some(cipher);
        Ok(())
    }

    /// Encrypt `plaintext` and write `[nonce ‖ ciphertext]` into the shared page at
    /// offset 80.  Also sets the request length field.
    pub fn send(&mut self, shared_page: &mut [u8], plaintext: &[u8]) -> Result<(), String> {
        let cipher = self.cipher.as_ref().ok_or("Handshake not completed")?;

        // Build nonce from counter.
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&self.nonce_counter.to_le_bytes());
        self.nonce_counter = self
            .nonce_counter
            .checked_add(1)
            .ok_or("Nonce counter exhausted (u64::MAX) — session key must be renegotiated")?;
        let nonce = Nonce::from(nonce_bytes);

        let ciphertext = cipher
            .encrypt(&nonce, plaintext)
            .map_err(|e| format!("Encrypt failed: {e}"))?;

        if ciphertext.len() > MAX_CIPHERTEXT {
            return Err(format!(
                "Ciphertext too large for shared page: {} > {}",
                ciphertext.len(),
                MAX_CIPHERTEXT
            ));
        }

        // Write nonce + ciphertext.
        let total = 12 + ciphertext.len();
        shared_page[OFF_PAYLOAD..OFF_PAYLOAD + 12].copy_from_slice(&nonce_bytes);
        shared_page[OFF_PAYLOAD + 12..OFF_PAYLOAD + total].copy_from_slice(&ciphertext);

        // Write request length (covers nonce + ciphertext).
        let len_bytes = (total as u32).to_le_bytes();
        shared_page[OFF_REQ_LEN..OFF_REQ_LEN + 4].copy_from_slice(&len_bytes);

        // Signal: request ready.
        shared_page[OFF_COMMAND] = CMD_REQUEST_READY;

        Ok(())
    }

    /// Read the guest's encrypted response from the shared page and decrypt it.
    pub fn receive(&mut self, shared_page: &[u8]) -> Result<Vec<u8>, String> {
        let cipher = self.cipher.as_ref().ok_or("Handshake not completed")?;

        // Read response length.
        let mut len_bytes = [0u8; 4];
        len_bytes.copy_from_slice(&shared_page[OFF_RESP_LEN..OFF_RESP_LEN + 4]);
        let total_len = u32::from_le_bytes(len_bytes) as usize;

        if total_len < 12 {
            return Err(format!("Response too short: {total_len}"));
        }
        if total_len > 4096 - OFF_PAYLOAD {
            return Err(format!("Response length exceeds page: {total_len}"));
        }

        let nonce_bytes = &shared_page[OFF_PAYLOAD..OFF_PAYLOAD + 12];
        let ciphertext = &shared_page[OFF_PAYLOAD + 12..OFF_PAYLOAD + total_len];

        let mut nonce_arr = [0u8; 12];
        nonce_arr.copy_from_slice(nonce_bytes);
        let nonce = Nonce::from(nonce_arr);
        let plaintext = cipher
            .decrypt(&nonce, ciphertext)
            .map_err(|e| format!("Decrypt failed: {e}"))?;

        Ok(plaintext)
    }
}

#[cfg(test)]
#[cfg(feature = "enclave")]
mod tests {
    use super::*;

    #[test]
    fn round_trip_encrypt_decrypt() {
        let mut page = vec![0u8; 4096];

        // Host creates channel (writes host pubkey).
        let mut host_chan = SharedMemoryChannel::new(&mut page);

        // Verify host pubkey was written to page[0..32].
        let host_pk_slot = &page[OFF_HOST_PUBKEY..OFF_HOST_PUBKEY + 32];
        assert_ne!(
            host_pk_slot, &[0u8; 32],
            "host pubkey must be non-zero after new()"
        );
        assert_eq!(host_pk_slot, host_chan.host_pubkey_bytes().as_slice());

        // Simulate guest: write a known guest pubkey into page[32..64].
        let guest_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let guest_pubkey = PublicKey::from(&guest_secret);
        page[OFF_GUEST_PUBKEY..OFF_GUEST_PUBKEY + 32].copy_from_slice(guest_pubkey.as_bytes());

        // Host completes handshake.
        host_chan.handshake(&page).unwrap();

        // Build the matching cipher on the "guest side" for verification.
        let mut host_key_bytes = [0u8; 32];
        host_key_bytes.copy_from_slice(&page[OFF_HOST_PUBKEY..OFF_HOST_PUBKEY + 32]);
        let host_pubkey = PublicKey::from(host_key_bytes);
        let guest_shared = guest_secret.diffie_hellman(&host_pubkey);

        let mut hasher = Sha256::new();
        hasher.update(b"ectoledger-enclave-ipc-v1");
        hasher.update(guest_shared.as_bytes());
        let guest_key = hasher.finalize();
        let guest_cipher = ChaCha20Poly1305::new_from_slice(&guest_key).unwrap();

        // Host encrypts a request.
        let prompt = b"What is the meaning of life?";
        host_chan.send(&mut page, prompt).unwrap();
        assert_eq!(page[OFF_COMMAND], CMD_REQUEST_READY);

        // Guest decrypts the request.
        let mut len_buf = [0u8; 4];
        len_buf.copy_from_slice(&page[OFF_REQ_LEN..OFF_REQ_LEN + 4]);
        let total_len = u32::from_le_bytes(len_buf) as usize;
        let mut nonce_buf = [0u8; 12];
        nonce_buf.copy_from_slice(&page[OFF_PAYLOAD..OFF_PAYLOAD + 12]);
        let nonce = Nonce::from(nonce_buf);
        let decrypted = guest_cipher
            .decrypt(&nonce, &page[OFF_PAYLOAD + 12..OFF_PAYLOAD + total_len])
            .unwrap();
        assert_eq!(&decrypted, prompt);

        // Guest encrypts a response.
        let response = b"42";
        let mut resp_nonce_bytes = [0u8; 12];
        resp_nonce_bytes[0] = 1; // guest nonce counter = 1
        let resp_nonce = Nonce::from(resp_nonce_bytes);
        let resp_ct = guest_cipher
            .encrypt(&resp_nonce, response.as_slice())
            .unwrap();
        let resp_total = 12 + resp_ct.len();
        page[OFF_PAYLOAD..OFF_PAYLOAD + 12].copy_from_slice(&resp_nonce_bytes);
        page[OFF_PAYLOAD + 12..OFF_PAYLOAD + resp_total].copy_from_slice(&resp_ct);
        page[OFF_RESP_LEN..OFF_RESP_LEN + 4].copy_from_slice(&(resp_total as u32).to_le_bytes());
        page[OFF_STATUS] = STATUS_RESPONSE_READY;

        // Host decrypts the response.
        let plaintext = host_chan.receive(&page).unwrap();
        assert_eq!(&plaintext, response);
    }

    /// Handshake must reject an all-zero guest public key (guest never wrote its key).
    #[test]
    fn handshake_rejects_null_guest_pubkey() {
        let mut page = vec![0u8; 4096];
        let mut chan = SharedMemoryChannel::new(&mut page);

        // page[32..64] is still all zeros — guest never wrote.
        let err = chan.handshake(&page).unwrap_err();
        assert!(
            err.contains("all-zero"),
            "expected null-pubkey rejection, got: {err}"
        );
    }

    /// send() before handshake must return an error (no cipher available).
    #[test]
    fn send_before_handshake_fails() {
        let mut page = vec![0u8; 4096];
        let mut chan = SharedMemoryChannel::new(&mut page);

        let err = chan.send(&mut page, b"hello").unwrap_err();
        assert!(
            err.contains("Handshake not completed"),
            "expected handshake error, got: {err}"
        );
    }

    /// receive() before handshake must return an error.
    #[test]
    fn receive_before_handshake_fails() {
        let mut page = vec![0u8; 4096];
        let mut chan = SharedMemoryChannel::new(&mut page);

        let err = chan.receive(&page).unwrap_err();
        assert!(
            err.contains("Handshake not completed"),
            "expected handshake error, got: {err}"
        );
    }

    /// Nonce counter must increment after each send, producing distinct ciphertexts.
    #[test]
    fn nonce_increments_across_sends() {
        let mut page = vec![0u8; 4096];
        let mut chan = SharedMemoryChannel::new(&mut page);

        // Set up guest key for handshake.
        let guest_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let guest_pubkey = PublicKey::from(&guest_secret);
        page[OFF_GUEST_PUBKEY..OFF_GUEST_PUBKEY + 32].copy_from_slice(guest_pubkey.as_bytes());
        chan.handshake(&page).unwrap();

        // Send twice and capture the nonces.
        chan.send(&mut page, b"msg1").unwrap();
        let mut nonce1 = [0u8; 12];
        nonce1.copy_from_slice(&page[OFF_PAYLOAD..OFF_PAYLOAD + 12]);

        chan.send(&mut page, b"msg2").unwrap();
        let mut nonce2 = [0u8; 12];
        nonce2.copy_from_slice(&page[OFF_PAYLOAD..OFF_PAYLOAD + 12]);

        assert_ne!(nonce1, nonce2, "nonces must differ between sends");
        // First nonce should encode counter=0, second counter=1.
        assert_eq!(nonce1[0], 0);
        assert_eq!(nonce2[0], 1);
    }

    /// Pubkey layout: host at [0..32], guest at [32..64], no overlap.
    #[test]
    fn pubkey_layout_non_overlapping() {
        let mut page = vec![0u8; 4096];
        let _chan = SharedMemoryChannel::new(&mut page);

        let host_pk = &page[0..32];
        assert_ne!(
            host_pk, &[0u8; 32],
            "host pubkey must be written at page[0..32]"
        );

        // Guest area must still be zero (guest hasn't written yet).
        let guest_pk = &page[32..64];
        assert_eq!(
            guest_pk, &[0u8; 32],
            "guest pubkey at page[32..64] must be zero before handshake"
        );

        // Command/status bytes at [64] and [65] must be idle.
        assert_eq!(page[64], CMD_IDLE);
        assert_eq!(page[65], STATUS_IDLE);
    }
}
