//! Integration test: enclave IPC crypto round-trip.
//!
//! Exercises the `SharedMemoryChannel` in isolation — no hypervisor or remote
//! enclave required.  This test is designed to run on any platform (Linux, macOS,
//! Windows) and verifies the full IPC protocol:
//!
//!   1. Host writes X25519 pubkey to `page[0..32]`.
//!   2. Guest writes X25519 pubkey to `page[32..64]`.
//!   3. Both sides derive the same ChaCha20-Poly1305 key.
//!   4. Host encrypts a prompt, guest decrypts it.
//!   5. Guest encrypts a response, host decrypts it.
//!
//! Run:  cargo test --features enclave -p ectoledger --test enclave_ipc

#[cfg(feature = "enclave")]
mod tests {
    use chacha20poly1305::{
        ChaCha20Poly1305, Nonce,
        aead::{Aead, KeyInit},
    };
    use ectoledger::enclave::ipc::*;
    use sha2::{Digest, Sha256};
    use x25519_dalek::{PublicKey, StaticSecret};

    /// Full bidirectional round-trip: host sends prompt, guest responds.
    #[test]
    fn full_round_trip() {
        let mut page = vec![0u8; 4096];

        // ── Host side ──────────────────────────────────────────────────────
        let mut host = SharedMemoryChannel::new(&mut page);

        // Verify host pubkey written to page[0..32].
        let host_pk = &page[0..32];
        assert_ne!(host_pk, &[0u8; 32]);

        // ── Guest side (simulated) ─────────────────────────────────────────
        let guest_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let guest_pubkey = PublicKey::from(&guest_secret);
        page[32..64].copy_from_slice(guest_pubkey.as_bytes());

        // ── Handshake ──────────────────────────────────────────────────────
        host.handshake(&page).unwrap();

        // Guest derives the same key independently.
        let mut host_pk_bytes = [0u8; 32];
        host_pk_bytes.copy_from_slice(&page[0..32]);
        let guest_shared = guest_secret.diffie_hellman(&PublicKey::from(host_pk_bytes));
        let mut h = Sha256::new();
        h.update(b"ectoledger-enclave-ipc-v1");
        h.update(guest_shared.as_bytes());
        let guest_cipher = ChaCha20Poly1305::new_from_slice(&h.finalize()).unwrap();

        // ── Host → Guest (prompt) ──────────────────────────────────────────
        let prompt = b"Analyze the PCI-DSS compliance gaps.";
        host.send(&mut page, prompt).unwrap();
        assert_eq!(page[OFF_COMMAND], CMD_REQUEST_READY);

        // Guest decrypts.
        let req_len =
            u32::from_le_bytes(page[OFF_REQ_LEN..OFF_REQ_LEN + 4].try_into().unwrap()) as usize;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&page[OFF_PAYLOAD..OFF_PAYLOAD + 12]);
        let nonce = Nonce::from(nonce_bytes);
        let decrypted = guest_cipher
            .decrypt(&nonce, &page[OFF_PAYLOAD + 12..OFF_PAYLOAD + req_len])
            .expect("guest decrypt failed");
        assert_eq!(&decrypted, prompt);

        // ── Guest → Host (response) ────────────────────────────────────────
        let response = b"Found 3 critical gaps in requirement 6.";
        let mut resp_nonce = [0u8; 12];
        resp_nonce[0] = 1;
        let resp_ct = guest_cipher
            .encrypt(&Nonce::from(resp_nonce), response.as_ref())
            .unwrap();
        let resp_total = 12 + resp_ct.len();
        page[OFF_PAYLOAD..OFF_PAYLOAD + 12].copy_from_slice(&resp_nonce);
        page[OFF_PAYLOAD + 12..OFF_PAYLOAD + resp_total].copy_from_slice(&resp_ct);
        page[OFF_RESP_LEN..OFF_RESP_LEN + 4].copy_from_slice(&(resp_total as u32).to_le_bytes());
        page[OFF_STATUS] = STATUS_RESPONSE_READY;

        let plaintext = host.receive(&page).expect("host decrypt failed");
        assert_eq!(&plaintext, response);
    }

    /// Verifying the exact byte-range layout:
    ///   page[0..32]  = host pubkey
    ///   page[32..64] = guest pubkey
    ///   page[64]     = command byte
    ///   page[65]     = status byte
    #[test]
    fn memory_layout_byte_ranges() {
        let mut page = vec![0u8; 4096];
        let _host = SharedMemoryChannel::new(&mut page);

        // Host pubkey occupies exactly page[0..32].
        assert_ne!(
            &page[0..32],
            &[0u8; 32],
            "host pubkey must be at page[0..32]"
        );
        // Guest pubkey area page[32..64] must be zero (guest hasn't written).
        assert_eq!(
            &page[32..64],
            &[0u8; 32],
            "page[32..64] must be zero before guest writes"
        );
        // Control bytes.
        assert_eq!(page[64], 0x00, "command byte at page[64] must be idle");
        assert_eq!(page[65], 0x00, "status byte at page[65] must be idle");
        // Length fields at page[68..72] and page[72..76] must be zero.
        assert_eq!(&page[68..72], &[0u8; 4]);
        assert_eq!(&page[72..76], &[0u8; 4]);
    }

    /// Keys derived independently on host and guest sides must produce
    /// identical ciphertexts when given the same nonce and plaintext.
    #[test]
    fn symmetric_key_agreement() {
        let mut page = vec![0u8; 4096];
        let mut host = SharedMemoryChannel::new(&mut page);

        let guest_secret = StaticSecret::random_from_rng(rand::thread_rng());
        let guest_pubkey = PublicKey::from(&guest_secret);
        page[32..64].copy_from_slice(guest_pubkey.as_bytes());

        host.handshake(&page).unwrap();

        // Guest derives key.
        let mut hpk = [0u8; 32];
        hpk.copy_from_slice(&page[0..32]);
        let gs = guest_secret.diffie_hellman(&PublicKey::from(hpk));
        let mut h = Sha256::new();
        h.update(b"ectoledger-enclave-ipc-v1");
        h.update(gs.as_bytes());
        let guest_cipher = ChaCha20Poly1305::new_from_slice(&h.finalize()).unwrap();

        // Host encrypts.
        let msg = b"test";
        host.send(&mut page, msg).unwrap();

        // Guest decrypts — if this works, keys are identical.
        let len = u32::from_le_bytes(page[68..72].try_into().unwrap()) as usize;
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes.copy_from_slice(&page[80..92]);
        let nonce = Nonce::from(nonce_bytes);
        let pt = guest_cipher.decrypt(&nonce, &page[92..80 + len]).unwrap();
        assert_eq!(&pt, msg);
    }
}
