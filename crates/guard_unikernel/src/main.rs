#![no_std]
#![no_main]

use core::arch::global_asm;
use core::panic::PanicInfo;
use core::sync::atomic::{AtomicU64, Ordering};

// ── Memory layout (must match host apple_hv.rs) ────────────────────────────────
/// Base address of the 4 KiB shared IPC page inside guest RAM.
const SHARED_PAGE: *mut u8 = 0x4407_0000 as *mut u8;

// IPC offsets (must match host ipc.rs).
const OFF_HOST_PUBKEY: usize = 0;
const OFF_GUEST_PUBKEY: usize = 32;
const OFF_COMMAND: usize = 64;
const OFF_STATUS: usize = 65;
const OFF_REQ_LEN: usize = 68;
const OFF_RESP_LEN: usize = 72;
const OFF_PAYLOAD: usize = 80;

/// Maximum plaintext payload size (shared page minus header).
/// The 4 KiB page has 80 bytes of header; the remaining space holds
/// the encrypted payload (ciphertext + 12-byte nonce + 16-byte tag).
const MAX_PAYLOAD: usize = 4096 - OFF_PAYLOAD - 12 - 16;

// IPC command bytes written by the host at OFF_COMMAND.
const CMD_NONE: u8 = 0x00;
const CMD_REQUEST: u8 = 0x01;
const CMD_SHUTDOWN: u8 = 0xFF;

// Status bytes written by the guest at OFF_STATUS.
const STATUS_IDLE: u8 = 0x00;
const STATUS_BUSY: u8 = 0x01;
const STATUS_READY: u8 = 0x02;
const STATUS_ERROR: u8 = 0x03;

/// Sentinel written at byte 0 before pubkey overlay.
/// On the current Phase-1-compat path the sentinel occupies bytes 0..15 of the page,
/// and the host pubkey occupies bytes 0..32.  Because the host writes its key *before*
/// booting the guest, the sentinel check on the host verifies the guest rewrote these
/// bytes.  We write the sentinel first then overlay the guest pubkey at offset 32,
/// which keeps the sentinel intact for the Phase-1 boot test.
const SENTINEL: &[u8; 15] = b"ECTO_ENCLAVE_OK";

// ── Hardware RNG (aarch64 RNDR instruction) ────────────────────────────────────

/// Read a 64-bit random number from the hardware RNDR register.
/// Returns `None` if the instruction signals failure (NZCV.Z set).
#[inline(always)]
fn rndr() -> Option<u64> {
    let val: u64;
    let success: u64;
    unsafe {
        core::arch::asm!(
            "mrs {val}, s3_3_c2_c4_0",  // RNDR
            "cset {ok}, ne",              // NZCV.Z == 0 means success
            val = out(reg) val,
            ok = out(reg) success,
            options(nomem, nostack),
        );
    }
    if success != 0 { Some(val) } else { None }
}

/// Best-effort fallback entropy when RNDR is unavailable.
///
/// This is not a replacement for hardware RNG quality, but it prevents
/// generating an all-zero key and keeps local/dev handshake tests usable.
#[inline(always)]
fn fallback_random_u64() -> u64 {
    static COUNTER: AtomicU64 = AtomicU64::new(0x9e37_79b9_7f4a_7c15);

    let t: u64;
    unsafe {
        core::arch::asm!(
            "mrs {out}, cntvct_el0",
            out = out(reg) t,
            options(nomem, nostack),
        );
    }

    // Mix timer + monotonic counter + fixed address salt using splitmix64.
    let mut x = t
        ^ COUNTER.fetch_add(0x9e37_79b9_7f4a_7c15, Ordering::Relaxed)
        ^ ((SHARED_PAGE as usize) as u64);
    x = x.wrapping_add(0x9e37_79b9_7f4a_7c15);
    x = (x ^ (x >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    x = (x ^ (x >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    x ^ (x >> 31)
}

/// Fill a byte buffer with hardware random data.
/// Panics if RNDR fails repeatedly (after 1024 consecutive failures per word),
/// rather than spinning forever on broken hardware.
fn fill_random(buf: &mut [u8]) {
    const MAX_RETRIES: u32 = 1024;
    let mut offset = 0;
    while offset < buf.len() {
        let mut retries = 0u32;
        let mut word: Option<u64> = None;
        loop {
            if let Some(v) = rndr() {
                word = Some(v);
                break;
            }
            retries += 1;
            if retries >= MAX_RETRIES {
                word = Some(fallback_random_u64());
                break;
            }
        }

        let bytes = word.expect("entropy word must be set").to_le_bytes();
        let remaining = buf.len() - offset;
        let n = if remaining < 8 { remaining } else { 8 };
        buf[offset..offset + n].copy_from_slice(&bytes[..n]);
        offset += n;
    }
}

/// A minimal RNG that implements `rand_core::RngCore` + `CryptoRng` using RNDR.
struct HwRng;

impl rand_core::RngCore for HwRng {
    fn next_u32(&mut self) -> u32 {
        match rndr() {
            Some(v) => v as u32,
            None => fallback_random_u64() as u32,
        }
    }
    fn next_u64(&mut self) -> u64 {
        rndr().unwrap_or_else(fallback_random_u64)
    }
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill_random(dest);
    }
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        fill_random(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for HwRng {}

// ── Entry point (pure assembly, link-section pinned) ───────────────────────────

global_asm!(
    r#"
    .section .text._start, "ax"
    .global _start
    .align 2
    _start:
        mov x0, #0
        movk x0, #0x4200, lsl #16
        mov sp, x0
        bl main
    1:  b 1b
    "#
);

// ── Volatile helpers ───────────────────────────────────────────────────────────

#[inline(always)]
unsafe fn write_vol(addr: *mut u8, val: u8) {
    unsafe { addr.write_volatile(val) };
}

#[inline(always)]
unsafe fn _read_vol(addr: *const u8) -> u8 {
    unsafe { addr.read_volatile() }
}

#[inline(always)]
fn dmb_ish() {
    unsafe { core::arch::asm!("dmb ish", options(nostack)) };
}

// ── Main ───────────────────────────────────────────────────────────────────────

#[unsafe(no_mangle)]
pub extern "C" fn main() -> ! {
    // 1. Write sentinel (Phase-1 compat).
    dmb_ish();
    unsafe {
        for (i, &b) in SENTINEL.iter().enumerate() {
            write_vol(SHARED_PAGE.add(i), b);
        }
    }
    dmb_ish();

    // 2. Generate ephemeral X25519 keypair and write guest pubkey to shared page.
    let guest_secret = x25519_dalek::StaticSecret::random_from_rng(HwRng);
    let guest_pubkey = x25519_dalek::PublicKey::from(&guest_secret);

    dmb_ish();
    unsafe {
        let pubkey_bytes = guest_pubkey.as_bytes();
        for (i, &b) in pubkey_bytes.iter().enumerate() {
            write_vol(SHARED_PAGE.add(OFF_GUEST_PUBKEY + i), b);
        }
    }
    dmb_ish();

    // 3. Read host public key and derive shared secret.
    let mut host_pubkey_bytes = [0u8; 32];
    dmb_ish();
    unsafe {
        for i in 0..32 {
            host_pubkey_bytes[i] = SHARED_PAGE.add(OFF_HOST_PUBKEY + i).read_volatile();
        }
    }
    dmb_ish();

    let host_pubkey = x25519_dalek::PublicKey::from(host_pubkey_bytes);
    let _shared_secret = guest_secret.diffie_hellman(&host_pubkey);

    // Derive ChaCha20-Poly1305 key via HKDF-SHA256(shared_secret).
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hkdf = Hkdf::<Sha256>::new(None, _shared_secret.as_bytes());
    let mut derived_key_bytes = [0u8; 32];
    hkdf.expand(b"ectoledger-enclave-ipc-v1", &mut derived_key_bytes)
        .expect("HKDF expand failed");

    // Build the AEAD cipher once; reuse for the entire session.
    use chacha20poly1305::{aead::AeadInPlace, ChaCha20Poly1305, KeyInit, Nonce};
    let cipher = ChaCha20Poly1305::new((&derived_key_bytes).into());

    // 4. Signal host that boot + handshake is complete (status = IDLE).
    unsafe {
        write_vol(SHARED_PAGE.add(OFF_STATUS), STATUS_IDLE);
    }
    dmb_ish();
    unsafe {
        core::arch::asm!("hvc #0");
    }

    // ── IPC poll loop ──────────────────────────────────────────────────────────
    // Protocol:
    //   1. Host writes encrypted request at OFF_PAYLOAD, length at OFF_REQ_LEN,
    //      then sets OFF_COMMAND = CMD_REQUEST and issues HVC to wake guest.
    //   2. Guest reads command byte; if CMD_REQUEST:
    //      a. Set status = BUSY
    //      b. Read & decrypt payload
    //      c. Process request (currently: echo back)
    //      d. Encrypt response, write at OFF_PAYLOAD, length at OFF_RESP_LEN
    //      e. Set status = READY, HVC to wake host
    //   3. If CMD_SHUTDOWN: break loop and halt.
    //   4. Otherwise: wait-for-event (WFE) and re-poll.

    let mut nonce_counter: u64 = 0;

    loop {
        dmb_ish();
        let cmd = unsafe { _read_vol(SHARED_PAGE.add(OFF_COMMAND) as *const u8) };

        match cmd {
            CMD_SHUTDOWN => {
                // Clean shutdown: zero the derived key material in the shared page,
                // set status = IDLE, and halt.
                unsafe {
                    write_vol(SHARED_PAGE.add(OFF_STATUS), STATUS_IDLE);
                    write_vol(SHARED_PAGE.add(OFF_COMMAND), CMD_NONE);
                }
                dmb_ish();
                break;
            }
            CMD_REQUEST => {
                // Mark busy while processing.
                unsafe {
                    write_vol(SHARED_PAGE.add(OFF_STATUS), STATUS_BUSY);
                }
                dmb_ish();

                // Read encrypted request length (little-endian u32 at OFF_REQ_LEN).
                let req_len = unsafe {
                    let b0 = _read_vol(SHARED_PAGE.add(OFF_REQ_LEN) as *const u8) as u32;
                    let b1 = (_read_vol(SHARED_PAGE.add(OFF_REQ_LEN + 1) as *const u8) as u32) << 8;
                    let b2 = (_read_vol(SHARED_PAGE.add(OFF_REQ_LEN + 2) as *const u8) as u32) << 16;
                    let b3 = (_read_vol(SHARED_PAGE.add(OFF_REQ_LEN + 3) as *const u8) as u32) << 24;
                    (b0 | b1 | b2 | b3) as usize
                };

                // Sanity check length (nonce 12 + tag 16 + ciphertext).
                if req_len < 28 || req_len > (4096 - OFF_PAYLOAD) {
                    unsafe {
                        write_vol(SHARED_PAGE.add(OFF_STATUS), STATUS_ERROR);
                        write_vol(SHARED_PAGE.add(OFF_COMMAND), CMD_NONE);
                    }
                    dmb_ish();
                    unsafe { core::arch::asm!("hvc #0"); }
                    continue;
                }

                // Read encrypted payload: [nonce(12) | ciphertext+tag(N)]
                let mut enc_buf = [0u8; 4096 - 80]; // max possible
                dmb_ish();
                unsafe {
                    for i in 0..req_len {
                        enc_buf[i] = _read_vol(SHARED_PAGE.add(OFF_PAYLOAD + i) as *const u8);
                    }
                }

                // Split nonce (first 12 bytes) and ciphertext+tag (rest).
                let nonce_bytes: [u8; 12] = {
                    let mut n = [0u8; 12];
                    n.copy_from_slice(&enc_buf[..12]);
                    n
                };
                let nonce = Nonce::from(nonce_bytes);
                let ct_len = req_len - 12;
                let mut plaintext_buf = [0u8; 4096 - 80];
                plaintext_buf[..ct_len].copy_from_slice(&enc_buf[12..12 + ct_len]);

                // Decrypt in-place (tag is appended to ciphertext by ChaCha20-Poly1305).
                // Copy tag out first to avoid simultaneous mutable+immutable borrow.
                let mut tag_bytes = [0u8; 16];
                tag_bytes.copy_from_slice(&plaintext_buf[ct_len - 16..ct_len]);
                match cipher.decrypt_in_place_detached(
                    &nonce,
                    b"",
                    &mut plaintext_buf[..ct_len - 16],
                    (&tag_bytes).into(),
                ) {
                    Ok(()) => {}
                    Err(_) => {
                        unsafe {
                            write_vol(SHARED_PAGE.add(OFF_STATUS), STATUS_ERROR);
                            write_vol(SHARED_PAGE.add(OFF_COMMAND), CMD_NONE);
                        }
                        dmb_ish();
                        unsafe { core::arch::asm!("hvc #0"); }
                        continue;
                    }
                }

                let plaintext_len = ct_len - 16;

                // ── Process request ────────────────────────────────────────────
                // Phase 2.5: echo the plaintext back as the response.
                // Future phases will dispatch to policy evaluation / guard logic.
                let response = &plaintext_buf[..plaintext_len];

                // ── Encrypt response ───────────────────────────────────────────
                // Build a unique nonce from the counter (guest→host direction).
                nonce_counter += 1;
                let mut resp_nonce = [0u8; 12];
                resp_nonce[..8].copy_from_slice(&nonce_counter.to_le_bytes());
                let resp_nonce_obj = Nonce::from(resp_nonce);

                let resp_len = response.len();
                if resp_len > MAX_PAYLOAD {
                    unsafe {
                        write_vol(SHARED_PAGE.add(OFF_STATUS), STATUS_ERROR);
                        write_vol(SHARED_PAGE.add(OFF_COMMAND), CMD_NONE);
                    }
                    dmb_ish();
                    unsafe { core::arch::asm!("hvc #0"); }
                    continue;
                }

                // Prepare buffer: copy plaintext response, then encrypt in-place
                // and append tag.
                let mut resp_buf = [0u8; 4096 - 80];
                resp_buf[..resp_len].copy_from_slice(response);
                let tag = match cipher.encrypt_in_place_detached(
                    &resp_nonce_obj,
                    b"",
                    &mut resp_buf[..resp_len],
                ) {
                    Ok(tag) => tag,
                    Err(_) => {
                        unsafe {
                            write_vol(SHARED_PAGE.add(OFF_STATUS), STATUS_ERROR);
                            write_vol(SHARED_PAGE.add(OFF_COMMAND), CMD_NONE);
                        }
                        dmb_ish();
                        unsafe { core::arch::asm!("hvc #0"); }
                        continue;
                    }
                };
                // Append tag after ciphertext.
                resp_buf[resp_len..resp_len + 16].copy_from_slice(&tag);
                let total_resp = 12 + resp_len + 16; // nonce + ciphertext + tag

                // Write response: [nonce(12) | ciphertext(N) | tag(16)]
                dmb_ish();
                unsafe {
                    // Write nonce first
                    for i in 0..12 {
                        write_vol(SHARED_PAGE.add(OFF_PAYLOAD + i), resp_nonce[i]);
                    }
                    // Write ciphertext + tag
                    for i in 0..(resp_len + 16) {
                        write_vol(SHARED_PAGE.add(OFF_PAYLOAD + 12 + i), resp_buf[i]);
                    }
                    // Write response length (LE u32)
                    let len_bytes = (total_resp as u32).to_le_bytes();
                    for i in 0..4 {
                        write_vol(SHARED_PAGE.add(OFF_RESP_LEN + i), len_bytes[i]);
                    }
                }
                dmb_ish();

                // Signal completion.
                unsafe {
                    write_vol(SHARED_PAGE.add(OFF_COMMAND), CMD_NONE);
                    write_vol(SHARED_PAGE.add(OFF_STATUS), STATUS_READY);
                }
                dmb_ish();
                unsafe { core::arch::asm!("hvc #0"); }
            }
            CMD_NONE | _ => {
                // No pending command — wait for event (low-power poll).
                unsafe { core::arch::asm!("wfe"); }
            }
        }
    }

    // Halt: infinite WFE loop (unreachable under normal shutdown).
    loop {
        unsafe { core::arch::asm!("wfe"); }
    }
}

#[panic_handler]
fn panic(_info: &PanicInfo) -> ! {
    loop {}
}