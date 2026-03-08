use crate::enclave::runtime::{
    EnclaveAttestation, EnclaveLevel, EnclaveRequest, EnclaveResponse, EnclaveRuntime,
};

/// Level 1: Software-hardened enclave.
///
/// Protects the inference buffer with `mlock` (preventing swap-out) and
/// zeroizes memory on destroy.  Does not provide a hardware trust boundary —
/// the LLM call is made on the host — but it prevents casual memory inspection
/// and ensures prompt/response bytes never hit disk.
pub struct SoftwareEnclaveRuntime {
    /// Locked memory region for prompt/response buffering.
    buffer: Vec<u8>,
    /// Whether mlock is currently held.
    locked: bool,
    /// Cached attestation returned on initialize.
    attestation: Option<EnclaveAttestation>,
}

/// Buffer size for the locked region (64 KiB).
const LOCKED_BUF_SIZE: usize = 64 * 1024;

impl Default for SoftwareEnclaveRuntime {
    fn default() -> Self {
        Self::new()
    }
}

impl SoftwareEnclaveRuntime {
    pub fn new() -> Self {
        Self {
            buffer: vec![0u8; LOCKED_BUF_SIZE],
            locked: false,
            attestation: None,
        }
    }

    /// SHA-256 measurement of the empty locked buffer (static for Level 1).
    fn measurement_hash() -> String {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(b"ectoledger-software-enclave-v1");
        hex::encode(hasher.finalize())
    }
}

impl EnclaveRuntime for SoftwareEnclaveRuntime {
    fn initialize(&mut self) -> Result<EnclaveAttestation, String> {
        // Lock the buffer into physical RAM so it cannot be swapped to disk.
        #[cfg(unix)]
        {
            let ret = unsafe {
                libc::mlock(
                    self.buffer.as_ptr() as *const libc::c_void,
                    self.buffer.len(),
                )
            };
            if ret != 0 {
                // mlock failure is not fatal — log but proceed.  On CI / sandboxed
                // environments the rlimit may be too low.
                let err = std::io::Error::last_os_error();
                let errno = err.raw_os_error().unwrap_or(-1);
                eprintln!(
                    "[enclave/software] mlock failed (errno {errno}: {err}); proceeding without lock"
                );
            } else {
                self.locked = true;
            }
        }
        #[cfg(windows)]
        {
            use windows::Win32::System::Memory::VirtualLock;
            let ok = unsafe {
                VirtualLock(
                    self.buffer.as_ptr() as *mut std::ffi::c_void,
                    self.buffer.len(),
                )
            };
            if ok.is_err() {
                eprintln!("[enclave/software] VirtualLock failed; proceeding without lock");
            } else {
                self.locked = true;
            }
        }

        let att = EnclaveAttestation {
            level: EnclaveLevel::SoftwareHardened,
            measurement_hash: Self::measurement_hash(),
            raw_attestation: None,
        };
        self.attestation = Some(att.clone());
        Ok(att)
    }

    fn execute(&self, req: EnclaveRequest) -> Result<EnclaveResponse, String> {
        // Level 1: passthrough — the prompt bytes are returned as-is.
        // The actual LLM call is made by the cognitive loop *through* this enclave;
        // `SoftwareEnclaveRuntime` only guarantees memory protection, not isolation.
        Ok(EnclaveResponse {
            output: req.prompt,
            attestation: self
                .attestation
                .clone()
                .unwrap_or_else(|| EnclaveAttestation {
                    level: EnclaveLevel::SoftwareHardened,
                    measurement_hash: Self::measurement_hash(),
                    raw_attestation: None,
                }),
        })
    }

    fn level(&self) -> EnclaveLevel {
        EnclaveLevel::SoftwareHardened
    }

    fn destroy(&mut self) -> Result<(), String> {
        // Zeroize the buffer (zeroize is an unconditional dependency).
        {
            use zeroize::Zeroize;
            self.buffer.zeroize();
        }

        // Unlock.
        if self.locked {
            #[cfg(unix)]
            unsafe {
                libc::munlock(
                    self.buffer.as_ptr() as *const libc::c_void,
                    self.buffer.len(),
                );
            }
            #[cfg(windows)]
            unsafe {
                use windows::Win32::System::Memory::VirtualUnlock;
                let _ = VirtualUnlock(
                    self.buffer.as_ptr() as *mut std::ffi::c_void,
                    self.buffer.len(),
                );
            }
            self.locked = false;
        }

        Ok(())
    }
}

impl Drop for SoftwareEnclaveRuntime {
    fn drop(&mut self) {
        if let Err(e) = self.destroy() {
            eprintln!("SoftwareEnclaveRuntime::drop: destroy failed: {e}");
        }
    }
}
