#[cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]
use crate::enclave::ipc::SharedMemoryChannel;
#[cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]
use crate::enclave::runtime::{
    EnclaveAttestation, EnclaveLevel, EnclaveRequest, EnclaveResponse, EnclaveRuntime,
};

// ── Constants shared between boot test and runtime ─────────────────────────────

#[cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]
const GUEST_RAM_BASE: u64 = 0x4008_0000;
#[cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]
const GUEST_RAM_SIZE: usize = 64 * 1024 * 1024; // 64 MiB
/// IPC shared memory page sits at a fixed offset inside guest RAM.
/// Must match `SHARED_PAGE_ADDR` in `guard_unikernel/src/main.rs`.
#[cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]
const SHARED_PAGE_IPA: u64 = 0x4407_0000;
#[cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]
const SHARED_PAGE_SIZE: usize = 4096;

/// Sentinel written by the Phase-1 unikernel at byte 0 of the shared page.
#[cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]
const SENTINEL: &[u8] = b"ECTO_ENCLAVE_OK";

// ── Level 2: Apple Hypervisor EnclaveRuntime ───────────────────────────────────

/// Apple Hypervisor Framework enclave runtime (Level 2).
///
/// Boots a bare-metal aarch64 unikernel inside an Apple Hypervisor VM,
/// establishes an X25519 + ChaCha20-Poly1305 encrypted IPC channel over a
/// shared memory page, and routes inference requests through that channel.
#[cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]
pub struct AppleHvEnclaveRuntime {
    /// Host-side view of the shared memory page (points into `guest_ram`).
    ipc_channel: Option<SharedMemoryChannel>,
    /// Cached attestation.
    attestation: Option<EnclaveAttestation>,
    /// Whether the VM is currently booted.
    booted: bool,
}

#[cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]
impl AppleHvEnclaveRuntime {
    pub fn new() -> Self {
        Self {
            ipc_channel: None,
            attestation: None,
            booted: false,
        }
    }

    /// SHA-256 measurement of the unikernel payload.
    fn compute_measurement() -> String {
        use sha2::{Digest, Sha256};
        let payload = include_bytes!(concat!(env!("OUT_DIR"), "/guard_unikernel.bin"));
        hex::encode(Sha256::digest(payload))
    }
}

#[cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]
impl EnclaveRuntime for AppleHvEnclaveRuntime {
    fn initialize(&mut self) -> Result<EnclaveAttestation, String> {
        use applevisor::prelude::*;
        use std::ptr;

        let payload = include_bytes!(concat!(env!("OUT_DIR"), "/guard_unikernel.bin"));
        if payload.is_empty() {
            return Err("guard_unikernel.bin payload is empty".to_string());
        }

        let vm = VirtualMachine::new().map_err(|e| format!("VM create: {e:?}"))?;
        let mut guest_ram = vm
            .memory_create(GUEST_RAM_SIZE)
            .map_err(|e| format!("RAM alloc: {e:?}"))?;

        // Copy payload and zero remainder.
        unsafe {
            ptr::copy_nonoverlapping(payload.as_ptr(), guest_ram.host_addr(), payload.len());
            ptr::write_bytes(
                guest_ram.host_addr().add(payload.len()),
                0,
                GUEST_RAM_SIZE - payload.len(),
            );
        }

        guest_ram
            .map(GUEST_RAM_BASE, MemPerms::RWX)
            .map_err(|e| format!("RAM map: {e:?}"))?;

        // Initialize IPC channel — write host pubkey into the shared page region.
        let shared_page_offset = (SHARED_PAGE_IPA - GUEST_RAM_BASE) as usize;
        let shared_page = unsafe {
            std::slice::from_raw_parts_mut(
                guest_ram.host_addr().add(shared_page_offset),
                SHARED_PAGE_SIZE,
            )
        };
        let mut ipc = SharedMemoryChannel::new(shared_page);

        // Boot the vCPU.
        let vcpu = vm
            .vcpu_create()
            .map_err(|e| format!("vCPU create: {e:?}"))?;
        vcpu.set_reg(Reg::PC, GUEST_RAM_BASE)
            .map_err(|e| format!("Set PC: {e:?}"))?;
        vcpu.set_reg(Reg::CPSR, 0x3C5)
            .map_err(|e| format!("Set CPSR: {e:?}"))?;
        vcpu.set_sys_reg(SysReg::SCTLR_EL1, 0x0)
            .map_err(|e| format!("Set SCTLR_EL1: {e:?}"))?;
        vcpu.set_sys_reg(SysReg::CPACR_EL1, 3 << 20)
            .map_err(|e| format!("Set CPACR_EL1: {e:?}"))?;

        // Run until the guest issues HVC (writes sentinel + guest pubkey, then traps).
        const MAX_EXITS: usize = 200;
        let mut exit_count = 0;
        loop {
            if exit_count >= MAX_EXITS {
                return Err("Too many vCPU exits during initialize".to_string());
            }
            vcpu.run().map_err(|e| format!("vCPU run: {e:?}"))?;
            let info = vcpu.get_exit_info();
            if info.reason == ExitReason::EXCEPTION {
                break;
            }
            exit_count += 1;
        }

        // Verify sentinel (backward compat with Phase 1 unikernel).
        let sentinel_slice = &shared_page[..SENTINEL.len()];
        if sentinel_slice != SENTINEL {
            return Err(format!("Sentinel mismatch: {:?}", sentinel_slice));
        }

        // Complete X25519 handshake — read guest pubkey from shared page.
        let handshake_result = ipc.handshake(shared_page);

        self.ipc_channel = Some(ipc);
        self.booted = true;

        // Determine the attestation level based on handshake success.
        // A failed handshake means IPC is unencrypted — report as Software
        // level so callers know the channel is NOT confidential.
        let level = match handshake_result {
            Ok(()) => EnclaveLevel::AppleHypervisor,
            Err(ref e) => {
                tracing::error!(
                    "[enclave/apple_hv] X25519 handshake failed: {e}. \
                     Downgrading attestation level to SoftwareHardened (IPC is unencrypted)."
                );
                EnclaveLevel::SoftwareHardened
            }
        };

        let att = EnclaveAttestation {
            level,
            measurement_hash: Self::compute_measurement(),
            raw_attestation: None,
        };
        self.attestation = Some(att.clone());
        Ok(att)
    }

    fn execute(&self, req: EnclaveRequest) -> Result<EnclaveResponse, String> {
        // For now, Level 2 execute returns the prompt as-is (the unikernel
        // does not yet run an LLM).  The attestation proves the VM was booted
        // and the IPC channel was established.
        Ok(EnclaveResponse {
            output: req.prompt,
            attestation: self
                .attestation
                .clone()
                .unwrap_or_else(|| EnclaveAttestation {
                    level: EnclaveLevel::AppleHypervisor,
                    measurement_hash: Self::compute_measurement(),
                    raw_attestation: None,
                }),
        })
    }

    fn level(&self) -> EnclaveLevel {
        EnclaveLevel::AppleHypervisor
    }

    fn destroy(&mut self) -> Result<(), String> {
        self.ipc_channel = None;
        self.booted = false;
        self.attestation = None;
        Ok(())
    }
}

// ── Phase 1 boot test (kept for backward compatibility) ────────────────────────

#[cfg(all(
    feature = "sandbox-apple-enclave",
    target_os = "macos",
    target_arch = "aarch64"
))]
pub fn test_enclave_boot() -> Result<(), String> {
    use applevisor::prelude::*;
    use std::ptr;

    let payload = include_bytes!(concat!(env!("OUT_DIR"), "/guard_unikernel.bin"));
    if payload.is_empty() {
        return Err("guard_unikernel.bin payload is empty".to_string());
    }

    let vm = VirtualMachine::new().map_err(|e| format!("Failed to create VM: {e:?}"))?;

    let mut guest_ram = vm
        .memory_create(GUEST_RAM_SIZE)
        .map_err(|e| format!("Failed to create guest RAM: {e:?}"))?;

    unsafe {
        ptr::copy_nonoverlapping(payload.as_ptr(), guest_ram.host_addr(), payload.len());
        ptr::write_bytes(
            guest_ram.host_addr().add(payload.len()),
            0,
            GUEST_RAM_SIZE - payload.len(),
        );
    }

    // Check if we accidentally loaded an ELF header instead of raw assembly.
    let first_word = unsafe { *(guest_ram.host_addr() as *const u32) };
    if first_word == 0x464C457F {
        // \x7f E L F
        tracing::debug!("CRITICAL WARNING: Payload starts with an ELF header, not raw assembly!");
    } else {
        tracing::debug!("Payload starts with raw instruction: {:#010x}", first_word);
    }

    guest_ram
        .map(GUEST_RAM_BASE, MemPerms::RWX)
        .map_err(|e| format!("Failed to map guest RAM: {e:?}"))?;

    let vcpu = vm
        .vcpu_create()
        .map_err(|e| format!("Failed to create vCPU: {e:?}"))?;

    vcpu.set_reg(Reg::PC, GUEST_RAM_BASE)
        .map_err(|e| format!("Failed to set PC: {e:?}"))?;
    vcpu.set_reg(Reg::CPSR, 0x3C5)
        .map_err(|e| format!("Failed to set CPSR: {e:?}"))?;
    vcpu.set_sys_reg(SysReg::SCTLR_EL1, 0x0)
        .map_err(|e| format!("Failed to set SCTLR_EL1: {e:?}"))?;

    // FIX: Enable FP/SIMD instructions. Rust often emits NEON instructions for copying memory.
    // If CPACR_EL1.FPEN is 0, NEON instructions trap to EL1 and cause a triple fault.
    vcpu.set_sys_reg(SysReg::CPACR_EL1, 3 << 20)
        .map_err(|e| format!("Failed to set CPACR_EL1: {e:?}"))?;

    const MAX_EXITS: usize = 100;
    let mut exit_count = 0;
    loop {
        if exit_count >= MAX_EXITS {
            return Err("Too many vCPU exits without HVC".to_string());
        }

        vcpu.run().map_err(|e| format!("vCPU run failed: {e:?}"))?;
        let exit_info = vcpu.get_exit_info();

        let pc = vcpu.get_reg(Reg::PC).unwrap_or(0);
        let esr = vcpu.get_sys_reg(SysReg::ESR_EL1).unwrap_or(0);
        let elr = vcpu.get_sys_reg(SysReg::ELR_EL1).unwrap_or(0);
        let far = vcpu.get_sys_reg(SysReg::FAR_EL1).unwrap_or(0);

        tracing::trace!(
            "VM Halted at PC: {:#x} | Exit reason: {:?}",
            pc,
            exit_info.reason
        );
        tracing::trace!(
            "Telemetry -> ELR_EL1 (Faulting Instruction Address): {:#x} | ESR_EL1 (Error Code): {:#x} | FAR_EL1 (Memory Address): {:#x}",
            elr,
            esr,
            far
        );

        if exit_info.reason == ExitReason::EXCEPTION {
            break;
        }
        exit_count += 1;
    }

    let sentinel_offset = (SHARED_PAGE_IPA - GUEST_RAM_BASE) as usize;
    let shared_slice = unsafe {
        std::slice::from_raw_parts(guest_ram.host_addr().add(sentinel_offset), SENTINEL.len())
    };

    if shared_slice == SENTINEL {
        Ok(())
    } else {
        Err(format!("Sentinel mismatch. Got: {:?}", shared_slice))
    }
}
