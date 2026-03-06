# Cross-Platform Sandbox Parity Documentation

## Overview

Ecto Ledger provides multiple sandboxing mechanisms to isolate untrusted code execution:
- **Linux**: Landlock (LSM) + seccomp-BPF + rlimits
- **macOS**: Seatbelt (sandbox_init FFI) — deprecated API but functional; graceful fallback to tripwires
- **Windows**: Job Objects with UI restrictions
- **Cross-platform**: Docker/Podman containers + Firecracker microVMs

This document outlines the implementation details, security properties, and parity analysis of each platform.

## Platform Support Matrix

| Feature | Linux | macOS | Windows | Docker | Firecracker | Enclave L1 | Enclave L2 | Enclave L3 |
|---------|-------|-------|---------|--------|-------------|------------|------------|------------|
| Filesystem isolation | ✅ Landlock | ⚠️ Seatbelt (ws r/w only) | ⚠️ Job Object | ✅ Read-only | ✅ Guest FS | ❌ | ✅ Guest VM | ✅ Remote TEE |
| Process isolation | ✅ Seccomp | ⚠️ deny process-exec | ✅ Job Object | ✅ Container | ✅ microVM | ❌ | ✅ vCPU | ✅ TEE |
| Resource limits | ✅ rlimits | ❌ not enforced | ⚠️ Job Object | ✅ cgroups | ✅ vCPU/Mem | ❌ | ✅ VM config | ✅ Enclave config |
| Memory confidentiality | ❌ | ❌ | ❌ | ❌ | ⚠️ KVM | ✅ mlock+zeroize | ✅ HV isolation | ✅ HW encryption |
| Attestation | ❌ | ❌ | ❌ | ❌ | ❌ | ⚠️ Self-report | ✅ vCPU state | ✅ COSE-Sign1 |
| Cross-platform | N/A | N/A | N/A | ✅ Yes | ❌ Linux only | ✅ All | ❌ macOS only | ✅ Linux/Win |

## Detailed Implementation Analysis

### Linux Sandbox (Landlock + seccomp-BPF)

**When enabled**: Compile with `--features sandbox` on Linux

#### Landlock (Read-only Workspace)
- **LSM module** providing MAC (Mandatory Access Control)
- **Rules**: Read-only access to workspace directory tree
- **Fallback**: If kernel ABI is too old, warns but continues (best-effort)
- **Code reference**: `crates/host/src/sandbox.rs:apply_landlock()`

```rust
// Landlock V3 ABI
- Read-only access to specified workspace path
- Denies all write operations inside workspace
```

#### seccomp-BPF (Strict Syscall Allowlist)
- **Target**: Guard-worker process (model validation subprocess)
- **Mode**: EPERM on denied syscalls (not KILL, so errors surface)
- **Denied**: ptrace, process_vm_readv, kexec_load, and all others not on allowlist
- **Allowed syscalls**: ~70 syscalls for tokio, HTTP, stdin/stdout JSON protocol
- **Architecture support**: x86_64, aarch64 (silent no-op on others)
- **Code reference**: `crates/host/src/sandbox.rs:apply_guard_worker_seccomp()`

#### Resource Limits (rlimits)
- **CPU time**: 30 seconds hard limit (RLIMIT_CPU)
- **Address space**: 512 MiB max (RLIMIT_AS)
- **File descriptors**: 64 max (RLIMIT_NOFILE) — prevents FD exhaustion attacks
- **Code reference**: `crates/host/src/sandbox.rs:apply_rlimits()`

**Security properties**:
- ✅ Kernel-enforced isolation (cannot be bypassed from userspace)
- ✅ Multi-layer defense: filesystem + process + resource limits
- ✅ Prevents prompt-injection attacks via binary execution
- ⚠️ Requires Linux kernel ≥ 5.13 (Landlock support)
- ⚠️ Landlock LSM must not be disabled in kernel config

---

### macOS Sandbox (Seatbelt)

**Status**: ⚠️ **SUPPORTED (deprecated API, graceful fallback)**

#### Implementation:

Ecto Ledger calls Apple's `sandbox_init()` C API via FFI to apply a Seatbelt
profile to each child process. While Apple has deprecated the public header,
the underlying XNU sandbox enforcement mechanism is still active and used by
first-party macOS system services.

**Seatbelt profile enforces:**
- Read-only access to system libraries (`/usr/lib`, `/System`, `/Library/Frameworks`)
- Read/write access restricted to the workspace directory only
- `(deny network*)` — blocks all network access from child processes
- `(deny process-exec)` — prevents spawning further sub-processes
- `(deny signal)` — prevents signal injection

**Graceful fallback:** If `sandbox_init()` fails at runtime (e.g., on a future
macOS version that removes the API), the error is logged as a warning and the
child process continues with advisory tripwire protection only. This ensures
the build never breaks due to macOS API deprecation.

#### Known limitations:

1. **No per-process network isolation**: Seatbelt `(deny network*)` blocks
   socket creation but the parent process retains full network access
2. **No resource limits**: macOS has no rlimit-equivalent enforcement via Seatbelt
3. **API stability risk**: `sandbox_init()` may be removed in future macOS releases
4. **Landlock/seccomp unavailable**: These are Linux-only; Seatbelt is the macOS equivalent

#### Recommendation for macOS production users:

```bash
# Option 1: Run inside Linux container (recommended)
docker run -it --rm \
  -v /path/to/audit:/audit \
  -e AGENT_LLAMA_URL=http://host.docker.internal:11434 \
  ghcr.io/ectoledger/agent-ledger:latest \
  audit "Your audit goal"

# Option 2: Run inside Lima VM (macOS Docker Desktop alternative)
# or Colima

# Option 3: Accept no kernel-level isolation
# - Document as non-production or dev-only
# - Rely on process isolation + Docker/Podman containers for `run_command`
```

#### Current behavior on macOS:
```rust
pub fn apply_child_sandbox(workspace: &Path) -> Result<(), SandboxError> {
    #[cfg(target_os = "macos")]
    {
        apply_seatbelt(workspace)?;  // sandbox_init FFI
    }
}
```

- Seatbelt profile applied to each child process via Unix `pre_exec` hook
- If `sandbox_init()` fails, logs warning and falls back to advisory tripwires
- Docker/Podman sandboxes are still available for `run_command` intents
- Firecracker is not available (Linux + KVM only)

---

### Windows Sandbox (Job Objects)

**When enabled**: Automatically on Windows (no feature flag required)

#### Job Object Implementation
- **Windows API**: `CreateJobObjectW()` + `AssignProcessToJobObject()`
- **Scope**: Applies to all child processes spawned by Ecto Ledger
- **Reference**: `crates/host/src/sandbox.rs:apply_windows_job_object()`

#### Configuration
1. **KILL_ON_JOB_CLOSE**: Ensures child processes are terminated when job handle closes
   - Prevents orphan LLM tool processes
   - Guarantees cleanup on supervisor crash

2. **UI Restrictions** (JOBOBJECT_BASIC_UI_RESTRICTIONS):
   - `UILIMIT_DESKTOP` — no desktop switching
   - `UILIMIT_DISPLAYSETTINGS` — no display mode changes
   - `UILIMIT_EXITWINDOWS` — no log-off/shutdown
   - `UILIMIT_GLOBALATOMS` — no global atom table access
   - `UILIMIT_HANDLES` — no raw handle access
   - `UILIMIT_READCLIPBOARD` — no clipboard theft
   - `UILIMIT_WRITECLIPBOARD` — no clipboard injection
   - `UILIMIT_SYSTEMPARAMETERS` — no system parameter changes

**Security properties**:
- ✅ Guarantees process cleanup (no orphan processes)
- ✅ Prevents UI escalation vectors (clipboard, display settings)
- ⚠️ **Limited filesystem isolation**: Job Objects do not restrict file access; relies on NTFS permissions
- ⚠️ **No syscall filtering**: Cannot prevent dangerous Windows APIs
- ⚠️ **Cooperative model**: Process can still execute most code before job termination

**Limitations vs. Linux**:
| Aspect | Linux | Windows |
|--------|-------|---------|
| Filesystem access control | ✅ Landlock read-only enforcement | ⚠️ NTFS ACLs only (process-controlled) |
| Syscall filtering | ✅ seccomp-BPF blocks dangerous syscalls | ❌ No equivalent (user-mode hook needed) |
| Resource limits | ✅ rlimits (CPU, memory, FDs) | ⚠️ Job Objects support memory/CPU but not enforced uniformly |
| Process isolation | ✅ seccomp + rlimits | ✅ Job Object cleanup guarantee |

---

## Container & MicroVM Sandboxes

### Docker/Podman (Cross-platform)

**Availability**: Linux, macOS (via Docker Desktop), Windows (via WSL2 or native)

**Configuration**: 
```bash
export ECTO_DOCKER_IMAGE=alpine:3.19
export ECTO_DOCKER_MEMORY=256m
export ECTO_DOCKER_CPUS=1
export ECTO_DOCKER_TIMEOUT=30
export ECTO_DOCKER_RUNTIME=auto  # auto-detect docker or podman
```

**Isolation guarantees**:
- ✅ `--network=none` — no network access
- ✅ `--read-only` — immutable root filesystem
- ✅ `--security-opt no-new-privileges` — blocks privilege escalation
- ✅ `--user nobody` — unprivileged execution
- ✅ `--memory` / `--cpus` — resource limits via cgroups

**Use case**: Recommended for dev/test and for macOS production (where native sandboxing is unavailable)

---

### Firecracker (Linux + KVM only)

**Availability**: Linux with KVM support (compile with `--features sandbox-firecracker`)

**Prerequisites**:
- Firecracker binary (≥1.5) at configurable path
- Linux kernel image (`vmlinux`)
- Root filesystem image (`rootfs.ext4`)

**Isolation guarantees**:
- ✅ Hardware-level KVM isolation (hypervisor-based)
- ✅ Each `run_command` in ephemeral microVM
- ✅ Guest kernel enforces isolation
- ✅ microVM destroyed after command completes

**Use case**: Maximum security for untrusted prompt injection attacks; suitable for multi-tenant SaaS

---

## Confidential AI Enclave Architecture

Ecto Ledger provides a three-tier enclave architecture that places AI inference inside a confidentiality boundary invisible to the host OS. Each tier offers increasing hardware isolation and produces attestation evidence embedded in `.elc` certificates.

### Enclave Level 1 — Software Hardened

**Feature flag**: `--features enclave`  
**Platforms**: All (Linux, macOS, Windows)  
**Code**: `crates/host/src/enclave/software.rs`

**Mechanism**:
- `libc::mlock()` pins inference buffers in physical RAM (prevents swap-to-disk)
- All buffers are `zeroize`d on drop (prevents cold-boot recovery)
- Delegates to the existing `LlmBackend` for actual inference

**Security properties**:
- ✅ Prevents secrets leaking to swap / page file
- ✅ Zeroizes memory on teardown
- ⚠️ No process isolation — host OS can still read memory
- ⚠️ Attestation is self-reported (no hardware root of trust)

**Attestation**: SHA-256 of the LLM backend identifier; no raw blob.

---

### Enclave Level 2 — Apple Hypervisor (macOS aarch64)

**Feature flag**: `--features sandbox-apple-enclave`  
**Platforms**: macOS on Apple Silicon only  
**Code**: `crates/host/src/enclave/apple_hv.rs` + `crates/guard_unikernel/`

**Mechanism**:
1. A bare-metal aarch64 unikernel (`guard_unikernel`) is compiled to `aarch64-unknown-none` and stripped to raw machine code via `llvm-objcopy`.
2. The host boots the unikernel inside an Apple Hypervisor Framework VM (`applevisor` crate).
3. A 4 KiB shared memory page at guest physical `0x10000000` provides the IPC channel.
4. X25519 key exchange + ChaCha20-Poly1305 AEAD encrypts all prompt/response data over the shared page.
5. The guest triggers `HVC #0` to signal completion; the host reads the encrypted response.

**Security properties**:
- ✅ Hardware vCPU isolation (Apple Hypervisor Framework)
- ✅ Encrypted IPC — host cannot read plaintext prompts in shared memory
- ✅ Attestation includes vCPU register state and binary measurement
- ⚠️ Apple Hypervisor has no remote attestation API (local trust only)
- ⚠️ Requires codesigning with `com.apple.security.hypervisor` entitlement

**Attestation**: SHA-256 of the unikernel binary payload.

**Requirements**:
- macOS 11+ on Apple Silicon (M1/M2/M3/M4)
- Entitlements XML: `entitlements.xml` with `com.apple.security.hypervisor = true`
- Test binary must be codesigned: `codesign -s - --entitlements entitlements.xml --force <binary>`

---

### Enclave Level 3 — Remote Hardware Enclave (Linux / Windows)

**Feature flag**: `--features enclave-remote`  
**Platforms**: Any (connects to remote TEE over HTTPS)  
**Code**: `crates/host/src/enclave/remote.rs`

**Mechanism**:
1. `POST /enclave/attest` — fetches a COSE-Sign1 attestation document from the remote enclave.
2. Parses the Nitro NSM / AMD SEV-SNP attestation document (CBOR-encoded).
3. Extracts PCR0 measurement, session public key, and certificate chain.
4. X25519 key exchange with the enclave's session public key.
5. `POST /enclave/infer` — sends encrypted prompt, receives encrypted response.
6. ChaCha20-Poly1305 AEAD with HKDF-SHA256 derived session key.

**Security properties**:
- ✅ Hardware-backed TEE isolation (AWS Nitro / AMD SEV-SNP / Intel TDX)
- ✅ Remote attestation with cryptographic proof of enclave identity
- ✅ End-to-end encrypted channel (prompt never visible to cloud host)
- ✅ Certificate chain validation against known CA roots
- ⚠️ Requires trusted remote enclave endpoint
- ⚠️ Network latency for each inference call

**Attestation**: PCR0 hash or SHA-256 of enclave module ID; raw COSE-Sign1 blob preserved.

**Environment variables**:
```bash
export ECTO_ENCLAVE_REMOTE_URL=https://enclave.example.com
```

---

### Enclave Routing Logic

The `EnclaveRouter` (`crates/host/src/enclave/router.rs`) selects the best available tier:

| Priority | Condition | Tier |
|----------|-----------|------|
| 1 | `ECTO_ENCLAVE_REMOTE_URL` set + `enclave-remote` feature | Level 3 — Remote Hardware |
| 2 | macOS aarch64 + `sandbox-apple-enclave` feature | Level 2 — Apple Hypervisor |
| 3 | `enclave` feature enabled | Level 1 — Software Hardened |
| 4 | No enclave feature | No enclave (plain LLM) |

Explicit routing via `EnclaveRoute` enum overrides auto-detection.

---

### IPC Shared Memory Layout

The shared memory page (4 KiB at guest physical `0x10000000`) uses the following byte-range layout for encrypted communication between host and guest:

```text
Byte Range     Size   Field                          Direction
──────────     ────   ─────                          ─────────
 [0..32)        32    Host X25519 public key          Host → Guest
[32..64)        32    Guest X25519 public key         Guest → Host
[64..65)         1    Command byte                   Host → Guest
                        0x00 = idle
                        0x01 = request ready
[65..66)         1    Status byte                    Guest → Host
                        0x00 = idle
                        0x02 = response ready
[66..68)         2    Reserved (alignment padding)
[68..72)         4    Request length (LE u32)        Host → Guest
[72..76)         4    Response length (LE u32)       Guest → Host
[76..80)         4    Reserved
[80..4096)      ..    Payload: Nonce (12B) ‖ AEAD ciphertext
```

**Byte-range summary** (the two critical ranges the handshake depends on):
- `page[0..32]`  — **host public key**: written by the host *before* booting the guest vCPU.
- `page[32..64]` — **guest public key**: written by the guest immediately after boot; host reads after first `HVC #0`.

**Key derivation**:
1. Host generates ephemeral X25519 keypair, writes public key to `page[0..32]`.
2. Guest generates ephemeral X25519 keypair, writes public key to `page[32..64]`.
3. Both sides compute `shared_secret = X25519(my_secret, their_pubkey)`.
4. Session key = `SHA-256("ectoledger-enclave-ipc-v1" ‖ shared_secret)` → 32-byte ChaCha20-Poly1305 key.

**ARM memory ordering — `DMB ISH` requirements**:

All reads and writes to the shared memory page **must** be flanked by `DMB ISH` (Data Memory Barrier, Inner Shareable) instructions on aarch64 to prevent ARM weak-memory reordering between the host CPU core and the guest vCPU.

The unikernel (`crates/guard_unikernel/src/main.rs`) implements this via a Rust helper:

```rust
#[inline(always)]
fn dmb_ish() {
    unsafe { core::arch::asm!("dmb ish", options(nostack)) };
}
```

Every shared-page access is wrapped:

```rust
// Writing guest pubkey to page[32..64]:
dmb_ish();
unsafe {
    for (i, &b) in guest_pubkey.as_bytes().iter().enumerate() {
        SHARED_PAGE.add(OFF_GUEST_PUBKEY + i).write_volatile(b);
    }
}
dmb_ish();

// Reading host pubkey from page[0..32]:
dmb_ish();
unsafe {
    for i in 0..32 {
        host_pubkey_bytes[i] = SHARED_PAGE.add(OFF_HOST_PUBKEY + i).read_volatile();
    }
}
dmb_ish();
```

**Why `DMB ISH` is mandatory:**
- ARM's weak memory model allows stores and loads to be reordered across cores.
- Without barriers, the guest may read stale host pubkey bytes from `page[0..32]`, causing an X25519 key mismatch and silent decryption failure.
- The `ISH` (Inner Shareable) domain is sufficient because host and guest share the same physical memory within the Apple Hypervisor's memory map.
- `volatile` read/write alone is **not enough** — it prevents compiler reordering but not hardware reordering.

---

### Enclave Attestation in `.elc` Certificates

When an enclave is active during a session, the attestation evidence is embedded as an **Enclave Attestation Pillar** in the `.elc` certificate:

```json
{
  "enclave_attestation": {
    "level": "apple_hypervisor",
    "measurement_hash": "a1b2c3d4e5f6…",
    "raw_attestation_hex": "d284…"  // only for hardware enclaves
  }
}
```

- The `enclave_attestation` field is **included** in the Ed25519 signing payload, making it tamper-evident.
- The `raw_attestation_hex` contains the full COSE-Sign1 blob (Level 3) or is `null` (Level 1).
- The `verify-cert` tool displays enclave level, measurement hash, and raw blob size.
- With `--features enclave-remote`, the verifier additionally validates the COSE-Sign1 envelope structure.

---

## Parity Analysis by Use Case

### Use Case: Prevent LLM Prompt Leakage

**Threat**: Host process memory dump reveals plaintext AI prompts containing sensitive audit data

| Platform | Mechanism | Effectiveness |
|----------|-----------|----------------|
| Linux | No memory protection by default | 🚫 Vulnerable |
| macOS | No memory protection by default | 🚫 Vulnerable |
| Windows | No memory protection by default | 🚫 Vulnerable |
| Docker | Container memory visible to host | 🚫 Vulnerable |
| Firecracker | Guest kernel isolation | ⚠️ KVM hypervisor can read guest memory |
| Enclave L1 | mlock + zeroize | ⚠️ Prevents swap leak; host can still read |
| Enclave L2 | Apple HV + encrypted IPC | ✅ Prompt encrypted in shared memory |
| Enclave L3 | Hardware TEE + COSE-Sign1 | ✅ Prompt encrypted end-to-end |

**Recommendation**: Use Enclave Level 2 (macOS) or Level 3 (Linux/Windows) for sessions handling sensitive data.

### Use Case: Prevent Token Extraction via `run_command`

**Threat**: Agent runs `echo $SECRET_API_KEY` via untrusted `run_command` intent

| Platform | Mechanism | Effectiveness |
|----------|-----------|----------------|
| Linux | Landlock hides files, seccomp blocks filesystem calls | ✅ Blocks |
| macOS | None (Docker recommended) | 🚫 Vulnerable |
| Windows | Job Object (no filesystem isolation) | 🚫 Vulnerable (if secret in env var) |
| Docker | Read-only FS + `--network=none` | ✅ Blocks |
| Firecracker | Guest kernel isolation | ✅ Blocks |

**Recommendation**: 
- Linux production: Use native Landlock + seccomp
- macOS production: Run inside Linux container
- Windows production: Use Docker or validate env var filtering

### Use Case: Prevent Prompt Injection via Binary PATH

**Threat**: Attacker injects `PATH=/tmp/evil run_command 'ls'` to execute malicious binary

| Platform | Mechanism | Effectiveness |
|----------|-----------|----------------|
| Linux | Landlock read-only workspace, seccomp allowlist | ✅ Blocks |
| macOS | None (Docker recommended) | 🚫 Vulnerable |
| Windows | Job Object + process isolation | ⚠️ Blocks if binary not on native PATH |
| Docker | Read-only FS | ✅ Blocks |
| Firecracker | Guest kernel isolation | ✅ Blocks |

### Use Case: Prevent Resource Exhaustion

**Threat**: Malicious command forks bomb or exhausts memory

| Platform | Mechanism | Effectiveness |
|----------|-----------|----------------|
| Linux | rlimits (CPU, memory, FDs) | ✅ Stops at 30s CPU or 512 MiB |
| macOS | None | 🚫 Vulnerable |
| Windows | Job Object (memory limits supported but not enforced uniformly) | ⚠️ Partial |
| Docker | cgroups (memory, CPU) | ✅ Stops at configured limit |
| Firecracker | vCPU/memory limits | ✅ Enforced by hypervisor |

---

## Configuration Recommendations

### Development Environment
```bash
# macOS or Windows dev
export ECTO_DOCKER_IMAGE=alpine:3.19
export ECTO_DOCKER_RUNTIME=auto
# Runs audit inside lightweight container for basic isolation
```

### Production: Linux
```bash
# Native Linux with kernel sandbox
cargo build --release --features sandbox
./ectoledger audit "Your goal" \
  --policy audit_policy.toml
# Landlock + seccomp + rlimits apply automatically
```

### Production: macOS
```bash
# Run inside container
docker run -v /audit-workspace:/audit \
  ghcr.io/ectoledger/agent-ledger:latest \
  audit "Your goal" --policy audit_policy.toml
# Container provides filesystem and process isolation
```

### Production: Windows
```bash
# Option 1: Docker Desktop (recommended)
docker run -v C:\audit-workspace:C:\audit `
  ghcr.io/ectoledger/agent-ledger:latest `
  audit "Your goal" --policy audit_policy.toml

# Option 2: Native (limited isolation via Job Objects)
ectoledger.exe audit "Your goal" `
  --policy audit_policy.toml
# Job Object applies UI restrictions and cleanup guarantee
```

### Production: Maximum Security (any platform)
```bash
# Run inside Firecracker (Linux only)
cargo build --release --features sandbox,sandbox-firecracker
export ECTO_FC_BINARY=/usr/local/bin/firecracker
export ECTO_FC_KERNEL=/opt/ectoledger/vmlinux
export ECTO_FC_ROOTFS=/opt/ectoledger/rootfs.ext4
./ectoledger audit "Your goal"
# Each run_command executes in ephemeral KVM microVM
```

---

## Security Guarantee Summary

### Linux (with `--features sandbox`)
✅ **Principle of least privilege**: Workspace read-only, syscalls allowlisted, resources limited  
✅ **Multi-layer defense**: Filesystem + process + resource levels  
✅ **Kernel-enforced**: Cannot bypass from userspace  
📝 **Assumption**: Kernel LSM and seccomp compiled in; Landlock ABI V3+ supported

### macOS
❌ **No native kernel sandbox**: Use containers  
✅ **Docker container option**: Provides filesystem + process isolation  
📝 **Recommendation**: macOS users should run inside Linux container for production

### Windows
⚠️ **Partial isolation**: Process cleanup, UI restrictions  
❌ **No filesystem isolation**: Relies on NTFS permissions  
❌ **No syscall filtering**: Cannot prevent dangerous Windows APIs  
✅ **Docker option**: Provides filesystem + resource isolation  
📝 **Recommendation**: Use Docker for production; native sandbox is advisory-only

### Docker (all platforms)
✅ **Cross-platform consistency**  
✅ **Read-only FS + network isolation**  
✅ **Resource limits (cgroups)**  
⚠️ **Container escape possible** (kernel vulnerability)  
📝 **Use case**: Recommended default for macOS/Windows production

### Firecracker (Linux only)
✅ **Hardware-level isolation (KVM)**  
✅ **Ephemeral microVM per command**  
✅ **Strongest isolation available**  
⚠️ **Complex setup** (kernel, rootfs, firecracker binary)  
📝 **Use case**: Maximum security for multi-tenant or adversarial scenarios

---

## Testing Cross-Platform Parity

### Linux Test: Verify Landlock + seccomp active
```bash
# Check if sandbox feature is compiled in
strings target/release/ectoledger | grep -q "Landlock" && echo "✅ Landlock support compiled"

# Run audit and check logs (requires RUST_LOG=debug)
RUST_LOG=debug cargo run --features sandbox -- audit "test goal" 2>&1 | grep -E "Landlock|seccomp|rlimit"
```

### Windows Test: Verify Job Object applied
```powershell
# Job Objects are process-internal (no direct CLI visibility)
# Verify behavior: Create `run_command` that tries to switch desktops or modify system parameters
# Should fail silently or return restricted error
```

### Docker Test: Verify container isolation
```bash
# Inside container, should be read-only:
docker run --rm alpine:3.19 touch /test.txt
# Should fail: "Read-only file system"

# Should have no network:
docker run --network=none --rm alpine:3.19 ping 8.8.8.8
# Should timeout or fail
```

### Firecracker Test: Verify microVM isolation
```bash
# microVM should be destroyed after command
# Check /tmp for leftover sockets or images — should be none
ls -la /tmp | grep firecracker
# Should return nothing if cleanup is working
```

### Enclave Test: IPC crypto round-trip
```bash
# Runs without Apple Hypervisor — pure crypto verification
cargo test --features enclave -p ectoledger --lib -- enclave::ipc::tests
# Should pass: round_trip_encrypt_decrypt
```

### Enclave Test: Apple Hypervisor boot (macOS Apple Silicon only)
```bash
# Requires codesigning — the test binary must have the hypervisor entitlement.
# Step 1: Build without running
cargo test --features sandbox-apple-enclave --no-run

# Step 2: Codesign the test binary (find the latest one)
BIN=$(ls -t target/debug/deps/enclave_apple_boot-* | grep -v '\.' | head -1)
codesign -s - --entitlements entitlements.xml --force "$BIN"

# Step 3: Run
"$BIN" --nocapture
# Should pass: enclave_apple_boot, enclave_runtime_lifecycle
```

### Enclave Test: Remote attestation crypto
```bash
# Runs without a remote enclave — tests COSE-Sign1 parsing and session key derivation
cargo test --features enclave-remote -p ectoledger --lib -- enclave::remote::tests
# Should pass: parse_attestation_round_trip, session_key_derivation, destroy_clears_state
```

---

## Future Work

- [ ] Add Seatbelt profile generation for macOS (if public API becomes available)
- [ ] Add Windows syscall filtering equivalent (API hooking or nested Job Objects)
- [ ] Add cgroup v2 support for Docker for better resource accounting
- [ ] Add OCI runtime hook for additional container sandbox layers
- [ ] Performance benchmarking across platforms
- [ ] Enclave Level 2: Add full LLM inference inside the unikernel (currently boots + IPC only)
- [ ] Enclave Level 3: Add AMD SEV-SNP and Intel TDX attestation report parsing
- [ ] Enclave Level 3: Certificate chain validation against AWS Nitro CA root
- [ ] Enclave: GPU-accelerated inference inside TEE (NVIDIA Confidential Computing)

