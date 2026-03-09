# Cross-Platform Sandbox

Platform-specific sandbox implementations and unified abstraction.

EctoLedger provides three layers of execution isolation, with different
guarantees on each platform.

## Security Tier 1: Hardware-Accelerated Virtualization (Linux only)

- **Firecracker microVM** (`sandbox-firecracker` feature)
  - Full process isolation via KVM: own kernel, filesystem, network stack
  - Strongest guarantee: guest cannot access host state
  - Requires: Linux 4.14+, nested KVM, unprivileged user namespaces

## Security Tier 2: Container + OS-Level Sandboxing (All Platforms)

- **Linux**: Landlock (LSM) + seccomp BPF allowlist
  - Landlock: read-only filesystem access to workspace, rlimit enforcement
  - seccomp: deny ptrace, process_vm_readv, kexec_load; return EPERM instead of kill
  - Applies to: host process, guard-worker, guard-worker children
- **macOS**: ⚠️ Seatbelt (sandbox_init FFI) — deprecated by Apple but still functional
  - Filesystem isolation: read-only system libs, read/write workspace only
  - Denies: network\*, process-exec, signal (child processes are sandboxed)
  - Limitation: no per-process network isolation (see security warning below)
  - Graceful fallback: if sandbox_init fails on a future macOS version, logs a
    warning and continues with advisory tripwires only — never breaks the build.
  - See [sandbox-parity.md](docs/sandbox-parity.md) and [sandbox-verification-report.md](docs/sandbox-verification-report.md) for details.
- **Windows**: Job Objects + mandatory handle inheritance restrictions
  - `CREATE_NEW_PROCESS_GROUP`: isolates subprocess tree
  - `JOB_OBJECT_LIMIT_PROCESS_TIME`: enforces timeout
  - `JOB_OBJECT_LIMIT_JOB_MEMORY`: memory ceiling
  - Child processes cannot escape (no `break on close`)

## Security Tier 3: Allowlist-Based Policy (All Platforms)

- Command blocklist (tripwire): dangerous flags like `-rf`, `sudo`, `&&`, `||`, etc.
- Network allowlist: only whitelisted domains; HTTPS required by default
- Filesystem allowlist: only workspace paths; no directory traversal (`..`)
- These are advisory; apply AFTER successful OS sandbox enforcement

## Cross-Platform Comparison Table

| Capability | Linux (Firecracker) | Linux (Landlock) | macOS (Seatbelt) | Windows (Job) | Docker/Podman |
|---|---|---|---|---|---|
| Process isolation | ✅ KVM | ❌ shared kernel | ⚠️ deny process-exec | ❌ shared kernel | ✅ container |
| File permissions | ✅ guest FS | ✅ read-only FS | ⚠️ Seatbelt r/w ws only | ⚠️ Job limits | ✅ container FS |
| Network isolation | ✅ guest stack | ✅ seccomp filter | ❌ no per-process net | ⚠️ Job limits | ✅ `--net=none` |
| Resource limits | ✅ guest RAM/CPU | ✅ rlimit | ❌ not enforced | ✅ Job limits | ✅ cgroup |
| ptrace protection | ✅ guest kernel | ✅ seccomp EPERM | ✅ Seatbelt deny | ⚠️ recommended | ✅ container |
| Timeout enforcement | ✅ guest timeout | ⚠️ host-level | ⚠️ host-level | ✅ Job timeout | ✅ cgroup |
| Startup time | ~200ms | ~5ms | ~5ms | ~5ms | ~100ms |
| Requires superuser | ⚠️ KVM setup | ✅ no | ✅ no | ✅ no | depends on runtime |
| Trusted base | ✅ small (KVM) | ⚠️ kernel | ⚠️ kernel | ⚠️ kernel | ⚠️ large (container) |

## Recommendations by Scenario

### Production (High Security, Linux)

1. **Enable Firecracker** (`ECTO_FC_BINARY=/path/to/fc`)
   - Provides maximum isolation; handles untrusted workloads safely
   - Overhead: ~200ms startup, negligible runtime cost
2. **Fallback to Landlock** if Firecracker unavailable or unsupported
   - Recommend running as non-root with user namespaces
3. **Enable EVM anchoring** (`EVM_RPC_URL=...`) for tamper-evidence
   - Commits proof-of-execution to public blockchain

### Production (macOS)

1. **Use Seatbelt** by default (compiled in, no extra setup)
   - Prevents most filesystem escapes and process spying
   - Enforce code signing: sign the binary before deployment
2. **Run as non-root user** (Seatbelt doesn't restrict root)
3. **Monitor Unified Log** for Seatbelt denials (search "deny-mach-port")

> **⚠️ SECURITY WARNING — Missing Network Isolation on macOS**
>
> Apple's Seatbelt framework does **not** support per-process network isolation.
> Unlike Linux seccomp/Landlock or Docker `--network=none`, macOS child processes
> inherit full outbound network access. This means a compromised agent action
> (e.g. a malicious `curl` or DNS exfiltration payload) can reach external hosts
> even when the Seatbelt sandbox is active.
>
> **This is an architectural limitation of macOS, not a bug in EctoLedger.**
>
> **Recommended mitigations for production macOS deployments:**
>
> 1. **Edge network filtering** — Deploy a network-level firewall (e.g. pfctl,
>    Little Snitch, Lulu, or a corporate proxy) to restrict outbound traffic
>    from the EctoLedger process to only the required LLM API endpoints, the
>    database host, and webhook destinations.
> 2. **Tripwire domain allowlist** — Configure `AGENT_ALLOWED_DOMAINS` to
>    restrict `http_get` actions to specific approved domains. Note: this does
>    not prevent raw socket access from shell commands.
> 3. **DNS sinkholing** — Use a local DNS resolver (e.g. dnsmasq or Unbound)
>    that only resolves approved domains, blocking exfiltration via DNS tunnelling.
> 4. **Container fallback** — On macOS, set `ECTO_DOCKER_IMAGE` to enable
>    Docker/Podman sandboxing for `run_command` actions. Docker Desktop for Mac
>    provides `--network=none` isolation that Seatbelt cannot.
> 5. **Code signing + entitlements** — Sign the production binary with a
>    restricted entitlements profile. While this cannot add network filtering,
>    it prevents tampering and enforces the Seatbelt profile.
>
> For maximum security on macOS, combine Tripwire domain restrictions with
> edge firewall rules and Docker container execution.

### Production (Windows)

1. **Enable Job Objects** by default via `sandbox` feature
   - Enforces memory/CPU limits and timeout
   - Creates a subprocess isolation boundary
2. **Disable console window inheritance** (set in Job config)
3. **Monitor Process Monitor (Procmon)** for denied operations

### Development/CI (Any Platform)

1. **Firecracker** if Linux + KVM available (fast feedback on isolation)
2. **Landlock/Seatbelt/Job** if Firecracker unavailable (zero setup)
3. **Fallback to Docker/Podman** with `--network=none --read-only`
4. **Skip sandbox** for unit tests (set `sandbox` to advisory-only, feature-gated)

## Known Limitations & Future Work

### Seatbelt (macOS)

- ❌ Does not isolate network access (all sockets allowed; no per-domain filtering)
  - **Mitigation**: Tripwire allowlist + DNS filtering at network edge
- ❌ Cannot revoke mach messaging (low-level system messaging)
  - **Mitigation**: Run as non-root; mach messaging restricted by OS limits
- ✅ Code signing + entitlements can further restrict; requires deployment-time setup

### Job Objects (Windows)

- ❌ Does not isolate filesystem (job inherits parent ACLs)
  - **Mitigation**: Run process as low-privilege user; tripwire guards paths
- ❌ No per-process memory accounting (memory reported as job total)
  - **Mitigation**: Set `JOB_OBJECT_LIMIT_JOB_MEMORY` conservatively
- ✅ Nested jobs supported; can add secondary sandboxes per sub-agent

### Landlock (Linux)

- ❌ Only available on Linux 5.13+
  - **Fix**: auto-disable Landlock on older kernels; fall through to tripwire
- ⚠️ Requires unprivileged user namespace support
  - **Mitigation**: Check `/proc/sys/user/unprivileged_userns_clone` and warn
- ✅ Supports stacked rulesets for per-agent policies (future work)

### Firecracker (Linux)

- ❌ KVM required (nested KVM for containers)
  - **Check**: `sudo kvm-ok` before launching guard-worker
- ⚠️ Network must be explicitly configured (microVM has no network by default)
  - **Design**: guard-worker does not require network; all LLM calls proxied by host
- ✅ Overhead negligible after startup; can run 100+ simultaneous microVMs

## Usage in Code

All sandbox functions are feature-gated:

```rust
#[cfg(all(target_os = "linux", feature = "sandbox"))]
pub fn apply_guard_worker_seccomp() -> Result<(), SandboxError> { ... }

#[cfg(target_os = "macos")]
pub fn apply_seatbelt() -> Result<(), SandboxError> { ... }

#[cfg(target_os = "windows")]
pub fn apply_job_object() -> Result<(), SandboxError> { ... }
```

At runtime, callers can choose to hard-fail or warn based on security requirements:

```rust
// Production: hard-fail if sandbox unavailable
apply_sandbox()?;  // returns Err if not available

// Development: warn and continue
if let Err(e) = apply_sandbox() {
    eprintln!("Warning: {} — running without sandbox", e);
}
```
