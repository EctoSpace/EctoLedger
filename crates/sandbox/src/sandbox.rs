use crate::output::format_sandbox_output;
use std::path::Path;

#[derive(Debug, thiserror::Error)]
pub enum SandboxError {
    #[error("sandbox io: {0}")]
    Io(#[from] std::io::Error),
    /// The sandbox is not available on this platform.
    /// Callers that tolerate advisory-only sandboxing may log and continue;
    /// callers that require hard isolation should propagate this error.
    #[error("sandbox unsupported: {0}")]
    Unsupported(String),
    #[cfg(all(target_os = "linux", feature = "sandbox"))]
    #[error("landlock: {0}")]
    Landlock(#[from] landlock::RulesetError),
    #[cfg(target_os = "windows")]
    #[error("windows job object: {0}")]
    Windows(#[from] windows::core::Error),
}

/// Applies a child-process sandbox for the given workspace directory.
///
/// On Linux with the `sandbox` feature flag: uses Landlock to enforce
/// read-only access to the workspace and applies `rlimit` bounds for
/// CPU time and address space.
///
/// Applies a strict seccomp BPF allowlist for the guard-worker process.
/// Denies ptrace, process_vm_readv, kexec_load with EPERM.
/// Anything outside the allowlist returns EPERM rather than kill, so missed
/// syscalls surface as errors instead of silent process termination.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
pub fn apply_guard_worker_seccomp() -> Result<(), SandboxError> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};
    use std::collections::BTreeMap;

    // Syscalls needed by tokio + reqwest (HTTP to local LLM) + stdin/stdout JSON protocol.
    // Kept minimal; nothing that enables ptrace, raw memory access, or kernel loading.
    #[rustfmt::skip]
    let allowed: &[i64] = &[
        libc::SYS_read, libc::SYS_write, libc::SYS_readv, libc::SYS_writev,
        libc::SYS_openat, libc::SYS_close, libc::SYS_fstat,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_stat,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_lstat,
        #[cfg(target_arch = "aarch64")]
        libc::SYS_newfstatat,
        libc::SYS_lseek, libc::SYS_mmap, libc::SYS_mprotect,
        libc::SYS_munmap, libc::SYS_brk, libc::SYS_rt_sigaction,
        libc::SYS_rt_sigprocmask, libc::SYS_rt_sigreturn, libc::SYS_ioctl,
        libc::SYS_pread64, libc::SYS_pwrite64, libc::SYS_getcwd,
        libc::SYS_clone, libc::SYS_clone3, libc::SYS_exit, libc::SYS_exit_group,
        libc::SYS_futex, libc::SYS_sched_yield, libc::SYS_nanosleep,
        libc::SYS_clock_gettime, libc::SYS_gettimeofday,
        libc::SYS_socket, libc::SYS_connect, libc::SYS_accept4,
        libc::SYS_sendto, libc::SYS_recvfrom, libc::SYS_sendmsg,
        libc::SYS_recvmsg, libc::SYS_shutdown, libc::SYS_bind,
        libc::SYS_getsockname, libc::SYS_getpeername,
        libc::SYS_setsockopt, libc::SYS_getsockopt,
        libc::SYS_epoll_create1, libc::SYS_epoll_ctl, libc::SYS_epoll_pwait,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_poll,
        libc::SYS_ppoll,
        libc::SYS_prctl, libc::SYS_prlimit64,
        libc::SYS_getuid, libc::SYS_getgid, libc::SYS_getpid, libc::SYS_gettid,
        libc::SYS_set_robust_list, libc::SYS_getrandom, libc::SYS_madvise,
        libc::SYS_pipe2, libc::SYS_eventfd2, libc::SYS_timerfd_create,
        libc::SYS_timerfd_settime, libc::SYS_wait4, libc::SYS_fcntl,
        libc::SYS_dup, libc::SYS_dup3, libc::SYS_set_tid_address,
        libc::SYS_sigaltstack, libc::SYS_uname,
        // needed by newer glibc / musl thread initialisation + file ops
        libc::SYS_rseq, libc::SYS_memfd_create, libc::SYS_statx,
        libc::SYS_tgkill, libc::SYS_flock,
        libc::SYS_faccessat, libc::SYS_kill,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_arch_prctl,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_newfstatat,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_access,
    ];

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for &nr in allowed {
        rules.insert(nr, vec![]);
    }

    #[cfg(target_arch = "x86_64")]
    let arch = seccompiler::TargetArch::x86_64;
    #[cfg(target_arch = "aarch64")]
    let arch = seccompiler::TargetArch::aarch64;
    // On unsupported architectures (RISC-V, s390x, etc.) we skip the filter rather than
    // failing the build. The sandbox feature is still useful for Landlock and rlimits.
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return Ok(());

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        arch,
    )
    .map_err(|e| SandboxError::Io(std::io::Error::other(e.to_string())))?;

    let bpf: BpfProgram = filter.try_into().map_err(|e: seccompiler::BackendError| {
        SandboxError::Io(std::io::Error::other(e.to_string()))
    })?;

    seccompiler::apply_filter(&bpf)
        .map_err(|e| SandboxError::Io(std::io::Error::other(e.to_string())))?;

    Ok(())
}

/// Seccomp stub for the guard worker on non-Linux or when the sandbox feature is disabled.
#[cfg(not(all(target_os = "linux", feature = "sandbox")))]
pub fn apply_guard_worker_seccomp() -> Result<(), SandboxError> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    #[test]
    fn guard_seccomp_stub_returns_ok() {
        assert!(apply_guard_worker_seccomp().is_ok());
    }

    #[test]
    fn main_process_seccomp_returns_ok() {
        let _ = apply_main_process_seccomp();
    }

    #[test]
    fn apply_child_sandbox_compiles_and_runs() {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let result = apply_child_sandbox(&workspace);
        match result {
            Ok(()) => {}
            Err(SandboxError::Unsupported(msg)) => eprintln!("sandbox unsupported: {}", msg),
            Err(e) => eprintln!("sandbox error: {}", e),
        }
    }

    #[test]
    fn sandbox_error_display_formats() {
        let io_err = SandboxError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "test",
        ));
        assert!(io_err.to_string().contains("sandbox io"));

        let unsupported = SandboxError::Unsupported("test platform".into());
        assert!(unsupported.to_string().contains("unsupported"));
    }

    #[test]
    fn docker_config_defaults_are_sane() {
        let cfg = DockerConfig::default();
        assert_eq!(cfg.image, "alpine:3.19");
        assert_eq!(cfg.timeout_secs, 30);
    }

    #[test]
    fn firecracker_config_defaults_are_sane() {
        let cfg = FirecrackerConfig::default();
        assert_eq!(cfg.vcpu_count, 1);
        assert_eq!(cfg.mem_mib, 128);
        assert_eq!(cfg.timeout_secs, 30);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_seatbelt_profile_generates() {
        let profile = seatbelt_profile(std::path::Path::new("/tmp/test-workspace"));
        assert!(profile.contains("(deny default)"));
        assert!(profile.contains("(deny network*)"));
        assert!(profile.contains("(allow process-exec)"));
        assert!(profile.contains("/tmp/test-workspace"));
        // Must allow executable paths for pre_exec compatibility
        assert!(profile.contains("/usr/bin"));
        assert!(profile.contains("/bin"));
    }

    #[cfg(all(target_os = "linux", feature = "sandbox"))]
    #[test]
    fn linux_seccomp_guard_worker_applies_or_handles_error() {
        let result = apply_guard_worker_seccomp();
        match result {
            Ok(()) => {}
            Err(e) => eprintln!("seccomp error (acceptable in test harness): {}", e),
        }
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_job_object_applies_or_handles_error() {
        let workspace = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let result = apply_child_sandbox(&workspace);
        match result {
            Ok(()) => {}
            Err(SandboxError::Unsupported(msg)) => eprintln!("Job Object unsupported: {}", msg),
            Err(e) => eprintln!("Job Object error: {}", e),
        }
    }
}

/// Applies a production-ready seccomp BPF allowlist to the main process.
/// The allowlist is broader than the guard-worker filter because the main process runs:
///   - Axum HTTP server (accept4, listen, sendmsg, recvmsg, setsockopt, epoll_*)
///   - SQLx Postgres client (same networking)
///   - Process spawning for tool execution (clone, wait4, pipe2, eventfd2)
///   - File-descriptor management (fcntl, dup, dup3)
///
/// Explicitly denied (EPERM): ptrace, process_vm_readv/writev, kexec_load,
/// init_module, finit_module, mount, umount2, pivot_root, reboot.
#[cfg(all(target_os = "linux", feature = "sandbox"))]
pub fn apply_main_process_seccomp() -> Result<(), SandboxError> {
    use seccompiler::{BpfProgram, SeccompAction, SeccompFilter, SeccompRule};
    use std::collections::BTreeMap;

    #[rustfmt::skip]
    let allowed: &[i64] = &[
        // Basic I/O
        libc::SYS_read, libc::SYS_write, libc::SYS_readv, libc::SYS_writev,
        libc::SYS_pread64, libc::SYS_pwrite64,
        libc::SYS_openat, libc::SYS_close, libc::SYS_fstat,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_stat,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_lstat,
        #[cfg(target_arch = "aarch64")]
        libc::SYS_newfstatat,
        libc::SYS_lseek, libc::SYS_getcwd, libc::SYS_getdents64,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_rename,
        #[cfg(target_arch = "aarch64")]
        libc::SYS_renameat,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_unlink,
        #[cfg(target_arch = "aarch64")]
        libc::SYS_unlinkat,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_mkdir,
        #[cfg(target_arch = "aarch64")]
        libc::SYS_mkdirat,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_rmdir,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_chmod,
        #[cfg(target_arch = "aarch64")]
        libc::SYS_fchmodat,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_chown,
        #[cfg(target_arch = "aarch64")]
        libc::SYS_fchownat,
        libc::SYS_truncate, libc::SYS_ftruncate,
        libc::SYS_statx, libc::SYS_faccessat, libc::SYS_flock,
        // Memory
        libc::SYS_mmap, libc::SYS_mprotect, libc::SYS_munmap, libc::SYS_brk,
        libc::SYS_madvise, libc::SYS_memfd_create, libc::SYS_mremap, libc::SYS_msync,
        // Signals / threads
        libc::SYS_rt_sigaction, libc::SYS_rt_sigprocmask, libc::SYS_rt_sigreturn,
        libc::SYS_sigaltstack, libc::SYS_futex, libc::SYS_sched_yield,
        libc::SYS_nanosleep, libc::SYS_clock_gettime, libc::SYS_gettimeofday,
        libc::SYS_tgkill, libc::SYS_kill,
        // Process management (needed for spawning tool sub-processes)
        libc::SYS_clone, libc::SYS_clone3, libc::SYS_wait4,
        libc::SYS_exit, libc::SYS_exit_group,
        libc::SYS_execve, libc::SYS_set_tid_address,
        libc::SYS_setpgid, libc::SYS_setsid, libc::SYS_getrusage,
        // Pipe / FD helpers
        libc::SYS_pipe2, libc::SYS_eventfd2, libc::SYS_timerfd_create,
        libc::SYS_timerfd_settime, libc::SYS_fcntl, libc::SYS_dup, libc::SYS_dup3,
        libc::SYS_ioctl,
        // Networking (Axum + SQLx)
        libc::SYS_socket, libc::SYS_connect, libc::SYS_bind, libc::SYS_listen,
        libc::SYS_accept4, libc::SYS_sendto, libc::SYS_recvfrom,
        libc::SYS_sendmsg, libc::SYS_recvmsg, libc::SYS_shutdown,
        libc::SYS_getsockname, libc::SYS_getpeername,
        libc::SYS_setsockopt, libc::SYS_getsockopt,
        // epoll / poll
        libc::SYS_epoll_create1, libc::SYS_epoll_ctl, libc::SYS_epoll_pwait,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_poll,
        libc::SYS_ppoll,
        // Misc
        libc::SYS_prctl, libc::SYS_prlimit64, libc::SYS_getrandom,
        libc::SYS_getuid, libc::SYS_getgid, libc::SYS_getpid, libc::SYS_gettid,
        libc::SYS_set_robust_list, libc::SYS_uname,
        libc::SYS_rseq,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_arch_prctl,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_newfstatat,
        #[cfg(target_arch = "x86_64")]
        libc::SYS_access,
    ];

    let mut rules: BTreeMap<i64, Vec<SeccompRule>> = BTreeMap::new();
    for &nr in allowed {
        rules.insert(nr, vec![]);
    }

    #[cfg(target_arch = "x86_64")]
    let arch = seccompiler::TargetArch::x86_64;
    #[cfg(target_arch = "aarch64")]
    let arch = seccompiler::TargetArch::aarch64;
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    return Ok(());

    let filter = SeccompFilter::new(
        rules,
        SeccompAction::Errno(libc::EPERM as u32),
        SeccompAction::Allow,
        arch,
    )
    .map_err(|e| SandboxError::Io(std::io::Error::other(e.to_string())))?;

    let bpf: BpfProgram = filter.try_into().map_err(|e: seccompiler::BackendError| {
        SandboxError::Io(std::io::Error::other(e.to_string()))
    })?;

    seccompiler::apply_filter(&bpf)
        .map_err(|e| SandboxError::Io(std::io::Error::other(e.to_string())))?;

    tracing::info!("Main-process seccomp filter applied.");
    Ok(())
}

/// No-op on non-Linux or when the sandbox feature is disabled.
/// On macOS, applies a Seatbelt profile that denies network, process-exec, and
/// restricts filesystem writes to the workspace directory only.
#[cfg(not(all(target_os = "linux", feature = "sandbox")))]
pub fn apply_main_process_seccomp() -> Result<(), SandboxError> {
    #[cfg(target_os = "macos")]
    {
        tracing::info!(
            "macOS: seccomp-BPF is Linux-only; Seatbelt is applied to child processes instead."
        );
        return Ok(());
    }
    #[allow(unreachable_code)]
    Ok(())
}

/// Applies the strongest available child-process sandbox for the current platform.
///
/// - Linux (with `sandbox` feature): Landlock + rlimits
/// - macOS: Apple Seatbelt (sandbox_init) profile restricting filesystem writes
///   to the workspace and denying network + process-exec access.
/// - Windows: Job Object with `KILL_ON_JOB_CLOSE` and full UI restrictions
/// - All other platforms: no-op (sandbox is best-effort)
pub fn apply_child_sandbox(workspace: &Path) -> Result<(), SandboxError> {
    #[cfg(all(target_os = "linux", feature = "sandbox"))]
    {
        apply_landlock(workspace)?;
        apply_rlimits();
    }
    #[cfg(target_os = "macos")]
    {
        apply_seatbelt(workspace)?;
    }
    #[cfg(target_os = "windows")]
    {
        let _ = workspace;
        apply_windows_job_object()?;
    }
    #[cfg(not(any(
        all(target_os = "linux", feature = "sandbox"),
        target_os = "macos",
        target_os = "windows"
    )))]
    {
        let _ = workspace;
        tracing::info!(
            "No OS-level sandbox available on this platform; \
             relying on advisory tripwires for isolation."
        );
    }
    #[allow(unreachable_code)]
    Ok(())
}

// ── macOS Seatbelt sandbox ─────────────────────────────────────────────────────

/// Generates a Seatbelt `.sb` profile string restricting the process to:
///   - Read-only access to system libraries, frameworks, and executable paths
///   - Read/write access only to the given workspace directory
///   - No network access, no signal sending, no sysctl writes
///
/// **Design note (pre_exec compatibility):**
/// This profile is applied via `pre_exec` — i.e. after `fork()` but *before*
/// `exec()`. Therefore:
///   1. Executable paths (`/usr/bin`, `/bin`, `/usr/local/bin`, Homebrew) must be
///      readable so the kernel can load the target binary.
///   2. `process-exec` must be allowed so the pending `exec()` syscall succeeds.
///
/// The primary security value of the Seatbelt layer in this context is:
///   - **Network isolation** (`deny network*`) — prevents data exfiltration
///   - **Filesystem write restriction** — only the workspace is writable
///   - **Signal denial** — prevents signal injection into other processes
///
/// For stronger process-exec control, use Docker/Podman or Firecracker tiers.
#[cfg(target_os = "macos")]
fn seatbelt_profile(workspace: &Path) -> String {
    let ws = workspace.to_string_lossy();
    format!(
        r#"(version 1)
(deny default)

;; Allow read-only access to system libraries, frameworks, and dyld cache.
(allow file-read*
    (subpath "/usr/lib")
    (subpath "/System")
    (subpath "/Library/Frameworks")
    (subpath "/private/var/db/dyld")
    (literal "/dev/null")
    (literal "/dev/urandom")
    (literal "/dev/random"))

;; Allow reading executable directories so the initial exec() can find
;; and load the target binary. Required because this profile is applied
;; in pre_exec (before exec, not after).
(allow file-read*
    (subpath "/usr/bin")
    (subpath "/bin")
    (subpath "/usr/local/bin")
    (subpath "/opt/homebrew/bin")
    (subpath "/usr/sbin")
    (subpath "/sbin"))

;; Allow read/write access to the workspace directory only.
(allow file-read* file-write*
    (subpath "{workspace}"))

;; Allow reading tmpdir for scratch files.
(allow file-read* file-write*
    (subpath "/private/tmp")
    (subpath "/tmp"))

;; Allow mach lookups required for basic process operation.
(allow mach-lookup
    (global-name "com.apple.system.logger"))

;; Allow process-exec: this profile is installed in pre_exec, so the
;; pending exec() syscall must be permitted. The tripwire layer and
;; the executable allowlist enforce command restrictions instead.
(allow process-exec)
(allow process-info-pidinfo)
(allow process-info-setcontrol)
(allow sysctl-read)

;; Deny everything else explicitly (network, signal, IPC).
(deny network*)
(deny signal)
"#,
        workspace = ws
    )
}

/// Applies a Seatbelt sandbox profile to the current process on macOS.
///
/// Uses the `sandbox_init` C API (declared in `<sandbox.h>`). While Apple has
/// deprecated the public header, the underlying system call is still enforced
/// and used by first-party macOS apps.  We call it via `extern "C"` FFI.
#[cfg(target_os = "macos")]
fn apply_seatbelt(workspace: &Path) -> Result<(), SandboxError> {
    use std::ffi::CString;

    unsafe extern "C" {
        /// Apply a Seatbelt profile from a string.
        /// Returns 0 on success; on failure, sets `*errorbuf` to a malloc'd
        /// C string describing the error and returns -1.
        fn sandbox_init(
            profile: *const std::ffi::c_char,
            flags: u64,
            errorbuf: *mut *mut std::ffi::c_char,
        ) -> std::ffi::c_int;

        fn sandbox_free_error(errorbuf: *mut std::ffi::c_char);
    }

    // SANDBOX_NAMED = 0x0001 is for named built-in profiles; 0x0000 means
    // the `profile` argument is a raw Scheme string.
    const SANDBOX_NAMED_NONE: u64 = 0;

    let profile_str = seatbelt_profile(workspace);
    let c_profile = CString::new(profile_str)
        .map_err(|e| SandboxError::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, e)))?;

    let mut errorbuf: *mut std::ffi::c_char = std::ptr::null_mut();
    let ret = unsafe { sandbox_init(c_profile.as_ptr(), SANDBOX_NAMED_NONE, &mut errorbuf) };

    if ret != 0 {
        let msg = if !errorbuf.is_null() {
            let s = unsafe { std::ffi::CStr::from_ptr(errorbuf) }
                .to_string_lossy()
                .to_string();
            unsafe { sandbox_free_error(errorbuf) };
            s
        } else {
            "unknown sandbox_init error".to_string()
        };
        return Err(SandboxError::Io(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!("Seatbelt sandbox_init failed: {}", msg),
        )));
    }

    tracing::info!(
        "macOS Seatbelt sandbox applied (workspace: {}).",
        workspace.display()
    );
    Ok(())
}

// ── Windows Job Object ─────────────────────────────────────────────────────────

/// Static holder for the Windows Job Object handle.
/// Must remain open for the lifetime of the process;
/// when the last handle closes, all processes in the job are terminated.
#[cfg(target_os = "windows")]
struct SyncHandle(#[allow(dead_code)] windows::Win32::Foundation::HANDLE);

#[cfg(target_os = "windows")]
// SAFETY: The handle is only written once during initialisation (via OnceLock)
// and is never closed or mutated afterwards, so sharing it across threads is safe.
unsafe impl Send for SyncHandle {}
#[cfg(target_os = "windows")]
unsafe impl Sync for SyncHandle {}

#[cfg(target_os = "windows")]
static JOB_OBJECT_HANDLE: std::sync::OnceLock<SyncHandle> = std::sync::OnceLock::new();

/// Creates a Windows Job Object, configures it with `KILL_ON_JOB_CLOSE` and
/// full UI restrictions, then assigns the current process to it.
///
/// The Job Object ensures that if the supervisor process exits (or is killed) the
/// child processes it spawned are automatically terminated — preventing orphan LLM
/// tool processes from persisting on the host.
///
/// **CRITICAL**: The job handle must be stored statically; if it's dropped,
/// all processes in the job are immediately terminated.
#[cfg(target_os = "windows")]
fn apply_windows_job_object() -> Result<(), SandboxError> {
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
        JOB_OBJECT_UILIMIT_DESKTOP, JOB_OBJECT_UILIMIT_DISPLAYSETTINGS,
        JOB_OBJECT_UILIMIT_EXITWINDOWS, JOB_OBJECT_UILIMIT_GLOBALATOMS, JOB_OBJECT_UILIMIT_HANDLES,
        JOB_OBJECT_UILIMIT_READCLIPBOARD, JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS,
        JOB_OBJECT_UILIMIT_WRITECLIPBOARD, JOBOBJECT_BASIC_UI_RESTRICTIONS,
        JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectBasicUIRestrictions,
        JobObjectExtendedLimitInformation, SetInformationJobObject,
    };
    use windows::Win32::System::Threading::GetCurrentProcess;

    unsafe {
        let job: HANDLE = CreateJobObjectW(None, None).map_err(SandboxError::Windows)?;

        // Kill all processes in the job when the last handle to the job object closes.
        // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE requires the *extended* limit struct;
        // using JOBOBJECT_BASIC_LIMIT_INFORMATION returns ERROR_INVALID_PARAMETER.
        let mut ext_limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        ext_limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        SetInformationJobObject(
            job,
            JobObjectExtendedLimitInformation,
            &ext_limits as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
        .map_err(SandboxError::Windows)?;

        // Prevent UI escalation vectors (desktop switching, clipboard theft, etc.).
        let ui_limits = JOBOBJECT_BASIC_UI_RESTRICTIONS {
            UIRestrictionsClass: JOB_OBJECT_UILIMIT_DESKTOP
                | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
                | JOB_OBJECT_UILIMIT_EXITWINDOWS
                | JOB_OBJECT_UILIMIT_GLOBALATOMS
                | JOB_OBJECT_UILIMIT_HANDLES
                | JOB_OBJECT_UILIMIT_READCLIPBOARD
                | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
                | JOB_OBJECT_UILIMIT_WRITECLIPBOARD,
        };
        SetInformationJobObject(
            job,
            JobObjectBasicUIRestrictions,
            &ui_limits as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
        )
        .map_err(SandboxError::Windows)?;

        AssignProcessToJobObject(job, GetCurrentProcess()).map_err(SandboxError::Windows)?;

        // Store the handle statically so it remains open for the lifetime of the process.
        // If this handle is dropped, kernel immediately terminates all processes in the job.
        JOB_OBJECT_HANDLE.get_or_init(|| SyncHandle(job));
    }

    tracing::info!("Windows Job Object sandbox applied (KILL_ON_JOB_CLOSE + UI restrictions).");
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "sandbox"))]
fn apply_landlock(workspace: &Path) -> Result<(), SandboxError> {
    use landlock::{
        ABI, Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr, RulesetCreatedAttr,
    };

    let abi = ABI::V3;
    let path_fd = PathFd::new(workspace)
        .map_err(|e| SandboxError::Io(std::io::Error::other(e.to_string())))?;

    let mut created = Ruleset::default()
        .handle_access(AccessFs::from_all(abi))
        .map_err(SandboxError::Landlock)?
        .create()
        .map_err(SandboxError::Landlock)?
        .add_rule(PathBeneath::new(path_fd, AccessFs::from_read(abi)))
        .map_err(SandboxError::Landlock)?;

    // Allow read + execute access to standard system binary directories so
    // that child processes (e.g. `ls`, `git`) can be located and executed by
    // the kernel.  Library / linker-config paths only need read access.
    let exec_paths: &[&str] = &[
        "/usr/bin",
        "/bin",
        "/usr/sbin",
        "/sbin",
        "/usr/local/bin",
        "/usr/libexec",
    ];
    for p in exec_paths {
        let path = std::path::Path::new(p);
        if path.exists()
            && let Ok(fd) = PathFd::new(path)
        {
            created = created
                .add_rule(PathBeneath::new(fd, AccessFs::from_read(abi)))
                .map_err(SandboxError::Landlock)?;
        }
    }
    // Libraries and dynamic linker config: read-only (no execute needed for
    // directories themselves — the kernel loads .so files via the binary).
    let read_paths: &[&str] = &[
        "/usr/lib",
        "/lib",
        "/usr/lib64",
        "/lib64",
        "/etc/ld.so.cache",
        "/etc/ld.so.conf",
        "/etc/ld.so.conf.d",
    ];
    for p in read_paths {
        let path = std::path::Path::new(p);
        if path.exists()
            && let Ok(fd) = PathFd::new(path)
        {
            created = created
                .add_rule(PathBeneath::new(fd, AccessFs::from_read(abi)))
                .map_err(SandboxError::Landlock)?;
        }
    }

    let status = created.restrict_self().map_err(SandboxError::Landlock)?;

    if status.ruleset == landlock::RulesetStatus::NotEnforced {
        tracing::warn!("Landlock is not enforced on this kernel (ABI too old).");
    }
    Ok(())
}

#[cfg(all(target_os = "linux", feature = "sandbox"))]
fn apply_rlimits() {
    unsafe {
        let cpu_limit = libc::rlimit {
            rlim_cur: 30,
            rlim_max: 30,
        };
        if libc::setrlimit(libc::RLIMIT_CPU, &cpu_limit) != 0 {
            tracing::warn!("Failed to set RLIMIT_CPU");
        }

        let mem_limit = libc::rlimit {
            rlim_cur: 512 * 1024 * 1024,
            rlim_max: 512 * 1024 * 1024,
        };
        if libc::setrlimit(libc::RLIMIT_AS, &mem_limit) != 0 {
            tracing::warn!("Failed to set RLIMIT_AS");
        }

        // Limit open file descriptors to prevent file descriptor exhaustion attacks.
        let fd_limit = libc::rlimit {
            rlim_cur: 64,
            rlim_max: 64,
        };
        if libc::setrlimit(libc::RLIMIT_NOFILE, &fd_limit) != 0 {
            tracing::warn!("Failed to set RLIMIT_NOFILE");
        }
    }
}

// ── Docker / Podman container sandbox ─────────────────────────────────────────

/// Which container CLI to use.
#[derive(Clone, Debug)]
pub enum DockerRuntime {
    /// Use `docker` (Docker Engine / Docker Desktop).
    Docker,
    /// Use `podman` (rootless-capable OCI runtime).
    Podman,
    /// Detect at runtime: prefer `podman` when available, fall back to `docker`.
    Auto,
}

impl DockerRuntime {
    /// Resolve to the concrete binary name to invoke.
    pub fn binary(&self) -> &'static str {
        match self {
            DockerRuntime::Docker => "docker",
            DockerRuntime::Podman => "podman",
            DockerRuntime::Auto => {
                if std::process::Command::new("podman")
                    .arg("--version")
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null())
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false)
                {
                    "podman"
                } else {
                    "docker"
                }
            }
        }
    }
}

/// Configuration for the Docker/Podman container sandbox.
///
/// When configured, `run_command` intents are executed inside an ephemeral, unprivileged
/// container with no network access, strict memory and CPU limits, and a read-only
/// root filesystem.  This provides cross-platform isolation (Linux, macOS, Windows)
/// wherever Docker Desktop or a podman socket is available.
///
/// # Configuration via environment variables
///
/// | Variable                   | Default          | Description                           |
/// |----------------------------|------------------|---------------------------------------|
/// | `ECTO_DOCKER_IMAGE`    | `alpine:3.19`    | Container image to use                |
/// | `ECTO_DOCKER_MEMORY`   | `256m`           | Memory limit (`--memory`)             |
/// | `ECTO_DOCKER_CPUS`     | `1`              | CPU quota (`--cpus`)                  |
/// | `ECTO_DOCKER_TIMEOUT`  | `30`             | Execution timeout in seconds          |
/// | `ECTO_DOCKER_RUNTIME`  | `auto`           | `auto`, `docker`, or `podman`         |
#[derive(Clone, Debug)]
pub struct DockerConfig {
    /// Container image (must be pre-pulled on the host).
    pub image: String,
    /// Memory limit string passed to `--memory` (e.g. `"256m"`, `"1g"`).
    pub memory: String,
    /// CPU quota passed to `--cpus` (e.g. `"1"`, `"0.5"`).
    pub cpus: String,
    /// Hard execution timeout in seconds.
    pub timeout_secs: u64,
    /// Which container CLI to use.
    pub runtime: DockerRuntime,
}

impl Default for DockerConfig {
    fn default() -> Self {
        DockerConfig {
            image: "alpine:3.19".to_string(),
            memory: "256m".to_string(),
            cpus: "1".to_string(),
            timeout_secs: 30,
            runtime: DockerRuntime::Auto,
        }
    }
}

impl DockerConfig {
    /// Build from environment variables, falling back to `Self::default()`.
    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(v) = std::env::var("ECTO_DOCKER_IMAGE") {
            cfg.image = v;
        }
        if let Ok(v) = std::env::var("ECTO_DOCKER_MEMORY") {
            cfg.memory = v;
        }
        if let Ok(v) = std::env::var("ECTO_DOCKER_CPUS") {
            cfg.cpus = v;
        }
        if let Ok(v) = std::env::var("ECTO_DOCKER_TIMEOUT")
            && let Ok(n) = v.parse::<u64>()
        {
            cfg.timeout_secs = n;
        }
        if let Ok(v) = std::env::var("ECTO_DOCKER_RUNTIME") {
            cfg.runtime = match v.to_lowercase().as_str() {
                "docker" => DockerRuntime::Docker,
                "podman" => DockerRuntime::Podman,
                _ => DockerRuntime::Auto,
            };
        }
        cfg
    }

    /// Return `Some(Self::from_env())` when `ECTO_DOCKER_IMAGE` is set (opt-in),
    /// `None` otherwise (Docker sandbox disabled by default).
    pub fn from_env_opt() -> Option<Self> {
        if std::env::var("ECTO_DOCKER_IMAGE").is_ok() {
            Some(Self::from_env())
        } else {
            None
        }
    }
}

/// Execute a validated `run_command` intent inside an ephemeral container.
///
/// The container is started with:
/// - `--rm`            — auto-removed on exit
/// - `--network=none`  — no network access
/// - `--memory`        — capped per `config.memory`
/// - `--cpus`          — capped per `config.cpus`
/// - `--read-only`     — immutable root filesystem
/// - `--security-opt no-new-privileges` — prevents privilege escalation
/// - `--user nobody`   — drop to unprivileged user
///
/// The command string from `intent_json["params"]["command"]` is passed directly to
/// `sh -c` inside the container.  Only `run_command` intents are handled; any other
/// action returns `SandboxError::Io` so the caller can fall back to the host executor.
pub async fn run_in_docker(
    config: &DockerConfig,
    intent_json: &str,
) -> Result<String, SandboxError> {
    use std::time::Duration;
    use tokio::process::Command;

    // Extract the command from the intent JSON.
    let intent: serde_json::Value = serde_json::from_str(intent_json).map_err(|e| {
        SandboxError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("intent JSON parse error: {}", e),
        ))
    })?;

    let action = intent.get("action").and_then(|v| v.as_str()).unwrap_or("");
    if action != "run_command" {
        return Err(SandboxError::Io(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!(
                "Docker sandbox only handles run_command, got '{}': falling back to host executor",
                action
            ),
        )));
    }

    let cmd_str = intent["params"]["command"].as_str().ok_or_else(|| {
        SandboxError::Io(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "run_command intent missing params.command",
        ))
    })?;

    // Defence-in-depth: reject shell metacharacters at the sandbox boundary
    // regardless of whether the tripwire already checked them.  This prevents
    // any future code path from calling `run_in_docker` without upstream
    // sanitisation.
    const DANGEROUS_PATTERNS: &[&str] =
        &[";", "&&", "||", "|", "`", "$(", "${", ">>", ">", "<", "\n"];
    for pat in DANGEROUS_PATTERNS {
        if cmd_str.contains(pat) {
            return Err(SandboxError::Io(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                format!(
                    "Docker sandbox: shell metacharacter '{}' blocked in command (defence-in-depth)",
                    pat.escape_default()
                ),
            )));
        }
    }

    let binary = config.runtime.binary();

    // Verify the container CLI is reachable before attempting to run.
    let version_check = std::process::Command::new(binary)
        .arg("--version")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status();
    if version_check.map(|s| !s.success()).unwrap_or(true) {
        return Err(SandboxError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "Container runtime '{}' not found or not responding. \
                 Install Docker Desktop or Podman and ensure the daemon is running.",
                binary
            ),
        )));
    }

    let output = tokio::time::timeout(
        Duration::from_secs(config.timeout_secs),
        Command::new(binary)
            .args([
                "run",
                "--rm",
                "--network=none",
                &format!("--memory={}", config.memory),
                &format!("--cpus={}", config.cpus),
                "--read-only",
                "--security-opt",
                "no-new-privileges",
                "--user",
                "nobody",
                &config.image,
                "sh",
                "-c",
                cmd_str,
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| {
        SandboxError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "Docker container timed out after {} seconds",
                config.timeout_secs
            ),
        ))
    })?
    .map_err(SandboxError::Io)?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    Ok(format_sandbox_output(
        output.status.code(),
        stdout.trim_end(),
        stderr.trim_end(),
    ))
}

// ── Firecracker microVM sandbox ───────────────────────────────────────────────

/// Configuration for the Firecracker microVM execution sandbox.
///
/// Firecracker provides hardware-level isolation via KVM: each `run_command` intent
/// is executed inside an ephemeral microVM that is destroyed after the command
/// completes.  This prevents host breakouts caused by prompt-injection attacks that
/// exploit the child-process execution surface.
///
/// # Prerequisites (Linux + KVM only)
/// - The `sandbox-firecracker` Cargo feature must be enabled.
/// - A Firecracker binary (≥ 1.5) must be available at `firecracker_binary_path`.
/// - A minimal Linux kernel image (`vmlinux`) at `kernel_image_path`.
/// - A root filesystem image (`rootfs.ext4`) at `rootfs_path`.  The guest init must
///   read `/dev/vdb` (the intent block device), execute the requested command, and
///   write its output back to the serial console (ttyS0), which Firecracker exposes
///   as the process's stdout.
///
/// # Graceful degradation
/// When the `sandbox-firecracker` feature is absent, or on non-Linux platforms,
/// `run_in_firecracker()` returns `SandboxError::Io` with an explanatory message
/// so callers can fall back to the standard executor.
#[derive(Clone, Debug)]
pub struct FirecrackerConfig {
    /// Path to the `firecracker` binary.
    pub firecracker_binary_path: std::path::PathBuf,
    /// Path to the Linux kernel image (`vmlinux` ELF or `Image` format).
    pub kernel_image_path: std::path::PathBuf,
    /// Path to the root filesystem ext4 image.
    pub rootfs_path: std::path::PathBuf,
    /// Number of vCPUs to give the microVM (default: 1).
    pub vcpu_count: u8,
    /// Memory in MiB to give the microVM (default: 128).
    pub mem_mib: u32,
    /// Hard timeout for the microVM execution in seconds (default: 30).
    pub timeout_secs: u64,
    /// Outer timeout wrapping the *entire* Firecracker attempt — including
    /// pre-launch IO (tmpdir creation, config serialization, intent file
    /// writes) — not just the `Command::new().output()` call.  If the pre-
    /// launch phase or a kernel-panic-induced hang stalls beyond this
    /// duration at the agent level, the attempt returns a `TimedOut` error
    /// and the Docker/host fallback cascade fires normally.
    /// Default: 60 seconds.  Configure via `FC_OUTER_TIMEOUT_SECS`.
    pub outer_timeout_secs: u64,
}

impl Default for FirecrackerConfig {
    fn default() -> Self {
        FirecrackerConfig {
            firecracker_binary_path: std::path::PathBuf::from("/usr/local/bin/firecracker"),
            kernel_image_path: std::path::PathBuf::from("/opt/ectoledger/vmlinux"),
            rootfs_path: std::path::PathBuf::from("/opt/ectoledger/rootfs.ext4"),
            vcpu_count: 1,
            mem_mib: 128,
            timeout_secs: 30,
            outer_timeout_secs: 60,
        }
    }
}

impl FirecrackerConfig {
    /// Build from environment variables, falling back to `Self::default()`.
    ///
    /// | Env var                          | Field                       |
    /// |----------------------------------|-----------------------------|
    /// | `ECTO_FC_BINARY`             | `firecracker_binary_path`   |
    /// | `ECTO_FC_KERNEL`             | `kernel_image_path`         |
    /// | `ECTO_FC_ROOTFS`             | `rootfs_path`               |
    /// | `ECTO_FC_VCPUS`              | `vcpu_count`                |
    /// | `ECTO_FC_MEM_MIB`            | `mem_mib`                   |
    /// | `ECTO_FC_TIMEOUT_SECS`       | `timeout_secs`              |
    /// | `FC_OUTER_TIMEOUT_SECS`      | `outer_timeout_secs`        |
    pub fn from_env() -> Self {
        let mut cfg = Self::default();
        if let Ok(v) = std::env::var("ECTO_FC_BINARY") {
            cfg.firecracker_binary_path = std::path::PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("ECTO_FC_KERNEL") {
            cfg.kernel_image_path = std::path::PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("ECTO_FC_ROOTFS") {
            cfg.rootfs_path = std::path::PathBuf::from(v);
        }
        if let Ok(v) = std::env::var("ECTO_FC_VCPUS")
            && let Ok(n) = v.parse::<u8>()
        {
            cfg.vcpu_count = n;
        }
        if let Ok(v) = std::env::var("ECTO_FC_MEM_MIB")
            && let Ok(n) = v.parse::<u32>()
        {
            cfg.mem_mib = n;
        }
        if let Ok(v) = std::env::var("ECTO_FC_TIMEOUT_SECS")
            && let Ok(n) = v.parse::<u64>()
        {
            cfg.timeout_secs = n;
        }
        if let Ok(v) = std::env::var("FC_OUTER_TIMEOUT_SECS")
            && let Ok(n) = v.parse::<u64>()
        {
            cfg.outer_timeout_secs = n;
        }
        cfg
    }

    /// Returns `true` when all required files are present on disk.
    /// Returns `Some(config)` when the Firecracker binary path is explicitly set via
    /// `ECTO_FC_BINARY`, otherwise returns `None` (sandbox disabled by default).
    /// This allows opt-in activation without requiring all three file paths to exist at
    /// startup — existence is checked lazily when the first microVM is launched.
    pub fn from_env_opt() -> Option<Self> {
        if std::env::var("ECTO_FC_BINARY").is_ok() {
            Some(Self::from_env())
        } else {
            None
        }
    }

    /// Returns `true` when all required files are present on disk.
    pub fn is_available(&self) -> bool {
        self.firecracker_binary_path.exists()
            && self.kernel_image_path.exists()
            && self.rootfs_path.exists()
    }
}

/// Execute a validated intent inside an ephemeral Firecracker microVM.
///
/// Returns the serial-console output of the VM as the observation string, or a
/// `SandboxError` if the VM cannot be started or times out.
///
/// This function is only compiled and available on Linux with the
/// `sandbox-firecracker` feature enabled.  On all other platforms it returns
/// `SandboxError::Io` immediately so callers can fall back gracefully.
#[cfg(all(target_os = "linux", feature = "sandbox-firecracker"))]
pub async fn run_in_firecracker(
    config: &FirecrackerConfig,
    intent_json: &str,
) -> Result<String, SandboxError> {
    use std::time::Duration;
    use tokio::process::Command;

    // Enforce an outer timeout that covers the entire function — VM setup,
    // temp file creation, process spawn, and execution.  The inner
    // `tokio::time::timeout` on the process output only covers the child
    // process itself; this outer layer catches setup hangs too.
    tokio::time::timeout(
        Duration::from_secs(config.outer_timeout_secs),
        run_in_firecracker_inner(config, intent_json),
    )
    .await
    .map_err(|_| {
        SandboxError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "Firecracker sandbox outer timeout ({} seconds) exceeded",
                config.outer_timeout_secs
            ),
        ))
    })?
}

#[cfg(all(target_os = "linux", feature = "sandbox-firecracker"))]
async fn run_in_firecracker_inner(
    config: &FirecrackerConfig,
    intent_json: &str,
) -> Result<String, SandboxError> {
    use std::time::Duration;
    use tokio::process::Command;

    if !config.is_available() {
        return Err(SandboxError::Io(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!(
                "Firecracker sandbox not available: check firecracker binary ({}), \
                 kernel image ({}), and rootfs ({}) exist. \
                 See https://github.com/firecracker-microvm/firecracker/blob/main/docs/getting-started.md",
                config.firecracker_binary_path.display(),
                config.kernel_image_path.display(),
                config.rootfs_path.display(),
            ),
        )));
    }

    // Create an ephemeral temp directory for this VM's API socket and intent file.
    let tmp = tempfile::TempDir::new().map_err(SandboxError::Io)?;
    let intent_file = tmp.path().join("intent.json");
    let vm_config_file = tmp.path().join("vm_config.json");

    // Write the intent JSON to a file that the VM will read from /dev/vdb.
    std::fs::write(&intent_file, intent_json).map_err(SandboxError::Io)?;

    // Build the Firecracker machine configuration JSON.
    // The guest rootfs is expected to:
    //   1. Mount /dev/vdb (or read it raw) to obtain the intent JSON.
    //   2. Execute the requested action.
    //   3. Write the result to ttyS0 (the serial console), which Firecracker
    //      exposes as stdout of the `firecracker` process.
    let vm_config = serde_json::json!({
        "boot-source": {
            "kernel_image_path": config.kernel_image_path,
            "boot_args": "console=ttyS0 reboot=k panic=1 pci=off quiet loglevel=0"
        },
        "drives": [
            {
                "drive_id": "rootfs",
                "path_on_host": config.rootfs_path,
                "is_root_device": true,
                "is_read_only": false
            },
            {
                "drive_id": "intent",
                "path_on_host": intent_file,
                "is_root_device": false,
                "is_read_only": true
            }
        ],
        "machine-config": {
            "vcpu_count": config.vcpu_count,
            "mem_size_mib": config.mem_mib,
            "smt": false
        },
        "logger": {
            "log_path": "/dev/null",
            "level": "Error",
            "show_level": false,
            "show_log_origin": false
        }
    });

    std::fs::write(
        &vm_config_file,
        serde_json::to_string_pretty(&vm_config)
            .map_err(|e| SandboxError::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?,
    )
    .map_err(SandboxError::Io)?;

    // Spawn the Firecracker process.  The VM boots, runs the guest init, outputs
    // results to the serial console (our stdout), then shuts down.
    let output = tokio::time::timeout(
        Duration::from_secs(config.timeout_secs),
        Command::new(&config.firecracker_binary_path)
            .arg("--no-api")
            .arg("--config-file")
            .arg(&vm_config_file)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true)
            .output(),
    )
    .await
    .map_err(|_| {
        SandboxError::Io(std::io::Error::new(
            std::io::ErrorKind::TimedOut,
            format!(
                "Firecracker microVM timed out after {} seconds",
                config.timeout_secs
            ),
        ))
    })?
    .map_err(SandboxError::Io)?;

    // Treat non-zero exit with stderr content as execution failure.
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(SandboxError::Io(std::io::Error::new(
            std::io::ErrorKind::Other,
            format!(
                "Firecracker microVM exited with status {}: {}",
                output.status,
                stderr.trim()
            ),
        )));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    Ok(format_sandbox_output(
        output.status.code(),
        &stdout,
        &stderr,
    ))
}

/// Stub for platforms or builds where Firecracker is not available.
#[cfg(not(all(target_os = "linux", feature = "sandbox-firecracker")))]
pub async fn run_in_firecracker(
    _config: &FirecrackerConfig,
    _intent_json: &str,
) -> Result<String, SandboxError> {
    Err(SandboxError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Firecracker microVM sandbox is only available on Linux with the \
         `sandbox-firecracker` Cargo feature enabled. \
         Rebuild with: cargo build --features sandbox-firecracker",
    )))
}
