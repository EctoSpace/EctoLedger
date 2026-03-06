use crate::intent::{ProposedIntent, ValidatedIntent};
use regex_lite::Regex;
use std::path::{Component, Path, PathBuf};

#[derive(Clone, Debug)]
pub struct Tripwire {
    allowed_path_prefixes: Vec<PathBuf>,
    allowed_domains: Vec<String>,
    banned_command_patterns: Vec<String>,
    /// Allowlist of permitted executable names (argv[0] basename).
    /// When empty (the default), allowlist checking is disabled for backward compatibility.
    /// Configure with `with_allowed_command_executables()` to enable strict allowlist mode.
    allowed_command_executables: Vec<String>,
    min_justification_length: u32,
    require_https: bool,
}

impl Tripwire {
    pub fn new(
        allowed_path_prefixes: Vec<PathBuf>,
        allowed_domains: Vec<String>,
        banned_command_patterns: Vec<String>,
        min_justification_length: u32,
        require_https: bool,
    ) -> Self {
        Tripwire {
            allowed_path_prefixes,
            allowed_domains,
            banned_command_patterns,
            allowed_command_executables: Vec::new(),
            min_justification_length,
            require_https,
        }
    }

    pub fn with_require_https(mut self, require: bool) -> Self {
        self.require_https = require;
        self
    }

    /// Configure an allowlist of permitted executable names (argv[0] basename).
    /// When set, only commands whose resolved executable basename is in this list are permitted.
    /// An empty list (the default) disables allowlist enforcement.
    pub fn with_allowed_command_executables(mut self, executables: Vec<String>) -> Self {
        self.allowed_command_executables = executables;
        self
    }

    pub fn validate(&self, intent: &ProposedIntent) -> Result<ValidatedIntent, TripwireError> {
        let min_len = self.min_justification_length as usize;
        if intent.action.as_str() != "complete" && intent.justification.trim().len() < min_len {
            return Err(TripwireError::InsufficientJustification(min_len));
        }

        let action = intent.action.as_str();
        match action {
            "run_command" => self.validate_command(intent),
            "read_file" => self.validate_path(intent),
            "http_get" => self.validate_url(intent),
            "complete" => Ok(ValidatedIntent::from_proposed(intent.clone())),
            _ => Err(TripwireError::UnknownAction(intent.action.clone())),
        }
    }

    fn validate_command(&self, intent: &ProposedIntent) -> Result<ValidatedIntent, TripwireError> {
        let cmd = intent
            .params_command()
            .ok_or(TripwireError::MissingParam("command"))?;

        // Tokenize via POSIX shell lexer so backslash escapes, quoting, and concatenated
        // tokens are resolved before any pattern matching.  shlex::split returns None for
        // unterminated quotes — treat that as a malformed (and therefore rejected) command.
        let tokens =
            shlex::split(cmd).ok_or_else(|| TripwireError::BannedCommand(cmd.to_string()))?;
        if tokens.is_empty() {
            return Err(TripwireError::MissingParam("command"));
        }

        // Resolve the executable name: strip any leading path prefix so that
        // /usr/bin/sudo and sudo are treated identically.
        let executable = std::path::Path::new(&tokens[0])
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(&tokens[0])
            .to_lowercase();

        // Allowlist check: if enabled, the resolved executable must be on the list.
        if !self.allowed_command_executables.is_empty()
            && !self
                .allowed_command_executables
                .iter()
                .any(|a| a.to_lowercase() == executable)
        {
            return Err(TripwireError::BannedCommand(cmd.to_string()));
        }

        // Defense-in-depth: reject shell command-chaining metacharacters.
        for token in &tokens {
            // Exact matches for logical operators (prevents blocking URLs with '&' or JSON with '>')
            if matches!(
                token.as_str(),
                ";" | "&&" | "||" | "|" | "&" | ">" | ">>" | "<"
            ) {
                return Err(TripwireError::BannedCommand(format!(
                    "shell operator '{}' detected",
                    token
                )));
            }
            // Substring matches for subshells, command substitutions, and
            // semicolons (these can be embedded in tokens by shlex when not
            // separated by whitespace, e.g. "dir;type").
            for dangerous in &[";", "$(", "`", "${", "<(", ">(", "\n", "\r"] {
                if token.contains(dangerous) {
                    return Err(TripwireError::BannedCommand(format!(
                        "shell metacharacter '{}' detected in: {}",
                        dangerous.escape_default(),
                        cmd
                    )));
                }
            }
        }

        // Defense-in-depth ban check operating on the normalised token stream.
        // Checking both individual tokens (single-word bans like "sudo") and
        // the space-joined reconstruction (multi-word bans like "rm -rf") catches
        // obfuscations that the old raw-string contains() check would have missed
        // (e.g. r\m -rf normalises to rm -rf after shlex tokenisation).
        let normalised_cmd = tokens.join(" ").to_lowercase();
        for banned in &self.banned_command_patterns {
            let banned_lower = banned.to_lowercase();
            // Multi-word pattern: match against full normalised command string.
            if normalised_cmd.contains(&banned_lower) {
                return Err(TripwireError::BannedCommand(cmd.to_string()));
            }
            // Single-token patterns: also check each token individually so that a
            // banned word embedded in a pipeline is caught even if the join differs.
            for token in &tokens {
                if token.to_lowercase().contains(&banned_lower) {
                    return Err(TripwireError::BannedCommand(cmd.to_string()));
                }
            }
        }

        Ok(ValidatedIntent::from_proposed(intent.clone()))
    }

    fn validate_path(&self, intent: &ProposedIntent) -> Result<ValidatedIntent, TripwireError> {
        validate_path_strict(
            intent
                .params_path()
                .ok_or(TripwireError::MissingParam("path"))?,
            &self.allowed_path_prefixes,
        )
        .map(|_| ValidatedIntent::from_proposed(intent.clone()))
    }

    fn validate_url(&self, intent: &ProposedIntent) -> Result<ValidatedIntent, TripwireError> {
        let url_str = intent
            .params_url()
            .ok_or(TripwireError::MissingParam("url"))?;
        let url = url_str
            .parse::<url::Url>()
            .map_err(|_| TripwireError::InvalidUrl(url_str.to_string()))?;
        if self.require_https && url.scheme() != "https" {
            return Err(TripwireError::HttpsRequired(url_str.to_string()));
        }
        let host = url
            .host_str()
            .ok_or(TripwireError::InvalidUrl(url_str.to_string()))?;
        let allowed = self
            .allowed_domains
            .iter()
            .any(|d| host == d.as_str() || host.ends_with(&format!(".{}", d)));
        if !allowed {
            return Err(TripwireError::DomainNotAllowed(host.to_string()));
        }
        Ok(ValidatedIntent::from_proposed(intent.clone()))
    }

    /// Scan a raw user prompt for embedded dangerous patterns.
    ///
    /// This is a defense-in-depth check that runs **before** the cognitive loop
    /// even starts.  It catches adversarial prompts that contain banned command
    /// patterns, prompt-injection markers, or exfiltration keywords — regardless
    /// of whether the LLM would actually propose a matching action.
    ///
    /// Returns `Ok(())` for benign prompts, or `Err(TripwireError::BannedCommand(..))`
    /// when a dangerous pattern is detected.
    pub fn scan_prompt(&self, prompt: &str) -> Result<(), TripwireError> {
        let lower = prompt.to_lowercase();

        // 1. Check against configured banned command patterns.
        for banned in &self.banned_command_patterns {
            let banned_lower = banned.to_lowercase();
            if lower.contains(&banned_lower) {
                return Err(TripwireError::BannedCommand(format!(
                    "prompt contains banned pattern '{}'",
                    banned
                )));
            }
        }

        // 2. Detect common prompt-injection / exfiltration markers.
        static DANGEROUS_PHRASES: &[&str] = &[
            "ignore all previous",
            "ignore your instructions",
            "disregard all previous",
            "override your system prompt",
            "you are now in maintenance mode",
            "disable all security",
            "do anything now",
            "exfiltrate",
            "/etc/shadow",
            "/etc/passwd",
            "~/.ssh/id_rsa",
            "~/.aws/credentials",
            "169.254.169.254",
        ];
        for phrase in DANGEROUS_PHRASES {
            if lower.contains(phrase) {
                return Err(TripwireError::BannedCommand(format!(
                    "prompt contains dangerous phrase '{}'",
                    phrase
                )));
            }
        }

        // 3. Detect Base64 / Hex encoded smuggling.
        //    Attackers encode shell commands or URLs in Base64 or hex to evade
        //    the regex-based banned-pattern and dangerous-phrase checks above.
        //    Flag any contiguous encoded blob that exceeds a plausible "random
        //    noise" threshold (32+ Base64 chars = 8+ groups of 4, or 32+ hex
        //    chars = 16+ pairs of 2).
        static B64_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        static HEX_RE: std::sync::OnceLock<Regex> = std::sync::OnceLock::new();
        let b64_re = B64_RE.get_or_init(|| {
            // Match 8+ groups-of-4 Base64 chars, an optional 2–3 char remainder,
            // and optional `=` padding.  Trailing `\b` is omitted because `=` is
            // a non-word char and would prevent the boundary from matching when
            // the blob is followed by whitespace.
            Regex::new(r"\b(?:[A-Za-z0-9+/]{4}){8,}(?:[A-Za-z0-9+/]{2,3})?={0,2}")
                .expect("invalid b64 scanner pattern")
        });
        let hex_re = HEX_RE.get_or_init(|| {
            Regex::new(r"\b(?:[0-9a-fA-F]{2}){16,}\b").expect("invalid hex scanner pattern")
        });
        if b64_re.is_match(prompt) {
            return Err(TripwireError::BannedCommand(
                "prompt contains suspected base64-encoded payload".to_string(),
            ));
        }
        if hex_re.is_match(prompt) {
            return Err(TripwireError::BannedCommand(
                "prompt contains suspected hex-encoded payload".to_string(),
            ));
        }

        Ok(())
    }
}

/// Normalizes a path without requiring filesystem access: removes `.` components
/// and collapses redundant slashes.
///
/// Returns `Err(TripwireError::PathTraversal)` if the path contains `..`
/// (`Component::ParentDir`). Callers should pre-reject such paths; this provides
/// defense-in-depth so a future caller that forgets the pre-check gets a proper
/// error instead of a panic or silent wrong path.
fn normalize_path(p: &Path) -> Result<PathBuf, TripwireError> {
    let mut out = PathBuf::new();
    for comp in p.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir => out.push(comp.as_os_str()),
            Component::CurDir => {}
            Component::ParentDir => {
                return Err(TripwireError::PathTraversal(p.display().to_string()));
            }
            Component::Normal(s) => out.push(s),
        }
    }
    if out.as_os_str().is_empty() {
        out.push(".");
    }
    Ok(out)
}

/// Strict path validation: reject `..` before any canonicalization, resolve without
/// requiring existence, then for existing paths verify canonical form and symlink targets.
pub fn validate_path_strict(
    path_str: &str,
    allowed_prefixes: &[PathBuf],
) -> Result<PathBuf, TripwireError> {
    // Reject UNC paths (\\server\share or //server/share) — not supported.
    #[cfg(target_os = "windows")]
    {
        if path_str.starts_with(r"\\") || path_str.starts_with(r"//") {
            return Err(TripwireError::InvalidPath(
                "UNC paths are not allowed".to_string(),
            ));
        }
    }
    // Reject NTFS Alternate Data Streams (colon after drive letter position).
    // Enforced on ALL platforms: user-supplied paths may target Windows filesystems
    // or shared mounts even when the host is Linux/macOS.
    if path_str.chars().skip(2).any(|c| c == ':') {
        return Err(TripwireError::InvalidPath(path_str.to_string()));
    }
    let raw = Path::new(path_str);
    for component in raw.components() {
        if component == Component::ParentDir {
            return Err(TripwireError::PathTraversal(path_str.to_string()));
        }
    }
    let absolute = if raw.is_absolute() {
        raw.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|_| TripwireError::InvalidPath(path_str.to_string()))?
            .join(raw)
    };
    let normalized = normalize_path(&absolute)?;
    let check_path = if normalized.exists() {
        let canonical = normalized
            .canonicalize()
            .map_err(|_| TripwireError::InvalidPath(path_str.to_string()))?;
        if !allowed_prefixes.iter().any(|p| canonical.starts_with(p)) {
            return Err(TripwireError::SymlinkEscape(
                canonical.display().to_string(),
            ));
        }
        canonical
    } else {
        // File does not yet exist.  To prevent an attacker from planting a symlink
        // in an *intermediate* directory that redirects a write outside the allowed
        // prefix via a non-existent leaf path, canonicalize the parent directory
        // (resolving any symlinks there) and then re-attach the filename component.
        let file_name = normalized
            .file_name()
            .ok_or_else(|| TripwireError::InvalidPath(path_str.to_string()))?;
        let parent = normalized
            .parent()
            .ok_or_else(|| TripwireError::InvalidPath(path_str.to_string()))?;
        let canonical_parent = parent
            .canonicalize()
            .map_err(|_| TripwireError::PathTraversal(path_str.to_string()))?;
        canonical_parent.join(file_name)
    };
    if !allowed_prefixes.iter().any(|p| check_path.starts_with(p)) {
        return Err(TripwireError::PathNotAllowed(
            check_path.display().to_string(),
        ));
    }
    Ok(check_path)
}

pub fn default_banned_command_patterns() -> Vec<String> {
    vec![
        "rm -rf".to_string(),
        "sudo".to_string(),
        "mkfs".to_string(),
        "dd".to_string(),
        "/dev/sda".to_string(),
        "chmod 777".to_string(),
        "> /dev/".to_string(),
        "wget".to_string(),
        "curl | sh".to_string(),
        "| sh".to_string(),
        "| bash".to_string(),
    ]
}

/// Returns a conservative default allowlist of executable names (argv[0] basename).
/// These mirror the executor's `ALLOWED_PROGRAMS` list so both layers are consistent.
/// Apply with `Tripwire::new(...).with_allowed_command_executables(default_allowed_command_executables())`.
pub fn default_allowed_command_executables() -> Vec<String> {
    vec![
        "ls".to_string(),
        "cat".to_string(),
        "find".to_string(),
        "grep".to_string(),
        "head".to_string(),
        "tail".to_string(),
        "wc".to_string(),
        "stat".to_string(),
        "file".to_string(),
        "diff".to_string(),
        "md5sum".to_string(),
        "sha256sum".to_string(),
        "sha1sum".to_string(),
        "ps".to_string(),
        "echo".to_string(),
        "date".to_string(),
        "id".to_string(),
        "hostname".to_string(),
        "uname".to_string(),
        "df".to_string(),
        "du".to_string(),
        "pwd".to_string(),
        "which".to_string(),
        "whoami".to_string(),
        "curl".to_string(),
        // NOTE: python3, node, git, and cargo are intentionally excluded.
        // They are interpreters / build tools that can execute arbitrary code
        // via -c, -e, hooks, or build scripts, bypassing banned pattern checks.
    ]
}

#[derive(Debug, thiserror::Error)]
pub enum TripwireError {
    #[error("unknown action: {0}")]
    UnknownAction(String),
    #[error("missing param: {0}")]
    MissingParam(&'static str),
    #[error("banned command: {0}")]
    BannedCommand(String),
    #[error("path traversal: {0}")]
    PathTraversal(String),
    #[error("invalid path: {0}")]
    InvalidPath(String),
    #[error("path not allowed: {0}")]
    PathNotAllowed(String),
    #[error("symlink escapes allowed path: {0}")]
    SymlinkEscape(String),
    #[error("policy violation: {0}")]
    PolicyViolation(String),
    #[error("invalid url: {0}")]
    InvalidUrl(String),
    #[error("https required: {0}")]
    HttpsRequired(String),
    #[error("domain not allowed: {0}")]
    DomainNotAllowed(String),
    #[error("justification missing or too short (min {0} chars)")]
    InsufficientJustification(usize),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tripwire_rejects_banned_command() {
        let tw = Tripwire::new(
            vec![],
            vec![],
            vec!["sudo".to_string(), "rm -rf".to_string()],
            5,
            true,
        );
        let intent = ProposedIntent {
            action: "run_command".to_string(),
            params: serde_json::json!({ "command": "sudo ls" }),
            justification: "elevated privilege check".to_string(),
            reasoning: String::new(),
        };
        assert!(tw.validate(&intent).is_err());
    }

    #[test]
    fn tripwire_rejects_empty_justification() {
        let tw = Tripwire::new(vec![], vec![], vec![], 5, true);
        let intent = ProposedIntent {
            action: "run_command".to_string(),
            params: serde_json::json!({ "command": "ls -la" }),
            justification: String::new(),
            reasoning: String::new(),
        };
        assert!(matches!(
            tw.validate(&intent),
            Err(TripwireError::InsufficientJustification(_))
        ));
    }

    #[test]
    fn tripwire_accepts_safe_command() {
        let tw = Tripwire::new(vec![], vec![], vec!["sudo".to_string()], 5, true);
        let intent = ProposedIntent {
            action: "run_command".to_string(),
            params: serde_json::json!({ "command": "ls -la" }),
            justification: "listing directory contents".to_string(),
            reasoning: String::new(),
        };
        assert!(tw.validate(&intent).is_ok());
    }

    #[test]
    fn tripwire_complete_always_ok() {
        let tw = Tripwire::new(vec![], vec![], vec!["sudo".to_string()], 5, true);
        let intent = ProposedIntent {
            action: "complete".to_string(),
            params: serde_json::Value::Object(serde_json::Map::new()),
            justification: String::new(),
            reasoning: String::new(),
        };
        assert!(tw.validate(&intent).is_ok());
    }
}
