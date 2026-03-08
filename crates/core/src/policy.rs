// Policy-as-code: TOML audit policies validated at each step.
//
// TOML schema (all sections optional):
//
//   name = "my-policy"
//   max_steps = 30
//
//   [[allowed_actions]]
//   action = "read_file"
//
//   [[forbidden_actions]]
//   action = "http_get"
//
//   [[command_rules]]
//   program = "curl"
//   arg_pattern = "^https://internal\\.corp"
//   decision = "allow"
//
//   [[command_rules]]
//   program = "curl"
//   arg_pattern = ".*"
//   decision = "deny"
//   reason = "curl only permitted to approved internal domains"
//
//   [[observation_rules]]
//   pattern = "(?i)(password|secret)\\s*[:=]\\s*\\S+"
//   action = "redact"
//   label = "credential_leak"
//
//   [[approval_gates]]
//   trigger = "action == 'run_command' && command_contains('nmap')"
//   require_approval = true
//   timeout_seconds = 300
//   on_timeout = "deny"
//
//   # Extended predicates (joinable with &&):
//   # - path_extension_matches('.key')           — read_file path ends with .key
//   # - path_extension_matches('(\\.pem|\\.key)') — regex over the full path string
//   # - url_host_in_cidr('10.0.0.0/8')            — http_get URL host IP in CIDR
//   # - command_matches_regex('^nmap\\s')          — full command matches regex
//
//   # Plugin system — third-party security tools loaded from the policy file.
//   # Each plugin adds its binary to the executor allowlist and supplies env_passthrough.
//
//   [[plugins]]
//   name = "trivy"
//   binary = "trivy"
//   description = "Container and filesystem vulnerability scanner"
//   arg_patterns = ["^image\\s+\\S+", "^fs\\s+\\."]
//   env_passthrough = ["TRIVY_USERNAME", "TRIVY_PASSWORD"]
//
//   [[plugins]]
//   name = "semgrep"
//   binary = "semgrep"
//   description = "Static analysis tool"
//   arg_patterns = ["^--config\\s+\\S+\\s+\\."]
//   env_passthrough = []

use crate::intent::ProposedIntent;
use regex_lite::Regex;
use serde::Deserialize;

// ── Structs ────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AuditPolicy {
    pub name: Option<String>,
    pub goal: Option<String>,
    pub max_steps: Option<u32>,
    pub require_findings: Option<bool>,
    pub min_severity_threshold: Option<String>,
    pub required_checks: Option<Vec<RequiredCheck>>,
    pub allowed_actions: Option<Vec<AllowedAction>>,
    pub forbidden_actions: Option<Vec<ForbiddenAction>>,
    pub findings: Option<FindingsPolicy>,
    /// Conditional command rules evaluated when action == "run_command".
    #[serde(default)]
    pub command_rules: Vec<CommandRule>,
    /// Post-execution observation content rules.
    #[serde(default)]
    pub observation_rules: Vec<ObservationRule>,
    /// Policy-driven approval gate triggers.
    #[serde(default)]
    pub approval_gates: Vec<ApprovalGateRule>,
    /// Third-party security tool plugins registered in this policy.
    #[serde(default)]
    pub plugins: Vec<PluginDefinition>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RequiredCheck {
    pub name: String,
    pub action: String,
    pub params: Option<toml::Value>,
    pub required: Option<bool>,
    pub timeout_steps: Option<u32>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct AllowedAction {
    pub action: String,
    pub path_pattern: Option<String>,
    pub allowed_commands: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ForbiddenAction {
    pub action: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct FindingsPolicy {
    pub require_evidence_for_severity: Option<Vec<String>>,
    pub evidence_must_reference_observation: Option<bool>,
}

/// A conditional rule applied to `run_command` actions.
/// Rules are evaluated in order; the first matching rule wins.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct CommandRule {
    /// Program name (first token of the command) to match.
    pub program: String,
    /// Regex applied to the full argument string (everything after the program name).
    pub arg_pattern: String,
    /// Decision when both `program` and `arg_pattern` match.
    pub decision: CommandDecision,
    /// Optional human-readable reason logged on deny.
    pub reason: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CommandDecision {
    Allow,
    Deny,
    RequireApproval,
}

/// A rule evaluated against the text content of an observation after execution.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ObservationRule {
    /// Regex applied to the observation content.
    pub pattern: String,
    /// Action to take when the pattern matches.
    pub action: ObservationAction,
    /// Short label recorded in the audit thought.
    pub label: String,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ObservationAction {
    /// Replace the matched text with `[REDACTED:<label>]`.
    Redact,
    /// Log a suspicious-content thought but continue.
    Flag,
    /// Abort the session immediately.
    Abort,
}

/// A policy-level approval gate trigger.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct ApprovalGateRule {
    /// Simple trigger expression (see `eval_trigger`).
    pub trigger: String,
    pub require_approval: bool,
    pub timeout_seconds: Option<u64>,
    pub on_timeout: Option<String>,
}

/// A third-party security tool plugin registered in the policy.
///
/// Each plugin extends the executor allowlist with its `binary` name and may supply
/// argument-pattern allow-rules and environment variable pass-through for that binary.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct PluginDefinition {
    /// Human-readable identifier (e.g. "trivy").
    pub name: String,
    /// Executable binary name or path (e.g. "trivy").
    pub binary: String,
    /// Optional description shown in diagnostics.
    pub description: Option<String>,
    /// Expected SHA-256 hash of the plugin binary (hex-encoded, lowercase).
    /// When set, the executor verifies the binary's hash before spawning it.
    /// (TM-5b hardening: prevents binary replacement / supply-chain attacks.)
    pub sha256: Option<String>,
    /// Regexes applied to the full argument string. Only these patterns are permitted.
    /// An empty list means all arguments are allowed.
    #[serde(default)]
    pub arg_patterns: Vec<String>,
    /// Host environment variables forwarded into the child process for this binary only.
    /// **Deny-by-default**: only variables explicitly listed here are forwarded;
    /// all others are blocked. Names matching sensitive patterns (SECRET, KEY, etc.)
    /// are always blocked regardless of this list (TM-5c hardening).
    #[serde(default)]
    pub env_passthrough: Vec<String>,
}

// ── Errors ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct PolicyViolation(pub String);

impl std::fmt::Display for PolicyViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "policy violation: {}", self.0)
    }
}

impl std::error::Error for PolicyViolation {}

/// Outcome returned by `validate_observation`.
#[derive(Debug, PartialEq)]
pub enum ObservationOutcome {
    /// Content is clean; use as-is.
    Clean,
    /// Content was modified (redactions applied).
    Redacted(String),
    /// A pattern was flagged; observation is logged but continues.
    Flagged(String),
    /// Session must be aborted.
    Abort(String),
}

// ── Engine ─────────────────────────────────────────────────────────────────────

pub struct PolicyEngine {
    policy: AuditPolicy,
    /// Pre-compiled regexes for command_rules, indexed in parallel with `policy.command_rules`.
    compiled_command_rules: Vec<Option<Regex>>,
    /// Pre-compiled regexes for observation_rules, indexed in parallel with `policy.observation_rules`.
    compiled_observation_rules: Vec<Option<Regex>>,
    /// Pre-compiled regexes for plugin arg_patterns, keyed by (plugin_index, pattern_index).
    compiled_plugin_patterns: Vec<Vec<Option<Regex>>>,
}

impl PolicyEngine {
    /// Creates a new `PolicyEngine`, pre-compiling all regex patterns in the policy.
    ///
    /// Returns `Err` if any regex pattern is invalid — this prevents silent
    /// bypasses caused by typos in `deny` rules.
    pub fn new(policy: AuditPolicy) -> Result<Self, PolicyViolation> {
        let mut errors: Vec<String> = Vec::new();
        let compiled_command_rules: Vec<Option<Regex>> = policy
            .command_rules
            .iter()
            .map(|rule| match Regex::new(&rule.arg_pattern) {
                Ok(r) => Some(r),
                Err(e) => {
                    errors.push(format!("command rule regex '{}': {}", rule.arg_pattern, e));
                    None
                }
            })
            .collect();
        let compiled_observation_rules: Vec<Option<Regex>> = policy
            .observation_rules
            .iter()
            .map(|rule| match Regex::new(&rule.pattern) {
                Ok(r) => Some(r),
                Err(e) => {
                    errors.push(format!("observation rule regex '{}': {}", rule.pattern, e));
                    None
                }
            })
            .collect();
        let compiled_plugin_patterns: Vec<Vec<Option<Regex>>> = policy
            .plugins
            .iter()
            .map(|plugin| {
                plugin
                    .arg_patterns
                    .iter()
                    .map(|pattern| match Regex::new(pattern) {
                        Ok(r) => Some(r),
                        Err(e) => {
                            errors.push(format!("plugin arg_pattern '{}': {}", pattern, e));
                            None
                        }
                    })
                    .collect()
            })
            .collect();
        if !errors.is_empty() {
            return Err(PolicyViolation(format!(
                "policy contains invalid regex pattern(s): {}",
                errors.join("; ")
            )));
        }
        Ok(Self {
            policy,
            compiled_command_rules,
            compiled_observation_rules,
            compiled_plugin_patterns,
        })
    }

    /// Validates a proposed intent against the policy.
    /// Returns `Err(PolicyViolation)` if the intent is forbidden.
    /// Also runs `command_rules` for `run_command` actions.
    pub fn validate_intent(
        &self,
        intent: &ProposedIntent,
        step: u32,
    ) -> Result<(), PolicyViolation> {
        // 0. Step limit enforcement.
        if let Some(max) = self.policy.max_steps
            && step >= max
        {
            return Err(PolicyViolation(format!(
                "step {} exceeds policy max_steps ({})",
                step, max
            )));
        }

        let action = intent.action.as_str();

        // 1. Forbidden actions list.
        if let Some(ref forbidden) = self.policy.forbidden_actions {
            for fa in forbidden {
                if fa.action == action {
                    return Err(PolicyViolation(format!(
                        "action '{}' is forbidden by policy",
                        action
                    )));
                }
            }
        }

        // 2. Allowed actions list.
        if let Some(ref allowed) = self.policy.allowed_actions {
            let mut matched = false;
            for aa in allowed {
                if aa.action != action {
                    continue;
                }
                if let Some(ref path_pattern) = aa.path_pattern {
                    let prefix = path_pattern.trim_end_matches("/**").trim_end_matches('*');
                    if let Some(p) = intent.params_path() {
                        // Reject path traversal attempts before prefix check.
                        if p.contains("..") {
                            return Err(PolicyViolation(
                                "path traversal ('..') detected in intent params".into(),
                            ));
                        }
                        if !std::path::Path::new(p).starts_with(std::path::Path::new(prefix)) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
                if let Some(ref commands) = aa.allowed_commands {
                    if let Some(cmd) = intent.params_command() {
                        let first_word = cmd.split_whitespace().next().unwrap_or("");
                        if !commands.iter().any(|c| first_word == c.as_str()) {
                            continue;
                        }
                    } else {
                        continue;
                    }
                }
                matched = true;
                break;
            }
            if !matched {
                return Err(PolicyViolation(format!(
                    "action '{}' with given params is not in policy allowed_actions",
                    action
                )));
            }
        }

        // 3. Command rules (only for run_command).
        if action == "run_command"
            && let Some(cmd_str) = intent.params_command()
        {
            let mut parts = cmd_str.splitn(2, char::is_whitespace);
            let program = parts.next().unwrap_or("").trim();
            let args = parts.next().unwrap_or("").trim();

            // 3a. Explicit command_rules take precedence.
            for (i, rule) in self.policy.command_rules.iter().enumerate() {
                if rule.program != program {
                    continue;
                }
                let re = match self.compiled_command_rules.get(i).and_then(|r| r.as_ref()) {
                    Some(r) => r,
                    None => continue, // regex failed to compile at load time
                };
                if !re.is_match(args) {
                    continue;
                }
                // Pattern matched.
                match rule.decision {
                    CommandDecision::Allow => return Ok(()),
                    CommandDecision::Deny => {
                        let reason = rule
                            .reason
                            .as_deref()
                            .unwrap_or("blocked by command_rules policy");
                        return Err(PolicyViolation(format!(
                            "command '{}' denied: {}",
                            cmd_str, reason
                        )));
                    }
                    CommandDecision::RequireApproval => {
                        // Signal via PolicyViolation with a special prefix that callers can
                        // detect. The agent loop treats this the same as an ApprovalGate trigger.
                        return Err(PolicyViolation(format!(
                            "REQUIRE_APPROVAL: command '{}' requires human approval before execution",
                            cmd_str
                        )));
                    }
                }
            }

            // 3b. Plugin arg_patterns validation for registered plugin binaries.
            self.validate_plugin_args(program, args)?;
        }

        Ok(())
    }

    /// Validates observation content after execution.
    /// Returns `ObservationOutcome` indicating how to handle the content.
    pub fn validate_observation(&self, content: &str) -> ObservationOutcome {
        let mut working = content.to_string();
        let mut flagged_labels: Vec<String> = Vec::new();

        for (i, rule) in self.policy.observation_rules.iter().enumerate() {
            let re = match self
                .compiled_observation_rules
                .get(i)
                .and_then(|r| r.as_ref())
            {
                Some(r) => r,
                None => continue, // regex failed to compile at load time
            };
            if !re.is_match(&working) {
                continue;
            }
            match rule.action {
                ObservationAction::Abort => {
                    return ObservationOutcome::Abort(format!(
                        "observation rule '{}' triggered abort",
                        rule.label
                    ));
                }
                ObservationAction::Flag => {
                    flagged_labels.push(rule.label.clone());
                }
                ObservationAction::Redact => {
                    let label = rule.label.clone();
                    working = re
                        .replace_all(&working, format!("[REDACTED:{}]", label).as_str())
                        .into_owned();
                }
            }
        }

        if !flagged_labels.is_empty() {
            return ObservationOutcome::Flagged(flagged_labels.join(", "));
        }
        if working != content {
            return ObservationOutcome::Redacted(working);
        }
        ObservationOutcome::Clean
    }

    /// Checks whether a proposed intent triggers any approval gate rules.
    /// Returns `Some(ApprovalGateRule)` if approval is required, otherwise `None`.
    pub fn check_approval_gates<'a>(
        &'a self,
        intent: &ProposedIntent,
    ) -> Option<&'a ApprovalGateRule> {
        for gate in &self.policy.approval_gates {
            if !gate.require_approval {
                continue;
            }
            if eval_trigger(&gate.trigger, intent) {
                return Some(gate);
            }
        }
        None
    }

    pub fn max_steps(&self) -> Option<u32> {
        self.policy.max_steps
    }

    pub fn policy(&self) -> &AuditPolicy {
        &self.policy
    }

    /// Binaries that must NEVER be added to the executor allowlist via plugin
    /// definitions, regardless of what a policy file declares.
    const BLOCKED_PLUGIN_BINARIES: &'static [&'static str] = &[
        "bash",
        "sh",
        "zsh",
        "fish",
        "csh",
        "dash",
        "ksh",
        "tcsh",
        "python",
        "python3",
        "ruby",
        "perl",
        "node",
        "php",
        "nc",
        "ncat",
        "socat",
        "telnet",
        "chmod",
        "chown",
        "rm",
        "dd",
        "mkfs",
        "sudo",
        "su",
        "doas",
        // Shell escape vectors
        "env",
        "xargs",
        "script",
        "expect",
        "awk",
        "gawk",
        "mawk",
        "nawk",
        "find",
        "tee",
        // Windows / cross-platform shells
        "pwsh",
        "powershell",
        "cmd",
    ];

    /// Returns plugin binary names registered in this policy, filtered through
    /// a blocklist of dangerous binaries (shells, interpreters, destructive utils).
    pub fn effective_allowed_programs(&self) -> Vec<String> {
        self.policy
            .plugins
            .iter()
            .filter(|p| {
                let lower = p.binary.to_lowercase();
                let base = std::path::Path::new(&lower)
                    .file_name()
                    .and_then(|f| f.to_str())
                    .unwrap_or(&lower);
                if Self::BLOCKED_PLUGIN_BINARIES.contains(&base) {
                    tracing::warn!(
                        "Plugin '{}' declares blocked binary '{}' — not added to allowlist",
                        p.name,
                        p.binary,
                    );
                    false
                } else {
                    true
                }
            })
            .map(|p| p.binary.clone())
            .collect()
    }

    /// Environment variable name patterns that must never be passed through to
    /// plugin child processes.
    const BLOCKED_ENV_PATTERNS: &'static [&'static str] = &[
        "SECRET",
        "KEY",
        "TOKEN",
        "PASSWORD",
        "CREDENTIAL",
        "PRIVATE",
        "DATABASE_URL",
        "DSN",
        "MONGO_URI",
        "REDIS_URL",
        "AUTH",
        "PASSPHRASE",
        "ENCRYPTION",
        "SIGNING",
        "SESSION",
    ];

    /// Returns the `env_passthrough` list for the plugin whose `binary` matches `program`,
    /// filtered to exclude sensitive environment variable names.
    ///
    /// **Deny-by-default (TM-5c)**: only variables explicitly listed in the plugin's
    /// `env_passthrough` are forwarded. Any variable whose name contains a sensitive
    /// substring (SECRET, KEY, TOKEN, etc.) is always blocked even if explicitly listed.
    pub fn plugin_env_passthrough_for(&self, program: &str) -> Vec<String> {
        let lower = program.to_lowercase();
        self.policy
            .plugins
            .iter()
            .find(|p| p.binary.to_lowercase() == lower)
            .map(|p| {
                // Deny-by-default: the returned list contains ONLY variables
                // that are (a) explicitly named in env_passthrough AND (b) do
                // not match any BLOCKED_ENV_PATTERNS.
                p.env_passthrough
                    .iter()
                    .filter(|var| {
                        let upper = var.to_uppercase();
                        let blocked = Self::BLOCKED_ENV_PATTERNS
                            .iter()
                            .any(|pat| upper.contains(pat));
                        if blocked {
                            tracing::warn!(
                                "Plugin '{}' env_passthrough '{}' blocked (sensitive name)",
                                program,
                                var,
                            );
                        }
                        !blocked
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Look up the `PluginDefinition` for a given binary name.
    pub fn plugin_for(&self, program: &str) -> Option<&PluginDefinition> {
        let lower = program.to_lowercase();
        self.policy
            .plugins
            .iter()
            .find(|p| p.binary.to_lowercase() == lower)
    }

    /// Validates argument string for a plugin binary.
    /// Returns `Err` if `arg_patterns` is non-empty and no pattern matches.
    pub fn validate_plugin_args(&self, program: &str, args: &str) -> Result<(), PolicyViolation> {
        let lower = program.to_lowercase();
        let plugin_idx = self
            .policy
            .plugins
            .iter()
            .position(|p| p.binary.to_lowercase() == lower);
        let Some(idx) = plugin_idx else {
            return Ok(()); // not a plugin binary
        };
        let plugin = &self.policy.plugins[idx];
        if plugin.arg_patterns.is_empty() {
            return Ok(()); // no restriction
        }
        if let Some(compiled) = self.compiled_plugin_patterns.get(idx) {
            for re in compiled.iter().flatten() {
                if re.is_match(args) {
                    return Ok(());
                }
            }
        }
        Err(PolicyViolation(format!(
            "plugin '{}': arguments '{}' do not match any allowed arg_pattern",
            plugin.name, args
        )))
    }
}

// ── Trigger expression evaluator ───────────────────────────────────────────────

/// Evaluates a simple trigger expression of the form:
///   `action == 'x' && command_contains('y')`
///
/// Supported predicates (joined by `&&`, evaluated left-to-right):
/// - `action == '<name>'`
/// - `command_contains('<substring>')`
fn eval_trigger(trigger: &str, intent: &ProposedIntent) -> bool {
    for clause in trigger.split("&&") {
        let clause = clause.trim();
        if !eval_clause(clause, intent) {
            return false;
        }
    }
    true
}

fn eval_clause(clause: &str, intent: &ProposedIntent) -> bool {
    if let Some(rest) = clause.strip_prefix("action == ") {
        let expected = rest.trim().trim_matches('\'').trim_matches('"');
        return intent.action == expected;
    }
    if let Some(rest) = clause.strip_prefix("command_contains(") {
        let needle = rest
            .trim_end_matches(')')
            .trim()
            .trim_matches('\'')
            .trim_matches('"');
        if let Some(cmd) = intent.params_command() {
            return cmd.contains(needle);
        }
        return false;
    }
    if let Some(rest) = clause.strip_prefix("path_extension_matches(") {
        let pattern = rest
            .trim_end_matches(')')
            .trim()
            .trim_matches('\'')
            .trim_matches('"');
        if let Some(path_str) = intent.params_path() {
            let path = std::path::Path::new(path_str);
            // If the pattern looks like a regex (contains |, (, or [), compile and match.
            if pattern.contains('|') || pattern.contains('(') || pattern.contains('[') {
                return match Regex::new(pattern) {
                    Ok(re) => re.is_match(path_str),
                    Err(e) => {
                        tracing::warn!("Invalid path_extension_matches regex '{}': {}", pattern, e);
                        true // fail-closed: require approval when policy regex is broken
                    }
                };
            }
            // Plain extension comparison (e.g. ".key" or "key").
            if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
                let pat = pattern.trim_start_matches('.');
                return ext.eq_ignore_ascii_case(pat);
            }
        }
        return false;
    }
    if let Some(rest) = clause.strip_prefix("url_host_in_cidr(") {
        let cidr_str = rest
            .trim_end_matches(')')
            .trim()
            .trim_matches('\'')
            .trim_matches('"');
        if let Some(url_str) = intent.params_url()
            && let Ok(parsed) = url::Url::parse(url_str)
            && let Some(host) = parsed.host_str()
            && let Ok(ip) = host.parse::<std::net::IpAddr>()
        {
            if let Ok(network) = cidr_str.parse::<ipnetwork::IpNetwork>() {
                return network.contains(ip);
            } else {
                tracing::warn!("Invalid CIDR in url_host_in_cidr: '{}'", cidr_str);
            }
        }
        return false;
    }
    if let Some(rest) = clause.strip_prefix("command_matches_regex(") {
        let pattern = rest
            .trim_end_matches(')')
            .trim()
            .trim_matches('\'')
            .trim_matches('"');
        if let Some(cmd) = intent.params_command() {
            return match Regex::new(pattern) {
                Ok(re) => re.is_match(cmd),
                Err(e) => {
                    tracing::warn!("Invalid command_matches_regex pattern '{}': {}", pattern, e);
                    true // fail-closed: require approval when policy regex is broken
                }
            };
        }
        return false;
    }
    // Unknown predicate: fail-closed to prevent silent bypass of approval gates.
    // A typo like 'acton == ...' must trigger the gate, not silently skip it.
    tracing::error!(
        "Unknown policy trigger clause: '{}' — failing closed (approval required)",
        clause
    );
    true
}

// ── Utility ────────────────────────────────────────────────────────────────────

/// SHA-256 hash of policy file contents, stored in genesis and session records.
pub fn policy_hash_bytes(content: &[u8]) -> String {
    crate::hash::sha256_hex(content)
}
