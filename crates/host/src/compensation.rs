//! Compensating Action / Rollback Protocol
//!
//! Provides a rule-based planner that proposes compensating (rollback) actions
//! when the tripwire or policy engine detects a violation *after* an intent has
//! been executed.  Rules are declared in a TOML file at the path returned by
//! [`config::rollback_rules_path`].
//!
//! # Rule file format
//!
//! ```toml
//! [[rules]]
//! # Match any "write_file" action that was rejected with a PolicyViolation.
//! action       = "write_file"
//! error_kind   = "PolicyViolation"
//! # The compensating intent: delete the file that was just written.
//! comp_action  = "run_command"
//! [rules.comp_params]
//! command  = "rm"
//! args     = ["-f", "{{params.path}}"]
//! comp_justification = "Compensating rollback: removing file written before policy violation was detected."
//!
//! [[rules]]
//! action     = "run_command"
//! error_kind = "BannedCommand"
//! comp_action = "run_command"
//! [rules.comp_params]
//! command = "echo"
//! args    = ["[ROLLBACK] banned command compensation step"]
//! comp_justification = "Compensating rollback: logging banned command execution attempt."
//! ```
//!
//! Template substitution (`{{params.key}}`) expands values from the original
//! rejected intent's `params` map so rollback commands can reference the same
//! paths and arguments as the original action.

use crate::config;
use crate::intent::ProposedIntent;
use crate::tripwire::TripwireError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// ── Rule model ────────────────────────────────────────────────────────────────

/// A single rollback rule loaded from the rules TOML file.
#[derive(Debug, Clone, Deserialize)]
pub struct RollbackRule {
    /// Action type that this rule applies to (e.g. `"run_command"`, `"write_file"`).
    pub action: String,
    /// `TripwireError` variant name that triggers this rule:
    /// `"BannedCommand"`, `"PolicyViolation"`, `"PathNotAllowed"`, etc.
    pub error_kind: String,
    /// The action field of the compensating intent.
    pub comp_action: String,
    /// Params for the compensating intent (may include `{{params.key}}` templates).
    #[serde(default)]
    pub comp_params: HashMap<String, serde_json::Value>,
    /// Justification text for the compensating intent.  Supports `{{params.key}}` templates.
    pub comp_justification: String,
}

/// The top-level structure of the rollback rules TOML file.
#[derive(Debug, Clone, Deserialize, Default)]
struct RollbackRulesFile {
    #[serde(default)]
    rules: Vec<RollbackRule>,
}

// ── Planner ───────────────────────────────────────────────────────────────────

/// Matches a rejected intent against a set of rollback rules and returns the
/// compensating `ProposedIntent` if a rule matches.
#[derive(Debug, Clone, Default)]
pub struct CompensationPlanner {
    rules: Vec<RollbackRule>,
}

impl CompensationPlanner {
    /// Load rules from the configured path.  Returns an empty planner if the
    /// file does not exist (silent — not all deployments need compensation rules).
    pub fn load() -> Self {
        let path = config::rollback_rules_path();
        if !path.exists() {
            return Self::default();
        }
        let content = match std::fs::read_to_string(&path) {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!(
                    "CompensationPlanner: could not read {}: {}",
                    path.display(),
                    e
                );
                return Self::default();
            }
        };
        match toml::from_str::<RollbackRulesFile>(&content) {
            Ok(f) => {
                tracing::info!(
                    "CompensationPlanner: loaded {} rollback rule(s) from {}",
                    f.rules.len(),
                    path.display()
                );
                Self { rules: f.rules }
            }
            Err(e) => {
                tracing::warn!(
                    "CompensationPlanner: invalid TOML in {}: {}",
                    path.display(),
                    e
                );
                Self::default()
            }
        }
    }

    /// Returns `true` if there are any rules loaded.
    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// Attempt to find a compensating `ProposedIntent` for a rejected intent.
    ///
    /// Returns `None` when no rule matches the `(action, error_kind)` pair.
    pub fn plan(
        &self,
        rejected: &ProposedIntent,
        error: &TripwireError,
    ) -> Option<CompensatingAction> {
        let error_kind = tripwire_error_kind(error);
        let rule = self
            .rules
            .iter()
            .find(|r| r.action == rejected.action && r.error_kind == error_kind)?;

        // Template-expand comp_params and comp_justification using the original
        // intent's params so rollback commands reference the same paths/args.
        let expanded_params = expand_params(&rule.comp_params, &rejected.params);
        let justification = expand_str(&rule.comp_justification, &rejected.params);

        Some(CompensatingAction {
            intent: ProposedIntent {
                action: rule.comp_action.clone(),
                params: serde_json::Value::Object(
                    expanded_params
                        .into_iter()
                        .collect::<serde_json::Map<_, _>>(),
                ),
                justification,
                reasoning: format!(
                    "Compensating rollback for {} ({}): {}",
                    rejected.action, error_kind, error,
                ),
            },
            original_action: rejected.action.clone(),
            error_kind: error_kind.to_string(),
        })
    }
}

/// A compensating action to be proposed and executed.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompensatingAction {
    pub intent: ProposedIntent,
    /// The original action type that triggered this compensation.
    pub original_action: String,
    /// The `TripwireError` variant name that matched the rule.
    pub error_kind: String,
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn tripwire_error_kind(e: &TripwireError) -> &'static str {
    match e {
        TripwireError::UnknownAction(_) => "UnknownAction",
        TripwireError::MissingParam(_) => "MissingParam",
        TripwireError::BannedCommand(_) => "BannedCommand",
        TripwireError::PathTraversal(_) => "PathTraversal",
        TripwireError::InvalidPath(_) => "InvalidPath",
        TripwireError::PathNotAllowed(_) => "PathNotAllowed",
        TripwireError::SymlinkEscape(_) => "SymlinkEscape",
        TripwireError::PolicyViolation(_) => "PolicyViolation",
        TripwireError::InvalidUrl(_) => "InvalidUrl",
        TripwireError::HttpsRequired(_) => "HttpsRequired",
        TripwireError::DomainNotAllowed(_) => "DomainNotAllowed",
        TripwireError::InsufficientJustification(_) => "InsufficientJustification",
    }
}

/// Sanitise a template expansion value: keep only safe characters and
/// reject directory-traversal sequences.
fn sanitize_template_value(s: &str) -> String {
    let sanitized: String = s
        .chars()
        .filter(|c| c.is_alphanumeric() || matches!(c, '/' | '.' | '-' | '_'))
        .collect();
    // Remove directory traversal *components* (".." path segments) to prevent
    // path escape. Operate on segments so "/tmp/../etc/passwd" is caught.
    let is_absolute = sanitized.starts_with('/');
    let parts: Vec<&str> = sanitized
        .split('/')
        .filter(|p| !p.is_empty() && *p != "..")
        .collect();
    let mut rebuilt = parts.join("/");
    if is_absolute {
        rebuilt.insert(0, '/');
    }
    rebuilt
}

/// Expand `{{params.key}}` placeholders in a string using values from the
/// rejected intent's params object.
fn expand_str(template: &str, params: &serde_json::Value) -> String {
    if let Some(obj) = params.as_object() {
        let mut out = template.to_string();
        for (k, v) in obj {
            let placeholder = format!("{{{{params.{}}}}}", k);
            let value_str = match v {
                serde_json::Value::String(s) => sanitize_template_value(s),
                other => sanitize_template_value(&other.to_string()),
            };
            out = out.replace(&placeholder, &value_str);
        }
        out
    } else {
        template.to_string()
    }
}

/// Expand template strings in all params values.
fn expand_params(
    template_params: &HashMap<String, serde_json::Value>,
    original_params: &serde_json::Value,
) -> HashMap<String, serde_json::Value> {
    template_params
        .iter()
        .map(|(k, v)| {
            let expanded = match v {
                serde_json::Value::String(s) => {
                    serde_json::Value::String(expand_str(s, original_params))
                }
                serde_json::Value::Array(arr) => serde_json::Value::Array(
                    arr.iter()
                        .map(|item| match item {
                            serde_json::Value::String(s) => {
                                serde_json::Value::String(expand_str(s, original_params))
                            }
                            other => other.clone(),
                        })
                        .collect(),
                ),
                other => other.clone(),
            };
            (k.clone(), expanded)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expand_str_replaces_placeholder() {
        let params = serde_json::json!({"path": "/tmp/foo.txt"});
        let result = expand_str("Removing {{params.path}} as rollback.", &params);
        assert_eq!(result, "Removing /tmp/foo.txt as rollback.");
    }

    #[test]
    fn expand_str_unknown_placeholder_unchanged() {
        let params = serde_json::json!({});
        let result = expand_str("{{params.missing}} stays.", &params);
        assert_eq!(result, "{{params.missing}} stays.");
    }

    #[test]
    fn planner_returns_none_when_no_rules() {
        let planner = CompensationPlanner::default();
        let intent = ProposedIntent {
            action: "run_command".to_string(),
            params: serde_json::json!({}),
            justification: "test".to_string(),
            reasoning: String::new(),
        };
        assert!(
            planner
                .plan(&intent, &TripwireError::BannedCommand("sudo".to_string()))
                .is_none()
        );
    }
}
