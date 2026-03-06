// Multi-agent orchestrator: runs three sequential sub-agents (Recon → Analysis → Verify)
// each in their own ledger session, then commits a CrossLedgerSeal event to every session.
//
// The cross-ledger seal hash is sha256(len(recon_tip) ‖ recon_tip ‖ len(analysis_tip) ‖ …) —
// a length-prefixed commitment binding all three ledgers together without merging their chains.
// Length prefixes prevent boundary-collision attacks where sha256("AB"‖"C") == sha256("A"‖"BC").
//
// Per-role policy overrides:
//   ECTO_RECON_POLICY=/path/to/recon.toml    — overrides built-in recon policy
//   ECTO_ANALYSIS_POLICY=/path/to/...toml    — overrides built-in analysis policy
//   ECTO_VERIFY_POLICY=/path/to/...toml      — overrides built-in verify policy
//   --policy /path/to/shared.toml               — fallback shared policy for all roles

use crate::agent::{self, AgentError, AgentLoopConfig};
use crate::ledger;
use crate::llm;
use crate::pool::DatabasePool;
use crate::schema::EventPayload;
use crate::tripwire::{self, Tripwire};
use reqwest::Client;
use sha2::{Digest, Sha256};
use std::path::PathBuf;
use std::sync::Arc;
use uuid::Uuid;

// ── Role definitions ───────────────────────────────────────────────────────────

/// The specialisation of a sub-agent within an orchestrated run.
#[derive(Clone, Debug)]
pub enum AgentRole {
    /// Reads files and runs commands; no HTTP access. Its observations are fed to Analysis.
    Recon,
    /// Receives recon observations as context; reads files; produces findings.
    Analysis,
    /// Independently verifies analysis findings before the run is complete.
    Verify,
}

impl AgentRole {
    pub fn name(&self) -> &'static str {
        match self {
            AgentRole::Recon => "recon",
            AgentRole::Analysis => "analysis",
            AgentRole::Verify => "verify",
        }
    }

    /// Environment variable that, when set to a file path, overrides the built-in
    /// TOML policy for this specific role.
    pub fn policy_env_var(&self) -> &'static str {
        match self {
            AgentRole::Recon => "ECTO_RECON_POLICY",
            AgentRole::Analysis => "ECTO_ANALYSIS_POLICY",
            AgentRole::Verify => "ECTO_VERIFY_POLICY",
        }
    }

    /// Returns a dynamically generated TOML policy string that restricts the role
    /// to its permitted action set.
    fn policy_toml(&self) -> String {
        match self {
            AgentRole::Recon => r#"
name = "recon-agent-policy"
max_steps = 30

[[allowed_actions]]
action = "read_file"

[[allowed_actions]]
action = "run_command"

[[allowed_actions]]
action = "complete"

[[forbidden_actions]]
action = "http_get"
"#
            .to_string(),

            AgentRole::Analysis => r#"
name = "analysis-agent-policy"
max_steps = 20

[[allowed_actions]]
action = "read_file"

[[allowed_actions]]
action = "complete"
"#
            .to_string(),

            AgentRole::Verify => r#"
name = "verify-agent-policy"
max_steps = 15

[[allowed_actions]]
action = "read_file"

[[allowed_actions]]
action = "complete"
"#
            .to_string(),
        }
    }
}

impl std::fmt::Display for AgentRole {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_role_names_and_policies() {
        let r = AgentRole::Recon;
        assert_eq!(r.name(), "recon");
        assert!(r.policy_toml().contains("read_file"));
        let a = AgentRole::Analysis;
        assert_eq!(a.name(), "analysis");
        assert!(a.policy_toml().contains("complete"));
        let v = AgentRole::Verify;
        assert_eq!(v.name(), "verify");
    }

    #[test]
    fn agent_role_policy_env_vars() {
        assert_eq!(AgentRole::Recon.policy_env_var(), "ECTO_RECON_POLICY");
        assert_eq!(AgentRole::Analysis.policy_env_var(), "ECTO_ANALYSIS_POLICY");
        assert_eq!(AgentRole::Verify.policy_env_var(), "ECTO_VERIFY_POLICY");
    }

    #[test]
    fn seal_hash_is_length_prefix_collision_resistant() {
        // Without length prefixes sha256("AB"||"C") == sha256("A"||"BC") — this must not happen.
        let h1 = compute_seal_hash("AB", "C", "X");
        let h2 = compute_seal_hash("A", "BC", "X");
        assert_ne!(
            h1, h2,
            "seal hash must differ when tip boundaries shift: 'AB'+'C' vs 'A'+'BC'"
        );

        // Identical inputs must produce identical hashes (determinism).
        let h3 = compute_seal_hash("abc", "def", "ghi");
        let h4 = compute_seal_hash("abc", "def", "ghi");
        assert_eq!(h3, h4, "seal hash must be deterministic");

        // Any change in any tip must change the hash.
        let h5 = compute_seal_hash("abc", "def", "ghi");
        let h6 = compute_seal_hash("abc", "def", "ghj");
        assert_ne!(h5, h6, "seal hash must reflect changes in any tip");
    }
}

// ── Configuration ──────────────────────────────────────────────────────────────

pub struct OrchestratorConfig {
    pub goal: String,
    /// Optional shared policy file path (applied on top of per-role defaults).
    pub policy: Option<PathBuf>,
    /// Maximum steps per sub-agent (overrides per-role policy max_steps if set).
    pub max_steps_per_agent: Option<u32>,
}

// ── Result ─────────────────────────────────────────────────────────────────────

#[derive(Debug)]
pub struct OrchestrationResult {
    pub recon_session_id: Uuid,
    pub analysis_session_id: Uuid,
    pub verify_session_id: Uuid,
    /// sha256(recon_tip || analysis_tip || verify_tip)
    pub seal_hash: String,
}

// ── Errors ─────────────────────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum OrchestratorError {
    #[error("agent error: {0}")]
    Agent(#[from] AgentError),
    #[error("db error: {0}")]
    Db(#[from] sqlx::Error),
    #[error("no events in {0} session")]
    NoEvents(AgentRole),
    #[error("policy parse error: {0}")]
    PolicyParse(#[from] toml::de::Error),
    /// Returned when a policy contains invalid regex patterns.
    #[error("policy regex error: {0}")]
    PolicyRegex(String),
    /// Returned when a role-specific policy file path (from env var or `--policy`) cannot be read.
    #[error("policy file I/O error: {0}")]
    PolicyIo(String),
}

// ── Implementation ─────────────────────────────────────────────────────────────

/// Runs a three-stage orchestrated audit:
/// 1. Recon agent — collects raw observations.
/// 2. Analysis agent — processes recon output into findings.
/// 3. Verify agent — independently confirms findings.
///
/// Each stage runs in its own ledger session. On completion, a `CrossLedgerSeal`
/// event is appended to every session tying them together.
pub async fn run_orchestration(
    pool: &DatabasePool,
    client: &Client,
    config: OrchestratorConfig,
) -> Result<OrchestrationResult, OrchestratorError> {
    let llm_backend_name = crate::config::llm_backend();
    let llm_model = crate::config::ollama_model();

    // ── Stage 1: Recon ─────────────────────────────────────────────────────────
    println!("[Orchestrator] Starting RECON agent…");
    let recon_id = run_role_agent(
        pool,
        client,
        &config,
        AgentRole::Recon,
        &config.goal,
        &llm_backend_name,
        &llm_model,
    )
    .await?;

    // Collect recon observations as context for the analysis stage.
    let recon_events = pool
        .get_events_by_session(recon_id)
        .await
        .map_err(OrchestratorError::Db)?;
    let recon_tip = recon_events
        .last()
        .map(|e| e.content_hash.clone())
        .ok_or_else(|| OrchestratorError::NoEvents(AgentRole::Recon))?;

    let recon_observations: String = recon_events
        .iter()
        .filter_map(|e| {
            if let EventPayload::Observation { content } = &e.payload {
                Some(content.as_str())
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join("\n---\n");

    // ── Stage 2: Analysis ─────────────────────────────────────────────────────
    println!("[Orchestrator] Starting ANALYSIS agent…");
    let analysis_goal = format!(
        "Analyse the following recon observations collected during the audit of \"{goal}\".\n\
         Produce structured findings with severity ratings.\n\n\
         === RECON OBSERVATIONS ===\n{recon_observations}",
        goal = config.goal,
        recon_observations = recon_observations,
    );
    let analysis_id = run_role_agent(
        pool,
        client,
        &config,
        AgentRole::Analysis,
        &analysis_goal,
        &llm_backend_name,
        &llm_model,
    )
    .await?;

    let analysis_events = pool
        .get_events_by_session(analysis_id)
        .await
        .map_err(OrchestratorError::Db)?;
    let analysis_tip = analysis_events
        .last()
        .map(|e| e.content_hash.clone())
        .ok_or_else(|| OrchestratorError::NoEvents(AgentRole::Analysis))?;

    let analysis_observations: String = analysis_events
        .iter()
        .filter_map(|e| {
            if let EventPayload::Observation { content } = &e.payload {
                Some(content.as_str())
            } else {
                None
            }
        })
        .collect::<Vec<_>>()
        .join("\n---\n");

    // ── Stage 3: Verify ───────────────────────────────────────────────────────
    println!("[Orchestrator] Starting VERIFY agent…");
    let verify_goal = format!(
        "Independently verify the following security findings for \"{goal}\".\n\
         Confirm each finding with evidence or mark it as unverified.\n\n\
         === ANALYSIS FINDINGS ===\n{analysis_observations}",
        goal = config.goal,
        analysis_observations = analysis_observations,
    );
    let verify_id = run_role_agent(
        pool,
        client,
        &config,
        AgentRole::Verify,
        &verify_goal,
        &llm_backend_name,
        &llm_model,
    )
    .await?;

    let verify_events = pool
        .get_events_by_session(verify_id)
        .await
        .map_err(OrchestratorError::Db)?;
    let verify_tip = verify_events
        .last()
        .map(|e| e.content_hash.clone())
        .ok_or_else(|| OrchestratorError::NoEvents(AgentRole::Verify))?;

    // ── Cross-ledger seal ─────────────────────────────────────────────────────
    let seal_hash = compute_seal_hash(&recon_tip, &analysis_tip, &verify_tip);
    let session_ids = vec![recon_id, analysis_id, verify_id];
    let session_tips = vec![recon_tip, analysis_tip, verify_tip];

    let seal_payload = EventPayload::CrossLedgerSeal {
        seal_hash: seal_hash.clone(),
        session_ids: session_ids.clone(),
        session_tip_hashes: session_tips.clone(),
    };

    // Append the seal event to all three sessions.
    for sid in &session_ids {
        if let Err(e) = pool
            .append_event(seal_payload.clone(), Some(*sid), None, None)
            .await
        {
            tracing::warn!("Failed to append CrossLedgerSeal to session {}: {}", sid, e);
        }
    }

    println!("[Orchestrator] Cross-ledger seal: {}", seal_hash);
    println!("[Orchestrator] Recon   session: {}", recon_id);
    println!("[Orchestrator] Analysis session: {}", analysis_id);
    println!("[Orchestrator] Verify  session: {}", verify_id);

    // Attempt EVM anchoring of the cross-ledger seal hash.
    // Gracefully skipped when EVM env vars are not set; non-fatal on RPC errors.
    #[cfg(feature = "evm")]
    {
        match crate::evm_anchor::anchor_to_evm(&seal_hash).await {
            Ok(result) => {
                println!(
                    "[Orchestrator] EVM anchor: tx {} on chain {} ({})",
                    result.tx_hash, result.chain_id, result.rpc_url
                );
            }
            Err(crate::evm_anchor::EvmAnchorError::MissingConfig(_)) => {
                // EVM_RPC_URL / EVM_CONTRACT_ADDRESS / EVM_PRIVATE_KEY not set — skip silently.
            }
            Err(e) => {
                tracing::warn!(
                    "[Orchestrator] EVM anchoring failed (non-fatal): {}. \
                     Set EVM_RPC_URL, EVM_CHAIN_ID, EVM_CONTRACT_ADDRESS, and EVM_PRIVATE_KEY \
                     to enable on-chain seal anchoring.",
                    e
                );
            }
        }
    }

    Ok(OrchestrationResult {
        recon_session_id: recon_id,
        analysis_session_id: analysis_id,
        verify_session_id: verify_id,
        seal_hash,
    })
}

// ── Helpers ────────────────────────────────────────────────────────────────────

async fn run_role_agent(
    pool: &DatabasePool,
    client: &Client,
    config: &OrchestratorConfig,
    role: AgentRole,
    goal: &str,
    llm_backend_name: &str,
    llm_model: &str,
) -> Result<Uuid, OrchestratorError> {
    use crate::policy::PolicyEngine;

    // Policy resolution order (highest priority first):
    //   1. Role-specific env var (ECTO_RECON_POLICY, ECTO_ANALYSIS_POLICY, ECTO_VERIFY_POLICY)
    //   2. Shared --policy file passed to the orchestrate command
    //   3. Built-in hardcoded defaults for this role
    let role_policy_toml = if let Ok(path) = std::env::var(role.policy_env_var()) {
        tracing::info!(
            "[Orchestrator] {} using policy from env var {}: {}",
            role.name(),
            role.policy_env_var(),
            path
        );
        std::fs::read_to_string(&path)
            .map_err(|e| OrchestratorError::PolicyIo(format!("{}: {}", path, e)))?
    } else if let Some(ref policy_path) = config.policy {
        tracing::info!(
            "[Orchestrator] {} using shared --policy file: {}",
            role.name(),
            policy_path.display()
        );
        std::fs::read_to_string(policy_path)
            .map_err(|e| OrchestratorError::PolicyIo(format!("{}: {}", policy_path.display(), e)))?
    } else {
        role.policy_toml()
    };

    let role_policy: crate::policy::AuditPolicy =
        toml::from_str(&role_policy_toml).map_err(OrchestratorError::PolicyParse)?;
    let policy_engine =
        PolicyEngine::new(role_policy).map_err(|e| OrchestratorError::PolicyRegex(e.0))?;
    let policy_hash = crate::policy::policy_hash_bytes(role_policy_toml.as_bytes());

    let (session, signing_key) = pool
        .create_session(goal, llm_backend_name, llm_model, Some(&policy_hash))
        .await
        .map_err(OrchestratorError::Db)?;

    let session_id = session.id;
    let signing_key_arc = Arc::new(signing_key);

    // Bootstrap genesis for this sub-session.
    // Include the session's verifying key in the payload so this genesis event
    // is cryptographically bound to the signing key and cannot be replayed
    // into a different session that uses a different key (TM-2c).
    let genesis_msg = format!("[{}] {}", role.name(), goal);
    let genesis_session_pk = hex::encode(signing_key_arc.verifying_key().to_bytes());
    pool.append_event(
        EventPayload::Genesis {
            message: genesis_msg,
            nonce: Some(hex::encode(uuid::Uuid::new_v4().as_bytes())),
            session_public_key: Some(genesis_session_pk),
        },
        Some(session_id),
        Some(goal),
        Some(&signing_key_arc),
    )
    .await
    .map_err(|e| {
        OrchestratorError::Db(match e {
            ledger::AppendError::Db(d) => d,
            other => sqlx::Error::Protocol(format!("append genesis: {}", other)),
        })
    })?;

    let llm = llm::backend_from_env(client).map_err(|e| {
        OrchestratorError::Agent(AgentError::Io(std::io::Error::other(e.to_string())))
    })?;

    let tripwire = Tripwire::new(
        vec![],
        vec![],
        tripwire::default_banned_command_patterns(),
        5,
        true,
    );
    let loop_config = AgentLoopConfig {
        llm,
        tripwire: &tripwire,
        max_steps: config.max_steps_per_agent,
        session_id: Some(session_id),
        session_goal: goal.to_string(),
        guard: None,
        policy: Some(&policy_engine),
        session_signing_key: Some(signing_key_arc),
        metrics: None,
        egress_tx: None,
        cloud_creds: None,
        interactive: false,
        approval_state: None,
        firecracker_config: None,
        docker_config: None,
        key_rotation_interval_steps: None,
        compensation: None,
        enclave: None,
        enclave_attestation: None,
        cancel: None,
    };

    // run_cognitive_loop now accepts &DatabasePool directly.
    // It internally requires PostgreSQL; SQLite orchestration is not yet supported.
    match agent::run_cognitive_loop(pool, client, loop_config).await {
        Ok(()) => {
            pool.finish_session(session_id, "completed")
                .await
                .map_err(OrchestratorError::Db)?;
        }
        Err(e) => {
            // Ensure the session is explicitly marked as "failed" before
            // propagating so it never stays in "running" state forever.
            if let Err(db_err) = pool.finish_session(session_id, "failed").await {
                tracing::error!(
                    "CRITICAL: failed to mark orchestrator session {} as failed: {}",
                    session_id,
                    db_err
                );
            }
            return Err(OrchestratorError::Agent(e));
        }
    }

    Ok(session_id)
}

/// sha256(len(recon_tip) ‖ recon_tip ‖ len(analysis_tip) ‖ analysis_tip ‖ len(verify_tip) ‖ verify_tip)
///
/// Each tip is prefixed with its byte length encoded as a little-endian u64.
/// This length-prefixed encoding prevents boundary-collision attacks: without it
/// sha256("AB" ‖ "C" ‖ …) would equal sha256("A" ‖ "BC" ‖ …), allowing an attacker
/// who controls two tip values to produce an identical seal hash from different sessions.
fn compute_seal_hash(recon_tip: &str, analysis_tip: &str, verify_tip: &str) -> String {
    let mut hasher = Sha256::new();
    for tip in [recon_tip, analysis_tip, verify_tip] {
        // Length prefix (8 bytes, LE) ensures no two distinct (a,b,c) triples share the same input.
        hasher.update((tip.len() as u64).to_le_bytes());
        hasher.update(tip.as_bytes());
    }
    hex::encode(hasher.finalize())
}
