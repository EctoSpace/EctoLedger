use crate::cloud_creds::CloudCredentialSet;
use crate::compensation::CompensationPlanner;
use crate::config;
use crate::executor;
use crate::guard::GuardDecision;
use crate::intent::ProposedIntent;
use crate::intent::ValidatedIntent;
use crate::ledger::{self, AppendError};
use crate::llm;
use crate::output_scanner;
use crate::policy::PolicyEngine;
use crate::pool::DatabasePool;
use crate::schema::{EventPayload, LedgerEventRow};
use crate::snapshot;
use crate::tripwire::{Tripwire, TripwireError};
use crate::wakeup::{self, WakeUpError};
use ed25519_dalek::SigningKey;
use reqwest::Client;
use sqlx::PgPool;
use std::sync::Arc;
use tokio_util::sync::CancellationToken;
use uuid::Uuid;

pub struct AgentLoopConfig<'a> {
    pub llm: Box<dyn crate::llm::LlmBackend>,
    pub tripwire: &'a Tripwire,
    pub max_steps: Option<u32>,
    pub session_id: Option<Uuid>,
    pub session_goal: String,
    pub guard: Option<Box<dyn crate::guard::GuardExecutor>>,
    pub policy: Option<&'a PolicyEngine>,
    pub session_signing_key: Option<Arc<SigningKey>>,
    pub metrics: Option<std::sync::Arc<crate::metrics::Metrics>>,
    /// Optional channel to the async webhook egress worker. When set, flagged and aborted
    /// observations are forwarded in the background without blocking the cognitive loop.
    pub egress_tx: Option<tokio::sync::mpsc::Sender<crate::webhook::EgressEvent>>,
    /// Ephemeral cloud credentials injected only into matching child processes.
    pub cloud_creds: Option<Arc<CloudCredentialSet>>,
    /// When true, approval gate decisions are prompted interactively on stdin instead of
    /// waiting for the REST API (Mode A). When false, the shared ApprovalState is polled.
    pub interactive: bool,
    /// Shared approval state from the Observer server, enabling REST-driven gate decisions.
    pub approval_state: Option<Arc<crate::approvals::ApprovalState>>,
    /// Optional Firecracker microVM configuration.  When present and the Firecracker binary,
    /// kernel, and rootfs are available, `run_command` intents are executed inside an
    /// ephemeral KVM microVM instead of as host child processes.  Requires Linux and the
    /// `sandbox-firecracker` Cargo feature.  Falls back to the standard executor on error.
    pub firecracker_config: Option<crate::sandbox::FirecrackerConfig>,
    /// Optional Docker/Podman container sandbox configuration.  When present, `run_command`
    /// intents are executed inside an ephemeral, network-isolated container.  This works on
    /// Linux, macOS, and Windows wherever Docker Desktop or Podman is running.
    /// Priority: Firecracker (if configured) > Docker > host executor.
    pub docker_config: Option<crate::sandbox::DockerConfig>,
    /// If set, the session signing key is rotated every N steps.  A `KeyRotation` event
    /// is appended to the ledger each time the key changes, preserving a complete
    /// cryptographic audit trail.  `None` (the default) disables automatic rotation.
    pub key_rotation_interval_steps: Option<u32>,
    /// Optional compensating-action planner loaded from `.ectoledger/rollback_rules.toml`.
    /// When set, tripwire rejections are matched against rollback rules and a compensating
    /// `ProposedIntent` is proposed as a `Thought` event for the next iteration.
    pub compensation: Option<CompensationPlanner>,
    /// Optional enclave runtime for confidential inference.  When set, LLM prompts are
    /// routed through the enclave's `execute()` method, and the resulting attestation
    /// is stored for embedding in the `.elc` certificate.
    pub enclave: Option<Box<dyn crate::enclave::runtime::EnclaveRuntime>>,
    /// Attestation evidence collected during enclave execution.
    /// Populated automatically after the first enclave-wrapped LLM call.
    pub enclave_attestation: Option<crate::enclave::runtime::EnclaveAttestation>,
    /// Optional cancellation token for cooperative shutdown.  When cancelled, the
    /// cognitive loop breaks gracefully at the next iteration boundary instead of
    /// relying on external future-drop from `tokio::select!`.
    pub cancel: Option<CancellationToken>,
}

pub async fn run_cognitive_loop(
    db: &DatabasePool,
    _client: &Client,
    mut config: AgentLoopConfig<'_>,
) -> Result<(), AgentError> {
    // The cognitive loop currently requires PostgreSQL internally (40+ callsites).
    // Accept DatabasePool for interface correctness; extract PgPool here.
    let pool: &PgPool = db.as_pg().ok_or_else(|| {
        AgentError::Io(std::io::Error::other(
            "run_cognitive_loop currently requires PostgreSQL (SQLite support planned)",
        ))
    })?;
    // NOTE: recover_zombie_sessions / recover_incomplete_actions are called
    // once at server startup (see commands/serve.rs), NOT per-session.  Running
    // them here would mark every *other* actively-running session as failed.
    let session_goal = config
        .session_id
        .as_ref()
        .map(|_| config.session_goal.as_str());

    // ── Prompt-level tripwire scan ─────────────────────────────────────────
    // Before entering the cognitive loop, scan the raw user prompt for banned
    // command patterns and known adversarial phrases.  This catches prompt-
    // injection attacks even when the LLM would not reproduce the dangerous
    // content in its proposed action (e.g. the LLM simply refuses or completes
    // without executing, but the prompt itself was malicious).
    if let Err(e) = config.tripwire.scan_prompt(&config.session_goal) {
        if let Some(m) = &config.metrics {
            m.inc_tripwire_rejections();
        }
        let msg = format!("Tripwire rejected: {}", e);
        append_thought(
            pool,
            &msg,
            config.session_id,
            session_goal,
            &config,
            config.metrics.as_deref(),
        )
        .await?;
        if let Some(ref tx) = config.egress_tx {
            crate::webhook::try_enqueue_event(
                tx,
                crate::webhook::EgressEvent {
                    session_id: config.session_id.unwrap_or_default(),
                    severity: "abort".to_string(),
                    rule_label: msg.clone(),
                    observation_preview: msg.chars().take(200).collect(),
                    kind: crate::webhook::EgressKind::TripwireRejection,
                },
            );
        }
        return Err(AgentError::TripwireAbort(msg));
    }

    // Log cloud credential set name (never the values) as an auditable thought.
    if let Some(ref creds) = config.cloud_creds {
        append_thought(
            pool,
            &format!(
                "Cloud credential set loaded: {} (provider: {})",
                creds.name, creds.provider
            ),
            config.session_id,
            session_goal,
            &config,
            config.metrics.as_deref(),
        )
        .await?;
    }

    // ── Enclave initialization ─────────────────────────────────────────────
    // If an enclave runtime is configured, initialize it now and persist the
    // attestation so that certificate generation can embed it later.
    //
    // EnclaveRuntime methods are synchronous (blocking I/O for remote enclaves),
    // so we run initialization on the blocking thread pool to avoid stalling the
    // Tokio executor.
    if let Some(mut enc) = config.enclave.take() {
        let init_result = tokio::task::spawn_blocking(move || {
            let result = enc.initialize();
            (enc, result)
        })
        .await
        .map_err(|e| {
            AgentError::Io(std::io::Error::other(format!(
                "Enclave init task panicked: {e}"
            )))
        })?;

        let (enc, result) = init_result;
        match result {
            Ok(att) => {
                // Persist to DB so `build_certificate` can embed it even after the process exits.
                if let Some(sid) = config.session_id
                    && let Err(e) = crate::ledger::store_enclave_attestation(pool, sid, &att).await
                {
                    tracing::warn!(
                        "Failed to persist enclave attestation for session {}: {}",
                        sid,
                        e
                    );
                }
                append_thought(
                    pool,
                    &format!(
                        "Enclave initialized: level={}, measurement={}",
                        att.level, att.measurement_hash,
                    ),
                    config.session_id,
                    session_goal,
                    &config,
                    config.metrics.as_deref(),
                )
                .await?;
                config.enclave_attestation = Some(att);
                config.enclave = Some(enc);
            }
            Err(e) => {
                append_thought(
                    pool,
                    &format!("Enclave initialization failed (falling back to plain LLM): {e}"),
                    config.session_id,
                    session_goal,
                    &config,
                    config.metrics.as_deref(),
                )
                .await?;
                // Enclave already taken out of config; it will be dropped here.
            }
        }
    }

    let mut step: u32 = 0;
    let max_steps = config
        .max_steps
        .or_else(|| config.policy.and_then(|p| p.max_steps()))
        .unwrap_or_else(config::max_steps);
    let llm_error_limit = config::llm_error_limit();
    let guard_denial_limit = config::guard_denial_limit();
    let mut consecutive_llm_errors: u32 = 0;
    let mut consecutive_guard_denials: u32 = 0;
    let mut consecutive_justification_failures: u32 = 0;
    let justification_failure_limit = config::justification_failure_limit();

    loop {
        // ── Cooperative cancellation check ─────────────────────────────────
        // If the CancellationToken has been triggered, break immediately so
        // the caller (audit.rs / server.rs) can mark the session appropriately.
        if let Some(ref cancel) = config.cancel
            && cancel.is_cancelled()
        {
            tracing::info!("CancellationToken triggered — breaking cognitive loop cooperatively.");
            return Err(AgentError::Cancelled);
        }

        if step >= max_steps {
            break;
        }
        step += 1;

        let state = perceive(pool).await?;
        if detect_loop(&state.replayed_events) {
            append_thought(
                pool,
                "Loop detected (repeated action); completing.",
                config.session_id,
                session_goal,
                &config,
                config.metrics.as_deref(),
            )
            .await?;
            let intent = ProposedIntent {
                action: "complete".to_string(),
                params: serde_json::json!({}),
                justification: "loop detected".to_string(),
                reasoning: String::new(),
            };
            let validated = match config.tripwire.validate(&intent) {
                Ok(v) => v,
                Err(e) => {
                    append_thought(
                        pool,
                        &format!("Tripwire rejected complete: {}", e),
                        config.session_id,
                        session_goal,
                        &config,
                        config.metrics.as_deref(),
                    )
                    .await?;
                    continue;
                }
            };
            let event_id = append_action(
                pool,
                &validated,
                config.session_id,
                session_goal,
                &config,
                config.metrics.as_deref(),
            )
            .await?;
            ledger::mark_action_executing(pool, event_id)
                .await
                .map_err(AgentError::Db)?;
            // Propagate executor errors instead of silently discarding them.
            // For `complete` this always returns Ok, but explicit error handling
            // ensures any future executor change is not silently swallowed.
            executor::execute_with_policy(validated, config.cloud_creds.clone(), config.policy)
                .await
                .map_err(|e| {
                    tracing::warn!("Loop-detection complete action executor error: {}", e);
                    AgentError::Io(std::io::Error::other(e.to_string()))
                })?;
            ledger::mark_action_completed(pool, event_id)
                .await
                .map_err(AgentError::Db)?;
            append_observation(
                pool,
                "Completed due to loop detection.",
                config.session_id,
                session_goal,
                &config,
                config.metrics.as_deref(),
            )
            .await?;

            // Issue a W3C Verifiable Credential for the completed session,
            // same as the normal completion path.
            if let (Some(ref key), Some(session_id)) =
                (config.session_signing_key.clone(), config.session_id)
            {
                use crate::verifiable_credential::build_vc_jwt;
                let policy_hash: Option<String> = sqlx::query_scalar::<_, Option<String>>(
                    "SELECT policy_hash FROM agent_sessions WHERE id = $1",
                )
                .bind(session_id)
                .fetch_optional(pool)
                .await
                .ok()
                .flatten()
                .flatten();
                let vc_jwt = build_vc_jwt(
                    session_id,
                    &config.session_goal,
                    policy_hash.as_deref(),
                    Some(key.as_ref()),
                );
                let vc_payload = EventPayload::VerifiableCredential { vc_jwt };
                if let Err(e) = ledger::append_event(
                    pool,
                    vc_payload,
                    config.session_id,
                    session_goal,
                    config.session_signing_key.as_deref(),
                )
                .await
                {
                    tracing::warn!(
                        "Failed to append VerifiableCredential event (loop-detect): {}",
                        e
                    );
                } else {
                    tracing::info!(
                        "Verifiable Credential issued for session {} (loop-detect)",
                        session_id
                    );
                }
            }
            break;
        }
        let few_shot = if state.replayed_events.len() <= 2 {
            llm::few_shot_examples()
        } else {
            ""
        };
        let user = format!(
            "Current goal: {}\n\n{}{}",
            config.session_goal,
            few_shot,
            llm::state_to_prompt(&state, 50)
        );
        // Token budget circuit breaker: abort before making the next LLM call if the
        // cumulative approximate token count exceeds AGENT_TOKEN_BUDGET_MAX.
        if let Some(budget) = config::token_budget_max() {
            let used = config
                .metrics
                .as_ref()
                .map(|m| m.current_token_count())
                .unwrap_or(0);
            if used >= budget {
                append_thought(
                    pool,
                    &format!(
                        "Token budget exceeded: ~{} tokens used, limit is {}. Aborting session.",
                        used, budget
                    ),
                    config.session_id,
                    session_goal,
                    &config,
                    config.metrics.as_deref(),
                )
                .await?;
                return Err(AgentError::TokenBudgetExceeded);
            }
        }

        let intent = match config.llm.propose(llm::DEFAULT_SYSTEM_PROMPT, &user).await {
            Ok(i) => {
                // Account for the prompt and response in the token budget.
                if let Some(m) = &config.metrics {
                    m.add_tokens_for_text(&user);
                    m.add_tokens_for_text(&i.action);
                    m.add_tokens_for_text(&i.justification);
                }
                consecutive_llm_errors = 0;
                i
            }
            Err(e) => {
                consecutive_llm_errors += 1;
                append_thought(
                    pool,
                    &format!("LLM error: {}", e),
                    config.session_id,
                    session_goal,
                    &config,
                    config.metrics.as_deref(),
                )
                .await?;
                if consecutive_llm_errors >= llm_error_limit {
                    let reason = format!(
                        "{} consecutive LLM errors; aborting session.",
                        consecutive_llm_errors
                    );
                    ledger::append_event(
                        pool,
                        EventPayload::CircuitBreaker {
                            reason,
                            consecutive_failures: consecutive_llm_errors,
                        },
                        config.session_id,
                        session_goal,
                        config.session_signing_key.as_deref(),
                    )
                    .await
                    .map_err(AgentError::Append)?;
                    if let Some(m) = &config.metrics {
                        m.inc_events_appended();
                    }
                    return Err(AgentError::CircuitBreaker);
                }
                continue;
            }
        };

        if let Some(policy) = config.policy {
            if let Err(pv) = policy.validate_intent(&intent, step) {
                if let Some(m) = &config.metrics {
                    m.inc_tripwire_rejections();
                }
                append_thought(
                    pool,
                    &format!("Policy rejected: {}", pv),
                    config.session_id,
                    session_goal,
                    &config,
                    config.metrics.as_deref(),
                )
                .await?;
                continue;
            }

            // Check approval gate rules from policy.
            if let Some(gate) = policy.check_approval_gates(&intent) {
                let gate_id = uuid::Uuid::new_v4().to_string();
                let timeout_secs = gate.timeout_seconds.unwrap_or(300);
                let on_timeout_deny = gate.on_timeout.as_deref() != Some("allow");

                let params_summary =
                    serde_json::to_string(&intent.params).unwrap_or_else(|_| "{}".to_string());
                ledger::append_event(
                    pool,
                    crate::schema::EventPayload::ApprovalRequired {
                        gate_id: gate_id.clone(),
                        action_name: intent.action.to_string(),
                        action_params_summary: params_summary,
                    },
                    config.session_id,
                    session_goal,
                    config.session_signing_key.as_deref(),
                )
                .await
                .map_err(|e| {
                    AgentError::Db(match e {
                        AppendError::Db(d) => d,
                        other => sqlx::Error::Protocol(format!("approval gate event: {}", other)),
                    })
                })?;

                // Collect the human operator's decision.
                let approved = if config.interactive {
                    // Mode A: prompt on stdin via a dedicated synchronous thread.
                    // Using std::thread avoids the "dangling read" bug where
                    // tokio::io::stdin() cannot be cancelled and blocks a runtime
                    // thread slot indefinitely if the timeout fires first.
                    let params_str =
                        serde_json::to_string(&intent.params).unwrap_or_else(|_| "{}".to_string());
                    let action_str = intent.action.to_string();

                    eprintln!();
                    eprintln!("[APPROVAL REQUIRED]");
                    eprintln!("  Action : {}", action_str);
                    eprintln!("  Params : {}", params_str);
                    eprint!("Approve? [y/N] (auto-deny in {}s): ", timeout_secs);
                    use std::io::Write;
                    let _ = std::io::stderr().flush();

                    let (tx, mut rx) = tokio::sync::mpsc::channel::<bool>(1);
                    std::thread::spawn(move || {
                        let mut line = String::new();
                        let result = match std::io::stdin().read_line(&mut line) {
                            Ok(_) => line.trim().to_lowercase() == "y",
                            Err(_) => false,
                        };
                        let _ = tx.blocking_send(result);
                    });

                    tokio::select! {
                        result = rx.recv() => result.unwrap_or(!on_timeout_deny),
                        _ = tokio::time::sleep(std::time::Duration::from_secs(timeout_secs)) => !on_timeout_deny,
                    }
                } else if let Some(ref approval_state) = config.approval_state {
                    // Mode B: poll the shared ApprovalState (REST API decisions from the dashboard).
                    let poll_session = config.session_id.unwrap_or_default();
                    let poll_gate = gate_id.clone();
                    let poll_state = Arc::clone(approval_state);
                    let deadline =
                        std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs);
                    loop {
                        if let Some((decided, _reason)) =
                            poll_state.take_decision(poll_session, &poll_gate)
                        {
                            break decided;
                        }
                        if std::time::Instant::now() >= deadline {
                            break !on_timeout_deny;
                        }
                        tokio::time::sleep(std::time::Duration::from_secs(2)).await;
                    }
                } else {
                    // No approval mechanism configured — apply the timeout policy.
                    !on_timeout_deny
                };

                // Record the decision source in the ledger.
                // ApprovalDecision is a security-critical audit event — failure to
                // write it must surface as an error, not be silently discarded.
                let operator = if config.interactive { "cli" } else { "api" };
                ledger::append_event(
                    pool,
                    crate::schema::EventPayload::ApprovalDecision {
                        gate_id: gate_id.clone(),
                        approved,
                        reason: Some(format!("operator:{}", operator)),
                    },
                    config.session_id,
                    session_goal,
                    config.session_signing_key.as_deref(),
                )
                .await
                .map_err(AgentError::Append)?;

                if !approved {
                    append_thought(
                        pool,
                        &format!(
                            "Approval gate '{}' denied (timeout or operator reject).",
                            gate_id
                        ),
                        config.session_id,
                        session_goal,
                        &config,
                        config.metrics.as_deref(),
                    )
                    .await?;
                    continue;
                }
                append_thought(
                    pool,
                    &format!("Approval gate '{}' approved.", gate_id),
                    config.session_id,
                    session_goal,
                    &config,
                    config.metrics.as_deref(),
                )
                .await?;
            }
        }

        let validated = match config.tripwire.validate(&intent) {
            Ok(v) => {
                consecutive_justification_failures = 0;
                v
            }
            Err(e) => {
                if let Some(m) = &config.metrics {
                    m.inc_tripwire_rejections();
                }

                // Schema errors (missing justification) get their own event type.
                let is_schema_error = matches!(&e, TripwireError::InsufficientJustification(_));
                let msg: String;

                if is_schema_error {
                    consecutive_justification_failures += 1;
                    msg = "Invalid justification: response is missing a valid \"justification\" field \
                           (must be at least 5 characters).".to_string();
                    ledger::append_event(
                        pool,
                        EventPayload::SchemaError {
                            message: msg.clone(),
                            attempt: consecutive_justification_failures,
                            max_attempts: justification_failure_limit,
                        },
                        config.session_id,
                        session_goal,
                        config.session_signing_key.as_deref(),
                    )
                    .await
                    .map_err(AgentError::Append)?;
                    if let Some(m) = &config.metrics {
                        m.inc_events_appended();
                    }
                } else {
                    msg = match &e {
                        TripwireError::PolicyViolation(_) => format!("Policy rejected: {}", e),
                        _ => format!("Tripwire rejected: {}", e),
                    };
                    append_thought(
                        pool,
                        &msg,
                        config.session_id,
                        session_goal,
                        &config,
                        config.metrics.as_deref(),
                    )
                    .await?;
                }

                if let Some(ref planner) = config.compensation
                    && let Some(comp) = planner.plan(&intent, &e)
                {
                    let comp_json = serde_json::to_string(&comp).unwrap_or_default();
                    append_thought(
                        pool,
                        &format!("Compensation proposed: {}", comp_json),
                        config.session_id,
                        session_goal,
                        &config,
                        config.metrics.as_deref(),
                    )
                    .await?;
                }
                if let Some(ref tx) = config.egress_tx {
                    crate::webhook::try_enqueue_event(
                        tx,
                        crate::webhook::EgressEvent {
                            session_id: config.session_id.unwrap_or_default(),
                            severity: "abort".to_string(),
                            rule_label: msg.clone(),
                            observation_preview: msg.chars().take(200).collect(),
                            kind: crate::webhook::EgressKind::TripwireRejection,
                        },
                    );
                }
                if consecutive_justification_failures >= justification_failure_limit {
                    let reason = format!(
                        "{} consecutive schema errors (missing justification); aborting session.",
                        consecutive_justification_failures
                    );
                    ledger::append_event(
                        pool,
                        EventPayload::CircuitBreaker {
                            reason,
                            consecutive_failures: consecutive_justification_failures,
                        },
                        config.session_id,
                        session_goal,
                        config.session_signing_key.as_deref(),
                    )
                    .await
                    .map_err(AgentError::Append)?;
                    if let Some(m) = &config.metrics {
                        m.inc_events_appended();
                    }
                    return Err(AgentError::CircuitBreaker);
                }
                continue;
            }
        };

        if let Some(guard) = &mut config.guard {
            match guard.evaluate(&config.session_goal, &intent).await {
                Ok(GuardDecision::Deny { reason }) => {
                    consecutive_guard_denials += 1;
                    if let Some(m) = &config.metrics {
                        m.inc_guard_denials();
                    }
                    append_thought(
                        pool,
                        &format!("Guard denied: {}", reason),
                        config.session_id,
                        session_goal,
                        &config,
                        config.metrics.as_deref(),
                    )
                    .await?;
                    if let Some(ref tx) = config.egress_tx {
                        crate::webhook::try_enqueue_event(
                            tx,
                            crate::webhook::EgressEvent {
                                session_id: config.session_id.unwrap_or_default(),
                                severity: "flag".to_string(),
                                rule_label: reason.clone(),
                                observation_preview: reason.chars().take(200).collect(),
                                kind: crate::webhook::EgressKind::GuardDenial,
                            },
                        );
                    }
                    if consecutive_guard_denials >= guard_denial_limit {
                        append_thought(
                            pool,
                            &format!(
                                "Security: Guard denied {} consecutive actions; aborting session.",
                                consecutive_guard_denials
                            ),
                            config.session_id,
                            session_goal,
                            &config,
                            config.metrics.as_deref(),
                        )
                        .await?;
                        return Err(AgentError::GuardAbort);
                    }
                    continue;
                }
                Ok(GuardDecision::Allow) => {
                    consecutive_guard_denials = 0;
                }
                Err(e) => {
                    append_thought(
                        pool,
                        &format!("Guard error (denying): {}", e),
                        config.session_id,
                        session_goal,
                        &config,
                        config.metrics.as_deref(),
                    )
                    .await?;
                    consecutive_guard_denials += 1;
                    continue;
                }
            }
        }

        let is_complete = validated.action() == "complete";

        if validated.action() == "http_get"
            && let Some(url) = validated.params().get("url").and_then(|v| v.as_str())
        {
            match ledger::find_cached_http_get(pool, url).await {
                Ok(Some(cached)) => {
                    append_thought(
                        pool,
                        &format!("Idempotency: returning cached http_get for {}", url),
                        config.session_id,
                        session_goal,
                        &config,
                        config.metrics.as_deref(),
                    )
                    .await?;
                    append_observation(
                        pool,
                        &cached,
                        config.session_id,
                        session_goal,
                        &config,
                        config.metrics.as_deref(),
                    )
                    .await?;
                    continue;
                }
                Ok(None) => {}
                Err(e) => {
                    tracing::warn!("Idempotency check failed (proceeding): {}", e);
                }
            }
        }

        let event_id = append_action(
            pool,
            &validated,
            config.session_id,
            session_goal,
            &config,
            config.metrics.as_deref(),
        )
        .await?;
        ledger::mark_action_executing(pool, event_id)
            .await
            .map_err(AgentError::Db)?;

        // Execute the validated intent.
        //
        // Sandbox priority: Firecracker (KVM, Linux only) → Docker/Podman (cross-platform)
        // → host executor (best-effort Landlock/seccomp on Linux).
        //
        // Each sandbox tier is tried in order; if the tier is not configured or returns
        // an error, execution falls through to the next tier.  This ensures a missing
        // or misconfigured sandbox never halts the agent.
        let is_run_command = validated.action() == "run_command";
        let intent_json_for_sandbox = if is_run_command {
            serde_json::json!({
                "action": validated.action(),
                "params": validated.params(),
            })
            .to_string()
        } else {
            String::new()
        };

        // Tier 1: Firecracker microVM (Linux + KVM).
        let fc_attempt: Option<Result<String, crate::sandbox::SandboxError>> = if is_run_command {
            if let Some(ref fc_cfg) = config.firecracker_config {
                // Outer timeout wraps the *entire* Firecracker attempt — including
                // pre-launch IO (tmpdir creation, config file writes, JSON
                // serialization) — not just the inner Command::new().output() spawn.
                // If the pre-launch phase hangs or the guest kernel panics and
                // fails to close the serial port, this ensures the cognitive loop
                // does not stall indefinitely.
                let outer = std::time::Duration::from_secs(fc_cfg.outer_timeout_secs);
                match tokio::time::timeout(
                    outer,
                    crate::sandbox::run_in_firecracker(fc_cfg, &intent_json_for_sandbox),
                )
                .await
                {
                    Ok(result) => Some(result),
                    Err(_elapsed) => {
                        tracing::warn!(
                            "Firecracker outer timeout ({}s) elapsed — pre-launch IO or \
                             kernel hang; falling through to Docker/host",
                            fc_cfg.outer_timeout_secs
                        );
                        Some(Err(crate::sandbox::SandboxError::Io(std::io::Error::new(
                            std::io::ErrorKind::TimedOut,
                            format!(
                                "Firecracker outer timeout after {} seconds \
                                     (covers pre-launch IO + microVM execution)",
                                fc_cfg.outer_timeout_secs
                            ),
                        ))))
                    }
                }
            } else {
                None
            }
        } else {
            None
        };

        let sandbox_result: Option<Result<String, crate::sandbox::SandboxError>> = match fc_attempt
        {
            Some(Ok(out)) => Some(Ok(out)),
            Some(Err(fc_err)) => {
                tracing::warn!("Firecracker sandbox error (trying Docker next): {}", fc_err);
                // Tier 2: Docker/Podman container.
                if let Some(ref docker_cfg) = config.docker_config {
                    Some(crate::sandbox::run_in_docker(docker_cfg, &intent_json_for_sandbox).await)
                } else {
                    Some(Err(fc_err))
                }
            }
            None => {
                // Firecracker not configured. Try Docker for run_command.
                if is_run_command {
                    if let Some(ref docker_cfg) = config.docker_config {
                        Some(
                            crate::sandbox::run_in_docker(docker_cfg, &intent_json_for_sandbox)
                                .await,
                        )
                    } else {
                        None
                    }
                } else {
                    None
                }
            }
        };

        let observation = match match sandbox_result {
            Some(Ok(out)) => Ok(out),
            Some(Err(sandbox_err)) => {
                tracing::warn!(
                    "Container sandbox error (falling back to host executor): {}",
                    sandbox_err
                );
                executor::execute_with_policy(validated, config.cloud_creds.clone(), config.policy)
                    .await
            }
            None => {
                // Tier 3: host executor (Landlock/seccomp on Linux, no-op otherwise).
                executor::execute_with_policy(validated, config.cloud_creds.clone(), config.policy)
                    .await
            }
        } {
            Ok(s) => s,
            Err(e) => {
                let msg = format!("Execution error: {}", e);
                // Failure to mark the action as failed leaves it in "executing"
                // state, which the wakeup recovery path would re-queue on restart.
                // Emit a warning rather than aborting the session — the more
                // important step is to record the observation so the audit trail
                // captures what happened.
                if let Err(db_err) = ledger::mark_action_failed(pool, event_id, &msg).await {
                    tracing::warn!(
                        "Failed to mark event {} as failed in ledger (continuing): {}",
                        event_id,
                        db_err
                    );
                }
                append_observation(
                    pool,
                    &msg,
                    config.session_id,
                    session_goal,
                    &config,
                    config.metrics.as_deref(),
                )
                .await?;
                continue;
            }
        };
        ledger::mark_action_completed(pool, event_id)
            .await
            .map_err(AgentError::Db)?;
        let scan = output_scanner::scan_observation(&observation);
        if scan.is_suspicious {
            append_thought(
                pool,
                &format!(
                    "Security: suspicious content detected ({:?})",
                    scan.matched_patterns
                ),
                config.session_id,
                session_goal,
                &config,
                config.metrics.as_deref(),
            )
            .await?;
        }

        // Apply policy observation rules (redact / flag / abort).
        let final_observation = if let Some(policy) = config.policy {
            use crate::policy::ObservationOutcome;
            match policy.validate_observation(&scan.sanitized_content) {
                ObservationOutcome::Clean => scan.sanitized_content.clone(),
                ObservationOutcome::Redacted(redacted) => {
                    append_thought(
                        pool,
                        "Policy: sensitive content redacted from observation.",
                        config.session_id,
                        session_goal,
                        &config,
                        config.metrics.as_deref(),
                    )
                    .await?;
                    redacted
                }
                ObservationOutcome::Flagged(labels) => {
                    append_thought(
                        pool,
                        &format!("Policy: observation flagged ({}); continuing.", labels),
                        config.session_id,
                        session_goal,
                        &config,
                        config.metrics.as_deref(),
                    )
                    .await?;
                    if let Some(ref tx) = config.egress_tx {
                        let preview = observation.chars().take(200).collect::<String>();
                        crate::webhook::try_enqueue_event(
                            tx,
                            crate::webhook::EgressEvent {
                                session_id: config.session_id.unwrap_or_default(),
                                severity: "flag".to_string(),
                                rule_label: labels.clone(),
                                observation_preview: preview,
                                kind: crate::webhook::EgressKind::Observation,
                            },
                        );
                    }
                    scan.sanitized_content.clone()
                }
                ObservationOutcome::Abort(reason) => {
                    append_thought(
                        pool,
                        &format!("Policy: aborting session — {}.", reason),
                        config.session_id,
                        session_goal,
                        &config,
                        config.metrics.as_deref(),
                    )
                    .await?;
                    if let Some(ref tx) = config.egress_tx {
                        let preview = observation.chars().take(200).collect::<String>();
                        crate::webhook::try_enqueue_event(
                            tx,
                            crate::webhook::EgressEvent {
                                session_id: config.session_id.unwrap_or_default(),
                                severity: "abort".to_string(),
                                rule_label: reason.clone(),
                                observation_preview: preview,
                                kind: crate::webhook::EgressKind::Observation,
                            },
                        );
                    }
                    return Err(AgentError::PolicyAbort(reason.clone()));
                }
            }
        } else {
            scan.sanitized_content.clone()
        };

        append_observation(
            pool,
            &final_observation,
            config.session_id,
            session_goal,
            &config,
            config.metrics.as_deref(),
        )
        .await?;

        // ── Signing key rotation ───────────────────────────────────────────────
        // When key_rotation_interval_steps is configured, replace the active signing key
        // every N steps.  A KeyRotation event is written to the ledger so verifiers can
        // determine which public key was active for each segment of events.
        if let Some(interval) = config.key_rotation_interval_steps
            && interval > 0
            && step.is_multiple_of(interval)
        {
            let (new_signing_key, new_verifying_key) = crate::signing::generate_keypair();
            let new_public_key_hex = crate::signing::public_key_hex(&new_verifying_key);
            let rotation_index = (step / interval) as u64;
            let rotation_payload = EventPayload::KeyRotation {
                new_public_key: new_public_key_hex.clone(),
                rotation_index,
            };
            // Append the rotation event signed with the *old* key (proves continuity).
            if let Err(e) = ledger::append_event(
                pool,
                rotation_payload,
                config.session_id,
                session_goal,
                config.session_signing_key.as_deref(),
            )
            .await
            {
                tracing::warn!("Failed to append KeyRotation event: {}", e);
            } else {
                tracing::info!(
                    "Session signing key rotated (index {}, new public key: {})",
                    rotation_index,
                    &new_public_key_hex[..16]
                );
                // Swap to the new key for all subsequent events.
                config.session_signing_key = Some(Arc::new(new_signing_key));
            }
        }

        let interval = config::snapshot_interval();
        if step.is_multiple_of(interval)
            && let Some((seq, _)) = ledger::get_latest(pool).await.map_err(AgentError::Db)?
            && snapshot::snapshot_at_sequence(pool, seq).await.is_ok()
            && let Some(m) = &config.metrics
        {
            m.inc_snapshots_created();
        }

        if is_complete {
            // Issue a W3C Verifiable Credential for this completed session.
            if let (Some(ref key), Some(session_id)) =
                (config.session_signing_key.clone(), config.session_id)
            {
                use crate::verifiable_credential::build_vc_jwt;
                // Get optional policy hash from ledger (best-effort).
                let policy_hash: Option<String> = sqlx::query_scalar::<_, Option<String>>(
                    "SELECT policy_hash FROM agent_sessions WHERE id = $1",
                )
                .bind(session_id)
                .fetch_optional(pool)
                .await
                .ok()
                .flatten()
                .flatten();
                let vc_jwt = build_vc_jwt(
                    session_id,
                    &config.session_goal,
                    policy_hash.as_deref(),
                    Some(key.as_ref()),
                );
                let vc_payload = EventPayload::VerifiableCredential { vc_jwt };
                if let Err(e) = ledger::append_event(
                    pool,
                    vc_payload,
                    config.session_id,
                    session_goal,
                    config.session_signing_key.as_deref(),
                )
                .await
                {
                    tracing::warn!("Failed to append VerifiableCredential event: {}", e);
                } else {
                    tracing::info!("Verifiable Credential issued for session {}", session_id);
                }
            }
            break;
        }
    }
    Ok(())
}

/// Returns true if the last 6 actions contain 3 or more repeats of the same (action, params).
///
/// Uses a frequency-counter hash map for O(n) complexity instead of O(n²) nested iteration.
fn detect_loop(events: &[LedgerEventRow]) -> bool {
    // Collect the last 6 action events as (name, canonicalized-params) pairs.
    // Params are canonicalized (keys sorted recursively) so that different JSON
    // key orderings of identical data produce the same string.
    let last: Vec<(String, String)> = events
        .iter()
        .filter_map(|e| {
            if let EventPayload::Action { name, params } = &e.payload {
                let params_key = canonical_json(params);
                Some((name.clone(), params_key))
            } else {
                None
            }
        })
        .rev()
        .take(6)
        .collect();

    if last.len() < 3 {
        return false;
    }

    let mut counts: std::collections::HashMap<(&str, &str), u32> =
        std::collections::HashMap::with_capacity(last.len());
    for (action, params) in &last {
        let n = counts
            .entry((action.as_str(), params.as_str()))
            .or_insert(0);
        *n += 1;
        if *n >= 3 {
            return true;
        }
    }
    false
}

/// Serialize a `serde_json::Value` to a canonical JSON string with keys sorted
/// recursively at every nesting level. This ensures that JSON objects with the
/// same key-value pairs but different insertion orders produce identical output.
fn canonical_json(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::Object(map) => {
            let mut entries: Vec<(&String, &serde_json::Value)> = map.iter().collect();
            entries.sort_by_key(|(k, _)| *k);
            let inner: Vec<String> = entries
                .into_iter()
                .map(|(k, v)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_default(),
                        canonical_json(v)
                    )
                })
                .collect();
            format!("{{{}}}", inner.join(","))
        }
        serde_json::Value::Array(arr) => {
            let inner: Vec<String> = arr.iter().map(canonical_json).collect();
            format!("[{}]", inner.join(","))
        }
        other => serde_json::to_string(other).unwrap_or_default(),
    }
}

async fn perceive(pool: &PgPool) -> Result<crate::schema::RestoredState, AgentError> {
    match wakeup::restore_state(pool, false).await {
        Ok(s) => Ok(s),
        Err(WakeUpError::NoSnapshot) => wakeup::restore_state_from_genesis(pool)
            .await
            .map_err(AgentError::WakeUp),
        Err(e) => Err(AgentError::WakeUp(e)),
    }
}

async fn append_thought(
    pool: &PgPool,
    content: &str,
    session_id: Option<Uuid>,
    session_goal: Option<&str>,
    config: &AgentLoopConfig<'_>,
    metrics: Option<&crate::metrics::Metrics>,
) -> Result<(), AgentError> {
    ledger::append_event(
        pool,
        EventPayload::Thought {
            content: content.to_string(),
        },
        session_id,
        session_goal,
        config.session_signing_key.as_deref(),
    )
    .await
    .map_err(AgentError::Append)?;
    if let Some(m) = metrics {
        m.inc_events_appended();
    }
    Ok(())
}

async fn append_action(
    pool: &PgPool,
    validated: &ValidatedIntent,
    session_id: Option<Uuid>,
    session_goal: Option<&str>,
    config: &AgentLoopConfig<'_>,
    metrics: Option<&crate::metrics::Metrics>,
) -> Result<i64, AgentError> {
    let name = validated.action().to_string();
    let params = validated.params().clone();
    let appended = ledger::append_event(
        pool,
        EventPayload::Action { name, params },
        session_id,
        session_goal,
        config.session_signing_key.as_deref(),
    )
    .await
    .map_err(AgentError::Append)?;
    if let Some(m) = metrics {
        m.inc_events_appended();
    }
    Ok(appended.id)
}

async fn append_observation(
    pool: &PgPool,
    content: &str,
    session_id: Option<Uuid>,
    session_goal: Option<&str>,
    config: &AgentLoopConfig<'_>,
    metrics: Option<&crate::metrics::Metrics>,
) -> Result<(), AgentError> {
    ledger::append_event(
        pool,
        EventPayload::Observation {
            content: content.to_string(),
        },
        session_id,
        session_goal,
        config.session_signing_key.as_deref(),
    )
    .await
    .map_err(AgentError::Append)?;
    if let Some(m) = metrics {
        m.inc_events_appended();
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum AgentError {
    #[error("wakeup: {0}")]
    WakeUp(#[from] WakeUpError),
    #[error("db: {0}")]
    Db(#[from] sqlx::Error),
    #[error("append: {0}")]
    Append(#[from] AppendError),
    #[error("circuit breaker: too many consecutive LLM errors")]
    CircuitBreaker,
    #[error("guard abort: too many consecutive denials")]
    GuardAbort,
    #[error("token budget exceeded: AGENT_TOKEN_BUDGET_MAX reached")]
    TokenBudgetExceeded,
    /// Policy observation rule triggered an abort.
    #[error("policy abort: {0}")]
    PolicyAbort(String),
    /// Prompt-level tripwire scan detected a dangerous pattern in the user goal.
    #[error("tripwire abort: {0}")]
    TripwireAbort(String),
    /// Generic I/O error (used by orchestrator to wrap errors).
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// The CancellationToken was triggered — the loop exited cooperatively.
    #[error("cancelled: cooperative shutdown via CancellationToken")]
    Cancelled,
}
