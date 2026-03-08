//! `ectoledger orchestrate`, `ectoledger diff-audit`, `ectoledger red-team`

use uuid::Uuid;

/// Run multi-agent orchestration (recon → analysis → verify).
pub async fn run_orchestrate(
    pool: &crate::pool::DatabasePool,
    goal: String,
    policy: Option<std::path::PathBuf>,
    max_steps: Option<u32>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use crate::orchestrator::{OrchestratorConfig, run_orchestration};

    let client = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(60))
        .build()?;

    // One-time startup recovery: clean up zombies from prior server runs.
    if let Some(pg) = pool.as_pg() {
        if let Err(e) = crate::wakeup::recover_zombie_sessions(pg).await {
            tracing::warn!("orchestrate startup: failed to recover zombie sessions: {e}");
        }
        if let Err(e) = crate::wakeup::recover_incomplete_actions(pg).await {
            tracing::warn!("orchestrate startup: failed to recover incomplete actions: {e}");
        }
    }

    let orch_config = OrchestratorConfig {
        goal: goal.clone(),
        policy,
        max_steps_per_agent: max_steps,
    };
    tracing::info!("Starting orchestrated audit for goal: {}", goal);
    match run_orchestration(pool, &client, orch_config).await {
        Ok(result) => {
            println!("\nOrchestration complete.");
            println!("  Recon    session: {}", result.recon_session_id);
            println!("  Analysis session: {}", result.analysis_session_id);
            println!("  Verify   session: {}", result.verify_session_id);
            println!("  Cross-ledger seal: {}", result.seal_hash);
            println!("\nGenerate per-session certificates with:");
            println!(
                "  cargo run -- report --format certificate --output audit-recon.elc {}",
                result.recon_session_id
            );
            println!(
                "  cargo run -- report --format certificate --output audit-analysis.elc {}",
                result.analysis_session_id
            );
            println!(
                "  cargo run -- report --format certificate --output audit-verify.elc {}",
                result.verify_session_id
            );
            Ok(())
        }
        Err(e) => Err(format!("Orchestration failed: {}", e).into()),
    }
}

/// Compare two audit sessions (baseline vs current).
pub async fn run_diff_audit(
    pool: &sqlx::PgPool,
    baseline: Uuid,
    current: Uuid,
    output: Option<std::path::PathBuf>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let rep_a = crate::report::build_report(pool, baseline).await?;
    let rep_b = crate::report::build_report(pool, current).await?;
    let out = format!(
        "Baseline session {} (ledger hash: {}, findings: {})\n\
         Current session {} (ledger hash: {}, findings: {})\n",
        baseline,
        rep_a.ledger_hash,
        rep_a.findings.len(),
        current,
        rep_b.ledger_hash,
        rep_b.findings.len(),
    );
    if let Some(path) = output {
        std::fs::write(&path, &out).map_err(|e| {
            tracing::error!("Write failed: {}", e);
            e
        })?;
        println!("Diff summary written to {}", path.display());
    } else {
        print!("{}", out);
    }
    Ok(())
}

/// Red-team mode: adversarial agent to test defenses.
pub async fn run_red_team(
    pool: &sqlx::PgPool,
    target_session: Uuid,
    attack_budget: u32,
    output: Option<std::path::PathBuf>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let config = crate::red_team::RedTeamConfig {
        target_session,
        attack_budget,
    };
    let report = crate::red_team::run_red_team(pool, config)
        .await
        .map_err(|e| {
            tracing::error!("Red-team error: {}", e);
            std::io::Error::other(e.to_string())
        })?;

    println!("{}", report);

    if let Some(path) = output {
        let json = serde_json::to_string_pretty(&report).map_err(|e| {
            tracing::error!("Report serialization failed: {}", e);
            std::io::Error::other(e.to_string())
        })?;
        std::fs::write(&path, &json).map_err(|e| {
            tracing::error!("Failed to write report: {}", e);
            e
        })?;
        println!("Report written to {}", path.display());
    }

    // Return error if any payload passed all defense layers.
    if report.passed_all > 0 {
        return Err(format!(
            "\n⚠  {} injection(s) passed all defense layers — review required.",
            report.passed_all
        )
        .into());
    }
    Ok(())
}
