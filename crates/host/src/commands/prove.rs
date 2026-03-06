//! `ectoledger prove-audit` — SP1 zero-knowledge proof generation.
//!
//! When compiled **without** `--features zk`, prints an informative message and exits 1.
//! When compiled **with** `--features zk`, generates a real SP1 RISC-V proof over the
//! full ledger session, embeds it in an Ecto Ledger Audit Certificate, and writes the .elc file.

use uuid::Uuid;

/// Dispatches to the feature-gated SP1 proof implementation.
pub async fn run(
    pool: &sqlx::PgPool,
    session: Uuid,
    policy_path: Option<std::path::PathBuf>,
    output: Option<std::path::PathBuf>,
    no_ots: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    #[cfg(not(feature = "zk"))]
    {
        let _ = (pool, session, policy_path, output, no_ots);
        Err("prove-audit: the `zk` feature is not enabled.\n\n\
             The SP1 zero-knowledge prover requires the SP1 toolchain \
             (https://docs.succinct.xyz/sp1/install).\n\
             SP1 is not supported on Windows or 32-bit architectures.\n\n\
             Recompile with ZK support:\n\
               cargo run --features zk -- prove-audit <session>\n\n\
             For verifiable audit provenance without ZK, use the Ecto Ledger Audit Certificate:\n\
               cargo run -- report --format certificate --output audit.elc <session>"
            .into())
    }

    #[cfg(feature = "zk")]
    prove_audit_zk(pool, session, policy_path, output, no_ots).await
}

#[cfg(feature = "zk")]
async fn prove_audit_zk(
    pool: &sqlx::PgPool,
    session: Uuid,
    policy_path: Option<std::path::PathBuf>,
    output: Option<std::path::PathBuf>,
    no_ots: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use crate::certificate::{build_certificate, embed_zk_proof, write_certificate_file};
    use ectoledger_core::hash::GENESIS_PREVIOUS_HASH;
    use ectoledger_core::merkle;
    use ectoledger_core::schema::{ChainEvent, GuestInput};
    use sp1_sdk::{CpuProver, Prover, SP1ProofWithPublicValues, SP1Stdin, include_elf};

    let elf = include_elf!("ectoledger-guest");

    println!("prove-audit: loading session {} from database…", session);

    let events = crate::ledger::get_events_by_session(pool, session)
        .await
        .map_err(|e| format!("Failed to load session events: {}", e))?;

    if events.is_empty() {
        return Err(format!("prove-audit: session {} has no events.", session).into());
    }

    println!("prove-audit: {} events loaded.", events.len());

    let chain_events: Vec<ChainEvent> = events
        .iter()
        .map(|e| {
            let previous_hash = if e.sequence == 0 {
                GENESIS_PREVIOUS_HASH.to_string()
            } else {
                e.previous_hash.clone()
            };
            let payload_json =
                serde_json::to_string(&e.payload).unwrap_or_else(|_| "{}".to_string());
            ChainEvent {
                sequence: e.sequence,
                previous_hash,
                payload_json,
            }
        })
        .collect();

    let genesis_hash = events
        .first()
        .map(|e| e.content_hash.clone())
        .ok_or_else(|| "prove-audit: events list empty after non-empty guard".to_string())?;
    let tip_hash = events
        .last()
        .map(|e| e.content_hash.clone())
        .ok_or_else(|| "prove-audit: events list empty after non-empty guard".to_string())?;
    let content_hash_refs: Vec<&str> = events.iter().map(|e| e.content_hash.as_str()).collect();
    let tree = merkle::build_merkle_tree(&content_hash_refs).map_err(|e| e.to_string())?;
    let merkle_root = merkle::root(&tree).map_err(|e| e.to_string())?;

    let policy_patterns: Vec<String> = if let Some(ref path) = policy_path {
        match crate::policy::load_policy_engine(path) {
            Ok(engine) => engine
                .policy()
                .observation_rules
                .iter()
                .map(|r| r.pattern.clone())
                .chain(
                    engine
                        .policy()
                        .command_rules
                        .iter()
                        .map(|r| r.arg_pattern.clone()),
                )
                .collect(),
            Err(e) => {
                tracing::warn!(
                    "prove-audit: failed to load policy file: {}. Proceeding with no patterns.",
                    e
                );
                vec![]
            }
        }
    } else {
        vec![]
    };

    let guest_input = GuestInput {
        genesis_hash,
        tip_hash,
        merkle_root,
        events: chain_events,
        policy_patterns,
    };

    let input_bytes =
        bincode::serialize(&guest_input).map_err(|e| format!("bincode serialize failed: {}", e))?;

    println!(
        "prove-audit: guest input serialized ({} bytes). generating SP1 proof…",
        input_bytes.len()
    );
    println!("prove-audit: this may take several minutes depending on event count and hardware.");

    let client = CpuProver::new().await;
    let pk = client
        .setup(elf)
        .await
        .map_err(|e| format!("SP1 setup failed: {}", e))?;

    let mut stdin = SP1Stdin::new();
    stdin.write_vec(input_bytes);

    let proof: SP1ProofWithPublicValues = client
        .prove(&pk, stdin)
        .await
        .map_err(|e| format!("SP1 proof generation failed: {}", e))?;

    println!(
        "prove-audit: proof generated successfully ({} bytes).",
        proof.bytes().len()
    );

    println!("prove-audit: building Ecto Ledger Audit Certificate…");
    let mut cert = build_certificate(pool, session, None, !no_ots, None)
        .await
        .map_err(|e| format!("certificate build failed: {}", e))?;

    embed_zk_proof(&mut cert, &proof.bytes());

    let out_path =
        output.unwrap_or_else(|| std::path::PathBuf::from(format!("audit-{}.elc", session)));
    write_certificate_file(&cert, &out_path)
        .map_err(|e| format!("write certificate failed: {}", e))?;

    println!("prove-audit: certificate written to {}", out_path.display());
    println!();
    println!("Verify the audit certificate:");
    println!("  cargo run -- verify-certificate {}", out_path.display());
    println!();
    println!(
        "The embedded SP1 proof can be verified independently with sp1_sdk::CpuProver::verify."
    );

    Ok(())
}

/// SQLite variant of `run` — not yet implemented.
pub async fn run_sqlite(
    _pool: &sqlx::SqlitePool,
    _session: Uuid,
    _policy_path: Option<std::path::PathBuf>,
    _output: Option<std::path::PathBuf>,
    _no_ots: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Err("prove-audit is not yet implemented for SQLite mode.".into())
}
