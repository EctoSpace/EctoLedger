//! `ectoledger report`, `ectoledger replay`, `ectoledger verify-session`,
//! `ectoledger verify-certificate`, `ectoledger verify-vc`

use colored::Colorize;
use uuid::Uuid;

/// Replay events for a session with colored output.
pub async fn run_replay(
    pool: &sqlx::PgPool,
    session: Uuid,
    to_step: Option<u32>,
    inject_observation: Vec<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let events = crate::ledger::get_events_by_session(pool, session).await?;
    print_replay(events, to_step, inject_observation);
    Ok(())
}

/// Shared replay display logic used by both Postgres and SQLite variants.
fn print_replay(
    events: Vec<crate::schema::LedgerEventRow>,
    to_step: Option<u32>,
    inject_observation: Vec<String>,
) {
    use crate::schema::EventPayload;

    let limit = to_step.map(|n| n as usize).unwrap_or(events.len());
    let inject_map: std::collections::HashMap<i64, String> = inject_observation
        .iter()
        .filter_map(|s| {
            let s = s.trim();
            let rest = s.strip_prefix("seq=")?;
            let (seq, payload) = rest.split_once(':')?;
            let seq = seq.trim().parse::<i64>().ok()?;
            Some((seq, payload.to_string()))
        })
        .collect();

    for (i, ev) in events.into_iter().take(limit).enumerate() {
        let step = i + 1;
        let payload_display = if let Some(injected) = inject_map.get(&ev.sequence) {
            if let EventPayload::Observation { .. } = &ev.payload {
                serde_json::to_string_pretty(&EventPayload::Observation {
                    content: format!("[INJECTED] {}", injected),
                })
                .unwrap_or_default()
            } else {
                serde_json::to_string_pretty(&ev.payload).unwrap_or_default()
            }
        } else {
            serde_json::to_string_pretty(&ev.payload).unwrap_or_default()
        };
        let (label, color_fn): (&str, fn(&str) -> colored::ColoredString) = match &ev.payload {
            EventPayload::Genesis { .. } => ("genesis", |s: &str| s.green()),
            EventPayload::PromptInput { .. } => ("prompt_input", |s: &str| s.green()),
            EventPayload::Thought { .. } => ("thought", |s: &str| s.blue()),
            EventPayload::SchemaError { .. } => ("schema_error", |s: &str| s.red()),
            EventPayload::CircuitBreaker { .. } => ("circuit_breaker", |s: &str| s.yellow()),
            EventPayload::Action { .. } => ("action", |s: &str| s.yellow()),
            EventPayload::Observation { .. } => ("observation", |s: &str| s.magenta()),
            EventPayload::ApprovalRequired { .. } | EventPayload::ApprovalDecision { .. } => {
                ("approval", |s: &str| s.cyan())
            }
            EventPayload::CrossLedgerSeal { .. } => ("cross_ledger_seal", |s: &str| s.white()),
            EventPayload::Anchor { .. } => ("anchor", |s: &str| s.white()),
            EventPayload::KeyRotation { .. } => ("key_rotation", |s: &str| s.cyan()),
            EventPayload::KeyRevocation { .. } => ("key_revocation", |s: &str| s.red()),
            EventPayload::VerifiableCredential { .. } => {
                ("verifiable_credential", |s: &str| s.green())
            }
            EventPayload::ChatMessage { .. } => ("chat", |s: &str| s.blue()),
        };
        println!(
            "{}",
            color_fn(&format!("[step {}] {} #{}", step, label, ev.sequence))
        );
        println!("{}", payload_display);
        println!();
    }
}

/// Verify event signatures for a session (ed25519).
pub async fn run_verify_session(
    pool: &sqlx::PgPool,
    session: Uuid,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let (verified, err) = crate::ledger::verify_session_signatures(pool, session).await?;
    if let Some(e) = err {
        return Err(format!(
            "Verification failed: {} ({} signatures verified)",
            e, verified
        )
        .into());
    }
    println!(
        "Verified {} event signatures for session {}.",
        verified, session
    );
    Ok(())
}

/// Export audit report for a session.
pub async fn run_report(
    pool: &sqlx::PgPool,
    session: Uuid,
    format: String,
    output: Option<std::path::PathBuf>,
    no_ots: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    if format.to_lowercase() == "certificate" {
        let out_path = output
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from(format!("audit-{}.elc", session)));
        println!(
            "Building Ecto Ledger Audit Certificate for session {}...",
            session
        );
        let cert = crate::certificate::build_certificate(
            pool, session, None, // signing_key: requires session key loaded from disk
            !no_ots, None, // enclave attestation: not available from CLI report command
        )
        .await
        .map_err(|e| format!("certificate build failed: {}", e))?;
        crate::certificate::write_certificate_file(&cert, &out_path)
            .map_err(|e| format!("write certificate failed: {}", e))?;
        println!("Certificate written to {}", out_path.display());
        println!("Verify with: verify-cert {}", out_path.display());
    } else {
        let report = crate::report::build_report(pool, session).await?;
        print_report(&report, session, format, output)?;
    }
    Ok(())
}

/// Shared report format + output logic used by both Postgres and SQLite variants.
fn print_report(
    report: &crate::report::AuditReport,
    session: Uuid,
    format: String,
    output: Option<std::path::PathBuf>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let out = match format.to_lowercase().as_str() {
        "sarif" => serde_json::to_string_pretty(&crate::report::report_to_sarif(report, session))
            .unwrap_or_default(),
        "html" => crate::report::report_to_html(report, session),
        "github_actions" => crate::report::report_to_github_actions(report),
        "gitlab_codequality" => serde_json::to_string_pretty(
            &crate::report::report_to_gitlab_codequality(report, session),
        )
        .unwrap_or_default(),
        _ => serde_json::to_string_pretty(report).unwrap_or_default(),
    };
    if let Some(path) = output {
        std::fs::write(&path, &out).map_err(|e| {
            tracing::error!("Write failed: {}", e);
            e
        })?;
        println!("Report written to {}", path.display());
    } else {
        println!("{}", out);
    }

    let has_high_or_critical = report
        .findings
        .iter()
        .any(|f| matches!(f.severity.as_str(), "high" | "critical"));
    if has_high_or_critical {
        return Err("Ecto Ledger: High or Critical findings detected — failing pipeline.".into());
    }
    Ok(())
}

/// Verify an Ecto Ledger Audit Certificate (.elc) file.
pub fn run_verify_certificate(
    file: &std::path::Path,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use crate::certificate::{canonical_json_for_signing, read_certificate_file};
    use crate::merkle;
    use ed25519_dalek::{Signature as Ed25519Sig, Verifier, VerifyingKey};
    use sha2::{Digest, Sha256 as Sha256Hasher};

    let cert =
        read_certificate_file(file).map_err(|e| format!("Could not read certificate: {}", e))?;
    println!("Verifying Ecto Ledger Audit Certificate");
    println!("  Session: {}", cert.session_id);
    println!("  Events : {}", cert.event_count);
    println!();

    let mut all_ok = true;

    // 1. Signature
    if let (Some(sig_hex), Some(pk_hex)) = (&cert.signature, &cert.session_public_key) {
        let canonical = canonical_json_for_signing(&cert)
            .map_err(|e| format!("canonical JSON error: {}", e))?;
        let pk_bytes = hex::decode(pk_hex).map_err(|e| format!("invalid pk hex: {}", e))?;
        let ok = pk_bytes
            .as_slice()
            .try_into()
            .ok()
            .and_then(|b: &[u8; 32]| VerifyingKey::from_bytes(b).ok())
            .and_then(|vk| {
                hex::decode(sig_hex).ok().and_then(|sb| {
                    <[u8; 64]>::try_from(sb.as_slice()).ok().map(|b| {
                        let s = Ed25519Sig::from_bytes(&b);
                        vk.verify(canonical.as_bytes(), &s).is_ok()
                    })
                })
            })
            .unwrap_or(false);
        if ok {
            println!("✓  Signature valid (ed25519)");
        } else {
            println!("✗  Signature INVALID");
            all_ok = false;
        }
    } else {
        println!("⚠  No signature in certificate");
    }

    // 2. Chain consistency + tip hash
    let tip_ok = cert
        .events
        .last()
        .map(|e| e.content_hash == cert.ledger_tip_hash)
        .unwrap_or(true);
    if tip_ok && cert.events.len() as u64 == cert.event_count {
        println!("✓  Hash chain intact ({} events)", cert.events.len());
    } else {
        println!("✗  Hash chain INVALID");
        all_ok = false;
    }

    // 3. Merkle proofs
    let content_hashes: Vec<&str> = cert
        .events
        .iter()
        .map(|e| e.content_hash.as_str())
        .collect();
    match merkle::build_merkle_tree(&content_hashes) {
        Err(e) => {
            println!("✗  Merkle build error: {}", e);
            all_ok = false;
        }
        Ok(tree) => {
            let computed_root = merkle::root(&tree).unwrap_or_default();
            if computed_root != cert.merkle_root {
                println!("✗  Merkle root INVALID");
                all_ok = false;
            } else {
                let seq_to_hash: std::collections::HashMap<i64, &str> = cert
                    .events
                    .iter()
                    .map(|e| (e.sequence, e.content_hash.as_str()))
                    .collect();
                let mut proof_ok = true;
                for finding in &cert.findings {
                    for (&seq, mp) in finding.evidence_sequence.iter().zip(&finding.merkle_proofs) {
                        if let Some(h) = seq_to_hash.get(&seq)
                            && !merkle::verify_proof(&cert.merkle_root, h, mp).unwrap_or(false)
                        {
                            proof_ok = false;
                        }
                    }
                }
                if proof_ok {
                    println!("✓  Merkle proofs valid ({} findings)", cert.findings.len());
                } else {
                    println!("✗  Merkle proofs INVALID");
                    all_ok = false;
                }
            }
        }
    }

    // 4. Goal hash
    let computed_gh = hex::encode(Sha256Hasher::digest(cert.goal.as_bytes()));
    if computed_gh == cert.goal_hash {
        println!("✓  Goal hash matches declared goal");
    } else {
        println!("✗  Goal hash INVALID");
        all_ok = false;
    }

    // 5. OTS (informational)
    if cert.ots_proof_hex.is_some() {
        println!("⚠  OTS proof present (manual verification required for Bitcoin confirmation)");
    } else {
        println!("⚠  No OTS proof");
    }

    println!();
    if all_ok {
        println!("CERTIFICATE VALID  — session {}", cert.session_id);
        Ok(())
    } else {
        Err("CERTIFICATE INVALID — one or more checks failed.".into())
    }
}

/// Decode and verify a W3C VC-JWT issued by Ecto Ledger.
pub fn run_verify_vc(
    jwt: &str,
    issuer_hex: Option<&str>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use crate::verifiable_credential::{VcVerifyError, verify_vc_jwt};
    use ed25519_dalek::VerifyingKey;

    let verifying_key: Option<VerifyingKey> = if let Some(hex_str) = issuer_hex {
        let key_bytes = hex::decode(hex_str.trim())
            .map_err(|e| format!("--issuer-hex is not valid hex: {}", e))?;
        if key_bytes.len() != 32 {
            return Err(format!(
                "--issuer-hex must be 32 bytes (64 hex chars), got {} bytes",
                key_bytes.len()
            )
            .into());
        }
        let arr: [u8; 32] = key_bytes.try_into().unwrap();
        Some(
            VerifyingKey::from_bytes(&arr)
                .map_err(|e| format!("invalid Ed25519 verifying key: {}", e))?,
        )
    } else {
        None
    };

    match verify_vc_jwt(jwt, verifying_key.as_ref()) {
        Ok(payload) => {
            let pretty =
                serde_json::to_string_pretty(&payload).unwrap_or_else(|_| payload.to_string());
            if verifying_key.is_some() {
                println!("✓  VC-JWT signature valid (Ed25519)");
            } else {
                println!("⚠  VC-JWT decoded (signature not verified — no --issuer-hex provided)");
            }
            println!();
            println!("{}", pretty);
            Ok(())
        }
        Err(VcVerifyError::Expired) => {
            Err("✗  VC-JWT has EXPIRED (exp claim is in the past).".into())
        }
        Err(VcVerifyError::InvalidSignature) => Err("✗  VC-JWT signature is INVALID.".into()),
        Err(VcVerifyError::Unsigned) => Err(
            "✗  VC-JWT is UNSIGNED (alg=none) but --issuer-hex was provided. \
             Remove --issuer-hex to decode without signature verification."
                .into(),
        ),
        Err(VcVerifyError::Malformed) => {
            Err("✗  VC-JWT is MALFORMED (expected header.payload.signature).".into())
        }
    }
}

// ─── SQLite variants ──────────────────────────────────────────────────────────
// These delegate to the SQLite-specific ledger functions and share display
// / formatting logic with the Postgres variants above.

/// Replay events for a session (SQLite variant).
pub async fn run_replay_sqlite(
    pool: &sqlx::SqlitePool,
    session: uuid::Uuid,
    to_step: Option<u32>,
    inject_observation: Vec<String>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let events = crate::ledger::sqlite::get_events_by_session_sqlite(pool, session).await?;
    print_replay(events, to_step, inject_observation);
    Ok(())
}

/// Verify event signatures for a session (SQLite variant).
pub async fn run_verify_session_sqlite(
    pool: &sqlx::SqlitePool,
    session: uuid::Uuid,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let ok = crate::ledger::sqlite::verify_session_signatures_sqlite(pool, session).await?;
    if ok {
        println!("All event signatures verified for session {}.", session);
        Ok(())
    } else {
        Err(format!("Signature verification failed for session {}.", session).into())
    }
}

/// Export audit report for a session (SQLite variant).
pub async fn run_report_sqlite(
    pool: &sqlx::SqlitePool,
    session: uuid::Uuid,
    format: String,
    output: Option<std::path::PathBuf>,
    _no_ots: bool,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Certificate format requires PgPool (build_certificate is Postgres-only).
    if format.to_lowercase() == "certificate" {
        return Err("Certificate export is not yet supported in SQLite mode.".into());
    }
    let report = crate::report::build_report_sqlite(pool, session).await?;
    print_report(&report, session, format, output)
}
