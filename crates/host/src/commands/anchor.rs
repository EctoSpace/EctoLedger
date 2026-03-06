//! `ectoledger anchor-session` — anchor a session's ledger tip to Bitcoin or EVM chains.

use uuid::Uuid;

/// Anchor a session's ledger tip hash to a blockchain.
pub async fn run(
    pool: &sqlx::PgPool,
    session: Uuid,
    chain: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use crate::schema::EventPayload;

    let events = crate::ledger::get_events_by_session(pool, session)
        .await
        .map_err(|e| format!("Failed to load session events: {}", e))?;
    if events.is_empty() {
        return Err(format!("Session {} has no events.", session).into());
    }
    let tip = &events
        .last()
        .ok_or("Events list unexpectedly empty")?
        .content_hash;

    match chain.as_str() {
        "ethereum" => {
            use crate::evm_anchor;
            println!("Anchoring session {} (tip {}) to EVM chain…", session, tip);
            match evm_anchor::anchor_to_evm(tip).await {
                Ok(result) => {
                    println!("EVM anchor tx: {}", result.tx_hash);
                    println!("Chain ID: {}", result.chain_id);
                    let anchor_payload = EventPayload::Anchor {
                        ledger_tip_hash: tip.clone(),
                        ots_proof_hex: format!("evm:{}", result.tx_hash),
                        bitcoin_block_height: None,
                    };
                    match crate::ledger::append_event(
                        pool,
                        anchor_payload,
                        Some(session),
                        None,
                        None,
                    )
                    .await
                    {
                        Ok(e) => {
                            tracing::info!("Anchor event appended at sequence {}.", e.sequence)
                        }
                        Err(e) => tracing::warn!("Failed to append Anchor event: {}", e),
                    }
                }
                Err(e) => {
                    return Err(format!("EVM anchor failed: {}", e).into());
                }
            }
        }
        _ => {
            // Default: Bitcoin via OpenTimestamps.
            use crate::ots;
            println!("Anchoring session {} to OpenTimestamps…", session);
            println!("Ledger tip hash: {}", tip);

            match ots::submit_ots_stamp(tip).await {
                Ok(stamp_bytes) => {
                    let proof_hex = hex::encode(&stamp_bytes);
                    println!(
                        "OTS stamp received ({} bytes). Status: pending Bitcoin confirmation.",
                        stamp_bytes.len()
                    );

                    let anchor_payload = EventPayload::Anchor {
                        ledger_tip_hash: tip.clone(),
                        ots_proof_hex: proof_hex.clone(),
                        bitcoin_block_height: None,
                    };
                    match crate::ledger::append_event(
                        pool,
                        anchor_payload,
                        Some(session),
                        None,
                        None,
                    )
                    .await
                    {
                        Ok(e) => {
                            tracing::info!("Anchor event appended at sequence {}.", e.sequence)
                        }
                        Err(e) => tracing::warn!("Failed to append Anchor event: {}", e),
                    }
                    println!("OTS proof (hex): {}", &proof_hex[..proof_hex.len().min(64)]);
                    println!(
                        "Run `ots upgrade` with the stamp file to confirm the Bitcoin block height."
                    );
                }
                Err(e) => {
                    return Err(format!("OTS submission failed: {}", e).into());
                }
            }
        }
    }
    Ok(())
}

/// SQLite variant of `run` — not yet implemented.
pub async fn run_sqlite(
    _pool: &sqlx::SqlitePool,
    _session: Uuid,
    _chain: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    Err("anchor-session is not yet implemented for SQLite mode.".into())
}
