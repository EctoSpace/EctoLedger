//! PostgreSQL implementation of `ledger_api::LedgerBackend`.
//!
//! This file contains the original EctoLedger logic, now exposed both as
//! free functions (keeping existing call-sites working) and as a concrete
//! `PostgresLedger` struct that implements `LedgerBackend`.

use crate::hash::{GENESIS_PREVIOUS_HASH, compute_content_hash, sha256_hex};
use crate::schema::{
    AppendedEvent, AuditFinding, EventPayload, FindingSeverity, LedgerEventRow, SessionRow,
};
use crate::signing;
use async_trait::async_trait;
use chrono::{Timelike as _, Utc};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sqlx::{FromRow, PgPool};
use subtle::ConstantTimeEq;
use uuid::Uuid;

// ── W3C DID key derivation ────────────────────────────────────────────────────

/// Derives a `did:key:z6Mk…` URI from an Ed25519 verifying key following the
/// W3C DID-key specification (multicodec prefix `0xed01` + base58btc encoding).
///
/// <https://w3c-ccg.github.io/did-method-key/#ed25519-x25519>
fn derive_did_key(verifying_key: &VerifyingKey) -> String {
    // Ed25519 multicodec varint prefix (little-endian): 0xed, 0x01
    let mut encoded = vec![0xed_u8, 0x01_u8];
    encoded.extend_from_slice(verifying_key.as_bytes());
    // `z` is the multibase prefix for base58btc.
    format!("did:key:z{}", bs58::encode(&encoded).into_string())
}

// ─── Internal row type ──────────────────────────────────────────────────────────

#[derive(FromRow)]
pub(super) struct AgentEventDbRow {
    pub id: i64,
    pub sequence: i64,
    pub previous_hash: String,
    pub content_hash: String,
    pub payload: sqlx::types::Json<EventPayload>,
    pub created_at: chrono::DateTime<Utc>,
    pub session_id: Option<Uuid>,
}

pub(super) fn db_row_to_ledger_event(row: AgentEventDbRow) -> LedgerEventRow {
    LedgerEventRow {
        id: row.id,
        sequence: row.sequence,
        previous_hash: row.previous_hash,
        content_hash: row.content_hash,
        payload: row.payload.0,
        created_at: row.created_at,
    }
}

// ─── Free functions (kept for backward-compat with existing call sites) ─────────

pub async fn get_latest(pool: &PgPool) -> Result<Option<(i64, String)>, sqlx::Error> {
    let row = sqlx::query_as::<_, (i64, String)>(
        "SELECT sequence, content_hash FROM agent_events ORDER BY sequence DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

pub async fn verify_chain(
    pool: &PgPool,
    from_sequence: i64,
    to_sequence: i64,
) -> Result<bool, sqlx::Error> {
    let rows = sqlx::query_as::<_, AgentEventDbRow>(
        "SELECT id, sequence, previous_hash, content_hash, payload, created_at, session_id
         FROM agent_events
         WHERE sequence >= $1 AND sequence <= $2
         ORDER BY sequence ASC",
    )
    .bind(from_sequence)
    .bind(to_sequence)
    .fetch_all(pool)
    .await?;

    if rows.is_empty() {
        return Ok(true);
    }

    let mut prev_content_hash: Option<String> = None;
    for row in rows {
        let expected_prev = prev_content_hash
            .as_deref()
            .unwrap_or(GENESIS_PREVIOUS_HASH);
        if row.previous_hash != expected_prev {
            return Ok(false);
        }
        let payload_json = serde_json::to_string(&row.payload.0).map_err(|_| {
            sqlx::Error::Decode(Box::new(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "payload serialize",
            )))
        })?;
        let sid_str = row.session_id.map(|u| u.to_string());
        let ts_str = row.created_at.to_rfc3339();
        // Try session-bound + timestamped hash first (new formula), fall back
        // through intermediate formats for events created before hardening.
        let expected_content = compute_content_hash(
            &row.previous_hash,
            row.sequence,
            &payload_json,
            sid_str.as_deref(),
            Some(&ts_str),
        );
        // Constant-time comparison to prevent timing side-channels (TM-4).
        let matches: bool = row
            .content_hash
            .as_bytes()
            .ct_eq(expected_content.as_bytes())
            .into();
        if !matches {
            // Fallback 1: session_id but no timestamp (TM-2 era).
            let mid = compute_content_hash(
                &row.previous_hash,
                row.sequence,
                &payload_json,
                sid_str.as_deref(),
                None,
            );
            let mid_matches: bool = row.content_hash.as_bytes().ct_eq(mid.as_bytes()).into();
            if !mid_matches {
                // Fallback 2: legacy — no session_id, no timestamp.
                let legacy = compute_content_hash(
                    &row.previous_hash,
                    row.sequence,
                    &payload_json,
                    None,
                    None,
                );
                let legacy_matches: bool =
                    row.content_hash.as_bytes().ct_eq(legacy.as_bytes()).into();
                if !legacy_matches {
                    // Fallback 3: sub-microsecond nanosecond precision mismatch.
                    //
                    // Before the write-path was fixed, `append_event` called
                    // `Utc::now().to_rfc3339()` which may produce 9 decimal places
                    // (e.g. "...970769388+00:00") when the system clock's nanosecond
                    // value has a non-zero sub-microsecond component.  PostgreSQL
                    // `TIMESTAMPTZ` truncates to microseconds (6 decimal places), so
                    // reading `created_at` back from the DB and calling `to_rfc3339()`
                    // produces "...970769+00:00" — a different string — causing a hash
                    // mismatch.  We brute-force the 999 possible sub-microsecond
                    // nanosecond offsets (1-999 ns) to recover those events.
                    let base_ns = row.created_at.nanosecond();
                    let sub_us_match = (1u32..=999).any(|sub_ns| {
                        let candidate_ns = base_ns + sub_ns;
                        // base_ns is a multiple of 1000 (microseconds from PG),
                        // so candidate_ns <= 999_999_999 — always valid.
                        let Some(candidate_dt) = row.created_at.with_nanosecond(candidate_ns)
                        else {
                            return false;
                        };
                        let candidate_ts = candidate_dt.to_rfc3339();
                        let h = compute_content_hash(
                            &row.previous_hash,
                            row.sequence,
                            &payload_json,
                            sid_str.as_deref(),
                            Some(&candidate_ts),
                        );
                        row.content_hash.as_bytes().ct_eq(h.as_bytes()).into()
                    });
                    if !sub_us_match {
                        return Ok(false);
                    }
                }
            }
        }
        prev_content_hash = Some(row.content_hash);
    }
    Ok(true)
}

pub async fn create_session(
    pool: &PgPool,
    goal: &str,
    llm_backend: &str,
    llm_model: &str,
    policy_hash: Option<&str>,
) -> Result<(SessionRow, SigningKey), sqlx::Error> {
    create_session_with_did(pool, goal, llm_backend, llm_model, policy_hash, None).await
}

pub async fn create_session_with_did(
    pool: &PgPool,
    goal: &str,
    llm_backend: &str,
    llm_model: &str,
    policy_hash: Option<&str>,
    session_did: Option<&str>,
) -> Result<(SessionRow, SigningKey), sqlx::Error> {
    let id = Uuid::new_v4();
    let goal_hash = sha256_hex(goal.as_bytes());
    let (signing_key, verifying_key) = signing::generate_keypair();
    let session_public_key = Some(signing::public_key_hex(&verifying_key));
    // Auto-derive a W3C did:key URI from the freshly generated Ed25519 keypair
    // unless the caller explicitly supplies one (rare override case).
    let did = session_did
        .map(String::from)
        .unwrap_or_else(|| derive_did_key(&verifying_key));
    let now = Utc::now();
    sqlx::query(
        "INSERT INTO agent_sessions
         (id, goal, goal_hash, status, llm_backend, llm_model, created_at, policy_hash, session_public_key, session_did)
         VALUES ($1, $2, $3, 'running', $4, $5, $6, $7, $8, $9)",
    )
    .bind(id)
    .bind(goal)
    .bind(&goal_hash)
    .bind(llm_backend)
    .bind(llm_model)
    .bind(now)
    .bind(policy_hash)
    .bind(&session_public_key)
    .bind(&did)
    .execute(pool)
    .await?;
    Ok((
        SessionRow {
            id,
            goal: goal.to_string(),
            goal_hash: Some(goal_hash),
            status: "running".to_string(),
            llm_backend: Some(llm_backend.to_string()),
            llm_model: Some(llm_model.to_string()),
            created_at: now,
            finished_at: None,
            policy_hash: policy_hash.map(String::from),
            session_public_key,
            session_did: Some(did.clone()),
            enclave_attestation_json: None,
        },
        signing_key,
    ))
}

pub async fn verify_goal_hash(
    pool: &PgPool,
    session_id: Uuid,
    current_goal: &str,
) -> Result<bool, sqlx::Error> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT goal_hash FROM agent_sessions WHERE id = $1")
            .bind(session_id)
            .fetch_optional(pool)
            .await?;
    let Some((Some(stored_hash),)) = row else {
        return Ok(false);
    };
    let expected = sha256_hex(current_goal.as_bytes());
    Ok(stored_hash == expected)
}

pub async fn finish_session(
    pool: &PgPool,
    session_id: Uuid,
    status: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query("UPDATE agent_sessions SET status = $1, finished_at = now() WHERE id = $2")
        .bind(status)
        .bind(session_id)
        .execute(pool)
        .await?;
    Ok(())
}

/// Persist enclave attestation evidence on a session so that certificate
/// generation can embed it even after the agent process exits.
pub async fn store_enclave_attestation(
    pool: &PgPool,
    session_id: Uuid,
    attestation: &crate::enclave::runtime::EnclaveAttestation,
) -> Result<(), sqlx::Error> {
    let json = serde_json::to_string(attestation).map_err(|e| {
        sqlx::Error::Protocol(format!("EnclaveAttestation serialisation failed: {}", e))
    })?;
    sqlx::query("UPDATE agent_sessions SET enclave_attestation_json = $1 WHERE id = $2")
        .bind(&json)
        .bind(session_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn list_sessions(pool: &PgPool) -> Result<Vec<SessionRow>, sqlx::Error> {
    list_sessions_filtered(pool, None, 200, 0).await
}

/// List sessions with optional status filter and pagination.
///
/// - `status` — e.g. `Some("completed")`, `Some("running")`; `None` returns all.
/// - `limit`  — maximum rows to return (capped at 500 by the server layer).
/// - `offset` — number of rows to skip (for page-based navigation).
pub async fn list_sessions_filtered(
    pool: &PgPool,
    status: Option<&str>,
    limit: i64,
    offset: i64,
) -> Result<Vec<SessionRow>, sqlx::Error> {
    let rows = match status {
        Some(s) => sqlx::query_as::<_, SessionRow>(
            "SELECT id, goal, goal_hash, status, llm_backend, llm_model, created_at, finished_at, \
                 policy_hash, session_public_key, session_did, enclave_attestation_json \
                 FROM agent_sessions WHERE status = $1 \
                 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(s)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?,
        None => sqlx::query_as::<_, SessionRow>(
            "SELECT id, goal, goal_hash, status, llm_backend, llm_model, created_at, finished_at, \
                 policy_hash, session_public_key, session_did, enclave_attestation_json \
                 FROM agent_sessions ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?,
    };
    Ok(rows)
}

/// Return the `session_did` for a session, if set.
pub async fn get_session_did(
    pool: &PgPool,
    session_id: Uuid,
) -> Result<Option<String>, sqlx::Error> {
    let row: Option<(Option<String>,)> =
        sqlx::query_as("SELECT session_did FROM agent_sessions WHERE id = $1")
            .bind(session_id)
            .fetch_optional(pool)
            .await?;
    Ok(row.and_then(|(did,)| did))
}

pub async fn append_event(
    pool: &PgPool,
    payload: EventPayload,
    session_id: Option<Uuid>,
    session_goal: Option<&str>,
    signing_key: Option<&SigningKey>,
) -> Result<AppendedEvent, AppendError> {
    if let (Some(sid), Some(goal)) = (session_id, session_goal) {
        let ok = verify_goal_hash(pool, sid, goal)
            .await
            .map_err(AppendError::Db)?;
        if !ok {
            return Err(AppendError::GoalMismatch);
        }
    }

    if let (Some(sid), EventPayload::Action { name, params }) = (session_id, &payload)
        && name == "complete"
        && let Some(findings_val) = params.get("findings")
        && let Ok(findings) = serde_json::from_value::<Vec<AuditFinding>>(findings_val.clone())
    {
        verify_findings(pool, sid, &findings).await?;
    }

    let payload_json = serde_json::to_string(&payload).map_err(AppendError::Serialize)?;

    let mut tx = pool.begin().await.map_err(AppendError::Db)?;

    // Advisory lock prevents race conditions during genesis (no rows to FOR UPDATE).
    sqlx::query("SELECT pg_advisory_xact_lock(42)")
        .execute(&mut *tx)
        .await
        .map_err(AppendError::Db)?;

    let latest = sqlx::query_as::<_, (i64, String)>(
        "SELECT sequence, content_hash FROM agent_events ORDER BY sequence DESC LIMIT 1 FOR UPDATE",
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppendError::Db)?;

    let (sequence, previous_hash) = match latest {
        None => (0_i64, GENESIS_PREVIOUS_HASH.to_string()),
        Some((seq, content_hash)) => (seq + 1, content_hash),
    };

    let now = Utc::now();
    // Truncate to microsecond precision to match what PostgreSQL TIMESTAMPTZ stores.
    // Without this, `now.to_rfc3339()` may produce 9 decimal places when the
    // sub-microsecond nanosecond component is non-zero (e.g. "…970769388+00:00"),
    // whereas reading `created_at` back from the DB always yields 6 decimal places
    // ("…970769+00:00"), causing `verify_chain` to compute a different hash.
    let now_us = now
        .with_nanosecond((now.nanosecond() / 1_000) * 1_000)
        .unwrap_or(now);
    let content_hash = compute_content_hash(
        &previous_hash,
        sequence,
        &payload_json,
        session_id.map(|u| u.to_string()).as_deref(),
        Some(&now_us.to_rfc3339()),
    );

    let row = sqlx::query_as::<_, (i64, i64, String, String, chrono::DateTime<Utc>)>(
        "INSERT INTO agent_events (sequence, previous_hash, content_hash, payload, created_at, session_id)
         VALUES ($1, $2, $3, $4, $5, $6)
         RETURNING id, sequence, previous_hash, content_hash, created_at",
    )
    .bind(sequence)
    .bind(&previous_hash)
    .bind(&content_hash)
    .bind(sqlx::types::Json(&payload))
    .bind(now)
    .bind(session_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppendError::Db)?;

    // Sign and insert the event signature inside the transaction so event+sig
    // are atomic — prevents unsigned events if the sig INSERT fails.
    if let (Some(sk), Some(_sid)) = (signing_key, session_id) {
        let pk_hex = signing::public_key_hex(&sk.verifying_key());
        let sig_hex = signing::sign_content_hash(sk, &row.3);
        sqlx::query(
            "INSERT INTO agent_event_signatures (event_id, content_hash, signature, public_key) VALUES ($1, $2, $3, $4)",
        )
        .bind(row.0)
        .bind(&row.3)
        .bind(&sig_hex)
        .bind(&pk_hex)
        .execute(&mut *tx)
        .await
        .map_err(AppendError::Db)?;
    }

    tx.commit().await.map_err(AppendError::Db)?;

    let appended = AppendedEvent {
        id: row.0,
        sequence: row.1,
        previous_hash: row.2,
        content_hash: row.3,
        created_at: row.4,
    };

    // Wake SSE stream handlers so they fetch the new event immediately.
    crate::server::notify_sse_subscribers();
    // Also issue a PostgreSQL NOTIFY for cross-instance SSE wakeup.
    crate::pg_notify::notify_new_event(pool).await;

    Ok(appended)
}

pub async fn ensure_genesis(pool: &PgPool) -> Result<AppendedEvent, AppendError> {
    let latest = get_latest(pool).await.map_err(AppendError::Db)?;
    if let Some((seq, _)) = latest {
        let row = sqlx::query_as::<_, (i64, i64, String, String, chrono::DateTime<Utc>)>(
            "SELECT id, sequence, previous_hash, content_hash, created_at FROM agent_events WHERE sequence = $1",
        )
        .bind(seq)
        .fetch_one(pool)
        .await
        .map_err(AppendError::Db)?;
        return Ok(AppendedEvent {
            id: row.0,
            sequence: row.1,
            previous_hash: row.2,
            content_hash: row.3,
            created_at: row.4,
        });
    }

    let payload = EventPayload::Genesis {
        message: "EctoLedger initialized".to_string(),
        nonce: Some(hex::encode(uuid::Uuid::new_v4().as_bytes())),
        session_public_key: None, // server-level genesis: no session signing key yet
    };
    append_event(pool, payload, None, None, None).await
}

pub async fn get_event_by_id(
    pool: &PgPool,
    event_id: i64,
) -> Result<Option<LedgerEventRow>, sqlx::Error> {
    let row = sqlx::query_as::<_, AgentEventDbRow>(
        "SELECT id, sequence, previous_hash, content_hash, payload, created_at, session_id
         FROM agent_events WHERE id = $1",
    )
    .bind(event_id)
    .fetch_optional(pool)
    .await?;
    Ok(row.map(db_row_to_ledger_event))
}

pub async fn mark_action_executing(pool: &PgPool, event_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query("INSERT INTO agent_action_log (event_id, status) VALUES ($1, 'executing')")
        .bind(event_id)
        .execute(pool)
        .await?;
    Ok(())
}

pub async fn mark_action_completed(pool: &PgPool, event_id: i64) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE agent_action_log SET status = 'completed', finished_at = now() WHERE event_id = $1",
    )
    .bind(event_id)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn mark_action_failed(
    pool: &PgPool,
    event_id: i64,
    error_msg: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE agent_action_log SET status = 'failed', finished_at = now(), error_msg = $2 WHERE event_id = $1",
    )
    .bind(event_id)
    .bind(error_msg)
    .execute(pool)
    .await?;
    Ok(())
}

pub async fn get_dangling_actions(pool: &PgPool) -> Result<Vec<i64>, sqlx::Error> {
    let rows = sqlx::query_scalar::<_, i64>(
        "SELECT event_id FROM agent_action_log WHERE status IN ('pending', 'executing') ORDER BY started_at ASC",
    )
    .fetch_all(pool)
    .await?;
    Ok(rows)
}

pub async fn get_events(
    pool: &PgPool,
    from_sequence: i64,
    to_sequence: i64,
) -> Result<Vec<LedgerEventRow>, sqlx::Error> {
    let rows = sqlx::query_as::<_, AgentEventDbRow>(
        "SELECT id, sequence, previous_hash, content_hash, payload, created_at, session_id
         FROM agent_events
         WHERE sequence >= $1 AND sequence <= $2
         ORDER BY sequence ASC",
    )
    .bind(from_sequence)
    .bind(to_sequence)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(db_row_to_ledger_event).collect())
}

pub async fn find_cached_http_get(pool: &PgPool, url: &str) -> Result<Option<String>, sqlx::Error> {
    let row = sqlx::query_scalar::<_, sqlx::types::Json<crate::schema::EventPayload>>(
        r#"SELECT ae_obs.payload
           FROM agent_events ae_act
           JOIN agent_action_log aal
             ON aal.event_id = ae_act.id AND aal.status = 'completed'
           JOIN agent_events ae_obs
             ON ae_obs.sequence = ae_act.sequence + 1
          WHERE ae_act.payload->>'type' = 'action'
            AND ae_act.payload->>'name' = 'http_get'
            AND ae_act.payload->'params'->>'url' = $1
          ORDER BY ae_act.sequence DESC
          LIMIT 1"#,
    )
    .bind(url)
    .fetch_optional(pool)
    .await?;

    if let Some(payload) = row
        && let crate::schema::EventPayload::Observation { content } = payload.0
    {
        return Ok(Some(content));
    }
    Ok(None)
}

pub async fn get_events_by_session(
    pool: &PgPool,
    session_id: Uuid,
) -> Result<Vec<LedgerEventRow>, sqlx::Error> {
    let rows = sqlx::query_as::<_, AgentEventDbRow>(
        "SELECT id, sequence, previous_hash, content_hash, payload, created_at, session_id
         FROM agent_events
         WHERE session_id = $1
         ORDER BY sequence ASC",
    )
    .bind(session_id)
    .fetch_all(pool)
    .await?;
    Ok(rows.into_iter().map(db_row_to_ledger_event).collect())
}

pub async fn verify_findings(
    pool: &PgPool,
    session_id: Uuid,
    findings: &[AuditFinding],
) -> Result<(), AppendError> {
    if findings.is_empty() {
        return Ok(());
    }
    let events = get_events_by_session(pool, session_id)
        .await
        .map_err(AppendError::Db)?;
    let observation_by_seq: std::collections::HashMap<i64, String> = events
        .into_iter()
        .filter_map(|e| {
            if let EventPayload::Observation { content } = e.payload {
                Some((e.sequence, content))
            } else {
                None
            }
        })
        .collect();

    for f in findings {
        if matches!(
            f.severity,
            FindingSeverity::High | FindingSeverity::Critical
        ) && f.evidence_sequence.is_empty()
        {
            return Err(AppendError::UnverifiedEvidence(format!(
                "finding '{}' (high/critical) has no evidence_sequence",
                f.title
            )));
        }
        for (i, &seq) in f.evidence_sequence.iter().enumerate() {
            let content = observation_by_seq.get(&seq).ok_or_else(|| {
                AppendError::UnverifiedEvidence(format!(
                    "finding '{}' references sequence {} which is not an observation in this session",
                    f.title, seq
                ))
            })?;
            let quote = f.evidence_quotes.get(i).map(String::as_str).unwrap_or("");
            if !quote.is_empty() && !content.contains(quote) {
                return Err(AppendError::UnverifiedEvidence(format!(
                    "finding '{}' evidence_quotes[{}] is not a substring of observation at sequence {}",
                    f.title, i, seq
                )));
            }
        }
    }
    Ok(())
}

// Re-export the shared `AppendError` so existing `ledger::postgres::AppendError`
// paths continue to resolve.
pub use super::AppendError;

pub async fn verify_session_signatures(
    pool: &PgPool,
    session_id: Uuid,
) -> Result<(usize, Option<crate::signing::SigningError>), sqlx::Error> {
    let Some(session) = list_sessions(pool)
        .await?
        .into_iter()
        .find(|s| s.id == session_id)
    else {
        return Ok((0, None));
    };
    let Some(session_public_key_hex) = session.session_public_key else {
        return Ok((0, None));
    };
    let events = get_events_by_session(pool, session_id).await?;

    // Build the set of authorised public keys for this session.
    // Starts with the session's original key; key-rotation events add new
    // authorised keys, key-revocation events remove them (TM-2d + TM-3f).
    let mut authorised_keys: std::collections::HashSet<String> = std::collections::HashSet::new();
    authorised_keys.insert(session_public_key_hex.clone());

    // Track revoked keys so we reject signatures by a revoked key even if it
    // was once authorised.
    let mut revoked_keys: std::collections::HashSet<String> = std::collections::HashSet::new();

    let mut verified = 0;
    let mut first_err = None;
    for ev in &events {
        // Process key lifecycle events to update the authorised key set.
        match &ev.payload {
            EventPayload::KeyRotation { new_public_key, .. } => {
                authorised_keys.insert(new_public_key.clone());
            }
            EventPayload::KeyRevocation {
                revoked_public_key, ..
            } => {
                revoked_keys.insert(revoked_public_key.clone());
                authorised_keys.remove(revoked_public_key);
            }
            _ => {}
        }

        let row: Option<(String, String, String)> = sqlx::query_as(
            "SELECT content_hash, signature, public_key FROM agent_event_signatures WHERE event_id = $1",
        )
        .bind(ev.id)
        .fetch_optional(pool)
        .await?;
        if let Some((content_hash, signature, sig_public_key)) = row {
            // TM-2d: Cross-check that the signature's public key is authorised
            // for this session and has not been revoked.
            if revoked_keys.contains(&sig_public_key) {
                if first_err.is_none() {
                    first_err = Some(crate::signing::SigningError::InvalidKey);
                }
                continue;
            }
            if !authorised_keys.contains(&sig_public_key) {
                if first_err.is_none() {
                    first_err = Some(crate::signing::SigningError::InvalidKey);
                }
                continue;
            }
            match signing::verify_signature(&sig_public_key, &content_hash, &signature) {
                Ok(()) => verified += 1,
                Err(e) if first_err.is_none() => first_err = Some(e),
                Err(_) => {}
            }
        }
    }
    Ok((verified, first_err))
}

// ─── Per-session advisory locks ───────────────────────────────────────────────

/// Derive a stable `i64` advisory-lock key from a session UUID.
///
/// Uses the upper 8 bytes of the UUID to avoid collisions with the
/// global genesis lock (key `42`).  The key space is large enough that
/// collisions across concurrent sessions are negligible.
pub fn session_lock_key(session_id: Uuid) -> i64 {
    let bytes = session_id.as_bytes();
    // Interpret the first 8 bytes as a big-endian i64.
    // Mask out the sign bit so the key is always positive (PostgreSQL
    // advisory-lock keys are `bigint`, but positive values are easier
    // to reason about in monitoring dashboards).
    let raw = i64::from_be_bytes([
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
    ]);
    // Ensure the key is ≥ 1000 to stay well clear of any small manually-
    // chosen lock keys (e.g. the genesis lock on key 42).
    (raw & i64::MAX).saturating_add(1000)
}

/// Try to acquire a session-level advisory lock.  Returns `true` if the
/// lock was acquired, `false` if another instance already holds it.
///
/// The lock is connection-scoped — it will be released when the
/// connection (or pool slot) is returned, or when explicitly released
/// with [`release_session_lock`].
///
/// # Usage
///
/// ```ignore
/// let key = session_lock_key(session_id);
/// if !try_acquire_session_lock(pool, key).await? {
///     tracing::warn!("Session {} already owned by another instance", session_id);
///     return Ok(());
/// }
/// // … run cognitive loop …
/// release_session_lock(pool, key).await?;
/// ```
pub async fn try_acquire_session_lock(pool: &PgPool, key: i64) -> Result<bool, sqlx::Error> {
    let row: (bool,) = sqlx::query_as("SELECT pg_try_advisory_lock($1)")
        .bind(key)
        .fetch_one(pool)
        .await?;
    Ok(row.0)
}

/// Release a previously acquired session-level advisory lock.
pub async fn release_session_lock(pool: &PgPool, key: i64) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(key)
        .execute(pool)
        .await?;
    Ok(())
}

// ─── LedgerBackend trait implementation ────────────────────────────────────────

/// Newtype wrapping `PgPool` that implements `ledger_api::LedgerBackend`.
pub struct PostgresLedger(pub PgPool);

#[async_trait]
impl ledger_api::LedgerBackend for PostgresLedger {
    async fn append_event(
        &self,
        payload: ledger_api::RawPayload,
        session_id: Option<Uuid>,
        session_goal: Option<&str>,
        signing_key_bytes: Option<&[u8]>,
    ) -> Result<ledger_api::AppendResult, ledger_api::LedgerError> {
        let typed_payload: EventPayload = serde_json::from_value(payload)
            .map_err(|e| ledger_api::LedgerError::Serialize(e.to_string()))?;
        let sk = match signing_key_bytes {
            Some(b) => {
                let arr: &[u8; 32] = b.try_into().map_err(|_| {
                    ledger_api::LedgerError::Serialize(
                        "signing key must be exactly 32 bytes".to_string(),
                    )
                })?;
                Some(ed25519_dalek::SigningKey::from_bytes(arr))
            }
            None => None,
        };
        let res = append_event(
            &self.0,
            typed_payload,
            session_id,
            session_goal,
            sk.as_ref(),
        )
        .await
        .map_err(|e| ledger_api::LedgerError::Database(e.to_string()))?;
        Ok(ledger_api::AppendResult {
            id: res.id,
            sequence: res.sequence,
            previous_hash: res.previous_hash,
            content_hash: res.content_hash,
            created_at: res.created_at,
        })
    }

    async fn create_session(
        &self,
        params: ledger_api::NewSession,
    ) -> Result<(ledger_api::Session, Vec<u8>), ledger_api::LedgerError> {
        let (row, sk) = create_session_with_did(
            &self.0,
            &params.goal,
            &params.llm_backend,
            &params.llm_model,
            params.policy_hash.as_deref(),
            params.session_did.as_deref(),
        )
        .await
        .map_err(|e| ledger_api::LedgerError::Database(e.to_string()))?;
        let session = ledger_api::Session {
            id: row.id,
            goal: row.goal,
            goal_hash: row.goal_hash,
            status: row.status,
            llm_backend: row.llm_backend,
            llm_model: row.llm_model,
            created_at: row.created_at,
            finished_at: row.finished_at,
            policy_hash: row.policy_hash,
            session_public_key: row.session_public_key,
            session_did: params.session_did,
        };
        Ok((session, sk.to_bytes().to_vec()))
    }

    async fn seal_session(
        &self,
        session_id: Uuid,
        status: &str,
    ) -> Result<(), ledger_api::LedgerError> {
        finish_session(&self.0, session_id, status)
            .await
            .map_err(|e| ledger_api::LedgerError::Database(e.to_string()))
    }

    async fn get_events_by_session(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<ledger_api::LedgerEvent>, ledger_api::LedgerError> {
        let rows = get_events_by_session(&self.0, session_id)
            .await
            .map_err(|e| ledger_api::LedgerError::Database(e.to_string()))?;
        rows.into_iter()
            .map(|r| {
                let payload = serde_json::to_value(&r.payload)
                    .map_err(|e| ledger_api::LedgerError::Serialize(e.to_string()))?;
                Ok(ledger_api::LedgerEvent {
                    id: r.id,
                    sequence: r.sequence,
                    previous_hash: r.previous_hash,
                    content_hash: r.content_hash,
                    payload,
                    created_at: r.created_at,
                })
            })
            .collect()
    }

    async fn list_sessions(&self) -> Result<Vec<ledger_api::Session>, ledger_api::LedgerError> {
        let rows = list_sessions(&self.0)
            .await
            .map_err(|e| ledger_api::LedgerError::Database(e.to_string()))?;
        Ok(rows
            .into_iter()
            .map(|r| ledger_api::Session {
                id: r.id,
                goal: r.goal,
                goal_hash: r.goal_hash,
                status: r.status,
                llm_backend: r.llm_backend,
                llm_model: r.llm_model,
                created_at: r.created_at,
                finished_at: r.finished_at,
                policy_hash: r.policy_hash,
                session_public_key: r.session_public_key,
                session_did: None,
            })
            .collect())
    }

    async fn verify_chain(&self, from: i64, to: i64) -> Result<bool, ledger_api::LedgerError> {
        verify_chain(&self.0, from, to)
            .await
            .map_err(|e| ledger_api::LedgerError::Database(e.to_string()))
    }

    async fn prove_compliance(&self, session_id: Uuid) -> Result<Vec<u8>, ledger_api::LedgerError> {
        // Phase 1: return a JSON-serialised summary of all events in the session.
        let events = get_events_by_session(&self.0, session_id)
            .await
            .map_err(|e| ledger_api::LedgerError::Database(e.to_string()))?;
        let bundle = serde_json::json!({
            "session_id": session_id,
            "event_count": events.len(),
            "events": events.iter().map(|e| serde_json::json!({
                "sequence": e.sequence,
                "content_hash": e.content_hash,
            })).collect::<Vec<_>>(),
        });
        serde_json::to_vec(&bundle).map_err(|e| ledger_api::LedgerError::Serialize(e.to_string()))
    }
}
