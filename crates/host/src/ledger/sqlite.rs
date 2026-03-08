//! SQLite-backed implementation of `ledger_api::LedgerBackend`.
//!
//! Use `DATABASE_URL=sqlite://ledger.db` (or `sqlite://:memory:`) to
//! activate this backend.  Good for zero-config local development.
//!
//! Schema is kept in `migrations/sqlite/` and applied at startup.

use crate::hash::{GENESIS_PREVIOUS_HASH, compute_content_hash, sha256_hex};
use crate::schema::{AppendedEvent, EventPayload, LedgerEventRow, SessionRow};
use crate::signing;
use async_trait::async_trait;
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sqlx::SqlitePool;
use subtle::ConstantTimeEq;
use uuid::Uuid;

// Re-import `AppendError` through the module root so the SQLite backend
// does not depend directly on the Postgres module.
use super::AppendError;

// ─── SQLite-specific row types ─────────────────────────────────────────────────
//
// Unlike Postgres (where UUIDs and JSON are native column types), SQLite stores
// both as TEXT.  These `FromRow` structs match the SQLite column types and are
// converted to the domain types in-memory.

/// Row returned by `SELECT … FROM agent_events`.
#[derive(sqlx::FromRow)]
struct SqliteEventRow {
    id: i64,
    sequence: i64,
    previous_hash: String,
    content_hash: String,
    payload: String,
    created_at: chrono::DateTime<Utc>,
    #[allow(dead_code)]
    session_id: Option<String>,
}

/// Row returned by `SELECT … FROM agent_sessions`.
#[derive(sqlx::FromRow)]
struct SqliteSessionRow {
    id: String,
    goal: String,
    goal_hash: Option<String>,
    status: String,
    llm_backend: Option<String>,
    llm_model: Option<String>,
    created_at: chrono::DateTime<Utc>,
    finished_at: Option<chrono::DateTime<Utc>>,
    policy_hash: Option<String>,
    session_public_key: Option<String>,
    session_did: Option<String>,
}

// ─── W3C DID key derivation (shared with Postgres backend) ─────────────────────

/// Derives a `did:key:z6Mk…` URI from an Ed25519 verifying key following the
/// W3C DID-key specification (multicodec prefix `0xed01` + base58btc encoding).
///
/// <https://w3c-ccg.github.io/did-method-key/#ed25519-x25519>
fn derive_did_key(verifying_key: &VerifyingKey) -> String {
    let mut encoded = vec![0xed_u8, 0x01_u8];
    encoded.extend_from_slice(verifying_key.as_bytes());
    format!("did:key:z{}", bs58::encode(&encoded).into_string())
}

/// Newtype wrapping `SqlitePool` that implements `ledger_api::LedgerBackend`.
pub struct SqliteLedger(pub SqlitePool);

impl SqliteLedger {
    /// Open (or create) a SQLite database at `url` and run migrations.
    ///
    /// Enables WAL journal mode (better concurrent-read performance on all
    /// platforms) and sets a 5-second busy timeout so that transient locks
    /// do not immediately fail — important on Windows where file-lock
    /// contention is more common.
    pub async fn connect(url: &str) -> Result<Self, sqlx::Error> {
        use sqlx::sqlite::SqliteConnectOptions;
        use std::str::FromStr;

        let opts = SqliteConnectOptions::from_str(url)?
            .journal_mode(sqlx::sqlite::SqliteJournalMode::Wal)
            .busy_timeout(std::time::Duration::from_secs(5))
            .create_if_missing(true);

        let pool = SqlitePool::connect_with(opts).await?;
        sqlx::migrate!("./migrations/sqlite")
            .run(&pool)
            .await
            .map_err(|e| sqlx::Error::Configuration(e.into()))?;
        Ok(Self(pool))
    }
}

// ─── In-process free functions ─────────────────────────────────────────────────
//
// These mirror the Postgres free functions in `ledger::postgres` and can be
// called from `main.rs`, `pool.rs`, and command handlers without constructing
// a full `SqliteLedger` wrapper.

pub async fn get_latest_sqlite(pool: &SqlitePool) -> Result<Option<(i64, String)>, sqlx::Error> {
    let row = sqlx::query_as::<_, (i64, String)>(
        "SELECT sequence, content_hash FROM agent_events ORDER BY sequence DESC LIMIT 1",
    )
    .fetch_optional(pool)
    .await?;
    Ok(row)
}

/// Verify hash-chain integrity for a range of sequences (inclusive).
///
/// When `from > 0` the function fetches event `from - 1` to seed the expected
/// `previous_hash` — otherwise verification would incorrectly compare the
/// first row's `previous_hash` against genesis.
pub async fn verify_chain_sqlite(
    pool: &SqlitePool,
    from: i64,
    to: i64,
) -> Result<bool, sqlx::Error> {
    // Wrap both reads in a transaction to guarantee a consistent snapshot;
    // without this, a concurrent writer could cause a false-negative.
    let mut tx = pool.begin().await?;

    let rows = sqlx::query_as::<
        _,
        (
            i64,
            String,
            String,
            String,
            Option<String>,
            chrono::DateTime<Utc>,
        ),
    >(
        "SELECT sequence, previous_hash, content_hash, payload, session_id, created_at
         FROM agent_events WHERE sequence >= ?1 AND sequence <= ?2 ORDER BY sequence ASC",
    )
    .bind(from)
    .bind(to)
    .fetch_all(&mut *tx)
    .await?;

    if rows.is_empty() {
        return Ok(true);
    }

    // Seed: if verifying from a non-genesis offset, fetch the preceding
    // event's content_hash so we can validate the first row's previous_hash.
    let mut prev: Option<String> = if from > 0 {
        sqlx::query_scalar::<_, String>("SELECT content_hash FROM agent_events WHERE sequence = ?1")
            .bind(from - 1)
            .fetch_optional(&mut *tx)
            .await?
    } else {
        None
    };

    for (seq, prev_hash, ch, payload_str, sid, created_at) in rows {
        let expected_prev = prev.as_deref().unwrap_or(GENESIS_PREVIOUS_HASH);
        if prev_hash != expected_prev {
            return Ok(false);
        }
        let ts_str = created_at.to_rfc3339();
        // Try session-bound + timestamped hash first (new formula), fall back
        // through intermediate formats for events created before hardening.
        let expected_ch =
            compute_content_hash(&prev_hash, seq, &payload_str, sid.as_deref(), Some(&ts_str));
        // Constant-time comparison to prevent timing side-channels (TM-4).
        let matches: bool = ch.as_bytes().ct_eq(expected_ch.as_bytes()).into();
        if !matches {
            // Fallback 1: session_id but no timestamp (TM-2 era).
            let mid = compute_content_hash(&prev_hash, seq, &payload_str, sid.as_deref(), None);
            let mid_matches: bool = ch.as_bytes().ct_eq(mid.as_bytes()).into();
            if !mid_matches {
                // Fallback 2: legacy — no session_id, no timestamp.
                let legacy = compute_content_hash(&prev_hash, seq, &payload_str, None, None);
                let legacy_matches: bool = ch.as_bytes().ct_eq(legacy.as_bytes()).into();
                if !legacy_matches {
                    return Ok(false);
                }
            }
        }
        prev = Some(ch);
    }
    Ok(true)
}

/// Verify Ed25519 event signatures for all events in a session.
///
/// Returns `true` when every signed event has a valid signature, or when
/// no signatures exist (unsigned sessions are not a verification failure).
pub async fn verify_session_signatures_sqlite(
    pool: &SqlitePool,
    session_id: Uuid,
) -> Result<bool, sqlx::Error> {
    // TM-2d: Fetch the session's authorised public key so we can cross-check
    // that every signature was produced by an authorised key.
    let session_pk: Option<String> =
        sqlx::query_scalar("SELECT session_public_key FROM agent_sessions WHERE id = ?1")
            .bind(session_id.to_string())
            .fetch_optional(pool)
            .await?
            .flatten();
    let Some(session_public_key) = session_pk else {
        // No session or no public key — nothing to verify.
        return Ok(true);
    };

    // Build the authorised-key set starting with the session's original key.
    let mut authorised_keys: std::collections::HashSet<String> = std::collections::HashSet::new();
    authorised_keys.insert(session_public_key);
    let mut revoked_keys: std::collections::HashSet<String> = std::collections::HashSet::new();

    // Fetch events to track key lifecycle (rotation/revocation) in order.
    let event_rows = sqlx::query_as::<_, (i64, String)>(
        "SELECT e.id, e.payload FROM agent_events e WHERE e.session_id = ?1 ORDER BY e.sequence ASC",
    )
    .bind(session_id.to_string())
    .fetch_all(pool)
    .await?;

    // Map event_id → payload for key lifecycle processing.
    let mut event_payloads: std::collections::HashMap<i64, EventPayload> =
        std::collections::HashMap::new();
    for (eid, payload_str) in &event_rows {
        if let Ok(p) = serde_json::from_str::<EventPayload>(payload_str) {
            event_payloads.insert(*eid, p);
        }
    }

    // Fetch all signatures ordered by event sequence.
    let rows = sqlx::query_as::<_, (i64, String, String, String)>(
        "SELECT s.event_id, s.content_hash, s.signature, s.public_key
         FROM agent_event_signatures s
         JOIN agent_events e ON e.id = s.event_id
         WHERE e.session_id = ?1
         ORDER BY e.sequence ASC",
    )
    .bind(session_id.to_string())
    .fetch_all(pool)
    .await?;

    // Process events and signatures together, updating authorised keys as we go.
    let mut sig_idx = 0;
    for (eid, _payload_str) in &event_rows {
        // Update key lifecycle from this event's payload.
        if let Some(payload) = event_payloads.get(eid) {
            match payload {
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
        }

        // Check if this event has a signature.
        while sig_idx < rows.len() && rows[sig_idx].0 == *eid {
            let (_, ref content_hash, ref signature_hex, ref pubkey_hex) = rows[sig_idx];
            sig_idx += 1;

            // TM-2d: Reject if the signing key was revoked or is not authorised.
            if revoked_keys.contains(pubkey_hex) || !authorised_keys.contains(pubkey_hex) {
                return Ok(false);
            }

            let pk_bytes = match hex::decode(pubkey_hex) {
                Ok(b) if b.len() == 32 => b,
                _ => return Ok(false),
            };
            let arr: [u8; 32] = match pk_bytes.try_into() {
                Ok(a) => a,
                Err(_) => return Ok(false),
            };
            let vk = match ed25519_dalek::VerifyingKey::from_bytes(&arr) {
                Ok(v) => v,
                Err(_) => return Ok(false),
            };
            if !signing::verify_content_hash(&vk, content_hash, signature_hex) {
                return Ok(false);
            }
        }
    }
    Ok(true)
}

pub async fn append_event_sqlite(
    pool: &SqlitePool,
    payload: &EventPayload,
    session_id: Option<Uuid>,
    signing_key: Option<&SigningKey>,
) -> Result<AppendedEvent, AppendError> {
    let payload_json = serde_json::to_string(payload).map_err(AppendError::Serialize)?;

    let mut tx = pool.begin().await.map_err(AppendError::Db)?;

    // Upgrade from DEFERRED to IMMEDIATE so the write lock is acquired *before*
    // we read the latest sequence.  Without this, two concurrent callers can
    // both read the same `latest` inside their DEFERRED transactions and then
    // one INSERT will fail with UNIQUE-constraint on `sequence`.  IMMEDIATE
    // serialises writers at BEGIN time — the SQLite equivalent of Postgres'
    // `pg_advisory_xact_lock(42)`.  Works on macOS, Windows, and Linux.
    sqlx::query("END; BEGIN IMMEDIATE")
        .execute(&mut *tx)
        .await
        .map_err(AppendError::Db)?;

    let latest = sqlx::query_as::<_, (i64, String)>(
        "SELECT sequence, content_hash FROM agent_events ORDER BY sequence DESC LIMIT 1",
    )
    .fetch_optional(&mut *tx)
    .await
    .map_err(AppendError::Db)?;

    let (sequence, previous_hash) = match latest {
        None => (0_i64, GENESIS_PREVIOUS_HASH.to_string()),
        Some((seq, ch)) => (seq + 1, ch),
    };

    let sid_str = session_id.map(|u| u.to_string());
    let now = Utc::now();
    let content_hash = compute_content_hash(
        &previous_hash,
        sequence,
        &payload_json,
        sid_str.as_deref(),
        Some(&now.to_rfc3339()),
    );

    let id = sqlx::query_scalar::<_, i64>(
        "INSERT INTO agent_events (sequence, previous_hash, content_hash, payload, created_at, session_id)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)
         RETURNING id",
    )
    .bind(sequence)
    .bind(&previous_hash)
    .bind(&content_hash)
    .bind(&payload_json)
    .bind(now)
    .bind(&sid_str)
    .fetch_one(&mut *tx)
    .await
    .map_err(AppendError::Db)?;

    // Insert signature inside the SAME transaction so event + signature are
    // committed atomically, matching the PostgreSQL backend's behaviour.
    if let (Some(sk), Some(_sid)) = (signing_key, session_id) {
        let pk_hex = signing::public_key_hex(&sk.verifying_key());
        let sig_hex = signing::sign_content_hash(sk, &content_hash);
        sqlx::query(
            "INSERT INTO agent_event_signatures (event_id, content_hash, signature, public_key) VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(id)
        .bind(&content_hash)
        .bind(&sig_hex)
        .bind(&pk_hex)
        .execute(&mut *tx)
        .await
        .map_err(AppendError::Db)?;
    }

    tx.commit().await.map_err(AppendError::Db)?;

    let appended = AppendedEvent {
        id,
        sequence,
        previous_hash,
        content_hash,
        created_at: now,
    };

    crate::server::notify_sse_subscribers();

    Ok(appended)
}

pub async fn create_session_sqlite(
    pool: &SqlitePool,
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
    // Auto-derive a W3C did:key URI from the Ed25519 keypair unless the
    // caller explicitly supplies one — matches the Postgres backend.
    let did = session_did
        .map(String::from)
        .unwrap_or_else(|| derive_did_key(&verifying_key));
    let now = Utc::now();
    let id_str = id.to_string();

    sqlx::query(
        "INSERT INTO agent_sessions
         (id, goal, goal_hash, status, llm_backend, llm_model, created_at, policy_hash, session_public_key, session_did)
         VALUES (?1, ?2, ?3, 'running', ?4, ?5, ?6, ?7, ?8, ?9)",
    )
    .bind(&id_str)
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
            session_did: Some(did),
            enclave_attestation_json: None,
        },
        signing_key,
    ))
}

/// Mark a session as finished with the given status.
///
/// Returns `sqlx::Error::RowNotFound` if no session with the given id exists,
/// preventing silent no-ops when the caller passes a stale or invalid UUID.
pub async fn finish_session_sqlite(
    pool: &SqlitePool,
    session_id: Uuid,
    status: &str,
) -> Result<(), sqlx::Error> {
    let result =
        sqlx::query("UPDATE agent_sessions SET status = ?1, finished_at = ?2 WHERE id = ?3")
            .bind(status)
            .bind(Utc::now())
            .bind(session_id.to_string())
            .execute(pool)
            .await?;
    if result.rows_affected() == 0 {
        return Err(sqlx::Error::RowNotFound);
    }
    Ok(())
}

/// Retrieve all events for a session, ordered by sequence.
///
/// Returns an error if any stored payload cannot be deserialised, rather than
/// silently fabricating a synthetic `Observation` — an immutable audit ledger
/// must never misrepresent its own data.
pub async fn get_events_by_session_sqlite(
    pool: &SqlitePool,
    session_id: Uuid,
) -> Result<Vec<LedgerEventRow>, sqlx::Error> {
    let rows = sqlx::query_as::<_, SqliteEventRow>(
        "SELECT id, sequence, previous_hash, content_hash, payload, created_at, session_id
         FROM agent_events WHERE session_id = ?1 ORDER BY sequence ASC",
    )
    .bind(session_id.to_string())
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|row| {
            let payload: EventPayload = serde_json::from_str(&row.payload).map_err(|e| {
                sqlx::Error::Decode(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("corrupt event payload at id={}: {}", row.id, e),
                )))
            })?;
            Ok(LedgerEventRow {
                id: row.id,
                sequence: row.sequence,
                previous_hash: row.previous_hash,
                content_hash: row.content_hash,
                payload,
                created_at: row.created_at,
            })
        })
        .collect()
}

/// List all sessions (for CLI display / reporting).
///
/// Returns a hard error if any stored `id` cannot be parsed as a UUID rather
/// than silently dropping the row — callers should be aware of corrupt data.
pub async fn list_sessions_sqlite(pool: &SqlitePool) -> Result<Vec<SessionRow>, sqlx::Error> {
    let rows = sqlx::query_as::<_, SqliteSessionRow>(
        "SELECT id, goal, goal_hash, status, llm_backend, llm_model,
                created_at, finished_at, policy_hash, session_public_key, session_did
         FROM agent_sessions ORDER BY created_at DESC",
    )
    .fetch_all(pool)
    .await?;

    rows.into_iter()
        .map(|row| {
            let id: Uuid = row.id.parse().map_err(|e| {
                sqlx::Error::Decode(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    format!("invalid UUID in agent_sessions.id '{}': {}", row.id, e),
                )))
            })?;
            Ok(SessionRow {
                id,
                goal: row.goal,
                goal_hash: row.goal_hash,
                status: row.status,
                llm_backend: row.llm_backend,
                llm_model: row.llm_model,
                created_at: row.created_at,
                finished_at: row.finished_at,
                policy_hash: row.policy_hash,
                session_public_key: row.session_public_key,
                session_did: row.session_did,
                enclave_attestation_json: None,
            })
        })
        .collect()
}

// ─── LedgerBackend impl ───────────────────���──────────────────────────────────

#[async_trait]
impl ledger_api::LedgerBackend for SqliteLedger {
    async fn append_event(
        &self,
        payload: ledger_api::RawPayload,
        session_id: Option<Uuid>,
        session_goal: Option<&str>,
        signing_key_bytes: Option<&[u8]>,
    ) -> Result<ledger_api::AppendResult, ledger_api::LedgerError> {
        // Goal-hash verification: reject events whose goal doesn't match the
        // session's stored goal hash, matching the Postgres backend's behaviour.
        if let (Some(sid), Some(goal)) = (session_id, session_goal) {
            let expected = sha256_hex(goal.as_bytes());
            let stored: Option<(String,)> =
                sqlx::query_as("SELECT goal_hash FROM agent_sessions WHERE id = ?1")
                    .bind(sid.to_string())
                    .fetch_optional(&self.0)
                    .await
                    .map_err(|e| ledger_api::LedgerError::Database(e.to_string()))?;
            match stored {
                Some((h,)) if h == expected => {}
                _ => return Err(ledger_api::LedgerError::GoalMismatch),
            }
        }

        let typed: EventPayload = serde_json::from_value(payload)
            .map_err(|e| ledger_api::LedgerError::Serialize(e.to_string()))?;
        let sk = match signing_key_bytes {
            Some(b) => {
                let arr: [u8; 32] = b.try_into().map_err(|_| {
                    ledger_api::LedgerError::Serialize(
                        "signing key must be exactly 32 bytes".to_string(),
                    )
                })?;
                Some(ed25519_dalek::SigningKey::from_bytes(&arr))
            }
            None => None,
        };
        let res = append_event_sqlite(&self.0, &typed, session_id, sk.as_ref())
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
        let (row, sk) = create_session_sqlite(
            &self.0,
            &params.goal,
            &params.llm_backend,
            &params.llm_model,
            params.policy_hash.as_deref(),
            params.session_did.as_deref(),
        )
        .await
        .map_err(|e| ledger_api::LedgerError::Database(e.to_string()))?;
        let s = ledger_api::Session {
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
            session_did: row.session_did,
        };
        Ok((s, sk.to_bytes().to_vec()))
    }

    async fn seal_session(
        &self,
        session_id: Uuid,
        status: &str,
    ) -> Result<(), ledger_api::LedgerError> {
        finish_session_sqlite(&self.0, session_id, status)
            .await
            .map_err(|e| ledger_api::LedgerError::Database(e.to_string()))
    }

    async fn get_events_by_session(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<ledger_api::LedgerEvent>, ledger_api::LedgerError> {
        // Delegate to the free function to avoid duplicating the query.
        let rows = get_events_by_session_sqlite(&self.0, session_id)
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
        // Delegate to the free function to avoid duplicating query + UUID parsing.
        let rows = list_sessions_sqlite(&self.0)
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
                session_did: r.session_did,
            })
            .collect())
    }

    async fn verify_chain(&self, from: i64, to: i64) -> Result<bool, ledger_api::LedgerError> {
        verify_chain_sqlite(&self.0, from, to)
            .await
            .map_err(|e| ledger_api::LedgerError::Database(e.to_string()))
    }

    async fn prove_compliance(&self, session_id: Uuid) -> Result<Vec<u8>, ledger_api::LedgerError> {
        let events = self.get_events_by_session(session_id).await?;
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

// ─── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod chain_verification_tests {
    use super::*;
    use crate::hash::{GENESIS_PREVIOUS_HASH, compute_content_hash};
    use crate::signing;

    /// Spin up an in-memory SQLite database with all migrations applied.
    async fn setup() -> SqlitePool {
        let pool = SqlitePool::connect("sqlite::memory:").await.unwrap();
        sqlx::migrate!("./migrations/sqlite")
            .run(&pool)
            .await
            .unwrap();
        pool
    }

    /// Helper: build a `Thought` payload.
    fn thought(msg: &str) -> EventPayload {
        EventPayload::Thought {
            content: msg.to_string(),
        }
    }

    /// Helper: insert a dummy session row so signature foreign keys are valid.
    async fn insert_session(pool: &SqlitePool, session_id: Uuid) {
        insert_session_with_key(pool, session_id, None).await;
    }

    async fn insert_session_with_key(
        pool: &SqlitePool,
        session_id: Uuid,
        public_key: Option<&str>,
    ) {
        sqlx::query(
            "INSERT INTO agent_sessions (id, goal, goal_hash, status, created_at, session_public_key)
             VALUES (?1, 'test-goal', 'h', 'running', datetime('now'), ?2)",
        )
        .bind(session_id.to_string())
        .bind(public_key)
        .execute(pool)
        .await
        .unwrap();
    }

    // ── Genesis & basic chain ──────────────────────────────────────────────

    /// Branches covered: A1 (genesis path in append), V3 (genesis seed), V7 (pass).
    #[tokio::test]
    async fn genesis_event_creates_valid_chain() {
        let pool = setup().await;
        let ev = append_event_sqlite(&pool, &thought("first"), None, None)
            .await
            .unwrap();

        assert_eq!(ev.sequence, 0);
        assert_eq!(ev.previous_hash, GENESIS_PREVIOUS_HASH);

        let expected_ch = compute_content_hash(
            GENESIS_PREVIOUS_HASH,
            0,
            &serde_json::to_string(&thought("first")).unwrap(),
            None,
            Some(&ev.created_at.to_rfc3339()),
        );
        assert_eq!(ev.content_hash, expected_ch);
        assert!(verify_chain_sqlite(&pool, 0, 0).await.unwrap());
    }

    /// Same as above but verifies the single-element iteration works.
    #[tokio::test]
    async fn single_event_verify() {
        let pool = setup().await;
        append_event_sqlite(&pool, &thought("only"), None, None)
            .await
            .unwrap();
        assert!(verify_chain_sqlite(&pool, 0, 0).await.unwrap());
    }

    /// Branches covered: A2 (continuation), V7 (full pass), V2 (mid-chain sub-range).
    #[tokio::test]
    async fn chain_of_five_events() {
        let pool = setup().await;
        for i in 0..5 {
            append_event_sqlite(&pool, &thought(&format!("step {i}")), None, None)
                .await
                .unwrap();
        }
        // Full chain
        assert!(verify_chain_sqlite(&pool, 0, 4).await.unwrap());
        // Sub-range starting from middle
        assert!(verify_chain_sqlite(&pool, 1, 3).await.unwrap());
    }

    // ── Empty / no-op ranges ───────────────────────────────────────────────

    /// Branch V1: empty row set → Ok(true).
    #[tokio::test]
    async fn verify_empty_range_returns_true() {
        let pool = setup().await;
        assert!(verify_chain_sqlite(&pool, 100, 200).await.unwrap());
    }

    // ── Mid-chain seeding ──────────────────────────────────────────────────

    /// Branch V2: from > 0, seed event exists → prior content_hash is used.
    #[tokio::test]
    async fn verify_from_mid_chain() {
        let pool = setup().await;
        for i in 0..5 {
            append_event_sqlite(&pool, &thought(&format!("ev {i}")), None, None)
                .await
                .unwrap();
        }
        // Verify only [2..4]; seeds from event 1's content_hash.
        assert!(verify_chain_sqlite(&pool, 2, 4).await.unwrap());
    }

    /// Branch V6: from > 0, seed event (from-1) absent → prev falls back to
    /// genesis, which doesn't match the fabricated previous_hash → false.
    #[tokio::test]
    async fn verify_from_mid_chain_seed_missing() {
        let pool = setup().await;
        // Insert seq 0 normally.
        append_event_sqlite(&pool, &thought("seq0"), None, None)
            .await
            .unwrap();

        // Raw-insert seq 5 with a fabricated previous_hash.
        let fake_prev = "cafecafecafecafecafecafecafecafecafecafecafecafecafecafecafecafe";
        let payload_json = serde_json::to_string(&thought("orphan")).unwrap();
        let fake_ch = compute_content_hash(fake_prev, 5, &payload_json, None, None);
        sqlx::query(
            "INSERT INTO agent_events (sequence, previous_hash, content_hash, payload, created_at)
             VALUES (5, ?1, ?2, ?3, datetime('now'))",
        )
        .bind(fake_prev)
        .bind(&fake_ch)
        .bind(&payload_json)
        .execute(&pool)
        .await
        .unwrap();

        // Seed event (seq 4) is absent → prev = None → genesis hash used.
        // fake_prev ≠ GENESIS_PREVIOUS_HASH → chain breaks (V4).
        assert!(!verify_chain_sqlite(&pool, 5, 5).await.unwrap());
    }

    // ── Tampered previous_hash ─────────────────────────────────────────────

    /// Branch V4: stored previous_hash doesn't match expected → false.
    #[tokio::test]
    async fn tampered_previous_hash_detected() {
        let pool = setup().await;
        for i in 0..3 {
            append_event_sqlite(&pool, &thought(&format!("t {i}")), None, None)
                .await
                .unwrap();
        }

        // Drop immutability trigger to simulate external/offline tampering.
        sqlx::query("DROP TRIGGER IF EXISTS agent_events_no_update")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query("UPDATE agent_events SET previous_hash = 'bad' WHERE sequence = 1")
            .execute(&pool)
            .await
            .unwrap();

        assert!(!verify_chain_sqlite(&pool, 0, 2).await.unwrap());
    }

    // ── Tampered content_hash ──────────────────────────────────────────────

    /// Branch V5: recomputed content_hash doesn't match stored → false.
    #[tokio::test]
    async fn tampered_content_hash_detected() {
        let pool = setup().await;
        for i in 0..3 {
            append_event_sqlite(&pool, &thought(&format!("c {i}")), None, None)
                .await
                .unwrap();
        }

        // Drop immutability trigger to simulate external/offline tampering.
        sqlx::query("DROP TRIGGER IF EXISTS agent_events_no_update")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE agent_events SET content_hash = 'deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef' WHERE sequence = 1",
        )
        .execute(&pool)
        .await
        .unwrap();

        assert!(!verify_chain_sqlite(&pool, 0, 2).await.unwrap());
    }

    // ── Corrupted payload ──────────────────────────────────────────────────

    /// Branch V5 via payload mutation: content_hash no longer matches
    /// compute_content_hash(prev, seq, altered_payload).
    #[tokio::test]
    async fn corrupted_payload_detected() {
        let pool = setup().await;
        for i in 0..3 {
            append_event_sqlite(&pool, &thought(&format!("p {i}")), None, None)
                .await
                .unwrap();
        }

        // Drop immutability trigger to simulate external/offline tampering.
        sqlx::query("DROP TRIGGER IF EXISTS agent_events_no_update")
            .execute(&pool)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE agent_events SET payload = '{\"type\":\"thought\",\"content\":\"TAMPERED\"}' WHERE sequence = 1",
        )
        .execute(&pool)
        .await
        .unwrap();

        assert!(!verify_chain_sqlite(&pool, 0, 2).await.unwrap());
    }

    // ── Gap in sequence numbers ────────────────────────────────────────────

    /// A gap (missing seq 1) causes the iterator to jump 0 → 2. After seq 0,
    /// prev = ev0.content_hash. Seq 2's previous_hash is a fabricated value
    /// that ≠ ev0.content_hash → V4 triggers.
    #[tokio::test]
    async fn gap_in_sequence_numbers_detected() {
        let pool = setup().await;
        let _ev0 = append_event_sqlite(&pool, &thought("zero"), None, None)
            .await
            .unwrap();

        // Raw-insert seq 2 with a previous_hash that doesn't chain from ev0.
        let fake_prev = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let payload_json = serde_json::to_string(&thought("two")).unwrap();
        let ch = compute_content_hash(fake_prev, 2, &payload_json, None, None);
        sqlx::query(
            "INSERT INTO agent_events (sequence, previous_hash, content_hash, payload, created_at)
             VALUES (2, ?1, ?2, ?3, datetime('now'))",
        )
        .bind(fake_prev)
        .bind(&ch)
        .bind(&payload_json)
        .execute(&pool)
        .await
        .unwrap();

        // After seq 0, prev = ev0.content_hash.
        // Seq 2 has previous_hash = fake_prev ≠ ev0.content_hash → false.
        assert!(!verify_chain_sqlite(&pool, 0, 2).await.unwrap());

        // Sanity: ev0 alone is still valid.
        assert!(verify_chain_sqlite(&pool, 0, 0).await.unwrap());
    }

    // ── Signature verification ─────────────────────────────────────────────

    /// Branches A3 (signing path), S5 (all signatures valid).
    #[tokio::test]
    async fn signed_event_round_trip() {
        let pool = setup().await;
        let session_id = Uuid::new_v4();
        let (sk, vk) = signing::generate_keypair();
        let pk_hex = signing::public_key_hex(&vk);
        insert_session_with_key(&pool, session_id, Some(&pk_hex)).await;

        append_event_sqlite(&pool, &thought("signed"), Some(session_id), Some(&sk))
            .await
            .unwrap();

        assert!(
            verify_session_signatures_sqlite(&pool, session_id)
                .await
                .unwrap()
        );
    }

    /// Branch A4 + S1: no signing key → no signature rows → vacuously true.
    #[tokio::test]
    async fn unsigned_session_passes_signature_verify() {
        let pool = setup().await;
        let session_id = Uuid::new_v4();
        insert_session(&pool, session_id).await;

        append_event_sqlite(&pool, &thought("unsigned"), Some(session_id), None)
            .await
            .unwrap();

        assert!(
            verify_session_signatures_sqlite(&pool, session_id)
                .await
                .unwrap()
        );
    }

    /// Branch S4: tampered signature hex → verify_content_hash returns false.
    #[tokio::test]
    async fn tampered_signature_detected() {
        let pool = setup().await;
        let session_id = Uuid::new_v4();
        let (sk, vk) = signing::generate_keypair();
        let pk_hex = signing::public_key_hex(&vk);
        insert_session_with_key(&pool, session_id, Some(&pk_hex)).await;

        append_event_sqlite(&pool, &thought("tamper-me"), Some(session_id), Some(&sk))
            .await
            .unwrap();

        // Drop immutability trigger to simulate external/offline tampering.
        sqlx::query("DROP TRIGGER IF EXISTS agent_event_signatures_no_update")
            .execute(&pool)
            .await
            .unwrap();

        // Corrupt the stored signature by flipping its first byte.
        sqlx::query("UPDATE agent_event_signatures SET signature = 'ff' || substr(signature, 3)")
            .execute(&pool)
            .await
            .unwrap();

        assert!(
            !verify_session_signatures_sqlite(&pool, session_id)
                .await
                .unwrap()
        );
    }

    /// Branch S2: invalid public key hex → decode fails or length ≠ 32 → false.
    #[tokio::test]
    async fn invalid_pubkey_in_signature_row() {
        let pool = setup().await;
        let session_id = Uuid::new_v4();
        // Insert session with a known valid public key so the TM-2d
        // cross-check can detect that 'not_valid_hex' is unauthorised.
        let (_sk, vk) = signing::generate_keypair();
        let pk_hex = signing::public_key_hex(&vk);
        insert_session_with_key(&pool, session_id, Some(&pk_hex)).await;

        let ev = append_event_sqlite(&pool, &thought("bad-pk"), Some(session_id), None)
            .await
            .unwrap();

        // Manually insert a signature row with an invalid public key.
        sqlx::query(
            "INSERT INTO agent_event_signatures (event_id, content_hash, signature, public_key)
             VALUES (?1, ?2, ?3, 'not_valid_hex')",
        )
        .bind(ev.id)
        .bind(&ev.content_hash)
        .bind("deadbeef")
        .execute(&pool)
        .await
        .unwrap();

        assert!(
            !verify_session_signatures_sqlite(&pool, session_id)
                .await
                .unwrap()
        );
    }

    /// Branch S2 (length path): valid hex but wrong length (16 bytes, not 32).
    #[tokio::test]
    async fn wrong_length_pubkey_in_signature_row() {
        let pool = setup().await;
        let session_id = Uuid::new_v4();
        // Insert session with a valid public key so TM-2d cross-check triggers.
        let (_sk, vk) = signing::generate_keypair();
        let pk_hex = signing::public_key_hex(&vk);
        insert_session_with_key(&pool, session_id, Some(&pk_hex)).await;

        let ev = append_event_sqlite(&pool, &thought("short-pk"), Some(session_id), None)
            .await
            .unwrap();

        // 16-byte hex string (valid hex, wrong length for Ed25519).
        let short_pk = "00112233445566778899aabbccddeeff";
        sqlx::query(
            "INSERT INTO agent_event_signatures (event_id, content_hash, signature, public_key)
             VALUES (?1, ?2, ?3, ?4)",
        )
        .bind(ev.id)
        .bind(&ev.content_hash)
        .bind("deadbeef")
        .bind(short_pk)
        .execute(&pool)
        .await
        .unwrap();

        assert!(
            !verify_session_signatures_sqlite(&pool, session_id)
                .await
                .unwrap()
        );
    }

    // ── Genesis constant ───────────────────────────────────────────────────

    #[tokio::test]
    async fn genesis_previous_hash_is_64_zeroes() {
        assert_eq!(GENESIS_PREVIOUS_HASH.len(), 64);
        assert!(GENESIS_PREVIOUS_HASH.chars().all(|c| c == '0'));
    }

    // ── Append continuation wires previous_hash correctly ──────────────────

    /// Verify that each subsequent append chains to the prior event's content_hash.
    #[tokio::test]
    async fn append_chains_previous_hash_correctly() {
        let pool = setup().await;
        let ev0 = append_event_sqlite(&pool, &thought("a"), None, None)
            .await
            .unwrap();
        let ev1 = append_event_sqlite(&pool, &thought("b"), None, None)
            .await
            .unwrap();
        let ev2 = append_event_sqlite(&pool, &thought("c"), None, None)
            .await
            .unwrap();

        assert_eq!(ev0.previous_hash, GENESIS_PREVIOUS_HASH);
        assert_eq!(ev1.previous_hash, ev0.content_hash);
        assert_eq!(ev2.previous_hash, ev1.content_hash);
        assert_eq!(ev1.sequence, 1);
        assert_eq!(ev2.sequence, 2);
    }
}
