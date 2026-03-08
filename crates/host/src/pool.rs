//! Runtime-dispatched database pool abstraction.
//!
//! `DatabasePool` wraps either a PostgreSQL or SQLite connection pool behind a
//! single enum so the server and embedded Tauri backend can work with both
//! engines from a single binary.  Query dispatch uses match-arms — thin runtime
//! cost, zero monomorphisation bloat.

use crate::ledger;
use crate::schema::{AppendedEvent, EventPayload, LedgerEventRow, SessionRow};
use crate::signing;
use chrono::Utc;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sqlx::{PgPool, SqlitePool};
use std::path::Path;
use uuid::Uuid;

/// Runtime-dispatched database pool.
#[derive(Clone)]
pub enum DatabasePool {
    Postgres(PgPool),
    Sqlite(SqlitePool),
}

impl DatabasePool {
    /// Convenience accessor — panics if not Postgres.
    pub fn as_pg(&self) -> Option<&PgPool> {
        match self {
            Self::Postgres(p) => Some(p),
            _ => None,
        }
    }

    /// Convenience accessor — panics if not SQLite.
    pub fn as_sqlite(&self) -> Option<&SqlitePool> {
        match self {
            Self::Sqlite(p) => Some(p),
            _ => None,
        }
    }
}

// ─── SQLite pool creation ─────────────────────────────────────────────────────

/// Create a new SQLite pool at `path`, running all migrations.
/// Creates parent directories and the file if they do not exist.
pub async fn create_sqlite_pool(
    path: &Path,
) -> Result<DatabasePool, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    let url = format!("sqlite://{}?mode=rwc", path.display());
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .max_connections(5)
        .connect(&url)
        .await?;

    // Enable WAL journal mode for better concurrent-read performance.
    sqlx::query("PRAGMA journal_mode=WAL;")
        .execute(&pool)
        .await?;
    // Set a 5-second busy timeout so transient locks are retried rather than
    // failing immediately — important on Windows where file-lock contention
    // is more common.
    sqlx::query("PRAGMA busy_timeout=5000;")
        .execute(&pool)
        .await?;

    // Run all SQLite migrations.
    sqlx::migrate!("./migrations/sqlite")
        .run(&pool)
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e.into() })?;

    Ok(DatabasePool::Sqlite(pool))
}

// ─── Ledger dispatch wrappers ─────────────────────────────────────────────────
// These mirror the free-function signatures in `ledger::postgres` and delegate
// to either the Postgres or SQLite implementation.

impl DatabasePool {
    pub async fn get_latest(&self) -> Result<Option<(i64, String)>, sqlx::Error> {
        match self {
            Self::Postgres(p) => ledger::get_latest(p).await,
            Self::Sqlite(p) => ledger::sqlite::get_latest_sqlite(p).await,
        }
    }

    pub async fn append_event(
        &self,
        payload: EventPayload,
        session_id: Option<Uuid>,
        session_goal: Option<&str>,
        signing_key: Option<&SigningKey>,
    ) -> Result<AppendedEvent, ledger::AppendError> {
        match self {
            Self::Postgres(p) => {
                ledger::append_event(p, payload, session_id, session_goal, signing_key).await
            }
            Self::Sqlite(p) => {
                ledger::sqlite::append_event_sqlite(p, &payload, session_id, signing_key).await
            }
        }
    }

    pub async fn create_session(
        &self,
        goal: &str,
        llm_backend: &str,
        llm_model: &str,
        policy_hash: Option<&str>,
    ) -> Result<(SessionRow, SigningKey), sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                ledger::create_session(p, goal, llm_backend, llm_model, policy_hash).await
            }
            Self::Sqlite(p) => {
                ledger::sqlite::create_session_sqlite(
                    p,
                    goal,
                    llm_backend,
                    llm_model,
                    policy_hash,
                    None,
                )
                .await
            }
        }
    }

    pub async fn create_session_with_did(
        &self,
        goal: &str,
        llm_backend: &str,
        llm_model: &str,
        policy_hash: Option<&str>,
        session_did: Option<&str>,
    ) -> Result<(SessionRow, SigningKey), sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                ledger::create_session_with_did(
                    p,
                    goal,
                    llm_backend,
                    llm_model,
                    policy_hash,
                    session_did,
                )
                .await
            }
            Self::Sqlite(p) => {
                ledger::sqlite::create_session_sqlite(
                    p,
                    goal,
                    llm_backend,
                    llm_model,
                    policy_hash,
                    session_did,
                )
                .await
            }
        }
    }

    pub async fn finish_session(&self, session_id: Uuid, status: &str) -> Result<(), sqlx::Error> {
        match self {
            Self::Postgres(p) => ledger::finish_session(p, session_id, status).await,
            Self::Sqlite(p) => {
                sqlx::query("UPDATE agent_sessions SET status = ?1, finished_at = ?2 WHERE id = ?3")
                    .bind(status)
                    .bind(Utc::now())
                    .bind(session_id.to_string())
                    .execute(p)
                    .await
                    .map(|_| ())
            }
        }
    }

    pub async fn list_sessions(&self) -> Result<Vec<SessionRow>, sqlx::Error> {
        match self {
            Self::Postgres(p) => ledger::list_sessions(p).await,
            Self::Sqlite(p) => {
                let rows = sqlx::query_as::<_, (String, String, String, String, String, String, chrono::DateTime<Utc>)>(
                    "SELECT id, goal, COALESCE(goal_hash,''), status, COALESCE(llm_backend,''), COALESCE(llm_model,''), created_at
                     FROM agent_sessions ORDER BY created_at DESC",
                )
                .fetch_all(p)
                .await?;

                Ok(rows
                    .into_iter()
                    .filter_map(
                        |(id_s, goal, goal_hash, status, lb, lm, ts)| match id_s.parse() {
                            Ok(id) => Some(SessionRow {
                                id,
                                goal,
                                goal_hash: Some(goal_hash),
                                status,
                                llm_backend: Some(lb),
                                llm_model: Some(lm),
                                created_at: ts,
                                finished_at: None,
                                policy_hash: None,
                                session_public_key: None,
                                session_did: None,
                                enclave_attestation_json: None,
                            }),
                            Err(e) => {
                                tracing::warn!(
                                    "Skipping session with unparseable UUID '{}': {}",
                                    id_s,
                                    e
                                );
                                None
                            }
                        },
                    )
                    .collect())
            }
        }
    }

    pub async fn list_sessions_filtered(
        &self,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<SessionRow>, sqlx::Error> {
        match self {
            Self::Postgres(p) => ledger::list_sessions_filtered(p, status, limit, offset).await,
            Self::Sqlite(p) => {
                let rows = if let Some(st) = status {
                    sqlx::query_as::<_, (String, String, String, String, String, String, chrono::DateTime<Utc>)>(
                        "SELECT id, goal, COALESCE(goal_hash,''), status, COALESCE(llm_backend,''), COALESCE(llm_model,''), created_at
                         FROM agent_sessions WHERE status = ?1 ORDER BY created_at DESC LIMIT ?2 OFFSET ?3",
                    )
                    .bind(st)
                    .bind(limit)
                    .bind(offset)
                    .fetch_all(p)
                    .await?
                } else {
                    sqlx::query_as::<_, (String, String, String, String, String, String, chrono::DateTime<Utc>)>(
                        "SELECT id, goal, COALESCE(goal_hash,''), status, COALESCE(llm_backend,''), COALESCE(llm_model,''), created_at
                         FROM agent_sessions ORDER BY created_at DESC LIMIT ?1 OFFSET ?2",
                    )
                    .bind(limit)
                    .bind(offset)
                    .fetch_all(p)
                    .await?
                };

                Ok(rows
                    .into_iter()
                    .filter_map(
                        |(id_s, goal, goal_hash, status, lb, lm, ts)| match id_s.parse() {
                            Ok(id) => Some(SessionRow {
                                id,
                                goal,
                                goal_hash: Some(goal_hash),
                                status,
                                llm_backend: Some(lb),
                                llm_model: Some(lm),
                                created_at: ts,
                                finished_at: None,
                                policy_hash: None,
                                session_public_key: None,
                                session_did: None,
                                enclave_attestation_json: None,
                            }),
                            Err(e) => {
                                tracing::warn!(
                                    "Skipping session with unparseable UUID '{}': {}",
                                    id_s,
                                    e
                                );
                                None
                            }
                        },
                    )
                    .collect())
            }
        }
    }

    pub async fn get_events_by_session(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<LedgerEventRow>, sqlx::Error> {
        match self {
            Self::Postgres(p) => ledger::get_events_by_session(p, session_id).await,
            Self::Sqlite(p) => {
                let rows = sqlx::query_as::<_, (i64, i64, String, String, String, chrono::DateTime<Utc>, Option<String>)>(
                    "SELECT id, sequence, previous_hash, content_hash, payload, created_at, session_id
                     FROM agent_events WHERE session_id = ?1 ORDER BY sequence ASC",
                )
                .bind(session_id.to_string())
                .fetch_all(p)
                .await?;

                let mut events = Vec::with_capacity(rows.len());
                for (id, seq, prev, ch, payload_str, ts, _sid) in rows {
                    let payload: EventPayload = match serde_json::from_str(&payload_str) {
                        Ok(p) => p,
                        Err(e) => {
                            tracing::warn!("Corrupt event payload at id={}: {}", id, e);
                            EventPayload::Observation {
                                content: format!("[corrupt payload: {}]", e),
                            }
                        }
                    };
                    events.push(LedgerEventRow {
                        id,
                        sequence: seq,
                        previous_hash: prev,
                        content_hash: ch,
                        payload,
                        created_at: ts,
                    });
                }
                Ok(events)
            }
        }
    }

    pub async fn ensure_genesis(&self) -> Result<AppendedEvent, ledger::AppendError> {
        match self {
            Self::Postgres(p) => ledger::ensure_genesis(p).await,
            Self::Sqlite(p) => {
                // If no events exist, create a genesis event.
                let latest = ledger::sqlite::get_latest_sqlite(p)
                    .await
                    .map_err(ledger::AppendError::Db)?;
                if latest.is_some() {
                    // Genesis already exists — return the first event.
                    let row = sqlx::query_as::<_, (i64, i64, String, String, chrono::DateTime<Utc>)>(
                        "SELECT id, sequence, previous_hash, content_hash, created_at FROM agent_events WHERE sequence = 0",
                    )
                    .fetch_one(p)
                    .await
                    .map_err(ledger::AppendError::Db)?;
                    return Ok(AppendedEvent {
                        id: row.0,
                        sequence: row.1,
                        previous_hash: row.2,
                        content_hash: row.3,
                        created_at: row.4,
                    });
                }
                ledger::sqlite::append_event_sqlite(
                    p,
                    &EventPayload::Genesis {
                        message: "genesis".to_string(),
                        nonce: Some(hex::encode(uuid::Uuid::new_v4().as_bytes())),
                        session_public_key: None, // server-level genesis: no session signing key yet
                    },
                    None,
                    None,
                )
                .await
            }
        }
    }

    pub async fn verify_goal_hash(
        &self,
        session_id: Uuid,
        current_goal: &str,
    ) -> Result<bool, sqlx::Error> {
        match self {
            Self::Postgres(p) => ledger::verify_goal_hash(p, session_id, current_goal).await,
            Self::Sqlite(p) => {
                let stored: Option<String> =
                    sqlx::query_scalar("SELECT goal_hash FROM agent_sessions WHERE id = ?1")
                        .bind(session_id.to_string())
                        .fetch_optional(p)
                        .await?;
                match stored {
                    None => Ok(false),
                    Some(h) => Ok(h == crate::hash::sha256_hex(current_goal.as_bytes())),
                }
            }
        }
    }

    // ─── Token queries (RBAC) ──────────────────────────────────────────────

    pub async fn find_token_role(&self, token_hash: &str) -> Result<Option<String>, sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                let row: Option<(String,)> = sqlx::query_as(
                    "SELECT role FROM api_tokens WHERE token_hash = $1 AND (expires_at IS NULL OR expires_at > now())",
                )
                .bind(token_hash)
                .fetch_optional(p)
                .await?;
                Ok(row.map(|r| r.0))
            }
            Self::Sqlite(p) => {
                let row: Option<(String,)> = sqlx::query_as(
                    "SELECT role FROM api_tokens WHERE token_hash = ?1 AND (expires_at IS NULL OR expires_at > datetime('now'))",
                )
                .bind(token_hash)
                .fetch_optional(p)
                .await?;
                Ok(row.map(|r| r.0))
            }
        }
    }

    pub async fn insert_token(
        &self,
        token_hash: &str,
        role: &str,
        label: Option<&str>,
        expires_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<(), sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                sqlx::query(
                    "INSERT INTO api_tokens (token_hash, role, label, expires_at) VALUES ($1, $2, $3, $4) ON CONFLICT (token_hash) DO NOTHING",
                )
                .bind(token_hash)
                .bind(role)
                .bind(label)
                .bind(expires_at)
                .execute(p)
                .await?;
                Ok(())
            }
            Self::Sqlite(p) => {
                let exp_str = expires_at.map(|t| t.to_rfc3339());
                sqlx::query(
                    "INSERT OR IGNORE INTO api_tokens (token_hash, role, label, expires_at) VALUES (?1, ?2, ?3, ?4)",
                )
                .bind(token_hash)
                .bind(role)
                .bind(label)
                .bind(exp_str)
                .execute(p)
                .await?;
                Ok(())
            }
        }
    }

    pub async fn list_tokens(&self) -> Result<Vec<TokenRow>, sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                let rows = sqlx::query_as::<_, TokenRow>(
                    "SELECT token_hash, role, label, created_at, expires_at FROM api_tokens ORDER BY created_at DESC",
                )
                .fetch_all(p)
                .await?;
                Ok(rows)
            }
            Self::Sqlite(p) => {
                let rows = sqlx::query_as::<_, TokenRow>(
                    "SELECT token_hash, role, label, created_at, expires_at FROM api_tokens ORDER BY created_at DESC",
                )
                .fetch_all(p)
                .await?;
                Ok(rows)
            }
        }
    }

    pub async fn delete_token(&self, token_hash: &str) -> Result<bool, sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                let result = sqlx::query("DELETE FROM api_tokens WHERE token_hash = $1")
                    .bind(token_hash)
                    .execute(p)
                    .await?;
                Ok(result.rows_affected() > 0)
            }
            Self::Sqlite(p) => {
                let result = sqlx::query("DELETE FROM api_tokens WHERE token_hash = ?1")
                    .bind(token_hash)
                    .execute(p)
                    .await?;
                Ok(result.rows_affected() > 0)
            }
        }
    }

    // ─── Webhook queries ───────────────────────────────────────────────────

    pub async fn list_webhooks(&self) -> Result<Vec<WebhookRow>, sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                // PG stores filter_kinds as TEXT[] – cast to TEXT for uniform WebhookRow.
                let rows = sqlx::query_as::<_, WebhookRow>(
                    "SELECT id::text, label, url, bearer_token, siem_format, \
                     array_to_string(filter_kinds, ',') AS filter_kinds, \
                     enabled, created_at::text, updated_at::text \
                     FROM webhooks ORDER BY created_at DESC",
                )
                .fetch_all(p)
                .await?;
                Ok(rows)
            }
            Self::Sqlite(p) => {
                let rows = sqlx::query_as::<_, WebhookRow>(
                    "SELECT id, label, url, bearer_token, siem_format, filter_kinds, enabled, created_at, updated_at FROM webhooks ORDER BY created_at DESC",
                )
                .fetch_all(p)
                .await?;
                Ok(rows)
            }
        }
    }

    pub async fn insert_webhook(
        &self,
        label: &str,
        url: &str,
        bearer_token: Option<&str>,
        siem_format: &str,
        filter_kinds: &[String],
        enabled: bool,
    ) -> Result<String, sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                let id: Uuid = sqlx::query_scalar(
                    "INSERT INTO webhooks (label, url, bearer_token, siem_format, filter_kinds, enabled) \
                     VALUES ($1, $2, $3, $4, $5, $6) RETURNING id",
                )
                .bind(label)
                .bind(url)
                .bind(bearer_token)
                .bind(siem_format)
                .bind(filter_kinds)
                .bind(enabled)
                .fetch_one(p)
                .await?;
                Ok(id.to_string())
            }
            Self::Sqlite(p) => {
                let id = Uuid::new_v4().to_string();
                let fk_csv = filter_kinds.join(",");
                sqlx::query(
                    "INSERT INTO webhooks (id, label, url, bearer_token, siem_format, filter_kinds, enabled) \
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                )
                .bind(&id)
                .bind(label)
                .bind(url)
                .bind(bearer_token)
                .bind(siem_format)
                .bind(&fk_csv)
                .bind(enabled)
                .execute(p)
                .await?;
                Ok(id)
            }
        }
    }

    pub async fn delete_webhook(&self, id: &str) -> Result<bool, sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                let uid: Uuid = id
                    .parse()
                    .map_err(|_| sqlx::Error::Protocol("invalid UUID".into()))?;
                let result = sqlx::query("DELETE FROM webhooks WHERE id = $1")
                    .bind(uid)
                    .execute(p)
                    .await?;
                Ok(result.rows_affected() > 0)
            }
            Self::Sqlite(p) => {
                let result = sqlx::query("DELETE FROM webhooks WHERE id = ?1")
                    .bind(id)
                    .execute(p)
                    .await?;
                Ok(result.rows_affected() > 0)
            }
        }
    }

    pub async fn toggle_webhook(&self, id: &str, enabled: bool) -> Result<bool, sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                let uid: Uuid = id
                    .parse()
                    .map_err(|_| sqlx::Error::Protocol("invalid UUID".into()))?;
                let result = sqlx::query(
                    "UPDATE webhooks SET enabled = $1, updated_at = now() WHERE id = $2",
                )
                .bind(enabled)
                .bind(uid)
                .execute(p)
                .await?;
                Ok(result.rows_affected() > 0)
            }
            Self::Sqlite(p) => {
                let result = sqlx::query(
                    "UPDATE webhooks SET enabled = ?1, updated_at = datetime('now') WHERE id = ?2",
                )
                .bind(enabled)
                .bind(id)
                .execute(p)
                .await?;
                Ok(result.rows_affected() > 0)
            }
        }
    }

    // ─── SSE event streaming ───────────────────────────────────────────────

    pub async fn stream_events_since(
        &self,
        after_id: i64,
        session_id: Option<Uuid>,
    ) -> Result<Vec<LedgerEventRow>, sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                let rows = if let Some(sid) = session_id {
                    sqlx::query_as::<_, (i64, i64, String, String, sqlx::types::Json<EventPayload>, chrono::DateTime<Utc>)>(
                        "SELECT id, sequence, previous_hash, content_hash, payload, created_at
                         FROM agent_events WHERE id > $1 AND session_id = $2 ORDER BY id ASC LIMIT 100",
                    )
                    .bind(after_id)
                    .bind(sid)
                    .fetch_all(p)
                    .await?
                } else {
                    sqlx::query_as::<
                        _,
                        (
                            i64,
                            i64,
                            String,
                            String,
                            sqlx::types::Json<EventPayload>,
                            chrono::DateTime<Utc>,
                        ),
                    >(
                        "SELECT id, sequence, previous_hash, content_hash, payload, created_at
                         FROM agent_events WHERE id > $1 ORDER BY id ASC LIMIT 100",
                    )
                    .bind(after_id)
                    .fetch_all(p)
                    .await?
                };
                Ok(rows
                    .into_iter()
                    .map(|(id, seq, prev, ch, payload, ts)| LedgerEventRow {
                        id,
                        sequence: seq,
                        previous_hash: prev,
                        content_hash: ch,
                        payload: payload.0,
                        created_at: ts,
                    })
                    .collect())
            }
            Self::Sqlite(p) => {
                if let Some(sid) = session_id {
                    let rows = sqlx::query_as::<_, (i64, i64, String, String, String, chrono::DateTime<Utc>, Option<String>)>(
                        "SELECT id, sequence, previous_hash, content_hash, payload, created_at, session_id
                         FROM agent_events WHERE id > ?1 AND session_id = ?2 ORDER BY id ASC LIMIT 100",
                    )
                    .bind(after_id)
                    .bind(sid.to_string())
                    .fetch_all(p)
                    .await?;

                    let mut events = Vec::with_capacity(rows.len());
                    for (id, seq, prev, ch, payload_str, ts, _sid_opt) in rows {
                        let payload: EventPayload = match serde_json::from_str(&payload_str) {
                            Ok(p) => p,
                            Err(e) => {
                                tracing::warn!("Corrupt event payload at id={}: {}", id, e);
                                EventPayload::Observation {
                                    content: format!("[corrupt payload: {}]", e),
                                }
                            }
                        };
                        events.push(LedgerEventRow {
                            id,
                            sequence: seq,
                            previous_hash: prev,
                            content_hash: ch,
                            payload,
                            created_at: ts,
                        });
                    }
                    Ok(events)
                } else {
                    let rows = sqlx::query_as::<_, (i64, i64, String, String, String, chrono::DateTime<Utc>, Option<String>)>(
                        "SELECT id, sequence, previous_hash, content_hash, payload, created_at, session_id
                         FROM agent_events WHERE id > ?1 ORDER BY id ASC LIMIT 100",
                    )
                    .bind(after_id)
                    .fetch_all(p)
                    .await?;

                    let mut events = Vec::with_capacity(rows.len());
                    for (id, seq, prev, ch, payload_str, ts, _sid_opt) in rows {
                        let payload: EventPayload = match serde_json::from_str(&payload_str) {
                            Ok(p) => p,
                            Err(e) => {
                                tracing::warn!("Corrupt event payload at id={}: {}", id, e);
                                EventPayload::Observation {
                                    content: format!("[corrupt payload: {}]", e),
                                }
                            }
                        };
                        events.push(LedgerEventRow {
                            id,
                            sequence: seq,
                            previous_hash: prev,
                            content_hash: ch,
                            payload,
                            created_at: ts,
                        });
                    }
                    Ok(events)
                }
            }
        }
    }

    // ─── Zombie session reaper ─────────────────────────────────────────────

    pub async fn reap_zombie_sessions(&self, max_age_minutes: i64) -> Result<u64, sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                let result = sqlx::query(
                    "UPDATE agent_sessions SET status = 'failed', finished_at = now()
                     WHERE status = 'running' AND created_at < now() - (interval '1 minute' * $1)",
                )
                .bind(max_age_minutes)
                .execute(p)
                .await?;
                Ok(result.rows_affected())
            }
            Self::Sqlite(p) => {
                let result = sqlx::query(
                    "UPDATE agent_sessions SET status = 'failed', finished_at = datetime('now')
                     WHERE status = 'running' AND created_at < datetime('now', ?1)",
                )
                .bind(format!("-{} minutes", max_age_minutes))
                .execute(p)
                .await?;
                Ok(result.rows_affected())
            }
        }
    }

    // ─── Demo data reset ─────────────────────────────────────────────────

    /// Delete **all** agent sessions, events, snapshots, and action-log rows.
    ///
    /// This is intended exclusively for the demo-mode "Reset Test Database"
    /// button — call-sites MUST gate on `config::is_demo_mode()`.
    pub async fn reset_demo_data(&self) -> Result<(), sqlx::Error> {
        match self {
            Self::Postgres(p) => {
                // The agent_events table has an immutable trigger that blocks
                // DELETE.  Temporarily disable it so the demo reset can clear
                // the ledger, then re-enable it immediately afterwards.
                sqlx::query("ALTER TABLE agent_events DISABLE TRIGGER agent_events_immutable")
                    .execute(p)
                    .await?;
                // Order matters: FK-safe (signatures → events → sessions).
                sqlx::query("DELETE FROM agent_action_log")
                    .execute(p)
                    .await?;
                sqlx::query("DELETE FROM agent_event_signatures")
                    .execute(p)
                    .await?;
                sqlx::query("DELETE FROM agent_events").execute(p).await?;
                sqlx::query("DELETE FROM agent_snapshots")
                    .execute(p)
                    .await?;
                sqlx::query("DELETE FROM agent_sessions").execute(p).await?;
                sqlx::query("ALTER TABLE agent_events ENABLE TRIGGER agent_events_immutable")
                    .execute(p)
                    .await?;
                Ok(())
            }
            Self::Sqlite(p) => {
                // SQLite: drop immutability triggers, delete, then recreate.
                sqlx::query("DROP TRIGGER IF EXISTS agent_events_no_update")
                    .execute(p)
                    .await?;
                sqlx::query("DROP TRIGGER IF EXISTS agent_events_no_delete")
                    .execute(p)
                    .await?;
                sqlx::query("DROP TRIGGER IF EXISTS agent_event_signatures_no_update")
                    .execute(p)
                    .await?;
                sqlx::query("DROP TRIGGER IF EXISTS agent_event_signatures_no_delete")
                    .execute(p)
                    .await?;

                sqlx::query("DELETE FROM agent_action_log")
                    .execute(p)
                    .await?;
                sqlx::query("DELETE FROM agent_event_signatures")
                    .execute(p)
                    .await?;
                sqlx::query("DELETE FROM agent_events").execute(p).await?;
                sqlx::query("DELETE FROM agent_snapshots")
                    .execute(p)
                    .await?;
                sqlx::query("DELETE FROM agent_sessions").execute(p).await?;

                // Recreate immutability triggers.
                sqlx::query(
                    "CREATE TRIGGER IF NOT EXISTS agent_events_no_update \
                     BEFORE UPDATE ON agent_events FOR EACH ROW BEGIN \
                     SELECT RAISE(ABORT, 'agent_events is append-only; UPDATE is not allowed.'); END"
                ).execute(p).await?;
                sqlx::query(
                    "CREATE TRIGGER IF NOT EXISTS agent_events_no_delete \
                     BEFORE DELETE ON agent_events FOR EACH ROW BEGIN \
                     SELECT RAISE(ABORT, 'agent_events is append-only; DELETE is not allowed.'); END"
                ).execute(p).await?;
                sqlx::query(
                    "CREATE TRIGGER IF NOT EXISTS agent_event_signatures_no_update \
                     BEFORE UPDATE ON agent_event_signatures FOR EACH ROW BEGIN \
                     SELECT RAISE(ABORT, 'agent_event_signatures is append-only; UPDATE is not allowed.'); END"
                ).execute(p).await?;
                sqlx::query(
                    "CREATE TRIGGER IF NOT EXISTS agent_event_signatures_no_delete \
                     BEFORE DELETE ON agent_event_signatures FOR EACH ROW BEGIN \
                     SELECT RAISE(ABORT, 'agent_event_signatures is append-only; DELETE is not allowed.'); END"
                ).execute(p).await?;
                Ok(())
            }
        }
    }

    // ─── Signing key lookup ────────────────────────────────────────────────

    pub async fn load_session_verifying_key(&self, session_id: Uuid) -> Option<VerifyingKey> {
        match self {
            Self::Postgres(p) => signing::load_session_verifying_key(p, session_id).await,
            Self::Sqlite(p) => {
                let pk_hex: Option<String> = sqlx::query_scalar(
                    "SELECT session_public_key FROM agent_sessions WHERE id = ?1",
                )
                .bind(session_id.to_string())
                .fetch_optional(p)
                .await
                .ok()?;

                let pk_hex = pk_hex?;
                let bytes = hex::decode(&pk_hex).ok()?;
                let arr: [u8; 32] = bytes.try_into().ok()?;
                VerifyingKey::from_bytes(&arr).ok()
            }
        }
    }
}

// ─── Row types for token/webhook queries ──────────────────────────────────────

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct TokenRow {
    pub token_hash: String,
    pub role: String,
    pub label: Option<String>,
    pub created_at: String,
    pub expires_at: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, sqlx::FromRow)]
pub struct WebhookRow {
    pub id: String,
    pub label: String,
    pub url: String,
    pub bearer_token: Option<String>,
    pub siem_format: String,
    pub filter_kinds: String,
    pub enabled: bool,
    pub created_at: String,
    pub updated_at: String,
}

impl DatabasePool {
    // ─── Chain verification & compliance (inherent wrappers) ─────────────────
    // These provide direct access without importing the LedgerBackend trait.

    /// Verify hash-chain integrity for all events in a session.
    pub async fn verify_chain_for_session(
        &self,
        session_id: Uuid,
    ) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
        let events = self.get_events_by_session(session_id).await?;
        if events.is_empty() {
            return Ok(true);
        }
        let from = events.first().unwrap().sequence;
        let to = events.last().unwrap().sequence;
        match self {
            Self::Postgres(p) => ledger::verify_chain(p, from, to)
                .await
                .map_err(|e| Box::new(e) as _),
            Self::Sqlite(p) => ledger::sqlite::verify_chain_sqlite(p, from, to)
                .await
                .map_err(|e| Box::new(e) as _),
        }
    }

    /// Generate a JSON compliance proof bundle for a session.
    pub async fn prove_compliance_for_session(
        &self,
        session_id: Uuid,
    ) -> Result<serde_json::Value, Box<dyn std::error::Error + Send + Sync>> {
        let events = self.get_events_by_session(session_id).await?;
        Ok(serde_json::json!({
            "session_id": session_id,
            "event_count": events.len(),
            "events": events.iter().map(|e| serde_json::json!({
                "sequence": e.sequence,
                "content_hash": e.content_hash,
            })).collect::<Vec<_>>(),
        }))
    }
}

// ─── LedgerBackend + LedgerAdmin implementations ─────────────────────────────
// These bridge the `DatabasePool` enum (used by the server) to the trait surface
// defined in `ledger-api`, enabling test doubles and future horizontal-scaling
// strategies to swap the backend via `Arc<dyn LedgerBackend>`.

use async_trait::async_trait;
use ledger_api::{LedgerAdmin, LedgerBackend, LedgerError};

#[async_trait]
impl LedgerBackend for DatabasePool {
    async fn append_event(
        &self,
        payload: ledger_api::RawPayload,
        session_id: Option<Uuid>,
        session_goal: Option<&str>,
        signing_key_bytes: Option<&[u8]>,
    ) -> Result<ledger_api::AppendResult, LedgerError> {
        let typed_payload: EventPayload =
            serde_json::from_value(payload).map_err(|e| LedgerError::Serialize(e.to_string()))?;
        let sk = match signing_key_bytes {
            Some(b) => {
                let arr: &[u8; 32] = b.try_into().map_err(|_| {
                    LedgerError::Serialize("signing key must be exactly 32 bytes".to_string())
                })?;
                Some(ed25519_dalek::SigningKey::from_bytes(arr))
            }
            None => None,
        };
        let res = self
            .append_event(typed_payload, session_id, session_goal, sk.as_ref())
            .await
            .map_err(|e| LedgerError::Database(e.to_string()))?;
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
    ) -> Result<(ledger_api::Session, Vec<u8>), LedgerError> {
        let (row, sk) = self
            .create_session_with_did(
                &params.goal,
                &params.llm_backend,
                &params.llm_model,
                params.policy_hash.as_deref(),
                params.session_did.as_deref(),
            )
            .await
            .map_err(|e| LedgerError::Database(e.to_string()))?;
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
            session_did: row.session_did,
        };
        Ok((session, sk.to_bytes().to_vec()))
    }

    async fn seal_session(&self, session_id: Uuid, status: &str) -> Result<(), LedgerError> {
        self.finish_session(session_id, status)
            .await
            .map_err(|e| LedgerError::Database(e.to_string()))
    }

    async fn get_events_by_session(
        &self,
        session_id: Uuid,
    ) -> Result<Vec<ledger_api::LedgerEvent>, LedgerError> {
        let rows = DatabasePool::get_events_by_session(self, session_id)
            .await
            .map_err(|e| LedgerError::Database(e.to_string()))?;
        rows.into_iter()
            .map(|r| {
                let payload = serde_json::to_value(&r.payload)
                    .map_err(|e| LedgerError::Serialize(e.to_string()))?;
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

    async fn list_sessions(&self) -> Result<Vec<ledger_api::Session>, LedgerError> {
        let rows = DatabasePool::list_sessions(self)
            .await
            .map_err(|e| LedgerError::Database(e.to_string()))?;
        Ok(rows.into_iter().map(session_row_to_api).collect())
    }

    async fn verify_chain(&self, from: i64, to: i64) -> Result<bool, LedgerError> {
        match self {
            Self::Postgres(p) => ledger::verify_chain(p, from, to)
                .await
                .map_err(|e| LedgerError::Database(e.to_string())),
            Self::Sqlite(p) => ledger::sqlite::verify_chain_sqlite(p, from, to)
                .await
                .map_err(|e| LedgerError::Database(e.to_string())),
        }
    }

    async fn prove_compliance(&self, session_id: Uuid) -> Result<Vec<u8>, LedgerError> {
        let events = DatabasePool::get_events_by_session(self, session_id)
            .await
            .map_err(|e| LedgerError::Database(e.to_string()))?;
        let bundle = serde_json::json!({
            "session_id": session_id,
            "event_count": events.len(),
            "events": events.iter().map(|e| serde_json::json!({
                "sequence": e.sequence,
                "content_hash": e.content_hash,
            })).collect::<Vec<_>>(),
        });
        serde_json::to_vec(&bundle).map_err(|e| LedgerError::Serialize(e.to_string()))
    }
}

#[async_trait]
impl LedgerAdmin for DatabasePool {
    async fn get_latest(&self) -> Result<Option<(i64, String)>, LedgerError> {
        DatabasePool::get_latest(self)
            .await
            .map_err(|e| LedgerError::Database(e.to_string()))
    }

    async fn ensure_genesis(&self) -> Result<ledger_api::AppendResult, LedgerError> {
        let res = DatabasePool::ensure_genesis(self)
            .await
            .map_err(|e| LedgerError::Database(e.to_string()))?;
        Ok(ledger_api::AppendResult {
            id: res.id,
            sequence: res.sequence,
            previous_hash: res.previous_hash,
            content_hash: res.content_hash,
            created_at: res.created_at,
        })
    }

    async fn stream_events_since(
        &self,
        after_id: i64,
        session_id: Option<Uuid>,
    ) -> Result<Vec<ledger_api::LedgerEvent>, LedgerError> {
        let rows = DatabasePool::stream_events_since(self, after_id, session_id)
            .await
            .map_err(|e| LedgerError::Database(e.to_string()))?;
        rows.into_iter()
            .map(|r| {
                let payload = serde_json::to_value(&r.payload)
                    .map_err(|e| LedgerError::Serialize(e.to_string()))?;
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

    async fn reap_zombie_sessions(&self, max_age_minutes: i64) -> Result<u64, LedgerError> {
        DatabasePool::reap_zombie_sessions(self, max_age_minutes)
            .await
            .map_err(|e| LedgerError::Database(e.to_string()))
    }

    async fn list_sessions_filtered(
        &self,
        status: Option<&str>,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ledger_api::Session>, LedgerError> {
        let rows = DatabasePool::list_sessions_filtered(self, status, limit, offset)
            .await
            .map_err(|e| LedgerError::Database(e.to_string()))?;
        Ok(rows.into_iter().map(session_row_to_api).collect())
    }
}

/// Convert a host `SessionRow` to an API `Session`.
fn session_row_to_api(r: SessionRow) -> ledger_api::Session {
    ledger_api::Session {
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
    }
}
