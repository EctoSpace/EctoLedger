use crate::ledger::{get_dangling_actions, get_events, mark_action_failed};
use crate::schema::{RestoredState, SnapshotRow};
use crate::snapshot::{
    SnapshotPayload, compute_state_hash, get_latest_snapshot, snapshot_at_sequence,
};
use serde_json::Value;
use sqlx::PgPool;

pub async fn replay_after_snapshot(
    pool: &PgPool,
    from_sequence: i64,
) -> Result<Vec<crate::schema::LedgerEventRow>, sqlx::Error> {
    let latest = get_latest(pool).await?;
    let to_sequence = match latest {
        None => return Ok(Vec::new()),
        Some((seq, _)) => seq,
    };
    if to_sequence <= from_sequence {
        return Ok(Vec::new());
    }
    get_events(pool, from_sequence + 1, to_sequence).await
}

async fn get_latest(pool: &PgPool) -> Result<Option<(i64, String)>, sqlx::Error> {
    crate::ledger::get_latest(pool).await
}

pub fn verify_snapshot_hash(snapshot: &SnapshotRow) -> Result<bool, serde_json::Error> {
    let payload: SnapshotPayload = serde_json::from_value(snapshot.payload.clone())?;
    let expected = compute_state_hash(&payload)?;
    Ok(snapshot.state_hash == expected)
}

pub async fn restore_state(
    pool: &PgPool,
    verify_snapshot: bool,
) -> Result<RestoredState, WakeUpError> {
    let snapshot = get_latest_snapshot(pool)
        .await
        .map_err(WakeUpError::Db)?
        .ok_or(WakeUpError::NoSnapshot)?;

    if verify_snapshot {
        let valid = verify_snapshot_hash(&snapshot).map_err(WakeUpError::Serialize)?;
        if !valid {
            return Err(WakeUpError::SnapshotHashMismatch);
        }
    }

    let replayed = replay_after_snapshot(pool, snapshot.sequence)
        .await
        .map_err(WakeUpError::Db)?;

    Ok(RestoredState {
        snapshot_sequence: snapshot.sequence,
        snapshot_payload: snapshot.payload,
        replayed_events: replayed,
    })
}

const RECOVERED_MSG: &str = "Action did not complete (recovered from previous run).";

const ZOMBIE_SESSION_MSG: &str = "Session did not complete (recovered after crash on next boot).";

/// Recover all sessions stuck in `"running"` status on startup.
///
/// For each zombie session:
/// 1. Appends an `Observation` event to the ledger noting the recovery.
/// 2. Marks the session as `"failed"` with `finished_at = now()`.
///
/// Should be called once during process startup, **before** the cognitive loop.
pub async fn recover_zombie_sessions(pool: &PgPool) -> Result<u64, WakeUpError> {
    let zombie_ids: Vec<uuid::Uuid> =
        sqlx::query_scalar("SELECT id FROM agent_sessions WHERE status = 'running'")
            .fetch_all(pool)
            .await
            .map_err(WakeUpError::Db)?;

    if zombie_ids.is_empty() {
        return Ok(0);
    }

    let count = zombie_ids.len() as u64;
    tracing::warn!(
        count,
        "recover_zombie_sessions: found {} session(s) still in 'running' status — marking failed",
        count,
    );

    for session_id in &zombie_ids {
        // Best-effort: append an observation to the ledger for auditability.
        if let Err(e) = crate::ledger::append_event(
            pool,
            crate::schema::EventPayload::Observation {
                content: format!("{} (session_id: {})", ZOMBIE_SESSION_MSG, session_id),
            },
            Some(*session_id),
            None,
            None,
        )
        .await
        {
            tracing::warn!(
                "recover_zombie_sessions: failed to append observation for session {}: {}",
                session_id,
                e
            );
        }

        // Mark the session as failed.
        if let Err(e) = crate::ledger::finish_session(pool, *session_id, "failed").await {
            tracing::warn!(
                "recover_zombie_sessions: failed to mark session {} as failed: {}",
                session_id,
                e
            );
        }
    }

    Ok(count)
}

pub async fn recover_incomplete_actions(pool: &PgPool) -> Result<(), WakeUpError> {
    let dangling = get_dangling_actions(pool).await.map_err(WakeUpError::Db)?;
    for event_id in dangling {
        if let Err(e) = crate::ledger::append_event(
            pool,
            crate::schema::EventPayload::Observation {
                content: RECOVERED_MSG.to_string(),
            },
            None,
            None,
            None,
        )
        .await
        {
            tracing::warn!(
                "Recovery: failed to append observation for dangling event {}: {}",
                event_id,
                e
            );
        }
        if let Err(e) = mark_action_failed(pool, event_id, RECOVERED_MSG).await {
            tracing::warn!(
                "Recovery: failed to mark action {} as failed: {}",
                event_id,
                e
            );
        }
    }
    Ok(())
}

pub async fn restore_state_from_genesis(pool: &PgPool) -> Result<RestoredState, WakeUpError> {
    let latest = get_latest(pool).await.map_err(WakeUpError::Db)?;
    match latest {
        None => Ok(RestoredState {
            snapshot_sequence: -1,
            snapshot_payload: Value::Object(serde_json::Map::new()),
            replayed_events: Vec::new(),
        }),
        Some((seq, _)) => {
            let replayed = get_events(pool, 0, seq).await.map_err(WakeUpError::Db)?;

            // Persist a checkpoint at the current tip so the next startup does not
            // repeat this full replay. On conflict (snapshot already exists for this
            // sequence) we simply skip silently.
            let snap_result = snapshot_at_sequence(pool, seq).await;
            let (snapshot_sequence, snapshot_payload) = match snap_result {
                Ok(row) => (row.sequence, row.payload),
                Err(crate::snapshot::SnapshotError::Db(ref e))
                    if e.to_string().contains("unique") || e.to_string().contains("duplicate") =>
                {
                    let existing = get_latest_snapshot(pool).await.map_err(WakeUpError::Db)?;
                    match existing {
                        Some(row) if row.sequence == seq => (row.sequence, row.payload),
                        _ => (seq, Value::Object(serde_json::Map::new())),
                    }
                }
                Err(e) => {
                    return Err(match e {
                        crate::snapshot::SnapshotError::Db(d) => WakeUpError::Db(d),
                        crate::snapshot::SnapshotError::Serialize(s) => WakeUpError::Serialize(s),
                    });
                }
            };

            Ok(RestoredState {
                snapshot_sequence,
                snapshot_payload,
                replayed_events: replayed,
            })
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum WakeUpError {
    #[error("db: {0}")]
    Db(#[from] sqlx::Error),
    #[error("serialize: {0}")]
    Serialize(#[from] serde_json::Error),
    #[error("no snapshot found")]
    NoSnapshot,
    #[error("snapshot state_hash mismatch")]
    SnapshotHashMismatch,
}
