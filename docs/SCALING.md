# Horizontal Scaling Guide

> **Status**: EctoLedger currently runs as a single-process worker.
> This document captures the scaling constraints, migration path, and
> architectural decisions required to run multiple EctoLedger instances
> behind a load balancer.

---

## Backend Matrix

| Feature | SQLite | PostgreSQL |
|---------|--------|------------|
| Single-instance | **Yes** | Yes |
| Multi-instance (horizontal) | **No** | Yes (with caveats below) |
| Concurrent reads | WAL mode (up to 5 connections) | Unlimited |
| Concurrent writes | Serialised by file lock | Serialised by advisory lock |
| SSE fanout | Process-local only | Process-local (LISTEN/NOTIFY planned) |
| Approval state | In-memory only | In-memory (DB-backed planned) |
| Session ownership | None | Advisory-lock guard (planned) |

### SQLite: Single-Instance Only

SQLite is designed for single-process, single-machine deployments:

- The database file uses OS-level file locks that prevent safe concurrent
  access from multiple processes.
- `max_connections(5)` in the pool refers to in-process connections sharing
  a single WAL file — not multi-process concurrency.
- Running two `ectoledger serve` processes against the same `.db` file **will
  corrupt data** or produce `SQLITE_BUSY` errors under write contention.

**Use SQLite for**: local development, CI pipelines, single-machine audits,
air-gapped environments, and the Tauri desktop GUI.

**Use PostgreSQL for**: production servers, team environments, and any
deployment with more than one EctoLedger process.

---

## Current Scaling Bottlenecks (PostgreSQL)

Even with PostgreSQL, the following subsystems are process-local and must be
addressed before deploying multiple instances.

### 1. SSE Fanout

**Problem**: The Server-Sent Events stream (`/api/stream`) uses an in-process
`tokio::sync::broadcast` channel to notify subscribers when new ledger events
are appended. Clients connected to Instance A never learn about events
written by Instance B.

**Location**: `crates/host/src/server.rs` — `SSE_WAKEUP` static, `notify_sse_subscribers()`.

**Mitigation path**:

1. **PostgreSQL `LISTEN/NOTIFY`** (recommended) — After each `INSERT` into
   `agent_events`, issue `NOTIFY ectoledger_events`. Each instance's SSE
   handler listens on the same channel and wakes its local broadcast.
2. **Periodic polling fallback** — Remove the wakeup dependency entirely;
   poll every 1–2 seconds. Simple, but adds latency.
3. **External pub/sub** (Redis, NATS) — Higher throughput, but introduces
   an additional infrastructure dependency.

The DB-poll stage (`stream_events_since()`) is already multi-node safe —
only the wakeup signal needs externalization.

### 2. Approval State

**Problem**: `ApprovalState` (`crates/host/src/approvals.rs`) is a pair of
`RwLock<HashMap<…>>` maps. If the agent loop runs on Node A and the
operator submits an approval decision via the REST API on Node B, the
decision never reaches the agent.

**Mitigation path**:

1. Add a `pending_approvals` table (migration provided in
   `20260224000013_add_pending_approvals.sql`).
2. Agent polls the DB table instead of — or in addition to — the in-memory
   map.
3. Optionally use LISTEN/NOTIFY to wake the agent immediately when a
   decision arrives.

### 3. Session Ownership

**Problem**: Nothing prevents two instances from running the same session's
cognitive loop concurrently, which would produce duplicate events and
conflicting LLM calls.

**Location**: `crates/host/src/ledger/postgres.rs` — `pg_advisory_xact_lock(42)`.

The current lock on key `42` is **transaction-scoped** and **global** — it
serialises all event appends regardless of session. This prevents sequence
gaps but does not prevent two instances from running the same session.

**Mitigation path**:

1. **Per-session advisory locks** — Before starting a cognitive loop for
   session `S`, acquire `pg_try_advisory_lock(hash(S))`. If the lock is
   already held, skip or wait.
2. **Owner column** — Add `owner_instance_id` and `heartbeat_at` to
   `agent_sessions`. Instances claim ownership and renew heartbeats;
   stale owners are reaped.
3. **The global lock on key 42** should migrate to per-session sequence
   counters or optimistic insert-with-retry to remove the single global
   contention point.

### 4. Guard Process Affinity

Guard workers (`guard-worker` binary) are spawned as child processes.
In a multi-instance deployment, each instance spawns its own guard pool.
This is acceptable (guard processes are stateless) but increases total
resource consumption linearly.

---

## Migration Checklist

Before running multiple EctoLedger instances:

- [ ] Deploy PostgreSQL (SQLite is not supported for multi-instance).
- [ ] Apply the `pending_approvals` migration.
- [ ] Enable DB-backed `ApprovalState` (set `ECTO_APPROVAL_BACKEND=db`
      when available).
- [ ] Replace the in-process SSE wakeup with LISTEN/NOTIFY or periodic
      polling.
- [ ] Enable per-session advisory locks to prevent duplicate loops.
- [ ] Run behind a load balancer with sticky sessions **or** ensure all
      API endpoints are stateless (no in-memory maps).
- [ ] Monitor `pg_stat_activity` for advisory-lock contention.

---

## Architecture Diagram (Target State)

```
                    ┌──────────────┐
                    │ Load Balancer│
                    └──────┬───────┘
               ┌───────────┼───────────┐
               ▼           ▼           ▼
         ┌──────────┐┌──────────┐┌──────────┐
         │ Ecto #1  ││ Ecto #2  ││ Ecto #3  │
         │ SSE + API││ SSE + API││ SSE + API│
         └────┬─────┘└────┬─────┘└────┬─────┘
              │           │           │
              └─────┬─────┘           │
                    ▼                 ▼
            ┌──────────────────────────────┐
            │         PostgreSQL           │
            │  LISTEN/NOTIFY channels      │
            │  Advisory locks per session  │
            │  pending_approvals table     │
            └──────────────────────────────┘
```

Each instance is stateless except for active guard-worker child processes.
Session ownership is enforced via PostgreSQL advisory locks. SSE wakeups
propagate through LISTEN/NOTIFY. Approval decisions flow through the
`pending_approvals` table.
