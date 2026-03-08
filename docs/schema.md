# Ecto Ledger — Schema

## Design

- **Agent state** lives in PostgreSQL. The Rust process is a transient worker.
- **Event log** is append-only and hash-chained to prevent tampering and support verification.
- **Snapshots** are derived from the log for fast state recovery (wake-up).
- **Sessions** group events into goal-scoped runs with per-session Ed25519 signing and optional DID identity.
- **RBAC tokens** control API access via hashed bearer tokens with role-based checks.
- **Webhooks** push real-time events to SIEM / external systems in JSON, CEF, or LEEF format.

## Tables

### `agent_events` (immutable)

| Column         | Type         | Description |
|----------------|--------------|-------------|
| `id`           | BIGSERIAL    | Primary key. |
| `sequence`     | BIGINT       | Strict ordering; unique. Genesis block uses `sequence = 0`. |
| `previous_hash`| VARCHAR(64)  | SHA-256 hex of the **previous** row’s `content_hash`. For genesis, a fixed constant (e.g. 64 zero hex chars). |
| `content_hash` | VARCHAR(64)  | SHA-256 hex of this event: `previous_hash || sequence || payload_json` (deterministic). |
| `payload`      | JSONB        | Event body (e.g. thought, action, observation, genesis). |
| `created_at`   | TIMESTAMPTZ  | Insert time. |
| `session_id`   | UUID         | FK → `agent_sessions(id)`. Links event to the session that produced it. |

**Invariants:** No `UPDATE` or `DELETE` in application code — enforced by a `prevent_updates()` trigger. Each row's `previous_hash` must equal the previous row's `content_hash`.

**Indexes:** `idx_agent_events_sequence`, `idx_agent_events_created_at`, `idx_agent_events_content_hash`, `idx_agent_events_session_id`.

### `agent_snapshots` (mutable)

| Column       | Type        | Description |
|--------------|-------------|-------------|
| `id`         | UUID        | Primary key. |
| `sequence`   | BIGINT      | Last replayed event `sequence` for this snapshot. |
| `state_hash` | VARCHAR(64) | SHA-256 hex of canonical snapshot payload (for verification). |
| `payload`    | JSONB       | Aggregated state / performance summary. |
| `created_at` | TIMESTAMPTZ | Insert time. |

Used by the **wake-up protocol**: load latest snapshot by `sequence`, then replay events where `sequence > snapshot.sequence`.

### `agent_action_log`

| Column               | Type        | Description |
|----------------------|-------------|-------------|
| `id`                 | UUID        | Primary key (auto-generated). |
| `event_id`           | BIGINT      | References the event that triggered this action. |
| `status`             | VARCHAR(16) | One of: `pending`, `executing`, `completed`, `failed`. |
| `started_at`         | TIMESTAMPTZ | When execution began. |
| `finished_at`        | TIMESTAMPTZ | When execution ended (nullable). |
| `error_msg`          | TEXT        | Error details on failure (nullable). |
| `compensating_action`| JSONB       | Rollback / undo payload proposed by the agent (nullable). |
| `compensation_status`| VARCHAR(16) | One of: `proposed`, `executing`, `executed`, `failed`, `skipped` (nullable). |

### `agent_sessions`

| Column                     | Type         | Description |
|----------------------------|--------------|-------------|
| `id`                       | UUID         | Primary key (auto-generated). |
| `goal`                     | TEXT         | Human-readable goal for the agent run. |
| `goal_hash`                | VARCHAR(64)  | SHA-256 hex of the goal text. |
| `status`                   | VARCHAR(16)  | One of: `running`, `completed`, `failed`, `aborted`. |
| `llm_backend`              | VARCHAR(32)  | LLM provider (e.g. `ollama`, `openai`, `anthropic`). |
| `llm_model`                | VARCHAR(128) | Model identifier used for the run. |
| `created_at`               | TIMESTAMPTZ  | Session start time. |
| `finished_at`              | TIMESTAMPTZ  | Session end time (nullable). |
| `policy_hash`              | VARCHAR(64)  | SHA-256 hex of the TOML policy active during this session. |
| `session_public_key`       | VARCHAR(128) | Ed25519 public key (hex) used to sign events in this session. |
| `session_did`              | TEXT         | W3C Decentralized Identifier (`did:key:…`) derived from session key. |
| `enclave_attestation_json` | TEXT         | Serialised enclave attestation evidence (TPM quote / Apple HV report). |

### `agent_event_signatures`

| Column        | Type         | Description |
|---------------|--------------|-------------|
| `event_id`    | BIGINT       | Primary key; FK → `agent_events(id)`. |
| `content_hash`| VARCHAR(64)  | Hash that was signed (must match the event's `content_hash`). |
| `signature`   | VARCHAR(128) | Ed25519 signature (hex). |
| `public_key`  | VARCHAR(128) | Signer's public key (hex); must match `agent_sessions.session_public_key`. |

### `api_tokens`

| Column       | Type        | Description |
|--------------|-------------|-------------|
| `token_hash` | VARCHAR(64) | Primary key. SHA-256 hex of the raw bearer token (raw value is never stored). |
| `role`       | VARCHAR(16) | One of: `admin`, `auditor`, `agent`. |
| `label`      | TEXT        | Human-readable label (nullable). |
| `created_at` | TIMESTAMPTZ | Creation time. |
| `expires_at` | TIMESTAMPTZ | Optional expiry (nullable). |

**Index:** `api_tokens_role_idx`.

### `webhooks`

| Column         | Type        | Description |
|----------------|-------------|-------------|
| `id`           | UUID        | Primary key (auto-generated). |
| `label`        | TEXT        | Human-readable name for the webhook. |
| `url`          | TEXT        | Destination URL. |
| `bearer_token` | TEXT        | Optional bearer token for `Authorization` header (nullable). |
| `siem_format`  | VARCHAR(8)  | Output format: `json`, `cef`, or `leef`. Default `json`. |
| `filter_kinds` | TEXT[]      | Event kinds to forward. Default `{observation, guard_denial, tripwire_rejection}`. |
| `enabled`      | BOOLEAN     | Whether the hook is active. Default `true`. |
| `created_at`   | TIMESTAMPTZ | Creation time. |
| `updated_at`   | TIMESTAMPTZ | Last modification time. |

**Index:** `webhooks_enabled_idx`.

## Genesis rule

- The first event has `sequence = 0` and `previous_hash = GENESIS_PREVIOUS_HASH` (e.g. 64 zero hex characters).
- `content_hash` is computed the same way as for any other event.

## Migration history

| # | File | Summary |
|---|------|---------|
| 1 | `20250219000001_create_agent_events.sql` | Create `agent_events` table + immutability trigger. |
| 2 | `20250219000002_create_agent_snapshots.sql` | Create `agent_snapshots` table. |
| 3 | `20250219000003_create_agent_action_log.sql` | Create `agent_action_log` table. |
| 4 | `20250219000004_create_agent_sessions.sql` | Create `agent_sessions` table. |
| 5 | `20250219000005_add_session_id_to_events.sql` | Add `session_id` FK to `agent_events`. |
| 6 | `20250219000006_add_policy_hash_to_sessions.sql` | Add `policy_hash` to `agent_sessions`. |
| 7 | `20250219000007_add_event_signing.sql` | Add `session_public_key` to sessions; create `agent_event_signatures`. |
| 8 | `20260221000008_add_session_did.sql` | Add `session_did` to sessions. |
| 9 | `20260222000009_add_rbac_tokens.sql` | Create `api_tokens` table. |
| 10 | `20260222000010_add_webhook_config.sql` | Create `webhooks` table. |
| 11 | `20260222000011_add_compensating_actions.sql` | Add compensation columns to `agent_action_log`. |
| 12 | `20260223000012_add_enclave_attestation.sql` | Add `enclave_attestation_json` to sessions. |
| 13 | `20260224000013_add_pending_approvals.sql` | Create `pending_approvals` table for horizontal-scaling approval state. |

### `pending_approvals`

| Column                | Type        | Description |
|-----------------------|-------------|-------------|
| `id`                  | BIGSERIAL   | Primary key. |
| `session_id`          | UUID        | Session requiring approval. |
| `gate_id`             | TEXT        | Identifier for the policy approval gate. |
| `action_name`         | TEXT        | Action that triggered the gate. |
| `action_params_summary` | TEXT      | Summary of action parameters (default empty). |
| `approved`            | BOOLEAN     | `NULL` = pending, `TRUE` = approved, `FALSE` = denied. |
| `reason`              | TEXT        | Human-provided reason for the decision (nullable). |
| `created_at`          | TIMESTAMPTZ | When the approval was requested. |
| `decided_at`          | TIMESTAMPTZ | When the decision was made (nullable). |

**Constraints:** `UNIQUE (session_id, gate_id)` prevents duplicate pending records for the same gate in the same session.

**Index:** `idx_pending_approvals_session_decided` — partial index on `session_id` where `approved IS NOT NULL` for efficient agent-side polling.
