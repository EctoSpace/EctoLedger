/** Shared types mirroring the EctoLedger API response shapes. */

// ── Sessions ────────────────────────────────────────────────────────────────

export interface Session {
  id: string;
  goal: string;
  goal_hash: string | null;
  status: string;
  llm_backend: string | null;
  llm_model: string | null;
  created_at: string;
  finished_at: string | null;
  policy_hash: string | null;
  session_public_key: string | null;
  session_did: string | null;
  enclave_attestation_json: string | null;
}

export interface CreateSessionOptions {
  goal: string;
  policy_hash?: string;
  session_did?: string;
}

export interface ListSessionsOptions {
  limit?: number;
  offset?: number;
  status?: string;
}

// ── Events ──────────────────────────────────────────────────────────────────

export interface LedgerEvent {
  id: number;
  session_id: string;
  payload: unknown;
  payload_hash: string;
  prev_hash: string | null;
  sequence: number;
  created_at: string;
  public_key: string | null;
  signature: string | null;
}

export interface AppendResult {
  id: number;
  payload_hash: string;
  sequence: number;
}

// ── Compliance ──────────────────────────────────────────────────────────────

export interface ComplianceBundle {
  session_id: string;
  events: Array<{ sequence: number; payload_hash: string }>;
  policy_hash: string | null;
  generated_at: string;
}

// ── Metrics ─────────────────────────────────────────────────────────────────

export interface MetricsSummary {
  total_sessions: number;
  total_events: number;
  [key: string]: unknown;
}

export interface SecurityMetrics {
  injection_attempts_detected_7d: number;
  injection_attempts_by_layer: Record<string, number>;
  sessions_aborted_circuit_breaker: number;
  chain_verification_failures: number;
}

// ── Approval Gates ──────────────────────────────────────────────────────────

export interface PendingApproval {
  gate_id: string;
  action_name: string;
  action_params_summary: string;
  created_at: string;
}

export interface ApprovalDecision {
  gate_id: string;
  approved: boolean;
  reason?: string;
}

// ── Client Options ──────────────────────────────────────────────────────────

export interface EctoLedgerClientOptions {
  baseUrl?: string;
  bearerToken?: string;
}

// ── Status ──────────────────────────────────────────────────────────────────

export interface StatusResponse {
  demo_mode: boolean;
  version: string;
}

// ── Chat ────────────────────────────────────────────────────────────────────

export interface ChatResponse {
  reply: string;
  backend: string;
  model: string;
}

// ── Config (Admin) ──────────────────────────────────────────────────────────

export interface ConfigResponse {
  database_url: string;
  llm_backend: string;
  ollama_base_url: string;
  ollama_model: string;
  guard_required: boolean;
  guard_llm_backend: string | null;
  guard_llm_model: string | null;
  max_steps: number;
  agent_allowed_domains: string[];
  sandbox_mode: string;
  evm_enabled: boolean;
  demo_mode: boolean;
}

export interface ConfigUpdate {
  database_url?: string;
  llm_backend?: string;
  ollama_base_url?: string;
  ollama_model?: string;
  guard_required?: boolean;
  guard_llm_backend?: string;
  guard_llm_model?: string;
  max_steps?: number;
  agent_allowed_domains?: string[];
}

// ── Tripwire ────────────────────────────────────────────────────────────────

export interface TripwireConfig {
  allowed_paths: string[];
  allowed_domains: string[];
  banned_command_patterns: string[];
  min_justification_length: number;
  require_https: boolean;
}

export interface TripwireConfigUpdate {
  allowed_paths: string[];
  allowed_domains: string[];
  banned_command_patterns: string[];
  min_justification_length?: number;
  require_https?: boolean;
}

// ── RBAC Tokens (Admin) ─────────────────────────────────────────────────────

export interface TokenListRow {
  token_hash: string;
  role: string;
  label?: string;
  created_at: string;
  expires_at?: string;
}

export interface CreateTokenRequest {
  label?: string;
  role: string;
  expires_in_days?: number;
}

export interface CreateTokenResponse {
  token: string;
  token_hash: string;
  role: string;
  label?: string;
}

// ── Webhooks (Admin) ────────────────────────────────────────────────────────

export interface WebhookListRow {
  id: string;
  label: string;
  url: string;
  siem_format: string;
  filter_kinds: string[];
  enabled: boolean;
  created_at: string;
}

export interface UpsertWebhookRequest {
  label: string;
  url: string;
  bearer_token?: string;
  siem_format?: string;
  filter_kinds?: string[];
  enabled?: boolean;
}

export interface ToggleWebhookBody {
  enabled: boolean;
}

// ── SSE Stream ──────────────────────────────────────────────────────────────

export interface StreamEvent {
  id: number;
  sequence: number;
  previous_hash: string;
  content_hash: string;
  payload: unknown | null;
  created_at: string;
}

export interface StreamOptions {
  after?: number;
  since?: number;
  session_id?: string;
  signal?: AbortSignal;
}
