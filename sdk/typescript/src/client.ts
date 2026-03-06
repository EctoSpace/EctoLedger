import type {
  AppendResult,
  ApprovalDecision,
  ChatResponse,
  ComplianceBundle,
  ConfigResponse,
  ConfigUpdate,
  CreateSessionOptions,
  CreateTokenRequest,
  CreateTokenResponse,
  EctoLedgerClientOptions,
  LedgerEvent,
  ListSessionsOptions,
  MetricsSummary,
  PendingApproval,
  SecurityMetrics,
  Session,
  StatusResponse,
  StreamEvent,
  StreamOptions,
  TokenListRow,
  TripwireConfig,
  TripwireConfigUpdate,
  ToggleWebhookBody,
  UpsertWebhookRequest,
  WebhookListRow,
} from "./models.js";

/** Typed error thrown when the server returns a non-2xx status. */
export class EctoLedgerApiError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: string,
    method: string,
    url: string,
  ) {
    super(`Ecto Ledger API ${method} ${url} → ${status}: ${body}`);
    this.name = "EctoLedgerApiError";
  }
}

/**
 * REST client for Ecto Ledger.
 *
 * @example
 * ```ts
 * const client = new EctoLedgerClient({ baseUrl: "http://localhost:3000" });
 * const sessions = await client.listSessions();
 * ```
 *
 * @remarks
 * The `baseUrl` option defaults to `http://localhost:3000`, which is suitable
 * for local development only.  In containerised or remote environments you
 * **must** supply the correct service URL:
 * ```ts
 * const client = new EctoLedgerClient({
 *   baseUrl: "http://ectoledger-host:3000",
 *   bearerToken: process.env.OBSERVER_TOKEN,
 * });
 * ```
 * Omitting `baseUrl` in Docker Compose / Kubernetes will cause every request
 * to fail with a connection-refused error against the loopback address inside
 * the calling container.
 */
export class EctoLedgerClient {
  private readonly baseUrl: string;
  private readonly headers: Record<string, string>;

  constructor({ baseUrl = "http://localhost:3000", bearerToken }: EctoLedgerClientOptions = {}) {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.headers = { "Content-Type": "application/json" };
    if (bearerToken) {
      this.headers["Authorization"] = `Bearer ${bearerToken}`;
    }
  }

  // ------------------------------------------------------------------ //
  // Sessions
  // ------------------------------------------------------------------ //

  async listSessions(opts?: number | ListSessionsOptions): Promise<Session[]> {
    const params = new URLSearchParams();
    if (typeof opts === "number") {
      params.set("limit", String(opts));
    } else if (opts) {
      if (opts.limit !== undefined) params.set("limit", String(opts.limit));
      if (opts.offset !== undefined) params.set("offset", String(opts.offset));
      if (opts.status !== undefined) params.set("status", opts.status);
    } else {
      params.set("limit", "50");
    }
    return this.get<Session[]>(`/api/sessions?${params.toString()}`);
  }

  async createSession(opts: CreateSessionOptions): Promise<Session> {
    return this.post<Session>("/api/sessions", opts);
  }

  async getSessionById(sessionId: string): Promise<Session> {
    return this.get<Session>(`/api/sessions/${encodeURIComponent(sessionId)}`);
  }

  async sealSession(sessionId: string): Promise<void> {
    await this.post<unknown>(`/api/sessions/${encodeURIComponent(sessionId)}/seal`, {});
  }

  // ------------------------------------------------------------------ //
  // Events
  // ------------------------------------------------------------------ //

  async getEvents(sessionId: string): Promise<LedgerEvent[]> {
    return this.get<LedgerEvent[]>(`/api/events?session_id=${encodeURIComponent(sessionId)}`);
  }

  async appendEvent(sessionId: string, payload: Record<string, unknown>): Promise<AppendResult> {
    return this.post<AppendResult>(`/api/sessions/${encodeURIComponent(sessionId)}/events`, payload);
  }

  // ------------------------------------------------------------------ //
  // Chain verification & compliance
  // ------------------------------------------------------------------ //

  async verifyChain(sessionId: string): Promise<boolean> {
    const data = await this.get<{ ok: boolean }>(`/api/sessions/${encodeURIComponent(sessionId)}/verify`);
    return data.ok;
  }

  async proveCompliance(sessionId: string): Promise<ComplianceBundle> {
    return this.get<ComplianceBundle>(`/api/sessions/${encodeURIComponent(sessionId)}/compliance`);
  }

  async exportCertificate(sessionId: string): Promise<Blob> {
    const url = `${this.baseUrl}/api/certificates/${encodeURIComponent(sessionId)}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30_000);
    try {
      const res = await fetch(url, { headers: this.headers, signal: controller.signal });
      if (!res.ok) {
        throw new EctoLedgerApiError(res.status, await res.text(), "GET", url);
      }
      return res.blob();
    } finally {
      clearTimeout(timeout);
    }
  }

  // ------------------------------------------------------------------ //
  // Reports & Verifiable Credentials
  // ------------------------------------------------------------------ //

  async getReport(sessionId: string): Promise<Record<string, unknown>> {
    return this.get<Record<string, unknown>>(`/api/reports/${encodeURIComponent(sessionId)}`);
  }

  async getSessionVc(sessionId: string): Promise<Record<string, unknown>> {
    return this.get<Record<string, unknown>>(`/api/sessions/${encodeURIComponent(sessionId)}/vc`);
  }

  async verifySessionVc(sessionId: string): Promise<Record<string, unknown>> {
    return this.get<Record<string, unknown>>(`/api/sessions/${encodeURIComponent(sessionId)}/vc/verify`);
  }

  // ------------------------------------------------------------------ //
  // Metrics
  // ------------------------------------------------------------------ //

  async getMetrics(): Promise<MetricsSummary> {
    return this.get<MetricsSummary>("/api/metrics");
  }

  async getSecurityMetrics(): Promise<SecurityMetrics> {
    return this.get<SecurityMetrics>("/api/metrics/security");
  }

  async getPrometheusMetrics(): Promise<string> {
    const url = `${this.baseUrl}/metrics`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30_000);
    try {
      const res = await fetch(url, { headers: this.headers, signal: controller.signal });
      if (!res.ok) {
        throw new EctoLedgerApiError(res.status, await res.text(), "GET", url);
      }
      return res.text();
    } finally {
      clearTimeout(timeout);
    }
  }

  // ------------------------------------------------------------------ //
  // Policies
  // ------------------------------------------------------------------ //

  async listPolicies(): Promise<string[]> {
    return this.get<string[]>("/api/policies");
  }

  async getPolicy(name: string): Promise<string> {
    const url = `${this.baseUrl}/api/policies/${encodeURIComponent(name)}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30_000);
    try {
      const res = await fetch(url, { headers: this.headers, signal: controller.signal });
      if (!res.ok) {
        throw new EctoLedgerApiError(res.status, await res.text(), "GET", url);
      }
      return res.text();
    } finally {
      clearTimeout(timeout);
    }
  }

  async savePolicy(name: string, content: string): Promise<void> {
    const url = `${this.baseUrl}/api/policies/${encodeURIComponent(name)}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30_000);
    try {
      const res = await fetch(url, {
        method: "PUT",
        headers: { ...this.headers, "Content-Type": "text/plain" },
        body: content,
        signal: controller.signal,
      });
      if (!res.ok) {
        throw new EctoLedgerApiError(res.status, await res.text(), "PUT", url);
      }
    } finally {
      clearTimeout(timeout);
    }
  }

  async deletePolicy(name: string): Promise<void> {
    const url = `${this.baseUrl}/api/policies/${encodeURIComponent(name)}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30_000);
    try {
      const res = await fetch(url, { method: "DELETE", headers: this.headers, signal: controller.signal });
      if (!res.ok) {
        throw new EctoLedgerApiError(res.status, await res.text(), "DELETE", url);
      }
    } finally {
      clearTimeout(timeout);
    }
  }

  // ------------------------------------------------------------------ //
  // Approval Gates
  // ------------------------------------------------------------------ //

  async getPendingApproval(sessionId: string): Promise<PendingApproval | null> {
    const data = await this.get<{ pending: PendingApproval | null }>(
      `/api/approvals/${sessionId}/pending`,
    );
    return data.pending;
  }

  async postApprovalDecision(
    sessionId: string,
    decision: ApprovalDecision,
  ): Promise<Record<string, unknown>> {
    return this.post<Record<string, unknown>>(`/api/approvals/${sessionId}`, decision);
  }

  // ------------------------------------------------------------------ //
  // Status (public — no auth required)
  // ------------------------------------------------------------------ //

  async getStatus(): Promise<StatusResponse> {
    return this.get<StatusResponse>("/api/status");
  }

  // ------------------------------------------------------------------ //
  // Chat
  // ------------------------------------------------------------------ //

  async chat(sessionId: string, message: string): Promise<ChatResponse> {
    return this.post<ChatResponse>(`/api/sessions/${encodeURIComponent(sessionId)}/chat`, { message });
  }

  // ------------------------------------------------------------------ //
  // Config (Admin)
  // ------------------------------------------------------------------ //

  async getConfig(): Promise<ConfigResponse> {
    return this.get<ConfigResponse>("/api/config");
  }

  async updateConfig(updates: ConfigUpdate): Promise<ConfigResponse> {
    return this.put<ConfigResponse>("/api/config", updates);
  }

  // ------------------------------------------------------------------ //
  // Admin
  // ------------------------------------------------------------------ //

  async resetDemo(): Promise<Record<string, unknown>> {
    return this.post<Record<string, unknown>>("/api/admin/reset-demo", {});
  }

  // ------------------------------------------------------------------ //
  // Tripwire
  // ------------------------------------------------------------------ //

  async getTripwireConfig(): Promise<TripwireConfig> {
    return this.get<TripwireConfig>("/api/tripwire");
  }

  async updateTripwireConfig(config: TripwireConfigUpdate): Promise<TripwireConfig> {
    return this.put<TripwireConfig>("/api/tripwire", config);
  }

  // ------------------------------------------------------------------ //
  // RBAC Tokens (Admin)
  // ------------------------------------------------------------------ //

  async listTokens(): Promise<TokenListRow[]> {
    return this.get<TokenListRow[]>("/api/tokens");
  }

  async createToken(request: CreateTokenRequest): Promise<CreateTokenResponse> {
    return this.post<CreateTokenResponse>("/api/tokens", request);
  }

  async deleteToken(tokenHash: string): Promise<void> {
    await this.del(`/api/tokens/${encodeURIComponent(tokenHash)}`);
  }

  // ------------------------------------------------------------------ //
  // Webhooks (Admin)
  // ------------------------------------------------------------------ //

  async listWebhooks(): Promise<WebhookListRow[]> {
    return this.get<WebhookListRow[]>("/api/webhooks");
  }

  async createWebhook(request: UpsertWebhookRequest): Promise<WebhookListRow> {
    return this.post<WebhookListRow>("/api/webhooks", request);
  }

  async deleteWebhook(webhookId: string): Promise<void> {
    await this.del(`/api/webhooks/${encodeURIComponent(webhookId)}`);
  }

  async toggleWebhook(webhookId: string, enabled: boolean): Promise<void> {
    await this.put<unknown>(`/api/webhooks/${encodeURIComponent(webhookId)}`, {
      enabled,
    } satisfies ToggleWebhookBody);
  }

  // ------------------------------------------------------------------ //
  // SSE Stream
  // ------------------------------------------------------------------ //

  async *streamEvents(opts?: StreamOptions): AsyncGenerator<StreamEvent, void, undefined> {
    const params = new URLSearchParams();
    if (opts?.after !== undefined) params.set("after", String(opts.after));
    if (opts?.since !== undefined) params.set("since", String(opts.since));
    if (opts?.session_id) params.set("session_id", opts.session_id);
    const qs = params.toString();
    const url = `${this.baseUrl}/api/stream${qs ? `?${qs}` : ""}`;
    const res = await fetch(url, {
      headers: { ...this.headers, Accept: "text/event-stream" },
      signal: opts?.signal,
    });
    if (!res.ok) {
      throw new EctoLedgerApiError(res.status, await res.text(), "GET", url);
    }
    if (!res.body) return;

    const reader = res.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";

    try {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });

        const parts = buffer.split("\n\n");
        buffer = parts.pop() ?? "";

        for (const part of parts) {
          if (!part.trim() || part.trim() === "keep-alive") continue;
          const dataLine = part
            .split("\n")
            .find((l) => l.startsWith("data:"));
          if (!dataLine) continue;
          const json = dataLine.slice(5).trim();
          if (!json) continue;
          try {
            yield JSON.parse(json) as StreamEvent;
          } catch {
            // skip malformed events
          }
        }
      }
    } finally {
      reader.releaseLock();
    }
  }

  // ------------------------------------------------------------------ //
  // Internals
  // ------------------------------------------------------------------ //

  private async get<T>(path: string): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30_000);
    try {
      const res = await fetch(url, { headers: this.headers, signal: controller.signal });
      if (!res.ok) {
        throw new EctoLedgerApiError(res.status, await res.text(), "GET", url);
      }
      const data = await res.json();
      return data as T;
    } finally {
      clearTimeout(timeout);
    }
  }

  private async post<T>(path: string, body: unknown): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30_000);
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: this.headers,
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      if (!res.ok) {
        throw new EctoLedgerApiError(res.status, await res.text(), "POST", url);
      }
      const data = await res.json();
      return data as T;
    } finally {
      clearTimeout(timeout);
    }
  }

  private async put<T>(path: string, body: unknown): Promise<T> {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30_000);
    try {
      const res = await fetch(url, {
        method: "PUT",
        headers: this.headers,
        body: JSON.stringify(body),
        signal: controller.signal,
      });
      if (!res.ok) {
        throw new EctoLedgerApiError(res.status, await res.text(), "PUT", url);
      }
      // Some PUT endpoints return 200 with no JSON body.
      const text = await res.text();
      if (!text) return undefined as T;
      return JSON.parse(text) as T;
    } finally {
      clearTimeout(timeout);
    }
  }

  private async del(path: string): Promise<void> {
    const url = `${this.baseUrl}${path}`;
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 30_000);
    try {
      const res = await fetch(url, {
        method: "DELETE",
        headers: this.headers,
        signal: controller.signal,
      });
      if (!res.ok) {
        throw new EctoLedgerApiError(res.status, await res.text(), "DELETE", url);
      }
    } finally {
      clearTimeout(timeout);
    }
  }
}
