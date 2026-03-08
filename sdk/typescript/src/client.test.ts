/**
 * EctoLedgerClient — Vitest test suite.
 *
 * All HTTP calls are intercepted by spying on `globalThis.fetch` so no live
 * server is required.  Each test asserts both the correct request URL / method
 * and the correct parsing / propagation of the mock response.
 */

import { beforeEach, describe, expect, it, vi } from "vitest";
import type { MockInstance } from "vitest";
import { EctoLedgerApiError, EctoLedgerClient } from "./client.js";
import type { PendingApproval, SecurityMetrics } from "./models.js";

// ── Helpers ─────────────────────────────────────────────────────────────────

const BASE_URL = "http://localhost:3000";
const SESSION_ID = "550e8400-e29b-41d4-a716-446655440000";

/** Build a minimal fetch Response mock that returns JSON. */
function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** Build a fetch Response mock that returns plain text. */
function textResponse(body: string, status = 200): Response {
  return new Response(body, {
    status,
    headers: { "Content-Type": "text/plain" },
  });
}

/** Build a fetch Response mock that returns binary bytes (for Blob tests). */
function blobResponse(content: string, status = 200): Response {
  return new Response(new TextEncoder().encode(content), {
    status,
    headers: { "Content-Type": "application/octet-stream" },
  });
}

const SAMPLE_SESSION = {
  id: SESSION_ID,
  goal: "Summarize quarterly report",
  goal_hash: "aabbccdd",
  status: "running",
  llm_backend: "mock",
  llm_model: "mock-v1",
  created_at: "2026-02-24T00:00:00Z",
  finished_at: null,
  policy_hash: null,
  session_public_key: null,
  session_did: null,
  enclave_attestation_json: null,
};

const SAMPLE_EVENT = {
  id: 1,
  session_id: SESSION_ID,
  payload: { step: "read" },
  payload_hash: "deadbeef",
  prev_hash: null,
  sequence: 1,
  created_at: "2026-02-24T00:00:01Z",
  public_key: null,
  signature: null,
};

const SAMPLE_APPEND = { id: 2, payload_hash: "cafebabe", sequence: 2 };

const SAMPLE_METRICS = {
  total_sessions: 5,
  total_events: 100,
};

const SAMPLE_SECURITY_METRICS: SecurityMetrics = {
  injection_attempts_detected_7d: 3,
  injection_attempts_by_layer: { regex: 2, schema: 1 },
  sessions_aborted_circuit_breaker: 0,
  chain_verification_failures: 0,
};

let client: EctoLedgerClient;
let fetchSpy: MockInstance<[input: RequestInfo | URL, init?: RequestInit], Promise<Response>>;

beforeEach(() => {
  client = new EctoLedgerClient({ baseUrl: BASE_URL });
  fetchSpy = vi.spyOn(globalThis, "fetch");
});

// ── Constructor ──────────────────────────────────────────────────────────────

describe("constructor", () => {
  it("strips trailing slash from baseUrl", async () => {
    const c = new EctoLedgerClient({ baseUrl: "http://localhost:3000/" });
    fetchSpy.mockResolvedValueOnce(jsonResponse([]));
    await c.listSessions();
    expect(fetchSpy.mock.calls[0][0]).toBe("http://localhost:3000/api/sessions?limit=50");
  });

  it("sets Authorization header when bearerToken is provided", async () => {
    const c = new EctoLedgerClient({ baseUrl: BASE_URL, bearerToken: "tok-abc" });
    fetchSpy.mockResolvedValueOnce(jsonResponse([]));
    await c.listSessions();
    const init = fetchSpy.mock.calls[0][1] as RequestInit;
    expect((init.headers as Record<string, string>)["Authorization"]).toBe("Bearer tok-abc");
  });

  it("does not set Authorization header when bearerToken is omitted", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse([]));
    await client.listSessions();
    const init = fetchSpy.mock.calls[0][1] as RequestInit;
    expect((init.headers as Record<string, string>)["Authorization"]).toBeUndefined();
  });
});

// ── Sessions ─────────────────────────────────────────────────────────────────

describe("listSessions", () => {
  it("GET /api/sessions?limit=50 (default)", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse([SAMPLE_SESSION]));
    const sessions = await client.listSessions();
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/api/sessions?limit=50`);
    expect(sessions).toHaveLength(1);
    expect(sessions[0].id).toBe(SESSION_ID);
  });

  it("accepts custom limit", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse([]));
    await client.listSessions(10);
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/api/sessions?limit=10`);
  });

  it("accepts ListSessionsOptions with status and offset", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse([]));
    await client.listSessions({ limit: 20, offset: 5, status: "completed" });
    const url = fetchSpy.mock.calls[0][0] as string;
    expect(url).toContain("limit=20");
    expect(url).toContain("offset=5");
    expect(url).toContain("status=completed");
  });

  it("throws EctoLedgerApiError on 500", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ detail: "server error" }, 500));
    await expect(client.listSessions()).rejects.toBeInstanceOf(EctoLedgerApiError);
  });
});

describe("createSession", () => {
  it("POST /api/sessions with goal in body", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse(SAMPLE_SESSION, 201));
    const session = await client.createSession({ goal: "Test audit" });
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/api/sessions`);
    const init = fetchSpy.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toMatchObject({ goal: "Test audit" });
    expect(session.id).toBe(SESSION_ID);
  });

  it("throws EctoLedgerApiError on 422", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ detail: "invalid" }, 422));
    await expect(client.createSession({ goal: "" })).rejects.toBeInstanceOf(EctoLedgerApiError);
  });
});

describe("getSessionById", () => {
  it("GET /api/sessions/:id", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse(SAMPLE_SESSION));
    const session = await client.getSessionById(SESSION_ID);
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/api/sessions/${SESSION_ID}`);
    expect(session.id).toBe(SESSION_ID);
    expect(session.goal).toBe("Summarize quarterly report");
  });

  it("throws EctoLedgerApiError on 404", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ detail: "not found" }, 404));
    await expect(client.getSessionById("nonexistent")).rejects.toBeInstanceOf(EctoLedgerApiError);
  });
});

describe("sealSession", () => {
  it("POST /api/sessions/:id/seal", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({}));
    await client.sealSession(SESSION_ID);
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/api/sessions/${SESSION_ID}/seal`);
    const init = fetchSpy.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("POST");
  });
});

// ── Events ───────────────────────────────────────────────────────────────────

describe("getEvents", () => {
  it("GET /api/events?session_id=:id", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse([SAMPLE_EVENT]));
    const events = await client.getEvents(SESSION_ID);
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/api/events?session_id=${SESSION_ID}`);
    expect(events[0].sequence).toBe(1);
  });
});

describe("appendEvent", () => {
  it("POST /api/sessions/:id/events", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse(SAMPLE_APPEND, 201));
    const result = await client.appendEvent(SESSION_ID, { step: "read" });
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/api/sessions/${SESSION_ID}/events`);
    const init = fetchSpy.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("POST");
    expect(result.sequence).toBe(2);
  });

  it("throws EctoLedgerApiError on 400", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ detail: "bad payload" }, 400));
    await expect(client.appendEvent(SESSION_ID, {})).rejects.toBeInstanceOf(EctoLedgerApiError);
  });
});

// ── Chain verification & compliance ──────────────────────────────────────────

describe("verifyChain", () => {
  it("GET /api/sessions/:id/verify and returns boolean", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ ok: true }));
    const ok = await client.verifyChain(SESSION_ID);
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/api/sessions/${SESSION_ID}/verify`);
    expect(ok).toBe(true);
  });

  it("returns false when server says not ok", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ ok: false }));
    expect(await client.verifyChain(SESSION_ID)).toBe(false);
  });
});

describe("proveCompliance", () => {
  it("GET /api/sessions/:id/compliance", async () => {
    const bundle = {
      session_id: SESSION_ID,
      events: [{ sequence: 1, payload_hash: "aa" }],
      policy_hash: null,
      generated_at: "2026-02-24T00:00:00Z",
    };
    fetchSpy.mockResolvedValueOnce(jsonResponse(bundle));
    const result = await client.proveCompliance(SESSION_ID);
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/api/sessions/${SESSION_ID}/compliance`);
    expect(result.session_id).toBe(SESSION_ID);
  });
});

describe("exportCertificate", () => {
  it("GET /api/certificates/:id and returns Blob", async () => {
    fetchSpy.mockResolvedValueOnce(blobResponse("CERT_BYTES"));
    const blob = await client.exportCertificate(SESSION_ID);
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/api/certificates/${SESSION_ID}`);
    expect(blob).toBeInstanceOf(Blob);
  });

  it("throws EctoLedgerApiError on non-2xx", async () => {
    fetchSpy.mockResolvedValueOnce(textResponse("not found", 404));
    await expect(client.exportCertificate(SESSION_ID)).rejects.toBeInstanceOf(EctoLedgerApiError);
  });
});

// ── Reports & VCs ────────────────────────────────────────────────────────────

describe("getReport", () => {
  it("GET /api/reports/:id", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ session_id: SESSION_ID, findings: [] }));
    const report = await client.getReport(SESSION_ID);
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/api/reports/${SESSION_ID}`);
    expect(report["session_id"]).toBe(SESSION_ID);
  });
});

describe("getSessionVc", () => {
  it("GET /api/sessions/:id/vc", async () => {
    const vc = { vc_jwt: "eyJ...", vc_payload: { iss: "did:key:z..." } };
    fetchSpy.mockResolvedValueOnce(jsonResponse(vc));
    const result = await client.getSessionVc(SESSION_ID);
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/api/sessions/${SESSION_ID}/vc`);
    expect(result["vc_jwt"]).toBe("eyJ...");
  });
});

describe("verifySessionVc", () => {
  it("GET /api/sessions/:id/vc/verify and returns validity info", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ valid: true, vc_payload: {} }));
    const result = await client.verifySessionVc(SESSION_ID);
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/api/sessions/${SESSION_ID}/vc/verify`);
    expect(result["valid"]).toBe(true);
  });
});

// ── Metrics ──────────────────────────────────────────────────────────────────

describe("getMetrics", () => {
  it("GET /api/metrics", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse(SAMPLE_METRICS));
    const m = await client.getMetrics();
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/api/metrics`);
    expect(m.total_sessions).toBe(5);
  });
});

describe("getSecurityMetrics", () => {
  it("GET /api/metrics/security and returns SecurityMetrics shape", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse(SAMPLE_SECURITY_METRICS));
    const m = await client.getSecurityMetrics();
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/api/metrics/security`);
    expect(m.injection_attempts_detected_7d).toBe(3);
    expect(m.injection_attempts_by_layer).toEqual({ regex: 2, schema: 1 });
  });
});

describe("getPrometheusMetrics", () => {
  it("GET /metrics (not /api/metrics) and returns raw text", async () => {
    const promText = "# HELP ectoledger_sessions\nectoledger_sessions 5\n";
    fetchSpy.mockResolvedValueOnce(textResponse(promText));
    const raw = await client.getPrometheusMetrics();
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/metrics`);
    expect(raw).toContain("ectoledger_sessions 5");
  });

  it("throws EctoLedgerApiError on non-2xx", async () => {
    fetchSpy.mockResolvedValueOnce(textResponse("forbidden", 403));
    await expect(client.getPrometheusMetrics()).rejects.toBeInstanceOf(EctoLedgerApiError);
  });
});

// ── Policies ────────────────────────────────────────────────────────────────

describe("listPolicies", () => {
  it("GET /api/policies", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse(["soc2-audit", "owasp-top10"]));
    const list = await client.listPolicies();
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/api/policies`);
    expect(list).toContain("soc2-audit");
  });
});

describe("getPolicy", () => {
  it("GET /api/policies/:name and returns TOML text", async () => {
    const toml = 'name = "soc2-audit"\nmax_steps = 30\n';
    fetchSpy.mockResolvedValueOnce(textResponse(toml));
    const content = await client.getPolicy("soc2-audit");
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/api/policies/soc2-audit`);
    expect(content).toContain("soc2-audit");
  });

  it("throws EctoLedgerApiError when policy does not exist", async () => {
    fetchSpy.mockResolvedValueOnce(textResponse("not found", 404));
    await expect(client.getPolicy("nonexistent")).rejects.toBeInstanceOf(EctoLedgerApiError);
  });
});

describe("savePolicy", () => {
  it("PUT /api/policies/:name with text/plain body", async () => {
    fetchSpy.mockResolvedValueOnce(new Response(null, { status: 204 }));
    await client.savePolicy("my-policy", "name = \"my-policy\"");
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE_URL}/api/policies/my-policy`);
    expect(init.method).toBe("PUT");
    expect((init.headers as Record<string, string>)["Content-Type"]).toBe("text/plain");
    expect(init.body).toBe("name = \"my-policy\"");
  });

  it("throws EctoLedgerApiError on failure", async () => {
    fetchSpy.mockResolvedValueOnce(textResponse("forbidden", 403));
    await expect(client.savePolicy("x", "content")).rejects.toBeInstanceOf(EctoLedgerApiError);
  });
});

describe("deletePolicy", () => {
  it("DELETE /api/policies/:name", async () => {
    fetchSpy.mockResolvedValueOnce(new Response(null, { status: 204 }));
    await client.deletePolicy("old-policy");
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE_URL}/api/policies/old-policy`);
    expect(init.method).toBe("DELETE");
  });

  it("throws EctoLedgerApiError on 404", async () => {
    fetchSpy.mockResolvedValueOnce(textResponse("not found", 404));
    await expect(client.deletePolicy("ghost")).rejects.toBeInstanceOf(EctoLedgerApiError);
  });
});

// ── Approval gates ───────────────────────────────────────────────────────────

const SAMPLE_APPROVAL: PendingApproval = {
  gate_id: "gate-001",
  action_name: "run_command",
  action_params_summary: "nmap -sV target",
  created_at: "2026-02-24T10:00:00Z",
};

describe("getPendingApproval", () => {
  it("GET /api/approvals/:id/pending and unwraps .pending", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ pending: SAMPLE_APPROVAL }));
    const result = await client.getPendingApproval(SESSION_ID);
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/api/approvals/${SESSION_ID}/pending`);
    expect(result).not.toBeNull();
    expect(result!.gate_id).toBe("gate-001");
  });

  it("returns null when no gate is pending", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ pending: null }));
    const result = await client.getPendingApproval(SESSION_ID);
    expect(result).toBeNull();
  });

  it("throws EctoLedgerApiError on 404", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ detail: "not found" }, 404));
    await expect(client.getPendingApproval(SESSION_ID)).rejects.toBeInstanceOf(EctoLedgerApiError);
  });
});

describe("postApprovalDecision", () => {
  it("POST /api/approvals/:id with approve decision", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ ok: true }));
    const res = await client.postApprovalDecision(SESSION_ID, {
      gate_id: "gate-001",
      approved: true,
    });
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE_URL}/api/approvals/${SESSION_ID}`);
    expect(init.method).toBe("POST");
    const body = JSON.parse(init.body as string);
    expect(body.approved).toBe(true);
    expect(body.gate_id).toBe("gate-001");
    expect(res["ok"]).toBe(true);
  });

  it("POST /api/approvals/:id with deny decision and reason", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ ok: true }));
    await client.postApprovalDecision(SESSION_ID, {
      gate_id: "gate-001",
      approved: false,
      reason: "Scope too broad",
    });
    const init = fetchSpy.mock.calls[0][1] as RequestInit;
    const body = JSON.parse(init.body as string);
    expect(body.approved).toBe(false);
    expect(body.reason).toBe("Scope too broad");
  });

  it("throws EctoLedgerApiError on non-2xx", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ detail: "gate expired" }, 409));
    await expect(
      client.postApprovalDecision(SESSION_ID, { gate_id: "g", approved: true }),
    ).rejects.toBeInstanceOf(EctoLedgerApiError);
  });
});

// ── Status ────────────────────────────────────────────────────────────────────

describe("getStatus", () => {
  it("GET /api/status", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ demo_mode: false, version: "0.6.2" }));
    const status = await client.getStatus();
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/api/status`);
    expect(status.version).toBe("0.6.2");
    expect(status.demo_mode).toBe(false);
  });
});

// ── Chat ──────────────────────────────────────────────────────────────────────

describe("chat", () => {
  it("POST /api/sessions/:id/chat with message", async () => {
    fetchSpy.mockResolvedValueOnce(
      jsonResponse({ reply: "Hello!", backend: "mock", model: "mock-v1" }),
    );
    const res = await client.chat(SESSION_ID, "Hi there");
    expect(fetchSpy.mock.calls[0][0]).toBe(
      `${BASE_URL}/api/sessions/${encodeURIComponent(SESSION_ID)}/chat`,
    );
    const init = fetchSpy.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("POST");
    expect(JSON.parse(init.body as string)).toMatchObject({ message: "Hi there" });
    expect(res.reply).toBe("Hello!");
    expect(res.backend).toBe("mock");
  });

  it("throws EctoLedgerApiError on 503", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ detail: "LLM not ready" }, 503));
    await expect(client.chat(SESSION_ID, "test")).rejects.toBeInstanceOf(EctoLedgerApiError);
  });
});

// ── Config ────────────────────────────────────────────────────────────────────

describe("getConfig", () => {
  it("GET /api/config", async () => {
    const configData = {
      database_url: "postgres://***@localhost/ectoledger",
      llm_backend: "ollama",
      ollama_base_url: "http://localhost:11434",
      ollama_model: "llama3",
      guard_required: true,
      guard_llm_backend: null,
      guard_llm_model: null,
      max_steps: 30,
      agent_allowed_domains: ["example.com"],
      sandbox_mode: "none",
      evm_enabled: false,
      demo_mode: false,
    };
    fetchSpy.mockResolvedValueOnce(jsonResponse(configData));
    const config = await client.getConfig();
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/api/config`);
    expect(config.llm_backend).toBe("ollama");
    expect(config.max_steps).toBe(30);
  });

  it("throws EctoLedgerApiError on 403", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ detail: "forbidden" }, 403));
    await expect(client.getConfig()).rejects.toBeInstanceOf(EctoLedgerApiError);
  });
});

describe("updateConfig", () => {
  it("PUT /api/config with partial update", async () => {
    const updated = {
      database_url: "postgres://localhost/ectoledger",
      llm_backend: "openai",
      ollama_base_url: "http://localhost:11434",
      ollama_model: "llama3",
      guard_required: true,
      guard_llm_backend: null,
      guard_llm_model: null,
      max_steps: 50,
      agent_allowed_domains: [],
      sandbox_mode: "none",
      evm_enabled: false,
      demo_mode: false,
    };
    fetchSpy.mockResolvedValueOnce(jsonResponse(updated));
    const res = await client.updateConfig({ max_steps: 50, llm_backend: "openai" });
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE_URL}/api/config`);
    expect(init.method).toBe("PUT");
    expect(res.max_steps).toBe(50);
  });
});

// ── Admin: Reset Demo ─────────────────────────────────────────────────────────

describe("resetDemo", () => {
  it("POST /api/admin/reset-demo", async () => {
    fetchSpy.mockResolvedValueOnce(
      jsonResponse({ ok: true, message: "Demo database reset successfully" }),
    );
    const res = await client.resetDemo();
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/api/admin/reset-demo`);
    const init = fetchSpy.mock.calls[0][1] as RequestInit;
    expect(init.method).toBe("POST");
    expect(res["ok"]).toBe(true);
  });

  it("throws EctoLedgerApiError on 403 when not in demo mode", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ detail: "forbidden" }, 403));
    await expect(client.resetDemo()).rejects.toBeInstanceOf(EctoLedgerApiError);
  });
});

// ── Tripwire ──────────────────────────────────────────────────────────────────

const SAMPLE_TRIPWIRE = {
  allowed_paths: ["/tmp", "/var/log"],
  allowed_domains: ["example.com"],
  banned_command_patterns: ["rm -rf"],
  min_justification_length: 5,
  require_https: true,
};

describe("getTripwireConfig", () => {
  it("GET /api/tripwire", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse(SAMPLE_TRIPWIRE));
    const tw = await client.getTripwireConfig();
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/api/tripwire`);
    expect(tw.require_https).toBe(true);
    expect(tw.allowed_paths).toContain("/tmp");
  });
});

describe("updateTripwireConfig", () => {
  it("PUT /api/tripwire", async () => {
    const updated = { ...SAMPLE_TRIPWIRE, require_https: false };
    fetchSpy.mockResolvedValueOnce(jsonResponse(updated));
    const res = await client.updateTripwireConfig({
      allowed_paths: ["/tmp"],
      allowed_domains: ["example.com"],
      banned_command_patterns: [],
      require_https: false,
    });
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE_URL}/api/tripwire`);
    expect(init.method).toBe("PUT");
    expect(res.require_https).toBe(false);
  });
});

// ── RBAC Tokens ───────────────────────────────────────────────────────────────

const SAMPLE_TOKEN_ROW = {
  token_hash: "abc123def456",
  role: "agent",
  label: "CI token",
  created_at: "2026-02-24T00:00:00Z",
};

describe("listTokens", () => {
  it("GET /api/tokens", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse([SAMPLE_TOKEN_ROW]));
    const tokens = await client.listTokens();
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/api/tokens`);
    expect(tokens).toHaveLength(1);
    expect(tokens[0].role).toBe("agent");
  });

  it("throws EctoLedgerApiError on 403 for non-admin", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ detail: "forbidden" }, 403));
    await expect(client.listTokens()).rejects.toBeInstanceOf(EctoLedgerApiError);
  });
});

describe("createToken", () => {
  it("POST /api/tokens", async () => {
    const created = {
      token: "raw-secret-token",
      token_hash: "abc123",
      role: "auditor",
      label: "Audit bot",
    };
    fetchSpy.mockResolvedValueOnce(jsonResponse(created));
    const res = await client.createToken({ role: "auditor", label: "Audit bot" });
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE_URL}/api/tokens`);
    expect(init.method).toBe("POST");
    expect(res.token).toBe("raw-secret-token");
    expect(res.role).toBe("auditor");
  });
});

describe("deleteToken", () => {
  it("DELETE /api/tokens/:hash returns void (204)", async () => {
    fetchSpy.mockResolvedValueOnce(new Response(null, { status: 204 }));
    await client.deleteToken("abc123def456");
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE_URL}/api/tokens/abc123def456`);
    expect(init.method).toBe("DELETE");
  });

  it("throws EctoLedgerApiError on 403", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ detail: "forbidden" }, 403));
    await expect(client.deleteToken("abc")).rejects.toBeInstanceOf(EctoLedgerApiError);
  });
});

// ── Webhooks ──────────────────────────────────────────────────────────────────

const SAMPLE_WEBHOOK = {
  id: "wh-001",
  label: "SIEM sink",
  url: "https://siem.example.com/webhook",
  siem_format: "json",
  filter_kinds: ["observation", "guard_denial"],
  enabled: true,
  created_at: "2026-02-24T00:00:00Z",
};

describe("listWebhooks", () => {
  it("GET /api/webhooks", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse([SAMPLE_WEBHOOK]));
    const hooks = await client.listWebhooks();
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/api/webhooks`);
    expect(hooks).toHaveLength(1);
    expect(hooks[0].siem_format).toBe("json");
  });
});

describe("createWebhook", () => {
  it("POST /api/webhooks", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse(SAMPLE_WEBHOOK, 201));
    const res = await client.createWebhook({
      label: "SIEM sink",
      url: "https://siem.example.com/webhook",
      siem_format: "json",
      filter_kinds: ["observation"],
    });
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE_URL}/api/webhooks`);
    expect(init.method).toBe("POST");
    expect(res.label).toBe("SIEM sink");
  });

  it("throws EctoLedgerApiError on 400 for invalid URL", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ detail: "invalid url" }, 400));
    await expect(
      client.createWebhook({ label: "x", url: "not-a-url" }),
    ).rejects.toBeInstanceOf(EctoLedgerApiError);
  });
});

describe("deleteWebhook", () => {
  it("DELETE /api/webhooks/:id returns void (204)", async () => {
    fetchSpy.mockResolvedValueOnce(new Response(null, { status: 204 }));
    await client.deleteWebhook("wh-001");
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE_URL}/api/webhooks/wh-001`);
    expect(init.method).toBe("DELETE");
  });
});

describe("toggleWebhook", () => {
  it("PUT /api/webhooks/:id with enabled=false", async () => {
    fetchSpy.mockResolvedValueOnce(new Response(null, { status: 200 }));
    await client.toggleWebhook("wh-001", false);
    const [url, init] = fetchSpy.mock.calls[0] as [string, RequestInit];
    expect(url).toBe(`${BASE_URL}/api/webhooks/wh-001`);
    expect(init.method).toBe("PUT");
    expect(JSON.parse(init.body as string)).toMatchObject({ enabled: false });
  });

  it("PUT /api/webhooks/:id with enabled=true", async () => {
    fetchSpy.mockResolvedValueOnce(new Response(null, { status: 200 }));
    await client.toggleWebhook("wh-001", true);
    const init = fetchSpy.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(init.body as string)).toMatchObject({ enabled: true });
  });
});

// ── SSE Stream ────────────────────────────────────────────────────────────────

describe("streamEvents", () => {
  it("GET /api/stream and yields parsed events", async () => {
    const ssePayload =
      'data: {"id":1,"sequence":1,"previous_hash":"000","content_hash":"aaa","payload":null,"created_at":"2026-02-24T00:00:00Z"}\n\n' +
      'data: {"id":2,"sequence":2,"previous_hash":"aaa","content_hash":"bbb","payload":null,"created_at":"2026-02-24T00:00:01Z"}\n\n';
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(ssePayload));
        controller.close();
      },
    });
    fetchSpy.mockResolvedValueOnce(new Response(stream, {
      status: 200,
      headers: { "Content-Type": "text/event-stream" },
    }));
    const events = [];
    for await (const ev of client.streamEvents()) {
      events.push(ev);
    }
    expect(events).toHaveLength(2);
    expect(events[0].sequence).toBe(1);
    expect(events[1].content_hash).toBe("bbb");
    expect(fetchSpy.mock.calls[0][0]).toBe(`${BASE_URL}/api/stream`);
  });

  it("passes query params for after, since, session_id", async () => {
    const stream = new ReadableStream({ start(c) { c.close(); } });
    fetchSpy.mockResolvedValueOnce(new Response(stream, { status: 200 }));
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    for await (const _ of client.streamEvents({ after: 5, session_id: SESSION_ID })) {
      // no events
    }
    const url = fetchSpy.mock.calls[0][0] as string;
    expect(url).toContain("after=5");
    expect(url).toContain(`session_id=${SESSION_ID}`);
  });

  it("skips keep-alive messages", async () => {
    const ssePayload =
      'keep-alive\n\n' +
      'data: {"id":1,"sequence":1,"previous_hash":"000","content_hash":"aaa","payload":null,"created_at":"2026-02-24T00:00:00Z"}\n\n' +
      'keep-alive\n\n';
    const stream = new ReadableStream({
      start(controller) {
        controller.enqueue(new TextEncoder().encode(ssePayload));
        controller.close();
      },
    });
    fetchSpy.mockResolvedValueOnce(new Response(stream, { status: 200 }));
    const events = [];
    for await (const ev of client.streamEvents()) {
      events.push(ev);
    }
    expect(events).toHaveLength(1);
  });

  it("throws EctoLedgerApiError on non-2xx", async () => {
    fetchSpy.mockResolvedValueOnce(textResponse("unauthorized", 401));
    const gen = client.streamEvents();
    await expect(gen.next()).rejects.toBeInstanceOf(EctoLedgerApiError);
  });
});

// ── EctoLedgerApiError ─────────────────────────────────────────────────────────

describe("EctoLedgerApiError", () => {
  it("exposes .status and .body", async () => {
    fetchSpy.mockResolvedValueOnce(jsonResponse({ detail: "internal error" }, 500));
    const err = await client.listSessions().catch((e) => e);
    expect(err).toBeInstanceOf(EctoLedgerApiError);
    expect((err as EctoLedgerApiError).status).toBe(500);
    expect((err as EctoLedgerApiError).body).toContain("internal error");
  });

  it("message includes method, url, and status", async () => {
    fetchSpy.mockResolvedValueOnce(textResponse("bad", 400));
    const err = await client.appendEvent(SESSION_ID, {}).catch((e) => e);
    expect(err.message).toContain("POST");
    expect(err.message).toContain("400");
  });
});
