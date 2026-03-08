# ectoledger-sdk

Lightweight TypeScript / JavaScript client for the [Ecto Ledger](https://github.com/EctoSpace/EctoLedger) AI-governance
ledger.  Zero runtime dependencies — works in Node 18+, Deno, Bun, and modern
browsers that support `fetch`.

## Installation

```bash
npm install ectoledger-sdk
```

## Quick start

```ts
import { EctoLedgerClient } from "ectoledger-sdk";

const client = new EctoLedgerClient({
  baseUrl: "http://localhost:3000",
  bearerToken: "my-api-token",       // optional – sent as Authorization: Bearer …
});

// 1. Create a session
const session = await client.createSession({ goal: "audit-run-42" });

// 2. Append events
await client.appendEvent(session.id, {
  event_type: "model_invocation",
  payload: { model: "gpt-4o", prompt_tokens: 120 },
});

// 3. Seal (finish) the session
await client.sealSession(session.id);

// 4. List all sessions (with optional filters)
const sessions = await client.listSessions({ limit: 10, status: "active" });
```

> **Note on event signing:** events appended through the SDK are *unsigned*
> (external).  Only events created server-side carry an Ed25519 signature.

---

## API reference

### Constructor

```ts
new EctoLedgerClient({ baseUrl: string; bearerToken?: string })
```

| Param         | Description |
|---------------|-------------|
| `baseUrl`     | Root URL of the EctoLedger server (no trailing slash). |
| `bearerToken` | If set, every request includes `Authorization: Bearer <token>`. |

---

### Core

| Method | HTTP | Description |
|--------|------|-------------|
| `createSession(opts?)` | `POST /api/sessions` | Create a new agent session. |
| `listSessions(limitOrOpts?)` | `GET /api/sessions` | List sessions. Accepts a plain number (limit) or `ListSessionsOptions`. |
| `getSessionById(id)` | `GET /api/sessions/:id` | Fetch a single session by ID. |
| `getEvents(sessionId)` | `GET /api/events?session_id=:id` | Retrieve all events for a session. |
| `appendEvent(sessionId, payload)` | `POST /api/sessions/:id/events` | Append an external event. |
| `sealSession(sessionId)` | `POST /api/sessions/:id/seal` | Seal (finish) a session. |

### Integrity & Compliance

| Method | HTTP | Description |
|--------|------|-------------|
| `verifyChain(sessionId)` | `GET /api/sessions/:id/verify` | Verify the hash-chain integrity. Returns `boolean`. |
| `proveCompliance(sessionId)` | `GET /api/sessions/:id/compliance` | Get a compliance proof bundle. |
| `exportCertificate(sessionId)` | `GET /api/certificates/:id` | Download the audit certificate as a `Blob`. |

### Reports & Verifiable Credentials

| Method | HTTP | Description |
|--------|------|-------------|
| `getReport(sessionId)` | `GET /api/reports/:id` | Audit report as JSON. |
| `getSessionVc(sessionId)` | `GET /api/sessions/:id/vc` | W3C Verifiable Credential for a session. |
| `verifySessionVc(sessionId)` | `GET /api/sessions/:id/vc/verify` | Verify VC structural integrity and expiry. |

### Policies

| Method | HTTP | Description |
|--------|------|-------------|
| `listPolicies()` | `GET /api/policies` | List loaded audit policy names. |
| `getPolicy(name)` | `GET /api/policies/:name` | Retrieve a policy's TOML content as text. |
| `savePolicy(name, content)` | `PUT /api/policies/:name` | Create or overwrite a policy. |
| `deletePolicy(name)` | `DELETE /api/policies/:name` | Delete a policy. |

### Approval Gates

| Method | HTTP | Description |
|--------|------|-------------|
| `getPendingApproval(sessionId)` | `GET /api/approvals/:id/pending` | Get the pending approval gate, or `null` if none. |
| `postApprovalDecision(sessionId, decision)` | `POST /api/approvals/:id` | Submit an `approve` or `deny` decision. |

### AI / Chat

| Method | HTTP | Description |
|--------|------|-------------|
| `chat(sessionId, message)` | `POST /api/sessions/:id/chat` | Send a chat message within a session. |

### Admin

| Method | HTTP | Description |
|--------|------|-------------|
| `getStatus()` | `GET /api/status` | Server health / version (no auth required). |
| `getConfig()` | `GET /api/config` | Read current server configuration. |
| `updateConfig(patch)` | `PUT /api/config` | Update server configuration. |
| `resetDemo()` | `POST /api/admin/reset-demo` | Wipe demo data and re-seed. |
| `getTripwireConfig()` | `GET /api/tripwire` | Read tripwire / guardrail settings. |
| `updateTripwireConfig(patch)` | `PUT /api/tripwire` | Update tripwire settings. |
| `listTokens()` | `GET /api/tokens` | List RBAC API tokens. |
| `createToken(req)` | `POST /api/tokens` | Create a new RBAC token. |
| `deleteToken(tokenHash)` | `DELETE /api/tokens/:hash` | Revoke a token by its hash. |
| `listWebhooks()` | `GET /api/webhooks` | List webhook configurations. |
| `createWebhook(req)` | `POST /api/webhooks` | Register a new webhook. |
| `deleteWebhook(id)` | `DELETE /api/webhooks/:id` | Remove a webhook. |
| `toggleWebhook(id, enabled)` | `PUT /api/webhooks/:id` | Enable or disable a webhook. |

### Observability

| Method | HTTP | Description |
|--------|------|-------------|
| `getMetrics()` | `GET /api/metrics` | Metrics summary as JSON. |
| `getSecurityMetrics()` | `GET /api/metrics/security` | Security event counters (injections, denials, aborts). |
| `getPrometheusMetrics()` | `GET /metrics` | Raw Prometheus text (for scraping). |
| `streamEvents(opts?)` | `GET /api/stream` | Server-Sent Events stream (async iterator). |

---

## Error handling

Every non-2xx response throws an `EctoLedgerApiError`, which extends `Error`
and exposes `.status` (number) and `.body` (raw response text):

```ts
import { EctoLedgerClient, EctoLedgerApiError } from "ectoledger-sdk";

try {
  await client.getSessionById("nonexistent-id");
} catch (e) {
  if (e instanceof EctoLedgerApiError) {
    console.error(e.status); // e.g. 404
    console.error(e.body);   // e.g. '{"error":"not found"}'
  }
}
```

Network failures and timeouts (30 s default) propagate as standard
`TypeError` / `AbortError`.

---

## Streaming events

`streamEvents` returns an `AsyncGenerator<StreamEvent>` that yields parsed SSE
objects in real time:

```ts
for await (const evt of client.streamEvents({ session_id: "abc" })) {
  console.log(evt.event_type, evt.payload);
}
```

Pass `session_id` to filter by session, or omit for all events.

---

## Building from source

```bash
npm install
npm run build     # tsc  →  dist/
```

The build produces ESM (`dist/index.js`) and CJS (`dist/index.cjs`) outputs,
plus TypeScript declaration files.

---

## Running tests

```bash
npm test          # vitest run
```

All tests use mocked `fetch` — no running server required.

---

## Licensing & Contact

Licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).

Maintained by [Björn Roman Kohlberger](https://linkedin.com/in/bkohlberger).
