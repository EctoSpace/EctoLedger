# EctoLedger SDK — Python

A typed async REST client for [EctoLedger](https://github.com/EctoSpace/EctoLedger) with built-in LangChain and AutoGen support.

EctoLedger is a tamper-proof audit trail for AI agents. It helps you prove what your AI did, in what order, and whether actions stayed within policy.

This is not a crypto trading product. Here, "ledger" means an auditable evidence log for AI behavior.

This SDK lets you create sessions, append events, and export verifiable `.elc` audit certificates from your Python applications.

## Installation

```bash
# Core client only
pip install ectoledger-sdk

# With LangChain support
pip install 'ectoledger-sdk[langchain]'

# With AutoGen support
pip install 'ectoledger-sdk[autogen]'
```

## Quick start

```python
import asyncio
from ectoledger_sdk import LedgerClient

async def main():
    async with LedgerClient("http://localhost:3000", bearer_token="your_token") as client:
        sessions = await client.list_sessions()
        print(f"Found {len(sessions)} active sessions.")

asyncio.run(main())
```

## Constructor

```python
LedgerClient(
    base_url="http://localhost:3000",  # Server URL (required in production)
    bearer_token=None,                 # Optional RBAC token
    timeout=30.0,                      # HTTP timeout in seconds
)
```

> **Note:** The default `base_url` only works for local development. In Docker Compose or Kubernetes you **must** pass the correct service URL.

## Error handling

All methods raise `LedgerSdkError` on non-2xx responses:

```python
from ectoledger_sdk import LedgerSdkError

try:
    await client.verify_chain(session_id)
except LedgerSdkError as exc:
    print(exc.status_code, exc.body)
```

## LangChain integration

```python
from ectoledger_sdk.langchain import LedgerTool

ledger_tool = LedgerTool(
    session_id="your-session-uuid",
    base_url="http://localhost:3000",
)
# Add ledger_tool to your agent's tool list
```

## AutoGen integration

```python
from ectoledger_sdk.autogen import LedgerHook

hook = LedgerHook(session_id="your-session-uuid")
hook.attach(my_agent)
```

## Testing

```bash
cd sdk/python
pip install ".[dev]"
pytest tests/ -v
```

## Troubleshooting

### Connection errors or timeouts

- Ensure `base_url` points to the running EctoLedger server (`http://localhost:3000` in local default setups).
- In Docker/Kubernetes, use the correct service hostname instead of localhost.
- Check that your network path allows access to `/api/status`.

### Authentication failures (401/403)

- Verify `bearer_token` is valid and has sufficient RBAC scope.
- Confirm token creation/revocation status in the server UI/API.

### Unexpected API errors

- Catch `LedgerSdkError` and inspect `status_code` + `body` for exact server response.
- Check backend mode constraints (some commands/features require PostgreSQL backend).

## API Reference

### Status

| Method | Returns | Description |
|--------|---------|-------------|
| `get_status()` | `StatusResponse` | Server status (demo mode, version) |

### Sessions

| Method | Returns | Description |
|--------|---------|-------------|
| `list_sessions(limit=50, offset=None, status=None)` | `list[Session]` | List recent sessions with optional pagination and status filter |
| `create_session(goal, policy_hash=None, session_did=None)` | `Session` | Open a new audit session |
| `get_session(session_id)` | `Session` | Fetch a single session |
| `seal_session(session_id)` | `None` | Mark session as finished |

### Chat

| Method | Returns | Description |
|--------|---------|-------------|
| `chat(session_id, message)` | `dict` | Send a message within a running session |

### Events

| Method | Returns | Description |
|--------|---------|-------------|
| `get_events(session_id)` | `list[LedgerEvent]` | Fetch all events for a session |
| `append_event(session_id, payload)` | `AppendResult` | Sign and append an event |
| `stream_events(session_id)` | `AsyncIterator[dict]` | SSE live event stream |

### Chain Verification & Compliance

| Method | Returns | Description |
|--------|---------|-------------|
| `verify_chain(session_id)` | `bool` | Verify hash chain integrity |
| `prove_compliance(session_id)` | `ComplianceBundle` | Typed compliance proof bundle |
| `export_certificate(session_id)` | `bytes` | Download `.elc` audit certificate |

### Reports & Verifiable Credentials

| Method | Returns | Description |
|--------|---------|-------------|
| `get_report(session_id)` | `dict` | Audit report as a dictionary |
| `get_session_vc(session_id)` | `dict` | W3C Verifiable Credential (VC-JWT) |
| `verify_session_vc(session_id)` | `dict` | Verify VC structural integrity |

### Metrics

| Method | Returns | Description |
|--------|---------|-------------|
| `get_metrics()` | `MetricsSummary` | System metrics summary |
| `get_security_metrics()` | `SecurityMetrics` | Security event counters |
| `get_prometheus_metrics()` | `str` | Raw Prometheus text output |

### Configuration

| Method | Returns | Description |
|--------|---------|-------------|
| `get_config()` | `ConfigResponse` | Current server configuration |
| `update_config(patch)` | `dict` | Apply partial config update |

### Tripwire Configuration

| Method | Returns | Description |
|--------|---------|-------------|
| `get_tripwire_config()` | `TripwireConfig` | Current tripwire guard config |
| `update_tripwire_config(patch)` | `dict` | Apply partial tripwire update |

### Policies

| Method | Returns | Description |
|--------|---------|-------------|
| `list_policies()` | `list[str]` | List available policy names |
| `get_policy(name)` | `str` | Retrieve policy TOML content |
| `save_policy(name, content)` | `None` | Create or overwrite a policy |
| `delete_policy(name)` | `None` | Remove a policy |

### RBAC Tokens

| Method | Returns | Description |
|--------|---------|-------------|
| `list_tokens()` | `list[TokenListRow]` | List tokens (hashed, not raw) |
| `create_token(role, label=None)` | `CreateTokenResponse` | Create a new API token |
| `delete_token(token_hash)` | `None` | Revoke a token |

### Webhooks

| Method | Returns | Description |
|--------|---------|-------------|
| `list_webhooks()` | `list[WebhookListRow]` | List configured webhooks |
| `create_webhook(label, url, siem_format="json", filter_kinds=None)` | `WebhookListRow` | Register a webhook |
| `delete_webhook(webhook_id)` | `None` | Remove a webhook |
| `toggle_webhook(webhook_id, enabled)` | `dict` | Enable/disable a webhook |

### Approval Gates

| Method | Returns | Description |
|--------|---------|-------------|
| `get_pending_approval(session_id)` | `PendingApproval \| None` | Get pending approval gate |
| `post_approval_decision(session_id, gate_id, approved, reason=None)` | `None` | Submit decision |

### Admin

| Method | Returns | Description |
|--------|---------|-------------|
| `reset_demo()` | `dict` | Reset server to demo defaults |

## Licensing & Contact

Licensed under the [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0).

Maintained by [Björn Roman Kohlberger](https://linkedin.com/in/bkohlberger).
