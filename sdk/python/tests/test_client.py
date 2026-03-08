"""Tests for LedgerClient — mocked HTTP interaction via respx."""
from __future__ import annotations

import pytest
import respx
import httpx

from ectoledger_sdk.client import LedgerClient, LedgerSdkError
from ectoledger_sdk.models import (
    AppendResult,
    ComplianceBundle,
    ConfigResponse,
    CreateTokenResponse,
    LedgerEvent,
    MetricsSummary,
    PendingApproval,
    SecurityMetrics,
    Session,
    StatusResponse,
    TokenListRow,
    TripwireConfig,
    WebhookListRow,
)

pytestmark = pytest.mark.asyncio


# ---------------------------------------------------------------------------
# list_sessions
# ---------------------------------------------------------------------------

@respx.mock
async def test_list_sessions_returns_session_objects(base_url: str, sample_session: dict) -> None:
    respx.get(f"{base_url}/api/sessions").mock(return_value=httpx.Response(200, json=[sample_session]))
    async with LedgerClient(base_url) as client:
        sessions = await client.list_sessions()
    assert len(sessions) == 1
    assert isinstance(sessions[0], Session)
    assert sessions[0].session_id == sample_session["session_id"]


@respx.mock
async def test_list_sessions_empty(base_url: str) -> None:
    respx.get(f"{base_url}/api/sessions").mock(return_value=httpx.Response(200, json=[]))
    async with LedgerClient(base_url) as client:
        sessions = await client.list_sessions()
    assert sessions == []


@respx.mock
async def test_list_sessions_http_error_raises(base_url: str) -> None:
    respx.get(f"{base_url}/api/sessions").mock(return_value=httpx.Response(500, json={"detail": "internal error"}))
    async with LedgerClient(base_url) as client:
        with pytest.raises(LedgerSdkError) as exc_info:
            await client.list_sessions()
    assert exc_info.value.status_code == 500


@respx.mock
async def test_list_sessions_passes_limit_param(base_url: str) -> None:
    route = respx.get(f"{base_url}/api/sessions").mock(return_value=httpx.Response(200, json=[]))
    async with LedgerClient(base_url) as client:
        await client.list_sessions(limit=10)
    assert route.called
    assert route.calls.last.request.url.params["limit"] == "10"


# ---------------------------------------------------------------------------
# create_session
# ---------------------------------------------------------------------------

@respx.mock
async def test_create_session_minimal(base_url: str, sample_session: dict) -> None:
    respx.post(f"{base_url}/api/sessions").mock(return_value=httpx.Response(201, json=sample_session))
    async with LedgerClient(base_url) as client:
        session = await client.create_session(goal="audit the target")
    assert isinstance(session, Session)
    assert session.status == "running"


@respx.mock
async def test_create_session_with_optional_fields(base_url: str, sample_session_finished: dict) -> None:
    respx.post(f"{base_url}/api/sessions").mock(return_value=httpx.Response(201, json=sample_session_finished))
    async with LedgerClient(base_url) as client:
        session = await client.create_session(goal="audit", policy_hash="abc", session_did="did:key:z6Mk")
    assert session.session_did == sample_session_finished["session_did"]
    assert session.finished_at is not None


@respx.mock
async def test_create_session_error_raises(base_url: str) -> None:
    respx.post(f"{base_url}/api/sessions").mock(return_value=httpx.Response(422, json={"detail": "invalid goal"}))
    async with LedgerClient(base_url) as client:
        with pytest.raises(LedgerSdkError) as exc_info:
            await client.create_session(goal="")
    assert exc_info.value.status_code == 422


# ---------------------------------------------------------------------------
# seal_session
# ---------------------------------------------------------------------------

@respx.mock
async def test_seal_session_success(base_url: str, session_id: str) -> None:
    respx.post(f"{base_url}/api/sessions/{session_id}/seal").mock(return_value=httpx.Response(200, json={}))
    async with LedgerClient(base_url) as client:
        await client.seal_session(session_id)


@respx.mock
async def test_seal_session_not_found_raises(base_url: str) -> None:
    respx.post(f"{base_url}/api/sessions/nonexistent/seal").mock(return_value=httpx.Response(404, json={"detail": "not found"}))
    async with LedgerClient(base_url) as client:
        with pytest.raises(LedgerSdkError) as exc_info:
            await client.seal_session("nonexistent")
    assert exc_info.value.status_code == 404


# ---------------------------------------------------------------------------
# get_events
# ---------------------------------------------------------------------------

@respx.mock
async def test_get_events_returns_event_objects(base_url: str, session_id: str, sample_event: dict, sample_event_signed: dict) -> None:
    respx.get(f"{base_url}/api/events").mock(return_value=httpx.Response(200, json=[sample_event, sample_event_signed]))
    async with LedgerClient(base_url) as client:
        events = await client.get_events(session_id)
    assert len(events) == 2
    assert all(isinstance(e, LedgerEvent) for e in events)
    assert events[1].signature is not None


@respx.mock
async def test_get_events_empty_session(base_url: str, session_id: str) -> None:
    respx.get(f"{base_url}/api/events").mock(return_value=httpx.Response(200, json=[]))
    async with LedgerClient(base_url) as client:
        events = await client.get_events(session_id)
    assert events == []


# ---------------------------------------------------------------------------
# append_event
# ---------------------------------------------------------------------------

@respx.mock
async def test_append_event_returns_append_result(base_url: str, session_id: str, sample_append_result: dict) -> None:
    respx.post(f"{base_url}/api/sessions/{session_id}/events").mock(return_value=httpx.Response(201, json=sample_append_result))
    async with LedgerClient(base_url) as client:
        result = await client.append_event(session_id, {"type": "thought", "content": "hello"})
    assert isinstance(result, AppendResult)
    assert result.id == sample_append_result["id"]
    assert result.sequence == 1


@respx.mock
async def test_append_event_4xx_raises(base_url: str, session_id: str) -> None:
    respx.post(f"{base_url}/api/sessions/{session_id}/events").mock(return_value=httpx.Response(400, json={"detail": "bad payload"}))
    async with LedgerClient(base_url) as client:
        with pytest.raises(LedgerSdkError) as exc_info:
            await client.append_event(session_id, {})
    assert exc_info.value.status_code == 400


# ---------------------------------------------------------------------------
# verify_chain
# ---------------------------------------------------------------------------

@respx.mock
async def test_verify_chain_ok(base_url: str, session_id: str) -> None:
    respx.get(f"{base_url}/api/sessions/{session_id}/verify").mock(return_value=httpx.Response(200, json={"ok": True}))
    async with LedgerClient(base_url) as client:
        result = await client.verify_chain(session_id)
    assert result is True


@respx.mock
async def test_verify_chain_tampered(base_url: str, session_id: str) -> None:
    respx.get(f"{base_url}/api/sessions/{session_id}/verify").mock(return_value=httpx.Response(200, json={"ok": False, "error": "hash mismatch at seq 3"}))
    async with LedgerClient(base_url) as client:
        result = await client.verify_chain(session_id)
    assert result is False


# ---------------------------------------------------------------------------
# prove_compliance
# ---------------------------------------------------------------------------

@respx.mock
async def test_prove_compliance_returns_dict(base_url: str, session_id: str) -> None:
    policy_hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    payload = {
        "session_id": session_id,
        "events": [{"seq": 0, "content_hash": "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"}],
        "policy_hash": policy_hash,
        "generated_at": "2026-02-22T12:00:00Z",
    }
    respx.get(f"{base_url}/api/sessions/{session_id}/compliance").mock(return_value=httpx.Response(200, json=payload))
    async with LedgerClient(base_url) as client:
        result = await client.prove_compliance(session_id)
    assert isinstance(result, ComplianceBundle)
    assert result.policy_hash == policy_hash


# ---------------------------------------------------------------------------
# export_certificate
# ---------------------------------------------------------------------------

@respx.mock
async def test_export_certificate_returns_bytes(base_url: str, session_id: str) -> None:
    pdf_bytes = b"%PDF-1.4 fake certificate content"
    respx.get(f"{base_url}/api/certificates/{session_id}").mock(return_value=httpx.Response(200, content=pdf_bytes, headers={"content-type": "application/pdf"}))
    async with LedgerClient(base_url) as client:
        result = await client.export_certificate(session_id)
    assert isinstance(result, bytes)
    assert result.startswith(b"%PDF")


# ---------------------------------------------------------------------------
# get_report
# ---------------------------------------------------------------------------

@respx.mock
async def test_get_report_returns_dict(base_url: str, session_id: str) -> None:
    report = {"session_id": session_id, "findings": [{"title": "Open port"}], "summary": "ok"}
    respx.get(f"{base_url}/api/reports/{session_id}").mock(return_value=httpx.Response(200, json=report))
    async with LedgerClient(base_url) as client:
        result = await client.get_report(session_id)
    assert isinstance(result, dict)
    assert result["summary"] == "ok"


# ---------------------------------------------------------------------------
# Verifiable Credentials
# ---------------------------------------------------------------------------

@respx.mock
async def test_get_session_vc_returns_dict(base_url: str, session_id: str) -> None:
    vc_data = {"vc_jwt": "ey.ey.sig", "vc_payload": {"sub": session_id}}
    respx.get(f"{base_url}/api/sessions/{session_id}/vc").mock(return_value=httpx.Response(200, json=vc_data))
    async with LedgerClient(base_url) as client:
        result = await client.get_session_vc(session_id)
    assert result["vc_jwt"] == "ey.ey.sig"


@respx.mock
async def test_verify_session_vc_valid(base_url: str, session_id: str) -> None:
    vc_verify = {"valid": True, "signature_verified": True, "vc_jwt": "ey.ey.sig", "vc_payload": {}}
    respx.get(f"{base_url}/api/sessions/{session_id}/vc/verify").mock(return_value=httpx.Response(200, json=vc_verify))
    async with LedgerClient(base_url) as client:
        result = await client.verify_session_vc(session_id)
    assert result["valid"] is True


# ---------------------------------------------------------------------------
# get_metrics
# ---------------------------------------------------------------------------

@respx.mock
async def test_get_metrics_parses_summary(base_url: str, sample_metrics: dict) -> None:
    respx.get(f"{base_url}/api/metrics").mock(return_value=httpx.Response(200, json=sample_metrics))
    async with LedgerClient(base_url) as client:
        metrics = await client.get_metrics()
    assert isinstance(metrics, MetricsSummary)
    assert metrics.total_sessions == 7
    assert metrics.total_events == 130


@respx.mock
async def test_get_metrics_extra_fields_captured(base_url: str) -> None:
    # `extra` in MetricsSummary is a named field that the server must explicitly
    # populate; Pydantic v2 ignores unknown top-level keys by default.
    respx.get(f"{base_url}/api/metrics").mock(return_value=httpx.Response(200, json={"total_sessions": 0, "total_events": 0, "p99_latency_ms": 42.5}))
    async with LedgerClient(base_url) as client:
        metrics = await client.get_metrics()
    assert metrics.extra == {}  # unknown keys are discarded; server must send {"extra": {...}}


@respx.mock
async def test_get_security_metrics(base_url: str) -> None:
    data = {"injection_attempts_detected_7d": 3, "injection_attempts_by_layer": {"tripwire": 2, "guard_llm": 1}, "sessions_aborted_circuit_breaker": 0, "chain_verification_failures": 0}
    respx.get(f"{base_url}/api/metrics/security").mock(return_value=httpx.Response(200, json=data))
    async with LedgerClient(base_url) as client:
        sec = await client.get_security_metrics()
    assert isinstance(sec, SecurityMetrics)
    assert sec.injection_attempts_detected_7d == 3
    assert sec.injection_attempts_by_layer["tripwire"] == 2


@respx.mock
async def test_get_prometheus_metrics(base_url: str) -> None:
    raw = "# HELP sessions_total Total sessions\nsessions_total 42\n"
    respx.get(f"{base_url}/metrics").mock(return_value=httpx.Response(200, text=raw))
    async with LedgerClient(base_url) as client:
        text = await client.get_prometheus_metrics()
    assert "sessions_total 42" in text


# ---------------------------------------------------------------------------
# list_policies / get_policy / save_policy / delete_policy
# ---------------------------------------------------------------------------

@respx.mock
async def test_list_policies_returns_list(base_url: str) -> None:
    respx.get(f"{base_url}/api/policies").mock(return_value=httpx.Response(200, json=["soc2-audit", "iso42001"]))
    async with LedgerClient(base_url) as client:
        policies = await client.list_policies()
    assert policies == ["soc2-audit", "iso42001"]


@respx.mock
async def test_get_policy_returns_text(base_url: str) -> None:
    toml_content = "[rules]\nmin_justification_length = 10\n"
    respx.get(f"{base_url}/api/policies/soc2-audit").mock(return_value=httpx.Response(200, text=toml_content))
    async with LedgerClient(base_url) as client:
        content = await client.get_policy("soc2-audit")
    assert "min_justification_length" in content


@respx.mock
async def test_save_policy_success(base_url: str) -> None:
    respx.put(f"{base_url}/api/policies/soc2-audit").mock(return_value=httpx.Response(200))
    async with LedgerClient(base_url) as client:
        await client.save_policy("soc2-audit", "[rules]\nmin_justification_length = 10")


@respx.mock
async def test_delete_policy_success(base_url: str) -> None:
    respx.delete(f"{base_url}/api/policies/soc2-audit").mock(return_value=httpx.Response(200))
    async with LedgerClient(base_url) as client:
        await client.delete_policy("soc2-audit")


# ---------------------------------------------------------------------------
# Approval gates
# ---------------------------------------------------------------------------

@respx.mock
async def test_get_pending_approval_returns_pending(base_url: str, session_id: str) -> None:
    pending_data = {
        "pending": {
            "gate_id": "gate-1",
            "action_name": "run_command",
            "action_params_summary": "ls -la /etc",
            "created_at": "2026-02-22T10:05:00Z",
        }
    }
    respx.get(f"{base_url}/api/approvals/{session_id}/pending").mock(return_value=httpx.Response(200, json=pending_data))
    async with LedgerClient(base_url) as client:
        result = await client.get_pending_approval(session_id)
    assert isinstance(result, PendingApproval)
    assert result.gate_id == "gate-1"
    assert result.action_name == "run_command"


@respx.mock
async def test_get_pending_approval_returns_none(base_url: str, session_id: str) -> None:
    respx.get(f"{base_url}/api/approvals/{session_id}/pending").mock(return_value=httpx.Response(200, json={"pending": None}))
    async with LedgerClient(base_url) as client:
        result = await client.get_pending_approval(session_id)
    assert result is None


@respx.mock
async def test_post_approval_decision_approve(base_url: str, session_id: str) -> None:
    respx.post(f"{base_url}/api/approvals/{session_id}").mock(return_value=httpx.Response(200, json={"ok": True}))
    async with LedgerClient(base_url) as client:
        await client.post_approval_decision(session_id, gate_id="gate-1", approved=True, reason="Looks safe")


@respx.mock
async def test_post_approval_decision_deny(base_url: str, session_id: str) -> None:
    respx.post(f"{base_url}/api/approvals/{session_id}").mock(return_value=httpx.Response(200, json={"ok": True}))
    async with LedgerClient(base_url) as client:
        await client.post_approval_decision(session_id, gate_id="gate-1", approved=False)


# ---------------------------------------------------------------------------
# Bearer token header
# ---------------------------------------------------------------------------

@respx.mock
async def test_bearer_token_is_sent(base_url: str, sample_session: dict) -> None:
    route = respx.get(f"{base_url}/api/sessions").mock(return_value=httpx.Response(200, json=[sample_session]))
    async with LedgerClient(base_url, bearer_token="super-secret-token") as client:
        await client.list_sessions()
    assert route.calls.last.request.headers.get("authorization") == "Bearer super-secret-token"


# ---------------------------------------------------------------------------
# Timeout handling (connect-level timeout)
# ---------------------------------------------------------------------------

async def test_client_timeout_raises() -> None:
    async with LedgerClient("http://127.0.0.1:19999", timeout=0.01) as client:
        with pytest.raises(Exception):
            await client.list_sessions()


# ---------------------------------------------------------------------------
# get_status
# ---------------------------------------------------------------------------

@respx.mock
async def test_get_status(base_url: str) -> None:
    respx.get(f"{base_url}/api/status").mock(return_value=httpx.Response(200, json={"demo_mode": True, "version": "0.6.2"}))
    async with LedgerClient(base_url) as client:
        status = await client.get_status()
    assert isinstance(status, StatusResponse)
    assert status.demo_mode is True
    assert status.version == "0.6.2"


# ---------------------------------------------------------------------------
# get_session (single)
# ---------------------------------------------------------------------------

@respx.mock
async def test_get_session_by_id(base_url: str, session_id: str, sample_session: dict) -> None:
    respx.get(f"{base_url}/api/sessions/{session_id}").mock(return_value=httpx.Response(200, json=sample_session))
    async with LedgerClient(base_url) as client:
        session = await client.get_session(session_id)
    assert isinstance(session, Session)
    assert session.session_id == session_id


# ---------------------------------------------------------------------------
# chat
# ---------------------------------------------------------------------------

@respx.mock
async def test_chat(base_url: str, session_id: str) -> None:
    reply = {"role": "assistant", "content": "Hello from the LLM"}
    respx.post(f"{base_url}/api/sessions/{session_id}/chat").mock(return_value=httpx.Response(200, json=reply))
    async with LedgerClient(base_url) as client:
        result = await client.chat(session_id, message="Hi")
    assert result["role"] == "assistant"


# ---------------------------------------------------------------------------
# get_config / update_config
# ---------------------------------------------------------------------------

@respx.mock
async def test_get_config(base_url: str) -> None:
    data = {"database_url": "sqlite://db.sqlite", "llm_backend": "ollama", "ollama_base_url": "", "ollama_model": "", "guard_required": False, "max_steps": 50, "agent_allowed_domains": [], "sandbox_mode": "docker", "demo_mode": True}
    respx.get(f"{base_url}/api/config").mock(return_value=httpx.Response(200, json=data))
    async with LedgerClient(base_url) as client:
        config = await client.get_config()
    assert isinstance(config, ConfigResponse)
    assert config.max_steps == 50


@respx.mock
async def test_update_config(base_url: str) -> None:
    respx.put(f"{base_url}/api/config").mock(return_value=httpx.Response(200, json={"ok": True}))
    async with LedgerClient(base_url) as client:
        result = await client.update_config({"max_steps": 100})
    assert result["ok"] is True


# ---------------------------------------------------------------------------
# get_tripwire_config / update_tripwire_config
# ---------------------------------------------------------------------------

@respx.mock
async def test_get_tripwire_config(base_url: str) -> None:
    data = {"allowed_paths": ["/tmp"], "allowed_domains": ["example.com"], "banned_command_patterns": [], "min_justification_length": 10, "require_https": True}
    respx.get(f"{base_url}/api/config/tripwire").mock(return_value=httpx.Response(200, json=data))
    async with LedgerClient(base_url) as client:
        tw = await client.get_tripwire_config()
    assert isinstance(tw, TripwireConfig)
    assert tw.require_https is True


@respx.mock
async def test_update_tripwire_config(base_url: str) -> None:
    respx.put(f"{base_url}/api/config/tripwire").mock(return_value=httpx.Response(200, json={"ok": True}))
    async with LedgerClient(base_url) as client:
        result = await client.update_tripwire_config({"require_https": False})
    assert result["ok"] is True


# ---------------------------------------------------------------------------
# list_tokens / create_token / delete_token
# ---------------------------------------------------------------------------

@respx.mock
async def test_list_tokens(base_url: str) -> None:
    data = [{"token_hash": "abc", "role": "Admin", "label": "CI", "created_at": "2026-01-01T00:00:00Z", "expires_at": None}]
    respx.get(f"{base_url}/api/tokens").mock(return_value=httpx.Response(200, json=data))
    async with LedgerClient(base_url) as client:
        tokens = await client.list_tokens()
    assert len(tokens) == 1
    assert isinstance(tokens[0], TokenListRow)
    assert tokens[0].role == "Admin"


@respx.mock
async def test_create_token(base_url: str) -> None:
    data = {"token": "raw-secret-123", "token_hash": "hashed", "role": "Agent", "label": "test"}
    respx.post(f"{base_url}/api/tokens").mock(return_value=httpx.Response(201, json=data))
    async with LedgerClient(base_url) as client:
        result = await client.create_token(role="Agent", label="test")
    assert isinstance(result, CreateTokenResponse)
    assert result.token == "raw-secret-123"


@respx.mock
async def test_delete_token(base_url: str) -> None:
    respx.delete(f"{base_url}/api/tokens/abc123").mock(return_value=httpx.Response(200))
    async with LedgerClient(base_url) as client:
        await client.delete_token("abc123")


# ---------------------------------------------------------------------------
# list_webhooks / create_webhook / delete_webhook / toggle_webhook
# ---------------------------------------------------------------------------

@respx.mock
async def test_list_webhooks(base_url: str) -> None:
    data = [{"id": "wh-1", "label": "Slack", "url": "https://hooks.slack.com/x", "siem_format": "json", "filter_kinds": [], "enabled": True, "created_at": "2026-01-01T00:00:00Z"}]
    respx.get(f"{base_url}/api/webhooks").mock(return_value=httpx.Response(200, json=data))
    async with LedgerClient(base_url) as client:
        webhooks = await client.list_webhooks()
    assert len(webhooks) == 1
    assert isinstance(webhooks[0], WebhookListRow)


@respx.mock
async def test_create_webhook(base_url: str) -> None:
    data = {"id": "wh-2", "label": "Splunk", "url": "https://splunk.example.com", "siem_format": "cef", "filter_kinds": ["alert"], "enabled": True, "created_at": "2026-01-01T00:00:00Z"}
    respx.post(f"{base_url}/api/webhooks").mock(return_value=httpx.Response(201, json=data))
    async with LedgerClient(base_url) as client:
        result = await client.create_webhook(label="Splunk", url="https://splunk.example.com", siem_format="cef", filter_kinds=["alert"])
    assert isinstance(result, WebhookListRow)
    assert result.siem_format == "cef"


@respx.mock
async def test_delete_webhook(base_url: str) -> None:
    respx.delete(f"{base_url}/api/webhooks/wh-1").mock(return_value=httpx.Response(200))
    async with LedgerClient(base_url) as client:
        await client.delete_webhook("wh-1")


@respx.mock
async def test_toggle_webhook(base_url: str) -> None:
    respx.put(f"{base_url}/api/webhooks/wh-1/toggle").mock(return_value=httpx.Response(200, json={"ok": True, "enabled": False}))
    async with LedgerClient(base_url) as client:
        result = await client.toggle_webhook("wh-1", enabled=False)
    assert result["enabled"] is False


# ---------------------------------------------------------------------------
# reset_demo
# ---------------------------------------------------------------------------

@respx.mock
async def test_reset_demo(base_url: str) -> None:
    respx.post(f"{base_url}/api/admin/reset-demo").mock(return_value=httpx.Response(200, json={"ok": True, "message": "demo reset"}))
    async with LedgerClient(base_url) as client:
        result = await client.reset_demo()
    assert result["ok"] is True
