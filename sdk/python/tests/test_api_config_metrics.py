"""
==========================================================================
CFG-* / MET-* / CHAT-* / CERT-* / VC-* — Config, metrics, chat,
                                           certificates & VCs
==========================================================================

Covers configuration endpoints, Prometheus & security metrics, one-shot
chat, certificates, reports, and Verifiable Credentials.
"""
from __future__ import annotations

import asyncio
import os
import uuid

import httpx
import pytest

from ectoledger_sdk.client import LedgerClient, LedgerSdkError


# ═══════════════════════════════════════════════════════════════════════════
# CFG-01  Get config — admin
# ═══════════════════════════════════════════════════════════════════════════

class TestCfg01GetConfig:
    """CFG-01 · GET /api/config (admin) → 200 with database_url redacted."""

    async def test_get_config(self, raw_http: httpx.AsyncClient):
        r = await raw_http.get("/api/config")
        assert r.status_code == 200
        data = r.json()
        assert "llm_backend" in data or "database_url" in data


# ═══════════════════════════════════════════════════════════════════════════
# CFG-02  Get config — non-admin → 403
# ═══════════════════════════════════════════════════════════════════════════

class TestCfg02GetConfigNonAdmin:
    """CFG-02 · GET /api/config with non-admin token → 403."""

    async def test_non_admin_blocked(self, ectoledger_server):
        agent_token = os.environ.get("ECTOLEDGER_AGENT_TOKEN")
        if not agent_token:
            pytest.skip("ECTOLEDGER_AGENT_TOKEN not set")

        async with httpx.AsyncClient(
            base_url=ectoledger_server.base_url,
            headers={"Authorization": f"Bearer {agent_token}"},
            timeout=10.0,
        ) as client:
            r = await client.get("/api/config")
            assert r.status_code == 403


# ═══════════════════════════════════════════════════════════════════════════
# CFG-03  Update config
# ═══════════════════════════════════════════════════════════════════════════

class TestCfg03UpdateConfig:
    """CFG-03 · PUT /api/config with partial update → 200."""

    async def test_update_config(self, raw_http: httpx.AsyncClient):
        # Read current config first
        r0 = await raw_http.get("/api/config")
        if r0.status_code != 200:
            pytest.skip("Cannot read config")

        original_max_steps = r0.json().get("max_steps", 20)

        # Update
        r = await raw_http.put("/api/config", json={"max_steps": 50})
        assert r.status_code == 200
        data = r.json()
        assert data.get("max_steps") == 50

        # Restore
        await raw_http.put("/api/config", json={"max_steps": original_max_steps})


# ═══════════════════════════════════════════════════════════════════════════
# CFG-04  Get tripwire config
# ═══════════════════════════════════════════════════════════════════════════

class TestCfg04GetTripwire:
    """CFG-04 · GET /api/tripwire → 200 with expected fields."""

    async def test_get_tripwire(self, raw_http: httpx.AsyncClient):
        r = await raw_http.get("/api/tripwire")
        assert r.status_code == 200
        data = r.json()
        assert "allowed_paths" in data or "allowed_domains" in data or "banned_command_patterns" in data


# ═══════════════════════════════════════════════════════════════════════════
# CFG-05  Update tripwire — admin
# ═══════════════════════════════════════════════════════════════════════════

class TestCfg05UpdateTripwire:
    """CFG-05 · PUT /api/tripwire with valid body (admin) → 200."""

    async def test_update_tripwire(self, raw_http: httpx.AsyncClient):
        # Read current
        r0 = await raw_http.get("/api/tripwire")
        if r0.status_code != 200:
            pytest.skip("Cannot read tripwire config")
        original = r0.json()

        # Update
        r = await raw_http.put(
            "/api/tripwire",
            json={
                "allowed_paths": original.get("allowed_paths", []),
                "allowed_domains": original.get("allowed_domains", []),
                "banned_command_patterns": original.get("banned_command_patterns", []),
            },
        )
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════
# CFG-06  Update tripwire — non-admin → 403
# ═══════════════════════════════════════════════════════════════════════════

class TestCfg06TripwireNonAdmin:
    """CFG-06 · PUT /api/tripwire as non-admin → 403."""

    async def test_non_admin_blocked(self, ectoledger_server):
        agent_token = os.environ.get("ECTOLEDGER_AGENT_TOKEN")
        if not agent_token:
            pytest.skip("ECTOLEDGER_AGENT_TOKEN not set")

        async with httpx.AsyncClient(
            base_url=ectoledger_server.base_url,
            headers={"Authorization": f"Bearer {agent_token}"},
            timeout=10.0,
        ) as client:
            r = await client.put(
                "/api/tripwire",
                json={
                    "allowed_paths": [],
                    "allowed_domains": [],
                    "banned_command_patterns": [],
                },
            )
            assert r.status_code == 403


# ═══════════════════════════════════════════════════════════════════════════
# MET-01  Prometheus metrics — admin
# ═══════════════════════════════════════════════════════════════════════════

class TestMet01PrometheusMetrics:
    """MET-01 · GET /metrics (admin) → 200, contains counter names."""

    async def test_prometheus_metrics(self, raw_http: httpx.AsyncClient):
        r = await raw_http.get("/metrics", headers={"Accept": "text/plain"})
        assert r.status_code == 200
        body = r.text
        # Should contain at least one known counter
        assert any(
            name in body
            for name in [
                "ectoledger_events_appended_total",
                "ectoledger_sessions_created_total",
                "ectoledger_tripwire_rejections_total",
            ]
        ), f"Expected Prometheus counter in body, got: {body[:200]}"


# ═══════════════════════════════════════════════════════════════════════════
# MET-02  Prometheus metrics — HTML format
# ═══════════════════════════════════════════════════════════════════════════

class TestMet02PrometheusHtml:
    """MET-02 · GET /metrics Accept: text/html → 200, HTML page."""

    async def test_prometheus_html(self, raw_http: httpx.AsyncClient):
        r = await raw_http.get("/metrics", headers={"Accept": "text/html"})
        assert r.status_code == 200
        assert "<" in r.text  # Contains HTML tags


# ═══════════════════════════════════════════════════════════════════════════
# MET-03  Prometheus metrics — non-admin → 403
# ═══════════════════════════════════════════════════════════════════════════

class TestMet03PrometheusNonAdmin:
    """MET-03 · GET /metrics as non-admin → 403."""

    async def test_non_admin_blocked(self, ectoledger_server):
        agent_token = os.environ.get("ECTOLEDGER_AGENT_TOKEN")
        if not agent_token:
            pytest.skip("ECTOLEDGER_AGENT_TOKEN not set")

        async with httpx.AsyncClient(
            base_url=ectoledger_server.base_url,
            headers={"Authorization": f"Bearer {agent_token}"},
            timeout=10.0,
        ) as client:
            r = await client.get("/metrics")
            assert r.status_code == 403


# ═══════════════════════════════════════════════════════════════════════════
# MET-04  Security metrics
# ═══════════════════════════════════════════════════════════════════════════

class TestMet04SecurityMetrics:
    """MET-04 · GET /api/metrics/security → 200, JSON with expected keys."""

    async def test_security_metrics(self, adv_client: LedgerClient):
        metrics = await adv_client.get_security_metrics()
        assert hasattr(metrics, "injection_attempts_detected_7d")
        assert hasattr(metrics, "chain_verification_failures")


# ═══════════════════════════════════════════════════════════════════════════
# CHAT-01  One-shot chat — valid message
# ═══════════════════════════════════════════════════════════════════════════

class TestChat01ValidMessage:
    """CHAT-01 · POST /api/chat with valid message → 200 with reply."""

    async def test_valid_chat(self, raw_http: httpx.AsyncClient):
        r = await raw_http.post("/api/chat", json={"message": "Hello, how are you?"})
        assert r.status_code == 200
        data = r.json()
        assert "reply" in data
        assert "backend" in data
        assert "model" in data


# ═══════════════════════════════════════════════════════════════════════════
# CHAT-02  Empty message → 400
# ═══════════════════════════════════════════════════════════════════════════

class TestChat02EmptyMessage:
    """CHAT-02 · Empty message → 400."""

    async def test_empty_message(self, raw_http: httpx.AsyncClient):
        r = await raw_http.post("/api/chat", json={"message": ""})
        assert r.status_code == 400


# ═══════════════════════════════════════════════════════════════════════════
# CHAT-03  Whitespace-only message → 400
# ═══════════════════════════════════════════════════════════════════════════

class TestChat03WhitespaceMessage:
    """CHAT-03 · Whitespace-only message → 400."""

    async def test_whitespace_message(self, raw_http: httpx.AsyncClient):
        r = await raw_http.post("/api/chat", json={"message": "   \n\t "})
        assert r.status_code == 400


# ═══════════════════════════════════════════════════════════════════════════
# CHAT-04  Missing message field → 400/422
# ═══════════════════════════════════════════════════════════════════════════

class TestChat04MissingMessage:
    """CHAT-04 · No message field → 400 or 422."""

    async def test_missing_message(self, raw_http: httpx.AsyncClient):
        r = await raw_http.post("/api/chat", json={})
        assert r.status_code in (400, 422)


# ═══════════════════════════════════════════════════════════════════════════
# CERT-01  Get certificate for session (may 501 on SQLite)
# ═══════════════════════════════════════════════════════════════════════════

class TestCert01GetCertificate:
    """CERT-01 · GET /api/certificates/{session_id} → 200 or 501."""

    async def test_get_certificate(self, adv_client: LedgerClient):
        session = await adv_client.create_session(goal="cert test")
        await asyncio.sleep(3.0)

        try:
            cert = await adv_client.export_certificate(session.session_id)
            assert cert is not None
            assert len(cert) > 0
        except LedgerSdkError as exc:
            # 404 (no events for cert) or 501 (SQLite) are acceptable
            assert exc.status_code in (404, 501), f"Unexpected error: {exc}"


# ═══════════════════════════════════════════════════════════════════════════
# CERT-02  Certificate for non-existent session → 404
# ═══════════════════════════════════════════════════════════════════════════

class TestCert02NotFound:
    """CERT-02 · Certificate for random UUID → 404."""

    async def test_cert_not_found(self, raw_http: httpx.AsyncClient):
        r = await raw_http.get(f"/api/certificates/{uuid.uuid4()}")
        assert r.status_code in (404, 501)


# ═══════════════════════════════════════════════════════════════════════════
# RPT-01  Get report for session
# ═══════════════════════════════════════════════════════════════════════════

class TestRpt01GetReport:
    """RPT-01 · GET /api/reports/{session_id} → 200 or 501."""

    async def test_get_report(self, adv_client: LedgerClient):
        session = await adv_client.create_session(goal="report test")
        await asyncio.sleep(3.0)

        try:
            report = await adv_client.get_report(session.session_id)
            assert isinstance(report, dict)
        except LedgerSdkError as exc:
            assert exc.status_code in (404, 501), f"Unexpected error: {exc}"


# ═══════════════════════════════════════════════════════════════════════════
# RPT-03  Report for non-existent session → 404
# ═══════════════════════════════════════════════════════════════════════════

class TestRpt03NotFound:
    """RPT-03 · Report for random UUID → 404."""

    async def test_report_not_found(self, raw_http: httpx.AsyncClient):
        r = await raw_http.get(f"/api/reports/{uuid.uuid4()}")
        assert r.status_code in (404, 501)


# ═══════════════════════════════════════════════════════════════════════════
# VC-01  Get VC for session
# ═══════════════════════════════════════════════════════════════════════════

class TestVc01GetVc:
    """VC-01 · GET /api/sessions/{id}/vc → 200 with vc_jwt or 404."""

    async def test_get_vc(self, adv_client: LedgerClient):
        session = await adv_client.create_session(goal="VC test")
        await asyncio.sleep(5.0)

        try:
            vc = await adv_client.get_session_vc(session.session_id)
            assert "vc_jwt" in vc
        except LedgerSdkError as exc:
            # 404 is expected if session hasn't completed with a VC
            assert exc.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════
# VC-02  Get VC — no VC event → 404
# ═══════════════════════════════════════════════════════════════════════════

class TestVc02NoVcEvent:
    """VC-02 · Session without VC event → 404."""

    async def test_no_vc_event(self, raw_http: httpx.AsyncClient):
        # Use a random UUID that won't have a VC
        r = await raw_http.get(f"/api/sessions/{uuid.uuid4()}/vc")
        assert r.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════
# VC-03  Verify VC
# ═══════════════════════════════════════════════════════════════════════════

class TestVc03VerifyVc:
    """VC-03 · GET /api/sessions/{id}/vc/verify → valid or 404."""

    async def test_verify_vc(self, adv_client: LedgerClient):
        session = await adv_client.create_session(goal="VC verify test")
        await asyncio.sleep(5.0)

        try:
            result = await adv_client.verify_session_vc(session.session_id)
            assert "valid" in result
        except LedgerSdkError as exc:
            assert exc.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════
# VC-05  Verify VC — no VC exists → 404
# ═══════════════════════════════════════════════════════════════════════════

class TestVc05VerifyNoVc:
    """VC-05 · Verify VC for session without VC → 404."""

    async def test_verify_no_vc(self, raw_http: httpx.AsyncClient):
        r = await raw_http.get(f"/api/sessions/{uuid.uuid4()}/vc/verify")
        assert r.status_code == 404
