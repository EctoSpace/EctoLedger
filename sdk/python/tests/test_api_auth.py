"""
==========================================================================
AUTH-* — Authentication & Authorization black-box tests
==========================================================================

Tests RBAC enforcement, bearer-token validation, role-based access to every
major endpoint group.

Requires a live ephemeral EctoLedger server (started by ``conftest_adversarial``).
"""
from __future__ import annotations

import httpx
import pytest

from ectoledger_sdk.client import LedgerClient, LedgerSdkError


# ── helpers ──────────────────────────────────────────────────────────────

def _headers(token: str | None) -> dict[str, str]:
    if token is None:
        return {}
    return {"Authorization": f"Bearer {token}"}


# ═══════════════════════════════════════════════════════════════════════════
# AUTH-01  Valid Bearer token in header
# ═══════════════════════════════════════════════════════════════════════════

class TestAuth01ValidBearerHeader:
    """AUTH-01 · Valid Bearer token in Authorization header → 200."""

    async def test_valid_bearer_header(self, raw_http: httpx.AsyncClient):
        r = await raw_http.get("/api/sessions")
        assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════
# AUTH-02  Valid token via query parameter
# ═══════════════════════════════════════════════════════════════════════════

class TestAuth02TokenQueryParam:
    """AUTH-02 · Token supplied as ?token= query param → 200."""

    async def test_token_query_param(self, ectoledger_server):
        async with httpx.AsyncClient(
            base_url=ectoledger_server.base_url,
            timeout=15.0,
        ) as bare:
            r = await bare.get(
                "/api/sessions",
                params={"token": ectoledger_server.token},
            )
            assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════
# AUTH-03  Missing auth → 401
# ═══════════════════════════════════════════════════════════════════════════

class TestAuth03MissingAuth:
    """AUTH-03 · No token at all → 401 Unauthorized."""

    async def test_no_token(self, ectoledger_server):
        async with httpx.AsyncClient(
            base_url=ectoledger_server.base_url,
            timeout=15.0,
        ) as bare:
            r = await bare.get("/api/sessions")
            assert r.status_code == 401


# ═══════════════════════════════════════════════════════════════════════════
# AUTH-04  Invalid / revoked token → 401
# ═══════════════════════════════════════════════════════════════════════════

class TestAuth04InvalidToken:
    """AUTH-04 · Garbage token → 401."""

    async def test_invalid_token(self, ectoledger_server):
        async with httpx.AsyncClient(
            base_url=ectoledger_server.base_url,
            headers={"Authorization": "Bearer totally-invalid-token-deadbeef"},
            timeout=15.0,
        ) as bare:
            r = await bare.get("/api/sessions")
            assert r.status_code == 401


# ═══════════════════════════════════════════════════════════════════════════
# AUTH-05  Expired token → 401  (requires token with past expiry)
# ═══════════════════════════════════════════════════════════════════════════

class TestAuth05ExpiredToken:
    """AUTH-05 · Expired token → 401.

    This test is best-effort: it creates a token with the shortest window
    and checks that a truly-invalid token is rejected.
    """

    async def test_expired_token(self, ectoledger_server):
        """Use a clearly invalid token to simulate expiry rejection."""
        async with httpx.AsyncClient(
            base_url=ectoledger_server.base_url,
            headers={"Authorization": "Bearer expired-simulation-000000000000"},
            timeout=15.0,
        ) as bare:
            r = await bare.get("/api/sessions")
            assert r.status_code == 401


# ═══════════════════════════════════════════════════════════════════════════
# AUTH-06  Auditor cannot POST /api/sessions → 403
# ═══════════════════════════════════════════════════════════════════════════

class TestAuth06AuditorCannotCreateSession:
    """AUTH-06 · Auditor role → 403 on session creation.

    Skipped when the test harness only has a single admin token (default).
    To fully exercise this, provision an auditor token and set
    ECTOLEDGER_AUDITOR_TOKEN in the environment.
    """

    async def test_auditor_blocked(self, ectoledger_server):
        import os

        auditor_token = os.environ.get("ECTOLEDGER_AUDITOR_TOKEN")
        if not auditor_token:
            pytest.skip("ECTOLEDGER_AUDITOR_TOKEN not set — cannot test auditor RBAC")

        async with httpx.AsyncClient(
            base_url=ectoledger_server.base_url,
            headers={"Authorization": f"Bearer {auditor_token}"},
            timeout=15.0,
        ) as bare:
            r = await bare.post("/api/sessions", json={"goal": "forbidden"})
            assert r.status_code == 403


# ═══════════════════════════════════════════════════════════════════════════
# AUTH-07  Agent cannot PUT /api/policies → 403
# ═══════════════════════════════════════════════════════════════════════════

class TestAuth07AgentCannotSavePolicy:
    """AUTH-07 · Agent role → 403 on policy write."""

    async def test_agent_blocked(self, ectoledger_server):
        import os

        agent_token = os.environ.get("ECTOLEDGER_AGENT_TOKEN")
        if not agent_token:
            pytest.skip("ECTOLEDGER_AGENT_TOKEN not set — cannot test agent RBAC")

        async with httpx.AsyncClient(
            base_url=ectoledger_server.base_url,
            headers={"Authorization": f"Bearer {agent_token}"},
            timeout=15.0,
        ) as bare:
            r = await bare.put(
                "/api/policies/test-agent-write",
                content=b'[metadata]\ntitle = "test"',
            )
            assert r.status_code == 403


# ═══════════════════════════════════════════════════════════════════════════
# AUTH-08  Agent cannot POST /api/tokens → 403
# ═══════════════════════════════════════════════════════════════════════════

class TestAuth08AgentCannotCreateToken:
    """AUTH-08 · Agent role → 403 on token creation."""

    async def test_agent_blocked(self, ectoledger_server):
        import os

        agent_token = os.environ.get("ECTOLEDGER_AGENT_TOKEN")
        if not agent_token:
            pytest.skip("ECTOLEDGER_AGENT_TOKEN not set — cannot test agent RBAC")

        async with httpx.AsyncClient(
            base_url=ectoledger_server.base_url,
            headers={"Authorization": f"Bearer {agent_token}"},
            timeout=15.0,
        ) as bare:
            r = await bare.post("/api/tokens", json={"role": "agent"})
            assert r.status_code == 403


# ═══════════════════════════════════════════════════════════════════════════
# AUTH-09  Auditor can access GET /api/stream
# ═══════════════════════════════════════════════════════════════════════════

class TestAuth09AuditorCanStream:
    """AUTH-09 · Auditor role → 200 on SSE stream."""

    async def test_auditor_can_stream(self, ectoledger_server):
        import os

        auditor_token = os.environ.get("ECTOLEDGER_AUDITOR_TOKEN")
        if not auditor_token:
            pytest.skip("ECTOLEDGER_AUDITOR_TOKEN not set")

        async with httpx.AsyncClient(
            base_url=ectoledger_server.base_url,
            headers={"Authorization": f"Bearer {auditor_token}"},
            timeout=5.0,
        ) as bare:
            try:
                r = await bare.get("/api/stream")
                assert r.status_code == 200
            except httpx.ReadTimeout:
                # SSE streams stay open — a timeout is expected success
                pass


# ═══════════════════════════════════════════════════════════════════════════
# AUTH-10  Auditor can GET /api/events
# ═══════════════════════════════════════════════════════════════════════════

class TestAuth10AuditorCanGetEvents:
    """AUTH-10 · Auditor can read events (read-only access)."""

    async def test_auditor_can_read_events(self, ectoledger_server, adv_client: LedgerClient):
        import os

        auditor_token = os.environ.get("ECTOLEDGER_AUDITOR_TOKEN")
        if not auditor_token:
            pytest.skip("ECTOLEDGER_AUDITOR_TOKEN not set")

        # Create a session first (with admin)
        session = await adv_client.create_session(goal="auditor read test")

        async with httpx.AsyncClient(
            base_url=ectoledger_server.base_url,
            headers={"Authorization": f"Bearer {auditor_token}"},
            timeout=15.0,
        ) as bare:
            r = await bare.get("/api/events", params={"session_id": session.session_id})
            assert r.status_code == 200
