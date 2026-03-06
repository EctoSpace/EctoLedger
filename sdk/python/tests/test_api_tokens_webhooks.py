"""
==========================================================================
TOK-* / WH-* — Token management & webhook black-box tests
==========================================================================

Covers RBAC token CRUD, webhook creation with SSRF protection, webhook
toggling, and deletion.
"""
from __future__ import annotations

import httpx
import pytest

from ectoledger_sdk.client import LedgerClient, LedgerSdkError


# ═══════════════════════════════════════════════════════════════════════════
# TOK-01  Create token — admin role
# ═══════════════════════════════════════════════════════════════════════════

class TestTok01CreateAdmin:
    """TOK-01 · POST /api/tokens with role=admin → 200, 64-char hex token."""

    async def test_create_admin_token(self, raw_http: httpx.AsyncClient):
        r = await raw_http.post("/api/tokens", json={"role": "admin"})
        assert r.status_code == 200
        data = r.json()
        assert "token" in data
        assert len(data["token"]) == 64, f"Token should be 64 hex chars, got {len(data['token'])}"
        assert "token_hash" in data
        assert data["role"] == "admin"

        # Clean up: delete the token we just created
        await raw_http.delete(f"/api/tokens/{data['token_hash']}")


# ═══════════════════════════════════════════════════════════════════════════
# TOK-02  Create token — agent role with label
# ═══════════════════════════════════════════════════════════════════════════

class TestTok02CreateAgentWithLabel:
    """TOK-02 · Agent role with label → 200, label preserved."""

    async def test_create_agent_with_label(self, raw_http: httpx.AsyncClient):
        r = await raw_http.post(
            "/api/tokens",
            json={"role": "agent", "label": "CI bot"},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["role"] == "agent"
        assert data.get("label") == "CI bot"

        await raw_http.delete(f"/api/tokens/{data['token_hash']}")


# ═══════════════════════════════════════════════════════════════════════════
# TOK-03  Create token — with expiry
# ═══════════════════════════════════════════════════════════════════════════

class TestTok03CreateWithExpiry:
    """TOK-03 · Token with expires_in_days=7 → 200."""

    async def test_create_with_expiry(self, raw_http: httpx.AsyncClient):
        r = await raw_http.post(
            "/api/tokens",
            json={"role": "auditor", "expires_in_days": 7},
        )
        assert r.status_code == 200
        data = r.json()
        assert data["role"] == "auditor"

        await raw_http.delete(f"/api/tokens/{data['token_hash']}")


# ═══════════════════════════════════════════════════════════════════════════
# TOK-04  Create token — invalid role → 400
# ═══════════════════════════════════════════════════════════════════════════

class TestTok04InvalidRole:
    """TOK-04 · Invalid role string → 400."""

    async def test_invalid_role(self, raw_http: httpx.AsyncClient):
        r = await raw_http.post("/api/tokens", json={"role": "superadmin"})
        assert r.status_code in (400, 422)


# ═══════════════════════════════════════════════════════════════════════════
# TOK-05  Create token — missing role → 400/422
# ═══════════════════════════════════════════════════════════════════════════

class TestTok05MissingRole:
    """TOK-05 · No role field → 400 or 422."""

    async def test_missing_role(self, raw_http: httpx.AsyncClient):
        r = await raw_http.post("/api/tokens", json={})
        assert r.status_code in (400, 422)


# ═══════════════════════════════════════════════════════════════════════════
# TOK-06  List tokens
# ═══════════════════════════════════════════════════════════════════════════

class TestTok06ListTokens:
    """TOK-06 · GET /api/tokens → 200, array with token_hash (no raw token)."""

    async def test_list_tokens(self, raw_http: httpx.AsyncClient):
        r = await raw_http.get("/api/tokens")
        assert r.status_code == 200
        tokens = r.json()
        assert isinstance(tokens, list)
        for t in tokens:
            assert "token_hash" in t
            assert "role" in t
            # Raw token should NEVER appear in listing
            assert "token" not in t or t.get("token") is None


# ═══════════════════════════════════════════════════════════════════════════
# TOK-07  Delete token
# ═══════════════════════════════════════════════════════════════════════════

class TestTok07DeleteToken:
    """TOK-07 · DELETE /api/tokens/{hash} → 204."""

    async def test_delete_token(self, raw_http: httpx.AsyncClient):
        # Create a token to delete
        r = await raw_http.post("/api/tokens", json={"role": "agent", "label": "delete-me"})
        assert r.status_code == 200
        token_hash = r.json()["token_hash"]

        # Delete it
        r2 = await raw_http.delete(f"/api/tokens/{token_hash}")
        assert r2.status_code == 204


# ═══════════════════════════════════════════════════════════════════════════
# TOK-08  Use deleted token → 401
# ═══════════════════════════════════════════════════════════════════════════

class TestTok08UseDeletedToken:
    """TOK-08 · Auth with a deleted token → 401."""

    async def test_use_deleted_token(self, ectoledger_server, raw_http: httpx.AsyncClient):
        # Create a throwaway token
        r = await raw_http.post("/api/tokens", json={"role": "agent", "label": "will-delete"})
        assert r.status_code == 200
        raw_token = r.json()["token"]
        token_hash = r.json()["token_hash"]

        # Delete it
        r2 = await raw_http.delete(f"/api/tokens/{token_hash}")
        assert r2.status_code == 204

        # Try to use the deleted token
        async with httpx.AsyncClient(
            base_url=ectoledger_server.base_url,
            headers={"Authorization": f"Bearer {raw_token}"},
            timeout=10.0,
        ) as client:
            r3 = await client.get("/api/sessions")
            assert r3.status_code == 401


# ═══════════════════════════════════════════════════════════════════════════
# WH-01  Create webhook — valid external URL
# ═══════════════════════════════════════════════════════════════════════════

class TestWh01CreateValid:
    """WH-01 · POST /api/webhooks with valid https URL → 201."""

    async def test_create_webhook(self, raw_http: httpx.AsyncClient):
        r = await raw_http.post(
            "/api/webhooks",
            json={
                "label": "Splunk Test",
                "url": "https://splunk.example.com/services/collector",
            },
        )
        assert r.status_code == 201
        data = r.json()
        assert "id" in data
        assert data["label"] == "Splunk Test"
        assert data.get("enabled") is True

        # Clean up
        await raw_http.delete(f"/api/webhooks/{data['id']}")


# ═══════════════════════════════════════════════════════════════════════════
# WH-02  SSRF: file:// URL blocked → 400
# ═══════════════════════════════════════════════════════════════════════════

class TestWh02SsrfFileProtocol:
    """WH-02 · file:// URL → 400 (SSRF protection)."""

    async def test_file_protocol_blocked(self, raw_http: httpx.AsyncClient):
        r = await raw_http.post(
            "/api/webhooks",
            json={"label": "ssrf-file", "url": "file:///etc/passwd"},
        )
        assert r.status_code == 400


# ═══════════════════════════════════════════════════════════════════════════
# WH-03  SSRF: loopback URL blocked → 400
# ═══════════════════════════════════════════════════════════════════════════

class TestWh03SsrfLoopback:
    """WH-03 · http://127.0.0.1:8080 → 400 (loopback blocked)."""

    async def test_loopback_blocked(self, raw_http: httpx.AsyncClient):
        r = await raw_http.post(
            "/api/webhooks",
            json={"label": "ssrf-loopback", "url": "http://127.0.0.1:8080"},
        )
        assert r.status_code == 400


# ═══════════════════════════════════════════════════════════════════════════
# WH-04  SSRF: cloud metadata URL blocked → 400
# ═══════════════════════════════════════════════════════════════════════════

class TestWh04SsrfCloudMetadata:
    """WH-04 · http://169.254.169.254 (AWS metadata) → 400."""

    async def test_metadata_blocked(self, raw_http: httpx.AsyncClient):
        r = await raw_http.post(
            "/api/webhooks",
            json={"label": "ssrf-metadata", "url": "http://169.254.169.254/latest/meta-data"},
        )
        assert r.status_code == 400


# ═══════════════════════════════════════════════════════════════════════════
# WH-05  Empty URL → 400
# ═══════════════════════════════════════════════════════════════════════════

class TestWh05EmptyUrl:
    """WH-05 · Empty URL string → 400."""

    async def test_empty_url(self, raw_http: httpx.AsyncClient):
        r = await raw_http.post(
            "/api/webhooks",
            json={"label": "empty-url", "url": ""},
        )
        assert r.status_code == 400


# ═══════════════════════════════════════════════════════════════════════════
# WH-06  Invalid siem_format → 400
# ═══════════════════════════════════════════════════════════════════════════

class TestWh06InvalidSiemFormat:
    """WH-06 · siem_format='xml' → 400."""

    async def test_invalid_siem_format(self, raw_http: httpx.AsyncClient):
        r = await raw_http.post(
            "/api/webhooks",
            json={
                "label": "bad-format",
                "url": "https://example.com/hook",
                "siem_format": "xml",
            },
        )
        assert r.status_code in (400, 422)


# ═══════════════════════════════════════════════════════════════════════════
# WH-07  List webhooks
# ═══════════════════════════════════════════════════════════════════════════

class TestWh07ListWebhooks:
    """WH-07 · GET /api/webhooks → 200, array."""

    async def test_list_webhooks(self, raw_http: httpx.AsyncClient):
        r = await raw_http.get("/api/webhooks")
        assert r.status_code == 200
        assert isinstance(r.json(), list)


# ═══════════════════════════════════════════════════════════════════════════
# WH-08  Toggle webhook disabled
# ═══════════════════════════════════════════════════════════════════════════

class TestWh08ToggleWebhook:
    """WH-08 · PUT /api/webhooks/{id} {enabled: false} → 200."""

    async def test_toggle_webhook(self, raw_http: httpx.AsyncClient):
        # Create one first
        r = await raw_http.post(
            "/api/webhooks",
            json={"label": "toggle-test", "url": "https://example.com/toggle"},
        )
        assert r.status_code == 201
        wh_id = r.json()["id"]

        # Toggle off
        r2 = await raw_http.put(f"/api/webhooks/{wh_id}", json={"enabled": False})
        assert r2.status_code == 200

        # Clean up
        await raw_http.delete(f"/api/webhooks/{wh_id}")


# ═══════════════════════════════════════════════════════════════════════════
# WH-09  Delete webhook → 204
# ═══════════════════════════════════════════════════════════════════════════

class TestWh09DeleteWebhook:
    """WH-09 · DELETE /api/webhooks/{id} → 204."""

    async def test_delete_webhook(self, raw_http: httpx.AsyncClient):
        r = await raw_http.post(
            "/api/webhooks",
            json={"label": "delete-test", "url": "https://example.com/delete"},
        )
        assert r.status_code == 201
        wh_id = r.json()["id"]

        r2 = await raw_http.delete(f"/api/webhooks/{wh_id}")
        assert r2.status_code == 204
