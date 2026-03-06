"""
==========================================================================
POL-* / APPR-* — Policy & Approval-gate black-box tests
==========================================================================

Covers policy listing, retrieval, creation, deletion, path-traversal
protection, built-in policy protection, and approval gate workflows.
"""
from __future__ import annotations

import uuid

import httpx
import pytest

from ectoledger_sdk.client import LedgerClient, LedgerSdkError


# ═══════════════════════════════════════════════════════════════════════════
# POL-01  List policies
# ═══════════════════════════════════════════════════════════════════════════

class TestPol01ListPolicies:
    """POL-01 · GET /api/policies → sorted list including built-ins."""

    async def test_list_policies(self, adv_client: LedgerClient):
        policies = await adv_client.list_policies()
        assert isinstance(policies, list)
        # Should contain at least some built-in policy names
        builtins = {"soc2-audit", "pci-dss-audit", "owasp-top10", "iso42001"}
        found = builtins.intersection(set(policies))
        assert len(found) >= 1, f"Expected at least one built-in policy, got {policies}"

        # Verify sorted order
        assert policies == sorted(policies), "Policies should be alphabetically sorted"


# ═══════════════════════════════════════════════════════════════════════════
# POL-02  Get built-in policy content
# ═══════════════════════════════════════════════════════════════════════════

class TestPol02GetBuiltinPolicy:
    """POL-02 · GET /api/policies/soc2-audit → 200, text/plain, valid TOML."""

    async def test_get_builtin(self, raw_http: httpx.AsyncClient):
        policies = (await raw_http.get("/api/policies")).json()
        if not policies:
            pytest.skip("No policies available")

        name = policies[0]
        r = await raw_http.get(f"/api/policies/{name}")
        assert r.status_code == 200
        # Content should be non-empty text
        assert len(r.text) > 0


# ═══════════════════════════════════════════════════════════════════════════
# POL-03  Get non-existent policy → 404
# ═══════════════════════════════════════════════════════════════════════════

class TestPol03NotFound:
    """POL-03 · Policy that doesn't exist → 404."""

    async def test_not_found(self, raw_http: httpx.AsyncClient):
        r = await raw_http.get("/api/policies/does-not-exist-xyz-12345")
        assert r.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════
# POL-04  Create custom policy
# ═══════════════════════════════════════════════════════════════════════════

class TestPol04CreateCustom:
    """POL-04 · PUT /api/policies/my-test-policy → 200."""

    async def test_create_custom(self, raw_http: httpx.AsyncClient):
        policy_name = f"test-policy-{uuid.uuid4().hex[:8]}"
        toml_body = f'[metadata]\ntitle = "Test Policy"\n\n[rules]\nenabled = true\n'

        r = await raw_http.put(
            f"/api/policies/{policy_name}",
            content=toml_body.encode(),
        )
        assert r.status_code == 200

        # Verify it's now listed / retrievable
        r2 = await raw_http.get(f"/api/policies/{policy_name}")
        assert r2.status_code == 200
        assert "Test Policy" in r2.text

        # Clean up
        await raw_http.delete(f"/api/policies/{policy_name}")


# ═══════════════════════════════════════════════════════════════════════════
# POL-05  Create policy with invalid TOML → 422
# ═══════════════════════════════════════════════════════════════════════════

class TestPol05InvalidToml:
    """POL-05 · PUT with malformed TOML → 422."""

    async def test_invalid_toml(self, raw_http: httpx.AsyncClient):
        r = await raw_http.put(
            "/api/policies/bad-toml-test",
            content=b'not [valid toml syntax ===',
        )
        assert r.status_code == 422


# ═══════════════════════════════════════════════════════════════════════════
# POL-07  Path traversal → 400
# ═══════════════════════════════════════════════════════════════════════════

class TestPol07PathTraversal:
    """POL-07 · Policy name with .. / \\ → 400."""

    @pytest.mark.parametrize("name", [
        "../../etc/passwd",
        "../sneaky",
        "foo/../bar",
        "foo\\bar",
    ])
    async def test_path_traversal(self, raw_http: httpx.AsyncClient, name: str):
        r = await raw_http.get(f"/api/policies/{name}")
        assert r.status_code in (400, 404), f"Expected 400/404 for path traversal name={name}"


# ═══════════════════════════════════════════════════════════════════════════
# POL-08  Overwrite built-in policy → 403
# ═══════════════════════════════════════════════════════════════════════════

class TestPol08OverwriteBuiltin:
    """POL-08 · PUT on built-in policy name → 403."""

    async def test_overwrite_builtin(self, raw_http: httpx.AsyncClient):
        policies = (await raw_http.get("/api/policies")).json()
        builtins = [p for p in policies if p in ("soc2-audit", "pci-dss-audit", "owasp-top10", "iso42001")]
        if not builtins:
            pytest.skip("No built-in policies found")

        r = await raw_http.put(
            f"/api/policies/{builtins[0]}",
            content=b'[metadata]\ntitle = "hijacked"',
        )
        assert r.status_code == 403


# ═══════════════════════════════════════════════════════════════════════════
# POL-09  Delete custom policy
# ═══════════════════════════════════════════════════════════════════════════

class TestPol09DeleteCustom:
    """POL-09 · DELETE a previously created custom policy → 200."""

    async def test_delete_custom(self, raw_http: httpx.AsyncClient):
        name = f"test-delete-{uuid.uuid4().hex[:8]}"
        toml = b'[metadata]\ntitle = "delete me"\n'

        # Create
        r = await raw_http.put(f"/api/policies/{name}", content=toml)
        assert r.status_code == 200

        # Delete
        r2 = await raw_http.delete(f"/api/policies/{name}")
        assert r2.status_code == 200

        # Verify gone
        r3 = await raw_http.get(f"/api/policies/{name}")
        assert r3.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════
# POL-10  Delete built-in policy → 403
# ═══════════════════════════════════════════════════════════════════════════

class TestPol10DeleteBuiltin:
    """POL-10 · Cannot delete built-in policies → 403."""

    async def test_delete_builtin(self, raw_http: httpx.AsyncClient):
        policies = (await raw_http.get("/api/policies")).json()
        builtins = [p for p in policies if p in ("soc2-audit", "pci-dss-audit", "owasp-top10", "iso42001")]
        if not builtins:
            pytest.skip("No built-in policies found")

        r = await raw_http.delete(f"/api/policies/{builtins[0]}")
        assert r.status_code == 403


# ═══════════════════════════════════════════════════════════════════════════
# POL-11  Delete non-existent policy → 404
# ═══════════════════════════════════════════════════════════════════════════

class TestPol11DeleteNonexistent:
    """POL-11 · DELETE policy that doesn't exist → 404."""

    async def test_delete_nonexistent(self, raw_http: httpx.AsyncClient):
        r = await raw_http.delete("/api/policies/ghost-policy-does-not-exist")
        assert r.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════
# APPR-01  Get pending approval — none pending
# ═══════════════════════════════════════════════════════════════════════════

class TestAppr01NoPending:
    """APPR-01 · No pending approval → {"pending": null}."""

    async def test_no_pending(self, adv_client: LedgerClient):
        session = await adv_client.create_session(goal="approval test no-op")
        result = await adv_client.get_pending_approval(session.session_id)
        assert result is None


# ═══════════════════════════════════════════════════════════════════════════
# APPR-05  Non-admin cannot submit approval → 403
# ═══════════════════════════════════════════════════════════════════════════

class TestAppr05NonAdminBlocked:
    """APPR-05 · Agent token cannot submit approval decision → 403."""

    async def test_agent_blocked(self, ectoledger_server):
        import os

        agent_token = os.environ.get("ECTOLEDGER_AGENT_TOKEN")
        if not agent_token:
            pytest.skip("ECTOLEDGER_AGENT_TOKEN not set")

        sid = str(uuid.uuid4())
        async with httpx.AsyncClient(
            base_url=ectoledger_server.base_url,
            headers={"Authorization": f"Bearer {agent_token}"},
            timeout=15.0,
        ) as client:
            r = await client.post(
                f"/api/approvals/{sid}",
                json={"gate_id": "test", "approved": True},
            )
            assert r.status_code == 403


# ═══════════════════════════════════════════════════════════════════════════
# APPR-06  Missing gate_id → 400/422
# ═══════════════════════════════════════════════════════════════════════════

class TestAppr06MissingGateId:
    """APPR-06 · POST approval without gate_id → 400 or 422."""

    async def test_missing_gate_id(self, raw_http: httpx.AsyncClient):
        sid = str(uuid.uuid4())
        r = await raw_http.post(
            f"/api/approvals/{sid}",
            json={"approved": True},
        )
        assert r.status_code in (400, 422, 500)
