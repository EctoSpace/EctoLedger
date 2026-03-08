"""
==========================================================================
SESS-* — Session lifecycle black-box tests
==========================================================================

Covers session creation, listing with filters/pagination, session retrieval
by ID, and session field validation.
"""
from __future__ import annotations

import hashlib
import uuid

import httpx
import pytest

from ectoledger_sdk.client import LedgerClient, LedgerSdkError


# ═══════════════════════════════════════════════════════════════════════════
# SESS-01  Create session with valid goal
# ═══════════════════════════════════════════════════════════════════════════

class TestSess01CreateValid:
    """SESS-01 · POST /api/sessions with valid goal → 200 + running session."""

    async def test_create_session(self, adv_client: LedgerClient):
        session = await adv_client.create_session(goal="Audit SOC2 controls")
        assert session.session_id, "session_id must be non-empty"
        assert session.status in ("running", "completed", "failed", "aborted")
        # Validate UUID format
        uuid.UUID(session.session_id)


# ═══════════════════════════════════════════════════════════════════════════
# SESS-02  Empty goal → 400
# ═══════════════════════════════════════════════════════════════════════════

class TestSess02EmptyGoal:
    """SESS-02 · Empty goal string → 400."""

    async def test_empty_goal(self, raw_http: httpx.AsyncClient):
        r = await raw_http.post("/api/sessions", json={"goal": ""})
        assert r.status_code == 400


# ═══════════════════════════════════════════════════════════════════════════
# SESS-03  Whitespace-only goal → 400
# ═══════════════════════════════════════════════════════════════════════════

class TestSess03WhitespaceGoal:
    """SESS-03 · Whitespace-only goal (trimmed to empty) → 400."""

    async def test_whitespace_goal(self, raw_http: httpx.AsyncClient):
        r = await raw_http.post("/api/sessions", json={"goal": "   \t\n  "})
        assert r.status_code == 400


# ═══════════════════════════════════════════════════════════════════════════
# SESS-04  Missing goal field → 400/422
# ═══════════════════════════════════════════════════════════════════════════

class TestSess04MissingGoal:
    """SESS-04 · No goal field → 400 or 422 (deserialization failure)."""

    async def test_missing_goal(self, raw_http: httpx.AsyncClient):
        r = await raw_http.post("/api/sessions", json={})
        assert r.status_code in (400, 422)


# ═══════════════════════════════════════════════════════════════════════════
# SESS-05  Extra unknown fields are ignored
# ═══════════════════════════════════════════════════════════════════════════

class TestSess05ExtraFields:
    """SESS-05 · Unknown fields in body → 200 (ignored)."""

    async def test_extra_fields(self, raw_http: httpx.AsyncClient):
        r = await raw_http.post(
            "/api/sessions",
            json={"goal": "Extra field test", "foo": "bar", "baz": 42},
        )
        assert r.status_code == 200
        data = r.json()
        assert "id" in data or "session_id" in data


# ═══════════════════════════════════════════════════════════════════════════
# SESS-06  List sessions — no filter
# ═══════════════════════════════════════════════════════════════════════════

class TestSess06ListNoFilter:
    """SESS-06 · GET /api/sessions with defaults → 200, array."""

    async def test_list_sessions(self, adv_client: LedgerClient):
        sessions = await adv_client.list_sessions()
        assert isinstance(sessions, list)


# ═══════════════════════════════════════════════════════════════════════════
# SESS-07  List sessions — filter by status
# ═══════════════════════════════════════════════════════════════════════════

class TestSess07FilterStatus:
    """SESS-07 · ?status=running → only running sessions."""

    async def test_filter_running(self, raw_http: httpx.AsyncClient):
        r = await raw_http.get("/api/sessions", params={"status": "running"})
        assert r.status_code == 200
        for s in r.json():
            assert s.get("status") == "running"


# ═══════════════════════════════════════════════════════════════════════════
# SESS-08  List sessions — invalid status value
# ═══════════════════════════════════════════════════════════════════════════

class TestSess08InvalidStatus:
    """SESS-08 · ?status=invalid_value → 200 empty or 400."""

    async def test_invalid_status(self, raw_http: httpx.AsyncClient):
        r = await raw_http.get("/api/sessions", params={"status": "nonexistent_status"})
        assert r.status_code in (200, 400)
        if r.status_code == 200:
            assert r.json() == []


# ═══════════════════════════════════════════════════════════════════════════
# SESS-09  List sessions — limit=1
# ═══════════════════════════════════════════════════════════════════════════

class TestSess09LimitOne:
    """SESS-09 · ?limit=1 → at most 1 result."""

    async def test_limit_one(self, adv_client: LedgerClient, raw_http: httpx.AsyncClient):
        # Ensure at least one session exists
        await adv_client.create_session(goal="limit test")
        r = await raw_http.get("/api/sessions", params={"limit": 1})
        assert r.status_code == 200
        assert len(r.json()) <= 1


# ═══════════════════════════════════════════════════════════════════════════
# SESS-10  List sessions — limit=0 clamped
# ═══════════════════════════════════════════════════════════════════════════

class TestSess10LimitZero:
    """SESS-10 · ?limit=0 → clamped to 1 (returns at most 1)."""

    async def test_limit_zero(self, raw_http: httpx.AsyncClient):
        r = await raw_http.get("/api/sessions", params={"limit": 0})
        assert r.status_code == 200
        assert len(r.json()) <= 1


# ═══════════════════════════════════════════════════════════════════════════
# SESS-11  List sessions — limit=9999 clamped to 500
# ═══════════════════════════════════════════════════════════════════════════

class TestSess11LimitClamped:
    """SESS-11 · ?limit=9999 → clamped to 500 (no crash)."""

    async def test_limit_clamped(self, raw_http: httpx.AsyncClient):
        r = await raw_http.get("/api/sessions", params={"limit": 9999})
        assert r.status_code == 200
        assert len(r.json()) <= 500


# ═══════════════════════════════════════════════════════════════════════════
# SESS-12  List sessions — offset pagination
# ═══════════════════════════════════════════════════════════════════════════

class TestSess12OffsetPagination:
    """SESS-12 · ?limit=5&offset=5 → second page, no overlap with first."""

    async def test_offset(self, raw_http: httpx.AsyncClient):
        page1 = await raw_http.get("/api/sessions", params={"limit": 5, "offset": 0})
        page2 = await raw_http.get("/api/sessions", params={"limit": 5, "offset": 5})
        assert page1.status_code == 200
        assert page2.status_code == 200

        ids1 = {s.get("id") or s.get("session_id") for s in page1.json()}
        ids2 = {s.get("id") or s.get("session_id") for s in page2.json()}
        assert ids1.isdisjoint(ids2), "pages should not overlap"


# ═══════════════════════════════════════════════════════════════════════════
# SESS-13  List sessions — negative offset
# ═══════════════════════════════════════════════════════════════════════════

class TestSess13NegativeOffset:
    """SESS-13 · ?offset=-1 → clamped to 0 or 400."""

    async def test_negative_offset(self, raw_http: httpx.AsyncClient):
        r = await raw_http.get("/api/sessions", params={"offset": -1})
        assert r.status_code in (200, 400)


# ═══════════════════════════════════════════════════════════════════════════
# SESS-14  Get session by valid ID
# ═══════════════════════════════════════════════════════════════════════════

class TestSess14GetById:
    """SESS-14 · GET /api/sessions/{id} for valid session → 200."""

    async def test_get_by_id(self, adv_client: LedgerClient, raw_http: httpx.AsyncClient):
        session = await adv_client.create_session(goal="get-by-id test")
        r = await raw_http.get(f"/api/sessions/{session.session_id}")
        assert r.status_code == 200
        data = r.json()
        sid = data.get("id") or data.get("session_id")
        assert sid == session.session_id


# ═══════════════════════════════════════════════════════════════════════════
# SESS-15  Get session — non-existent UUID → 404
# ═══════════════════════════════════════════════════════════════════════════

class TestSess15NotFound:
    """SESS-15 · GET /api/sessions/<random-uuid> → 404."""

    async def test_not_found(self, raw_http: httpx.AsyncClient):
        fake_id = str(uuid.uuid4())
        r = await raw_http.get(f"/api/sessions/{fake_id}")
        assert r.status_code == 404


# ═══════════════════════════════════════════════════════════════════════════
# SESS-16  Get session — malformed ID
# ═══════════════════════════════════════════════════════════════════════════

class TestSess16MalformedId:
    """SESS-16 · GET /api/sessions/not-a-uuid → 400 or 404."""

    async def test_malformed_id(self, raw_http: httpx.AsyncClient):
        r = await raw_http.get("/api/sessions/not-a-uuid")
        assert r.status_code in (400, 404, 422)


# ═══════════════════════════════════════════════════════════════════════════
# SESS-17  goal_hash == SHA-256(goal)
# ═══════════════════════════════════════════════════════════════════════════

class TestSess17GoalHash:
    """SESS-17 · goal_hash field matches SHA-256 of the goal text."""

    async def test_goal_hash(self, raw_http: httpx.AsyncClient):
        goal = "Verify goal hash computation"
        r = await raw_http.post("/api/sessions", json={"goal": goal})
        assert r.status_code == 200
        data = r.json()
        goal_hash = data.get("goal_hash")
        if goal_hash:
            expected = hashlib.sha256(goal.encode()).hexdigest()
            assert goal_hash == expected, f"goal_hash mismatch: {goal_hash} != {expected}"
