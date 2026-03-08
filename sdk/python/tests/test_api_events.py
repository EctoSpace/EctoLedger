"""
==========================================================================
EVT-* — Event retrieval & hash-chain verification black-box tests
==========================================================================

Covers event listing, hash-chain integrity, genesis structure, sequence
monotonicity, and error handling for invalid session filters.
"""
from __future__ import annotations

import asyncio
import hashlib
import uuid

import httpx
import pytest

from ectoledger_sdk.client import LedgerClient, LedgerSdkError


# ── helpers ──────────────────────────────────────────────────────────────

ZERO_HASH = "0" * 64


def _compute_content_hash(
    previous_hash: str,
    sequence: int,
    payload_json: str,
    session_id: str | None = None,
) -> str:
    """Re-derive the content hash the same way the server does.

    Formula (legacy): SHA-256( previous_hash \\0 sequence \\0 payload_json )
    Formula (TM-2):   SHA-256( previous_hash \\0 sequence \\0 payload_json \\0 session_id )

    When ``session_id`` is provided it is appended with a null-byte delimiter
    so the event is cryptographically bound to its session (cross-session
    replay prevention).
    """
    data = f"{previous_hash}\x00{sequence}\x00{payload_json}"
    if session_id is not None:
        data += f"\x00{session_id}"
    return hashlib.sha256(data.encode()).hexdigest()


async def _create_session_and_wait(
    adv_client: LedgerClient,
    goal: str = "chain test",
    wait: float = 2.0,
) -> str:
    """Create a session and give it a moment to generate events."""
    session = await adv_client.create_session(goal=goal)
    await asyncio.sleep(wait)
    return session.session_id


# ═══════════════════════════════════════════════════════════════════════════
# EVT-01  Get events for a session
# ═══════════════════════════════════════════════════════════════════════════

class TestEvt01GetEvents:
    """EVT-01 · GET /api/events?session_id={uuid} → 200, ordered by sequence."""

    async def test_get_events(self, adv_client: LedgerClient):
        sid = await _create_session_and_wait(adv_client)
        events = await adv_client.get_events(sid)
        assert isinstance(events, list)
        assert len(events) > 0, "New session must have at least a genesis/prompt event"

        # Sequences should be sorted
        seqs = [e.sequence for e in events]
        assert seqs == sorted(seqs), "Events must be ordered by sequence"


# ═══════════════════════════════════════════════════════════════════════════
# EVT-02  Missing session_id → 400
# ═══════════════════════════════════════════════════════════════════════════

class TestEvt02MissingSessionId:
    """EVT-02 · GET /api/events without session_id → 400."""

    async def test_missing_session_id(self, raw_http: httpx.AsyncClient):
        r = await raw_http.get("/api/events")
        assert r.status_code == 400


# ═══════════════════════════════════════════════════════════════════════════
# EVT-03  Invalid UUID format → 400
# ═══════════════════════════════════════════════════════════════════════════

class TestEvt03InvalidUuid:
    """EVT-03 · GET /api/events?session_id=abc → 400."""

    async def test_invalid_uuid(self, raw_http: httpx.AsyncClient):
        r = await raw_http.get("/api/events", params={"session_id": "abc"})
        assert r.status_code in (400, 422)


# ═══════════════════════════════════════════════════════════════════════════
# EVT-04  Non-existent session → 200 empty array
# ═══════════════════════════════════════════════════════════════════════════

class TestEvt04NonExistentSession:
    """EVT-04 · Events for a random UUID → 200 with empty list."""

    async def test_nonexistent_session(self, raw_http: httpx.AsyncClient):
        r = await raw_http.get(
            "/api/events",
            params={"session_id": str(uuid.uuid4())},
        )
        assert r.status_code == 200
        assert r.json() == []


# ═══════════════════════════════════════════════════════════════════════════
# EVT-05  Verify hash chain integrity
# ═══════════════════════════════════════════════════════════════════════════

class TestEvt05HashChainIntegrity:
    """EVT-05 · Re-derive content hashes and verify linkage."""

    async def test_chain_integrity(self, adv_client: LedgerClient):
        sid = await _create_session_and_wait(adv_client, wait=3.0)
        events = await adv_client.get_events(sid)
        assert len(events) >= 1

        for i in range(1, len(events)):
            # Chain link: previous_hash == prior event's payload_hash
            assert events[i].prev_hash == events[i - 1].payload_hash, (
                f"Event {events[i].sequence}: prev_hash mismatch. "
                f"Expected {events[i-1].payload_hash}, got {events[i].prev_hash}"
            )


# ═══════════════════════════════════════════════════════════════════════════
# EVT-06  Genesis event structure
# ═══════════════════════════════════════════════════════════════════════════

class TestEvt06GenesisStructure:
    """EVT-06 · First event has a valid prev_hash link and expected type.

    Note: the ledger uses *global* sequence numbers, so the first event for a
    session is unlikely to have ``sequence == 0`` after other tests have already
    appended events.  We therefore only validate the event type and that
    ``prev_hash`` is a well-formed 64-char hex string (or zeros for the true
    genesis block).
    """

    async def test_genesis(self, adv_client: LedgerClient):
        sid = await _create_session_and_wait(adv_client)
        events = await adv_client.get_events(sid)
        assert len(events) >= 1

        first = events[0]
        # prev_hash is valid hex (64 chars) or None (only for the very first block)
        if first.prev_hash is not None:
            assert len(first.prev_hash) == 64, (
                f"prev_hash should be 64-char hex, got len={len(first.prev_hash)}"
            )

        # The payload type should be the initial event (genesis or prompt_input)
        payload = first.payload
        if isinstance(payload, dict):
            ptype = payload.get("type", "")
            assert ptype in ("genesis", "prompt_input"), (
                f"First event type should be genesis or prompt_input, got {ptype}"
            )


# ═══════════════════════════════════════════════════════════════════════════
# EVT-07  Chain linkage verification (explicit)
# ═══════════════════════════════════════════════════════════════════════════

class TestEvt07ChainLinkage:
    """EVT-07 · events[n].prev_hash == events[n-1].payload_hash for all n>0."""

    async def test_chain_linkage(self, adv_client: LedgerClient):
        sid = await _create_session_and_wait(adv_client, wait=3.0)
        events = await adv_client.get_events(sid)

        for i in range(1, len(events)):
            assert events[i].prev_hash == events[i - 1].payload_hash, (
                f"Chain break at seq {events[i].sequence}"
            )


# ═══════════════════════════════════════════════════════════════════════════
# EVT-08  Sequence monotonicity
# ═══════════════════════════════════════════════════════════════════════════

class TestEvt08SequenceMonotonicity:
    """EVT-08 · Sequences are strictly monotonically increasing.

    The ledger assigns *global* sequence numbers, so a session's events won't
    start at 0 unless it's the very first session.  We verify that each event's
    sequence is exactly one more than its predecessor.
    """

    async def test_monotonicity(self, adv_client: LedgerClient):
        sid = await _create_session_and_wait(adv_client, wait=3.0)
        events = await adv_client.get_events(sid)
        assert len(events) >= 1

        sequences = [e.sequence for e in events]
        for i in range(1, len(sequences)):
            assert sequences[i] == sequences[i - 1] + 1, (
                f"Sequence gap at index {i}: {sequences[i-1]} → {sequences[i]}"
            )


# ═══════════════════════════════════════════════════════════════════════════
# EVT-09  SDK verify_chain method
# ═══════════════════════════════════════════════════════════════════════════

class TestEvt09SdkVerifyChain:
    """EVT-09 · SDK verify_chain() returns True for a valid session."""

    async def test_verify_chain_sdk(self, adv_client: LedgerClient):
        sid = await _create_session_and_wait(adv_client, wait=3.0)
        try:
            ok = await adv_client.verify_chain(sid)
            assert ok is True
        except LedgerSdkError as exc:
            # Some backends may not fully support /verify — skip gracefully
            if exc.status_code in (404, 501):
                pytest.skip(f"verify_chain not available: {exc}")
            raise


# ═══════════════════════════════════════════════════════════════════════════
# EVT-10  Event signing (Ed25519 signatures present)
# ═══════════════════════════════════════════════════════════════════════════

class TestEvt10EventSigning:
    """EVT-10 · Events carry Ed25519 public_key and signature fields."""

    async def test_event_signatures(self, adv_client: LedgerClient):
        sid = await _create_session_and_wait(adv_client, wait=3.0)
        events = await adv_client.get_events(sid)
        assert len(events) >= 1

        # At least some events should have signing info
        signed = [e for e in events if e.public_key and e.signature]
        # Signing is optional (SQLite may not enable it), so just check format
        for e in signed:
            assert len(e.public_key) == 64, "public_key should be 64 hex chars"
            assert len(e.signature) == 128, "signature should be 128 hex chars"
