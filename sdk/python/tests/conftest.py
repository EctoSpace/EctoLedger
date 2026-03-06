"""Shared pytest fixtures for the Ecto Ledger Python SDK test suite."""
from __future__ import annotations

import pytest

pytest_plugins = ["conftest_adversarial"]

BASE_URL = "http://localhost:3000"
SESSION_ID = "550e8400-e29b-41d4-a716-446655440000"


@pytest.fixture
def base_url() -> str:
    return BASE_URL


@pytest.fixture
def session_id() -> str:
    return SESSION_ID


@pytest.fixture
def sample_session() -> dict:
    return {
        "session_id": SESSION_ID,
        "goal_hash": "abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
        "started_at": "2026-02-22T10:00:00Z",
        "finished_at": None,
        "status": "running",
        "session_did": None,
    }


@pytest.fixture
def sample_session_finished() -> dict:
    return {
        "session_id": SESSION_ID,
        "goal_hash": "abc123def456abc123def456abc123def456abc123def456abc123def456abcd",
        "started_at": "2026-02-22T10:00:00Z",
        "finished_at": "2026-02-22T11:00:00Z",
        "status": "completed",
        "session_did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    }


@pytest.fixture
def sample_event() -> dict:
    return {
        "id": 1,
        "session_id": SESSION_ID,
        "payload": {"type": "thought", "content": "Processing..."},
        "payload_hash": "deadbeef01234567deadbeef01234567deadbeef01234567deadbeef01234567",
        "prev_hash": None,
        "sequence": 0,
        "created_at": "2026-02-22T10:00:01Z",
        "public_key": None,
        "signature": None,
    }


@pytest.fixture
def sample_event_signed(sample_event: dict) -> dict:
    return {
        **sample_event,
        "id": 2,
        "sequence": 1,
        "prev_hash": sample_event["payload_hash"],
        "public_key": "a" * 64,
        "signature": "b" * 128,
    }


@pytest.fixture
def sample_append_result() -> dict:
    return {"id": 42, "payload_hash": "cafebabe01234567cafebabe01234567cafebabe01234567cafebabe01234567", "sequence": 1}


@pytest.fixture
def sample_metrics() -> dict:
    return {"total_sessions": 7, "total_events": 130}
