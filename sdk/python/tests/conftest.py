"""Shared pytest fixtures for the EctoLedger Python SDK test suite."""
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


# Realistic SHA-256 hash of the goal string "Perform SOC 2 compliance audit of staging environment"
GOAL_HASH = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
# Ed25519 public key (32 bytes hex-encoded)
ED25519_PUBKEY = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa3f4a18446b0b8d1801f17"
# Ed25519 signature (64 bytes hex-encoded)
ED25519_SIGNATURE = (
    "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
    "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
)


@pytest.fixture
def sample_session() -> dict:
    return {
        "session_id": SESSION_ID,
        "goal_hash": GOAL_HASH,
        "started_at": "2026-02-22T10:00:00Z",
        "finished_at": None,
        "status": "running",
        "session_did": None,
    }


@pytest.fixture
def sample_session_finished() -> dict:
    return {
        "session_id": SESSION_ID,
        "goal_hash": GOAL_HASH,
        "started_at": "2026-02-22T10:00:00Z",
        "finished_at": "2026-02-22T11:00:00Z",
        "status": "completed",
        "session_did": "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
    }


# SHA-256 of the genesis event payload
GENESIS_CONTENT_HASH = "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
# SHA-256 of the second event payload (chained from genesis)
EVENT_1_CONTENT_HASH = "2c624232cdd221771294dfbb310aca000462b31802e26ad0a0f5f6c4e7f2e08b"


@pytest.fixture
def sample_event() -> dict:
    return {
        "id": 1,
        "session_id": SESSION_ID,
        "payload": {"type": "thought", "content": "Enumerating open ports on target host"},
        "payload_hash": GENESIS_CONTENT_HASH,
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
        "public_key": ED25519_PUBKEY,
        "signature": ED25519_SIGNATURE,
    }


@pytest.fixture
def sample_append_result() -> dict:
    return {"id": 42, "payload_hash": EVENT_1_CONTENT_HASH, "sequence": 1}


@pytest.fixture
def sample_metrics() -> dict:
    return {"total_sessions": 7, "total_events": 130}
