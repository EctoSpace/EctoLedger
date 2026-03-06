"""Tests for Pydantic model construction, validation, and serialisation."""
from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from ectoledger_sdk.models import (
    AppendResult,
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


# ---------------------------------------------------------------------------
# Session
# ---------------------------------------------------------------------------

class TestSession:
    def test_minimal_session(self) -> None:
        session = Session(session_id="s1", goal_hash="gh1", started_at=datetime.now(tz=timezone.utc), status="running")
        assert session.finished_at is None
        assert session.session_did is None

    def test_full_session(self, sample_session_finished: dict) -> None:
        session = Session.model_validate(sample_session_finished)
        assert session.status == "completed"
        assert session.finished_at is not None
        assert session.session_did is not None

    def test_started_at_parsed_from_iso_string(self) -> None:
        session = Session.model_validate({"session_id": "s1", "goal_hash": "g1", "started_at": "2026-02-22T10:00:00Z", "status": "running"})
        assert isinstance(session.started_at, datetime)

    def test_started_at_must_be_present(self) -> None:
        with pytest.raises(ValidationError):
            Session.model_validate({"session_id": "s1", "goal_hash": "g1", "status": "running"})

    def test_session_round_trip_serialisation(self, sample_session: dict) -> None:
        session = Session.model_validate(sample_session)
        dumped = session.model_dump(mode="json")
        restored = Session.model_validate(dumped)
        assert restored.session_id == session.session_id
        assert restored.goal_hash == session.goal_hash


# ---------------------------------------------------------------------------
# LedgerEvent
# ---------------------------------------------------------------------------

class TestLedgerEvent:
    def test_minimal_event(self) -> None:
        event = LedgerEvent(id=1, session_id="s1", payload={"type": "thought", "content": "x"}, payload_hash="h", prev_hash=None, sequence=0, created_at=datetime.now(tz=timezone.utc))
        assert event.public_key is None
        assert event.signature is None

    def test_event_with_signature(self, sample_event_signed: dict) -> None:
        event = LedgerEvent.model_validate(sample_event_signed)
        assert event.public_key is not None
        assert event.signature is not None
        assert event.prev_hash is not None

    def test_event_payload_can_be_arbitrary_json(self) -> None:
        event = LedgerEvent.model_validate({"id": 1, "session_id": "s", "payload": {"type": "action", "name": "run_command", "params": {"command": "ls"}}, "payload_hash": "h", "prev_hash": None, "sequence": 0, "created_at": "2026-02-22T10:00:00Z"})
        assert event.payload["name"] == "run_command"

    def test_event_missing_required_field_raises(self) -> None:
        """Omitting the ``content_hash`` / ``payload_hash`` field must fail."""
        with pytest.raises(ValidationError):
            LedgerEvent.model_validate({"id": 1, "sequence": 0, "created_at": "2026-02-22T10:00:00Z"})

    def test_event_sequence_is_integer(self, sample_event: dict) -> None:
        event = LedgerEvent.model_validate(sample_event)
        assert isinstance(event.sequence, int)


# ---------------------------------------------------------------------------
# AppendResult
# ---------------------------------------------------------------------------

class TestAppendResult:
    def test_valid_append_result(self) -> None:
        result = AppendResult(id=1, payload_hash="deadbeef", sequence=0)
        assert result.id == 1

    def test_append_result_from_dict(self, sample_append_result: dict) -> None:
        result = AppendResult.model_validate(sample_append_result)
        assert result.sequence == sample_append_result["sequence"]
        assert result.payload_hash == sample_append_result["payload_hash"]

    def test_append_result_missing_field_raises(self) -> None:
        with pytest.raises(ValidationError):
            AppendResult.model_validate({"id": 1, "sequence": 0})

    def test_append_result_round_trip(self, sample_append_result: dict) -> None:
        result = AppendResult.model_validate(sample_append_result)
        assert AppendResult.model_validate(result.model_dump()).id == result.id


# ---------------------------------------------------------------------------
# MetricsSummary
# ---------------------------------------------------------------------------

class TestMetricsSummary:
    def test_defaults(self) -> None:
        metrics = MetricsSummary()
        assert metrics.total_sessions == 0
        assert metrics.total_events == 0
        assert metrics.extra == {}

    def test_populated(self, sample_metrics: dict) -> None:
        metrics = MetricsSummary.model_validate(sample_metrics)
        assert metrics.total_sessions == 7
        assert metrics.total_events == 130

    def test_extra_fields_captured_in_extra(self) -> None:
        # Pydantic v2 ignores unknown keys by default; the `extra` field must be
        # populated explicitly by the server (i.e. as a key named "extra" in the
        # JSON response).  Unknown top-level keys are silently discarded.
        metrics = MetricsSummary.model_validate({"total_sessions": 1, "total_events": 5, "custom_counter": 99})
        assert metrics.extra == {}

    def test_empty_dict_uses_defaults(self) -> None:
        metrics = MetricsSummary.model_validate({})
        assert metrics.total_sessions == 0


# ---------------------------------------------------------------------------
# SecurityMetrics
# ---------------------------------------------------------------------------

class TestSecurityMetrics:
    def test_defaults(self) -> None:
        sm = SecurityMetrics()
        assert sm.injection_attempts_detected_7d == 0
        assert sm.injection_attempts_by_layer == {}
        assert sm.sessions_aborted_circuit_breaker == 0
        assert sm.chain_verification_failures == 0

    def test_populated(self) -> None:
        sm = SecurityMetrics.model_validate({"injection_attempts_detected_7d": 5, "injection_attempts_by_layer": {"tripwire": 3, "guard_llm": 2}, "sessions_aborted_circuit_breaker": 1, "chain_verification_failures": 0})
        assert sm.injection_attempts_detected_7d == 5
        assert sm.injection_attempts_by_layer["tripwire"] == 3


# ---------------------------------------------------------------------------
# PendingApproval
# ---------------------------------------------------------------------------

class TestPendingApproval:
    def test_valid_pending(self) -> None:
        pa = PendingApproval.model_validate({"gate_id": "g1", "action_name": "run_command", "action_params_summary": "ls -la", "created_at": "2026-02-22T10:00:00Z"})
        assert pa.gate_id == "g1"
        assert pa.action_name == "run_command"

    def test_missing_field_raises(self) -> None:
        with pytest.raises(ValidationError):
            PendingApproval.model_validate({"gate_id": "g1"})


# ---------------------------------------------------------------------------
# StatusResponse
# ---------------------------------------------------------------------------

class TestStatusResponse:
    def test_defaults(self) -> None:
        sr = StatusResponse()
        assert sr.demo_mode is False
        assert sr.version == ""

    def test_populated(self) -> None:
        sr = StatusResponse.model_validate({"demo_mode": True, "version": "0.6.2"})
        assert sr.demo_mode is True
        assert sr.version == "0.6.2"


# ---------------------------------------------------------------------------
# TokenListRow
# ---------------------------------------------------------------------------

class TestTokenListRow:
    def test_valid_token(self) -> None:
        t = TokenListRow.model_validate({"token_hash": "abc123", "role": "Admin", "label": "CI token", "created_at": "2026-01-01T00:00:00Z", "expires_at": None})
        assert t.role == "Admin"
        assert t.label == "CI token"

    def test_missing_role_raises(self) -> None:
        with pytest.raises(ValidationError):
            TokenListRow.model_validate({"token_hash": "abc123", "created_at": "2026-01-01T00:00:00Z"})


# ---------------------------------------------------------------------------
# CreateTokenResponse
# ---------------------------------------------------------------------------

class TestCreateTokenResponse:
    def test_valid_response(self) -> None:
        ct = CreateTokenResponse.model_validate({"token": "raw-secret", "token_hash": "hashed", "role": "Agent", "label": None})
        assert ct.token == "raw-secret"
        assert ct.role == "Agent"


# ---------------------------------------------------------------------------
# WebhookListRow
# ---------------------------------------------------------------------------

class TestWebhookListRow:
    def test_valid_webhook(self) -> None:
        w = WebhookListRow.model_validate({"id": "wh-1", "label": "Slack", "url": "https://hooks.slack.com/x", "siem_format": "json", "filter_kinds": ["alert"], "enabled": True, "created_at": "2026-01-01T00:00:00Z"})
        assert w.label == "Slack"
        assert w.filter_kinds == ["alert"]

    def test_defaults(self) -> None:
        w = WebhookListRow.model_validate({"id": "wh-2", "label": "Splunk", "url": "https://splunk.example.com", "created_at": "2026-01-01T00:00:00Z"})
        assert w.siem_format == "json"
        assert w.filter_kinds == []
        assert w.enabled is True


# ---------------------------------------------------------------------------
# ConfigResponse
# ---------------------------------------------------------------------------

class TestConfigResponse:
    def test_defaults(self) -> None:
        c = ConfigResponse()
        assert c.database_url == ""
        assert c.max_steps == 0
        assert c.agent_allowed_domains == []

    def test_populated(self) -> None:
        c = ConfigResponse.model_validate({"database_url": "sqlite://db.sqlite", "llm_backend": "ollama", "ollama_base_url": "http://localhost:11434", "ollama_model": "llama3", "guard_required": True, "max_steps": 50, "agent_allowed_domains": ["example.com"], "sandbox_mode": "docker", "demo_mode": False})
        assert c.llm_backend == "ollama"
        assert c.guard_required is True
        assert c.max_steps == 50


# ---------------------------------------------------------------------------
# TripwireConfig
# ---------------------------------------------------------------------------

class TestTripwireConfig:
    def test_defaults(self) -> None:
        t = TripwireConfig()
        assert t.allowed_paths == []
        assert t.min_justification_length == 0
        assert t.require_https is False

    def test_populated(self) -> None:
        t = TripwireConfig.model_validate({"allowed_paths": ["/tmp"], "allowed_domains": ["example.com"], "banned_command_patterns": ["rm -rf"], "min_justification_length": 10, "require_https": True})
        assert t.allowed_paths == ["/tmp"]
        assert t.banned_command_patterns == ["rm -rf"]
        assert t.require_https is True
