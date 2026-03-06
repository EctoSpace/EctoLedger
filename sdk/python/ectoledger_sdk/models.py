"""Shared Pydantic models matching the Ecto Ledger API response shapes."""

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


# ------------------------------------------------------------------ #
# Core models
# ------------------------------------------------------------------ #

class Session(BaseModel):
    """Represents an agent session returned by the EctoLedger API.

    Field aliases map the server's ``id`` / ``created_at`` names to the
    friendlier ``session_id`` / ``started_at`` names exposed by the SDK.
    ``populate_by_name=True`` allows construction using either name.
    """

    model_config = ConfigDict(populate_by_name=True)

    session_id: str = Field(alias="id")
    goal: str = ""
    goal_hash: str | None = None
    started_at: datetime = Field(alias="created_at")
    finished_at: datetime | None = None
    status: str = ""
    llm_backend: str | None = None
    llm_model: str | None = None
    policy_hash: str | None = None
    session_public_key: str | None = None
    session_did: str | None = None
    enclave_attestation_json: str | None = None


class LedgerEvent(BaseModel):
    """A single immutable event in the append-only ledger.

    Field aliases map the server's native names (``content_hash``,
    ``previous_hash``) to the SDK's public names (``payload_hash``,
    ``prev_hash``).  ``populate_by_name=True`` accepts either form.
    """

    model_config = ConfigDict(populate_by_name=True)

    id: int
    session_id: str | None = None
    payload: Any = None
    payload_hash: str = Field(alias="content_hash")
    prev_hash: str | None = Field(default=None, alias="previous_hash")
    sequence: int
    created_at: datetime
    public_key: str | None = None
    signature: str | None = None


class AppendResult(BaseModel):
    id: int
    payload_hash: str
    sequence: int


class ComplianceBundle(BaseModel):
    """Typed compliance bundle returned by ``prove_compliance()``."""

    session_id: str
    events: list[dict[str, Any]]
    policy_hash: str | None = None
    generated_at: str


class MetricsSummary(BaseModel):
    total_sessions: int = 0
    total_events: int = 0
    extra: dict[str, Any] = Field(default_factory=dict)


class SecurityMetrics(BaseModel):
    injection_attempts_detected_7d: int = 0
    injection_attempts_by_layer: dict[str, int] = Field(default_factory=dict)
    sessions_aborted_circuit_breaker: int = 0
    chain_verification_failures: int = 0


class PendingApproval(BaseModel):
    gate_id: str
    action_name: str
    action_params_summary: str
    created_at: datetime


# ------------------------------------------------------------------ #
# Status
# ------------------------------------------------------------------ #

class StatusResponse(BaseModel):
    demo_mode: bool = False
    version: str = ""


# ------------------------------------------------------------------ #
# Token management
# ------------------------------------------------------------------ #

class TokenListRow(BaseModel):
    token_hash: str
    role: str
    label: str | None = None
    created_at: str
    expires_at: str | None = None


class CreateTokenResponse(BaseModel):
    token: str
    token_hash: str
    role: str
    label: str | None = None


# ------------------------------------------------------------------ #
# Webhook management
# ------------------------------------------------------------------ #

class WebhookListRow(BaseModel):
    id: str
    label: str
    url: str
    siem_format: str = "json"
    filter_kinds: list[str] = Field(default_factory=list)
    enabled: bool = True
    created_at: str


# ------------------------------------------------------------------ #
# Configuration
# ------------------------------------------------------------------ #

class ConfigResponse(BaseModel):
    database_url: str = ""
    llm_backend: str = ""
    ollama_base_url: str = ""
    ollama_model: str = ""
    guard_required: bool = False
    guard_llm_backend: str | None = None
    guard_llm_model: str | None = None
    max_steps: int = 0
    agent_allowed_domains: list[str] = Field(default_factory=list)
    sandbox_mode: str = ""
    evm_enabled: bool = False
    demo_mode: bool = False


# ------------------------------------------------------------------ #
# Tripwire
# ------------------------------------------------------------------ #

class TripwireConfig(BaseModel):
    allowed_paths: list[str] = Field(default_factory=list)
    allowed_domains: list[str] = Field(default_factory=list)
    banned_command_patterns: list[str] = Field(default_factory=list)
    min_justification_length: int = 0
    require_https: bool = False
