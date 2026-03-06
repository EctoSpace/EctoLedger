"""LedgerClient — async-first REST client for Ecto Ledger."""

import httpx
from typing import Any, AsyncIterator
from urllib.parse import quote

from ectoledger_sdk.models import (
    AppendResult,
    ComplianceBundle,
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


class LedgerSdkError(Exception):
    """Raised when the Ecto Ledger API returns an unexpected or non-JSON response.

    Attributes
    ----------
    status_code:
        HTTP status code of the response, or ``None`` when no HTTP response
        was received (e.g. a network error before the server replied).
    body:
        Raw response body text, or ``None`` if unavailable.
    """

    def __init__(self, message: str, *, status_code: int | None = None, body: str | None = None) -> None:
        super().__init__(message)
        self.status_code = status_code
        self.body = body


class LedgerClient:
    """Async REST client for the Ecto Ledger API.

    Usage::

        async with LedgerClient("http://localhost:3000") as client:
            sessions = await client.list_sessions()

    .. warning::
        The ``base_url`` parameter defaults to ``http://localhost:3000``, which
        works for local development only.  In containerised or remote environments
        you **must** pass the correct service URL explicitly::

            LedgerClient(base_url="http://ectoledger-host:3000", bearer_token="...")

        Omitting ``base_url`` in Docker Compose / Kubernetes will cause every
        method to fail with a connection-refused error against the loopback
        address inside the calling container.
    """

    def __init__(
        self,
        base_url: str = "http://localhost:3000",
        *,
        bearer_token: str | None = None,
        timeout: float = 30.0,
    ) -> None:
        headers: dict[str, str] = {}
        if bearer_token:
            headers["Authorization"] = f"Bearer {bearer_token}"
        self._client = httpx.AsyncClient(
            base_url=base_url,
            headers=headers,
            timeout=timeout,
        )

    async def close(self) -> None:
        await self._client.aclose()

    async def __aenter__(self) -> "LedgerClient":
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.close()

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    @staticmethod
    def _check(r: httpx.Response, context: str = "") -> None:
        """Raise :class:`LedgerSdkError` for any non-2xx response."""
        try:
            r.raise_for_status()
        except httpx.HTTPStatusError as exc:
            body: str | None = None
            try:
                body = exc.response.text
            except Exception:
                pass
            label = f"{context}: " if context else ""
            raise LedgerSdkError(f"{label}HTTP {exc.response.status_code}", status_code=exc.response.status_code, body=body) from exc

    @staticmethod
    def _parse_json(r: httpx.Response, context: str = "") -> Any:
        """Decode JSON from *r*, wrapping decode errors in :class:`LedgerSdkError`."""
        try:
            return r.json()
        except (ValueError, TypeError) as exc:
            label = f"{context}: " if context else ""
            raise LedgerSdkError(f"{label}server returned non-JSON body", status_code=r.status_code, body=r.text) from exc

    # ------------------------------------------------------------------ #
    # Sessions
    # ------------------------------------------------------------------ #

    async def list_sessions(
        self,
        limit: int = 50,
        offset: int | None = None,
        status: str | None = None,
    ) -> list[Session]:
        """Return the most recent *limit* sessions."""
        params: dict[str, Any] = {"limit": limit}
        if offset is not None:
            params["offset"] = offset
        if status is not None:
            params["status"] = status
        r = await self._client.get("/api/sessions", params=params)
        self._check(r, "list_sessions")
        return [Session.model_validate(s) for s in self._parse_json(r, "list_sessions")]

    async def create_session(
        self,
        goal: str,
        policy_hash: str | None = None,
        session_did: str | None = None,
    ) -> Session:
        """Open a new agent session (returns full Session object)."""
        body: dict = {"goal": goal}
        if policy_hash:
            body["policy_hash"] = policy_hash
        if session_did:
            body["session_did"] = session_did
        r = await self._client.post("/api/sessions", json=body)
        self._check(r, "create_session")
        return Session.model_validate(self._parse_json(r, "create_session"))

    async def seal_session(self, session_id: str) -> None:
        """Mark a session as finished."""
        r = await self._client.post(f"/api/sessions/{quote(session_id, safe='')}/seal")
        self._check(r, "seal_session")

    # ------------------------------------------------------------------ #
    # Events
    # ------------------------------------------------------------------ #

    async def get_events(self, session_id: str) -> list[LedgerEvent]:
        """Fetch all events belonging to *session_id*."""
        r = await self._client.get("/api/events", params={"session_id": session_id})
        self._check(r, "get_events")
        return [LedgerEvent.model_validate(e) for e in self._parse_json(r, "get_events")]

    async def append_event(
        self,
        session_id: str,
        payload: dict,
    ) -> AppendResult:
        """Append a single event and return the hash + sequence number."""
        r = await self._client.post(
            f"/api/sessions/{quote(session_id, safe='')}/events",
            json=payload,
        )
        self._check(r, "append_event")
        return AppendResult.model_validate(self._parse_json(r, "append_event"))

    # ------------------------------------------------------------------ #
    # Chain verification
    # ------------------------------------------------------------------ #

    async def verify_chain(self, session_id: str) -> bool:
        """Return ``True`` if the hash chain for *session_id* is intact."""
        r = await self._client.get(f"/api/sessions/{quote(session_id, safe='')}/verify")
        self._check(r, "verify_chain")
        data = self._parse_json(r, "verify_chain")
        return bool(data.get("ok", False))

    # ------------------------------------------------------------------ #
    # Compliance & certificates
    # ------------------------------------------------------------------ #

    async def prove_compliance(self, session_id: str) -> ComplianceBundle:
        """Return a typed compliance bundle (hashes, signatures, policy).

        Raises
        ------
        LedgerSdkError
            If the server returns a non-2xx status or a non-JSON body.
        """
        r = await self._client.get(f"/api/sessions/{quote(session_id, safe='')}/compliance")
        self._check(r, "prove_compliance")
        return ComplianceBundle.model_validate(self._parse_json(r, "prove_compliance"))

    async def export_certificate(self, session_id: str) -> bytes:
        """Download the .elc audit certificate for *session_id*."""
        r = await self._client.get(f"/api/certificates/{quote(session_id, safe='')}")
        self._check(r, "export_certificate")
        return r.content

    async def get_report(self, session_id: str) -> dict:
        """Download the JSON audit report for *session_id*."""
        r = await self._client.get(f"/api/reports/{quote(session_id, safe='')}")
        self._check(r, "get_report")
        return self._parse_json(r, "get_report")

    # ------------------------------------------------------------------ #
    # Verifiable Credentials
    # ------------------------------------------------------------------ #

    async def get_session_vc(self, session_id: str) -> dict:
        """Retrieve the VC-JWT and decoded payload for a completed session."""
        r = await self._client.get(f"/api/sessions/{quote(session_id, safe='')}/vc")
        self._check(r, "get_session_vc")
        return self._parse_json(r, "get_session_vc")

    async def verify_session_vc(self, session_id: str) -> dict:
        """Verify the VC-JWT for a completed session.

        Returns a dict with ``"valid": true/false`` and optional ``"reason"``
        or ``"vc_payload"`` fields.
        """
        r = await self._client.get(f"/api/sessions/{quote(session_id, safe='')}/vc/verify")
        self._check(r, "verify_session_vc")
        return self._parse_json(r, "verify_session_vc")

    # ------------------------------------------------------------------ #
    # Metrics
    # ------------------------------------------------------------------ #

    async def get_metrics(self) -> MetricsSummary:
        """Fetch Prometheus-compatible metrics as a parsed summary object."""
        r = await self._client.get("/api/metrics")
        self._check(r, "get_metrics")
        return MetricsSummary.model_validate(self._parse_json(r, "get_metrics"))

    async def get_security_metrics(self) -> SecurityMetrics:
        """Fetch structured security metrics (injection attempts, circuit breaker, etc.)."""
        r = await self._client.get("/api/metrics/security")
        self._check(r, "get_security_metrics")
        return SecurityMetrics.model_validate(self._parse_json(r, "get_security_metrics"))

    async def get_prometheus_metrics(self) -> str:
        """Return raw Prometheus exposition text."""
        r = await self._client.get("/metrics")
        self._check(r, "get_prometheus_metrics")
        return r.text

    # ------------------------------------------------------------------ #
    # Policies
    # ------------------------------------------------------------------ #

    async def list_policies(self) -> list[str]:
        """Return a list of available policy names.

        Raises
        ------
        LedgerSdkError
            If the server returns a non-2xx status or a non-JSON body.
        """
        r = await self._client.get("/api/policies")
        self._check(r, "list_policies")
        return self._parse_json(r, "list_policies")

    async def get_policy(self, name: str) -> str:
        """Return the raw content of a named policy file."""
        r = await self._client.get(f"/api/policies/{quote(name, safe='')}")
        self._check(r, "get_policy")
        return r.text

    async def save_policy(self, name: str, content: str) -> None:
        """Overwrite a policy file on the server."""
        r = await self._client.put(
            f"/api/policies/{quote(name, safe='')}",
            content=content.encode(),
            headers={"Content-Type": "text/plain; charset=utf-8"},
        )
        self._check(r, "save_policy")

    async def delete_policy(self, name: str) -> None:
        """Delete a policy file from the server."""
        r = await self._client.delete(f"/api/policies/{quote(name, safe='')}")
        self._check(r, "delete_policy")

    # ------------------------------------------------------------------ #
    # Approval gates (human-in-the-loop)
    # ------------------------------------------------------------------ #

    async def get_pending_approval(self, session_id: str) -> PendingApproval | None:
        """Check for a pending approval gate on *session_id*.

        Returns a :class:`PendingApproval` if a gate is active, or ``None``.
        """
        r = await self._client.get(f"/api/approvals/{quote(session_id, safe='')}/pending")
        self._check(r, "get_pending_approval")
        data = self._parse_json(r, "get_pending_approval")
        pending = data.get("pending") if isinstance(data, dict) else None
        if pending is None:
            return None
        return PendingApproval.model_validate(pending)

    async def post_approval_decision(
        self,
        session_id: str,
        gate_id: str,
        approved: bool,
        reason: str | None = None,
    ) -> None:
        """Submit an approve/deny decision for a pending approval gate."""
        body: dict = {"gate_id": gate_id, "approved": approved}
        if reason is not None:
            body["reason"] = reason
        r = await self._client.post(f"/api/approvals/{quote(session_id, safe='')}", json=body)
        self._check(r, "post_approval_decision")

    # ------------------------------------------------------------------ #
    # Status & chat
    # ------------------------------------------------------------------ #

    async def get_status(self) -> StatusResponse:
        """Return the server status (demo mode, version, etc.)."""
        r = await self._client.get("/api/status")
        self._check(r, "get_status")
        return StatusResponse.model_validate(self._parse_json(r, "get_status"))

    async def get_session(self, session_id: str) -> Session:
        """Fetch a single session by its ID."""
        r = await self._client.get(f"/api/sessions/{quote(session_id, safe='')}")
        self._check(r, "get_session")
        return Session.model_validate(self._parse_json(r, "get_session"))

    async def chat(self, session_id: str, message: str) -> dict:
        """Send a chat message within a running session.

        Returns the raw JSON response dict from the server.
        """
        r = await self._client.post(
            f"/api/sessions/{quote(session_id, safe='')}/chat",
            json={"message": message},
        )
        self._check(r, "chat")
        return self._parse_json(r, "chat")

    # ------------------------------------------------------------------ #
    # Configuration
    # ------------------------------------------------------------------ #

    async def get_config(self) -> ConfigResponse:
        """Retrieve the current server configuration."""
        r = await self._client.get("/api/config")
        self._check(r, "get_config")
        return ConfigResponse.model_validate(self._parse_json(r, "get_config"))

    async def update_config(self, patch: dict) -> dict:
        """Apply a partial configuration update and return the server response."""
        r = await self._client.put("/api/config", json=patch)
        self._check(r, "update_config")
        return self._parse_json(r, "update_config")

    # ------------------------------------------------------------------ #
    # Tripwire configuration
    # ------------------------------------------------------------------ #

    async def get_tripwire_config(self) -> TripwireConfig:
        """Retrieve the current tripwire guard configuration."""
        r = await self._client.get("/api/tripwire")
        self._check(r, "get_tripwire_config")
        return TripwireConfig.model_validate(self._parse_json(r, "get_tripwire_config"))

    async def update_tripwire_config(self, patch: dict) -> dict:
        """Apply a partial tripwire configuration update."""
        r = await self._client.put("/api/tripwire", json=patch)
        self._check(r, "update_tripwire_config")
        return self._parse_json(r, "update_tripwire_config")

    # ------------------------------------------------------------------ #
    # RBAC token management
    # ------------------------------------------------------------------ #

    async def list_tokens(self) -> list[TokenListRow]:
        """List all API tokens (hashed, never the raw secret)."""
        r = await self._client.get("/api/tokens")
        self._check(r, "list_tokens")
        return [TokenListRow.model_validate(t) for t in self._parse_json(r, "list_tokens")]

    async def create_token(self, role: str, label: str | None = None, expires_in_days: int | None = None) -> CreateTokenResponse:
        """Create a new API token with the given role."""
        body: dict = {"role": role}
        if label is not None:
            body["label"] = label
        if expires_in_days is not None:
            body["expires_in_days"] = expires_in_days
        r = await self._client.post("/api/tokens", json=body)
        self._check(r, "create_token")
        return CreateTokenResponse.model_validate(self._parse_json(r, "create_token"))

    async def delete_token(self, token_hash: str) -> None:
        """Revoke a token by its hash."""
        r = await self._client.delete(f"/api/tokens/{quote(token_hash, safe='')}")
        self._check(r, "delete_token")

    # ------------------------------------------------------------------ #
    # Webhook management
    # ------------------------------------------------------------------ #

    async def list_webhooks(self) -> list[WebhookListRow]:
        """List configured SIEM / notification webhooks."""
        r = await self._client.get("/api/webhooks")
        self._check(r, "list_webhooks")
        return [WebhookListRow.model_validate(w) for w in self._parse_json(r, "list_webhooks")]

    async def create_webhook(
        self,
        label: str,
        url: str,
        *,
        siem_format: str = "json",
        filter_kinds: list[str] | None = None,
    ) -> WebhookListRow:
        """Register a new webhook endpoint."""
        body: dict = {"label": label, "url": url, "siem_format": siem_format}
        if filter_kinds is not None:
            body["filter_kinds"] = filter_kinds
        r = await self._client.post("/api/webhooks", json=body)
        self._check(r, "create_webhook")
        return WebhookListRow.model_validate(self._parse_json(r, "create_webhook"))

    async def delete_webhook(self, webhook_id: str) -> None:
        """Remove a webhook by its ID."""
        r = await self._client.delete(f"/api/webhooks/{quote(webhook_id, safe='')}")
        self._check(r, "delete_webhook")

    async def toggle_webhook(self, webhook_id: str, enabled: bool) -> dict:
        """Enable or disable a webhook."""
        r = await self._client.put(
            f"/api/webhooks/{quote(webhook_id, safe='')}",
            json={"enabled": enabled},
        )
        self._check(r, "toggle_webhook")
        return self._parse_json(r, "toggle_webhook")

    # ------------------------------------------------------------------ #
    # Admin
    # ------------------------------------------------------------------ #

    async def reset_demo(self) -> dict:
        """Reset the server to demo defaults (demo mode only)."""
        r = await self._client.post("/api/admin/reset-demo")
        self._check(r, "reset_demo")
        return self._parse_json(r, "reset_demo")

    # ------------------------------------------------------------------ #
    # Server-Sent Events (SSE)
    # ------------------------------------------------------------------ #

    async def stream_events(self, session_id: str) -> AsyncIterator[dict]:
        """Yield parsed SSE data dicts from the live event stream.

        Usage::

            async for event in client.stream_events(session_id):
                print(event)

        The caller is responsible for breaking out of the loop.
        """
        import json as _json

        async with self._client.stream(
            "GET", f"/api/sessions/{quote(session_id, safe='')}/events/stream"
        ) as resp:
            self._check(resp, "stream_events")
            buf = ""
            async for chunk in resp.aiter_text():
                buf += chunk
                while "\n\n" in buf:
                    raw, buf = buf.split("\n\n", 1)
                    for line in raw.splitlines():
                        if line.startswith("data:"):
                            payload = line[len("data:"):].strip()
                            try:
                                yield _json.loads(payload)
                            except ValueError:
                                pass
