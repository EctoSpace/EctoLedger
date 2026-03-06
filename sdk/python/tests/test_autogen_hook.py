"""Tests for LedgerHook (AutoGen integration).

A minimal `autogen` stub is injected into `sys.modules` when pyautogen is not
installed, enabling the hook's HTTP logic to be tested without the heavy
dependency.
"""
from __future__ import annotations

import importlib
import sys
from typing import Any
from unittest.mock import MagicMock, call

import pytest
import respx
import httpx

# ---------------------------------------------------------------------------
# AutoGen stub – only activated when pyautogen is not installed.
# ---------------------------------------------------------------------------

def _ensure_autogen_stub() -> None:
    if importlib.util.find_spec("autogen") is not None:
        return

    class _ConversableAgent:
        """Minimal stub that tracks registered hooks for test inspection."""
        def __init__(self, name: str = "test_agent") -> None:
            self.name = name
            self._hooks: dict[str, list] = {}

        def register_hook(self, hook_type: str, fn: Any) -> None:
            self._hooks.setdefault(hook_type, []).append(fn)

        def trigger_hook(self, hook_type: str, messages: list, sender: Any = None, config: Any = None) -> Any:
            results = []
            for fn in self._hooks.get(hook_type, []):
                results.append(fn(messages, sender, config))
            return results

    stub = type(sys)("autogen")
    stub.ConversableAgent = _ConversableAgent
    sys.modules.setdefault("autogen", stub)
    sys.modules.pop("ectoledger_sdk.autogen.hook", None)
    sys.modules.pop("ectoledger_sdk.autogen", None)


_ensure_autogen_stub()

from ectoledger_sdk.autogen.hook import LedgerHook  # noqa: E402

# The sync hook tests use regular (non-async) functions; remove asyncio pytestmark
# from the module-level mark for this file to avoid spurious warnings.
import pytest as _pytest
pytestmark = []  # no module-level marks — each async test is already discovered via asyncio_mode=auto


BASE_URL = "http://localhost:3000"
SESSION_ID = "550e8400-e29b-41d4-a716-446655440000"

APPEND_RESULT = {"id": 10, "payload_hash": "cafebabe12345678cafebabe12345678cafebabe12345678cafebabe12345678", "sequence": 10}


def _make_agent(name: str = "audit_agent") -> Any:
    from autogen import ConversableAgent
    return ConversableAgent(name=name)


# ---------------------------------------------------------------------------
# attach – hook registration
# ---------------------------------------------------------------------------

def test_attach_registers_hook_on_agent() -> None:
    agent = _make_agent()
    hook = LedgerHook(session_id=SESSION_ID, base_url=BASE_URL)
    hook.attach(agent)
    assert "process_last_received_message" in agent._hooks
    assert len(agent._hooks["process_last_received_message"]) == 1


def test_attach_multiple_agents_independently() -> None:
    agent_a, agent_b = _make_agent("a"), _make_agent("b")
    LedgerHook(session_id=SESSION_ID, base_url=BASE_URL).attach(agent_a)
    LedgerHook(session_id=SESSION_ID, base_url=BASE_URL).attach(agent_b)
    assert len(agent_a._hooks["process_last_received_message"]) == 1
    assert len(agent_b._hooks["process_last_received_message"]) == 1


# ---------------------------------------------------------------------------
# hook invocation – happy path
# ---------------------------------------------------------------------------

@respx.mock
def test_hook_appends_last_message_to_ledger() -> None:
    respx.post(f"{BASE_URL}/api/sessions/{SESSION_ID}/events").mock(return_value=httpx.Response(201, json=APPEND_RESULT))
    agent = _make_agent()
    LedgerHook(session_id=SESSION_ID, base_url=BASE_URL).attach(agent)
    messages = [{"role": "assistant", "content": "CVE-2024-12345 found in target."}, {"role": "user", "content": "next step?"}]
    results = agent.trigger_hook("process_last_received_message", messages)
    assert len(results) == 1
    flag, none_val = results[0]
    assert flag is False
    assert none_val is None


@respx.mock
def test_hook_sends_agent_name_and_role_in_payload() -> None:
    route = respx.post(f"{BASE_URL}/api/sessions/{SESSION_ID}/events").mock(return_value=httpx.Response(201, json=APPEND_RESULT))
    agent = _make_agent("recon_agent")
    LedgerHook(session_id=SESSION_ID, base_url=BASE_URL).attach(agent)
    agent.trigger_hook("process_last_received_message", [{"role": "assistant", "content": "target scanned"}])
    import json
    payload = json.loads(route.calls.last.request.read())
    assert payload["agent_name"] == "recon_agent"
    assert payload["role"] == "assistant"
    assert payload["observation"] == "target scanned"


@respx.mock
def test_hook_sends_bearer_token() -> None:
    route = respx.post(f"{BASE_URL}/api/sessions/{SESSION_ID}/events").mock(return_value=httpx.Response(201, json=APPEND_RESULT))
    agent = _make_agent()
    LedgerHook(session_id=SESSION_ID, base_url=BASE_URL, bearer_token="secret-hook-token").attach(agent)
    agent.trigger_hook("process_last_received_message", [{"role": "assistant", "content": "done"}])
    assert route.calls.last.request.headers.get("authorization") == "Bearer secret-hook-token"


# ---------------------------------------------------------------------------
# hook invocation – empty message list
# ---------------------------------------------------------------------------

@respx.mock
def test_hook_does_nothing_on_empty_messages() -> None:
    route = respx.post(f"{BASE_URL}/api/sessions/{SESSION_ID}/events").mock(return_value=httpx.Response(201, json=APPEND_RESULT))
    agent = _make_agent()
    LedgerHook(session_id=SESSION_ID, base_url=BASE_URL).attach(agent)
    results = agent.trigger_hook("process_last_received_message", [])
    assert len(results) == 1
    assert route.call_count == 0


# ---------------------------------------------------------------------------
# hook invocation – HTTP error is silenced (does not crash the agent loop)
# ---------------------------------------------------------------------------

@respx.mock
def test_hook_swallows_http_error() -> None:
    # After the error-handling update, the hook logs a warning instead of
    # propagating exceptions — this prevents crashing the AutoGen agent loop.
    respx.post(f"{BASE_URL}/api/sessions/{SESSION_ID}/events").mock(return_value=httpx.Response(503, json={"detail": "down"}))
    agent = _make_agent()
    LedgerHook(session_id=SESSION_ID, base_url=BASE_URL).attach(agent)
    # Should NOT raise — the hook swallows the error and logs a warning.
    results = agent.trigger_hook("process_last_received_message", [{"role": "assistant", "content": "ping"}])
    assert len(results) == 1
    flag, none_val = results[0]
    assert flag is False
    assert none_val is None
