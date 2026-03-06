"""Tests for LedgerTool (LangChain integration).

If `langchain_core` is not installed, a minimal Pydantic-based stub is injected
into `sys.modules` so the tool module can be imported and its HTTP logic tested
in isolation.  The stub faithfully reproduces the fields and method signatures
that `LedgerTool` relies on, so these tests exercise the real SDK code paths.
"""
from __future__ import annotations

import importlib
import sys
from typing import Any, Type
from unittest.mock import AsyncMock, patch

import pytest
import respx
import httpx
from pydantic import BaseModel, ConfigDict

# ---------------------------------------------------------------------------
# Langchain stub – only activated when langchain_core is not installed.
# ---------------------------------------------------------------------------

def _ensure_langchain_stub() -> None:
    """Inject a minimal langchain_core stub into sys.modules if needed."""
    if importlib.util.find_spec("langchain_core") is not None:
        return  # Real package available; use it.

    class _BaseTool(BaseModel):
        """Minimal pydantic-compatible stub matching LangChain's BaseTool API."""
        model_config = ConfigDict(arbitrary_types_allowed=True)

        name: str = ""
        description: str = ""
        args_schema: Type[BaseModel] | None = None

        def _run(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover
            raise NotImplementedError

        async def _arun(self, *args: Any, **kwargs: Any) -> str:  # pragma: no cover
            raise NotImplementedError

        def run(self, tool_input: str | dict, **kwargs: Any) -> str:
            import asyncio
            if isinstance(tool_input, str):
                tool_input = {"observation": tool_input}
            return asyncio.get_event_loop().run_until_complete(self._arun(**tool_input))

    stub_tools = type(sys)("langchain_core.tools")
    stub_tools.BaseTool = _BaseTool
    stub_lc = type(sys)("langchain_core")
    stub_lc.tools = stub_tools
    sys.modules.setdefault("langchain_core", stub_lc)
    sys.modules.setdefault("langchain_core.tools", stub_tools)
    # Remove any cached (possibly failed) import of the tool module.
    sys.modules.pop("ectoledger_sdk.langchain.tool", None)
    sys.modules.pop("ectoledger_sdk.langchain", None)


_ensure_langchain_stub()

from ectoledger_sdk.langchain.tool import LedgerTool  # noqa: E402

pytestmark = pytest.mark.asyncio

BASE_URL = "http://localhost:3000"
SESSION_ID = "550e8400-e29b-41d4-a716-446655440000"

APPEND_RESULT = {"id": 1, "payload_hash": "deadbeef01234567deadbeef01234", "sequence": 5}


# ---------------------------------------------------------------------------
# _arun – happy path
# ---------------------------------------------------------------------------

@respx.mock
async def test_arun_records_observation_and_returns_formatted_string() -> None:
    respx.post(f"{BASE_URL}/api/sessions/{SESSION_ID}/events").mock(return_value=httpx.Response(201, json=APPEND_RESULT))
    tool = LedgerTool(session_id=SESSION_ID, base_url=BASE_URL)
    result = await tool._arun(observation="target responded with 200 OK")
    assert "seq=5" in result
    assert "deadbeef01234567" in result


@respx.mock
async def test_arun_includes_metadata_in_payload() -> None:
    route = respx.post(f"{BASE_URL}/api/sessions/{SESSION_ID}/events").mock(return_value=httpx.Response(201, json=APPEND_RESULT))
    tool = LedgerTool(session_id=SESSION_ID, base_url=BASE_URL)
    await tool._arun(observation="step done", metadata={"step": 3, "tool_name": "nmap_scan"})
    body = route.calls.last.request.read()
    import json
    payload = json.loads(body)
    assert payload["observation"] == "step done"
    assert payload["step"] == 3
    assert payload["tool_name"] == "nmap_scan"


# ---------------------------------------------------------------------------
# _arun – HTTP error path
# ---------------------------------------------------------------------------

@respx.mock
async def test_arun_raises_on_http_failure() -> None:
    # _arun() propagates HTTP errors directly; the swallowing of errors only
    # happens in the synchronous _run() wrapper via its except clause.
    respx.post(f"{BASE_URL}/api/sessions/{SESSION_ID}/events").mock(return_value=httpx.Response(503, json={"detail": "service unavailable"}))
    tool = LedgerTool(session_id=SESSION_ID, base_url=BASE_URL)
    from ectoledger_sdk.client import LedgerSdkError
    with pytest.raises(LedgerSdkError):
        await tool._arun(observation="some step")


# ---------------------------------------------------------------------------
# _arun – bearer token forwarded
# ---------------------------------------------------------------------------

@respx.mock
async def test_arun_sends_bearer_token_when_configured() -> None:
    route = respx.post(f"{BASE_URL}/api/sessions/{SESSION_ID}/events").mock(return_value=httpx.Response(201, json=APPEND_RESULT))
    tool = LedgerTool(session_id=SESSION_ID, base_url=BASE_URL, bearer_token="tok-xyz")
    await tool._arun(observation="observation text")
    auth_header = route.calls.last.request.headers.get("authorization", "")
    assert auth_header == "Bearer tok-xyz"


# ---------------------------------------------------------------------------
# _arun – empty metadata uses empty dict
# ---------------------------------------------------------------------------

@respx.mock
async def test_arun_no_metadata_defaults_to_empty_dict() -> None:
    route = respx.post(f"{BASE_URL}/api/sessions/{SESSION_ID}/events").mock(return_value=httpx.Response(201, json=APPEND_RESULT))
    tool = LedgerTool(session_id=SESSION_ID, base_url=BASE_URL)
    await tool._arun(observation="just text")
    import json
    payload = json.loads(route.calls.last.request.read())
    assert "observation" in payload


# ---------------------------------------------------------------------------
# _run (sync wrapper) – happy path
# ---------------------------------------------------------------------------

def test_run_sync_happy_path() -> None:
    """The synchronous _run() wrapper should return the formatted result string."""
    with respx.mock:
        respx.post(f"{BASE_URL}/api/sessions/{SESSION_ID}/events").mock(
            return_value=httpx.Response(201, json=APPEND_RESULT)
        )
        tool = LedgerTool(session_id=SESSION_ID, base_url=BASE_URL)
        result = tool._run(observation="sync observation")
    assert "seq=5" in result
    assert "deadbeef01234567" in result


# ---------------------------------------------------------------------------
# _run (sync wrapper) – error is swallowed
# ---------------------------------------------------------------------------

def test_run_sync_swallows_error() -> None:
    """When appending fails, _run() returns an error string instead of raising."""
    with respx.mock:
        respx.post(f"{BASE_URL}/api/sessions/{SESSION_ID}/events").mock(
            return_value=httpx.Response(503, json={"detail": "service unavailable"})
        )
        tool = LedgerTool(session_id=SESSION_ID, base_url=BASE_URL)
        result = tool._run(observation="sync observation that will fail")
    assert "[LedgerTool error]" in result
