"""LangChain Tool that writes every agent observation to the EctoLedger."""

import asyncio
import atexit
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Type

from pydantic import BaseModel, Field

try:
    from langchain_core.tools import BaseTool
except ImportError as e:  # pragma: no cover
    raise ImportError(
        "Install 'langchain-core' (pip install ectoledger-sdk[langchain]) to use LedgerTool."
    ) from e

from ectoledger_sdk.client import LedgerClient

_POOL = ThreadPoolExecutor(max_workers=2)
atexit.register(_POOL.shutdown, wait=False)


class _LedgerInput(BaseModel):
    """Input for the LedgerTool."""

    observation: str = Field(..., description="The agent observation to record.")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Optional structured metadata (step, tool_name, etc.).",
    )


class LedgerTool(BaseTool):
    """A LangChain tool that appends each agent observation to the EctoLedger.

    Attach this to any LangChain agent to get a tamper-evident audit trail::

        from ectoledger_sdk.langchain import LedgerTool

        ledger_tool = LedgerTool(
            session_id="<uuid>",
            base_url="http://localhost:3000",
        )
        agent = AgentExecutor(agent=..., tools=[ledger_tool, ...])
    """

    name: str = "ectoledger_ledger"
    description: str = (
        "Records an observation to the EctoLedger tamper-evident audit ledger. "
        "Always call this tool to store important reasoning steps, tool outputs, "
        "or policy decisions for compliance purposes."
    )
    args_schema: Type[BaseModel] = _LedgerInput

    session_id: str
    base_url: str = "http://localhost:3000"
    bearer_token: str | None = None

    def _run(self, observation: str, metadata: dict[str, Any] | None = None) -> str:
        """Synchronous wrapper — runs the async path in a new event loop.

        Uses ``asyncio.get_running_loop()`` (Python 3.10+) instead of the
        deprecated ``asyncio.get_event_loop()`` to detect whether we are
        already inside an async context.  Falls back gracefully when called
        from a plain synchronous environment.
        """
        payload = {"observation": observation, **(metadata or {})}
        try:
            try:
                asyncio.get_running_loop()
                # We are inside an async context (e.g. Jupyter, running LangChain
                # agent) — offload to a background thread to avoid blocking.
                future = _POOL.submit(asyncio.run, self._append(payload))
                return future.result()
            except RuntimeError:
                # No running event loop — safe to use asyncio.run directly.
                return asyncio.run(self._append(payload))
        except Exception as exc:
            return f"[LedgerTool error] {exc}"

    async def _arun(self, observation: str, metadata: dict[str, Any] | None = None) -> str:
        payload = {"observation": observation, **(metadata or {})}
        return await self._append(payload)

    async def _append(self, payload: dict) -> str:
        async with LedgerClient(
            self.base_url, bearer_token=self.bearer_token
        ) as client:
            result = await client.append_event(self.session_id, payload)
            return (
                f"Recorded to ledger: seq={result.sequence} "
                f"hash={result.payload_hash[:16]}…"
            )
