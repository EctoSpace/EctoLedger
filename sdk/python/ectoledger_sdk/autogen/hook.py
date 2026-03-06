"""AutoGen reply hook that appends each agent message to the Ecto Ledger."""

import asyncio
import atexit
import logging
from concurrent.futures import ThreadPoolExecutor
from typing import Any

try:
    # autogen-agentchat >= 0.4 (modern namespace)
    from autogen_agentchat.agents import ConversableAgent
except ImportError:
    try:
        # pyautogen 0.2 / 0.3 legacy namespace
        from autogen import ConversableAgent  # type: ignore[no-redef]
    except ImportError as e:  # pragma: no cover
        raise ImportError(
            "Install 'autogen-agentchat' via: pip install ectoledger-sdk[autogen]"
        ) from e

from ectoledger_sdk.client import LedgerClient, LedgerSdkError

_POOL = ThreadPoolExecutor(max_workers=2)
atexit.register(_POOL.shutdown, wait=False)

_log = logging.getLogger(__name__)


class LedgerHook:
    """Registers a post-reply hook on a ``ConversableAgent`` that records every
    outbound message to the Ecto Ledger tamper-evident audit trail.

    Usage::

        from ectoledger_sdk.autogen import LedgerHook

        hook = LedgerHook(session_id="<uuid>", base_url="http://localhost:3000")
        hook.attach(my_autogen_agent)
    """

    def __init__(
        self,
        session_id: str,
        base_url: str = "http://localhost:3000",
        bearer_token: str | None = None,
    ) -> None:
        self.session_id = session_id
        self.base_url = base_url
        self.bearer_token = bearer_token

    def attach(self, agent: "ConversableAgent") -> None:
        """Attach the ledger hook to *agent*'s ``process_last_received_message`` hook."""

        def _hook(messages: list[dict], sender: Any, config: Any) -> tuple[bool, None]:
            last = messages[-1] if messages else None
            if last:
                content = last.get("content", "")
                payload = {
                    "observation": content,
                    "agent_name": agent.name,
                    "role": last.get("role", "unknown"),
                }
                self._sync_append(payload)
            return False, None

        agent.register_hook("process_last_received_message", _hook)

    def _sync_append(self, payload: dict) -> None:
        """Run the async append safely from any context (sync, async, Jupyter)."""
        try:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = None

            if loop is not None and loop.is_running():
                future = _POOL.submit(asyncio.run, self._append(payload))
                future.result(timeout=30)
            else:
                asyncio.run(self._append(payload))
        except (LedgerSdkError, Exception) as exc:
            _log.warning("LedgerHook: failed to append event: %s", exc)

    async def _append(self, payload: dict) -> None:
        async with LedgerClient(
            self.base_url, bearer_token=self.bearer_token
        ) as client:
            await client.append_event(self.session_id, payload)
