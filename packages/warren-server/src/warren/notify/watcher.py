"""Agent-state watcher: polls each running workspace's reported agent state and turns
transitions into notifications (warren.notify.events.detect).

State is read with the same host-side reader the idle reaper uses
(`WorkspaceRegistry.agent_state`: the hook's state.json, the OSC fallback, and the agent
supervisor's report). Only workspaces someone is listening for are read: all of them
when a server-wide webhook is set, otherwise only subscribed owners' workspaces, and
none (no reads at all) when nobody has a webhook.
"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

import structlog
from warren.notify.dispatcher import Notifier
from warren.notify.events import agent_message, detect
from warren_common import agent_state as st

log = structlog.get_logger(__name__)

StateReader = Callable[[Any], Awaitable[st.AgentState | None]]


async def _read(reader: StateReader, ws: Any) -> st.AgentState | None:
    try:
        agent = await reader(ws)
    except Exception:
        return None
    return agent if isinstance(agent, st.AgentState) and agent.state in st.STATES else None


async def poll_once(
    registry: Any, notifier: Notifier, last: dict[str, st.AgentState], reader: StateReader
) -> list[tuple[str, str]]:
    """One pass. Returns the (workspace_id, event) pairs emitted."""
    owners = await notifier.watched_owners()
    if owners is not None and not owners:
        last.clear()
        return []
    emitted: list[tuple[str, str]] = []
    seen: set[str] = set()
    for ws in await registry.store.list_non_terminal():
        if ws.status != "running" or (owners is not None and ws.owner_id not in owners):
            continue
        seen.add(ws.workspace_id)
        cur = await _read(reader, ws)
        if cur is None:
            last.pop(ws.workspace_id, None)
            continue
        event = detect(last.get(ws.workspace_id), cur)
        last[ws.workspace_id] = cur
        if event is not None and notifier.emit(event, ws, agent_message(event, cur)):
            emitted.append((ws.workspace_id, event))
    for workspace_id in [w for w in last if w not in seen]:
        del last[workspace_id]
    return emitted


async def run_agent_state_watcher(
    registry: Any,
    notifier: Notifier,
    *,
    poll_interval: float = 30.0,
    read_agent_state: StateReader | None = None,
    sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
) -> None:
    reader = read_agent_state if read_agent_state is not None else registry.agent_state
    last: dict[str, st.AgentState] = {}
    while True:
        try:
            await poll_once(registry, notifier, last, reader)
        except asyncio.CancelledError:
            raise
        except Exception as exc:
            log.warning("notify_watcher_iteration_failed", error=type(exc).__name__)
        await sleep(poll_interval)
