"""Reaper coroutine — Plan 05-06 Task 1.

Periodically polls the runtime for each non-terminal workspace and reconciles
the registry's status. Per D-21, a workspace is only marked `unknown` after
two consecutive `unknown` polls. Per Pitfall 5, the reaper first checks that
the runtime itself is reachable via `runtime.list_by_server(server_id)`; if
that call times out or raises `RuntimeUnreachable`, the whole iteration is
skipped so a transient socket blip cannot mass-mark every workspace unknown.

AH2: a single-turn workspace whose app has exited is handed to
`registry.complete_single_turn` (workspace.completed event, then destroy) instead of
being marked stopped. A runtime with no `list_by_server` (ECS) skips the reachability
check, and only single-turn workspaces are polled there, so interactive ECS
workspaces keep their previous (unpolled) behavior.

The loop body is wrapped in a broad `except Exception` so an unexpected error
from any single workspace status call logs and continues — only
`asyncio.CancelledError` propagates out (cooperative shutdown).

Timeouts use `asyncio.timeout()`, not `asyncio.wait_for()`: on Python 3.11,
`wait_for` swallows a `task.cancel()` that arrives after the inner awaitable
has already finished (it returns the result instead of re-raising
CancelledError, cpython gh-86296, fixed by the 3.12 rewrite). The status calls
here usually complete immediately, so a shutdown cancel landing in that window
was silently dropped and the loop ran forever -- hanging app shutdown and
`test_reaper.py` (`task.cancel(); await task`). `asyncio.timeout()` tracks
cancellation via `Task.uncancel()` and always propagates an outside cancel.
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

from warren_common.errors import RuntimeUnreachable

log = structlog.get_logger(__name__)


async def run_reaper(
    registry: Any,
    *,
    poll_interval: float = 2.0,
    status_timeout: float = 3.0,
    unknown_threshold: int = 2,
) -> None:
    """Async reaper loop; runs until cancelled."""
    unknown_counts: dict[str, int] = {}
    runtime = registry.runtime
    can_list = hasattr(runtime, "list_by_server")

    while True:
        try:
            if can_list:
                try:
                    server_id = getattr(registry, "server_id", "")
                    async with asyncio.timeout(status_timeout):
                        await runtime.list_by_server(server_id)
                except (asyncio.TimeoutError, TimeoutError, RuntimeUnreachable) as e:
                    log.warning("reaper_runtime_unreachable", error=str(e))
                    await asyncio.sleep(poll_interval)
                    continue

            workspaces = await registry.list_non_terminal()

            for ws in workspaces:
                single_turn = getattr(ws, "mode", "interactive") == "single-turn"
                if not can_list and not single_turn:
                    continue
                if not ws.handle.runtime_id:
                    # Audit 2026-10-16 P1 #32: an empty runtime_id means this
                    # workspace is still being PROVISIONED (no container
                    # exists yet) -- podman.py's status() returns "unknown"
                    # for exactly this case, which this loop used to treat
                    # as a real "unknown status" worth counting toward
                    # unknown_threshold and eventually writing to the DB,
                    # racing the in-flight provision operation (which holds
                    # or will hold this workspace's lifecycle lock) without
                    # taking that lock itself. A row with no container_id
                    # yet is simply not this reaper's business -- skip it
                    # entirely, and drop any stale count from a prior poll.
                    unknown_counts.pop(ws.workspace_id, None)
                    continue

                try:
                    async with asyncio.timeout(status_timeout):
                        status = await runtime.status(ws.handle)
                except (asyncio.TimeoutError, TimeoutError):
                    status = "unknown"

                if status == "unknown":
                    unknown_counts[ws.workspace_id] = (
                        unknown_counts.get(ws.workspace_id, 0) + 1
                    )
                    if unknown_counts[ws.workspace_id] >= unknown_threshold:
                        async with await registry._lock_for(ws.workspace_id):
                            await registry.mark_unknown(ws.workspace_id)
                elif status == "stopped":
                    unknown_counts.pop(ws.workspace_id, None)
                    if single_turn:
                        await registry.complete_single_turn(ws.workspace_id)
                        continue
                    async with await registry._lock_for(ws.workspace_id):
                        await registry.mark_stopped(ws.workspace_id)
                else:
                    unknown_counts.pop(ws.workspace_id, None)

        except asyncio.CancelledError:
            log.info("reaper_cancelled")
            raise
        except Exception:
            log.exception("reaper_iteration_failed")

        await asyncio.sleep(poll_interval)
