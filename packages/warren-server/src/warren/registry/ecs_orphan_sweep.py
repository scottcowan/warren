"""ECS orphan task sweep — background asyncio loop (AI3).

Lists the tasks this server launched (ECSRuntime.list_owned_tasks: startedBy
plus an exact server_instance tag match) and stops any whose ARN isn't the
container_id of a non-destroyed workspace row: leftovers from a crash or a
lost DB write between RunTask and update_container_id. Tasks started by any
other server are never listed, so never touched.
"""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from warren.registry.registry import WorkspaceRegistry

log = structlog.get_logger(__name__)


async def _is_live(registry: "WorkspaceRegistry", workspace_id: str, task_arn: str) -> bool:
    row = await registry.store.get(workspace_id) if workspace_id else None
    return row is not None and row.status != "destroyed" and row.container_id == task_arn


async def sweep_ecs_orphans(
    registry: "WorkspaceRegistry", *, min_age_seconds: float = 900.0
) -> list[str]:
    """Run one sweep; return the ARNs stopped."""
    runtime: Any = registry.runtime
    now = datetime.now(timezone.utc)
    stopped: list[str] = []
    for task in await runtime.list_owned_tasks():
        task_arn = task["task_arn"]
        workspace_id = task.get("workspace_id", "")
        created_at = task.get("created_at")
        if not isinstance(created_at, datetime):
            continue
        if created_at.tzinfo is None:
            created_at = created_at.replace(tzinfo=timezone.utc)
        if (now - created_at).total_seconds() < min_age_seconds:
            continue
        if await _is_live(registry, workspace_id, task_arn):
            continue
        # Re-check under the workspace lock: a provision holding it may be
        # about to record this ARN.
        lock = await registry._lock_for(workspace_id) if workspace_id else asyncio.Lock()
        async with lock:
            if await _is_live(registry, workspace_id, task_arn):
                continue
            try:
                await runtime.stop_task_arn(
                    task_arn, workspace_id=workspace_id, reason="warren orphan sweep"
                )
            except Exception:
                log.exception(
                    "ecs_orphan_stop_failed", task_arn=task_arn, workspace_id=workspace_id
                )
                continue
        log.warning("ecs_orphan_task_stopped", task_arn=task_arn, workspace_id=workspace_id)
        stopped.append(task_arn)
    return stopped


async def run_ecs_orphan_sweep(
    registry: "WorkspaceRegistry",
    *,
    interval_seconds: float = 900.0,
    min_age_seconds: float = 900.0,
) -> None:
    """Async sweep loop; runs until cancelled."""
    while True:
        try:
            await sweep_ecs_orphans(registry, min_age_seconds=min_age_seconds)
        except asyncio.CancelledError:
            log.info("ecs_orphan_sweep_cancelled")
            raise
        except Exception:
            log.exception("ecs_orphan_sweep_iteration_failed")
        await asyncio.sleep(interval_seconds)
