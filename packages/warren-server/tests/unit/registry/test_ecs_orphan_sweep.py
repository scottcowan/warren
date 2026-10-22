"""AI3: ECS orphan task sweep."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest

from warren.registry.ecs_orphan_sweep import run_ecs_orphan_sweep, sweep_ecs_orphans
from warren.registry.registry import WorkspaceRegistry
from warren.registry.store import WorkspaceStore

_OLD = datetime.now(timezone.utc) - timedelta(hours=2)


def _runtime(tasks):
    rt = MagicMock(spec_set=["list_owned_tasks", "stop_task_arn"])
    rt.list_owned_tasks = AsyncMock(return_value=tasks)
    rt.stop_task_arn = AsyncMock()
    return rt


async def _insert(store, ws_id, container_id, status="running"):
    await store.insert(
        workspace_id=ws_id, project="p", intent="i", image="img", root_path="",
        server_instance="test", status=status, container_id=container_id,
    )


@pytest.mark.asyncio
async def test_sweep_stops_only_tasks_without_a_live_row(sqlite_path):
    store = await WorkspaceStore.open(sqlite_path)
    await _insert(store, "ws-live", "arn:live")
    await _insert(store, "ws-dup", "arn:dup-tracked")
    await _insert(store, "ws-gone", "", status="destroyed")
    runtime = _runtime([
        {"task_arn": "arn:live", "workspace_id": "ws-live", "created_at": _OLD},
        {"task_arn": "arn:dup-orphan", "workspace_id": "ws-dup", "created_at": _OLD},
        {"task_arn": "arn:destroyed", "workspace_id": "ws-gone", "created_at": _OLD},
        {"task_arn": "arn:no-row", "workspace_id": "ws-never", "created_at": _OLD},
        {"task_arn": "arn:untagged", "workspace_id": "", "created_at": _OLD},
    ])
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")

    stopped = await sweep_ecs_orphans(registry, min_age_seconds=60)

    assert stopped == ["arn:dup-orphan", "arn:destroyed", "arn:no-row", "arn:untagged"]
    assert "arn:live" not in [c.args[0] for c in runtime.stop_task_arn.await_args_list]


@pytest.mark.asyncio
async def test_sweep_skips_young_tasks_and_unknown_age(sqlite_path):
    """An in-flight provision may not have recorded its ARN yet."""
    store = await WorkspaceStore.open(sqlite_path)
    runtime = _runtime([
        {"task_arn": "arn:young", "workspace_id": "ws-x", "created_at": datetime.now(timezone.utc)},
        {"task_arn": "arn:no-age", "workspace_id": "ws-x", "created_at": None},
    ])
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")

    assert await sweep_ecs_orphans(registry, min_age_seconds=600) == []
    runtime.stop_task_arn.assert_not_awaited()


@pytest.mark.asyncio
async def test_sweep_rechecks_under_workspace_lock(sqlite_path):
    """A provision holding the lock that records the ARN wins over the sweep."""
    store = await WorkspaceStore.open(sqlite_path)
    await _insert(store, "ws-1", "")
    runtime = _runtime([{"task_arn": "arn:new", "workspace_id": "ws-1", "created_at": _OLD}])
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")

    lock = await registry._lock_for("ws-1")
    await lock.acquire()
    sweep = asyncio.create_task(sweep_ecs_orphans(registry, min_age_seconds=60))
    await asyncio.sleep(0.01)
    await store.update_container_id("ws-1", "arn:new")
    lock.release()

    assert await sweep == []
    runtime.stop_task_arn.assert_not_awaited()


@pytest.mark.asyncio
async def test_sweep_continues_after_stop_failure(sqlite_path):
    store = await WorkspaceStore.open(sqlite_path)
    runtime = _runtime([
        {"task_arn": "arn:a", "workspace_id": "ws-a", "created_at": _OLD},
        {"task_arn": "arn:b", "workspace_id": "ws-b", "created_at": _OLD},
    ])
    runtime.stop_task_arn.side_effect = [RuntimeError("boom"), None]
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")

    assert await sweep_ecs_orphans(registry, min_age_seconds=60) == ["arn:b"]


@pytest.mark.asyncio
async def test_run_loop_survives_iteration_error_and_cancels(sqlite_path):
    store = await WorkspaceStore.open(sqlite_path)
    runtime = _runtime([])
    runtime.list_owned_tasks.side_effect = [RuntimeError("aws down"), [], [], [], [], [], []]
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")

    task = asyncio.create_task(run_ecs_orphan_sweep(registry, interval_seconds=0.01))
    # Poll rather than sleep a fixed 50ms: rendering the logged traceback can take
    # longer than that on a loaded machine.
    for _ in range(500):
        if runtime.list_owned_tasks.await_count >= 2:
            break
        await asyncio.sleep(0.01)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert runtime.list_owned_tasks.await_count >= 2
