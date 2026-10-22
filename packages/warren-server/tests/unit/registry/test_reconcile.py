"""Reconciliation unit tests — FakeRuntime driven, no live Podman.

Cases per D-13:
  a) DB row with matching running container → status "running"
  b) DB row with matching stopped container → status "stopped"
  c) DB row with no matching container → status "stopped"
  d) Container labelled warren.server_instance=<us> with no DB row →
     destroyed via runtime.destroy and warning logged
"""

from __future__ import annotations

import logging

import pytest

from warren.registry.reconcile import reconcile_from_disk  # RED until Plan 02
from warren.registry.store import WorkspaceStore  # RED until Plan 02
from warren_common.runtime.fake import FakeContainer, FakeRuntime


@pytest.mark.asyncio
async def test_reconcile_adopts_running(sqlite_path: str, fake_runtime: FakeRuntime):
    store = await WorkspaceStore.open(sqlite_path)
    await store.insert(
        workspace_id="ws-run",
        project="p",
        intent="i",
        image="img",
        root_path="/tmp/ws-run",
        server_instance="test-server",
        status="running",
    )
    fake_runtime._seed(
        FakeContainer(
            id="fake-ws-run",
            labels={"warren.workspace_id": "ws-run", "warren.server_instance": "test-server"},
            status="running",
        )
    )
    await reconcile_from_disk(runtime=fake_runtime, store=store, server_id="test-server")
    row = await store.get("ws-run")
    assert row.status == "running"


@pytest.mark.asyncio
async def test_reconcile_marks_stopped_when_container_stopped(sqlite_path: str, fake_runtime: FakeRuntime):
    store = await WorkspaceStore.open(sqlite_path)
    await store.insert(
        workspace_id="ws-stop",
        project="p",
        intent="i",
        image="img",
        root_path="/tmp/ws-stop",
        server_instance="test-server",
        status="running",
    )
    fake_runtime._seed(
        FakeContainer(
            id="fake-ws-stop",
            labels={"warren.workspace_id": "ws-stop", "warren.server_instance": "test-server"},
            status="stopped",
        )
    )
    await reconcile_from_disk(runtime=fake_runtime, store=store, server_id="test-server")
    row = await store.get("ws-stop")
    assert row.status == "stopped"


@pytest.mark.asyncio
async def test_reconcile_marks_stopped_when_container_missing(sqlite_path: str, fake_runtime: FakeRuntime):
    store = await WorkspaceStore.open(sqlite_path)
    await store.insert(
        workspace_id="ws-gone",
        project="p",
        intent="i",
        image="img",
        root_path="/tmp/ws-gone",
        server_instance="test-server",
        status="running",
    )
    await reconcile_from_disk(runtime=fake_runtime, store=store, server_id="test-server")
    row = await store.get("ws-gone")
    assert row.status == "stopped"


@pytest.mark.asyncio
async def test_reconcile_survives_restart_for_stopped_workspace(
    sqlite_path: str, fake_runtime: FakeRuntime
):
    """Regression for finding 6: a "stopped" row is NOT in list_non_terminal(),
    so its container must not be treated as an orphan and force-removed on
    every server restart -- it's the idle reaper's own reconnectable state,
    exactly what ensure_running() is designed to bring back."""
    store = await WorkspaceStore.open(sqlite_path)
    await store.insert(
        workspace_id="ws-idle-stopped",
        project="p",
        intent="i",
        image="img",
        root_path="/tmp/ws-idle-stopped",
        server_instance="test-server",
        status="stopped",
        container_id="fake-ws-idle-stopped",
    )
    fake_runtime._seed(
        FakeContainer(
            id="fake-ws-idle-stopped",
            labels={
                "warren.workspace_id": "ws-idle-stopped",
                "warren.server_instance": "test-server",
            },
            status="stopped",
        )
    )

    await reconcile_from_disk(runtime=fake_runtime, store=store, server_id="test-server")

    # The container must still be there -- not destroyed as a false orphan.
    assert "ws-idle-stopped" in {
        c.labels.get("warren.workspace_id") for c in fake_runtime.list_by_server("test-server")
    }
    row = await store.get("ws-idle-stopped")
    assert row.status == "stopped"


@pytest.mark.asyncio
async def test_reconcile_destroyed_workspace_container_is_still_orphan(
    sqlite_path: str, fake_runtime: FakeRuntime, caplog
):
    """A "destroyed" row does NOT exempt a leftover container from orphan
    cleanup -- destroy() clears container_id, so any container still labelled
    with that workspace_id is a genuine leak, not a legitimately paused one."""
    store = await WorkspaceStore.open(sqlite_path)
    await store.insert(
        workspace_id="ws-destroyed",
        project="p",
        intent="i",
        image="img",
        root_path="/tmp/ws-destroyed",
        server_instance="test-server",
        status="destroyed",
    )
    fake_runtime._seed(
        FakeContainer(
            id="fake-ws-destroyed",
            labels={
                "warren.workspace_id": "ws-destroyed",
                "warren.server_instance": "test-server",
            },
            status="running",
        )
    )

    with caplog.at_level(logging.WARNING):
        await reconcile_from_disk(runtime=fake_runtime, store=store, server_id="test-server")

    assert "ws-destroyed" not in {
        c.labels.get("warren.workspace_id") for c in fake_runtime.list_by_server("test-server")
    }


@pytest.mark.asyncio
async def test_reconcile_orphan_destroyed(sqlite_path: str, fake_runtime: FakeRuntime, caplog):
    store = await WorkspaceStore.open(sqlite_path)
    fake_runtime._seed(
        FakeContainer(
            id="fake-orphan",
            labels={"warren.workspace_id": "ws-orphan", "warren.server_instance": "test-server"},
            status="running",
        )
    )
    with caplog.at_level(logging.WARNING):
        await reconcile_from_disk(runtime=fake_runtime, store=store, server_id="test-server")
    assert "ws-orphan" not in {c.labels.get("warren.workspace_id") for c in fake_runtime.list_by_server("test-server")}
    assert any("orphan" in r.getMessage().lower() for r in caplog.records)


@pytest.mark.asyncio
async def test_reconcile_ecs(sqlite_path: str):
    """ECS reconcile branch calls describe_tasks by explicit ARN (Plan 07-01 RED stub)."""
    from warren.runtime.ecs import ECSRuntime  # noqa: F401 — triggers xfail on ImportError
    from warren.registry.reconcile import reconcile_from_disk
    from warren.registry.store import WorkspaceStore
    from unittest.mock import MagicMock

    store = await WorkspaceStore.open(sqlite_path)
    task_arn = "arn:aws:ecs:us-east-1:123:task/test-cluster/abc123"
    await store.insert(
        workspace_id="ws-ecs-01",
        project="p",
        intent="i",
        image="img",
        root_path="",
        server_instance="test-server",
        status="running",
    )
    # Update container_id to task ARN (runtime_id for ECS)
    await store.update_container_id("ws-ecs-01", task_arn)

    mock_ecs = MagicMock(name="ecs_client")
    mock_ecs.describe_tasks.return_value = {
        "tasks": [{"taskArn": task_arn, "lastStatus": "RUNNING"}],
        "failures": [],
    }

    rt = ECSRuntime(server_id="test-server")
    rt._ecs = mock_ecs
    rt._ssm = MagicMock()
    rt._preflight_ok = True

    await reconcile_from_disk(runtime=rt, store=store, server_id="test-server")

    # ECS reconcile must have called describe_tasks with the explicit ARN
    mock_ecs.describe_tasks.assert_called_once()
    call_args = mock_ecs.describe_tasks.call_args
    call_str = str(call_args)
    assert task_arn in call_str

    row = await store.get("ws-ecs-01")
    assert row.status == "running"


@pytest.mark.asyncio
async def test_reconcile_ecs_starting_task_is_provisioning(sqlite_path: str):
    """BB4: "starting" isn't a stored status; a launching task reconciles to provisioning."""
    from unittest.mock import MagicMock

    from warren.runtime.ecs import ECSRuntime

    store = await WorkspaceStore.open(sqlite_path)
    task_arn = "arn:aws:ecs:us-east-1:123:task/test-cluster/abc123"
    await store.insert(
        workspace_id="ws-ecs-01", project="p", intent="i", image="img", root_path="",
        server_instance="test-server", status="running",
    )
    await store.update_container_id("ws-ecs-01", task_arn)

    rt = ECSRuntime(server_id="test-server")
    rt._ecs = MagicMock(name="ecs_client")
    rt._ecs.describe_tasks.return_value = {
        "tasks": [{"taskArn": task_arn, "lastStatus": "PENDING"}],
        "failures": [],
    }
    rt._ssm = MagicMock()

    await reconcile_from_disk(runtime=rt, store=store, server_id="test-server")

    row = await store.get("ws-ecs-01")
    assert row.status == "provisioning"
