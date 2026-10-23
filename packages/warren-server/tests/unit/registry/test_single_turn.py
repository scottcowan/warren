"""AH2: single-turn workspaces emit workspace.completed before destroy."""

from __future__ import annotations

import asyncio
import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from warren_common.runtime.base import WorkspaceSpec


def _spec(ws_id: str, mode: str = "single-turn", folders=None) -> WorkspaceSpec:
    return WorkspaceSpec(
        workspace_id=ws_id, project="p", intent="i", image="img", root_path="",
        app="claude -p task", mode=mode, folders=folders or [],
    )


async def _registry(sqlite_path, runtime, *, settings=None, git_manager=None, spec=None):
    from warren.registry.events import WorkspaceEventStore
    from warren.registry.registry import WorkspaceRegistry, serialize_spec_extra
    from warren.registry.store import WorkspaceStore

    store = await WorkspaceStore.open(sqlite_path)
    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", event_store=WorkspaceEventStore(),
        settings=settings, git_manager=git_manager,
    )
    spec = spec or _spec("ws-1")
    await store.insert(
        workspace_id=spec.workspace_id, project="p", intent="i", image="img", root_path="",
        server_instance="test", status="running", spec_json=serialize_spec_extra(spec),
    )
    await store.update_container_id(spec.workspace_id, "cid-1")
    return registry


def _events(registry, ws_id: str) -> list[dict]:
    buf = registry.event_store.get(ws_id)
    return [json.loads(line) for _, line in buf._events]


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True)


@pytest.mark.asyncio
async def test_completion_event_then_destroy_podman(sqlite_path, tmp_path: Path):
    root = tmp_path / "worktrees" / "ws-1"
    src = tmp_path / "src"
    _git("init", "-q", "-b", "main", str(src))
    (src / "a").write_text("a\n")
    _git("-C", str(src), "add", "a")
    _git("-C", str(src), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "a")
    _git("clone", "-q", str(src), str(root))
    (root / ".warren").mkdir()
    (root / ".warren" / "verdict.json").write_text('{"status": "pass", "summary": "done"}')
    git_manager = SimpleNamespace(
        worktree_path=lambda ws: tmp_path / "worktrees" / ws,
        folder_worktree_path=lambda ws, name: tmp_path / "worktrees" / ws / name,
        shadow_root=tmp_path / "shadow",
        remove_worktree=AsyncMock(),
    )
    runtime = SimpleNamespace(exit_code=AsyncMock(return_value=3), destroy=AsyncMock())
    registry = await _registry(
        sqlite_path, runtime, git_manager=git_manager,
        settings=SimpleNamespace(runtime_type="podman", single_turn_event_retention_seconds=60),
    )

    await registry.complete_single_turn("ws-1")

    (event,) = _events(registry, "ws-1")
    assert event["type"] == "workspace.completed"
    assert event["exit_code"] == 3
    assert event["verdict"] == {"status": "pass", "summary": "done"}
    assert event["git"]["branch"] == "main"
    assert event["git"]["head_commit"] == _git("-C", str(src), "rev-parse", "HEAD").strip()
    assert event["git"]["branch_safe"] is False
    assert event["git"]["is_clean"] is False  # .warren/ is untracked
    assert set(event["git"]) == {"branch", "head_commit", "base_commit", "branch_safe", "is_clean"}
    assert event["capture_errors"] == []
    runtime.destroy.assert_awaited_once()
    assert (await registry.store.get("ws-1")).status == "destroyed"
    assert registry.event_store.get("ws-1").closed


@pytest.mark.asyncio
async def test_capture_failure_still_emits_and_destroys(sqlite_path):
    runtime = SimpleNamespace(
        exit_code=AsyncMock(side_effect=RuntimeError("describe failed")),
        read_file=AsyncMock(side_effect=ValueError("not a regular file")),
        destroy=AsyncMock(),
    )
    git_manager = SimpleNamespace(
        worktree_path=lambda ws: Path("/nonexistent") / ws,
        folder_worktree_path=lambda ws, name: Path("/nonexistent") / ws / name,
        shadow_root=Path("/nonexistent/shadow"),
        remove_worktree=AsyncMock(),
    )
    registry = await _registry(
        sqlite_path, runtime, git_manager=git_manager, settings=SimpleNamespace(runtime_type="podman")
    )

    await registry.complete_single_turn("ws-1")

    (event,) = _events(registry, "ws-1")
    assert event["exit_code"] is None
    assert event["verdict"] is None
    assert any("exit_code" in e for e in event["capture_errors"])
    assert any("verdict" in e for e in event["capture_errors"])
    runtime.destroy.assert_awaited_once()
    assert (await registry.store.get("ws-1")).status == "destroyed"


@pytest.mark.asyncio
async def test_ecs_without_efs_mount_reports_why_and_still_destroys(sqlite_path, tmp_path: Path):
    runtime = SimpleNamespace(exit_code=AsyncMock(return_value=0), destroy=AsyncMock())
    settings = SimpleNamespace(runtime_type="ecs", efs_local_mount_path="", data_dir=tmp_path)
    registry = await _registry(sqlite_path, runtime, settings=settings)

    await registry.complete_single_turn("ws-1")

    (event,) = _events(registry, "ws-1")
    assert event["exit_code"] == 0
    assert "WARREN_EFS_LOCAL_MOUNT_PATH" in event["capture_errors"][0]
    runtime.destroy.assert_awaited_once()


@pytest.mark.asyncio
async def test_ecs_reads_verdict_from_volume(sqlite_path, tmp_path: Path):
    volume = tmp_path / "efs" / "workspaces" / "ws-1" / "workspace" / ".warren"
    volume.mkdir(parents=True)
    (volume / "verdict.json").write_text('{"ok": 1}')
    runtime = SimpleNamespace(exit_code=AsyncMock(return_value=0), destroy=AsyncMock())
    settings = SimpleNamespace(
        runtime_type="ecs", efs_local_mount_path=str(tmp_path / "efs"), data_dir=tmp_path
    )
    registry = await _registry(sqlite_path, runtime, settings=settings)

    await registry.complete_single_turn("ws-1")

    (event,) = _events(registry, "ws-1")
    assert event["verdict"] == {"ok": 1}
    assert event["capture_errors"] == []


@pytest.mark.asyncio
async def test_completion_is_idempotent_after_destroy(sqlite_path):
    runtime = SimpleNamespace(exit_code=AsyncMock(return_value=0), destroy=AsyncMock())
    registry = await _registry(sqlite_path, runtime, settings=SimpleNamespace(runtime_type="podman"))

    await registry.complete_single_turn("ws-1")
    await registry.complete_single_turn("ws-1")

    assert len(_events(registry, "ws-1")) == 1
    runtime.destroy.assert_awaited_once()


@pytest.mark.asyncio
async def test_ensure_running_never_relaunches_an_exited_single_turn(sqlite_path):
    from warren.registry.registry import WorkspaceDestroyedError

    runtime = SimpleNamespace(
        status=AsyncMock(return_value="stopped"),
        exit_code=AsyncMock(return_value=0),
        destroy=AsyncMock(),
        provision=AsyncMock(),
    )
    registry = await _registry(sqlite_path, runtime, settings=SimpleNamespace(runtime_type="ecs"))
    await registry.store.update_ssh_port("ws-1", 2222)

    with pytest.raises(WorkspaceDestroyedError):
        await registry.ensure_running("ws-1")

    runtime.provision.assert_not_awaited()
    assert _events(registry, "ws-1")[0]["type"] == "workspace.completed"
    assert (await registry.store.get("ws-1")).status == "destroyed"


@pytest.mark.asyncio
async def test_stop_never_interrupts_a_single_turn_run(sqlite_path):
    runtime = SimpleNamespace(stop=AsyncMock(), destroy=AsyncMock())
    registry = await _registry(sqlite_path, runtime, settings=SimpleNamespace(runtime_type="podman"))

    await registry.stop("ws-1")

    runtime.stop.assert_not_awaited()
    assert (await registry.store.get("ws-1")).status == "running"


@pytest.mark.asyncio
async def test_list_non_terminal_carries_mode(sqlite_path):
    runtime = SimpleNamespace()
    registry = await _registry(sqlite_path, runtime)
    from warren.registry.registry import serialize_spec_extra

    await registry.store.insert(
        workspace_id="ws-2", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="running",
        spec_json=serialize_spec_extra(_spec("ws-2", mode="interactive")),
    )
    modes = {r.workspace_id: r.mode for r in await registry.list_non_terminal()}
    assert modes == {"ws-1": "single-turn", "ws-2": "interactive"}


def _row(ws_id: str, mode: str):
    handle = SimpleNamespace(workspace_id=ws_id, runtime_id=f"cid-{ws_id}", root_path="")
    return SimpleNamespace(workspace_id=ws_id, handle=handle, mode=mode)


async def _run_reaper_briefly(registry) -> None:
    from warren.registry.reaper import run_reaper

    task = asyncio.create_task(run_reaper(registry, poll_interval=0.01, status_timeout=1.0))
    await asyncio.sleep(0.1)
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


@pytest.mark.asyncio
async def test_reaper_completes_exited_single_turn_instead_of_marking_stopped():
    rows = [_row("st", "single-turn"), _row("ia", "interactive")]
    registry = SimpleNamespace(
        runtime=SimpleNamespace(
            status=AsyncMock(return_value="stopped"), list_by_server=AsyncMock(return_value=[])
        ),
        list_non_terminal=AsyncMock(return_value=rows),
        mark_stopped=AsyncMock(),
        mark_unknown=AsyncMock(),
        complete_single_turn=AsyncMock(),
        _lock_for=AsyncMock(side_effect=lambda _id: asyncio.Lock()),
    )

    await _run_reaper_briefly(registry)

    assert {c.args[0] for c in registry.complete_single_turn.await_args_list} == {"st"}
    assert {c.args[0] for c in registry.mark_stopped.await_args_list} == {"ia"}


@pytest.mark.asyncio
async def test_reaper_on_ecs_polls_only_single_turn_workspaces():
    """ECS has no list_by_server: skip the reachability probe, poll single-turn rows only."""
    status = AsyncMock(return_value="running")
    registry = SimpleNamespace(
        runtime=SimpleNamespace(status=status),
        list_non_terminal=AsyncMock(return_value=[_row("st", "single-turn"), _row("ia", "interactive")]),
        mark_stopped=AsyncMock(),
        mark_unknown=AsyncMock(),
        complete_single_turn=AsyncMock(),
        _lock_for=AsyncMock(side_effect=lambda _id: asyncio.Lock()),
    )

    await _run_reaper_briefly(registry)

    assert status.await_count >= 1
    assert {c.args[0].workspace_id for c in status.await_args_list} == {"st"}
    registry.mark_stopped.assert_not_awaited()
