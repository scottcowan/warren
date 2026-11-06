"""Headless runs end to end in the registry: completion records the run's result, which
outlives the destroyed workspace; timeouts; EBS tasks reporting their own result."""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from warren.registry import runs
from warren_common.headless import headless_command
from warren_common.models import FolderSpec
from warren_common.runtime.base import ExecExit, WorkspaceSpec

SCRIPT = Path(__file__).parents[3] / "images" / "ecs-base" / "warren-run-result.sh"
CLAUDE_OUT = json.dumps({
    "type": "result", "subtype": "success", "is_error": False, "num_turns": 3,
    "result": "Added the flag. Opened https://github.com/acme/app/pull/12", "session_id": "sess-1",
})


def _git(*args: str, cwd: Path | None = None) -> str:
    return subprocess.check_output(
        ["git", "-c", "user.email=t@t", "-c", "user.name=t", *args], text=True, cwd=cwd,
    )


def _repo(path: Path, origin: Path) -> None:
    """A clone of `origin` on branch warren/fix with one commit, one edit and one new file."""
    _git("init", "-q", "-b", "main", str(origin))
    (origin / "a.txt").write_text("one\n")
    _git("add", "a.txt", cwd=origin)
    _git("commit", "-qm", "base", cwd=origin)
    _git("clone", "-q", str(origin), str(path))
    _git("checkout", "-qb", "warren/fix", cwd=path)
    (path / "b.txt").write_text("b\nb\n")
    _git("add", "b.txt", cwd=path)
    _git("commit", "-qm", "add b", cwd=path)
    (path / "a.txt").write_text("one\ntwo\n")
    (path / "new.md").write_text("x\n")


def _spec(ws_id="ws-1", *, app="claude", ecs_storage="", folders=None) -> WorkspaceSpec:
    return WorkspaceSpec(
        workspace_id=ws_id, project="p", intent="t", image="img", root_path="",
        app=headless_command(app, "do it"), mode="single-turn", ecs_storage=ecs_storage,
        folders=folders or [],
    )


async def _registry(sqlite_path, runtime, settings, spec, *, git_manager=None, timeout=None):
    from warren.registry.events import WorkspaceEventStore
    from warren.registry.registry import WorkspaceRegistry, serialize_spec_extra
    from warren.registry.store import WorkspaceStore

    store = await WorkspaceStore.open(sqlite_path)
    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", event_store=WorkspaceEventStore(),
        settings=settings, git_manager=git_manager,
    )
    registry.run_store = runs.RunStore(store._db)
    await store.insert(
        workspace_id=spec.workspace_id, project="p", intent="t", image="img", root_path="",
        server_instance="test", status="running", owner_id="alice", spec_json=serialize_spec_extra(spec),
    )
    await store.update_container_id(spec.workspace_id, "cid-1")
    await registry.run_store.create(
        run_id=spec.workspace_id, owner_id="alice", project="p", template="t", timeout_seconds=timeout,
    )
    return registry


def _events(registry, ws_id="ws-1") -> list[dict]:
    return [json.loads(line) for _, line in registry.event_store.get(ws_id)._events]


# --- podman: the control plane reads the checkout and the harness output ------------


async def test_podman_run_result_survives_destroy(sqlite_path, tmp_path: Path):
    root = tmp_path / "worktrees" / "ws-1"
    _repo(root, tmp_path / "origin")
    harness = tmp_path / "data" / "harness" / "ws-1" / ".session"
    harness.mkdir(parents=True)
    (harness / "run-output.txt").write_text(CLAUDE_OUT)
    git_manager = SimpleNamespace(
        worktree_path=lambda ws: tmp_path / "worktrees" / ws,
        folder_worktree_path=lambda ws, name: tmp_path / "worktrees" / ws / name,
        shadow_root=tmp_path / "shadow",
        remove_worktree=AsyncMock(),
    )
    runtime = SimpleNamespace(exit_code=AsyncMock(return_value=0), destroy=AsyncMock())
    settings = SimpleNamespace(runtime_type="podman", data_dir=tmp_path / "data")
    registry = await _registry(sqlite_path, runtime, settings, _spec(), git_manager=git_manager)

    await registry.complete_single_turn("ws-1")

    assert (await registry.store.get("ws-1")).status == "destroyed"
    run = await registry.run_store.get("ws-1")
    assert run["status"] == "succeeded" and run["ended_at"]
    result = run["result"]
    assert result["result_source"] == "control-plane"
    assert result["exit_code"] == 0 and result["harness"] == "claude"
    assert result["final_message"].startswith("Added the flag.")
    assert result["harness_result"]["num_turns"] == 3
    assert result["pull_requests"] == ["https://github.com/acme/app/pull/12"]
    assert result["transcript"]["session_id"] == "sess-1" and result["transcript"]["retained"] is False
    (repo,) = result["git"]
    assert repo["branch"] == "warren/fix" and repo["pushed"] is False
    # A root clone has no base branch, so the diff is against HEAD: the edit and the new file.
    assert {f["path"]: f["status"] for f in repo["changed_files"]} == {"a.txt": "modified", "new.md": "untracked"}
    assert repo["diffstat"]["insertions"] == 1
    # The event the MCP/SSE clients read is unchanged.
    assert set(_events(registry)[0]["git"]) == {"branch", "head_commit", "base_commit", "branch_safe", "is_clean"}


async def test_podman_folder_diff_is_against_the_base_branch(sqlite_path, tmp_path: Path):
    folder = FolderSpec(name="app", type="git-worktree", url="https://example.com/app.git", mount="code/app")
    path = tmp_path / "worktrees" / "ws-1" / "app"
    _repo(path, tmp_path / "origin")
    git_manager = SimpleNamespace(
        worktree_path=lambda ws: tmp_path / "worktrees" / ws,
        folder_worktree_path=lambda ws, name: tmp_path / "worktrees" / ws / name,
        shadow_root=tmp_path / "shadow",
        remove_worktree=AsyncMock(),
    )
    runtime = SimpleNamespace(exit_code=AsyncMock(return_value=1), destroy=AsyncMock())
    registry = await _registry(
        sqlite_path, runtime, SimpleNamespace(runtime_type="podman"), _spec(folders=[folder]),
        git_manager=git_manager,
    )

    await registry.complete_single_turn("ws-1")

    run = await registry.run_store.get("ws-1")
    assert run["status"] == "failed"
    (repo,) = run["result"]["git"]
    assert repo["mount"] == "code/app" and repo["base_branch"] == "main" and repo["base_commit"]
    assert {f["path"] for f in repo["changed_files"]} == {"a.txt", "b.txt", "new.md"}
    assert repo["diffstat"] == {"files": 3, "insertions": 3, "deletions": 0}


async def test_run_recorded_for_a_single_turn_workspace_without_a_row(sqlite_path, tmp_path: Path):
    runtime = SimpleNamespace(exit_code=AsyncMock(return_value=0), destroy=AsyncMock())
    registry = await _registry(sqlite_path, runtime, SimpleNamespace(runtime_type="podman"), _spec())
    await registry.run_store._db.execute("DELETE FROM runs")

    await registry.complete_single_turn("ws-1")

    run = await registry.run_store.get("ws-1")
    assert run["owner_id"] == "alice" and run["status"] == "succeeded"


async def test_completion_survives_a_run_store_failure(sqlite_path):
    runtime = SimpleNamespace(exit_code=AsyncMock(return_value=0), destroy=AsyncMock())
    registry = await _registry(sqlite_path, runtime, SimpleNamespace(runtime_type="podman"), _spec())
    registry.run_store = SimpleNamespace(get=AsyncMock(side_effect=RuntimeError("db gone")))

    await registry.complete_single_turn("ws-1")

    assert (await registry.store.get("ws-1")).status == "destroyed"


async def test_podman_prefers_the_recorded_exit_code_over_tmuxs(sqlite_path, tmp_path: Path):
    """warren-docker-base runs the app inside tmux, so the container exits 0 whatever the
    app did; the run reports the code its command wrote to the bind-mounted harness dir."""
    harness = tmp_path / "data" / "harness" / "ws-1" / ".session"
    harness.mkdir(parents=True)
    (harness / "run-output.txt").write_text("compile error\n")
    (harness / "run-exit-code").write_text("3\n")
    runtime = SimpleNamespace(exit_code=AsyncMock(return_value=0), destroy=AsyncMock())
    settings = SimpleNamespace(runtime_type="podman", data_dir=tmp_path / "data")
    registry = await _registry(sqlite_path, runtime, settings, _spec(app="./build.sh"))

    await registry.complete_single_turn("ws-1")

    assert _events(registry)[0]["exit_code"] == 0  # the event keeps the container's
    run = await registry.run_store.get("ws-1")
    assert run["status"] == "failed" and run["result"]["exit_code"] == 3
    assert run["result"]["harness"] is None and run["result"]["final_message"] == "compile error"


async def test_podman_reads_the_container_when_the_harness_dir_is_absent(sqlite_path, tmp_path: Path):
    """A row provisioned before runs mounted the harness dir: read the stopped container."""
    files = {"/var/lib/warren/harness/.session/run-output.txt": CLAUDE_OUT.encode(),
             "/var/lib/warren/harness/.session/run-exit-code": b"0\n"}

    async def read_file(handle, path, max_bytes):
        return files.get(path)

    runtime = SimpleNamespace(exit_code=AsyncMock(return_value=0), destroy=AsyncMock(), read_file=read_file)
    git_manager = SimpleNamespace(
        worktree_path=lambda ws: tmp_path / "none" / ws,
        folder_worktree_path=lambda ws, name: tmp_path / "none" / ws / name,
        shadow_root=tmp_path / "shadow",
        remove_worktree=AsyncMock(),
    )
    settings = SimpleNamespace(runtime_type="podman", data_dir=tmp_path / "data")
    registry = await _registry(sqlite_path, runtime, settings, _spec(), git_manager=git_manager)

    await registry.complete_single_turn("ws-1")

    result = (await registry.run_store.get("ws-1"))["result"]
    assert result["status"] == "succeeded" and result["final_message"].startswith("Added the flag.")


async def test_efs_reads_output_and_checkouts_from_the_volume(sqlite_path, tmp_path: Path):
    volume = tmp_path / "efs" / "workspaces" / "ws-1"
    (volume / "harness" / ".session").mkdir(parents=True)
    (volume / "harness" / ".session" / "run-output.txt").write_text(CLAUDE_OUT)
    (volume / "harness" / ".session" / "run-exit-code").write_text("0\n")
    runtime = SimpleNamespace(exit_code=AsyncMock(return_value=0), destroy=AsyncMock())
    settings = SimpleNamespace(runtime_type="ecs", efs_local_mount_path=str(tmp_path / "efs"), data_dir=tmp_path)
    registry = await _registry(sqlite_path, runtime, settings, _spec(ecs_storage="efs"))

    await registry.complete_single_turn("ws-1")

    result = (await registry.run_store.get("ws-1"))["result"]
    assert result["status"] == "succeeded" and result["result_source"] == "control-plane"
    assert result["final_message"].startswith("Added the flag.")
    assert result["transcript"]["retained"] is True


# --- timeouts ------------------------------------------------------------------------


async def test_tick_times_out_a_run_past_its_timeout(sqlite_path):
    runtime = SimpleNamespace(exit_code=AsyncMock(return_value=None), destroy=AsyncMock())
    registry = await _registry(sqlite_path, runtime, SimpleNamespace(runtime_type="podman"), _spec(), timeout=60)
    started = runs.parse_iso((await registry.run_store.get("ws-1"))["started_at"])

    await registry.tick_single_turn("ws-1", now=started + timedelta(seconds=59))
    assert (await registry.store.get("ws-1")).status == "running"

    await registry.tick_single_turn("ws-1", now=started + timedelta(seconds=60))
    run = await registry.run_store.get("ws-1")
    assert run["status"] == "timed_out" and run["result"]["status"] == "timed_out"
    runtime.destroy.assert_awaited_once()


async def test_reaper_ticks_running_single_turn_workspaces():
    from warren.registry.reaper import run_reaper

    handle = SimpleNamespace(workspace_id="st", runtime_id="cid", root_path="")
    tick = AsyncMock(side_effect=[RuntimeError("boom"), None, None, None, None, None])
    registry = SimpleNamespace(
        runtime=SimpleNamespace(status=AsyncMock(return_value="running")),
        list_non_terminal=AsyncMock(return_value=[
            SimpleNamespace(workspace_id="st", handle=handle, mode="single-turn"),
            SimpleNamespace(workspace_id="ia", handle=handle, mode="interactive"),
        ]),
        tick_single_turn=tick,
    )
    task = asyncio.create_task(run_reaper(registry, poll_interval=0.01, status_timeout=1.0))
    for _ in range(200):
        await asyncio.sleep(0.01)
        if tick.await_count >= 2:
            break
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert tick.await_count >= 2  # a failing tick doesn't stop the loop
    assert {c.args[0] for c in tick.await_args_list} == {"st"}


# --- EBS: the task records its own result ---------------------------------------------


def _ecs_settings(tmp_path: Path, **over):
    base = dict(runtime_type="ecs", efs_local_mount_path="", data_dir=tmp_path, run_result_probe_seconds=20.0)
    base.update(over)
    return SimpleNamespace(**base)


class _ScriptRuntime:
    """ECS stand-in whose exec_stream runs images/ecs-base/warren-run-result.sh locally."""

    def __init__(self, env: dict[str, str], *, exit_code=None, ready=True) -> None:
        self.env = env
        self.calls: list[list[str]] = []
        self.ready = ready
        self.exit_code = AsyncMock(return_value=exit_code)
        self.destroy = AsyncMock()

    async def exec_stream(self, handle, argv):
        self.calls.append(argv)
        assert argv[0] == "/usr/local/bin/warren-run-result"
        if not self.ready and argv[1] == "cat":
            yield ExecExit(3)
            return
        proc = subprocess.run(
            ["sh", str(SCRIPT), *argv[1:]], env={**os.environ, **self.env}, capture_output=True, check=False,
        )
        # ECS Exec runs under a TTY: CRLF line endings and session banners.
        yield b"Starting session with SessionId: x\r\n"
        yield proc.stdout.replace(b"\n", b"\r\n")
        yield ExecExit(proc.returncode)


def _task_fs(tmp_path: Path) -> dict[str, str]:
    ws_dir = tmp_path / "task" / "workspace"
    _repo(ws_dir / "code" / "app", tmp_path / "origin")
    (ws_dir / ".warren").mkdir(parents=True)
    (ws_dir / ".warren" / "verdict.json").write_text('{"status": "pass"}')
    out = tmp_path / "task" / "harness" / ".session" / "run-output.txt"
    out.parent.mkdir(parents=True)
    out.write_text(CLAUDE_OUT)
    return {
        "WARREN_RUN_RESULT_DIR": str(tmp_path / "task" / "run"),
        "WARREN_WORKSPACE_DIR": str(ws_dir),
        "WARREN_RUN_OUTPUT": str(out),
        "WARREN_RUN_REPOS": "code/app=main ../escape bad;name=main",
    }


async def test_ebs_tick_collects_the_task_record_and_completes(sqlite_path, tmp_path: Path):
    env = _task_fs(tmp_path)
    subprocess.run(["sh", str(SCRIPT), "write", "0"], env={**os.environ, **env}, check=True)
    runtime = _ScriptRuntime(env)
    folder = FolderSpec(name="app", type="git-worktree", url="https://example.com/app.git", mount="code/app")
    registry = await _registry(
        sqlite_path, runtime, _ecs_settings(tmp_path), _spec(ecs_storage="ebs", folders=[folder])
    )

    await registry.tick_single_turn("ws-1")

    assert runtime.calls == [["/usr/local/bin/warren-run-result", "cat"]]
    assert (await registry.store.get("ws-1")).status == "destroyed"
    event = _events(registry)[0]
    assert event["exit_code"] == 0 and event["verdict"] == {"status": "pass"}
    assert event["git"]["branch"] == "warren/fix" and event["git"]["branch_safe"] is True
    assert event["capture_errors"] == []
    run = await registry.run_store.get("ws-1")
    result = run["result"]
    assert run["status"] == "succeeded" and result["result_source"] == "workspace"
    assert result["final_message"].startswith("Added the flag.")
    (repo,) = result["git"]  # the unsafe REPOS entries were dropped by the script
    assert repo["mount"] == "code/app" and repo["base_commit"]
    assert {f["path"] for f in repo["changed_files"]} == {"a.txt", "b.txt", "new.md"}


async def test_ebs_tick_waits_for_the_record_and_throttles_probes(sqlite_path, tmp_path: Path, monkeypatch):
    runtime = _ScriptRuntime(_task_fs(tmp_path), ready=False)
    registry = await _registry(sqlite_path, runtime, _ecs_settings(tmp_path), _spec(ecs_storage="ebs"))
    now = [100.0]
    monkeypatch.setattr("time.monotonic", lambda: now[0])

    await registry.tick_single_turn("ws-1")
    await registry.tick_single_turn("ws-1")  # within run_result_probe_seconds: no exec
    assert len(runtime.calls) == 1
    now[0] += 21
    await registry.tick_single_turn("ws-1")
    assert len(runtime.calls) == 2
    assert (await registry.store.get("ws-1")).status == "running"
    assert (await registry.run_store.get("ws-1"))["status"] == "running"


async def test_ebs_timeout_takes_a_live_snapshot(sqlite_path, tmp_path: Path):
    runtime = _ScriptRuntime(_task_fs(tmp_path), ready=False)
    registry = await _registry(
        sqlite_path, runtime, _ecs_settings(tmp_path), _spec(ecs_storage="ebs"), timeout=10
    )
    started = runs.parse_iso((await registry.run_store.get("ws-1"))["started_at"])

    await registry.tick_single_turn("ws-1", now=started + timedelta(seconds=11))

    assert runtime.calls == [["/usr/local/bin/warren-run-result", "snapshot"]]
    run = await registry.run_store.get("ws-1")
    assert run["status"] == "timed_out"
    assert run["result"]["exit_code"] is None and run["result"]["result_source"] == "workspace"


async def test_ebs_fallback_without_a_record(sqlite_path, tmp_path: Path):
    """An old image (no warren-run-result) or no ECS Exec: the task exits, the reaper sees
    it stopped, and the run completes with its exit code and an explanation."""
    runtime = SimpleNamespace(exit_code=AsyncMock(return_value=0), destroy=AsyncMock())
    registry = await _registry(sqlite_path, runtime, _ecs_settings(tmp_path), _spec(ecs_storage="ebs"))

    await registry.complete_single_turn("ws-1")

    event = _events(registry)[0]
    assert event["git"] is None and event["verdict"] is None
    assert "EBS volume isn't readable" in event["capture_errors"][0]
    run = await registry.run_store.get("ws-1")
    assert run["status"] == "succeeded"
    assert run["result"]["result_source"] == "control-plane" and run["result"]["git"] == []
    assert run["result"]["final_message"] is None


async def test_ebs_tick_tolerates_exec_failure(sqlite_path, tmp_path: Path):
    async def broken(handle, argv):
        raise RuntimeError("session-manager-plugin is not installed")
        yield  # pragma: no cover

    runtime = SimpleNamespace(exec_stream=broken, destroy=AsyncMock())
    registry = await _registry(sqlite_path, runtime, _ecs_settings(tmp_path), _spec(ecs_storage="ebs"))

    await registry.tick_single_turn("ws-1")

    assert (await registry.store.get("ws-1")).status == "running"
    runtime.destroy.assert_not_awaited()
