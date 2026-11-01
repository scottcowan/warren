"""EBS single-turn runs: the task env and the result record (runtime/ecs_run_result.py)."""

from __future__ import annotations

import base64
from pathlib import Path

import pytest
from warren.runtime import ecs_run_result as rr
from warren_common.models import FolderSpec
from warren_common.runtime.base import ExecExit, WorkspaceHandle

from .test_ecs_ebs import _env, _runtime, _spec

ENTRYPOINT = Path(__file__).parents[3] / "images" / "ecs-base" / "entrypoint.sh"
DOCKERFILE = Path(__file__).parents[3] / "images" / "ecs-base" / "Dockerfile"
HANDLE = WorkspaceHandle(workspace_id="ws-1", runtime_id="arn:task", root_path="")


def _line(key: str, value: str) -> bytes:
    return key.encode() + b"\t" + base64.b64encode(value.encode()) + b"\n"


def test_run_result_env_lists_safe_git_checkouts():
    folders = [
        FolderSpec(name="app", type="git-worktree", url="https://x/app.git", mount="code/app", branch="main"),
        FolderSpec(name="ref", type="git-clone", url="https://x/ref.git", mount="refs/ref", branch="dev;rm"),
        FolderSpec(name="wiki", type="local-path", path="/w", mount="wiki"),
    ]
    env = rr.run_result_env(folders, 120)
    assert env == {
        "WARREN_RUN_RESULT": "1",
        "WARREN_RUN_RESULT_HOLD_SECONDS": "120",
        "WARREN_RUN_REPOS": "code/app=main refs/ref",
    }


async def test_ebs_single_turn_task_gets_the_run_result_env():
    rt, ecs, _ = _runtime()
    rt._settings.run_result_hold_seconds = 90
    await rt.provision(_spec(app="claude -p hi", mode="single-turn"))
    env = _env(ecs, "workspace")
    assert env["WARREN_RUN_RESULT"] == "1" and env["WARREN_RUN_RESULT_HOLD_SECONDS"] == "90"


@pytest.mark.parametrize("over", [dict(mode="interactive", app="acp-serve"), dict(mode="single-turn", app="claude", ecs_storage="efs")])
async def test_other_tasks_do_not(over):
    rt, ecs, _ = _runtime(storage=over.get("ecs_storage", "ebs"))
    await rt.provision(_spec(**over))
    assert "WARREN_RUN_RESULT" not in _env(ecs, "workspace")


def test_parse_record_groups_repo_fields_and_skips_noise():
    raw = (
        b"Starting session with SessionId: abc\r\n"
        + _line("version", "1") + _line("exit_code", "3") + _line("output", "hello\n")
        + _line("repo", "code/a") + _line("repo.branch", "warren/x")
        + b"garbage line\n" + b"bad\t!!notbase64\n"
        + _line("repo", "code/b") + _line("repo.error", "no checkout")
    )
    rec = rr.parse_record(raw.replace(b"\n", b"\r\n"))
    assert rec["exit_code"] == "3" and rec["output"] == "hello\n"
    assert rec["repos"] == [{"mount": "code/a", "branch": "warren/x"}, {"mount": "code/b", "error": "no checkout"}]


def test_parse_record_requires_v1():
    with pytest.raises(rr.ResultUnavailable):
        rr.parse_record(_line("exit_code", "0"))


async def test_read_result_maps_exit_codes_and_failures():
    def runtime(*items, exc=None):
        async def exec_stream(handle, argv):
            if exc is not None:
                raise exc
            for item in items:
                yield item

        return type("R", (), {"exec_stream": staticmethod(exec_stream)})()

    assert await rr.read_result(runtime(_line("version", "1"), ExecExit(0)), HANDLE) == _line("version", "1")
    with pytest.raises(rr.ResultUnavailable, match="no result recorded yet"):
        await rr.read_result(runtime(ExecExit(3)), HANDLE)
    with pytest.raises(rr.ResultUnavailable, match="exec failed"):
        await rr.read_result(runtime(exc=RuntimeError("no plugin")), HANDLE)
    with pytest.raises(rr.ResultUnavailable, match="exceeds"):
        await rr.read_result(runtime(b"x" * (rr.MAX_RECORD_BYTES + 1), ExecExit(0)), HANDLE)
    with pytest.raises(rr.ResultUnavailable, match="no exec"):
        await rr.read_result(object(), HANDLE)


def test_image_installs_the_script_and_entrypoint_uses_it():
    assert "/usr/local/bin/warren-run-result" in DOCKERFILE.read_text()
    text = ENTRYPOINT.read_text()
    run_block = text.index('"${WARREN_RUN_RESULT:-}" = 1')
    assert run_block < text.index('exec sh -c "$WARREN_APP_CMD"')
    assert "warren-run-result write" in text
