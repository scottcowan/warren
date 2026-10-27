"""ECS secret delivery through the workspace's own EFS volume: the control plane's
writer (runtime/ecs_secrets.py), the provision/stop/destroy wiring in ECSRuntime, and
the image side that consumes the file (warren-secrets.sh, entrypoint.sh, git-init)."""

from __future__ import annotations

import asyncio
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from warren.runtime import ecs_secrets
from warren.runtime.ecs_git import WORKSPACE_DIR
from warren.runtime.ecs_secrets import GIT_INIT_FILE, WORKSPACE_FILE, decode, encode
from warren_common.errors import ProvisionError
from warren_common.models import FolderSpec
from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

from .test_ecs_runtime import _make_runtime, _mock_ecs, _mock_ssm

IMAGES = Path(__file__).parents[3] / "images" / "ecs-base"
LIB = IMAGES / "warren-secrets.sh"
WS_ID = "ws-abcdef12-0000"
APP = FolderSpec(name="app", type="git-worktree", mount="code/app",
                 url="https://github.com/org/app.git", branch="main")
VALUES = {
    "ANTHROPIC_API_KEY": "sk-ant $(id) `id` 'q' \"dq\"\nline2\n",
    "GITHUB_PAT": "ghp_x=y",
    "UNDECLARED": "never",
}

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX file semantics")


def _ws_dir(mount: Path) -> Path:
    return mount / "workspaces" / WS_ID


def _secrets_file(mount: Path, name: str = WORKSPACE_FILE) -> Path:
    return _ws_dir(mount) / ".warren" / name


# --- format -----------------------------------------------------------------


def test_format_round_trips_any_value_and_is_inert():
    data = encode(VALUES)
    for line in data.decode().splitlines():
        name, _, b64 = line.partition("=")
        assert name.isidentifier() and set(b64) <= set(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        )
    assert decode(data) == VALUES


@pytest.mark.parametrize("name", ["a-b", "1A", "A B", "x/y", "", "A=B"])
def test_format_refuses_non_env_names(name):
    with pytest.raises(ValueError):
        encode({name: "v"})


def test_decode_skips_malformed_lines():
    assert decode(b"GOOD=dg==\nBAD NAME=dg==\nNOEQ\nX=not base64!\n") == {"GOOD": "v"}


def test_secrets_dir_is_outside_the_working_tree():
    assert not ecs_secrets.CONTAINER_SECRETS_DIR.startswith(WORKSPACE_DIR + "/")
    assert ecs_secrets.CONTAINER_SECRETS_DIR == "/var/lib/warren/.warren"


# --- writer -----------------------------------------------------------------


@posix_only
def test_write_creates_private_dir_and_read_only_file(tmp_path):
    ecs_secrets.write_secrets(str(tmp_path), WS_ID, {WORKSPACE_FILE: {"A": "1"}, GIT_INIT_FILE: {}})
    f = _secrets_file(tmp_path)
    assert decode(f.read_bytes()) == {"A": "1"}
    assert stat.S_IMODE(f.stat().st_mode) == 0o400
    assert stat.S_IMODE(f.parent.stat().st_mode) == 0o700
    assert stat.S_IMODE(_ws_dir(tmp_path).stat().st_mode) == 0o700
    assert sorted(os.listdir(f.parent)) == [WORKSPACE_FILE]  # atomic: no temp file left
    assert not _secrets_file(tmp_path, GIT_INIT_FILE).exists()


@posix_only
def test_write_replaces_a_planted_symlinked_dir_and_never_writes_through_it(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    mount = tmp_path / "mount"
    _ws_dir(mount).mkdir(parents=True)
    (_ws_dir(mount) / ".warren").symlink_to(outside)

    ecs_secrets.write_secrets(str(mount), WS_ID, {WORKSPACE_FILE: {"A": "1"}})

    assert os.listdir(outside) == []
    assert not (_ws_dir(mount) / ".warren").is_symlink()
    assert decode(_secrets_file(mount).read_bytes()) == {"A": "1"}


@posix_only
def test_write_replaces_a_planted_symlink_file_without_following_it(tmp_path):
    target = tmp_path / "target"
    target.write_text("original")
    (_ws_dir(tmp_path) / ".warren").mkdir(parents=True)
    _secrets_file(tmp_path).symlink_to(target)

    ecs_secrets.write_secrets(str(tmp_path), WS_ID, {WORKSPACE_FILE: {"A": "1"}})

    assert target.read_text() == "original"
    assert not _secrets_file(tmp_path).is_symlink()


@posix_only
def test_write_refuses_a_symlinked_workspace_dir(tmp_path):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (tmp_path / "workspaces").mkdir()
    _ws_dir(tmp_path).symlink_to(elsewhere)
    with pytest.raises(OSError):
        ecs_secrets.write_secrets(str(tmp_path), WS_ID, {WORKSPACE_FILE: {"A": "1"}})
    assert os.listdir(elsewhere) == []


def test_write_refuses_a_bad_workspace_id(tmp_path):
    with pytest.raises(ProvisionError):
        ecs_secrets.write_secrets(str(tmp_path), "../x", {WORKSPACE_FILE: {"A": "1"}})


@posix_only
def test_remove_deletes_files_and_temp_leftovers_only(tmp_path):
    ecs_secrets.write_secrets(str(tmp_path), WS_ID, {WORKSPACE_FILE: {"A": "1"}, GIT_INIT_FILE: {"B": "2"}})
    d = _secrets_file(tmp_path).parent
    (d / ".workspace.env.abc.tmp").write_text("x")
    (d / "keep").write_text("x")
    ecs_secrets.remove_secrets(str(tmp_path), WS_ID)
    assert sorted(os.listdir(d)) == ["keep"]
    ecs_secrets.remove_secrets(str(tmp_path), "ws-missing")  # no-op


# --- ECSRuntime wiring --------------------------------------------------------


def _runtime(tmp_path, *, local_mount=True, values=VALUES):
    ecs = _mock_ecs()
    rt = _make_runtime(ecs, _mock_ssm())
    rt._settings = SimpleNamespace(
        efs_id="fs-1", efs_local_mount_path=str(tmp_path) if local_mount else ""
    )
    vol = MagicMock(last_access_point_id="fsap-1")
    vol.attach = AsyncMock()
    vol.detach = AsyncMock()
    rt._volume = vol

    async def secret_values(owner_id, names):
        assert owner_id == "test-user"
        return {n: values[n] for n in names if n in values}

    rt.secret_values = AsyncMock(side_effect=secret_values)
    return rt, ecs


def _spec(folders=(APP,), names=("ANTHROPIC_API_KEY", "GITHUB_PAT", "NOT_SET")):
    return WorkspaceSpec(
        workspace_id=WS_ID, project="p", intent="dev", image="public.ecr.aws/test/warren-base:latest",
        root_path="", owner_id="test-user", folders=list(folders), secret_names=list(names),
    )


@posix_only
def test_provision_delivers_declared_secrets_split_between_containers(tmp_path):
    rt, ecs = _runtime(tmp_path)
    seen = {}

    def run_task(**kw):
        # Written before RunTask, so the task's containers find it at start.
        seen["ws"] = decode(_secrets_file(tmp_path).read_bytes())
        seen["init"] = decode(_secrets_file(tmp_path, GIT_INIT_FILE).read_bytes())
        return {"tasks": [{"taskArn": "arn:task/1"}], "failures": []}

    ecs.run_task.side_effect = run_task
    asyncio.run(rt.provision(_spec()))

    rt.secret_values.assert_awaited_once_with("test-user", ["ANTHROPIC_API_KEY", "GITHUB_PAT", "NOT_SET"])
    assert seen["ws"] == {"ANTHROPIC_API_KEY": VALUES["ANTHROPIC_API_KEY"]}
    assert seen["init"] == {"GITHUB_PAT": VALUES["GITHUB_PAT"]}
    # No value ever reaches the task definition or RunTask.
    sent = repr(ecs.register_task_definition.call_args) + repr(ecs.run_task.call_args)
    for value in VALUES.values():
        assert value.strip() not in sent and "sk-ant" not in sent


@posix_only
def test_relaunch_rewrites_the_file_and_drops_removed_secrets(tmp_path):
    values = dict(VALUES)
    rt, ecs = _runtime(tmp_path, values=values)
    asyncio.run(rt.provision(_spec(folders=())))
    values["ANTHROPIC_API_KEY"] = "rotated"
    asyncio.run(rt.provision(_spec(folders=())))
    assert decode(_secrets_file(tmp_path).read_bytes()) == {
        "ANTHROPIC_API_KEY": "rotated", "GITHUB_PAT": "ghp_x=y"
    }
    del values["ANTHROPIC_API_KEY"], values["GITHUB_PAT"]
    asyncio.run(rt.provision(_spec(folders=())))
    assert not _secrets_file(tmp_path).exists()


@posix_only
def test_adopting_a_live_task_writes_nothing(tmp_path):
    rt, ecs = _runtime(tmp_path)
    rt._find_live_task = AsyncMock(return_value="arn:task/live")
    asyncio.run(rt.provision(_spec()))
    assert not _secrets_file(tmp_path).exists()
    ecs.run_task.assert_not_called()


@posix_only
def test_definitive_run_task_failure_removes_the_file(tmp_path):
    rt, ecs = _runtime(tmp_path)
    ecs.run_task.return_value = {"tasks": [], "failures": [{"reason": "RESOURCE:MEMORY"}]}
    with pytest.raises(ProvisionError):
        asyncio.run(rt.provision(_spec()))
    assert not _secrets_file(tmp_path).exists()
    assert not _secrets_file(tmp_path, GIT_INIT_FILE).exists()


@posix_only
@pytest.mark.parametrize("method", ["stop", "destroy"])
def test_stop_and_destroy_remove_any_lingering_file(tmp_path, method):
    rt, _ = _runtime(tmp_path)
    asyncio.run(rt.provision(_spec()))
    assert _secrets_file(tmp_path).exists()
    handle = WorkspaceHandle(workspace_id=WS_ID, runtime_id="arn:task/1", root_path="")
    asyncio.run(getattr(rt, method)(handle))
    assert not _secrets_file(tmp_path).exists()
    assert not _secrets_file(tmp_path, GIT_INIT_FILE).exists()


def test_secrets_without_an_efs_mount_fail_closed_before_any_aws_call(tmp_path):
    rt, ecs = _runtime(tmp_path, local_mount=False)
    with pytest.raises(ProvisionError, match="WARREN_EFS_LOCAL_MOUNT_PATH"):
        asyncio.run(rt.provision(_spec()))
    ecs.register_task_definition.assert_not_called()
    ecs.run_task.assert_not_called()
    rt._volume.attach.assert_not_awaited()


def test_no_secrets_needs_no_mount(tmp_path):
    rt, ecs = _runtime(tmp_path, local_mount=False, values={})
    asyncio.run(rt.provision(_spec()))
    ecs.run_task.assert_called_once()


@posix_only
def test_non_env_secret_names_are_skipped(tmp_path):
    rt, _ = _runtime(tmp_path, values={"my.key": "x", "OK": "y"})
    asyncio.run(rt.provision(_spec(folders=(), names=("my.key", "OK"))))
    assert decode(_secrets_file(tmp_path).read_bytes()) == {"OK": "y"}


def test_server_never_uses_ssm():
    src = Path(__file__).parents[3] / "src" / "warren"
    for py in src.rglob("*.py"):
        if py.name == "token_issuer.py":  # opt-in GitHub App key source, one named parameter
            continue
        text = py.read_text()
        assert 'client("ssm")' not in text and "put_parameter" not in text, py


# --- image side -----------------------------------------------------------------

shell = pytest.mark.skipif(
    sys.platform == "win32" or shutil.which("base64") is None, reason="needs a POSIX sh + base64"
)


def _write(dirpath: Path, name: str, secrets: dict[str, str]) -> Path:
    dirpath.mkdir(parents=True, exist_ok=True)
    f = dirpath / name
    f.write_bytes(encode(secrets))
    return f


@shell
def test_shell_reader_exports_exact_values_without_evaluating_them(tmp_path):
    d = tmp_path / ".warren"
    f = _write(d, "workspace.env", {"A": VALUES["ANTHROPIC_API_KEY"], "B": "", "C": "x\n\n"})
    with f.open("ab") as fh:
        fh.write(b"BAD;touch pwned=eA==\n1X=eA==\nY=$(touch pwned)\n")
    copy = tmp_path / "run" / "secrets.env"
    out = tmp_path / "out"
    script = (
        f'. "{LIB}"\n'
        f'warren_secrets_take "{d}" workspace.env "{copy}"\n'
        f'printf "%s" "$A" > "{out}.A"; printf "%s" "$B" > "{out}.B"; printf "%s" "$C" > "{out}.C"\n'
        'env | grep -c "^Y=" > "' + str(out) + '.Y" || true\n'
    )
    r = subprocess.run(["/bin/sh", "-c", script], cwd=tmp_path, capture_output=True, text=True, timeout=10)
    assert r.returncode == 0, r.stderr
    assert Path(f"{out}.A").read_text() == VALUES["ANTHROPIC_API_KEY"]
    assert Path(f"{out}.B").read_text() == ""
    assert Path(f"{out}.C").read_text() == "x\n\n"
    assert Path(f"{out}.Y").read_text().strip() == "0"
    assert not (tmp_path / "pwned").exists()
    assert not f.exists()
    assert stat.S_IMODE(copy.stat().st_mode) == 0o600 and decode(copy.read_bytes())["A"]
    assert VALUES["ANTHROPIC_API_KEY"] not in r.stdout + r.stderr


@shell
def test_shell_reader_ignores_a_symlinked_dir(tmp_path):
    real = tmp_path / "real"
    f = _write(real, "workspace.env", {"A": "1"})
    (tmp_path / "link").symlink_to(real)
    script = f'. "{LIB}"\nwarren_secrets_take "{tmp_path / "link"}" workspace.env\nprintf "%s" "${{A:-unset}}"\n'
    r = subprocess.run(["/bin/sh", "-c", script], capture_output=True, text=True, timeout=10)
    assert r.stdout == "unset" and f.exists()


def _entrypoint(tmp_path: Path) -> Path:
    text = (IMAGES / "entrypoint.sh").read_text()
    text = text.replace("/usr/local/lib/warren/secrets.sh", str(LIB))
    text = text.replace("/var/lib/warren", str(tmp_path / "vol"))
    script = tmp_path / "entrypoint.sh"
    script.write_text(text)
    return script


@shell
@pytest.mark.skipif(os.geteuid() == 0, reason="runs the entrypoint's non-root path")
def test_entrypoint_exports_secrets_and_deletes_both_files_before_the_app_starts(tmp_path):
    d = tmp_path / "vol" / ".warren"
    ws = _write(d, "workspace.env", {"API_KEY": "s3cret\n"})
    init = _write(d, "git-init.env", {"GITHUB_PAT": "clone-only"})
    out = tmp_path / "out"
    app = (
        f'printf "%s" "$API_KEY" > {out}; '
        f'[ -e {ws} ] || [ -e {init} ] && echo LEFT >> {out}; '
        f'printf "%s" "${{GITHUB_PAT:-}}" >> {out}'
    )
    r = subprocess.run(
        ["/bin/sh", str(_entrypoint(tmp_path))],
        env={"PATH": os.environ["PATH"], "HOME": str(tmp_path), "WARREN_APP_CMD": app},
        capture_output=True, text=True, timeout=20,
    )
    assert r.returncode == 0, r.stderr
    assert out.read_text() == "s3cret\n"  # exported, both files gone, no clone credential
    assert "s3cret" not in r.stdout + r.stderr


def test_entrypoint_and_session_consume_before_any_workspace_process():
    text = (IMAGES / "entrypoint.sh").read_text()
    take = text.index("warren_secrets_take /var/lib/warren/.warren workspace.env")
    for later in ("/usr/local/bin/warren-init-volume", "exec /sbin/su-exec warren:warren",
                  "warren-harness-init", 'exec sh -c "$WARREN_APP_CMD"'):
        assert take < text.index(later), later
    session = (IMAGES / "warren-session.sh").read_text()
    assert session.index("warren_secrets_load /run/warren/secrets.env") < session.index(
        "exec /sbin/su-exec warren:warren"
    )
    dockerfile = (IMAGES / "Dockerfile").read_text()
    assert "warren-secrets.sh /usr/local/lib/warren/secrets.sh" in dockerfile


needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


@shell
@needs_git
@pytest.mark.skipif(os.geteuid() == 0, reason="runs git-init's non-root path")
def test_git_init_reads_its_credentials_from_the_file_and_deletes_it(tmp_path):
    root = tmp_path / "efs"
    init = _write(root / ".warren", "git-init.env", {"GITHUB_PAT": "ghp_secret"})
    script = tmp_path / "git-materialize.sh"
    script.write_text(
        (IMAGES / "git-materialize.sh").read_text().replace("/usr/local/lib/warren/secrets.sh", str(LIB))
    )
    record = "\t".join(["clone", "app", "code/app", "https://127.0.0.1:9/x.git", "main", "-", "pat", "GITHUB_PAT"])
    r = subprocess.run(
        ["sh", str(script)],
        env={"PATH": os.environ["PATH"], "WARREN_GIT_ROOT": str(root), "WARREN_GIT_FOLDERS": record},
        capture_output=True, text=True, timeout=60,
    )
    assert not init.exists()
    assert "credential GITHUB_PAT not set" not in r.stderr  # it was found in the file
    assert "ghp_secret" not in r.stdout + r.stderr
