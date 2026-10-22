"""Wave 0 RED: NsjailRuntime provision/exec/status/destroy (Plan 05-02/05-04).

Every test is xfail-guarded on the not-yet-shipped implementation. The tests
pin down the behavioural contract:

  - provision writes nsjail.cfg AND state.json to the out-of-tree state dir
  - state.json is written atomically (tmp + os.replace)
  - status distinguishes provisioned/stopped/unknown
  - exec streams stdout chunks
  - destroy removes the workspace dir
  - preflight raises RuntimeUnreachable when the binary path is missing
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
from pathlib import Path
import sys
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="nsjail is a Linux sandbox"
)


@pytest.fixture
def fake_nsjail(tmp_path: Path, monkeypatch) -> Path:
    """Install a fake executable at WARREN_NSJAIL_PATH so preflight passes."""
    binary = tmp_path / "fake-nsjail"
    binary.write_text("#!/bin/sh\nexit 0\n")
    binary.chmod(binary.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    monkeypatch.setenv("WARREN_NSJAIL_PATH", str(binary))
    return binary


def _spec(workspace_id: str, root_path: str):
    from warren_common.runtime.base import WorkspaceSpec

    return WorkspaceSpec(
        workspace_id=workspace_id,
        project="demo-project",
        intent="claude",
        image="",
        root_path=root_path,
        env={"ANTHROPIC_API_KEY": "sk-test"},
        worktree_paths=[(f"{root_path}/main", "/workspace/main")],
        reference_paths=[],
        app="claude",
    )


@pytest.mark.asyncio
async def test_provision_writes_cfg_and_state(tmp_path: Path, fake_nsjail, monkeypatch):
    from warren_common.runtime.nsjail import NsjailRuntime

    # state.json (env_snapshot holds secrets) lives OUTSIDE root_path (R3) —
    # WARREN_STATE_DIR override avoids writing into the real operator home.
    monkeypatch.setenv("WARREN_STATE_DIR", str(tmp_path / "state"))
    root = tmp_path / "ws-1"
    root.mkdir()
    rt = NsjailRuntime(server_id="test-host")
    handle = await rt.provision(_spec("ws-1", str(root)))

    # workspace_dir must be chmod 0o700 (T-05-08)
    assert stat.S_IMODE(root.stat().st_mode) == 0o700

    assert not (root / "nsjail.cfg").exists()
    assert not (root / "state.json").exists()

    assert handle.state_dir, "nsjail must report where state.json lives"
    cfg_path = Path(handle.state_dir) / "nsjail.cfg"
    assert cfg_path.exists() and cfg_path.stat().st_size > 0
    assert stat.S_IMODE(cfg_path.stat().st_mode) == 0o600
    state_path = Path(handle.state_dir) / "state.json"
    assert state_path.exists()

    state = json.loads(state_path.read_text())
    for key in (
        "workspace_id",
        "project",
        "intent",
        "app",
        "root_path",
        "worktree_paths",
        "created_at",
    ):
        assert key in state, f"state.json missing key {key!r}: {state!r}"
    assert state["workspace_id"] == "ws-1"


@pytest.mark.asyncio
async def test_provision_state_written_atomically(tmp_path: Path, fake_nsjail, monkeypatch):
    """If json.dumps blows up mid-write, no partial state.json is readable."""
    from warren_common.runtime.nsjail import NsjailRuntime

    state_dir_override = tmp_path / "state"
    monkeypatch.setenv("WARREN_STATE_DIR", str(state_dir_override))
    root = tmp_path / "ws-2"
    root.mkdir()
    rt = NsjailRuntime(server_id="test-host")

    with patch("warren_common.runtime.nsjail.json.dumps", side_effect=RuntimeError("boom")):
        with pytest.raises(RuntimeError):
            await rt.provision(_spec("ws-2", str(root)))

    # The final state.json must NOT be readable (either absent, or if a tmp
    # sibling exists it is not the canonical name).
    assert not (root / "state.json").exists()
    assert not (state_dir_override / "ws-2" / "state.json").exists()


@pytest.mark.asyncio
async def test_status_returns_stopped_when_state_json_exists(tmp_path: Path):
    from warren_common.runtime.base import WorkspaceHandle
    from warren_common.runtime.nsjail import NsjailRuntime

    root = tmp_path / "ws-3"
    root.mkdir()
    state_dir = tmp_path / "state-3"
    state_dir.mkdir()
    (state_dir / "state.json").write_text('{"workspace_id": "ws-3"}')
    rt = NsjailRuntime(server_id="test-host")
    handle = WorkspaceHandle(
        workspace_id="ws-3",
        runtime_id="",
        root_path=str(root),
        sidecar_url="",
        state_dir=str(state_dir),
    )
    assert await rt.status(handle) == "stopped"


@pytest.mark.asyncio
async def test_status_returns_unknown_when_no_state_json(tmp_path: Path):
    from warren_common.runtime.base import WorkspaceHandle
    from warren_common.runtime.nsjail import NsjailRuntime

    rt = NsjailRuntime(server_id="test-host")
    handle = WorkspaceHandle(
        workspace_id="ws-missing",
        runtime_id="",
        root_path=str(tmp_path / "does-not-exist"),
        sidecar_url="",
    )
    assert await rt.status(handle) == "unknown"


# Fields every post-BB3 state.json carries (see test_write_cfg_refuses_pre_bb3_state).
_PERSISTED = {"bind_mounts": [], "ssh_key_paths": [], "ssh_agent_sock": None}


@pytest.mark.asyncio
async def test_exec_streams_stdout(tmp_path: Path, monkeypatch):
    from warren_common.runtime.base import WorkspaceHandle
    from warren_common.runtime.nsjail import NsjailRuntime

    monkeypatch.setenv("WARREN_STATE_DIR", str(tmp_path / "state"))
    root = tmp_path / "ws-4"
    root.mkdir()
    (tmp_path / "state" / "ws-4").mkdir(parents=True)
    (tmp_path / "state" / "ws-4" / "state.json").write_text(json.dumps(_PERSISTED))

    fake_stdout = MagicMock()
    fake_stdout.read = AsyncMock(side_effect=[b"chunk-1", b"chunk-2", b""])
    fake_proc = MagicMock(stdout=fake_stdout)
    fake_proc.wait = AsyncMock(return_value=0)

    async def _fake_create(*args, **kwargs):
        return fake_proc

    with patch(
        "warren_common.runtime.nsjail.asyncio.create_subprocess_exec",
        new=_fake_create,
    ):
        rt = NsjailRuntime(server_id="test-host")
        handle = WorkspaceHandle(
            workspace_id="ws-4",
            runtime_id="",
            root_path=str(root),
            sidecar_url="",
        )
        chunks = [chunk async for chunk in rt.exec(handle, ["/bin/echo", "hi"])]

    assert b"chunk-1" in chunks
    assert b"chunk-2" in chunks


@pytest.mark.asyncio
async def test_exec_writes_secret_env_file_and_deletes_only_after_process_exits(
    tmp_path: Path, monkeypatch
):
    """S6 follow-up: secrets travel via a short-lived env file sourced inside
    the jail (never as plaintext `envar:` lines in nsjail.cfg, and never on
    this process's own argv). Code-review fix: the file must still exist for
    the ENTIRE subprocess lifetime -- deleting it right after spawn (instead
    of after the process actually exits) races against nsjail's own
    bind-mount setup, which happens inside the child's startup, asynchronously
    from this parent process's perspective."""
    from warren_common.runtime.base import WorkspaceHandle
    from warren_common.runtime.nsjail import NsjailRuntime
    from warren_common.runtime.sandbox_env import nsjail_secret_env_path

    monkeypatch.setenv("WARREN_STATE_DIR", str(tmp_path / "state"))

    root = tmp_path / "ws-5"
    root.mkdir()
    (tmp_path / "state" / "ws-5").mkdir(parents=True)
    (tmp_path / "state" / "ws-5" / "state.json").write_text(
        json.dumps({"env_snapshot": {"ANTHROPIC_API_KEY": "sk-should-not-leak"}, **_PERSISTED})
    )

    env_path = nsjail_secret_env_path("ws-5")
    existed_at_spawn_time = {}

    fake_stdout = MagicMock()
    fake_stdout.read = AsyncMock(side_effect=[b""])
    fake_proc = MagicMock(stdout=fake_stdout)
    fake_proc.wait = AsyncMock(return_value=0)

    async def _fake_create(*args, **kwargs):
        # The env file must exist (and NOT yet be deleted) at the moment the
        # subprocess is spawned -- this is the moment nsjail itself would be
        # performing its own bind-mount setup.
        existed_at_spawn_time["value"] = env_path.exists()
        if env_path.exists():
            existed_at_spawn_time["content"] = env_path.read_text()
        return fake_proc

    with patch(
        "warren_common.runtime.nsjail.asyncio.create_subprocess_exec",
        new=_fake_create,
    ):
        rt = NsjailRuntime(server_id="test-host")
        handle = WorkspaceHandle(
            workspace_id="ws-5", runtime_id="", root_path=str(root), sidecar_url=""
        )
        assert not env_path.exists()  # not written before exec() runs
        [chunk async for chunk in rt.exec(handle, ["/bin/echo", "hi"])]

    assert existed_at_spawn_time["value"] is True
    assert "sk-should-not-leak" in existed_at_spawn_time["content"]
    # Deleted only AFTER the (fake) process has fully "exited" -- i.e. after
    # exec() returns, not the instant the subprocess object was created.
    assert not env_path.exists()


@pytest.mark.asyncio
async def test_exec_deletes_secret_env_file_even_if_subprocess_raises(
    tmp_path: Path, monkeypatch
):
    """The env file must never be left behind on disk even when spawning or
    streaming fails -- it's still cleaned up via the surrounding try/finally."""
    from warren_common.runtime.base import WorkspaceHandle
    from warren_common.runtime.nsjail import NsjailRuntime
    from warren_common.runtime.sandbox_env import nsjail_secret_env_path

    monkeypatch.setenv("WARREN_STATE_DIR", str(tmp_path / "state"))

    root = tmp_path / "ws-6"
    root.mkdir()
    (tmp_path / "state" / "ws-6").mkdir(parents=True)
    (tmp_path / "state" / "ws-6" / "state.json").write_text(
        json.dumps({"env_snapshot": {"K": "v"}, **_PERSISTED})
    )

    env_path = nsjail_secret_env_path("ws-6")

    async def _fake_create_raises(*args, **kwargs):
        raise OSError("nsjail binary not found")

    with patch(
        "warren_common.runtime.nsjail.asyncio.create_subprocess_exec",
        new=_fake_create_raises,
    ):
        rt = NsjailRuntime(server_id="test-host")
        handle = WorkspaceHandle(
            workspace_id="ws-6", runtime_id="", root_path=str(root), sidecar_url=""
        )
        with pytest.raises(OSError):
            [chunk async for chunk in rt.exec(handle, ["/bin/echo", "hi"])]

    assert not env_path.exists()


@pytest.mark.asyncio
async def test_destroy_removes_workspace_dir_and_state_dir(tmp_path: Path):
    from warren_common.runtime.base import WorkspaceHandle
    from warren_common.runtime.nsjail import NsjailRuntime

    root = tmp_path / "ws-5"
    root.mkdir()
    (root / "nsjail.cfg").write_text("mode: ONCE\n")
    state_dir = tmp_path / "state-5"
    state_dir.mkdir()
    (state_dir / "state.json").write_text("{}")

    rt = NsjailRuntime(server_id="test-host")
    handle = WorkspaceHandle(
        workspace_id="ws-5",
        runtime_id="",
        root_path=str(root),
        sidecar_url="",
        state_dir=str(state_dir),
    )
    await rt.destroy(handle)
    assert not root.exists()
    assert not state_dir.exists()


@pytest.mark.asyncio
async def test_provision_never_writes_state_json_under_root_path(tmp_path: Path, fake_nsjail, monkeypatch):
    """R3: nsjail's state.json (env_snapshot holds secrets) must never live
    under root_path — root_path is bound rw into the jail by nsjail's own
    config, so a state.json stored there could be rewritten by the jailed
    process and trusted on the next `warren connect` (same class of bug the
    seatbelt/bwrap runtimes were already fixed for)."""
    from warren_common.runtime.nsjail import NsjailRuntime

    monkeypatch.setenv("WARREN_STATE_DIR", str(tmp_path / "state"))
    root = tmp_path / "ws-6"
    root.mkdir()
    rt = NsjailRuntime(server_id="test-host")
    handle = await rt.provision(_spec("ws-6", str(root)))

    assert not (root / "state.json").exists()
    assert handle.state_dir and not handle.state_dir.startswith(str(root))


@pytest.mark.asyncio
async def test_preflight_raises_when_binary_missing(tmp_path: Path, monkeypatch):
    from warren_common.errors import RuntimeUnreachable
    from warren_common.runtime.nsjail import NsjailRuntime

    missing = tmp_path / "no-such-nsjail"
    monkeypatch.setenv("WARREN_NSJAIL_PATH", str(missing))
    with pytest.raises(RuntimeUnreachable) as ei:
        rt = NsjailRuntime(server_id="test-host")
        # First-use fallback: if construction is lazy, force preflight now.
        preflight = getattr(rt, "preflight", None)
        if preflight is not None:
            maybe = preflight()
            if asyncio.iscoroutine(maybe):
                await maybe
    assert "nsjail binary not found" in str(ei.value).lower()


@pytest.mark.asyncio
async def test_exec_regenerates_cfg_and_ignores_tampered_copies(
    tmp_path: Path, fake_nsjail, monkeypatch
):
    """BB3: a jailed process can write the workspace root, so a nsjail.cfg
    there (or a tampered one in the state dir) must never be what nsjail runs."""
    from warren_common.runtime.base import WorkspaceSpec
    from warren_common.runtime.nsjail import NsjailRuntime

    monkeypatch.setenv("WARREN_STATE_DIR", str(tmp_path / "state"))
    root = tmp_path / "ws-7"
    root.mkdir()
    spec = WorkspaceSpec(
        workspace_id="ws-7", project="p", intent="t", image="",
        root_path=str(root), bind_mounts=[("/srv/data", "data", "ro")],
    )
    rt = NsjailRuntime(server_id="test-host")
    handle = await rt.provision(spec)
    state_cfg = Path(handle.state_dir) / "nsjail.cfg"
    original = state_cfg.read_text()

    (root / "nsjail.cfg").write_text('mount { src: "/" dst: "/host" rw: true }\n')
    state_cfg.write_text('mount { src: "/" dst: "/host" rw: true }\n')

    seen: dict = {}
    fake_stdout = MagicMock()
    fake_stdout.read = AsyncMock(side_effect=[b""])
    fake_proc = MagicMock(stdout=fake_stdout)
    fake_proc.wait = AsyncMock(return_value=0)

    async def _fake_create(*args, **kwargs):
        cfg_arg = Path(args[args.index("--config") + 1])
        seen["cfg_path"] = cfg_arg
        seen["cfg_text"] = cfg_arg.read_text()
        return fake_proc

    with patch("warren_common.runtime.nsjail.asyncio.create_subprocess_exec", new=_fake_create):
        [chunk async for chunk in rt.exec(handle, ["/bin/true"])]

    assert seen["cfg_path"] == state_cfg
    assert not seen["cfg_path"].is_relative_to(root)
    assert seen["cfg_text"] == original
    assert 'dst: "/host"' not in seen["cfg_text"]
    assert '"/srv/data"' in seen["cfg_text"]


def test_write_cfg_refuses_pre_bb3_state(tmp_path: Path):
    """BB14: state.json without bind_mounts/ssh fields would regenerate a
    config that silently drops them -- refuse with a recreate hint instead."""
    import json

    from warren_common.errors import WorkspaceNeedsRecreate
    from warren_common.runtime.nsjail import write_nsjail_cfg

    state_dir = tmp_path / "state" / "ws-old"
    state_dir.mkdir(parents=True)
    (state_dir / "state.json").write_text(json.dumps({
        "workspace_id": "ws-old", "root_path": str(tmp_path / "ws-old"),
        "cfg_path": str(tmp_path / "ws-old" / "nsjail.cfg"),
    }))
    with pytest.raises(WorkspaceNeedsRecreate, match="warren destroy ws-old"):
        write_nsjail_cfg(state_dir, "ws-old")
    assert not (state_dir / "nsjail.cfg").exists()

    state = json.loads((state_dir / "state.json").read_text())
    state.update(bind_mounts=[], ssh_key_paths=[], ssh_agent_sock=None)
    (state_dir / "state.json").write_text(json.dumps(state))
    assert write_nsjail_cfg(state_dir, "ws-old").is_file()


@pytest.mark.asyncio
async def test_provision_records_absolute_nsjail_path(tmp_path: Path, fake_nsjail, monkeypatch):
    """AE2: the nsjail binary is resolved once and recorded as an absolute path."""
    from warren_common.runtime.nsjail import NsjailRuntime

    monkeypatch.setenv("WARREN_STATE_DIR", str(tmp_path / "state"))
    root = tmp_path / "ws-abs"
    root.mkdir()
    rt = NsjailRuntime(server_id="h")
    handle = await rt.provision(_spec("ws-abs", str(root)))
    state = json.loads((Path(handle.state_dir) / "state.json").read_text())
    assert state["nsjail_path"] == os.path.realpath(fake_nsjail)


def test_relative_nsjail_env_path_ignored(monkeypatch):
    from warren_common.runtime_detect import resolve_nsjail

    monkeypatch.setenv("WARREN_NSJAIL_PATH", "nsjail")
    monkeypatch.setenv("PATH", "/nonexistent")
    assert resolve_nsjail() in (None, "/usr/sbin/nsjail")


def test_reference_clones_mounted_read_only():
    """AE1 equivalent: reference clones are ro mounts, so their git dir can't be renamed."""
    from warren_common.runtime.base import WorkspaceSpec
    from warren_common.runtime.nsjail_config import NsjailConfig

    spec = WorkspaceSpec(
        workspace_id="w", project="p", intent="i", image="", root_path="/ws",
        reference_paths=[("/refs/repo", "/refs/repo")],
    )
    mounts = [m for m in NsjailConfig.from_spec(spec).mounts if m.src == "/refs/repo"]
    assert len(mounts) == 1 and mounts[0].rw is False
