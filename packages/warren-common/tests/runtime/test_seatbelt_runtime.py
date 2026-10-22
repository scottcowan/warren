"""Wave 0 GREEN: SeatbeltRuntime profile emission + exec shape (Plan 05b-05)."""

from __future__ import annotations

import json
import logging
import os
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from warren_common.runtime.base import RuntimeConfig, WorkspaceSpec
from warren_common.runtime.seatbelt import SeatbeltRuntime

# Explicit loop scope prevents cross-package asyncio event loop interference
# when tests run alongside warren-common tests (which use aiosqlite).
pytestmark = [
    pytest.mark.asyncio(loop_scope="function"),
    pytest.mark.skipif(sys.platform == "win32", reason="seatbelt is a macOS sandbox"),
]


def _spec(root_path: str, **over) -> WorkspaceSpec:
    kw = dict(
        workspace_id="ws-1",
        project="proj",
        intent="int",
        image="",
        root_path=root_path,
    )
    kw.update(over)
    return WorkspaceSpec(**kw)


@pytest.fixture
def rt(tmp_path, monkeypatch) -> SeatbeltRuntime:
    # state.json/sandbox.sb live OUTSIDE root_path (finding #1) — WARREN_STATE_DIR
    # keeps unit tests from writing into the real operator ~/.warren/state/.
    monkeypatch.setenv("WARREN_STATE_DIR", str(tmp_path / "state"))
    r = SeatbeltRuntime(server_id="srv-1", config=RuntimeConfig(type="nsjail"))
    r._preflight_ok = True  # skip binary check in unit tests
    return r


async def test_profile_written_atomically(tmp_path, rt):
    spec = _spec(str(tmp_path / "ws"))
    handle = await rt.provision(spec)
    assert handle.state_dir, "seatbelt must report where sandbox.sb/state.json live"
    profile = Path(handle.state_dir) / "sandbox.sb"
    state = Path(handle.state_dir) / "state.json"
    assert profile.is_file()
    assert state.is_file()
    assert not (Path(handle.root_path) / "sandbox.sb").exists(), (
        "sandbox.sb must not live under root_path — a sandboxed process can write there"
    )
    assert not (Path(handle.root_path) / "state.json").exists()
    # 0o600 mode
    assert profile.stat().st_mode & 0o777 == 0o600
    assert state.stat().st_mode & 0o777 == 0o600
    text = profile.read_text()
    assert '(allow file-read* (literal "/"))' in text
    payload = json.loads(state.read_text())
    assert payload["schema_version"] == 1
    assert payload["profile_path"] == str(profile)


async def test_env_snapshot_in_state_not_profile(tmp_path, rt):
    spec = _spec(str(tmp_path / "ws"), env={"SECRET": "s3cret", "FOO": "bar"})
    handle = await rt.provision(spec)
    profile_text = (Path(handle.state_dir) / "sandbox.sb").read_text()
    assert "SECRET" not in profile_text
    assert "s3cret" not in profile_text
    state = json.loads((Path(handle.state_dir) / "state.json").read_text())
    assert state["env_snapshot"] == {"SECRET": "s3cret", "FOO": "bar"}


async def test_env_via_subprocess_not_profile(tmp_path, rt):
    spec = _spec(str(tmp_path / "ws"), env={"SECRET": "s3cret"})
    handle = await rt.provision(spec)

    captured: dict = {}

    class FakeProc:
        def __init__(self):
            self.stdout = AsyncMock()
            self.stdout.read = AsyncMock(side_effect=[b"out", b""])

        async def wait(self):
            return 0

    async def fake_create(*args, **kwargs):
        captured["args"] = args
        captured["env"] = kwargs.get("env")
        return FakeProc()

    with patch("asyncio.create_subprocess_exec", side_effect=fake_create):
        chunks = []
        async for c in rt.exec(handle, ["echo", "hi"]):
            chunks.append(c)

    state = json.loads((Path(handle.state_dir) / "state.json").read_text())
    params = [a for k, v in state["profile_params"].items() for a in ("-D", f"{k}={v}")]
    assert captured["args"][0] == "/usr/bin/sandbox-exec"
    assert captured["args"][1] == "-f"
    assert captured["args"][2] == str(Path(handle.state_dir) / "sandbox.sb")
    assert list(captured["args"][3:-2]) == params
    assert captured["args"][-2:] == ("echo", "hi")
    assert captured["env"]["SECRET"] == "s3cret"


async def test_exec_env_is_allowlisted_not_full_os_environ(tmp_path, rt, monkeypatch):
    """Audit finding #4: exec() used to merge the operator's FULL os.environ
    on top of env_snapshot — any AWS key/API token sitting in the operator's
    own shell (not declared by the template) would reach the sandboxed
    process. Only the base allow-list (PATH/HOME/TERM/LANG) plus env_snapshot
    may appear."""
    monkeypatch.setenv("WARREN_TOTALLY_UNRELATED_HOST_SECRET", "leaked-if-broken")
    spec = _spec(str(tmp_path / "ws"), env={"FOO": "bar"})
    handle = await rt.provision(spec)

    captured: dict = {}

    class FakeProc:
        def __init__(self):
            self.stdout = AsyncMock()
            self.stdout.read = AsyncMock(side_effect=[b"", b""])

        async def wait(self):
            return 0

    async def fake_create(*args, **kwargs):
        captured["env"] = kwargs.get("env")
        return FakeProc()

    with patch("asyncio.create_subprocess_exec", side_effect=fake_create):
        async for _ in rt.exec(handle, ["true"]):
            pass

    assert "WARREN_TOTALLY_UNRELATED_HOST_SECRET" not in captured["env"]
    assert captured["env"]["FOO"] == "bar"


async def test_ignores_spec_image_with_warning(tmp_path, rt):
    import structlog
    from structlog.testing import capture_logs
    spec = _spec(str(tmp_path / "ws"), image="python:3.12")
    with capture_logs() as logs:
        await rt.provision(spec)
    # image is ignored (D-21); structlog warning emitted
    events = [e["event"] for e in logs]
    assert any("seatbelt_ignoring_spec_image" in e for e in events), f"Expected warning not found in: {events}"


def test_prior_art_attribution_comment():
    src = Path(__file__).parent.parent.parent / "src/warren_common/runtime/seatbelt.py"
    assert "akitaonrails/ai-jail" in src.read_text()


async def test_status_unknown_when_state_missing(tmp_path, rt):
    spec = _spec(str(tmp_path / "ws"))
    handle = await rt.provision(spec)
    os.remove(Path(handle.state_dir) / "state.json")
    assert await rt.status(handle) == "unknown"


async def test_destroy_removes_workspace(tmp_path, rt):
    spec = _spec(str(tmp_path / "ws"))
    handle = await rt.provision(spec)
    root = Path(handle.root_path)
    state_dir = Path(handle.state_dir)
    assert root.exists()
    assert state_dir.exists()
    await rt.destroy(handle)
    assert not root.exists()
    # The out-of-tree state dir (env_snapshot secrets, T-05b-19) must not be
    # left orphaned on disk after destroy.
    assert not state_dir.exists()


async def test_sandbox_sb_and_state_json_not_under_root_path(tmp_path, rt):
    """Audit finding #1: root_path is `(allow file-write* (subpath root_path))`
    in the generated profile itself — so a sandbox.sb/state.json stored under
    root_path is a profile a sandboxed process could rewrite and have trusted
    on the NEXT `warren connect`. They must live entirely outside root_path."""
    spec = _spec(str(tmp_path / "ws"))
    handle = await rt.provision(spec)
    root = Path(handle.root_path)
    state_dir = Path(handle.state_dir)
    assert not str(state_dir).startswith(str(root) + "/")
    assert state_dir != root
    assert (state_dir / "sandbox.sb").is_file()
    assert (state_dir / "state.json").is_file()
    assert not (root / "sandbox.sb").exists()
    assert not (root / "state.json").exists()


def test_preflight_missing_binary_raises(monkeypatch):
    from warren_common.errors import RuntimeUnreachable

    r = SeatbeltRuntime(server_id="s", config=None)
    r.sandbox_exec_path = "/nonexistent/sandbox-exec"
    with pytest.raises(RuntimeUnreachable):
        r.preflight()


def test_sandbox_exec_is_absolute_and_not_env_overridable(monkeypatch):
    """AE2: a PATH (or env) lookup would let a planted `sandbox-exec` run the
    next connect unsandboxed."""
    monkeypatch.setenv("WARREN_SANDBOX_EXEC_PATH", "/tmp/fake-sandbox-exec")
    monkeypatch.setenv("PATH", "/tmp")
    assert SeatbeltRuntime(server_id="s", config=None).sandbox_exec_path == "/usr/bin/sandbox-exec"


async def test_profile_params_persisted_in_state(tmp_path, rt):
    """AE3: the profile references paths as params; state.json carries their
    values so exec/connect can pass them as -D."""
    handle = await rt.provision(_spec(str(tmp_path / "ws")))
    text = (Path(handle.state_dir) / "sandbox.sb").read_text()
    state = json.loads((Path(handle.state_dir) / "state.json").read_text())
    assert str(tmp_path / "ws") not in text
    assert os.path.realpath(tmp_path / "ws") in state["profile_params"].values()
