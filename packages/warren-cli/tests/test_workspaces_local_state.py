"""Audit finding #1 (2026-10-16): the sandbox profile/state a `warren connect`
reconnects to must come from OUTSIDE the workspace root, never from inside
it — otherwise a sandboxed process could rewrite its own sandbox.sb/
state.json and have the rewritten one trusted on the next connect.

These tests cover `commands/workspaces.py::_load_workspace_state`, the
lookup `warren connect <id>`/`warren exec <id>` uses to reconnect to an
*already-provisioned* workspace — the actual "next connect" attack surface
the finding describes.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from warren_cli.commands.workspaces import _load_workspace_state

posix_exec_only = pytest.mark.skipif(
    sys.platform == "win32", reason="asserts the POSIX os.execvp hand-off; Windows covered by test_windows_handoff"
)


def _seed_workspace(home: Path, workspace_id: str) -> Path:
    ws_dir = home / ".warren" / "workspaces" / workspace_id
    ws_dir.mkdir(parents=True, exist_ok=True)
    return ws_dir


def test_seatbelt_state_resolved_from_out_of_tree_dir_not_root(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    workspace_id = "aaaaaaaa-1111-2222-3333-444444444444"
    ws_dir = _seed_workspace(tmp_path, workspace_id)

    state_dir = tmp_path / ".warren" / "state" / workspace_id
    state_dir.mkdir(parents=True)
    (state_dir / "sandbox.sb").write_text("(version 1)\n(deny default)\n")
    (state_dir / "state.json").write_text(json.dumps({
        "workspace_id": workspace_id,
        "project": "proj",
        "intent": "claude",
        "app": "claude",
        "root_path": str(ws_dir),
        "env_snapshot": {},
    }))

    # A sandboxed process planting its OWN sandbox.sb/state.json inside the
    # workspace root must be ignored entirely — only the out-of-tree copy
    # under ~/.warren/state/<id>/ is ever trusted.
    (ws_dir / "sandbox.sb").write_text("(version 1)\n(allow default)\n")
    (ws_dir / "state.json").write_text(json.dumps({"workspace_id": "attacker-controlled"}))

    state = _load_workspace_state(workspace_id)

    assert state["runtime_type"] == "seatbelt"
    assert state["profile_path"] == str(state_dir / "sandbox.sb")
    assert state["workspace_id"] == workspace_id  # NOT "attacker-controlled"
    assert state["root_path"] == str(ws_dir)


def test_bwrap_state_resolved_from_out_of_tree_dir_not_root(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    workspace_id = "bbbbbbbb-1111-2222-3333-444444444444"
    ws_dir = _seed_workspace(tmp_path, workspace_id)

    state_dir = tmp_path / ".warren" / "state" / workspace_id
    state_dir.mkdir(parents=True)
    (state_dir / "state.json").write_text(json.dumps({
        "workspace_id": workspace_id,
        "project": "proj",
        "intent": "claude",
        "app": "claude",
        "root_path": str(ws_dir),
        "env_snapshot": {},
    }))

    state = _load_workspace_state(workspace_id)

    assert state["runtime_type"] == "bwrap"
    assert state["bwrap_state_dir"] == str(state_dir)
    assert state["root_path"] == str(ws_dir)


@pytest.mark.parametrize("in_root", [True, False])
def test_pre_bb3_nsjail_state_refused_with_recreate_hint(tmp_path, monkeypatch, capsys, in_root):
    """BB14: state.json from before bind_mounts/ssh were persisted can't be
    regenerated faithfully, and its in-tree nsjail.cfg isn't trusted -- refuse
    with a recreate hint rather than silently dropping mounts/ssh."""
    import typer

    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    workspace_id = "c0c0c0c0-1111-2222-3333-444444444444"
    ws_dir = _seed_workspace(tmp_path, workspace_id)
    (ws_dir / "nsjail.cfg").write_text('mount { src: "/srv/data" dst: "/data" rw: true }')
    state_dir = ws_dir if in_root else tmp_path / ".warren" / "state" / workspace_id
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "state.json").write_text(json.dumps({
        "workspace_id": workspace_id,
        "app": "claude",
        "runtime_type": "nsjail",
        "root_path": str(ws_dir),
        "cfg_path": str(ws_dir / "nsjail.cfg"),
    }))

    with pytest.raises(typer.Exit):
        _load_workspace_state(workspace_id)
    err = " ".join(capsys.readouterr().err.split())
    assert "Recreate it" in err and f"warren destroy {workspace_id}" in err


# --- Legacy in-root state (pre finding #1) is sandbox-writable: it is
# refused, never migrated into the trusted state dir. ------------------------


@pytest.mark.parametrize("runtime", ["seatbelt", "bwrap", "nsjail"])
def test_legacy_in_root_state_is_refused_not_promoted(tmp_path, monkeypatch, capsys, runtime):
    import typer

    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    workspace_id = "dddddddd-1111-2222-3333-444444444444"
    ws_dir = _seed_workspace(tmp_path, workspace_id)
    payload = {
        "workspace_id": workspace_id, "project": "proj", "intent": "claude",
        "app": "claude", "root_path": str(ws_dir), "env_snapshot": {},
        "bind_mounts": [["/", "host", "rw"]], "ssh_key_paths": [], "ssh_agent_sock": None,
    }
    if runtime == "seatbelt":
        (ws_dir / "sandbox.sb").write_text("(version 1)\n(allow default)\n")
    if runtime == "nsjail":
        payload["runtime_type"] = "nsjail"
    (ws_dir / "state.json").write_text(json.dumps(payload))

    with pytest.raises(typer.Exit):
        _load_workspace_state(workspace_id)

    err = " ".join(capsys.readouterr().err.split())
    assert f"warren destroy {workspace_id}" in err
    assert not (tmp_path / ".warren" / "state" / workspace_id).exists()
    assert (ws_dir / "state.json").is_file()


@pytest.mark.parametrize(
    "bad_id", ["/etc", "../../victim", "a/b", "..", ".", "", "~", "-rf", "x\\y"]
)
def test_path_like_workspace_id_refused(tmp_path, monkeypatch, bad_id):
    import typer

    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    _seed_workspace(tmp_path, "aaaaaaaa-1111-2222-3333-444444444444")
    with pytest.raises(typer.Exit):
        _load_workspace_state(bad_id)


@posix_exec_only
def test_symlinked_workspace_dir_refused(tmp_path, monkeypatch):
    import typer

    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "state.json").write_text(json.dumps({"container_id": "x"}))
    root = tmp_path / ".warren" / "workspaces"
    root.mkdir(parents=True)
    (root / "aaaaaaaa-1111-2222-3333-444444444444").symlink_to(victim)
    for wid in ("aaaaaaaa-1111-2222-3333-444444444444", "aaaa"):
        with pytest.raises(typer.Exit):
            _load_workspace_state(wid)


@posix_exec_only
def test_symlinked_state_dir_refused(tmp_path, monkeypatch):
    import typer

    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    workspace_id = "bbbbbbbb-1111-2222-3333-444444444444"
    ws_dir = _seed_workspace(tmp_path, workspace_id)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "state.json").write_text(json.dumps({"root_path": str(ws_dir)}))
    (tmp_path / ".warren" / "state").mkdir(parents=True)
    (tmp_path / ".warren" / "state" / workspace_id).symlink_to(elsewhere)
    with pytest.raises(typer.Exit):
        _load_workspace_state(workspace_id)


def test_docker_state_not_migrated_stays_in_root(tmp_path, monkeypatch):
    """Docker's state.json is intentionally left in root_path — a docker
    container has no host-filesystem write access to it the way
    seatbelt/nsjail/bwrap's sandboxed process does, so there's no analogous
    attack to migrate away from."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    workspace_id = "ffffffff-1111-2222-3333-444444444444"
    ws_dir = _seed_workspace(tmp_path, workspace_id)
    (ws_dir / "state.json").write_text(json.dumps({
        "workspace_id": workspace_id,
        "project": "proj",
        "intent": "claude",
        "app": "claude",
        "container_id": "abc123",
    }))

    state = _load_workspace_state(workspace_id)

    assert state["runtime_type"] == "docker"
    assert (ws_dir / "state.json").is_file()
    assert not (tmp_path / ".warren" / "state" / workspace_id).exists()


def test_in_root_nsjail_cfg_does_not_change_runtime_detection(tmp_path, monkeypatch):
    """BB3: a sandboxed process can drop nsjail.cfg into its own root; that
    must not turn a bwrap workspace into an nsjail one."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    workspace_id = "dddddddd-1111-2222-3333-444444444444"
    ws_dir = _seed_workspace(tmp_path, workspace_id)
    (ws_dir / "nsjail.cfg").write_text('mount { src: "/" dst: "/host" rw: true }')
    state_dir = tmp_path / ".warren" / "state" / workspace_id
    state_dir.mkdir(parents=True)
    (state_dir / "state.json").write_text(json.dumps({
        "workspace_id": workspace_id, "project": "p", "intent": "t",
        "app": "bash", "root_path": str(ws_dir),
    }))

    assert _load_workspace_state(workspace_id)["runtime_type"] == "bwrap"


@posix_exec_only
def test_nsjail_connect_regenerates_cfg_from_state_not_workspace_root(tmp_path, monkeypatch):
    from warren_cli import dispatch as d

    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    workspace_id = "eeeeeeee-1111-2222-3333-444444444444"
    ws_dir = _seed_workspace(tmp_path, workspace_id)
    (ws_dir / "nsjail.cfg").write_text('mount { src: "/" dst: "/host" rw: true }')
    state_dir = tmp_path / ".warren" / "state" / workspace_id
    state_dir.mkdir(parents=True)
    (state_dir / "state.json").write_text(json.dumps({
        "workspace_id": workspace_id, "project": "p", "intent": "t",
        "app": "sh", "runtime_type": "nsjail", "root_path": str(ws_dir),
        "bind_mounts": [["/srv/data", "data", "ro"]],
        "ssh_key_paths": [], "ssh_agent_sock": None,
    }))
    (state_dir / "nsjail.cfg").write_text('mount { src: "/" dst: "/host" rw: true }')

    captured: dict = {}

    def _fake_execvpe(prog, argv, env):
        captured["argv"] = list(argv)
        raise SystemExit(0)

    monkeypatch.setattr(d.os, "execvpe", _fake_execvpe)
    with pytest.raises(SystemExit):
        d._connect_via_execvp(_load_workspace_state(workspace_id))

    cfg_path = Path(captured["argv"][captured["argv"].index("--config") + 1])
    assert cfg_path == state_dir / "nsjail.cfg"
    text = cfg_path.read_text()
    assert 'dst: "/host"' not in text
    assert '"/srv/data"' in text
