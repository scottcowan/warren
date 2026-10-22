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


def test_nsjail_state_migrated_from_workspace_root(tmp_path, monkeypatch):
    """nsjail now keeps state.json out-of-tree too (R3) — a workspace
    provisioned before that fix (state.json only in root_path) gets migrated
    on next connect rather than trusted in place. The in-root nsjail.cfg is
    no longer used at all (BB3): connect regenerates it in the state dir."""
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    workspace_id = "cccccccc-1111-2222-3333-444444444444"
    ws_dir = _seed_workspace(tmp_path, workspace_id)
    (ws_dir / "nsjail.cfg").write_text("{}")
    (ws_dir / "state.json").write_text(json.dumps({
        "workspace_id": workspace_id,
        "project": "proj",
        "intent": "claude",
        "app": "claude",
        "cfg_path": str(ws_dir / "nsjail.cfg"),
        "bind_mounts": [],
        "ssh_key_paths": [],
        "ssh_agent_sock": None,
    }))

    state = _load_workspace_state(workspace_id)

    state_dir = tmp_path / ".warren" / "state" / workspace_id
    assert state["runtime_type"] == "nsjail"
    assert "cfg_path" not in state
    assert state["nsjail_state_dir"] == str(state_dir)
    assert (state_dir / "state.json").is_file()
    assert not (ws_dir / "state.json").exists()


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


# --- R3 (2026-10-17): the fix above (finding #1) was undone for every
# workspace provisioned BEFORE it shipped -- those still had only the
# sandbox-writable in-root copy, and the old fallback trusted it silently.
# These tests cover the migration that replaces that silent fallback. --------


def test_legacy_seatbelt_state_migrated_out_of_root(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    workspace_id = "dddddddd-1111-2222-3333-444444444444"
    ws_dir = _seed_workspace(tmp_path, workspace_id)
    (ws_dir / "sandbox.sb").write_text("(version 1)\n(deny default)\n")
    (ws_dir / "state.json").write_text(json.dumps({
        "workspace_id": workspace_id,
        "project": "proj",
        "intent": "claude",
        "app": "claude",
        "root_path": str(ws_dir),
        "env_snapshot": {},
    }))

    state = _load_workspace_state(workspace_id)

    state_dir = tmp_path / ".warren" / "state" / workspace_id
    assert state["runtime_type"] == "seatbelt"
    assert state["profile_path"] == str(state_dir / "sandbox.sb")
    # The legacy in-root copies are gone -- a sandboxed process can no longer
    # influence what gets trusted on a LATER connect by rewriting them.
    assert not (ws_dir / "sandbox.sb").exists()
    assert not (ws_dir / "state.json").exists()
    assert (state_dir / "sandbox.sb").is_file()
    assert (state_dir / "state.json").is_file()


def test_legacy_bwrap_state_migrated_out_of_root(tmp_path, monkeypatch):
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
    workspace_id = "eeeeeeee-1111-2222-3333-444444444444"
    ws_dir = _seed_workspace(tmp_path, workspace_id)
    (ws_dir / "state.json").write_text(json.dumps({
        "workspace_id": workspace_id,
        "project": "proj",
        "intent": "claude",
        "app": "claude",
        "root_path": str(ws_dir),
        "env_snapshot": {},
    }))

    state = _load_workspace_state(workspace_id)

    state_dir = tmp_path / ".warren" / "state" / workspace_id
    assert state["runtime_type"] == "bwrap"
    assert state["bwrap_state_dir"] == str(state_dir)
    assert not (ws_dir / "state.json").exists()
    assert (state_dir / "state.json").is_file()


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
