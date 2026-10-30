"""Local-mode `warren workspaces list` — scans ~/.warren/workspaces/*/state.json."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from typer.testing import CliRunner

from warren_cli.main import app


runner = CliRunner()


def _seed_state(root: Path, workspace_id: str, project: str, intent: str, app_name: str = "bash") -> None:
    ws_dir = root / ".warren" / "workspaces" / workspace_id
    ws_dir.mkdir(parents=True, exist_ok=True)
    state = {
        "schema_version": 1,
        "workspace_id": workspace_id,
        "project": project,
        "intent": intent,
        "app": app_name,
        "cfg_path": str(ws_dir / "nsjail.cfg"),
        "worktree_paths": [],
        "reference_paths": [],
        "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "status": "provisioned",
    }
    (ws_dir / "state.json").write_text(json.dumps(state, indent=2))


def test_list_empty_dir_shows_message(tmp_path: Path, monkeypatch):
    """No local workspaces and no configured remotes -> clean, silent exit.

    `list_local` deliberately stopped printing "No local workspaces." when
    `list-local` was folded into `list` (a consolidated command shouldn't claim
    "none" just because the *local* side is empty while remotes have active
    ones) — and a missing config.toml must not print a "config not found"
    error either, since having no config at all is the normal state for
    local-only use, not a precondition failure.
    """
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    # --config passed explicitly rather than relying on HOME/Path.home()
    # monkeypatching for the remote-config lookup: DEFAULT_CONFIG_PATH in
    # config.py is a module-level constant resolved from Path.home() at
    # *import* time, so patching Path.home() this late has no effect on it --
    # without this, the test silently falls through to whatever real
    # ~/.warren/config.toml exists on the machine running it (a real,
    # pre-existing test-isolation gap, out of scope to fix here).
    result = runner.invoke(app, ["list", "--config", str(tmp_path / "nonexistent.toml")])

    assert result.exit_code == 0, result.output
    assert result.output.strip() == ""


def test_list_shows_workspaces_from_state_json(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    _seed_state(tmp_path, "aaaaaaaa-1111-2222-3333-444444444444", "demo-project", "claude", "claude")
    _seed_state(tmp_path, "bbbbbbbb-1111-2222-3333-444444444444", "demo", "observe", "bash")

    result = runner.invoke(app, ["list"])

    assert result.exit_code == 0, (result.stdout, result.stderr)
    assert "demo-project" in result.stdout
    assert "demo" in result.stdout
    assert "claude" in result.stdout
    assert "observe" in result.stdout


def test_list_skips_invalid_json(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    _seed_state(tmp_path, "aaaaaaaa-1111-2222-3333-444444444444", "demo-project", "claude")
    bad_dir = tmp_path / ".warren" / "workspaces" / "cccccccc-1111-2222-3333-444444444444"
    bad_dir.mkdir(parents=True)
    (bad_dir / "state.json").write_text("{not valid json")
    (bad_dir / "state.json.tmp").write_text("partial")

    result = runner.invoke(app, ["list"])

    assert result.exit_code == 0, (result.stdout, result.stderr)
    assert "demo-project" in result.stdout


def test_list_shows_healthz_inline(tmp_path: Path, monkeypatch):
    """Online remote with /healthz data shows enriched header: online  podman ✓  1 running."""
    from warren_cli.main import _gather_remote_workspaces
    from warren_cli.config import RemoteProfile
    import asyncio

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    ws_data = [{"workspace_id": "aaa", "project": "proj", "intent": "default", "status": "running", "created_at": "2026-01-01T00:00:00Z"}]
    hz_data = {"runtime": {"type": "podman", "reachable": True}, "workspaces": {"running": 1, "total": 1}}

    async def _fake_gather(remotes):
        return [("node2", ws_data, hz_data)]

    monkeypatch.setattr("warren_cli.main._gather_remote_workspaces", _fake_gather)

    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        '[defaults]\nmode = "local"\n\n[remotes.node2]\nurl = "http://node2.local:8420"\n'
    )
    cfg_path.chmod(0o600)

    result = runner.invoke(app, ["list", "--config", str(cfg_path)])

    assert result.exit_code == 0, result.output
    assert "online" in result.output
    assert "podman" in result.output
    assert "✓" in result.output  # ✓
    assert "1 running" in result.output


def test_gather_remote_workspaces_falls_back_to_plain_healthz_for_non_admin_token(tmp_path: Path, monkeypatch):
    """A non-admin auth_token gets 403 from /healthz/detail (admin-gated, audit
    #45) -- this used to leave `health=None` entirely, which `list`'s header
    rendering then showed as "unknown ✗  0 running" even though the server is
    actually healthy. Must fall back to plain /healthz and render a bare
    "online" header instead of fabricating runtime/count fields that were
    never fetched."""
    import asyncio

    import httpx
    import respx

    from warren_cli.config import RemoteProfile
    from warren_cli.main import _gather_remote_workspaces

    profile = RemoteProfile(url="http://node2.local:8420", auth_token="tok-non-admin")

    with respx.mock(base_url="http://node2.local:8420") as m:
        m.get("/workspaces").mock(return_value=httpx.Response(200, json=[]))
        m.get("/healthz/detail").mock(return_value=httpx.Response(403, json={"detail": "admin required"}))
        m.get("/healthz").mock(return_value=httpx.Response(200, json={"status": "ok", "version": "0.2.0"}))

        results = asyncio.run(_gather_remote_workspaces({"node2": profile}))

    name, data, health = results[0]
    assert name == "node2"
    assert data == []
    assert health == {}  # confirmed up, but no detail fields -- not None, not populated


def test_list_shows_online_header_with_zero_active_workspaces(tmp_path: Path, monkeypatch):
    """A reachable remote with zero active workspaces (e.g. everything idle-reaped)
    used to print nothing at all -- making a successful, possibly multi-second
    remote fetch (ssh/ecs tunnel setup included) look like it had silently failed.
    Must still show the online header; just skip the (empty) workspace table."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    ws_data = [{"workspace_id": "aaa", "project": "proj", "intent": "default", "status": "stopped", "created_at": "2026-01-01T00:00:00Z"}]
    hz_data = {"runtime": {"type": "podman", "reachable": True}, "workspaces": {"running": 0, "total": 1}}

    async def _fake_gather(remotes):
        return [("node2", ws_data, hz_data)]

    monkeypatch.setattr("warren_cli.main._gather_remote_workspaces", _fake_gather)

    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        '[defaults]\nmode = "local"\n\n[remotes.node2]\nurl = "http://node2.local:8420"\n'
    )
    cfg_path.chmod(0o600)

    result = runner.invoke(app, ["list", "--config", str(cfg_path)])

    assert result.exit_code == 0, result.output
    assert "[node2]" in result.output
    assert "online" in result.output
    assert "0 running" in result.output


def test_list_all_shows_live_before_reaped_by_recency(tmp_path: Path, monkeypatch):
    """`--all` must read top-to-bottom as "what's live" then "what recently
    died", most-recent-first within each group -- not an arbitrary server-row
    order. Rows are deliberately given out of order here to prove sorting
    happens, not just pass-through."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    ws_data = [
        {"workspace_id": "oldstop1", "project": "p", "intent": "default", "status": "stopped",
         "created_at": "2026-01-01T00:00:00Z", "updated_at": "2026-01-01T00:00:00Z"},
        {"workspace_id": "running1", "project": "p", "intent": "default", "status": "running",
         "created_at": "2026-01-02T00:00:00Z", "updated_at": "2026-01-02T00:00:00Z"},
        {"workspace_id": "newstop1", "project": "p", "intent": "default", "status": "stopped",
         "created_at": "2026-01-03T00:00:00Z", "updated_at": "2026-01-03T00:00:00Z"},
    ]

    async def _fake_gather(remotes):
        return [("node2", ws_data, None)]

    monkeypatch.setattr("warren_cli.main._gather_remote_workspaces", _fake_gather)

    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        '[defaults]\nmode = "local"\n\n[remotes.node2]\nurl = "http://node2.local:8420"\n'
    )
    cfg_path.chmod(0o600)

    result = runner.invoke(app, ["list", "--all", "--config", str(cfg_path)])

    assert result.exit_code == 0, result.output
    positions = {
        wid: result.output.index(wid)
        for wid in ("running1", "newstop1", "oldstop1")
    }
    assert positions["running1"] < positions["newstop1"] < positions["oldstop1"]


def test_list_offline_unchanged(tmp_path: Path, monkeypatch):
    """Offline remote shows 'offline' and NOT 'online'."""
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))

    async def _fake_gather(remotes):
        return [("node2", None, None)]

    monkeypatch.setattr("warren_cli.main._gather_remote_workspaces", _fake_gather)

    cfg_path = tmp_path / "config.toml"
    cfg_path.write_text(
        '[defaults]\nmode = "local"\n\n[remotes.node2]\nurl = "http://node2.local:8420"\n'
    )
    cfg_path.chmod(0o600)

    result = runner.invoke(app, ["list", "--config", str(cfg_path)])

    assert result.exit_code == 0, result.output
    combined = result.output + (result.stderr or "")
    assert "offline" in combined or "unreachable" in combined
    assert "online" not in combined
