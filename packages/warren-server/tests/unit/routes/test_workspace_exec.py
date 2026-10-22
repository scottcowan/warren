"""#59: server-mode exec relay -- owner/scope checks, bounds, audit."""

from __future__ import annotations

import json
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import structlog
from fastapi.testclient import TestClient
from warren.app import app
from warren.registry.store import WorkspaceStore
from warren_common.runtime.fake import FakeRuntime

from tests.conftest import TEST_BOOTSTRAP_TOKEN

_ADMIN = {"Authorization": f"Bearer {TEST_BOOTSTRAP_TOKEN}"}


@contextmanager
def _client(monkeypatch, tmp_path, *, runtime=None, **settings_env):
    for key, value in {
        "WARREN_SECRET_KEY": "x" * 32,
        "WARREN_BOOTSTRAP_TOKEN": TEST_BOOTSTRAP_TOKEN,
        "WARREN_DATA_DIR": str(tmp_path),
        "WARREN_PODMAN_SOCKET": str(tmp_path / "podman.sock"),
        "WARREN_SERVER_ID": "test-server",
        "WARREN_PROJECTS_DIR": str(tmp_path / "projects"),
        "WARREN_DRY_RUN_SKIP_PREFLIGHT": "1",
        "WARREN_REAPER_ENABLED": "0",
        **settings_env,
    }.items():
        monkeypatch.setenv(key, value)
    registry = MagicMock()
    registry.server_id = "test-server"
    registry.reconcile_from_disk = AsyncMock()
    registry.runtime = runtime if runtime is not None else FakeRuntime("test-server")
    try:
        with (
            patch("warren.app.WorkspaceRegistry", return_value=registry),
            patch("warren.app.PodmanRuntime"),
            TestClient(app) as client,
        ):
            app.state.registry = registry
            registry.store = WorkspaceStore(app.state.db)
            owner = client.get("/admin/users", headers=_ADMIN).json()[0]["user_id"]
            for ws_id, status, ws_owner in (
                ("ws-a", "running", owner),
                ("ws-b", "running", owner),
                ("ws-other", "running", "someone-else"),
                ("ws-stopped", "stopped", owner),
            ):
                client.portal.call(
                    lambda ws_id=ws_id, status=status, ws_owner=ws_owner: registry.store.insert(
                        workspace_id=ws_id, project="demo", intent="observe", image="img",
                        root_path="", server_instance="test-server", status=status, owner_id=ws_owner,
                    )
                )
                client.portal.call(lambda ws_id=ws_id: registry.store.update_container_id(ws_id, f"c-{ws_id}"))
            yield client, registry
    finally:
        app.state._state.clear()


def _frames(resp) -> list[dict]:
    return [json.loads(line) for line in resp.text.splitlines() if line]


def _echo(ws_id: str, argv: list[str]) -> tuple[list[bytes], int]:
    return [b"hello ", " ".join(argv).encode() + b"\n"], 7


def test_owner_exec_streams_output_and_exit_code(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as (client, registry):
        registry.runtime.exec_handler = _echo
        with structlog.testing.capture_logs() as logs:
            resp = client.post("/workspaces/ws-a/exec", json={"argv": ["echo", "hi"]}, headers=_ADMIN)
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/x-ndjson")
        frames = _frames(resp)
        assert "".join(f["data"] for f in frames if f["type"] == "output") == "hello echo hi\n"
        assert frames[-1] == {
            "type": "exit", "exit_code": 7, "timed_out": False, "truncated": False,
            "output_bytes": 14, "error": None,
        }
        assert registry.runtime.exec_calls == [("ws-a", ["echo", "hi"])]
        audits = {e["action"]: e for e in logs if e.get("event") == "audit"}
        assert audits["workspace.exec"]["command"] == "echo"
        assert audits["workspace.exec"]["argc"] == 2
        assert "argv" not in audits["workspace.exec"]
        assert audits["workspace.exec.finished"]["exit_code"] == 7


def test_non_owner_and_bad_requests_rejected(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as (client, registry):
        with structlog.testing.capture_logs() as logs:
            assert client.post("/workspaces/ws-other/exec", json={"argv": ["id"]}, headers=_ADMIN).status_code == 403
        assert any(e.get("action") == "workspace.exec" and e["outcome"] == "denied" for e in logs)
        assert client.post("/workspaces/nope/exec", json={"argv": ["id"]}, headers=_ADMIN).status_code == 404
        assert client.post("/workspaces/ws-stopped/exec", json={"argv": ["id"]}, headers=_ADMIN).status_code == 409
        assert client.post("/workspaces/ws-a/exec", json={"argv": []}, headers=_ADMIN).status_code == 422
        assert client.post("/workspaces/ws-a/exec", json={"argv": ["x"] * 300}, headers=_ADMIN).status_code == 422
        assert client.post("/workspaces/ws-a/exec", json={"argv": ["id"], "timeout_seconds": 0}, headers=_ADMIN).status_code == 422
        assert registry.runtime.exec_calls == []


def test_runtime_without_exec_channel_is_501(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path, runtime=MagicMock(spec=["status"])) as (client, _):
        resp = client.post("/workspaces/ws-a/exec", json={"argv": ["id"]}, headers=_ADMIN)
        assert resp.status_code == 501


def test_output_is_truncated_at_the_configured_bound(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path, WARREN_EXEC_MAX_OUTPUT_BYTES="1024") as (client, registry):
        registry.runtime.exec_handler = lambda ws, argv: ([b"a" * 1000, b"b" * 1000, b"c"], 0)
        frames = _frames(client.post("/workspaces/ws-a/exec", json={"argv": ["yes"]}, headers=_ADMIN))
        out = "".join(f["data"] for f in frames if f["type"] == "output")
        assert out == "a" * 1000 + "b" * 24
        assert frames[-1]["truncated"] is True
        assert frames[-1]["output_bytes"] == 1024
        assert frames[-1]["exit_code"] is None


def test_workspace_token_execs_only_in_its_own_workspace(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as (client, registry):
        registry.runtime.exec_handler = _echo
        minted = client.post("/workspaces/ws-a/tokens", json={}, headers=_ADMIN).json()
        h = {"Authorization": f"Bearer {minted['token']}"}
        with structlog.testing.capture_logs() as logs:
            assert client.post("/workspaces/ws-a/exec", json={"argv": ["true"]}, headers=h).status_code == 200
        (start,) = [e for e in logs if e.get("action") == "workspace.exec"]
        assert start["caller_workspace_scope"] == "ws-a"
        assert client.post("/workspaces/ws-b/exec", json={"argv": ["true"]}, headers=h).status_code == 403
        assert [ws for ws, _ in registry.runtime.exec_calls] == ["ws-a"]
