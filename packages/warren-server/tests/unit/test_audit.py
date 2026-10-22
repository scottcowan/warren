"""AI4: one structured audit event format for secret and workspace lifecycle actions."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import structlog
from fastapi.testclient import TestClient

from tests.conftest import TEST_BOOTSTRAP_TOKEN
from warren.app import app
from warren.audit import AUDIT_VERSION, audit_event
from warren.registry.models import Workspace

_REQUIRED_KEYS = {
    "audit_version",
    "action",
    "outcome",
    "caller_id",
    "caller_token_id",
    "caller_workspace_scope",
    "owner_id",
    "workspace_id",
}


def _audits(logs: list[dict]) -> list[dict]:
    return [e for e in logs if e.get("event") == "audit"]


def test_audit_event_has_fixed_schema():
    with structlog.testing.capture_logs() as logs:
        audit_event("workspace.destroy", caller_id="u1", workspace_id="ws1", owner_id="u1")
    (event,) = _audits(logs)
    assert _REQUIRED_KEYS <= event.keys()
    assert event["audit_version"] == AUDIT_VERSION
    assert event["caller_id"] == "u1"


@pytest.mark.parametrize("field", ["value", "token", "private_key", "env"])
def test_audit_event_rejects_secret_material(field):
    with pytest.raises(ValueError):
        audit_event("secret.write", caller_id="u1", **{field: "x"})


def _ws(owner_id: str) -> Workspace:
    now = datetime.now(timezone.utc)
    return Workspace(
        workspace_id="ws-test",
        project="demo",
        intent="observe",
        image="img",
        root_path="",
        status="running",
        server_instance="test-server",
        created_at=now,
        updated_at=now,
        owner_id=owner_id,
    )


def _registry() -> MagicMock:
    r = MagicMock()
    r.server_id = "test-server"
    r.reconcile_from_disk = AsyncMock()
    r._do_provision = AsyncMock()
    r.destroy = AsyncMock()
    r.ensure_running = AsyncMock(return_value=MagicMock(runtime_id="c1"))
    r.issue_ssh_credential = AsyncMock(return_value=(30001, b"k"))
    r.start_turn_session = AsyncMock(return_value=None)
    r.resolve_current_image = AsyncMock(return_value=None)
    r.store = MagicMock()
    r.store.insert = AsyncMock()
    r.store.get = AsyncMock(return_value=None)
    r.store.list_non_terminal = AsyncMock(return_value=[])
    return r


@contextmanager
def _client(registry, project_cfg):
    with (
        patch("warren.app.WorkspaceRegistry", return_value=registry),
        patch("warren.app.PodmanRuntime"),
        patch("warren_common.loader.ProjectLoader.load_effective", return_value=project_cfg),
        TestClient(app, headers={"Authorization": f"Bearer {TEST_BOOTSTRAP_TOKEN}"}) as client,
    ):
        app.state.registry = registry
        yield client


@pytest.fixture
def env_defaults(monkeypatch, tmp_path):
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_BOOTSTRAP_TOKEN", TEST_BOOTSTRAP_TOKEN)
    monkeypatch.setenv("WARREN_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("WARREN_PODMAN_SOCKET", str(tmp_path / "podman.sock"))
    monkeypatch.setenv("WARREN_SERVER_ID", "test-server")
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(tmp_path / "projects"))
    monkeypatch.setenv("WARREN_DRY_RUN_SKIP_PREFLIGHT", "1")
    monkeypatch.setenv("WARREN_REAPER_ENABLED", "0")
    yield
    app.state._state.clear()


def _project():
    from warren_common.models import ProjectConfig

    return ProjectConfig.model_validate(
        {
            "name": "demo",
            "docker_image": "ghcr.io/scottcowan/warren-base:latest",
            "templates": {"observe": {"secrets": [{"name": "API_KEY"}]}},
        }
    )


def test_lifecycle_and_secret_events_carry_server_resolved_caller(env_defaults):
    registry = _registry()
    with _client(registry, _project()) as client:
        user_id = client.get("/admin/users").json()[0]["user_id"]
        registry.store.get = AsyncMock(return_value=_ws(user_id))
        with structlog.testing.capture_logs() as logs:
            assert client.put("/secrets", json={"name": "API_KEY", "value": "sk-abc"}).status_code == 204
            resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
            assert resp.status_code == 202
            assert client.post("/workspaces/ws-test/connect").status_code == 200
            assert client.post("/workspaces/ws-test/ensure_running").status_code == 200
            assert client.delete("/workspaces/ws-test").status_code == 204
            assert client.delete("/secrets/API_KEY").status_code == 204

    events = _audits(logs)
    assert [e["action"] for e in events] == [
        "secret.write",
        "workspace.provision",
        "secret.deliver",
        "workspace.connect",
        "workspace.connect",
        "workspace.destroy",
        "secret.delete",
    ]
    for e in events:
        assert _REQUIRED_KEYS <= e.keys()
        assert e["caller_id"] == user_id
        assert e["caller_token_id"]
        assert e["outcome"] == "success"
    deliver = events[2]
    assert deliver["secret_names"] == ["API_KEY"]
    assert deliver["owner_id"] == user_id
    assert deliver["workspace_id"] == events[1]["workspace_id"]
    assert "sk-abc" not in repr(events)


def test_denied_destroy_is_audited(env_defaults):
    registry = _registry()
    registry.store.get = AsyncMock(return_value=_ws("someone-else"))
    with _client(registry, _project()) as client:
        with structlog.testing.capture_logs() as logs:
            assert client.delete("/workspaces/ws-test").status_code == 403
    (event,) = _audits(logs)
    assert event["action"] == "workspace.destroy"
    assert event["outcome"] == "denied"
    registry.destroy.assert_not_called()


def test_secret_rotate_is_audited_without_values(env_defaults):
    registry = _registry()
    with _client(registry, _project()) as client:
        user_id = client.get("/admin/users").json()[0]["user_id"]
        assert client.put("/secrets", json={"name": "API_KEY", "value": "sk-abc"}).status_code == 204
        with structlog.testing.capture_logs() as logs:
            assert client.post("/secrets/API_KEY/rotate", json={"value": "sk-new"}).status_code == 204
            assert client.post("/secrets/API_KEY/rotate").status_code == 204

    events = _audits(logs)
    assert [(e["action"], e["rotation"]) for e in events] == [
        ("secret.rotate", "new_value"),
        ("secret.rotate", "reencrypt"),
    ]
    assert all(e["caller_id"] == user_id and e["secret_names"] == ["API_KEY"] for e in events)
    assert "sk-new" not in repr(events) and "sk-abc" not in repr(events)
