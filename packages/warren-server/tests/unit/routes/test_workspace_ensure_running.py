"""POST /workspaces/{id}/ensure_running route tests.

Mirrors test_workspace_connect.py's ownership-gate coverage, but for the
podman/docker `warren connect` path: no SSH credential minted (in-container
sshd was never built, see #8) -- the CLI uses the
returned container_id to `podman exec` over its own SSH connection to the
server host instead.
"""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from tests.conftest import TEST_BOOTSTRAP_TOKEN
from warren.app import app
from warren.registry.models import Workspace


def _fake_workspace(owner_id: str | None, status: str = "stopped") -> Workspace:
    return Workspace(
        workspace_id="ws-test",
        project="demo",
        intent="observe",
        image="ghcr.io/scottcowan/warren-base:latest",
        root_path="",
        status=status,  # type: ignore[arg-type]
        server_instance="test-server",
        created_at=datetime.now(timezone.utc),
        updated_at=datetime.now(timezone.utc),
        owner_id=owner_id,
    )


def _fake_handle(runtime_id: str = "ctr-restarted"):
    from warren_common.runtime.base import WorkspaceHandle

    return WorkspaceHandle(workspace_id="ws-test", runtime_id=runtime_id, root_path="")


def _make_fake_registry(owner_id: str | None, **overrides) -> MagicMock:
    r = MagicMock()
    r.server_id = "test-server"
    r.reconcile_from_disk = AsyncMock()
    r.provision = AsyncMock()
    r._do_provision = AsyncMock()
    r.destroy = AsyncMock()
    r.ensure_running = AsyncMock(return_value=_fake_handle())
    r.start_turn_session = AsyncMock(return_value=None)
    r.resolve_current_image = AsyncMock(return_value=None)
    r.store = MagicMock()
    r.store.insert = AsyncMock()
    r.store.get = AsyncMock(return_value=_fake_workspace(owner_id))
    r.store.list_all = AsyncMock(return_value=[])
    for k, v in overrides.items():
        setattr(r, k, v)
    return r


@contextmanager
def _lifespan_patches(fake_registry):
    with (
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry),
        patch("warren.app.PodmanRuntime"),
    ):
        yield


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


def _bootstrap_user_id(client) -> str:
    resp = client.get("/admin/users")
    return resp.json()[0]["user_id"]


def test_ensure_running_as_owner_returns_200_with_container_id(env_defaults, auth_headers):
    fake_registry = _make_fake_registry(owner_id=None)
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            owner_id = _bootstrap_user_id(client)
            fake_registry.store.get = AsyncMock(return_value=_fake_workspace(owner_id))

            resp = client.post("/workspaces/ws-test/ensure_running")

    assert resp.status_code == 200
    body = resp.json()
    assert body["container_id"] == "ctr-restarted"
    assert body["status"] == "running"
    fake_registry.ensure_running.assert_awaited_once_with("ws-test")
    assert body["image"] == "ghcr.io/scottcowan/warren-base:latest"
    assert body["newer_image"] is None


def test_ensure_running_reports_a_newer_image(env_defaults, auth_headers):
    """AB1: a running task keeps its image; connect can say a newer one exists."""
    fake_registry = _make_fake_registry(owner_id=None, resolve_current_image=AsyncMock(return_value="img:v2"))
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            owner_id = _bootstrap_user_id(client)
            fake_registry.store.get = AsyncMock(return_value=_fake_workspace(owner_id))
            resp = client.post("/workspaces/ws-test/ensure_running")

    assert resp.json()["newer_image"] == "img:v2"


def test_ensure_running_non_owner_returns_403_and_does_not_call_registry(env_defaults, auth_headers):
    fake_registry = _make_fake_registry(owner_id="some-other-user-id")
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.post("/workspaces/ws-test/ensure_running")

    assert resp.status_code == 403
    fake_registry.ensure_running.assert_not_called()


def test_ensure_running_null_owner_returns_403(env_defaults, auth_headers):
    """Legacy row with owner_id=NULL fails closed rather than being treated as public."""
    fake_registry = _make_fake_registry(owner_id=None)
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.post("/workspaces/ws-test/ensure_running")

    assert resp.status_code == 403
    fake_registry.ensure_running.assert_not_called()


def test_ensure_running_unknown_workspace_returns_404(env_defaults, auth_headers):
    fake_registry = _make_fake_registry(owner_id=None)
    fake_registry.store.get = AsyncMock(return_value=None)
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.post("/workspaces/unknown-id/ensure_running")

    assert resp.status_code == 404


def test_ensure_running_without_token_returns_401(env_defaults):
    fake_registry = _make_fake_registry(owner_id=None)
    with _lifespan_patches(fake_registry):
        with TestClient(app) as client:
            app.state.registry = fake_registry
            resp = client.post("/workspaces/ws-test/ensure_running")

    assert resp.status_code == 401


def test_ensure_running_provision_error_maps_to_status_code(env_defaults, auth_headers):
    from warren_common.errors import CapacityExhausted

    fake_registry = _make_fake_registry(owner_id=None)
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            owner_id = _bootstrap_user_id(client)
            fake_registry.store.get = AsyncMock(return_value=_fake_workspace(owner_id))
            fake_registry.ensure_running = AsyncMock(side_effect=CapacityExhausted())

            resp = client.post("/workspaces/ws-test/ensure_running")

    assert resp.status_code == 503
    assert "capacity_exhausted" in resp.json().get("detail", {}).get("error", "")


def test_ensure_running_still_starting_maps_to_503(env_defaults, auth_headers):
    """BB4: a task that never left the starting state is a retryable 503."""
    from warren.registry.registry import WorkspaceStillStarting

    fake_registry = _make_fake_registry(owner_id=None)
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            owner_id = _bootstrap_user_id(client)
            fake_registry.store.get = AsyncMock(return_value=_fake_workspace(owner_id))
            fake_registry.ensure_running = AsyncMock(
                side_effect=WorkspaceStillStarting("still starting", retry_after_seconds=7)
            )

            resp = client.post("/workspaces/ws-test/ensure_running")

    assert resp.status_code == 503
    assert resp.json()["detail"]["error"] == "workspace_starting"
    assert resp.headers["Retry-After"] == "7"
