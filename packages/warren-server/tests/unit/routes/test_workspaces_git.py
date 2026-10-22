"""POST /workspaces/{id}/git/pull route tests -- LIFE-03/D-07 (04-06 Task 3).

Mirrors test_workspace_connect.py's ownership-gate style exactly: fake registry
via MagicMock, real AuthMiddleware/admin-bootstrap flow through TestClient, an
AsyncMock `pull_git` on the fake registry.
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


def _fake_workspace(owner_id: str | None, status: str = "running") -> Workspace:
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


def _make_fake_registry(owner_id: str | None, **overrides) -> MagicMock:
    r = MagicMock()
    r.server_id = "test-server"
    r.reconcile_from_disk = AsyncMock()
    r.provision = AsyncMock()
    r._do_provision = AsyncMock()
    r.destroy = AsyncMock()
    r.pull_git = AsyncMock(return_value={"root": "abc123deadbeef"})
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


def test_pull_as_owner_returns_200_with_commit(env_defaults, auth_headers):
    fake_registry = _make_fake_registry(owner_id=None)
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            owner_id = _bootstrap_user_id(client)
            fake_registry.store.get = AsyncMock(return_value=_fake_workspace(owner_id))

            resp = client.post("/workspaces/ws-test/git/pull")

    assert resp.status_code == 200
    body = resp.json()
    assert body["commits"] == {"root": "abc123deadbeef"}
    assert body["workspace_id"] == "ws-test"


def test_pull_destroyed_workspace_returns_410(env_defaults, auth_headers):
    """Audit R8: pull_git() itself has no notion of "destroyed" -- it only
    reads worktree paths off disk, never consults runtime status -- so
    without an explicit check here it would happily keep pulling a deleted
    workspace's git state forever."""
    fake_registry = _make_fake_registry(owner_id=None)
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            owner_id = _bootstrap_user_id(client)
            fake_registry.store.get = AsyncMock(
                return_value=_fake_workspace(owner_id, status="destroyed")
            )

            resp = client.post("/workspaces/ws-test/git/pull")

    assert resp.status_code == 410
    fake_registry.pull_git.assert_not_called()


def test_pull_unknown_workspace_returns_404(env_defaults, auth_headers):
    fake_registry = _make_fake_registry(owner_id=None)
    fake_registry.store.get = AsyncMock(return_value=None)
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.post("/workspaces/unknown-id/git/pull")

    assert resp.status_code == 404
    fake_registry.pull_git.assert_not_called()


def test_pull_non_owner_returns_403_and_denied_log(env_defaults, auth_headers, caplog):
    from warren.logging import configure_logging

    configure_logging()

    fake_registry = _make_fake_registry(owner_id="some-other-user-id")
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            with caplog.at_level("WARNING"):
                resp = client.post("/workspaces/ws-test/git/pull")

    assert resp.status_code == 403
    fake_registry.pull_git.assert_not_called()
    denied = [r for r in caplog.records if "git_pull_denied" in r.getMessage()]
    assert denied, "expected a git_pull_denied log event"


def test_pull_null_owner_returns_403(env_defaults, auth_headers):
    """A legacy row with owner_id=NULL fails closed, exactly as connect_workspace does."""
    fake_registry = _make_fake_registry(owner_id=None)
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.post("/workspaces/ws-test/git/pull")

    assert resp.status_code == 403
    fake_registry.pull_git.assert_not_called()


def test_pull_without_token_returns_401(env_defaults):
    fake_registry = _make_fake_registry(owner_id=None)
    with _lifespan_patches(fake_registry):
        with TestClient(app) as client:
            app.state.registry = fake_registry
            resp = client.post("/workspaces/ws-test/git/pull")

    assert resp.status_code == 401


def test_pull_git_pull_error_returns_502(env_defaults, auth_headers):
    from warren.git.manager import GitPullError

    fake_registry = _make_fake_registry(owner_id=None)
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            owner_id = _bootstrap_user_id(client)
            fake_registry.store.get = AsyncMock(return_value=_fake_workspace(owner_id))
            fake_registry.pull_git = AsyncMock(side_effect=GitPullError("boom"))

            resp = client.post("/workspaces/ws-test/git/pull")

    assert resp.status_code == 502
    assert resp.json()["detail"]["error"] == "git_pull_failed"


def test_pull_github_auth_error_returns_fixed_502_message(env_defaults, auth_headers):
    from warren.git.github_app import GitHubAuthError

    fake_registry = _make_fake_registry(owner_id=None)
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            owner_id = _bootstrap_user_id(client)
            fake_registry.store.get = AsyncMock(return_value=_fake_workspace(owner_id))
            fake_registry.pull_git = AsyncMock(
                side_effect=GitHubAuthError("some request-specific leaky detail")
            )

            resp = client.post("/workspaces/ws-test/git/pull")

    assert resp.status_code == 502
    body = resp.json()
    assert body["detail"]["error"] == "git_auth_failed"
    assert "some request-specific leaky detail" not in resp.text


def test_pull_response_never_leaks_credential_or_host_path(env_defaults, auth_headers):
    fake_registry = _make_fake_registry(owner_id=None)
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            owner_id = _bootstrap_user_id(client)
            fake_registry.store.get = AsyncMock(return_value=_fake_workspace(owner_id))

            resp = client.post("/workspaces/ws-test/git/pull")

    assert "x-access-token" not in resp.text
    assert "/var/lib/warren" not in resp.text
