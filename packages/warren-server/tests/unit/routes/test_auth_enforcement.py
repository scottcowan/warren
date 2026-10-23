"""End-to-end auth enforcement tests against the REAL warren.app.app — AUTH-03 / T-02-24..29.

Verifies (against the real app, not a throwaway FastAPI instance) that:
- /_status and /healthz are unauthenticated
- every other route 401s without a valid token
- a bootstrap-minted admin token authorizes protected routes, including /admin
- POST /admin/users mints a token that itself authorizes /workspaces
- DELETE /admin/tokens/{id} revokes exactly the targeted token
- the /workspaces/{id}/events StreamingResponse still streams multiple chunks
  once wrapped by AuthMiddleware (RESEARCH Pitfall 3)
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


def _fake_workspace(status: str = "running", owner_id: str | None = None) -> Workspace:
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


def _bootstrap_user_id(client) -> str:
    """Resolve the real bootstrap-admin user_id via the admin API."""
    resp = client.get("/admin/users")
    return resp.json()[0]["user_id"]


def _make_fake_registry(**overrides) -> MagicMock:
    r = MagicMock()
    r.server_id = "test-server"
    r.reconcile_from_disk = AsyncMock()
    r.provision = AsyncMock()
    r._do_provision = AsyncMock()
    r.destroy = AsyncMock()
    r.store = MagicMock()
    r.store.insert = AsyncMock()
    r.store.get = AsyncMock(return_value=_fake_workspace())
    r.store.list_all = AsyncMock(return_value=[])
    for k, v in overrides.items():
        setattr(r, k, v)
    return r


@contextmanager
def _lifespan_patches(fake_registry):
    """Mock lifespan dependencies so TestClient can start without a real Podman socket."""
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
    # Clean up app.state to prevent test pollution of the module-level app singleton
    app.state._state.clear()


def test_status_unauthenticated_returns_200(env_defaults):
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app) as client:
            app.state.registry = fake_registry
            resp = client.get("/_status")
    assert resp.status_code == 200


def test_healthz_unauthenticated_returns_200(env_defaults, monkeypatch):
    monkeypatch.setattr(
        "warren.routes.health.check_podman_health",
        AsyncMock(return_value={"type": "podman", "reachable": True, "socket": "/tmp/podman.sock"}),
    )
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app) as client:
            app.state.registry = fake_registry
            resp = client.get("/healthz")
    assert resp.status_code == 200


def test_workspaces_unauthenticated_returns_401(env_defaults):
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app) as client:
            app.state.registry = fake_registry
            resp = client.get("/workspaces")
    assert resp.status_code == 401
    assert resp.json() == {"detail": "unauthorized"}


def test_projects_unauthenticated_returns_401(env_defaults):
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app) as client:
            app.state.registry = fake_registry
            resp = client.get("/projects")
    assert resp.status_code == 401


def test_peers_unauthenticated_returns_401(env_defaults):
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app) as client:
            app.state.registry = fake_registry
            resp = client.get("/peers")
    assert resp.status_code == 401


def test_admin_users_unauthenticated_returns_401(env_defaults):
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app) as client:
            app.state.registry = fake_registry
            resp = client.get("/admin/users")
    assert resp.status_code == 401


def test_workspaces_bogus_token_returns_401(env_defaults):
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app) as client:
            app.state.registry = fake_registry
            resp = client.get(
                "/workspaces",
                headers={"Authorization": "Bearer wrn_not-a-real-token"},
            )
    assert resp.status_code == 401


def test_workspaces_bootstrap_token_not_401(env_defaults, auth_headers):
    fake_registry = _make_fake_registry()
    fake_registry.store.list_all = AsyncMock(return_value=[])
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.get("/workspaces")
    assert resp.status_code != 401


def test_admin_mint_then_new_token_authorizes_workspaces(env_defaults, auth_headers):
    fake_registry = _make_fake_registry()
    fake_registry.store.list_all = AsyncMock(return_value=[])
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry

            create_resp = client.post(
                "/admin/users",
                json={"username": "alice", "is_admin": False},
            )
            assert create_resp.status_code == 201
            minted_token = create_resp.json()["token"]["token"]

            ws_resp = client.get(
                "/workspaces",
                headers={"Authorization": f"Bearer {minted_token}"},
            )
    assert ws_resp.status_code == 200


def test_revoked_token_401s_while_admin_token_still_works(env_defaults, auth_headers):
    fake_registry = _make_fake_registry()
    fake_registry.store.list_all = AsyncMock(return_value=[])
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry

            create_resp = client.post(
                "/admin/users",
                json={"username": "bob", "is_admin": False},
            )
            assert create_resp.status_code == 201
            token_id = create_resp.json()["token"]["token_id"]
            minted_token = create_resp.json()["token"]["token"]

            revoke_resp = client.delete(f"/admin/tokens/{token_id}")
            assert revoke_resp.status_code == 204

            revoked_resp = client.get(
                "/workspaces",
                headers={"Authorization": f"Bearer {minted_token}"},
            )
            assert revoked_resp.status_code == 401

            admin_still_works = client.get("/workspaces")
    assert admin_still_works.status_code == 200


def test_admin_mint_records_created_by_token_id(env_defaults, auth_headers):
    """End-to-end (through the real AuthMiddleware): a token minted by POST
    /admin/users/{id}/tokens records the calling bootstrap-admin token's id."""
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry

            create_resp = client.post("/admin/users", json={"username": "provenance-user"})
            user_id = create_resp.json()["user"]["user_id"]

            mint_resp = client.post(f"/admin/users/{user_id}/tokens")
            minted_token_id = mint_resp.json()["token_id"]

            tokens_resp = client.get(f"/admin/users/{user_id}/tokens")

    minted = next(t for t in tokens_resp.json() if t["token_id"] == minted_token_id)
    assert minted["created_by_token_id"] is not None


def test_disabled_user_token_401s_immediately(env_defaults, auth_headers):
    fake_registry = _make_fake_registry()
    fake_registry.store.list_all = AsyncMock(return_value=[])
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry

            create_resp = client.post("/admin/users", json={"username": "disableme-e2e"})
            user_id = create_resp.json()["user"]["user_id"]
            minted_token = create_resp.json()["token"]["token"]

            still_works = client.get(
                "/workspaces", headers={"Authorization": f"Bearer {minted_token}"}
            )
            assert still_works.status_code == 200

            disable_resp = client.post(f"/admin/users/{user_id}/disable")
            assert disable_resp.status_code == 200

            after_disable = client.get(
                "/workspaces", headers={"Authorization": f"Bearer {minted_token}"}
            )
            assert after_disable.status_code == 401


def test_workspace_events_streams_multiple_chunks(env_defaults, auth_headers):
    fake_registry = _make_fake_registry()

    async def _fake_stream():
        for line in ('{"type":"workspace_ready"}', '{"type":"log_line"}'):
            yield line

    fake_event_store = MagicMock()
    fake_buf = MagicMock()
    fake_buf.stream = MagicMock(return_value=_fake_stream())
    fake_event_store.get_or_create = MagicMock(return_value=fake_buf)

    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            app.state.event_store = fake_event_store
            owner_id = _bootstrap_user_id(client)
            fake_registry.store.get = AsyncMock(
                return_value=_fake_workspace(status="running", owner_id=owner_id)
            )
            with client.stream("GET", "/workspaces/ws-test/events") as response:
                assert response.status_code == 200
                chunks = list(response.iter_lines())

    assert len(chunks) >= 2
    assert any("workspace_ready" in c for c in chunks)
    assert any("log_line" in c for c in chunks)
