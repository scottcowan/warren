"""POST /workspaces/{id}/connect route tests — ACCESS-02/ACCESS-03, D-11 ownership gate."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from tests.conftest import TEST_BOOTSTRAP_TOKEN
from warren.app import app
from warren.registry.models import Workspace

_FAKE_PRIVATE_PEM = (
    b"-----BEGIN OPENSSH PRIVATE KEY-----\nfakefakefake\n-----END OPENSSH PRIVATE KEY-----\n"
)


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
    r.issue_ssh_credential = AsyncMock(return_value=(30001, _FAKE_PRIVATE_PEM))
    r.start_turn_session = AsyncMock(return_value=None)
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
    """Resolve the real bootstrap-admin user_id via the admin API."""
    resp = client.get("/admin/users")
    return resp.json()[0]["user_id"]


def test_connect_as_owner_returns_200(env_defaults, auth_headers):
    fake_registry = _make_fake_registry(owner_id=None)
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            owner_id = _bootstrap_user_id(client)
            fake_registry.store.get = AsyncMock(return_value=_fake_workspace(owner_id))

            resp = client.post("/workspaces/ws-test/connect")

    assert resp.status_code == 200
    body = resp.json()
    assert body["user"] == "warren"
    assert body["break_glass_user"] == "warren-shell"
    assert body["port"] == 30001
    assert body["private_key"].startswith("-----BEGIN OPENSSH PRIVATE KEY-----")
    assert body["host"] == "test-server"  # ssh_advertised_host empty -> server_id


def test_connect_non_owner_returns_403_and_does_not_mint(env_defaults, auth_headers):
    fake_registry = _make_fake_registry(owner_id="some-other-user-id")
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.post("/workspaces/ws-test/connect")

    assert resp.status_code == 403
    fake_registry.issue_ssh_credential.assert_not_called()


def test_connect_null_owner_returns_403(env_defaults, auth_headers):
    """Legacy row with owner_id=NULL fails closed rather than being treated as public."""
    fake_registry = _make_fake_registry(owner_id=None)
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.post("/workspaces/ws-test/connect")

    assert resp.status_code == 403
    fake_registry.issue_ssh_credential.assert_not_called()


def test_connect_unknown_workspace_returns_404(env_defaults, auth_headers):
    fake_registry = _make_fake_registry(owner_id=None)
    fake_registry.store.get = AsyncMock(return_value=None)
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.post("/workspaces/unknown-id/connect")

    assert resp.status_code == 404


def test_connect_without_token_returns_401(env_defaults):
    fake_registry = _make_fake_registry(owner_id=None)
    with _lifespan_patches(fake_registry):
        with TestClient(app) as client:
            app.state.registry = fake_registry
            resp = client.post("/workspaces/ws-test/connect")

    assert resp.status_code == 401


def test_connect_provision_error_maps_to_status_code(env_defaults, auth_headers):
    from warren_common.errors import CapacityExhausted

    fake_registry = _make_fake_registry(owner_id=None)
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            owner_id = _bootstrap_user_id(client)
            fake_registry.store.get = AsyncMock(return_value=_fake_workspace(owner_id))
            fake_registry.issue_ssh_credential = AsyncMock(side_effect=CapacityExhausted())

            resp = client.post("/workspaces/ws-test/connect")

    assert resp.status_code == 503
    assert "capacity_exhausted" in resp.json().get("detail", {}).get("error", "")


def test_connect_success_log_never_contains_private_key(env_defaults, auth_headers, caplog):
    """The connect_issued log line carries only identifiers, never the private key.

    warren.logging.configure_logging() routes structlog through stdlib logging (as
    tests/unit/test_logging.py and tests/unit/auth/test_bootstrap.py also do), so
    pytest's caplog — which captures at the stdlib logging layer — sees the same
    rendered records production logging would emit.
    """
    from warren.logging import configure_logging

    configure_logging()

    fake_registry = _make_fake_registry(owner_id=None)

    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            owner_id = _bootstrap_user_id(client)
            fake_registry.store.get = AsyncMock(return_value=_fake_workspace(owner_id))

            with caplog.at_level("INFO"):
                resp = client.post("/workspaces/ws-test/connect")

    assert resp.status_code == 200
    for record in caplog.records:
        assert "BEGIN OPENSSH PRIVATE KEY" not in record.getMessage()

    connect_records = [r for r in caplog.records if "connect_issued" in r.getMessage()]
    assert connect_records, "expected a connect_issued log event"
    assert "workspace_id='ws-test'" in connect_records[0].getMessage()
    assert "ssh_port=" in connect_records[0].getMessage()
