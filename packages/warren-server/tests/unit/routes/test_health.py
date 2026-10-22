"""Health + peers route tests — SV-01, PD-01, PD-02."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from tests.conftest import TEST_BOOTSTRAP_TOKEN
from warren.app import app
from warren.registry.models import Workspace


def _fake_workspace(status: str = "running") -> Workspace:
    """Return a minimal valid Workspace for mock responses."""
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
    )


def _make_fake_registry(**overrides) -> MagicMock:
    """Return a MagicMock registry with all async methods pre-configured."""
    r = MagicMock()
    r.server_id = "test-server"
    r.reconcile_from_disk = AsyncMock()
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


def test_healthz_returns_200(env_defaults, auth_headers):
    """GET /healthz is a bare liveness signal -- no internals, no auth required
    (audit 2026-10-16 #45)."""
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app) as client:
            app.state.registry = fake_registry
            resp = client.get("/healthz")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "ok"
    assert "version" in body
    for key in ("warren_id", "runtime", "workspaces", "secret_store"):
        assert key not in body, f"unexpected internal key leaked: {key}"


def test_healthz_detail_requires_auth(env_defaults):
    """GET /healthz/detail is NOT exempt from auth -- unlike /healthz."""
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app) as client:
            app.state.registry = fake_registry
            resp = client.get("/healthz/detail")
    assert resp.status_code == 401


def test_healthz_detail_returns_200(env_defaults, monkeypatch, auth_headers):
    """GET /healthz/detail returns 200 with all required top-level keys for an admin."""
    monkeypatch.setattr(
        "warren.routes.health.check_podman_health",
        AsyncMock(return_value={"type": "podman", "reachable": True, "socket": "/tmp/podman.sock"}),
    )
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.get("/healthz/detail")
    assert resp.status_code == 200
    body = resp.json()
    for key in ("warren_id", "version", "runtime", "workspaces", "secret_store"):
        assert key in body, f"missing key: {key}"


def test_healthz_detail_runtime_unreachable(env_defaults, monkeypatch, auth_headers):
    """GET /healthz/detail returns 200 even when Podman is unreachable; runtime.reachable is False."""
    monkeypatch.setattr(
        "warren.routes.health.check_podman_health",
        AsyncMock(return_value={"type": "podman", "reachable": False, "socket": "/tmp/podman.sock"}),
    )
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.get("/healthz/detail")
    assert resp.status_code == 200
    assert resp.json()["runtime"]["reachable"] is False


def test_healthz_detail_workspace_counts(env_defaults, monkeypatch, auth_headers):
    """With two workspaces (one running, one stopped), workspaces.running==1 and total==2."""
    monkeypatch.setattr(
        "warren.routes.health.check_podman_health",
        AsyncMock(return_value={"type": "podman", "reachable": True, "socket": "/tmp/podman.sock"}),
    )
    fake_registry = _make_fake_registry(
        store=MagicMock(
            list_all=AsyncMock(
                return_value=[
                    _fake_workspace(status="running"),
                    _fake_workspace(status="stopped"),
                ]
            )
        )
    )
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.get("/healthz/detail")
    assert resp.status_code == 200
    ws = resp.json()["workspaces"]
    assert ws["running"] == 1
    assert ws["total"] == 2


def test_healthz_detail_secret_store_reachable_and_empty(env_defaults, monkeypatch, auth_headers):
    """secret_store.reachable is True and count==0 against a freshly-schema'd, empty
    `secrets` table (warren.secrets.store) -- the local secret store is always present
    once app startup applies schema.sql, regardless of runtime_type."""
    monkeypatch.setattr(
        "warren.routes.health.check_podman_health",
        AsyncMock(return_value={"type": "podman", "reachable": True, "socket": "/tmp/podman.sock"}),
    )
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.get("/healthz/detail")
    assert resp.status_code == 200
    ss = resp.json()["secret_store"]
    assert ss["reachable"] is True
    assert ss["count"] == 0


def test_healthz_detail_reports_ecs_runtime_type_not_hardcoded_podman(env_defaults, monkeypatch, auth_headers):
    """Regression guard for audit 2026-10-16 #36: /healthz used to hardcode
    runtime.type="podman" unconditionally, lying about an ECS deployment's
    actual runtime. It must read settings.runtime_type instead, and must
    never call check_podman_health (no podman socket exists on ECS)."""
    monkeypatch.setenv("WARREN_RUNTIME_TYPE", "ecs")
    check_podman_health = AsyncMock()
    monkeypatch.setattr("warren.routes.health.check_podman_health", check_podman_health)
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            # R16: runtime.reachable now reflects a real preflight() call rather than
            # a hardcoded True -- inject a fake runtime whose preflight() succeeds so
            # this test still exercises "ecs reported, reachable when actually up".
            app.state.runtime = MagicMock(preflight=AsyncMock(return_value=None))
            resp = client.get("/healthz/detail")
    assert resp.status_code == 200
    runtime = resp.json()["runtime"]
    assert runtime["type"] == "ecs"
    assert runtime["reachable"] is True
    check_podman_health.assert_not_called()


def test_healthz_detail_ecs_reachable_false_when_preflight_raises(env_defaults, monkeypatch, auth_headers):
    """R16: runtime.reachable must be False when the ECS runtime's own preflight()
    (the same check guarding provision()) actually fails -- not hardcoded True
    regardless of real cluster state."""
    monkeypatch.setenv("WARREN_RUNTIME_TYPE", "ecs")
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            app.state.runtime = MagicMock(
                preflight=AsyncMock(side_effect=RuntimeError("ECS cluster unreachable"))
            )
            resp = client.get("/healthz/detail")
    assert resp.status_code == 200
    runtime = resp.json()["runtime"]
    assert runtime["type"] == "ecs"
    assert runtime["reachable"] is False


def test_healthz_detail_docker_reachable_reflects_real_ping(env_defaults, monkeypatch, auth_headers):
    """R16: the docker runtime branch must also call a real reachability check
    (DockerRuntime.preflight(), a daemon ping) instead of hardcoding True."""
    monkeypatch.setenv("WARREN_RUNTIME_TYPE", "docker")
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            app.state.runtime = MagicMock(
                preflight=AsyncMock(side_effect=RuntimeError("docker daemon unreachable"))
            )
            resp = client.get("/healthz/detail")
    assert resp.status_code == 200
    runtime = resp.json()["runtime"]
    assert runtime["type"] == "docker"
    assert runtime["reachable"] is False


def test_healthz_detail_reachability_check_times_out_safely(env_defaults, monkeypatch, auth_headers):
    """R16: a hung preflight() (e.g. AWS API never responding) must report
    reachable=False rather than hanging the route or the whole response."""
    import asyncio

    monkeypatch.setenv("WARREN_RUNTIME_TYPE", "ecs")
    monkeypatch.setattr("warren.routes.health._REACHABILITY_PROBE_TIMEOUT_SECONDS", 0.01)

    async def _hang():
        await asyncio.sleep(10)

    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            app.state.runtime = MagicMock(preflight=_hang)
            resp = client.get("/healthz/detail")
    assert resp.status_code == 200
    assert resp.json()["runtime"]["reachable"] is False


def test_healthz_detail_fallback_still_reports_configured_runtime_type(env_defaults, monkeypatch, auth_headers):
    """Even on the except-Exception fallback path, runtime.type should
    reflect the configured runtime_type rather than lying with 'podman'."""
    monkeypatch.setenv("WARREN_RUNTIME_TYPE", "ecs")
    fake_registry = _make_fake_registry(
        store=MagicMock(list_all=AsyncMock(side_effect=RuntimeError("db exploded")))
    )
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.get("/healthz/detail")
    assert resp.status_code == 200
    runtime = resp.json()["runtime"]
    assert runtime["type"] == "ecs"
    assert runtime["reachable"] is False


def test_peers_returns_empty_list(env_defaults, auth_headers):
    """GET /peers returns 200 with an empty list."""
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            resp = client.get("/peers")
    assert resp.status_code == 200
    assert resp.json() == []
