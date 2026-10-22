"""D-14: GET /workspaces/{id}/events route."""

from __future__ import annotations

from contextlib import contextmanager
from datetime import datetime, timezone
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from warren.app import app
from warren.registry.events import WorkspaceEventBuffer
from warren.registry.models import Workspace

from tests.conftest import TEST_BOOTSTRAP_TOKEN


def _make_fake_registry(**overrides) -> MagicMock:
    r = MagicMock()
    r.server_id = "test-server"
    r.reconcile_from_disk = AsyncMock()
    r.store = MagicMock()
    r.store.get = AsyncMock(return_value=None)
    for k, v in overrides.items():
        setattr(r, k, v)
    return r


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
    return client.get("/admin/users").json()[0]["user_id"]


def _get_events(auth_headers, fake_event_store, status: str = "running", path: str = ""):
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            fake_registry.store.get = AsyncMock(
                return_value=_fake_workspace(_bootstrap_user_id(client), status=status)
            )
            app.state.registry = fake_registry
            app.state.event_store = fake_event_store
            return client.get(f"/workspaces/ws-test/events{path}")


class _FiniteBuffer:
    """Records stream() kwargs and yields a fixed set of lines, then ends."""

    def __init__(self, lines: list[str]) -> None:
        self.lines = lines
        self.calls: list[dict] = []

    async def stream(self, **kwargs):
        self.calls.append(kwargs)
        for line in self.lines:
            yield line


def _store_for(buf) -> MagicMock:
    store = MagicMock()
    store.get_or_create = MagicMock(return_value=buf)
    return store


def test_events_route_404_unknown_workspace(env_defaults, auth_headers):
    """GET /workspaces/no-such-id/events must return 404 for unknown workspace."""
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            app.state.registry = fake_registry
            response = client.get("/workspaces/no-such-id/events")
    assert response.status_code == 404


def test_events_route_410_destroyed_workspace(env_defaults, auth_headers):
    """Audit R8: without this check, a destroyed workspace's events route
    created a FRESH event buffer (get_or_create) and streamed from it
    forever -- there is no container left to ever produce an event into
    that buffer, so the connection would just hang open indefinitely for a
    workspace that no longer exists."""
    fake_event_store = MagicMock()
    fake_event_store.get.return_value = None
    response = _get_events(auth_headers, fake_event_store, status="destroyed")
    assert response.status_code == 410
    fake_event_store.get_or_create.assert_not_called()


def test_events_route_410_destroyed_with_open_buffer(env_defaults, auth_headers):
    fake_event_store = MagicMock()
    fake_event_store.get.return_value = WorkspaceEventBuffer()
    response = _get_events(auth_headers, fake_event_store, status="destroyed")
    assert response.status_code == 410


def test_events_route_replays_completed_single_turn_after_destroy(env_defaults, auth_headers):
    """AH2: a destroyed single-turn workspace's closed buffer replays (?since=) and ends."""
    import asyncio
    import json

    from warren.registry.events import WorkspaceEventStore

    store = WorkspaceEventStore()
    buf = store.get_or_create("ws-test")

    async def fill() -> None:
        await buf.push(json.dumps({"type": "output", "content": "hi"}))
        await buf.push(json.dumps({"type": "workspace.completed", "exit_code": 0}))
        await buf.close()

    asyncio.run(fill())
    response = _get_events(auth_headers, store, status="destroyed", path="?since=0")
    assert response.status_code == 200
    lines = [json.loads(line) for line in response.text.splitlines()]
    assert lines == [{"type": "workspace.completed", "exit_code": 0}]


def test_events_route_200_streams_ndjson(env_defaults, auth_headers):
    """GET /workspaces/{id}/events returns 200 with application/x-ndjson and buffered lines."""
    buf = _FiniteBuffer(['{"type":"sidecar_ready"}'])
    response = _get_events(auth_headers, _store_for(buf))
    assert response.status_code == 200
    assert "ndjson" in response.headers.get("content-type", "")
    assert response.text == '{"type":"sidecar_ready"}\n'
    assert buf.calls == [{"since": None}]


def test_events_route_passes_since_through(env_defaults, auth_headers):
    buf = _FiniteBuffer([])
    response = _get_events(auth_headers, _store_for(buf), path="?since=41")
    assert response.status_code == 200
    assert buf.calls == [{"since": 41}]


def test_events_route_rejects_invalid_since(env_defaults, auth_headers):
    buf = _FiniteBuffer([])
    response = _get_events(auth_headers, _store_for(buf), path="?since=-2")
    assert response.status_code == 422
    assert buf.calls == []


async def test_events_route_since_replays_from_real_buffer(env_defaults, auth_headers):
    buf = WorkspaceEventBuffer()
    for i in range(1200):
        await buf.push(f'{{"i":{i}}}')

    class _Once:
        async def stream(self, since=None):
            async for line in buf.stream(since=since):
                yield line
                if line == '{"i":1199}':
                    return

    response = _get_events(auth_headers, _store_for(_Once()), path="?since=5")
    lines = response.text.splitlines()
    assert '"events_evicted"' in lines[0]
    assert lines[1:] == [f'{{"i":{i}}}' for i in range(200, 1200)]
