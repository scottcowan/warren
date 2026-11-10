"""Template-declared ports on podman/docker: the registry records where each one was
published on host loopback (after every create and start), the store persists it, and
the workspace API returns it as `host_ports` (`warren proxy` forwards to it)."""

from __future__ import annotations

import json
from datetime import UTC
from unittest.mock import AsyncMock

import pytest
from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

_PORTS = {"t3": {"port": 3773, "description": ""}, "code": {"port": 8080, "description": "code-server"}}


async def _store_with_row(sqlite_path, status="provisioning", spec_json=None):
    from warren.registry.store import WorkspaceStore

    store = await WorkspaceStore.open(sqlite_path)
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status=status, spec_json=spec_json,
    )
    return store


def _runtime(published: dict, *, ssh: bool = True) -> AsyncMock:
    runtime = AsyncMock()
    if ssh:
        runtime.supports_ssh_access = True
    else:
        del runtime.supports_ssh_access
    runtime.provision.return_value = WorkspaceHandle(workspace_id="ws-1", runtime_id="ctr-1", root_path="")
    runtime.published_ports = AsyncMock(return_value=published)
    return runtime


@pytest.mark.asyncio
@pytest.mark.parametrize("ssh", [True, False], ids=["podman", "docker"])
async def test_provision_records_host_ports_by_name(sqlite_path, ssh):
    from warren.registry.registry import WorkspaceRegistry

    store = await _store_with_row(sqlite_path)
    runtime = _runtime({3773: ("127.0.0.1", 41001), 8080: ("127.0.0.1", 41002)}, ssh=ssh)
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")
    spec = WorkspaceSpec(workspace_id="ws-1", project="p", intent="i", image="img", root_path="", ports=_PORTS)

    await registry._do_provision("ws-1", spec)

    row = await store.get("ws-1")
    assert row.status == "running"
    assert json.loads(row.host_ports_json) == {
        "t3": {"host": "127.0.0.1", "port": 41001},
        "code": {"host": "127.0.0.1", "port": 41002},
    }
    runtime.published_ports.assert_awaited_once()


@pytest.mark.asyncio
async def test_provision_without_declared_ports_does_not_inspect(sqlite_path):
    from warren.registry.registry import WorkspaceRegistry

    store = await _store_with_row(sqlite_path)
    runtime = _runtime({})
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")
    spec = WorkspaceSpec(workspace_id="ws-1", project="p", intent="i", image="img", root_path="")

    await registry._do_provision("ws-1", spec)

    assert (await store.get("ws-1")).host_ports_json is None
    runtime.published_ports.assert_not_awaited()


@pytest.mark.asyncio
async def test_a_failed_inspect_does_not_fail_the_provision(sqlite_path):
    from warren.registry.registry import WorkspaceRegistry

    store = await _store_with_row(sqlite_path)
    runtime = _runtime({})
    runtime.published_ports.side_effect = RuntimeError("socket gone")
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")
    spec = WorkspaceSpec(workspace_id="ws-1", project="p", intent="i", image="img", root_path="", ports=_PORTS)

    await registry._do_provision("ws-1", spec)

    row = await store.get("ws-1")
    assert row.status == "running" and row.host_ports_json is None


@pytest.mark.asyncio
async def test_starting_a_stopped_container_records_its_new_host_ports(sqlite_path):
    """docker assigns new host ports at every start; the record follows them."""
    from warren.registry.registry import WorkspaceRegistry

    store = await _store_with_row(sqlite_path, status="stopped", spec_json=json.dumps({"ports": _PORTS}))
    await store.update_container_id("ws-1", "ctr-1")
    await store.update_host_ports("ws-1", {"t3": {"host": "127.0.0.1", "port": 41001}})
    await store.update_ssh_port("ws-1", 30000)
    runtime = _runtime({3773: ("127.0.0.1", 49999)})
    runtime.status.return_value = "stopped"
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")

    handle = await registry.ensure_running("ws-1")

    assert handle is not None
    runtime.start.assert_awaited_once()
    assert json.loads((await store.get("ws-1")).host_ports_json) == {"t3": {"host": "127.0.0.1", "port": 49999}}


@pytest.mark.asyncio
async def test_store_migrates_an_old_database_with_the_new_column(sqlite_path):
    """A database created before host_ports_json gains it on open (ALTER TABLE)."""
    import aiosqlite
    from warren.registry.store import WorkspaceStore

    async with aiosqlite.connect(sqlite_path) as db:
        await db.execute(
            """CREATE TABLE workspaces (
                workspace_id TEXT PRIMARY KEY, project TEXT NOT NULL, intent TEXT NOT NULL,
                image TEXT NOT NULL, root_path TEXT NOT NULL, container_id TEXT,
                status TEXT NOT NULL, server_instance TEXT NOT NULL,
                labels_json TEXT NOT NULL DEFAULT '{}', created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL, ssh_port INTEGER, owner_id TEXT,
                idle_ttl_seconds REAL, spec_json TEXT)"""
        )
        await db.execute(
            "INSERT INTO workspaces (workspace_id, project, intent, image, root_path, status, "
            "server_instance, created_at, updated_at) VALUES "
            "('old', 'p', 'i', 'img', '', 'running', 's', '2026-01-01T00:00:00+00:00', '2026-01-01T00:00:00+00:00')"
        )
        await db.commit()
    store = await WorkspaceStore.open(sqlite_path)
    assert (await store.get("old")).host_ports_json is None
    await store.update_host_ports("old", {"t3": {"host": "127.0.0.1", "port": 41001}})
    assert json.loads((await store.get("old")).host_ports_json)["t3"]["port"] == 41001
    await store.update_host_ports("old", {})
    assert (await store.get("old")).host_ports_json is None


def _ws(host_ports, ports=_PORTS):
    from datetime import datetime

    from warren.registry.models import Workspace

    now = datetime.now(UTC)
    return Workspace(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="/srv/x",
        container_id="ctr-1", status="running", server_instance="s", created_at=now, updated_at=now,
        spec_json=json.dumps({"ports": ports}),
        host_ports_json=json.dumps(host_ports) if host_ports is not None else None,
    )


def test_workspace_view_returns_host_ports_next_to_ports():
    from warren.registry.models import WorkspaceView

    view = WorkspaceView.from_workspace(_ws({"t3": {"host": "127.0.0.1", "port": 41001}}))
    dumped = view.model_dump()
    assert dumped["ports"]["t3"] == {"port": 3773, "description": "", "protocol": "tcp"}
    assert dumped["host_ports"] == {"t3": {"host": "127.0.0.1", "port": 41001}}


def test_workspace_view_host_ports_are_loopback_declared_and_well_formed_only():
    from warren.registry.models import WorkspaceView

    view = WorkspaceView.from_workspace(
        _ws(
            {
                "t3": {"host": "0.0.0.0", "port": 41001},     # never handed out
                "code": {"host": "127.0.0.1", "port": 41002},
                "gone": {"host": "127.0.0.1", "port": 41003},  # no longer declared
                "bad": "x",
            },
            ports={**_PORTS, "bad": {"port": 9}},
        )
    )
    assert {k: v.model_dump() for k, v in view.host_ports.items()} == {"code": {"host": "127.0.0.1", "port": 41002}}
    assert WorkspaceView.from_workspace(_ws(None)).host_ports == {}
    broken = _ws(None)
    broken.host_ports_json = "{not json"
    assert WorkspaceView.from_workspace(broken).host_ports == {}


def test_ports_view_exposes_protocol_defaulting_to_tcp():
    from warren.registry.models import _ports_view

    view = _ports_view({"a": {"port": 1, "protocol": "http"}, "b": {"port": 2}, "c": {"port": 3, "protocol": "x"}})
    assert {k: v.protocol for k, v in view.items()} == {"a": "http", "b": "tcp", "c": "tcp"}
