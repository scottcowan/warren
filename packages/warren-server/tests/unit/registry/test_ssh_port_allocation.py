"""Coverage for WorkspaceRegistry.allocate_ssh_port() and its wiring into
_do_provision() (D-05/D-06/D-07, plan 03-04 Task 1)."""

from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock


@pytest.mark.asyncio
async def test_allocate_ssh_port_empty_registry_returns_range_start(sqlite_path):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry

    store = await WorkspaceStore.open(sqlite_path)
    registry = WorkspaceRegistry(runtime=MagicMock(), store=store, server_id="test")

    port = await registry.allocate_ssh_port()

    assert port == 30000


@pytest.mark.asyncio
async def test_allocate_ssh_port_without_settings_still_uses_default_start(sqlite_path):
    """A registry constructed without settings= still allocates from 30000."""
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry

    store = await WorkspaceStore.open(sqlite_path)
    # 3-arg construction, exactly as every pre-existing call site does.
    registry = WorkspaceRegistry(MagicMock(), store, "test")

    port = await registry.allocate_ssh_port()

    assert port == 30000


@pytest.mark.asyncio
async def test_allocate_ssh_port_skips_ports_held_by_non_terminal_workspaces(sqlite_path):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry

    store = await WorkspaceStore.open(sqlite_path)
    registry = WorkspaceRegistry(runtime=MagicMock(), store=store, server_id="test")

    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="running", ssh_port=30000,
    )
    await store.insert(
        workspace_id="ws-2", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="provisioning", ssh_port=30001,
    )

    port = await registry.allocate_ssh_port()

    assert port == 30002


@pytest.mark.asyncio
async def test_allocate_ssh_port_stays_reserved_for_stopped_workspace(sqlite_path):
    """A stopped workspace's port stays reserved (D-04 ensure_running() reuses it to
    reconnect it later — freeing it here would let a new workspace collide with it)."""
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry

    store = await WorkspaceStore.open(sqlite_path)
    registry = WorkspaceRegistry(runtime=MagicMock(), store=store, server_id="test")

    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="stopped", ssh_port=30000,
    )
    await store.insert(
        workspace_id="ws-2", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="failed", ssh_port=30001,
    )

    port = await registry.allocate_ssh_port()

    assert port == 30002


@pytest.mark.asyncio
async def test_allocate_ssh_port_reclaims_port_from_destroyed_workspace(sqlite_path):
    """Audit P1 #24: a destroyed workspace's port must be reclaimable, or every
    port in the range leaks permanently the moment its workspace is destroyed."""
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry

    store = await WorkspaceStore.open(sqlite_path)
    registry = WorkspaceRegistry(runtime=MagicMock(), store=store, server_id="test")

    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="destroyed", ssh_port=30000,
    )

    port = await registry.allocate_ssh_port()

    assert port == 30000


@pytest.mark.asyncio
async def test_allocate_ssh_port_raises_capacity_exhausted_when_range_full(sqlite_path):
    from warren_common.errors import CapacityExhausted
    from warren.config import WarrenSettings
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry

    settings = WarrenSettings(
        secret_key="s" * 32, ssh_port_range_start=30000, ssh_port_range_end=30002
    )
    store = await WorkspaceStore.open(sqlite_path)
    registry = WorkspaceRegistry(
        runtime=MagicMock(), store=store, server_id="test", settings=settings
    )

    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="running", ssh_port=30000,
    )
    await store.insert(
        workspace_id="ws-2", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="running", ssh_port=30001,
    )

    with pytest.raises(CapacityExhausted) as exc_info:
        await registry.allocate_ssh_port()

    assert exc_info.value.reason == "capacity_exhausted"


@pytest.mark.asyncio
async def test_do_provision_ssh_capable_runtime_passes_and_persists_port(sqlite_path):
    """_do_provision on an SSH-capable runtime allocates+persists the port
    unconditionally. Audit R12: whether it's actually PUBLISHED on the
    container is a separate, settings-gated concern (see
    test_registry.py's publish_ssh_port tests) -- with no settings object at
    all (this registry's construction below), publish_ssh_port defaults to
    False, matching WarrenSettings.ssh_access_enabled's own default."""
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.supports_ssh_access = True
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-1", runtime_id="ctr-1", root_path=""
    )
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")

    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="provisioning",
    )
    spec = WorkspaceSpec(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path=""
    )

    await registry._do_provision("ws-1", spec)

    runtime.provision.assert_awaited_once_with(spec, ssh_port=30000, publish_ssh_port=False)
    row = await store.get("ws-1")
    assert row.ssh_port == 30000
    assert row.status == "running"


@pytest.mark.asyncio
async def test_do_provision_non_ssh_runtime_calls_single_arg_provision(sqlite_path):
    """_do_provision on a runtime WITHOUT supports_ssh_access calls provision(spec) only."""
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    del runtime.supports_ssh_access
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-1", runtime_id="ctr-1", root_path=""
    )
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")

    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="provisioning",
    )
    spec = WorkspaceSpec(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path=""
    )

    await registry._do_provision("ws-1", spec)

    runtime.provision.assert_awaited_once_with(spec)
    row = await store.get("ws-1")
    assert row.ssh_port is None


@pytest.mark.asyncio
async def test_do_provision_capacity_exhausted_marks_failed_no_container(sqlite_path):
    """When allocate_ssh_port() raises CapacityExhausted, _do_provision marks failed
    and never calls runtime.provision — no workspace left running without SSH."""
    from warren.config import WarrenSettings
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.runtime.base import WorkspaceSpec

    settings = WarrenSettings(
        secret_key="s" * 32, ssh_port_range_start=30000, ssh_port_range_end=30001
    )
    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.supports_ssh_access = True
    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", settings=settings
    )

    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="running", ssh_port=30000,
    )
    await store.insert(
        workspace_id="ws-2", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="provisioning",
    )
    spec = WorkspaceSpec(
        workspace_id="ws-2", project="p", intent="i", image="img", root_path=""
    )

    await registry._do_provision("ws-2", spec)

    runtime.provision.assert_not_awaited()
    row = await store.get("ws-2")
    assert row.status == "failed"
