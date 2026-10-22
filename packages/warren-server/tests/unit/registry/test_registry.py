"""RED scaffolds for WorkspaceRegistry provision tests — WS-01."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace

import pytest
from unittest.mock import AsyncMock, MagicMock


@pytest.mark.asyncio
async def test_do_provision_success(sqlite_path, fake_runtime):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.runtime.base import WorkspaceSpec

    store = await WorkspaceStore.open(sqlite_path)
    registry = WorkspaceRegistry(runtime=fake_runtime, store=store, server_id="test")
    await store.insert(
        workspace_id="ws-01",
        project="p",
        intent="i",
        image="img:latest",
        root_path="",
        server_instance="test",
        status="provisioning",
    )
    spec = WorkspaceSpec(
        workspace_id="ws-01",
        project="p",
        intent="i",
        image="img:latest",
        root_path="",
    )
    await registry._do_provision("ws-01", spec)
    await asyncio.sleep(0)
    row = await store.get("ws-01")
    assert row.status == "running"


@pytest.mark.asyncio
async def test_do_provision_threads_ssh_access_enabled_as_publish_ssh_port(sqlite_path):
    """Audit R12: settings.ssh_access_enabled (default False -- no shipped
    workspace image runs sshd on this port yet) must thread through to the
    runtime's publish_ssh_port kwarg, not just be read and ignored. Port
    ALLOCATION (allocate_ssh_port/update_ssh_port) is unconditional either
    way -- only the actual container-level publish is gated."""
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.supports_ssh_access = True
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-ssh", runtime_id="ctr-ssh", root_path=""
    )
    settings = SimpleNamespace(ssh_access_enabled=False, ssh_port_range_start=30000, ssh_port_range_end=31000)
    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", settings=settings
    )
    await store.insert(
        workspace_id="ws-ssh", project="p", intent="i", image="img:latest",
        root_path="", server_instance="test", status="provisioning",
    )
    spec = WorkspaceSpec(
        workspace_id="ws-ssh", project="p", intent="i", image="img:latest", root_path="",
    )

    await registry._do_provision("ws-ssh", spec)
    await asyncio.sleep(0)

    _, kwargs = runtime.provision.call_args
    assert kwargs["publish_ssh_port"] is False

    # Port allocation itself is still unconditional.
    row = await store.get("ws-ssh")
    assert row.ssh_port is not None


@pytest.mark.asyncio
async def test_do_provision_publishes_ssh_port_when_settings_enable_it(sqlite_path):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.supports_ssh_access = True
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-ssh2", runtime_id="ctr-ssh2", root_path=""
    )
    settings = SimpleNamespace(ssh_access_enabled=True, ssh_port_range_start=30000, ssh_port_range_end=31000)
    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", settings=settings
    )
    await store.insert(
        workspace_id="ws-ssh2", project="p", intent="i", image="img:latest",
        root_path="", server_instance="test", status="provisioning",
    )
    spec = WorkspaceSpec(
        workspace_id="ws-ssh2", project="p", intent="i", image="img:latest", root_path="",
    )

    await registry._do_provision("ws-ssh2", spec)
    await asyncio.sleep(0)

    _, kwargs = runtime.provision.call_args
    assert kwargs["publish_ssh_port"] is True


@pytest.mark.asyncio
async def test_do_provision_failure_updates_status(sqlite_path):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.runtime.base import WorkspaceSpec
    from warren_common.errors import RuntimeUnreachable
    from types import SimpleNamespace

    async def _fail_provision(spec):
        raise RuntimeUnreachable("unreachable")

    fake_runtime = SimpleNamespace(provision=_fail_provision)
    store = await WorkspaceStore.open(sqlite_path)
    registry = WorkspaceRegistry(runtime=fake_runtime, store=store, server_id="test")
    await store.insert(
        workspace_id="ws-02",
        project="p",
        intent="i",
        image="img:latest",
        root_path="",
        server_instance="test",
        status="provisioning",
    )
    spec = WorkspaceSpec(
        workspace_id="ws-02",
        project="p",
        intent="i",
        image="img:latest",
        root_path="",
    )
    await registry._do_provision("ws-02", spec)
    await asyncio.sleep(0)
    row = await store.get("ws-02")
    assert row.status == "failed"


@pytest.mark.asyncio
async def test_destroy_calls_event_store_discard(sqlite_path, fake_runtime):
    """WorkspaceRegistry.destroy() must call event_store.discard(workspace_id) (04-05, T-04-05-02)."""
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren.registry.events import WorkspaceEventStore

    store = await WorkspaceStore.open(sqlite_path)
    event_store = WorkspaceEventStore()
    # Pre-populate a buffer so discard can be verified
    event_store.get_or_create("ws-destroy")
    assert "ws-destroy" in event_store._buffers

    registry = WorkspaceRegistry(
        runtime=fake_runtime,
        store=store,
        server_id="test",
        event_store=event_store,
    )
    await store.insert(
        workspace_id="ws-destroy",
        project="p",
        intent="i",
        image="img:latest",
        root_path="",
        server_instance="test",
        status="running",
    )
    await registry.destroy("ws-destroy")
    # Buffer must be discarded after destroy
    assert "ws-destroy" not in event_store._buffers


@pytest.mark.asyncio
async def test_destroy_runtime_failure_marks_unknown_not_stopped(sqlite_path):
    """Regression for issue #8: a runtime.destroy() that raises must not be
    recorded as "stopped" — the container may still be running and reachable,
    just no longer tracked. "unknown" is the honest, retryable state."""
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren.registry.events import WorkspaceEventStore

    store = await WorkspaceStore.open(sqlite_path)
    event_store = WorkspaceEventStore()
    event_store.get_or_create("ws-destroy-fail")
    runtime = AsyncMock()
    runtime.destroy.side_effect = RuntimeError("boom")
    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", event_store=event_store
    )
    await store.insert(
        workspace_id="ws-destroy-fail",
        project="p",
        intent="i",
        image="img:latest",
        root_path="",
        server_instance="test",
        status="running",
        container_id="ctr-1",
    )

    await registry.destroy("ws-destroy-fail")

    row = await store.get("ws-destroy-fail")
    assert row.status == "unknown"
    # A failed destroy must not discard the event buffer either — the
    # container may still be alive and producing events.
    assert "ws-destroy-fail" in event_store._buffers


@pytest.mark.asyncio
async def test_provision_and_destroy_race_does_not_resurrect_workspace(sqlite_path):
    """Regression for issue #7: a destroy() arriving while a slower
    _do_provision() for the same workspace_id is still in flight must not be
    silently overwritten back to "running" once provision finally completes.
    The per-workspace lock forces destroy to wait for provision to finish
    first, so the workspace ends up destroyed, not resurrected."""
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.runtime.base import WorkspaceSpec, WorkspaceHandle

    provision_started = asyncio.Event()
    release_provision = asyncio.Event()

    class _SlowRuntime:
        async def provision(self, spec):
            provision_started.set()
            await release_provision.wait()
            return WorkspaceHandle(
                workspace_id=spec.workspace_id,
                runtime_id="ctr-slow",
                root_path="",
                sidecar_url="",
            )

        async def destroy(self, handle):
            return None

    store = await WorkspaceStore.open(sqlite_path)
    registry = WorkspaceRegistry(runtime=_SlowRuntime(), store=store, server_id="test")
    await store.insert(
        workspace_id="ws-race",
        project="p",
        intent="i",
        image="img:latest",
        root_path="",
        server_instance="test",
        status="provisioning",
    )
    spec = WorkspaceSpec(
        workspace_id="ws-race", project="p", intent="i", image="img:latest", root_path=""
    )

    provision_task = asyncio.create_task(registry._do_provision("ws-race", spec))
    await provision_started.wait()

    destroy_task = asyncio.create_task(registry.destroy("ws-race"))
    # Give destroy a chance to start and block on the same workspace's lock.
    await asyncio.sleep(0)

    release_provision.set()
    await provision_task
    await destroy_task

    row = await store.get("ws-race")
    # destroy() ran strictly after provision() finished (lock-serialized), so
    # its "destroyed" write is the last one — never silently reverted to
    # "running" by a provision call that was actually still in flight.
    assert row.status == "destroyed"


# --- stop() (LIFE-01) — plan 04-05 Task 1 ---


@pytest.mark.asyncio
async def test_stop_calls_runtime_stop_and_sets_status_stopped(sqlite_path, fake_runtime):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry

    store = await WorkspaceStore.open(sqlite_path)
    registry = WorkspaceRegistry(runtime=fake_runtime, store=store, server_id="test")
    await store.insert(
        workspace_id="ws-stop",
        project="p",
        intent="i",
        image="img:latest",
        root_path="",
        server_instance="test",
        status="running",
        container_id="fake-ws-stop",
    )

    await registry.stop("ws-stop")

    row = await store.get("ws-stop")
    assert row.status == "stopped"


@pytest.mark.asyncio
async def test_stop_unknown_workspace_is_silent_noop(sqlite_path, fake_runtime):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry

    store = await WorkspaceStore.open(sqlite_path)
    registry = WorkspaceRegistry(runtime=fake_runtime, store=store, server_id="test")

    # Must not raise.
    await registry.stop("ws-does-not-exist")


@pytest.mark.asyncio
async def test_stop_on_destroyed_workspace_is_safe_noop(sqlite_path, fake_runtime):
    """Audit R8: stop() must never write "stopped" over a genuinely terminal
    "destroyed" status. Without this check, the idle reaper's read-then-call
    of stop() can race a concurrent destroy() -- the reaper observes
    "running", the owner destroys the workspace, then the reaper's stop()
    call takes the lock and would otherwise resurrect it as "stopped",
    reconnectable via a later ensure_running()."""
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry

    store = await WorkspaceStore.open(sqlite_path)
    registry = WorkspaceRegistry(runtime=fake_runtime, store=store, server_id="test")
    await store.insert(
        workspace_id="ws-destroyed",
        project="p",
        intent="i",
        image="img:latest",
        root_path="",
        server_instance="test",
        status="destroyed",
        container_id=None,
    )

    await registry.stop("ws-destroyed")  # must not raise

    row = await store.get("ws-destroyed")
    assert row.status == "destroyed"


@pytest.mark.asyncio
async def test_stop_swallows_runtime_exception_and_marks_unknown(sqlite_path):
    """Regression for issue #8: a failed stop() must not be recorded as
    "stopped" — that falsely implies the container is confirmed gone. It now
    lands on "unknown", a non-terminal state reconciliation can act on."""
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.stop.side_effect = RuntimeError("boom")
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")
    await store.insert(
        workspace_id="ws-1",
        project="p",
        intent="i",
        image="img:latest",
        root_path="",
        server_instance="test",
        status="running",
        container_id="ctr-1",
    )

    await registry.stop("ws-1")

    row = await store.get("ws-1")
    assert row.status == "unknown"


@pytest.mark.asyncio
async def test_stop_preserves_ssh_port_and_event_buffer(sqlite_path, fake_runtime):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren.registry.events import WorkspaceEventStore

    store = await WorkspaceStore.open(sqlite_path)
    event_store = WorkspaceEventStore()
    event_store.get_or_create("ws-1")
    registry = WorkspaceRegistry(
        runtime=fake_runtime, store=store, server_id="test", event_store=event_store
    )
    await store.insert(
        workspace_id="ws-1",
        project="p",
        intent="i",
        image="img:latest",
        root_path="",
        server_instance="test",
        status="running",
        container_id="fake-ws-1",
        ssh_port=30010,
    )

    await registry.stop("ws-1")

    row = await store.get("ws-1")
    assert row.ssh_port == 30010
    assert "ws-1" in event_store._buffers


@pytest.mark.asyncio
async def test_stop_falls_back_to_destroy_when_runtime_has_no_stop(sqlite_path):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from types import SimpleNamespace

    destroy_calls = []

    async def _destroy(handle):
        destroy_calls.append(handle)

    runtime = SimpleNamespace(destroy=_destroy)
    store = await WorkspaceStore.open(sqlite_path)
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")
    await store.insert(
        workspace_id="ws-1",
        project="p",
        intent="i",
        image="img:latest",
        root_path="",
        server_instance="test",
        status="running",
        container_id="ctr-1",
    )

    await registry.stop("ws-1")

    assert len(destroy_calls) == 1
    row = await store.get("ws-1")
    assert row.status == "stopped"


# --- ensure_running() (D-04) + issue_ssh_credential() (D-01/D-02) — plan 03-04 Task 2 ---


def _handle_from(ws_id: str, container_id: str) -> "object":
    from warren_common.runtime.base import WorkspaceHandle

    return WorkspaceHandle(
        workspace_id=ws_id, runtime_id=container_id, root_path="", sidecar_url=""
    )


@pytest.mark.asyncio
async def test_ensure_running_already_running_returns_handle_without_start_or_provision(
    sqlite_path,
):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.supports_ssh_access = True
    runtime.status.return_value = "running"
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")

    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="running", container_id="ctr-1", ssh_port=30000,
    )

    handle = await registry.ensure_running("ws-1")

    assert handle is not None
    assert handle.runtime_id == "ctr-1"
    runtime.start.assert_not_awaited()
    runtime.provision.assert_not_awaited()


@pytest.mark.asyncio
async def test_ensure_running_stopped_container_calls_start(sqlite_path):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.supports_ssh_access = True
    runtime.status.return_value = "stopped"
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")

    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="stopped", container_id="ctr-1", ssh_port=30000,
    )

    handle = await registry.ensure_running("ws-1")

    assert handle is not None
    runtime.start.assert_awaited_once()
    runtime.provision.assert_not_awaited()
    row = await store.get("ws-1")
    assert row.status == "running"


@pytest.mark.asyncio
async def test_ensure_running_no_container_reprovisions_with_stored_port(sqlite_path):
    """A re-provisioned workspace reuses its stored ssh_port (D-05)."""
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.runtime.base import WorkspaceHandle

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.supports_ssh_access = True
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-1", runtime_id="ctr-new", root_path=""
    )
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")

    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="stopped", container_id="", ssh_port=30005,
    )

    handle = await registry.ensure_running("ws-1")

    assert handle is not None
    assert handle.runtime_id == "ctr-new"
    runtime.status.assert_not_awaited()
    runtime.start.assert_not_awaited()
    _, kwargs = runtime.provision.call_args
    assert kwargs["ssh_port"] == 30005
    row = await store.get("ws-1")
    assert row.container_id == "ctr-new"
    assert row.ssh_port == 30005
    assert row.status == "running"


@pytest.mark.asyncio
async def test_ensure_running_ecs_stopped_task_reprovisions_instead_of_starting(sqlite_path):
    """Regression for finding 9: ECS (no supports_ssh_access) has no "start a
    stopped task" operation -- a "stopped" status must trigger a fresh
    RunTask via reprovision, never a call to runtime.start() against a dead
    task ARN."""
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.runtime.base import WorkspaceHandle

    store = await WorkspaceStore.open(sqlite_path)
    # spec_set (no "start", no "supports_ssh_access") mirrors ECSRuntime's real
    # attribute surface -- any accidental runtime.start() call would raise
    # AttributeError instead of silently succeeding against a dead task ARN.
    runtime = MagicMock(spec_set=["provision", "status", "destroy"])
    runtime.provision = AsyncMock(
        return_value=WorkspaceHandle(workspace_id="ws-1", runtime_id="arn:task-new", root_path="")
    )
    runtime.status = AsyncMock(return_value="stopped")
    runtime.destroy = AsyncMock()
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")

    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="stopped", container_id="arn:task-old",
    )

    handle = await registry.ensure_running("ws-1")

    # runtime has no "start" in its spec -- calling it would raise AttributeError,
    # so successfully reaching here already proves start() was never attempted.
    assert handle.runtime_id == "arn:task-new"
    runtime.provision.assert_awaited_once()
    # AI3: the previous task ARN is this launch's generation (fresh clientToken).
    assert runtime.provision.call_args.args[0].provision_generation == "arn:task-old"
    row = await store.get("ws-1")
    assert row.container_id == "arn:task-new"
    assert row.status == "running"


def _ecs_like_runtime(statuses, new_arn="arn:task-new"):
    from warren_common.runtime.base import WorkspaceHandle

    runtime = MagicMock(spec_set=["provision", "status", "destroy"])
    runtime.provision = AsyncMock(
        return_value=WorkspaceHandle(workspace_id="ws-1", runtime_id=new_arn, root_path="")
    )
    runtime.status = AsyncMock(side_effect=list(statuses))
    runtime.destroy = AsyncMock()
    return runtime


_FAST_START_WAIT = SimpleNamespace(
    runtime_type="ecs", ecs_start_wait_timeout_seconds=1.0, ecs_start_poll_interval_seconds=0.01
)


@pytest.mark.asyncio
async def test_ensure_running_waits_on_starting_task_instead_of_reprovisioning(sqlite_path):
    """BB4: a task still PROVISIONING/PENDING must be waited on, not duplicated."""
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry

    store = await WorkspaceStore.open(sqlite_path)
    runtime = _ecs_like_runtime(["starting", "starting", "running"])
    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", settings=_FAST_START_WAIT
    )
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="running", container_id="arn:task-launching",
        ssh_port=30000,
    )

    handle = await registry.ensure_running("ws-1")

    assert handle.runtime_id == "arn:task-launching"
    runtime.provision.assert_not_awaited()
    assert runtime.status.await_count == 3


@pytest.mark.asyncio
async def test_ensure_running_starting_then_stopped_reprovisions(sqlite_path):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry

    store = await WorkspaceStore.open(sqlite_path)
    runtime = _ecs_like_runtime(["starting", "stopped"])
    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", settings=_FAST_START_WAIT
    )
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="running", container_id="arn:task-launching",
        ssh_port=30000,
    )

    handle = await registry.ensure_running("ws-1")

    assert handle.runtime_id == "arn:task-new"
    runtime.provision.assert_awaited_once()


@pytest.mark.asyncio
async def test_ensure_running_starting_timeout_raises_without_reprovisioning(sqlite_path):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry, WorkspaceStillStarting

    store = await WorkspaceStore.open(sqlite_path)
    runtime = MagicMock(spec_set=["provision", "status", "destroy"])
    runtime.provision = AsyncMock()
    runtime.status = AsyncMock(return_value="starting")
    settings = SimpleNamespace(
        ecs_start_wait_timeout_seconds=0.05,
        ecs_start_poll_interval_seconds=0.01,
        ecs_start_retry_after_seconds=4,
    )
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test", settings=settings)
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="running", container_id="arn:task-stuck",
        ssh_port=30000,
    )

    with pytest.raises(WorkspaceStillStarting) as excinfo:
        await registry.ensure_running("ws-1")

    assert excinfo.value.reason == "workspace_starting"
    assert excinfo.value.retry_after_seconds == 4
    runtime.provision.assert_not_awaited()
    row = await store.get("ws-1")
    assert row.container_id == "arn:task-stuck"


@pytest.mark.asyncio
async def test_ensure_running_unknown_status_reprovisions(sqlite_path):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.runtime.base import WorkspaceHandle

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.supports_ssh_access = True
    runtime.status.return_value = "unknown"
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-1", runtime_id="ctr-new", root_path=""
    )
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")

    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="unknown", container_id="ctr-stale", ssh_port=30005,
    )

    handle = await registry.ensure_running("ws-1")

    assert handle.runtime_id == "ctr-new"
    _, kwargs = runtime.provision.call_args
    assert kwargs["ssh_port"] == 30005


@pytest.mark.asyncio
async def test_ensure_running_legacy_row_without_ssh_port_allocates_and_persists(sqlite_path):
    """A legacy row with no stored ssh_port allocates one and persists it."""
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.runtime.base import WorkspaceHandle

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.supports_ssh_access = True
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-1", runtime_id="ctr-new", root_path=""
    )
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")

    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="stopped", container_id="",
    )

    await registry.ensure_running("ws-1")

    row = await store.get("ws-1")
    assert row.ssh_port == 30000


@pytest.mark.asyncio
async def test_ensure_running_unknown_workspace_returns_none(sqlite_path):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry

    store = await WorkspaceStore.open(sqlite_path)
    registry = WorkspaceRegistry(runtime=AsyncMock(), store=store, server_id="test")

    handle = await registry.ensure_running("ws-does-not-exist")

    assert handle is None


@pytest.mark.asyncio
async def test_ensure_running_propagates_provision_error(sqlite_path):
    from warren_common.errors import RuntimeUnreachable
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.supports_ssh_access = True
    runtime.provision.side_effect = RuntimeUnreachable("unreachable")
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")

    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="stopped", container_id="", ssh_port=30000,
    )

    with pytest.raises(RuntimeUnreachable):
        await registry.ensure_running("ws-1")


# --- ensure_running() reprovision-with-full-spec (finding 7) ---


@pytest.mark.asyncio
async def test_ensure_running_reprovisions_with_full_spec(sqlite_path):
    """Regression for finding 7: a reaped-and-gone container must come back
    with the SAME secrets/folders/app/idle_ttl it started with, not an empty
    shell built from the bare DB row alone.

    Audit R1: env is deliberately NOT part of what's asserted to round-trip
    verbatim through spec_json -- see test_ensure_running_reprovision_never_
    persists_decrypted_secret_value and test_ensure_running_reprovision_
    resolves_secrets_fresh_from_store below for the corrected behavior (env
    is re-resolved from the secrets store on every reprovision, never
    persisted in spec_json).
    """
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry, serialize_spec_extra
    from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec
    from warren_common.models import FolderSpec

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.supports_ssh_access = True
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-1", runtime_id="ctr-new", root_path=""
    )
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")

    original_spec = WorkspaceSpec(
        workspace_id="ws-1",
        project="p",
        intent="i",
        image="img",
        root_path="",
        env={"ANTHROPIC_API_KEY": "sk-secret"},
        secret_names=["ANTHROPIC_API_KEY"],
        owner_id="user-1",
        folders=[FolderSpec(name="repo", type="git-worktree", mount="code/repo", url="git@example.com:repo.git")],
        app="claude",
        idle_ttl_seconds=7200.0,
    )

    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="unknown", container_id="ctr-stale", ssh_port=30005,
        owner_id="user-1", idle_ttl_seconds=7200.0,
        spec_json=serialize_spec_extra(original_spec),
    )

    handle = await registry.ensure_running("ws-1")

    assert handle.runtime_id == "ctr-new"
    spec_arg, kwargs = runtime.provision.call_args
    reprovisioned_spec = spec_arg[0]
    assert reprovisioned_spec.secret_names == ["ANTHROPIC_API_KEY"]
    assert reprovisioned_spec.owner_id == "user-1"
    assert reprovisioned_spec.app == "claude"
    assert reprovisioned_spec.idle_ttl_seconds == 7200.0
    assert len(reprovisioned_spec.folders) == 1
    assert reprovisioned_spec.folders[0].name == "repo"
    assert kwargs["ssh_port"] == 30005
    # No settings configured on this registry -> secret resolution is skipped
    # entirely (same as create_workspace's own ECS-skips-this-path behavior),
    # so env is empty here, not a security assertion in this particular test.
    assert reprovisioned_spec.env == {}


@pytest.mark.asyncio
async def test_ensure_running_reprovision_never_persists_decrypted_secret_value(
    sqlite_path,
):
    """Audit R1 (critical): spec_json must never contain a secret's decrypted
    value -- only secret_names (the declared name, not the value). Previously
    `env` (which holds decrypted values for podman/docker) was persisted
    verbatim, landing every secret's plaintext in SQLite and bypassing the
    Fernet-encrypted secrets store entirely."""
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry, serialize_spec_extra
    from warren_common.runtime.base import WorkspaceSpec

    store = await WorkspaceStore.open(sqlite_path)
    registry = WorkspaceRegistry(runtime=AsyncMock(), store=store, server_id="test")

    spec = WorkspaceSpec(
        workspace_id="ws-1",
        project="p",
        intent="i",
        image="img",
        root_path="",
        env={"ANTHROPIC_API_KEY": "sk-should-never-be-persisted"},
        secret_names=["ANTHROPIC_API_KEY"],
        owner_id="user-1",
    )

    dumped = serialize_spec_extra(spec)

    assert "sk-should-never-be-persisted" not in dumped
    assert "env" not in __import__("json").loads(dumped)


@pytest.mark.asyncio
async def test_ensure_running_reprovision_resolves_secrets_fresh_from_store(
    sqlite_path, monkeypatch
):
    """Audit R1: on reprovision, env must be re-resolved from the live secrets
    store (using the persisted owner_id/secret_names), not read back from
    spec_json -- so a rotated secret reaches the reprovisioned workspace with
    its NEW value, and a deleted one doesn't reach it at all."""
    from pydantic import SecretStr
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry, serialize_spec_extra
    from warren.secrets import store as local_store
    from warren.secrets.cipher import LocalCipher
    from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.supports_ssh_access = True
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-1", runtime_id="ctr-new", root_path=""
    )

    secret_key = "a" * 32
    settings = SimpleNamespace(runtime_type="podman", secret_key=SecretStr(secret_key))
    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", settings=settings
    )

    cipher = LocalCipher(secret_key)
    # The value stored at ORIGINAL provision time -- never persisted anywhere
    # in spec_json, only used here to prove reprovision reads the CURRENT
    # store value instead, not this one.
    await local_store.set_secret(store._db, cipher, "user-1", "API_KEY", "stale-original-value")

    original_spec = WorkspaceSpec(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        env={"API_KEY": "stale-original-value"}, secret_names=["API_KEY"], owner_id="user-1",
    )
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="unknown", container_id="ctr-stale", ssh_port=30006,
        owner_id="user-1", spec_json=serialize_spec_extra(original_spec),
    )

    # Rotate the secret after the workspace's original provision.
    await local_store.set_secret(store._db, cipher, "user-1", "API_KEY", "rotated-new-value")

    await registry.ensure_running("ws-1")

    spec_arg, _ = runtime.provision.call_args
    reprovisioned_spec = spec_arg[0]
    assert reprovisioned_spec.env == {"API_KEY": "rotated-new-value"}


@pytest.mark.asyncio
async def test_ensure_running_legacy_row_without_spec_json_reprovisions_bare(sqlite_path):
    """A legacy row provisioned before finding-7's fix (no spec_json at all)
    still reprovisions -- just without the fields it never had -- matching
    the old bare-DB-row behavior exactly rather than erroring."""
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.runtime.base import WorkspaceHandle

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.supports_ssh_access = True
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-1", runtime_id="ctr-new", root_path=""
    )
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")

    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="unknown", container_id="ctr-stale", ssh_port=30005,
    )

    handle = await registry.ensure_running("ws-1")

    assert handle.runtime_id == "ctr-new"


@pytest.mark.asyncio
async def test_ensure_running_reprovision_strips_stale_plaintext_env_on_ecs(sqlite_path):
    """Audit V3: a pre-R1 row's spec_json can still carry a plaintext "env" key (store.py's
    open_db() scrub handles the DB at rest, but this proves _reprovision_spec itself never
    lets it reach WorkspaceSpec either). The ECS branch never re-resolves spec.env at all
    (that's podman/docker-only), so without this fix the stale plaintext secret value
    would reach runtime.provision() as an ECS task-environment override -- worse than the
    original R1 exposure, since SSM SecureString at least encrypts at rest."""
    import json
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.runtime.base import WorkspaceHandle

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.supports_ssh_access = False
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-1", runtime_id="ctr-new", root_path=""
    )
    settings = SimpleNamespace(runtime_type="ecs")
    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", settings=settings
    )

    # Simulates a row written before R1 removed "env" from _SPEC_EXTRA_FIELDS --
    # store.py's own scrub normally cleans this on open_db(), so insert it directly
    # into an already-open store to isolate _reprovision_spec's own defense.
    legacy_spec_json = json.dumps(
        {"secret_names": ["API_KEY"], "env": {"API_KEY": "stale-plaintext-secret"}}
    )
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="unknown", container_id="ctr-stale", ssh_port=30007,
        owner_id="user-1", spec_json=legacy_spec_json,
    )

    await registry.ensure_running("ws-1")

    spec_arg, _ = runtime.provision.call_args
    reprovisioned_spec = spec_arg[0]
    assert reprovisioned_spec.env == {}


@pytest.mark.asyncio
async def test_ensure_running_reprovision_strips_unsanctioned_local_path_folder(
    sqlite_path, tmp_path
):
    """Audit Z1: create_workspace re-validates local-path folders against the
    server-wide file (Y1/V2), but _reprovision_spec was restoring `folders`
    straight from spec_json with no re-check -- a workspace provisioned during
    the window before that fix existed (or whose spec_json otherwise ended up
    with an unsanctioned entry) would have it re-mounted on every reprovision
    forever. No server-wide file exists in this test, so nothing can be
    sanctioned."""
    import json
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.runtime.base import WorkspaceHandle

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.supports_ssh_access = False
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-1", runtime_id="ctr-new", root_path=""
    )
    from pydantic import SecretStr

    settings = SimpleNamespace(
        runtime_type="podman", projects_dir=tmp_path / "projects", secret_key=SecretStr("a" * 32)
    )
    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", settings=settings
    )

    legacy_spec_json = json.dumps(
        {
            "folders": [
                {"name": "wiki", "type": "local-path", "mount": "wiki", "path": "/etc"}
            ],
        }
    )
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="unknown", container_id="ctr-stale", ssh_port=30008,
        owner_id="user-1", spec_json=legacy_spec_json,
    )

    await registry.ensure_running("ws-1")

    spec_arg, _ = runtime.provision.call_args
    reprovisioned_spec = spec_arg[0]
    assert reprovisioned_spec.folders == []


@pytest.mark.asyncio
async def test_ensure_running_reprovision_strips_unsanctioned_docker_network(
    sqlite_path, tmp_path
):
    """Audit Z1 (same class, docker_networks side): docker_networks is persisted
    in _SPEC_EXTRA_FIELDS the same way folders is, so it needs the same
    reprovision-time re-check R24 added for create_workspace."""
    import json
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.runtime.base import WorkspaceHandle

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.supports_ssh_access = False
    runtime.provision.return_value = WorkspaceHandle(
        workspace_id="ws-1", runtime_id="ctr-new", root_path=""
    )
    from pydantic import SecretStr

    settings = SimpleNamespace(
        runtime_type="podman",
        projects_dir=tmp_path / "projects",
        allowed_docker_networks=[],
        secret_key=SecretStr("a" * 32),
    )
    registry = WorkspaceRegistry(
        runtime=runtime, store=store, server_id="test", settings=settings
    )

    legacy_spec_json = json.dumps({"docker_networks": ["host-internal-net"]})
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="unknown", container_id="ctr-stale", ssh_port=30009,
        owner_id="user-1", spec_json=legacy_spec_json,
    )

    await registry.ensure_running("ws-1")

    spec_arg, _ = runtime.provision.call_args
    reprovisioned_spec = spec_arg[0]
    assert reprovisioned_spec.docker_networks == []


# --- "destroyed" terminal state (finding 8) ---


@pytest.mark.asyncio
async def test_destroy_sets_destroyed_status_and_clears_container_id(sqlite_path, fake_runtime):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry

    store = await WorkspaceStore.open(sqlite_path)
    registry = WorkspaceRegistry(runtime=fake_runtime, store=store, server_id="test")
    await store.insert(
        workspace_id="ws-destroy",
        project="p",
        intent="i",
        image="img:latest",
        root_path="",
        server_instance="test",
        status="running",
        container_id="fake-ws-destroy",
    )

    await registry.destroy("ws-destroy")

    row = await store.get("ws-destroy")
    assert row.status == "destroyed"
    assert row.container_id is None


@pytest.mark.asyncio
async def test_destroy_prunes_the_lock_entry(sqlite_path, fake_runtime):
    """Regression guard for audit 2026-10-16 #35: `_locks` grows one entry
    per workspace_id ever seen and is never pruned -- a confirmed destroy
    (a terminal state; no further lifecycle transition for this
    workspace_id will need serializing again) must drop its entry."""
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry

    store = await WorkspaceStore.open(sqlite_path)
    registry = WorkspaceRegistry(runtime=fake_runtime, store=store, server_id="test")
    await store.insert(
        workspace_id="ws-prune",
        project="p",
        intent="i",
        image="img:latest",
        root_path="",
        server_instance="test",
        status="running",
        container_id="fake-ws-prune",
    )

    await registry.destroy("ws-prune")

    assert "ws-prune" not in registry._locks


@pytest.mark.asyncio
async def test_destroy_is_idempotent_on_already_destroyed_row(sqlite_path):
    """A second destroy() on an already-destroyed row must not call the
    runtime again (its container_id is already gone/cleared)."""
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="destroyed",
    )

    await registry.destroy("ws-1")

    runtime.destroy.assert_not_called()


@pytest.mark.asyncio
async def test_ensure_running_destroyed_workspace_raises_instead_of_resurrecting(sqlite_path):
    """Regression for finding 8: /connect and /ensure_running must never
    reprovision a workspace the owner explicitly destroyed, even though its
    stale container_id would otherwise look reprovision-able."""
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry, WorkspaceDestroyedError

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="destroyed", container_id="stale-ctr",
    )

    with pytest.raises(WorkspaceDestroyedError):
        await registry.ensure_running("ws-1")

    runtime.provision.assert_not_called()
    runtime.status.assert_not_called()


@pytest.mark.asyncio
async def test_issue_ssh_credential_returns_port_and_valid_key_injects_once(sqlite_path):
    from cryptography.hazmat.primitives import serialization
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.supports_ssh_access = True
    runtime.status.return_value = "running"
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")

    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="running", container_id="ctr-1", ssh_port=30007,
    )

    result = await registry.issue_ssh_credential("ws-1")

    assert result is not None
    ssh_port, private_pem = result
    assert ssh_port == 30007
    private_key = serialization.load_ssh_private_key(private_pem, password=None)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    assert isinstance(private_key, Ed25519PrivateKey)

    runtime.inject_ssh_key.assert_awaited_once()
    handle_arg, pubkey_arg = runtime.inject_ssh_key.call_args.args
    assert handle_arg.runtime_id == "ctr-1"

    # Injected public key must correspond to the returned private key.
    injected_pub = serialization.load_ssh_public_key(pubkey_arg.encode())
    priv_pub_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    injected_pub_bytes = injected_pub.public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw
    )
    assert priv_pub_bytes == injected_pub_bytes


@pytest.mark.asyncio
async def test_issue_ssh_credential_two_calls_return_different_private_keys(sqlite_path):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.supports_ssh_access = True
    runtime.status.return_value = "running"
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")

    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="running", container_id="ctr-1", ssh_port=30007,
    )

    _, pem1 = await registry.issue_ssh_credential("ws-1")
    _, pem2 = await registry.issue_ssh_credential("ws-1")

    assert pem1 != pem2


@pytest.mark.asyncio
async def test_issue_ssh_credential_unknown_workspace_returns_none(sqlite_path):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry

    store = await WorkspaceStore.open(sqlite_path)
    registry = WorkspaceRegistry(runtime=AsyncMock(), store=store, server_id="test")

    result = await registry.issue_ssh_credential("ws-does-not-exist")

    assert result is None


@pytest.mark.asyncio
async def test_issue_ssh_credential_never_logs_private_key(sqlite_path, monkeypatch):
    from warren.registry.store import WorkspaceStore
    from warren.registry.registry import WorkspaceRegistry
    import warren.registry.registry as registry_mod

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.supports_ssh_access = True
    runtime.status.return_value = "running"
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test")

    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="running", container_id="ctr-1", ssh_port=30007,
    )

    logged_payloads = []
    orig_info = registry_mod.log.info

    def _capture(event, *args, **kwargs):
        logged_payloads.append((event, args, kwargs))
        return orig_info(event, *args, **kwargs)

    monkeypatch.setattr(registry_mod.log, "info", _capture)

    ssh_port, private_pem = await registry.issue_ssh_credential("ws-1")

    for event, args, kwargs in logged_payloads:
        serialized = repr((event, args, kwargs))
        assert private_pem.decode(errors="ignore") not in serialized


def test_spec_extra_round_trips_template_env():
    from warren.registry.registry import deserialize_spec_extra, serialize_spec_extra
    from warren_common.runtime.base import WorkspaceSpec

    spec = WorkspaceSpec(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        env={"API_KEY": "sk-secret"}, template_env={"OLLAMA_HOST": "http://gpu:11434"},
    )
    raw = serialize_spec_extra(spec)
    assert "sk-secret" not in raw
    assert deserialize_spec_extra(raw)["template_env"] == {"OLLAMA_HOST": "http://gpu:11434"}


def test_spec_extra_never_persists_seed_prompt():
    from warren.registry.registry import serialize_spec_extra
    from warren_common.runtime.base import WorkspaceSpec

    spec = WorkspaceSpec(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        app="claude", seed_prompt="first turn only",
    )
    assert "first turn only" not in serialize_spec_extra(spec)
