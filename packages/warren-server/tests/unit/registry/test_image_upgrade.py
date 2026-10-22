"""AB1 req 6: a workspace that needs a new task re-resolves its image like
create_workspace does, through the same allow-list; a running task is never
replaced."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from warren.registry.registry import WorkspaceRegistry, serialize_spec_extra
from warren.registry.store import WorkspaceStore
from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

WS = "0b1c2d3e-0000-4000-8000-0000000000aa"


def _ecs_runtime(status: str):
    """ECS-like: no supports_ssh_access, so a stopped task is reprovisioned."""
    return SimpleNamespace(
        status=AsyncMock(return_value=status),
        provision=AsyncMock(return_value=WorkspaceHandle(workspace_id=WS, runtime_id="arn:task-new", root_path="")),
        start=AsyncMock(),
        stop=AsyncMock(),
        destroy=AsyncMock(),
    )


async def _setup(sqlite_path, tmp_path, runtime, *, server_yaml, user_yaml=None, allowed=()):
    projects = tmp_path / "projects"
    projects.mkdir()
    (projects / "p.yaml").write_text(server_yaml)
    if user_yaml is not None:
        (projects / "users" / "user-1").mkdir(parents=True)
        (projects / "users" / "user-1" / "p.yaml").write_text(user_yaml)
    settings = SimpleNamespace(
        runtime_type="ecs",
        projects_dir=projects,
        ecs_default_image="registry/ws:v2",
        allowed_images=list(allowed),
        ecs_start_wait_timeout_seconds=1,
        ecs_start_poll_interval_seconds=0.01,
    )
    store = await WorkspaceStore.open(sqlite_path)
    spec = WorkspaceSpec(workspace_id=WS, project="p", intent="dev", image="registry/ws:v1", root_path="")
    await store.insert(
        workspace_id=WS, project="p", intent="dev", image="registry/ws:v1", root_path="", server_instance="t",
        status="stopped", container_id="arn:task-old", ssh_port=30001, owner_id="user-1",
        spec_json=serialize_spec_extra(spec),
    )
    return WorkspaceRegistry(runtime=runtime, store=store, server_id="t", settings=settings), store


_DEFAULT_TEMPLATE = "name: p\ntemplates:\n  dev:\n    app: bash\n"


@pytest.mark.asyncio
async def test_relaunch_picks_up_the_new_default_image(sqlite_path, tmp_path):
    runtime = _ecs_runtime("stopped")
    registry, store = await _setup(sqlite_path, tmp_path, runtime, server_yaml=_DEFAULT_TEMPLATE)

    await registry.ensure_running(WS)

    assert runtime.provision.call_args.args[0].image == "registry/ws:v2"
    assert (await store.get(WS)).image == "registry/ws:v2"


@pytest.mark.asyncio
async def test_template_pinned_image_is_kept(sqlite_path, tmp_path):
    runtime = _ecs_runtime("stopped")
    registry, store = await _setup(
        sqlite_path, tmp_path, runtime,
        server_yaml="name: p\ntemplates:\n  dev:\n    ecs_image: registry/pinned:1\n",
    )

    await registry.ensure_running(WS)

    assert runtime.provision.call_args.args[0].image == "registry/pinned:1"
    assert (await store.get(WS)).image == "registry/pinned:1"


@pytest.mark.asyncio
async def test_unsanctioned_user_image_is_not_used(sqlite_path, tmp_path):
    """Z1/Z12 on reprovision: a user-scoped override can't swap in its own image."""
    runtime = _ecs_runtime("stopped")
    registry, _ = await _setup(
        sqlite_path, tmp_path, runtime, server_yaml=_DEFAULT_TEMPLATE,
        user_yaml="name: p\ntemplates:\n  dev:\n    ecs_image: evil/image:1\n",
    )

    await registry.ensure_running(WS)

    assert runtime.provision.call_args.args[0].image == "registry/ws:v2"



@pytest.mark.asyncio
async def test_allow_listed_user_image_is_used(sqlite_path, tmp_path):
    runtime = _ecs_runtime("stopped")
    registry, _ = await _setup(
        sqlite_path, tmp_path, runtime, server_yaml=_DEFAULT_TEMPLATE,
        user_yaml="name: p\ntemplates:\n  dev:\n    ecs_image: team/image:1\n", allowed=["team/image:1"],
    )

    await registry.ensure_running(WS)

    assert runtime.provision.call_args.args[0].image == "team/image:1"


@pytest.mark.asyncio
async def test_running_task_is_never_replaced_but_reports_newer_image(sqlite_path, tmp_path):
    runtime = _ecs_runtime("running")
    registry, store = await _setup(sqlite_path, tmp_path, runtime, server_yaml=_DEFAULT_TEMPLATE)

    handle = await registry.ensure_running(WS)

    assert handle.runtime_id == "arn:task-old"
    runtime.provision.assert_not_awaited()
    ws = await store.get(WS)
    assert ws.image == "registry/ws:v1"
    assert await registry.resolve_current_image(ws) == "registry/ws:v2"


@pytest.mark.asyncio
async def test_unresolvable_template_keeps_stored_image(sqlite_path, tmp_path):
    runtime = _ecs_runtime("stopped")
    registry, _ = await _setup(sqlite_path, tmp_path, runtime, server_yaml="name: p\ntemplates: {}\n")

    await registry.ensure_running(WS)

    assert runtime.provision.call_args.args[0].image == "registry/ws:v1"
