"""AB1: a podman workspace's harness state lives in <data_dir>/harness/<id>,
mounted at /var/lib/warren/harness, so it survives reprovision and image
changes and goes away with the workspace."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from cryptography.fernet import Fernet
from pydantic import SecretStr

from warren.registry.registry import WorkspaceRegistry, serialize_spec_extra
from warren.registry.store import WorkspaceStore
from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

WS = "0b1c2d3e-0000-4000-8000-000000000001"


def _runtime():
    runtime = AsyncMock()
    runtime.supports_ssh_access = True
    runtime.provision.return_value = WorkspaceHandle(workspace_id=WS, runtime_id="ctr-new", root_path="")
    return runtime


async def _registry(sqlite_path, tmp_path, runtime, *, runtime_type="podman", harnesses=("claude",)):
    store = await WorkspaceStore.open(sqlite_path)
    settings = SimpleNamespace(
        runtime_type=runtime_type,
        data_dir=tmp_path / "data",
        host_data_dir=None,
        ssh_access_enabled=False,
        ssh_port_range_start=30000,
        ssh_port_range_end=31000,
        secret_key=SecretStr(Fernet.generate_key().decode()),
    )
    spec = WorkspaceSpec(
        workspace_id=WS, project="p", intent="i", image="img", root_path="", harnesses=list(harnesses)
    )
    await store.insert(
        workspace_id=WS, project="p", intent="i", image="img", root_path="", server_instance="test",
        status="unknown", container_id="", ssh_port=30001, spec_json=serialize_spec_extra(spec),
    )
    return WorkspaceRegistry(runtime=runtime, store=store, server_id="test", settings=settings), store


@pytest.mark.asyncio
async def test_reprovision_mounts_the_same_harness_state_dir(sqlite_path, tmp_path):
    runtime = _runtime()
    registry, _ = await _registry(sqlite_path, tmp_path, runtime)
    state = tmp_path / "data" / "harness" / WS

    await registry.ensure_running(WS)
    (state / "claude" / "projects").mkdir(parents=True)
    (state / "claude" / "projects" / "s.jsonl").write_text("{}")
    await registry.ensure_running(WS)

    for call in runtime.provision.call_args_list:
        mounts = call.args[0].bind_mounts
        assert (str(state), "/var/lib/warren/harness", "rw") in mounts
        assert sum(1 for m in mounts if m[1] == "/var/lib/warren/harness") == 1
    assert (state / "claude" / "projects" / "s.jsonl").exists()
    assert oct(state.stat().st_mode & 0o777) == "0o700"


@pytest.mark.asyncio
async def test_destroy_removes_the_harness_state(sqlite_path, tmp_path):
    runtime = _runtime()
    registry, store = await _registry(sqlite_path, tmp_path, runtime)
    await registry.ensure_running(WS)
    state = tmp_path / "data" / "harness" / WS
    assert state.is_dir()

    await registry.destroy(WS)

    assert not state.exists()
    assert (await store.get(WS)).status == "destroyed"


@pytest.mark.asyncio
async def test_no_mount_without_harnesses_or_on_ecs(sqlite_path, tmp_path):
    runtime = _runtime()
    registry, _ = await _registry(sqlite_path, tmp_path, runtime, harnesses=())
    await registry.ensure_running(WS)
    assert not any(m[1] == "/var/lib/warren/harness" for m in runtime.provision.call_args.args[0].bind_mounts)

    assert WorkspaceRegistry(
        runtime=runtime, store=registry.store, server_id="t", settings=SimpleNamespace(runtime_type="ecs", data_dir=tmp_path)
    )._harness_state_dir(WS) is None
    assert registry._harness_state_dir("../escape") is None
