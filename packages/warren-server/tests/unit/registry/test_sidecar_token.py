"""Audit finding 12: every workspace's sidecar gets a per-workspace token the
server stores (encrypted) so it can authenticate its own sidecar calls."""

from __future__ import annotations

import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
from pydantic import SecretStr


def _spec(**kw):
    from warren_common.runtime.base import WorkspaceSpec

    return WorkspaceSpec(workspace_id="ws-1", project="p", intent="i", image="img", root_path="", **kw)


async def _registry(sqlite_path, secret_key="a" * 32):
    from warren.registry.registry import WorkspaceRegistry
    from warren.registry.store import WorkspaceStore
    from warren_common.runtime.base import WorkspaceHandle

    store = await WorkspaceStore.open(sqlite_path)
    runtime = AsyncMock()
    runtime.supports_ssh_access = False
    runtime.provision.return_value = WorkspaceHandle(workspace_id="ws-1", runtime_id="ctr-1", root_path="")
    settings = SimpleNamespace(
        runtime_type="podman", secret_key=SecretStr(secret_key),
        ssh_port_range_start=30000, ssh_port_range_end=30100,
    )
    registry = WorkspaceRegistry(runtime=runtime, store=store, server_id="test", settings=settings)
    return registry, store, runtime


@pytest.mark.asyncio
async def test_provision_and_reprovision_hand_the_sidecar_the_same_stored_token(sqlite_path):
    from warren.registry.registry import serialize_spec_extra

    registry, store, runtime = await _registry(sqlite_path)
    spec = _spec(secret_names=[], owner_id="u")
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="provisioning", spec_json=serialize_spec_extra(spec),
    )

    await registry._do_provision("ws-1", spec)
    token = runtime.provision.call_args.args[0].sidecar_token
    assert len(token) >= 32
    assert await registry.sidecar_token("ws-1") == token

    stored = await store.get_sidecar_token_enc("ws-1")
    assert stored and token.encode() not in stored
    row = await store.get("ws-1")
    assert token not in (row.spec_json or "")
    assert "sidecar_token" not in json.loads(row.spec_json)

    await store.update_status("ws-1", "unknown")
    await registry.ensure_running("ws-1")
    assert runtime.provision.call_args.args[0].sidecar_token == token


@pytest.mark.asyncio
async def test_each_workspace_gets_its_own_token(sqlite_path):
    registry, store, _ = await _registry(sqlite_path)
    for ws in ("ws-1", "ws-2"):
        await store.insert(
            workspace_id=ws, project="p", intent="i", image="img", root_path="",
            server_instance="test", status="provisioning",
        )
    assert await registry.sidecar_token("ws-1") != await registry.sidecar_token("ws-2")


@pytest.mark.asyncio
async def test_undecryptable_token_is_replaced(sqlite_path):
    registry, store, _ = await _registry(sqlite_path)
    await store.insert(
        workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
        server_instance="test", status="provisioning",
    )
    await store.set_sidecar_token_enc("ws-1", b"not-a-fernet-token")
    token = await registry.sidecar_token("ws-1")
    assert token and await registry.sidecar_token("ws-1") == token
