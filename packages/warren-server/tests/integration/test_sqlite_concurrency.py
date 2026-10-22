"""Pitfall #12 validation: 50 concurrent update_status calls must not deadlock."""

from __future__ import annotations

import asyncio

import pytest

from warren.registry.store import WorkspaceStore


@pytest.mark.asyncio
async def test_50_concurrent_writes_no_lock(sqlite_path: str):
    store = await WorkspaceStore.open(sqlite_path)
    await store.insert(
        workspace_id="ws-hot",
        project="p",
        intent="i",
        image="img",
        root_path="/tmp/ws-hot",
        server_instance="s1",
        status="provisioning",
    )

    statuses = ["running", "stopping", "unknown", "provisioning"] * 13
    statuses = statuses[:50]

    await asyncio.gather(*(store.update_status("ws-hot", s) for s in statuses))

    row = await store.get("ws-hot")
    assert row.status in {"running", "stopping", "unknown", "provisioning"}
