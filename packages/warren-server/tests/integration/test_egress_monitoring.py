"""Real-socket integration coverage for LIFE-02 egress monitoring (Plan 04-02).

Proves the same properties `scripts/verify_phase4_host_support.py` checks on a bare
node2 host, but through the real code path: `PodmanRuntime.provision()` attaches the
container to its own per-workspace `warren-egress-<id>` bridge, and
`warren.network.egress.read_container_egress_bytes` reads its cumulative tx_bytes
counter via host-side veth sysfs.

Gated by the `requires_podman` marker: skipped (not errored) when `PODMAN_SOCKET` is
unset, per `tests/conftest.py::pytest_collection_modifyitems`.

Per D-05: this test never asserts egress is blocked or restricted — only that the
byte counter is readable and non-decreasing. Traffic flowing freely through the
shared bridge is the intended, expected behavior this phase ships.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from warren.network.egress import read_container_egress_bytes
from warren.runtime.podman import PodmanRuntime
from warren_common.runtime.base import WorkspaceSpec

pytestmark = pytest.mark.requires_podman


async def test_provisioned_container_egress_bytes_readable_and_non_decreasing(
    itest_server_id: str,
    itest_long_running_image: str,
) -> None:
    socket_path = os.environ["PODMAN_SOCKET"]
    runtime = PodmanRuntime(socket_path=socket_path, server_id=itest_server_id)

    spec = WorkspaceSpec(
        workspace_id=f"{itest_server_id}-egress",
        project="p",
        intent="dev",
        image=itest_long_running_image,
        root_path="/tmp/egress-itest",
    )

    handle = await runtime.provision(spec)
    try:
        # (c) the container is attached to its own per-workspace bridge only.
        container = await asyncio.to_thread(
            runtime._client.containers.get, handle.runtime_id
        )
        networks = (container.attrs.get("NetworkSettings") or {}).get("Networks") or {}
        assert list(networks) == [f"warren-egress-{spec.workspace_id}"]

        # (a) a first read returns an int without raising.
        first = read_container_egress_bytes(handle.runtime_id)
        assert isinstance(first, int)

        # (b) a second read after generating traffic is non-decreasing. Do not
        # assert a strict increase — the long-running busybox itest image may
        # have no network tooling (wget/ping) available to generate traffic.
        await asyncio.to_thread(
            container.exec_run,
            ["sh", "-c", "wget -q -O /dev/null http://example.com || true"],
        )
        second = read_container_egress_bytes(handle.runtime_id)
        assert second >= first
    finally:
        await runtime.destroy(handle)
