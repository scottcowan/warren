"""Finding 9: one podman workspace can't reach another's ports (east-west isolation).

Each workspace gets its own `isolate`d bridge; B serves HTTP on its bridge IP, which B
itself can fetch (positive control) and A can't. Gated by `requires_podman`.
"""

from __future__ import annotations

import asyncio
import os

import pytest

from warren.runtime.podman import PodmanRuntime
from warren_common.runtime.base import WorkspaceSpec

pytestmark = pytest.mark.requires_podman

_PORT = 8080


def _spec(server_id: str, suffix: str, image: str) -> WorkspaceSpec:
    return WorkspaceSpec(
        workspace_id=f"{server_id}-{suffix}",
        project="p",
        intent="dev",
        image=image,
        root_path="",
    )


async def _exec(runtime: PodmanRuntime, runtime_id: str, script: str) -> tuple[int, str]:
    container = await asyncio.to_thread(runtime._client.containers.get, runtime_id)
    code, out = await asyncio.to_thread(container.exec_run, ["sh", "-c", script])
    return code, out.decode(errors="replace") if isinstance(out, bytes) else str(out)


async def test_workspace_cannot_reach_another_workspace(
    itest_server_id: str,
    itest_long_running_image: str,
) -> None:
    runtime = PodmanRuntime(socket_path=os.environ["PODMAN_SOCKET"], server_id=itest_server_id)
    spec_a = _spec(itest_server_id, "a", itest_long_running_image)
    spec_b = _spec(itest_server_id, "b", itest_long_running_image)
    handles = []
    try:
        handles.append(await runtime.provision(spec_a))
        handles.append(await runtime.provision(spec_b))
        handle_a, handle_b = handles

        container_b = await asyncio.to_thread(runtime._client.containers.get, handle_b.runtime_id)
        networks_b = container_b.attrs["NetworkSettings"]["Networks"]
        assert list(networks_b) == [f"warren-egress-{spec_b.workspace_id}"]
        ip_b = next(iter(networks_b.values()))["IPAddress"]
        assert ip_b

        code, out = await _exec(
            runtime,
            handle_b.runtime_id,
            f"mkdir -p /tmp/www && echo isolated-ok > /tmp/www/index.html && httpd -p {_PORT} -h /tmp/www",
        )
        assert code == 0, out
        fetch = f"wget -q -T 3 -O- http://{ip_b}:{_PORT}/"

        code, out = await _exec(runtime, handle_b.runtime_id, fetch)
        assert code == 0 and "isolated-ok" in out, out

        code, out = await _exec(runtime, handle_a.runtime_id, fetch)
        assert code != 0, f"workspace A reached workspace B at {ip_b}: {out!r}"
        assert "isolated-ok" not in out
    finally:
        for handle in handles:
            await runtime.destroy(handle)
    remaining = [
        n.name
        for n in await asyncio.to_thread(runtime._client.networks.list)
        if (n.attrs.get("labels") or {}).get("warren.server_instance") == itest_server_id
    ]
    assert remaining == []
