"""Finding 9: podman workspaces can't reach each other, nor the host's loopback services.

Each workspace gets its own `isolate`d bridge and its SSH port is published on host
loopback only. Every negative check has a positive control showing the target really is
listening. Also covers the startup migration off the legacy shared bridge. Gated by
`requires_podman`.
"""

from __future__ import annotations

import asyncio
import os
import socket
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from warren.network.egress import read_container_egress_bytes
from warren.runtime.podman import PodmanRuntime
from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

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


async def _networks(runtime: PodmanRuntime, runtime_id: str) -> dict:
    container = await asyncio.to_thread(runtime._client.containers.get, runtime_id)
    return container.attrs["NetworkSettings"]["Networks"]


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _host_ip() -> str | None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        try:
            s.connect(("192.0.2.1", 9))  # no packet is sent for a UDP connect
            return s.getsockname()[0]
        except OSError:
            return None


def _http_get(url: str) -> str:
    with urllib.request.urlopen(url, timeout=5) as resp:  # noqa: S310 -- fixed loopback URL
        return resp.read().decode()


def _serve_on_loopback(body: bytes) -> tuple[ThreadingHTTPServer, int]:
    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            self.send_response(200)
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args) -> None:
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


async def _labelled_networks(runtime: PodmanRuntime, server_id: str) -> list[str]:
    return [
        n.name
        for n in await asyncio.to_thread(runtime._client.networks.list)
        if (n.attrs.get("labels") or {}).get("warren.server_instance") == server_id
    ]


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

        networks_b = await _networks(runtime, handle_b.runtime_id)
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
    assert await _labelled_networks(runtime, itest_server_id) == []


async def test_workspace_cannot_reach_published_ports_or_host_loopback(
    itest_server_id: str,
    itest_long_running_image: str,
) -> None:
    """B's published SSH port and a host service on 127.0.0.1 both answer from the host,
    and neither answers workspace A on any address that leads back to the host."""
    runtime = PodmanRuntime(socket_path=os.environ["PODMAN_SOCKET"], server_id=itest_server_id)
    spec_a = _spec(itest_server_id, "pa", itest_long_running_image)
    spec_b = _spec(itest_server_id, "pb", itest_long_running_image)
    ssh_port = _free_port()
    host_server, host_port = _serve_on_loopback(b"host-ok")
    handles = []
    try:
        handles.append(await runtime.provision(spec_a))
        handles.append(await runtime.provision(spec_b, ssh_port=ssh_port))
        handle_a, handle_b = handles

        code, out = await _exec(
            runtime,
            handle_b.runtime_id,
            "mkdir -p /tmp/www && echo published-ok > /tmp/www/index.html && httpd -p 22 -h /tmp/www",
        )
        assert code == 0, out

        assert "published-ok" in await asyncio.to_thread(_http_get, f"http://127.0.0.1:{ssh_port}/")
        assert "host-ok" in await asyncio.to_thread(_http_get, f"http://127.0.0.1:{host_port}/")

        net_a = next(iter((await _networks(runtime, handle_a.runtime_id)).values()))
        ip_b = next(iter((await _networks(runtime, handle_b.runtime_id)).values()))["IPAddress"]
        hosts = {net_a["Gateway"], "host.containers.internal", "10.0.2.2", "169.254.1.2", _host_ip()}
        targets = [f"{h}:{p}" for h in sorted(filter(None, hosts)) for p in (ssh_port, host_port)]
        targets.append(f"{ip_b}:22")

        for target in targets:
            code, out = await _exec(runtime, handle_a.runtime_id, f"wget -q -T 3 -O- http://{target}/")
            assert code != 0, f"workspace A reached {target}: {out!r}"
            assert "published-ok" not in out and "host-ok" not in out, target

        # Outbound internet still goes out through the workspace's own bridge. Any HTTP
        # response counts (example.com occasionally answers CI with a 503).
        for _ in range(3):
            code, out = await _exec(
                runtime, handle_a.runtime_id, "wget -q -T 10 -O /dev/null http://example.com/"
            )
            reached = code == 0 or "server returned error: HTTP/" in out
            if reached:
                break
        assert reached, f"workspace A has no outbound access: {out!r}"
    finally:
        host_server.shutdown()
        host_server.server_close()
        for handle in handles:
            await runtime.destroy(handle)
    assert await _labelled_networks(runtime, itest_server_id) == []


async def test_reconcile_migrates_legacy_shared_bridge_workspace(
    itest_server_id: str,
    itest_long_running_image: str,
) -> None:
    """A container provisioned the pre-Finding-9 way (shared, unlabelled bridge) is moved
    onto its own isolated network, keeps a readable egress counter, and the shared bridge
    is removed once nothing uses it."""
    shared = f"{itest_server_id}-shared"
    runtime = PodmanRuntime(
        socket_path=os.environ["PODMAN_SOCKET"],
        server_id=itest_server_id,
        egress_bridge_name=shared,
    )
    client = runtime._client
    ws_id = f"{itest_server_id}-legacy"
    container = None
    try:
        await asyncio.to_thread(client.networks.create, shared, driver="bridge")
        container = await asyncio.to_thread(
            client.containers.create,
            image=itest_long_running_image,
            labels={"warren.workspace_id": ws_id, "warren.server_instance": itest_server_id},
            networks={shared: {}},
            network_mode="bridge",
            init=True,
            detach=True,
        )
        await asyncio.to_thread(container.start)
        assert list(await _networks(runtime, container.id)) == [shared]

        await runtime.reconcile_networks(itest_server_id, {ws_id})

        target = f"{shared}-{ws_id}"
        networks = await _networks(runtime, container.id)
        assert list(networks) == [target]
        assert next(iter(networks.values()))["IPAddress"]
        assert not await asyncio.to_thread(client.networks.exists, shared)
        net = await asyncio.to_thread(client.networks.get, target)
        assert net.attrs["options"]["isolate"] == "true"

        first = await asyncio.to_thread(read_container_egress_bytes, container.id)
        await _exec(runtime, container.id, "wget -q -T 5 -O /dev/null http://example.com/ || true")
        assert await asyncio.to_thread(read_container_egress_bytes, container.id) >= first
    finally:
        if container is not None:
            await runtime.destroy(
                WorkspaceHandle(workspace_id=ws_id, runtime_id=container.id, root_path="")
            )
        if await asyncio.to_thread(client.networks.exists, shared):
            await asyncio.to_thread(client.networks.remove, shared, True)
