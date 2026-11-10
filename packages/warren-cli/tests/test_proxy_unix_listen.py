"""MappingProxy with listen=unix: relay for tcp and http kinds, peer-uid drop, cleanup."""

from __future__ import annotations

import asyncio
import os
import shutil
import socket
import stat
import tempfile
from pathlib import Path

import pytest
import pytest_asyncio

from warren_cli import proxy, proxy_http, proxy_unix

pytestmark = pytest.mark.skipif(not hasattr(socket, "AF_UNIX") or os.name == "nt", reason="unix sockets")

_WS = "abc12345"


class Upstream:
    """Echoes raw bytes upper-cased (tcp) or answers any HTTP request with 200 + the request line."""

    def __init__(self) -> None:
        self.connections = 0
        self.heads: list[bytes] = []
        self.port = 0

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.port = self.server.sockets[0].getsockname()[1]

    async def _handle(self, r, w) -> None:
        self.connections += 1
        try:
            first = await r.read(4096)
            if first.startswith((b"GET ", b"POST ")):
                self.heads.append(first)
                body = first.split(b"\r\n", 1)[0]
                w.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
            else:
                w.write(first.upper())
                while data := await r.read(4096):
                    w.write(data.upper())
                    await w.drain()
            await w.drain()
        except (ConnectionError, OSError):
            pass
        finally:
            w.close()

    async def stop(self) -> None:
        self.server.close()


class Resolver:
    async def resolve(self, mapping):
        return proxy.Target(workspace_id=_WS, kind="direct", host="127.0.0.1", host_port=1)


class Forwarder:
    def __init__(self, port: int) -> None:
        self.port = port

    async def start(self, target, remote_port):
        return proxy._DirectSession("127.0.0.1", self.port)


@pytest.fixture
def sock_path():
    d = Path(tempfile.mkdtemp(prefix="wl", dir="/tmp"))
    yield d / "p.sock"
    shutil.rmtree(d, ignore_errors=True)


async def _make(kind: str, path: Path):
    up = Upstream()
    await up.start()
    m = proxy.Mapping("s", _WS, 80, 0, kind=kind, listen="unix", socket_path=str(path))
    mp = proxy.MappingProxy(m, Resolver(), Forwarder(up.port), proxy.ProxySettings(keepalive_seconds=0))
    await mp.listen()
    return up, mp


@pytest_asyncio.fixture
async def tcp_rig(sock_path):
    up, mp = await _make("tcp", sock_path)
    yield up, mp
    await mp.close()
    await up.stop()


@pytest_asyncio.fixture
async def http_rig(sock_path):
    up, mp = await _make("http", sock_path)
    yield up, mp
    await mp.close()
    await up.stop()


@pytest.mark.asyncio
async def test_tcp_kind_relays_bytes_over_a_0600_socket(tcp_rig, sock_path):
    st = os.lstat(sock_path)
    assert stat.S_ISSOCK(st.st_mode) and stat.S_IMODE(st.st_mode) == 0o600
    r, w = await asyncio.open_unix_connection(str(sock_path))
    w.write(b"hello")
    await w.drain()
    assert await asyncio.wait_for(r.readexactly(5), 5) == b"HELLO"
    w.close()


@pytest.mark.asyncio
async def test_http_kind_needs_no_host_cookie_or_start_link(http_rig, sock_path):
    up, mp = http_rig
    assert mp.gateway is not None and mp.start_link() is None
    r, w = await asyncio.open_unix_connection(str(sock_path))
    w.write(b"GET /x HTTP/1.1\r\nHost: whatever.example\r\nConnection: close\r\n\r\n")
    await w.drain()
    out = await asyncio.wait_for(r.read(), 5)
    assert out.startswith(b"HTTP/1.1 200") and b"GET /x HTTP/1.1" in out
    w.close()


@pytest.mark.asyncio
async def test_http_kind_still_enforces_parser_and_method_limits(http_rig, sock_path):
    async def send(payload: bytes) -> bytes:
        r, w = await asyncio.open_unix_connection(str(sock_path))
        w.write(payload)
        await w.drain()
        try:
            return await asyncio.wait_for(r.read(), 5)
        finally:
            w.close()

    assert (await send(b"TRACE / HTTP/1.1\r\nHost: a\r\n\r\n")).startswith(b"HTTP/1.1 405")
    smuggle = b"POST / HTTP/1.1\r\nHost: a\r\nContent-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n"
    assert (await send(smuggle)).startswith(b"HTTP/1.1 400")
    # the start link does not exist in socket mode
    assert (await send(b"GET /__proxy/start?k=x HTTP/1.1\r\nHost: a\r\n\r\n")).startswith(b"HTTP/1.1 404")
    up, _ = http_rig
    assert up.connections == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["tcp", "http"])
async def test_connections_from_another_uid_are_dropped(kind, sock_path, monkeypatch):
    monkeypatch.setattr(proxy_unix, "peer_uid", lambda sock: os.getuid() + 1)
    up, mp = await _make(kind, sock_path)
    try:
        r, w = await asyncio.open_unix_connection(str(sock_path))
        w.write(b"GET / HTTP/1.1\r\nHost: a\r\n\r\n")
        try:
            await w.drain()
        except ConnectionError:
            pass
        try:
            assert await asyncio.wait_for(r.read(), 5) == b""
        except ConnectionResetError:
            pass  # Linux may report the server's close as a reset
        assert up.connections == 0 and mp.active == 0
        w.close()
    finally:
        await mp.close()
        await up.stop()


@pytest.mark.asyncio
async def test_close_unlinks_the_socket(sock_path):
    up, mp = await _make("tcp", sock_path)
    assert sock_path.exists()
    await mp.close()
    assert not sock_path.exists()
    await up.stop()


@pytest.mark.asyncio
async def test_close_leaves_a_replacement_file_alone(sock_path):
    up, mp = await _make("tcp", sock_path)
    sock_path.unlink()
    sock_path.write_text("not ours")
    await mp.close()
    assert sock_path.read_text() == "not ours"
    await up.stop()


@pytest.mark.asyncio
async def test_listen_refuses_a_live_socket(sock_path):
    up, mp = await _make("tcp", sock_path)
    try:
        other = proxy.MappingProxy(mp.mapping, Resolver(), Forwarder(up.port), proxy.ProxySettings(keepalive_seconds=0))
        with pytest.raises(OSError, match="in use"):
            await other.listen()
        assert sock_path.exists()  # the live one is untouched
    finally:
        await mp.close()
        await up.stop()


@pytest.mark.asyncio
async def test_default_socket_path_is_used_when_none_is_saved(monkeypatch):
    d = Path(tempfile.mkdtemp(prefix="wh", dir="/tmp"))
    monkeypatch.setenv("HOME", str(d))
    up = Upstream()
    await up.start()
    m = proxy.Mapping("s", _WS, 80, 0, name="web", listen="unix")
    mp = proxy.MappingProxy(m, Resolver(), Forwarder(up.port), proxy.ProxySettings(keepalive_seconds=0))
    try:
        await mp.listen()
        expected = d / ".warren" / "run" / f"s-{_WS}-web.sock"
        assert expected.exists() and stat.S_IMODE(os.lstat(d / ".warren" / "run").st_mode) == 0o700
    finally:
        await mp.close()
        await up.stop()
        shutil.rmtree(d, ignore_errors=True)
        assert not expected.exists()


@pytest.mark.asyncio
async def test_daemon_stop_removes_sockets(sock_path, tmp_path):
    store = proxy.MappingStore(tmp_path / "proxy.json")
    store.save([proxy.Mapping("s", _WS, 80, 0, listen="unix", socket_path=str(sock_path))])
    up = Upstream()
    await up.start()
    daemon = proxy.ProxyDaemon(store, Resolver(), Forwarder(up.port), proxy.ProxySettings(keepalive_seconds=0))
    stop = asyncio.Event()
    task = asyncio.ensure_future(daemon.run(stop, started=lambda: stop.set()))
    await asyncio.wait_for(task, 10)  # stop (what SIGTERM sets) -> run() finally -> close()
    assert not sock_path.exists()
    await up.stop()
