"""`kind: http` proxy mappings: the HTTP gateway (Host/Origin checks, one-time start
link, session cookie, strict parsing, passthrough) plus tcp-kind hardening.

No network beyond loopback, no AWS: the upstream is an in-process asyncio server.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import stat
import sys

import pytest
import pytest_asyncio

from warren_cli import dispatch, proxy, proxy_http

_WS = "abc12345-aaaa-bbbb-cccc-ddddeeeeffff"


# ---------------------------------------------------------------------------
# harness
# ---------------------------------------------------------------------------


class Upstream:
    """Tiny HTTP server: echoes what it received as JSON; /sse streams events;
    /ws answers 101 and echoes bytes; /chunked answers chunked."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.connections = 0
        self.gate = asyncio.Event()
        self.local_port = 0
        self.host = "127.0.0.1"
        self.server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        self.server = await asyncio.start_server(self._handle, "127.0.0.1", 0)
        self.local_port = self.server.sockets[0].getsockname()[1]

    async def _handle(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        self.connections += 1
        try:
            head = await r.readuntil(b"\r\n\r\n")
            lines = head.decode("latin-1").split("\r\n")
            method, target, _ = lines[0].split(" ")
            hdrs = {k.lower(): v for k, v in (ln.split(": ", 1) for ln in lines[1:] if ln)}
            body = b""
            if "content-length" in hdrs:
                body = await r.readexactly(int(hdrs["content-length"]))
            elif hdrs.get("transfer-encoding") == "chunked":
                while True:
                    size = int((await r.readuntil(b"\r\n"))[:-2], 16)
                    body += await r.readexactly(size + 2)
                    if size == 0:
                        break
                body = body.replace(b"\r\n", b"")
            self.requests.append({"method": method, "target": target, "headers": hdrs, "body": body.decode()})
            if target == "/sse":
                w.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nAccess-Control-Allow-Origin: *\r\n\r\n")
                w.write(b"data: one\n\n")
                await w.drain()
                await self.gate.wait()
                w.write(b"data: two\n\n")
            elif target == "/ws":
                w.write(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
                await w.drain()
                while data := await r.read(1024):
                    w.write(data.upper())
                    await w.drain()
            elif target == "/chunked":
                w.write(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Security-Policy: default-src 'self'\r\n\r\n")
                w.write(b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n")
            else:
                out = json.dumps(self.requests[-1]).encode()
                w.write(
                    b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\n"
                    + f"Content-Length: {len(out)}\r\n\r\n".encode()
                    + out
                )
            await w.drain()
        except (asyncio.IncompleteReadError, ConnectionError, OSError):
            pass
        finally:
            w.close()


class StaticForwarder:
    def __init__(self, port: int) -> None:
        self.port = port

    async def start(self, target, remote_port):
        return proxy._DirectSession("127.0.0.1", self.port)


class StaticResolver:
    def __init__(self, workspace_id: str = _WS) -> None:
        self.workspace_id = workspace_id

    async def resolve(self, mapping):
        return proxy.Target(workspace_id=self.workspace_id, kind="direct", host="127.0.0.1", host_port=1)


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class Rig:
    def __init__(self, up: Upstream, mp: proxy.MappingProxy, port: int, clock: Clock) -> None:
        self.up, self.mp, self.port, self.clock = up, mp, port, clock

    @property
    def gw(self) -> proxy_http.HttpGateway:
        assert self.mp.gateway is not None
        return self.mp.gateway

    async def raw(self, payload: bytes, *, eof: bool = True, timeout: float = 5) -> bytes:
        r, w = await asyncio.open_connection("127.0.0.1", self.port)
        w.write(payload)
        await w.drain()
        if eof:
            w.write_eof()
        try:
            return await asyncio.wait_for(r.read(), timeout)
        finally:
            w.close()

    def req(self, method="GET", path="/", host=None, headers=(), body=b"", cookie=None) -> bytes:
        hs = [("Host", host or f"127.0.0.1:{self.port}"), *headers]
        if cookie:
            hs.append(("Cookie", f"{self.gw.cookie_name}={cookie}"))
        if body:
            hs.append(("Content-Length", str(len(body))))
        head = f"{method} {path} HTTP/1.1\r\n" + "".join(f"{k}: {v}\r\n" for k, v in hs) + "\r\n"
        return head.encode() + body

    async def login(self) -> str:
        link = self.gw.start_link()
        path = link.split(f":{self.port}", 1)[1]
        out = await self.raw(self.req(path=path, headers=[("Connection", "close")]))
        m = re.search(rb"set-cookie: " + self.gw.cookie_name.encode() + rb"=([^;]+);", out, re.I)
        assert m, out
        return m.group(1).decode()


def status(out: bytes) -> int:
    return int(out.split(b" ", 2)[1])


def header(out: bytes, name: str) -> str | None:
    m = re.search(rb"(?im)^" + name.encode() + rb": (.*?)\r$", out.split(b"\r\n\r\n")[0] + b"\r")
    return m.group(1).decode() if m else None


@pytest_asyncio.fixture
async def rig():
    up = Upstream()
    await up.start()
    clock = Clock()
    port = dispatch._free_local_port()
    m = proxy.Mapping(server="s", workspace="abc12345", remote_port=80, local_port=port, kind="http")
    limits = proxy_http.GatewayLimits(max_connections=4, header_timeout=2, keepalive_timeout=2)
    mp = proxy.MappingProxy(
        m, StaticResolver(), StaticForwarder(up.local_port), proxy.ProxySettings(keepalive_seconds=0, http_limits=limits)
    )
    await mp.listen()
    assert mp.gateway is not None
    mp.gateway.auth.clock = clock
    yield Rig(up, mp, port, clock)
    up.gate.set()
    await mp.close()
    assert up.server is not None
    up.server.close()


# ---------------------------------------------------------------------------
# Host / session / origin
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_start_link_exchanges_once_for_a_cookie_and_redirects(rig):
    link = rig.gw.start_link()
    assert link.startswith(f"http://127.0.0.1:{rig.port}/__proxy/start?k=")
    path = link.split(f":{rig.port}", 1)[1]
    out = await rig.raw(rig.req(path=path))
    assert status(out) == 303 and header(out, "location") == "/"
    cookie = header(out, "set-cookie") or ""
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie and "Path=/" in cookie
    assert "Domain" not in cookie and "Secure" not in cookie
    assert header(out, "cache-control") == "no-store"
    assert header(out, "x-content-type-options") == "nosniff" and header(out, "referrer-policy") == "no-referrer"
    # The secret is spent: the same link now fails and sets nothing.
    again = await rig.raw(rig.req(path=path))
    assert status(again) == 403 and header(again, "set-cookie") is None
    assert rig.up.requests == []


@pytest.mark.asyncio
async def test_forged_wrong_and_expired_secrets_are_refused(rig):
    rig.gw.start_link()
    for path in ("/__proxy/start", "/__proxy/start?k=", "/__proxy/start?k=nope", "/__proxy/start?k=a&k=b"):
        assert status(await rig.raw(rig.req(path=path))) == 403
    link = rig.gw.start_link()
    rig.clock.now += rig.gw.limits.start_ttl_seconds + 1
    assert status(await rig.raw(rig.req(path=link.split(f":{rig.port}", 1)[1]))) == 403
    assert status(await rig.raw(rig.req(path="/__proxy/start?k=x", method="POST"))) == 405


@pytest.mark.asyncio
async def test_requests_need_a_valid_session_cookie(rig):
    assert status(await rig.raw(rig.req())) == 401
    assert status(await rig.raw(rig.req(cookie="forged"))) == 401
    assert status(await rig.raw(rig.req(headers=[("Cookie", "other=1")]))) == 401
    assert rig.up.requests == []
    sid = await rig.login()
    out = await rig.raw(rig.req(path="/hello", cookie=sid))
    assert status(out) == 200 and json.loads(out.split(b"\r\n\r\n", 1)[1])["target"] == "/hello"


@pytest.mark.asyncio
async def test_session_expires_when_idle_and_the_cookie_is_not_sent_upstream(rig):
    sid = await rig.login()
    rig.clock.now += rig.gw.limits.session_idle_seconds - 1
    out = await rig.raw(rig.req(cookie=sid, headers=[("Cookie", "app=1")]))
    assert status(out) == 200  # activity refreshes the session
    seen = rig.up.requests[-1]["headers"]["cookie"]
    assert seen == "app=1" and sid not in seen
    rig.clock.now += rig.gw.limits.session_idle_seconds + 1
    assert status(await rig.raw(rig.req(cookie=sid))) == 401


@pytest.mark.parametrize(
    "host",
    ["evil.example", "127.0.0.1.evil.example", "0x7f.1", "localhost.", "LOCALHOST", "127.0.0.1", "[::1]", "evil.example:{port}",
     "localhost:1", "127.0.0.1:{port}.evil.example", ""],
)  # fmt: skip
@pytest.mark.asyncio
async def test_host_header_rebinding_hosts_are_refused(rig, host):
    sid = await rig.login()
    host = host.replace("{port}", str(rig.port))
    out = await rig.raw(rig.req(host=host + "x" if host == "" else host, cookie=sid))
    assert status(out) == 421
    assert rig.up.requests == []


@pytest.mark.asyncio
async def test_exact_loopback_authorities_pass(rig):
    sid = await rig.login()
    for host in (f"127.0.0.1:{rig.port}", f"localhost:{rig.port}"):
        assert status(await rig.raw(rig.req(host=host, cookie=sid))) == 200
    assert rig.gw.authorities == {f"127.0.0.1:{rig.port}", f"localhost:{rig.port}"}
    assert proxy_http.allowed_authorities("::1", 5) == {"[::1]:5", "localhost:5"}


@pytest.mark.asyncio
async def test_cross_origin_state_changing_requests_and_upgrades_are_refused(rig):
    sid = await rig.login()
    own = f"http://127.0.0.1:{rig.port}"
    for method in ("POST", "PUT", "PATCH", "DELETE"):
        bad = [("Origin", "http://evil.example")], [("Origin", "null")], [("Sec-Fetch-Site", "cross-site")], [("Sec-Fetch-Site", "same-site")]
        for hs in bad:
            assert status(await rig.raw(rig.req(method, headers=hs, cookie=sid, body=b"x"))) == 403
    assert rig.up.requests == []
    ok = await rig.raw(rig.req("POST", headers=[("Origin", own), ("Sec-Fetch-Site", "same-origin")], cookie=sid, body=b"hi"))
    assert status(ok) == 200 and rig.up.requests[-1]["body"] == "hi"
    ws = [("Upgrade", "websocket"), ("Connection", "Upgrade"), ("Origin", "http://evil.example")]
    assert status(await rig.raw(rig.req(path="/ws", headers=ws, cookie=sid))) == 403
    assert not any(r["target"] == "/ws" for r in rig.up.requests)


@pytest.mark.asyncio
async def test_preflight_is_refused_and_no_cors_headers_are_emitted(rig):
    sid = await rig.login()
    pre = rig.req("OPTIONS", headers=[("Origin", "http://evil.example"), ("Access-Control-Request-Method", "POST")], cookie=sid)
    out = await rig.raw(pre)
    assert status(out) == 403 and b"access-control" not in out.lower()
    out = await rig.raw(rig.req(cookie=sid, headers=[("Origin", "http://evil.example")]))
    assert status(out) == 200 and b"access-control" not in out.lower()  # the upstream's own header is dropped
    assert header(out, "x-content-type-options") == "nosniff" and header(out, "referrer-policy") == "no-referrer"
    assert status(await rig.raw(rig.req("TRACE", cookie=sid))) == 405


@pytest.mark.asyncio
async def test_reserved_paths_are_not_forwarded(rig):
    sid = await rig.login()
    assert status(await rig.raw(rig.req(path="/__proxy/other", cookie=sid))) == 404
    assert rig.up.requests == []


# ---------------------------------------------------------------------------
# strict parsing and smuggling
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    "extra",
    [
        "Content-Length: 3\r\nTransfer-Encoding: chunked\r\n",
        "Content-Length: 3\r\nContent-Length: 3\r\n",
        "Content-Length: +3\r\n",
        "Content-Length: 3, 3\r\n",
        "Transfer-Encoding: gzip, chunked\r\n",
        "Transfer-Encoding : chunked\r\n",
        "Host: 127.0.0.1\r\n",  # duplicate Host
        "X-Fold: a\r\n  folded\r\n",  # obs-fold
        "X-Bad\r\n",
        "X-Nul: a\x00b\r\n",
        "Bad Name: x\r\n",
    ],
)  # fmt: skip
@pytest.mark.asyncio
async def test_ambiguous_or_malformed_heads_are_rejected(rig, extra):
    sid = await rig.login()
    raw = f"POST / HTTP/1.1\r\nHost: 127.0.0.1:{rig.port}\r\nCookie: {rig.gw.cookie_name}={sid}\r\n{extra}\r\nabc".encode()
    out = await rig.raw(raw)
    assert status(out) == 400
    assert rig.up.requests == []


@pytest.mark.parametrize(
    "line",
    [b"GET http://evil.example/ HTTP/1.1", b"GET /\x7f HTTP/1.1", b"GET / HTTP/2.0", b"GET  / HTTP/1.1", b"G@T / HTTP/1.1",
     b"CONNECT 127.0.0.1:80 HTTP/1.1", b"GET /\r HTTP/1.1"],
)  # fmt: skip
@pytest.mark.asyncio
async def test_bad_request_lines_are_rejected(rig, line):
    out = await rig.raw(line + f"\r\nHost: 127.0.0.1:{rig.port}\r\n\r\n".encode())
    assert status(out) in (400, 405) and rig.up.requests == []


@pytest.mark.asyncio
async def test_header_injection_through_the_target_is_impossible(rig):
    sid = await rig.login()
    out = await rig.raw(rig.req(path="/a%0d%0aX-Evil:%201", cookie=sid))
    assert status(out) == 200
    assert "x-evil" not in rig.up.requests[-1]["headers"]  # the escape stays an escape


@pytest.mark.asyncio
async def test_bare_lf_and_missing_host_are_rejected(rig):
    assert status(await rig.raw(b"GET / HTTP/1.1\nHost: x\n\n\r\n\r\n")) == 400
    assert status(await rig.raw(b"GET / HTTP/1.1\r\n\r\n")) == 400


@pytest.mark.asyncio
async def test_oversized_heads_and_bodies(rig):
    sid = await rig.login()
    assert status(await rig.raw(rig.req(headers=[("X-Big", "a" * 20000)], cookie=sid))) == 431
    try:  # far past the reader's limit: the peer may reset the connection instead of answering
        assert status(await rig.raw(rig.req(headers=[("X-Big", "a" * 200000)], cookie=sid))) == 431
    except ConnectionResetError:
        pass
    many = [(f"X-{i}", "1") for i in range(150)]
    assert status(await rig.raw(rig.req(headers=many, cookie=sid))) == 431
    big = rig.req("POST", cookie=sid).replace(b"\r\n\r\n", b"\r\nContent-Length: 999999999999\r\n\r\n")
    assert status(await rig.raw(big)) == 413
    assert rig.up.requests == []


@pytest.mark.asyncio
async def test_chunked_request_bodies_are_validated_and_forwarded(rig):
    sid = await rig.login()
    head = rig.req("POST", cookie=sid, headers=[("Transfer-Encoding", "chunked")])
    ok = await rig.raw(head + b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n")
    assert status(ok) == 200 and rig.up.requests[-1]["body"] == "abcde"
    for bad in (b"3;ext=1\r\nabc\r\n0\r\n\r\n", b"zz\r\n", b"3\r\nabcXX0\r\n\r\n", b"0\r\nTrailer: x\r\n\r\n"):
        assert status(await rig.raw(head + bad)) == 400


# ---------------------------------------------------------------------------
# passthrough, keep-alive, limits
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_keep_alive_reuses_the_client_connection(rig):
    sid = await rig.login()
    r, w = await asyncio.open_connection("127.0.0.1", rig.port)
    for i in range(3):
        w.write(rig.req(path=f"/n{i}", cookie=sid))
        await w.drain()
        head = await r.readuntil(b"\r\n\r\n")
        assert head.startswith(b"HTTP/1.1 200") and b"connection: keep-alive" in head.lower()
        n = int(re.search(rb"(?i)content-length: (\d+)", head).group(1))
        assert json.loads(await r.readexactly(n))["target"] == f"/n{i}"
    w.close()
    assert [q["target"] for q in rig.up.requests] == ["/n0", "/n1", "/n2"]


@pytest.mark.asyncio
async def test_upstream_sees_no_hop_by_hop_headers_and_gets_provider_headers(rig):
    provider = proxy_http.StaticUpstreamAuth(x_warren_user="alice")
    rig.gw.provider = provider
    sid = await rig.login()
    await rig.raw(rig.req(cookie=sid, headers=[("X-Warren-User", "mallory"), ("Keep-Alive", "5"), ("Connection", "keep-alive, X-Drop"), ("X-Drop", "1")]))
    seen = rig.up.requests[-1]["headers"]
    assert seen["x-warren-user"] == "alice" and "keep-alive" not in seen and "x-drop" not in seen
    assert seen["connection"] == "close" and provider.calls[-1].path == "/"


@pytest.mark.asyncio
async def test_noop_provider_adds_nothing(rig):
    assert list(proxy_http.NoUpstreamAuth().headers(None)) == []  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_sse_streams_before_the_response_ends(rig):
    sid = await rig.login()
    r, w = await asyncio.open_connection("127.0.0.1", rig.port)
    w.write(rig.req(path="/sse", cookie=sid))
    await w.drain()
    head = await r.readuntil(b"\r\n\r\n")
    assert b"text/event-stream" in head and b"access-control" not in head.lower()
    assert await asyncio.wait_for(r.readuntil(b"\n\n"), 2) == b"data: one\n\n"
    rig.up.gate.set()
    assert (await asyncio.wait_for(r.read(), 2)) == b"data: two\n\n"
    w.close()


@pytest.mark.asyncio
async def test_chunked_response_keeps_app_csp_and_stays_open(rig):
    sid = await rig.login()
    out = await rig.raw(rig.req(path="/chunked", cookie=sid))
    assert header(out, "content-security-policy") == "default-src 'self'"
    assert out.endswith(b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n")


@pytest.mark.asyncio
async def test_websocket_upgrade_passes_through_after_validation(rig):
    sid = await rig.login()
    own = f"http://127.0.0.1:{rig.port}"
    r, w = await asyncio.open_connection("127.0.0.1", rig.port)
    w.write(rig.req(path="/ws", cookie=sid, headers=[("Upgrade", "websocket"), ("Connection", "Upgrade"), ("Origin", own)]))
    await w.drain()
    head = await r.readuntil(b"\r\n\r\n")
    assert head.startswith(b"HTTP/1.1 101")
    w.write(b"hello")
    assert await asyncio.wait_for(r.readexactly(5), 2) == b"HELLO"
    w.close()
    assert "cookie" not in rig.up.requests[-1]["headers"]
    # Unsupported upgrades never reach the app, and neither do unauthenticated ones.
    assert status(await rig.raw(rig.req(cookie=sid, headers=[("Upgrade", "h2c"), ("Connection", "Upgrade")]))) == 400
    assert status(await rig.raw(rig.req(path="/ws", headers=[("Upgrade", "websocket"), ("Connection", "Upgrade")]))) == 401


@pytest.mark.asyncio
async def test_concurrent_connection_cap(rig):
    held = [await asyncio.open_connection("127.0.0.1", rig.port) for _ in range(4)]
    await asyncio.sleep(0.1)
    try:
        assert status(await rig.raw(rig.req(), timeout=3)) == 503
    except ConnectionResetError:  # refused before reading the request
        pass
    assert rig.gw.refused == 1
    for _, w in held:
        w.close()
    await asyncio.sleep(0.2)
    assert status(await rig.raw(rig.req())) == 401  # served again (and answered by the gateway)


@pytest.mark.asyncio
async def test_slow_head_times_out_and_tasks_stay_referenced(rig):
    r, w = await asyncio.open_connection("127.0.0.1", rig.port)
    w.write(b"GET / HTTP/1.1\r\nHost:")
    await w.drain()
    await asyncio.sleep(0.1)
    assert len(rig.mp._connections) == 1  # strong reference kept for the connection task
    assert await asyncio.wait_for(r.read(), 5) == b""
    w.close()


@pytest.mark.asyncio
async def test_upstream_down_gives_a_clean_error(rig):
    sid = await rig.login()
    assert rig.up.server is not None
    rig.up.server.close()
    await rig.up.server.wait_closed()
    assert status(await rig.raw(rig.req(cookie=sid))) in (502, 503)


@pytest.mark.asyncio
async def test_workspace_identity_change_halts_the_mapping(rig):
    sid = await rig.login()
    assert status(await rig.raw(rig.req(cookie=sid))) == 200
    rig.mp.resolver = StaticResolver("zzz-other")
    rig.mp.session = None
    out = await rig.raw(rig.req(cookie=sid))
    assert status(out) == 503 and b"workspace changed" in out
    assert rig.mp.halted
    assert status(await rig.raw(rig.req(cookie=sid))) == 503


# ---------------------------------------------------------------------------
# store: kind, permissions, names; tcp hardening
# ---------------------------------------------------------------------------


def test_kind_is_stored_and_old_files_load_as_tcp(tmp_path):
    path = tmp_path / "proxy.json"
    path.write_text(json.dumps({"mappings": [{"server": "s", "workspace": "ws1", "remote_port": 1, "local_port": 47100}]}))
    store = proxy.MappingStore(path)
    assert store.load()[0].kind == "tcp"
    m, _ = store.add("s", "ws1", 1, kind="http")
    assert m.kind == "http" and m.local_port == 47100  # same port, new kind
    assert json.loads(path.read_text())["mappings"][0]["kind"] == "http"
    assert store.add("s", "ws1", 1)[0].kind == "http"  # re-adding without --kind keeps it
    with pytest.raises(proxy.ProxyError, match="unknown mapping kind"):
        store.add("s", "ws1", 1, kind="ftp")


def test_tcp_rows_do_not_write_kind(tmp_path):
    store = proxy.MappingStore(tmp_path / "proxy.json")
    store.add("s", "ws1", 1, port_free=lambda p: True)
    assert "kind" not in json.loads(store.path.read_text())["mappings"][0]


def test_unknown_kind_or_bad_names_in_the_file_are_skipped(tmp_path):
    rows = [
        {"server": "s", "workspace": "ws1", "remote_port": 1, "local_port": 47100, "kind": "weird"},
        {"server": "s", "workspace": "../../etc", "remote_port": 1, "local_port": 47101},
        {"server": "s", "workspace": "ws1; rm -rf", "remote_port": 1, "local_port": 47102},
        {"server": "s", "workspace": "ws2", "remote_port": 1, "local_port": 47103, "name": "Bad Name"},
        {"server": "s", "workspace": "ok1", "remote_port": 1, "local_port": 47104},
    ]
    (tmp_path / "proxy.json").write_text(json.dumps({"mappings": rows}))
    assert [m.workspace for m in proxy.MappingStore(tmp_path / "proxy.json").load()] == ["ok1"]


@pytest.mark.parametrize("ws", ["", "a b", "a;b", "$(x)", "../x", "a/b", "-" * 80, "a\nb"])
def test_add_validates_names_strictly(tmp_path, ws):
    with pytest.raises(proxy.ProxyError):
        proxy.MappingStore(tmp_path / "p.json").add("s", ws, 1, port_free=lambda p: True)
    with pytest.raises(proxy.ProxyError):
        proxy.MappingStore(tmp_path / "p.json").add("s", "ws1", 1, name="Bad_Name", port_free=lambda p: True)


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes and symlinks")
def test_store_permissions_symlinks_and_atomic_writes(tmp_path):
    d = tmp_path / ".warren"
    store = proxy.MappingStore(d / "proxy.json")
    store.add("s", "ws1", 1, port_free=lambda p: True)
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(store.path).st_mode) == 0o600
    assert [p.name for p in d.iterdir()] == ["proxy.json"]  # no temp file left behind
    target = tmp_path / "elsewhere.json"
    target.write_text("keep")
    store.path.unlink()
    store.path.symlink_to(target)
    with pytest.raises(proxy.ProxyError, match="symlink"):
        store.add("s", "ws2", 2, port_free=lambda p: True)
    assert target.read_text() == "keep"


def test_explicit_local_port_held_by_another_process_is_refused(tmp_path):
    import socket

    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        s.listen()
        busy = s.getsockname()[1]
        with pytest.raises(proxy.ProxyError, match="in use by another process"):
            proxy.MappingStore(tmp_path / "p.json").add("s", "ws1", 1, local_port=busy)


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "192.168.1.5", "10.0.0.1", "example.com", "", "127.0.0.1.evil.example"])
def test_listeners_fail_closed_for_non_loopback_binds(host):
    with pytest.raises(proxy.ProxyError, match="loopback"):
        proxy.check_loopback(host)
    with pytest.raises(proxy.ProxyError):
        proxy.ProxyDaemon(None, None, None, proxy.ProxySettings(bind=host))  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_listen_refuses_wildcard_bind_and_accepts_loopback_forms():
    for kind in ("tcp", "http"):
        m = proxy.Mapping("s", "ws1", 1, dispatch._free_local_port(), kind=kind)
        mp = proxy.MappingProxy(m, StaticResolver(), StaticForwarder(1), proxy.ProxySettings(bind="0.0.0.0"))
        with pytest.raises(proxy.ProxyError):
            await mp.listen()
        assert mp._server is None
    assert proxy.check_loopback("localhost") == "127.0.0.1" and proxy.check_loopback("::1") == "::1"


@pytest.mark.asyncio
async def test_daemon_records_bind_failures_and_announces_http_links(tmp_path):
    import socket

    store = proxy.MappingStore(tmp_path / "proxy.json")
    free = {"port_free": lambda p: True}
    a, _ = store.add("s", "ws1", 1, kind="http", local_port=dispatch._free_local_port(), **free)
    b, _ = store.add("s", "ws2", 2, local_port=dispatch._free_local_port(), **free)
    with socket.socket() as squat:
        squat.bind(("127.0.0.1", b.local_port))
        squat.listen()
        links: list[tuple[proxy.Mapping, str]] = []
        d = proxy.ProxyDaemon(store, StaticResolver(), StaticForwarder(1), proxy.ProxySettings(), announce=lambda m, u: links.append((m, u)))
        await d.reconcile()
        try:
            assert set(d.failed) == {b} and set(d.proxies) == {a}
            assert [m for m, _ in links] == [a] and "/__proxy/start?k=" in links[0][1]
            d.reissue_links()
            assert len(links) == 2 and links[0][1] != links[1][1]
        finally:
            for p in d.proxies.values():
                await p.close()


def test_secrets_are_not_logged(tmp_path):
    from structlog.testing import capture_logs

    gw = proxy_http.HttpGateway(bind="127.0.0.1", port=1234)
    with capture_logs() as logs:
        link = gw.start_link()
    assert logs == [] and link.split("k=")[1] not in json.dumps(logs)


def test_declared_protocols_reads_the_api_shape():
    ws = {"ports": {"t3": {"port": 3773, "protocol": "http"}, "ssh": {"port": 2222}, "old": 1}}
    assert proxy.declared_protocols(ws) == {"t3": "http", "ssh": "tcp", "old": "tcp"}
    assert proxy.declared_protocols({}) == {}
