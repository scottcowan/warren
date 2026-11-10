"""HTTP-aware gateway for ``kind: http`` proxy mappings (see docs/proxy.md).

A ``tcp`` mapping is a byte relay that trusts whoever can reach the loopback port.
An ``http`` mapping puts this gateway in front of the upstream instead, so that a
web UI served through the proxy is not reachable by arbitrary local processes or by
web pages (DNS rebinding, cross-site requests to localhost):

* strict request parsing (malformed, ambiguous or oversized requests are refused,
  never forwarded: no request smuggling through this hop);
* ``Host`` must be one of the exact loopback authorities the mapping listens on;
* every request but the one-time exchange needs a session cookie that the operator
  obtained by opening the link ``warren proxy run`` printed to their terminal;
* state-changing requests and WebSocket upgrades must be same-origin; CORS is never
  emitted and preflights are refused;
* an ``UpstreamAuthProvider`` hook may add headers to upstream requests (the future
  identity-injection point; the default adds nothing).

Stdlib asyncio only. One upstream connection per request (``Connection: close``
upstream); the client side supports keep-alive, streamed bodies, SSE and WebSocket
passthrough.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import re
import secrets
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable, Iterable, Protocol
from urllib.parse import parse_qs, quote

import structlog

log = structlog.get_logger(__name__)

START_PATH = "/__proxy/start"
RESERVED_PREFIX = "/__proxy"
METHODS = frozenset({"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"})
SAFE_METHODS = frozenset({"GET", "HEAD"})
_HOP_BY_HOP = frozenset(
    {
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "proxy-connection",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
        "content-length",
        "expect",
    }
)
_TOKEN_RE = re.compile(rb"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")
_TARGET_BAD_RE = re.compile(rb"[\x00-\x20\x7f-\xff]")
_VALUE_BAD_RE = re.compile(rb"[\x00-\x08\x0a-\x1f\x7f]")
_CL_RE = re.compile(rb"^[0-9]{1,15}$")
_CHUNK_RE = re.compile(rb"^[0-9a-fA-F]{1,15}$")
_STATUS_RE = re.compile(rb"^HTTP/1\.[01] ([0-9]{3})(?: ([^\x00-\x08\x0a-\x1f\x7f]*))?$")
_HEADER_NAME_RE = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


class HttpReject(Exception):
    """A request (or upstream response) the gateway will not pass on."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


_REASONS = {
    200: "OK", 303: "See Other", 400: "Bad Request", 401: "Unauthorized", 403: "Forbidden",
    404: "Not Found", 405: "Method Not Allowed", 413: "Content Too Large", 421: "Misdirected Request",
    431: "Request Header Fields Too Large", 501: "Not Implemented", 502: "Bad Gateway",
    503: "Service Unavailable", 504: "Gateway Timeout",
}  # fmt: skip


# ---------------------------------------------------------------------------
# configuration and hooks
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class GatewayLimits:
    max_head_bytes: int = 16 * 1024
    max_headers: int = 100
    max_request_body: int = 64 * 1024 * 1024
    max_response_head_bytes: int = 64 * 1024
    max_response_body: int = 1024 * 1024 * 1024  # Content-Length-framed responses only; streams are unbounded
    max_connections: int = 64
    header_timeout: float = 15.0
    keepalive_timeout: float = 30.0
    connect_timeout: float = 15.0
    body_timeout: float = 60.0  # per read of a request body
    response_timeout: float = 120.0  # wait for the upstream's response head
    start_ttl_seconds: float = 120.0
    session_idle_seconds: float = 30 * 60.0
    max_sessions: int = 16


@dataclass(frozen=True)
class Request:
    method: str
    target: str
    path: str
    query: str
    version: str
    headers: tuple[tuple[str, str], ...]  # (lowercase name, value)
    body: str  # "none", "length" or "chunked"
    length: int = 0

    def header(self, name: str) -> str | None:
        for k, v in self.headers:
            if k == name:
                return v
        return None

    def header_all(self, name: str) -> list[str]:
        return [v for k, v in self.headers if k == name]

    @property
    def connection_tokens(self) -> set[str]:
        return {t for v in self.header_all("connection") for t in _tokens(v)}

    @property
    def keep_alive(self) -> bool:
        return self.version == "HTTP/1.1" and "close" not in self.connection_tokens


class UpstreamAuthProvider(Protocol):
    """Extension point: headers to add to a request on its way upstream.

    Called after the request passed every gateway check. Returned headers replace any
    same-named header the client sent (so a client cannot spoof them). The default
    adds nothing; identity injection for the control plane is deliberately not
    implemented here."""

    def headers(self, request: Request) -> Iterable[tuple[str, str]]: ...


class NoUpstreamAuth:
    def headers(self, request: Request) -> Iterable[tuple[str, str]]:
        return ()


class StaticUpstreamAuth:
    """Adds fixed headers; a test double for the provider hook."""

    def __init__(self, **headers: str) -> None:
        self._headers = [(k.replace("_", "-"), v) for k, v in headers.items()]
        self.calls: list[Request] = []

    def headers(self, request: Request) -> Iterable[tuple[str, str]]:
        self.calls.append(request)
        return list(self._headers)


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------


def _tokens(value: str) -> list[str]:
    return [t.strip().lower() for t in value.split(",") if t.strip()]


def _parse_header_lines(lines: list[bytes], max_headers: int) -> list[tuple[str, str]]:
    if len(lines) > max_headers:
        raise HttpReject(431, "too many header fields")
    out: list[tuple[str, str]] = []
    for line in lines:
        if not line:
            raise HttpReject(400, "empty header line")
        if line[0] in b" \t":
            raise HttpReject(400, "obsolete line folding is not accepted")
        name, sep, value = line.partition(b":")
        if not sep or not _TOKEN_RE.match(name):
            raise HttpReject(400, "malformed header field")
        value = value.strip(b" \t")
        if _VALUE_BAD_RE.search(value):
            raise HttpReject(400, "control character in header value")
        out.append((name.decode("ascii").lower(), value.decode("latin-1")))
    return out


def _split_lines(raw: bytes) -> list[bytes]:
    if not raw.endswith(b"\r\n\r\n"):
        raise HttpReject(400, "malformed message head")
    lines = raw[:-4].split(b"\r\n")
    if any(b"\n" in ln or b"\r" in ln or b"\x00" in ln for ln in lines):
        raise HttpReject(400, "bare CR, LF or NUL in message head")
    return lines


def parse_request_head(raw: bytes, *, max_headers: int = 100) -> Request:
    """Strictly parse a request head (through the blank line)."""
    lines = _split_lines(raw)
    parts = lines[0].split(b" ")
    if len(parts) != 3:
        raise HttpReject(400, "malformed request line")
    method_b, target_b, version_b = parts
    if not _TOKEN_RE.match(method_b):
        raise HttpReject(400, "malformed method")
    if version_b not in (b"HTTP/1.1", b"HTTP/1.0"):
        raise HttpReject(400, "unsupported HTTP version")
    if not target_b.startswith(b"/") or _TARGET_BAD_RE.search(target_b):
        raise HttpReject(400, "request target must be an origin-form path")
    method, target, version = method_b.decode(), target_b.decode("ascii"), version_b.decode()
    headers = _parse_header_lines(lines[1:], max_headers)
    names = [k for k, _ in headers]
    if names.count("host") != 1:
        raise HttpReject(400, "exactly one Host header is required")
    cls = [v for k, v in headers if k == "content-length"]
    tes = [v for k, v in headers if k == "transfer-encoding"]
    if cls and tes:
        raise HttpReject(400, "Content-Length with Transfer-Encoding is refused")
    body, length = "none", 0
    if tes:
        if len(tes) != 1 or tes[0].strip().lower() != "chunked" or version != "HTTP/1.1":
            raise HttpReject(400, "only a single 'Transfer-Encoding: chunked' is supported")
        body = "chunked"
    elif cls:
        if len(cls) != 1 or not _CL_RE.match(cls[0].encode()):
            raise HttpReject(400, "invalid Content-Length")
        body, length = "length", int(cls[0])
    path, _, query = target.partition("?")
    return Request(method, target, path, query, version, tuple(headers), body, length)


@dataclass(frozen=True)
class ResponseHead:
    status: int
    reason: str
    headers: tuple[tuple[str, str], ...]


def parse_response_head(raw: bytes, *, max_headers: int = 200) -> ResponseHead:
    try:
        lines = _split_lines(raw)
        m = _STATUS_RE.match(lines[0])
        if not m:
            raise HttpReject(502, "malformed upstream status line")
        headers = _parse_header_lines(lines[1:], max_headers)
    except HttpReject as exc:
        raise HttpReject(502, f"bad upstream response: {exc.message}") from exc
    reason = (m.group(2) or b"").decode("latin-1")
    return ResponseHead(int(m.group(1)), reason, tuple(headers))


# ---------------------------------------------------------------------------
# sessions
# ---------------------------------------------------------------------------


class SessionAuth:
    """The one-time start secret and the server-side session table."""

    def __init__(self, limits: GatewayLimits, clock: Callable[[], float] = time.monotonic) -> None:
        self.limits = limits
        self.clock = clock
        self._secret: str | None = None
        self._secret_expires = 0.0
        self._sessions: dict[str, float] = {}  # session id -> last seen

    def mint_secret(self) -> str:
        self._secret = secrets.token_urlsafe(32)
        self._secret_expires = self.clock() + self.limits.start_ttl_seconds
        return self._secret

    def exchange(self, candidate: str) -> str | None:
        """A new session id for the right, unexpired, unused secret (which is then
        spent), else None."""
        secret = self._secret
        if secret is None:
            return None
        ok = hmac.compare_digest(candidate.encode(), secret.encode())
        if not ok or self.clock() > self._secret_expires:
            if self.clock() > self._secret_expires:
                self._secret = None
            return None
        self._secret = None
        self._prune()
        if len(self._sessions) >= self.limits.max_sessions:
            oldest = min(self._sessions, key=self._sessions.__getitem__)
            del self._sessions[oldest]
        sid = secrets.token_urlsafe(32)
        self._sessions[sid] = self.clock()
        return sid

    def _prune(self) -> None:
        now = self.clock()
        for sid in [s for s, seen in self._sessions.items() if now - seen > self.limits.session_idle_seconds]:
            del self._sessions[sid]

    def valid(self, sid: str | None) -> bool:
        if not sid:
            return False
        self._prune()
        match = None
        for known in self._sessions:  # compare against every session: no early exit on a prefix
            if hmac.compare_digest(sid.encode(), known.encode()):
                match = known
        if match is None:
            return False
        self._sessions[match] = self.clock()
        return True


def allowed_authorities(bind: str, port: int) -> frozenset[str]:
    host = f"[{bind}]" if ":" in bind else bind
    return frozenset({f"{host}:{port}", f"localhost:{port}"})


Connect = Callable[[], Awaitable[tuple[asyncio.StreamReader, asyncio.StreamWriter]]]


# ---------------------------------------------------------------------------
# the gateway
# ---------------------------------------------------------------------------


class HttpGateway:
    def __init__(
        self,
        *,
        bind: str,
        port: int,
        provider: UpstreamAuthProvider | None = None,
        limits: GatewayLimits | None = None,
        clock: Callable[[], float] = time.monotonic,
        trusted_peer: bool = False,
    ) -> None:
        # trusted_peer: the listener is a 0600 unix socket whose peer uid the caller
        # has already checked, so file permissions are the authentication: no Host/Origin
        # check (there is no browser origin), no session cookie, no start link. The
        # strict parser, method/upgrade rules, body limits and connection caps all stay.
        self.trusted_peer = trusted_peer
        self.bind = bind
        self.port = port
        self.limits = limits or GatewayLimits()
        self.provider = provider or NoUpstreamAuth()
        self.auth = SessionAuth(self.limits, clock)
        self.authorities = allowed_authorities(bind, port)
        self.origins = frozenset(f"http://{a}" for a in self.authorities)
        self.cookie_name = f"warren_proxy_{port}"  # cookies are shared across ports of a host
        self.connections = 0
        self.refused = 0

    def start_link(self) -> str:
        """Mint a fresh one-time link (any earlier unused one stops working)."""
        host = f"[{self.bind}]" if ":" in self.bind else self.bind
        return f"http://{host}:{self.port}{START_PATH}?k={quote(self.auth.mint_secret(), safe='')}"

    # -- connection loop ----------------------------------------------------

    async def serve(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, connect: Connect) -> None:
        if self.connections >= self.limits.max_connections:
            self.refused += 1
            await self._respond(writer, 503, "too many connections")
            await _close(writer)
            return
        self.connections += 1
        try:
            first = True
            while True:
                try:
                    req = await self._read_request(reader, first)
                except _ClientGone:
                    break
                except HttpReject as exc:
                    await self._respond(writer, exc.status, exc.message)
                    break
                first = False
                if not await self._dispatch(req, reader, writer, connect):
                    break
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            pass
        except Exception as exc:  # never let one connection kill the listener
            log.error("proxy_http_failed", error=repr(exc))
        finally:
            self.connections -= 1
            await _close(writer)

    async def _read_request(self, reader: asyncio.StreamReader, first: bool) -> Request:
        timeout = self.limits.header_timeout if first else self.limits.keepalive_timeout
        try:
            raw = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout)
        except asyncio.IncompleteReadError as exc:
            if not exc.partial:
                raise _ClientGone from exc
            raise HttpReject(400, "incomplete request head") from exc
        except asyncio.LimitOverrunError as exc:
            raise HttpReject(431, "request head too large") from exc
        except asyncio.TimeoutError as exc:
            raise _ClientGone from exc
        if len(raw) > self.limits.max_head_bytes:
            raise HttpReject(431, "request head too large")
        return parse_request_head(raw, max_headers=self.limits.max_headers)

    # -- request handling ---------------------------------------------------

    async def _dispatch(
        self, req: Request, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, connect: Connect
    ) -> bool:
        """Handle one request; True to keep the client connection open."""
        host = req.header("host")
        if not self.trusted_peer and host not in self.authorities:
            await self._respond(writer, 421, "unexpected Host")
            return False
        if req.method == "OPTIONS":
            await self._respond(writer, 403, "preflight requests are refused")
            return False
        if req.method not in METHODS:
            await self._respond(writer, 405, "method not allowed")
            return False
        if req.path == START_PATH and not self.trusted_peer:
            return await self._exchange(req, writer)
        if req.path == RESERVED_PREFIX or req.path.startswith(RESERVED_PREFIX + "/"):
            await self._respond(writer, 404, "not found")
            return False
        if not self.trusted_peer and not self.auth.valid(self._cookie(req)):
            await self._respond(writer, 401, "no valid session: open the link `warren proxy run` printed")
            return False
        upgrade = req.header("upgrade")
        if upgrade is not None:
            if (
                upgrade.strip().lower() != "websocket"
                or "upgrade" not in req.connection_tokens
                or req.method != "GET"
                or req.body != "none"
            ):
                await self._respond(writer, 400, "unsupported upgrade")
                return False
        elif "upgrade" in req.connection_tokens:
            await self._respond(writer, 400, "Connection: upgrade without Upgrade")
            return False
        if not self.trusted_peer and not self._same_origin_ok(req, upgrade is not None):
            await self._respond(writer, 403, "cross-origin request refused")
            return False
        if req.body == "length" and req.length > self.limits.max_request_body:
            await self._respond(writer, 413, "request body too large")
            return False
        return await self._forward(req, reader, writer, connect, upgrade is not None)

    def _cookie(self, req: Request) -> str | None:
        for line in req.header_all("cookie"):
            for part in line.split(";"):
                name, _, value = part.strip().partition("=")
                if name == self.cookie_name:
                    return value
        return None

    def _same_origin_ok(self, req: Request, upgrade: bool) -> bool:
        if req.method in SAFE_METHODS and not upgrade:
            return True
        origin = req.header("origin")
        if origin is not None and origin not in self.origins:
            return False  # includes "null" and every foreign origin
        site = req.header("sec-fetch-site")
        if site is not None and site.strip().lower() not in ("same-origin", "none"):
            return False
        return True

    async def _exchange(self, req: Request, writer: asyncio.StreamWriter) -> bool:
        if req.method != "GET":
            await self._respond(writer, 405, "method not allowed")
            return False
        keys = parse_qs(req.query).get("k", [])
        sid = self.auth.exchange(keys[0]) if len(keys) == 1 else None
        if sid is None:
            await self._respond(writer, 403, "link invalid, used or expired: run `warren proxy run` for a new one")
            return False
        # No Secure attribute: this is plain http on loopback, where Secure cookies are not
        # reliably accepted. No Domain, so it is host-only; SameSite=Strict keeps it off cross-site requests.
        cookie = f"{self.cookie_name}={sid}; HttpOnly; SameSite=Strict; Path=/"
        await self._respond(writer, 303, "", extra=[("Location", "/"), ("Set-Cookie", cookie)])
        return req.keep_alive

    async def _forward(
        self,
        req: Request,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        connect: Connect,
        upgrade: bool,
    ) -> bool:
        lim = self.limits
        try:
            up_r, up_w = await asyncio.wait_for(connect(), lim.connect_timeout)
        except asyncio.TimeoutError:
            await self._respond(writer, 504, "upstream connect timed out")
            return False
        except Exception as exc:
            from .proxy import ProxyError  # noqa: PLC0415

            await self._respond(writer, 503 if isinstance(exc, ProxyError) else 502, str(exc) if isinstance(exc, ProxyError) else "upstream unavailable")
            return False
        try:
            up_w.write(self._upstream_head(req, upgrade))
            await up_w.drain()
            try:
                if req.body == "length":
                    await _copy_length(reader, up_w, req.length, lim.body_timeout)
                elif req.body == "chunked":
                    await _copy_chunked(reader, up_w, max_total=lim.max_request_body, timeout=lim.body_timeout)
            except HttpReject as exc:
                await self._respond(writer, exc.status, exc.message)
                return False
            try:
                head = await self._read_response_head(up_r)
            except HttpReject as exc:
                await self._respond(writer, exc.status, exc.message)
                return False
            except asyncio.TimeoutError:
                await self._respond(writer, 504, "upstream response timed out")
                return False
            if upgrade and head.status == 101:
                return await self._pass_upgrade(req, head, reader, writer, up_r, up_w)
            return await self._pass_response(req, head, writer, up_r)
        except (OSError, asyncio.IncompleteReadError):
            return False
        finally:
            if not upgrade:
                await _close(up_w)

    def _upstream_head(self, req: Request, upgrade: bool) -> bytes:
        drop = set(_HOP_BY_HOP) | {t for t in req.connection_tokens}
        extra = [(k, v) for k, v in self.provider.headers(req)]
        for k, v in extra:
            if not _HEADER_NAME_RE.match(k) or re.search(r"[\x00-\x08\x0a-\x1f\x7f]", v):
                raise ValueError("upstream auth provider returned an invalid header")
        replaced = {k.lower() for k, _ in extra}
        lines = [f"{req.method} {req.target} HTTP/1.1"]
        cookies: list[str] = []
        for k, v in req.headers:
            if k in drop or k in replaced:
                continue
            if k == "cookie":  # our session cookie never reaches the app
                kept = [p.strip() for p in v.split(";") if p.strip().partition("=")[0] != self.cookie_name]
                if kept:
                    cookies.append("; ".join(kept))
                continue
            lines.append(f"{k}: {v}")
        if cookies:
            lines.append("cookie: " + "; ".join(cookies))
        lines += [f"{k}: {v}" for k, v in extra]
        if upgrade:
            lines += ["connection: Upgrade", "upgrade: websocket"]
        else:
            lines.append("connection: close")
        if req.body == "length":
            lines.append(f"content-length: {req.length}")
        elif req.body == "chunked":
            lines.append("transfer-encoding: chunked")
        return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")

    async def _read_response_head(self, up_r: asyncio.StreamReader) -> ResponseHead:
        while True:
            try:
                raw = await asyncio.wait_for(up_r.readuntil(b"\r\n\r\n"), self.limits.response_timeout)
            except asyncio.IncompleteReadError as exc:
                raise HttpReject(502, "upstream closed without a response") from exc
            except asyncio.LimitOverrunError as exc:
                raise HttpReject(502, "upstream response head too large") from exc
            if len(raw) > self.limits.max_response_head_bytes:
                raise HttpReject(502, "upstream response head too large")
            head = parse_response_head(raw)
            if 100 <= head.status < 200 and head.status != 101:
                continue  # interim response: the client gets the final one (we send the body unprompted)
            return head

    def _client_head(self, head: ResponseHead, *, connection: str, framing: list[tuple[str, str]]) -> bytes:
        lines = [f"HTTP/1.1 {head.status} {head.reason}".rstrip()]
        names = set()
        for k, v in head.headers:
            if k in _HOP_BY_HOP or k.startswith("access-control-"):
                continue
            names.add(k)
            lines.append(f"{k}: {v}")
        lines += [f"{k}: {v}" for k, v in framing]
        if "x-content-type-options" not in names:
            lines.append("x-content-type-options: nosniff")
        if "referrer-policy" not in names:
            lines.append("referrer-policy: no-referrer")
        lines.append(f"connection: {connection}")
        return ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1")

    async def _pass_upgrade(
        self,
        req: Request,
        head: ResponseHead,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        up_r: asyncio.StreamReader,
        up_w: asyncio.StreamWriter,
    ) -> bool:
        from .proxy import relay  # noqa: PLC0415

        hdrs = [(k, v) for k, v in head.headers if k not in _HOP_BY_HOP and not k.startswith("access-control-")]
        lines = ["HTTP/1.1 101 Switching Protocols", *(f"{k}: {v}" for k, v in hdrs)]
        lines += ["connection: Upgrade", "upgrade: websocket", "x-content-type-options: nosniff", "referrer-policy: no-referrer"]
        writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1"))
        await writer.drain()
        await relay(reader, writer, up_r, up_w)
        return False

    async def _pass_response(
        self, req: Request, head: ResponseHead, writer: asyncio.StreamWriter, up_r: asyncio.StreamReader
    ) -> bool:
        lim = self.limits
        cls = [v for k, v in head.headers if k == "content-length"]
        tes = [v for k, v in head.headers if k == "transfer-encoding"]
        mode, length = "eof", 0
        if req.method == "HEAD" or head.status in (204, 304) or head.status < 200:
            mode = "none"
            # keep the declared length on HEAD/304 so the client's view stays accurate
            if len(cls) == 1 and _CL_RE.match(cls[0].encode()) and head.status != 204:
                framing = [("content-length", cls[0])]
            else:
                framing = []
        elif tes:
            if cls or len(tes) != 1 or tes[0].strip().lower() != "chunked":
                await self._respond(writer, 502, "ambiguous upstream response framing")
                return False
            mode, framing = "chunked", [("transfer-encoding", "chunked")]
        elif cls:
            if len(cls) != 1 or not _CL_RE.match(cls[0].encode()) or int(cls[0]) > lim.max_response_body:
                await self._respond(writer, 502, "invalid or oversized upstream Content-Length")
                return False
            mode, length, framing = "length", int(cls[0]), [("content-length", cls[0])]
        else:
            framing = []
        keep = req.keep_alive and mode != "eof"
        writer.write(self._client_head(head, connection="keep-alive" if keep else "close", framing=framing))
        await writer.drain()
        if mode == "length":
            await _copy_length(up_r, writer, length, None)
        elif mode == "chunked":
            await _copy_chunked(up_r, writer, max_total=None, timeout=None, trailers=True)
        elif mode == "eof":
            while data := await up_r.read(64 * 1024):
                writer.write(data)
                await writer.drain()
        return keep

    async def _respond(
        self, writer: asyncio.StreamWriter, status: int, message: str, *, extra: Iterable[tuple[str, str]] = ()
    ) -> None:
        """A gateway-generated response; always closes the connection (the request body, if any, is unread)."""
        body = (message + "\n").encode() if message else b""
        lines = [
            f"HTTP/1.1 {status} {_REASONS.get(status, 'Error')}",
            "content-type: text/plain; charset=utf-8",
            f"content-length: {len(body)}",
            "cache-control: no-store",
            "x-content-type-options: nosniff",
            "referrer-policy: no-referrer",
            "connection: close",
            *(f"{k}: {v}" for k, v in extra),
        ]
        with contextlib.suppress(Exception):
            writer.write(("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body)
            await writer.drain()


class _ClientGone(Exception):
    pass


async def _close(writer: asyncio.StreamWriter) -> None:
    with contextlib.suppress(Exception):
        writer.close()
        await writer.wait_closed()


async def _read(reader: asyncio.StreamReader, n: int, timeout: float | None) -> bytes:
    coro = reader.read(n)
    return await (asyncio.wait_for(coro, timeout) if timeout else coro)


async def _copy_length(src: asyncio.StreamReader, dst: asyncio.StreamWriter, n: int, timeout: float | None) -> None:
    while n > 0:
        try:
            data = await _read(src, min(n, 64 * 1024), timeout)
        except asyncio.TimeoutError as exc:
            raise HttpReject(400, "request body timed out") from exc
        if not data:
            raise HttpReject(400, "body ended before Content-Length")
        n -= len(data)
        dst.write(data)
        await dst.drain()


async def _readline(src: asyncio.StreamReader, timeout: float | None) -> bytes:
    try:
        coro = src.readuntil(b"\r\n")
        return (await (asyncio.wait_for(coro, timeout) if timeout else coro))[:-2]
    except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError) as exc:
        raise HttpReject(400, "malformed chunked body") from exc


async def _copy_chunked(
    src: asyncio.StreamReader,
    dst: asyncio.StreamWriter,
    *,
    max_total: int | None,
    timeout: float | None,
    trailers: bool = False,
) -> None:
    """Copy a chunked body, validating the framing. Request bodies may not carry
    trailers or chunk extensions (``trailers=False``)."""
    total = 0
    while True:
        line = await _readline(src, timeout)
        if not _CHUNK_RE.match(line):
            raise HttpReject(400, "malformed chunk size")
        size = int(line, 16)
        total += size
        if max_total is not None and total > max_total:
            raise HttpReject(413, "request body too large")
        dst.write(line + b"\r\n")
        if size == 0:
            break
        await _copy_length(src, dst, size, timeout)
        if await _readline(src, timeout) != b"":
            raise HttpReject(400, "malformed chunk terminator")
        dst.write(b"\r\n")
        await dst.drain()
    count = 0
    while True:
        line = await _readline(src, timeout)
        if not line:
            break
        count += 1
        if not trailers or count > 20 or b"\x00" in line:
            raise HttpReject(400, "chunked trailers are not accepted")
        dst.write(line + b"\r\n")
    dst.write(b"\r\n")
    await dst.drain()
