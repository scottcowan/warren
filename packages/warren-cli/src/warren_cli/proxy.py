"""`warren proxy`: stable loopback addresses for ports inside ECS workspaces.

Each mapping (server, workspace, remote port) owns one local port, chosen once
and saved in ``~/.warren/proxy.json`` so a client that remembers the address
(a paired T3 Code server, a bookmarked dev server) keeps working across
restarts of the proxy, the workspace, or its task.

``warren proxy run`` listens on every mapping's port (loopback only). Nothing
talks to AWS until a client connects: the first connection resolves the
workspace's current task through the control plane, starts one
``AWS-StartPortForwardingSession`` to an ephemeral local port, and relays bytes
both ways. Later connections share that session. When the session's process
exits (task replaced, SSM timeout, network drop) the next connection resolves
the task again and starts a new one. A session with no connections for
``idle_minutes`` is stopped.

The relay is a plain bidirectional byte copy, so anything that runs over one
TCP connection (HTTP, WebSockets, gRPC) works unchanged.
"""

from __future__ import annotations

import asyncio
import contextlib
import ipaddress
import json
import os
import re
import socket
import subprocess
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Iterable, Protocol

import structlog

from warren_common.fileperms import restrict_to_owner

log = structlog.get_logger(__name__)

LOOPBACK_HOST = "127.0.0.1"
_PORT_SEARCH_SPAN = 1000
_RELAY_CHUNK = 64 * 1024


def default_store_path() -> Path:
    """``~/.warren/proxy.json``, resolved at call time (tests isolate HOME)."""
    return Path.home() / ".warren" / "proxy.json"


# ---------------------------------------------------------------------------
# errors
# ---------------------------------------------------------------------------


class ProxyError(Exception):
    """A failure to reach a mapping's workspace, with a message meant for the operator."""


class WorkspaceUnavailable(ProxyError):
    """The workspace is not running (stopped, failed, gone) or has no task yet."""


class AwsCredentialsExpired(ProxyError):
    """The AWS CLI refused to run because the operator's credentials have expired."""


# What the AWS CLI prints when SSO or session credentials have run out, e.g.
#   "Error when retrieving token from sso: Token has expired and refresh failed"
#   "The SSO session associated with this profile has expired or is otherwise invalid."
#   "Error loading SSO Token: Token for my-sso does not exist"
#   "An error occurred (ExpiredTokenException) ... The security token included in the request is expired"
_EXPIRED_RE = re.compile(
    r"token has expired"
    r"|sso session associated with this profile has expired"
    r"|error loading sso token"
    r"|expiredtoken"
    r"|security token included in the request is expired",
    re.IGNORECASE,
)


def aws_login_hint() -> str:
    profile = os.environ.get("AWS_PROFILE") or "default"
    return f"run `aws sso login --profile {profile}`"


def credentials_error(text: str) -> AwsCredentialsExpired | None:
    """An ``AwsCredentialsExpired`` when ``text`` (AWS CLI stderr, or an error
    carrying it) says the credentials have expired, else None."""
    if not _EXPIRED_RE.search(text):
        return None
    return AwsCredentialsExpired(f"AWS credentials have expired: {aws_login_hint()}, then retry")


# ---------------------------------------------------------------------------
# mapping store
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Mapping:
    server: str
    workspace: str
    remote_port: int
    local_port: int

    @property
    def key(self) -> tuple[str, str, int]:
        return (self.server, self.workspace, self.remote_port)

    @property
    def label(self) -> str:
        return f"{self.server}/{self.workspace}:{self.remote_port}"

    @property
    def address(self) -> str:
        return f"http://{LOOPBACK_HOST}:{self.local_port}"


def _valid_port(port: int) -> bool:
    return isinstance(port, int) and 1 <= port <= 65535


def _port_bindable(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind((LOOPBACK_HOST, port))
        except OSError:
            return False
    return True


class MappingStore:
    """The saved mappings, as a small owner-only JSON file."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path if path is not None else default_store_path()

    def load(self) -> list[Mapping]:
        try:
            data = json.loads(self.path.read_text())
        except FileNotFoundError:
            return []
        except (OSError, ValueError) as exc:
            raise ProxyError(f"could not read {self.path}: {exc}") from exc
        out = []
        for row in data.get("mappings", []):
            try:
                m = Mapping(
                    server=str(row["server"]),
                    workspace=str(row["workspace"]),
                    remote_port=int(row["remote_port"]),
                    local_port=int(row["local_port"]),
                )
            except (KeyError, TypeError, ValueError):
                log.warning("proxy_mapping_skipped", reason="malformed entry", path=str(self.path))
                continue
            out.append(m)
        return out

    def save(self, mappings: Iterable[Mapping]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        tmp = self.path.with_name(self.path.name + ".tmp")
        tmp.write_text(json.dumps({"mappings": [asdict(m) for m in mappings]}, indent=2) + "\n")
        restrict_to_owner(tmp)
        os.replace(tmp, self.path)

    def add(
        self,
        server: str,
        workspace: str,
        remote_port: int,
        *,
        local_port: int | None = None,
        port_base: int = 47100,
        port_free: Callable[[int], bool] = _port_bindable,
    ) -> tuple[Mapping, bool]:
        """Record a mapping; returns ``(mapping, created)``.

        Adding the same (server, workspace, remote port) again returns the saved
        mapping and its port unchanged, unless ``local_port`` asks for a different
        one. A new port is the first one from ``port_base`` that no other mapping
        uses and that nothing on this machine is listening on right now.
        """
        if not _valid_port(remote_port):
            raise ProxyError(f"remote port {remote_port} is not a TCP port")
        if local_port is not None and not _valid_port(local_port):
            raise ProxyError(f"local port {local_port} is not a TCP port")
        mappings = self.load()
        existing = next((m for m in mappings if m.key == (server, workspace, remote_port)), None)
        if existing and (local_port is None or local_port == existing.local_port):
            return existing, False
        others = [m for m in mappings if m is not existing]
        used = {m.local_port for m in others}
        if local_port is not None:
            if local_port in used:
                owner = next(m for m in others if m.local_port == local_port)
                raise ProxyError(f"local port {local_port} is already used by {owner.label}")
            port = local_port
        else:
            port = next(
                (p for p in range(port_base, min(port_base + _PORT_SEARCH_SPAN, 65536)) if p not in used and port_free(p)),
                None,
            )
            if port is None:
                raise ProxyError(f"no free local port in {port_base}-{port_base + _PORT_SEARCH_SPAN - 1}")
        mapping = Mapping(server=server, workspace=workspace, remote_port=remote_port, local_port=port)
        self.save([*others, mapping])
        return mapping, existing is None

    def remove(self, selector: str, *, server: str | None = None) -> list[Mapping]:
        """Remove mappings matching ``selector``: a local port, ``<workspace>`` (every
        port of it) or ``<workspace>:<remote-port>``; ``server`` narrows the match.
        Returns what was removed."""
        mappings = self.load()

        def matches(m: Mapping) -> bool:
            if server is not None and m.server != server:
                return False
            if selector.isdigit():
                return m.local_port == int(selector)
            ws, sep, port = selector.rpartition(":")
            if sep and port.isdigit():
                return m.workspace == ws and m.remote_port == int(port)
            return m.workspace == selector

        removed = [m for m in mappings if matches(m)]
        if removed:
            self.save([m for m in mappings if not matches(m)])
        return removed


# ---------------------------------------------------------------------------
# resolving a workspace and forwarding to it
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Target:
    """Where a mapping's workspace runs right now."""

    workspace_id: str
    cluster: str
    task_arn: str


class Resolver(Protocol):
    async def resolve(self, mapping: Mapping) -> Target: ...


class Session(Protocol):
    """One live port-forward: connections to ``127.0.0.1:local_port`` reach the workspace."""

    local_port: int

    def alive(self) -> bool: ...

    def stop(self) -> None: ...


class Forwarder(Protocol):
    async def start(self, target: Target, remote_port: int) -> Session: ...


def match_workspace(workspaces: list[dict], workspace: str) -> dict:
    """Exact id, else a unique prefix (same rule as `warren connect`)."""
    for w in workspaces:
        if w.get("workspace_id") == workspace:
            return w
    hits = [w for w in workspaces if str(w.get("workspace_id", "")).startswith(workspace)]
    if len(hits) == 1:
        return hits[0]
    if hits:
        raise ProxyError(f"workspace id {workspace!r} is ambiguous: {[w.get('workspace_id') for w in hits]}")
    raise WorkspaceUnavailable(f"workspace {workspace!r} not found")


def target_for(ws: dict, *, cluster: str, server: str) -> Target:
    """The running task for a workspace row from ``GET /workspaces``, or a
    ``WorkspaceUnavailable`` saying why there isn't one."""
    wid = str(ws.get("workspace_id", ""))
    status = ws.get("status")
    task_arn = ws.get("container_id")
    if status == "running" and task_arn:
        return Target(workspace_id=wid, cluster=cluster, task_arn=str(task_arn))
    if status == "provisioning" or (status == "running" and not task_arn):
        raise WorkspaceUnavailable(f"workspace {wid[:8]} is still starting; try again shortly")
    raise WorkspaceUnavailable(
        f"workspace {wid[:8]} is {status}; start it with `warren connect {wid[:8]} --server {server}`"
    )


class ControlPlaneResolver:
    """Resolve a mapping's workspace to its current ECS task through the
    control plane (``GET /workspaces``), tunnelling to the orchestrator the same
    way every other remote command does (``make_remote_client``).

    Runs in a worker thread with its own event loop: opening the orchestrator
    tunnel blocks for up to ~10s, and the proxy's own loop must keep relaying
    other connections meanwhile."""

    def __init__(self, cfg: Any) -> None:
        self.cfg = cfg

    async def resolve(self, mapping: Mapping) -> Target:
        return await asyncio.to_thread(asyncio.run, self._resolve(mapping))

    async def _resolve(self, mapping: Mapping) -> Target:
        from .client import make_remote_client  # noqa: PLC0415

        remote = remote_for(self.cfg, mapping.server)
        cluster = remote.ecs_cluster or os.environ.get("WARREN_ECS_CLUSTER", "")
        try:
            async with make_remote_client(remote, timeout=15.0) as c:
                r = await c.get("/workspaces")
        except Exception as exc:  # tunnel or HTTP transport failure
            raise credentials_error(str(exc)) or ProxyError(
                f"control plane for {mapping.server!r} unreachable: {exc}"
            ) from exc
        if r.status_code in (401, 403):
            raise ProxyError(f"control plane for {mapping.server!r} refused the request (HTTP {r.status_code})")
        if not r.is_success:
            raise ProxyError(f"control plane for {mapping.server!r} answered HTTP {r.status_code}")
        return target_for(match_workspace(r.json(), mapping.workspace), cluster=cluster, server=mapping.server)


def remote_for(cfg: Any, server: str) -> Any:
    """The ecs remote profile ``server``; a ``ProxyError`` for anything else.

    Podman/docker servers (``http``/``ssh`` remotes) are refused: their workspace
    ports are inside containers on the server host, which the CLI's SSH forward
    (to the host's loopback control plane) doesn't reach."""
    try:
        remote = cfg.get_remote(server)
    except KeyError as exc:
        raise ProxyError(str(exc.args[0]) if exc.args else str(exc)) from exc
    if remote.runtime_type != "ecs":
        raise ProxyError(
            f"remote {server!r} is runtime_type {remote.runtime_type!r}: warren proxy only reaches ECS "
            "workspaces (their ports have no other network path); podman/docker workspace ports are on "
            "the server host, reach them with your own `ssh -L`"
        )
    if not (remote.ecs_cluster or os.environ.get("WARREN_ECS_CLUSTER")):
        raise ProxyError(f"remote {server!r} has no ecs_cluster")
    return remote


class _PopenSession:
    def __init__(self, proc: subprocess.Popen, local_port: int) -> None:
        self.proc = proc
        self.local_port = local_port

    def alive(self) -> bool:
        return self.proc.poll() is None

    def stop(self) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.kill()


class SsmForwarder:
    """Start ``aws ssm start-session`` port-forwards (``dispatch.start_workspace_port_forward``)."""

    async def start(self, target: Target, remote_port: int) -> Session:
        from . import dispatch  # noqa: PLC0415

        try:
            proc, port = await asyncio.to_thread(
                dispatch.start_workspace_port_forward, target.cluster, target.task_arn, remote_port
            )
        except RuntimeError as exc:
            raise credentials_error(str(exc)) or ProxyError(str(exc)) from exc
        return _PopenSession(proc, port)


# ---------------------------------------------------------------------------
# listeners and relay
# ---------------------------------------------------------------------------


def check_loopback(host: str) -> str:
    """``host`` if it is a loopback address (``localhost`` means 127.0.0.1);
    ``ProxyError`` otherwise. The proxy carries the operator's own access into a
    workspace, so it never listens where another machine could reach it."""
    if host == "localhost":
        return LOOPBACK_HOST
    try:
        addr = ipaddress.ip_address(host)
    except ValueError as exc:
        raise ProxyError(f"refusing to bind {host!r}: warren proxy binds loopback addresses only") from exc
    if not addr.is_loopback:
        raise ProxyError(f"refusing to bind {host!r}: warren proxy binds loopback addresses only")
    return host


async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
    while True:
        data = await src.read(_RELAY_CHUNK)
        if not data:
            break
        dst.write(data)
        await dst.drain()
    # Pass the half-close on (HTTP/1.0-style "request done" clients rely on it).
    with contextlib.suppress(OSError, RuntimeError):
        if dst.can_write_eof():
            dst.write_eof()


async def relay(
    a_reader: asyncio.StreamReader,
    a_writer: asyncio.StreamWriter,
    b_reader: asyncio.StreamReader,
    b_writer: asyncio.StreamWriter,
) -> None:
    """Copy bytes both ways until both directions finish. A clean EOF is passed on
    as a half-close; a reset on either side tears down both."""
    tasks = [asyncio.ensure_future(_pipe(a_reader, b_writer)), asyncio.ensure_future(_pipe(b_reader, a_writer))]
    try:
        pending = set(tasks)
        while pending:
            done, pending = await asyncio.wait(pending, return_when=asyncio.FIRST_COMPLETED)
            if any(t.exception() is not None for t in done):
                break
    finally:
        for t in tasks:
            t.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        for w in (a_writer, b_writer):
            with contextlib.suppress(Exception):
                w.close()
        for w in (a_writer, b_writer):
            with contextlib.suppress(Exception):
                await w.wait_closed()


_HTTP_METHOD_RE = re.compile(rb"^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS) ")


async def _reject(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, message: str) -> None:
    """Close a client connection we can't serve. If the client has already sent an
    HTTP request line (most do, straight away), answer 503 with the reason first,
    so a browser or HTTP client shows it rather than a bare reset."""
    with contextlib.suppress(Exception):
        head = await asyncio.wait_for(reader.read(1024), timeout=0.5)
        if _HTTP_METHOD_RE.match(head or b""):
            body = f"warren proxy: {message}\n".encode()
            writer.write(
                b"HTTP/1.1 503 Service Unavailable\r\nContent-Type: text/plain; charset=utf-8\r\n"
                + f"Content-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                + body
            )
            await writer.drain()
    with contextlib.suppress(Exception):
        writer.close()
        await writer.wait_closed()


@dataclass(frozen=True)
class ProxySettings:
    idle_minutes: float = 30.0
    keepalive_seconds: float = 240.0
    bind: str = LOOPBACK_HOST


class MappingProxy:
    """One mapping: its listener, and the (at most one) SSM session behind it."""

    def __init__(self, mapping: Mapping, resolver: Resolver, forwarder: Forwarder, settings: ProxySettings) -> None:
        self.mapping = mapping
        self.resolver = resolver
        self.forwarder = forwarder
        self.settings = settings
        self.session: Session | None = None
        self.target: Target | None = None
        self.active = 0
        self.sessions_started = 0
        self._lock = asyncio.Lock()
        self._server: asyncio.AbstractServer | None = None
        self._idle_task: asyncio.Task | None = None
        self._keepalive_task: asyncio.Task | None = None
        self._log = log.bind(mapping=mapping.label, local_port=mapping.local_port)

    async def listen(self) -> None:
        host = check_loopback(self.settings.bind)
        self._server = await asyncio.start_server(self._handle, host, self.mapping.local_port)
        self._log.info("proxy_listening", address=f"{host}:{self.mapping.local_port}")

    async def close(self) -> None:
        if self._server is not None:
            self._server.close()
            with contextlib.suppress(Exception):
                await asyncio.wait_for(self._server.wait_closed(), timeout=2)
        for task in (self._idle_task, self._keepalive_task):
            if task is not None:
                task.cancel()
        self._stop_session("proxy_stopped")

    def _stop_session(self, reason: str) -> None:
        if self.session is not None:
            self.session.stop()
            self._log.info("proxy_session_stopped", reason=reason)
        self.session = None
        if self._keepalive_task is not None:
            self._keepalive_task.cancel()
            self._keepalive_task = None

    async def ensure_session(self) -> Session:
        """The live session, starting one (resolving the task afresh) when there is
        none or the last one's process has exited. Concurrent callers share it."""
        async with self._lock:
            if self.session is not None and self.session.alive():
                return self.session
            if self.session is not None:
                self._log.warning("proxy_session_exited", task_arn=self.target.task_arn if self.target else None)
                self._stop_session("exited")
            target = await self.resolver.resolve(self.mapping)
            if self.target is not None and target.task_arn != self.target.task_arn:
                self._log.info("proxy_task_changed", old_task_arn=self.target.task_arn, task_arn=target.task_arn)
            self.target = target
            self.session = await self.forwarder.start(target, self.mapping.remote_port)
            self.sessions_started += 1
            self._log.info(
                "proxy_session_started",
                workspace_id=target.workspace_id,
                task_arn=target.task_arn,
                forward_port=self.session.local_port,
            )
            if self.settings.keepalive_seconds > 0:
                self._keepalive_task = asyncio.ensure_future(self._keepalive(self.session))
            return self.session

    async def _connect_upstream(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        for attempt in range(2):
            session = await self.ensure_session()
            try:
                return await asyncio.open_connection(LOOPBACK_HOST, session.local_port)
            except OSError as exc:
                # The forward is up as a process but not accepting: treat it as dead
                # and start over once (the task may have been replaced under it).
                self._log.warning("proxy_upstream_refused", error=str(exc), attempt=attempt + 1)
                async with self._lock:
                    if self.session is session:
                        self._stop_session("refused")
        raise ProxyError("the SSM port-forward is not accepting connections")

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.active += 1
        if self._idle_task is not None:
            self._idle_task.cancel()
            self._idle_task = None
        try:
            try:
                up_reader, up_writer = await self._connect_upstream()
            except ProxyError as exc:
                self._log.error("proxy_connection_refused", error=str(exc))
                await _reject(reader, writer, str(exc))
                return
            except Exception as exc:  # never let one connection kill the listener
                self._log.error("proxy_connection_failed", error=repr(exc))
                await _reject(reader, writer, "internal error, see the proxy's log")
                return
            self._log.debug("proxy_connection_open", active=self.active)
            await relay(reader, writer, up_reader, up_writer)
        finally:
            self.active -= 1
            self._log.debug("proxy_connection_closed", active=self.active)
            if self.active == 0 and self.session is not None and self.settings.idle_minutes > 0:
                self._idle_task = asyncio.ensure_future(self._idle_close())

    async def _idle_close(self) -> None:
        await asyncio.sleep(self.settings.idle_minutes * 60)
        async with self._lock:
            if self.active == 0 and self.session is not None:
                self._stop_session(f"idle {self.settings.idle_minutes:g} min")

    async def _keepalive(self, session: Session) -> None:
        """While clients are connected, open and close a connection through the
        session every ``keepalive_seconds``: each one is a stream open/close over
        the SSM data channel, i.e. session traffic even when the app is silent.
        Best-effort (see docs/proxy.md); also notices a dead session early."""
        while True:
            await asyncio.sleep(self.settings.keepalive_seconds)
            if not session.alive():
                self._log.warning("proxy_session_exited", task_arn=self.target.task_arn if self.target else None)
                return
            if self.active == 0:
                continue
            try:
                _, w = await asyncio.wait_for(asyncio.open_connection(LOOPBACK_HOST, session.local_port), timeout=10)
                w.close()
                with contextlib.suppress(Exception):
                    await w.wait_closed()
                self._log.debug("proxy_keepalive")
            except (OSError, asyncio.TimeoutError) as exc:
                self._log.warning("proxy_keepalive_failed", error=str(exc))


class ProxyDaemon:
    """Every saved mapping's listener, reloaded from the store as it changes."""

    def __init__(
        self,
        store: MappingStore,
        resolver: Resolver,
        forwarder: Forwarder,
        settings: ProxySettings,
        *,
        reload_seconds: float = 5.0,
    ) -> None:
        check_loopback(settings.bind)
        self.store = store
        self.resolver = resolver
        self.forwarder = forwarder
        self.settings = settings
        self.reload_seconds = reload_seconds
        self.proxies: dict[Mapping, MappingProxy] = {}
        self._mtime: float | None = None

    async def reconcile(self) -> None:
        wanted = set(self.store.load())
        for mapping in [m for m in self.proxies if m not in wanted]:
            await self.proxies.pop(mapping).close()
        for mapping in wanted - set(self.proxies):
            proxy = MappingProxy(mapping, self.resolver, self.forwarder, self.settings)
            try:
                await proxy.listen()
            except OSError as exc:
                log.error("proxy_listen_failed", mapping=mapping.label, local_port=mapping.local_port, error=str(exc))
                continue
            self.proxies[mapping] = proxy

    def _store_mtime(self) -> float | None:
        try:
            return self.store.path.stat().st_mtime
        except OSError:
            return None

    async def run(self, stop: asyncio.Event, *, started: Callable[[], Awaitable[None] | None] | None = None) -> None:
        self._mtime = self._store_mtime()
        await self.reconcile()
        if started is not None:
            result = started()
            if asyncio.iscoroutine(result):
                await result
        try:
            while not stop.is_set():
                with contextlib.suppress(asyncio.TimeoutError):
                    await asyncio.wait_for(stop.wait(), timeout=self.reload_seconds)
                mtime = self._store_mtime()
                if mtime != self._mtime:
                    self._mtime = mtime
                    log.info("proxy_mappings_reloaded", path=str(self.store.path))
                    try:
                        await self.reconcile()
                    except ProxyError as exc:
                        log.error("proxy_mappings_unreadable", error=str(exc))
        finally:
            for proxy in self.proxies.values():
                await proxy.close()
            self.proxies.clear()
