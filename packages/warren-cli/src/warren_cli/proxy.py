"""`warren proxy`: stable loopback addresses for ports inside workspaces.

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

Podman/docker workspaces publish each template-declared port on the server
host's loopback, on a host port the container engine picks; the control plane
reports it per port name (``host_ports``). For an ``ssh`` remote the session is
an ``ssh -L <ephemeral>:127.0.0.1:<host-port>`` to the server host, the same kind
of forward the CLI already uses for that server's control plane; for an ``http``
remote on this machine's loopback (a local server) the proxy connects straight to
``127.0.0.1:<host-port>``. A container that comes back with a different host port
is picked up the same way as a replaced ECS task: the next connection after a
failure, or the first one after ``revalidate_seconds`` without any, resolves again.

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
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Awaitable, Callable, Iterable, Literal, Protocol
from urllib.parse import urlparse

import structlog

from warren_common.fileperms import restrict_to_owner

from . import proxy_http

from . import proxy_http

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
    # The template's port name (`ports:` in the template), when the mapping was
    # added by name or with --from-template. Not part of identity: naming an
    # existing mapping must not restart its listener.
    name: str | None = field(default=None, compare=False)
    # "tcp": a plain byte relay (ssh, T3, ACP). "http": the HTTP-aware gateway in
    # front of a web UI (proxy_http.py). Part of identity: changing it restarts the listener.
    kind: str = "tcp"

    @property
    def key(self) -> tuple[str, str, int]:
        return (self.server, self.workspace, self.remote_port)

    @property
    def label(self) -> str:
        if self.name:
            return f"{self.server}/{self.workspace}/{self.name}"
        return f"{self.server}/{self.workspace}:{self.remote_port}"

    @property
    def address(self) -> str:
        return f"http://{LOOPBACK_HOST}:{self.local_port}"


KINDS = ("tcp", "http")
_WORKSPACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}$")
_PORT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_SERVER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def validate_identifiers(server: str, workspace: str, name: str | None = None) -> None:
    """Strict shapes for the strings that reach file paths, command lines and logs."""
    if not _SERVER_RE.match(server):
        raise ProxyError(f"invalid server name {server!r}")
    if not _WORKSPACE_RE.match(workspace):
        raise ProxyError(f"invalid workspace id {workspace!r}: letters, digits and '-' only")
    if name is not None and not _PORT_NAME_RE.match(name):
        raise ProxyError(f"invalid port name {name!r}: lowercase letters, digits and '-' only")


KINDS = ("tcp", "http")
_WORKSPACE_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}$")
_PORT_NAME_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,62}$")
_SERVER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")


def validate_identifiers(server: str, workspace: str, name: str | None = None) -> None:
    """Strict shapes for the strings that reach file paths, command lines and logs."""
    if not _SERVER_RE.match(server):
        raise ProxyError(f"invalid server name {server!r}")
    if not _WORKSPACE_RE.match(workspace):
        raise ProxyError(f"invalid workspace id {workspace!r}: letters, digits and '-' only")
    if name is not None and not _PORT_NAME_RE.match(name):
        raise ProxyError(f"invalid port name {name!r}: lowercase letters, digits and '-' only")


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
                    name=str(row["name"]) if row.get("name") else None,
                    kind=str(row.get("kind") or "tcp"),
                )
                if m.kind not in KINDS:
                    raise ValueError(f"unknown kind {m.kind!r}")
                validate_identifiers(m.server, m.workspace, m.name)
                if not (_valid_port(m.remote_port) and _valid_port(m.local_port)):
                    raise ValueError("port out of range")
            except (KeyError, TypeError, ValueError, ProxyError):
                log.warning("proxy_mapping_skipped", reason="malformed entry", path=str(self.path))
                continue
            out.append(m)
        return out

    def save(self, mappings: Iterable[Mapping]) -> None:
        """Atomic, owner-only write; refuses to write through a symlink."""
        parent = self.path.parent
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.path.is_symlink():
            raise ProxyError(f"refusing to write {self.path}: it is a symlink")
        with contextlib.suppress(OSError):
            restrict_to_owner(parent, directory=True)
        rows = [
            {k: v for k, v in asdict(m).items() if (k != "name" or v) and (k != "kind" or v != "tcp")}
            for m in mappings
        ]
        # mkstemp: O_EXCL, 0600, unpredictable name, so nothing planted can be followed.
        fd, tmp_name = tempfile.mkstemp(prefix=self.path.name + ".", suffix=".tmp", dir=parent)
        try:
            with os.fdopen(fd, "w") as f:
                f.write(json.dumps({"mappings": rows}, indent=2) + "\n")
                f.flush()
                os.fsync(f.fileno())
            restrict_to_owner(tmp_name)
            os.replace(tmp_name, self.path)
        except BaseException:
            with contextlib.suppress(OSError):
                os.unlink(tmp_name)
            raise

    def add(
        self,
        server: str,
        workspace: str,
        remote_port: int,
        *,
        local_port: int | None = None,
        name: str | None = None,
        kind: str | None = None,
        port_base: int = 47100,
        port_free: Callable[[int], bool] = _port_bindable,
    ) -> tuple[Mapping, bool]:
        """Record a mapping; returns ``(mapping, created)``.

        Adding the same (server, workspace, remote port) again returns the saved
        mapping and its port unchanged, unless ``local_port`` asks for a different
        one. A new port is the first one from ``port_base`` that no other mapping
        uses and that nothing on this machine is listening on right now.

        ``name`` labels the mapping ``<server>/<workspace>/<name>``. A name already
        mapped on that workspace to a different remote port (the template changed
        the port) moves to the new remote port and keeps its local port, so the
        address stays stable; if the new remote port is already mapped too, that's
        a conflict for the operator to resolve with ``warren proxy rm``.
        """
        validate_identifiers(server, workspace, name)
        if kind is not None and kind not in KINDS:
            raise ProxyError(f"unknown mapping kind {kind!r} (expected one of: {', '.join(KINDS)})")
        validate_identifiers(server, workspace, name)
        if kind is not None and kind not in KINDS:
            raise ProxyError(f"unknown mapping kind {kind!r} (expected one of: {', '.join(KINDS)})")
        if not _valid_port(remote_port):
            raise ProxyError(f"remote port {remote_port} is not a TCP port")
        if local_port is not None and not _valid_port(local_port):
            raise ProxyError(f"local port {local_port} is not a TCP port")
        mappings = self.load()
        existing = next((m for m in mappings if m.key == (server, workspace, remote_port)), None)
        if name:
            named = next(
                (m for m in mappings if (m.server, m.workspace, m.name) == (server, workspace, name) and m is not existing),
                None,
            )
            if named is not None:
                if existing is not None:
                    raise ProxyError(
                        f"{named.label} maps remote port {named.remote_port} but the workspace declares "
                        f"{name!r} as {remote_port}, which {existing.label} already maps; "
                        f"remove one with `warren proxy rm`"
                    )
                existing = named
        if existing and (local_port is None or local_port == existing.local_port):
            new_kind = kind or existing.kind
            if (
                (existing.name or None) == (name or existing.name)
                and existing.remote_port == remote_port
                and existing.kind == new_kind
            ):
                return existing, False
            renamed = Mapping(
                server=server,
                workspace=workspace,
                remote_port=remote_port,
                local_port=existing.local_port,
                name=name or existing.name,
                kind=new_kind,
            )
            self.save([renamed if m is existing else m for m in mappings])
            return renamed, False
        name = name or (existing.name if existing else None)
        kind = kind or (existing.kind if existing else "tcp")
        others = [m for m in mappings if m is not existing]
        used = {m.local_port for m in others}
        if local_port is not None:
            if local_port in used:
                owner = next(m for m in others if m.local_port == local_port)
                raise ProxyError(f"local port {local_port} is already used by {owner.label}")
            if not port_free(local_port):
                raise ProxyError(f"local port {local_port} is already in use by another process")
            port = local_port
        else:
            port = next(
                (p for p in range(port_base, min(port_base + _PORT_SEARCH_SPAN, 65536)) if p not in used and port_free(p)),
                None,
            )
            if port is None:
                raise ProxyError(f"no free local port in {port_base}-{port_base + _PORT_SEARCH_SPAN - 1}")
        mapping = Mapping(server=server, workspace=workspace, remote_port=remote_port, local_port=port, name=name, kind=kind)
        self.save([*others, mapping])
        return mapping, existing is None

    def remove(self, selector: str, *, server: str | None = None) -> list[Mapping]:
        """Remove mappings matching ``selector``: a local port, ``<workspace>`` (every
        port of it), ``<workspace>:<remote-port>`` or ``<workspace>/<port-name>``;
        ``server`` narrows the match. Returns what was removed."""
        mappings = self.load()

        def matches(m: Mapping) -> bool:
            if server is not None and m.server != server:
                return False
            if selector.isdigit():
                return m.local_port == int(selector)
            ws_, slash, port_name = selector.rpartition("/")
            if slash and ws_ and port_name:
                return m.workspace == ws_ and m.name == port_name
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


TargetKind = Literal["ecs", "ssh", "direct"]


@dataclass(frozen=True)
class Target:
    """Where a mapping's workspace port is reachable right now.

    ``ecs``: the workspace's task (``cluster``/``task_arn``), reached over SSM.
    ``ssh``/``direct``: a podman/docker workspace port published on the server
    host's loopback at ``host:host_port``, reached through ``ssh -L`` to
    ``ssh_host`` or, when the server runs on this machine, directly."""

    workspace_id: str
    cluster: str = ""
    task_arn: str = ""
    kind: TargetKind = "ecs"
    host: str = ""
    host_port: int = 0
    ssh_host: str = ""
    ssh_key_path: str | None = None

    @property
    def endpoint(self) -> str:
        """What a forward is bound to: a different endpoint needs a new forward."""
        if self.kind == "ecs":
            return self.task_arn
        return f"{self.host}:{self.host_port}"


class Resolver(Protocol):
    async def resolve(self, mapping: Mapping) -> Target: ...


class Session(Protocol):
    """One live port-forward: connections to ``host:local_port`` (``host`` defaults to
    127.0.0.1) reach the workspace."""

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


def _require_running(ws: dict, server: str) -> tuple[str, str]:
    """``(workspace_id, container_id)`` of a running workspace row, else a
    ``WorkspaceUnavailable`` saying why it isn't."""
    wid = str(ws.get("workspace_id", ""))
    status = ws.get("status")
    runtime_id = ws.get("container_id")
    if status == "running" and runtime_id:
        return wid, str(runtime_id)
    if status == "provisioning" or (status == "running" and not runtime_id):
        raise WorkspaceUnavailable(f"workspace {wid[:8]} is still starting; try again shortly")
    raise WorkspaceUnavailable(
        f"workspace {wid[:8]} is {status}; start it with `warren connect {wid[:8]} --server {server}`"
    )


def target_for(ws: dict, *, cluster: str, server: str) -> Target:
    """The running task for a workspace row from ``GET /workspaces``, or a
    ``WorkspaceUnavailable`` saying why there isn't one."""
    wid, task_arn = _require_running(ws, server)
    return Target(workspace_id=wid, cluster=cluster, task_arn=task_arn)


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def published_target(ws: dict, *, remote_port: int, remote: Any, server: str) -> Target:
    """Where a running podman/docker workspace publishes ``remote_port`` on the server
    host (``host_ports`` in ``GET /workspaces``), as an ``ssh`` target for an ssh
    remote and a ``direct`` one for a local server. Only template-declared ports are
    published, and only on loopback; anything else is a ``ProxyError``."""
    wid, _ = _require_running(ws, server)
    declared = declared_ports(ws)
    names = sorted(name for name, port in declared.items() if port == remote_port)
    if not names:
        known = ", ".join(f"{n}={p}" for n, p in sorted(declared.items())) or "none"
        raise ProxyError(
            f"port {remote_port} isn't one of workspace {wid[:8]}'s template ports (declared: {known}); "
            "podman/docker workspaces publish only declared ports: add it under `ports:` in the "
            "template and recreate the workspace"
        )
    raw = ws.get("host_ports")
    entry = raw.get(names[0]) if isinstance(raw, dict) else None
    host = entry.get("host") if isinstance(entry, dict) else None
    host_port = entry.get("port") if isinstance(entry, dict) else None
    if not (isinstance(host_port, int) and not isinstance(host_port, bool) and _valid_port(host_port)):
        raise WorkspaceUnavailable(
            f"server {server!r} reports no host port for {names[0]!r} on workspace {wid[:8]} (a server "
            "predating published ports, or a container created before the template declared it: "
            "recreate the workspace)"
        )
    if not (isinstance(host, str) and _is_loopback(host)):
        # The server only publishes on loopback; refuse to forward anywhere else.
        raise ProxyError(f"server {server!r} reports {names[0]!r} on {host!r}, not a loopback address")
    if remote.runtime_type == "ssh":
        return Target(
            workspace_id=wid,
            kind="ssh",
            host=host,
            host_port=host_port,
            ssh_host=str(remote.ssh_host),
            ssh_key_path=remote.ssh_key_path,
        )
    return Target(workspace_id=wid, kind="direct", host=host, host_port=host_port)


def declared_ports(ws: dict) -> dict[str, int]:
    """The ``ports`` a workspace row from ``GET /workspaces`` declares, as
    ``{name: port}`` (a server predating named ports sends none)."""
    out: dict[str, int] = {}
    raw = ws.get("ports")
    if not isinstance(raw, dict):
        return out
    for name, entry in raw.items():
        port = entry.get("port") if isinstance(entry, dict) else entry
        if isinstance(port, int) and not isinstance(port, bool) and _valid_port(port):
            out[str(name)] = port
    return out


def declared_protocols(ws: dict) -> dict[str, str]:
    """``{name: "tcp" | "http"}`` for the declared ports (a server predating
    ``protocol`` sends none: tcp)."""
    raw = ws.get("ports")
    if not isinstance(raw, dict):
        return {}
    return {
        str(n): "http" if isinstance(e, dict) and e.get("protocol") == "http" else "tcp" for n, e in raw.items()
    }


async def fetch_workspaces(cfg: Any, server: str) -> list[dict]:
    """``GET /workspaces`` on ``server``'s control plane, with operator-facing errors."""
    from .client import make_remote_client  # noqa: PLC0415

    remote = remote_for(cfg, server)
    try:
        async with make_remote_client(remote, timeout=15.0) as c:
            r = await c.get("/workspaces")
    except Exception as exc:  # tunnel or HTTP transport failure
        raise credentials_error(str(exc)) or ProxyError(f"control plane for {server!r} unreachable: {exc}") from exc
    if r.status_code in (401, 403):
        raise ProxyError(f"control plane for {server!r} refused the request (HTTP {r.status_code})")
    if not r.is_success:
        raise ProxyError(f"control plane for {server!r} answered HTTP {r.status_code}")
    return r.json()


class ControlPlaneResolver:
    """Resolve a mapping's workspace to its current ECS task, or its podman/docker
    port's current host binding, through the control plane (``GET /workspaces``),
    tunnelling to it the same way every other remote command does
    (``make_remote_client``).

    Runs in a worker thread with its own event loop: opening the orchestrator
    tunnel blocks for up to ~10s, and the proxy's own loop must keep relaying
    other connections meanwhile."""

    def __init__(self, cfg: Any) -> None:
        self.cfg = cfg

    async def resolve(self, mapping: Mapping) -> Target:
        return await asyncio.to_thread(asyncio.run, self._resolve(mapping))

    async def _resolve(self, mapping: Mapping) -> Target:
        remote = remote_for(self.cfg, mapping.server)
        workspaces = await fetch_workspaces(self.cfg, mapping.server)
        ws = match_workspace(workspaces, mapping.workspace)
        if remote.runtime_type == "ecs":
            cluster = remote.ecs_cluster or os.environ.get("WARREN_ECS_CLUSTER", "")
            return target_for(ws, cluster=cluster, server=mapping.server)
        return published_target(ws, remote_port=mapping.remote_port, remote=remote, server=mapping.server)


def is_local_remote(remote: Any) -> bool:
    """An ``http`` remote whose URL is on this machine's loopback: a server (podman or
    docker) on this host, whose published workspace ports are this host's loopback too."""
    if remote.runtime_type != "http" or not remote.url:
        return False
    host = (urlparse(str(remote.url)).hostname or "").lower()
    return host == "localhost" or _is_loopback(host)


def proxy_capable(remote: Any) -> bool:
    return remote.runtime_type in ("ecs", "ssh") or is_local_remote(remote)


def remote_for(cfg: Any, server: str) -> Any:
    """The remote profile ``server`` if `warren proxy` can reach its workspaces, else a
    ``ProxyError``: ``ecs`` (SSM), ``ssh`` (an SSH forward to the podman/docker host's
    loopback, where declared ports are published) and an ``http`` remote on this
    machine's loopback (connect to the published port directly). An ``http`` remote
    on another host is refused: its workspace ports are on that host's loopback, which
    only an SSH forward reaches."""
    try:
        remote = cfg.get_remote(server)
    except KeyError as exc:
        raise ProxyError(str(exc.args[0]) if exc.args else str(exc)) from exc
    if remote.runtime_type == "ecs":
        if not (remote.ecs_cluster or os.environ.get("WARREN_ECS_CLUSTER")):
            raise ProxyError(f"remote {server!r} has no ecs_cluster")
        return remote
    if not proxy_capable(remote):
        raise ProxyError(
            f"remote {server!r} is an http remote on another host ({remote.url}): its workspace ports are "
            "published on that host's loopback, which warren proxy reaches over SSH; add the server as an "
            "ssh remote (`warren remote add --ssh-host ...`) and map through that"
        )
    return remote


class _PopenSession:
    host = LOOPBACK_HOST

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


class SshForwarder:
    """``ssh -L <ephemeral>:<host>:<host-port>`` to the server host, where a podman/docker
    workspace publishes the port (``dispatch.start_ssh_port_forward``, the same forward
    the CLI uses for that server's control plane)."""

    async def start(self, target: Target, remote_port: int) -> Session:
        from . import dispatch  # noqa: PLC0415

        try:
            proc, port = await asyncio.to_thread(
                dispatch.start_ssh_port_forward,
                target.ssh_host,
                target.host_port,
                ssh_key_path=target.ssh_key_path,
                remote_host=target.host,
            )
        except RuntimeError as exc:
            raise ProxyError(str(exc)) from exc
        return _PopenSession(proc, port)


class _DirectSession:
    """No forward at all: the published port is on this machine's loopback."""

    def __init__(self, host: str, port: int) -> None:
        self.host = host
        self.local_port = port

    def alive(self) -> bool:
        return True

    def stop(self) -> None:
        pass


class DirectForwarder:
    async def start(self, target: Target, remote_port: int) -> Session:
        return _DirectSession(target.host, target.host_port)


class RuntimeForwarder:
    """Picks the forward for a target's kind: SSM (ECS), SSH, or none (local server)."""

    def __init__(
        self,
        ecs: Forwarder | None = None,
        ssh: Forwarder | None = None,
        direct: Forwarder | None = None,
    ) -> None:
        self.by_kind: dict[str, Forwarder] = {
            "ecs": ecs or SsmForwarder(),
            "ssh": ssh or SshForwarder(),
            "direct": direct or DirectForwarder(),
        }

    async def start(self, target: Target, remote_port: int) -> Session:
        return await self.by_kind[target.kind].start(target, remote_port)


def _session_host(session: Session) -> str:
    return getattr(session, "host", None) or LOOPBACK_HOST


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


async def _pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter, counter: list[int] | None = None) -> None:
    while True:
        data = await src.read(_RELAY_CHUNK)
        if not data:
            break
        if counter is not None:
            counter[0] += len(data)
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
) -> int:
    """Copy bytes both ways until both directions finish. A clean EOF is passed on
    as a half-close; a reset on either side tears down both. Returns how many bytes
    came from ``b`` (the upstream)."""
    from_b = [0]
    tasks = [
        asyncio.ensure_future(_pipe(a_reader, b_writer)),
        asyncio.ensure_future(_pipe(b_reader, a_writer, from_b)),
    ]
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
    return from_b[0]


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
    # podman/docker targets: a connection arriving when no other is open, this long
    # after the last resolve, checks the control plane for a moved host port first
    # (an SSH forward to a stale port stays up and just drops connections).
    revalidate_seconds: float = 15.0
    # kind "http" mappings: gateway limits/timeouts, and the upstream-auth hook
    # (None: add no headers).
    http_limits: proxy_http.GatewayLimits = proxy_http.GatewayLimits()
    upstream_auth: proxy_http.UpstreamAuthProvider | None = None


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
        self._resolved_at = 0.0
        self._suspect = False
        self._lock = asyncio.Lock()
        self._server: asyncio.AbstractServer | None = None
        self._idle_task: asyncio.Task | None = None
        self._keepalive_task: asyncio.Task | None = None
        # Strong references to every connection's task. asyncio holds tasks only
        # weakly, and once a client half-closes its transport stops reading, so
        # nothing else reaches the task (the upstream protocol holds its reader
        # weakly too): a garbage collection mid-relay would destroy it and drop
        # the connection.
        self._connections: set[asyncio.Task] = set()
        self.gateway: proxy_http.HttpGateway | None = None
        # The workspace id this mapping first resolved to; a later resolve to another id
        # halts the mapping (see _check_identity).
        self._pinned_workspace: str | None = None
        self.halted: str | None = None
        self._log = log.bind(mapping=mapping.label, local_port=mapping.local_port)

    async def listen(self) -> None:
        host = check_loopback(self.settings.bind)
        if self.mapping.kind == "http":
            self.gateway = proxy_http.HttpGateway(
                bind=host,
                port=self.mapping.local_port,
                provider=self.settings.upstream_auth,
                limits=self.settings.http_limits,
            )
        self._server = await asyncio.start_server(self._handle, host, self.mapping.local_port)
        self._log.info("proxy_listening", address=f"{host}:{self.mapping.local_port}")

    def start_link(self) -> str | None:
        """A fresh one-time exchange URL for an http mapping (None for tcp)."""
        return self.gateway.start_link() if self.gateway is not None else None

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

    def _needs_revalidation(self) -> bool:
        """A podman/docker target may have moved to a new host port without the forward
        noticing (an SSH forward stays up and drops connections). Check again before a
        connection that is the only one open, if the last one looked dead (upstream
        sent nothing) or the last resolve is older than ``revalidate_seconds``."""
        if self.target is None or self.target.kind == "ecs" or self.active > 1:
            return False
        age = asyncio.get_running_loop().time() - self._resolved_at
        return self._suspect or age >= self.settings.revalidate_seconds

    async def _resolve(self) -> Target:
        target = await self.resolver.resolve(self.mapping)
        self._resolved_at = asyncio.get_running_loop().time()
        self._suspect = False
        return target

    def _check_identity(self, target: Target) -> None:
        """A mapping is for one workspace. If a later resolve names a different one (the
        id the saved prefix matched is gone and another now matches, or the server was
        repointed), stop serving it rather than hand a client someone else's workspace."""
        if self._pinned_workspace is None:
            self._pinned_workspace = target.workspace_id
            return
        if target.workspace_id != self._pinned_workspace:
            self.halted = (
                f"workspace changed from {self._pinned_workspace} to {target.workspace_id}; "
                "restart `warren proxy run` after checking with `warren list`"
            )
            self._log.error(
                "proxy_workspace_identity_changed",
                expected=self._pinned_workspace,
                got=target.workspace_id,
            )
            self._stop_session("workspace_changed")
            raise ProxyError(f"mapping halted: {self.halted}")

    async def ensure_session(self) -> Session:
        """The live session, starting one (resolving the target afresh) when there is
        none, the last one's process has exited, or a podman/docker target's host port
        has moved. Concurrent callers share it."""
        async with self._lock:
            target: Target | None = None
            if self.session is not None and self.session.alive():
                if not self._needs_revalidation():
                    return self.session
                target = await self._resolve()
                self._check_identity(target)
                if self.target is not None and target.endpoint == self.target.endpoint:
                    return self.session
                self._stop_session("target_moved")
            if self.session is not None:
                self._log.warning("proxy_session_exited", task_arn=self.target.task_arn if self.target else None)
                self._stop_session("exited")
            if target is None:
                target = await self._resolve()
            self._check_identity(target)
            if self.target is not None and target.endpoint != self.target.endpoint:
                if target.kind == "ecs":
                    self._log.info("proxy_task_changed", old_task_arn=self.target.task_arn, task_arn=target.task_arn)
                else:
                    self._log.info("proxy_host_port_changed", old=self.target.endpoint, new=target.endpoint)
            self.target = target
            self.session = await self.forwarder.start(target, self.mapping.remote_port)
            self.sessions_started += 1
            self._log.info(
                "proxy_session_started",
                workspace_id=target.workspace_id,
                kind=target.kind,
                task_arn=target.task_arn or None,
                endpoint=target.endpoint,
                forward_port=self.session.local_port,
            )
            # The probe keeps an SSM session busy; an SSH forward or a direct
            # connection has no idle timeout to beat.
            if self.settings.keepalive_seconds > 0 and target.kind == "ecs":
                self._keepalive_task = asyncio.ensure_future(self._keepalive(self.session))
            return self.session

    async def _connect_upstream(self) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        if self.halted:
            raise ProxyError(f"mapping halted: {self.halted}")
        for attempt in range(2):
            session = await self.ensure_session()
            try:
                return await asyncio.open_connection(_session_host(session), session.local_port)
            except OSError as exc:
                # The forward is up as a process but not accepting: treat it as dead
                # and start over once (the task may have been replaced under it).
                self._log.warning("proxy_upstream_refused", error=str(exc), attempt=attempt + 1)
                async with self._lock:
                    if self.session is session:
                        self._stop_session("refused")
        if self.target is not None and self.target.kind != "ecs":
            raise ProxyError(
                f"nothing accepts connections at the workspace's published port ({self.target.endpoint} on "
                "the server host); is the workspace running?"
            )
        raise ProxyError("the SSM port-forward is not accepting connections")

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        task = asyncio.current_task()
        if task is not None:
            self._connections.add(task)
            task.add_done_callback(self._connections.discard)
        self.active += 1
        if self._idle_task is not None:
            self._idle_task.cancel()
            self._idle_task = None
        try:
            if self.gateway is not None:
                await self.gateway.serve(reader, writer, self._connect_upstream)
                return
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
            if await relay(reader, writer, up_reader, up_writer) == 0:
                # Upstream closed without a byte: what a forward to a moved or closed
                # host port looks like. The next connection checks the target first.
                self._suspect = True
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
        announce: Callable[[Mapping, str], None] | None = None,
    ) -> None:
        check_loopback(settings.bind)
        self.store = store
        self.resolver = resolver
        self.forwarder = forwarder
        self.settings = settings
        self.reload_seconds = reload_seconds
        # Called with (mapping, one-time URL) for http mappings; the URL carries a secret, so
        # it goes to the operator's terminal via this callback and is never logged.
        self.announce = announce
        # Mappings whose port could not be bound, with the reason. `warren proxy run` treats
        # any entry at startup as fatal so a client never talks to whatever holds the port.
        self.failed: dict[Mapping, str] = {}
        self.proxies: dict[Mapping, MappingProxy] = {}
        self._mtime: float | None = None

    async def reconcile(self) -> None:
        wanted = set(self.store.load())
        for mapping in [m for m in self.failed if m not in wanted]:
            del self.failed[mapping]
        for mapping in [m for m in self.proxies if m not in wanted]:
            await self.proxies.pop(mapping).close()
        for mapping in wanted - set(self.proxies):
            proxy = MappingProxy(mapping, self.resolver, self.forwarder, self.settings)
            try:
                await proxy.listen()
            except OSError as exc:
                log.error("proxy_listen_failed", mapping=mapping.label, local_port=mapping.local_port, error=str(exc))
                self.failed[mapping] = str(exc)
                continue
            self.failed.pop(mapping, None)
            self.proxies[mapping] = proxy
            self._announce(proxy)

    def _announce(self, proxy: MappingProxy) -> None:
        link = proxy.start_link()
        if link is not None and self.announce is not None:
            self.announce(proxy.mapping, link)

    def reissue_links(self) -> None:
        """Mint and announce a fresh one-time link for every http mapping."""
        for proxy in self.proxies.values():
            self._announce(proxy)

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
