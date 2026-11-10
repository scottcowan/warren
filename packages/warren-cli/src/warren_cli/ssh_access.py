"""SSH into warren workspaces for editor remoting (VS Code, Cursor, JetBrains Gateway).

ECS (warren-ecs-ssh-base): the image runs an sshd on the task's own ``127.0.0.1:2222``
(as the workspace user, key-only). A Fargate task has no inbound path to it, so the
client reaches it through an SSM port-forward, the same ``AWS-StartPortForwardingSession``
to ``ecs:<cluster>_<task>_<runtime-id>`` that ``warren tunnel`` and ``warren proxy`` use:

- ``warren proxy stdio <ws> 2222`` resolves the workspace's current task through the
  control plane, starts that forward on an ephemeral loopback port and pipes
  stdin/stdout through it, which is what an ssh ``ProxyCommand`` needs;
- ``warren ssh-config <ws>`` prints the ``~/.ssh/config`` Host block that uses it.

podman/docker servers: the workspace's sshd port is published on the server host's
127.0.0.1 (``WARREN_SSH_ACCESS_ENABLED``, ``WARREN_SSH_PUBLISH_HOST``), and the server's
``POST /workspaces/{id}/connect`` mints a per-workspace key and injects its public half.
``warren ssh-config`` calls that, keeps the private key under ``~/.warren/ssh/`` and
prints a block that jumps through the server host (or connects directly to a local one).

Both pin ``HostKeyAlias`` to ``warren-<server>-<workspace id>``, so a workspace's
known_hosts entry is the same whatever task, forward port or route reaches it.

See docs/workspace-ssh.md.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from typing import Any, Callable, Iterator
from urllib.parse import urlsplit

from warren_common.fileperms import restrict_to_owner

from . import proxy

SSH_PORT = 2222
SSH_USER = "warren"
_CHUNK = 64 * 1024

# Everything interpolated into the Host block is checked against these, so nothing a
# server or a user passes can add a line or an option to the config.
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")

StartForward = Callable[[str, str, int], "tuple[subprocess.Popen, int]"]


class SshAccessError(Exception):
    """A failure meant for the operator (printed on stderr; ssh shows it)."""


def check_name(kind: str, value: str) -> str:
    if not _NAME_RE.fullmatch(value or ""):
        raise SshAccessError(f"{kind} {value!r} must match {_NAME_RE.pattern}")
    return value


def host_key_alias(server: str, workspace_id: str) -> str:
    """The known_hosts name for a workspace's sshd: stable for the workspace's life,
    whatever task or local forward port it is reached through."""
    # "+" is outside _NAME_RE, so (server, workspace) pairs can't collide ("a-b"+"c" vs "a"+"b-c").
    return f"warren-{check_name('server', server)}+{check_name('workspace id', workspace_id)}"


def warren_command() -> str:
    """How a ProxyCommand runs this CLI: its absolute path when it is on PATH."""
    return shutil.which("warren") or "warren"


def _quote(arg: str) -> str:
    # ssh expands %-tokens in ProxyCommand; a literal % is written %%.
    if sys.platform == "win32":  # ssh runs ProxyCommand without a shell there
        quoted = f'"{arg}"' if any(c in arg for c in ' \t"') else arg
    else:
        quoted = shlex.quote(arg)
    return quoted.replace("%", "%%")


def proxy_command(
    *, server: str, workspace_id: str, port: int = SSH_PORT, warren: str | None = None, config: str | None = None
) -> str:
    argv = [warren or warren_command()]
    if config:
        argv += ["proxy", "stdio", "--config", config]
    else:
        argv += ["proxy", "stdio"]
    argv += ["--server", check_name("server", server), check_name("workspace id", workspace_id), str(port)]
    return " ".join(_quote(a) for a in argv)


def _host_block(
    *,
    comment: list[str],
    host: str,
    hostname: str,
    port: int,
    user: str,
    route: list[str],
    server: str,
    workspace_id: str,
    identity_file: str | None,
) -> str:
    lines = [*(f"# {c}" for c in comment), f"Host {check_name('host alias', host)}",
             f"    HostName {hostname}", f"    Port {int(port)}", f"    User {check_name('user', user)}"]
    lines += [f"    {r}" for r in route]
    lines += [f"    HostKeyAlias {host_key_alias(server, workspace_id)}", "    StrictHostKeyChecking accept-new"]
    if identity_file:
        if any(c in identity_file for c in "\r\n\"") or not identity_file.strip():
            raise SshAccessError(f"identity file {identity_file!r} can't be written into an ssh config")
        value = f'"{identity_file}"' if " " in identity_file else identity_file
        lines += [f"    IdentityFile {value}", "    IdentitiesOnly yes"]
    lines += [
        "    PreferredAuthentications publickey",
        "    PasswordAuthentication no",
        "    KbdInteractiveAuthentication no",
        "    ForwardAgent no",
        "    ForwardX11 no",
        "    ServerAliveInterval 30",
        "    ServerAliveCountMax 4",
    ]
    return "\n".join(lines) + "\n"


def render_ssh_config(
    *,
    server: str,
    workspace_id: str,
    host: str | None = None,
    identity_file: str | None = None,
    warren: str | None = None,
    config: str | None = None,
    port: int = SSH_PORT,
) -> str:
    """The ``~/.ssh/config`` Host block for an ECS workspace (warren-ecs-ssh-base)."""
    pc = proxy_command(server=server, workspace_id=workspace_id, port=port, warren=warren, config=config)
    return _host_block(
        comment=[
            f"warren workspace {workspace_id} on {server}: its sshd (warren-ecs-ssh-base) on the",
            f"task's 127.0.0.1:{port}, reached over SSM. Needs the aws CLI, session-manager-plugin",
            "and ssm:StartSession on the task. See docs/workspace-ssh.md.",
        ],
        host=host or f"warren-{workspace_id[:8]}",
        hostname="127.0.0.1",
        port=port,
        user=SSH_USER,
        route=[f"ProxyCommand {pc}"],
        server=server,
        workspace_id=workspace_id,
        identity_file=identity_file,
    )


# ---------------------------------------------------------------------------
# podman/docker servers: the workspace's sshd port, published on the server host's
# 127.0.0.1, with the per-connection key POST /workspaces/{id}/connect mints
# ---------------------------------------------------------------------------

# An ssh destination (`host`, `user@host`, `user@[::1]`, an ssh_config alias); never an option.
_JUMP_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.@:\[\]-]{0,252}$")
_LOOPBACK_NAMES = {"localhost", "127.0.0.1", "::1"}


def check_jump(value: str) -> str:
    if not _JUMP_RE.fullmatch(value or ""):
        raise SshAccessError(f"jump host {value!r} is not a plain ssh destination")
    return value


def server_host_route(remote: Any, advertised_host: str, jump: str | None = None) -> list[str]:
    """How the client reaches the server host's loopback, where the workspace's SSH port
    is published (``WARREN_SSH_PUBLISH_HOST``, 127.0.0.1 by default).

    - ``jump`` given: through that host (``""`` means connect directly);
    - an ``ssh`` remote: through its ``ssh_host``, the same SSH access the CLI already
      uses to reach that server's control plane; with ``ssh_key_path`` set, as a
      ProxyCommand passing that key, like ``dispatch.start_ssh_port_forward``;
    - an ``http`` remote on this machine (loopback URL): directly;
    - any other ``http`` remote: through the host the server advertises in its connect
      response (``WARREN_SSH_ADVERTISED_HOST``, else its server id).
    """
    if jump is not None:
        return [f"ProxyJump {check_jump(jump)}"] if jump else []
    if remote.runtime_type == "ssh":
        target = check_jump(remote.ssh_host)
        if remote.ssh_key_path:
            key = os.path.expanduser(remote.ssh_key_path)
            argv = ["ssh", "-i", key, "-o", "BatchMode=yes", "-W", "%h:%p", "--", target]
            # %h/%p stay ssh tokens here; only the key path is quoted (and %-escaped).
            return ["ProxyCommand " + " ".join(a if a in ("%h:%p",) else _quote(a) for a in argv)]
        return [f"ProxyJump {target}"]
    url_host = urlsplit(remote.url or "").hostname or ""
    if url_host in _LOOPBACK_NAMES:
        return []
    return [f"ProxyJump {check_jump(advertised_host)}"]


def render_podman_ssh_config(
    *,
    server: str,
    workspace_id: str,
    remote: Any,
    connection: dict,
    identity_file: str,
    host: str | None = None,
    user: str | None = None,
    jump: str | None = None,
) -> str:
    """The Host block for a podman/docker-server workspace, from its connect response."""
    port = connection.get("port")
    if not isinstance(port, int) or not 1 <= port <= 65535:
        raise SshAccessError(f"the server returned no SSH port for workspace {workspace_id[:8]}")
    return _host_block(
        comment=[
            f"warren workspace {workspace_id} on {server}: the workspace's sshd, published on the",
            f"server host's 127.0.0.1:{port}, with a key minted for this config (another",
            "`warren ssh-config` for this workspace replaces it). See docs/workspace-ssh.md.",
        ],
        host=host or f"warren-{workspace_id[:8]}",
        hostname="127.0.0.1",
        port=port,
        user=user or str(connection.get("break_glass_user") or connection.get("user") or ""),
        route=server_host_route(remote, str(connection.get("host") or ""), jump),
        server=server,
        workspace_id=workspace_id,
        identity_file=identity_file,
    )


def key_path(server: str, workspace_id: str) -> Path:
    """Where `warren ssh-config` keeps a podman/docker workspace's minted key."""
    return Path.home() / ".warren" / "ssh" / f"{check_name('server', server)}+{check_name('workspace id', workspace_id)}"


def _legacy_key_path(path: Path) -> Path | None:
    """The pre-"+" name of ``path`` (``server-workspace``, ambiguous), if it has one."""
    server, sep, workspace = path.name.partition("+")
    return path.with_name(f"{server}-{workspace}") if sep else None


def save_private_key(path: Path, private_key: str) -> None:
    """Write ``private_key`` owner-only (0600 in a 0700 directory), replacing any old one."""
    path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(path.parent, 0o700)
    # mkstemp: unique, O_EXCL, 0600 -- no fixed name another process could pre-create.
    fd, tmp_name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w") as f:
            f.write(private_key if private_key.endswith("\n") else private_key + "\n")
        restrict_to_owner(tmp)
        os.replace(tmp, path)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp.unlink()
        raise
    # The ambiguous old name may belong to a different server/workspace pair; its key is
    # no longer referenced by any config we print, so drop it.
    legacy = _legacy_key_path(path)
    if legacy is not None and legacy.is_file() and not legacy.is_symlink():
        with contextlib.suppress(OSError):
            legacy.unlink()


async def _control_plane(remote: Any, server: str, method: str, path: str) -> Any:
    from .client import make_remote_client  # noqa: PLC0415

    try:
        async with make_remote_client(remote, timeout=60.0) as c:
            r = await c.request(method, path)
    except Exception as exc:  # tunnel or HTTP transport failure
        raise proxy.credentials_error(str(exc)) or SshAccessError(
            f"control plane for {server!r} unreachable: {exc}"
        ) from exc
    if r.status_code == 403:
        raise SshAccessError(f"{server!r}: not your workspace (HTTP 403)")
    if r.status_code == 404:
        raise SshAccessError(f"{server!r}: workspace not found (HTTP 404)")
    if not r.is_success:
        raise SshAccessError(f"control plane for {server!r} answered HTTP {r.status_code}: {r.text[:200]}")
    return r.json()


async def match_remote_workspace(remote: Any, server: str, workspace: str) -> str:
    """The full id of ``workspace`` (an id or a unique prefix) on ``remote``."""
    rows = await _control_plane(remote, server, "GET", "/workspaces")
    return str(proxy.match_workspace(rows, workspace)["workspace_id"])


async def resolve_workspace_id(cfg: Any, server: str, workspace: str) -> str:
    """The full id of ``workspace`` (an id or a unique prefix) on an ECS remote."""
    return await match_remote_workspace(proxy.remote_for(cfg, server), server, workspace)


async def issue_connection(remote: Any, server: str, workspace_id: str) -> dict:
    """``POST /workspaces/{id}/connect``: (re)starts the workspace if needed, mints a
    fresh key for it (the previous one stops working) and returns host/port/users and
    the private key, once."""
    check_name("workspace id", workspace_id)
    return await _control_plane(remote, server, "POST", f"/workspaces/{workspace_id}/connect")


# ---------------------------------------------------------------------------
# stdio relay (ProxyCommand)
# ---------------------------------------------------------------------------


def relay_stdio(sock: socket.socket, in_fd: int, out_fd: int) -> None:
    """Copy ``in_fd`` to ``sock`` and ``sock`` to ``out_fd`` until the remote side
    closes. EOF on ``in_fd`` is passed on as a half-close, and the far side's output
    is still drained after it."""

    def upstream() -> None:
        try:
            while data := os.read(in_fd, _CHUNK):
                sock.sendall(data)
        except OSError:
            pass
        finally:
            try:
                sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    threading.Thread(target=upstream, name="warren-stdio-up", daemon=True).start()
    try:
        while data := sock.recv(_CHUNK):
            view = memoryview(data)
            while view:
                view = view[os.write(out_fd, view):]
    except OSError:
        pass


def _stop(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()


def run_stdio(
    cfg: Any,
    server: str,
    workspace: str,
    remote_port: int,
    *,
    resolver: proxy.Resolver | None = None,
    start_forward: StartForward | None = None,
    in_fd: int = 0,
    out_fd: int = 1,
) -> None:
    """Resolve ``workspace``'s task, forward to its ``remote_port`` over SSM and relay
    stdio through the forward until either side closes. Raises ``proxy.ProxyError``
    (incl. ``WorkspaceUnavailable``/``AwsCredentialsExpired``) for the operator."""
    if not 1 <= remote_port <= 65535:
        raise proxy.ProxyError(f"remote port {remote_port} is not a TCP port")
    remote = proxy.remote_for(cfg, server)
    # `warren proxy` itself also reaches podman/docker remotes (published loopback
    # ports), but this relay is an SSM port-forward: ECS only. podman/docker
    # workspaces get a ProxyJump/ProxyCommand route from `warren ssh-config` instead.
    if remote.runtime_type != "ecs":
        raise proxy.ProxyError(
            f"remote {server!r} is runtime_type {remote.runtime_type!r}: `warren proxy stdio` only reaches ECS "
            "workspaces (over SSM); for podman/docker workspaces use `warren ssh-config`, which routes "
            "through the server host"
        )
    resolver = resolver or proxy.ControlPlaneResolver(cfg)
    mapping = proxy.Mapping(server=server, workspace=workspace, remote_port=remote_port, local_port=0)
    target = asyncio.run(resolver.resolve(mapping))
    if start_forward is None:
        from . import dispatch  # noqa: PLC0415

        start_forward = dispatch.start_workspace_port_forward
    # ssh sends its ProxyCommand SIGHUP when the session ends (SIGTERM from editors that
    # stop it): turn those into an exit that runs the finally below, so the `aws ssm`
    # process is stopped rather than orphaned.
    with _exit_on_hangup():
        try:
            proc, port = start_forward(target.cluster, target.task_arn, remote_port)
        except RuntimeError as exc:
            raise proxy.credentials_error(str(exc)) or proxy.ProxyError(str(exc)) from exc
        _relay_through(proc, port, in_fd, out_fd)


@contextlib.contextmanager
def _exit_on_hangup() -> Iterator[None]:
    if threading.current_thread() is not threading.main_thread():
        yield
        return

    def _exit(signum: int, _frame: Any) -> None:
        raise SystemExit(128 + signum)

    signals = [s for s in (getattr(signal, "SIGHUP", None), signal.SIGTERM) if s is not None]
    previous = {s: signal.signal(s, _exit) for s in signals}
    try:
        yield
    finally:
        for s, handler in previous.items():
            signal.signal(s, handler)


def _relay_through(proc: subprocess.Popen, port: int, in_fd: int, out_fd: int) -> None:
    try:
        try:
            sock = socket.create_connection((proxy.LOOPBACK_HOST, port), timeout=10)
        except OSError as exc:
            raise proxy.ProxyError(f"the SSM port-forward is not accepting connections: {exc}") from exc
        with sock:
            sock.settimeout(None)
            relay_stdio(sock, in_fd, out_fd)
    finally:
        _stop(proc)
