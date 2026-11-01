"""`warren ssh-config` and `warren proxy stdio`: the Host block, its injection guards,
and the stdio relay over a (fake) SSM port-forward.

No AWS and no real ssh: the "forward" is an in-process TCP echo server and the
control plane is respx. Nothing reads or writes the operator's ~/.ssh.
"""

from __future__ import annotations

import os
import socket
import subprocess
import sys
import threading
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
import respx
from typer.testing import CliRunner

from warren_cli import dispatch, proxy, ssh_access
from warren_cli.config import WarrenCLIConfig
from warren_cli.main import app

runner = CliRunner()

_WS = "abc12345-aaaa-bbbb-cccc-ddddeeeeffff"
_TASK = "arn:aws:ecs:us-east-1:1:task/prod-cluster/task1111"
_CONFIG = (
    '[remotes.prodecs]\nruntime_type = "ecs"\necs_cluster = "prod-cluster"\n'
    'ecs_service = "warren-orchestrator"\naws_audience = "warren-prod"\n'
    '[remotes.homelab]\nruntime_type = "ssh"\nssh_host = "node2"\n'
)


def _config(tmp_path: Path) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(_CONFIG)
    return path


# ---------------------------------------------------------------------------
# Host block
# ---------------------------------------------------------------------------


def _directives(block: str) -> dict[str, str]:
    out = {}
    for line in block.splitlines():
        if line.startswith("    "):
            key, _, value = line.strip().partition(" ")
            out[key] = value
    return out


def test_host_block_proxies_over_ssm_and_pins_the_host_key_alias():
    block = ssh_access.render_ssh_config(server="prodecs", workspace_id=_WS, warren="/opt/bin/warren")
    assert "\nHost warren-abc12345\n" in block
    d = _directives(block)
    assert d["ProxyCommand"] == f"/opt/bin/warren proxy stdio --server prodecs {_WS} 2222"
    assert d["HostKeyAlias"] == f"warren-prodecs-{_WS}"
    assert d["User"] == "warren"
    assert d["Port"] == "2222"
    assert d["StrictHostKeyChecking"] == "accept-new"
    # The client never offers anything but a key, and forwards nothing by default.
    assert d["PreferredAuthentications"] == "publickey"
    assert d["PasswordAuthentication"] == "no"
    assert d["KbdInteractiveAuthentication"] == "no"
    assert d["ForwardAgent"] == "no"
    assert d["ForwardX11"] == "no"
    assert "IdentityFile" not in d


def test_host_block_with_identity_file_alias_and_config():
    block = ssh_access.render_ssh_config(
        server="prodecs", workspace_id=_WS, host="my-ws", identity_file="~/.ssh/warren_ed25519",
        warren="/opt/bin/warren", config="/home/me/.warren/config.toml",
    )
    assert "\nHost my-ws\n" in block
    d = _directives(block)
    assert d["IdentityFile"] == "~/.ssh/warren_ed25519"
    assert d["IdentitiesOnly"] == "yes"
    assert d["ProxyCommand"] == (
        f"/opt/bin/warren proxy stdio --config /home/me/.warren/config.toml --server prodecs {_WS} 2222"
    )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX quoting")
def test_proxy_command_quotes_paths_and_escapes_percent():
    cmd = ssh_access.proxy_command(server="prodecs", workspace_id=_WS, warren="/Users/a b/100%/warren")
    assert cmd.startswith("'/Users/a b/100%%/warren' proxy stdio ")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"server": "prod\n    ProxyCommand evil", "workspace_id": _WS},
        {"server": "prodecs", "workspace_id": f"{_WS}\nHost *"},
        {"server": "prodecs", "workspace_id": "-oProxyCommand=evil"},
        {"server": "prodecs", "workspace_id": "a b"},
        {"server": "prodecs", "workspace_id": _WS, "host": "x\n    ProxyCommand evil"},
        {"server": "prodecs", "workspace_id": _WS, "host": "*"},
        {"server": "prodecs", "workspace_id": _WS, "identity_file": "k\n    ProxyCommand evil"},
    ],
)
def test_nothing_can_inject_lines_or_options_into_the_block(kwargs):
    with pytest.raises(ssh_access.SshAccessError):
        ssh_access.render_ssh_config(warren="/opt/bin/warren", **kwargs)


def test_ssh_config_cli_no_resolve(tmp_path, monkeypatch):
    monkeypatch.setattr(ssh_access, "warren_command", lambda: "/opt/bin/warren")
    cfg = _config(tmp_path)
    result = runner.invoke(app, ["ssh-config", _WS, "--server", "prodecs", "--no-resolve", "--config", str(cfg)])
    assert result.exit_code == 0, result.output
    d = _directives(result.stdout)
    assert d["ProxyCommand"] == f"/opt/bin/warren proxy stdio --config {cfg.resolve()} --server prodecs {_WS} 2222"
    assert d["HostKeyAlias"] == f"warren-prodecs-{_WS}"


def test_ssh_config_cli_resolves_a_prefix_to_the_full_id(tmp_path, monkeypatch):
    monkeypatch.setattr(ssh_access, "warren_command", lambda: "/opt/bin/warren")
    monkeypatch.setattr(dispatch, "start_orchestrator_port_forward", lambda *a, **kw: (MagicMock(), 54329))
    with respx.mock(base_url="http://127.0.0.1:54329") as m:
        m.get("/workspaces").mock(
            return_value=httpx.Response(200, json=[{"workspace_id": _WS, "status": "stopped", "container_id": None}])
        )
        result = runner.invoke(app, ["ssh-config", "abc1", "--server", "prodecs", "--config", str(_config(tmp_path))])
    assert result.exit_code == 0, result.output
    # A stopped workspace still gets a block: the ProxyCommand resolves the task at connect time.
    assert _directives(result.stdout)["HostKeyAlias"] == f"warren-prodecs-{_WS}"


def test_ssh_config_needs_server_when_several_remotes(tmp_path):
    result = runner.invoke(app, ["ssh-config", _WS, "--no-resolve", "--config", str(_config(tmp_path))])
    assert result.exit_code == 1
    assert "pass --server" in result.output


# ---------------------------------------------------------------------------
# podman/docker servers
# ---------------------------------------------------------------------------

_CONN = {
    "host": "node2.lan",
    "port": 30007,
    "user": "warren",
    "break_glass_user": "warren-shell",
    "private_key": "-----BEGIN OPENSSH PRIVATE KEY-----\nZmFrZQ==\n-----END OPENSSH PRIVATE KEY-----\n",
    "session_id": None,
}


def _remote(**kw):
    from warren_cli.config import RemoteProfile  # noqa: PLC0415

    return RemoteProfile(**kw)


def _podman_block(remote, **kw) -> dict[str, str]:
    block = ssh_access.render_podman_ssh_config(
        server="homelab", workspace_id=_WS, remote=remote, connection=_CONN, identity_file="/k/id", **kw
    )
    assert "ProxyCommand warren" not in block
    return _directives(block)


def test_podman_block_jumps_through_the_ssh_remotes_host():
    d = _podman_block(_remote(runtime_type="ssh", ssh_host="node2"))
    assert d["HostName"] == "127.0.0.1" and d["Port"] == "30007"
    assert d["ProxyJump"] == "node2"
    assert d["User"] == "warren-shell"  # the shell user, not the ForceCommand one
    assert d["HostKeyAlias"] == f"warren-homelab-{_WS}"
    assert d["IdentityFile"] == "/k/id" and d["IdentitiesOnly"] == "yes"
    assert d["PasswordAuthentication"] == "no"


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX quoting")
def test_podman_block_passes_the_remotes_ssh_key_like_the_cli_forward():
    d = _podman_block(_remote(runtime_type="ssh", ssh_host="admin@node2", ssh_key_path="/keys/id homelab"))
    assert "ProxyJump" not in d
    assert d["ProxyCommand"] == "ssh -i '/keys/id homelab' -o BatchMode=yes -W %h:%p -- admin@node2"


def test_podman_block_for_a_local_server_connects_directly():
    d = _podman_block(_remote(runtime_type="http", url="http://127.0.0.1:8420"))
    assert "ProxyJump" not in d and "ProxyCommand" not in d
    assert d["HostName"] == "127.0.0.1" and d["Port"] == "30007"


def test_podman_block_for_a_remote_http_server_jumps_through_its_advertised_host():
    d = _podman_block(_remote(runtime_type="http", url="https://warren.lan:8420"))
    assert d["ProxyJump"] == "node2.lan"


def test_podman_block_jump_and_user_overrides():
    remote = _remote(runtime_type="ssh", ssh_host="node2")
    assert _podman_block(remote, jump="bastion")["ProxyJump"] == "bastion"
    d = _podman_block(remote, jump="", user="warren")
    assert "ProxyJump" not in d and d["User"] == "warren"


@pytest.mark.parametrize("jump", ["-oProxyCommand=evil", "a b", "x\n    ProxyCommand evil", "%h"])
def test_podman_block_rejects_unsafe_jump_hosts(jump):
    with pytest.raises(ssh_access.SshAccessError):
        _podman_block(_remote(runtime_type="ssh", ssh_host="node2"), jump=jump)


def test_podman_block_needs_a_published_port():
    with pytest.raises(ssh_access.SshAccessError, match="no SSH port"):
        ssh_access.render_podman_ssh_config(
            server="homelab", workspace_id=_WS, remote=_remote(runtime_type="ssh", ssh_host="node2"),
            connection={**_CONN, "port": None}, identity_file="/k/id",
        )


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_saved_key_is_owner_only_and_replaced(tmp_path):
    path = tmp_path / "ssh" / "homelab-ws"
    ssh_access.save_private_key(path, "first")
    ssh_access.save_private_key(path, "second\n")
    assert path.read_text() == "second\n"
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700


def test_ssh_config_cli_podman_mints_saves_and_prints(tmp_path, monkeypatch):
    monkeypatch.setattr(dispatch, "start_ssh_port_forward", lambda *a, **kw: (MagicMock(), 54331))
    with respx.mock(base_url="http://127.0.0.1:54331") as m:
        m.get("/workspaces").mock(
            return_value=httpx.Response(200, json=[{"workspace_id": _WS, "status": "stopped", "container_id": "c1"}])
        )
        connect = m.post(f"/workspaces/{_WS}/connect").mock(return_value=httpx.Response(200, json=_CONN))
        result = runner.invoke(app, ["ssh-config", "abc1", "--server", "homelab", "--config", str(_config(tmp_path))])
    assert result.exit_code == 0, result.output
    assert connect.called
    key = Path.home() / ".warren" / "ssh" / f"homelab-{_WS}"
    assert key.read_text() == _CONN["private_key"]
    d = _directives(result.stdout)
    assert d["IdentityFile"] == str(key)
    assert d["ProxyJump"] == "node2"
    assert d["HostKeyAlias"] == f"warren-homelab-{_WS}"
    # stdout is only the block (it gets appended to ~/.ssh/config); the note goes to stderr.
    assert "BEGIN OPENSSH" not in result.stdout
    assert result.stdout.lstrip().startswith("# warren workspace")
    assert "saved to" in result.stderr


def test_ssh_config_cli_podman_not_owner(tmp_path, monkeypatch):
    monkeypatch.setattr(dispatch, "start_ssh_port_forward", lambda *a, **kw: (MagicMock(), 54332))
    with respx.mock(base_url="http://127.0.0.1:54332") as m:
        m.post(f"/workspaces/{_WS}/connect").mock(return_value=httpx.Response(403, json={"detail": "not workspace owner"}))
        result = runner.invoke(
            app, ["ssh-config", _WS, "--server", "homelab", "--no-resolve", "--config", str(_config(tmp_path))]
        )
    assert result.exit_code == 1
    assert "not your workspace" in result.output
    assert not (Path.home() / ".warren" / "ssh" / f"homelab-{_WS}").exists()


# ---------------------------------------------------------------------------
# stdio relay
# ---------------------------------------------------------------------------


class EchoServer:
    """A loopback TCP server standing in for the SSM forward's local end. Prefixes
    each reply with a banner, echoes, then closes after the client half-closes."""

    def __init__(self) -> None:
        self.sock = socket.create_server(("127.0.0.1", 0))
        self.port = self.sock.getsockname()[1]
        self.accepted = 0
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self) -> None:
        while True:
            try:
                conn, _ = self.sock.accept()
            except OSError:
                return
            self.accepted += 1
            with conn:
                conn.sendall(b"SSH-2.0-fake\r\n")
                while data := conn.recv(65536):
                    conn.sendall(data)

    def close(self) -> None:
        self.sock.close()


def _run_relay(server_port: int, payload: bytes, **kwargs) -> bytes:
    """Feed ``payload`` on a pipe as stdin and collect what the relay writes to stdout."""
    in_r, in_w = os.pipe()
    out_r, out_w = os.pipe()
    received = bytearray()

    def reader() -> None:
        while chunk := os.read(out_r, 65536):
            received.extend(chunk)

    def writer() -> None:
        view = memoryview(payload)
        while view:
            view = view[os.write(in_w, view):]
        os.close(in_w)

    t = threading.Thread(target=reader, daemon=True)
    t.start()
    threading.Thread(target=writer, daemon=True).start()
    try:
        if "relay" in kwargs:
            kwargs.pop("relay")(in_r, out_w)
        else:
            with socket.create_connection(("127.0.0.1", server_port)) as s:
                ssh_access.relay_stdio(s, in_r, out_w)
    finally:
        os.close(out_w)
        t.join(timeout=5)
        os.close(in_r)
        os.close(out_r)
    return bytes(received)


def test_relay_copies_both_ways_and_drains_after_stdin_eof():
    srv = EchoServer()
    try:
        payload = os.urandom(300_000)
        out = _run_relay(srv.port, payload)
        assert out == b"SSH-2.0-fake\r\n" + payload
    finally:
        srv.close()


class _Resolver:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.calls: list[proxy.Mapping] = []

    async def resolve(self, mapping: proxy.Mapping) -> proxy.Target:
        self.calls.append(mapping)
        if self.error:
            raise self.error
        return proxy.Target(workspace_id=_WS, cluster="prod-cluster", task_arn=_TASK)


def _cfg(tmp_path: Path) -> WarrenCLIConfig:
    return WarrenCLIConfig.load(_config(tmp_path))


def test_run_stdio_forwards_to_the_task_and_stops_the_forward(tmp_path):
    srv = EchoServer()
    resolver = _Resolver()
    started: list[tuple] = []
    proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])

    def start_forward(cluster, task_arn, port):
        started.append((cluster, task_arn, port))
        return proc, srv.port

    try:
        out = _run_relay(
            srv.port, b"hello",
            relay=lambda i, o: ssh_access.run_stdio(
                _cfg(tmp_path), "prodecs", "abc1", 2222,
                resolver=resolver, start_forward=start_forward, in_fd=i, out_fd=o,
            ),
        )
        assert out == b"SSH-2.0-fake\r\nhello"
        assert started == [("prod-cluster", _TASK, 2222)]
        assert resolver.calls[0].workspace == "abc1" and resolver.calls[0].remote_port == 2222
        assert proc.wait(timeout=10) is not None  # the SSM process is stopped afterwards
    finally:
        if proc.poll() is None:
            proc.kill()
        srv.close()


def test_run_stdio_reports_an_unavailable_workspace_without_starting_a_forward(tmp_path):
    resolver = _Resolver(proxy.WorkspaceUnavailable("workspace abc12345 is stopped; start it with `warren connect`"))

    def start_forward(*_a):
        raise AssertionError("no forward for a stopped workspace")

    with pytest.raises(proxy.WorkspaceUnavailable, match="is stopped"):
        ssh_access.run_stdio(_cfg(tmp_path), "prodecs", _WS, 2222, resolver=resolver, start_forward=start_forward)


def test_run_stdio_maps_expired_sso_on_the_forward(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "warren-dev")

    def start_forward(*_a):
        raise RuntimeError("SSM port-forward to workspace exited early: Error when retrieving token from sso: Token has expired and refresh failed")

    with pytest.raises(proxy.AwsCredentialsExpired, match="aws sso login --profile warren-dev"):
        ssh_access.run_stdio(_cfg(tmp_path), "prodecs", _WS, 2222, resolver=_Resolver(), start_forward=start_forward)


def test_run_stdio_refuses_non_ecs_remotes_and_bad_ports(tmp_path):
    with pytest.raises(proxy.ProxyError, match="only reaches ECS"):
        ssh_access.run_stdio(_cfg(tmp_path), "homelab", _WS, 2222, resolver=_Resolver())
    with pytest.raises(proxy.ProxyError, match="not a TCP port"):
        ssh_access.run_stdio(_cfg(tmp_path), "prodecs", _WS, 0, resolver=_Resolver())


def test_proxy_stdio_cli_reports_errors_on_stderr_only(tmp_path, monkeypatch):
    def unavailable(*_a, **_kw):
        raise proxy.WorkspaceUnavailable("workspace abc12345 is stopped")

    monkeypatch.setattr(ssh_access, "run_stdio", unavailable)
    result = runner.invoke(app, ["proxy", "stdio", _WS, "2222", "--config", str(_config(tmp_path))])
    assert result.exit_code == 1
    assert result.stdout == ""
    assert "is stopped" in result.stderr


_HANGUP_CHILD = r"""
import socket, subprocess, sys, threading
from warren_cli import proxy, ssh_access
from warren_cli.config import WarrenCLIConfig

srv = socket.create_server(("127.0.0.1", 0))
held = []
threading.Thread(target=lambda: held.append(srv.accept()), daemon=True).start()

class R:
    async def resolve(self, m):
        return proxy.Target(workspace_id="ws", cluster="c", task_arn="arn:aws:ecs:r:1:task/c/t")

def fwd(cluster, task, port):
    p = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(120)"])
    print(p.pid, flush=True)
    return p, srv.getsockname()[1]

ssh_access.run_stdio(WarrenCLIConfig.load(sys.argv[1]), "prodecs", "ws", 2222, resolver=R(), start_forward=fwd,
                     in_fd=0, out_fd=2)
"""


@pytest.mark.skipif(sys.platform == "win32", reason="SIGHUP is POSIX")
def test_hangup_from_ssh_stops_the_ssm_forward(tmp_path):
    import signal as _signal  # noqa: PLC0415
    import time as _time  # noqa: PLC0415

    child = subprocess.Popen(
        [sys.executable, "-c", _HANGUP_CHILD, str(_config(tmp_path))],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True,
    )
    try:
        forward_pid = int(child.stdout.readline())
        _time.sleep(0.5)  # relaying now, blocked on both sides
        child.send_signal(_signal.SIGHUP)
        assert child.wait(timeout=15) == 128 + _signal.SIGHUP
        deadline = _time.monotonic() + 10
        while _time.monotonic() < deadline:
            try:
                os.kill(forward_pid, 0)
            except ProcessLookupError:
                break
            # A terminated child of the exited process may linger as a zombie until reaped by init.
            try:
                if os.waitpid(forward_pid, os.WNOHANG) != (0, 0):
                    break
            except ChildProcessError:
                pass
            _time.sleep(0.1)
        else:
            os.kill(forward_pid, _signal.SIGKILL)
            pytest.fail("the SSM forward process outlived its ProxyCommand")
    finally:
        if child.poll() is None:
            child.kill()
