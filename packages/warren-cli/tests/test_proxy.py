"""`warren proxy`: mapping store, loopback-only listeners, lazy shared SSM
sessions, relay, idle close, re-resolution and error paths.

No AWS: sessions come from a fake forwarder (an in-process echo server per
"SSM session") or, for the real SsmForwarder, a fake `aws` executable on PATH.
"""

from __future__ import annotations

import asyncio
import json
import os
import stat
import sys
import textwrap
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import pytest
import respx
from structlog.testing import capture_logs
from typer.testing import CliRunner

from warren_cli import dispatch, proxy
from warren_cli.config import WarrenCLIConfig
from warren_cli.main import app

runner = CliRunner()
posix_only = pytest.mark.skipif(sys.platform == "win32", reason="fake `aws` is a POSIX shebang script")

_WS = "abc12345-aaaa-bbbb-cccc-ddddeeeeffff"
_TASK1 = "arn:aws:ecs:us-east-1:1:task/prod-cluster/task1111"
_TASK2 = "arn:aws:ecs:us-east-1:1:task/prod-cluster/task2222"

_CONFIG = (
    '[remotes.prodecs]\nruntime_type = "ecs"\necs_cluster = "prod-cluster"\n'
    'ecs_service = "warren-orchestrator"\naws_audience = "warren-prod"\n'
    '[remotes.homelab]\nruntime_type = "ssh"\nssh_host = "node2"\n'
)


def _config(tmp_path: Path, extra: str = "") -> Path:
    path = tmp_path / "config.toml"
    path.write_text(_CONFIG + extra)
    return path


# ---------------------------------------------------------------------------
# fakes
# ---------------------------------------------------------------------------


async def _echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
        writer.write_eof()
    except (ConnectionError, OSError):
        pass
    finally:
        writer.close()


class FakeSession:
    """Stands in for one `aws ssm start-session`: a local echo server."""

    def __init__(self, target: proxy.Target) -> None:
        self.target = target
        self.accepted = 0
        self.stopped = False
        self._dead = False
        self._server: asyncio.AbstractServer | None = None
        self._writers: list[asyncio.StreamWriter] = []
        self.local_port = 0

    async def start(self) -> None:
        async def handle(r, w):
            self.accepted += 1
            self._writers.append(w)
            await _echo(r, w)

        self._server = await asyncio.start_server(handle, "127.0.0.1", 0)
        self.local_port = self._server.sockets[0].getsockname()[1]

    def alive(self) -> bool:
        return not (self._dead or self.stopped)

    def die(self) -> None:
        """The SSM process exited: listener and every open stream go away."""
        self._dead = True
        assert self._server is not None
        self._server.close()
        for w in self._writers:
            w.close()

    def stop(self) -> None:
        self.stopped = True
        if self._server is not None:
            self._server.close()
        for w in self._writers:
            w.close()


class FakeForwarder:
    def __init__(self, error: Exception | None = None) -> None:
        self.sessions: list[FakeSession] = []
        self.error = error

    async def start(self, target: proxy.Target, remote_port: int) -> FakeSession:
        await asyncio.sleep(0.05)  # a real session takes a while; lets concurrent callers pile up
        if self.error is not None:
            raise self.error
        session = FakeSession(target)
        await session.start()
        self.sessions.append(session)
        return session


class FakeResolver:
    def __init__(self, *task_arns: str, error: Exception | None = None) -> None:
        self.task_arns = list(task_arns)
        self.calls = 0
        self.error = error

    async def resolve(self, mapping: proxy.Mapping) -> proxy.Target:
        self.calls += 1
        if self.error is not None:
            raise self.error
        arn = self.task_arns[min(self.calls, len(self.task_arns)) - 1]
        return proxy.Target(workspace_id=_WS, cluster="prod-cluster", task_arn=arn)


def _free_port() -> int:
    return dispatch._free_local_port()


def _mapping(port: int | None = None) -> proxy.Mapping:
    return proxy.Mapping(server="prodecs", workspace=_WS[:8], remote_port=3773, local_port=port or _free_port())


async def _started(resolver, forwarder, **settings) -> proxy.MappingProxy:
    mp = proxy.MappingProxy(_mapping(), resolver, forwarder, proxy.ProxySettings(**settings))
    await mp.listen()
    return mp


async def _roundtrip(port: int, payload: bytes) -> bytes:
    r, w = await asyncio.open_connection("127.0.0.1", port)
    w.write(payload)
    await w.drain()
    w.write_eof()
    data = await asyncio.wait_for(r.read(), timeout=5)
    w.close()
    return data


# ---------------------------------------------------------------------------
# mapping store
# ---------------------------------------------------------------------------


def test_store_picks_stable_ports_and_reuses_them(tmp_path):
    store = proxy.MappingStore(tmp_path / "proxy.json")
    a, created_a = store.add("prodecs", "ws1", 3773, port_base=47100, port_free=lambda p: True)
    b, _ = store.add("prodecs", "ws2", 3773, port_base=47100, port_free=lambda p: True)
    again, created_again = store.add("prodecs", "ws1", 3773, port_base=47100, port_free=lambda p: True)
    assert (a.local_port, b.local_port) == (47100, 47101)
    assert created_a and not created_again and again == a
    # A fresh store object (a later CLI run) sees the same ports.
    assert {m.local_port for m in proxy.MappingStore(tmp_path / "proxy.json").load()} == {47100, 47101}


def test_store_skips_ports_in_use_and_honours_an_explicit_one(tmp_path):
    store = proxy.MappingStore(tmp_path / "proxy.json")
    m, _ = store.add("prodecs", "ws1", 1, port_base=47100, port_free=lambda p: p != 47100)
    assert m.local_port == 47101
    pinned, _ = store.add("prodecs", "ws2", 2, local_port=50000)
    assert pinned.local_port == 50000
    with pytest.raises(proxy.ProxyError, match="already used by prodecs/ws2:2"):
        store.add("prodecs", "ws3", 3, local_port=50000)
    moved, _ = store.add("prodecs", "ws1", 1, local_port=50001)
    assert moved.local_port == 50001 and len(store.load()) == 2


def test_store_rejects_bad_ports(tmp_path):
    store = proxy.MappingStore(tmp_path / "proxy.json")
    with pytest.raises(proxy.ProxyError):
        store.add("prodecs", "ws1", 0)
    with pytest.raises(proxy.ProxyError):
        store.add("prodecs", "ws1", 80, local_port=70000)


def test_store_remove_by_port_workspace_or_workspace_port(tmp_path):
    store = proxy.MappingStore(tmp_path / "proxy.json")
    free = {"port_free": lambda p: True}
    store.add("prodecs", "ws1", 3773, **free)
    store.add("prodecs", "ws1", 5173, **free)
    store.add("prodecs", "ws2", 3773, **free)
    store.add("other", "ws3", 3773, **free)
    assert [m.label for m in store.remove("ws1:5173")] == ["prodecs/ws1:5173"]
    assert [m.label for m in store.remove("47100")] == ["prodecs/ws1:3773"]
    assert store.remove("ws3", server="prodecs") == []
    assert [m.label for m in store.remove("ws2")] == ["prodecs/ws2:3773"]
    assert [m.label for m in store.load()] == ["other/ws3:3773"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX modes")
def test_store_file_is_owner_only(tmp_path):
    store = proxy.MappingStore(tmp_path / "proxy.json")
    store.add("prodecs", "ws1", 3773, port_free=lambda p: True)
    assert stat.S_IMODE(os.stat(store.path).st_mode) == 0o600


def test_default_store_lives_in_warrens_own_config_dir():
    assert proxy.default_store_path() == Path.home() / ".warren" / "proxy.json"


def test_cli_add_list_rm(tmp_path):
    cfg = _config(tmp_path)
    r = runner.invoke(app, ["proxy", "add", "ws1", "3773", "--config", str(cfg)])
    assert r.exit_code == 0, r.output
    assert "prodecs/ws1:3773 added: http://127.0.0.1:" in r.output
    address = r.output.split("added: ")[1].split()[0]
    r2 = runner.invoke(app, ["proxy", "add", "ws1", "3773", "--server", "prodecs", "--config", str(cfg)])
    assert f"already mapped: {address}" in r2.output
    listed = runner.invoke(app, ["proxy", "list", "--json"])
    assert [m["address"] for m in json.loads(listed.output)] == [address]
    assert runner.invoke(app, ["proxy", "rm", "ws1:3773"]).exit_code == 0
    assert "no mappings" in runner.invoke(app, ["proxy", "list"]).output
    assert runner.invoke(app, ["proxy", "rm", "ws1"]).exit_code == 1


def test_cli_add_refuses_a_non_ecs_remote(tmp_path):
    r = runner.invoke(app, ["proxy", "add", "ws1", "3773", "--server", "homelab", "--config", str(_config(tmp_path))])
    assert r.exit_code == 1
    assert "only reaches ECS workspaces" in " ".join(r.output.split())
    assert not proxy.default_store_path().exists()


# ---------------------------------------------------------------------------
# loopback only
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("host", ["0.0.0.0", "192.168.1.10", "::", "example.com"])
def test_non_loopback_binds_are_refused(host):
    with pytest.raises(proxy.ProxyError, match="loopback addresses only"):
        proxy.check_loopback(host)
    with pytest.raises(proxy.ProxyError):
        proxy.ProxyDaemon(proxy.MappingStore(), FakeResolver(), FakeForwarder(), proxy.ProxySettings(bind=host))


def test_loopback_binds_are_allowed():
    assert proxy.check_loopback("localhost") == "127.0.0.1"
    assert proxy.check_loopback("127.0.0.1") == "127.0.0.1"
    assert proxy.check_loopback("::1") == "::1"


def test_cli_run_refuses_a_non_loopback_bind(tmp_path):
    cfg = _config(tmp_path)
    runner.invoke(app, ["proxy", "add", "ws1", "3773", "--config", str(cfg)])
    r = runner.invoke(app, ["proxy", "run", "--bind", "0.0.0.0", "--config", str(cfg)])
    assert r.exit_code == 1
    assert "loopback addresses only" in " ".join(r.output.split())


@pytest.mark.asyncio
async def test_listener_is_bound_to_loopback():
    mp = await _started(FakeResolver(_TASK1), FakeForwarder())
    try:
        assert {s.getsockname()[0] for s in mp._server.sockets} == {"127.0.0.1"}
    finally:
        await mp.close()


# ---------------------------------------------------------------------------
# lazy start, relay, sharing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_nothing_starts_until_the_first_connection():
    resolver, forwarder = FakeResolver(_TASK1), FakeForwarder()
    mp = await _started(resolver, forwarder)
    try:
        await asyncio.sleep(0.1)
        assert resolver.calls == 0 and forwarder.sessions == []
        assert await _roundtrip(mp.mapping.local_port, b"hello") == b"hello"
        assert resolver.calls == 1 and len(forwarder.sessions) == 1
        assert forwarder.sessions[0].target.task_arn == _TASK1
    finally:
        await mp.close()
    assert forwarder.sessions[0].stopped


@pytest.mark.asyncio
async def test_relay_carries_a_long_bidirectional_stream():
    """WebSocket-shaped: one long-lived connection, many small frames each way,
    interleaved, plus a large burst; then a half-close is passed through."""
    mp = await _started(FakeResolver(_TASK1), FakeForwarder())
    try:
        r, w = await asyncio.open_connection("127.0.0.1", mp.mapping.local_port)
        w.write(b"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\n")
        await w.drain()
        assert await r.readexactly(40) == b"GET /ws HTTP/1.1\r\nUpgrade: websocket\r\n\r\n"
        for i in range(300):
            frame = b"\x81" + bytes([10]) + f"frame{i:05d}".encode()[:10]
            w.write(frame)
            await w.drain()
            assert await asyncio.wait_for(r.readexactly(len(frame)), timeout=5) == frame
            if i % 100 == 0:
                await asyncio.sleep(0.05)
        blob = os.urandom(3 * 1024 * 1024)
        w.write(blob)
        await w.drain()
        assert await asyncio.wait_for(r.readexactly(len(blob)), timeout=10) == blob
        w.write_eof()
        assert await asyncio.wait_for(r.read(), timeout=5) == b""
        w.close()
    finally:
        await mp.close()


@pytest.mark.asyncio
async def test_concurrent_connections_share_one_session():
    resolver, forwarder = FakeResolver(_TASK1), FakeForwarder()
    mp = await _started(resolver, forwarder)
    try:
        results = await asyncio.gather(*[_roundtrip(mp.mapping.local_port, f"c{i}".encode()) for i in range(8)])
        assert results == [f"c{i}".encode() for i in range(8)]
        assert resolver.calls == 1 and len(forwarder.sessions) == 1
        assert forwarder.sessions[0].accepted == 8
    finally:
        await mp.close()


# ---------------------------------------------------------------------------
# idle close, keepalive, self-healing
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_idle_session_is_closed_and_restarted_on_demand():
    resolver, forwarder = FakeResolver(_TASK1), FakeForwarder()
    mp = await _started(resolver, forwarder, idle_minutes=0.2 / 60, keepalive_seconds=0)
    try:
        r, w = await asyncio.open_connection("127.0.0.1", mp.mapping.local_port)
        w.write(b"x")
        assert await r.readexactly(1) == b"x"
        await asyncio.sleep(0.4)  # longer than the idle timeout, but a connection is open
        assert not forwarder.sessions[0].stopped
        w.close()
        await asyncio.sleep(0.5)
        assert forwarder.sessions[0].stopped and mp.session is None
        assert await _roundtrip(mp.mapping.local_port, b"again") == b"again"
        assert len(forwarder.sessions) == 2
    finally:
        await mp.close()


@pytest.mark.asyncio
async def test_keepalive_probes_the_session_while_clients_are_connected():
    forwarder = FakeForwarder()
    mp = await _started(FakeResolver(_TASK1), forwarder, keepalive_seconds=0.05)
    try:
        r, w = await asyncio.open_connection("127.0.0.1", mp.mapping.local_port)
        w.write(b"x")
        await r.readexactly(1)
        await asyncio.sleep(0.4)
        assert forwarder.sessions[0].accepted >= 3  # the client's connection plus probes
        w.close()
        await asyncio.sleep(0.1)
        after_close = forwarder.sessions[0].accepted
        await asyncio.sleep(0.3)
        assert forwarder.sessions[0].accepted == after_close  # no probes once nobody is connected
    finally:
        await mp.close()


@pytest.mark.asyncio
async def test_exited_session_is_restarted_against_the_new_task():
    """The workspace restarted: the old SSM session died, and the control plane
    now reports a different task; the next connection follows it."""
    resolver, forwarder = FakeResolver(_TASK1, _TASK2), FakeForwarder()
    mp = await _started(resolver, forwarder)
    try:
        r, w = await asyncio.open_connection("127.0.0.1", mp.mapping.local_port)
        w.write(b"a")
        assert await r.readexactly(1) == b"a"
        with capture_logs() as logs:
            forwarder.sessions[0].die()
            # The open connection ends with the session...
            assert await asyncio.wait_for(r.read(), timeout=5) == b""
            w.close()
            # ...and the next one re-resolves and reaches the new task.
            assert await _roundtrip(mp.mapping.local_port, b"b") == b"b"
        assert resolver.calls == 2
        assert [s.target.task_arn for s in forwarder.sessions] == [_TASK1, _TASK2]
        events = [e["event"] for e in logs]
        assert "proxy_session_exited" in events and "proxy_task_changed" in events
    finally:
        await mp.close()


# ---------------------------------------------------------------------------
# control-plane resolution: stopped workspace, SSO expiry
# ---------------------------------------------------------------------------


def _resolver(tmp_path, monkeypatch) -> proxy.ControlPlaneResolver:
    monkeypatch.setattr(dispatch, "start_orchestrator_port_forward", lambda *a, **kw: (MagicMock(), 54323))
    return proxy.ControlPlaneResolver(WarrenCLIConfig.load(_config(tmp_path)))


@pytest.mark.asyncio
async def test_control_plane_resolver_returns_the_current_task(tmp_path, monkeypatch):
    resolver = _resolver(tmp_path, monkeypatch)
    with respx.mock(base_url="http://127.0.0.1:54323") as m:
        m.get("/workspaces").mock(
            return_value=httpx.Response(200, json=[{"workspace_id": _WS, "status": "running", "container_id": _TASK2}])
        )
        target = await resolver.resolve(_mapping())
    assert target == proxy.Target(workspace_id=_WS, cluster="prod-cluster", task_arn=_TASK2)


@pytest.mark.asyncio
async def test_stopped_workspace_closes_the_connection_with_a_clear_error(tmp_path, monkeypatch):
    resolver = _resolver(tmp_path, monkeypatch)
    forwarder = FakeForwarder()
    mp = await _started(resolver, forwarder)
    try:
        with respx.mock(base_url="http://127.0.0.1:54323") as m:
            m.get("/workspaces").mock(
                return_value=httpx.Response(200, json=[{"workspace_id": _WS, "status": "stopped", "container_id": None}])
            )
            with capture_logs() as logs:
                # An HTTP client gets a 503 naming the problem...
                reply = await _roundtrip(mp.mapping.local_port, b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                # ...anything else just gets closed.
                r, w = await asyncio.open_connection("127.0.0.1", mp.mapping.local_port)
                assert await asyncio.wait_for(r.read(), timeout=5) == b""
                w.close()
        assert reply.startswith(b"HTTP/1.1 503 ")
        assert b"workspace abc12345 is stopped; start it with `warren connect abc12345 --server prodecs`" in reply
        assert forwarder.sessions == []
        errors = [e for e in logs if e["event"] == "proxy_connection_refused"]
        assert errors and "is stopped" in errors[0]["error"] and errors[0]["log_level"] == "error"
    finally:
        await mp.close()


@pytest.mark.asyncio
async def test_unknown_workspace_is_unavailable(tmp_path, monkeypatch):
    resolver = _resolver(tmp_path, monkeypatch)
    with respx.mock(base_url="http://127.0.0.1:54323") as m:
        m.get("/workspaces").mock(return_value=httpx.Response(200, json=[]))
        with pytest.raises(proxy.WorkspaceUnavailable, match="not found"):
            await resolver.resolve(_mapping())


_SSO_EXPIRED = "Error when retrieving token from sso: Token has expired and refresh failed"


@pytest.mark.asyncio
async def test_expired_sso_on_the_control_plane_tunnel(tmp_path, monkeypatch):
    monkeypatch.setenv("AWS_PROFILE", "warren-dev")

    def expired(*_a, **_kw):
        raise RuntimeError(f"SSM port-forward to orchestrator exited early: {_SSO_EXPIRED}")

    monkeypatch.setattr(dispatch, "start_orchestrator_port_forward", expired)
    resolver = proxy.ControlPlaneResolver(WarrenCLIConfig.load(_config(tmp_path)))
    mp = await _started(resolver, FakeForwarder())
    try:
        with capture_logs() as logs:
            reply = await _roundtrip(mp.mapping.local_port, b"GET / HTTP/1.1\r\n\r\n")
        assert b"run `aws sso login --profile warren-dev`" in reply
        assert any("aws sso login --profile warren-dev" in e.get("error", "") for e in logs)
    finally:
        await mp.close()


@pytest.mark.parametrize(
    "text",
    [
        _SSO_EXPIRED,
        "The SSO session associated with this profile has expired or is otherwise invalid. To refresh this "
        "SSO session run aws sso login with the corresponding profile.",
        "Error loading SSO Token: Token for my-sso does not exist",
        "An error occurred (ExpiredTokenException) when calling the StartSession operation: "
        "The security token included in the request is expired",
    ],
)
def test_expired_credential_texts_are_recognised(text, monkeypatch):
    monkeypatch.delenv("AWS_PROFILE", raising=False)
    err = proxy.credentials_error(text)
    assert isinstance(err, proxy.AwsCredentialsExpired)
    assert "run `aws sso login --profile default`" in str(err)


def test_other_errors_are_not_mistaken_for_expiry():
    assert proxy.credentials_error("TargetNotConnected: ecs:prod_x_y is not connected.") is None


def test_non_ecs_remote_is_refused_by_the_resolver(tmp_path):
    cfg = WarrenCLIConfig.load(_config(tmp_path))
    with pytest.raises(proxy.ProxyError, match="only reaches ECS workspaces"):
        proxy.remote_for(cfg, "homelab")


# ---------------------------------------------------------------------------
# the real SsmForwarder against a fake `aws`
# ---------------------------------------------------------------------------

_FAKE_AWS = textwrap.dedent(
    """\
    #!{python}
    import json, os, socket, sys, threading
    argv = sys.argv[1:]
    with open(os.environ["FAKE_AWS_LOG"], "a") as f:
        f.write(json.dumps(argv) + "\\n")
    if os.environ.get("FAKE_AWS_EXPIRED"):
        sys.stderr.write("Error when retrieving token from sso: Token has expired and refresh failed\\n")
        sys.exit(255)
    if argv[:2] == ["ecs", "describe-tasks"]:
        print("rt-42")
        sys.exit(0)
    if argv[:2] == ["ssm", "start-session"]:
        params = dict(kv.split("=") for kv in argv[argv.index("--parameters") + 1].split(","))
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind(("127.0.0.1", int(params["localPortNumber"])))
        srv.listen()
        print("Waiting for connections...", flush=True)
        def echo(c):
            while data := c.recv(65536):
                c.sendall(data)
            c.close()
        while True:
            c, _ = srv.accept()
            threading.Thread(target=echo, args=(c,), daemon=True).start()
    sys.exit(2)
    """
)


@pytest.fixture
def fake_aws(tmp_path, monkeypatch):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    aws = bin_dir / "aws"
    aws.write_text(_FAKE_AWS.format(python=sys.executable))
    aws.chmod(0o755)
    plugin = bin_dir / "session-manager-plugin"
    plugin.write_text("#!/bin/sh\nexit 0\n")
    plugin.chmod(0o755)
    log_path = tmp_path / "aws.log"
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '')}")
    monkeypatch.setenv("FAKE_AWS_LOG", str(log_path))
    return log_path


@posix_only
@pytest.mark.asyncio
async def test_ssm_forwarder_runs_a_port_forwarding_session(fake_aws):
    session = await proxy.SsmForwarder().start(
        proxy.Target(workspace_id=_WS, cluster="prod-cluster", task_arn=_TASK1), 3773
    )
    try:
        assert session.alive()
        assert await _roundtrip(session.local_port, b"through ssm") == b"through ssm"
        calls = [json.loads(line) for line in fake_aws.read_text().splitlines()]
        assert calls[-1] == [
            "ssm", "start-session",
            "--target", "ecs:prod-cluster_task1111_rt-42",
            "--document-name", "AWS-StartPortForwardingSession",
            "--parameters", f"portNumber=3773,localPortNumber={session.local_port}",
        ]
    finally:
        session.stop()
    assert not session.alive()


@posix_only
@pytest.mark.asyncio
async def test_ssm_forwarder_reports_expired_sso(fake_aws, monkeypatch):
    monkeypatch.setenv("FAKE_AWS_EXPIRED", "1")
    monkeypatch.setenv("AWS_PROFILE", "warren-dev")
    with pytest.raises(proxy.AwsCredentialsExpired, match=r"run `aws sso login --profile warren-dev`"):
        await proxy.SsmForwarder().start(proxy.Target(workspace_id=_WS, cluster="c", task_arn=_TASK1), 3773)


# ---------------------------------------------------------------------------
# the daemon
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_daemon_serves_saved_mappings_and_follows_store_changes(tmp_path):
    store = proxy.MappingStore(tmp_path / "proxy.json")
    first, _ = store.add("prodecs", "ws1", 3773, local_port=_free_port())
    daemon = proxy.ProxyDaemon(store, FakeResolver(_TASK1), FakeForwarder(), proxy.ProxySettings(), reload_seconds=0.05)
    stop = asyncio.Event()
    ready = asyncio.Event()
    task = asyncio.ensure_future(daemon.run(stop, started=ready.set))
    try:
        await asyncio.wait_for(ready.wait(), timeout=5)
        assert await _roundtrip(first.local_port, b"one") == b"one"
        second, _ = store.add("prodecs", "ws2", 3773, local_port=_free_port())
        os.utime(store.path, (0, 0))  # mtime granularity: make sure the change is seen
        for _ in range(100):
            if second in daemon.proxies:
                break
            await asyncio.sleep(0.05)
        assert await _roundtrip(second.local_port, b"two") == b"two"
        store.remove("ws1")
        os.utime(store.path, (1, 1))
        for _ in range(100):
            if first not in daemon.proxies:
                break
            await asyncio.sleep(0.05)
        with pytest.raises(OSError):
            await asyncio.open_connection("127.0.0.1", first.local_port)
    finally:
        stop.set()
        await asyncio.wait_for(task, timeout=5)
