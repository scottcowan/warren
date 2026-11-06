"""`warren proxy`: mapping store, loopback-only listeners, lazy shared SSM
sessions, relay, idle close, re-resolution and error paths.

No AWS: sessions come from a fake forwarder (an in-process echo server per
"SSM session") or, for the real SsmForwarder, a fake `aws` executable on PATH.
"""

from __future__ import annotations

import asyncio
import gc
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
    '[defaults]\nserver = "prodecs"\n'
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

    def __init__(self, target: proxy.Target, gate: asyncio.Event | None = None) -> None:
        self.target = target
        self.accepted = 0
        self.stopped = False
        self._dead = False
        self._server: asyncio.AbstractServer | None = None
        self._writers: list[asyncio.StreamWriter] = []
        self._tasks: set[asyncio.Task] = set()
        self.local_port = 0
        # With a gate, each connection reads its whole request (to EOF), reports
        # it in ``half_closed``, and answers only once the gate is set.
        self.gate = gate
        self.half_closed = 0
        self.half_closed_changed = asyncio.Event()

    async def start(self) -> None:
        async def handle(r, w):
            self._tasks.add(asyncio.current_task())
            self.accepted += 1
            self._writers.append(w)
            if self.gate is None:
                await _echo(r, w)
                return
            try:
                data = await r.read()
                self.half_closed += 1
                self.half_closed_changed.set()
                await self.gate.wait()
                w.write(data)
                await w.drain()
                w.write_eof()
            except (ConnectionError, OSError):
                pass
            finally:
                w.close()

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
    def __init__(self, error: Exception | None = None, gate: asyncio.Event | None = None) -> None:
        self.sessions: list[FakeSession] = []
        self.error = error
        self.gate = gate
        self.started = asyncio.Event()

    async def start(self, target: proxy.Target, remote_port: int) -> FakeSession:
        await asyncio.sleep(0.05)  # a real session takes a while; lets concurrent callers pile up
        if self.error is not None:
            raise self.error
        session = FakeSession(target, self.gate)
        await session.start()
        self.sessions.append(session)
        self.started.set()
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


def test_cli_add_refuses_an_http_remote_on_another_host(tmp_path):
    cfg = _config(tmp_path, '[remotes.lan]\nurl = "http://10.0.0.5:8420"\n')
    r = runner.invoke(app, ["proxy", "add", "ws1", "3773", "--server", "lan", "--config", str(cfg)])
    assert r.exit_code == 1
    assert "add the server as an ssh remote" in " ".join(r.output.split())
    assert not proxy.default_store_path().exists()


def test_cli_add_accepts_an_ssh_remote(tmp_path):
    r = runner.invoke(app, ["proxy", "add", "ws1", "3773", "--server", "homelab", "--config", str(_config(tmp_path))])
    assert r.exit_code == 0, r.output
    assert "homelab/ws1:3773 added: http://127.0.0.1:" in r.output


def test_pick_server_without_a_default_needs_one_capable_remote(tmp_path):
    two = tmp_path / "two.toml"
    two.write_text(_CONFIG.replace('[defaults]\nserver = "prodecs"\n', ""))
    r = runner.invoke(app, ["proxy", "add", "ws1", "3773", "--config", str(two)])
    assert r.exit_code == 1
    assert "more than one remote warren proxy can reach (homelab, prodecs): pass --server" in " ".join(
        r.output.split()
    )
    # An http remote on another host doesn't count; a local one does.
    one = tmp_path / "one.toml"
    one.write_text('[remotes.lan]\nurl = "http://10.0.0.5:8420"\n[remotes.here]\nurl = "http://127.0.0.1:8420"\n')
    r = runner.invoke(app, ["proxy", "add", "ws1", "3773", "--config", str(one)])
    assert r.exit_code == 0, r.output
    assert "here/ws1:3773 added" in r.output


# ---------------------------------------------------------------------------
# named ports (template `ports:`)
# ---------------------------------------------------------------------------

_DECLARED = {"t3": {"port": 3773, "description": ""}, "code": {"port": 8080, "description": "code-server"}}


def _ws_row(ports: dict | None = None) -> dict:
    row = {"workspace_id": _WS, "status": "running", "container_id": _TASK1}
    if ports is not None:
        row["ports"] = ports
    return row


@pytest.fixture
def control_plane(monkeypatch):
    """`GET /workspaces` through a faked orchestrator tunnel; yields the respx router."""
    monkeypatch.setattr(dispatch, "start_orchestrator_port_forward", lambda *a, **kw: (MagicMock(), 54323))
    with respx.mock(base_url="http://127.0.0.1:54323", assert_all_called=False) as m:
        yield m


def _add(cfg: Path, *args: str):
    return runner.invoke(app, ["proxy", "add", *args, "--config", str(cfg)])


def test_declared_ports_reads_the_api_shape():
    assert proxy.declared_ports(_ws_row(_DECLARED)) == {"t3": 3773, "code": 8080}
    assert proxy.declared_ports(_ws_row()) == {}  # a server predating named ports
    assert proxy.declared_ports(_ws_row({"bad": {"port": 0}, "flag": {"port": True}, "ok": 22})) == {"ok": 22}


def test_cli_add_from_template_maps_every_declared_port_and_is_idempotent(tmp_path, control_plane):
    control_plane.get("/workspaces").mock(return_value=httpx.Response(200, json=[_ws_row(_DECLARED)]))
    cfg = _config(tmp_path)
    r = _add(cfg, "abc12345", "--from-template")
    assert r.exit_code == 0, r.output
    assert "prodecs/abc12345/code added: http://127.0.0.1:" in r.output
    assert "prodecs/abc12345/t3 added: http://127.0.0.1:" in r.output
    first = {(m.name, m.remote_port): m.local_port for m in proxy.MappingStore().load()}
    assert set(first) == {("t3", 3773), ("code", 8080)}

    again = _add(cfg, "abc12345", "--from-template")
    assert again.exit_code == 0, again.output
    assert "added" not in again.output and again.output.count("already mapped") == 2
    assert {(m.name, m.remote_port): m.local_port for m in proxy.MappingStore().load()} == first

    listed = runner.invoke(app, ["proxy", "list"])
    assert "-> prodecs/abc12345/t3 (port 3773)" in listed.output
    as_json = json.loads(runner.invoke(app, ["proxy", "list", "--json"]).output)
    assert {m["name"] for m in as_json} == {"t3", "code"}

    assert runner.invoke(app, ["proxy", "rm", "abc12345/t3"]).exit_code == 0
    assert [m.name for m in proxy.MappingStore().load()] == ["code"]


def test_cli_add_by_port_name(tmp_path, control_plane):
    control_plane.get("/workspaces").mock(return_value=httpx.Response(200, json=[_ws_row(_DECLARED)]))
    cfg = _config(tmp_path)
    r = _add(cfg, "abc12345", "t3", "--local-port", "50123")
    assert r.exit_code == 0, r.output
    assert "prodecs/abc12345/t3 added: http://127.0.0.1:50123" in r.output
    # --from-template afterwards keeps t3's address and only adds the rest.
    r2 = _add(cfg, "abc12345", "--from-template")
    assert "prodecs/abc12345/t3 already mapped: http://127.0.0.1:50123" in r2.output
    assert "prodecs/abc12345/code added" in r2.output

    unknown = _add(cfg, "abc12345", "acp")
    assert unknown.exit_code == 1
    assert "no port named 'acp' (declared: code, t3)" in " ".join(unknown.output.split())


def test_cli_add_names_an_existing_numeric_mapping_without_moving_it(tmp_path, control_plane):
    control_plane.get("/workspaces").mock(return_value=httpx.Response(200, json=[_ws_row(_DECLARED)]))
    cfg = _config(tmp_path)
    numeric = _add(cfg, "abc12345", "3773")
    address = numeric.output.split("added: ")[1].split()[0]
    named = _add(cfg, "abc12345", "--from-template")
    assert f"prodecs/abc12345/t3 already mapped: {address}" in named.output
    assert len(proxy.MappingStore().load()) == 2


def test_cli_add_numeric_port_needs_no_control_plane(tmp_path, monkeypatch):
    def unreachable(*_a, **_kw):
        raise AssertionError("a numeric port must not contact the control plane")

    monkeypatch.setattr(dispatch, "start_orchestrator_port_forward", unreachable)
    assert _add(_config(tmp_path), "ws1", "3773").exit_code == 0


def test_cli_add_from_template_with_no_declared_ports(tmp_path, control_plane):
    control_plane.get("/workspaces").mock(return_value=httpx.Response(200, json=[_ws_row()]))
    r = _add(_config(tmp_path), "abc12345", "--from-template")
    assert r.exit_code == 1
    assert "declares no ports" in " ".join(r.output.split())
    assert proxy.MappingStore().load() == []


def test_cli_add_from_template_unknown_workspace(tmp_path, control_plane):
    control_plane.get("/workspaces").mock(return_value=httpx.Response(200, json=[]))
    r = _add(_config(tmp_path), "nope", "--from-template")
    assert r.exit_code == 1 and "not found" in r.output


@pytest.mark.parametrize(
    "args",
    [["abc12345", "3773", "--from-template"], ["abc12345"], ["abc12345", "--from-template", "--local-port", "5000"]],
)
def test_cli_add_rejects_bad_argument_combinations(tmp_path, args):
    assert _add(_config(tmp_path), *args).exit_code == 2


def test_store_moves_a_renumbered_name_and_keeps_its_address(tmp_path):
    store = proxy.MappingStore(tmp_path / "proxy.json")
    free = {"port_free": lambda p: True}
    t3, _ = store.add("prodecs", "ws1", 3773, name="t3", **free)
    moved, created = store.add("prodecs", "ws1", 3774, name="t3", **free)
    assert not created and moved.local_port == t3.local_port and moved.remote_port == 3774
    assert [(m.name, m.remote_port) for m in store.load()] == [("t3", 3774)]


def test_store_name_conflict_with_an_existing_mapping(tmp_path):
    store = proxy.MappingStore(tmp_path / "proxy.json")
    free = {"port_free": lambda p: True}
    store.add("prodecs", "ws1", 3773, name="t3", **free)
    store.add("prodecs", "ws1", 3774, **free)
    with pytest.raises(proxy.ProxyError, match="already maps; remove one with `warren proxy rm`"):
        store.add("prodecs", "ws1", 3774, name="t3", **free)
    assert len(store.load()) == 2


def test_store_without_names_still_reads_old_files(tmp_path):
    path = tmp_path / "proxy.json"
    path.write_text(json.dumps({"mappings": [
        {"server": "prodecs", "workspace": "ws1", "remote_port": 3773, "local_port": 47100}
    ]}))
    [m] = proxy.MappingStore(path).load()
    assert m.name is None and m.label == "prodecs/ws1:3773"
    proxy.MappingStore(path).add("prodecs", "ws1", 8080, port_free=lambda p: True)
    assert all("name" not in row for row in json.loads(path.read_text())["mappings"])


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
    """Eight clients each send a request and half-close, then wait for the
    answer. The workspace answers only once all eight requests have arrived,
    and a garbage collection runs while every connection is half-closed: a
    connection task the proxy doesn't hold on to is unreachable then (its
    client transport has stopped reading) and would be destroyed mid-relay,
    leaving its client an empty response."""
    gate = asyncio.Event()
    resolver, forwarder = FakeResolver(_TASK1), FakeForwarder(gate=gate)
    mp = await _started(resolver, forwarder)
    try:
        clients = [asyncio.ensure_future(_roundtrip(mp.mapping.local_port, f"c{i}".encode())) for i in range(8)]
        await asyncio.wait_for(forwarder.started.wait(), timeout=5)
        session = forwarder.sessions[0]
        while session.half_closed < 8:
            session.half_closed_changed.clear()
            await asyncio.wait_for(session.half_closed_changed.wait(), timeout=5)
        gc.collect()
        gate.set()
        results = await asyncio.gather(*clients)
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


def test_remote_for_accepts_ecs_ssh_and_local_http_only(tmp_path):
    cfg = WarrenCLIConfig.load(
        _config(
            tmp_path,
            '[remotes.here]\nurl = "http://localhost:8420"\n'
            '[remotes.here6]\nurl = "http://[::1]:8420"\n'
            '[remotes.lan]\nurl = "http://10.0.0.5:8420"\n',
        )
    )
    assert proxy.remote_for(cfg, "prodecs").runtime_type == "ecs"
    assert proxy.remote_for(cfg, "homelab").runtime_type == "ssh"
    assert proxy.is_local_remote(proxy.remote_for(cfg, "here"))
    assert proxy.is_local_remote(proxy.remote_for(cfg, "here6"))
    with pytest.raises(proxy.ProxyError, match="http remote on another host"):
        proxy.remote_for(cfg, "lan")


# ---------------------------------------------------------------------------
# podman/docker: published host ports, ssh and direct targets
# ---------------------------------------------------------------------------

_HOST_PORTS = {"t3": {"host": "127.0.0.1", "port": 41001}, "code": {"host": "127.0.0.1", "port": 41002}}


def _podman_row(status: str = "running", host_ports: dict | None = None, ports: dict | None = None) -> dict:
    return {
        "workspace_id": _WS,
        "status": status,
        "container_id": "c0ffee" if status == "running" else None,
        "ports": _DECLARED if ports is None else ports,
        "host_ports": _HOST_PORTS if host_ports is None else host_ports,
    }


def _remote(tmp_path, name: str, extra: str = ""):
    return WarrenCLIConfig.load(_config(tmp_path, extra)).get_remote(name)


def test_published_target_for_an_ssh_remote(tmp_path):
    remote = _remote(tmp_path, "homelab")
    target = proxy.published_target(_podman_row(), remote_port=3773, remote=remote, server="homelab")
    assert target == proxy.Target(
        workspace_id=_WS, kind="ssh", host="127.0.0.1", host_port=41001, ssh_host="node2", ssh_key_path=None
    )
    assert target.endpoint == "127.0.0.1:41001"


def test_published_target_for_a_local_server_is_direct(tmp_path):
    remote = _remote(tmp_path, "here", '[remotes.here]\nurl = "http://127.0.0.1:8420"\n')
    target = proxy.published_target(_podman_row(), remote_port=8080, remote=remote, server="here")
    assert (target.kind, target.host, target.host_port) == ("direct", "127.0.0.1", 41002)


def test_published_target_errors(tmp_path):
    remote = _remote(tmp_path, "homelab")
    with pytest.raises(proxy.ProxyError, match=r"port 5173 isn't one of workspace abc12345's template ports"):
        proxy.published_target(_podman_row(), remote_port=5173, remote=remote, server="homelab")
    with pytest.raises(proxy.WorkspaceUnavailable, match="reports no host port for 't3'"):
        proxy.published_target(_podman_row(host_ports={}), remote_port=3773, remote=remote, server="homelab")
    with pytest.raises(proxy.WorkspaceUnavailable, match="is stopped"):
        proxy.published_target(_podman_row(status="stopped"), remote_port=3773, remote=remote, server="homelab")
    # The server only publishes on loopback; anything else is refused, not forwarded to.
    lan = {"t3": {"host": "0.0.0.0", "port": 41001}}
    with pytest.raises(proxy.ProxyError, match="not a loopback address"):
        proxy.published_target(_podman_row(host_ports=lan), remote_port=3773, remote=remote, server="homelab")


@pytest.mark.asyncio
async def test_control_plane_resolver_for_an_ssh_remote(tmp_path, monkeypatch):
    """The control plane is reached over the ssh remote's own tunnel; the target is the
    port's host binding on that host."""
    calls = []

    def fake_forward(*a, **kw):
        calls.append((a, kw))
        return MagicMock(), 54324

    monkeypatch.setattr(dispatch, "start_ssh_port_forward", fake_forward)
    resolver = proxy.ControlPlaneResolver(WarrenCLIConfig.load(_config(tmp_path)))
    mapping = proxy.Mapping(server="homelab", workspace=_WS[:8], remote_port=3773, local_port=47100)
    with respx.mock(base_url="http://127.0.0.1:54324") as m:
        m.get("/workspaces").mock(return_value=httpx.Response(200, json=[_podman_row()]))
        target = await resolver.resolve(mapping)
    assert calls == [(("node2", 8420), {"ssh_key_path": None})]
    assert (target.kind, target.ssh_host, target.host, target.host_port) == ("ssh", "node2", "127.0.0.1", 41001)


@pytest.mark.asyncio
async def test_ssh_forwarder_forwards_to_the_published_loopback_port(monkeypatch):
    calls = []

    def fake_forward(*a, **kw):
        calls.append((a, kw))
        return MagicMock(poll=MagicMock(return_value=None)), 55555

    monkeypatch.setattr(dispatch, "start_ssh_port_forward", fake_forward)
    target = proxy.Target(
        workspace_id=_WS, kind="ssh", host="127.0.0.1", host_port=41001, ssh_host="node2", ssh_key_path="~/.ssh/k"
    )
    session = await proxy.RuntimeForwarder().start(target, 3773)
    assert calls == [(("node2", 41001), {"ssh_key_path": "~/.ssh/k", "remote_host": "127.0.0.1"})]
    assert (session.host, session.local_port, session.alive()) == ("127.0.0.1", 55555, True)


@pytest.mark.asyncio
async def test_runtime_forwarder_picks_by_kind():
    picked = []

    class Rec:
        def __init__(self, name):
            self.name = name

        async def start(self, target, remote_port):
            picked.append(self.name)
            return MagicMock()

    fwd = proxy.RuntimeForwarder(ecs=Rec("ecs"), ssh=Rec("ssh"), direct=Rec("direct"))
    for kind in ("ecs", "ssh", "direct"):
        await fwd.start(proxy.Target(workspace_id=_WS, kind=kind), 1)
    assert picked == ["ecs", "ssh", "direct"]
    direct = await proxy.DirectForwarder().start(
        proxy.Target(workspace_id=_WS, kind="direct", host="127.0.0.1", host_port=41001), 3773
    )
    assert (direct.host, direct.local_port, direct.alive()) == ("127.0.0.1", 41001, True)


async def _echo_server(body_prefix: bytes = b"") -> asyncio.AbstractServer:
    async def handle(r, w):
        if body_prefix:
            w.write(body_prefix)
        await _echo(r, w)

    return await asyncio.start_server(handle, "127.0.0.1", 0)


async def _closing_server() -> asyncio.AbstractServer:
    """Accepts and closes without a byte: an SSH forward whose host port went away."""

    async def handle(r, w):
        w.close()

    return await asyncio.start_server(handle, "127.0.0.1", 0)


def _port_of(server: asyncio.AbstractServer) -> int:
    return server.sockets[0].getsockname()[1]


class SequenceResolver:
    def __init__(self, *targets: proxy.Target) -> None:
        self.targets = list(targets)
        self.calls = 0

    async def resolve(self, mapping):
        self.calls += 1
        return self.targets[min(self.calls, len(self.targets)) - 1]


def _direct(port: int) -> proxy.Target:
    return proxy.Target(workspace_id=_WS, kind="direct", host="127.0.0.1", host_port=port)


@pytest.mark.asyncio
async def test_direct_target_follows_a_moved_host_port():
    """Local server: the proxy connects straight to the published port. When the
    container comes back on another host port, the old one refuses, and the next
    connection resolves again and reaches the new one."""
    old, new = await _echo_server(), await _echo_server()
    old_port, new_port = _port_of(old), _port_of(new)
    resolver = SequenceResolver(_direct(old_port), _direct(new_port))
    mp = await _started(resolver, proxy.DirectForwarder(), revalidate_seconds=3600)
    try:
        assert await _roundtrip(mp.mapping.local_port, b"one") == b"one"
        old.close()
        await old.wait_closed()
        with capture_logs() as logs:
            assert await _roundtrip(mp.mapping.local_port, b"two") == b"two"
        assert resolver.calls == 2
        assert mp.target.endpoint == f"127.0.0.1:{new_port}"
        assert "proxy_host_port_changed" in [e["event"] for e in logs]
        assert mp._keepalive_task is None  # no SSM session to keep busy
    finally:
        await mp.close()
        new.close()


def _ssh(port: int) -> proxy.Target:
    return proxy.Target(workspace_id=_WS, kind="ssh", host="127.0.0.1", host_port=port, ssh_host="node2")


class FakeSshForwarder:
    """Each 'ssh -L' is a local listener relaying to the target's host port, which stays
    up (like ssh) even when nothing answers on the far side."""

    def __init__(self, upstreams: dict[int, int]) -> None:
        self.upstreams = upstreams
        self.started: list[proxy.Target] = []
        self.sessions: list = []

    async def start(self, target, remote_port):
        self.started.append(target)
        upstream = self.upstreams[target.host_port]
        session = _ForwardSession(upstream)
        await session.start()
        self.sessions.append(session)
        return session


class _ForwardSession:
    host = "127.0.0.1"

    def __init__(self, upstream: int) -> None:
        self.upstream = upstream
        self.local_port = 0
        self.stopped = False
        self._server = None

    async def start(self):
        async def handle(r, w):
            ur, uw = await asyncio.open_connection("127.0.0.1", self.upstream)
            await proxy.relay(r, w, ur, uw)

        self._server = await asyncio.start_server(handle, "127.0.0.1", 0)
        self.local_port = _port_of(self._server)

    def alive(self):
        return not self.stopped

    def stop(self):
        self.stopped = True
        self._server.close()


@pytest.mark.asyncio
async def test_ssh_target_revalidates_after_a_dead_looking_connection():
    """SSH remote: the forward stays up after the container moved to a new host port,
    and connections through it just close. The next connection checks the control
    plane, finds the new port and starts a new forward to it."""
    gone, new = await _closing_server(), await _echo_server()
    resolver = SequenceResolver(_ssh(41001), _ssh(41002))
    forwarder = FakeSshForwarder({41001: _port_of(gone), 41002: _port_of(new)})
    mp = await _started(resolver, forwarder, revalidate_seconds=3600)
    try:
        assert await _roundtrip(mp.mapping.local_port, b"lost") == b""
        assert await _roundtrip(mp.mapping.local_port, b"found") == b"found"
        assert [t.host_port for t in forwarder.started] == [41001, 41002]
        assert forwarder.sessions[0].stopped
        # A healthy session isn't re-checked again until revalidate_seconds pass.
        assert await _roundtrip(mp.mapping.local_port, b"again") == b"again"
        assert resolver.calls == 2
    finally:
        await mp.close()
        gone.close()
        new.close()


@pytest.mark.asyncio
async def test_ssh_target_revalidation_keeps_the_forward_when_nothing_moved():
    up = await _echo_server()
    resolver = SequenceResolver(_ssh(41001))
    forwarder = FakeSshForwarder({41001: _port_of(up)})
    mp = await _started(resolver, forwarder, revalidate_seconds=0)
    try:
        for payload in (b"a", b"b", b"c"):
            assert await _roundtrip(mp.mapping.local_port, payload) == payload
        assert resolver.calls == 3  # checked before each lone connection...
        assert len(forwarder.started) == 1  # ...but the same forward is reused
    finally:
        await mp.close()
        up.close()


@pytest.mark.asyncio
async def test_ecs_targets_are_not_revalidated():
    resolver, forwarder = FakeResolver(_TASK1), FakeForwarder()
    mp = await _started(resolver, forwarder, revalidate_seconds=0)
    try:
        for payload in (b"a", b"b"):
            assert await _roundtrip(mp.mapping.local_port, payload) == payload
        assert resolver.calls == 1
    finally:
        await mp.close()


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
