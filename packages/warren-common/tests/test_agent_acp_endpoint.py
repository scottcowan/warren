"""AM3: the agent workspace's one loopback ACP endpoint, with a fake JSON-RPC agent."""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

from test_agent_supervisor import FAKE, PROMPT, Client, events, finish, make_spec, run_bg, state
from warren_common import agent_supervisor as sv

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX process groups")


async def _handshake(c: Client, cwd: str) -> list:
    init = await c.call("initialize", {"protocolVersion": 1, "clientCapabilities": {}})
    assert init["result"]["agentCapabilities"]["loadSession"] is True
    new = await c.call("session/new", {"cwd": cwd, "mcpServers": []})
    assert new["result"]["sessionId"] == "sess-1"
    notes: list = []
    done = await c.call("session/prompt", PROMPT, notes)
    assert done["result"] == {"stopReason": "end_turn"}
    return notes


async def test_native_acp_is_passed_through_from_stdio(tmp_path):
    spec = make_spec(tmp_path, [sys.executable, FAKE])
    sup = sv.Supervisor(spec)
    task = await run_bg(sup)
    c = await Client.connect(spec["port"])
    notes = await _handshake(c, str(tmp_path))
    assert notes == [{"jsonrpc": "2.0", "method": "session/update", "params": {
        "sessionId": "sess-1",
        "update": {"sessionUpdate": "agent_message_chunk", "content": {"type": "text", "text": "echo hi"}},
    }}]
    c.close()
    await finish(sup, task)


async def test_tcp_adapter_is_proxied_and_peers_are_capped(tmp_path):
    spec = make_spec(
        tmp_path, ["claude", "-p"], transport="tcp", max_peers=2,
        adapter=[sys.executable, FAKE, "tcp", "127.0.0.1", "{port}"],
    )
    sup = sv.Supervisor(spec)
    task = await run_bg(sup)
    a, b = await Client.connect(spec["port"]), await Client.connect(spec["port"])
    await _handshake(a, str(tmp_path))
    await _handshake(b, str(tmp_path))
    third = await Client.connect(spec["port"])
    assert (await third.read())["error"]["message"] == "ACP endpoint busy"
    assert "acp.peer_rejected" in [e["event"] for e in events(tmp_path)]
    for c in (a, b, third):
        c.close()
    await finish(sup, task)


async def test_stdio_endpoint_takes_one_peer_and_bounds_lines(tmp_path):
    spec = make_spec(tmp_path, [sys.executable, FAKE], max_line_bytes=2048, max_peers=4)
    assert spec["max_peers"] == 1
    sup = sv.Supervisor(spec)
    task = await run_bg(sup)
    a = await Client.connect(spec["port"])
    await a.call("initialize", {"protocolVersion": 1})
    b = await Client.connect(spec["port"])
    assert (await b.read())["error"]["code"] == -32000
    a.w.write(b'{"jsonrpc":"2.0","id":9,"method":"x","params":"' + b"a" * 4096 + b'"}\n')
    await a.w.drain()
    assert (await a.read())["error"]["code"] == -32600
    assert await asyncio.wait_for(a.r.read(), 5) == b""
    c = await Client.connect(spec["port"])
    assert (await c.call("initialize", {"protocolVersion": 1}))["result"]["protocolVersion"] == 1
    c.close()
    await finish(sup, task)


async def test_a_wide_listener_stops_the_agent_for_good(tmp_path):
    spec = make_spec(tmp_path, [sys.executable, FAKE], restart={"policy": "always", "max_restarts": 5})
    sup = sv.Supervisor(spec, listeners=lambda pid: [("127.0.0.1", 1), ("0.0.0.0", spec["inner_port"])],
                        listener_check_seconds=0.01)
    assert await asyncio.wait_for(sup.run(), 10) == sv.EXIT_WIDE_LISTENER
    ev = events(tmp_path)
    assert [e["event"] for e in ev].count("agent.started") == 1
    assert [e for e in ev if e["event"] == "agent.listener_rejected"][0]["listeners"] == [
        f"0.0.0.0:{spec['inner_port']}"
    ]
    assert state(tmp_path)["state"] == "exited"


@pytest.mark.skipif(not Path("/proc/net/tcp").exists(), reason="needs Linux /proc")
async def test_an_adapter_binding_all_interfaces_fails_startup(tmp_path):
    spec = make_spec(tmp_path, ["x"], transport="tcp", adapter=[sys.executable, FAKE, "tcp", "0.0.0.0", "{port}"])
    sup = sv.Supervisor(spec, listener_check_seconds=0.05)
    assert await asyncio.wait_for(sup.run(), 20) == sv.EXIT_WIDE_LISTENER


def _fake_proc(root: Path, owned: dict[int, list[str]], children: dict[int, list[int]]) -> Path:
    (root / "net").mkdir(parents=True)
    header = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
    (root / "net" / "tcp").write_text(header + "".join([
        "   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 111 1\n",
        "   1: 00000000:1F91 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 222 1\n",
        "   2: 0100007F:1F92 0100007F:A000 01 00000000:00000000 00:00000000 00000000  1000        0 444 1\n",
    ]))
    (root / "net" / "tcp6").write_text(header + (
        "   0: 00000000000000000000000001000000:1F93 00000000000000000000000000000000:0000 0A "
        "00000000:00000000 00:00000000 00000000  1000        0 333 1\n"
    ))
    for pid, inodes in owned.items():
        (root / str(pid) / "fd").mkdir(parents=True)
        (root / str(pid) / "task" / str(pid)).mkdir(parents=True)
        (root / str(pid) / "task" / str(pid) / "children").write_text(" ".join(map(str, children.get(pid, []))))
        for n, inode in enumerate(inodes):
            os.symlink(f"socket:[{inode}]", root / str(pid) / "fd" / str(n + 3))
    return root


def test_proc_listeners_follow_the_process_tree(tmp_path):
    proc = _fake_proc(tmp_path / "proc", {42: ["111", "444"], 43: ["333"]}, {42: [43]})
    assert sorted(sv.proc_listeners(42, proc)) == [("127.0.0.1", 8080), ("::1", 8083)]
    proc2 = _fake_proc(tmp_path / "proc2", {42: ["222"]}, {})
    assert sv.proc_listeners(42, proc2) == [("0.0.0.0", 8081)]
    assert sv.proc_listeners(42, tmp_path / "none") is None


@pytest.mark.parametrize(("addr", "ok"), [
    ("127.0.0.1", True), ("127.0.0.53", True), ("::1", True), ("::ffff:127.0.0.1", True),
    ("0.0.0.0", False), ("::", False), ("10.1.2.3", False), ("localhost", False),
])
def test_is_loopback(addr, ok):
    assert sv.is_loopback(addr) is ok


def test_spec_from_the_environment(monkeypatch, tmp_path):
    monkeypatch.setenv(sv.SPEC_ENV, json.dumps({**make_spec(tmp_path, ["x"]), "host": "0.0.0.0"}))
    assert sv.main() == sv.EXIT_BAD_SPEC
