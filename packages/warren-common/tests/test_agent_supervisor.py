"""AG2b/AM3: the agent supervisor, driven with a fake ACP agent (no harness, no model)."""
from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
from pathlib import Path

import pytest

from warren_common import agent_supervisor as sv

FAKE = str(Path(__file__).with_name("fake_acp_agent.py"))
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX process groups")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def make_spec(tmp_path: Path, argv: list[str], **over) -> dict:
    port = free_port()
    raw = {
        "harness": "claude",
        "argv": argv,
        "resume_args": ["--resume", "{id}"],
        "env": {"FAKE_LOG": str(tmp_path / "fake.log")},
        "adapter": None,
        "transport": "stdio",
        "host": "127.0.0.1",
        "port": port,
        "inner_port": free_port(),
        "state_dir": str(tmp_path / "state"),
        "restart": {"policy": "on-failure", "max_restarts": 3, "backoff_seconds": 0.01,
                    "backoff_max_seconds": 0.02, "stable_seconds": 60},
        "max_line_bytes": 64 * 1024,
        "max_peers": 1,
    }
    raw.update(over)
    return sv.load_spec(json.dumps(raw))


def events(tmp_path: Path) -> list[dict]:
    path = tmp_path / "state" / sv.EVENTS_FILE
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


def state(tmp_path: Path) -> dict:
    return json.loads((tmp_path / "state" / sv.STATE_FILE).read_text())


class Client:
    def __init__(self, r, w):
        self.r, self.w, self.n = r, w, 0

    @classmethod
    async def connect(cls, port: int) -> "Client":
        for _ in range(100):
            try:
                return cls(*await asyncio.open_connection("127.0.0.1", port))
            except OSError:
                await asyncio.sleep(0.05)
        raise AssertionError("endpoint never listened")

    async def send(self, obj: dict) -> None:
        self.w.write((json.dumps(obj) + "\n").encode())
        await self.w.drain()

    async def read(self) -> dict:
        return json.loads(await asyncio.wait_for(self.r.readline(), 10))

    async def call(self, method: str, params: dict, notes: list | None = None) -> dict:
        self.n += 1
        await self.send({"jsonrpc": "2.0", "id": self.n, "method": method, "params": params})
        while True:
            msg = await self.read()
            if msg.get("id") == self.n and "method" not in msg:
                return msg
            if notes is not None:
                notes.append(msg)

    def close(self) -> None:
        self.w.close()


async def run_bg(sup: sv.Supervisor) -> asyncio.Task:
    task = asyncio.create_task(sup.run())
    await asyncio.sleep(0)
    return task


async def finish(sup: sv.Supervisor, task: asyncio.Task) -> int:
    sup.stop()
    return await asyncio.wait_for(task, 10)


PROMPT = {"sessionId": "sess-1", "prompt": [{"type": "text", "text": "hi"}]}


# --- AG2b: restart policy ---

async def test_restarts_with_backoff_then_gives_up(tmp_path):
    spec = make_spec(tmp_path, [sys.executable, "-c", "import sys; sys.exit(1)"])
    rc = await asyncio.wait_for(sv.Supervisor(spec).run(), 10)
    assert rc == 1
    ev = events(tmp_path)
    assert [e["event"] for e in ev].count("agent.started") == 4
    assert [e["delay_seconds"] for e in ev if e["event"] == "agent.restarting"] == [0.01, 0.02, 0.02]
    assert all(e["exit_code"] == 1 for e in ev if e["event"] == "agent.exited")
    assert ev[-1]["event"] == "agent.gave_up"
    assert state(tmp_path)["state"] == "exited"


async def test_clean_exit_is_not_restarted_on_failure_policy(tmp_path):
    spec = make_spec(tmp_path, [sys.executable, "-c", "pass"])
    assert await asyncio.wait_for(sv.Supervisor(spec).run(), 10) == 0
    assert [e["event"] for e in events(tmp_path)].count("agent.started") == 1
    assert state(tmp_path)["state"] == "exited"


async def test_always_policy_restarts_a_clean_exit(tmp_path):
    spec = make_spec(tmp_path, [sys.executable, "-c", "pass"],
                     restart={"policy": "always", "max_restarts": 1, "backoff_seconds": 0})
    await asyncio.wait_for(sv.Supervisor(spec).run(), 10)
    assert [e["event"] for e in events(tmp_path)].count("agent.started") == 2


async def test_signal_exit_recorded_as_128_plus_signal(tmp_path):
    spec = make_spec(tmp_path, [sys.executable, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGKILL)"],
                     restart={"policy": "never"})
    assert await asyncio.wait_for(sv.Supervisor(spec).run(), 10) == 137


async def test_stop_terminates_the_agent(tmp_path):
    spec = make_spec(tmp_path, [sys.executable, FAKE])
    sup = sv.Supervisor(spec)
    task = await run_bg(sup)
    await asyncio.wait_for(sup.running.wait(), 10)
    assert sup.proc is not None and sup.proc.pid != 1
    assert await finish(sup, task) == 0
    assert state(tmp_path)["event"] == "supervisor/stopped"


# --- AG2b: resume by exact session id ---

def test_adapter_argv_resumes_the_hook_recorded_session(tmp_path):
    spec = make_spec(
        tmp_path, ["claude", "-p"], transport="tcp",
        adapter=["acp-serve", "--port", "{port}", "--session", "{session_id}", "--", "{harness_argv}", "{resume_argv}"],
    )
    sup = sv.Supervisor(spec)
    assert sup.argv() == ["acp-serve", "--port", str(spec["inner_port"]), "--session", "", "--", "claude", "-p"]
    state_dir = tmp_path / "state"
    state_dir.mkdir()
    (state_dir / "claude.sid").write_text("abc-123\n")
    sup.session_id = sup.recorded_session()
    assert sup.argv()[-4:] == ["claude", "-p", "--resume", "abc-123"]
    assert sup.child_env()["WARREN_AGENT_SESSION_ID"] == "abc-123"
    assert sv.SPEC_ENV not in sup.child_env()


def test_newest_session_record_wins(tmp_path):
    d = tmp_path / "state"
    d.mkdir()
    (d / "claude.sid").write_text("old-id")
    os.utime(d / "claude.sid", (1, 1))
    (d / sv.SESSION_FILE).write_text(json.dumps({"session_id": "new-id"}))
    assert sv.Supervisor(make_spec(tmp_path, ["x"])).recorded_session() == "new-id"
    (d / sv.SESSION_FILE).write_text(json.dumps({"session_id": "bad id!"}))
    assert sv.Supervisor(make_spec(tmp_path, ["x"])).recorded_session() == "old-id"


async def test_restart_reloads_the_connected_peers_session(tmp_path):
    spec = make_spec(tmp_path, [sys.executable, FAKE])
    sup = sv.Supervisor(spec)
    task = await run_bg(sup)
    c = await Client.connect(spec["port"])
    await c.call("initialize", {"protocolVersion": 1})
    assert (await c.call("session/new", {"cwd": str(tmp_path), "mcpServers": []}))["result"]["sessionId"] == "sess-1"
    crashed = await c.call("session/prompt", {**PROMPT, "prompt": [{"type": "text", "text": "crash"}]})
    assert crashed["error"]["code"] == -32603
    notes: list = []
    again = await c.call("session/prompt", PROMPT, notes)
    assert again["result"] == {"stopReason": "end_turn"}
    assert [n["params"]["update"]["sessionUpdate"] for n in notes] == ["agent_message_chunk"]
    log = (tmp_path / "fake.log").read_text().split("\n")
    pids = {line.split()[0] for line in log if line}
    assert len(pids) == 2
    assert any(line.endswith("session/load sess-1") for line in log)
    assert json.loads((tmp_path / "state" / sv.SESSION_FILE).read_text())["session_id"] == "sess-1"
    assert "agent.resumed" in [e["event"] for e in events(tmp_path)]
    c.close()
    await finish(sup, task)


async def test_relaunch_picks_up_the_recorded_session(tmp_path):
    spec = make_spec(tmp_path, [sys.executable, FAKE])
    (tmp_path / "state").mkdir()
    (tmp_path / "state" / sv.SESSION_FILE).write_text(json.dumps({"session_id": "sess-9"}))
    sup = sv.Supervisor(spec)
    task = await run_bg(sup)
    await asyncio.wait_for(sup.running.wait(), 10)
    assert sup.session_id == "sess-9"
    assert [e for e in events(tmp_path) if e["event"] == "agent.started"][0]["session_id"] == "sess-9"
    await finish(sup, task)


# --- AM1 state mapping ---

async def test_states_follow_the_acp_traffic(tmp_path):
    spec = make_spec(tmp_path, [sys.executable, FAKE])
    sup = sv.Supervisor(spec)
    task = await run_bg(sup)
    c = await Client.connect(spec["port"])
    await c.call("initialize", {"protocolVersion": 1})
    await c.call("session/new", {"cwd": str(tmp_path), "mcpServers": []})
    assert state(tmp_path)["state"] == "idle"
    c.n += 1
    await c.send({"jsonrpc": "2.0", "id": c.n, "method": "session/prompt",
                  "params": {**PROMPT, "prompt": [{"type": "text", "text": "permission"}]}})
    ask = await c.read()
    assert ask["method"] == "session/request_permission"
    assert state(tmp_path)["state"] == "blocked"
    await c.send({"jsonrpc": "2.0", "id": ask["id"], "result": {"outcome": {"outcome": "selected", "optionId": "allow"}}})
    while (await c.read()).get("id") != c.n:
        pass
    assert state(tmp_path) | {"ts": 0} == {
        "harness": "claude", "state": "idle", "session_id": "sess-1",
        "event": "session/prompt/done", "ts": 0, "source": "supervisor",
    }
    c.close()
    await finish(sup, task)
    assert state(tmp_path)["state"] == "exited"
