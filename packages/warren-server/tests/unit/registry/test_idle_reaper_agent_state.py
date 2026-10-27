"""AM1: state-aware reaping. Hook-reported agent state (AG5) holds a due workspace
back but never stops one early; no hook behaves exactly as the egress rule."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

import warren.registry.idle_reaper as mod
from warren.registry.registry import WorkspaceRegistry as Registry
from warren_common.agent_state import AgentState
from warren_common.runtime.base import ExecExit, ExecUnavailable

_REAL_SLEEP = asyncio.sleep
TTL, BLOCKED_TTL, MAX_HOLD, STEP = 50.0, 200.0, 1000.0, 20.0


class _Clock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now


class _Events:
    def __init__(self) -> None:
        self.pushed: list[dict] = []

    def get_or_create(self, _wid):
        return SimpleNamespace(push=self._push)

    async def _push(self, line: str) -> None:
        self.pushed.append(json.loads(line))


def _registry(ws):
    stopped = SimpleNamespace(**{**vars(ws), "status": "stopped"})
    return SimpleNamespace(
        store=SimpleNamespace(
            list_non_terminal=AsyncMock(return_value=[ws]),
            get=AsyncMock(return_value=stopped),
            mark_idle_stopped=AsyncMock(),
            list_idle_stopped=AsyncMock(return_value=[]),
        ),
        # Like production: a stopped workspace no longer lists as running.
        stop=AsyncMock(side_effect=lambda _wid: setattr(ws, "status", "stopped")),
        event_store=_Events(),
    )


def _ws(spec: dict | None = None):
    return SimpleNamespace(
        workspace_id="ws-1", status="running", container_id="ctr-1", idle_ttl_seconds=None, root_path="/w",
        spec_json=json.dumps(spec or {}),
    )


async def _run(registry, monkeypatch, *, polls: int, state, egress=lambda t: 1000, attached=None, until_stop=True):
    """Poll `polls` times, STEP seconds apart. `state(t)` / `egress(t)` give the
    reported agent state and egress byte count at time t. Returns the stop time or None.
    With until_stop=False it runs all `polls` passes, so the result never depends on
    how many passes happen before cancellation."""
    clock = _Clock()
    n = {"polls": 0, "stopped_at": None}
    done = asyncio.Event()

    async def _sleep(_s):
        n["polls"] += 1
        if registry.stop.await_count and n["stopped_at"] is None:
            n["stopped_at"] = clock.now
        clock.now += STEP
        if n["polls"] >= polls or (until_stop and n["stopped_at"] is not None):
            done.set()
        await _REAL_SLEEP(0)

    monkeypatch.setattr(mod.asyncio, "sleep", _sleep)

    async def _state(_ws):
        return state(clock.now)

    async def _attached(_ws):
        return attached

    extra = {} if attached is None else {"client_attached": _attached}
    task = asyncio.create_task(mod.run_idle_reaper(
        registry, poll_interval=0.001, idle_ttl_seconds=TTL, clock=clock,
        read_egress_bytes=lambda _cid: egress(clock.now), read_agent_state=_state,
        blocked_ttl_seconds=BLOCKED_TTL, hook_max_hold_seconds=MAX_HOLD, **extra,
    ))
    try:
        await asyncio.wait_for(done.wait(), timeout=10)
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    return n["stopped_at"]


@pytest.mark.asyncio
async def test_no_hook_behaves_as_the_egress_rule(monkeypatch):
    reg = _registry(_ws())
    stopped_at = await _run(reg, monkeypatch, polls=20, state=lambda t: None)
    assert stopped_at is not None and stopped_at <= TTL + 2 * STEP
    reg.stop.assert_awaited_with("ws-1")


@pytest.mark.asyncio
async def test_a_tool_running_past_the_ttl_is_not_reaped(monkeypatch):
    reg = _registry(_ws())
    working = AgentState("working", ts=1.0, session_id="s", harness="claude")
    assert await _run(reg, monkeypatch, polls=30, state=lambda t: working) is None
    reg.stop.assert_not_awaited()


@pytest.mark.asyncio
async def test_hooks_hold_back_only_up_to_the_hard_max(monkeypatch):
    reg = _registry(_ws())
    stopped_at = await _run(
        reg, monkeypatch, polls=200, state=lambda t: AgentState("working", ts=t)  # an event every poll
    )
    assert stopped_at is not None and MAX_HOLD <= stopped_at <= MAX_HOLD + TTL + 3 * STEP


@pytest.mark.asyncio
async def test_blocked_is_notified_then_stopped_only_after_blocked_ttl(monkeypatch):
    reg = _registry(_ws())
    blocked = AgentState("blocked", ts=1.0, harness="claude", event="PermissionRequest")
    stopped_at = await _run(reg, monkeypatch, polls=100, state=lambda t: blocked, until_stop=False)
    assert stopped_at is not None and BLOCKED_TTL <= stopped_at <= BLOCKED_TTL + 2 * STEP
    assert reg.stop.await_count == 1
    assert reg.event_store.pushed == [{"type": "workspace.agent_blocked", "workspace_id": "ws-1", "harness": "claude"}]


@pytest.mark.asyncio
async def test_blocked_notified_once_per_episode(monkeypatch):
    reg = _registry(_ws())

    def state(t):
        if t < 100:
            return AgentState("blocked", ts=1.0)
        if t < 120:
            return None  # unreadable for a pass: tracking resets, episode is the same
        if t < 200:
            return AgentState("blocked", ts=1.0)
        if t < 300:
            return AgentState("idle", ts=250.0)
        return AgentState("blocked", ts=300.0)

    await _run(reg, monkeypatch, polls=20, state=state, egress=lambda t: int(t), until_stop=False)
    reg.stop.assert_not_awaited()
    assert [e["type"] for e in reg.event_store.pushed] == ["workspace.agent_blocked"] * 2


@pytest.mark.asyncio
async def test_idle_events_reset_the_clock_then_idle_is_reaped(monkeypatch):
    reg = _registry(_ws())
    # An idle report each poll until t=300 (e.g. turns finishing), then silence.
    stopped_at = await _run(reg, monkeypatch, polls=100, state=lambda t: AgentState("idle", ts=min(t, 300.0) + 1))
    assert stopped_at is not None and 300 + TTL <= stopped_at <= 300 + TTL + 2 * STEP


@pytest.mark.asyncio
async def test_idle_with_a_client_attached_is_held(monkeypatch):
    reg = _registry(_ws())
    idle = AgentState("idle", ts=1.0)
    assert await _run(reg, monkeypatch, polls=30, state=lambda t: idle, attached=True) is None


@pytest.mark.asyncio
async def test_the_registry_client_check_is_used_by_default(monkeypatch):
    reg = _registry(_ws())
    reg.client_attached = AsyncMock(return_value=True)
    idle = AgentState("idle", ts=1.0)
    assert await _run(reg, monkeypatch, polls=30, state=lambda t: idle) is None
    reg.client_attached.assert_awaited()
    reg.client_attached = AsyncMock(side_effect=RuntimeError("exec failed"))
    assert await _run(reg, monkeypatch, polls=30, state=lambda t: idle) is not None


@pytest.mark.asyncio
async def test_a_hook_never_stops_a_workspace_early(monkeypatch):
    reg = _registry(_ws())
    exited = AgentState("exited", ts=1.0)
    assert await _run(reg, monkeypatch, polls=30, state=lambda t: exited, egress=lambda t: int(t)) is None


@pytest.mark.asyncio
async def test_single_turn_stays_excluded_with_hooks(monkeypatch):
    reg = _registry(_ws({"mode": "single-turn"}))
    assert await _run(reg, monkeypatch, polls=100, state=lambda t: AgentState("idle", ts=1.0)) is None


@pytest.mark.asyncio
async def test_a_failing_state_reader_is_unverifiable(monkeypatch):
    reg = _registry(_ws())

    def boom(t):
        raise OSError("sidecar unreachable")

    assert await _run(reg, monkeypatch, polls=20, state=boom) is not None


@pytest.mark.asyncio
async def test_registry_reads_hook_state_then_osc_without_following_links(tmp_path):
    base = tmp_path / "harness" / "ws-1"
    (base / ".session").mkdir(parents=True)
    reg = SimpleNamespace(_agent_state_dir=lambda ws: base)
    ws = _ws()
    assert await Registry.agent_state(reg, ws) is None
    (base / ".session" / "osc-state.json").write_text(json.dumps({"state": "working", "ts": 3}))
    assert (await Registry.agent_state(reg, ws)).source == "osc"
    (base / ".session" / "state.json").write_text(
        json.dumps({"state": "blocked", "ts": 4, "session_id": "s1", "harness": "claude"})
    )
    got = await Registry.agent_state(reg, ws)
    assert (got.state, got.session_id, got.source) == ("blocked", "s1", "hook")
    (base / ".session" / "state.json").unlink()
    (base / ".session" / "osc-state.json").unlink()
    (tmp_path / "elsewhere.json").write_text(json.dumps({"state": "working", "ts": 9}))
    (base / ".session" / "state.json").symlink_to(tmp_path / "elsewhere.json")
    assert await Registry.agent_state(reg, ws) is None
    assert await Registry.agent_state(SimpleNamespace(_agent_state_dir=lambda ws: None), ws) is None


def _ecs_registry(mount: str):
    reg = SimpleNamespace(settings=SimpleNamespace(runtime_type="ecs", efs_local_mount_path=mount))
    reg._harness_state_dir = lambda wid: None
    reg._ecs_mount = lambda ws: Registry._ecs_mount(reg, ws)
    reg._agent_state_dir = lambda ws: Registry._agent_state_dir(reg, ws)
    return reg


@pytest.mark.asyncio
async def test_ecs_agent_state_is_read_from_the_workspace_efs_dir(tmp_path):
    session = tmp_path / "workspaces" / "ws-1" / "harness" / ".session"
    session.mkdir(parents=True)
    (session / "state.json").write_text(json.dumps({"state": "working", "ts": 7, "harness": "codex"}))
    got = await Registry.agent_state(_ecs_registry(str(tmp_path)), _ws())
    assert (got.state, got.harness) == ("working", "codex")
    assert await Registry.agent_state(_ecs_registry(""), _ws()) is None
    bad = SimpleNamespace(**{**vars(_ws()), "workspace_id": "../ws-1"})
    assert await Registry.agent_state(_ecs_registry(str(tmp_path)), bad) is None


@pytest.mark.asyncio
async def test_supervised_agent_state_holds_the_workspace_over_an_idle_shell(tmp_path):
    """AG2b: the supervisor and the agent's hook report under .session/agent/; the busier
    of shell and agent wins, and the supervisor's exit is final for the agent."""
    session = tmp_path / "workspaces" / "ws-1" / "harness" / ".session"
    agent = session / "agent"
    agent.mkdir(parents=True)
    (session / "state.json").write_text(json.dumps({"state": "idle", "ts": 9, "harness": "claude"}))
    (agent / "supervisor.json").write_text(
        json.dumps({"state": "working", "ts": 5, "harness": "opencode", "session_id": "s-1"})
    )
    reg = _ecs_registry(str(tmp_path))
    got = await Registry.agent_state(reg, _ws())
    assert (got.state, got.harness, got.session_id, got.source) == ("working", "opencode", "s-1", "supervisor")
    (agent / "supervisor.json").write_text(json.dumps({"state": "idle", "ts": 5, "harness": "opencode"}))
    (agent / "state.json").write_text(json.dumps({"state": "blocked", "ts": 6, "harness": "opencode"}))
    assert (await Registry.agent_state(reg, _ws())).state == "blocked"
    (agent / "supervisor.json").write_text(json.dumps({"state": "exited", "ts": 8, "harness": "opencode"}))
    assert (await Registry.agent_state(reg, _ws())).state == "idle"


class _Runtime:
    def __init__(self, items=(), exc=None, hang=False):
        self.items, self.exc, self.hang, self.argv = list(items), exc, hang, None

    async def exec_stream(self, handle, argv):
        self.argv = argv
        if self.exc:
            raise self.exc
        if self.hang:
            await asyncio.Event().wait()
        for item in self.items:
            yield item


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("items", "exc", "hang", "expected"),
    [
        ([b"attached\r\n", ExecExit(0)], None, False, True),
        ([b"", ExecExit(0)], None, False, False),
        ([b"attached\n", ExecExit(1)], None, False, False),
        ([], ExecUnavailable("no plugin"), False, False),
        ([], None, True, False),
    ],
)
async def test_client_attached_asks_tmux_through_the_runtime_exec(items, exc, hang, expected):
    runtime = _Runtime(items, exc, hang)
    reg = SimpleNamespace(runtime=runtime)
    assert await Registry.client_attached(reg, _ws(), timeout=0.2) is expected
    assert runtime.argv[:2] == ["sh", "-c"] and "list-clients -t main" in runtime.argv[2]
    assert await Registry.client_attached(SimpleNamespace(runtime=SimpleNamespace()), _ws()) is False
