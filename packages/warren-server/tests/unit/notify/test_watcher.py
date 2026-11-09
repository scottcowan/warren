"""The agent-state watcher and the lifecycle hooks (idle reaper, provision failure)."""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

from pydantic import SecretStr
from warren.notify import events as ev
from warren.notify.dispatcher import Notifier
from warren.notify.targets import Target
from warren.notify.watcher import poll_once, run_agent_state_watcher
from warren_common import agent_state as st


def _ws(wid="ws-1", owner="u1", status="running"):
    return SimpleNamespace(workspace_id=wid, project="p", owner_id=owner, intent="t", status=status,
                           container_id="c", spec_json="{}", idle_ttl_seconds=None)


class Recorder(Notifier):
    def __init__(self, owners=None, server=True):
        async def watched():
            return owners or set()

        super().__init__(
            server_target=Target(url=SecretStr("https://h.example.com/x")) if server else None,
            watched_owners=watched, sender=AsyncMock(return_value=200), dedupe_seconds=0,
        )
        self.emitted: list[tuple[str, str, str]] = []

    def emit(self, event, ws, message):
        self.emitted.append((ws.workspace_id, event, message))
        return True


def _registry(workspaces):
    reg = MagicMock()
    reg.store.list_non_terminal = AsyncMock(return_value=workspaces)
    return reg


class Script:
    """Agent state per workspace, advanced by the test."""

    def __init__(self):
        self.states: dict[str, st.AgentState | None] = {}
        self.reads: list[str] = []

    async def __call__(self, ws):
        self.reads.append(ws.workspace_id)
        return self.states.get(ws.workspace_id)


async def test_transitions_become_events_and_flaps_are_detected_once_per_change():
    reg, n, script, last = _registry([_ws()]), Recorder(), Script(), {}
    script.states["ws-1"] = st.AgentState(st.WORKING, 1, harness="claude", event="PreToolUse")
    assert await poll_once(reg, n, last, script) == []  # baseline
    script.states["ws-1"] = st.AgentState(st.BLOCKED, 2, harness="claude", event="PermissionRequest")
    assert await poll_once(reg, n, last, script) == [("ws-1", ev.AGENT_WAITING)]
    assert await poll_once(reg, n, last, script) == []  # unchanged
    script.states["ws-1"] = st.AgentState(st.IDLE, 3, harness="claude", event="Stop")
    assert await poll_once(reg, n, last, script) == [("ws-1", ev.AGENT_FINISHED)]
    script.states["ws-1"] = st.AgentState(st.IDLE, 4, harness="claude", event="StopFailure")
    assert await poll_once(reg, n, last, script) == [("ws-1", ev.AGENT_FAILED)]
    assert n.emitted[0][2] == "claude is waiting for input"


async def test_only_running_workspaces_of_watched_owners_are_read():
    wss = [_ws("a", "u1"), _ws("b", "u2"), _ws("c", "u1", status="provisioning")]
    reg, script = _registry(wss), Script()
    await poll_once(reg, Recorder(owners={"u1"}, server=False), {}, script)
    assert script.reads == ["a"]


async def test_nobody_listening_reads_nothing():
    reg, script, last = _registry([_ws()]), Script(), {"stale": st.AgentState(st.IDLE, 1)}
    await poll_once(reg, Recorder(owners=set(), server=False), last, script)
    assert script.reads == [] and last == {}
    reg.store.list_non_terminal.assert_not_awaited()


async def test_gone_workspace_is_forgotten_and_reader_errors_are_tolerated():
    reg, n, last = _registry([_ws()]), Recorder(), {"old": st.AgentState(st.IDLE, 1)}

    async def broken(ws):
        raise OSError("unreadable")

    assert await poll_once(reg, n, last, broken) == []
    assert last == {}


async def test_run_loop_survives_errors_and_cancels():
    reg = MagicMock()
    reg.store.list_non_terminal = AsyncMock(side_effect=RuntimeError("db"))
    sleeps = []

    async def sleep(d):
        sleeps.append(d)
        if len(sleeps) >= 2:
            raise asyncio.CancelledError

    try:
        await run_agent_state_watcher(reg, Recorder(), poll_interval=7, read_agent_state=Script(), sleep=sleep)
    except asyncio.CancelledError:
        pass
    assert sleeps == [7, 7]


async def test_idle_reaper_notifies_on_stop(monkeypatch):
    from warren.registry.idle_reaper import run_idle_reaper

    ws = _ws()
    stopped = SimpleNamespace(**{**vars(ws), "status": "stopped"})
    reg = MagicMock()
    reg.store.list_non_terminal = AsyncMock(return_value=[ws])
    reg.store.get = AsyncMock(return_value=stopped)
    reg.store.mark_idle_stopped = AsyncMock()
    reg.store.list_idle_stopped = AsyncMock(return_value=[])
    reg.stop = AsyncMock()
    reg.notifier = Recorder()
    clock = iter([0.0, 100.0, 200.0])
    polls = []

    async def fake_sleep(_d):
        polls.append(1)
        if len(polls) >= 2:
            raise asyncio.CancelledError

    import warren.registry.idle_reaper as ir

    monkeypatch.setattr(ir.asyncio, "sleep", fake_sleep)
    try:
        await run_idle_reaper(
            reg, poll_interval=1, idle_ttl_seconds=10, clock=lambda: next(clock),
            read_egress_bytes=lambda _cid: 5, read_agent_state=AsyncMock(return_value=None),
        )
    except asyncio.CancelledError:
        pass
    assert reg.notifier.emitted == [("ws-1", ev.IDLE_STOPPED, "stopped by the idle reaper (egress_idle)")]


async def test_provision_failure_notifies():
    from warren.registry.registry import WorkspaceRegistry
    from warren_common.errors import ImageUnavailable

    store = MagicMock()
    store.update_status = AsyncMock()
    store.get = AsyncMock(return_value=_ws(status="failed"))
    reg = WorkspaceRegistry(runtime=MagicMock(), store=store, server_id="s")
    reg.notifier = Recorder()
    reg._materialize_and_provision = AsyncMock(side_effect=ImageUnavailable("no image at /secret/path"))
    await reg._do_provision("ws-1", MagicMock())
    assert reg.notifier.emitted == [("ws-1", ev.PROVISION_FAILED, "provisioning failed (image_unavailable)")]

    reg.notifier.emitted.clear()
    reg._materialize_and_provision = AsyncMock(side_effect=RuntimeError("token=abc"))
    await reg._do_provision("ws-1", MagicMock())
    assert reg.notifier.emitted == [("ws-1", ev.PROVISION_FAILED, "provisioning failed (unexpected_error)")]


async def test_no_notifier_is_a_no_op():
    from warren.notify import notify_workspace, notify_workspace_id

    reg = MagicMock()  # a MagicMock attribute is not a Notifier
    notify_workspace(reg, ev.IDLE_STOPPED, _ws(), "m")
    await notify_workspace_id(reg, ev.IDLE_STOPPED, "ws-1", "m")
