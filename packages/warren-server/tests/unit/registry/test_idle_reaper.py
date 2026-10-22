"""Unit tests for run_idle_reaper — Plan 04-05 Task 2 (LIFE-01).

Drives the loop by monkeypatching asyncio.sleep (as seen by the idle_reaper module)
to a hook that never really waits, so the loop advances through many iterations
instantly. No real sleeps/timers are used anywhere in this file.

IMPORTANT: `warren.registry.idle_reaper` does `import asyncio` and calls
`asyncio.sleep(...)`, so `mod.asyncio` IS the process-wide `asyncio` module object —
monkeypatching `mod.asyncio.sleep` therefore also replaces the *global* `asyncio.sleep`
for the duration of the test (including calls made directly in this test file). Every
fake-sleep implementation below captures the REAL `asyncio.sleep` before patching and
awaits it internally (with a 0 duration) so control is still genuinely yielded back to
the event loop — otherwise the reaper task never actually gets scheduled.
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

import warren.registry.idle_reaper as mod

_REAL_SLEEP = asyncio.sleep


def _ws(
    workspace_id: str,
    status: str = "running",
    container_id: str = "ctr-1",
    idle_ttl_seconds: float | None = None,
):
    return SimpleNamespace(
        workspace_id=workspace_id,
        status=status,
        container_id=container_id,
        idle_ttl_seconds=idle_ttl_seconds,
    )


class _FakeClock:
    """Deterministic monotonic clock — advanced explicitly by the sleep hook."""

    def __init__(self, start: float = 0.0) -> None:
        self._now = start

    def __call__(self) -> float:
        return self._now

    def advance(self, seconds: float) -> None:
        self._now += seconds


async def _drive_until(registry, monkeypatch, *, clock, on_sleep, min_polls: int):
    """Start run_idle_reaper, run it for at least `min_polls` poll iterations, cancel it.

    `on_sleep` is called (no args) once per simulated `asyncio.sleep` inside the loop —
    tests use it to advance the fake clock and/or mutate mock return values between polls.
    """
    poll_count = {"n": 0}
    done = asyncio.Event()

    async def _fake_sleep(_seconds):
        poll_count["n"] += 1
        on_sleep()
        if poll_count["n"] >= min_polls:
            done.set()
        await _REAL_SLEEP(0)

    monkeypatch.setattr(mod.asyncio, "sleep", _fake_sleep)

    task = asyncio.create_task(
        mod.run_idle_reaper(registry, poll_interval=0.001, idle_ttl_seconds=50.0, clock=clock)
    )
    try:
        await asyncio.wait_for(done.wait(), timeout=5.0)
    finally:
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass
    return poll_count["n"]


@pytest.mark.asyncio
async def test_stops_workspace_after_ttl_with_no_egress_delta(monkeypatch):
    ws = _ws("ws-1")
    clock = _FakeClock()
    registry = SimpleNamespace(
        store=SimpleNamespace(list_non_terminal=AsyncMock(return_value=[ws])),
        stop=AsyncMock(),
    )

    def _fake_egress(*args, **kwargs):
        return 1000  # never changes

    monkeypatch.setattr(mod, "read_container_egress_bytes", _fake_egress)

    # First poll seeds the timer; the clock advances by 100s (> 50s TTL) between
    # polls via on_sleep, so the second poll observes the TTL has elapsed.
    await _drive_until(
        registry, monkeypatch, clock=clock, on_sleep=lambda: clock.advance(100.0), min_polls=2
    )

    assert registry.stop.await_count >= 1
    registry.stop.assert_awaited_with("ws-1")


@pytest.mark.asyncio
async def test_per_workspace_idle_ttl_override_wins_over_global_default(monkeypatch):
    """A workspace row carrying its own idle_ttl_seconds (threaded from
    ProjectConfig.idle_ttl_seconds at provision time) must use that instead of
    the server-wide default -- an unattended ops workspace needs a much longer
    grace period than the operator's global TTL. 100s of flat egress exceeds
    _drive_until's hardcoded 50s global default, but not this workspace's own
    200s override, so it must NOT be stopped."""
    ws = _ws("ws-1", idle_ttl_seconds=200.0)
    clock = _FakeClock()
    registry = SimpleNamespace(
        store=SimpleNamespace(list_non_terminal=AsyncMock(return_value=[ws])),
        stop=AsyncMock(),
    )

    def _fake_egress(*args, **kwargs):
        return 1000  # never changes

    monkeypatch.setattr(mod, "read_container_egress_bytes", _fake_egress)

    await _drive_until(
        registry, monkeypatch, clock=clock, on_sleep=lambda: clock.advance(100.0), min_polls=2
    )

    registry.stop.assert_not_awaited()


@pytest.mark.asyncio
async def test_traffic_resets_idle_timer(monkeypatch):
    ws = _ws("ws-1")
    clock = _FakeClock()
    registry = SimpleNamespace(
        store=SimpleNamespace(list_non_terminal=AsyncMock(return_value=[ws])),
        stop=AsyncMock(),
    )

    counts = {"n": 0}

    def _fake_egress(*args, **kwargs):
        counts["n"] += 1000
        return counts["n"]  # strictly increasing every poll -> never idle

    monkeypatch.setattr(mod, "read_container_egress_bytes", _fake_egress)

    await _drive_until(
        registry, monkeypatch, clock=clock, on_sleep=lambda: clock.advance(1000.0), min_polls=5
    )

    registry.stop.assert_not_awaited()


@pytest.mark.asyncio
async def test_first_sighting_starts_timer_now(monkeypatch):
    # Simulate a server that has been up a long time: an old clock start must not
    # matter, since the timer only starts once this loop observes the workspace.
    clock = _FakeClock(start=99999.0)
    ws = _ws("ws-1")
    registry = SimpleNamespace(
        store=SimpleNamespace(list_non_terminal=AsyncMock(return_value=[ws])),
        stop=AsyncMock(),
    )

    def _fake_egress(*args, **kwargs):
        return 42  # constant, but this is the FIRST poll every time

    monkeypatch.setattr(mod, "read_container_egress_bytes", _fake_egress)

    # Clock never advances between polls -> byte count "changes" is irrelevant here;
    # the point is the very first poll must never stop the workspace.
    await _drive_until(registry, monkeypatch, clock=clock, on_sleep=lambda: None, min_polls=1)

    registry.stop.assert_not_awaited()


@pytest.mark.asyncio
async def test_skips_non_running_rows(monkeypatch):
    provisioning_ws = _ws("ws-1", status="provisioning")
    stopping_ws = _ws("ws-2", status="stopping")
    unknown_ws = _ws("ws-3", status="unknown")
    registry = SimpleNamespace(
        store=SimpleNamespace(
            list_non_terminal=AsyncMock(
                return_value=[provisioning_ws, stopping_ws, unknown_ws]
            )
        ),
        stop=AsyncMock(),
    )

    egress_calls: list[str] = []

    def _fake_egress(container_id, *args, **kwargs):
        egress_calls.append(container_id)
        return 1

    monkeypatch.setattr(mod, "read_container_egress_bytes", _fake_egress)

    await _drive_until(
        registry, monkeypatch, clock=_FakeClock(), on_sleep=lambda: None, min_polls=1
    )

    assert egress_calls == []
    registry.stop.assert_not_awaited()


@pytest.mark.asyncio
async def test_skips_rows_without_container_id(monkeypatch):
    ws_none = _ws("ws-1", container_id=None)
    ws_empty = _ws("ws-2", container_id="")
    registry = SimpleNamespace(
        store=SimpleNamespace(list_non_terminal=AsyncMock(return_value=[ws_none, ws_empty])),
        stop=AsyncMock(),
    )

    egress_calls: list[str] = []

    def _fake_egress(container_id, *args, **kwargs):
        egress_calls.append(container_id)
        return 1

    monkeypatch.setattr(mod, "read_container_egress_bytes", _fake_egress)

    await _drive_until(
        registry, monkeypatch, clock=_FakeClock(), on_sleep=lambda: None, min_polls=1
    )

    assert egress_calls == []


@pytest.mark.asyncio
async def test_egress_unavailable_skips_only_that_workspace(monkeypatch):
    from warren.network.egress import EgressUnavailable

    bad_ws = _ws("ws-bad", container_id="ctr-bad")
    good_ws = _ws("ws-good", container_id="ctr-good")
    registry = SimpleNamespace(
        store=SimpleNamespace(list_non_terminal=AsyncMock(return_value=[bad_ws, good_ws])),
        stop=AsyncMock(),
    )

    def _fake_egress(container_id, *args, **kwargs):
        if container_id == "ctr-bad":
            raise EgressUnavailable("boom")
        return 1

    monkeypatch.setattr(mod, "read_container_egress_bytes", _fake_egress)

    polls = await _drive_until(
        registry, monkeypatch, clock=_FakeClock(), on_sleep=lambda: None, min_polls=2
    )

    assert polls >= 2, "loop must survive EgressUnavailable and keep polling"
    registry.stop.assert_not_awaited()


@pytest.mark.asyncio
async def test_stopped_workspace_tracking_discarded(monkeypatch):
    ws = _ws("ws-1")
    clock = _FakeClock()
    registry = SimpleNamespace(
        store=SimpleNamespace(list_non_terminal=AsyncMock(return_value=[ws])),
        stop=AsyncMock(),
    )

    def _fake_egress(*args, **kwargs):
        return 1000  # constant -> idle

    monkeypatch.setattr(mod, "read_container_egress_bytes", _fake_egress)

    # Poll 1 seeds the timer. Poll 2 observes idle_seconds >= TTL and stops the
    # workspace, discarding its tracking entry. Poll 3 re-seeds a fresh timer for
    # the same still-"running" mock workspace (this mock never flips status) rather
    # than re-firing immediately off the stale entry — proving discard happened.
    await _drive_until(
        registry, monkeypatch, clock=clock, on_sleep=lambda: clock.advance(100.0), min_polls=3
    )

    assert registry.stop.await_count == 1


@pytest.mark.asyncio
async def test_cancellation_propagates():
    registry = SimpleNamespace(
        store=SimpleNamespace(list_non_terminal=AsyncMock(return_value=[])),
        stop=AsyncMock(),
    )

    task = asyncio.create_task(
        mod.run_idle_reaper(
            registry, poll_interval=0.001, idle_ttl_seconds=50.0, clock=lambda: 0.0
        )
    )
    await asyncio.sleep(0)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.asyncio
async def test_survives_unexpected_exception(monkeypatch):
    registry = SimpleNamespace(
        store=SimpleNamespace(
            list_non_terminal=AsyncMock(side_effect=RuntimeError("boom"))
        ),
        stop=AsyncMock(),
    )

    polls = await _drive_until(
        registry, monkeypatch, clock=_FakeClock(), on_sleep=lambda: None, min_polls=2
    )

    assert polls >= 2, "loop must survive an unexpected exception and keep polling"


def _stopped_ws(workspace_id: str, status: str = "stopped", idle_destroy_seconds=None):
    import json

    spec = {} if idle_destroy_seconds is None else {"idle_destroy_seconds": idle_destroy_seconds}
    return SimpleNamespace(workspace_id=workspace_id, status=status, spec_json=json.dumps(spec))


def _destroy_registry(rows: dict, stopped_at):
    store = SimpleNamespace(
        list_idle_stopped=AsyncMock(return_value=[(wid, stopped_at) for wid in rows]),
        get=AsyncMock(side_effect=lambda wid: rows[wid]),
        clear_idle_stopped=AsyncMock(),
    )
    return SimpleNamespace(store=store, destroy=AsyncMock())


@pytest.mark.asyncio
async def test_idle_destroy_uses_template_ttl_then_server_default():
    from datetime import datetime, timedelta, timezone

    now = datetime(2026, 10, 22, tzinfo=timezone.utc)
    rows = {
        "tmpl-expired": _stopped_ws("tmpl-expired", idle_destroy_seconds=100.0),
        "tmpl-fresh": _stopped_ws("tmpl-fresh", idle_destroy_seconds=1000.0),
        "default-expired": _stopped_ws("default-expired"),
    }
    registry = _destroy_registry(rows, now - timedelta(seconds=500))

    await mod._destroy_expired_idle_stops(registry, 300.0, now)

    destroyed = sorted(c.args[0] for c in registry.destroy.await_args_list)
    assert destroyed == ["default-expired", "tmpl-expired"]


@pytest.mark.asyncio
async def test_idle_destroy_off_by_default():
    from datetime import datetime, timedelta, timezone

    now = datetime(2026, 10, 22, tzinfo=timezone.utc)
    registry = _destroy_registry({"ws-1": _stopped_ws("ws-1")}, now - timedelta(days=30))
    await mod._destroy_expired_idle_stops(registry, None, now)
    registry.destroy.assert_not_awaited()


@pytest.mark.asyncio
async def test_idle_destroy_clears_marker_once_workspace_is_no_longer_stopped():
    from datetime import datetime, timedelta, timezone

    now = datetime(2026, 10, 22, tzinfo=timezone.utc)
    registry = _destroy_registry(
        {"ws-1": _stopped_ws("ws-1", status="running", idle_destroy_seconds=1.0)},
        now - timedelta(days=1),
    )
    await mod._destroy_expired_idle_stops(registry, None, now)
    registry.destroy.assert_not_awaited()
    registry.store.clear_idle_stopped.assert_awaited_once_with("ws-1")


@pytest.mark.asyncio
async def test_idle_stop_records_idle_stop_marker(monkeypatch):
    ws = _ws("ws-1")
    clock = _FakeClock()
    registry = SimpleNamespace(
        store=SimpleNamespace(
            list_non_terminal=AsyncMock(return_value=[ws]),
            get=AsyncMock(return_value=SimpleNamespace(status="stopped")),
            mark_idle_stopped=AsyncMock(),
            list_idle_stopped=AsyncMock(return_value=[]),
        ),
        stop=AsyncMock(),
    )
    monkeypatch.setattr(mod, "read_container_egress_bytes", lambda *a, **kw: 1000)

    await _drive_until(registry, monkeypatch, clock=clock, on_sleep=lambda: clock.advance(100.0), min_polls=2)

    registry.store.mark_idle_stopped.assert_awaited_with("ws-1")


@pytest.mark.asyncio
async def test_store_idle_stop_marker_cleared_by_status_change(tmp_path):
    from warren.registry.store import WorkspaceStore

    store = await WorkspaceStore.open(tmp_path / "w.db")
    try:
        await store.insert(
            workspace_id="ws-1", project="p", intent="i", image="img", root_path="",
            server_instance="s", status="running",
        )
        await store.update_status("ws-1", "stopped")
        await store.mark_idle_stopped("ws-1")
        assert [w for w, _ in await store.list_idle_stopped()] == ["ws-1"]
        await store.update_status("ws-1", "stopped")
        assert [w for w, _ in await store.list_idle_stopped()] == ["ws-1"]
        await store.update_status("ws-1", "provisioning")
        assert await store.list_idle_stopped() == []
    finally:
        await store.close()


@pytest.mark.asyncio
async def test_never_idle_stops_a_single_turn_workspace(monkeypatch):
    """AH2: a single-turn run ends via workspace.completed, never an idle stop."""
    import json

    st = _ws("st")
    st.spec_json = json.dumps({"mode": "single-turn"})
    ia = _ws("ia")
    ia.spec_json = json.dumps({"mode": "interactive"})
    clock = _FakeClock()
    registry = SimpleNamespace(
        store=SimpleNamespace(
            list_non_terminal=AsyncMock(return_value=[st, ia]),
            get=AsyncMock(return_value=None),
            list_idle_stopped=AsyncMock(return_value=[]),
        ),
        stop=AsyncMock(),
    )
    monkeypatch.setattr(mod, "read_container_egress_bytes", lambda *_a, **_k: 1000)

    await _drive_until(
        registry, monkeypatch, clock=clock, on_sleep=lambda: clock.advance(100.0), min_polls=3
    )

    assert {c.args[0] for c in registry.stop.await_args_list} == {"ia"}


@pytest.mark.asyncio
async def test_idle_destroy_skips_single_turn():
    import json
    from datetime import datetime, timedelta, timezone

    now = datetime(2026, 10, 22, tzinfo=timezone.utc)
    ws = _stopped_ws("st")
    ws.spec_json = json.dumps({"mode": "single-turn", "idle_destroy_seconds": 1.0})
    registry = _destroy_registry({"st": ws}, now - timedelta(days=1))
    await mod._destroy_expired_idle_stops(registry, 1.0, now)
    registry.destroy.assert_not_awaited()
