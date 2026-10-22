"""D-08: WorkspaceEventBuffer and WorkspaceEventStore ring buffer.

The push/stream API is async (issue #12's asyncio.Condition-based fix) —
these tests were originally written as sync xfail RED stubs against a
pre-implementation shape; converted to real async tests now that the module
is implemented and shipped.
"""

from __future__ import annotations

import asyncio
import json

import pytest

from warren.registry.events import WorkspaceEventBuffer, WorkspaceEventStore


@pytest.mark.asyncio
async def test_push_appends_event():
    buf = WorkspaceEventBuffer()
    await buf.push('{"type":"x"}')
    assert [line for _, line in buf._events][0] == '{"type":"x"}'


def test_get_or_create_idempotent():
    store = WorkspaceEventStore()
    b1 = store.get_or_create("ws-1")
    b2 = store.get_or_create("ws-1")
    assert b1 is b2


def test_discard_removes_buffer():
    store = WorkspaceEventStore()
    store.get_or_create("ws-1")
    store.discard("ws-1")
    assert "ws-1" not in store._buffers


@pytest.mark.asyncio
async def test_buffer_maxlen_1000():
    buf = WorkspaceEventBuffer()
    for i in range(1001):
        await buf.push(f'{{"seq":{i}}}')
    assert len(buf._events) == 1000


@pytest.mark.asyncio
async def test_stream_yields_events_pushed_after_rollover():
    """Regression for issue #12: after more than MAX_EVENTS have ever been
    pushed, stream() must keep yielding new events — the old raw-index
    approach stopped yielding forever once total pushes exceeded 1,000."""
    buf = WorkspaceEventBuffer()
    for i in range(1500):
        await buf.push(f'{{"seq":{i}}}')

    received: list[str] = []

    async def _consume():
        async for line in buf.stream():
            received.append(line)
            if len(received) >= buf.MAX_EVENTS + 2:
                return

    consumer = asyncio.create_task(_consume())
    await asyncio.sleep(0)  # let it drain the initial 1000-event snapshot

    await buf.push('{"seq":1500}')
    await buf.push('{"seq":1501}')

    await asyncio.wait_for(consumer, timeout=1.0)

    assert received[-1] == '{"seq":1501}'
    assert received[-2] == '{"seq":1500}'


@pytest.mark.asyncio
async def test_stream_does_not_lose_a_push_landing_right_before_wait():
    """Regression for issue #12's lost-wakeup window: with the old hand-rolled
    Future-list waiters, a push landing between the consumer's initial
    snapshot and it registering as a waiter woke nothing — and if no further
    push ever followed, that already-buffered event was never delivered.
    asyncio.Condition's lock makes the check-then-wait atomic, so this can no
    longer happen."""
    buf = WorkspaceEventBuffer()
    received: list[str] = []

    async def _consume():
        async for line in buf.stream():
            received.append(line)
            return  # stop after the first event

    task = asyncio.create_task(_consume())
    # Let the consumer run far enough to take its (empty) initial snapshot
    # and reach `await self._condition.wait()` before the push below lands.
    for _ in range(5):
        await asyncio.sleep(0)

    await buf.push('{"type":"only-event"}')

    await asyncio.wait_for(task, timeout=1.0)
    assert received == ['{"type":"only-event"}']


async def _take(buf: WorkspaceEventBuffer, n: int, since: int | None = None) -> list[str]:
    out: list[str] = []

    async def _consume():
        async for line in buf.stream(since=since):
            out.append(line)
            if len(out) == n:
                return

    await asyncio.wait_for(_consume(), timeout=1.0)
    return out


@pytest.mark.asyncio
async def test_live_subscriber_receives_2500_events_in_order():
    buf = WorkspaceEventBuffer()
    received: list[str] = []

    async def _consume():
        async for line in buf.stream():
            received.append(line)
            if len(received) == 2500:
                return

    task = asyncio.create_task(_consume())
    for i in range(2500):
        await buf.push(f'{{"i":{i}}}')
        if i % 7 == 0:
            await asyncio.sleep(0)
    await asyncio.wait_for(task, timeout=5.0)
    assert received == [f'{{"i":{i}}}' for i in range(2500)]


@pytest.mark.asyncio
async def test_stream_since_replays_after_seq():
    buf = WorkspaceEventBuffer()
    for i in range(10):
        await buf.push(f"line-{i}")
    assert await _take(buf, 3, since=6) == ["line-7", "line-8", "line-9"]


@pytest.mark.asyncio
async def test_stream_since_minus_one_replays_everything():
    buf = WorkspaceEventBuffer()
    for i in range(3):
        await buf.push(f"line-{i}")
    assert await _take(buf, 3, since=-1) == ["line-0", "line-1", "line-2"]


@pytest.mark.asyncio
async def test_stream_since_evicted_emits_marker_first():
    buf = WorkspaceEventBuffer()
    for i in range(1500):
        await buf.push(f"line-{i}")
    lines = await _take(buf, 1001, since=10)
    marker = json.loads(lines[0])
    assert marker["type"] == "events_evicted"
    assert (marker["since"], marker["oldest_seq"], marker["dropped"]) == (10, 500, 489)
    assert lines[1:] == [f"line-{i}" for i in range(500, 1500)]


@pytest.mark.asyncio
async def test_stream_without_since_has_no_marker_after_rollover():
    buf = WorkspaceEventBuffer()
    for i in range(1500):
        await buf.push(f"line-{i}")
    lines = await _take(buf, 1000)
    assert lines == [f"line-{i}" for i in range(500, 1500)]
