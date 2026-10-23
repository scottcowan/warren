"""SD-04/SD-05: EventBuffer and GET /events endpoint."""

from __future__ import annotations

import asyncio
import json

import httpx
from fastapi.testclient import TestClient
from warren_sidecar.app import app
from warren_sidecar.auth import TOKEN_HEADER
from warren_sidecar.config import SidecarSettings
from warren_sidecar.events import EventBuffer

from tests.conftest import TEST_SIDECAR_TOKEN

_AUTH = {TOKEN_HEADER: TEST_SIDECAR_TOKEN}


def test_seq_monotonic():
    """EventBuffer seq values must be monotonically increasing: 0, 1, 2."""
    buf = EventBuffer()
    buf.push({"type": "x"})
    buf.push({"type": "y"})
    buf.push({"type": "z"})
    events = list(buf._events)
    seqs = [e["seq"] for e in events]
    assert seqs == [0, 1, 2]


def test_event_has_required_fields():
    """Each event dict must have 'ts', 'seq', and 'type' keys."""
    buf = EventBuffer()
    buf.push({"type": "test"})
    event = list(buf._events)[0]
    assert "ts" in event
    assert "seq" in event
    assert "type" in event


def test_events_stream_returns_ndjson(env_defaults):
    with TestClient(app) as client:
        response = client.get("/events", headers=_AUTH)
    assert response.status_code == 200
    assert "ndjson" in response.headers.get("content-type", "")


def _ndjson(text: str) -> list[dict]:
    return [json.loads(line) for line in text.splitlines() if line]


def _client_with_buffer(n: int) -> tuple[TestClient, EventBuffer]:
    """No lifespan, so no supervisor pushes events in between ours."""
    buf = EventBuffer()
    for i in range(n):
        buf.push({"type": "x", "i": i})
    app.state.event_buffer = buf
    app.state.settings = SidecarSettings()
    return TestClient(app, headers=_AUTH), buf


async def test_stream_live_subscriber_receives_all_events_past_ring_capacity():
    """BB9: the old index cursor stalled for good once the deque filled at 1,000."""
    buf = EventBuffer()
    received: list[int] = []

    async def _consume():
        async for line in buf.stream():
            received.append(json.loads(line)["seq"])
            if len(received) == 2500:
                return

    task = asyncio.create_task(_consume())
    for i in range(2500):
        buf.push({"type": "x", "i": i})
        if i % 7 == 0:
            await asyncio.sleep(0)
    await asyncio.wait_for(task, timeout=5)
    assert received == list(range(2500))


async def test_events_route_live_subscriber_receives_all_events(env_defaults):
    buf = EventBuffer()
    app.state.event_buffer = buf
    app.state.settings = SidecarSettings()

    async def _produce():
        await asyncio.sleep(0.01)
        for i in range(2500):
            buf.push({"type": "x", "i": i})
            if i % 50 == 0:
                await asyncio.sleep(0.001)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://sidecar", headers=_AUTH) as client:
        producer = asyncio.create_task(_produce())
        response = await client.get("/events")
        await producer

    events = _ndjson(response.text)
    assert [e["seq"] for e in events] == list(range(2500))


def test_events_route_without_since_replays_everything_buffered(env_defaults):
    client, _ = _client_with_buffer(1200)
    events = _ndjson(client.get("/events").text)
    assert [e["seq"] for e in events] == list(range(200, 1200))


def test_events_route_since_replays_after_seq(env_defaults):
    client, _ = _client_with_buffer(10)
    events = _ndjson(client.get("/events?since=6").text)
    assert [e["seq"] for e in events] == [7, 8, 9]


def test_events_route_since_at_head_returns_nothing(env_defaults):
    client, _ = _client_with_buffer(10)
    assert _ndjson(client.get("/events?since=9").text) == []


def test_events_route_since_evicted_emits_marker_first(env_defaults):
    client, _ = _client_with_buffer(1500)
    events = _ndjson(client.get("/events?since=10").text)
    marker = events[0]
    assert marker["type"] == "events_evicted"
    assert (marker["since"], marker["oldest_seq"], marker["dropped"]) == (10, 500, 489)
    assert "seq" not in marker
    assert [e["seq"] for e in events[1:]] == list(range(500, 1500))


def test_events_route_rejects_invalid_since(env_defaults):
    client, _ = _client_with_buffer(0)
    assert client.get("/events?since=-2").status_code == 422
    assert client.get("/events?since=abc").status_code == 422


def test_read_after_marks_consumer_that_falls_off_the_ring():
    buf = EventBuffer()
    buf.push({"type": "x"})
    _, cursor = buf.read_after(-1)
    assert cursor == 0
    for _ in range(1500):
        buf.push({"type": "x"})
    events, cursor = buf.read_after(cursor)
    assert events[0]["type"] == "events_evicted"
    assert (events[0]["since"], events[0]["oldest_seq"]) == (0, 501)
    assert [e["seq"] for e in events[1:]] == list(range(501, 1501))
    assert cursor == 1500
