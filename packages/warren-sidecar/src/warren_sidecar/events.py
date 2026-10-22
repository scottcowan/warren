"""EventBuffer: monotonic seq NDJSON ring buffer for the sidecar."""

from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from itertools import islice
from typing import Any

import structlog

log = structlog.get_logger(__name__)

MAX_EVENTS = 1000

EVICTED_EVENT_TYPE = "events_evicted"


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class EventBuffer:
    """In-memory NDJSON ring buffer with monotonic seq counter (SD-04).

    Consumers track the seq of the last event they saw, not an index into the
    deque: once the deque is full an index stops advancing and every later
    read comes back empty (audit BB9).
    """

    def __init__(self) -> None:
        self._events: deque[dict[str, Any]] = deque(maxlen=MAX_EVENTS)
        self._waiters: list[asyncio.Future[None]] = []
        self._seq: int = 0

    def push(self, event: dict[str, Any]) -> None:
        """Embed ts and seq, store dict, notify waiters."""
        event = dict(event)
        event["ts"] = _now()
        event["seq"] = self._seq
        self._seq += 1
        self._events.append(event)
        for f in self._waiters:
            if not f.done():
                f.set_result(None)
        self._waiters.clear()

    def push_output_event(self, stream: str, content: str) -> None:
        """Convenience wrapper for supervisor stdout/stderr lines."""
        self.push({"type": "output", "stream": stream, "content": content.rstrip()})

    def _serialize(self, event: dict[str, Any]) -> str:
        return json.dumps(event)

    def _oldest_seq(self) -> int:
        return self._events[0]["seq"] if self._events else self._seq

    def start_cursor(self, since: int | None) -> int:
        """Cursor for a new subscriber: everything buffered, or everything after `since`."""
        return self._oldest_seq() - 1 if since is None else since

    def read_after(self, cursor: int) -> tuple[list[dict[str, Any]], int]:
        """Return events with seq > cursor and the advanced cursor.

        If events after `cursor` have already rolled off the ring, an
        `events_evicted` marker comes first so the client knows it has a gap.
        """
        oldest = self._oldest_seq()
        out: list[dict[str, Any]] = []
        if cursor + 1 < oldest:
            out.append({
                "type": EVICTED_EVENT_TYPE,
                "ts": _now(),
                "since": cursor,
                "oldest_seq": oldest,
                "dropped": oldest - cursor - 1,
            })
            cursor = oldest - 1
        out.extend(islice(self._events, cursor + 1 - oldest, None))
        return out, max(cursor, self._seq - 1)

    async def wait_after(self, cursor: int, timeout: float | None = None) -> bool:
        """Wait until an event with seq > cursor exists; False on timeout."""
        if self._seq - 1 > cursor:
            return True
        f: asyncio.Future[None] = asyncio.get_running_loop().create_future()
        self._waiters.append(f)
        try:
            await asyncio.wait_for(f, timeout)
        except TimeoutError:
            return False
        finally:
            if f in self._waiters:
                self._waiters.remove(f)
        return True

    async def stream(self, since: int | None = None):
        """Yield buffered events (as JSON strings) after `since`, then wait for new ones."""
        cursor = self.start_cursor(since)
        while True:
            events, cursor = self.read_after(cursor)
            for event in events:
                yield self._serialize(event)
            await self.wait_after(cursor)
