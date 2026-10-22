"""WorkspaceEventBuffer + WorkspaceEventStore — in-memory NDJSON ring buffer (D-08).

Per-workspace ring buffer (deque maxlen=1000) with async streaming.
WorkspaceEventStore is a singleton map of workspace_id → buffer.
"""

from __future__ import annotations

import asyncio
import json
import time
from collections import deque
from itertools import islice

import structlog

log = structlog.get_logger(__name__)

EVICTED_EVENT_TYPE = "events_evicted"


class WorkspaceEventBuffer:
    """In-memory NDJSON ring buffer for one workspace (D-08).

    push(line) stores pre-serialized JSON strings from container.logs or from
    push_output_event(). stream() is an async generator that yields all buffered
    events then waits for new ones.

    Fix for issue #12: a consumer's position in the stream is tracked as an
    absolute, monotonically increasing sequence number (never reset, never
    capped), not a raw index into the capped `deque`. The old raw-index
    approach broke permanently once 1,000 events had ever been pushed: the
    index equaled the deque's max length forever after, so every slice past
    it came back empty and no event was ever yielded again. Each buffered
    entry now carries its own absolute seq, so "give me everything after
    seq N" stays well-defined regardless of how many older entries have since
    rolled off the ring buffer.

    Waiting/waking uses `asyncio.Condition` rather than a hand-rolled list of
    `asyncio.Future`s — this also fixes two smaller issues the old approach
    had: a lost-wakeup window (a push landing between a snapshot being taken
    and the next waiter being registered woke nothing, and if no further push
    ever followed, already-buffered data was never delivered), and cancelled
    waiters never being cleaned out of the waiter list (asyncio.Condition
    handles removing a cancelled waiter on its own).
    """

    MAX_EVENTS = 1000

    def __init__(self) -> None:
        # Each entry is (seq, line); seq is the absolute, never-reset sequence
        # number of that event. The deque itself still caps at MAX_EVENTS —
        # old entries roll off — but a consumer's position is this seq, not a
        # position within the (possibly-rolled-over) deque.
        self._events: deque[tuple[int, str]] = deque(maxlen=self.MAX_EVENTS)
        self._next_seq: int = 0
        self._condition = asyncio.Condition()
        # Separate counter feeding push_output_event's own JSON "seq" field —
        # historically distinct from the ring buffer's internal seq above,
        # kept as its own attribute so that field's numbering is unaffected.
        self._output_seq: int = 0
        self._closed = False

    @property
    def closed(self) -> bool:
        return self._closed

    async def close(self) -> None:
        """No more events will arrive (AH2: workspace destroyed); stream() ends once drained."""
        async with self._condition:
            self._closed = True
            self._condition.notify_all()

    async def push(self, line: str) -> None:
        """Append a pre-serialized NDJSON line and wake up any stream() waiters."""
        async with self._condition:
            self._events.append((self._next_seq, line))
            self._next_seq += 1
            self._condition.notify_all()

    def _oldest_seq(self) -> int:
        return self._events[0][0] if self._events else self._next_seq

    def _read_after(self, last_seq: int) -> tuple[list[str], int]:
        """Lines with seq > last_seq, preceded by an eviction marker if some are gone."""
        oldest = self._oldest_seq()
        out: list[str] = []
        if last_seq + 1 < oldest:
            out.append(json.dumps({
                "type": EVICTED_EVENT_TYPE,
                "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "since": last_seq,
                "oldest_seq": oldest,
                "dropped": oldest - last_seq - 1,
            }))
            last_seq = oldest - 1
        out.extend(line for _, line in islice(self._events, last_seq + 1 - oldest, None))
        return out, max(last_seq, self._next_seq - 1)

    async def stream(self, since: int | None = None):
        """Yield buffered events (after `since`, if given) then wait indefinitely for new ones.

        `since` is the buffer's own seq: the Nth line this buffer ever received
        has seq N-1. Callers should cancel the enclosing task (or check
        request.is_disconnected()) to stop the generator.
        """
        async with self._condition:
            last_seq = self._oldest_seq() - 1 if since is None else since
        while True:
            async with self._condition:
                while self._next_seq - 1 <= last_seq:
                    if self._closed:
                        return
                    await self._condition.wait()
                new, last_seq = self._read_after(last_seq)
            for line in new:
                yield line

    async def read(
        self, since: int | None = None, *, limit: int = 100, wait_seconds: float = 0.0
    ) -> tuple[list[tuple[int | None, str]], int, bool]:
        """AI8: one page of (seq, line) after `since`, waiting up to `wait_seconds` for
        the first new event. Returns (events, next_since, closed); an eviction marker
        has seq None."""
        async with self._condition:
            last_seq = self._oldest_seq() - 1 if since is None else since
            if wait_seconds > 0:
                try:
                    await asyncio.wait_for(
                        self._condition.wait_for(lambda: self._next_seq - 1 > last_seq or self._closed),
                        wait_seconds,
                    )
                except (asyncio.TimeoutError, TimeoutError):
                    pass
            oldest = self._oldest_seq()
            out: list[tuple[int | None, str]] = []
            if last_seq + 1 < oldest:
                marker, _ = self._read_after(last_seq)
                out.append((None, marker[0]))
                last_seq = oldest - 1
            for seq, line in islice(self._events, last_seq + 1 - oldest, None):
                if len(out) >= limit:
                    break
                out.append((seq, line))
                last_seq = seq
            return out, last_seq, self._closed and last_seq >= self._next_seq - 1

    async def push_output_event(self, stream_name: str, content: str) -> None:
        """Create a D-07 output event and push it to the buffer.

        Used by the supervisor to push workspace app stdout/stderr lines.
        seq is monotonic per buffer; increments on every push_output_event call.
        """
        event = json.dumps({
            "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "seq": self._output_seq,
            "type": "output",
            "stream": stream_name,
            "content": content.rstrip(),
        })
        self._output_seq += 1
        await self.push(event)


class WorkspaceEventStore:
    """Registry of per-workspace event buffers.

    Held as a singleton on app.state.event_store. WorkspaceRegistry receives
    it at construction so _do_provision can call get_or_create() after provision.
    """

    def __init__(self) -> None:
        self._buffers: dict[str, WorkspaceEventBuffer] = {}

    def get_or_create(self, workspace_id: str) -> WorkspaceEventBuffer:
        """Return the existing buffer for workspace_id, or create and store a new one."""
        if workspace_id not in self._buffers:
            self._buffers[workspace_id] = WorkspaceEventBuffer()
        return self._buffers[workspace_id]

    def get(self, workspace_id: str) -> WorkspaceEventBuffer | None:
        return self._buffers.get(workspace_id)

    def discard(self, workspace_id: str) -> None:
        """Remove the buffer for workspace_id (called on workspace destroy)."""
        self._buffers.pop(workspace_id, None)

    def discard_later(self, workspace_id: str, delay_seconds: float) -> None:
        """AH2: keep a destroyed workspace's (closed) buffer replayable for a while."""
        asyncio.get_running_loop().call_later(delay_seconds, self.discard, workspace_id)
