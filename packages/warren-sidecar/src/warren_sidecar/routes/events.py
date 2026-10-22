"""GET /events route — NDJSON stream from EventBuffer (SD-02, SD-04, SD-05)."""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Query, Request
from fastapi.responses import StreamingResponse

log = structlog.get_logger(__name__)
router = APIRouter()

# Seconds to wait for new events before closing the stream.
# Clients should poll/reconnect. Short for test harness compatibility.
_POLL_INTERVAL_S: float = 0.1
_MAX_IDLE_WAITS: int = 5  # 0.5 s total idle before closing if no disconnect signal


@router.get("/events")
async def stream_events(
    request: Request, since: int | None = Query(default=None, ge=-1)
) -> StreamingResponse:
    """Stream buffered NDJSON events (after `since`, if given) then new events as they arrive."""
    buf = request.app.state.event_buffer

    async def _generate():
        cursor = buf.start_cursor(since)
        idle = 0
        while True:
            events, cursor = buf.read_after(cursor)
            for event in events:
                yield buf._serialize(event) + "\n"
            # Close on disconnect or timeout
            if idle >= _MAX_IDLE_WAITS or await request.is_disconnected():
                break
            if await buf.wait_after(cursor, timeout=_POLL_INTERVAL_S):
                idle = 0
            else:
                idle += 1

    return StreamingResponse(_generate(), media_type="application/x-ndjson")
