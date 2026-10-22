"""#59: server-mode exec relay.

Runs one non-interactive command in a server workspace through the runtime's
`exec_stream` (Podman exec API, or ECS ExecuteCommand under the control plane's
own role) and relays its output as NDJSON frames, bounded in bytes and time:

    {"type": "output", "data": "..."}                        (zero or more)
    {"type": "exit", "exit_code": 0, "timed_out": false, "truncated": false,
     "output_bytes": 12, "error": null}

Ownership and workspace-token scope are checked by the caller (the route or
the MCP tool), not here.
"""

from __future__ import annotations

import asyncio
import codecs
import json
import time
from collections.abc import AsyncIterator
from typing import Any

import structlog
from warren_common.runtime.base import ExecExit, ExecUnavailable, WorkspaceHandle

log = structlog.get_logger(__name__)

MAX_ARGV_ITEMS = 256
MAX_ARG_CHARS = 8192


def validate_argv(argv: list[str]) -> None:
    if not argv or not argv[0]:
        raise ValueError("argv must name a command")
    if len(argv) > MAX_ARGV_ITEMS:
        raise ValueError(f"argv has more than {MAX_ARGV_ITEMS} items")
    if any(len(a) > MAX_ARG_CHARS or "\x00" in a for a in argv):
        raise ValueError(f"argv items must be at most {MAX_ARG_CHARS} chars with no NUL")


def handle_for(ws: Any) -> WorkspaceHandle:
    return WorkspaceHandle(
        workspace_id=ws.workspace_id, runtime_id=ws.container_id or "", root_path=ws.root_path
    )


async def relay(
    runtime: Any,
    handle: WorkspaceHandle,
    argv: list[str],
    *,
    timeout_seconds: float,
    max_output_bytes: int,
) -> AsyncIterator[dict]:
    stream = runtime.exec_stream(handle, argv)
    decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
    sent = 0
    exit_code: int | None = None
    timed_out = truncated = False
    error: str | None = None
    deadline = time.monotonic() + timeout_seconds
    try:
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                timed_out = True
                break
            try:
                item = await asyncio.wait_for(anext(stream), timeout=remaining)
            except StopAsyncIteration:
                break
            except asyncio.TimeoutError:
                timed_out = True
                break
            except ExecUnavailable as exc:
                error = str(exc)
                break
            except Exception:
                log.exception("exec_relay_failed", workspace_id=handle.workspace_id)
                error = "exec failed"
                break
            if isinstance(item, ExecExit):
                exit_code = item.exit_code
                break
            chunk = item[: max_output_bytes - sent]
            sent += len(chunk)
            text = decoder.decode(chunk)
            if text:
                yield {"type": "output", "data": text}
            if len(chunk) < len(item):
                truncated = True
                break
    finally:
        await stream.aclose()
    tail = decoder.decode(b"", final=True)
    if tail:
        yield {"type": "output", "data": tail}
    yield {
        "type": "exit",
        "exit_code": exit_code,
        "timed_out": timed_out,
        "truncated": truncated,
        "output_bytes": sent,
        "error": error,
    }


async def relay_ndjson(frames: AsyncIterator[dict]) -> AsyncIterator[str]:
    async for frame in frames:
        yield json.dumps(frame) + "\n"


async def collect(frames: AsyncIterator[dict]) -> dict:
    """Fold relay frames into one result (the MCP exec_command shape)."""
    out: list[str] = []
    result: dict = {}
    async for frame in frames:
        if frame["type"] == "output":
            out.append(frame["data"])
        else:
            result = {k: v for k, v in frame.items() if k != "type"}
    return {"output": "".join(out), **result}


def bounded_timeout(settings: Any, requested: float | None) -> float:
    default = float(getattr(settings, "exec_default_timeout_seconds", 60.0))
    ceiling = float(getattr(settings, "exec_max_timeout_seconds", 600.0))
    return min(requested if requested is not None else default, ceiling)
