"""POST /exec route — NDJSON streaming subprocess execution (SD-02)."""

from __future__ import annotations

import asyncio
import json
import time

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from warren_sidecar.auth import require_sidecar_token

log = structlog.get_logger(__name__)
router = APIRouter(dependencies=[Depends(require_sidecar_token)])


class ExecRequest(BaseModel):
    cmd: list[str]


def _iso_now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


@router.post("/exec")
async def exec_command(body: ExecRequest, request: Request) -> StreamingResponse:
    if not body.cmd:
        raise HTTPException(status_code=400, detail="cmd must not be empty")

    async def _generate():
        seq = 0
        proc = await asyncio.create_subprocess_exec(
            *body.cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Audit 2026-10-16 P1 #28: draining stdout to EOF before even
        # starting to read stderr is a classic subprocess-pipe deadlock -- a
        # command that writes more than its stderr pipe's OS buffer (~64KB)
        # while stdout isn't being read never gets its stderr drained,
        # blocks forever trying to write more, and this route hangs with it.
        # Both streams are now read CONCURRENTLY via two tasks feeding one
        # queue, same pattern `WorkspaceAppSupervisor` already uses for its
        # own stdout/stderr pump tasks (supervisor.py).
        queue: asyncio.Queue[tuple[str, bytes] | None] = asyncio.Queue()

        async def _pump(stream, stream_name: str) -> None:
            # Chunked `.read(n)`, NOT line iteration (`async for line in
            # stream`, i.e. StreamReader.readline()/readuntil(b"\n")) --
            # readline() has a default 64KB limit on how much unterminated
            # (no "\n" yet) data it will buffer before raising
            # LimitOverrunError. A single write larger than that with no
            # newline (exactly what large, non-line-oriented stderr output
            # can look like) would silently kill this pump task, its EOF
            # sentinel would never reach the queue below, and the main loop
            # would hang forever waiting on it -- trading the original
            # stdout-then-stderr deadlock for a new one. `.read(n)` has no
            # such separator-search limit; it just returns whatever's
            # available (or less), looping until EOF (`b""`).
            while True:
                chunk = await stream.read(65536)
                if not chunk:
                    break
                await queue.put((stream_name, chunk))
            await queue.put(None)  # sentinel: this stream reached EOF

        assert proc.stdout
        assert proc.stderr
        pump_tasks = [
            asyncio.create_task(_pump(proc.stdout, "stdout")),
            asyncio.create_task(_pump(proc.stderr, "stderr")),
        ]

        done_streams = 0
        while done_streams < len(pump_tasks):
            item = await queue.get()
            if item is None:
                done_streams += 1
                continue
            stream_name, line = item
            event = {
                "ts": _iso_now(),
                "seq": seq,
                "type": "exec_output",
                "stream": stream_name,
                "content": line.decode(errors="replace").rstrip(),
            }
            seq += 1
            yield json.dumps(event) + "\n"

        await asyncio.gather(*pump_tasks)
        await proc.wait()
        exit_event = {
            "ts": _iso_now(),
            "seq": seq,
            "type": "exec_exit",
            "returncode": proc.returncode,
        }
        yield json.dumps(exit_event) + "\n"

    return StreamingResponse(_generate(), media_type="application/x-ndjson")
