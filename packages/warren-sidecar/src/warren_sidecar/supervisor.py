"""WorkspaceAppSupervisor: observes the entrypoint's tmux pane, feeding its output into EventBuffer.

The entrypoint (images/warren-docker-base/entrypoint.py) is the sole owner of the
workspace app process: in server/no-TTY mode it runs the app inside a detached
tmux session named "main" (a human reattaches via `tmux attach -t main`); in
local/TTY mode it execs the app directly with no tmux session at all.

This supervisor must NOT fork a second copy of the app -- it only tails a copy
of the tmux pane's output via `tmux pipe-pane`, so EventBuffer/`/events` stays
backed by what the real, interactive session actually produced. It never signals
the app process itself; starting/stopping that process is the entrypoint/tmux's
job alone.
"""

from __future__ import annotations

import asyncio
import os
import pathlib
import tempfile
from typing import TYPE_CHECKING

import structlog

if TYPE_CHECKING:
    from warren_sidecar.events import EventBuffer

log = structlog.get_logger(__name__)

TMUX_SESSION = "main"

_SESSION_WAIT_RETRIES = 20
_SESSION_WAIT_DELAY_S = 0.25


class WorkspaceAppSupervisor:
    """Attaches a `tmux pipe-pane` observer to the entrypoint's tmux session.

    Does not start, own, or signal the workspace app process. It waits for the
    named tmux session to exist (the entrypoint creates it; there's a startup
    race since the sidecar may come up first), pipes a copy of the pane's
    output to a plain file via `tmux pipe-pane`, and tails that file with its
    own `tail -F` subprocess into EventBuffer.

    Degrades gracefully (logs a warning, does nothing else) when tmux isn't
    installed or the session never appears -- e.g. local/TTY mode, where the
    app runs directly with no tmux session.
    """

    def __init__(self, event_buffer: EventBuffer, session: str = TMUX_SESSION, on_output=None) -> None:
        self._session = session
        self._on_output = on_output
        self._buf = event_buffer
        self._pane_log_path = os.path.join(tempfile.gettempdir(), f"warren-sidecar-pane-{session}.log")
        self._tail_proc: asyncio.subprocess.Process | None = None
        self._reader_task: asyncio.Task | None = None
        self._active = False

    async def start(self) -> None:
        """Wait for the tmux session, start `pipe-pane`, and tail its output file."""
        if not await self._wait_for_session():
            log.warning(
                "supervisor_no_tmux_session",
                session=self._session,
                detail="no tmux session found; live event streaming disabled",
            )
            return

        # Truncate any stale file from a prior run before (re)registering the pipe.
        await asyncio.to_thread(pathlib.Path(self._pane_log_path).write_text, "")

        # `tmux pipe-pane -o <cmd>` streams a copy of the pane's output to <cmd>'s
        # stdin without becoming the process that produced that output -- the
        # tmux session (and whatever the entrypoint launched inside it) remains
        # the sole producer/owner of the app. `-o` only turns piping on if it
        # isn't already on, so repeated calls are idempotent. The registering
        # command itself (this subprocess) exits immediately once tmux has
        # taken over the pipe; the "cat" it names runs as a child of the tmux
        # server, not of us.
        register = await asyncio.create_subprocess_exec(
            "tmux", "pipe-pane", "-t", self._session, "-o",
            f"cat >> {self._pane_log_path}",
        )
        await register.wait()

        # Our own subprocess: tails the plain file `cat` is appending to. This
        # is "the tmux attach/pipe mechanism", not a second copy of the app --
        # we own and read this process, never the app itself.
        self._tail_proc = await asyncio.create_subprocess_exec(
            "tail", "-n", "+1", "-F", self._pane_log_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        self._active = True
        self._reader_task = asyncio.create_task(self._pipe_stdout(), name="supervisor-pane-tail")
        log.info("supervisor_started", session=self._session, pane_log=self._pane_log_path)

    async def _wait_for_session(self) -> bool:
        for _ in range(_SESSION_WAIT_RETRIES):
            try:
                proc = await asyncio.create_subprocess_exec(
                    "tmux", "has-session", "-t", self._session,
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                )
            except FileNotFoundError:
                return False  # tmux isn't installed; no point retrying.
            if await proc.wait() == 0:
                return True
            await asyncio.sleep(_SESSION_WAIT_DELAY_S)
        return False

    async def _pipe_stdout(self) -> None:
        assert self._tail_proc and self._tail_proc.stdout
        async for line in self._tail_proc.stdout:
            if self._on_output is not None:
                try:
                    self._on_output(line)
                except Exception:
                    log.exception("supervisor_output_hook_failed")
            self._buf.push_output_event("stdout", line.decode(errors="replace"))

    async def stop(self) -> None:
        """Turn off pipe-pane and stop our tail process; never signals the app."""
        if not self._active:
            return
        turn_off = await asyncio.create_subprocess_exec(
            "tmux", "pipe-pane", "-t", self._session,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await turn_off.wait()

        if self._reader_task:
            self._reader_task.cancel()
        if self._tail_proc and self._tail_proc.returncode is None:
            self._tail_proc.terminate()
            await self._tail_proc.wait()

        self._active = False
        log.info("supervisor_stopped", session=self._session)

    @property
    def active(self) -> bool:
        return self._active
