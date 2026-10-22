"""WorkspaceAppSupervisor: observes the entrypoint's tmux pane via pipe-pane.

Verifies the supervisor does NOT fork a second copy of the workspace app --
it waits for the entrypoint's tmux session, registers `tmux pipe-pane`, tails
that pane's output file with its own owned subprocess, and on stop() turns
piping off without signaling the app process. Also verifies graceful
degradation when no tmux session is available.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest
from warren_sidecar.events import EventBuffer
from warren_sidecar.supervisor import WorkspaceAppSupervisor


def _fake_proc(returncode: int = 0, stdout_lines: list[bytes] | None = None) -> MagicMock:
    """Build a MagicMock standing in for an asyncio.subprocess.Process."""
    proc = MagicMock()
    proc.returncode = returncode
    proc.wait = AsyncMock(return_value=returncode)
    proc.terminate = MagicMock()

    if stdout_lines is not None:
        async def _aiter():
            for line in stdout_lines:
                yield line

        stdout = MagicMock()
        stdout.__aiter__ = lambda self=None: _aiter()
        proc.stdout = stdout

    return proc


@pytest.mark.asyncio
async def test_start_waits_for_session_then_pipes_pane(monkeypatch, tmp_path):
    """start() must call `tmux has-session`, then `pipe-pane`, then tail -- never fork the app."""
    calls: list[list[str]] = []

    has_session_proc = _fake_proc(returncode=0)
    pipe_pane_register_proc = _fake_proc(returncode=0)
    tail_proc = _fake_proc(returncode=None, stdout_lines=[b"hello from pane\n"])

    async def fake_create_subprocess_exec(*args, **kwargs):
        calls.append(list(args))
        if args[0] == "tmux" and args[1] == "has-session":
            return has_session_proc
        if args[0] == "tmux" and args[1] == "pipe-pane":
            return pipe_pane_register_proc
        if args[0] == "tail":
            return tail_proc
        raise AssertionError(f"unexpected subprocess exec: {args}")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    buf = EventBuffer()
    supervisor = WorkspaceAppSupervisor(event_buffer=buf, session="main")
    await supervisor.start()
    await supervisor._reader_task

    assert ["tmux", "has-session", "-t", "main"] == calls[0]
    assert calls[1][:4] == ["tmux", "pipe-pane", "-t", "main"]
    assert "-o" in calls[1]
    assert calls[2][0] == "tail"
    assert "-F" in calls[2]
    # Never forks the actual app command -- only tmux/tail invocations happen.
    assert all(c[0] in ("tmux", "tail") for c in calls)

    events = list(buf._events)
    assert any(e["type"] == "output" and "hello from pane" in e["content"] for e in events)

    assert supervisor.active is True


@pytest.mark.asyncio
async def test_stop_turns_off_pipe_pane_without_signaling_app(monkeypatch):
    """stop() must call `tmux pipe-pane -t main` (no -o/command) and only terminate OUR tail process."""
    calls: list[list[str]] = []

    has_session_proc = _fake_proc(returncode=0)
    pipe_pane_register_proc = _fake_proc(returncode=0)
    pipe_pane_off_proc = _fake_proc(returncode=0)
    tail_proc = _fake_proc(returncode=None, stdout_lines=[])

    async def fake_create_subprocess_exec(*args, **kwargs):
        calls.append(list(args))
        if args[0] == "tmux" and args[1] == "has-session":
            return has_session_proc
        if args[0] == "tmux" and args[1] == "pipe-pane":
            if "-o" in args:
                return pipe_pane_register_proc
            return pipe_pane_off_proc
        if args[0] == "tail":
            return tail_proc
        raise AssertionError(f"unexpected subprocess exec: {args}")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    buf = EventBuffer()
    supervisor = WorkspaceAppSupervisor(event_buffer=buf, session="main")
    await supervisor.start()
    await supervisor.stop()

    turn_off_calls = [c for c in calls if c[0] == "tmux" and c[1] == "pipe-pane" and "-o" not in c]
    assert len(turn_off_calls) == 1
    assert turn_off_calls[0] == ["tmux", "pipe-pane", "-t", "main"]

    # Only the tail subprocess (ours) is terminated -- never a signal to the app.
    tail_proc.terminate.assert_called_once()
    assert supervisor.active is False


@pytest.mark.asyncio
async def test_start_degrades_gracefully_when_no_session(monkeypatch):
    """When has-session never succeeds, start() must log a warning and not crash or fork anything."""
    no_session_proc = _fake_proc(returncode=1)

    async def fake_create_subprocess_exec(*args, **kwargs):
        if args[0] == "tmux" and args[1] == "has-session":
            return no_session_proc
        raise AssertionError(f"unexpected subprocess exec after session wait gave up: {args}")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)
    import warren_sidecar.supervisor as supervisor_mod

    monkeypatch.setattr(supervisor_mod, "_SESSION_WAIT_RETRIES", 2)
    monkeypatch.setattr(supervisor_mod, "_SESSION_WAIT_DELAY_S", 0.0)

    buf = EventBuffer()
    supervisor = WorkspaceAppSupervisor(event_buffer=buf, session="main")
    await supervisor.start()  # must not raise

    assert supervisor.active is False
    await supervisor.stop()  # must also be a no-op, not raise


@pytest.mark.asyncio
async def test_start_degrades_gracefully_when_tmux_missing(monkeypatch):
    """When the tmux binary itself is missing, start() must not crash the lifespan."""

    async def fake_create_subprocess_exec(*args, **kwargs):
        raise FileNotFoundError("tmux: command not found")

    monkeypatch.setattr(asyncio, "create_subprocess_exec", fake_create_subprocess_exec)

    buf = EventBuffer()
    supervisor = WorkspaceAppSupervisor(event_buffer=buf, session="main")
    await supervisor.start()  # must not raise

    assert supervisor.active is False
