"""Wave 0 RED: reaper loop unit tests (Plan 05-06).

Covers D-21 semantics:
  - two consecutive `unknown` polls -> registry.mark_unknown once
  - confirmed `stopped` -> registry.mark_stopped
  - runtime raising per-workspace does not crash the loop
  - runtime.list_by_server timing out skips the whole iteration (no status calls)
"""

from __future__ import annotations

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

def _ws(workspace_id: str, runtime_id: str = "cid-default"):
    # Audit 2026-10-16 P1 #32: the reaper now skips any row with an empty
    # runtime_id entirely (still-provisioning, no container yet) -- these
    # tests exercise the POLLING behavior, which only applies to a row that
    # already has a real container, hence the non-empty default here.
    handle = SimpleNamespace(
        workspace_id=workspace_id, runtime_id=runtime_id, root_path="/tmp"
    )
    return SimpleNamespace(workspace_id=workspace_id, handle=handle)


def _lock_for_mock() -> AsyncMock:
    """A `registry._lock_for` stand-in returning a real asyncio.Lock, so the
    reaper's `async with await registry._lock_for(...)` works against a
    SimpleNamespace registry double."""
    return AsyncMock(side_effect=lambda workspace_id: asyncio.Lock())


async def _cancel_and_wait(task: asyncio.Task, timeout: float = 2.0) -> None:
    """Cancel the reaper and wait for it to exit, failing (not hanging) if
    the cancellation is swallowed."""
    task.cancel()
    done, _ = await asyncio.wait({task}, timeout=timeout)
    assert done, "reaper ignored task.cancel() -- cancellation was swallowed"
    assert task.cancelled()


@pytest.mark.asyncio
async def test_marks_unknown_after_two_consecutive_polls():
    from warren.registry.reaper import run_reaper

    ws = _ws("ws-1")
    runtime = SimpleNamespace(
        status=AsyncMock(return_value="unknown"),
        list_by_server=AsyncMock(return_value=[ws]),
    )
    registry = SimpleNamespace(
        runtime=runtime,
        list_non_terminal=AsyncMock(return_value=[ws]),
        mark_unknown=AsyncMock(),
        mark_stopped=AsyncMock(),
        _lock_for=_lock_for_mock(),
    )

    task = asyncio.create_task(
        run_reaper(registry, poll_interval=0.01, status_timeout=1.0)
    )
    await asyncio.sleep(0.1)
    await _cancel_and_wait(task)

    assert registry.mark_unknown.await_count >= 1
    # Argument shape: first positional is the workspace id.
    called_ids = [call.args[0] for call in registry.mark_unknown.await_args_list]
    assert "ws-1" in called_ids


@pytest.mark.asyncio
async def test_marks_stopped_when_confirmed_gone():
    from warren.registry.reaper import run_reaper

    ws = _ws("ws-2")
    runtime = SimpleNamespace(
        status=AsyncMock(return_value="stopped"),
        list_by_server=AsyncMock(return_value=[ws]),
    )
    registry = SimpleNamespace(
        runtime=runtime,
        list_non_terminal=AsyncMock(return_value=[ws]),
        mark_unknown=AsyncMock(),
        mark_stopped=AsyncMock(),
        _lock_for=_lock_for_mock(),
    )

    task = asyncio.create_task(
        run_reaper(registry, poll_interval=0.01, status_timeout=1.0)
    )
    await asyncio.sleep(0.05)
    await _cancel_and_wait(task)

    assert registry.mark_stopped.await_count >= 1
    assert registry.mark_unknown.await_count == 0


@pytest.mark.asyncio
async def test_survives_runtime_exception():
    from warren.registry.reaper import run_reaper

    ws = _ws("ws-3")
    calls = {"n": 0}

    async def _flaky_status(handle):
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("boom")
        return "running"

    runtime = SimpleNamespace(
        status=_flaky_status,
        list_by_server=AsyncMock(return_value=[ws]),
    )
    registry = SimpleNamespace(
        runtime=runtime,
        list_non_terminal=AsyncMock(return_value=[ws]),
        mark_unknown=AsyncMock(),
        mark_stopped=AsyncMock(),
        _lock_for=_lock_for_mock(),
    )

    task = asyncio.create_task(
        run_reaper(registry, poll_interval=0.01, status_timeout=1.0)
    )
    await asyncio.sleep(0.3)
    assert not task.done(), "reaper crashed on runtime exception"
    await _cancel_and_wait(task)
    assert calls["n"] >= 2


@pytest.mark.asyncio
async def test_empty_runtime_id_never_polled_or_marked():
    """Audit 2026-10-16 P1 #32: a workspace still being provisioned (no
    container yet, runtime_id == "") must be skipped entirely -- never
    polled (podman.py's status() would return "unknown" for it, flapping a
    still-provisioning row to "unknown" in a race against the provision
    operation itself) and never passed to mark_unknown/mark_stopped."""
    from warren.registry.reaper import run_reaper

    ws = _ws("ws-provisioning", runtime_id="")
    status_mock = AsyncMock(return_value="unknown")
    runtime = SimpleNamespace(
        status=status_mock,
        list_by_server=AsyncMock(return_value=[ws]),
    )
    registry = SimpleNamespace(
        runtime=runtime,
        list_non_terminal=AsyncMock(return_value=[ws]),
        mark_unknown=AsyncMock(),
        mark_stopped=AsyncMock(),
        _lock_for=_lock_for_mock(),
    )

    task = asyncio.create_task(
        run_reaper(registry, poll_interval=0.01, status_timeout=1.0)
    )
    await asyncio.sleep(0.1)
    await _cancel_and_wait(task)

    assert status_mock.await_count == 0
    assert registry.mark_unknown.await_count == 0
    assert registry.mark_stopped.await_count == 0


@pytest.mark.asyncio
async def test_runtime_unreachable_skips_iteration():
    from warren.registry.reaper import run_reaper

    status_mock = AsyncMock(return_value="running")
    runtime = SimpleNamespace(
        status=status_mock,
        list_by_server=AsyncMock(side_effect=TimeoutError("runtime down")),
    )
    registry = SimpleNamespace(
        runtime=runtime,
        list_non_terminal=AsyncMock(side_effect=TimeoutError("runtime down")),
        mark_unknown=AsyncMock(),
        mark_stopped=AsyncMock(),
    )

    task = asyncio.create_task(
        run_reaper(registry, poll_interval=0.01, status_timeout=1.0)
    )
    await asyncio.sleep(0.05)
    await _cancel_and_wait(task)

    assert status_mock.await_count == 0


@pytest.mark.asyncio
@pytest.mark.parametrize("cancel_in", ["list_by_server", "status"])
async def test_cancel_landing_as_runtime_call_completes_is_not_swallowed(cancel_in):
    """Deterministic regression for the intermittent hang in
    test_marks_unknown_after_two_consecutive_polls: on Python 3.11,
    asyncio.wait_for() returns the inner result and drops a cancel that
    arrives once the inner awaitable has finished (cpython gh-86296). Here the
    runtime call cancels the reaper task and then returns, hitting that window
    every time; the reaper must still exit."""
    from warren.registry.reaper import run_reaper

    ws = _ws("ws-cancel")
    box: dict[str, asyncio.Task] = {}

    def _cancel_then(value):
        async def _call(*_args):
            box["task"].cancel()
            return value

        return _call

    runtime = SimpleNamespace(
        list_by_server=(
            _cancel_then([ws])
            if cancel_in == "list_by_server"
            else AsyncMock(return_value=[ws])
        ),
        status=(
            _cancel_then("running")
            if cancel_in == "status"
            else AsyncMock(return_value="running")
        ),
    )
    registry = SimpleNamespace(
        runtime=runtime,
        list_non_terminal=AsyncMock(return_value=[ws]),
        mark_unknown=AsyncMock(),
        mark_stopped=AsyncMock(),
        _lock_for=_lock_for_mock(),
    )

    task = asyncio.create_task(
        run_reaper(registry, poll_interval=0.01, status_timeout=1.0)
    )
    box["task"] = task
    done, _ = await asyncio.wait({task}, timeout=2.0)
    if not done:
        task.cancel()
    assert done, "reaper swallowed a cancel delivered as the runtime call completed"
    assert task.cancelled()
