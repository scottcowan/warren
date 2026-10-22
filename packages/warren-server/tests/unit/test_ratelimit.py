"""SlidingWindowRateLimiter pruning — audit S10.

S10: the in-memory limiter never pruned stale keys, so a key that aged out and was
never touched again sat in `_events` for the server's entire uptime. These tests cover
`prune()` itself and `run_rate_limiter_pruner`'s background-loop wiring.
"""

from __future__ import annotations

import asyncio

import pytest

from warren.ratelimit import SlidingWindowRateLimiter, run_rate_limiter_pruner


def test_prune_drops_keys_whose_events_all_aged_out():
    limiter = SlidingWindowRateLimiter(max_events=5, window_seconds=10.0)
    limiter.allow("abandoned-key")
    assert "abandoned-key" in limiter._events

    # Simulate enough time passing that the key's one event ages out of the window,
    # without ever calling allow() for it again (the scenario allow()'s own per-call
    # trim can't handle).
    dropped = limiter.prune(now=limiter._events["abandoned-key"][0] + 11.0)

    assert dropped == 1
    assert "abandoned-key" not in limiter._events


def test_prune_keeps_keys_with_events_still_in_window():
    limiter = SlidingWindowRateLimiter(max_events=5, window_seconds=10.0)
    limiter.allow("active-key")

    dropped = limiter.prune(now=limiter._events["active-key"][0] + 1.0)

    assert dropped == 0
    assert "active-key" in limiter._events


def test_prune_partially_trims_without_dropping_key_that_still_has_recent_events():
    limiter = SlidingWindowRateLimiter(max_events=5, window_seconds=10.0)
    limiter.allow("mixed-key")
    first_ts = limiter._events["mixed-key"][0]
    # A second, more recent event on the same key, simulated directly to control timing
    # precisely rather than depending on real wall-clock elapsed time between calls.
    limiter._events["mixed-key"].append(first_ts + 9.0)

    dropped = limiter.prune(now=first_ts + 10.5)  # first event now stale, second isn't

    assert dropped == 0
    assert list(limiter._events["mixed-key"]) == [first_ts + 9.0]


def test_prune_returns_zero_on_empty_limiter():
    limiter = SlidingWindowRateLimiter(max_events=5, window_seconds=10.0)
    assert limiter.prune() == 0


@pytest.mark.asyncio
async def test_run_rate_limiter_pruner_prunes_each_limiter_until_cancelled():
    limiter_a = SlidingWindowRateLimiter(max_events=5, window_seconds=0.01)
    limiter_b = SlidingWindowRateLimiter(max_events=5, window_seconds=0.01)
    limiter_a.allow("k")
    limiter_b.allow("k")
    await asyncio.sleep(0.02)  # let both keys age out of their 0.01s windows

    task = asyncio.create_task(
        run_rate_limiter_pruner([limiter_a, limiter_b], interval_seconds=0.01)
    )
    try:
        for _ in range(200):
            if "k" not in limiter_a._events and "k" not in limiter_b._events:
                break
            await asyncio.sleep(0.01)
        else:
            pytest.fail("run_rate_limiter_pruner never pruned the aged-out keys")
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task


@pytest.mark.asyncio
async def test_run_rate_limiter_pruner_survives_one_limiter_raising(monkeypatch):
    """A single prune() call raising (e.g. a future bug) must not kill the loop or
    stop OTHER limiters in the same list from being pruned on the next iteration."""
    good_limiter = SlidingWindowRateLimiter(max_events=5, window_seconds=0.01)
    good_limiter.allow("k")
    await asyncio.sleep(0.02)

    class _ExplodingLimiter(SlidingWindowRateLimiter):
        def prune(self, now=None):
            raise RuntimeError("boom")

    bad_limiter = _ExplodingLimiter(max_events=5, window_seconds=0.01)

    task = asyncio.create_task(
        run_rate_limiter_pruner([bad_limiter, good_limiter], interval_seconds=0.01)
    )
    try:
        for _ in range(200):
            if "k" not in good_limiter._events:
                break
            await asyncio.sleep(0.01)
        else:
            pytest.fail("good_limiter was never pruned despite bad_limiter raising")
    finally:
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
