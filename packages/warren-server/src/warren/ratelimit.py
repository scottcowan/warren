"""In-memory sliding-window rate limiter — audit 2026-10-16 P2 #46.

Single-process only, deliberately not Redis/distributed-backed: warren-server is a
single-server app (no horizontal scaling story today), so a per-process in-memory window
is the right amount of mechanism for "stop a tight retry loop", not a shared rate-limit
service.
"""

from __future__ import annotations

import asyncio
import time
from collections import defaultdict, deque

import structlog

log = structlog.get_logger(__name__)

# S10: default interval for run_rate_limiter_pruner's background sweep -- infrequent
# enough that it's never the dominant cost of a long-running server, frequent enough
# that an abandoned key's memory doesn't linger for the server's entire uptime.
_DEFAULT_PRUNE_INTERVAL_SECONDS = 300.0


class SlidingWindowRateLimiter:
    """Tracks event timestamps per key; `allow()` both checks and records in one call.

    S10: `_events` previously grew forever -- `allow()`'s own per-call trim only ever
    runs for the key being touched RIGHT NOW, so a key that stops being called entirely
    once its events age out (e.g. a one-off abandoned IP/user that's never seen again)
    keeps its stale deque sitting in this dict for the server's entire uptime; nothing
    ever revisits that key to trim it. `prune()` below does a full sweep across every
    key, dropping any whose deque has entirely aged out -- see run_rate_limiter_pruner,
    which calls it periodically from app.py's lifespan, the same background-task
    pattern as registry/idle_reaper.py's run_idle_reaper.

    S10 (known limitation, not fixed here): every client reaching this server through an
    SSH tunnel or an ECS SSM port-forward appears as source IP 127.0.0.1 (that's the
    apparent origin once the tunnel/forward terminates locally) -- any limiter keyed by
    IP (auth/middleware.py's `_failed_auth_limiter`, specifically) therefore treats every
    such user as ONE shared bucket, not one each. A real fix needs per-request identity
    that's available before authentication succeeds or fails -- which, for a limiter
    whose entire purpose is throttling repeated FAILED/missing-auth attempts, does not
    exist: there is no user_id yet at the point this limiter is consulted. (Contrast
    routes/workspaces.py's `_create_workspace_limiter`, which already keys on
    `user.user_id` rather than IP, since that call site runs only after authentication
    succeeds -- no fix was needed there.) Left as a documented, accepted tradeoff rather
    than guessing at a fix that would need restructuring when identity becomes
    available, matching this codebase's existing style of calling out such tradeoffs
    explicitly instead of silently.
    """

    def __init__(self, max_events: int, window_seconds: float) -> None:
        self.max_events = max_events
        self.window_seconds = window_seconds
        self._events: dict[str, deque[float]] = defaultdict(deque)

    def allow(self, key: str) -> bool:
        """Return True and record an event for `key` if under the limit, else False
        (and record nothing -- a rejected call doesn't itself count against the window)."""
        now = time.monotonic()
        events = self._events[key]
        cutoff = now - self.window_seconds
        while events and events[0] < cutoff:
            events.popleft()
        if len(events) >= self.max_events:
            return False
        events.append(now)
        return True

    def prune(self, now: float | None = None) -> int:
        """Drop every key whose events have all aged out of the window (S10).

        Catches what `allow()`'s own per-call trim can't: a key that is NEVER called
        again after its events expire (e.g. a one-off abandoned IP) has no future
        `allow()` call to trim it, so without a periodic full sweep it would sit in
        `_events` for the server's entire uptime. Safe to call concurrently with
        `allow()` -- both only ever pop/append on `deque`, and a key popped here that
        `allow()` is simultaneously re-populating just gets recreated by the
        `defaultdict`, same as if `prune()` had never run.

        Returns the number of keys dropped (for tests/observability).
        """
        now = now if now is not None else time.monotonic()
        cutoff = now - self.window_seconds
        dropped = 0
        for key in list(self._events.keys()):
            events = self._events.get(key)
            if events is None:
                continue
            while events and events[0] < cutoff:
                events.popleft()
            if not events:
                self._events.pop(key, None)
                dropped += 1
        return dropped


async def run_rate_limiter_pruner(
    limiters: list[SlidingWindowRateLimiter],
    *,
    interval_seconds: float = _DEFAULT_PRUNE_INTERVAL_SECONDS,
) -> None:
    """Async background loop pruning every limiter in `limiters`; runs until cancelled.

    S10: mirrors registry/idle_reaper.py's run_idle_reaper -- a `while True` /
    `asyncio.sleep` loop started once from app.py's lifespan and cancelled on shutdown,
    rather than a reaper per limiter instance.
    """
    while True:
        for limiter in limiters:
            try:
                dropped = limiter.prune()
                if dropped:
                    log.debug("rate_limiter_pruned", dropped=dropped)
            except asyncio.CancelledError:
                raise
            except Exception:
                # One limiter raising (a future bug in a custom subclass, say) must not
                # stop every OTHER limiter in this list from being pruned, nor kill the
                # loop itself.
                log.exception("rate_limiter_prune_failed")
        await asyncio.sleep(interval_seconds)
