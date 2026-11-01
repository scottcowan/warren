"""Async, best-effort webhook delivery.

`Notifier.emit` is synchronous and never blocks or raises: it dedupes the event per
(workspace, event) within `dedupe_seconds` (so a flapping agent can't spam), then puts it
on a bounded queue, dropping it (logged) when the queue is full. Worker tasks deliver
each notification to every target that wants it: the server-wide webhook and the
workspace owner's own. Each POST has a timeout; connection errors, timeouts, 429 and 5xx
are retried a few times with exponential backoff; anything else is logged and dropped.

Logging discipline: a log line names the event, workspace id, target kind ("server" /
"owner"), and an HTTP status or exception class. Never the URL (it is the credential)
and never the exception text (httpx puts the URL in it).
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime, timezone
from typing import Any

import structlog
from warren.notify.events import Notification, render
from warren.notify.targets import (
    Resolver,
    Target,
    default_resolver,
    is_public_destination,
)

log = structlog.get_logger(__name__)

# (url, body, timeout) -> HTTP status
Sender = Callable[[str, bytes, float], Awaitable[int]]
OwnerLookup = Callable[[str], Awaitable[Target | None]]
WatchedOwners = Callable[[], Awaitable[set[str]]]

_RETRY_STATUSES = frozenset({408, 425, 429})
_DEDUPE_PRUNE_AT = 2048


class HttpxSender:
    """POST JSON with httpx; no redirects (a redirect could point anywhere)."""

    def __init__(self) -> None:
        self._client: Any = None

    async def __call__(self, url: str, body: bytes, timeout: float) -> int:
        import httpx  # noqa: PLC0415

        if self._client is None:
            self._client = httpx.AsyncClient(follow_redirects=False)
        resp = await self._client.post(
            url, content=body, timeout=timeout,
            headers={"Content-Type": "application/json", "User-Agent": "warren-notify"},
        )
        return resp.status_code

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None


class Notifier:
    def __init__(
        self,
        *,
        server_target: Target | None = None,
        owner_lookup: OwnerLookup | None = None,
        watched_owners: WatchedOwners | None = None,
        sender: Sender | None = None,
        queue_size: int = 100,
        workers: int = 2,
        max_retries: int = 3,
        backoff_seconds: float = 1.0,
        backoff_max_seconds: float = 30.0,
        timeout_seconds: float = 5.0,
        dedupe_seconds: float = 300.0,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
        resolver: Resolver = default_resolver,
        wall_clock: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self.server_target = server_target
        self._owner_lookup = owner_lookup
        self._watched_owners = watched_owners
        self._sender: Sender = sender if sender is not None else HttpxSender()
        self._queue: asyncio.Queue[Notification] = asyncio.Queue(maxsize=queue_size)
        self._workers = max(1, workers)
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self.backoff_max_seconds = backoff_max_seconds
        self.timeout_seconds = timeout_seconds
        self.dedupe_seconds = dedupe_seconds
        self._clock = clock
        self._sleep = sleep
        self._resolver = resolver
        self._wall_clock = wall_clock
        self._last_sent: dict[tuple[str, str], float] = {}
        self._tasks: list[asyncio.Task] = []

    # --- producer side ---

    def emit(self, event: str, ws: Any, message: str) -> bool:
        """Queue `event` for `ws`. False if deduped or dropped. Never raises."""
        try:
            workspace_id = str(getattr(ws, "workspace_id", "") or "")
            key = (workspace_id, event)
            now = self._clock()
            last = self._last_sent.get(key)
            if last is not None and now - last < self.dedupe_seconds:
                log.debug("notify_deduped", notify_event=event, workspace_id=workspace_id)
                return False
            notification = Notification.for_workspace(event, ws, message, now=self._wall_clock())
            self._queue.put_nowait(notification)
            self._last_sent[key] = now
            if len(self._last_sent) > _DEDUPE_PRUNE_AT:
                self._prune(now)
            return True
        except asyncio.QueueFull:
            log.warning("notify_queue_full_dropped", notify_event=event)
            return False
        except Exception as exc:
            log.warning("notify_emit_failed", notify_event=event, error=type(exc).__name__)
            return False

    def _prune(self, now: float) -> None:
        for key in [k for k, t in self._last_sent.items() if now - t >= self.dedupe_seconds]:
            del self._last_sent[key]

    async def watched_owners(self) -> set[str] | None:
        """Owners whose workspaces need watching: None means all (a server-wide
        webhook is set), an empty set means nobody is listening."""
        if self.server_target is not None:
            return None
        if self._watched_owners is None:
            return set()
        try:
            return await self._watched_owners()
        except Exception as exc:
            log.warning("notify_owner_list_failed", error=type(exc).__name__)
            return set()

    # --- consumer side ---

    def start(self) -> None:
        if not self._tasks:
            self._tasks = [asyncio.create_task(self._worker()) for _ in range(self._workers)]

    async def stop(self) -> None:
        for task in self._tasks:
            task.cancel()
        for task in self._tasks:
            try:
                await task
            except (asyncio.CancelledError, Exception):
                pass
        self._tasks = []
        aclose = getattr(self._sender, "aclose", None)
        if aclose is not None:
            try:
                await aclose()
            except Exception:
                pass

    async def _worker(self) -> None:
        while True:
            notification = await self._queue.get()
            try:
                await self.deliver(notification)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                log.warning("notify_delivery_failed", notify_event=notification.event,
                            workspace_id=notification.workspace_id, error=type(exc).__name__)
            finally:
                self._queue.task_done()

    async def targets_for(self, n: Notification) -> list[Target]:
        targets = [self.server_target] if self.server_target is not None else []
        if n.owner and self._owner_lookup is not None:
            try:
                owner = await self._owner_lookup(n.owner)
            except Exception as exc:
                log.warning("notify_owner_lookup_failed", workspace_id=n.workspace_id, error=type(exc).__name__)
                owner = None
            if owner is not None:
                targets.append(owner)
        return [t for t in targets if t.wants(n.event)]

    async def deliver(self, n: Notification) -> None:
        for target in await self.targets_for(n):
            await self._deliver_one(n, target)

    async def _deliver_one(self, n: Notification, target: Target) -> bool:
        fields = {"notify_event": n.event, "workspace_id": n.workspace_id, "target": target.kind}
        url = target.url.get_secret_value()
        if target.require_public and not await is_public_destination(url, self._resolver):
            log.warning("notify_target_rejected", reason="non_public_destination", **fields)
            return False
        body = render(n, target.format)
        attempts = 1 + self.max_retries
        # The sender gets the timeout too; this outer bound catches one that ignores it.
        guard = self.timeout_seconds + min(1.0, self.timeout_seconds)
        for attempt in range(attempts):
            status: int | None = None
            try:
                code = await asyncio.wait_for(self._sender(url, body, self.timeout_seconds), timeout=guard)
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # timeouts, connection errors
                outcome = type(exc).__name__
            else:
                status = code
                if 200 <= code < 300:
                    log.info("notify_delivered", attempts=attempt + 1, **fields)
                    return True
                outcome = f"http_{code}"
                if code < 500 and code not in _RETRY_STATUSES:
                    log.warning("notify_rejected", status=code, **fields)
                    return False
            if attempt + 1 < attempts:
                delay = min(self.backoff_seconds * (2**attempt), self.backoff_max_seconds)
                log.info("notify_retrying", attempt=attempt + 1, outcome=outcome, delay_seconds=delay, **fields)
                await self._sleep(delay)
            else:
                log.warning("notify_dropped", attempts=attempts, outcome=outcome, status=status, **fields)
        return False

    async def drain(self) -> None:
        """Wait until every queued notification has been handled (tests, shutdown)."""
        await self._queue.join()
