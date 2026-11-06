"""Notifier: dedupe, bounded queue, retries/backoff (fake clock and sleep), timeouts,
target selection, SSRF guard, and no URL in logs. No real HTTP: a fake sender."""

from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest
from pydantic import SecretStr
from structlog.testing import capture_logs
from warren.notify import events as ev
from warren.notify.dispatcher import Notifier
from warren.notify.targets import Target

SERVER_URL = "https://hooks.example.com/services/T000/B000/serversecret"
OWNER_URL = "https://owner.example.com/hook/ownersecret"
WS = SimpleNamespace(workspace_id="ws-1", project="proj", owner_id="u1", intent="tmpl")


class FakeClock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


class FakeSleep:
    def __init__(self) -> None:
        self.delays: list[float] = []

    async def __call__(self, delay: float) -> None:
        self.delays.append(delay)


class FakeSender:
    def __init__(self, *responses) -> None:
        self.responses = list(responses)
        self.calls: list[tuple[str, dict]] = []

    async def __call__(self, url: str, body: bytes, timeout: float) -> int:
        self.calls.append((url, json.loads(body)))
        r = self.responses.pop(0) if self.responses else 200
        if isinstance(r, BaseException):
            raise r
        if r == "hang":
            await asyncio.sleep(3600)
        return r


async def _public(host, port):
    return ["93.184.216.34"]


def _notifier(sender, *, server=True, owner=None, **kw) -> Notifier:
    async def lookup(owner_id):
        return owner

    kw.setdefault("clock", FakeClock())
    kw.setdefault("sleep", FakeSleep())
    return Notifier(
        server_target=Target(url=SecretStr(SERVER_URL)) if server else None,
        owner_lookup=lookup,
        sender=sender,
        resolver=_public,
        **kw,
    )


def _all_log_text(logs) -> str:
    return json.dumps(logs, default=str)


async def test_dedupe_per_workspace_and_event():
    clock = FakeClock()
    n = _notifier(FakeSender(), clock=clock, dedupe_seconds=300)
    assert n.emit(ev.AGENT_WAITING, WS, "m") is True
    assert n.emit(ev.AGENT_WAITING, WS, "m") is False  # flap
    assert n.emit(ev.AGENT_FINISHED, WS, "m") is True  # other event
    assert n.emit(ev.AGENT_WAITING, SimpleNamespace(**{**vars(WS), "workspace_id": "ws-2"}), "m") is True
    clock.now += 299
    assert n.emit(ev.AGENT_WAITING, WS, "m") is False
    clock.now += 1
    assert n.emit(ev.AGENT_WAITING, WS, "m") is True


async def test_bounded_queue_drops_when_full():
    n = _notifier(FakeSender(), queue_size=2, dedupe_seconds=0)
    assert n.emit(ev.AGENT_WAITING, WS, "a")
    assert n.emit(ev.AGENT_FINISHED, WS, "b")
    with capture_logs() as logs:
        assert n.emit(ev.AGENT_FAILED, WS, "c") is False
    assert any(e["event"] == "notify_queue_full_dropped" for e in logs)


async def test_emit_never_raises():
    n = _notifier(FakeSender())
    assert n.emit(ev.AGENT_WAITING, object(), "m") in (True, False)


async def test_retries_with_exponential_backoff_then_succeeds():
    sleep = FakeSleep()
    sender = FakeSender(503, ConnectionError("boom " + SERVER_URL), 429, 200)
    n = _notifier(sender, sleep=sleep, max_retries=3, backoff_seconds=1.0)
    with capture_logs() as logs:
        await n.deliver(ev.Notification.for_workspace(ev.AGENT_WAITING, WS, "m"))
    assert len(sender.calls) == 4
    assert sleep.delays == [1.0, 2.0, 4.0]
    assert any(e["event"] == "notify_delivered" and e["attempts"] == 4 for e in logs)
    assert SERVER_URL not in _all_log_text(logs) and "serversecret" not in _all_log_text(logs)


async def test_gives_up_after_max_retries_and_logs_without_url():
    sleep = FakeSleep()
    sender = FakeSender(*[RuntimeError(f"failed POST {SERVER_URL}")] * 10)
    n = _notifier(sender, sleep=sleep, max_retries=2, backoff_seconds=0.5, backoff_max_seconds=0.75)
    with capture_logs() as logs:
        await n.deliver(ev.Notification.for_workspace(ev.AGENT_FAILED, WS, "m"))
    assert len(sender.calls) == 3
    assert sleep.delays == [0.5, 0.75]  # capped
    dropped = [e for e in logs if e["event"] == "notify_dropped"]
    assert dropped and dropped[0]["outcome"] == "RuntimeError" and dropped[0]["target"] == "server"
    assert "serversecret" not in _all_log_text(logs)


async def test_client_error_is_not_retried():
    sender = FakeSender(404)
    sleep = FakeSleep()
    n = _notifier(sender, sleep=sleep)
    with capture_logs() as logs:
        await n.deliver(ev.Notification.for_workspace(ev.AGENT_FAILED, WS, "m"))
    assert len(sender.calls) == 1 and sleep.delays == []
    assert any(e["event"] == "notify_rejected" and e["status"] == 404 for e in logs)


async def test_timeout_is_enforced_and_retried():
    sender = FakeSender("hang", 200)
    n = _notifier(sender, timeout_seconds=0.01, max_retries=1)
    with capture_logs() as logs:
        await asyncio.wait_for(n.deliver(ev.Notification.for_workspace(ev.AGENT_WAITING, WS, "m")), 2)
    assert len(sender.calls) == 2
    assert any(e["event"] == "notify_retrying" and e["outcome"] == "TimeoutError" for e in logs)


async def test_server_and_owner_targets_and_event_filter():
    owner = Target(url=SecretStr(OWNER_URL), format="slack", events=frozenset({ev.AGENT_WAITING}),
                   kind="owner", require_public=True)
    sender = FakeSender()
    n = _notifier(sender, owner=owner)
    await n.deliver(ev.Notification.for_workspace(ev.AGENT_WAITING, WS, "m"))
    assert [c[0] for c in sender.calls] == [SERVER_URL, OWNER_URL]
    assert "event" in sender.calls[0][1] and "text" in sender.calls[1][1]  # json, then slack
    sender.calls.clear()
    await n.deliver(ev.Notification.for_workspace(ev.AGENT_FINISHED, WS, "m"))
    assert [c[0] for c in sender.calls] == [SERVER_URL]  # owner didn't opt in to finished


@pytest.mark.parametrize("addr", ["127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "fd00::1"])
async def test_owner_target_must_resolve_public(addr):
    async def resolver(host, port):
        return [addr]

    owner = Target(url=SecretStr(OWNER_URL), kind="owner", require_public=True)
    sender = FakeSender()
    n = Notifier(owner_lookup=lambda _o: _ret(owner), sender=sender, resolver=resolver, sleep=FakeSleep())
    with capture_logs() as logs:
        await n.deliver(ev.Notification.for_workspace(ev.AGENT_WAITING, WS, "m"))
    assert sender.calls == []
    assert any(e["event"] == "notify_target_rejected" for e in logs)
    assert "ownersecret" not in _all_log_text(logs)


async def _ret(value):
    return value


async def test_worker_delivers_queued_notifications_and_stops():
    sender = FakeSender()
    n = _notifier(sender)
    n.start()
    try:
        n.emit(ev.PROVISION_FAILED, WS, "provisioning failed (image_unavailable)")
        await asyncio.wait_for(n.drain(), 2)
    finally:
        await n.stop()
    assert sender.calls[0][1]["event"] == "workspace.provision_failed"


async def test_watched_owners():
    assert await _notifier(FakeSender()).watched_owners() is None  # server webhook: watch all

    async def owners():
        return {"u1"}

    n = Notifier(watched_owners=owners, sender=FakeSender())
    assert await n.watched_owners() == {"u1"}
    assert await Notifier(sender=FakeSender()).watched_owners() == set()
