"""Agent notifications: webhooks on agent state changes and workspace lifecycle events.

See docs/notifications.md. Pieces: events (detection + payloads), targets (URL
validation, SSRF guard), store (per-owner subscriptions in the secrets store),
dispatcher (bounded queue, dedupe, retries) and watcher (agent-state polling).
"""

from __future__ import annotations

from typing import Any

import structlog
from warren.notify.dispatcher import Notifier
from warren.notify.events import EVENTS, IDLE_STOPPED, PROVISION_FAILED, code
from warren.notify.targets import Target, parse_events

log = structlog.get_logger(__name__)

__all__ = ["EVENTS", "Notifier", "build_notifier", "notify_workspace", "notify_workspace_id"]


def build_notifier(settings: Any, secrets: Any) -> Notifier:
    """The server's Notifier from WARREN_NOTIFY_* settings and the server's secret store
    (a `SecretStoreProtocol`; None: server-wide webhook only)."""
    from warren.notify import store  # noqa: PLC0415

    server_target = None
    if settings.notify_webhook_url is not None:
        server_target = Target(
            url=settings.notify_webhook_url,
            format=settings.notify_format,
            events=parse_events(settings.notify_events),
            kind="server",
        )

    async def owner_lookup(owner_id: str) -> Target | None:
        return await store.get(secrets, owner_id)

    async def watched_owners() -> set[str]:
        return await store.subscribed_owners(secrets)

    return Notifier(
        server_target=server_target,
        owner_lookup=owner_lookup if secrets is not None else None,
        watched_owners=watched_owners if secrets is not None else None,
        queue_size=settings.notify_queue_size,
        max_retries=settings.notify_max_retries,
        timeout_seconds=settings.notify_timeout_seconds,
        dedupe_seconds=settings.notify_dedupe_seconds,
    )


def notify_workspace(registry: Any, event: str, ws: Any, message: str) -> None:
    """Emit through `registry.notifier` if one is wired. Never raises."""
    notifier = getattr(registry, "notifier", None)
    if isinstance(notifier, Notifier) and ws is not None:
        notifier.emit(event, ws, message)


async def notify_workspace_id(registry: Any, event: str, workspace_id: str, message: str) -> None:
    """notify_workspace for a workspace id (looked up in the registry's store)."""
    notifier = getattr(registry, "notifier", None)
    if not isinstance(notifier, Notifier):
        return
    try:
        ws = await registry.store.get(workspace_id)
    except Exception as exc:
        log.warning("notify_workspace_lookup_failed", workspace_id=workspace_id, error=type(exc).__name__)
        return
    notify_workspace(registry, event, ws, message)


def idle_stopped_message(reason: str) -> str:
    return f"stopped by the idle reaper ({code(reason)})"


def provision_failed_message(reason: str) -> str:
    return f"provisioning failed ({code(reason)})"


__all__ += ["IDLE_STOPPED", "PROVISION_FAILED", "idle_stopped_message", "provision_failed_message"]
