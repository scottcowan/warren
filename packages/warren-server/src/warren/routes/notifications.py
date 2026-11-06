"""Per-owner notification webhook (warren.notify).

    PUT    /notifications/webhook   {"url", "format": "json"|"slack", "events": [...]}
    GET    /notifications/webhook   {"configured", "format", "events"}  (never the URL)
    DELETE /notifications/webhook

The caller is the owner: their webhook gets events for workspaces they own
(`workspaces.owner_id`). Stored encrypted in the secrets store (warren.notify.store).
Workspace-scoped tokens can't reach these routes (auth.workspace_tokens allow-list).
"""

from __future__ import annotations

import structlog
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, Field
from warren.audit import audit_event
from warren.auth.deps import current_user
from warren.notify import store as notify_store
from warren.notify.events import EVENTS
from warren.notify.targets import Format, parse_events, validate_webhook_url
from warren.secrets.cipher import LocalCipher

log = structlog.get_logger(__name__)

router = APIRouter()


class WebhookWriteRequest(BaseModel):
    url: str = Field(max_length=2048)
    format: Format = "json"
    # Omitted or empty: every event.
    events: list[str] | None = Field(default=None, max_length=len(EVENTS))


class WebhookView(BaseModel):
    configured: bool
    format: Format | None = None
    events: list[str] = Field(default_factory=list)
    available_events: list[str] = Field(default_factory=lambda: list(EVENTS))


def _cipher(request: Request) -> LocalCipher:
    return LocalCipher(request.app.state.settings.secret_key.get_secret_value())


@router.put("/notifications/webhook", status_code=204)
async def put_webhook(body: WebhookWriteRequest, request: Request) -> Response:
    user = current_user(request)
    try:
        url = validate_webhook_url(body.url)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error": "invalid_webhook_url", "detail": str(exc)}) from None
    try:
        events = parse_events(body.events)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error": "invalid_events", "detail": str(exc)}) from None
    await notify_store.put(request.app.state.db, _cipher(request), user.user_id, url, body.format, events)
    log.info("notify_webhook_written", owner_id=user.user_id, format=body.format, events=sorted(events))
    audit_event("notify.webhook.write", request=request, owner_id=user.user_id)
    return Response(status_code=204)


@router.get("/notifications/webhook", response_model=WebhookView)
async def get_webhook(request: Request) -> WebhookView:
    user = current_user(request)
    target = await notify_store.get(request.app.state.db, _cipher(request), user.user_id)
    if target is None:
        return WebhookView(configured=False)
    return WebhookView(configured=True, format=target.format, events=sorted(target.events))


@router.delete("/notifications/webhook", status_code=204)
async def delete_webhook(request: Request) -> Response:
    user = current_user(request)
    if not await notify_store.delete(request.app.state.db, user.user_id):
        raise HTTPException(status_code=404, detail={"error": "webhook_not_found"})
    log.info("notify_webhook_deleted", owner_id=user.user_id)
    audit_event("notify.webhook.delete", request=request, owner_id=user.user_id)
    return Response(status_code=204)
