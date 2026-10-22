"""GET /healthz route (SD-01)."""

from __future__ import annotations

import structlog
from fastapi import APIRouter, Request

log = structlog.get_logger(__name__)
router = APIRouter()


@router.get("/healthz")
async def healthz(request: Request) -> dict:
    settings = request.app.state.settings
    return {"status": "ok", "workspace_id": settings.workspace_id}
