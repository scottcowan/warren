"""GET /agent-state: the agent's latest reported state (AG5/AM1)."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, Request

from warren_sidecar.agent_state import current_state
from warren_sidecar.auth import require_sidecar_token

router = APIRouter(dependencies=[Depends(require_sidecar_token)])


@router.get("/agent-state")
async def agent_state(request: Request) -> dict:
    root = request.app.state.settings.harness_root.rstrip("/")
    return await asyncio.to_thread(current_state, f"{root}/.session")
