"""GET /agent-state: the agent's latest reported state (AG5/AM1)."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Request

from warren_sidecar.agent_state import current_state

router = APIRouter()


@router.get("/agent-state")
async def agent_state(request: Request) -> dict:
    root = request.app.state.settings.harness_root.rstrip("/")
    return await asyncio.to_thread(current_state, f"{root}/.session")
