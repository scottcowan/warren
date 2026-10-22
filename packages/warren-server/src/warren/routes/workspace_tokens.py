"""POST /workspaces/{id}/tokens -- mint a workspace-scoped machine token (AI9);
POST /workspace-tokens -- mint one for a workspace that is yet to be provisioned (AI8/AJ2).

Only the workspace's owner, presenting their own user token, can mint one.
A workspace-scoped token can never mint another (AuthMiddleware doesn't route
it here, and this handler checks again).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import structlog
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field
from warren.audit import audit_event
from warren.auth.deps import current_token_id, current_user, current_workspace_scope
from warren.auth.tokens import derive_token_pepper, hash_token
from warren.auth.workspace_tokens import (
    DEFAULT_TTL_SECONDS,
    MAX_TTL_SECONDS,
    generate_workspace_token,
    parse_public_key,
)

log = structlog.get_logger(__name__)

router = APIRouter()


class WorkspaceTokenRequest(BaseModel):
    ttl_seconds: int = Field(default=DEFAULT_TTL_SECONDS, ge=60, le=MAX_TTL_SECONDS)
    public_key: str | None = None


class MintedWorkspaceToken(BaseModel):
    token_id: str
    token: str
    workspace_id: str
    expires_at: datetime
    key_bound: bool


@router.post("/workspaces/{workspace_id}/tokens", status_code=201, response_model=MintedWorkspaceToken)
async def mint_workspace_token(
    workspace_id: str, body: WorkspaceTokenRequest, request: Request
) -> MintedWorkspaceToken:
    user = current_user(request)
    if current_workspace_scope(request) is not None:
        raise HTTPException(status_code=403, detail="workspace-scoped tokens cannot mint tokens")

    ws = await request.app.state.registry.store.get(workspace_id)
    if ws is None:
        raise HTTPException(status_code=404, detail="workspace not found")
    if ws.owner_id is None or ws.owner_id != user.user_id:
        audit_event("workspace_token.issue", request=request, outcome="denied", workspace_id=workspace_id)
        raise HTTPException(status_code=403, detail="not workspace owner")
    if ws.status == "destroyed":
        raise HTTPException(status_code=410, detail="workspace was destroyed")

    if body.public_key is not None:
        try:
            parse_public_key(body.public_key)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    settings = request.app.state.settings
    pepper = derive_token_pepper(settings.secret_key.get_secret_value())
    raw = generate_workspace_token()
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=body.ttl_seconds)
    minted = await request.app.state.auth_store.create_workspace_token(
        workspace_id=workspace_id,
        user_id=user.user_id,
        hashed_token=hash_token(raw, pepper),
        expires_at=expires_at,
        public_key=body.public_key,
        created_by_token_id=current_token_id(request),
    )
    audit_event(
        "workspace_token.issue",
        request=request,
        owner_id=ws.owner_id,
        workspace_id=workspace_id,
        issued_token_id=minted.token_id,
        expires_at=expires_at.isoformat(),
        key_bound=body.public_key is not None,
    )
    return MintedWorkspaceToken(
        token_id=minted.token_id,
        token=raw,
        workspace_id=workspace_id,
        expires_at=expires_at,
        key_bound=body.public_key is not None,
    )


@router.post("/workspace-tokens", status_code=201, response_model=MintedWorkspaceToken)
async def reserve_workspace_token(body: WorkspaceTokenRequest, request: Request) -> MintedWorkspaceToken:
    """AI8/AJ2: mint a reservation token for a server-chosen workspace id that doesn't
    exist yet. It can provision that one workspace once (POST /workspaces or the MCP
    new_workspace tool), then acts on it like any workspace token."""
    user = current_user(request)
    if current_workspace_scope(request) is not None:
        raise HTTPException(status_code=403, detail="workspace-scoped tokens cannot mint tokens")
    if body.public_key is not None:
        try:
            parse_public_key(body.public_key)
        except ValueError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    workspace_id = str(uuid.uuid4())
    settings = request.app.state.settings
    pepper = derive_token_pepper(settings.secret_key.get_secret_value())
    raw = generate_workspace_token()
    expires_at = datetime.now(timezone.utc) + timedelta(seconds=body.ttl_seconds)
    minted = await request.app.state.auth_store.create_workspace_token(
        workspace_id=workspace_id,
        user_id=user.user_id,
        hashed_token=hash_token(raw, pepper),
        expires_at=expires_at,
        public_key=body.public_key,
        created_by_token_id=current_token_id(request),
        provision_grant=True,
    )
    audit_event(
        "workspace_token.issue",
        request=request,
        owner_id=user.user_id,
        workspace_id=workspace_id,
        issued_token_id=minted.token_id,
        expires_at=expires_at.isoformat(),
        key_bound=body.public_key is not None,
        reservation=True,
    )
    return MintedWorkspaceToken(
        token_id=minted.token_id,
        token=raw,
        workspace_id=workspace_id,
        expires_at=expires_at,
        key_bound=body.public_key is not None,
    )
