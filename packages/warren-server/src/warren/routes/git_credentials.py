"""GET /workspaces/{id}/git-credential -- the control-plane issuer's endpoint (AK1).

Called by the workspace's git credential helper (or `gh` wrapper) with the
workspace's AI9 scoped token, or by the owner. Answers in git-credential
format (or the bare token with `format=token`), for the one repo named by
`path`, which must belong to the workspace's template. Never mints for a
destroyed workspace.
"""

from __future__ import annotations

import asyncio

import structlog
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import PlainTextResponse
from warren.audit import audit_event
from warren.auth.deps import current_user, require_workspace_access
from warren.registry.registry import deserialize_spec_extra
from warren_common.github_tokens import (
    TokenIssuerError,
    git_credential_response,
    github_grants_for,
    grant_for_path,
)

log = structlog.get_logger(__name__)

router = APIRouter()


@router.get("/workspaces/{workspace_id}/git-credential", response_class=PlainTextResponse)
async def workspace_git_credential(
    workspace_id: str, request: Request, path: str = "", format: str = "git"  # noqa: A002
) -> PlainTextResponse:
    user = current_user(request)
    require_workspace_access(request, workspace_id)
    ws = await request.app.state.registry.store.get(workspace_id)
    if ws is None:
        raise HTTPException(status_code=404, detail="workspace not found")
    if ws.owner_id is None or ws.owner_id != user.user_id:
        raise HTTPException(status_code=403, detail="not workspace owner")
    if ws.status == "destroyed":
        raise HTTPException(status_code=410, detail="workspace was destroyed")

    issuer = getattr(request.app.state, "github_token_issuer", None)
    if issuer is None:
        raise HTTPException(status_code=503, detail="github app token issuer not configured")

    grants = github_grants_for(deserialize_spec_extra(ws.spec_json).get("folders", []))
    grant = grant_for_path(grants, path)
    if grant is None:
        audit_event(
            "github_token.issue",
            request=request,
            outcome="denied",
            owner_id=ws.owner_id,
            workspace_id=workspace_id,
            repo_path=path,
        )
        raise HTTPException(status_code=403, detail="repository not granted to this workspace")

    try:
        issued = await asyncio.to_thread(issuer.issue, grant)
    except TokenIssuerError as exc:
        log.warning("github_token_issue_failed", workspace_id=workspace_id, error=str(exc))
        raise HTTPException(status_code=502, detail="github app token exchange failed") from exc

    audit_event(
        "github_token.issue",
        request=request,
        owner_id=ws.owner_id,
        workspace_id=workspace_id,
        github_owner=grant.owner,
        repositories=list(grant.repositories),
        permissions=dict(grant.permissions),
        expires_at=issued.expires_at,
    )
    body = issued.token if format == "token" else git_credential_response(issued)
    return PlainTextResponse(body, headers={"Cache-Control": "no-store"})
