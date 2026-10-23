"""Self-service token API — a normal (non-admin) user can mint, list, and revoke their
OWN tokens, without needing an admin to do it for them.

Deliberately NOT under /admin and NOT gated by require_admin: /admin/* (routes/admin.py)
is the separate, narrower "manage any user" surface reserved for operator cleanup. This
router is the same create/revoke primitive, but every operation is scoped to
current_user.user_id — there is no user_id path parameter here, so a caller can never
name another user's token by id; ownership is enforced server-side, not by the caller
supplying the right id.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel
from warren.auth.deps import current_token_id, current_user
from warren.auth.models import Token, User
from warren.auth.store import TokenLimitReached
from warren.auth.tokens import derive_token_pepper, generate_token, hash_token

log = structlog.get_logger(__name__)

router = APIRouter(prefix="/tokens", tags=["tokens"])


class MintedToken(BaseModel):
    """Carries the raw token. Only ever returned at mint time — never re-retrievable."""

    token_id: str
    token: str
    created_at: datetime
    expires_at: datetime | None = None


@router.post("", status_code=201, response_model=MintedToken)
async def mint_own_token(
    request: Request,
    user: User = Depends(current_user),
    acting_token_id: str | None = Depends(current_token_id),
) -> MintedToken:
    """Mint an additional token for the calling user — no admin required.

    Issue #11: capped at `settings.max_tokens_per_user` live (non-expired, non-revoked)
    tokens -- previously any valid token could mint unlimited further ones, unboundedly
    growing a stolen token's blast radius. `created_by_token_id` records which token
    minted this one (provenance for a possible future cascading-revoke-by-lineage
    feature; not implemented yet).
    """
    store = request.app.state.auth_store
    settings = request.app.state.settings
    pepper = derive_token_pepper(settings.secret_key.get_secret_value())

    raw_token = generate_token()
    hashed = hash_token(raw_token, pepper)
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.token_ttl_days)
    try:
        token = await store.create_token(
            user_id=user.user_id,
            hashed_token=hashed,
            expires_at=expires_at,
            created_by_token_id=acting_token_id,
            max_active=settings.max_tokens_per_user,
        )
    except TokenLimitReached:
        raise HTTPException(
            status_code=429,
            detail=f"max_tokens_per_user ({settings.max_tokens_per_user}) reached",
        ) from None

    log.info("self_token_minted", user_id=user.user_id, token_id=token.token_id)

    return MintedToken(
        token_id=token.token_id,
        token=raw_token,
        created_at=token.created_at,
        expires_at=token.expires_at,
    )


@router.get("", response_model=list[Token])
async def list_own_tokens(request: Request, user: User = Depends(current_user)) -> list[Token]:
    """List the calling user's own tokens. Never returns hash material."""
    store = request.app.state.auth_store
    return await store.list_tokens_for_user(user.user_id)


@router.delete("/{token_id}", status_code=204)
async def revoke_own_token(
    token_id: str, request: Request, user: User = Depends(current_user)
) -> Response:
    """Revoke one of the calling user's own tokens.

    A token_id belonging to another user is reported 404, identically to an unknown
    token_id — this never confirms or denies that another user's token exists.
    """
    store = request.app.state.auth_store

    token = await store.get_token(token_id)
    if token is None or token.user_id != user.user_id:
        raise HTTPException(status_code=404, detail="token not found")

    revoked = await store.revoke_token(token_id)
    if not revoked:
        raise HTTPException(status_code=404, detail="token not found")

    log.info("self_token_revoked", user_id=user.user_id, token_id=token_id)

    return Response(status_code=204)
