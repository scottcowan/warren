"""Admin HTTP surface — AUTH-02 (create user + mint token, mint extra token, list, revoke).

D-01: this repo owns the admin API; the sibling `warren-cli` repo's `warren users create` /
`warren tokens revoke` commands are thin wrappers over these endpoints, not implemented here.
D-02: every route depends on `require_admin` — declared on the router itself so a future
admin route cannot forget the gate.
D-09: POST /admin/users creates the user AND mints its first token in one call, so a user
can never exist with zero tokens.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import aiosqlite
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field
from warren.auth.deps import current_token_id, require_admin
from warren.auth.models import Token, User
from warren.auth.store import LastAdminError, TokenLimitReached
from warren.auth.tokens import derive_token_pepper, generate_token, hash_token

log = structlog.get_logger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"], dependencies=[Depends(require_admin)])


class UserCreateRequest(BaseModel):
    username: str = Field(min_length=1, max_length=64, pattern=r"^[a-z0-9_-]+$")
    is_admin: bool = False


class MintedToken(BaseModel):
    """Carries the raw token. Only ever returned at mint time — never re-retrievable."""

    token_id: str
    token: str
    created_at: datetime
    expires_at: datetime | None = None


class UserResponse(BaseModel):
    user_id: str
    username: str
    is_admin: bool
    created_at: datetime
    disabled_at: datetime | None = None


class UserCreateResponse(BaseModel):
    user: UserResponse
    token: MintedToken


class UserDisableResponse(BaseModel):
    user: UserResponse
    revoked_token_count: int


def _token_expiry(request: Request) -> datetime:
    ttl_days = request.app.state.settings.token_ttl_days
    return datetime.now(timezone.utc) + timedelta(days=ttl_days)


@router.post("/users", status_code=201, response_model=UserCreateResponse)
async def create_user(
    body: UserCreateRequest, request: Request, acting_token_id: str | None = Depends(current_token_id)
) -> UserCreateResponse:
    """Create a user and mint its first token in one call (D-09)."""
    store = request.app.state.auth_store
    pepper = derive_token_pepper(request.app.state.settings.secret_key.get_secret_value())

    try:
        user = await store.create_user(username=body.username, is_admin=body.is_admin)
    except aiosqlite.IntegrityError as exc:
        raise HTTPException(status_code=409, detail="username already exists") from exc

    raw_token = generate_token()
    hashed = hash_token(raw_token, pepper)
    token = await store.create_token(
        user_id=user.user_id,
        hashed_token=hashed,
        expires_at=_token_expiry(request),
        created_by_token_id=acting_token_id,
    )

    log.info("admin.user_created", user_id=user.user_id, token_id=token.token_id)

    return UserCreateResponse(
        user=UserResponse(**user.model_dump()),
        token=MintedToken(
            token_id=token.token_id,
            token=raw_token,
            created_at=token.created_at,
            expires_at=token.expires_at,
        ),
    )


@router.get("/users", response_model=list[UserResponse])
async def list_users(request: Request) -> list[UserResponse]:
    """List all users. Never returns token or hash material."""
    store = request.app.state.auth_store
    users = await store.list_users()
    return [UserResponse(**u.model_dump()) for u in users]


@router.post("/users/{user_id}/tokens", status_code=201, response_model=MintedToken)
async def mint_token(
    user_id: str, request: Request, acting_token_id: str | None = Depends(current_token_id)
) -> MintedToken:
    """Mint an additional token for an existing user.

    Issue #11: subject to the same per-user live-token cap as self-service minting
    (routes/tokens.py) -- the admin surface is not a way around that cap.

    The cap is checked and the token inserted in one statement (AuthStore.create_token's
    `max_active`), so concurrent mints can't overshoot it.
    """
    store = request.app.state.auth_store
    settings = request.app.state.settings
    pepper = derive_token_pepper(settings.secret_key.get_secret_value())

    user = await store.get_user(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")

    raw_token = generate_token()
    hashed = hash_token(raw_token, pepper)
    try:
        token = await store.create_token(
            user_id=user.user_id,
            hashed_token=hashed,
            expires_at=_token_expiry(request),
            created_by_token_id=acting_token_id,
            max_active=settings.max_tokens_per_user,
        )
    except TokenLimitReached:
        raise HTTPException(
            status_code=429,
            detail=f"max_tokens_per_user ({settings.max_tokens_per_user}) reached for this user",
        ) from None

    log.info("admin.token_minted", user_id=user.user_id, token_id=token.token_id)

    return MintedToken(
        token_id=token.token_id,
        token=raw_token,
        created_at=token.created_at,
        expires_at=token.expires_at,
    )


@router.get("/users/{user_id}/tokens", response_model=list[Token])
async def list_user_tokens(user_id: str, request: Request) -> list[Token]:
    """List a user's tokens (metadata only -- never hash material). Admin-gated."""
    store = request.app.state.auth_store
    user = await store.get_user(user_id)
    if user is None:
        raise HTTPException(status_code=404, detail="user not found")
    return await store.list_tokens_for_user(user_id)


@router.post("/users/{user_id}/disable", response_model=UserDisableResponse)
async def disable_user(
    user_id: str, request: Request, admin_user: User = Depends(require_admin)
) -> UserDisableResponse:
    """Disable a user and revoke all of their live tokens in one call.

    Issue #11: chose "disable implies revoke-all" over a separate standalone
    revoke-all-tokens route -- a disabled user with surviving live tokens defeats the
    point of disabling (AuthStore's resolve query already blocks them going forward via
    `disabled_at IS NULL`, but revoking them too keeps `list_user_tokens` and the user's
    own self-service /tokens list honest about what's actually usable). Idempotent: disabling
    an already-disabled user re-sweeps any tokens minted since (e.g. a race), revoking 0
    more if there are none.

    Audit V5: two self-lockout guards, checked before the actual disable --
    disabling yourself revokes your own token via revoke_all_tokens_for_user below,
    locking you out mid-request with no way back in except another admin or
    `recover-admin`; disabling the last enabled admin locks EVERYONE out of normal
    admin access the same way. Neither is ever a legitimate single API call -- an
    admin stepping down deliberately still needs another admin to do the disabling,
    or a deployment with only one admin needs to promote a second one first.
    """
    store = request.app.state.auth_store

    if user_id == admin_user.user_id:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "cannot_disable_self",
                "detail": "an admin cannot disable their own account",
            },
        )

    try:
        disabled = await store.disable_user(user_id, keep_last_admin=True)
    except LastAdminError:
        raise HTTPException(
            status_code=422,
            detail={
                "error": "cannot_disable_last_admin",
                "detail": "refusing to disable the only enabled admin -- "
                "promote another admin first",
            },
        ) from None
    if not disabled:
        raise HTTPException(status_code=404, detail="user not found")

    revoked_count = await store.revoke_all_tokens_for_user(user_id)
    user = await store.get_user(user_id)
    assert user is not None  # just confirmed to exist above

    log.info(
        "admin.user_disabled",
        user_id=user_id,
        revoked_token_count=revoked_count,
        acting_admin_user_id=admin_user.user_id,
    )

    return UserDisableResponse(
        user=UserResponse(**user.model_dump()),
        revoked_token_count=revoked_count,
    )


@router.delete("/tokens/{token_id}", status_code=204)
async def revoke_token(
    token_id: str, request: Request, admin_user: User = Depends(require_admin)
) -> Response:
    """Revoke a single token by id. Idempotent-safe: unknown or already-revoked ids are 404.

    Scoped strictly to one token_id — there is no bulk/user-wide revoke endpoint, which is
    what guarantees one user's revocation cannot affect another's access (T-02-18).
    """
    store = request.app.state.auth_store

    revoked = await store.revoke_token(token_id)
    if not revoked:
        raise HTTPException(status_code=404, detail="token not found")

    log.info("admin.token_revoked", token_id=token_id, acting_admin_user_id=admin_user.user_id)

    return Response(status_code=204)
