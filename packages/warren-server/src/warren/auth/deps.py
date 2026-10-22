"""FastAPI request accessors for the authenticated user.

MIDDLEWARE CONTRACT: the auth middleware (plan 02-02) sets scope["state"]["user"] = User,
which Starlette exposes as `request.state.user`.

`require_admin` is a SECOND explicit gate on top of the base auth middleware, per D-02 —
the middleware only proves "a valid user", never "an admin". Route handlers that require
admin privileges must depend on `require_admin`, not `current_user`.
"""

from __future__ import annotations

from fastapi import HTTPException, Request
from warren.auth.identity import resolve_owner_id as resolve_owner_id
from warren.auth.models import User

__all__ = [
    "current_token_id",
    "current_user",
    "current_workspace_scope",
    "require_admin",
    "require_workspace_access",
    "resolve_owner_id",
]


def current_user(request: Request) -> User:
    """Return the authenticated User for this request, or raise 401 if absent."""
    user = getattr(request.state, "user", None)
    if user is None:
        raise HTTPException(status_code=401, detail="unauthorized")
    return user


def current_token_id(request: Request) -> str | None:
    """Return the token_id AuthMiddleware resolved the calling bearer token to, or None.

    Issue #11: route handlers that mint a new token (routes/tokens.py, routes/admin.py)
    use this to stamp `created_by_token_id` provenance on it. None only when auth was
    somehow bypassed for this request (e.g. a test overriding `current_user` directly
    without going through AuthMiddleware) -- never for a normally-authenticated request.
    """
    return getattr(request.state, "token_id", None)


def current_workspace_scope(request: Request) -> str | None:
    """AI9: the workspace a workspace-scoped token is bound to, or None for a user token."""
    return getattr(request.state, "workspace_scope", None)


def require_workspace_access(request: Request, workspace_id: str) -> None:
    """Defense in depth behind AuthMiddleware's route allow-list: a workspace-scoped
    token may only ever act on its own workspace."""
    scope = current_workspace_scope(request)
    if scope is not None and scope != workspace_id:
        raise HTTPException(status_code=403, detail="workspace-scoped token cannot access this resource")


def require_admin(request: Request) -> User:
    """Return the authenticated admin User for this request, or raise 403 if not an admin."""
    user = current_user(request)
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="admin required")
    return user
