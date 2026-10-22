"""Pydantic models mirroring the users/tokens SQLite schema."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel


class User(BaseModel):
    user_id: str
    username: str
    is_admin: bool
    created_at: datetime
    # Issue #11: None means active. Checked by AuthStore.get_active_user_by_hashed_token
    # so a disabled user's existing tokens stop authenticating immediately, not just
    # "no new tokens".
    disabled_at: datetime | None = None


class Token(BaseModel):
    """Token metadata only. Deliberately has no hashed_token field so a Token can be
    serialized into an API response without leaking the digest."""

    token_id: str
    user_id: str
    created_at: datetime
    expires_at: datetime | None = None
    revoked_at: datetime | None = None
    # Issue #11: the token that minted this one (None for the bootstrap admin's first
    # token). Provenance only, for a possible future cascading-revoke-by-lineage feature.
    created_by_token_id: str | None = None


class WorkspaceToken(BaseModel):
    """AI9: a machine token valid for exactly one workspace."""

    token_id: str
    workspace_id: str
    user_id: str
    created_at: datetime
    expires_at: datetime
    revoked_at: datetime | None = None
    public_key: str | None = None
    created_by_token_id: str | None = None
    # AI8/AJ2: a reservation token, minted before its workspace exists, may provision it once.
    provision_grant: bool = False
    # None while a reservation is still unprovisioned.
    workspace_status: str | None = None
