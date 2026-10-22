"""First-admin bootstrap (D-03/D-04): create the first admin user from WARREN_BOOTSTRAP_TOKEN
when the `users` table is empty, idempotently across every lifespan invocation (RESEARCH.md
Pitfall 5).
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import aiosqlite
import structlog
from warren.auth.tokens import derive_token_pepper, hash_token

if TYPE_CHECKING:
    from warren.auth.store import AuthStore
    from warren.config import WarrenSettings

log = structlog.get_logger(__name__)

_BOOTSTRAP_ADMIN_USERNAME = "bootstrap-admin"


async def ensure_bootstrap_admin(store: "AuthStore", settings: "WarrenSettings") -> str | None:
    """Create the first admin user/token from WARREN_BOOTSTRAP_TOKEN if no admin exists yet.

    Returns the created admin's user_id, or None when bootstrap was skipped (no bootstrap
    token configured, an admin already exists, or a racing concurrent bootstrap won the
    insert first).

    Never logs or returns the raw bootstrap token value or its hash.
    """
    if settings.bootstrap_token is None:
        log.warning("auth_bootstrap_skipped_no_token")
        return None

    if await store.count_admins() > 0:
        # D-04: re-triggerable, not one-shot — an env var left behind after the first
        # boot must not mint a second admin or reset the first.
        return None

    raw_token = settings.bootstrap_token.get_secret_value()
    pepper = derive_token_pepper(settings.secret_key.get_secret_value())
    hashed = hash_token(raw_token, pepper)

    try:
        user = await store.create_user(username=_BOOTSTRAP_ADMIN_USERNAME, is_admin=True)
    except aiosqlite.IntegrityError:
        # A concurrent/racing second bootstrap call lost the race on the unique username —
        # degrade to a logged no-op rather than crashing startup (T-02-22). No user was
        # created by this call, so there is nothing to clean up.
        log.warning("auth_bootstrap_race_ignored")
        return None

    # Issue #11: the bootstrap admin's token is as subject to the TTL as any other --
    # there is no "permanent" token path left in this codebase.
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.token_ttl_days)
    try:
        await store.create_token(user_id=user.user_id, hashed_token=hashed, expires_at=expires_at)
    except aiosqlite.IntegrityError:
        # The admin user now exists but has no working token, and count_admins() > 0 will
        # block every future bootstrap attempt from retrying — this is a stuck deployment,
        # not a benign race, so it must be loud rather than logged identically to the
        # ignorable case above. No raw token or hash is logged.
        log.error("auth_bootstrap_token_creation_failed_admin_stranded", user_id=user.user_id)
        raise

    log.info("auth_bootstrap_admin_created", user_id=user.user_id, username=_BOOTSTRAP_ADMIN_USERNAME)
    return user.user_id
