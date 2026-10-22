"""Admin token recovery — audit 2026-10-16 P2 #44.

Before this, the only way to regain access after losing the last admin token was
re-bootstrapping, which requires either wiping the `users` table or never having had
one -- `ensure_bootstrap_admin` is a deliberate no-op once `count_admins() > 0` (D-04).
This module mints a fresh token for an *existing* admin user directly against the
database, with no HTTP surface and no new token-granting concept: it is the moral
equivalent of an admin calling `POST /admin/users/{user_id}/tokens` on themselves, just
reachable without a working token in hand.

Gating: this requires whatever already gates direct access to the server process and its
data directory and WARREN_SECRET_KEY (operator shell access, container exec, etc.) -- the
same trust level `ensure_bootstrap_admin` itself relies on for WARREN_BOOTSTRAP_TOKEN.
This is deliberately NOT a promote/demote system; it only mints a new token for a user
who is already an admin.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING

import structlog
from warren.auth.tokens import derive_token_pepper, generate_token, hash_token

if TYPE_CHECKING:
    from warren.auth.models import Token, User
    from warren.auth.store import AuthStore
    from warren.config import WarrenSettings

log = structlog.get_logger(__name__)


class NoAdminFoundError(Exception):
    """No admin user exists at all -- recovery can't help; re-bootstrap instead."""


class AmbiguousAdminError(Exception):
    """More than one admin user exists; caller must pass --username to pick one."""


class TargetAdminDisabledError(Exception):
    """The only/named admin is disabled -- a token minted for them would never
    authenticate (auth middleware rejects disabled users), so recovery would
    silently report success while leaving the operator just as locked out.
    Audit R9/S9: this used to be a PERMANENT lockout with no way out -- pass
    reenable=True to recover_admin_token (or --reenable on the CLI) to clear
    disabled_at as part of the same recovery operation.
    """


async def recover_admin_token(
    store: AuthStore,
    settings: WarrenSettings,
    *,
    username: str | None = None,
    reenable: bool = False,
) -> tuple[User, Token, str]:
    """Mint a fresh, full-TTL token for an existing admin user.

    Returns (user, token, raw_token). Never logs or returns the raw token anywhere but
    this one return value -- the caller (the CLI entrypoint) is responsible for printing
    it exactly once and not persisting it.

    Raises TargetAdminDisabledError if the selected admin is disabled and
    `reenable` wasn't passed -- minting a token for a disabled user would
    silently produce one that can never authenticate. Passing reenable=True
    clears disabled_at as part of this same operation; this stays a conscious
    opt-in rather than an automatic side effect, since this module is
    deliberately not a general promote/demote system.
    """
    admins = await store.list_admins()
    if not admins:
        raise NoAdminFoundError("no admin user exists -- re-run bootstrap instead")

    if username is not None:
        matches = [a for a in admins if a.username == username]
        if not matches:
            raise NoAdminFoundError(f"no admin user named {username!r}")
        target = matches[0]
    elif len(admins) == 1:
        target = admins[0]
    else:
        names = ", ".join(sorted(a.username for a in admins))
        raise AmbiguousAdminError(
            f"multiple admin users exist ({names}) -- pass --username to pick one"
        )

    if target.disabled_at is not None:
        if not reenable:
            raise TargetAdminDisabledError(
                f"admin {target.username!r} is disabled -- a token minted for them "
                "would never authenticate. Pass --reenable to also re-enable them "
                "as part of recovery."
            )
        await store.enable_user(target.user_id)
        log.info("auth_admin_reenabled_during_recovery", user_id=target.user_id, username=target.username)

    raw_token = generate_token()
    pepper = derive_token_pepper(settings.secret_key.get_secret_value())
    hashed = hash_token(raw_token, pepper)
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.token_ttl_days)
    token = await store.create_token(user_id=target.user_id, hashed_token=hashed, expires_at=expires_at)

    log.info("auth_admin_token_recovered", user_id=target.user_id, username=target.username)
    return target, token, raw_token
