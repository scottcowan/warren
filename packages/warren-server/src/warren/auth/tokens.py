"""Token generation, hashing, and resolution.

We hash with HMAC-SHA256 peppered by the server `secret_key`, deliberately not a slow,
memory-hard password-hashing KDF. A `generate_token()` value is 256 bits of CSPRNG
entropy, so its security comes from that entropy, not from hash-function slowness — and
unlike a login password, this hash runs on every single authenticated request, so a slow
KDF would be a self-inflicted DoS vector for no security benefit.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from warren.auth.models import User
    from warren.auth.store import AuthStore


_PEPPER_DERIVATION_LABEL = b"warren-auth-token-pepper-v1"


def generate_token() -> str:
    """Return a new random bearer token, prefixed for secret-scanner identifiability."""
    return f"wrn_{secrets.token_urlsafe(32)}"


def derive_token_pepper(secret_key: str) -> str:
    """Derive the token-hashing pepper from `WARREN_SECRET_KEY` with a fixed context label.

    `secret_key` is a single server-wide secret that other subsystems (e.g. a future
    Fernet-backed secret store) may also derive material from. Using the raw secret_key
    directly as the HMAC pepper here would mean a compromise or reuse of one purpose's
    derived key leaks the other; this single-label HKDF-Expand-style derivation keeps the
    two purposes cryptographically independent even though they share one root secret.
    """
    return hmac.new(secret_key.encode(), _PEPPER_DERIVATION_LABEL, hashlib.sha256).hexdigest()


def hash_token(token: str, pepper: str) -> str:
    """Return the HMAC-SHA256 hex digest of `token`, peppered with the derived token pepper.

    Callers must pass a pepper produced by `derive_token_pepper`, not the raw secret_key.
    """
    return hmac.new(pepper.encode(), token.encode(), hashlib.sha256).hexdigest()


async def resolve_token(store: "AuthStore", token: str, pepper: str) -> "User | None":
    """Resolve a raw bearer token to its owning User, or None if not live.

    Plain function, no container-runtime-backend-specific logic (D-07) — auth and the
    container runtime backend are orthogonal concerns.
    """
    result = await resolve_active_token(store, token, pepper)
    return result[0] if result else None


async def resolve_active_token(
    store: "AuthStore", token: str, pepper: str
) -> "tuple[User, str] | None":
    """Like `resolve_token`, but also returns the resolved token's id.

    Used by AuthMiddleware so route handlers can later read the *calling* token's id off
    the request (see auth/deps.py `current_token_id`) and stamp it as `created_by_token_id`
    provenance on any token they go on to mint (Issue #11).
    """
    if not token:
        return None
    hashed = hash_token(token, pepper)
    return await store.get_active_user_and_token_id_by_hashed_token(hashed)
