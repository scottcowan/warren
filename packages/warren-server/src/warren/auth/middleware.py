"""Global auth enforcement gate — AUTH-03 / D-06.

Implemented as a raw ASGI class, not Starlette's convenience buffering middleware base class:
that base class buffers streaming responses by running the downstream app in a separate task and
re-streaming its body through an in-memory channel, which would break
`src/warren/routes/workspaces.py`'s `/workspaces/{id}/events` `StreamingResponse` endpoint (see
RESEARCH.md Pitfall 3). This class instead implements the raw ASGI contract directly and never
wraps `send`, so a downstream streaming response passes straight through, chunk by chunk.

D-06: a global gate (not a per-route `Depends()`) so a new route cannot accidentally ship
unauthenticated. `EXEMPT_PATHS` below is the *only* way to add an unauthenticated route.
Non-`http` scope types other than `lifespan` (e.g. a future `websocket` route) go through the
same bearer-token check rather than passing through untouched, so a new route of any scope
type cannot silently ship without auth.
"""

from __future__ import annotations

import time

import structlog
from warren.auth.tokens import derive_token_pepper, resolve_active_token
from warren.auth.workspace_tokens import (
    PROOF_HEADER,
    is_workspace_token,
    resolve_workspace_token,
    scoped_request_allowed,
    verify_proof,
)
from warren.ratelimit import SlidingWindowRateLimiter

log = structlog.get_logger(__name__)

# Audit 2026-10-16 P2 #46: nothing throttled repeated failed auth. 20 failures per minute
# per client IP is generous for a legitimately misconfigured client (a few retries) while
# still bounding a brute-force/credential-stuffing loop to a low rate.
_FAILED_AUTH_MAX = 20
_FAILED_AUTH_WINDOW_SECONDS = 60.0

# S10: this limiter is deliberately an INSTANCE attribute, not a module-level singleton
# (unlike routes/workspaces.py's `_create_workspace_limiter`) -- tests/unit/auth/
# test_middleware_ratelimit.py relies on each test building a fresh AuthMiddleware
# instance precisely so one test's deliberately-exhausted rate limit can never bleed
# into another via a shared global. That rules out wiring this into a single shared
# background pruner task the way run_idle_reaper-style tasks work (there's no one
# stable instance to hand the task). Instead, pruned lazily but unconditionally over
# time: every _PRUNE_INTERVAL_SECONDS of actual traffic through this instance, prune()
# runs once, piggybacking on a request that was going to run anyway rather than
# spawning a dedicated task per instance.
_PRUNE_INTERVAL_SECONDS = 300.0

_TOO_MANY_REQUESTS_STATUS = 429
_TOO_MANY_REQUESTS_HEADERS: list[tuple[bytes, bytes]] = [(b"content-type", b"application/json")]
_TOO_MANY_REQUESTS_BODY = b'{"detail":"too many failed auth attempts"}'


def _client_ip(scope: dict) -> str:
    client = scope.get("client")
    return client[0] if client else "unknown"

# Explicit allowlist, module-level. Adding a path here is the ONLY way to ship an
# unauthenticated route (D-06). Deliberately does NOT include the API docs endpoints or /peers —
# peer discovery is a privileged surface, not a public health check.
EXEMPT_PATHS: frozenset[str] = frozenset({"/_status", "/healthz"})

_UNAUTHORIZED_STATUS = 401
_UNAUTHORIZED_HEADERS: list[tuple[bytes, bytes]] = [(b"content-type", b"application/json")]
_UNAUTHORIZED_BODY = b'{"detail":"unauthorized"}'
_OUT_OF_SCOPE_BODY = b'{"detail":"workspace-scoped token cannot access this resource"}'


def _header(scope: dict, name: bytes) -> str | None:
    for key, value in scope.get("headers", []):
        if key == name:
            return value.decode("latin-1")
    return None


def _extract_bearer_token(scope: dict) -> str | None:
    """Return the bearer credential from scope["headers"], or None if absent/malformed.

    scope["headers"] is a list of (lowercase-name, value) byte-string pairs per the ASGI spec.
    """
    for name, value in scope.get("headers", []):
        if name == b"authorization":
            scheme, _, credential = value.decode("latin-1").partition(" ")
            if scheme.lower() != "bearer" or not credential:
                return None
            return credential
    return None


class AuthMiddleware:
    """Pure-ASGI class — intentionally not built on Starlette's convenience middleware base
    class. See module docstring for why."""

    def __init__(self, app) -> None:
        self.app = app
        self._failed_auth_limiter = SlidingWindowRateLimiter(
            max_events=_FAILED_AUTH_MAX, window_seconds=_FAILED_AUTH_WINDOW_SECONDS
        )
        self._last_prune_at = time.monotonic()

    async def __call__(self, scope, receive, send) -> None:
        scope_type = scope["type"]
        if scope_type == "lifespan":
            # Not a request; nothing to authenticate.
            await self.app(scope, receive, send)
            return
        if scope_type == "http" and scope["path"] in EXEMPT_PATHS:
            await self.app(scope, receive, send)
            return
        if scope_type not in ("http", "websocket"):
            # Unknown/future ASGI scope type — fail closed rather than silently pass through
            # (D-06: EXEMPT_PATHS is the only sanctioned way to skip auth).
            log.error("auth_middleware_unsupported_scope", scope_type=scope_type)
            await self._deny(scope, send, reason="unsupported_scope")
            return

        token = _extract_bearer_token(scope)
        if token is None:
            await self._deny_or_throttle(scope, send, reason="missing_or_malformed_bearer")
            return

        app_state = getattr(scope.get("app"), "state", None)
        auth_store = getattr(app_state, "auth_store", None)
        settings = getattr(app_state, "settings", None)
        if auth_store is None or settings is None:
            # Fail closed: a mis-wired startup must never silently disable auth (T-02-09).
            log.error("auth_middleware_misconfigured", path=scope["path"])
            await self._deny(scope, send, reason="auth_not_configured")
            return

        pepper = derive_token_pepper(settings.secret_key.get_secret_value())
        if is_workspace_token(token):
            await self._handle_workspace_token(scope, receive, send, auth_store, token, pepper)
            return
        resolved = await resolve_active_token(auth_store, token, pepper)
        if resolved is None:
            await self._deny_or_throttle(scope, send, reason="invalid_or_inactive_token")
            return
        user, token_id = resolved

        scope["state"] = {**scope.get("state", {}), "user": user, "token_id": token_id}
        await self.app(scope, receive, send)

    async def _handle_workspace_token(self, scope, receive, send, auth_store, token, pepper) -> None:
        """AI9: resolve a workspace-scoped token, check its key binding, and only
        let it through to its own workspace's allow-listed routes."""
        resolved = await resolve_workspace_token(auth_store, token, pepper)
        if resolved is None:
            await self._deny_or_throttle(scope, send, reason="invalid_or_inactive_workspace_token")
            return
        user, ws_token = resolved
        method = scope.get("method", "GET")
        if ws_token.public_key is not None and not verify_proof(
            ws_token.public_key, _header(scope, PROOF_HEADER), method, scope["path"]
        ):
            await self._deny_or_throttle(scope, send, reason="workspace_token_proof_invalid")
            return
        if not scoped_request_allowed(method, scope["path"], ws_token):
            log.warning(
                "workspace_token_out_of_scope",
                path=scope.get("path"),
                token_id=ws_token.token_id,
                workspace_id=ws_token.workspace_id,
            )
            await self._forbid(scope, send)
            return
        scope["state"] = {
            **scope.get("state", {}),
            "user": user,
            "token_id": ws_token.token_id,
            "workspace_scope": ws_token.workspace_id,
            "workspace_token": ws_token,
        }
        await self.app(scope, receive, send)

    @staticmethod
    async def _forbid(scope: dict, send) -> None:
        if scope.get("type") == "websocket":
            await send({"type": "websocket.close", "code": 4403})
            return
        await send(
            {"type": "http.response.start", "status": 403, "headers": _UNAUTHORIZED_HEADERS}
        )
        await send({"type": "http.response.body", "body": _OUT_OF_SCOPE_BODY})

    async def _deny_or_throttle(self, scope: dict, send, *, reason: str) -> None:
        """Like `_deny`, but first checks the per-IP failed-auth rate limit (audit #46) --
        a client that's already over the threshold gets 429 instead of 401, independent
        of whether this particular attempt would otherwise have succeeded or failed."""
        # S10: opportunistic prune -- see _PRUNE_INTERVAL_SECONDS above for why this
        # isn't a dedicated background task. Runs at most once per interval regardless
        # of request volume (checked before doing any pruning work).
        now = time.monotonic()
        if now - self._last_prune_at > _PRUNE_INTERVAL_SECONDS:
            self._failed_auth_limiter.prune(now)
            self._last_prune_at = now

        ip = _client_ip(scope)
        if not self._failed_auth_limiter.allow(ip):
            log.warning("auth_rate_limited", path=scope.get("path"), client_ip=ip)
            if scope.get("type") == "websocket":
                await send({"type": "websocket.close", "code": 4429})
                return
            await send(
                {
                    "type": "http.response.start",
                    "status": _TOO_MANY_REQUESTS_STATUS,
                    "headers": _TOO_MANY_REQUESTS_HEADERS,
                }
            )
            await send({"type": "http.response.body", "body": _TOO_MANY_REQUESTS_BODY})
            return
        await self._deny(scope, send, reason=reason)

    @staticmethod
    async def _deny(scope: dict, send, *, reason: str) -> None:
        # Static reason string only — never the presented token, its hash, or a per-user detail.
        log.info("auth_denied", path=scope.get("path"), reason=reason, scope_type=scope.get("type"))
        if scope.get("type") == "websocket":
            # ASGI websocket protocol has no http.response.* messages; refuse the handshake.
            await send({"type": "websocket.close", "code": 4401})
            return
        await send(
            {
                "type": "http.response.start",
                "status": _UNAUTHORIZED_STATUS,
                "headers": _UNAUTHORIZED_HEADERS,
            }
        )
        await send({"type": "http.response.body", "body": _UNAUTHORIZED_BODY})
