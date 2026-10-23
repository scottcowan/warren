"""Shared-secret auth for every sidecar route except /healthz.

The sidecar listens on a `/tmp` AF_UNIX socket running as root with no other
access control, so anything able to reach that socket — including, on prod
hosts where /tmp ends up shared, processes outside the workspace container —
could otherwise read files, diffs, events or run commands. Every request must
carry the per-workspace token issued at provision time via the
`X-Warren-Sidecar-Token` header. Enforced as ASGI middleware so a new route is
protected by default (audit finding 12: /diff and /events were added without
the per-router dependency).
"""

from __future__ import annotations

import hmac
import json

TOKEN_HEADER = "X-Warren-Sidecar-Token"
OPEN_PATHS = frozenset({"/healthz"})

_TOKEN_HEADER_BYTES = TOKEN_HEADER.lower().encode()


def token_valid(expected: str, provided: str) -> bool:
    """Fails CLOSED: an unconfigured token (`""`) never matches anything."""
    return bool(expected) and hmac.compare_digest(provided.encode(), expected.encode())


class SidecarTokenMiddleware:
    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] not in ("http", "websocket") or scope["path"] in OPEN_PATHS:
            await self.app(scope, receive, send)
            return
        settings = getattr(scope["app"].state, "settings", None)
        expected = settings.sidecar_token if settings is not None else ""
        provided = ""
        for name, value in scope.get("headers", ()):
            if name == _TOKEN_HEADER_BYTES:
                provided = value.decode("latin-1")
                break
        if token_valid(expected, provided):
            await self.app(scope, receive, send)
            return
        if scope["type"] == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        body = json.dumps({"detail": "missing or invalid sidecar token"}).encode()
        await send({
            "type": "http.response.start",
            "status": 401,
            "headers": [
                (b"content-type", b"application/json"),
                (b"content-length", str(len(body)).encode()),
            ],
        })
        await send({"type": "http.response.body", "body": body})
