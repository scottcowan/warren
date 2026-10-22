"""Request body size cap — audit 2026-10-16 P2 #46.

Nothing bounded the size of a request body before this: `/secrets`, `/projects/{name}`,
and friends all read the full body into memory (`request.body()`, FastAPI's own
pydantic-model parsing) with no limit, so an oversized POST/PUT is a cheap way to make
this single-process server allocate arbitrarily large buffers.

Implemented as a raw ASGI class (same reasoning as `auth/middleware.py`'s AuthMiddleware):
wrapping only `receive`, never `send`, so a downstream streaming *response* (the
`/workspaces/{id}/events` NDJSON stream) is completely unaffected -- this middleware only
ever cares about bytes coming IN.
"""

from __future__ import annotations

import structlog

log = structlog.get_logger(__name__)

# A few hundred KB is plenty for a secret value, a project YAML, or a provision request --
# all of this app's write bodies are short, human-authored config/credential blobs, never
# bulk data uploads.
DEFAULT_MAX_BODY_BYTES = 256 * 1024

_PAYLOAD_TOO_LARGE_STATUS = 413
_PAYLOAD_TOO_LARGE_HEADERS: list[tuple[bytes, bytes]] = [(b"content-type", b"application/json")]
_PAYLOAD_TOO_LARGE_BODY = b'{"detail":"request body too large"}'


class BodySizeLimitMiddleware:
    """Pure-ASGI class -- see module docstring for why."""

    def __init__(self, app, *, max_body_bytes: int = DEFAULT_MAX_BODY_BYTES) -> None:
        self.app = app
        self.max_body_bytes = max_body_bytes

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_length = None
        for name, value in scope.get("headers", []):
            if name == b"content-length":
                try:
                    content_length = int(value)
                except ValueError:
                    content_length = None
                break

        if content_length is not None and content_length > self.max_body_bytes:
            await self._reject(scope, send)
            return

        seen = 0

        async def limited_receive():
            nonlocal seen
            message = await receive()
            if message["type"] == "http.request":
                seen += len(message.get("body", b""))
                if seen > self.max_body_bytes:
                    raise _BodyTooLarge()
            return message

        try:
            await self.app(scope, limited_receive, send)
        except _BodyTooLarge:
            await self._reject(scope, send)

    @staticmethod
    async def _reject(scope: dict, send) -> None:
        log.info("request_body_too_large", path=scope.get("path"))
        await send(
            {
                "type": "http.response.start",
                "status": _PAYLOAD_TOO_LARGE_STATUS,
                "headers": _PAYLOAD_TOO_LARGE_HEADERS,
            }
        )
        await send({"type": "http.response.body", "body": _PAYLOAD_TOO_LARGE_BODY})


class _BodyTooLarge(Exception):
    """Internal signal only -- never escapes this module."""
