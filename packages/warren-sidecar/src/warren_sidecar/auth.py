"""Shared-secret auth dependency for /files and /exec (audit 2026-10-16 P2 #47).

The sidecar listens on a `/tmp` AF_UNIX socket running as root with no other
access control, so anything able to reach that socket — including, on prod
hosts where /tmp ends up shared, processes outside the workspace container —
could otherwise read arbitrary files or run arbitrary commands. Every
request to a protected route must carry the per-workspace token issued at
provision time via the `X-Warren-Sidecar-Token` header.
"""

from __future__ import annotations

import hmac

from fastapi import HTTPException, Request

TOKEN_HEADER = "X-Warren-Sidecar-Token"


def require_sidecar_token(request: Request) -> None:
    """FastAPI dependency: 401 unless the request's token header matches.

    Fails CLOSED: a sidecar started with no `WARREN_SIDECAR_TOKEN` configured
    (`settings.sidecar_token == ""`) rejects every request rather than
    treating an unconfigured token as "auth disabled".
    """
    settings = request.app.state.settings
    expected = settings.sidecar_token
    provided = request.headers.get(TOKEN_HEADER, "")
    if not expected or not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="missing or invalid sidecar token")
