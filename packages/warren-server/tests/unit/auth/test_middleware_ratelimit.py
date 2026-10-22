"""AuthMiddleware failed-auth rate limiting — audit 2026-10-16 P2 #46.

Uses a throwaway Starlette app with a FRESH AuthMiddleware instance (not the real
`warren.app.app` singleton) so this test's deliberately-exhausted rate limit can
never bleed into other test files sharing that singleton's cached middleware stack.
"""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from warren.auth.middleware import AuthMiddleware, _FAILED_AUTH_MAX


async def _ok(request):
    return PlainTextResponse("ok")


def _make_app() -> Starlette:
    app = Starlette(routes=[Route("/thing", _ok)])
    app.add_middleware(AuthMiddleware)
    return app


def test_missing_token_401s_under_threshold():
    client = TestClient(_make_app())
    resp = client.get("/thing")
    assert resp.status_code == 401


def test_repeated_missing_token_throttles_to_429_past_threshold():
    client = TestClient(_make_app())
    for _ in range(_FAILED_AUTH_MAX):
        resp = client.get("/thing")
        assert resp.status_code == 401

    resp = client.get("/thing")
    assert resp.status_code == 429


def test_rate_limit_is_per_client_ip():
    """A different client IP hitting the SAME app/middleware instance must not be
    throttled by another IP's failures."""
    app = _make_app()
    client = TestClient(app, client=("203.0.113.1", 12345))
    for _ in range(_FAILED_AUTH_MAX):
        client.get("/thing")

    throttled = client.get("/thing")
    assert throttled.status_code == 429

    other_client = TestClient(app, client=("203.0.113.5", 12345))
    resp = other_client.get("/thing")
    assert resp.status_code == 401
