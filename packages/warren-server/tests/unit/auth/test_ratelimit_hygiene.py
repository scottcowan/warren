"""Failed-auth limiter keyed by IP+token prefix; per-token budget helpers; security headers."""

from __future__ import annotations

from warren.auth.middleware import (
    _FAILED_AUTH_MAX,
    _SECURITY_HEADERS,
    _budgeted_route,
    _failed_auth_key,
)


def _scope(token: str) -> dict:
    return {"client": ("127.0.0.1", 1), "headers": [(b"authorization", f"Bearer {token}".encode())]}


def test_failed_auth_key_separates_tokens_on_shared_ip():
    assert _failed_auth_key(_scope("aaaaaaaa-1")) != _failed_auth_key(_scope("bbbbbbbb-1"))
    assert _failed_auth_key(_scope("aaaaaaaa-1")) == _failed_auth_key(_scope("aaaaaaaa-2"))
    assert "aaaaaaaa-1" not in _failed_auth_key(_scope("aaaaaaaa-1"))


def test_one_bad_token_does_not_exhaust_another_bucket():
    from warren.ratelimit import SlidingWindowRateLimiter

    lim = SlidingWindowRateLimiter(max_events=_FAILED_AUTH_MAX, window_seconds=60)
    for _ in range(_FAILED_AUTH_MAX):
        assert lim.allow(_failed_auth_key(_scope("aaaaaaaaXXXX")))
    assert not lim.allow(_failed_auth_key(_scope("aaaaaaaaXXXX")))
    assert lim.allow(_failed_auth_key(_scope("bbbbbbbbYYYY")))


def test_budgeted_routes():
    assert _budgeted_route("GET", "/workspaces")
    assert _budgeted_route("GET", "/workspaces/w1/git-credential")
    assert _budgeted_route("POST", "/runs")
    assert not _budgeted_route("GET", "/workspaces/w1")
    assert not _budgeted_route("GET", "/runs")


def test_security_headers_defined():
    names = {n for n, _ in _SECURITY_HEADERS}
    assert names == {b"x-content-type-options", b"cache-control", b"referrer-policy"}
