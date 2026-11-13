"""User-token scopes (`full`, `ui-read`, `ui-act`), their route allow-lists, and the
parent/child lineage rules.

`full` is the historical behaviour (every route). `ui-read` and `ui-act` are for a browser
UI: they may reach only the (method, route template) pairs named below, enforced in
AuthMiddleware after the token is resolved. A route in none of the three sets is denied to
both ui scopes, and tests/unit/auth/test_scope_routes.py fails until a new route is put in
exactly one of them, so a new route is never silently reachable from a ui token.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Literal, get_args
from urllib.parse import parse_qs

if TYPE_CHECKING:
    from warren.auth.models import Token

TokenScope = Literal["full", "ui-read", "ui-act"]
SCOPES: tuple[str, ...] = get_args(TokenScope)
DEFAULT_SCOPE: TokenScope = "full"

# Breadth: a child may never rank above its parent.
_RANK = {"ui-read": 0, "ui-act": 1, "full": 2}


class TokenLineageViolation(ValueError):
    """A child token would be broader or longer-lived than the token minting it."""


def validate_scope(scope: str) -> None:
    if scope not in _RANK:
        raise ValueError(f"unknown token scope {scope!r}")


def check_child_token(parent: "Token | None", scope: str, expires_at: datetime | None) -> None:
    """Raise TokenLineageViolation unless (scope, expires_at) fits within `parent`.
    A missing parent (purged provenance, bootstrap) constrains nothing."""
    validate_scope(scope)
    if parent is None:
        return
    if _RANK[scope] > _RANK.get(parent.scope, 2):
        raise TokenLineageViolation(f"a {parent.scope} token cannot mint a {scope} token")
    if parent.expires_at is not None and (expires_at is None or expires_at > parent.expires_at):
        raise TokenLineageViolation("a child token cannot outlive its parent")


def child_expiry(parent: "Token | None", default: datetime) -> datetime:
    """The default expiry for a child, clamped to the parent's."""
    if parent is not None and parent.expires_at is not None:
        return min(default, parent.expires_at)
    return default


def default_expiry(now: datetime, ttl_days: float, parent: "Token | None") -> datetime:
    return child_expiry(parent, now + timedelta(days=ttl_days))


# ---------------------------------------------------------------------------
# Route classification (method, route template as registered in FastAPI)
# ---------------------------------------------------------------------------

UI_READ_ROUTES: frozenset[tuple[str, str]] = frozenset({
    ("GET", "/workspaces"),
    ("GET", "/workspaces/{workspace_id}/status"),
    ("GET", "/workspaces/{workspace_id}/refs"),
    ("GET", "/workspaces/{workspace_id}/events"),
    ("GET", "/operations/{operation_id}"),
    ("GET", "/projects"),
    ("GET", "/projects/{name}"),
    ("GET", "/runs"),
    ("GET", "/runs/{run_id}"),
    ("GET", "/runs/{run_id}/result"),
    ("GET", "/secrets"),  # names only
    ("GET", "/notifications/webhook"),
})

UI_ACT_ROUTES: frozenset[tuple[str, str]] = frozenset({
    ("POST", "/workspaces"),
    ("POST", "/workspaces/{workspace_id}/ensure_running"),
    ("POST", "/workspaces/{workspace_id}/git/pull"),
    ("POST", "/workspaces/{workspace_id}/branch"),
    ("DELETE", "/workspaces/{workspace_id}"),
    ("POST", "/runs"),
    ("PUT", "/projects/{name}"),  # user scope only, see _deny_server_wide
    ("DELETE", "/projects/{name}"),
})

# Named so that "not allowed" is a decision, not an omission.
UI_DENIED_ROUTES: frozenset[tuple[str, str]] = frozenset({
    ("POST", "/workspaces/{workspace_id}/exec"),
    ("POST", "/workspaces/{workspace_id}/connect"),
    ("GET", "/workspaces/{workspace_id}/git-credential"),
    ("POST", "/workspaces/{workspace_id}/tokens"),
    ("POST", "/workspace-tokens"),
    ("POST", "/tokens"),
    ("GET", "/tokens"),
    ("DELETE", "/tokens/{token_id}"),
    ("GET", "/mcp"), ("POST", "/mcp"), ("DELETE", "/mcp"),
    ("POST", "/admin/users"),
    ("GET", "/admin/users"),
    ("POST", "/admin/users/{user_id}/tokens"),
    ("GET", "/admin/users/{user_id}/tokens"),
    ("POST", "/admin/users/{user_id}/disable"),
    ("DELETE", "/admin/tokens/{token_id}"),
    ("PUT", "/secrets"),
    ("DELETE", "/secrets/{name}"),
    ("POST", "/secrets/{name}/rotate"),
    ("PUT", "/notifications/webhook"),
    ("DELETE", "/notifications/webhook"),
    ("GET", "/healthz/detail"),
    ("GET", "/peers"),
    ("GET", "/openapi.json"),
    ("GET", "/docs"),
    ("GET", "/docs/oauth2-redirect"),
    ("GET", "/redoc"),
})


def _compile(routes: frozenset[tuple[str, str]]) -> list[tuple[str, re.Pattern[str]]]:
    return [(m, re.compile("^" + re.sub(r"\{[^}/]+\}", "[^/]+", re.escape(p).replace(r"\{", "{").replace(r"\}", "}")) + "$"))
            for m, p in routes]


_READ = _compile(UI_READ_ROUTES)
_ACT = _compile(UI_ACT_ROUTES)


def _matches(table: list[tuple[str, re.Pattern[str]]], method: str, path: str) -> bool:
    return any(m == method and rx.fullmatch(path) for m, rx in table)


def _deny_server_wide(path: str, query: bytes) -> bool:
    """Project writes reach the shared (admin) config when `server_wide` is present in any
    form: a ui token never sends it, so its mere presence is refused."""
    return path.startswith("/projects/") and "server_wide" in parse_qs(query.decode("latin-1"), keep_blank_values=True)


def scope_allows(scope: str, method: str, path: str, query: bytes) -> bool:
    """Whether a token of `scope` may call `method path`. Unknown scopes fail closed."""
    if scope == "full":
        return True
    method = method.upper()
    if scope == "ui-read":
        return _matches(_READ, method, path)
    if scope == "ui-act":
        if _matches(_READ, method, path):
            return True
        return _matches(_ACT, method, path) and not _deny_server_wide(path, query)
    return False
