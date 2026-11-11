"""Route classification for token scopes: every route of the real app must be explicitly
classified, so a new route is denied to ui-* scopes until someone decides where it goes."""

from __future__ import annotations

from warren.app import app
from warren.auth.scopes import UI_ACT_ROUTES, UI_DENIED_ROUTES, UI_READ_ROUTES, scope_allows


def _app_routes() -> set[tuple[str, str]]:
    found: set[tuple[str, str]] = set()
    for r in app.routes:
        if hasattr(r, "original_router"):
            prefix = r.include_context.prefix
            subs = [(prefix + s.path, s) for s in r.original_router.routes]
        else:
            subs = [(r.path, r)]
        for path, s in subs:
            for m in getattr(s, "methods", None) or ():
                if m != "HEAD":
                    found.add((m, path))
    return found


def test_every_route_is_classified():
    classified = UI_READ_ROUTES | UI_ACT_ROUTES | UI_DENIED_ROUTES
    exempt = {("GET", "/_status"), ("GET", "/healthz")}  # before auth, never scoped
    missing = _app_routes() - classified - exempt
    assert not missing, f"unclassified routes (add to auth/scopes.py): {sorted(missing)}"


def test_classification_has_no_stale_or_overlapping_entries():
    routes = _app_routes()
    classified = UI_READ_ROUTES | UI_ACT_ROUTES | UI_DENIED_ROUTES
    assert not classified - routes, f"entries without a route: {sorted(classified - routes)}"
    assert not (UI_READ_ROUTES & UI_ACT_ROUTES)
    assert not (UI_READ_ROUTES & UI_DENIED_ROUTES)
    assert not (UI_ACT_ROUTES & UI_DENIED_ROUTES)


def test_read_routes_are_get_only():
    assert all(m == "GET" for m, _ in UI_READ_ROUTES)


def test_dangerous_routes_are_denied_to_ui():
    for m, p in [
        ("POST", "/workspaces/{workspace_id}/exec"), ("POST", "/workspaces/{workspace_id}/connect"),
        ("GET", "/workspaces/{workspace_id}/git-credential"), ("POST", "/tokens"),
        ("POST", "/workspace-tokens"), ("POST", "/workspaces/{workspace_id}/tokens"),
        ("GET", "/mcp"), ("POST", "/mcp"), ("DELETE", "/mcp"), ("GET", "/admin/users"),
        ("PUT", "/secrets"), ("POST", "/secrets/{name}/rotate"),
    ]:
        assert (m, p) in UI_DENIED_ROUTES, (m, p)


def test_scope_allows_matrix():
    q = b""
    assert scope_allows("full", "DELETE", "/admin/tokens/x", q)
    assert scope_allows("ui-read", "GET", "/workspaces", q)
    assert scope_allows("ui-read", "GET", "/workspaces/abc/status", q)
    assert not scope_allows("ui-read", "POST", "/workspaces", q)
    assert not scope_allows("ui-read", "GET", "/workspaces/abc/git-credential", q)
    assert not scope_allows("ui-read", "GET", "/tokens", q)
    assert scope_allows("ui-act", "GET", "/runs", q)
    assert scope_allows("ui-act", "POST", "/workspaces", q)
    assert scope_allows("ui-act", "DELETE", "/workspaces/abc", q)
    assert not scope_allows("ui-act", "POST", "/workspaces/abc/exec", q)
    assert not scope_allows("ui-act", "POST", "/tokens", q)
    assert not scope_allows("ui-act", "GET", "/mcp", q)
    assert not scope_allows("ui-act", "GET", "/nonexistent", q)
    assert not scope_allows("bogus", "GET", "/workspaces", q)  # unknown scope fails closed


def test_path_tricks_do_not_widen():
    q = b""
    assert not scope_allows("ui-read", "GET", "/workspaces/abc/status/../exec", q)
    assert not scope_allows("ui-read", "GET", "/workspaces/a/b/status", q)
    assert not scope_allows("ui-read", "GET", "//workspaces", q)


def test_server_wide_project_writes_denied_to_ui_act():
    assert scope_allows("ui-act", "PUT", "/projects/p", b"")
    assert scope_allows("ui-act", "DELETE", "/projects/p", b"")
    assert not scope_allows("ui-act", "PUT", "/projects/p", b"server_wide=true")
    assert not scope_allows("ui-act", "PUT", "/projects/p", b"expected_version=x&server_wide=1")
    assert not scope_allows("ui-act", "PUT", "/projects/p", b"server_wide=false")  # fail closed on presence
