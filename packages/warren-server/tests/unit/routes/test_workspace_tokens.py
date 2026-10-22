"""AI9: workspace-scoped machine tokens can only act on their own workspace."""

from __future__ import annotations

import base64
import time
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from fastapi.testclient import TestClient

from tests.conftest import TEST_BOOTSTRAP_TOKEN
from warren.app import app
from warren.auth.workspace_tokens import proof_message, scoped_route_allowed
from warren.registry.store import WorkspaceStore

_ADMIN = {"Authorization": f"Bearer {TEST_BOOTSTRAP_TOKEN}"}


@pytest.fixture
def env_defaults(monkeypatch, tmp_path):
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_BOOTSTRAP_TOKEN", TEST_BOOTSTRAP_TOKEN)
    monkeypatch.setenv("WARREN_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("WARREN_PODMAN_SOCKET", str(tmp_path / "podman.sock"))
    monkeypatch.setenv("WARREN_SERVER_ID", "test-server")
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(tmp_path / "projects"))
    monkeypatch.setenv("WARREN_DRY_RUN_SKIP_PREFLIGHT", "1")
    monkeypatch.setenv("WARREN_REAPER_ENABLED", "0")
    yield
    app.state._state.clear()


@contextmanager
def _client():
    registry = MagicMock()
    registry.server_id = "test-server"
    registry.reconcile_from_disk = AsyncMock()
    registry.destroy = AsyncMock()
    with (
        patch("warren.app.WorkspaceRegistry", return_value=registry),
        patch("warren.app.PodmanRuntime"),
        TestClient(app) as client,
    ):
        app.state.registry = registry
        registry.store = WorkspaceStore(app.state.db)
        owner = client.get("/admin/users", headers=_ADMIN).json()[0]["user_id"]
        for ws_id in ("ws-a", "ws-b"):
            client.portal.call(
                lambda ws_id=ws_id: registry.store.insert(
                    workspace_id=ws_id,
                    project="demo",
                    intent="observe",
                    image="img",
                    root_path="",
                    server_instance="test-server",
                    status="running",
                    owner_id=owner,
                )
            )
        yield client, registry


def _mint(client, ws_id="ws-a", **body) -> dict:
    resp = client.post(f"/workspaces/{ws_id}/tokens", json=body, headers=_ADMIN)
    assert resp.status_code == 201, resp.text
    return resp.json()


def _bearer(token: str, **extra) -> dict:
    return {"Authorization": f"Bearer {token}", **extra}


def test_scoped_token_reaches_only_its_own_workspace(env_defaults):
    with _client() as (client, registry):
        minted = _mint(client)
        assert minted["token"].startswith("wrnw_")
        h = _bearer(minted["token"])

        assert client.get("/workspaces/ws-a/status", headers=h).status_code == 200
        assert client.get("/workspaces/ws-b/status", headers=h).status_code == 403
        assert client.delete("/workspaces/ws-b", headers=h).status_code == 403
        registry.destroy.assert_not_called()
        assert client.post("/workspaces", json={"project": "demo", "template": "observe"}, headers=h).status_code == 403
        assert client.get("/workspaces", headers=h).status_code == 403
        assert client.post("/workspaces/ws-a/tokens", json={}, headers=h).status_code == 403
        assert client.post("/workspaces/ws-a/connect", headers=h).status_code == 403
        assert client.get("/secrets", headers=h).status_code == 403
        assert client.post("/tokens", headers=h).status_code == 403


def test_scoped_token_dies_with_its_workspace(env_defaults):
    with _client() as (client, registry):
        h = _bearer(_mint(client)["token"])
        assert client.delete("/workspaces/ws-a", headers=h).status_code == 204
        registry.destroy.assert_awaited_once_with("ws-a")
        assert client.get("/workspaces/ws-a/status", headers=h).status_code == 401


def test_scoped_token_rejected_after_workspace_marked_destroyed(env_defaults):
    with _client() as (client, registry):
        h = _bearer(_mint(client)["token"])
        client.portal.call(lambda: registry.store.update_status("ws-a", "destroyed"))
        assert client.get("/workspaces/ws-a/status", headers=h).status_code == 401


def test_expired_scoped_token_rejected(env_defaults):
    with _client() as (client, _):
        minted = _mint(client)
        client.portal.call(
            lambda: app.state.db.execute(
                "UPDATE workspace_tokens SET expires_at = '2000-01-01T00:00:00+00:00' WHERE token_id = ?",
                (minted["token_id"],),
            )
        )
        assert client.get("/workspaces/ws-a/status", headers=_bearer(minted["token"])).status_code == 401


def test_ttl_is_capped_and_non_owner_cannot_mint(env_defaults):
    with _client() as (client, registry):
        resp = client.post("/workspaces/ws-a/tokens", json={"ttl_seconds": 7200}, headers=_ADMIN)
        assert resp.status_code == 422
        client.portal.call(
            lambda: app.state.db.execute(
                "UPDATE workspaces SET owner_id = 'someone-else' WHERE workspace_id = 'ws-b'"
            )
        )
        assert client.post("/workspaces/ws-b/tokens", json={}, headers=_ADMIN).status_code == 403


def _proof(key: Ed25519PrivateKey, method: str, path: str, ts: int | None = None) -> str:
    ts = int(time.time()) if ts is None else ts
    sig = key.sign(proof_message(ts, method, path))
    return f"{ts}.{base64.urlsafe_b64encode(sig).decode().rstrip('=')}"


def test_key_bound_token_requires_valid_proof(env_defaults):
    key = Ed25519PrivateKey.generate()
    pub = base64.b64encode(
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()
    with _client() as (client, _):
        minted = _mint(client, public_key=pub)
        assert minted["key_bound"] is True
        path = "/workspaces/ws-a/status"
        token = minted["token"]

        assert client.get(path, headers=_bearer(token)).status_code == 401
        good = _proof(key, "GET", path)
        assert client.get(path, headers=_bearer(token, **{"X-Warren-Proof": good})).status_code == 200
        wrong_path = _proof(key, "GET", "/workspaces/ws-a/events")
        assert client.get(path, headers=_bearer(token, **{"X-Warren-Proof": wrong_path})).status_code == 401
        stale = _proof(key, "GET", path, ts=int(time.time()) - 600)
        assert client.get(path, headers=_bearer(token, **{"X-Warren-Proof": stale})).status_code == 401
        other = _proof(Ed25519PrivateKey.generate(), "GET", path)
        assert client.get(path, headers=_bearer(token, **{"X-Warren-Proof": other})).status_code == 401


def test_invalid_public_key_rejected(env_defaults):
    with _client() as (client, _):
        resp = client.post("/workspaces/ws-a/tokens", json={"public_key": "nope"}, headers=_ADMIN)
        assert resp.status_code == 422


@pytest.mark.parametrize(
    ("method", "path", "allowed"),
    [
        ("GET", "/workspaces/A/status", True),
        ("GET", "/workspaces/A/events", True),
        ("DELETE", "/workspaces/A", True),
        ("GET", "/workspaces/A/git-credential", True),
        ("GET", "/workspaces/A/refs", True),
        ("POST", "/workspaces/A/branch", False),
        ("GET", "/workspaces/B/status", False),
        ("POST", "/workspaces/A/tokens", False),
        ("POST", "/workspaces/A/connect", False),
        ("GET", "/workspaces/A/../B/status", False),
        ("POST", "/workspaces", False),
        ("GET", "/secrets", False),
    ],
)
def test_scoped_route_allow_list(method, path, allowed):
    assert scoped_route_allowed(method, path, "A") is allowed


def _token(status: str | None, grant: bool = False):
    from datetime import datetime, timezone

    from warren.auth.models import WorkspaceToken

    now = datetime.now(timezone.utc)
    return WorkspaceToken(
        token_id="t", workspace_id="A", user_id="u", created_at=now, expires_at=now,
        provision_grant=grant, workspace_status=status,
    )


@pytest.mark.parametrize(
    ("status", "grant", "method", "path", "allowed"),
    [
        ("running", False, "POST", "/mcp", True),
        ("running", False, "POST", "/workspaces/A/exec", True),
        ("running", False, "POST", "/workspaces", False),
        (None, True, "POST", "/workspaces", True),
        (None, False, "POST", "/workspaces", False),
        (None, True, "GET", "/workspaces/A/status", False),
        (None, True, "POST", "/mcp", True),
        ("destroyed", False, "GET", "/workspaces/A/events", True),
        ("destroyed", False, "DELETE", "/workspaces/A", True),
        ("destroyed", False, "POST", "/workspaces/A/exec", False),
        ("destroyed", False, "GET", "/workspaces/A/git-credential", False),
    ],
)
def test_scoped_request_allowed(status, grant, method, path, allowed):
    from warren.auth.workspace_tokens import scoped_request_allowed

    assert scoped_request_allowed(method, path, _token(status, grant)) is allowed


def test_key_bound_token_signs_mcp_requests(env_defaults):
    key = Ed25519PrivateKey.generate()
    pub = base64.b64encode(
        key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    ).decode()
    with _client() as (client, _):
        token = _mint(client, public_key=pub)["token"]
        body = {"jsonrpc": "2.0", "id": 1, "method": "tools/list"}
        accept = {"Accept": "application/json, text/event-stream"}
        assert client.post("/mcp", json=body, headers=_bearer(token, **accept)).status_code == 401
        signed = _bearer(token, **accept, **{"X-Warren-Proof": _proof(key, "POST", "/mcp")})
        assert client.post("/mcp", json=body, headers=signed).status_code == 200


def test_reservation_mint_requires_a_user_token(env_defaults):
    with _client() as (client, _):
        resp = client.post("/workspace-tokens", json={"ttl_seconds": 120}, headers=_ADMIN)
        assert resp.status_code == 201
        assert resp.json()["workspace_id"] not in ("ws-a", "ws-b")
        h = _bearer(_mint(client)["token"])
        assert client.post("/workspace-tokens", json={}, headers=h).status_code == 403
        assert client.post("/workspace-tokens", json={"public_key": "nope"}, headers=_ADMIN).status_code == 422


@pytest.mark.asyncio
async def test_provision_grant_column_is_added_to_an_existing_database(tmp_path):
    import aiosqlite

    from warren.registry.store import open_db

    path = tmp_path / "old.db"
    async with aiosqlite.connect(path) as db:
        await db.execute(
            "CREATE TABLE workspace_tokens (token_id TEXT PRIMARY KEY, workspace_id TEXT NOT NULL, "
            "user_id TEXT NOT NULL, hashed_token TEXT NOT NULL UNIQUE, public_key TEXT, "
            "created_at TEXT NOT NULL, expires_at TEXT NOT NULL, revoked_at TEXT, created_by_token_id TEXT)"
        )
        await db.commit()
    db = await open_db(path)
    try:
        async with db.execute("PRAGMA table_info(workspace_tokens)") as cur:
            assert "provision_grant" in {row[1] for row in await cur.fetchall()}
    finally:
        await db.close()
