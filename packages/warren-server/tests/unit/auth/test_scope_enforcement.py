"""AuthMiddleware enforces ui-read / ui-act token scopes after token resolution, and the
token API mints, lists and revokes scoped tokens and lineages."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from warren.auth.middleware import AuthMiddleware
from warren.auth.store import AuthStore
from warren.auth.tokens import derive_token_pepper, generate_token, hash_token
from warren.routes import tokens as token_routes

SECRET = "scope-test-secret"
PEPPER = derive_token_pepper(SECRET)


class _Secret:
    def get_secret_value(self) -> str:
        return SECRET


def _settings(**kw):
    return SimpleNamespace(secret_key=_Secret(), token_ttl_days=90, max_tokens_per_user=50, **kw)


@pytest.fixture
async def store(sqlite_path):
    s = await AuthStore.open(sqlite_path)
    yield s
    await s.close()


@pytest.fixture
def app(store):
    app = FastAPI()
    app.add_middleware(AuthMiddleware)
    app.include_router(token_routes.router)

    @app.get("/workspaces")
    async def _list() -> dict:
        return {"ok": True}

    @app.post("/workspaces")
    async def _create() -> dict:
        return {"ok": True}

    @app.post("/workspaces/{wid}/exec")
    async def _exec(wid: str) -> dict:
        return {"ok": True}

    @app.put("/projects/{name}")
    async def _put(name: str, request: Request) -> dict:
        return {"ok": True}

    app.state.auth_store = store
    app.state.settings = _settings()
    return app


@pytest.fixture
def client(app):
    return TestClient(app)


async def _token(store, user, scope="full", **kw) -> str:
    raw = generate_token()
    await store.create_token(user_id=user.user_id, hashed_token=hash_token(raw, PEPPER), scope=scope, **kw)
    return raw


def _h(raw):
    return {"Authorization": f"Bearer {raw}"}


@pytest.fixture
async def alice(store):
    return await store.create_user(username="alice", is_admin=False)


@pytest.mark.asyncio
async def test_full_scope_unaffected(client, store, alice):
    raw = await _token(store, alice)
    assert client.post("/workspaces/w/exec", headers=_h(raw)).status_code == 200


@pytest.mark.asyncio
async def test_ui_read_gets_only_allowlisted_reads(client, store, alice):
    h = _h(await _token(store, alice, "ui-read"))
    assert client.get("/workspaces", headers=h).status_code == 200
    for method, path in [("POST", "/workspaces"), ("POST", "/workspaces/w/exec"), ("GET", "/tokens"),
                         ("POST", "/tokens"), ("GET", "/nonexistent")]:
        r = client.request(method, path, headers=h)
        assert r.status_code == 403, (method, path)


@pytest.mark.asyncio
async def test_ui_act_adds_named_mutations_but_not_exec_or_tokens(client, store, alice):
    h = _h(await _token(store, alice, "ui-act"))
    assert client.get("/workspaces", headers=h).status_code == 200
    assert client.post("/workspaces", headers=h).status_code == 200
    assert client.put("/projects/p", headers=h).status_code == 200
    assert client.put("/projects/p?server_wide=true", headers=h).status_code == 403
    assert client.post("/workspaces/w/exec", headers=h).status_code == 403
    assert client.post("/tokens", headers=h).status_code == 403


@pytest.mark.asyncio
async def test_denied_scope_does_not_hide_invalid_token(client):
    assert client.get("/workspaces", headers=_h("wrn_bogus")).status_code == 401


@pytest.mark.asyncio
async def test_legacy_sqlite_tokens_table_migrates_to_full(sqlite_path):
    db = sqlite3.connect(sqlite_path)
    db.executescript(
        "CREATE TABLE users (user_id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, is_admin INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL, disabled_at TEXT);"
        "CREATE TABLE tokens (token_id TEXT PRIMARY KEY, user_id TEXT NOT NULL, hashed_token TEXT NOT NULL UNIQUE, created_at TEXT NOT NULL, expires_at TEXT, revoked_at TEXT, created_by_token_id TEXT);"
        "INSERT INTO users VALUES ('u1','old',0,'2026-01-01T00:00:00+00:00',NULL);"
        "INSERT INTO tokens VALUES ('t1','u1','hh','2026-01-01T00:00:00+00:00',NULL,NULL,NULL);"
    )
    db.commit()
    db.close()
    s = await AuthStore.open(sqlite_path)
    try:
        assert (await s.get_token("t1")).scope == "full"
    finally:
        await s.close()


@pytest.mark.asyncio
async def test_mint_with_scope_and_inherit_limits(client, store, alice):
    full = _h(await _token(store, alice))
    r = client.post("/tokens", headers=full, json={"scope": "ui-read"})
    assert r.status_code == 201 and r.json()["scope"] == "ui-read"
    # No body still mints a full token (backwards compatible).
    r = client.post("/tokens", headers=full)
    assert r.status_code == 201 and r.json()["scope"] == "full"
    assert client.post("/tokens", headers=full, json={"scope": "root"}).status_code == 422
    listed = client.get("/tokens", headers=full).json()
    assert {t["scope"] for t in listed} == {"full", "ui-read"}


@pytest.mark.asyncio
async def test_child_default_expiry_is_clamped_to_parent(client, store, alice):
    exp = datetime.now(timezone.utc) + timedelta(days=2)
    parent = _h(await _token(store, alice, expires_at=exp))
    r = client.post("/tokens", headers=parent, json={"scope": "ui-act"})
    assert r.status_code == 201
    assert datetime.fromisoformat(r.json()["expires_at"]) <= exp


@pytest.mark.asyncio
async def test_deleting_a_token_revokes_its_descendants(client, store, alice):
    root_raw = await _token(store, alice)
    root = _h(root_raw)
    child = client.post("/tokens", headers=root, json={"scope": "ui-act"}).json()
    other = client.post("/tokens", headers=root).json()
    # Mint a grandchild from the (full) child so it descends from `other`.
    grand = client.post("/tokens", headers=_h(other["token"])).json()
    assert client.delete(f"/tokens/{other['token_id']}", headers=root).status_code == 204
    assert client.get("/workspaces", headers=_h(grand["token"])).status_code == 401
    assert client.get("/workspaces", headers=_h(other["token"])).status_code == 401
    assert client.get("/workspaces", headers=_h(child["token"])).status_code == 200
    assert client.get("/workspaces", headers=root).status_code == 200
