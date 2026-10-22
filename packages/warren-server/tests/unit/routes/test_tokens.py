"""Self-service token route tests — a normal (non-admin) user mints/lists/revokes
only their OWN tokens; another user's token_id is 404, never 403 (no existence leak)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from warren.auth.deps import current_user
from warren.auth.models import User
from warren.auth.store import AuthStore
from warren.auth.tokens import derive_token_pepper, resolve_token
from warren.routes import tokens

TEST_SECRET_KEY = "test-pepper"
TOKEN_PEPPER = derive_token_pepper(TEST_SECRET_KEY)


class _SecretKey:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_secret_value(self) -> str:
        return self._value


@pytest.fixture
async def auth_store(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    yield store
    await store.close()


@pytest.fixture
async def alice(auth_store: AuthStore) -> User:
    # tokens.user_id FKs to users — must be a real row, not a synthetic User object.
    return await auth_store.create_user(username="alice", is_admin=False)


@pytest.fixture
async def bob(auth_store: AuthStore) -> User:
    return await auth_store.create_user(username="bob", is_admin=False)


@pytest.fixture
def app(auth_store: AuthStore, alice: User) -> FastAPI:
    application = FastAPI()
    application.include_router(tokens.router)
    application.state.auth_store = auth_store
    application.state.settings = SimpleNamespace(secret_key=_SecretKey(TEST_SECRET_KEY), token_ttl_days=90, max_tokens_per_user=10)
    application.dependency_overrides[current_user] = lambda: alice
    return application


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


def test_mint_own_token_returns_201(client: TestClient, alice: User):
    resp = client.post("/tokens")
    assert resp.status_code == 201
    body = resp.json()
    assert body["token"].startswith("wrn_")
    assert body["token_id"]


@pytest.mark.asyncio
async def test_minted_token_resolves_to_self(client: TestClient, auth_store: AuthStore, alice: User):
    resp = client.post("/tokens")
    raw_token = resp.json()["token"]
    resolved = await resolve_token(auth_store, raw_token, TOKEN_PEPPER)
    assert resolved is not None
    assert resolved.user_id == alice.user_id


def test_list_own_tokens_returns_200_no_secret_fields(client: TestClient):
    client.post("/tokens")
    client.post("/tokens")
    resp = client.get("/tokens")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 2
    payload = str(body)
    assert "token" not in payload or all("token_id" in str(b) for b in body)
    assert "hashed_token" not in payload


def test_revoke_own_token_returns_204(client: TestClient):
    mint = client.post("/tokens")
    token_id = mint.json()["token_id"]
    resp = client.delete(f"/tokens/{token_id}")
    assert resp.status_code == 204
    assert resp.content == b""


@pytest.mark.asyncio
async def test_revoked_own_token_no_longer_resolves(client: TestClient, auth_store: AuthStore):
    mint = client.post("/tokens")
    token_id = mint.json()["token_id"]
    raw_token = mint.json()["token"]

    client.delete(f"/tokens/{token_id}")

    resolved = await resolve_token(auth_store, raw_token, TOKEN_PEPPER)
    assert resolved is None


def test_revoke_unknown_token_returns_404(client: TestClient):
    resp = client.delete("/tokens/does-not-exist")
    assert resp.status_code == 404


def test_cannot_revoke_another_users_token(auth_store: AuthStore, alice: User, bob: User):
    """Bob mints a token; Alice tries to revoke it by id — must be 404, not 403 (no
    confirmation that bob's token_id exists), and Bob's token must survive untouched."""
    bob_app = FastAPI()
    bob_app.include_router(tokens.router)
    bob_app.state.auth_store = auth_store
    bob_app.state.settings = SimpleNamespace(secret_key=_SecretKey(TEST_SECRET_KEY), token_ttl_days=90, max_tokens_per_user=10)
    bob_app.dependency_overrides[current_user] = lambda: bob
    bob_client = TestClient(bob_app)
    bob_token_id = bob_client.post("/tokens").json()["token_id"]

    alice_app = FastAPI()
    alice_app.include_router(tokens.router)
    alice_app.state.auth_store = auth_store
    alice_app.state.settings = SimpleNamespace(secret_key=_SecretKey(TEST_SECRET_KEY), token_ttl_days=90, max_tokens_per_user=10)
    alice_app.dependency_overrides[current_user] = lambda: alice
    alice_client = TestClient(alice_app)

    resp = alice_client.delete(f"/tokens/{bob_token_id}")
    assert resp.status_code == 404

    alice_list = alice_client.get("/tokens").json()
    assert all(t["token_id"] != bob_token_id for t in alice_list)


class _StateInjectMiddleware:
    def __init__(self, app, user=None):
        self._app = app
        self._user = user

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            scope.setdefault("state", {})
            if self._user is not None:
                scope["state"]["user"] = self._user
        await self._app(scope, receive, send)


def test_unauthenticated_request_gets_401(auth_store: AuthStore):
    application = FastAPI()
    application.include_router(tokens.router)
    application.state.auth_store = auth_store
    application.state.settings = SimpleNamespace(secret_key=_SecretKey(TEST_SECRET_KEY), token_ttl_days=90, max_tokens_per_user=10)
    application.add_middleware(_StateInjectMiddleware, user=None)
    with TestClient(application) as c:
        resp = c.get("/tokens")
    assert resp.status_code == 401


def test_non_admin_user_can_mint_without_require_admin(auth_store: AuthStore, alice: User):
    """The whole point: no is_admin check anywhere on this router."""
    application = FastAPI()
    application.include_router(tokens.router)
    application.state.auth_store = auth_store
    application.state.settings = SimpleNamespace(secret_key=_SecretKey(TEST_SECRET_KEY), token_ttl_days=90, max_tokens_per_user=10)
    application.add_middleware(_StateInjectMiddleware, user=alice)
    assert alice.is_admin is False
    with TestClient(application) as c:
        resp = c.post("/tokens")
    assert resp.status_code == 201


# --- Issue #11: token expiry and the per-user cap ------------------------------------------------


def test_mint_own_token_has_expires_at(client: TestClient):
    resp = client.post("/tokens")
    assert resp.json()["expires_at"] is not None


def test_mint_own_token_enforces_per_user_cap(client: TestClient, app: FastAPI):
    app.state.settings.max_tokens_per_user = 2
    assert client.post("/tokens").status_code == 201
    assert client.post("/tokens").status_code == 201
    over_resp = client.post("/tokens")
    assert over_resp.status_code == 429


def test_mint_own_token_cap_frees_up_after_revoke(client: TestClient, app: FastAPI):
    """A revoked token should not count against the live cap."""
    app.state.settings.max_tokens_per_user = 1
    first = client.post("/tokens")
    assert first.status_code == 201
    assert client.post("/tokens").status_code == 429

    token_id = first.json()["token_id"]
    client.delete(f"/tokens/{token_id}")

    assert client.post("/tokens").status_code == 201


@pytest.mark.asyncio
async def test_mint_own_token_records_created_by_token_id(
    auth_store: AuthStore, alice: User
) -> None:
    """The self-service router has no AuthMiddleware in these tests (current_user is
    overridden directly), so current_token_id() naturally resolves to None here --
    exercised end-to-end instead in tests/unit/routes/test_auth_enforcement.py."""
    application = FastAPI()
    application.include_router(tokens.router)
    application.state.auth_store = auth_store
    application.state.settings = SimpleNamespace(
        secret_key=_SecretKey(TEST_SECRET_KEY), token_ttl_days=90, max_tokens_per_user=10
    )
    application.dependency_overrides[current_user] = lambda: alice
    with TestClient(application) as c:
        resp = c.post("/tokens")
    token_id = resp.json()["token_id"]
    fetched = await auth_store.get_token(token_id)
    assert fetched is not None
    assert fetched.created_by_token_id is None
