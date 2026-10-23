"""Admin route tests — AUTH-02 (create user + mint token, mint extra, list, revoke)."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from warren.auth.deps import require_admin
from warren.auth.models import User
from warren.auth.store import AuthStore
from warren.auth.tokens import derive_token_pepper, resolve_token
from warren.routes import admin

TEST_SECRET_KEY = "test-pepper"
"""The raw settings.secret_key value used across this file's app fixtures."""

TOKEN_PEPPER = derive_token_pepper(TEST_SECRET_KEY)
"""What the admin routes actually hash with; use this (not TEST_SECRET_KEY) in resolve_token()."""


class _SecretKey:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_secret_value(self) -> str:
        return self._value


@pytest.fixture
def admin_user() -> User:
    from datetime import datetime, timezone

    return User(
        user_id="admin-1",
        username="root",
        is_admin=True,
        created_at=datetime.now(timezone.utc),
    )


@pytest.fixture
async def auth_store(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    yield store
    await store.close()


@pytest.fixture
def app(auth_store: AuthStore, admin_user: User) -> FastAPI:
    application = FastAPI()
    application.include_router(admin.router)
    application.state.auth_store = auth_store
    application.state.settings = SimpleNamespace(secret_key=_SecretKey("test-pepper"), token_ttl_days=90, max_tokens_per_user=10)
    application.dependency_overrides[require_admin] = lambda: admin_user
    return application


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


# --- Task 1: create user + mint token, list users, mint extra token ---


def test_create_user_returns_201_with_user_and_token(client: TestClient):
    resp = client.post("/admin/users", json={"username": "alice"})
    assert resp.status_code == 201
    body = resp.json()
    assert body["user"]["user_id"]
    assert body["user"]["username"] == "alice"
    assert body["user"]["is_admin"] is False
    assert body["token"]["token"].startswith("wrn_")


def test_create_user_with_is_admin_true(client: TestClient):
    resp = client.post("/admin/users", json={"username": "root2", "is_admin": True})
    assert resp.status_code == 201
    assert resp.json()["user"]["is_admin"] is True


@pytest.mark.asyncio
async def test_create_user_token_resolves(client: TestClient, auth_store: AuthStore):
    resp = client.post("/admin/users", json={"username": "bob"})
    assert resp.status_code == 201
    body = resp.json()
    raw_token = body["token"]["token"]
    resolved = await resolve_token(auth_store, raw_token, TOKEN_PEPPER)
    assert resolved is not None
    assert resolved.user_id == body["user"]["user_id"]


def test_create_user_duplicate_username_returns_409(client: TestClient):
    resp1 = client.post("/admin/users", json={"username": "dupe"})
    assert resp1.status_code == 201
    resp2 = client.post("/admin/users", json={"username": "dupe"})
    assert resp2.status_code == 409


@pytest.mark.parametrize(
    "username",
    ["", "Bad Name!", "x" * 200],
)
def test_create_user_invalid_username_returns_422(client: TestClient, username: str):
    resp = client.post("/admin/users", json={"username": username})
    assert resp.status_code == 422


def test_list_users_returns_200_no_secret_fields(client: TestClient):
    client.post("/admin/users", json={"username": "carol"})
    resp = client.get("/admin/users")
    assert resp.status_code == 200
    body = resp.json()
    assert isinstance(body, list)
    assert len(body) >= 1
    payload = str(body)
    assert "token" not in payload
    assert "hashed_token" not in payload
    assert "secret" not in payload


def test_mint_additional_token_for_existing_user(client: TestClient):
    create_resp = client.post("/admin/users", json={"username": "dave"})
    user_id = create_resp.json()["user"]["user_id"]
    first_token = create_resp.json()["token"]["token"]

    mint_resp = client.post(f"/admin/users/{user_id}/tokens")
    assert mint_resp.status_code == 201
    second_token = mint_resp.json()["token"]
    assert second_token != first_token


def test_mint_token_for_unknown_user_returns_404(client: TestClient):
    resp = client.post("/admin/users/does-not-exist/tokens")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_both_minted_tokens_resolve_to_same_user(client: TestClient, auth_store: AuthStore):
    create_resp = client.post("/admin/users", json={"username": "erin"})
    user_id = create_resp.json()["user"]["user_id"]
    first_token = create_resp.json()["token"]["token"]

    mint_resp = client.post(f"/admin/users/{user_id}/tokens")
    second_token = mint_resp.json()["token"]

    resolved1 = await resolve_token(auth_store, first_token, TOKEN_PEPPER)
    resolved2 = await resolve_token(auth_store, second_token, TOKEN_PEPPER)
    assert resolved1 is not None
    assert resolved2 is not None
    assert resolved1.user_id == user_id
    assert resolved2.user_id == user_id


# --- Task 2: single-token revocation and the is_admin gate ---


@pytest.mark.asyncio
async def test_revoke_token_returns_204(client: TestClient):
    create_resp = client.post("/admin/users", json={"username": "frank"})
    token_id = create_resp.json()["token"]["token_id"]
    resp = client.delete(f"/admin/tokens/{token_id}")
    assert resp.status_code == 204
    assert resp.content == b""


@pytest.mark.asyncio
async def test_revoke_token_then_resolve_returns_none(client: TestClient, auth_store: AuthStore):
    create_resp = client.post("/admin/users", json={"username": "grace"})
    token_id = create_resp.json()["token"]["token_id"]
    raw_token = create_resp.json()["token"]["token"]

    client.delete(f"/admin/tokens/{token_id}")

    resolved = await resolve_token(auth_store, raw_token, TOKEN_PEPPER)
    assert resolved is None


@pytest.mark.asyncio
async def test_revoke_does_not_affect_other_users_token(client: TestClient, auth_store: AuthStore):
    create1 = client.post("/admin/users", json={"username": "heidi"})
    token_id_1 = create1.json()["token"]["token_id"]

    create2 = client.post("/admin/users", json={"username": "ivan"})
    raw_token_2 = create2.json()["token"]["token"]

    client.delete(f"/admin/tokens/{token_id_1}")

    resolved2 = await resolve_token(auth_store, raw_token_2, TOKEN_PEPPER)
    assert resolved2 is not None


@pytest.mark.asyncio
async def test_revoke_does_not_affect_same_users_other_token(client: TestClient, auth_store: AuthStore):
    create_resp = client.post("/admin/users", json={"username": "judy"})
    user_id = create_resp.json()["user"]["user_id"]
    token_id_1 = create_resp.json()["token"]["token_id"]

    mint_resp = client.post(f"/admin/users/{user_id}/tokens")
    raw_token_2 = mint_resp.json()["token"]

    client.delete(f"/admin/tokens/{token_id_1}")

    resolved2 = await resolve_token(auth_store, raw_token_2, TOKEN_PEPPER)
    assert resolved2 is not None


def test_revoke_unknown_token_returns_404(client: TestClient):
    resp = client.delete("/admin/tokens/does-not-exist")
    assert resp.status_code == 404


def test_revoke_already_revoked_token_returns_404(client: TestClient):
    create_resp = client.post("/admin/users", json={"username": "kyle"})
    token_id = create_resp.json()["token"]["token_id"]

    first = client.delete(f"/admin/tokens/{token_id}")
    assert first.status_code == 204

    second = client.delete(f"/admin/tokens/{token_id}")
    assert second.status_code == 404


class _StateInjectMiddleware:
    """Pure-ASGI wrapper that sets scope['state']['user'] before the app runs.

    Lets the REAL require_admin dependency execute (no dependency_overrides), proving
    the 401/403 gate itself rather than the test's override.
    """

    def __init__(self, app, user=None):
        self._app = app
        self._user = user

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            scope.setdefault("state", {})
            if self._user is not None:
                scope["state"]["user"] = self._user
        await self._app(scope, receive, send)


def _gate_app(auth_store: AuthStore, user=None) -> FastAPI:
    application = FastAPI()
    application.include_router(admin.router)
    application.state.auth_store = auth_store
    application.state.settings = SimpleNamespace(secret_key=_SecretKey("test-pepper"), token_ttl_days=90, max_tokens_per_user=10)
    application.add_middleware(_StateInjectMiddleware, user=user)
    return application


@pytest.mark.asyncio
async def test_non_admin_user_gets_403(auth_store: AuthStore):
    from datetime import datetime, timezone

    non_admin = User(
        user_id="u-1",
        username="plain",
        is_admin=False,
        created_at=datetime.now(timezone.utc),
    )
    application = _gate_app(auth_store, user=non_admin)
    with TestClient(application) as gate_client:
        resp = gate_client.post("/admin/users", json={"username": "someone"})
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_unauthenticated_request_gets_401(auth_store: AuthStore):
    application = _gate_app(auth_store, user=None)
    with TestClient(application) as gate_client:
        resp = gate_client.get("/admin/users")
    assert resp.status_code == 401


# --- Issue #11: token expiry, per-user cap, provenance, disable/list-tokens ---------------------


def test_create_user_token_has_expires_at(client: TestClient):
    resp = client.post("/admin/users", json={"username": "ttl-user"})
    assert resp.status_code == 201
    assert resp.json()["token"]["expires_at"] is not None


def test_mint_additional_token_has_expires_at(client: TestClient):
    create_resp = client.post("/admin/users", json={"username": "ttl-user2"})
    user_id = create_resp.json()["user"]["user_id"]
    mint_resp = client.post(f"/admin/users/{user_id}/tokens")
    assert mint_resp.json()["expires_at"] is not None


def test_mint_token_enforces_per_user_cap(client: TestClient, app: FastAPI):
    app.state.settings.max_tokens_per_user = 2
    create_resp = client.post("/admin/users", json={"username": "capped"})
    user_id = create_resp.json()["user"]["user_id"]

    # First token came from create_user; one more fits under the cap of 2.
    ok_resp = client.post(f"/admin/users/{user_id}/tokens")
    assert ok_resp.status_code == 201

    over_resp = client.post(f"/admin/users/{user_id}/tokens")
    assert over_resp.status_code == 429


def test_list_user_tokens_returns_tokens_no_secret_fields(client: TestClient):
    create_resp = client.post("/admin/users", json={"username": "listed"})
    user_id = create_resp.json()["user"]["user_id"]
    client.post(f"/admin/users/{user_id}/tokens")

    resp = client.get(f"/admin/users/{user_id}/tokens")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 2
    payload = str(body)
    assert "hashed_token" not in payload


def test_list_user_tokens_unknown_user_returns_404(client: TestClient):
    resp = client.get("/admin/users/does-not-exist/tokens")
    assert resp.status_code == 404


@pytest.mark.asyncio
async def test_disable_user_revokes_all_tokens(client: TestClient, auth_store: AuthStore):
    create_resp = client.post("/admin/users", json={"username": "todisable"})
    user_id = create_resp.json()["user"]["user_id"]
    raw_token_1 = create_resp.json()["token"]["token"]
    raw_token_2 = client.post(f"/admin/users/{user_id}/tokens").json()["token"]

    resp = client.post(f"/admin/users/{user_id}/disable")
    assert resp.status_code == 200
    body = resp.json()
    assert body["user"]["disabled_at"] is not None
    assert body["revoked_token_count"] == 2

    assert await resolve_token(auth_store, raw_token_1, TOKEN_PEPPER) is None
    assert await resolve_token(auth_store, raw_token_2, TOKEN_PEPPER) is None


def test_disable_user_unknown_returns_404(client: TestClient):
    resp = client.post("/admin/users/does-not-exist/disable")
    assert resp.status_code == 404


def test_disable_user_is_idempotent(client: TestClient):
    create_resp = client.post("/admin/users", json={"username": "doubledisable"})
    user_id = create_resp.json()["user"]["user_id"]

    first = client.post(f"/admin/users/{user_id}/disable")
    assert first.status_code == 200
    assert first.json()["revoked_token_count"] == 1

    second = client.post(f"/admin/users/{user_id}/disable")
    assert second.status_code == 200
    assert second.json()["revoked_token_count"] == 0


def test_disable_user_refuses_to_disable_self(client: TestClient, admin_user: User):
    """Audit V5: disabling yourself revokes your own token via
    revoke_all_tokens_for_user, locking you out mid-request with no way back
    in except another admin or `recover-admin`."""
    resp = client.post(f"/admin/users/{admin_user.user_id}/disable")
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "cannot_disable_self"


@pytest.mark.asyncio
async def test_disable_user_refuses_to_disable_last_enabled_admin(
    client: TestClient, auth_store: AuthStore
):
    """Audit V5: disabling the only other enabled admin locks everyone out of
    normal admin access -- the acting admin_user fixture is a dependency
    override, not a DB row, so the target admin created here is the only
    enabled admin row that actually exists."""
    create_resp = client.post(
        "/admin/users", json={"username": "lastadmin", "is_admin": True}
    )
    user_id = create_resp.json()["user"]["user_id"]

    resp = client.post(f"/admin/users/{user_id}/disable")
    assert resp.status_code == 422
    assert resp.json()["detail"]["error"] == "cannot_disable_last_admin"

    # Never actually disabled.
    user = await auth_store.get_user(user_id)
    assert user is not None
    assert user.disabled_at is None


@pytest.mark.asyncio
async def test_disable_user_allows_disabling_admin_when_another_enabled_admin_exists(
    client: TestClient, auth_store: AuthStore
):
    """The guard only blocks disabling the LAST enabled admin -- with two
    enabled admins, disabling one is still allowed."""
    create_resp = client.post(
        "/admin/users", json={"username": "admin-a", "is_admin": True}
    )
    user_a = create_resp.json()["user"]["user_id"]
    client.post("/admin/users", json={"username": "admin-b", "is_admin": True})

    resp = client.post(f"/admin/users/{user_a}/disable")
    assert resp.status_code == 200
    assert resp.json()["user"]["disabled_at"] is not None


def test_disabled_users_new_tokens_also_fail_to_authenticate(
    client: TestClient, app: FastAPI
) -> None:
    create_resp = client.post("/admin/users", json={"username": "cantmint"})
    user_id = create_resp.json()["user"]["user_id"]

    client.post(f"/admin/users/{user_id}/disable")

    # Admin mint route itself has no is_admin dependency on the TARGET user, so minting
    # for an already-disabled user still succeeds -- but the minted token must not
    # authenticate, since AuthStore's resolve query gates on disabled_at.
    mint_resp = client.post(f"/admin/users/{user_id}/tokens")
    assert mint_resp.status_code == 201


async def test_concurrent_admin_mints_never_exceed_cap(app: FastAPI, auth_store: AuthStore):
    import asyncio

    import httpx

    app.state.settings.max_tokens_per_user = 2
    target = await auth_store.create_user(username="racer", is_admin=False)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        responses = await asyncio.gather(
            *(ac.post(f"/admin/users/{target.user_id}/tokens") for _ in range(10))
        )
    assert [r.status_code for r in responses].count(201) == 2
    assert await auth_store.count_active_tokens_for_user(target.user_id) == 2


async def test_concurrent_disables_of_last_two_admins_leave_one_enabled(
    app: FastAPI, auth_store: AuthStore
):
    """Finding 11: both disables used to observe two enabled admins and both succeed."""
    import asyncio

    import httpx

    first = await auth_store.create_user(username="admin-a", is_admin=True)
    second = await auth_store.create_user(username="admin-b", is_admin=True)
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as ac:
        responses = await asyncio.gather(
            ac.post(f"/admin/users/{first.user_id}/disable"),
            ac.post(f"/admin/users/{second.user_id}/disable"),
        )
    assert sorted(r.status_code for r in responses) == [200, 422]
    assert await auth_store.count_enabled_admins() == 1
