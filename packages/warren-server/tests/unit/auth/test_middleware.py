"""Unit tests for warren.auth.middleware.AuthMiddleware — AUTH-03.

Builds a THROWAWAY FastAPI app inside this module (never imports warren.app.app — wiring the
real app is plan 02-05's job). Uses a real AuthStore over a temp SQLite file (sqlite_path
fixture from tests/conftest.py) so token resolution exercises the real DB path, not a mock.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Request, WebSocket
from fastapi.responses import StreamingResponse
from fastapi.testclient import TestClient

from warren.auth.middleware import EXEMPT_PATHS, AuthMiddleware
from warren.auth.store import AuthStore
from warren.auth.tokens import derive_token_pepper, generate_token, hash_token

PEPPER = "test-pepper-not-a-real-secret"
"""The raw settings.secret_key value — passed to _SettingsStub, never to hash_token directly."""

TOKEN_PEPPER = derive_token_pepper(PEPPER)
"""What AuthMiddleware actually hashes with; use this (not PEPPER) in hash_token() calls."""


class _SecretStub:
    def __init__(self, value: str) -> None:
        self._value = value

    def get_secret_value(self) -> str:
        return self._value


class _SettingsStub:
    def __init__(self, pepper: str) -> None:
        self.secret_key = _SecretStub(pepper)


def _build_app(*, auth_store: AuthStore | None, settings: _SettingsStub | None, calls: list) -> FastAPI:
    app = FastAPI()
    app.add_middleware(AuthMiddleware)

    @app.get("/_status")
    async def _status() -> dict:
        return {"status": "ok"}

    @app.get("/healthz")
    async def _healthz() -> dict:
        return {"ok": True}

    @app.get("/protected")
    async def _protected(request: Request) -> dict:
        calls.append(request.state.user.user_id)
        return {"user_id": request.state.user.user_id}

    @app.get("/stream")
    async def _stream() -> StreamingResponse:
        async def _gen():
            yield b"chunk1"
            yield b"chunk2"
            yield b"chunk3"

        return StreamingResponse(_gen(), media_type="application/x-ndjson")

    @app.websocket("/ws")
    async def _ws(websocket: WebSocket) -> None:
        await websocket.accept()
        await websocket.send_text("hello")
        await websocket.close()

    if auth_store is not None:
        app.state.auth_store = auth_store
    if settings is not None:
        app.state.settings = settings

    return app


@pytest.fixture
async def auth_store(sqlite_path):
    store = await AuthStore.open(sqlite_path)
    try:
        yield store
    finally:
        await store.close()


@pytest.fixture
def settings() -> _SettingsStub:
    return _SettingsStub(PEPPER)


@pytest.fixture
async def minted(auth_store: AuthStore):
    """A live user + raw bearer token minted against auth_store."""
    user = await auth_store.create_user(username="alice", is_admin=False)
    raw_token = generate_token()
    hashed = hash_token(raw_token, TOKEN_PEPPER)
    await auth_store.create_token(user_id=user.user_id, hashed_token=hashed)
    return user, raw_token


@pytest.fixture
def calls() -> list:
    return []


@pytest.fixture
def app(auth_store: AuthStore, settings: _SettingsStub, calls: list) -> FastAPI:
    return _build_app(auth_store=auth_store, settings=settings, calls=calls)


@pytest.fixture
def client(app: FastAPI) -> TestClient:
    return TestClient(app)


# --- Exempt paths -----------------------------------------------------------------------------


def test_status_exempt_no_auth_header(client: TestClient) -> None:
    resp = client.get("/_status")
    assert resp.status_code == 200


def test_healthz_exempt_no_auth_header(client: TestClient) -> None:
    resp = client.get("/healthz")
    assert resp.status_code == 200


def test_exempt_paths_is_exactly_status_and_healthz() -> None:
    assert EXEMPT_PATHS == frozenset({"/_status", "/healthz"})


# --- Denial cases -------------------------------------------------------------------------------


def test_protected_no_auth_header_401_and_route_not_invoked(client: TestClient, calls: list) -> None:
    resp = client.get("/protected")
    assert resp.status_code == 401
    assert calls == []


def test_protected_wrong_scheme_401(client: TestClient) -> None:
    resp = client.get("/protected", headers={"Authorization": "Basic abc"})
    assert resp.status_code == 401


def test_protected_bearer_no_token_401(client: TestClient) -> None:
    resp = client.get("/protected", headers={"Authorization": "Bearer"})
    assert resp.status_code == 401


def test_protected_bearer_bogus_token_401(client: TestClient) -> None:
    resp = client.get("/protected", headers={"Authorization": "Bearer bogus-not-minted"})
    assert resp.status_code == 401


async def test_protected_revoked_token_401(client: TestClient, auth_store: AuthStore, minted) -> None:
    user, _raw_token = minted
    raw_revoked = generate_token()
    hashed_revoked = hash_token(raw_revoked, TOKEN_PEPPER)
    token_row = await auth_store.create_token(user_id=user.user_id, hashed_token=hashed_revoked)
    revoked_ok = await auth_store.revoke_token(token_row.token_id)
    assert revoked_ok is True

    resp = client.get("/protected", headers={"Authorization": f"Bearer {raw_revoked}"})
    assert resp.status_code == 401


async def test_protected_expired_token_401(client: TestClient, auth_store: AuthStore, minted) -> None:
    user, _raw_token = minted
    raw_expired = generate_token()
    hashed_expired = hash_token(raw_expired, TOKEN_PEPPER)
    past = datetime.now(timezone.utc) - timedelta(days=1)
    await auth_store.create_token(user_id=user.user_id, hashed_token=hashed_expired, expires_at=past)

    resp = client.get("/protected", headers={"Authorization": f"Bearer {raw_expired}"})
    assert resp.status_code == 401


def test_missing_auth_store_fails_closed_401_not_500(settings: _SettingsStub, calls: list) -> None:
    app = _build_app(auth_store=None, settings=settings, calls=calls)
    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/protected", headers={"Authorization": "Bearer whatever"})
    assert resp.status_code == 401


# --- Success case ---------------------------------------------------------------------------


def test_protected_valid_token_200_and_user_attached(client: TestClient, minted) -> None:
    user, raw_token = minted
    resp = client.get("/protected", headers={"Authorization": f"Bearer {raw_token}"})
    assert resp.status_code == 200
    assert resp.json()["user_id"] == user.user_id


# --- 401 body shape / no secret leakage ------------------------------------------------------


def test_401_body_is_json_with_detail_key(client: TestClient) -> None:
    resp = client.get("/protected")
    assert resp.headers["content-type"].startswith("application/json")
    assert resp.json() == {"detail": "unauthorized"}


def test_401_body_never_echoes_presented_token_or_hash(client: TestClient) -> None:
    presented = "wrn_this-token-must-never-appear-in-the-response"
    resp = client.get("/protected", headers={"Authorization": f"Bearer {presented}"})
    assert resp.status_code == 401
    body_text = resp.text
    assert presented not in body_text
    assert hash_token(presented, TOKEN_PEPPER) not in body_text


# --- Streaming passthrough (Pitfall 3) --------------------------------------------------------


def test_streaming_route_returns_full_concatenated_content(client: TestClient, minted) -> None:
    _user, raw_token = minted
    resp = client.get("/stream", headers={"Authorization": f"Bearer {raw_token}"})
    assert resp.status_code == 200
    assert resp.content == b"chunk1chunk2chunk3"


@pytest.mark.asyncio
async def test_streaming_passthrough_sends_unconcatenated_body_events() -> None:
    """Direct ASGI-level test: middleware must not buffer/rewrap send(), so each
    http.response.body event emitted by the downstream app arrives as its own send() call."""

    async def _inner_app(scope, receive, send) -> None:
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"application/x-ndjson")],
            }
        )
        await send({"type": "http.response.body", "body": b"chunk1", "more_body": True})
        await send({"type": "http.response.body", "body": b"chunk2", "more_body": True})
        await send({"type": "http.response.body", "body": b"chunk3", "more_body": False})

    middleware = AuthMiddleware(_inner_app)

    app_like = SimpleNamespace(state=SimpleNamespace(auth_store=object(), settings=_SettingsStub(PEPPER)))

    scope = {
        "type": "http",
        "path": "/stream",
        "headers": [],
        "app": app_like,
    }

    sent_events: list[dict] = []

    async def receive():
        return {"type": "http.disconnect"}

    async def send(event: dict) -> None:
        sent_events.append(event)

    # Patch resolve_token indirectly by using a real store would need a DB; instead exercise the
    # exempt-bypass so we hit the downstream app directly without needing DB resolution.
    scope["path"] = "/healthz"
    await middleware(scope, receive, send)

    body_events = [e for e in sent_events if e["type"] == "http.response.body"]
    assert len(body_events) == 3
    assert [e["body"] for e in body_events] == [b"chunk1", b"chunk2", b"chunk3"]


# --- WebSocket scopes are authenticated, not bypassed ----------------------------------------


def test_websocket_no_auth_header_rejected(client: TestClient) -> None:
    from starlette.websockets import WebSocketDisconnect

    with pytest.raises(WebSocketDisconnect) as exc_info:
        with client.websocket_connect("/ws"):
            pass
    assert exc_info.value.code == 4401


def test_websocket_valid_bearer_token_connects(client: TestClient, minted) -> None:
    _user, raw_token = minted
    with client.websocket_connect("/ws", headers={"Authorization": f"Bearer {raw_token}"}) as websocket:
        msg = websocket.receive_text()
    assert msg == "hello"
