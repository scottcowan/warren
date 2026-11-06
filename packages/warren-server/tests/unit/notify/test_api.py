"""Per-owner webhook API and its encrypted storage."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from structlog.testing import capture_logs
from warren.app import app

from tests.conftest import TEST_BOOTSTRAP_TOKEN

URL = "https://hooks.slack.com/services/T000/B000/ownerSECRETpart"


def _make_fake_registry() -> MagicMock:
    r = MagicMock()
    r.server_id = "test-server"
    r.reconcile_from_disk = AsyncMock()
    r.store = MagicMock()
    r.store.list_all = AsyncMock(return_value=[])
    r.store.list_non_terminal = AsyncMock(return_value=[])
    return r


@contextmanager
def _client(headers):
    with (
        patch("warren.app.WorkspaceRegistry", return_value=_make_fake_registry()),
        patch("warren.app.PodmanRuntime"),
        TestClient(app, headers=headers) as client,
    ):
        yield client


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
    monkeypatch.setenv("WARREN_IDLE_REAPER_ENABLED", "0")
    yield tmp_path
    app.state._state.clear()


def _db_rows(data_dir) -> list[tuple]:
    dbs = list(data_dir.rglob("*.db"))
    assert dbs
    with sqlite3.connect(dbs[0]) as conn:
        return conn.execute("SELECT owner_id, name, ciphertext FROM secrets").fetchall()


def test_put_get_delete_roundtrip(env_defaults, auth_headers):
    with _client(auth_headers) as client:
        assert client.get("/notifications/webhook").json()["configured"] is False
        with capture_logs() as logs:
            r = client.put("/notifications/webhook",
                           json={"url": URL, "format": "slack", "events": ["agent.waiting", "agent.failed"]})
        assert r.status_code == 204
        got = client.get("/notifications/webhook")
        assert got.status_code == 200
        body = got.json()
        assert body["configured"] is True and body["format"] == "slack"
        assert body["events"] == ["agent.failed", "agent.waiting"]
        assert "workspace.idle_stopped" in body["available_events"]
        assert "ownerSECRETpart" not in got.text
        assert "ownerSECRETpart" not in str(logs)

        rows = _db_rows(env_defaults)
        assert [r[1] for r in rows] == ["warren.notify.webhook"]
        assert b"ownerSECRETpart" not in bytes(rows[0][2])  # encrypted at rest

        assert client.delete("/notifications/webhook").status_code == 204
        assert client.get("/notifications/webhook").json()["configured"] is False
        assert client.delete("/notifications/webhook").status_code == 404


def test_defaults_to_all_events_and_json(env_defaults, auth_headers):
    with _client(auth_headers) as client:
        assert client.put("/notifications/webhook", json={"url": URL}).status_code == 204
        body = client.get("/notifications/webhook").json()
        assert body["format"] == "json" and len(body["events"]) == 5


@pytest.mark.parametrize(
    "payload",
    [
        {"url": "http://hooks.example.com/x"},
        {"url": "https://u:p@hooks.example.com/x"},
        {"url": URL, "format": "xml"},
        {"url": URL, "events": ["agent.nope"]},
    ],
)
def test_rejects_invalid(env_defaults, auth_headers, payload):
    with _client(auth_headers) as client:
        r = client.put("/notifications/webhook", json=payload)
        assert r.status_code in (400, 422)
        assert "hooks.example.com" not in r.text
        assert client.get("/notifications/webhook").json()["configured"] is False


def test_owners_are_isolated(env_defaults, auth_headers):
    with _client(auth_headers) as admin:
        admin.put("/notifications/webhook", json={"url": URL})
        resp = admin.post("/admin/users", json={"username": "bob", "is_admin": False})
        bob_token = resp.json()["token"]["token"]
    with _client({"Authorization": f"Bearer {bob_token}"}) as bob:
        assert bob.get("/notifications/webhook").json()["configured"] is False
        assert bob.delete("/notifications/webhook").status_code == 404


def test_generic_secrets_route_cannot_write_reserved_name(env_defaults, auth_headers):
    with _client(auth_headers) as client:
        r = client.put("/secrets", json={"name": "warren.notify.webhook", "value": '{"url": "http://x"}'})
        assert r.status_code == 400 and r.json()["detail"]["error"] == "reserved_secret_name"


def test_unauthenticated_is_rejected(env_defaults):
    with _client({}) as client:
        assert client.get("/notifications/webhook").status_code == 401


def test_lifespan_wires_notifier(env_defaults, auth_headers):
    from warren.notify import Notifier

    with _client(auth_headers):
        assert isinstance(app.state.notifier, Notifier)
        assert app.state.notify_watcher_task is not None


def test_notify_disabled(env_defaults, auth_headers, monkeypatch):
    monkeypatch.setenv("WARREN_NOTIFY_ENABLED", "false")
    with _client(auth_headers):
        assert app.state.notifier is None and app.state.notify_watcher_task is None


async def test_store_roundtrip_and_tampered_record_fails_closed(tmp_path):
    from warren.notify import store
    from warren.registry.store import open_db
    from warren.secrets import store as secret_store
    from warren.secrets.cipher import LocalCipher

    db = await open_db(tmp_path / "w.db")
    try:
        cipher = LocalCipher("k" * 32)
        secrets = secret_store.SqliteSecretStore(db, cipher)
        await store.put(secrets, "u1", URL, "slack", frozenset({"agent.waiting"}))
        t = await store.get(secrets, "u1")
        assert t is not None and t.kind == "owner" and t.require_public and t.format == "slack"
        assert t.url.get_secret_value() == URL and "ownerSECRETpart" not in repr(t)
        assert await store.subscribed_owners(secrets) == {"u1"}
        await secret_store.set_secret(db, cipher, "u2", store.SECRET_NAME, '{"url": "http://internal/x"}')
        assert await store.get(secrets, "u2") is None
        assert await store.delete(secrets, "u1") is True
        assert await store.get(secrets, "u1") is None
    finally:
        await db.close()



async def test_store_on_every_secrets_backend(secret_store):
    """The webhook record goes through SecretStoreProtocol: SQLite + Fernet and Secrets
    Manager (moto) behave the same (fixture in tests/unit/conftest.py)."""
    from warren.notify import store

    await store.put(secret_store, "u1", URL, "json", frozenset({"agent.failed"}))
    await store.put(secret_store, "arn:aws:iam::1:user/u2", URL, "slack", frozenset())
    await secret_store.set("u3", "NOT_A_WEBHOOK", "x")
    assert await store.subscribed_owners(secret_store) == {"u1", "arn:aws:iam::1:user/u2"}
    t = await store.get(secret_store, "u1")
    assert t is not None and t.events == {"agent.failed"} and t.url.get_secret_value() == URL
    assert (await store.get(secret_store, "arn:aws:iam::1:user/u2")).format == "slack"
    assert await store.get(secret_store, "u3") is None
    await store.put(secret_store, "u1", URL, "slack", frozenset({"agent.waiting"}))
    assert (await store.get(secret_store, "u1")).events == {"agent.waiting"}  # write invalidates any cache
    assert await store.delete(secret_store, "u1") is True
    assert await store.delete(secret_store, "u1") is False
    assert await store.get(secret_store, "u1") is None
    assert await store.subscribed_owners(secret_store) == {"arn:aws:iam::1:user/u2"}
