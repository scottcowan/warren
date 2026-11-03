"""The app wired to WARREN_STATE_BACKEND=dynamodb + WARREN_SECRETS_BACKEND=secretsmanager
(moto): bootstrap, auth, admin and secret routes work, no SQLite file or writer lock is
created, and a missing table fails startup."""

from __future__ import annotations

from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from tests.conftest import TEST_BOOTSTRAP_TOKEN
from warren.state.errors import StateBackendError


@pytest.fixture
def aws_env(monkeypatch, tmp_path, dynamo_table, sm_client):
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_BOOTSTRAP_TOKEN", TEST_BOOTSTRAP_TOKEN)
    monkeypatch.setenv("WARREN_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("WARREN_PODMAN_SOCKET", str(tmp_path / "podman.sock"))
    monkeypatch.setenv("WARREN_SERVER_ID", "test-server")
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(tmp_path / "projects"))
    monkeypatch.setenv("WARREN_REAPER_ENABLED", "0")
    monkeypatch.setenv("WARREN_AWS_REGION", "us-east-1")
    monkeypatch.setenv("WARREN_STATE_BACKEND", "dynamodb")
    monkeypatch.setenv("WARREN_DYNAMODB_TABLE", dynamo_table.name)
    monkeypatch.setenv("WARREN_SECRETS_BACKEND", "secretsmanager")
    monkeypatch.setenv("WARREN_SECRETSMANAGER_PREFIX", "warren/test")
    yield tmp_path / "data"
    from warren.app import app

    app.state._state.clear()


def _fake_registry() -> MagicMock:
    r = MagicMock()
    r.server_id = "test-server"
    r.reconcile_from_disk = AsyncMock()
    r.store = MagicMock()
    r.store.list_all = AsyncMock(return_value=[])
    return r


def test_routes_run_on_dynamodb_and_secretsmanager(aws_env, sm_client, dynamo_table):
    from warren.app import app

    headers = {"Authorization": f"Bearer {TEST_BOOTSTRAP_TOKEN}"}
    with (
        patch("warren.app.run_preflight", AsyncMock()),  # podman's; the state preflight still runs
        patch("warren.app.WorkspaceRegistry", return_value=_fake_registry()) as reg_cls,
        patch("warren.app.PodmanRuntime"),
        TestClient(app, headers=headers) as client,
    ):
        assert app.state.db is None
        assert type(reg_cls.call_args.kwargs["secret_store"]).__name__ == "SecretsManagerSecretStore"
        resp = client.post("/admin/users", json={"username": "bob", "is_admin": False})
        assert resp.status_code == 201
        assert client.post("/admin/users", json={"username": "bob", "is_admin": False}).status_code == 409
        bob = {"Authorization": f"Bearer {resp.json()['token']['token']}"}

        assert client.put("/secrets", json={"name": "API_KEY", "value": "sk-1"}, headers=bob).status_code == 204
        assert client.get("/secrets", headers=bob).json() == [{"name": "API_KEY"}]
        assert client.get("/secrets").json() == []  # the admin's own: none
        assert client.post("/secrets/API_KEY/rotate", headers=bob).status_code == 204
        assert client.delete("/secrets/API_KEY", headers=bob).status_code == 204
        assert client.delete("/secrets/API_KEY", headers=bob).status_code == 404
        detail = client.get("/healthz/detail").json()
        assert detail["secret_store"] == {"reachable": True, "count": 0}

    names = [s["Name"] for s in sm_client.list_secrets(IncludePlannedDeletion=True)["SecretList"]]
    assert len(names) == 1 and names[0].startswith("warren/test/")
    # Nothing SQLite: no database file and no writer lock.
    assert not (aws_env / "warren.db").exists() and not (aws_env / "warren.db.lock").exists()


def test_missing_table_fails_startup(aws_env, monkeypatch):
    from warren.app import app

    monkeypatch.setenv("WARREN_DYNAMODB_TABLE", "does-not-exist")
    with (
        patch("warren.app.run_preflight", AsyncMock()),
        patch("warren.app.WorkspaceRegistry", return_value=_fake_registry()),
        patch("warren.app.PodmanRuntime"),
        pytest.raises(StateBackendError, match="does-not-exist"),
    ):
        with TestClient(app):
            pass


def test_dynamodb_with_sqlite_secrets_keeps_the_writer_lock(aws_env, monkeypatch):
    from warren.app import app

    monkeypatch.setenv("WARREN_SECRETS_BACKEND", "sqlite")
    headers = {"Authorization": f"Bearer {TEST_BOOTSTRAP_TOKEN}"}
    with (
        patch("warren.app.run_preflight", AsyncMock()),
        patch("warren.app.WorkspaceRegistry", return_value=_fake_registry()),
        patch("warren.app.PodmanRuntime"),
        TestClient(app, headers=headers) as client,
    ):
        assert (aws_env / "warren.db.lock").exists()
        assert client.put("/secrets", json={"name": "A", "value": "v"}).status_code == 204
        assert client.get("/secrets").json() == [{"name": "A"}]


def test_settings_validation(monkeypatch):
    from pydantic import ValidationError

    from warren.config import WarrenSettings

    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_STATE_BACKEND", "dynamodb")
    with pytest.raises(ValidationError, match="WARREN_DYNAMODB_TABLE"):
        WarrenSettings()
    monkeypatch.setenv("WARREN_DYNAMODB_TABLE", "t")
    monkeypatch.setenv("WARREN_SECRETSMANAGER_PREFIX", "/bad/")
    with pytest.raises(ValidationError, match="PREFIX"):
        WarrenSettings()
    monkeypatch.setenv("WARREN_SECRETSMANAGER_PREFIX", "warren/prod")
    monkeypatch.setenv("WARREN_SECRETSMANAGER_RECOVERY_WINDOW_DAYS", "3")
    with pytest.raises(ValidationError):
        WarrenSettings()
    monkeypatch.delenv("WARREN_SECRETSMANAGER_RECOVERY_WINDOW_DAYS")
    s = WarrenSettings()
    assert (s.state_backend, s.secrets_backend, s.secretsmanager_force_delete) == ("dynamodb", "sqlite", False)


def test_default_prefix_is_per_server():
    from types import SimpleNamespace

    from warren.state import secretsmanager_prefix, uses_sqlite

    assert secretsmanager_prefix(SimpleNamespace(secretsmanager_prefix="", server_id="ip-10-0-0-1")) == "warren/ip-10-0-0-1"
    assert secretsmanager_prefix(SimpleNamespace(secretsmanager_prefix="p/q", server_id="s")) == "p/q"
    assert uses_sqlite(SimpleNamespace(state_backend="sqlite", secrets_backend="secretsmanager"))
    assert not uses_sqlite(SimpleNamespace(state_backend="dynamodb", secrets_backend="secretsmanager"))
