"""Secret store route tests — per-owner isolation, SSM mirror. No permission
tier (removed 2026-10-13) — every secret is just (owner_id, name)."""

from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from tests.conftest import TEST_BOOTSTRAP_TOKEN
from warren.app import app


def _make_fake_registry() -> MagicMock:
    r = MagicMock()
    r.server_id = "test-server"
    r.reconcile_from_disk = AsyncMock()
    r.store = MagicMock()
    r.store.list_all = AsyncMock(return_value=[])
    return r


@contextmanager
def _lifespan_patches(fake_registry):
    with (
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry),
        patch("warren.app.PodmanRuntime"),
    ):
        yield


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


def _mint_user_token(client, username: str) -> str:
    resp = client.post("/admin/users", json={"username": username, "is_admin": False})
    assert resp.status_code == 201
    return resp.json()["token"]["token"]


def test_put_then_list_roundtrip(env_defaults, auth_headers):
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            put_resp = client.put("/secrets", json={"name": "API_KEY", "value": "sk-abc"})
            assert put_resp.status_code == 204

            list_resp = client.get("/secrets")
            assert list_resp.status_code == 200
            assert list_resp.json() == [{"name": "API_KEY"}]


def test_list_never_returns_secret_values(env_defaults, auth_headers):
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            client.put("/secrets", json={"name": "API_KEY", "value": "super-secret-value"})
            list_resp = client.get("/secrets")
    assert "super-secret-value" not in list_resp.text


def test_delete_unknown_secret_404s(env_defaults, auth_headers):
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            resp = client.delete("/secrets/NOPE")
    assert resp.status_code == 404


def test_delete_removes_secret(env_defaults, auth_headers):
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            client.put("/secrets", json={"name": "A", "value": "v"})
            del_resp = client.delete("/secrets/A")
            assert del_resp.status_code == 204
            assert client.get("/secrets").json() == []


def test_two_users_secrets_are_isolated(env_defaults, auth_headers):
    """Alice's secret is invisible to Bob even at the same name — per-owner
    isolation (routes/secrets.py), not a server-wide store."""
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            alice_token = _mint_user_token(client, "alice")
            bob_token = _mint_user_token(client, "bob")

            alice_headers = {"Authorization": f"Bearer {alice_token}"}
            bob_headers = {"Authorization": f"Bearer {bob_token}"}

            put_resp = client.put(
                "/secrets",
                json={"name": "SHARED_NAME", "value": "alices-value"},
                headers=alice_headers,
            )
            assert put_resp.status_code == 204

            # Bob sees nothing under his own list.
            bob_list = client.get("/secrets", headers=bob_headers)
            assert bob_list.json() == []

            # Bob deleting the same name finds nothing to delete either.
            bob_delete = client.delete("/secrets/SHARED_NAME", headers=bob_headers)
            assert bob_delete.status_code == 404

            # Alice still sees her own.
            alice_list = client.get("/secrets", headers=alice_headers)
            assert alice_list.json() == [{"name": "SHARED_NAME"}]


def test_non_admin_can_write_and_list_their_own_secrets(env_defaults, auth_headers):
    """Writing a secret is not admin-gated — every caller manages their own
    isolated secrets, same as a user-scoped project write."""
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            alice_token = _mint_user_token(client, "alice")
            alice_headers = {"Authorization": f"Bearer {alice_token}"}

            put_resp = client.put("/secrets", json={"name": "A", "value": "v"}, headers=alice_headers)
            assert put_resp.status_code == 204


def test_put_rejects_ssm_unsafe_name(env_defaults, auth_headers):
    """Issue #22: a name outside SSM's allowed charset must fail fast, before
    any write happens -- not only once it reaches the (ECS-only) mirror step."""
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            resp = client.put("/secrets", json={"name": "bad name!", "value": "v"})
            assert resp.status_code == 400
            assert resp.json()["detail"]["error"] == "invalid_secret_name"
            assert client.get("/secrets").json() == []


def test_put_rejects_oversized_value(env_defaults, auth_headers):
    """Issue #22: SSM Standard tier caps a parameter value at 4KB -- reject
    up front rather than letting it only fail once mirrored to SSM."""
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            resp = client.put("/secrets", json={"name": "A", "value": "x" * 4097})
            assert resp.status_code == 400
            assert resp.json()["detail"]["error"] == "secret_value_too_large"
            assert client.get("/secrets").json() == []


def test_put_failed_ssm_mirror_leaves_no_ghost_local_secret(env_defaults, monkeypatch, auth_headers):
    """Issue #22: if the SSM mirror fails, the secret must never become visible
    via GET /secrets -- previously the local write committed BEFORE the mirror
    attempt, so a failed put left a ghost secret listed locally that no ECS
    workspace ever actually received."""
    monkeypatch.setenv("WARREN_RUNTIME_TYPE", "ecs")
    fake_registry = _make_fake_registry()
    fake_ssm = MagicMock()
    fake_ssm.put_parameter.side_effect = RuntimeError("ssm unavailable")
    fake_runtime = MagicMock()
    fake_runtime.ssm_client.return_value = fake_ssm
    aws_headers = {"X-AWS-STS-Signed-Request": '{"url": "https://sts.amazonaws.com/"}'}
    derived_owner_id = "deadbeef" * 4

    with (
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry),
        patch("warren.runtime.ecs.ECSRuntime", return_value=fake_runtime),
        patch(
            "warren.auth.aws_identity.verify_signed_caller_identity",
            AsyncMock(return_value=derived_owner_id),
        ),
    ):
        with TestClient(app, headers={**auth_headers, **aws_headers}) as client:
            put_resp = client.put("/secrets", json={"name": "A", "value": "v"})
            assert put_resp.status_code == 502
            # Audit R14: the mirror now runs BEFORE the local write (that's the
            # whole point of this test -- no ghost secret), so the error message
            # must say the secret was NOT saved, not that it "was saved locally".
            detail = put_resp.json()["detail"]["detail"]
            assert "was NOT saved" in detail
            assert "was saved locally" not in detail

            list_resp = client.get("/secrets")
            assert list_resp.json() == []


def test_delete_failed_ssm_mirror_keeps_local_row_for_retry(env_defaults, monkeypatch, auth_headers):
    """Issue #22: if the SSM mirror delete fails, the local row must stay so a
    retry can actually retry against the still-present SSM parameter --
    previously the local row was deleted FIRST, so a failed mirror delete left
    an orphaned SSM parameter and a retry just 404'd against the gone row."""
    monkeypatch.setenv("WARREN_RUNTIME_TYPE", "ecs")
    fake_registry = _make_fake_registry()
    fake_ssm = MagicMock()
    fake_ssm.delete_parameter.side_effect = RuntimeError("ssm unavailable")
    fake_runtime = MagicMock()
    fake_runtime.ssm_client.return_value = fake_ssm
    aws_headers = {"X-AWS-STS-Signed-Request": '{"url": "https://sts.amazonaws.com/"}'}
    derived_owner_id = "deadbeef" * 4

    with (
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry),
        patch("warren.runtime.ecs.ECSRuntime", return_value=fake_runtime),
        patch(
            "warren.auth.aws_identity.verify_signed_caller_identity",
            AsyncMock(return_value=derived_owner_id),
        ),
    ):
        with TestClient(app, headers={**auth_headers, **aws_headers}) as client:
            fake_ssm.put_parameter.side_effect = None
            put_resp = client.put("/secrets", json={"name": "A", "value": "v"})
            assert put_resp.status_code == 204

            del_resp = client.delete("/secrets/A")
            assert del_resp.status_code == 502
            # Audit R14: mirror-delete runs BEFORE the local delete (that's why
            # the row survives for retry below), so the message must say the
            # secret was NOT deleted, not that it "was deleted locally".
            detail = del_resp.json()["detail"]["detail"]
            assert "was NOT deleted" in detail
            assert "was deleted locally" not in detail

            # Row must still be present locally for a retry -- not 404.
            retry_resp = client.delete("/secrets/A")
            assert retry_resp.status_code != 404
            assert retry_resp.status_code == 502


def test_ssm_mirror_not_attempted_on_podman(env_defaults, auth_headers):
    """runtime_type defaults to 'podman' in these tests -- no SSM mirror call,
    and no app.state.runtime.ssm_client() dependency at all."""
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            # app.state.runtime is a real PodmanRuntime-shaped mock with no
            # ssm_client attribute; if the route tried to call it, this would
            # raise AttributeError and the request would 500.
            resp = client.put("/secrets", json={"name": "A", "value": "v"})
    assert resp.status_code == 204


def test_ecs_put_without_aws_identity_header_401s(env_defaults, monkeypatch, auth_headers):
    """ECS deployments resolve secret ownership from the caller's verified AWS
    identity, not warren's bearer token -- omitting the presigned STS header
    must fail closed, not silently fall back to the warren user_id."""
    monkeypatch.setenv("WARREN_RUNTIME_TYPE", "ecs")
    fake_registry = _make_fake_registry()
    fake_runtime = MagicMock()

    with (
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry),
        patch("warren.runtime.ecs.ECSRuntime", return_value=fake_runtime),
    ):
        with TestClient(app, headers=auth_headers) as client:
            resp = client.put("/secrets", json={"name": "A", "value": "v"})
    assert resp.status_code == 401
    assert resp.json()["detail"]["error"] == "aws_identity_required"


def test_ssm_mirror_called_on_ecs_put_and_delete(env_defaults, monkeypatch, auth_headers):
    monkeypatch.setenv("WARREN_RUNTIME_TYPE", "ecs")
    fake_registry = _make_fake_registry()
    fake_ssm = MagicMock()
    fake_runtime = MagicMock()
    fake_runtime.ssm_client.return_value = fake_ssm
    aws_headers = {"X-AWS-STS-Signed-Request": '{"url": "https://sts.amazonaws.com/"}'}
    derived_owner_id = "deadbeef" * 4  # SSM-safe hex, as derive_owner_id would return

    with (
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry),
        patch("warren.runtime.ecs.ECSRuntime", return_value=fake_runtime),
        patch(
            "warren.auth.aws_identity.verify_signed_caller_identity",
            AsyncMock(return_value=derived_owner_id),
        ),
    ):
        with TestClient(app, headers={**auth_headers, **aws_headers}) as client:
            put_resp = client.put("/secrets", json={"name": "A", "value": "v"})
            assert put_resp.status_code == 204
            fake_ssm.put_parameter.assert_called_once()
            assert derived_owner_id in fake_ssm.put_parameter.call_args.kwargs["Name"]

            del_resp = client.delete("/secrets/A")
            assert del_resp.status_code == 204
            fake_ssm.delete_parameter.assert_called_once()


def test_put_secret_logs_audit_line_never_value(env_defaults, auth_headers, caplog):
    """Audit #46: secret writes weren't logged at all. Must log name/owner/action, and
    must never log the secret value."""
    import logging

    from warren.logging import configure_logging

    configure_logging()
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            with caplog.at_level(logging.INFO):
                resp = client.put("/secrets", json={"name": "API_KEY", "value": "sk-very-secret"})
    assert resp.status_code == 204
    rendered = " ".join(r.getMessage() for r in caplog.records)
    assert "secret_written" in rendered
    assert "API_KEY" in rendered
    assert "sk-very-secret" not in rendered


def test_delete_secret_logs_audit_line(env_defaults, auth_headers, caplog):
    """Audit #46: secret deletes weren't logged at all."""
    import logging

    from warren.logging import configure_logging

    configure_logging()
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            client.put("/secrets", json={"name": "API_KEY", "value": "sk-very-secret"})
            with caplog.at_level(logging.INFO):
                resp = client.delete("/secrets/API_KEY")
    assert resp.status_code == 204
    rendered = " ".join(r.getMessage() for r in caplog.records)
    assert "secret_deleted" in rendered
    assert "API_KEY" in rendered


def test_put_secret_oversized_body_rejected_with_413(env_defaults, auth_headers):
    """Audit #46: the global BodySizeLimitMiddleware bounds /secrets writes too."""
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            resp = client.put(
                "/secrets", json={"name": "API_KEY", "value": "x" * (512 * 1024)}
            )
    assert resp.status_code == 413


def _read_secret(client, owner_id: str, name: str) -> tuple[bytes, str]:
    from warren.secrets.cipher import LocalCipher

    async def _read():
        db = app.state.db
        async with db.execute(
            "SELECT ciphertext FROM secrets WHERE owner_id = ? AND name = ?", (owner_id, name)
        ) as cur:
            row = await cur.fetchone()
        return row[0], LocalCipher("x" * 32).decrypt(row[0])

    return client.portal.call(_read)


def _admin_user_id(client) -> str:
    return client.get("/admin/users").json()[0]["user_id"]


def test_rotate_without_value_reencrypts_and_keeps_plaintext(env_defaults, auth_headers):
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            client.put("/secrets", json={"name": "API_KEY", "value": "sk-abc"})
            owner = _admin_user_id(client)
            before, _ = _read_secret(client, owner, "API_KEY")

            resp = client.post("/secrets/API_KEY/rotate")
            assert resp.status_code == 204

            after, plaintext = _read_secret(client, owner, "API_KEY")
    assert after != before
    assert plaintext == "sk-abc"


def test_rotate_with_value_replaces_secret(env_defaults, auth_headers):
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            client.put("/secrets", json={"name": "API_KEY", "value": "sk-old"})
            resp = client.post("/secrets/API_KEY/rotate", json={"value": "sk-new"})
            assert resp.status_code == 204
            _, plaintext = _read_secret(client, _admin_user_id(client), "API_KEY")
    assert plaintext == "sk-new"


def test_rotate_another_users_secret_404s(env_defaults, auth_headers):
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            alice = {"Authorization": f"Bearer {_mint_user_token(client, 'alice')}"}
            bob = {"Authorization": f"Bearer {_mint_user_token(client, 'bob')}"}
            client.put("/secrets", json={"name": "A", "value": "v"}, headers=alice)
            resp = client.post("/secrets/A/rotate", json={"value": "bobs"}, headers=bob)
    assert resp.status_code == 404


def test_rotate_rejects_oversized_value(env_defaults, auth_headers):
    fake_registry = _make_fake_registry()
    with _lifespan_patches(fake_registry):
        with TestClient(app, headers=auth_headers) as client:
            client.put("/secrets", json={"name": "A", "value": "v"})
            resp = client.post("/secrets/A/rotate", json={"value": "x" * 4097})
    assert resp.status_code == 400
