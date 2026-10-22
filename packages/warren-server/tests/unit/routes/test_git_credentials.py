"""AK1 control-plane issuer: GET /workspaces/{id}/git-credential with a workspace-scoped token.

Generated RSA test key, mocked GitHub API, fake Secrets Manager / SSM clients.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import httpx
import pytest
import structlog
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from tests.conftest import TEST_BOOTSTRAP_TOKEN
from warren.app import app
from warren.git.token_issuer import (
    CachedKey,
    FileKeySource,
    SecretsManagerKeySource,
    SsmKeySource,
    control_plane_issuer,
)
from warren.registry.store import WorkspaceStore
from warren_common.github_tokens import GitHubAppMinter, TokenIssuerError
from warren_common.models import FolderSpec

_ADMIN = {"Authorization": f"Bearer {TEST_BOOTSTRAP_TOKEN}"}
_MINTED = "ghs_control_plane_minted"


@pytest.fixture(scope="module")
def pem() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


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


def _spec_json(*folders: FolderSpec) -> str:
    return json.dumps({"folders": [f.model_dump(mode="json") for f in folders]})


@contextmanager
def _client(pem: bytes, calls: list):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.path == "/repos/acme/app/installation":
            return httpx.Response(200, json={"id": 9})
        if request.url.path == "/app/installations/9/access_tokens":
            return httpx.Response(201, json={"token": _MINTED, "expires_at": "2099-01-01T00:00:00Z"})
        return httpx.Response(404)

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
        app.state.github_token_issuer = GitHubAppMinter(
            "123", lambda: pem, transport=httpx.MockTransport(handler)
        )
        owner = client.get("/admin/users", headers=_ADMIN).json()[0]["user_id"]
        specs = {
            "ws-a": _spec_json(
                FolderSpec(name="app", type="git-worktree", url="https://github.com/acme/app.git", mount="code/app"),
                FolderSpec(name="docs", type="git-clone", url="https://github.com/acme/docs.git", mount="refs/docs"),
            ),
            "ws-b": _spec_json(
                FolderSpec(name="lib", type="git-worktree", url="https://github.com/acme/lib.git", mount="code/lib"),
            ),
        }
        for ws_id, spec_json in specs.items():
            client.portal.call(
                lambda ws_id=ws_id, spec_json=spec_json: registry.store.insert(
                    workspace_id=ws_id,
                    project="demo",
                    intent="develop",
                    image="img",
                    root_path="",
                    server_instance="test-server",
                    status="running",
                    owner_id=owner,
                    spec_json=spec_json,
                )
            )
        yield client, registry


def _scoped(client, ws_id: str) -> dict:
    resp = client.post(f"/workspaces/{ws_id}/tokens", json={}, headers=_ADMIN)
    assert resp.status_code == 201
    return {"Authorization": f"Bearer {resp.json()['token']}"}


def test_scoped_token_gets_narrowed_token_for_template_repo(env_defaults, pem):
    calls: list[httpx.Request] = []
    with _client(pem, calls) as (client, _):
        h = _scoped(client, "ws-a")
        with structlog.testing.capture_logs() as logs:
            resp = client.get("/workspaces/ws-a/git-credential", params={"path": "acme/app.git"}, headers=h)
        assert resp.status_code == 200
        assert resp.text == f"username=x-access-token\npassword={_MINTED}\n"
        assert resp.headers["cache-control"] == "no-store"
        body = json.loads(calls[-1].content)
        assert body == {
            "repositories": ["app", "docs"],
            "permissions": {"contents": "write", "pull_requests": "write"},
        }
        token_resp = client.get(
            "/workspaces/ws-a/git-credential", params={"path": "acme/app", "format": "token"}, headers=h
        )
        assert token_resp.text == _MINTED

    (event,) = [e for e in logs if e.get("event") == "audit"]
    assert event["action"] == "github_token.issue"
    assert event["caller_workspace_scope"] == "ws-a"
    assert _MINTED not in repr(event)


def test_scoped_token_cannot_get_repos_outside_its_template_or_workspace(env_defaults, pem):
    with _client(pem, []) as (client, _):
        h = _scoped(client, "ws-a")
        outside = client.get("/workspaces/ws-a/git-credential", params={"path": "acme/lib.git"}, headers=h)
        assert outside.status_code == 403
        other_ws = client.get("/workspaces/ws-b/git-credential", params={"path": "acme/lib.git"}, headers=h)
        assert other_ws.status_code == 403


def test_no_token_for_destroyed_workspace(env_defaults, pem):
    with _client(pem, []) as (client, registry):
        h = _scoped(client, "ws-a")
        client.portal.call(lambda: registry.store.update_status("ws-a", "destroyed"))
        assert client.get("/workspaces/ws-a/git-credential", params={"path": "acme/app"}, headers=h).status_code == 401
        owner = client.get("/workspaces/ws-a/git-credential", params={"path": "acme/app"}, headers=_ADMIN)
        assert owner.status_code == 410


def test_unconfigured_issuer_is_503(env_defaults, pem):
    with _client(pem, []) as (client, _):
        app.state.github_token_issuer = None
        resp = client.get("/workspaces/ws-a/git-credential", params={"path": "acme/app"}, headers=_scoped(client, "ws-a"))
        assert resp.status_code == 503


class _FakeSecretsManager:
    def __init__(self, pem: bytes) -> None:
        self.pem = pem
        self.calls = 0

    def get_secret_value(self, SecretId):  # noqa: N803
        self.calls += 1
        assert SecretId == "warren/github-app-key"
        return {"SecretString": self.pem.decode()}


class _FakeSsm:
    def __init__(self, pem: bytes) -> None:
        self.pem = pem

    def get_parameter(self, Name, WithDecryption):  # noqa: N803
        assert WithDecryption is True
        return {"Parameter": {"Value": self.pem.decode()}}


def test_key_sources(pem, tmp_path):
    sm = _FakeSecretsManager(pem)
    assert SecretsManagerKeySource("warren/github-app-key", client=sm)() == pem
    assert SsmKeySource("/warren/github-app-key", client=_FakeSsm(pem))() == pem

    key_file = tmp_path / "app.pem"
    key_file.write_bytes(pem)
    key_file.chmod(0o644)
    with pytest.raises(TokenIssuerError, match="chmod 600"):
        FileKeySource(key_file)()
    key_file.chmod(0o600)
    assert FileKeySource(key_file)() == pem

    cached = CachedKey(SecretsManagerKeySource("warren/github-app-key", client=sm))
    cached()
    cached()
    assert sm.calls == 2


def test_control_plane_credential_files_point_at_this_workspace():
    from warren.git.token_issuer import control_plane_credential_files

    files = control_plane_credential_files("https://warren.example/", "ws-a", "wrnw_x")
    assert files[".warren/credential-endpoint"][0] == "https://warren.example/workspaces/ws-a/git-credential\n"
    assert files[".warren/credential-auth"] == ("Authorization: Bearer wrnw_x\n", 0o600)


def test_control_plane_issuer_disabled_unless_configured():
    base = dict(
        github_app_id="123",
        github_workspace_token_key_source="",
        github_workspace_token_key_id="",
        github_app_private_key_path=None,
        github_api_base="https://api.github.com",
    )
    assert control_plane_issuer(SimpleNamespace(**base)) is None
    assert control_plane_issuer(SimpleNamespace(**{**base, "github_workspace_token_key_source": "ssm", "github_app_id": ""})) is None
    issuer = control_plane_issuer(SimpleNamespace(**{**base, "github_workspace_token_key_source": "secretsmanager", "github_workspace_token_key_id": "x"}))
    assert isinstance(issuer, GitHubAppMinter)
