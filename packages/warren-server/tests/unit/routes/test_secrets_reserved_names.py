"""PUT /secrets refuses names that would change how a workspace starts (secrets/names.py)."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from warren.app import app

from .test_secrets import _lifespan_patches, _make_fake_registry, env_defaults  # noqa: F401


@pytest.mark.parametrize(
    "name",
    ["LD_PRELOAD", "PATH", "BASH_ENV", "ENV", "IFS", "GIT_SSH_COMMAND", "AWS_ENDPOINT_URL_KMS",
     "AWS_CONTAINER_CREDENTIALS_FULL_URI", "WARREN_APP", "WARREN_GIT_TOKENS", "HOME", "NODE_OPTIONS"],
)
def test_put_rejects_reserved_env_names_with_422(env_defaults, auth_headers, name):  # noqa: F811
    with _lifespan_patches(_make_fake_registry()):
        with TestClient(app, headers=auth_headers) as client:
            resp = client.put("/secrets", json={"name": name, "value": "v"})
            assert resp.status_code == 422
            assert resp.json()["detail"]["error"] == "reserved_secret_name"
            assert name in resp.json()["detail"]["detail"]
            assert client.get("/secrets").json() == []


@pytest.mark.parametrize(
    "name",
    ["ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY", "GITHUB_TOKEN", "GITHUB_PAT", "AWS_ACCESS_KEY_ID",
     "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_REGION", "AWS_DEFAULT_REGION",
     "WARREN_GIT_SSH_KEY", "WARREN_GIT_SSH_KEY_GITLAB"],
)
def test_put_accepts_provider_and_workload_names(env_defaults, auth_headers, name):  # noqa: F811
    with _lifespan_patches(_make_fake_registry()):
        with TestClient(app, headers=auth_headers) as client:
            assert client.put("/secrets", json={"name": name, "value": "v"}).status_code == 204
