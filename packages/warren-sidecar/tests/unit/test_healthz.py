"""SD-01: GET /healthz endpoint."""

from __future__ import annotations

from fastapi.testclient import TestClient

from warren_sidecar.app import app


def test_healthz_returns_200(env_defaults):
    with TestClient(app) as client:
        response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_healthz_contains_workspace_id(env_defaults):
    with TestClient(app) as client:
        response = client.get("/healthz")
    assert "workspace_id" in response.json()
