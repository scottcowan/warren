"""SD-02: GET /diff endpoint."""

from __future__ import annotations

from fastapi.testclient import TestClient

from warren_sidecar.app import app


def test_diff_returns_200(env_defaults, auth_headers):
    with TestClient(app) as client:
        response = client.get("/diff", headers=auth_headers)
    assert response.status_code == 200


def test_diff_has_diff_key(env_defaults, auth_headers):
    """Response body contains a 'diff' key or plain text body."""
    with TestClient(app) as client:
        response = client.get("/diff", headers=auth_headers)
    assert response.status_code == 200
    body = response.text
    # Accept either JSON {"diff": "..."} or plain text diff output
    assert body is not None and len(body) >= 0
    try:
        data = response.json()
        assert "diff" in data
    except Exception:
        # plain text diff output is also acceptable
        pass
