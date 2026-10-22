"""SD-02: POST /exec endpoint (NDJSON subprocess streaming)."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from warren_sidecar.app import app


def test_exec_streams_ndjson(env_defaults, auth_headers):
    with TestClient(app) as client:
        response = client.post(
            "/exec", json={"cmd": ["echo", "hello"]}, headers=auth_headers
        )
    assert response.status_code == 200
    assert "ndjson" in response.headers.get("content-type", "")


def test_exec_each_line_has_type_field(env_defaults, auth_headers):
    with TestClient(app) as client:
        response = client.post(
            "/exec", json={"cmd": ["echo", "hello"]}, headers=auth_headers
        )
    lines = [line for line in response.text.splitlines() if line.strip()]
    assert len(lines) > 0
    for line in lines:
        event = json.loads(line)
        assert "type" in event


def test_exec_requires_auth_header(env_defaults):
    with TestClient(app) as client:
        response = client.post("/exec", json={"cmd": ["echo", "hello"]})
    assert response.status_code == 401
