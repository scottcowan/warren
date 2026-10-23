"""Audit finding 12: every route except /healthz requires the sidecar token."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from warren_sidecar.app import app

PROTECTED = [
    ("GET", "/diff"),
    ("GET", "/events"),
    ("GET", "/files"),
    ("GET", "/files/x.txt"),
    ("GET", "/agent-state"),
    ("POST", "/exec"),
    ("GET", "/openapi.json"),
    ("GET", "/docs"),
    ("GET", "/no-such-route"),
]


@pytest.mark.parametrize(("method", "path"), PROTECTED)
def test_unauthenticated_request_is_rejected(env_defaults, method, path):
    with TestClient(app) as client:
        response = client.request(method, path, json={"cmd": ["true"]})
    assert response.status_code == 401


@pytest.mark.parametrize(("method", "path"), PROTECTED)
def test_wrong_token_is_rejected(env_defaults, method, path):
    with TestClient(app) as client:
        response = client.request(
            method, path, json={"cmd": ["true"]}, headers={"X-Warren-Sidecar-Token": "wrong"}
        )
    assert response.status_code == 401


def test_diff_and_events_accept_valid_token(env_defaults, auth_headers):
    with TestClient(app) as client:
        assert client.get("/diff", headers=auth_headers).status_code == 200
        assert client.get("/events", headers=auth_headers).status_code == 200


def test_healthz_is_open(env_defaults):
    with TestClient(app) as client:
        assert client.get("/healthz").status_code == 200


def test_unconfigured_token_fails_closed(env_defaults, monkeypatch, auth_headers):
    monkeypatch.delenv("WARREN_SIDECAR_TOKEN")
    with TestClient(app) as client:
        assert client.get("/diff", headers=auth_headers).status_code == 401
        assert client.get("/diff", headers={"X-Warren-Sidecar-Token": ""}).status_code == 401
        assert client.get("/healthz").status_code == 200
