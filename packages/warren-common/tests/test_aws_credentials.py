"""AK3 `export` mode: host-side credentials endpoint. No real AWS calls."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from types import SimpleNamespace

import pytest

from warren_common import aws_credentials as ac

_CREDS = {
    "Version": 1,
    "AccessKeyId": "AKIAEXAMPLE",
    "SecretAccessKey": "secret",
    "SessionToken": "session",
    "Expiration": "2030-01-01T00:00:00+00:00",
}


def _get(url: str, token: str | None):
    req = urllib.request.Request(url, headers={"Authorization": token} if token else {})
    try:
        with urllib.request.urlopen(req, timeout=5) as r:
            return r.status, json.loads(r.read())
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def test_export_credentials_runs_host_cli_for_profile(monkeypatch):
    monkeypatch.setattr(ac.shutil, "which", lambda _: "/usr/local/bin/aws")
    seen = {}

    def _run(argv, **kw):
        seen["argv"] = argv
        return SimpleNamespace(returncode=0, stdout=json.dumps(_CREDS))

    assert ac.export_credentials("dev", run=_run)["AccessKeyId"] == "AKIAEXAMPLE"
    assert seen["argv"] == [
        "/usr/local/bin/aws", "configure", "export-credentials",
        "--profile", "dev", "--format", "process",
    ]


def test_export_credentials_expired_session_says_sso_login(monkeypatch):
    monkeypatch.setattr(ac.shutil, "which", lambda _: "/usr/local/bin/aws")
    with pytest.raises(ac.CredentialsUnavailable, match="aws sso login --profile dev"):
        ac.export_credentials("dev", run=lambda *a, **k: SimpleNamespace(returncode=255, stdout=""))


def test_cache_refreshes_before_expiry():
    now = [1000.0]
    fetches = []

    def _fetch():
        fetches.append(now[0])
        return {**_CREDS, "Expiration": "1970-01-01T01:00:00+00:00"}  # epoch 3600

    cache = ac.CredentialCache(_fetch, clock=lambda: now[0], margin=300)
    cache.get()
    now[0] = 3000.0
    cache.get()
    assert len(fetches) == 1
    now[0] = 3301.0
    creds = cache.get()
    assert len(fetches) == 2
    assert creds == {
        "AccessKeyId": "AKIAEXAMPLE",
        "SecretAccessKey": "secret",
        "Token": "session",
        "Expiration": "1970-01-01T01:00:00+00:00",
    }


def test_endpoint_serves_container_credentials_with_token():
    env = ac.start_credentials_endpoint("dev", "ws-1", fork=False, fetch=lambda: dict(_CREDS))
    url = env["AWS_CONTAINER_CREDENTIALS_FULL_URI"]
    token = env["AWS_CONTAINER_AUTHORIZATION_TOKEN"]
    assert url.startswith("http://127.0.0.1:") and url.endswith("/creds/ws-1")
    assert len(token) >= 32

    status, body = _get(url, token)
    assert status == 200
    assert body["AccessKeyId"] == "AKIAEXAMPLE" and body["Token"] == "session"

    assert _get(url, None)[0] == 403
    assert _get(url, "wrong")[0] == 403
    assert _get(url.replace("/creds/ws-1", "/creds/other"), token)[0] == 404


def test_endpoint_reports_expired_host_session():
    def _fetch():
        raise ac.CredentialsUnavailable("run `aws sso login --profile dev` on the host")

    env = ac.start_credentials_endpoint("dev", "ws-1", fork=False, fetch=_fetch)
    status, body = _get(env["AWS_CONTAINER_CREDENTIALS_FULL_URI"], env["AWS_CONTAINER_AUTHORIZATION_TOKEN"])
    assert status == 503
    assert "aws sso login" in body["message"]
