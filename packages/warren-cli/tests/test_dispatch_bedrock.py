"""Bedrock-backed Claude: no OAuth handoff; models via the workspace's own AWS identity.

HOME is a per-test throwaway dir (conftest); the Keychain read is stubbed.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest
import typer

from warren_cli import dispatch as d
from warren_common import harness_config

from test_dispatch_sandbox_hardening import _capture_exec, _provision, _seed_host_claude, host_home  # noqa: F401

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="local POSIX sandbox harness dirs and the os.execvp hand-off"
)

BEDROCK_BODIES = [
    "    app: claude\n    model_access: bedrock\n",
    "    app: claude\n    env:\n      CLAUDE_CODE_USE_BEDROCK: '1'\n",
    "    app: claude\n    env:\n      ANTHROPIC_BEDROCK_BASE_URL: https://bedrock.example\n",
]


@pytest.fixture
def no_keychain(monkeypatch):
    def _fail(*_a):
        raise AssertionError("Keychain read in bedrock mode")

    monkeypatch.setattr(harness_config, "_read_keychain", _fail)


@pytest.mark.parametrize("body", BEDROCK_BODIES)
def test_bedrock_provision_hands_over_no_claude_login(tmp_path, host_home, no_keychain, body):  # noqa: F811
    _seed_host_claude(host_home)
    spec = _provision(tmp_path, body)
    cdir = d._local_harness_root(spec.workspace_id) / "claude"
    assert spec.model_access == "bedrock"
    assert spec.env["CLAUDE_CODE_USE_BEDROCK"] == "1"
    assert cdir.is_dir()
    assert not (cdir / ".credentials.json").exists()


def test_subscription_mode_still_copies_access_token(tmp_path, host_home):  # noqa: F811
    _seed_host_claude(host_home)
    spec = _provision(tmp_path, "    app: claude\n    model_access: subscription\n")
    assert spec.model_access == ""
    assert (d._local_harness_root(spec.workspace_id) / "claude" / ".credentials.json").is_file()


def test_oauth_token_secret_rejected_in_bedrock_mode(tmp_path):
    with pytest.raises(Exception, match="remove secret"):
        _provision(tmp_path, "    app: claude\n    model_access: bedrock\n    secrets:\n      - name: CLAUDE_CODE_OAUTH_TOKEN\n")


def _connect(tmp_path, spec, **extra):
    root = Path(spec.root_path)
    root.mkdir(parents=True, exist_ok=True)
    d._connect_via_execvp({
        "runtime_type": "seatbelt", "app": "claude", "root_path": str(root),
        "workspace_id": spec.workspace_id, "profile_path": str(tmp_path / "sandbox.sb"),
        "harnesses": ["claude"], "harness_root": spec.harness_root, "model_access": spec.model_access,
        "env_snapshot": dict(spec.env), **extra,
    })


def test_bedrock_connect_without_aws_credentials_errors(tmp_path, host_home, no_keychain, monkeypatch, capsys):  # noqa: F811
    spec = _provision(tmp_path, BEDROCK_BODIES[0])
    stale = d._local_harness_root(spec.workspace_id) / "claude" / ".credentials.json"
    stale.write_text('{"claudeAiOauth": {"accessToken": "old"}}')
    calls = _capture_exec(monkeypatch)
    with pytest.raises(typer.Exit):
        _connect(tmp_path, spec, aws={"mode": "export", "profile": ""})
    assert calls == []
    err = capsys.readouterr().err
    assert "Bedrock" in err and "no AWS credentials" in err
    assert not stale.exists()


def test_bedrock_connect_uses_export_credentials_not_profile(tmp_path, host_home, no_keychain, monkeypatch):  # noqa: F811
    import warren_common.aws_credentials as ac

    monkeypatch.setattr(
        ac, "start_credentials_endpoint",
        lambda profile, ws, *, fork=True, fetch=None: {
            "AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://127.0.0.1:1/creds/ws",
            "AWS_CONTAINER_AUTHORIZATION_TOKEN": "tok",
        },
    )
    monkeypatch.setattr(ac, "profile_region", lambda profile: "us-west-2")
    spec = _provision(tmp_path, BEDROCK_BODIES[0] + "    aws:\n      profile: bedrock-dev\n")
    calls = _capture_exec(monkeypatch)
    with pytest.raises(SystemExit):
        _connect(tmp_path, spec, aws={"mode": "export", "profile": "bedrock-dev"})
    env = calls[0][2]
    assert env["CLAUDE_CODE_USE_BEDROCK"] == "1"
    assert env["AWS_CONTAINER_CREDENTIALS_FULL_URI"].startswith("http://127.0.0.1:1/")
    assert env["AWS_REGION"] == "us-west-2"
    assert "AWS_PROFILE" not in env
    assert not (Path(spec.harness_root) / "claude" / ".credentials.json").exists()


def test_bedrock_connect_without_region_errors(tmp_path, host_home, no_keychain, monkeypatch, capsys):  # noqa: F811
    import warren_common.aws_credentials as ac

    monkeypatch.setattr(
        ac, "start_credentials_endpoint",
        lambda profile, ws, *, fork=True, fetch=None: {"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://x/"},
    )
    monkeypatch.setattr(ac, "profile_region", lambda profile: None)
    spec = _provision(tmp_path, BEDROCK_BODIES[0] + "    aws:\n      profile: p\n")
    _capture_exec(monkeypatch)
    with pytest.raises(typer.Exit):
        _connect(tmp_path, spec, aws={"mode": "export", "profile": "p"})
    assert "no AWS region" in capsys.readouterr().err
