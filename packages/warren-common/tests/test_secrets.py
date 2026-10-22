"""Wave 0 RED tests for SecretLoader and parse_secrets_env (Plan 03 will turn GREEN)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from warren_common import SecretLoader, parse_secrets_env


posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX permissions only")


def test_parse_variants():
    text = (
        "KEY=value\n"
        'KEY2="quoted value"\n'
        "KEY3='single'\n"
        "# a comment\n"
        "\n"
        "export KEY4=x\n"
    )
    result = parse_secrets_env(text)
    assert result == {
        "KEY": "value",
        "KEY2": "quoted value",
        "KEY3": "single",
        "KEY4": "x",
    }


def test_parse_crlf_lines():
    text = "KEY=value\r\nKEY2=other\r\n"
    result = parse_secrets_env(text)
    assert result["KEY"] == "value"
    assert result["KEY2"] == "other"
    assert not any(v.endswith("\r") for v in result.values())


def test_load_local_returns_dict(tmp_projects_dir: Path):
    proj_dir = tmp_projects_dir / "proj"
    proj_dir.mkdir()
    secrets_file = proj_dir / "secrets.env"
    secrets_file.write_text("FOO=bar\nBAZ=qux\n")
    secrets_file.chmod(0o600)
    result = SecretLoader.load_local("proj", tmp_projects_dir)
    assert result == {"FOO": "bar", "BAZ": "qux"}


def test_load_local_missing_file_returns_empty(tmp_projects_dir: Path):
    proj_dir = tmp_projects_dir / "proj"
    proj_dir.mkdir()
    result = SecretLoader.load_local("proj", tmp_projects_dir)
    assert result == {}


@posix_only
def test_perm_warn(tmp_projects_dir: Path, structlog_capture):
    proj_dir = tmp_projects_dir / "proj"
    proj_dir.mkdir()
    secrets_file = proj_dir / "secrets.env"
    secrets_file.write_text("FOO=bar\n")
    secrets_file.chmod(0o644)
    result = SecretLoader.load_local("proj", tmp_projects_dir)
    assert result == {"FOO": "bar"}
    warns = [
        e for e in structlog_capture
        if e.get("event") == "secrets_file_permissions_lax"
    ]
    assert warns, "expected a lax-permission warning"
    assert warns[0].get("mode") == "0o644"
