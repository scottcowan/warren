"""_patch_claude_onboarding on a workspace's own .claude.json (AG3), with a throwaway HOME (conftest) and a fake `claude`."""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

from warren_cli import dispatch as d

_REAL_CLAUDE_VERSION = d._claude_version
pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="fake /bin/sh `claude` and POSIX mode bits; local sandbox onboarding"
)


@pytest.fixture
def fake_claude(tmp_path, monkeypatch):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    claude = bindir / "claude"
    monkeypatch.setenv("PATH", f"{bindir}:/usr/bin:/bin")
    monkeypatch.setattr(d, "_claude_version", _REAL_CLAUDE_VERSION)

    def _set(output: str) -> None:
        claude.write_text(f"#!/bin/sh\nprintf '%s\\n' '{output}'\n")
        claude.chmod(0o755)

    return _set


def _ws_claude_json() -> Path:
    path = Path.home() / ".warren" / "state" / "ws" / "harness" / "claude" / ".claude.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    return path


def _claude_json(data: dict, mode: int = 0o600) -> Path:
    path = _ws_claude_json()
    path.write_text(json.dumps(data))
    path.chmod(mode)
    return path


@pytest.mark.parametrize("output", ["2.1.307 (Claude Code)", "2.1.307"])
def test_records_parsed_semver(fake_claude, output):
    fake_claude(output)
    path = _claude_json({"lastOnboardingVersion": "Code)", "other": 1}, mode=0o640)
    d._patch_claude_onboarding(path)
    data = json.loads(path.read_text())
    assert data == {
        "lastOnboardingVersion": "2.1.307",
        "other": 1,
        "hasCompletedFirstRun": True,
        "hasCompletedOnboarding": True,
    }
    assert stat.S_IMODE(path.stat().st_mode) == 0o640
    assert [p.name for p in path.parent.iterdir() if p.name.startswith(".claude.json.tmp")] == []


@pytest.mark.parametrize("output", ["Claude Code", "", "v2", "2.1 (Claude Code)"])
def test_unparseable_version_writes_nothing(fake_claude, output):
    fake_claude(output)
    path = _claude_json({"other": 1})
    before = path.read_bytes(), path.stat().st_mtime_ns
    d._patch_claude_onboarding(path)
    assert (path.read_bytes(), path.stat().st_mtime_ns) == before


def test_no_write_when_already_current(fake_claude):
    fake_claude("2.1.307 (Claude Code)")
    path = _claude_json(
        {"hasCompletedFirstRun": True, "hasCompletedOnboarding": True, "lastOnboardingVersion": "2.1.307"}
    )
    inode = path.stat().st_ino
    before = path.read_bytes()
    d._patch_claude_onboarding(path)
    assert path.read_bytes() == before
    assert path.stat().st_ino == inode


def test_invalid_json_left_untouched(fake_claude):
    fake_claude("2.1.307")
    path = _ws_claude_json()
    path.write_text("{not json")
    d._patch_claude_onboarding(path)
    assert path.read_text() == "{not json"


def test_failed_write_leaves_original(fake_claude, monkeypatch):
    fake_claude("2.1.307")
    path = _claude_json({"other": 1})
    before = path.read_bytes()

    def _boom(*_a, **_kw):
        raise OSError("disk full")

    monkeypatch.setattr(d.os, "replace", _boom)
    d._patch_claude_onboarding(path)
    assert path.read_bytes() == before
    assert [p.name for p in path.parent.iterdir() if p.name.startswith(".claude.json.tmp")] == []


def test_home_is_throwaway():
    assert Path.home() != Path(os.path.expanduser("~root"))
    assert "pytest" in str(Path.home())


def test_symlink_never_followed(fake_claude, tmp_path):
    fake_claude("2.1.307")
    host = Path.home() / ".claude.json"
    host.write_text('{"x": 1}')
    path = _ws_claude_json()
    path.symlink_to(host)
    d._patch_claude_onboarding(path)
    assert host.read_text() == '{"x": 1}'
