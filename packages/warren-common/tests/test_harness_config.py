"""AG3: per-workspace harness config dirs, seeded on a throwaway HOME (conftest)."""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

import pytest

from warren_common import agent_state
from warren_common.harness import harness_dirs
from warren_common.harness_config import _read_keychain as _REAL_READ_KEYCHAIN
from warren_common.harness_config import copy_in_credentials, prepare_harness_dirs

pytestmark = pytest.mark.skipif(
    sys.platform == "win32",
    reason="fd-relative O_NOFOLLOW writes, POSIX mode bits, symlinks and the macOS `security` broker",
)


@pytest.fixture
def home():
    home = Path.home()
    (home / ".claude").mkdir()
    (home / ".claude" / "settings.json").write_text(
        json.dumps({"model": "opus", "env": {"ANTHROPIC_API_KEY": "sk"}, "apiKeyHelper": "x"})
    )
    (home / ".claude" / "CLAUDE.md").write_text("host instructions\n")
    (home / ".claude" / ".credentials.json").write_text('{"t": 1}')
    return home


def _mode(p: Path) -> int:
    return stat.S_IMODE(p.lstat().st_mode)


def test_seeds_non_secret_settings_read_only(home, tmp_path):
    root = tmp_path / "harness"
    prepare_harness_dirs(["claude"], root, home=home)
    cdir = root / "claude"
    settings = json.loads((cdir / "settings.json").read_text())
    assert settings.pop("hooks") == json.loads(agent_state.claude_settings())["hooks"]
    assert settings == {"model": "opus"}
    assert _mode(cdir / "settings.json") == 0o400
    assert (cdir / "CLAUDE.md").read_text() == "host instructions\n"
    assert (cdir / "hooks").is_dir() and (cdir / "projects").is_dir()
    assert not (cdir / ".credentials.json").exists()
    assert _mode(root) == 0o700


def test_unparseable_settings_not_seeded(home, tmp_path):
    (home / ".claude" / "settings.json").write_text("{nope")
    prepare_harness_dirs(["claude"], tmp_path, home=home)
    assert json.loads((tmp_path / "claude" / "settings.json").read_text()) == json.loads(agent_state.claude_settings())


def test_generated_config_rewritten_and_harness_state_kept(home, tmp_path):
    prepare_harness_dirs(["codex", "claude"], tmp_path, home=home)
    toml = tmp_path / "codex" / "config.toml"
    toml.chmod(0o644)
    toml.write_text("tampered = true\n")
    cj = tmp_path / "claude" / ".claude.json"
    cj.write_text('{"projects": {}}')
    prepare_harness_dirs(["codex", "claude"], tmp_path, home=home)
    assert toml.read_text().startswith("approval_policy")
    assert _mode(toml) == 0o400
    assert cj.read_text() == '{"projects": {}}'


def test_planted_symlinks_replaced_not_followed(home, tmp_path):
    victim = home / "victim"
    victim.write_text("keep")
    victim_dir = home / "victim-dir"
    victim_dir.mkdir()
    prepare_harness_dirs(["codex"], tmp_path, home=home)
    toml = tmp_path / "codex" / "config.toml"
    toml.unlink()
    toml.symlink_to(victim)
    prepare_harness_dirs(["codex"], tmp_path, home=home)
    assert victim.read_text() == "keep" and not toml.is_symlink()

    import shutil

    shutil.rmtree(tmp_path / "codex")
    (tmp_path / "codex").symlink_to(victim_dir)
    prepare_harness_dirs(["codex"], tmp_path, home=home)
    assert list(victim_dir.iterdir()) == []
    assert (tmp_path / "codex").is_dir() and not (tmp_path / "codex").is_symlink()


def test_credentials_copied_in_one_way(home, tmp_path):
    copied = copy_in_credentials(["claude", "codex"], tmp_path, home=home)
    creds = tmp_path / "claude" / ".credentials.json"
    assert copied == [str(creds)]
    assert _mode(creds) == 0o600
    creds.write_text('{"t": "sandbox"}')
    copy_in_credentials(["claude"], tmp_path, home=home)
    assert (home / ".claude" / ".credentials.json").read_text() == '{"t": 1}'
    assert creds.read_text() == '{"t": 1}'


def test_custom_and_unselected_get_no_dir(home, tmp_path):
    prepare_harness_dirs(["custom", "pi"], tmp_path, home=home)
    assert sorted(p.name for p in tmp_path.iterdir()) == [".hooks", ".session", "pi"]
    prepare_harness_dirs(["custom"], tmp_path / "none", home=home)
    assert not (tmp_path / "none").exists()


def test_session_dir_is_granted_and_created_for_the_shell(home, tmp_path):
    """AG4: the warren shell records the running harness under <root>/.session."""
    from warren_common.harness import sandbox_grants

    grants = sandbox_grants(["codex"], home=home, root=tmp_path)
    assert str(tmp_path / ".session") in grants.write
    assert "/var/lib/warren/harness/.session" in harness_dirs(["codex"], "/var/lib/warren/harness")
    assert harness_dirs(["custom"], "/var/lib/warren/harness") == []


def test_server_harness_dirs():
    dirs = harness_dirs(["opencode", "codex"], "/var/lib/warren/harness")
    assert "/var/lib/warren/harness/opencode/config" in dirs
    assert "/var/lib/warren/harness/opencode/data" in dirs
    assert "/var/lib/warren/harness/codex/sessions" in dirs
    assert not any(d.endswith(".db") for d in dirs)


_BLOB = {"claudeAiOauth": {"accessToken": "at", "refreshToken": "rt", "expiresAt": 1}}


def test_claude_keychain_service_naming_matches_claude_code():
    import hashlib

    from warren_common.harness import PROFILES
    from warren_common.harness_config import keychain_service

    p = PROFILES["claude"]
    base = "Claude Code-credentials"
    h = lambda s: hashlib.sha256(s.encode()).hexdigest()[:8]  # noqa: E731
    assert keychain_service(p, base, {}) == base
    assert keychain_service(p, base, {"CLAUDE_CONFIG_DIR": ""}) == base
    assert keychain_service(p, base, {"CLAUDE_CONFIG_DIR": "/c"}) == f"{base}-{h('/c')}"
    assert keychain_service(p, base, {"CLAUDE_CONFIG_DIR": "/c", "CLAUDE_SECURESTORAGE_CONFIG_DIR": ""}) == base
    assert keychain_service(p, base, {"CLAUDE_SECURESTORAGE_CONFIG_DIR": "/s"}) == f"{base}-{h('/s')}"


def test_keychain_token_brokered_without_refresh_token(home, tmp_path, monkeypatch):
    from warren_common import harness_config

    calls = []

    def _fake(service, account):
        calls.append((service, account))
        return json.dumps(_BLOB).encode()

    monkeypatch.setattr(harness_config, "_read_keychain", _fake)
    copy_in_credentials(["claude", "codex"], tmp_path, home=home, env={"USER": "op"})
    assert calls == [("Claude Code-credentials", "op")]
    creds = tmp_path / "claude" / ".credentials.json"
    assert json.loads(creds.read_text()) == {"claudeAiOauth": {"accessToken": "at", "expiresAt": 1}}
    assert _mode(creds) == 0o600


def test_file_credentials_used_when_keychain_has_none(home, tmp_path):
    (home / ".claude" / ".credentials.json").write_text(json.dumps(_BLOB))
    copy_in_credentials(["claude"], tmp_path, home=home, env={"USER": "op"})
    assert "refreshToken" not in (tmp_path / "claude" / ".credentials.json").read_text()


def test_read_keychain_only_on_macos_via_absolute_security(monkeypatch):
    import subprocess
    import sys
    from types import SimpleNamespace

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: pytest.fail("ran security"))
    assert _REAL_READ_KEYCHAIN("Claude Code-credentials", "op") is None

    argv = []
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr("os.path.isfile", lambda p: True)
    monkeypatch.setattr(
        subprocess, "run", lambda a, **k: argv.append(a) or SimpleNamespace(returncode=44, stdout=b"")
    )
    assert _REAL_READ_KEYCHAIN("svc", "op") is None
    assert argv == [["/usr/bin/security", "find-generic-password", "-a", "op", "-w", "-s", "svc"]]


def test_remove_credentials_deletes_copies_without_following(home, tmp_path):
    from warren_common.harness_config import remove_credentials

    copy_in_credentials(["claude"], tmp_path, home=home)
    assert remove_credentials(["claude", "codex"], tmp_path) == [str(tmp_path / "claude" / ".credentials.json")]
    victim = home / "victim"
    victim.write_text("keep")
    (tmp_path / "claude" / ".credentials.json").symlink_to(victim)
    remove_credentials(["claude"], tmp_path)
    assert victim.read_text() == "keep"
    assert not (tmp_path / "claude" / ".credentials.json").exists()
    assert remove_credentials(["claude"], tmp_path) == []
