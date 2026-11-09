"""ecs-base's warren-git-token: installs git_write tokens from stdin or a KMS envelope
(through warren-secrets-decrypt), removes them. Runs the real script as non-root with
its test hooks (a temp token dir and a fake decrypt helper); never prints a token."""

from __future__ import annotations

import base64
import os
import stat
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[3] / "images" / "ecs-base" / "warren-git-token.sh"
TOKEN_A = "ghs_" + "a" * 36
TOKEN_B = "ghs_" + "b" * 36

# Debian's sh is dash; use it where the host has it.
SH = "/bin/dash" if os.path.exists("/bin/dash") else "/bin/sh"

pytestmark = pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0, reason="runs the POSIX script as non-root"
)


def _run(tmp_path, *args, stdin="", env=None):
    full = {"PATH": "/usr/bin:/bin", "WARREN_GIT_TOKEN_DIR": str(tmp_path / "warren-git"), **(env or {})}
    return subprocess.run(
        [SH, str(SCRIPT), *args], input=stdin, env=full, capture_output=True, text=True, timeout=10
    )


def test_install_writes_one_private_file_per_owner(tmp_path):
    r = _run(tmp_path, "install", stdin=f"acme {TOKEN_A}\nother {TOKEN_B}")
    assert r.returncode == 0, r.stderr
    assert r.stdout == "warren-git-token: installed 2\n"
    d = tmp_path / "warren-git"
    assert stat.S_IMODE(d.stat().st_mode) == 0o755
    for owner, token in (("acme", TOKEN_A), ("other", TOKEN_B)):
        f = d / owner
        assert f.read_text() == token + "\n"
        assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert sorted(p.name for p in d.iterdir()) == ["acme", "other"]  # no temp files left
    assert TOKEN_A not in r.stdout + r.stderr


def test_install_replaces_and_skips_malformed_lines(tmp_path):
    _run(tmp_path, "install", stdin=f"acme {TOKEN_A}\n")
    r = _run(
        tmp_path, "install",
        stdin=f"acme {TOKEN_B}\n../etc {TOKEN_A}\n-x {TOKEN_A}\nUPPER {TOKEN_A}\nbad tok;en\n\n",
    )
    assert r.stdout == "warren-git-token: installed 1\n"
    d = tmp_path / "warren-git"
    assert (d / "acme").read_text() == TOKEN_B + "\n"
    assert sorted(p.name for p in d.iterdir()) == ["acme"]


def test_install_refuses_a_symlinked_token_dir(tmp_path):
    (tmp_path / "target").mkdir()
    os.symlink(tmp_path / "target", tmp_path / "warren-git")
    r = _run(tmp_path, "install", stdin=f"acme {TOKEN_A}\n")
    assert r.returncode != 0
    assert list((tmp_path / "target").iterdir()) == []


def _fake_decrypt(tmp_path, payload_lines: str, expect_blob="ENVELOPE") -> Path:
    fake = tmp_path / "decrypt"
    fake.write_text(
        "#!/bin/sh\n"
        '[ "$1" = workspace ] || exit 3\n'
        f'[ "$WARREN_SECRETS_BLOB" = {expect_blob} ] || exit 4\n'
        '[ "$WARREN_WORKSPACE_ID" = ws-1 ] || exit 5\n'
        f"printf '%s\\n' '{payload_lines}'\n"
    )
    fake.chmod(0o755)
    return fake


def test_install_envelope_decrypts_and_installs(tmp_path):
    b64 = base64.b64encode(f"acme {TOKEN_A}\n".encode()).decode()
    fake = _fake_decrypt(tmp_path, f"OTHER=eA==\nWARREN_GIT_TOKENS={b64}")
    r = _run(
        tmp_path, "install-envelope",
        env={"WARREN_SECRETS_BLOB": "ENVELOPE", "WARREN_WORKSPACE_ID": "ws-1", "WARREN_SECRETS_DECRYPT": str(fake)},
    )
    assert r.returncode == 0, r.stderr
    assert r.stdout == "warren-git-token: installed 1\n"
    assert (tmp_path / "warren-git" / "acme").read_text() == TOKEN_A + "\n"


def test_install_envelope_fails_closed(tmp_path):
    fake = _fake_decrypt(tmp_path, "OTHER=eA==")
    env = {"WARREN_SECRETS_BLOB": "ENVELOPE", "WARREN_WORKSPACE_ID": "ws-1", "WARREN_SECRETS_DECRYPT": str(fake)}
    assert _run(tmp_path, "install-envelope", env=env).returncode != 0
    assert _run(tmp_path, "install-envelope", env={**env, "WARREN_SECRETS_BLOB": "WRONG"}).returncode != 0
    assert _run(tmp_path, "install-envelope", env={"WARREN_SECRETS_DECRYPT": str(fake)}).returncode != 0
    assert not (tmp_path / "warren-git").exists() or not any((tmp_path / "warren-git").iterdir())


def test_remove_drops_every_token(tmp_path):
    _run(tmp_path, "install", stdin=f"acme {TOKEN_A}\n")
    r = _run(tmp_path, "remove")
    assert r.returncode == 0
    assert not (tmp_path / "warren-git").exists()


def test_root_ignores_the_test_hooks():
    text = SCRIPT.read_text()
    hooks = text.index('if [ "$(id -u)" != 0 ]; then')
    assert "dir=/run/warren-git" in text[:hooks]
    assert "decrypt=/usr/local/bin/warren-secrets-decrypt" in text[:hooks]


IMAGES = SCRIPT.parent


def test_entrypoint_never_lets_the_tokens_reach_a_workspace_process(tmp_path):
    lib = IMAGES / "warren-secrets.sh"
    text = (IMAGES / "entrypoint.sh").read_text()
    text = text.replace("/usr/local/lib/warren/secrets.sh", str(lib))
    text = text.replace("/var/lib/warren", str(tmp_path / "vol"))
    entry = tmp_path / "entrypoint.sh"
    entry.write_text(text)
    d = tmp_path / "vol" / ".warren"
    d.mkdir(parents=True)
    payload = base64.b64encode(f"acme {TOKEN_A}\n".encode()).decode()
    (d / "workspace.env").write_text(
        f"WARREN_GIT_TOKENS={payload}\nAPI_KEY={base64.b64encode(b'k').decode()}\n"
    )
    out = tmp_path / "out"
    app = f'printf "%s|%s" "${{WARREN_GIT_TOKENS:-unset}}" "$API_KEY" > {out}'
    r = subprocess.run(
        [SH, str(entry)],
        env={"PATH": os.environ["PATH"], "HOME": str(tmp_path), "WARREN_APP_CMD": app},
        capture_output=True, text=True, timeout=20,
    )
    assert r.returncode == 0, r.stderr
    assert out.read_text() == "unset|k"
    assert TOKEN_A not in r.stdout + r.stderr


def test_image_installs_before_dropping_root_and_sessions_unset_the_variable():
    entry = (IMAGES / "entrypoint.sh").read_text()
    drop = entry.index("exec /sbin/su-exec warren:warren")
    assert entry.index("/usr/local/bin/warren-git-token install") < drop
    assert entry.index("unset WARREN_GIT_TOKENS") < drop
    session = (IMAGES / "warren-session.sh").read_text()
    assert (
        session.index("warren_secrets_load /run/warren/secrets.env")
        < session.index("unset WARREN_GIT_TOKENS")
        < session.index("exec /sbin/su-exec warren:warren")
    )
    dockerfile = (IMAGES / "Dockerfile").read_text()
    assert "warren-git-token.sh /usr/local/bin/warren-git-token" in dockerfile
    assert "warren_git_credential.sh /usr/local/bin/git-credential-warren" in dockerfile
    assert "credential.https://github.com.helper /usr/local/bin/git-credential-warren" in dockerfile
