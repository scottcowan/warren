"""The reserved-secret-name rule: Python side, and parity with the image's shell loader."""

from __future__ import annotations

import base64
import os
import subprocess
import sys
from pathlib import Path

import pytest
from warren.runtime.ecs_kms_secrets import seal
from warren.runtime.ecs_secrets import encode
from warren.secrets.names import INTERNAL_NAMES, is_deliverable, is_denied

LIB = Path(__file__).parents[3] / "images" / "ecs-base" / "warren-secrets.sh"
SH = "/bin/dash" if os.path.exists("/bin/dash") else "/bin/sh"

DENIED = [
    "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_", "BASH_ENV", "BASH_FUNC_x", "AWS_CONTAINER_CREDENTIALS_FULL_URI",
    "AWS_CONTAINER_AUTHORIZATION_TOKEN", "AWS_ENDPOINT_URL_KMS", "AWS_PROFILE", "AWS_CONFIG_FILE",
    "GIT_SSH_COMMAND", "GIT_CONFIG_GLOBAL", "GIT_CRYPT_KEY", "WARREN_WORKSPACE_ID", "WARREN_APP",
    "WARREN_SECRETS_BLOB",
    *"PATH IFS ENV SHELL HOME PWD OLDPWD USER LOGNAME TMPDIR HISTFILE CDPATH PS1 PS4 PROMPT_COMMAND "
    "NODE_OPTIONS PYTHONPATH PYTHONHOME PERL5LIB RUBYLIB".split(),
]
ALLOWED = [
    "ANTHROPIC_AUTH_TOKEN", "OPENAI_API_KEY", "GITHUB_TOKEN", "GITHUB_PAT", "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_REGION", "AWS_DEFAULT_REGION",
    "WARREN_GIT_SSH_KEY", "WARREN_GIT_SSH_KEY_GITLAB", "MY_PATH", "PATHS", "HOMEDIR", "LDX", "path", "ld_preload",
]


@pytest.mark.parametrize("name", DENIED)
def test_denied(name):
    assert is_denied(name)
    with pytest.raises(ValueError, match=name):
        encode({name: "v"})
    with pytest.raises(ValueError, match=name):
        seal(b"k" * 32, b"w", {name: "v"}, workspace_id="ws-1", container="workspace", region="us-east-1")


@pytest.mark.parametrize("name", ALLOWED)
def test_allowed(name):
    assert not is_denied(name)
    encode({name: "v"})


def test_internal_tokens_name_encodes_for_the_control_plane_only():
    assert is_denied("WARREN_GIT_TOKENS")  # so a user cannot write it (routes/secrets.py)
    assert "WARREN_GIT_TOKENS" in INTERNAL_NAMES and is_deliverable("WARREN_GIT_TOKENS")
    encode({"WARREN_GIT_TOKENS": "acme t"})
    seal(b"k" * 32, b"w", {"WARREN_GIT_TOKENS": "x"}, workspace_id="ws-1", container="workspace", region="us-east-1")


posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell")


@posix_only
@pytest.mark.parametrize("name", DENIED + ALLOWED)
def test_shell_denylist_matches_python(name):
    r = subprocess.run(
        [SH, "-c", f'. "{LIB}"; warren_secret_name_denied "$1" && echo denied || echo ok', "x", name],
        capture_output=True, text=True, timeout=10,
    )
    assert r.stdout.strip() == ("denied" if is_denied(name) else "ok"), r.stderr


@posix_only
def test_shell_lets_the_internal_tokens_name_through():
    r = subprocess.run(
        [SH, "-c", f'. "{LIB}"; warren_secret_name_denied WARREN_GIT_TOKENS && echo denied || echo ok'],
        capture_output=True, text=True, timeout=10,
    )
    assert r.stdout.strip() == "ok"


@posix_only
def test_loader_skips_reserved_names_exports_the_rest_and_never_prints_values(tmp_path):
    secrets = {
        "LD_PRELOAD": "/tmp/evil-VALUE1.so", "BASH_ENV": "/tmp/evil-VALUE2", "PATH": "/tmp/evil-VALUE3",
        "AWS_ENDPOINT_URL_KMS": "http://evil-VALUE4", "GIT_SSH_COMMAND": "evil-VALUE5", "WARREN_APP": "evil-VALUE6",
        "IFS": "x", "ENV": "/tmp/evil-VALUE7",
        "ANTHROPIC_AUTH_TOKEN": "tok-ok", "GITHUB_TOKEN": "gh-ok", "AWS_ACCESS_KEY_ID": "AKIAOK",
        "WARREN_GIT_SSH_KEY": "key-ok", "WARREN_GIT_TOKENS": "acme t",
    }
    f = tmp_path / "secrets.env"
    f.write_text("".join(f"{n}={base64.b64encode(v.encode()).decode()}\n" for n, v in secrets.items()))
    names = "LD_PRELOAD BASH_ENV AWS_ENDPOINT_URL_KMS GIT_SSH_COMMAND WARREN_APP IFS ENV " \
            "ANTHROPIC_AUTH_TOKEN GITHUB_TOKEN AWS_ACCESS_KEY_ID WARREN_GIT_SSH_KEY WARREN_GIT_TOKENS"
    script = (
        f'. "{LIB}"; before=$PATH; warren_secrets_load "{f}"; '
        f'for n in {names}; do eval "v=\\${{$n-<unset>}}"; printf "%s=%s\\n" "$n" "$v"; done; '
        '[ "$PATH" = "$before" ] && echo PATH_OK'
    )
    r = subprocess.run([SH, "-c", script], env={"PATH": "/usr/bin:/bin"}, capture_output=True, text=True, timeout=10)
    assert r.returncode == 0, r.stderr
    out = dict(line.split("=", 1) for line in r.stdout.splitlines() if "=" in line)
    for n in ("LD_PRELOAD", "BASH_ENV", "AWS_ENDPOINT_URL_KMS", "GIT_SSH_COMMAND", "WARREN_APP", "IFS", "ENV"):
        if n != "IFS":  # the shell always has its own IFS; it must just not be "x"
            assert out[n] == "<unset>", n
        else:
            assert out[n] != "x"
        assert f"skipping reserved secret name {n}\n" in r.stderr
    assert "PATH_OK" in r.stdout and "skipping reserved secret name PATH\n" in r.stderr
    assert out["ANTHROPIC_AUTH_TOKEN"] == "tok-ok" and out["GITHUB_TOKEN"] == "gh-ok"
    assert out["AWS_ACCESS_KEY_ID"] == "AKIAOK" and out["WARREN_GIT_SSH_KEY"] == "key-ok"
    assert out["WARREN_GIT_TOKENS"] == "acme t"
    assert "VALUE" not in r.stderr + r.stdout
