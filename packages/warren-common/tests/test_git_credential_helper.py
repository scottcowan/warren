"""git-credential-warren (assets/warren_git_credential.sh): answers git's `get` for
https://github.com from /run/warren-git/<owner>, and nothing else. Runs the real script."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "src" / "warren_common" / "assets" / "warren_git_credential.sh"
TOKEN = "ghs_" + "a" * 36

# Debian's sh is dash; use it where the host has it.
SH = "/bin/dash" if os.path.exists("/bin/dash") else "/bin/sh"

pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell script")


@pytest.fixture
def tokens(tmp_path):
    d = tmp_path / "warren-git"
    d.mkdir()
    (d / "acme").write_text(TOKEN + "\n")
    (d / "acme").chmod(0o600)
    return d


def _get(tokens: Path, stdin: str, op: str = "get") -> subprocess.CompletedProcess:
    return subprocess.run(
        [SH, str(SCRIPT), op],
        input=stdin,
        env={"PATH": "/usr/bin:/bin", "WARREN_GIT_TOKEN_DIR": str(tokens)},
        capture_output=True,
        text=True,
        timeout=10,
    )


def test_answers_github_https_for_the_owner(tokens):
    r = _get(tokens, "protocol=https\nhost=github.com\npath=acme/app.git\n\n")
    assert r.returncode == 0
    assert r.stdout == f"username=x-access-token\npassword={TOKEN}\n"


def test_owner_match_is_case_insensitive(tokens):
    r = _get(tokens, "protocol=https\nhost=github.com\npath=Acme/app.git\n\n")
    assert TOKEN in r.stdout


@pytest.mark.parametrize(
    "request_",
    [
        "protocol=http\nhost=github.com\npath=acme/app.git\n\n",
        "protocol=https\nhost=gitlab.com\npath=acme/app.git\n\n",
        "protocol=https\nhost=github.com.evil.com\npath=acme/app.git\n\n",
        "protocol=https\nhost=github.com\npath=other/app.git\n\n",
        "protocol=https\nhost=github.com\npath=../acme/app.git\n\n",
        "protocol=https\nhost=github.com\n\n",
    ],
)
def test_says_nothing_for_anything_else(tokens, request_):
    r = _get(tokens, request_)
    assert r.returncode == 0
    assert r.stdout == ""


@pytest.mark.parametrize("op", ["store", "erase"])
def test_store_and_erase_are_noops(tokens, op):
    r = _get(tokens, "protocol=https\nhost=github.com\npath=acme/app.git\npassword=x\n\n", op)
    assert r.returncode == 0 and r.stdout == ""
    assert (tokens / "acme").read_text() == TOKEN + "\n"


def test_symlinked_or_malformed_token_files_are_ignored(tokens, tmp_path):
    other = tmp_path / "elsewhere"
    other.write_text(TOKEN + "\n")
    os.symlink(other, tokens / "linked")
    (tokens / "bad").write_text("ghs x\nusername=evil\n")
    for owner in ("linked", "bad"):
        r = _get(tokens, f"protocol=https\nhost=github.com\npath={owner}/app.git\n\n")
        assert r.stdout == "", owner


def test_only_the_first_line_is_ever_answered(tokens):
    (tokens / "two").write_text(TOKEN + "\nhost=evil.example\n")
    r = _get(tokens, "protocol=https\nhost=github.com\npath=two/app.git\n\n")
    assert r.stdout == f"username=x-access-token\npassword={TOKEN}\n"


def test_no_token_dir_means_no_answer(tmp_path):
    r = _get(tmp_path / "missing", "protocol=https\nhost=github.com\npath=acme/app.git\n\n")
    assert r.returncode == 0 and r.stdout == ""
