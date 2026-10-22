"""AK2: git-crypt policy -- `none` never unlocks, `unlock_and_drop` decrypts then drops the key."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path

import pytest

from warren_common.git_crypt import (
    GitCryptError,
    apply_git_crypt_policy,
    check_key_not_delivered,
    encrypted_paths,
)
from warren_common.models import ProjectConfig
from warren_common.templates import resolve_template

requires_git_crypt = pytest.mark.skipif(not shutil.which("git-crypt"), reason="git-crypt not installed")

_SECRET = "hunter2-plaintext"
_GIT_ENV_ARGS = ["-c", "user.email=t@example.com", "-c", "user.name=t", "-c", "init.defaultBranch=main"]


def _run(*args: str, cwd: Path, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(list(args), cwd=cwd, capture_output=True, text=True, check=check)


@pytest.fixture
def encrypted_repo(tmp_path: Path) -> tuple[Path, bytes]:
    """A bare store + per-workspace worktree (warren's layout) of a git-crypt repo."""
    src = tmp_path / "src"
    src.mkdir()
    _run("git", *_GIT_ENV_ARGS, "init", "-q", cwd=src)
    _run("git-crypt", "init", cwd=src)
    (src / ".gitattributes").write_text("secret/** filter=git-crypt diff=git-crypt\n")
    (src / "secret").mkdir()
    (src / "secret" / "a.txt").write_text(_SECRET + "\n")
    (src / "README").write_text("public\n")
    _run("git", "add", ".", cwd=src)
    _run("git", *_GIT_ENV_ARGS, "commit", "-qm", "init", cwd=src)
    key_file = tmp_path / "exported.key"
    _run("git-crypt", "export-key", str(key_file), cwd=src)
    bare = tmp_path / "store.git"
    _run("git", "clone", "-q", "--bare", str(src), str(bare), cwd=tmp_path)
    wt = tmp_path / "ws" / "code" / "app"
    _run("git", "-C", str(bare), "worktree", "add", "-q", "-b", "warren/ws", str(wt), "main", cwd=tmp_path)
    return wt, key_file.read_bytes()


def _git_crypt_dirs(wt: Path) -> list[Path]:
    out = _run("git", "rev-parse", "--path-format=absolute", "--git-dir", "--git-common-dir", cwd=wt).stdout
    return [Path(p) / "git-crypt" for p in out.split()]


@requires_git_crypt
def test_none_keeps_ciphertext_and_no_key(encrypted_repo):
    wt, _ = encrypted_repo
    stale = _git_crypt_dirs(wt)[0] / "keys"
    stale.mkdir(parents=True)
    (stale / "default").write_bytes(b"stale key")

    result = apply_git_crypt_policy(wt, "none")

    assert result.uses_git_crypt
    assert (wt / "secret" / "a.txt").read_bytes().startswith(b"\x00GITCRYPT")
    assert not any(d.exists() for d in _git_crypt_dirs(wt))


@requires_git_crypt
def test_unlock_and_drop_decrypts_checkout_then_removes_key(encrypted_repo, monkeypatch):
    wt, key = encrypted_repo
    staged: list[str] = []
    real_mkdtemp = tempfile.mkdtemp

    def _mkdtemp(*a, **k):
        staged.append(real_mkdtemp(*a, **k))
        return staged[-1]

    monkeypatch.setattr(tempfile, "mkdtemp", _mkdtemp)

    result = apply_git_crypt_policy(wt, "unlock_and_drop", key)

    assert (wt / "secret" / "a.txt").read_text().strip() == _SECRET
    assert result.decrypted_paths == ["secret/a.txt"]
    assert "skip-worktree" in (result.message or "")
    assert not any(d.exists() for d in _git_crypt_dirs(wt))
    assert staged and not Path(staged[0]).exists()

    assert _run("git-crypt", "unlock", cwd=wt, check=False).returncode != 0
    history = _run("git", "log", "-p", "--", "secret/a.txt", cwd=wt).stdout
    assert _SECRET not in history
    assert _run("git", "status", "--porcelain", cwd=wt).stdout == ""

    (wt / "secret" / "a.txt").write_text("edited\n")
    assert _run("git", "status", "--porcelain", cwd=wt).stdout == ""
    commit = _run("git", *_GIT_ENV_ARGS, "commit", "-am", "try", cwd=wt, check=False)
    assert commit.returncode != 0
    shown = subprocess.run(["git", "show", "HEAD:secret/a.txt"], cwd=wt, capture_output=True, check=True)
    assert shown.stdout.startswith(b"\x00GITCRYPT")


@requires_git_crypt
def test_unlock_and_drop_without_key_fails(encrypted_repo):
    wt, _ = encrypted_repo
    with pytest.raises(GitCryptError, match="needs the git-crypt key"):
        apply_git_crypt_policy(wt, "unlock_and_drop", None)


@requires_git_crypt
def test_wrong_key_fails_and_leaves_no_key(encrypted_repo, tmp_path):
    wt, _ = encrypted_repo
    other = tmp_path / "other"
    other.mkdir()
    _run("git", *_GIT_ENV_ARGS, "init", "-q", cwd=other)
    _run("git-crypt", "init", cwd=other)
    _run("git-crypt", "export-key", str(tmp_path / "wrong.key"), cwd=other)
    with pytest.raises(GitCryptError):
        apply_git_crypt_policy(wt, "unlock_and_drop", (tmp_path / "wrong.key").read_bytes())
    assert not any(d.exists() for d in _git_crypt_dirs(wt))


def test_repo_without_git_crypt_is_untouched(tmp_path):
    _run("git", *_GIT_ENV_ARGS, "init", "-q", cwd=tmp_path)
    (tmp_path / "f").write_text("x")
    _run("git", "add", "f", cwd=tmp_path)
    assert encrypted_paths(tmp_path) == []
    assert not apply_git_crypt_policy(tmp_path, "unlock_and_drop", None).uses_git_crypt


def test_key_secret_must_not_be_delivered_as_workspace_secret():
    check_key_not_delivered(["API_KEY"], "GIT_CRYPT_KEY")
    with pytest.raises(GitCryptError):
        check_key_not_delivered(["API_KEY", "GIT_CRYPT_KEY"], "GIT_CRYPT_KEY")


def test_policy_defaults_to_none_and_templates_override():
    root = ProjectConfig.model_validate(
        {"name": "vault", "templates": {"agent": {}, "human": {"git_crypt": "unlock_and_drop"}}}
    )
    assert root.git_crypt == "none"
    assert resolve_template(root, "agent").git_crypt == "none"
    assert resolve_template(root, "human").git_crypt == "unlock_and_drop"
    with pytest.raises(ValueError):
        ProjectConfig.model_validate({"git_crypt": "unlock"})
