"""BB12: host-side git never follows repo-supplied object alternates.

Workspace A plants `objects/info/alternates` pointing at workspace B's objects;
no host-side read (status/log/checkout/pull/turn refs) may resolve B's objects,
and nothing of B's may end up in A's repo.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest

if sys.platform == "win32":
    pytest.skip(
        "safe_git shadows git dirs via dir_fd/O_NOFOLLOW reads: POSIX hosts only",
        allow_module_level=True,
    )

from warren_common.safe_git import (
    SafeGitError,
    object_scrubbed_environ,
    own_objects_dir,
    readonly_shadow_git_dir,
    run_git,
    shadow_git_dir,
)
from warren_common.turn_refs import (
    Snapshot,
    apply_snapshot,
    list_refs,
    read_turn_format,
    resolve_snapshot,
)

_IDENT = ["-c", "user.email=t@t", "-c", "user.name=t"]


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], text=True, capture_output=True, check=True).stdout.strip()


def _repo(path: Path, content: str) -> tuple[Path, str]:
    _git("init", "-q", "-b", "main", str(path))
    (path / "a.txt").write_text(content)
    _git("-C", str(path), "add", "a.txt")
    _git("-C", str(path), *_IDENT, "commit", "-qm", content.strip())
    return path, _git("-C", str(path), "rev-parse", "HEAD")


def _has_object(git_dir: Path, sha: str) -> bool:
    """Whether `sha` is in git_dir's *own* objects (alternates ignored)."""
    env = {**object_scrubbed_environ(), "GIT_ALTERNATE_OBJECT_DIRECTORIES": ""}
    alt = git_dir / "objects" / "info" / "alternates"
    saved = alt.read_bytes() if alt.exists() else None
    if saved is not None:
        alt.unlink()
    try:
        return subprocess.run(
            ["git", "--git-dir", str(git_dir), "cat-file", "-e", sha], env=env, capture_output=True
        ).returncode == 0
    finally:
        if saved is not None:
            alt.write_bytes(saved)


@pytest.fixture
def ab(tmp_path: Path) -> tuple[Path, Path, str]:
    """(A, B, B's secret commit); A's alternates point at B's objects and A
    has a ref naming B's commit."""
    upstream, _ = _repo(tmp_path / "upstream", "one\n")
    a = tmp_path / "ws-a" / "repo"
    _git("clone", "-q", str(upstream), str(a))
    b, b_sha = _repo(tmp_path / "ws-b" / "repo", "secret-of-b\n")
    info = a / ".git" / "objects" / "info"
    info.mkdir(exist_ok=True)
    (info / "alternates").write_text(f"{b / '.git' / 'objects'}\n")
    (a / ".git" / "refs" / "heads" / "stolen").write_text(b_sha + "\n")
    # The attack is real: plain git in A resolves B's commit through the file.
    _git("-C", str(a), "cat-file", "-e", b_sha)
    return a, b, b_sha


def test_shadow_refuses_repo_with_alternates(ab, tmp_path: Path):
    a, _b, b_sha = ab
    for name in ("alternates", "http-alternates"):
        info = a / ".git" / "objects" / "info"
        for f in info.iterdir():
            f.unlink()
        (info / name).write_text("/elsewhere\n")
        with pytest.raises(SafeGitError, match="alternates"):
            with shadow_git_dir(a / ".git", tmp_path / "shadow", [], work_tree=a):
                pass
        with pytest.raises(SafeGitError, match="alternates"):
            with readonly_shadow_git_dir(a / ".git", tmp_path / "shadow", work_tree=a):
                pass
    assert not _has_object(a / ".git", b_sha)


def test_symlinked_alternates_and_info_refused(ab, tmp_path: Path):
    a, b, _ = ab
    info = a / ".git" / "objects" / "info"
    (info / "alternates").unlink()
    target = tmp_path / "alt-target"
    target.write_text(f"{b / '.git' / 'objects'}\n")
    (info / "alternates").symlink_to(target)
    with pytest.raises(SafeGitError, match="alternates"):
        own_objects_dir(a / ".git")
    (info / "alternates").unlink()
    info.rmdir()
    elsewhere = tmp_path / "info-elsewhere"
    elsewhere.mkdir()
    (elsewhere / "alternates").write_text(f"{b / '.git' / 'objects'}\n")
    info.symlink_to(elsewhere)
    with pytest.raises(SafeGitError):
        own_objects_dir(a / ".git")


def test_pull_and_checkout_copy_nothing_from_b(ab, tmp_path: Path):
    a, b, b_sha = ab
    config = [("remote.origin.url", str(b)),
              ("remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*")]
    head = (a / ".git" / "HEAD").read_bytes()
    with pytest.raises(SafeGitError):
        with shadow_git_dir(a / ".git", tmp_path / "shadow", config, work_tree=a) as sh:
            run_git("checkout", "-q", "stolen", extra_env=sh.env(), isolated=True)
    assert (a / ".git" / "HEAD").read_bytes() == head
    assert (a / "a.txt").read_text() == "one\n"
    assert not _has_object(a / ".git", b_sha)


def test_turn_ref_reads_refused(ab, tmp_path: Path):
    a, _b, b_sha = ab
    (a / ".git" / "refs" / "git-turn" / "sessions" / "s").mkdir(parents=True)
    (a / ".git" / "refs" / "git-turn" / "sessions" / "s" / "turn-1").write_text(b_sha + "\n")
    shadow = tmp_path / "shadow"
    with pytest.raises(SafeGitError, match="alternates"):
        list_refs(a / ".git", shadow)
    with pytest.raises(SafeGitError, match="alternates"):
        read_turn_format(a / ".git", shadow)
    with pytest.raises(SafeGitError, match="alternates"):
        resolve_snapshot(a / ".git", shadow, "refs/git-turn/sessions/s/turn-1")


def test_apply_snapshot_refuses_source_or_dest_with_alternates(ab, tmp_path: Path):
    a, b, b_sha = ab
    tree = _git("-C", str(b), "rev-parse", "HEAD^{tree}")
    # Source A (alternates -> B) offering B's commit as its snapshot.
    snap = Snapshot("refs/git-turn/sessions/s/turn-1", b_sha, tree, "head-ref-only", a / ".git" / "objects")
    dest, _ = _repo(tmp_path / "dest", "dest\n")
    with pytest.raises(SafeGitError, match="alternates"):
        apply_snapshot(dest / ".git", dest, snap, "warren/branch/x", tmp_path / "shadow")
    assert not _has_object(dest / ".git", b_sha)
    # Destination A (alternates -> B) asked to branch from a clean source.
    src, src_sha = _repo(tmp_path / "src", "src\n")
    clean = Snapshot("r", src_sha, _git("-C", str(src), "rev-parse", "HEAD^{tree}"),
                     "head-ref-only", src / ".git" / "objects")
    with pytest.raises(SafeGitError, match="alternates"):
        apply_snapshot(a / ".git", a, clean, "warren/branch/y", tmp_path / "shadow")
    assert not (a / ".git" / "refs" / "heads" / "warren").exists()


def test_alternates_planted_mid_run_blocks_write_back(tmp_path: Path):
    a, _ = _repo(tmp_path / "a", "one\n")
    b, b_sha = _repo(tmp_path / "b", "secret-of-b\n")
    with pytest.raises(SafeGitError, match="alternates"):
        with shadow_git_dir(a / ".git", tmp_path / "shadow", []) as sh:
            info = a / ".git" / "objects" / "info"
            info.mkdir(exist_ok=True)
            (info / "alternates").write_text(f"{b / '.git' / 'objects'}\n")
            run_git("update-ref", "refs/heads/stolen", b_sha, extra_env=sh.env(), isolated=True)
    assert not (a / ".git" / "refs" / "heads" / "stolen").exists()


def test_env_alternates_and_object_dir_ignored(tmp_path: Path, monkeypatch):
    a, a_sha = _repo(tmp_path / "a", "one\n")
    b, b_sha = _repo(tmp_path / "b", "secret-of-b\n")
    monkeypatch.setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", str(b / ".git" / "objects"))
    monkeypatch.setenv("GIT_OBJECT_DIRECTORY", str(b / ".git" / "objects"))
    assert "GIT_ALTERNATE_OBJECT_DIRECTORIES" not in object_scrubbed_environ()
    assert "GIT_OBJECT_DIRECTORY" not in object_scrubbed_environ()
    with shadow_git_dir(a / ".git", tmp_path / "shadow", [], work_tree=a) as sh:
        assert sh.env()["GIT_ALTERNATE_OBJECT_DIRECTORIES"] == ""
        assert run_git("rev-parse", "HEAD", extra_env=sh.env(), isolated=True).strip() == a_sha
        with pytest.raises(SafeGitError):
            run_git("cat-file", "-e", b_sha, extra_env=sh.env(), isolated=True)
        run_git("status", "--porcelain", extra_env=sh.env(), isolated=True)
        run_git("log", "--oneline", extra_env=sh.env(), isolated=True)
    with readonly_shadow_git_dir(a / ".git", tmp_path / "shadow", work_tree=a) as sh:
        with pytest.raises(SafeGitError):
            run_git("cat-file", "-e", b_sha, extra_env=sh.env(), isolated=True)


def test_objects_dir_symlink_refused(tmp_path: Path):
    a, _ = _repo(tmp_path / "a", "one\n")
    b, _ = _repo(tmp_path / "b", "two\n")
    os.rename(a / ".git" / "objects", tmp_path / "moved")
    (a / ".git" / "objects").symlink_to(b / ".git" / "objects")
    with pytest.raises(SafeGitError):
        own_objects_dir(a / ".git")


def test_normal_repo_unaffected(tmp_path: Path):
    a, a_sha = _repo(tmp_path / "a", "one\n")
    assert own_objects_dir(a / ".git") == a / ".git" / "objects"
    with shadow_git_dir(a / ".git", tmp_path / "shadow", [], work_tree=a) as sh:
        run_git("branch", "feature", extra_env=sh.env(), isolated=True)
        run_git("checkout", "-q", "feature", extra_env=sh.env(), isolated=True)
    assert _git("-C", str(a), "rev-parse", "feature") == a_sha
    assert _git("-C", str(a), "symbolic-ref", "--short", "HEAD") == "feature"
