"""Host git never resolves a path inside a workspace-writable object store.

The workspace can swap `.git/objects` (or the git dir / work tree) for a
symlink to another workspace's store at any moment, including while host git
runs. shadow_git_dir links the repo's objects into a warren-owned dir through
a no-follow fd, so the swap can't redirect git's reads or writes.
"""

from __future__ import annotations

import errno
import os
import subprocess
import sys
from pathlib import Path

import pytest

if sys.platform == "win32":
    pytest.skip("safe_git shadows git dirs via dir_fd/O_NOFOLLOW: POSIX only", allow_module_level=True)

from warren_common import safe_git
from warren_common.safe_git import (
    SafeGitError,
    readonly_shadow_git_dir,
    run_git,
    shadow_git_dir,
)

_IDENT = {"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t", "GIT_COMMITTER_EMAIL": "t@t"}


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], text=True, capture_output=True, check=True).stdout.strip()


def _repo(path: Path, content: str) -> tuple[Path, str]:
    _git("init", "-q", "-b", "main", str(path))
    (path / "a.txt").write_text(content)
    _git("-C", str(path), "add", "a.txt")
    _git("-C", str(path), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "c")
    return path, _git("-C", str(path), "rev-parse", "HEAD")


def _loose(git_dir: Path, sha: str) -> Path:
    return git_dir / "objects" / sha[:2] / sha[2:]


def _has(git_dir: Path, sha: str) -> bool:
    return subprocess.run(
        ["git", f"--git-dir={git_dir}", "cat-file", "-e", sha], capture_output=True
    ).returncode == 0


def _swap_objects(a: Path, b: Path) -> Path:
    moved = a / ".git" / "objects-moved"
    os.rename(a / ".git" / "objects", moved)
    (a / ".git" / "objects").symlink_to(b / ".git" / "objects")
    return moved


def _commit_in_shadow(sh, message: str) -> str:
    env = {**sh.env(), **_IDENT}
    tree = run_git("write-tree", extra_env=env, isolated=True).strip()
    return run_git("commit-tree", tree, "-p", "HEAD", "-m", message, extra_env=env, isolated=True).strip()


def test_objects_swapped_mid_run_never_reach_other_store(tmp_path: Path):
    a, _ = _repo(tmp_path / "a", "one\n")
    b, b_sha = _repo(tmp_path / "b", "secret-of-b\n")
    with shadow_git_dir(a / ".git", tmp_path / "shadow", [], work_tree=a) as sh:
        moved = _swap_objects(a, b)
        with pytest.raises(SafeGitError):
            run_git("cat-file", "-e", b_sha, extra_env=sh.env(), isolated=True)
        new = _commit_in_shadow(sh, "after swap")
        run_git("update-ref", "refs/heads/main", new, extra_env=sh.env(), isolated=True)
    assert not _has(b / ".git", new)
    assert (moved / new[:2] / new[2:]).is_file()
    assert not _loose(b / ".git", new).exists()


def test_symlink_inside_objects_refused(tmp_path: Path):
    a, _ = _repo(tmp_path / "a", "one\n")
    b, _ = _repo(tmp_path / "b", "two\n")
    _git("-C", str(a), "gc", "-q")
    _git("-C", str(b), "gc", "-q")
    pack = a / ".git" / "objects" / "pack"
    os.rename(pack, tmp_path / "a-pack")
    pack.symlink_to(b / ".git" / "objects" / "pack")
    with pytest.raises(SafeGitError, match="symlink"):
        with shadow_git_dir(a / ".git", tmp_path / "shadow", []):
            pass


def test_symlinked_loose_object_refused(tmp_path: Path):
    a, _ = _repo(tmp_path / "a", "one\n")
    b, b_sha = _repo(tmp_path / "b", "two\n")
    target = _loose(a / ".git", b_sha)
    target.parent.mkdir(exist_ok=True)
    target.symlink_to(_loose(b / ".git", b_sha))
    with pytest.raises(SafeGitError, match="symlink"):
        with shadow_git_dir(a / ".git", tmp_path / "shadow", []):
            pass


def test_git_dir_swapped_mid_run_publishes_nothing(tmp_path: Path):
    a, a_sha = _repo(tmp_path / "a", "one\n")
    b, b_sha = _repo(tmp_path / "b", "two\n")
    b_head = (b / ".git" / "refs" / "heads" / "main").read_text()
    with pytest.raises(SafeGitError, match="replaced"):
        with shadow_git_dir(a / ".git", tmp_path / "shadow", []) as sh:
            os.rename(a / ".git", tmp_path / "a-git")
            (a / ".git").symlink_to(b / ".git")
            run_git("update-ref", "refs/heads/stolen", a_sha, extra_env=sh.env(), isolated=True)
    assert not (b / ".git" / "refs" / "heads" / "stolen").exists()
    assert not (tmp_path / "a-git" / "refs" / "heads" / "stolen").exists()
    assert (b / ".git" / "refs" / "heads" / "main").read_text() == b_head
    assert b_sha in b_head


def test_work_tree_swapped_mid_run_publishes_nothing(tmp_path: Path):
    a, a_sha = _repo(tmp_path / "a", "one\n")
    other = tmp_path / "other"
    other.mkdir()
    tree = tmp_path / "tree"
    tree.mkdir()
    with pytest.raises(SafeGitError, match="replaced"):
        with shadow_git_dir(a / ".git", tmp_path / "shadow", [], work_tree=tree) as sh:
            os.rename(tree, tmp_path / "tree-moved")
            tree.symlink_to(other)
            run_git("update-ref", "refs/heads/stolen", a_sha, extra_env=sh.env(), isolated=True)
    assert not (a / ".git" / "refs" / "heads" / "stolen").exists()


def test_new_objects_published_and_copy_fallback(tmp_path: Path, monkeypatch):
    a, _ = _repo(tmp_path / "a", "one\n")
    _git("-C", str(a), "gc", "-q")

    def no_link(*_args, **_kwargs):
        raise OSError(errno.EXDEV, "cross-device link")

    monkeypatch.setattr(safe_git.os, "link", no_link)
    with shadow_git_dir(a / ".git", tmp_path / "shadow", []) as sh:
        new = _commit_in_shadow(sh, "copied")
        run_git("update-ref", "refs/heads/main", new, extra_env=sh.env(), isolated=True)
    assert _git("-C", str(a), "rev-parse", "main") == new
    _git("-C", str(a), "fsck", "--no-dangling")


def test_readonly_result_voided_when_objects_swapped(tmp_path: Path):
    a, _ = _repo(tmp_path / "a", "one\n")
    b, _ = _repo(tmp_path / "b", "two\n")
    with pytest.raises(SafeGitError):
        with readonly_shadow_git_dir(a / ".git", tmp_path / "shadow", work_tree=a) as sh:
            run_git("rev-parse", "HEAD", extra_env=sh.env(), isolated=True)
            _swap_objects(a, b)


def _unlinkable_sources(monkeypatch) -> list[Path]:
    """os.link fails for repo-side sources (as under protected_hardlinks) and
    records every copy made instead."""
    real_link, real_copy = os.link, safe_git._copy_fd
    copies: list[Path] = []

    def link(src, dst, *args, **kwargs):
        if kwargs.get("src_dir_fd") is not None:
            raise OSError(errno.EPERM, "protected_hardlinks")
        return real_link(src, dst, *args, **kwargs)

    def copy(fd, dst, **kwargs):
        copies.append(Path(dst))
        return real_copy(fd, dst, **kwargs)

    monkeypatch.setattr(safe_git.os, "link", link)
    monkeypatch.setattr(safe_git, "_copy_fd", copy)
    return copies


def test_unlinkable_objects_copied_once_then_reused(tmp_path: Path, monkeypatch):
    a, a_sha = _repo(tmp_path / "a", "one\n")
    shadow_root = tmp_path / "shadow"
    copies = _unlinkable_sources(monkeypatch)
    for _ in range(2):
        with shadow_git_dir(a / ".git", shadow_root, [], work_tree=a) as sh:
            assert run_git("rev-parse", "HEAD", extra_env=sh.env(), isolated=True).strip() == a_sha
            run_git("cat-file", "-p", "HEAD:a.txt", extra_env=sh.env(), isolated=True)
    first = len(copies)
    assert first == 3  # blob, tree, commit
    assert all(p.parent.parent == shadow_root / "object-cache" for p in copies)

    loose = _loose(a / ".git", a_sha)
    data = loose.read_bytes()
    loose.chmod(0o644)
    loose.write_bytes(data)  # same bytes, new ctime: never trusted from cache
    os.unlink(_loose(a / ".git", _git("-C", str(a), "rev-parse", "HEAD:a.txt")))
    with shadow_git_dir(a / ".git", shadow_root, []) as sh:
        run_git("rev-parse", "HEAD", extra_env=sh.env(), isolated=True)
    assert len(copies) == first + 1
    (partition,) = (shadow_root / "object-cache").iterdir()
    assert len(list(partition.iterdir())) == 2  # the removed blob's entry was pruned

    safe_git.drop_object_cache(a / ".git", shadow_root)
    assert not partition.exists()
