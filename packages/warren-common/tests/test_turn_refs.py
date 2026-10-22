"""Turn-ref protocol reader/writer (HIST-05/09/10/11), against real git repos."""

from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path

import pytest

from test_safe_git import plant_hostile
from warren_common.safe_git import SafeGitError
from warren_common.turn_refs import (
    Snapshot,
    TurnRefError,
    TurnRefNotFound,
    apply_snapshot,
    list_refs,
    read_turn_format,
    resolve_snapshot,
    worktree_git_dir,
    write_session_file,
)

_IDENT = ["-c", "user.email=t@t", "-c", "user.name=t"]
_GIT_TURN_FORMAT = {
    "version": "1",
    "tool": "git-turn",
    "schema": "turns/v1",
    "ref_pattern": "refs/git-turn/sessions/{id}/turn-{N}",
    "notes_ref": "refs/notes/git-turn",
}


def _git(*args: str, cwd: Path | None = None, input: str | None = None) -> str:
    return subprocess.run(
        ["git", *args], cwd=cwd, input=input, text=True, capture_output=True, check=True
    ).stdout.strip()


def _repo(path: Path) -> Path:
    _git("init", "-q", "-b", "main", str(path))
    (path / "a.txt").write_text("one\n")
    _git("-C", str(path), "add", "a.txt")
    _git("-C", str(path), *_IDENT, "commit", "-qm", "one")
    return path


def _write_format(repo: Path, fmt: dict | str) -> None:
    body = fmt if isinstance(fmt, str) else json.dumps(fmt)
    blob = _git("-C", str(repo), "hash-object", "-w", "--stdin", input=body)
    _git("-C", str(repo), "update-ref", "refs/git-turn/format", blob)


def _snapshot_turn(repo: Path, session: str, n: int) -> str:
    """A git-turn style dangling snapshot: worktree tree, index tree as parent."""
    index_tree = _git("-C", str(repo), "write-tree")
    index_commit = _git("-C", str(repo), *_IDENT, "commit-tree", index_tree, "-m", "index")
    env = {**os.environ, "GIT_INDEX_FILE": str(repo / ".git" / "turn-index")}
    subprocess.run(["git", "-C", str(repo), "add", "-A"], env=env, check=True)
    tree = subprocess.run(
        ["git", "-C", str(repo), "write-tree"], env=env, check=True, capture_output=True, text=True
    ).stdout.strip()
    sha = _git("-C", str(repo), *_IDENT, "commit-tree", tree, "-p", index_commit, "-m", f"turn {n}")
    _git("-C", str(repo), "update-ref", f"refs/git-turn/sessions/{session}/turn-{n}", sha)
    return sha


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    return _repo(tmp_path / "src")


def test_format_falls_back_to_head_ref_only(repo, tmp_path):
    assert read_turn_format(repo / ".git", tmp_path / "shadow") == {"snapshot_model": "head-ref-only"}


def test_git_turn_format_defaults_to_two_tree(repo, tmp_path):
    _write_format(repo, _GIT_TURN_FORMAT)
    fmt = read_turn_format(repo / ".git", tmp_path / "shadow")
    assert fmt["tool"] == "git-turn"
    assert fmt["snapshot_model"] == "two-tree-dangling-commit"


def test_explicit_snapshot_model_wins(repo, tmp_path):
    _write_format(repo, {**_GIT_TURN_FORMAT, "snapshot_model": "session-branch-commit"})
    assert read_turn_format(repo / ".git", tmp_path / "shadow")["snapshot_model"] == "session-branch-commit"


@pytest.mark.parametrize("body", ["not json", "[1, 2]", json.dumps({"x": "y" * 70_000})])
def test_bad_format_blob_rejected(repo, tmp_path, body):
    _write_format(repo, body)
    with pytest.raises(TurnRefError):
        read_turn_format(repo / ".git", tmp_path / "shadow")


def test_list_refs_filters_by_prefix(repo, tmp_path):
    sha = _snapshot_turn(repo, "abc", 1)
    _git("-C", str(repo), "update-ref", "refs/other/x", sha)
    refs = list_refs(repo / ".git", tmp_path / "shadow", "refs/git-turn/sessions/")
    assert refs == [{"ref": "refs/git-turn/sessions/abc/turn-1", "sha": sha}]
    assert {r["ref"] for r in list_refs(repo / ".git", tmp_path / "shadow", "refs/")} >= {
        "refs/heads/main", "refs/other/x"
    }


def test_list_refs_sees_packed_refs(repo, tmp_path):
    sha = _snapshot_turn(repo, "abc", 1)
    _git("-C", str(repo), "pack-refs", "--all")
    assert list_refs(repo / ".git", tmp_path / "shadow") == [
        {"ref": "refs/git-turn/sessions/abc/turn-1", "sha": sha}
    ]


@pytest.mark.parametrize("prefix", ["heads/", "refs/../x", "refs//x", "--all", "refs/$(id)", "refs/a b"])
def test_list_refs_rejects_bad_prefix(repo, tmp_path, prefix):
    with pytest.raises(TurnRefError):
        list_refs(repo / ".git", tmp_path / "shadow", prefix)


def test_hostile_config_never_runs(repo, tmp_path):
    _write_format(repo, _GIT_TURN_FORMAT)
    _snapshot_turn(repo, "abc", 1)
    marker = plant_hostile(repo / ".git", repo, tmp_path)
    shadow = tmp_path / "shadow"
    list_refs(repo / ".git", shadow)
    read_turn_format(repo / ".git", shadow)
    snap = resolve_snapshot(repo / ".git", shadow, "refs/git-turn/sessions/abc/turn-1")
    dest = _repo(tmp_path / "dest")
    apply_snapshot(dest / ".git", dest, snap, "warren/branch/x", shadow)
    assert not marker.exists()


def test_alternates_refused(repo, tmp_path):
    (repo / ".git" / "objects" / "info").mkdir(exist_ok=True)
    (repo / ".git" / "objects" / "info" / "alternates").write_text("/elsewhere/objects\n")
    with pytest.raises(SafeGitError):
        list_refs(repo / ".git", tmp_path / "shadow")


def test_resolve_snapshot_errors(repo, tmp_path):
    shadow = tmp_path / "shadow"
    with pytest.raises(TurnRefNotFound):
        resolve_snapshot(repo / ".git", shadow, "refs/git-turn/sessions/nope/turn-1")
    for bad in ("HEAD", "main", "refs/git-turn/format", "refs/heads/a..b", "refs/x.lock"):
        with pytest.raises(TurnRefError):
            resolve_snapshot(repo / ".git", shadow, bad)
    _write_format(repo, {"snapshot_model": "mystery"})
    with pytest.raises(TurnRefError, match="unsupported"):
        resolve_snapshot(repo / ".git", shadow, "refs/heads/main")


def test_two_tree_branch_carries_uncommitted_worktree(repo, tmp_path):
    _write_format(repo, _GIT_TURN_FORMAT)
    (repo / "a.txt").write_text("edited\n")
    (repo / "new.txt").write_text("untracked\n")
    turn = _snapshot_turn(repo, "abc", 3)
    shadow = tmp_path / "shadow"
    snap = resolve_snapshot(repo / ".git", shadow, "refs/git-turn/sessions/abc/turn-3")
    assert snap.snapshot_model == "two-tree-dangling-commit"
    assert snap.commit == turn

    dest = _repo(tmp_path / "dest")
    base = _git("-C", str(dest), "rev-parse", "HEAD")
    tip = apply_snapshot(dest / ".git", dest, snap, "warren/branch/x", shadow)

    assert (dest / "a.txt").read_text() == "edited\n"
    assert (dest / "new.txt").read_text() == "untracked\n"
    assert _git("-C", str(dest), "symbolic-ref", "--short", "HEAD") == "warren/branch/x"
    assert _git("-C", str(dest), "rev-parse", f"{tip}^") == base
    assert _git("-C", str(dest), "status", "--porcelain") == ""
    _git("-C", str(dest), "fsck", "--connectivity-only")


def test_head_ref_only_branch_starts_at_commit(repo, tmp_path):
    dest = _repo(tmp_path / "dest")
    (repo / "b.txt").write_text("two\n")
    _git("-C", str(repo), "add", "b.txt")
    _git("-C", str(repo), *_IDENT, "commit", "-qm", "two")
    head = _git("-C", str(repo), "rev-parse", "HEAD")
    _git("-C", str(repo), "update-ref", "refs/turns/s/turn-1", head)
    shadow = tmp_path / "shadow"
    snap = resolve_snapshot(repo / ".git", shadow, "refs/turns/s/turn-1")
    assert snap.snapshot_model == "head-ref-only"
    assert apply_snapshot(dest / ".git", dest, snap, "warren/branch/y", shadow) == head
    assert (dest / "b.txt").read_text() == "two\n"
    _git("-C", str(dest), "fsck", "--connectivity-only")


def test_apply_refuses_symlinked_objects(repo, tmp_path):
    dest = _repo(tmp_path / "dest")
    link = tmp_path / "objects-link"
    link.symlink_to(repo / ".git" / "objects")
    snap = Snapshot("refs/x", "0" * 40, "0" * 40, "head-ref-only", link)
    with pytest.raises(SafeGitError):
        apply_snapshot(dest / ".git", dest, snap, "b", tmp_path / "shadow")


def test_write_session_file(repo):
    payload = write_session_file(repo / ".git", "ws-1")
    on_disk = json.loads((repo / ".git" / "git-turn" / "session.json").read_text())
    assert on_disk == payload
    assert payload["workspace_id"] == "ws-1"
    assert payload["turn_n"] == 0
    assert payload["refs_namespace"] == "refs/git-turn"
    assert write_session_file(repo / ".git", "ws-1")["session_id"] != payload["session_id"]


def test_write_session_file_never_follows_symlinks(repo, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (repo / ".git" / "git-turn").symlink_to(outside)
    with pytest.raises(OSError):
        write_session_file(repo / ".git", "ws-1")
    assert list(outside.iterdir()) == []

    (repo / ".git" / "git-turn").unlink()
    (repo / ".git" / "git-turn").mkdir()
    (repo / ".git" / "git-turn" / "session.json").symlink_to(outside / "victim")
    write_session_file(repo / ".git", "ws-1")
    assert not (outside / "victim").exists()
    assert not (repo / ".git" / "git-turn" / "session.json").is_symlink()


def test_worktree_git_dir(tmp_path):
    plain = _repo(tmp_path / "plain")
    assert worktree_git_dir(plain) == plain / ".git"

    bare = tmp_path / "demo.git-store"
    _git("clone", "-q", "--bare", str(plain), str(bare))
    wt = tmp_path / "ws" / "code"
    _git("-C", str(bare), "worktree", "add", "-q", "-b", "w", str(wt), "main")
    gd = worktree_git_dir(wt)
    assert gd is not None and gd.parent.parent.name == "demo.git-store"

    other = tmp_path / "ws" / "other"
    other.mkdir()
    (other / ".git").write_text(f"gitdir: {gd}\n")
    assert worktree_git_dir(other) is None
    (other / ".git").write_text(f"gitdir: {plain / '.git'}\n")
    assert worktree_git_dir(other) is None
