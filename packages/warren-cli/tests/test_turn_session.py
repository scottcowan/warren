"""HIST-10: local `warren connect` writes `.git/git-turn/session.json`."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

from warren_cli.dispatch import write_turn_sessions

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="local worktree turn sessions use dir_fd reads: POSIX hosts only"
)

_IDENT = ["-c", "user.email=t@t", "-c", "user.name=t"]


def _git(*args: str) -> str:
    return subprocess.run(["git", *args], text=True, capture_output=True, check=True).stdout.strip()


def _bare_with_worktree(tmp_path: Path) -> tuple[Path, Path]:
    src = tmp_path / "src"
    _git("init", "-q", "-b", "main", str(src))
    (src / "a.txt").write_text("one\n")
    _git("-C", str(src), "add", "a.txt")
    _git("-C", str(src), *_IDENT, "commit", "-qm", "one")
    bare = tmp_path / "projects" / "demo" / "demo.git-store"
    _git("clone", "-q", "--bare", str(src), str(bare))
    wt = tmp_path / "ws" / "code"
    _git("-C", str(bare), "worktree", "add", "-q", "-b", "warren/x/ws1/code", str(wt), "main")
    return bare, wt


def test_writes_session_into_linked_worktree_git_dir(tmp_path):
    _bare, wt = _bare_with_worktree(tmp_path)
    session_id = write_turn_sessions({"workspace_id": "ws1", "worktree_paths": [[str(wt), "code"]]})
    git_dir = Path(_git("-C", str(wt), "rev-parse", "--absolute-git-dir"))
    data = json.loads((git_dir / "git-turn" / "session.json").read_text())
    assert data == {
        "session_id": session_id, "workspace_id": "ws1", "turn_n": 0, "refs_namespace": "refs/git-turn",
    }


def test_forged_gitdir_pointer_is_ignored(tmp_path):
    _bare, wt = _bare_with_worktree(tmp_path)
    victim = tmp_path / "victim.git-store" / "worktrees" / "v"
    victim.mkdir(parents=True)
    (victim / "gitdir").write_text("/somewhere/else/.git\n")
    (wt / ".git").write_text(f"gitdir: {victim}\n")
    assert write_turn_sessions({"workspace_id": "ws1", "worktree_paths": [[str(wt), "code"]]}) is None
    assert not (victim / "git-turn").exists()


def test_no_worktrees_is_a_noop():
    assert write_turn_sessions({"workspace_id": "ws1"}) is None
