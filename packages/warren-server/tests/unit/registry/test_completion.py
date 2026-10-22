"""AH2: completion capture helpers against real (hostile) git checkouts."""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from warren.registry import completion
from warren_common.models import FolderSpec

_IDENT = ["-c", "user.email=t@t", "-c", "user.name=t"]


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], text=True)


def _plant_hostile(git_dir: Path, work_tree: Path, tmp_path: Path) -> Path:
    marker = tmp_path / "pwned"
    script = tmp_path / "evil.sh"
    script.write_text(f"#!/bin/sh\necho \"$0\" >> {marker}\nexit 1\n")
    script.chmod(script.stat().st_mode | stat.S_IXUSR)
    for key in ("core.fsmonitor", "filter.evil.clean", "filter.evil.process", "core.pager", "diff.external"):
        _git("config", "--file", str(git_dir / "config"), key, str(script))
    hooks = git_dir / "hooks"
    hooks.mkdir(exist_ok=True)
    (hooks / "reference-transaction").write_text(f"#!/bin/sh\necho hook >> {marker}\n")
    (hooks / "reference-transaction").chmod(0o755)
    (work_tree / ".gitattributes").write_text("* filter=evil\n")
    return marker


@pytest.fixture
def upstream(tmp_path: Path) -> Path:
    src = tmp_path / "upstream"
    _git("init", "-q", "-b", "main", str(src))
    (src / "a.txt").write_text("one\n")
    _git("-C", str(src), "add", "a.txt")
    _git("-C", str(src), *_IDENT, "commit", "-qm", "one")
    return src


def _folder(name: str, mount: str, kind: str = "git-clone", branch: str = "main") -> FolderSpec:
    return FolderSpec(name=name, type=kind, url="https://github.com/o/r.git", mount=mount, branch=branch)


def test_podman_clone_on_workspace_branch(tmp_path: Path, upstream: Path):
    root = tmp_path / "worktrees" / "ws-1"
    clone = root / "repo"
    _git("clone", "-q", str(upstream), str(clone))
    base = _git("-C", str(clone), "rev-parse", "HEAD").strip()
    _git("-C", str(clone), "checkout", "-qb", "feature")
    (clone / "b.txt").write_text("b\n")
    (clone / ".gitattributes").write_text("* filter=evil\n")
    _git("-C", str(clone), "add", "b.txt", ".gitattributes")
    _git("-C", str(clone), *_IDENT, "commit", "-qm", "b")
    head = _git("-C", str(clone), "rev-parse", "HEAD").strip()
    marker = _plant_hostile(clone / ".git", clone, tmp_path)
    gm = SimpleNamespace(
        worktree_path=lambda ws: tmp_path / "worktrees" / ws,
        folder_worktree_path=lambda ws, name: tmp_path / "worktrees" / ws / name,
    )

    targets = completion.podman_targets(gm, "ws-1", [_folder("repo", "repo")])
    results, errors = completion.inspect_all(targets, tmp_path / "shadow")

    assert errors == []
    assert results == [{
        "mount": "repo",
        "branch": "feature",
        "head_commit": head,
        "base_commit": base,
        "branch_safe": True,
        "is_clean": True,
    }]
    assert not marker.exists()


def test_podman_dirty_clone_on_base_branch_is_not_branch_safe(tmp_path: Path, upstream: Path):
    root = tmp_path / "worktrees" / "ws-1"
    _git("clone", "-q", str(upstream), str(root))
    (root / "a.txt").write_text("changed\n")
    gm = SimpleNamespace(worktree_path=lambda ws: root, folder_worktree_path=None)

    targets = completion.podman_targets(gm, "ws-1", [])
    results, _ = completion.inspect_all(targets, tmp_path / "shadow")

    assert results[0]["mount"] == ""
    assert results[0]["branch"] == "main"
    assert results[0]["branch_safe"] is False
    assert results[0]["is_clean"] is False


def _ecs_volume(tmp_path: Path, upstream: Path) -> tuple[Path, str]:
    volume = tmp_path / "efs" / "workspaces" / "ws-1"
    store = volume / "git" / "repo.git-store"
    _git("clone", "-q", "--bare", str(upstream), str(store))
    wt = volume / "workspace" / "repo"
    _git("-C", str(store), "worktree", "add", "-q", "-b", "warren/t/ws-1/repo", str(wt), "main")
    (wt / ".git").write_text("gitdir: /var/lib/warren/git/repo.git-store/worktrees/repo\n")
    return volume, _git("-C", str(upstream), "rev-parse", "HEAD").strip()


def test_ecs_linked_worktree_on_volume(tmp_path: Path, upstream: Path):
    volume, base = _ecs_volume(tmp_path, upstream)
    marker = _plant_hostile(volume / "git" / "repo.git-store", volume / "workspace" / "repo", tmp_path)

    targets, errors = completion.ecs_targets(volume, [_folder("repo", "repo", kind="git-worktree")])
    results, git_errors = completion.inspect_all(targets, tmp_path / "shadow")

    assert errors == git_errors == []
    assert results[0]["branch"] == "warren/t/ws-1/repo"
    assert results[0]["head_commit"] == base == results[0]["base_commit"]
    assert results[0]["branch_safe"] is True
    assert results[0]["is_clean"] is False  # the planted .gitattributes is untracked
    assert not marker.exists()


def test_ecs_gitfile_pointing_elsewhere_is_rejected(tmp_path: Path, upstream: Path):
    volume, _ = _ecs_volume(tmp_path, upstream)
    (volume / "workspace" / "repo" / ".git").write_text("gitdir: /var/lib/warren/../other/.git\n")

    targets, errors = completion.ecs_targets(volume, [_folder("repo", "repo", kind="git-worktree")])

    assert targets == []
    assert "does not point at its own worktree" in errors[0]


def test_ecs_symlink_out_of_the_volume_is_rejected(tmp_path: Path, upstream: Path):
    other = tmp_path / "efs" / "workspaces" / "ws-2"
    _git("clone", "-q", str(upstream), str(other / "workspace" / "repo"))
    volume = tmp_path / "efs" / "workspaces" / "ws-1"
    volume.mkdir(parents=True)
    os.symlink(other / "workspace", volume / "workspace")

    targets, errors = completion.ecs_targets(volume, [_folder("repo", "repo")])

    assert targets == []
    assert "outside the workspace's storage" in errors[0]


def test_read_nofollow_verdict(tmp_path: Path):
    (tmp_path / ".warren").mkdir()
    (tmp_path / ".warren" / "verdict.json").write_text('{"ok": true}')
    data = completion.read_nofollow(tmp_path, completion.VERDICT_REL, 1024)
    assert completion.parse_verdict(data) == {"ok": True}
    assert completion.read_nofollow(tmp_path / "missing", completion.VERDICT_REL, 1024) is None


def test_read_nofollow_refuses_symlinks_and_oversize(tmp_path: Path):
    secret = tmp_path / "secret.json"
    secret.write_text('{"stolen": 1}')
    ws = tmp_path / "ws"
    (ws / ".warren").mkdir(parents=True)
    os.symlink(secret, ws / ".warren" / "verdict.json")
    with pytest.raises(completion.CaptureError):
        completion.read_nofollow(ws, completion.VERDICT_REL, 1024)

    ws2 = tmp_path / "ws2"
    ws2.mkdir()
    os.symlink(tmp_path, ws2 / ".warren")
    with pytest.raises(completion.CaptureError):
        completion.read_nofollow(ws2, completion.VERDICT_REL, 1024)

    ws3 = tmp_path / "ws3"
    (ws3 / ".warren").mkdir(parents=True)
    (ws3 / ".warren" / "verdict.json").write_text("x" * 2000)
    with pytest.raises(completion.CaptureError):
        completion.read_nofollow(ws3, completion.VERDICT_REL, 1024)


@pytest.mark.parametrize("raw", [b"[1, 2]", b"not json", b"\xff\xfe"])
def test_parse_verdict_requires_a_json_object(raw: bytes):
    with pytest.raises(completion.CaptureError):
        completion.parse_verdict(raw)
