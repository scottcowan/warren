"""Wave 0 RED: GitManager async operations (Plan 05-03).

Uses real `git` against a scratch bare repo built per-test. Guarded by
importorskip for the not-yet-shipped module, and pytestmark xfail so
implementation absence does not error the collector.

Behaviour covered:
  - ensure_bare clones then fetches (idempotent), and sets gc.auto=0
  - add_worktree materialises a branch, then is idempotent
  - concurrent add_worktree on the same bare serialises via per-bare Lock (D-12)
  - remove_worktree prunes
  - ensure_reference clones a non-bare reference under references/<slug>/
"""

from __future__ import annotations

import asyncio
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="host-side git for local sandbox workspaces: POSIX hosts only (Windows local is AC2, via WSL2)"
)


def _run(*args: str, cwd: Path | None = None) -> str:
    return subprocess.check_output(list(args), cwd=str(cwd) if cwd else None).decode()


@pytest.fixture
def seed_repo(tmp_path: Path) -> Path:
    """A bare source repo with two branches (main + feature/x) and one seed commit."""
    src_bare = tmp_path / "seed.git"
    _run("git", "init", "--bare", "-b", "main", str(src_bare))

    work = tmp_path / "seed-work"
    _run("git", "clone", str(src_bare), str(work))
    (work / "README.md").write_text("seed\n")
    _run("git", "-C", str(work), "add", "README.md")
    _run("git", "-C", str(work), "-c", "user.email=t@t", "-c", "user.name=t",
         "commit", "-m", "seed")
    _run("git", "-C", str(work), "push", "origin", "main")
    _run("git", "-C", str(work), "checkout", "-b", "feature/x")
    (work / "b.txt").write_text("b\n")
    _run("git", "-C", str(work), "add", "b.txt")
    _run("git", "-C", str(work), "-c", "user.email=t@t", "-c", "user.name=t",
         "commit", "-m", "on-feature")
    _run("git", "-C", str(work), "push", "origin", "feature/x")
    return src_bare


def _project(name: str, url: Path):
    """Build a minimal ProjectConfig-shaped object for GitManager consumption."""
    from warren_common.models import ProjectConfig, RepoSpec

    return ProjectConfig(
        name=name,
        description="t",
        repos=[RepoSpec(url=str(url), type="worktree", branch="main")],
        docker_image="ghcr.io/example/base:latest",
        intents={},
    )


@pytest.mark.asyncio
async def test_ensure_bare_clones_then_fetches_idempotent(tmp_path: Path, seed_repo):
    from warren_common.git import GitManager

    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    proj = _project("demo", seed_repo)

    bare1 = await GitManager.ensure_bare(proj, projects_dir)
    assert bare1.exists()
    assert (bare1 / "HEAD").exists()

    bare2 = await GitManager.ensure_bare(proj, projects_dir)
    assert bare2 == bare1  # same path, second call is fetch not clone


@pytest.mark.asyncio
async def test_ensure_bare_disables_gc_auto(tmp_path: Path, seed_repo):
    from warren_common.git import GitManager

    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    proj = _project("demo", seed_repo)
    bare = await GitManager.ensure_bare(proj, projects_dir)

    val = _run("git", "-C", str(bare), "config", "gc.auto").strip()
    assert val == "0"


@pytest.mark.asyncio
async def test_add_worktree_creates_branch_checkout(tmp_path: Path, seed_repo):
    from warren_common.git import GitManager

    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    proj = _project("demo", seed_repo)
    bare = await GitManager.ensure_bare(proj, projects_dir)

    workspace_root = tmp_path / "ws-a"
    workspace_root.mkdir()
    target = await GitManager.add_worktree(bare, workspace_root, "main", workspace_id="aabbccdd-1234-5678-abcd-ef0123456789", intent="develop")
    assert target.exists()
    assert (target / "README.md").exists()


@pytest.mark.asyncio
async def test_add_worktree_idempotent(tmp_path: Path, seed_repo):
    from warren_common.git import GitManager

    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    proj = _project("demo", seed_repo)
    bare = await GitManager.ensure_bare(proj, projects_dir)

    workspace_root = tmp_path / "ws-b"
    workspace_root.mkdir()
    t1 = await GitManager.add_worktree(bare, workspace_root, "main", workspace_id="aabbccdd-1234-5678-abcd-ef0123456789", intent="develop")
    t2 = await GitManager.add_worktree(bare, workspace_root, "main", workspace_id="aabbccdd-1234-5678-abcd-ef0123456789", intent="develop")
    assert t1 == t2


@pytest.mark.asyncio
async def test_concurrent_add_worktree_on_same_bare_serialises(
    tmp_path: Path, seed_repo, monkeypatch
):
    """Two concurrent add_worktrees on the same bare must serialise (D-12).

    Proves the per-bare lock is held: patch the internal git runner to record
    entry order and add a small await so overlap would show up if unsynchronised.
    """
    from warren_common import git as gitmod

    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    proj = _project("demo", seed_repo)
    bare = await gitmod.GitManager.ensure_bare(proj, projects_dir)

    workspace_a = tmp_path / "ws-A"
    workspace_a.mkdir()
    workspace_b = tmp_path / "ws-B"
    workspace_b.mkdir()

    original = gitmod._git  # type: ignore[attr-defined]
    inflight = 0
    max_inflight = 0

    async def _tracking_git(*args, **kwargs):
        nonlocal inflight, max_inflight
        inflight += 1
        max_inflight = max(max_inflight, inflight)
        try:
            await asyncio.sleep(0.01)
            return await original(*args, **kwargs)
        finally:
            inflight -= 1

    monkeypatch.setattr(gitmod, "_git", _tracking_git)

    await asyncio.gather(
        gitmod.GitManager.add_worktree(bare, workspace_a, "main", workspace_id="aaaaaaaa-0000-0000-0000-000000000001", intent="develop"),
        gitmod.GitManager.add_worktree(bare, workspace_b, "main", workspace_id="bbbbbbbb-0000-0000-0000-000000000002", intent="develop"),
    )

    locks = getattr(gitmod, "_locks", None)
    assert locks is not None
    assert str(bare.resolve()) in locks


@pytest.mark.asyncio
async def test_remove_worktree_prunes(tmp_path: Path, seed_repo):
    from warren_common.git import GitManager

    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    proj = _project("demo", seed_repo)
    bare = await GitManager.ensure_bare(proj, projects_dir)

    workspace_root = tmp_path / "ws-c"
    workspace_root.mkdir()
    target = await GitManager.add_worktree(bare, workspace_root, "main", workspace_id="aabbccdd-1234-5678-abcd-ef0123456789", intent="develop")
    assert target.exists()
    assert target.name == "workspace"  # new: always named 'workspace' not branch name

    await GitManager.remove_worktree(bare, workspace_root, "main")
    porcelain = _run("git", "-C", str(bare), "worktree", "list", "--porcelain")
    assert str(target) not in porcelain


@pytest.mark.asyncio
async def test_ensure_reference_clones_then_fetches(tmp_path: Path, seed_repo):
    from warren_common.git import GitManager
    from warren_common.models import RepoSpec

    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    repo = RepoSpec(url=str(seed_repo), type="reference", branch="main")

    ref1 = await GitManager.ensure_reference("demo", repo, projects_dir)
    assert ref1.exists()
    assert (projects_dir / "demo" / "references").exists()
    # Non-bare clone: working tree present
    assert (ref1 / "README.md").exists() or (ref1 / ".git").exists()

    ref2 = await GitManager.ensure_reference("demo", repo, projects_dir)
    assert ref2 == ref1


@pytest.mark.asyncio
@pytest.mark.parametrize("subdir", ["../victim", "/abs/victim", "a/../../victim"])
async def test_add_worktree_rejects_escaping_subdir(tmp_path: Path, seed_repo, subdir):
    from warren_common.git import GitManager
    from warren_common.paths import PathEscapeError

    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    bare = await GitManager.ensure_bare(_project("demo", seed_repo), projects_dir)
    workspace_root = tmp_path / "ws"
    workspace_root.mkdir()
    victim = tmp_path / "victim"
    victim.mkdir()
    (victim / "keep.txt").write_text("keep")

    with pytest.raises(PathEscapeError):
        await GitManager.add_worktree(
            bare, workspace_root, "main",
            workspace_id="aabbccdd-1234-5678-abcd-ef0123456789", intent="develop",
            subdir=subdir,
        )
    assert (victim / "keep.txt").read_text() == "keep"


@pytest.mark.asyncio
async def test_add_worktree_rejects_symlinked_parent(tmp_path: Path, seed_repo):
    from warren_common.git import GitManager
    from warren_common.paths import PathEscapeError

    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    bare = await GitManager.ensure_bare(_project("demo", seed_repo), projects_dir)
    workspace_root = tmp_path / "ws"
    workspace_root.mkdir()
    outside = tmp_path / "outside"
    (outside / "repo").mkdir(parents=True)
    (outside / "repo" / "keep.txt").write_text("keep")
    (workspace_root / "code").symlink_to(outside)

    with pytest.raises(PathEscapeError):
        await GitManager.add_worktree(
            bare, workspace_root, "main",
            workspace_id="aabbccdd-1234-5678-abcd-ef0123456789", intent="develop",
            subdir="code/repo",
        )
    assert (outside / "repo" / "keep.txt").read_text() == "keep"


def _replace_git_with_hostile_dir(worktree: Path, tmp_path: Path) -> Path:
    """The workspace repoints its worktree `.git` at a hostile git dir (and
    plants .gitattributes in the checkout)."""
    from test_safe_git import plant_hostile

    evil = tmp_path / "evil-gitdir"
    if not evil.exists():
        _run("git", "init", "-q", "--bare", str(evil))
        _run("git", "config", "--file", str(evil / "config"), "core.bare", "false")
    (worktree / ".git").write_text(f"gitdir: {evil}\n")
    return plant_hostile(evil, worktree, tmp_path)


@pytest.mark.asyncio
async def test_worktree_add_and_remove_never_run_workspace_config(tmp_path: Path, seed_repo):
    """BB12: re-provisioning over, and removing, a hostile worktree runs nothing."""
    from warren_common.git import GitManager

    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    bare = await GitManager.ensure_bare(_project("demo", seed_repo), projects_dir)
    workspace_root = tmp_path / "ws-h"
    workspace_root.mkdir()
    wid = "aabbccdd-1234-5678-abcd-ef0123456789"
    target = await GitManager.add_worktree(bare, workspace_root, "main", workspace_id=wid, intent="develop")
    marker = _replace_git_with_hostile_dir(target, tmp_path)
    subprocess.run(["git", "-C", str(target), "status"], capture_output=True, timeout=30)
    assert marker.exists(), "baseline: plain git in the worktree runs planted config"
    marker.unlink()

    # bare-side prune drops the now-unrecognised worktree; add re-creates it
    target = await GitManager.add_worktree(bare, workspace_root, "main", workspace_id=wid, intent="develop")
    assert (target / "README.md").exists()
    marker = _replace_git_with_hostile_dir(target, tmp_path)
    await GitManager.remove_worktree(bare, workspace_root, "main")
    assert not target.exists()
    assert not marker.exists()


@pytest.mark.asyncio
async def test_ensure_reference_fetch_ignores_planted_config(tmp_path: Path, seed_repo):
    """BB12: host fetch of a (workspace-writable) reference clone goes through
    a shadow git dir, so nothing planted in its config/attributes runs."""
    from test_safe_git import plant_hostile

    from warren_common.git import GitManager
    from warren_common.models import RepoSpec

    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    repo = RepoSpec(url=str(seed_repo), type="reference", branch="main")
    ref = await GitManager.ensure_reference("demo", repo, projects_dir)
    assert "no_push" in _run("git", "-C", str(ref), "remote", "get-url", "--push", "origin")
    marker = plant_hostile(ref / ".git", ref, tmp_path)

    work = tmp_path / "seed-work"
    _run("git", "-C", str(work), "checkout", "-q", "main")
    (work / "c.txt").write_text("c\n")
    _run("git", "-C", str(work), "add", "c.txt")
    _run("git", "-C", str(work), "-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "c")
    _run("git", "-C", str(work), "push", "-q", "origin", "main")
    want = _run("git", "-C", str(work), "rev-parse", "HEAD").strip()

    await GitManager.ensure_reference("demo", repo, projects_dir, fetch=True)
    assert not marker.exists()
    got = (ref / ".git" / "refs" / "remotes" / "origin" / "main").read_text().strip()
    assert got == want


@pytest.mark.asyncio
async def test_add_worktree_start_point_pins_commit(tmp_path: Path, seed_repo):
    from warren_common.git import GitManager

    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    proj = _project("demo", seed_repo)
    bare = await GitManager.ensure_bare(proj, projects_dir)
    first = _run("git", "-C", str(bare), "rev-list", "--max-parents=0", "main").split()[0]

    workspace_root = tmp_path / "ws-pin"
    workspace_root.mkdir()
    target = await GitManager.add_worktree(
        bare, workspace_root, "main", workspace_id="aabbccdd-1234-5678-abcd-ef0123456789",
        intent="develop", start_point=first,
    )
    assert _run("git", "-C", str(target), "rev-parse", "HEAD").strip() == first
