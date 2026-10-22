"""GitManager: async wrappers around `git` CLI for bare clones, worktrees, and reference clones.

Ownership & responsibility (D-06..D-13):
    - Sole owner of bare-clone / worktree / reference-clone lifecycle.
    - NsjailRuntime knows nothing about git; dispatch layer calls these methods and
      passes resolved paths into WorkspaceSpec.

Concurrency model:
    A module-level `_locks: dict[str, asyncio.Lock]` maps `str(bare.resolve())` to a
    Lock. Every mutation on a bare acquires the corresponding lock. Reads inside a
    materialised worktree do not need the lock (single-writer contract is only at
    the bare-repo level). A small `_registry_lock` guards insertion into `_locks`
    so two concurrent `_lock_for(...)` calls cannot race on `dict.setdefault`
    across an `await` point (Pitfall #7, Pattern 5 in 05-RESEARCH.md).

Safety:
    - Every subprocess uses `asyncio.create_subprocess_exec` with argv form
      (never shell=true form) — command injection via YAML-supplied URLs / branch
      names is prevented at the syscall boundary (T-05-05).
    - Bare clones set `gc.auto=0` so opportunistic gc cannot corrupt a worktree
      in-progress on another task (T-05-06 / Pitfall #7).
    - `_git` never logs the URL directly: SSH URLs of shape `git@host:path` may
      carry a deployment-key token; we log only the path suffix (T-05-07).
"""

from __future__ import annotations

import asyncio
import re
import shutil
import time
from pathlib import Path
from typing import TYPE_CHECKING

import structlog

from .paths import ensure_within
from .safe_git import object_scrubbed_environ, run_git, safe_git_argv, shadow_git_dir

if TYPE_CHECKING:  # pragma: no cover
    from .models import ProjectConfig, RepoSpec

log = structlog.get_logger(__name__)


class ProvisionError(RuntimeError):
    """A git subprocess exited non-zero. Message includes the leading argv + stderr tail."""


_locks: dict[str, asyncio.Lock] = {}
_registry_lock = asyncio.Lock()


async def _lock_for(path: Path) -> asyncio.Lock:
    key = str(path.resolve())
    async with _registry_lock:
        lock = _locks.get(key)
        if lock is None:
            lock = asyncio.Lock()
            _locks[key] = lock
    return lock


def _sanitise_url_for_log(url: str) -> str:
    """Strip `user@host:` prefix so SSH deploy-key tokens never hit logs."""
    if "@" in url and ("://" not in url or url.startswith("ssh://")):
        # user@host:path or ssh://user@host/path
        tail = url.rsplit("@", 1)[-1]
        return tail.split(":", 1)[-1] if ":" in tail else tail
    return url


async def _git(*argv: str) -> str:
    """Run `git ...` argv-form; return stdout on success, raise ProvisionError otherwise.

    Argv form only. stderr is captured for error reporting only; stdout is
    returned as decoded text (utf-8 with replace) for the caller's convenience.
    `argv[0]` must be "git"; the command runs via safe_git_argv (BB7).
    """
    if not argv or argv[0] != "git":
        raise ValueError("_git argv must start with 'git'")
    started = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *safe_git_argv(*argv[1:]),
        env=object_scrubbed_environ(),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout_b, stderr_b = await proc.communicate()
    duration_ms = int((time.monotonic() - started) * 1000)

    op = argv[1] if len(argv) > 1 else argv[0]
    # bare_path heuristic: look for `-C <path>` in argv; otherwise final arg for `clone`
    bare_path: str | None = None
    for i, tok in enumerate(argv):
        if tok == "-C" and i + 1 < len(argv):
            bare_path = argv[i + 1]
            break
    log.info(
        "git_op",
        op=op,
        bare_path=bare_path,
        duration_ms=duration_ms,
        rc=proc.returncode,
    )

    if proc.returncode != 0:
        stderr_txt = stderr_b.decode(errors="replace")[:512]
        head = list(argv[:3])
        raise ProvisionError(f"git {head} failed rc={proc.returncode}: {stderr_txt}")

    return stdout_b.decode(errors="replace")


_slug_non_alnum = re.compile(r"[^a-z0-9]+")


def _repo_slug(url: str) -> str:
    """Full slug: org-repo (e.g. acmecorp-acme-api). Used for on-disk storage."""
    s = url.strip()
    if "://" in s:
        s = s.split("://", 1)[1]
    if "@" in s:
        s = s.split("@", 1)[-1]
    for sep in (":", "/"):
        if sep in s:
            s = s.split(sep, 1)[-1]
            break
    s = s.lower()
    if s.endswith(".git"):
        s = s[:-4]
    s = _slug_non_alnum.sub("-", s)
    return s.strip("-")


def _short_slug(url: str) -> str:
    """Short slug: just the repo name (e.g. acme-api). Used for display paths."""
    full = _repo_slug(url)
    # last segment after the last '-' boundary that looks like an org separator
    # e.g. acmecorp-acme-api → acme-api
    parts = full.split("-")
    # heuristic: if first part looks like an org (no digits, 3+ chars), drop it
    if len(parts) >= 2 and parts[0].isalpha() and len(parts[0]) >= 3:
        return "-".join(parts[1:])
    return full


def _slug_for_repos(urls: list[str]) -> dict[str, str]:
    """Return display slug for each URL — short unless collision, then full."""
    short = {url: _short_slug(url) for url in urls}
    # detect collisions
    counts: dict[str, int] = {}
    for s in short.values():
        counts[s] = counts.get(s, 0) + 1
    return {
        url: _repo_slug(url) if counts[short[url]] > 1 else short[url]
        for url in urls
    }


def _fetch_reference(ref_dir: Path, url: str, shadow_root: Path) -> None:
    config = [
        ("remote.origin.url", url),
        ("remote.origin.fetch", "+refs/heads/*:refs/remotes/origin/*"),
    ]
    with shadow_git_dir(ref_dir / ".git", shadow_root, config) as shadow:
        run_git("fetch", "origin", "--prune", extra_env=shadow.env())


class GitManager:
    @staticmethod
    async def ensure_bare(
        project: "ProjectConfig",
        projects_dir: Path,
        fetch: bool = False,
    ) -> Path:
        """Legacy single-repo bare clone. Delegates to ensure_bare_for_repo for first worktree."""
        first_worktree = next((r for r in project.repos if r.type == "worktree"), None)
        if first_worktree is None:
            raise ValueError(f"Project {project.name} has no worktree repos")
        return await GitManager.ensure_bare_for_repo(
            project.name, first_worktree.url, projects_dir, fetch=fetch
        )

    @staticmethod
    async def ensure_bare_for_repo(
        project_name: str,
        url: str,
        projects_dir: Path,
        fetch: bool = False,
        seed_from: str | None = None,
    ) -> Path:
        """Ensure a per-repo bare clone at `<projects_dir>/<project>/<slug>.git-store`.

        Each repo gets its own bare clone — multiple worktree repos in the same
        project each have independent object stores.
        """
        slug = _repo_slug(url)
        bare = projects_dir / project_name / f"{slug}.git-store"
        lock = await _lock_for(bare)
        async with lock:
            if bare.exists():
                if fetch:
                    await _git("git", "-C", str(bare), "fetch", "--upload-pack=git-upload-pack", "origin", "--prune")
            else:
                bare.parent.mkdir(parents=True, exist_ok=True)
                clone_src = url
                if seed_from:
                    _expanded = Path(seed_from).expanduser()
                    if _expanded.exists():
                        clone_src = str(_expanded)
                        log.info("git_clone_bare_from_seed", dest=str(bare), seed=str(_expanded))
                    else:
                        log.warning("seed_from_not_found", path=str(_expanded))
                if clone_src == url:
                    log.info("git_clone_bare", dest=str(bare), url_suffix=_sanitise_url_for_log(url))
                await _git("git", "clone", "--bare", clone_src, str(bare))
                # Set remote to real URL (not local seed) for future fetches
                if clone_src != url:
                    await _git("git", "-C", str(bare), "remote", "set-url", "origin", url)
                await _git("git", "-C", str(bare), "config", "gc.auto", "0")
        return bare

    @staticmethod
    async def ensure_reference(
        project_name: str,
        repo: "RepoSpec",
        projects_dir: Path,
        fetch: bool = False,
    ) -> Path:
        """Ensure a non-bare reference clone under `<projects_dir>/<project>/references/<slug>/`.

        Clones on first use. Does NOT fetch on subsequent calls unless fetch=True.
        """
        slug = _repo_slug(repo.url)
        ref_dir = projects_dir / project_name / "references" / slug
        lock = await _lock_for(ref_dir)
        async with lock:
            if ref_dir.exists():
                if fetch:
                    # The reference clone is workspace-writable: fetch through
                    # a warren-owned shadow git dir, never its own config (BB12).
                    await asyncio.to_thread(
                        _fetch_reference, ref_dir, repo.url, projects_dir / ".git-shadow"
                    )
            else:
                ref_dir.parent.mkdir(parents=True, exist_ok=True)
                log.info(
                    "git_clone_reference",
                    dest=str(ref_dir),
                    url_suffix=_sanitise_url_for_log(repo.url),
                )
                # pushurl=no_push blocks accidental pushes from inside the sandbox
                await _git(
                    "git", "clone", "--config", "remote.origin.pushurl=no_push",
                    repo.url, str(ref_dir),
                )
        return ref_dir

    @staticmethod
    async def add_worktree(
        bare: Path,
        workspace_root: Path,
        branch: str,
        workspace_id: str,
        intent: str,
        subdir: str = "workspace",
        start_point: str | None = None,
    ) -> Path:
        """Create a per-workspace branch from `branch` (or from `start_point`,
        e.g. a pinned commit) and materialise it at `workspace_root/workspace`.

        Each workspace gets its own local branch `warren/<intent>/<short-id>`
        that tracks `branch`. This means:
        - Multiple workspaces on the same source branch are fully independent
        - `observe` workspaces get a read-only tracking branch (no push)
        - The checked-out path is always `workspace_root/workspace` (not branch-named)
        """
        short_id = workspace_id[:8]
        # Include subdir slug in branch name to avoid collision when two worktrees
        # from the same bare repo are provisioned in the same workspace (e.g. docs-kb + main)
        subdir_slug = _slug_non_alnum.sub("-", subdir.lower()).strip("-") or "workspace"
        ws_branch = f"warren/{intent}/{short_id}/{subdir_slug}"
        target = workspace_root / subdir
        ensure_within(workspace_root, target)
        lock = await _lock_for(bare)
        async with lock:
            try:
                await _git("git", "-C", str(bare), "worktree", "prune")
            except Exception:
                pass
            listing = await _git(
                "git", "-C", str(bare), "worktree", "list", "--porcelain"
            )
            if str(target) in listing:
                return target
            # If the branch or target dir exists from a failed previous provision,
            # clean up before recreating. Must remove the dir first so git allows
            # branch deletion (git refuses to delete a branch used by a worktree).
            # Specs persisted before FolderSpec.mount was validated may still
            # carry an escaping mount -- re-check right before deleting.
            if target.is_symlink():
                ensure_within(workspace_root, target.parent, allow_root=True)
                target.unlink()
            elif target.exists():
                ensure_within(workspace_root, target)
                shutil.rmtree(str(target), ignore_errors=True)
                # Re-prune after removing the dir
                try:
                    await _git("git", "-C", str(bare), "worktree", "prune")
                except Exception:
                    pass
            try:
                branch_list = await _git(
                    "git", "-C", str(bare), "branch", "--list", ws_branch
                )
                if ws_branch in branch_list:
                    await _git(
                        "git", "-C", str(bare), "branch", "-D", ws_branch
                    )
            except Exception:
                pass
            # Create a new local branch tracking the source branch, then add worktree
            await _git(
                "git", "-C", str(bare), "worktree", "add",
                "-b", ws_branch, str(target), start_point or branch
            )
        return target

    @staticmethod
    async def remove_worktree(
        bare: Path, workspace_root: Path, branch: str, subdir: str = "workspace"
    ) -> None:
        """Remove the worktree at `workspace_root/<subdir>` and prune bare metadata."""
        target = workspace_root / subdir
        lock = await _lock_for(bare)
        async with lock:
            # Delete the checkout ourselves rather than `worktree remove`, so
            # host git never opens the workspace-writable worktree (BB12).
            if target.is_symlink():
                target.unlink()
            elif target.exists():
                ensure_within(workspace_root, target)
                shutil.rmtree(str(target))
            await _git("git", "-C", str(bare), "worktree", "prune")
