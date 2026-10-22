"""AH2: what a single-turn workspace left behind once its app exited.

Everything read here was written by the agent, so: git runs only through a read-only
shadow git dir (warren_common.safe_git, no repo config/hooks/filters, nothing written
back), files are opened without following symlinks, and every path must resolve inside
the workspace's own storage root. Each piece fails on its own; callers record the error
and carry on.
"""
from __future__ import annotations

import json
import os
import re
import stat
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from warren.runtime.ecs_git import EFS_MOUNT_PATH
from warren_common.safe_git import SafeGitError, readonly_shadow_git_dir, run_git

VERDICT_PATH = "/workspace/.warren/verdict.json"
VERDICT_REL = (".warren", "verdict.json")
MAX_VERDICT_BYTES = 256 * 1024
_GIT_TIMEOUT_S = 30.0
_SAFE_COMPONENT = re.compile(r"^[A-Za-z0-9_.-]+$")
_SAFE_MOUNT = re.compile(r"^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$")
_NOFOLLOW_DIR = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW


class CaptureError(Exception):
    pass


@dataclass
class RepoTarget:
    mount: str
    work_tree: Path
    git_dir: Path
    common_dir: Path
    base_branch: str | None = None


def _safe_component(name: str) -> bool:
    return bool(_SAFE_COMPONENT.match(name)) and name not in (".", "..")


def _safe_mount(mount: str) -> bool:
    return bool(_SAFE_MOUNT.match(mount)) and all(p not in (".", "..") for p in mount.split("/"))


def read_nofollow(base: Path, parts: Sequence[str], max_bytes: int) -> bytes | None:
    """`base/<parts>` read without following a symlink anywhere below `base`; None if absent."""
    try:
        fd = os.open(base, _NOFOLLOW_DIR)
    except FileNotFoundError:
        return None
    try:
        for part in parts[:-1]:
            nfd = os.open(part, _NOFOLLOW_DIR, dir_fd=fd)
            os.close(fd)
            fd = nfd
        ffd = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
    except FileNotFoundError:
        os.close(fd)
        return None
    except OSError as exc:
        os.close(fd)
        raise CaptureError(f"{'/'.join(parts)}: {exc.strerror or exc}") from exc
    os.close(fd)
    try:
        if not stat.S_ISREG(os.fstat(ffd).st_mode):
            raise CaptureError(f"{'/'.join(parts)} is not a regular file")
        chunks: list[bytes] = []
        size = 0
        while size <= max_bytes:
            chunk = os.read(ffd, max_bytes + 1 - size)
            if not chunk:
                break
            chunks.append(chunk)
            size += len(chunk)
    finally:
        os.close(ffd)
    if size > max_bytes:
        raise CaptureError(f"{'/'.join(parts)} exceeds {max_bytes} bytes")
    return b"".join(chunks)


def parse_verdict(data: bytes) -> dict[str, Any]:
    try:
        value = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise CaptureError(f"verdict.json is not valid JSON: {exc}") from exc
    if not isinstance(value, dict):
        raise CaptureError("verdict.json must contain a JSON object")
    return value


def _require_within(root: Path, *paths: Path) -> None:
    real_root = os.path.realpath(root)
    for p in paths:
        real = os.path.realpath(p)
        if real != real_root and not real.startswith(real_root + os.sep):
            raise CaptureError(f"{p} resolves outside the workspace's storage")


def inspect_repo(target: RepoTarget, shadow_root: Path) -> dict[str, Any]:
    """{branch, head_commit, base_commit, branch_safe, is_clean} for one checkout.

    branch_safe: HEAD is on a named branch other than the base branch the workspace
    started from (or, with no known base, a warren/ workspace branch).
    """
    with readonly_shadow_git_dir(
        target.git_dir, shadow_root, common_dir=target.common_dir, work_tree=target.work_tree
    ) as shadow:
        env = shadow.env()

        def git(*args: str) -> str:
            return run_git(
                "--no-optional-locks", *args, extra_env=env, isolated=True, timeout=_GIT_TIMEOUT_S
            )

        head = git("rev-parse", "--verify", "HEAD^{commit}").strip()
        try:
            branch: str | None = git("symbolic-ref", "--quiet", "--short", "HEAD").strip() or None
        except SafeGitError:
            branch = None
        base_commit = None
        if target.base_branch:
            for ref in (f"refs/remotes/origin/{target.base_branch}", f"refs/heads/{target.base_branch}"):
                try:
                    base_commit = git("merge-base", "HEAD", ref).strip()
                    break
                except SafeGitError:
                    continue
        is_clean = not git("status", "--porcelain", "--ignore-submodules=all").strip()
    if branch is None:
        branch_safe = False
    elif target.base_branch:
        branch_safe = branch != target.base_branch
    else:
        branch_safe = branch.startswith("warren/")
    return {
        "branch": branch,
        "head_commit": head,
        "base_commit": base_commit,
        "branch_safe": branch_safe,
        "is_clean": is_clean,
    }


def podman_targets(git_manager: Any, workspace_id: str, folders: Sequence[Any]) -> list[RepoTarget]:
    """Host-side clones GitManager made for this workspace (registry._materialize_and_provision)."""
    root = git_manager.worktree_path(workspace_id)
    targets: list[RepoTarget] = []
    if os.path.lexists(root / ".git"):
        targets.append(RepoTarget("", root, root / ".git", root / ".git"))
    for folder in folders:
        if folder.type not in ("git-worktree", "git-clone") or not folder.url:
            continue
        path = git_manager.folder_worktree_path(workspace_id, folder.name)
        if os.path.lexists(path / ".git"):
            targets.append(RepoTarget(folder.mount, path, path / ".git", path / ".git", folder.branch or None))
    for t in targets:
        _require_within(root, t.work_tree, t.git_dir)
    return targets


def _linked_git_dir(work_tree: Path, store: Path, name: str) -> Path:
    data = read_nofollow(work_tree, [".git"], 4096)
    if data is None:
        raise CaptureError(f"{work_tree.name}: no .git")
    line = data.decode("utf-8", "replace").strip()
    prefix = f"gitdir: {EFS_MOUNT_PATH}/git/{name}.git-store/worktrees/"
    rest = line[len(prefix):] if line.startswith(prefix) else ""
    if not _safe_component(rest):
        raise CaptureError(f"{work_tree.name}/.git does not point at its own worktree")
    return store / "worktrees" / rest


def ecs_targets(volume_root: Path, folders: Sequence[Any]) -> tuple[list[RepoTarget], list[str]]:
    """Checkouts git-init made on this workspace's EFS volume (images/ecs-base/git-materialize.sh),
    read through the control plane's own mount of the file system root."""
    targets: list[RepoTarget] = []
    errors: list[str] = []
    for folder in folders:
        if folder.type not in ("git-worktree", "git-clone") or not folder.url:
            continue
        try:
            if not (_safe_component(folder.name) and _safe_mount(folder.mount)):
                raise CaptureError(f"unsafe folder {folder.name!r}")
            work_tree = volume_root / "workspace" / folder.mount
            _require_within(volume_root, work_tree)
            if folder.type == "git-worktree":
                common = volume_root / "git" / f"{folder.name}.git-store"
                git_dir = _linked_git_dir(work_tree, common, folder.name)
            else:
                common = git_dir = work_tree / ".git"
            _require_within(volume_root, work_tree, git_dir, common)
            targets.append(RepoTarget(folder.mount, work_tree, git_dir, common, folder.branch or None))
        except CaptureError as exc:
            errors.append(f"git[{folder.mount}]: {exc}")
    return targets, errors


def inspect_all(targets: Sequence[RepoTarget], shadow_root: Path) -> tuple[list[dict[str, Any]], list[str]]:
    results: list[dict[str, Any]] = []
    errors: list[str] = []
    for t in targets:
        try:
            results.append({"mount": t.mount, **inspect_repo(t, shadow_root)})
        except (SafeGitError, CaptureError, OSError) as exc:
            errors.append(f"git[{t.mount or '.'}]: {exc}")
    return results, errors
