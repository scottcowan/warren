"""AH1: git materialization for ECS workspaces.

Podman/docker workspaces get their checkouts from warren-server's own GitManager
(registry.py), bind-mounted from this host. An ECS task runs elsewhere, so instead the
task definition gets a non-essential `git-init` container that runs
images/ecs-base/git-materialize.sh against the same `/var/lib/warren` volume, and the
workspace container `dependsOn` it with condition SUCCESS.

The clone credentials (GITHUB_PAT / WARREN_GIT_SSH_KEY / a folder's pat_secret or
ssh_key_secret) are delivered to the init container only (runtime/ecs_secrets.py's
git-init.env) and withheld from the workspace's, so the agent never holds them.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import structlog
from warren.git.manager import (
    GitError,
    _is_ssh_url,
    _validate_clone_url,
    _validate_folder_name,
)
from warren_common.runtime.base import WorkspaceSpec

log = structlog.get_logger(__name__)

GIT_INIT_CONTAINER = "git-init"
GIT_INIT_ENTRYPOINT = "/usr/local/bin/warren-git-materialize"
EFS_MOUNT_PATH = "/var/lib/warren"
WORKSPACE_DIR = f"{EFS_MOUNT_PATH}/workspace"

DEFAULT_PAT_SECRET = "GITHUB_PAT"
DEFAULT_SSH_KEY_SECRET = "WARREN_GIT_SSH_KEY"

_SAFE_MOUNT = re.compile(r"^[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*$")
_SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_slug_non_alnum = re.compile(r"[^a-z0-9]+")


@dataclass
class GitInitPlan:
    folders_env: str
    init_secret_names: tuple[str, ...] = field(default_factory=tuple)
    # EBS bare seeds (runtime/ebs_seeds.py): the volume is created from the owner's seed
    # snapshot, so git-init may clone from the bares on it (WARREN_GIT_SEEDED=1).
    seeded: bool = False


@dataclass(frozen=True)
class GitFolderRef:
    """A validated git folder: what git-init clones and with which credential."""

    kind: str  # "worktree" | "clone"
    name: str
    mount: str
    url: str
    branch: str
    cred_kind: str  # "pat" | "ssh"
    cred_secret: str


def git_folder_refs(folders, *, workspace_id: str = "") -> list[GitFolderRef]:
    """The folders git-init would materialize, validated like build_git_init_plan; the
    credential is the folder's configured secret name (available or not)."""
    out: list[GitFolderRef] = []
    for folder in folders:
        if folder.type not in ("git-worktree", "git-clone") or not folder.url:
            continue
        try:
            _validate_folder_name(folder.name)
            _validate_mount(folder.mount)
            _validate_clone_url(folder.url)
            _validate_ref(folder.branch)
            if any(c in folder.url for c in "\t\n\r "):
                raise GitError("whitespace in url")
        except GitError as exc:
            log.warning(
                "ecs_git_folder_skipped", workspace_id=workspace_id,
                folder=folder.name, reason=str(exc),
            )
            continue
        if _is_ssh_url(folder.url):
            cred_kind, cred = "ssh", folder.ssh_key_secret or DEFAULT_SSH_KEY_SECRET
        else:
            cred_kind, cred = "pat", folder.pat_secret or DEFAULT_PAT_SECRET
        out.append(
            GitFolderRef(
                kind="worktree" if folder.type == "git-worktree" else "clone",
                name=folder.name, mount=folder.mount, url=folder.url, branch=folder.branch,
                cred_kind=cred_kind, cred_secret=cred,
            )
        )
    return out


def workspace_branch(workspace_id: str, intent: str, mount: str) -> str:
    """Mirrors warren_common.git.GitManager.add_worktree's per-workspace branch name."""
    subdir_slug = _slug_non_alnum.sub("-", mount.lower()).strip("-") or "workspace"
    intent_slug = _slug_non_alnum.sub("-", intent.lower()).strip("-") or "workspace"
    return f"warren/{intent_slug}/{workspace_id[:8]}/{subdir_slug}"


def _validate_mount(mount: str) -> None:
    if not _SAFE_MOUNT.match(mount) or any(p in (".", "..") for p in mount.split("/")):
        raise GitError(f"unsafe folder mount: {mount!r}")


def _validate_ref(ref: str) -> None:
    if not _SAFE_REF.match(ref) or ".." in ref or ref.endswith((".lock", "/", ".")):
        raise GitError(f"unsafe git ref: {ref!r}")


def build_git_init_plan(spec: WorkspaceSpec, available: set[str] | frozenset[str]) -> GitInitPlan | None:
    """Return the init-container plan for `spec`'s git folders, or None if it has none.

    `available` is the secret names this workspace will get; the credentials a folder
    needs go to the init container instead, everything else stays on the workspace.
    """
    records: list[str] = []
    cred_names: set[str] = set()

    for ref in git_folder_refs(spec.folders, workspace_id=spec.workspace_id):
        cred_kind, cred = ref.cred_kind, ref.cred_secret
        if cred in available:
            cred_names.add(cred)
        else:
            cred_kind, cred = "none", "-"
        if ref.kind == "worktree":
            ws_branch = workspace_branch(spec.workspace_id, spec.intent, ref.mount)
        else:
            ws_branch = "-"
        records.append(
            "\t".join([ref.kind, ref.name, ref.mount, ref.url, ref.branch, ws_branch, cred_kind, cred])
        )

    if not records:
        return None
    return GitInitPlan(folders_env="\n".join(records), init_secret_names=tuple(sorted(cred_names)))
