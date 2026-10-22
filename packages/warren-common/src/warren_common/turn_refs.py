"""Generic turn-ref protocol (SEED-011, HIST-05/09/10/11).

A turn-checkpointing tool (git-turn, or any other) writes refs under its own
namespace and declares their shape in a JSON blob at `refs/git-turn/format`.
Warren reads that blob rather than knowing about any one tool.

Every repo touched here is workspace-writable, so all git runs through a
shadow git dir (safe_git, BB12) and session.json is written without following
symlinks.
"""

from __future__ import annotations

import contextlib
import json
import os
import re
import stat
import uuid
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .safe_git import SafeGitError, own_objects_dir, run_git, shadow_git_dir

TURN_NAMESPACE = "refs/git-turn"
FORMAT_REF = f"{TURN_NAMESPACE}/format"
DEFAULT_SNAPSHOT_MODEL = "head-ref-only"
# git-turn's shipped format blob has no snapshot_model; its refs are two-tree snapshots.
_TOOL_DEFAULT_MODELS = {"git-turn": "two-tree-dangling-commit"}
# Models whose ref is a snapshot commit: only its tree is carried into a branch.
TREE_MODELS = frozenset({"two-tree-dangling-commit", "dangling-commit-with-metadata-message"})
# Models whose ref is a real commit: the branch starts at that commit.
COMMIT_MODELS = frozenset({"head-ref-only", "session-branch-commit"})
SNAPSHOT_MODELS = TREE_MODELS | COMMIT_MODELS

SESSION_DIR = "git-turn"
SESSION_FILE = "session.json"

_MAX_FORMAT_BYTES = 64 * 1024
_MAX_REFS = 10_000
_GIT_TIMEOUT_S = 30.0
_REF_RE = re.compile(r"^refs/[A-Za-z0-9._/-]*$")
# POSIX only (dir_fd reads); getattr keeps the module importable on Windows clients.
_NOFOLLOW_DIR = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
_IDENT_ENV = {
    "GIT_AUTHOR_NAME": "warren",
    "GIT_AUTHOR_EMAIL": "warren@localhost",
    "GIT_COMMITTER_NAME": "warren",
    "GIT_COMMITTER_EMAIL": "warren@localhost",
}


class TurnRefError(ValueError):
    """A ref, prefix or format blob is invalid or can't be resolved."""


class TurnRefNotFound(TurnRefError):
    """The named ref doesn't exist."""


@dataclass(frozen=True)
class Snapshot:
    ref: str
    commit: str
    tree: str
    snapshot_model: str
    objects: Path
    format: dict = field(default_factory=dict)


def validate_prefix(prefix: str) -> str:
    if not _REF_RE.match(prefix) or ".." in prefix or "//" in prefix:
        raise TurnRefError(f"invalid ref prefix: {prefix!r}")
    return prefix


def _validate_ref(ref: str) -> str:
    validate_prefix(ref)
    if ref.endswith("/") or ref == FORMAT_REF:
        raise TurnRefError(f"invalid ref: {ref!r}")
    try:
        run_git("check-ref-format", ref, isolated=True, timeout=_GIT_TIMEOUT_S)
    except SafeGitError as e:
        raise TurnRefError(f"invalid ref: {ref!r}") from e
    return ref


Git = Callable[..., str]


@contextlib.contextmanager
def _reader(git_dir: Path, shadow_root: Path) -> Iterator[Git]:
    # shadow_git_dir refuses a repo with object alternates (safe_git.own_objects_dir).
    with shadow_git_dir(git_dir, shadow_root, []) as shadow:
        env = shadow.env()
        yield lambda *args: run_git(*args, extra_env=env, isolated=True, timeout=_GIT_TIMEOUT_S)


def _resolve(git: Git, rev: str) -> str | None:
    try:
        return git("rev-parse", "-q", "--verify", "--end-of-options", rev).strip() or None
    except SafeGitError:
        return None


def _read_format(git: Git) -> dict:
    sha = _resolve(git, f"{FORMAT_REF}^{{blob}}")
    if sha is None:
        return {"snapshot_model": DEFAULT_SNAPSHOT_MODEL}
    if int(git("cat-file", "-s", sha).strip()) > _MAX_FORMAT_BYTES:
        raise TurnRefError(f"{FORMAT_REF} blob exceeds {_MAX_FORMAT_BYTES} bytes")
    try:
        data = json.loads(git("cat-file", "blob", sha))
    except json.JSONDecodeError as e:
        raise TurnRefError(f"{FORMAT_REF} is not valid JSON") from e
    if not isinstance(data, dict):
        raise TurnRefError(f"{FORMAT_REF} must be a JSON object")
    if "snapshot_model" not in data:
        data["snapshot_model"] = _TOOL_DEFAULT_MODELS.get(data.get("tool"), DEFAULT_SNAPSHOT_MODEL)
    return data


def read_turn_format(git_dir: Path, shadow_root: Path) -> dict:
    """The parsed `refs/git-turn/format` blob, or `{"snapshot_model": "head-ref-only"}`."""
    with _reader(git_dir, shadow_root) as git:
        return _read_format(git)


def list_refs(git_dir: Path, shadow_root: Path, prefix: str = f"{TURN_NAMESPACE}/") -> list[dict]:
    validate_prefix(prefix)
    with _reader(git_dir, shadow_root) as git:
        out = git(
            "for-each-ref", f"--count={_MAX_REFS}",
            "--format=%(refname)%00%(objectname)", "--end-of-options", prefix,
        )
    refs = []
    for line in out.splitlines():
        name, _, sha = line.partition("\0")
        if name.startswith(prefix):
            refs.append({"ref": name, "sha": sha})
    return refs


def resolve_snapshot(git_dir: Path, shadow_root: Path, ref: str) -> Snapshot:
    """Resolve `ref` to the commit/tree a branch should start from (HIST-05)."""
    _validate_ref(ref)
    with _reader(git_dir, shadow_root) as git:
        fmt = _read_format(git)
        model = fmt["snapshot_model"]
        if model not in SNAPSHOT_MODELS:
            raise TurnRefError(f"unsupported snapshot_model {model!r}")
        try:
            sha = git("show-ref", "--verify", "--hash", "--end-of-options", ref).strip()
        except SafeGitError as e:
            raise TurnRefNotFound(f"ref not found: {ref}") from e
        commit = _resolve(git, f"{sha}^{{commit}}")
        tree = _resolve(git, f"{sha}^{{tree}}")
    if commit is None or tree is None:
        raise TurnRefError(f"{ref} does not point at a commit")
    return Snapshot(ref, commit, tree, model, git_dir / "objects", fmt)


def apply_snapshot(
    git_dir: Path, work_tree: Path, snapshot: Snapshot, branch: str, shadow_root: Path
) -> str:
    """Check out `snapshot` on a new `branch` in the clone at `work_tree`.

    The snapshot's objects are borrowed from the source repo for this call only
    and repacked into this repo, so the result doesn't depend on the source.
    Returns the new branch tip.
    """
    # The one alternate host git is given is warren's choice, never the repo's:
    # the source store gets the same checks as the destination's own
    # (plain dir, no symlinks, no alternates of its own).
    source = own_objects_dir(snapshot.objects.parent)
    if source != snapshot.objects:
        raise SafeGitError(f"{snapshot.objects} is not a repo's own objects dir")
    with shadow_git_dir(git_dir, shadow_root, [], work_tree=work_tree) as shadow:
        env = {**shadow.env(), **_IDENT_ENV, "GIT_ALTERNATE_OBJECT_DIRECTORIES": str(source)}

        def git(*args: str) -> str:
            return run_git(*args, extra_env=env, isolated=True, timeout=_GIT_TIMEOUT_S)

        if snapshot.snapshot_model in TREE_MODELS:
            message = (
                f"warren: branch from {snapshot.ref}\n\n"
                f"Source-Commit: {snapshot.commit}\nSnapshot-Model: {snapshot.snapshot_model}\n"
            )
            tip = git("commit-tree", snapshot.tree, "-p", "HEAD", "-m", message).strip()
        else:
            tip = snapshot.commit
        git("update-ref", f"refs/heads/{branch}", tip, "")
        git("repack", "-a", "-d", "-q")
        git("checkout", "-q", branch)
    return tip


def write_session_file(
    git_dir: Path,
    workspace_id: str,
    *,
    session_id: str | None = None,
    refs_namespace: str = TURN_NAMESPACE,
) -> dict:
    """Write `<git_dir>/git-turn/session.json` (HIST-10), never following a symlink."""
    payload = {
        "session_id": session_id or str(uuid.uuid4()),
        "workspace_id": workspace_id,
        "turn_n": 0,
        "refs_namespace": refs_namespace,
    }
    data = (json.dumps(payload, indent=2) + "\n").encode()
    root = os.open(git_dir, _NOFOLLOW_DIR)
    try:
        with contextlib.suppress(FileExistsError):
            os.mkdir(SESSION_DIR, 0o755, dir_fd=root)
        sub = os.open(SESSION_DIR, _NOFOLLOW_DIR, dir_fd=root)
    finally:
        os.close(root)
    try:
        tmp = f".{SESSION_FILE}.{uuid.uuid4().hex}.tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644, dir_fd=sub)
        try:
            os.write(fd, data)
        finally:
            os.close(fd)
        os.replace(tmp, SESSION_FILE, src_dir_fd=sub, dst_dir_fd=sub)
    finally:
        os.close(sub)
    return payload


def worktree_git_dir(worktree: Path) -> Path | None:
    """The git dir for `worktree`, trusting only what a workspace can't forge.

    A plain `.git` directory is used as-is. A linked worktree's `.git` file is
    workspace-writable, so its target is accepted only if it's a `.git-store`
    worktree entry whose own (read-only) `gitdir` backlink names this worktree.
    """
    dot_git = worktree / ".git"
    try:
        st = os.lstat(dot_git)
    except OSError:
        return None
    if stat.S_ISDIR(st.st_mode):
        return dot_git
    if not stat.S_ISREG(st.st_mode):
        return None
    try:
        content = dot_git.read_text(errors="replace").strip()
    except OSError:
        return None
    if not content.startswith("gitdir:"):
        return None
    target = Path(content[len("gitdir:"):].strip())
    if not target.is_absolute():
        target = worktree / target
    target = Path(os.path.normpath(target))
    if target.parent.name != "worktrees" or not target.parent.parent.name.endswith(".git-store"):
        return None
    try:
        backlink = (target / "gitdir").read_text(errors="replace").strip()
    except OSError:
        return None
    if Path(os.path.normpath(backlink)) != Path(os.path.normpath(dot_git)):
        return None
    return target
