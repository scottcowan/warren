"""Path containment checks for host-side operations on workspace paths."""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path


class PathEscapeError(ValueError):
    """A path resolved outside the directory it was required to stay inside."""


def ensure_within(
    root: Path | str, target: Path | str, *, allow_root: bool = False
) -> Path:
    """Return `target`'s realpath, raising PathEscapeError unless it is inside
    `root`'s realpath (strictly inside unless `allow_root`).

    Symlinks anywhere along `target` (including the final component) are
    followed, so a symlinked parent that points elsewhere is rejected.
    """
    real_root = Path(os.path.realpath(root))
    real_target = Path(os.path.realpath(target))
    if real_target == real_root:
        if allow_root:
            return real_target
        raise PathEscapeError(f"{target} resolves to {root} itself")
    if not real_target.is_relative_to(real_root):
        raise PathEscapeError(f"{target} resolves outside {root}")
    return real_target


# Workspace ids are uuid4 strings (or a prefix of one typed at the CLI);
# anything else is refused before it is ever joined onto a host path.
_WORKSPACE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")


class UnsafeWorkspaceIdError(PathEscapeError):
    """A workspace id that is not a single safe path component."""


def validate_workspace_id(workspace_id: str) -> str:
    """Return `workspace_id` unchanged, or raise UnsafeWorkspaceIdError unless
    it is a single path component of the form warren generates (no
    separators, no `.`/`..`, not absolute, not empty)."""
    if not isinstance(workspace_id, str) or not _WORKSPACE_ID_RE.fullmatch(workspace_id):
        raise UnsafeWorkspaceIdError(f"invalid workspace id: {workspace_id!r}")
    return workspace_id


def workspace_child(root: Path | str, workspace_id: str) -> Path:
    """Return `root/<workspace_id>` after validating the id and refusing a
    symlinked entry or one whose resolved parent is not exactly `root`."""
    validate_workspace_id(workspace_id)
    root = Path(root)
    child = root / workspace_id
    if child.is_symlink():
        raise PathEscapeError(f"{child} is a symlink")
    if Path(os.path.realpath(child)).parent != Path(os.path.realpath(root)):
        raise PathEscapeError(f"{child} resolves outside {root}")
    return child


def ensure_private_dir(path: Path | str) -> Path:
    """Refuse `path` if it is a symlink, not a directory, not owned by the
    current user, or group/world-writable. Missing paths are allowed."""
    path = Path(path)
    try:
        st = os.lstat(path)
    except FileNotFoundError:
        return path
    if stat.S_ISLNK(st.st_mode) or not stat.S_ISDIR(st.st_mode):
        raise PathEscapeError(f"{path} is not a real directory")
    if hasattr(os, "getuid") and st.st_uid != os.getuid():
        raise PathEscapeError(f"{path} is not owned by the current user")
    if os.name != "nt" and st.st_mode & 0o022:
        raise PathEscapeError(f"{path} is group/world-writable")
    return path
