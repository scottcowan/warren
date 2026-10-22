"""Path containment checks for host-side operations on workspace paths."""

from __future__ import annotations

import os
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
