"""Gitignore-aware, descriptor-based file access for GET /files (SD-03).

Every path below the workspace root is opened relative to its parent's
directory descriptor with O_NOFOLLOW, so a symlink (or a component swapped for
one mid-request) is never followed out of the root, and the listing and a
direct read apply the same exclusions (audit finding 12).
"""

from __future__ import annotations

import os
import stat
from pathlib import Path, PurePosixPath

import pathspec

_ALWAYS_EXCLUDE = {".git", "node_modules", ".venv", "__pycache__"}
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_DIR_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | _CLOEXEC
_FILE_FLAGS = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | _CLOEXEC
_GITIGNORE_MAX_BYTES = 1_048_576


class PathDenied(Exception):
    """The request path is malformed, excluded, a symlink or not a regular file."""


def _read_gitignore(root_fd: int) -> list[str]:
    try:
        fd = os.open(".gitignore", _FILE_FLAGS, dir_fd=root_fd)
    except OSError:
        return []
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return []
        return os.read(fd, _GITIGNORE_MAX_BYTES).decode(errors="replace").splitlines()
    finally:
        os.close(fd)


def _gitignore_spec(root_fd: int) -> pathspec.PathSpec:
    return pathspec.PathSpec.from_lines("gitignore", _read_gitignore(root_fd))


def _is_excluded(rel: PurePosixPath, gi_spec: pathspec.PathSpec) -> bool:
    if any(part in _ALWAYS_EXCLUDE for part in rel.parts):
        return True
    if rel.parts[-1].startswith(".env"):
        return True
    return gi_spec.match_file(str(rel))


def _open_root(root: Path) -> int:
    # The configured root itself is trusted (it may legitimately be a symlink,
    # e.g. /workspace); nothing below it is followed.
    return os.open(root, os.O_RDONLY | os.O_DIRECTORY | _CLOEXEC)


def walk_tree(root: Path) -> list[dict]:
    """Return a sorted list of non-excluded file/dir entries under root."""
    try:
        root_fd = _open_root(root)
    except OSError:
        return []
    results: list[dict] = []
    try:
        _walk(root_fd, PurePosixPath(), _gitignore_spec(root_fd), results)
    finally:
        os.close(root_fd)
    results.sort(key=lambda e: e["path"])
    return results


def _walk(dir_fd: int, rel: PurePosixPath, gi_spec: pathspec.PathSpec, results: list[dict]) -> None:
    try:
        with os.scandir(dir_fd) as it:
            entries = sorted(it, key=lambda e: e.name)
    except OSError:
        return
    for entry in entries:
        child = rel / entry.name
        if _is_excluded(child, gi_spec):
            continue
        try:
            st = entry.stat(follow_symlinks=False)
        except OSError:
            continue
        if stat.S_ISLNK(st.st_mode):
            continue
        is_dir = stat.S_ISDIR(st.st_mode)
        results.append({"path": str(child), "size": st.st_size, "is_dir": is_dir})
        if is_dir:
            try:
                child_fd = os.open(entry.name, _DIR_FLAGS, dir_fd=dir_fd)
            except OSError:
                continue
            try:
                _walk(child_fd, child, gi_spec, results)
            finally:
                os.close(child_fd)


def request_parts(file_path: str) -> tuple[str, ...]:
    """Split a request path into components, always relative to the root.

    A leading "/" is ignored (an absolute request is joined onto the root, never
    served as-is); "." and ".." are rejected outright rather than resolved.
    """
    parts = tuple(p for p in file_path.split("/") if p)
    if not parts or any(p in (".", "..") or "\0" in p for p in parts):
        raise PathDenied("path traversal denied")
    return parts


def read_file(root: Path, file_path: str, limit: int) -> bytes:
    """Read up to `limit` bytes of a non-excluded regular file under `root`.

    Raises FileNotFoundError, IsADirectoryError or PathDenied.
    """
    parts = request_parts(file_path)
    try:
        dir_fd = _open_root(root)
    except OSError as exc:
        raise FileNotFoundError(file_path) from exc
    try:
        # Same rules as the listing, which never descends into an excluded dir.
        gi_spec = _gitignore_spec(dir_fd)
        if any(_is_excluded(PurePosixPath(*parts[:i]), gi_spec) for i in range(1, len(parts) + 1)):
            raise FileNotFoundError(file_path)
        for part in parts[:-1]:
            dir_fd = _step(dir_fd, part, file_path)
        fd = _open_leaf(dir_fd, parts[-1], file_path)
    finally:
        os.close(dir_fd)
    try:
        mode = os.fstat(fd).st_mode
        if stat.S_ISDIR(mode):
            raise IsADirectoryError(file_path)
        if not stat.S_ISREG(mode):
            raise PathDenied("not a regular file")
        chunks: list[bytes] = []
        remaining = limit
        while remaining > 0:
            chunk = os.read(fd, min(remaining, 65536))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)
    finally:
        os.close(fd)


def _step(dir_fd: int, name: str, file_path: str) -> int:
    try:
        next_fd = os.open(name, _DIR_FLAGS, dir_fd=dir_fd)
    except FileNotFoundError:
        raise
    except OSError as exc:
        if _is_symlink(dir_fd, name):
            raise PathDenied("symbolic links are not followed") from exc
        raise FileNotFoundError(file_path) from exc
    os.close(dir_fd)
    return next_fd


def _open_leaf(dir_fd: int, name: str, file_path: str) -> int:
    try:
        return os.open(name, _FILE_FLAGS, dir_fd=dir_fd)
    except (FileNotFoundError, IsADirectoryError):
        raise
    except OSError as exc:
        if _is_symlink(dir_fd, name):
            raise PathDenied("symbolic links are not followed") from exc
        raise FileNotFoundError(file_path) from exc


def _is_symlink(dir_fd: int, name: str) -> bool:
    try:
        return stat.S_ISLNK(os.stat(name, dir_fd=dir_fd, follow_symlinks=False).st_mode)
    except OSError:
        return False
