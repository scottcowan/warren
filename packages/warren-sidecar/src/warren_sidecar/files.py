"""Gitignore-aware file tree walker for GET /files (SD-03)."""

from __future__ import annotations

from pathlib import Path

import pathspec

_ALWAYS_EXCLUDE = {".git", "node_modules", ".venv", "__pycache__"}


def _load_gitignore_spec(root: Path) -> pathspec.PathSpec:
    gi = root / ".gitignore"
    patterns = gi.read_text().splitlines() if gi.exists() else []
    return pathspec.PathSpec.from_lines("gitignore", patterns)


def _is_excluded(path: Path, root: Path, gi_spec: pathspec.PathSpec) -> bool:
    rel = path.relative_to(root)
    # Hard exclusions regardless of .gitignore
    if any(part in _ALWAYS_EXCLUDE for part in rel.parts):
        return True
    # .env* files — check last component only
    if rel.parts[-1].startswith(".env"):
        return True
    # gitignore spec
    return gi_spec.match_file(str(rel))


def walk_tree(root: Path) -> list[dict]:
    """Return a sorted list of non-excluded file/dir entries under root."""
    if not root.exists():
        return []
    gi_spec = _load_gitignore_spec(root)
    results: list[dict] = []
    _walk(root, root, gi_spec, results)
    results.sort(key=lambda e: e["path"])
    return results


def _walk(current: Path, root: Path, gi_spec: pathspec.PathSpec, results: list[dict]) -> None:
    try:
        entries = sorted(current.iterdir())
    except PermissionError:
        return
    for entry in entries:
        if _is_excluded(entry, root, gi_spec):
            continue
        rel = entry.relative_to(root)
        results.append({
            "path": str(rel),
            "size": entry.stat().st_size,
            "is_dir": entry.is_dir(),
        })
        if entry.is_dir():
            _walk(entry, root, gi_spec, results)
