"""GET /files and GET /files/{path} routes (SD-02, SD-03)."""

from __future__ import annotations

from pathlib import Path

import aiofiles
import structlog
from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import Response

from warren_sidecar.auth import require_sidecar_token
from warren_sidecar.files import walk_tree

log = structlog.get_logger(__name__)
router = APIRouter(dependencies=[Depends(require_sidecar_token)])

MAX_FILE_BYTES = 1_048_576  # 1 MiB


def _workspace_root(request: Request) -> Path:
    """Resolve the workspace root from settings or fall back to /workspace."""
    settings = request.app.state.settings
    paths = settings.worktree_paths if settings.worktree_paths else ""
    if paths:
        first = paths.split(":")[0]
        if first:
            return Path(first)
    return Path("/workspace")


def _resolve_under_root(file_path: str, root: Path) -> Path:
    """Resolve `file_path` strictly under `root`, rejecting any escape.

    Audit 2026-10-16 P2 #47: a caller-supplied absolute path (e.g.
    `/proc/1/environ`) used to skip the traversal guard entirely by taking
    an early-return branch that trusted it outright. Every request path —
    absolute or relative, `..` or not — is now joined onto `root` and must
    resolve to a path at or under `root.resolve()`; nothing else is served.
    """
    # Path(file_path) with a leading "/" is absolute; stripping it first
    # means both "/etc/passwd" and "etc/passwd" land at the same place
    # (root / "etc/passwd") and are judged by the same containment check
    # below — there is no longer a code path that trusts an absolute
    # request path outright.
    relative = file_path.lstrip("/")
    root_resolved = root.resolve()
    resolved = (root_resolved / relative).resolve()
    if resolved != root_resolved and root_resolved not in resolved.parents:
        raise HTTPException(status_code=400, detail="path traversal denied")
    return resolved


@router.get("/files")
async def list_files(request: Request) -> list[dict]:
    """Return a directory tree excluding .git, node_modules, .venv, .env*, gitignored paths."""
    return walk_tree(_workspace_root(request))


@router.get("/files/{file_path:path}")
async def get_file(file_path: str, request: Request) -> Response:
    """Return file contents with 1 MiB cap (413 if exceeded)."""
    root = _workspace_root(request)
    resolved = _resolve_under_root(file_path, root)

    if not resolved.exists():
        raise HTTPException(status_code=404, detail="not found")
    if resolved.is_dir():
        raise HTTPException(status_code=400, detail="path is a directory")

    async with aiofiles.open(resolved, "rb") as f:
        data = await f.read(MAX_FILE_BYTES + 1)

    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail="file exceeds 1 MiB limit")

    return Response(content=data, media_type="application/octet-stream")
