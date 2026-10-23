"""GET /files and GET /files/{path} routes (SD-02, SD-03)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import structlog
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

from warren_sidecar.files import PathDenied, read_file, walk_tree

log = structlog.get_logger(__name__)
router = APIRouter()

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


@router.get("/files")
async def list_files(request: Request) -> list[dict]:
    """Return a directory tree excluding .git, node_modules, .venv, .env*, gitignored paths."""
    return await asyncio.to_thread(walk_tree, _workspace_root(request))


@router.get("/files/{file_path:path}")
async def get_file(file_path: str, request: Request) -> Response:
    """Return file contents with 1 MiB cap (413 if exceeded).

    Excluded paths 404 exactly as if absent; symlinks are refused, never followed.
    """
    root = _workspace_root(request)
    try:
        data = await asyncio.to_thread(read_file, root, file_path, MAX_FILE_BYTES + 1)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="not found") from None
    except IsADirectoryError:
        raise HTTPException(status_code=400, detail="path is a directory") from None
    except PathDenied as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from None

    if len(data) > MAX_FILE_BYTES:
        raise HTTPException(status_code=413, detail="file exceeds 1 MiB limit")

    return Response(content=data, media_type="application/octet-stream")
