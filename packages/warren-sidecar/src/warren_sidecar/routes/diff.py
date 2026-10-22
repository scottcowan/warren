"""GET /diff route — git diff HEAD (SD-02)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import structlog
from fastapi import APIRouter, Request

log = structlog.get_logger(__name__)
router = APIRouter()


@router.get("/diff")
async def get_diff(request: Request) -> dict:
    settings = request.app.state.settings
    paths = settings.worktree_paths if settings.worktree_paths else ""
    if paths:
        first = paths.split(":")[0]
        cwd = first if first else "/workspace"
    else:
        cwd = "/workspace"

    # Fall back to cwd if the path doesn't exist (test environments)
    if not Path(cwd).exists():
        import os
        cwd = os.getcwd()

    proc = await asyncio.create_subprocess_exec(
        "git", "diff", "HEAD",
        cwd=cwd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    return {
        "diff": stdout.decode(errors="replace"),
        "stderr": stderr.decode(errors="replace"),
        "returncode": proc.returncode,
    }
