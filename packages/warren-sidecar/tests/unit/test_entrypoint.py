"""IM-02: entrypoint.py NDJSON preflight event contract.

Tests run the entrypoint as a subprocess.  In container the entrypoint lives at
/entrypoint.py; in the monorepo dev/CI environment it lives at
images/warren-docker-base/entrypoint.py (resolved relative to the repo root via the
REPO_ROOT sentinel below).

WARREN_APP defaults to "bash" which may hang.  The helper sets WARREN_APP="true"
(POSIX no-op that exits 0) so the entrypoint exits promptly after emitting events.
It also passes through PATH so Python/uvicorn subprocesses can resolve binaries.
"""

from __future__ import annotations

import json
import os
import pathlib
import subprocess
import sys

import pytest

# Resolve entrypoint path: prefer /entrypoint.py (container), fall back to repo location.
_CONTAINER_EP = pathlib.Path("/entrypoint.py")
_REPO_EP = pathlib.Path(__file__).parents[4] / "images" / "warren-docker-base" / "entrypoint.py"
_ENTRYPOINT = str(_CONTAINER_EP if _CONTAINER_EP.exists() else _REPO_EP)

# Base environment for subprocess: inherit PATH + minimal WARREN_APP so entrypoint exits.
_BASE_ENV: dict[str, str] = {
    "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
    "WARREN_APP": "true",  # POSIX no-op; exits 0 immediately
}


def _run_entrypoint(env: dict[str, str]) -> subprocess.CompletedProcess:
    merged = {**_BASE_ENV, **env}
    return subprocess.run(
        [sys.executable, _ENTRYPOINT],
        env=merged,
        capture_output=True,
        text=True,
        timeout=15,
    )


def test_entrypoint_emits_workspace_ready():
    """Entrypoint final event must have type == 'workspace_ready'."""
    result = _run_entrypoint({"WARREN_WORKSPACE_ID": "ws-test"})
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    assert len(lines) > 0
    last = json.loads(lines[-1])
    assert last["type"] == "workspace_ready"


def test_entrypoint_emits_events_in_order():
    """When WARREN_WORKTREE_PATHS is empty, order must be: claude_md_ready, sidecar_ready, workspace_ready."""
    result = _run_entrypoint({"WARREN_WORKSPACE_ID": "ws-test"})
    events = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    types = [e["type"] for e in events]
    assert types == ["claude_md_ready", "sidecar_ready", "workspace_ready"]


def test_preflight_fail_missing_workspace_id():
    """Entrypoint must exit non-zero and emit workspace_failed when WARREN_WORKSPACE_ID is absent."""
    result = _run_entrypoint({})
    assert result.returncode != 0
    assert "workspace_failed" in result.stdout
