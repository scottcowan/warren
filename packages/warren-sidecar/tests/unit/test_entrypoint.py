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
    """When WARREN_WORKTREE_PATHS is empty, order must be: claude_md_ready, workspace_ready."""
    result = _run_entrypoint({"WARREN_WORKSPACE_ID": "ws-test"})
    events = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    types = [e["type"] for e in events]
    assert types == ["claude_md_ready", "workspace_ready"]


def test_preflight_fail_missing_workspace_id():
    """Entrypoint must exit non-zero and emit workspace_failed when WARREN_WORKSPACE_ID is absent."""
    result = _run_entrypoint({})
    assert result.returncode != 0
    assert "workspace_failed" in result.stdout



@pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell shim")
def test_entrypoint_starts_the_app_and_the_agent_state_recorder(tmp_path):
    """A `tmux` shim on PATH stands in for the workspace session: it records what the
    entrypoint (app launch) and the recorder (session probe, pipe-pane) ask of it, and
    writes an OSC 7501 state into the pane log the recorder tails."""
    calls = tmp_path / "tmux-calls"
    app_env = tmp_path / "app-env"
    session = tmp_path / "harness" / ".session"
    session.mkdir(parents=True)
    shim = tmp_path / "bin" / "tmux"
    shim.parent.mkdir()
    shim.write_text(
        "#!/bin/sh\n"
        f'echo "$1" >> "{calls}"\n'
        'case "$1" in\n'
        f'  new-session) env > "{app_env}"\n'
        "    (sleep 1; printf '\\033]7501;working\\007\\n' >> \"$TMPDIR/warren-sidecar-pane-main.log\") & ;;\n"
        "  wait-for) sleep 4 ;;\n"
        "esac\n"
        "exit 0\n"
    )
    shim.chmod(0o755)
    result = _run_entrypoint({
        "WARREN_WORKSPACE_ID": "ws-test",
        "WARREN_HARNESS_ROOT": str(tmp_path / "harness"),
        "TMPDIR": str(tmp_path),
        "PATH": f"{shim.parent}{os.pathsep}{_BASE_ENV['PATH']}",
    })
    assert result.returncode == 0, result.stdout + result.stderr
    invoked = calls.read_text().split()
    assert "new-session" in invoked
    assert {"has-session", "pipe-pane"} <= set(invoked)
    assert "WARREN_WORKSPACE_ID=ws-test" in app_env.read_text()
    assert json.loads((session / "osc-state.json").read_text())["state"] == "working"
