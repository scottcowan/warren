"""The sidecar: an in-container agent-state recorder (AG5/AM1).

Tails the workspace's tmux pane (WorkspaceAppSupervisor) through the OSC 7501
parser (OscRecorder), which writes `<harness root>/.session/osc-state.json`. The
server reads that file host-side. Nothing listens: the orchestrator never dials the
sidecar (docs/threat-model.md).
"""

from __future__ import annotations

import asyncio
import os
import threading

import structlog

from warren_sidecar.agent_state import OscRecorder
from warren_sidecar.supervisor import WorkspaceAppSupervisor

log = structlog.get_logger(__name__)

DEFAULT_HARNESS_ROOT = "/var/lib/warren/harness"


def session_dir() -> str:
    root = os.environ.get("WARREN_HARNESS_ROOT") or DEFAULT_HARNESS_ROOT
    return f"{root.rstrip('/')}/.session"


async def run(stop: asyncio.Event | None = None) -> None:
    """Record until `stop` is set (forever when None)."""
    supervisor = WorkspaceAppSupervisor(on_output=OscRecorder(session_dir()).feed)
    await supervisor.start()
    try:
        await (stop or asyncio.Event()).wait()
    finally:
        await supervisor.stop()


def start_thread() -> threading.Thread:
    """Run the recorder on its own event loop in a daemon thread."""
    thread = threading.Thread(target=asyncio.run, args=(run(),), name="warren-sidecar", daemon=True)
    thread.start()
    return thread
