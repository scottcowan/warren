"""warren-sidecar FastAPI application with lifespan and all routes."""

from __future__ import annotations

import asyncio
import contextlib
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from warren_sidecar.agent_state import OscRecorder
from warren_sidecar.auth import SidecarTokenMiddleware
from warren_sidecar.config import SidecarSettings
from warren_sidecar.events import EventBuffer
from warren_sidecar.supervisor import WorkspaceAppSupervisor

log = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = SidecarSettings()
    event_buffer = EventBuffer()
    osc = OscRecorder(f"{settings.harness_root.rstrip('/')}/.session")
    supervisor = WorkspaceAppSupervisor(event_buffer=event_buffer, on_output=osc.feed)

    if not settings.sidecar_token:
        log.warning("sidecar_token_unset", detail="every request except /healthz is refused")
    app.state.settings = settings
    app.state.event_buffer = event_buffer
    app.state.supervisor = supervisor

    # supervisor.start() can block for several seconds waiting for the
    # entrypoint's tmux session to appear (_wait_for_session) -- the
    # entrypoint only starts that tmux session AFTER its own preflight phase
    # (which starts this sidecar) returns, so the wait is structurally
    # guaranteed to run near its full timeout on every no-TTY/server-mode
    # workspace. uvicorn does not bind the socket until lifespan startup
    # returns, so awaiting start() here directly raced the entrypoint's own
    # (much shorter) socket-ready poll and failed it in practice. Run it as
    # a background task instead so the socket binds immediately regardless
    # of whether/when the tmux session shows up.
    supervisor_task = asyncio.create_task(supervisor.start())
    app.state.supervisor_task = supervisor_task
    try:
        yield
    finally:
        supervisor_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await supervisor_task
        await supervisor.stop()
        app.state._state.clear()


app = FastAPI(title="warren-sidecar", version="0.1.0", lifespan=lifespan)
app.add_middleware(SidecarTokenMiddleware)

from warren_sidecar.routes import healthz as healthz_routes  # noqa: E402
app.include_router(healthz_routes.router)
from warren_sidecar.routes import exec as exec_routes  # noqa: E402
app.include_router(exec_routes.router)
from warren_sidecar.routes import events as events_routes  # noqa: E402
app.include_router(events_routes.router)
from warren_sidecar.routes import files as files_routes  # noqa: E402
app.include_router(files_routes.router)
from warren_sidecar.routes import diff as diff_routes  # noqa: E402
app.include_router(diff_routes.router)
from warren_sidecar.routes import agent_state as agent_state_routes  # noqa: E402
app.include_router(agent_state_routes.router)
