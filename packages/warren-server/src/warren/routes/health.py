"""Health and peer discovery endpoints — SV-01, PD-01, PD-02.

Audit 2026-10-16 P2 #45: /healthz is unauthenticated (auth/middleware.py's EXEMPT_PATHS
-- load balancers need it reachable with no token) so it must disclose nothing beyond
"is the process up": no podman socket path, no workspace counts, no secret counts. The
detailed diagnostics that used to live in /healthz moved to /healthz/detail, which is
NOT exempt and additionally requires an admin token (Depends(require_admin)) -- those
fields (socket paths, live workspace/secret inventory) are only useful to someone who
already has deep operational access, not to an anonymous caller.
"""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel

from warren.auth.deps import require_admin
from warren.preflight import _WARREN_VERSION, check_podman_health

# R16: bound on how long a docker/ECS reachability probe may take before this (admin-only,
# not LB-polled) route gives up and reports reachable=False rather than hanging. Podman's own
# check_podman_health already applies the same 2s bound per call internally.
_REACHABILITY_PROBE_TIMEOUT_SECONDS = 3.0


class RuntimeStatus(BaseModel):
    type: str
    reachable: bool
    socket: str


class WorkspaceCounts(BaseModel):
    running: int
    total: int


class SecretStoreStatus(BaseModel):
    reachable: bool
    count: int


class HealthzResponse(BaseModel):
    status: str
    version: str


class HealthzDetailResponse(BaseModel):
    warren_id: str
    version: str
    runtime: RuntimeStatus
    workspaces: WorkspaceCounts
    secret_store: SecretStoreStatus


async def _check_runtime_reachable(runtime, runtime_type: str) -> dict:
    """Return a real reachability dict for a non-podman runtime (R16).

    Previously hardcoded `reachable=True` unconditionally for every runtime except
    podman -- a docker daemon that was down, or an ECS cluster that had gone INACTIVE,
    was reported healthy regardless. Both DockerRuntime and ECSRuntime already expose
    `preflight()` (called before every provision() to guard against exactly this), so
    this reuses it rather than hardcoding or inventing a second check: docker's is a
    cheap local-socket ping, ECS's is one bounded `describe_clusters` call. Both are
    wrapped in a timeout since this route must never hang -- on timeout or any other
    error, reachable=False (never silently reachable=True).

    `runtime` may be None (e.g. app.state.runtime not yet set during startup, or a test
    harness) -- reported as reachable=False rather than raising, same as every other
    error path here.
    """
    if runtime is None or not hasattr(runtime, "preflight"):
        return {"type": runtime_type, "reachable": False, "socket": ""}
    try:
        await asyncio.wait_for(
            runtime.preflight(), timeout=_REACHABILITY_PROBE_TIMEOUT_SECONDS
        )
        return {"type": runtime_type, "reachable": True, "socket": ""}
    except Exception:
        return {"type": runtime_type, "reachable": False, "socket": ""}


async def _check_secret_store(db) -> dict:
    """Return secret store reachability dict.

    Executes a COUNT(*) against the `secrets` table (warren.secrets.store) --
    the row count of warren's own Fernet-encrypted local secret store, the
    single source of truth on every runtime including ECS (see
    routes/secrets.py). Returns reachable=False and count=0 on any error,
    e.g. a database opened before the `secrets` table existed in schema.sql.
    """
    try:
        async with db.execute("SELECT COUNT(*) FROM secrets") as cur:
            row = await cur.fetchone()
        return {"reachable": True, "count": row[0]}
    except Exception:
        return {"reachable": False, "count": 0}


router = APIRouter()


@router.get("/healthz", response_model=HealthzResponse)
async def healthz() -> HealthzResponse:
    """Liveness signal only — unauthenticated (auth/middleware.py's EXEMPT_PATHS), so it
    must never disclose anything beyond "the process is up" (audit #45). Always HTTP 200.
    """
    return HealthzResponse(status="ok", version=_WARREN_VERSION)


@router.get("/healthz/detail", response_model=HealthzDetailResponse, dependencies=[Depends(require_admin)])
async def healthz_detail(request: Request) -> HealthzDetailResponse:
    """Return detailed warren health status — admin-only (audit #45: this used to be the
    unauthenticated /healthz response, disclosing the podman socket path and workspace/
    secret counts to anyone). Always HTTP 200 once past the admin gate, never raises.

    Runs Podman health check, workspace count, and secret store check
    concurrently via asyncio.gather. All errors are reflected in the
    response fields (e.g. runtime.reachable=False) rather than raising.
    """
    try:
        settings = request.app.state.settings
        store = request.app.state.registry.store
        db = request.app.state.db

        # check_podman_health actually probes a podman socket -- meaningless (and
        # misleading, if reported as the runtime type regardless) for a non-podman
        # deployment such as ECS, which has no local podman socket at all (audit
        # 2026-10-16 #36: this used to hardcode runtime.type="podman" unconditionally).
        if settings.runtime_type == "podman":
            runtime_dict, all_ws, secret_dict = await asyncio.gather(
                check_podman_health(settings.podman_socket),
                store.list_all(),
                _check_secret_store(db),
            )
        else:
            # R16: used to hardcode reachable=True here unconditionally for every
            # non-podman runtime (docker, ECS) -- see _check_runtime_reachable.
            runtime = getattr(request.app.state, "runtime", None)
            all_ws, secret_dict, runtime_dict = await asyncio.gather(
                store.list_all(),
                _check_secret_store(db),
                _check_runtime_reachable(runtime, settings.runtime_type),
            )

        running = sum(1 for w in all_ws if w.status == "running")
        total = len(all_ws)

        return HealthzDetailResponse(
            warren_id=settings.server_id,
            version=_WARREN_VERSION,
            runtime=RuntimeStatus(**runtime_dict),
            workspaces=WorkspaceCounts(running=running, total=total),
            secret_store=SecretStoreStatus(**secret_dict),
        )
    except Exception:
        # Fallback — ensure /healthz/detail never returns 5xx
        runtime_type = "unknown"
        try:
            runtime_type = request.app.state.settings.runtime_type
        except Exception:
            pass
        return HealthzDetailResponse(
            warren_id="unknown",
            version=_WARREN_VERSION,
            runtime=RuntimeStatus(type=runtime_type, reachable=False, socket=""),
            workspaces=WorkspaceCounts(running=0, total=0),
            secret_store=SecretStoreStatus(reachable=False, count=0),
        )


@router.get("/peers")
async def peers(request: Request) -> list:
    # PD-01 UDP beacon deferred per D-01 (CONTEXT.md) — warren remote add is the registration mechanism
    return []
