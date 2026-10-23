"""FastAPI app with lifespan wiring per Plan 01-05 (Pattern 5, D-14).

Startup order:
    1. WarrenSettings()
    2. run runtime.preflight() — ECS: await runtime.preflight(); else: run_preflight(podman_socket)
    3. open_db(db_path(settings))
    4. Construct AuthStore(db) + ensure_bootstrap_admin(auth_store, settings) (D-03/D-04) —
       before reconcile so a reconcile timeout can never leave the server admin-less
    5. Construct runtime (ECSRuntime | DockerRuntime | PodmanRuntime) + WorkspaceStore + WorkspaceRegistry
    6. asyncio.wait_for(registry.reconcile_from_disk(), timeout=30) — TimeoutError logged, non-fatal (D-14)
    7. Store singletons on app.state
    8. yield

Every HTTP request now passes through `warren.auth.middleware.AuthMiddleware` (AUTH-03, D-06).
`warren.auth.middleware.EXEMPT_PATHS` is the single, explicit list of unauthenticated paths —
adding a new public route means adding it there deliberately; it is never done by disabling or
conditionally skipping this middleware.
"""

from __future__ import annotations

import asyncio
import os
from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI

from warren.auth.bootstrap import ensure_bootstrap_admin
from warren.auth.store import AuthStore
from warren.config import WarrenSettings
from warren.paths import db_path
from warren.preflight import run_preflight
from warren.registry.reaper import run_reaper
from warren.registry.registry import WorkspaceRegistry
from warren.registry.store import LaunchAttemptStore, OperationStore, WorkspaceStore, open_db
from warren.runtime.podman import PodmanRuntime

log = structlog.get_logger(__name__)

_RECONCILE_TIMEOUT_S: float = 30.0


@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = WarrenSettings()

    _efs_volume = None  # set below when runtime_type == "ecs" and efs_id is configured

    if settings.runtime_type == "ecs":
        from warren.runtime.ecs import ECSRuntime  # noqa: PLC0415
        # D-10: EFS is opt-in — only wire EFSMount when efs_id is configured.
        if settings.efs_id:
            from warren.runtime.efs import EFSMount  # noqa: PLC0415
            _efs_volume = EFSMount(
                efs_id=settings.efs_id,
                server_id=settings.server_id,
                retention_days=settings.efs_retention_days,
                settings=settings,
            )
        runtime = ECSRuntime(server_id=settings.server_id, settings=settings, volume=_efs_volume)
    elif settings.runtime_type == "docker":
        from warren_common.runtime.docker import DockerRuntime  # noqa: PLC0415
        runtime = DockerRuntime(server_id=settings.server_id)
    else:
        # default: podman
        runtime = PodmanRuntime(
            socket_path=settings.podman_socket,
            server_id=settings.server_id,
            egress_bridge_name=settings.egress_bridge_name,
            ssh_publish_host=settings.ssh_publish_host,
        )

    if not os.environ.get("WARREN_DRY_RUN_SKIP_PREFLIGHT"):
        if settings.runtime_type in ("ecs", "docker"):
            await runtime.preflight()
        else:
            await run_preflight(settings.podman_socket)

    db = await open_db(db_path(settings))
    auth_store = AuthStore(db)
    await ensure_bootstrap_admin(auth_store, settings)
    store = WorkspaceStore(db)
    if settings.runtime_type == "ecs":
        runtime.launch_store = LaunchAttemptStore(db)
    from warren.registry.events import WorkspaceEventStore
    event_store = WorkspaceEventStore()

    # GitManager materializes server-side worktree clones (registry.py's
    # _do_provision) that get bind-mounted into the container -- only
    # meaningful when the runtime shares this host's filesystem with the
    # container (podman/docker). ECS tasks run on a different host entirely,
    # so a host-side clone here would never reach them (they materialize
    # in-task instead, via runtime/ecs_git.py's git-init container); wiring it in was a
    # real, previously-shipped gap for podman/docker (nothing ever
    # instantiated GitManager in production, so every server-side clone
    # path was dead code despite being fully implemented and tested).
    git_manager = None
    if settings.runtime_type != "ecs":
        from warren.git.manager import GitManager  # noqa: PLC0415

        credentials = None
        if (
            settings.github_app_id
            and settings.github_app_installation_id
            and settings.github_app_private_key_path
        ):
            from warren.git.github_app import GitHubAppCredentials  # noqa: PLC0415

            credentials = GitHubAppCredentials(
                app_id=settings.github_app_id,
                private_key_path=settings.github_app_private_key_path,
                installation_id=settings.github_app_installation_id,
                allowed_repos=settings.github_app_allowed_repos,
            )

        git_manager = GitManager(
            worktree_root=settings.data_dir / "worktrees", credentials=credentials
        )

    registry = WorkspaceRegistry(
        runtime=runtime,
        store=store,
        server_id=settings.server_id,
        event_store=event_store,
        settings=settings,
        git_manager=git_manager,
    )

    try:
        await asyncio.wait_for(registry.reconcile_from_disk(), timeout=_RECONCILE_TIMEOUT_S)
    except asyncio.TimeoutError:
        log.error("reconciliation timeout, starting with stale state", timeout_s=_RECONCILE_TIMEOUT_S)

    app.state.db = db
    app.state.settings = settings
    app.state.runtime = runtime
    app.state.registry = registry
    app.state.event_store = event_store
    app.state.auth_store = auth_store
    app.state.operation_store = OperationStore(db)
    from warren.git.token_issuer import control_plane_issuer  # noqa: PLC0415

    app.state.github_token_issuer = control_plane_issuer(settings)
    app.state.reaper_task = None

    if os.environ.get("WARREN_REAPER_ENABLED", "1") != "0":
        try:
            app.state.reaper_task = asyncio.create_task(run_reaper(registry))
        except Exception:
            log.exception("reaper_spawn_failed")

    app.state.idle_reaper_task = None
    if settings.idle_reaper_enabled:
        try:
            from warren.registry.idle_reaper import run_idle_reaper  # noqa: PLC0415

            idle_reaper_kwargs: dict = {}
            if settings.egress_shim_socket is not None:
                import functools  # noqa: PLC0415

                from warren.network.egress import (  # noqa: PLC0415
                    read_container_egress_bytes_via_shim,
                )

                idle_reaper_kwargs["read_egress_bytes"] = functools.partial(
                    read_container_egress_bytes_via_shim,
                    socket_path=settings.egress_shim_socket,
                )

            app.state.idle_reaper_task = asyncio.create_task(
                run_idle_reaper(
                    registry,
                    poll_interval=settings.idle_reaper_poll_interval,
                    idle_ttl_seconds=settings.idle_ttl_seconds,
                    idle_destroy_seconds=settings.idle_destroy_seconds,
                    blocked_ttl_seconds=settings.blocked_ttl_seconds,
                    hook_max_hold_seconds=settings.hook_max_hold_seconds,
                    client_attached=registry.client_attached,
                    **idle_reaper_kwargs,
                )
            )
            log.info(
                "idle_reaper_started",
                poll_interval=settings.idle_reaper_poll_interval,
                idle_ttl_seconds=settings.idle_ttl_seconds,
                egress_shim_socket=str(settings.egress_shim_socket)
                if settings.egress_shim_socket
                else None,
            )
        except Exception:
            log.exception("idle_reaper_spawn_failed")

    # S10: the in-memory sliding-window rate limiters (ratelimit.py) never pruned old
    # entries on their own -- a key whose events all aged out and was never touched
    # again sat in memory for the server's entire uptime. routes/workspaces.py's
    # `_create_workspace_limiter` is a stable module-level singleton (unlike
    # auth/middleware.py's per-instance `_failed_auth_limiter`, which prunes itself
    # opportunistically on use instead -- see that module's comment for why), so it's
    # the one wired into a dedicated background task here, same run-until-cancelled
    # pattern as run_idle_reaper above.
    app.state.rate_limiter_pruner_task = None
    try:
        from warren.ratelimit import run_rate_limiter_pruner  # noqa: PLC0415
        from warren.routes.workspaces import _create_workspace_limiter  # noqa: PLC0415

        app.state.rate_limiter_pruner_task = asyncio.create_task(
            run_rate_limiter_pruner([_create_workspace_limiter])
        )
    except Exception:
        log.exception("rate_limiter_pruner_spawn_failed")

    app.state.efs_reaper_task = None
    efs_id = getattr(settings, "efs_id", "") or ""
    if efs_id:
        try:
            from warren.registry.efs_reaper import run_efs_reaper  # noqa: PLC0415
            efs_interval_s = float(getattr(settings, "efs_reaper_interval_hours", 6)) * 3600.0
            # Get EFS client from the EFSMount instance wired into ECSRuntime.
            # _efs_volume is set above when efs_id is configured; warm the client now
            # so the reaper has a session immediately rather than waiting for first provision.
            efs_client = None
            if _efs_volume is not None:
                efs_client = _efs_volume._ensure_client()
            if efs_client is None:
                log.warning("efs_reaper_no_client_skipping")
            else:
                app.state.efs_reaper_task = asyncio.create_task(
                    run_efs_reaper(
                        efs_client,
                        efs_id,
                        settings.server_id,
                        interval_seconds=efs_interval_s,
                        local_mount_path=getattr(settings, "efs_local_mount_path", "") or "",
                    )
                )
                log.info("efs_reaper_started", efs_id=efs_id, interval_s=efs_interval_s)
        except Exception:
            log.exception("efs_reaper_spawn_failed")

    app.state.ecs_orphan_sweep_task = None
    sweep_interval_s = float(getattr(settings, "ecs_orphan_sweep_interval_seconds", 0) or 0)
    if settings.runtime_type == "ecs" and sweep_interval_s > 0:
        try:
            from warren.registry.ecs_orphan_sweep import run_ecs_orphan_sweep  # noqa: PLC0415

            app.state.ecs_orphan_sweep_task = asyncio.create_task(
                run_ecs_orphan_sweep(
                    registry,
                    interval_seconds=sweep_interval_s,
                    min_age_seconds=settings.ecs_orphan_sweep_min_age_seconds,
                )
            )
            log.info("ecs_orphan_sweep_started", interval_s=sweep_interval_s)
        except Exception:
            log.exception("ecs_orphan_sweep_spawn_failed")

    from warren.control_mcp import new_session_manager  # noqa: PLC0415

    app.state.mcp_session_manager = new_session_manager()

    try:
        async with app.state.mcp_session_manager.run():
            yield
    finally:
        sweep_task = getattr(app.state, "ecs_orphan_sweep_task", None)
        if sweep_task is not None:
            sweep_task.cancel()
            try:
                await sweep_task
            except asyncio.CancelledError:
                pass
            except Exception:
                log.exception("ecs_orphan_sweep_shutdown_error")
        task = getattr(app.state, "reaper_task", None)
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            except Exception:
                log.exception("reaper_shutdown_error")
        efs_task = getattr(app.state, "efs_reaper_task", None)
        if efs_task is not None:
            efs_task.cancel()
            try:
                await efs_task
            except asyncio.CancelledError:
                pass
            except Exception:
                log.exception("efs_reaper_shutdown_error")
        idle_reaper_task = getattr(app.state, "idle_reaper_task", None)
        if idle_reaper_task is not None:
            idle_reaper_task.cancel()
            try:
                await idle_reaper_task
            except asyncio.CancelledError:
                pass
            except Exception:
                log.exception("idle_reaper_shutdown_error")
        rate_limiter_pruner_task = getattr(app.state, "rate_limiter_pruner_task", None)
        if rate_limiter_pruner_task is not None:
            rate_limiter_pruner_task.cancel()
            try:
                await rate_limiter_pruner_task
            except asyncio.CancelledError:
                pass
            except Exception:
                log.exception("rate_limiter_pruner_shutdown_error")
        await db.close()


app = FastAPI(lifespan=lifespan)

from warren.auth.middleware import AuthMiddleware  # noqa: E402
app.add_middleware(AuthMiddleware)
from warren.http_limits import BodySizeLimitMiddleware  # noqa: E402
app.add_middleware(BodySizeLimitMiddleware)

from warren.routes import workspaces as ws_routes  # noqa: E402
app.include_router(ws_routes.router)
from warren.routes import projects as proj_routes  # noqa: E402
app.include_router(proj_routes.router)
from warren.routes import health as health_routes  # noqa: E402
app.include_router(health_routes.router)
from warren.routes import admin as admin_routes  # noqa: E402
app.include_router(admin_routes.router)
from warren.routes import secrets as secrets_routes  # noqa: E402
app.include_router(secrets_routes.router)
from warren.routes import tokens as tokens_routes  # noqa: E402
app.include_router(tokens_routes.router)
from warren.routes import workspace_tokens as workspace_tokens_routes  # noqa: E402
app.include_router(workspace_tokens_routes.router)
from warren.routes import git_credentials as git_credentials_routes  # noqa: E402
app.include_router(git_credentials_routes.router)
# AI8: the control-plane MCP endpoint (streamable HTTP). A plain Route, not a Mount, so
# scope["app"] stays this app and AuthMiddleware's scope state reaches the tools.
from starlette.routing import Route  # noqa: E402

from warren import control_mcp  # noqa: E402
app.router.routes.append(Route("/mcp", endpoint=control_mcp.asgi, methods=["GET", "POST", "DELETE"]))


@app.get("/_status")
async def _status() -> dict[str, str]:
    return {"status": "ok"}
