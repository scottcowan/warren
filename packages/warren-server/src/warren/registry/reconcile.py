"""Startup reconciliation (D-13).

Adopts running containers, marks stopped/missing ones, and destroys orphan
containers labelled with our `warren.server_instance` but lacking a DB row.

Reconciliation only touches containers filtered by
`warren.server_instance=<server_id>` — that label is the trust anchor for
warren-managed ownership (D-12, V4 Access Control).
"""

from __future__ import annotations

import inspect
import logging
from typing import Any, Protocol

import structlog

from warren.registry.store import WorkspaceStore
from warren_common.runtime.base import WorkspaceHandle

log = structlog.get_logger(__name__)
_stdlib_log = logging.getLogger(__name__)


class _RuntimeLike(Protocol):
    def list_by_server(self, server_id: str) -> Any: ...
    async def destroy(self, handle: WorkspaceHandle) -> None: ...


def _container_status(container: Any) -> str:
    """Return container state as a lowercase string.

    Handles three shapes: podman-py's list-summary API response, where
    `attrs["State"]` is a plain string (e.g. "running") rather than a nested
    object — confirmed via a real-socket integration test (Phase 1, 01-03)
    once `list_by_server()` started returning real matches; podman-py's
    inspect/get-shaped `container.attrs["State"]["Status"]`; and the
    `FakeContainer.status` attribute shape used by unit tests.
    """
    attrs = getattr(container, "attrs", None)
    if isinstance(attrs, dict):
        state = attrs.get("State")
        if isinstance(state, str) and state:
            return state.lower()
        if isinstance(state, dict):
            status = state.get("Status")
            if status:
                return str(status).lower()
    status = getattr(container, "status", None)
    return str(status or "").lower()


def _container_labels(container: Any) -> dict[str, str]:
    labels = getattr(container, "labels", None)
    if isinstance(labels, dict):
        return labels
    attrs = getattr(container, "attrs", None)
    if isinstance(attrs, dict):
        config = attrs.get("Config") or {}
        return config.get("Labels") or {}
    return {}


async def _maybe_await(value: Any) -> Any:
    if inspect.isawaitable(value):
        return await value
    return value


async def reconcile_from_disk(
    *,
    runtime: _RuntimeLike,
    store: WorkspaceStore,
    server_id: str,
) -> None:
    rows = await store.list_non_terminal()

    # Finding 6: a "stopped" row (the idle reaper's own reconnectable state --
    # exactly what ensure_running() is designed to bring back) is NOT in
    # list_non_terminal()'s result, so the orphan-detection loop below must
    # consult every non-destroyed row, not just the non-terminal ones, or it
    # force-removes every idle-stopped container's runtime on every restart.
    # "destroyed" rows are excluded on purpose: destroy() clears their
    # container_id, so a leftover container still labelled with that
    # workspace_id IS a genuine orphan.
    known_ws_ids = {
        row.workspace_id for row in await store.list_all() if row.status != "destroyed"
    }

    # ECS runtime: reconcile per-row via status() using stored task ARN.
    # ECSRuntime does not implement list_by_server — duck-type check via _ecs attr.
    if hasattr(runtime, "_ecs"):
        for row in rows:
            if not row.container_id:
                await store.update_status(row.workspace_id, "stopped")
                continue
            handle = WorkspaceHandle(
                workspace_id=row.workspace_id,
                runtime_id=row.container_id,
                root_path="",
            )
            try:
                ws_status = await runtime.status(handle)
            except Exception:
                ws_status = "unknown"
            if ws_status == "starting":
                ws_status = "provisioning"
            await store.update_status(row.workspace_id, ws_status)
        return

    # Container-based runtimes (Podman, Docker, nsjail): existing path.
    containers = list(await _maybe_await(runtime.list_by_server(server_id)))

    by_ws_id: dict[str, Any] = {}
    for c in containers:
        ws_id = _container_labels(c).get("warren.workspace_id")
        if ws_id:
            by_ws_id[ws_id] = c

    for row in rows:
        container = by_ws_id.get(row.workspace_id)
        if container is None:
            await store.update_status(row.workspace_id, "stopped")
            continue
        state = _container_status(container)
        new_status = "running" if state == "running" else "stopped"
        await store.update_status(row.workspace_id, new_status)

    for c in containers:
        labels = _container_labels(c)
        ws_id = labels.get("warren.workspace_id")
        if not ws_id or ws_id in known_ws_ids:
            continue
        if labels.get("warren.server_instance") != server_id:
            continue
        log.warning("orphan container", ws_id=ws_id, container_id=getattr(c, "id", None))
        _stdlib_log.warning("orphan container ws_id=%s container_id=%s", ws_id, getattr(c, "id", None))
        handle = WorkspaceHandle(
            workspace_id=ws_id,
            runtime_id=getattr(c, "id", ""),
            root_path="",
        )
        await runtime.destroy(handle)

    # Finding 9 (podman): move workspaces still on the legacy shared bridge onto
    # their own network, and drop per-workspace networks whose row is gone (a
    # provision that failed before destroy() could run).
    reconcile_networks = getattr(runtime, "reconcile_networks", None)
    if reconcile_networks is not None:
        await reconcile_networks(server_id, known_ws_ids)
