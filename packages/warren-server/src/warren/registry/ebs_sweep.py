"""EBS volume/snapshot sweep — background asyncio loop (runtime/ebs.py).

Catches what the stop/destroy paths couldn't finish: a volume retained by a task that
died on its own or by a crash between StopTask and the snapshot (snapshotted, then
deleted, while its workspace exists; just deleted once the workspace is destroyed or
gone), a volume a destroy left attached past its deadline, superseded snapshots, and
the snapshots of workspaces that no longer exist. Only this server's tagged resources
are listed (warren=true + warren.server_instance), and each workspace is handled under
its lifecycle lock so the sweep never races its stop, launch or destroy.
"""
from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Any

import structlog

if TYPE_CHECKING:
    from warren.registry.registry import WorkspaceRegistry

log = structlog.get_logger(__name__)


async def sweep_ebs(registry: "WorkspaceRegistry", *, min_age_seconds: float = 900.0) -> dict[str, int]:
    """Run one sweep; returns counts of what was snapshotted/deleted."""
    ebs: Any = getattr(registry.runtime, "ebs", None)
    if ebs is None:
        return {}

    async def exists(workspace_id: str) -> bool:
        row = await registry.store.get(workspace_id)
        return row is not None and row.status != "destroyed"

    stats = await ebs.sweep(exists, registry._lock_for, min_age_seconds=min_age_seconds)
    if any(stats.values()):
        log.info("ebs_sweep_done", **stats)
    return stats


async def run_ebs_sweep(
    registry: "WorkspaceRegistry",
    *,
    interval_seconds: float = 900.0,
    min_age_seconds: float = 900.0,
) -> None:
    """Async sweep loop; runs until cancelled."""
    while True:
        try:
            await sweep_ebs(registry, min_age_seconds=min_age_seconds)
        except asyncio.CancelledError:
            log.info("ebs_sweep_cancelled")
            raise
        except Exception:
            log.exception("ebs_sweep_iteration_failed")
        await asyncio.sleep(interval_seconds)
