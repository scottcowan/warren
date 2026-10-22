"""RUN-03: real-socket restart-survival coverage + cross-server-id orphan safety.

Simulates a warren-server restart by exiting and re-entering `lifespan(app)`
against the same SQLite file and Podman socket (no second OS process — see
CONTEXT.md D-04). Also regression-tests the `warren.server_instance` label
boundary that `reconcile_from_disk()`'s orphan-cleanup branch relies on: a
container labelled with a *different* server_instance must never be adopted
or destroyed by this server's reconciliation pass (RESEARCH.md Security
Domain V4 Access Control).
"""

from __future__ import annotations

import uuid

import pytest
import structlog
from warren_common.runtime.base import WorkspaceSpec

from warren.app import app, lifespan

log = structlog.get_logger(__name__)

pytestmark = pytest.mark.requires_podman


async def test_restart_survives_and_reconciles(itest_env: dict[str, object]) -> None:
    workspace_id = "ws-restart-test"

    async with lifespan(app):
        registry = app.state.registry
        await registry.store.insert(
            workspace_id=workspace_id,
            project="p",
            intent="dev",
            image=itest_env["image"],
            root_path="",
            server_instance=registry.server_id,
            status="provisioning",
        )
        await registry._do_provision(
            workspace_id,
            WorkspaceSpec(
                workspace_id=workspace_id,
                project="p",
                intent="dev",
                image=itest_env["image"],
                root_path="",
            ),
        )
        row = await registry.store.get(workspace_id)
        assert row.status == "running"

    # Second lifespan entry — simulates a server restart. Same WARREN_DATA_DIR
    # and WARREN_PODMAN_SOCKET (still active from itest_env's monkeypatch), so
    # this reads the same SQLite file and reconciles against the same live
    # container rather than a stale DB read.
    async with lifespan(app):
        row = await app.state.registry.store.get(workspace_id)
        assert row.status == "running"
        await app.state.registry.destroy(workspace_id)


async def test_reconcile_does_not_touch_foreign_server_container(
    itest_env: dict[str, object],
) -> None:
    import os

    from podman import PodmanClient

    socket_path = os.environ["PODMAN_SOCKET"]
    foreign_id = "foreign-" + uuid.uuid4().hex[:8]

    client = PodmanClient(base_url=f"unix://{socket_path}", timeout=30)
    foreign_container = None
    try:
        foreign_container = client.containers.create(
            image=itest_env["image"],
            labels={
                "warren.workspace_id": "ws-foreign",
                "warren.server_instance": foreign_id,
            },
            detach=True,
        )
        foreign_container.start()

        async with lifespan(app):
            await app.state.registry.reconcile_from_disk()

        refreshed = client.containers.get(foreign_container.id)
        refreshed.reload()
        assert _status(refreshed) == "running"
    finally:
        if foreign_container is not None:
            try:
                client.containers.get(foreign_container.id).remove(force=True)
            except Exception:
                log.warning(
                    "foreign container cleanup failed",
                    container_id=foreign_container.id,
                )
        client.close()


def _status(container: object) -> str:
    attrs = getattr(container, "attrs", None)
    if isinstance(attrs, dict):
        state = attrs.get("State") or {}
        status = state.get("Status")
        if status:
            return str(status).lower()
    return str(getattr(container, "status", "") or "").lower()
