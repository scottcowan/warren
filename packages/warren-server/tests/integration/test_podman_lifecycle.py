"""Real-socket integration coverage for RUN-01/RUN-02 (Plan 01-02).

Drives the actual FastAPI routes (`POST/GET/DELETE /workspaces`) against a live
rootless Podman socket via `PodmanRuntime` — no mocks. Gated by the
`requires_podman` marker: skipped (not errored) when `PODMAN_SOCKET` is unset,
per `tests/conftest.py::pytest_collection_modifyitems`.

Lives in a separate `tests/integration/` tier from the mocked
`tests/unit/runtime/test_podman.py` (CONTEXT.md D-03).
"""

from __future__ import annotations

import asyncio
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

pytestmark = pytest.mark.requires_podman

_POLL_ATTEMPTS = 30
_POLL_INTERVAL_S = 0.5


async def _provision_and_wait(client: AsyncClient) -> str:
    """POST a workspace, poll until it reaches status "running", return its id."""
    response = await client.post("/workspaces", json={"project": "p", "template": "dev"})
    assert response.status_code == 202, response.text
    workspace_id = response.json()["workspace_id"]

    status = None
    for _ in range(_POLL_ATTEMPTS):
        status_response = await client.get(f"/workspaces/{workspace_id}/status")
        assert status_response.status_code == 200, status_response.text
        status = status_response.json()["status"]
        if status == "running":
            break
        await asyncio.sleep(_POLL_INTERVAL_S)

    assert status == "running", f"never reached running, last status={status}"
    return workspace_id


async def test_provision_list_status_and_destroy(itest_env: dict[str, object]) -> None:
    with patch(
        "warren.routes.workspaces._resolve_image",
        return_value=itest_env["image"],
    ):
        from warren.app import app, lifespan

        auth_headers = {"Authorization": "Bearer itest-bootstrap-token00000000000"}  # itest_env's WARREN_BOOTSTRAP_TOKEN
        async with lifespan(app), AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test", headers=auth_headers
        ) as client:
            workspace_id = await _provision_and_wait(client)

            list_response = await client.get("/workspaces")
            assert list_response.status_code == 200, list_response.text
            workspace_ids = [ws["workspace_id"] for ws in list_response.json()]
            assert workspace_id in workspace_ids

            delete_response = await client.delete(f"/workspaces/{workspace_id}")
            assert delete_response.status_code == 204

            final_status_response = await client.get(
                f"/workspaces/{workspace_id}/status"
            )
            assert final_status_response.status_code == 200
            # DELETE /workspaces/{id} calls registry.destroy(), which sets the
            # distinct "destroyed" terminal status (audit P0 #8), not "stopped"
            # -- this assertion predated that fix and was never caught because
            # the integration suite wasn't actually running in CI (audit S3).
            assert final_status_response.json()["status"] == "destroyed"


async def test_destroy_is_idempotent(itest_env: dict[str, object]) -> None:
    with patch(
        "warren.routes.workspaces._resolve_image",
        return_value=itest_env["image"],
    ):
        from warren.app import app, lifespan

        auth_headers = {"Authorization": "Bearer itest-bootstrap-token00000000000"}  # itest_env's WARREN_BOOTSTRAP_TOKEN
        async with lifespan(app), AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test", headers=auth_headers
        ) as client:
            workspace_id = await _provision_and_wait(client)

            first_delete = await client.delete(f"/workspaces/{workspace_id}")
            second_delete = await client.delete(f"/workspaces/{workspace_id}")

            assert first_delete.status_code == 204
            assert second_delete.status_code == 204
