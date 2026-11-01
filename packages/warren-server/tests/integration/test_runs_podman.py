"""Headless runs against a live rootless Podman socket: POST /runs, the reaper completes
the run when the app exits, the server reads the app's output from the bind-mounted harness
dir, destroys the workspace and keeps the result. Gated by `requires_podman`."""

from __future__ import annotations

import asyncio
import os
from pathlib import Path
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

pytestmark = pytest.mark.requires_podman

_IMAGE_TAG = "localhost/warren-itest-run:latest"
_AUTH = {"Authorization": "Bearer itest-bootstrap-token00000000000"}
# A stand-in `claude`: prints a Claude Code JSON result naming its prompt, exits with $FAKE_RC.
_FAKE_CLAUDE = """#!/bin/sh
for last; do :; done
printf '{"type":"result","subtype":"success","is_error":false,"num_turns":1,"result":"done: %s","session_id":"s-1"}\\n' "$last"
exit "${FAKE_RC:-0}"
"""


@pytest.fixture(scope="module")
def run_image(tmp_path_factory: pytest.TempPathFactory) -> str:
    socket_path = os.environ.get("PODMAN_SOCKET")
    if not socket_path:
        pytest.skip("PODMAN_SOCKET not set")
    from podman import PodmanClient

    build_dir = tmp_path_factory.mktemp("itest-run-image")
    (build_dir / "claude").write_text(_FAKE_CLAUDE)
    # The server images' entrypoints run $WARREN_APP; this one just evaluates it.
    (build_dir / "Containerfile").write_text(
        "FROM docker.io/library/busybox:latest\n"
        "COPY claude /usr/local/bin/claude\n"
        "RUN chmod 0755 /usr/local/bin/claude\n"
        'CMD ["sh", "-c", "eval \\"$WARREN_APP\\""]\n'
    )
    client = PodmanClient(base_url=f"unix://{socket_path}", timeout=30)
    try:
        client.images.build(path=str(build_dir), dockerfile="Containerfile", tag=_IMAGE_TAG, rm=True, timeout=120)
    finally:
        client.close()
    return _IMAGE_TAG


def _project(env: dict[str, str]):
    from warren_common.models import ProjectConfig

    return ProjectConfig.model_validate({"name": "p", "templates": {"fix": {"app": "claude", "env": env}}})


async def _run_to_completion(client: AsyncClient, prompt: str) -> tuple[str, dict]:
    resp = await client.post("/runs", json={"project": "p", "template": "fix", "prompt": prompt})
    assert resp.status_code == 202, resp.text
    run_id = resp.json()["run_id"]
    status = "running"
    for _ in range(120):
        status = (await client.get(f"/runs/{run_id}")).json()["status"]
        if status != "running":
            break
        await asyncio.sleep(0.5)
    assert status != "running", "the run never finished"
    result = await client.get(f"/runs/{run_id}/result")
    assert result.status_code == 200, result.text
    return run_id, result.json()


@pytest.mark.parametrize(("rc", "expected"), [("0", "succeeded"), ("3", "failed")])
async def test_run_result_on_podman(itest_env: dict[str, object], run_image: str, rc: str, expected: str) -> None:
    with (
        patch("warren.routes.workspaces._resolve_image", return_value=run_image),
        patch("warren_common.loader.ProjectLoader.load_effective", return_value=_project({"FAKE_RC": rc})),
    ):
        from warren.app import app, lifespan

        async with lifespan(app), AsyncClient(
            transport=ASGITransport(app=app), base_url="http://test", headers=_AUTH
        ) as client:
            run_id, result = await _run_to_completion(client, "add a flag")
            ws_status = (await client.get(f"/workspaces/{run_id}/status")).json()["status"]

    assert result["status"] == expected
    assert result["exit_code"] == int(rc)
    assert result["result_source"] == "control-plane"
    assert result["harness"] == "claude"
    assert result["final_message"] == "done: add a flag"
    assert result["harness_result"]["session_id"] == "s-1"
    assert result["transcript"]["retained"] is False
    assert ws_status == "destroyed"
    # The harness dir the output was read from went with the workspace.
    assert not (Path(str(itest_env["data_dir"])) / "harness" / run_id).exists()
