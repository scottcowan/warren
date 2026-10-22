"""Live-Podman end-to-end proof of ACCESS-01/ACCESS-03 and the D-03 invalidation boundary.

Drives the actual FastAPI routes (`POST /workspaces`, `GET /workspaces/{id}/status`,
`GET /workspaces`, `POST /workspaces/{id}/connect`) against a real container built from
a self-contained test fixture image (tests/integration/fixtures/ssh_test_image/, via the
`itest_workspace_docker_image` fixture — the production ACP-over-SSH ForceCommand pattern
itself now lives in github.com/scottcowan/agent-poc, standalone), then performs a real
SSH handshake against the published host port with the minted private key.

Gated by BOTH the existing `requires_podman` marker (skipped when `PODMAN_SOCKET` is
unset, per `tests/conftest.py::pytest_collection_modifyitems`) AND an explicit
`shutil.which("ssh")` check — this test drives a genuine SSH handshake and there is no
SSH client library in this repo's dependency set, only the host's own `ssh` binary.
"""

from __future__ import annotations

import asyncio
import shutil
import subprocess
from pathlib import Path
from unittest.mock import patch

import pytest
from httpx import ASGITransport, AsyncClient

pytestmark = pytest.mark.requires_podman

_POLL_ATTEMPTS = 30
_POLL_INTERVAL_S = 0.5

_SSH_CONNECT_ATTEMPTS = 10
_SSH_CONNECT_RETRY_INTERVAL_S = 1.0

_SSH_COMMON_OPTS = [
    "-o",
    "StrictHostKeyChecking=no",
    "-o",
    "UserKnownHostsFile=/dev/null",
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=10",
]


def _ssh_argv(keyfile: Path, port: int, user: str, command: str | None = None) -> list[str]:
    argv = [
        "ssh",
        "-i",
        str(keyfile),
        "-p",
        str(port),
        *_SSH_COMMON_OPTS,
        f"{user}@127.0.0.1",
    ]
    if command is not None:
        argv.append(command)
    return argv


async def _run_ssh_with_retry(argv: list[str]) -> subprocess.CompletedProcess:
    """Run an SSH handshake, retrying on connection-refused for a bounded number of
    short attempts, since sshd inside a just-started container needs a moment to come up.

    Runs ssh in a worker thread rather than calling subprocess.run()/time.sleep()
    directly: this test runs inside the app's lifespan, and blocking the event loop for
    seconds at a time starves its background tasks (the reaper's in-flight podman call
    completes in its thread while the loop is blocked). That is what made this test hang
    intermittently on Python 3.11: lifespan exit then cancelled the reaper inside
    asyncio.wait_for's swallowed-cancel window (cpython gh-86296; fixed in reaper.py by
    switching to asyncio.timeout) and `await task` waited forever. stdin is /dev/null so
    ssh never blocks on, or forwards, the runner's inherited stdin.
    """
    last: subprocess.CompletedProcess | None = None
    for _ in range(_SSH_CONNECT_ATTEMPTS):
        last = await asyncio.to_thread(
            subprocess.run,
            argv,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            timeout=20,
        )
        if last.returncode == 0:
            return last
        stderr_lower = (last.stderr or "").lower()
        if "connection refused" in stderr_lower or "connection reset" in stderr_lower:
            await asyncio.sleep(_SSH_CONNECT_RETRY_INTERVAL_S)
            continue
        # Any other failure (auth failure, command failure, etc.) is a real result —
        # stop retrying and let the caller assert on it.
        return last
    assert last is not None
    return last


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


def _write_project_yaml(projects_dir: Path, image_tag: str) -> None:
    """Write a minimal project YAML naming `image_tag` as the project's docker_image.

    `_resolve_image()` resolves the "dev" template against `WARREN_PROJECTS_DIR/
    {project}.yaml` — leaving the template's own docker_image unset means it
    inherits the project-level docker_image (this fixture's tag).
    """
    projects_dir.mkdir(parents=True, exist_ok=True)
    (projects_dir / "p.yaml").write_text(
        f"""\
name: p
docker_image: {image_tag}
templates:
  dev: {{}}
"""
    )


async def test_ssh_access_end_to_end(
    itest_env: dict[str, object],
    itest_workspace_docker_image: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    if shutil.which("ssh") is None:
        pytest.skip("ssh (openssh-client) not installed on this host")

    # Point _resolve_image at the D-10 reference image via a real project YAML, not the
    # itest_env's default busybox `itest_long_running_image` fixture.
    projects_dir = tmp_path / "projects"
    _write_project_yaml(projects_dir, itest_workspace_docker_image)
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(projects_dir))
    # R12: ssh port publishing is opt-in (default off) — this test exercises
    # the real SSH path end-to-end, so it needs it explicitly enabled.
    monkeypatch.setenv("WARREN_SSH_ACCESS_ENABLED", "true")

    from warren.app import app, lifespan

    auth_headers = {"Authorization": "Bearer itest-bootstrap-token00000000000"}  # itest_env's WARREN_BOOTSTRAP_TOKEN
    async with lifespan(app), AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", headers=auth_headers
    ) as client:
        workspace_id = await _provision_and_wait(client)

        # ACCESS-01: the published ssh_port sits inside the configured range.
        list_response = await client.get("/workspaces")
        assert list_response.status_code == 200, list_response.text
        ws = next(w for w in list_response.json() if w["workspace_id"] == workspace_id)
        ssh_port = ws["ssh_port"]
        settings = app.state.settings
        assert ssh_port is not None
        assert settings.ssh_port_range_start <= ssh_port < settings.ssh_port_range_end

        # ACCESS-02 (server-side half)/D-01: mint and return a real OpenSSH credential.
        connect_response = await client.post(f"/workspaces/{workspace_id}/connect")
        assert connect_response.status_code == 200, connect_response.text
        payload = connect_response.json()
        assert payload["user"] == "warren"
        assert payload["break_glass_user"] == "warren-shell"
        assert payload["private_key"].startswith("-----BEGIN OPENSSH PRIVATE KEY-----")

        keyfile = tmp_path / "id_ed25519"
        keyfile.write_text(payload["private_key"])
        keyfile.chmod(0o600)
        port = payload["port"]
        assert port == ssh_port

        # ACCESS-01/ACCESS-03: the break-glass shell path authenticates and runs a plain
        # command deterministically. Equivalent to:
        #   ssh -i <keyfile> -p <port> ... warren-shell@127.0.0.1 true
        break_glass_result = await _run_ssh_with_retry(_ssh_argv(keyfile, port, "warren-shell", "true"))
        assert break_glass_result.returncode == 0, (
            f"break-glass SSH handshake failed: stdout={break_glass_result.stdout!r} "
            f"stderr={break_glass_result.stderr!r}"
        )

        # ACCESS-03/D-08: the default `warren` login authenticates but is routed through
        # the image's ACP entry wrapper, not a plain shell. This reference image ships no
        # ACP agent, so with no explicit command the wrapper fails loudly (exit 127 +
        # stderr message) rather than silently dropping to a shell — that is the routing
        # split this assertion proves, not any specific protocol being served (D-08: what
        # actually rides the default path in a real workspace image is out of
        # warren-server's scope).
        default_result = await _run_ssh_with_retry(_ssh_argv(keyfile, port, "warren"))
        assert default_result.returncode != 0
        assert "acp-entry" in (default_result.stderr or "")

        # D-03: stop the workspace through the runtime path the API exposes (no stop
        # route exists in this phase) and confirm the previously-minted credential no
        # longer authenticates. This is the single most important assertion in this file.
        from warren_common.runtime.base import WorkspaceHandle

        stored_ws = await app.state.registry.store.get(workspace_id)
        assert stored_ws is not None and stored_ws.container_id
        handle = WorkspaceHandle(
            workspace_id=workspace_id,
            runtime_id=stored_ws.container_id,
            root_path=stored_ws.root_path,
        )
        await app.state.registry.runtime.stop(handle)

        post_stop_result = await _run_ssh_with_retry(_ssh_argv(keyfile, port, "warren-shell", "true"))
        assert post_stop_result.returncode != 0, (
            "SSH handshake unexpectedly SUCCEEDED after the workspace was stopped — "
            "the D-03 key-invalidation boundary is broken"
        )

        # Let itest_env's teardown remove the container; no competing cleanup here.
