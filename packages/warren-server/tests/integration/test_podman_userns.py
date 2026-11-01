"""Live-podman proof of WARREN_PODMAN_USERNS (default keep-id:uid=1000,gid=1000).

A server-side clone bind-mounted into the workspace is owned by uid 1000 inside the
container and writable by it; what uid 1000 writes there is owned by the server user on
the host; the container itself still starts as root; and a workspace's SSH login as
`warren` (uid 1000) can save a file in the checkout. With WARREN_PODMAN_USERNS=host the
old mapping (host user = container root) is back.

The clone is a real GitManager clone, of a local repo: the https/ssh-only URL guard and
GIT_ALLOW_PROTOCOL are relaxed to `file` for these tests only.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from httpx import ASGITransport, AsyncClient

pytestmark = pytest.mark.requires_podman

_AUTH = {"Authorization": "Bearer itest-bootstrap-token00000000000"}
_SSH_OPTS = [
    "-o", "StrictHostKeyChecking=no",
    "-o", "UserKnownHostsFile=/dev/null",
    "-o", "BatchMode=yes",
    "-o", "ConnectTimeout=10",
]


def _git(cwd: Path, *args: str) -> None:
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": str(cwd),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_AUTHOR_NAME": "itest", "GIT_AUTHOR_EMAIL": "itest@example.invalid",
        "GIT_COMMITTER_NAME": "itest", "GIT_COMMITTER_EMAIL": "itest@example.invalid",
    }
    subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True)


def _source_repo(tmp_path: Path) -> Path:
    src = tmp_path / "src-repo"
    src.mkdir()
    _git(src, "init", "-q", "-b", "main")
    (src / "README.md").write_text("hello\n")
    _git(src, "add", "README.md")
    _git(src, "commit", "-q", "-m", "init")
    return src


@pytest.fixture
def clone_project(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Write project `p`, whose `dev` template clones a local repo to /workspace/repo."""
    if shutil.which("git") is None:
        pytest.skip("git not installed")
    from warren.git import manager

    monkeypatch.setattr(manager, "_validate_clone_url", lambda url: None)
    monkeypatch.setattr(manager, "_GIT_ALLOW_PROTOCOL_ENV", {"GIT_ALLOW_PROTOCOL": "file"})
    src = _source_repo(tmp_path)
    projects = tmp_path / "projects"
    projects.mkdir()
    monkeypatch.setenv("WARREN_PROJECTS_DIR", str(projects))

    def write(image: str) -> None:
        (projects / "p.yaml").write_text(
            f"""\
name: p
docker_image: {image}
templates:
  dev:
    folders:
      - name: repo
        type: git-clone
        url: file://{src}
        branch: main
        mount: repo
"""
        )

    return write


async def _provision(client: AsyncClient) -> str:
    response = await client.post("/workspaces", json={"project": "p", "template": "dev"})
    assert response.status_code == 202, response.text
    workspace_id = response.json()["workspace_id"]
    status = None
    for _ in range(60):
        status = (await client.get(f"/workspaces/{workspace_id}/status")).json()["status"]
        if status in ("running", "failed", "error"):
            break
        await asyncio.sleep(0.5)
    assert status == "running", f"never reached running, last status={status}"
    return workspace_id


async def _container(app, workspace_id: str):
    ws = await app.state.registry.store.get(workspace_id)
    assert ws is not None and ws.container_id
    return await asyncio.to_thread(app.state.registry.runtime._client.containers.get, ws.container_id)


async def _exec(container, cmd: str, user: str | None = None) -> tuple[int, str]:
    kwargs = {"user": user} if user else {}
    code, (out, err) = await asyncio.to_thread(container.exec_run, ["sh", "-c", cmd], demux=True, **kwargs)
    return code, ((out or b"") + (err or b"")).decode().strip()


def _clone_dir(app, workspace_id: str) -> Path:
    return app.state.registry.git_manager.folder_worktree_path(workspace_id, "repo")


async def test_clone_is_owned_by_uid_1000_inside_and_its_writes_by_the_server_user(
    itest_env: dict[str, object], clone_project
) -> None:
    clone_project(str(itest_env["image"]))
    from warren.app import app, lifespan

    async with lifespan(app), AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", headers=_AUTH
    ) as client:
        assert app.state.settings.podman_userns == "keep-id:uid=1000,gid=1000"
        workspace_id = await _provision(client)
        container = await _container(app, workspace_id)
        clone = _clone_dir(app, workspace_id)
        assert (clone / "README.md").read_text() == "hello\n"

        # The container still starts (and execs) as root, as before.
        assert await _exec(container, "id -u") == (0, "0")
        # What the server's clone wrote is uid/gid 1000's inside... (A podman machine on
        # macOS shares the host over virtiofs, which reports every file as owned by
        # whoever stats it, so only uid 1000's own view is checked there.)
        stat_user = "1000:1000" if sys.platform == "darwin" else None
        assert await _exec(
            container, "stat -c %u:%g /workspace/repo /workspace/repo/README.md", user=stat_user
        ) == (0, "1000:1000\n1000:1000")
        # ...and uid 1000 can change it and add to it.
        code, out = await _exec(
            container,
            "echo more >> /workspace/repo/README.md && echo new > /workspace/repo/from-ws.txt"
            " && mkdir /workspace/repo/wsdir && echo y > /workspace/repo/wsdir/f",
            user="1000:1000",
        )
        assert code == 0, out
        assert (clone / "README.md").read_text() == "hello\nmore\n"
        for written in (clone / "from-ws.txt", clone / "wsdir", clone / "wsdir" / "f"):
            assert written.stat().st_uid == os.getuid(), written

        # Container root still writes there (as a subuid on a Linux host); destroy must
        # still clean the clone up, through `podman unshare` when the server can't.
        code, out = await _exec(
            container, "mkdir -m 700 /workspace/repo/rootdir && echo z > /workspace/repo/rootdir/f"
        )
        assert code == 0, out
        assert (await client.delete(f"/workspaces/{workspace_id}")).status_code == 204
        assert not clone.exists()


async def test_host_userns_keeps_the_old_mapping(
    itest_env: dict[str, object], clone_project, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WARREN_PODMAN_USERNS", "host")
    clone_project(str(itest_env["image"]))
    from warren.app import app, lifespan

    async with lifespan(app), AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", headers=_AUTH
    ) as client:
        workspace_id = await _provision(client)
        container = await _container(app, workspace_id)
        assert await _exec(container, "id -u") == (0, "0")
        assert await _exec(container, "stat -c %u /workspace/repo/README.md") == (0, "0")


async def _ssh(keyfile: Path, port: int, user: str, command: str) -> subprocess.CompletedProcess:
    argv = ["ssh", "-i", str(keyfile), "-p", str(port), *_SSH_OPTS, f"{user}@127.0.0.1", command]
    last = None
    for _ in range(30):
        last = await asyncio.to_thread(
            subprocess.run, argv, stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=20
        )
        err = (last.stderr or "").lower()
        if last.returncode == 0 or not ("connection refused" in err or "connection reset" in err):
            return last
        await asyncio.sleep(1.0)
    return last


async def _ssh_as_warren_saves_a_file(image: str, clone_project, tmp_path: Path, monkeypatch) -> None:
    if shutil.which("ssh") is None:
        pytest.skip("ssh (openssh-client) not installed on this host")
    clone_project(image)
    monkeypatch.setenv("WARREN_SSH_ACCESS_ENABLED", "true")
    from warren.app import app, lifespan

    async with lifespan(app), AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", headers=_AUTH
    ) as client:
        workspace_id = await _provision(client)
        payload = (await client.post(f"/workspaces/{workspace_id}/connect")).json()
        keyfile = tmp_path / "id_ed25519"
        keyfile.write_text(payload["private_key"])
        keyfile.chmod(0o600)

        result = await _ssh(
            keyfile, payload["port"], payload["user"],
            "id -u && echo saved > /workspace/repo/saved-by-warren.txt && echo ok >> /workspace/repo/README.md",
        )
        assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
        assert result.stdout.split()[0] == "1000"
        clone = _clone_dir(app, workspace_id)
        saved = clone / "saved-by-warren.txt"
        assert saved.read_text() == "saved\n"
        assert saved.stat().st_uid == os.getuid()
        assert (clone / "README.md").read_text() == "hello\nok\n"

        root = await _ssh(keyfile, payload["port"], "root", "true")
        assert root.returncode != 0 and "Permission denied" in root.stderr


async def test_ssh_as_warren_saves_a_file_in_the_checkout(
    itest_env: dict[str, object],
    itest_workspace_docker_image: str,
    clone_project,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The SSH fixture image: `warren` is uid 1000 (its ForceCommand runs the command)."""
    await _ssh_as_warren_saves_a_file(itest_workspace_docker_image, clone_project, tmp_path, monkeypatch)


async def test_ssh_as_warren_saves_a_file_with_warren_docker_ssh_base(
    itest_env: dict[str, object],
    itest_docker_ssh_base_image_if_present: str,
    clone_project,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The same with the shipped warren-docker-ssh-base (PR #71), when it's available."""
    await _ssh_as_warren_saves_a_file(itest_docker_ssh_base_image_if_present, clone_project, tmp_path, monkeypatch)
