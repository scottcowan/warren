"""Live-podman proof that warren-docker-base runs its workload as `warren` (uid 1000).

Runs the image this checkout builds (itest_docker_base_image). Under the default keep-id
userns the entrypoint starts as container root, writes /etc/warren/*, then drops to uid
1000 for the tmux server, harness init, agent supervisor and the app; so what the agent
creates in the checkout belongs to the server user on the host, which can write, pull into
and remove it with no `podman unshare`. With WARREN_PODMAN_USERNS=host the workload stays
root (the server user is container root there), as before.

On macOS the podman machine shares the host over virtiofs, which reports ownership
differently from a Linux host, so the host-side owner assertions run on Linux (CI) only;
everything else runs on both.
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
from warren_common.runtime.base import WorkspaceHandle

from .test_podman_userns import (
    _AUTH,
    _clone_dir,
    _container,
    _exec,
    _git,
    _provision,
    _ssh,
    clone_project,  # noqa: F401  (fixture)
)

pytestmark = pytest.mark.requires_podman

_WORKLOAD_UID_SCRIPT = (
    # uid of the process that runs the shell-first workspace's app (`tail -f /dev/null`)
    # and of the entrypoint itself: both are started by it, so both are the workload.
    'for p in /proc/[0-9]*; do c=$(tr "\\0" " " < $p/cmdline 2>/dev/null); '
    'case "$c" in "tail -f /dev/null"*) echo "tail $(stat -c %u $p)";; *entrypoint.py*) echo "entrypoint $(stat -c %u $p)";; esac; done'
)


def _host_owned(path: Path) -> bool:
    return True if sys.platform == "darwin" else path.stat().st_uid == os.getuid()


async def _workload_uids(container) -> dict[str, str]:
    """{process: uid} once the entrypoint has finished its root phase and started the app."""
    for _ in range(60):
        code, out = await _exec(container, _WORKLOAD_UID_SCRIPT)
        found = dict(line.split() for line in out.splitlines() if line.strip())
        if code == 0 and "tail" in found and "entrypoint" in found:
            return found
        await asyncio.sleep(0.5)
    raise AssertionError(f"workload never started: {out!r}")


async def _tmux_creates(container, rel: str) -> None:
    """Start tmux session `main` from a ROOT exec (what `podman exec` does) and let its
    command create a file in the checkout, as an agent would."""
    code, out = await _exec(
        container,
        f"tmux new-session -d -s main 'sh -c \"mkdir -p /workspace/repo/agent-dir && touch /workspace/repo/{rel}; sleep 300\"'",
    )
    assert code == 0, out
    for _ in range(40):
        if (await _exec(container, f"test -e /workspace/repo/{rel}"))[0] == 0:
            return
        await asyncio.sleep(0.25)
    raise AssertionError(f"{rel} never appeared")


class _Spy:
    """Records `podman unshare` calls while delegating to the real subprocess.run."""

    def __init__(self) -> None:
        self.unshare_calls: list[list[str]] = []
        self._real = subprocess.run

    def __call__(self, argv, *a, **k):
        if isinstance(argv, list) and argv[1:2] == ["unshare"]:
            self.unshare_calls.append(argv)
        return self._real(argv, *a, **k)


async def test_keep_id_workload_is_uid_1000_and_its_files_are_the_server_users(
    itest_env: dict[str, object], itest_docker_base_image: str, clone_project, monkeypatch: pytest.MonkeyPatch
) -> None:
    clone_project(itest_docker_base_image)
    spy = _Spy()
    monkeypatch.setattr("warren.runtime.userns.subprocess.run", spy)
    from warren.app import app, lifespan

    async with lifespan(app), AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", headers=_AUTH
    ) as client:
        workspace_id = await _provision(client)
        container = await _container(app, workspace_id)
        clone = _clone_dir(app, workspace_id)

        # The workload, and the entrypoint supervising it, run as uid 1000.
        assert await _workload_uids(container) == {"tail": "1000", "entrypoint": "1000"}
        # The root phase did its root-only work first: root-owned files in /etc/warren
        # (the container still *starts* as root, so a bare exec is root).
        assert await _exec(container, "id -u") == (0, "0")
        assert await _exec(container, "stat -c '%u:%g %a' /etc/warren/workload /etc/warren/session.env") == (
            0,
            "0:0 644\n0:0 644",
        )
        assert (await _exec(container, "cat /etc/warren/workload"))[1] == "1000 1000 /home/warren warren"
        # Server-side exec sessions run as the workload user (the warren.exec_user label).
        runtime = app.state.registry.runtime
        ws = await app.state.registry.store.get(workspace_id)
        handle = WorkspaceHandle(workspace_id=workspace_id, runtime_id=ws.container_id, root_path="")
        out = b""
        async for item in runtime.exec_stream(handle, ["id", "-u"]):
            if isinstance(item, bytes):
                out += item
        assert out.strip() == b"1000"

        # A tmux session started by a root `podman exec` lands in the workload's tmux
        # server (uid 1000), not a second root one.
        await _tmux_creates(container, "by-tmux.txt")
        assert (await _exec(container, "ls -d /tmp/tmux-1000 && ! test -e /tmp/tmux-0"))[0] == 0
        assert (await _exec(container, "stat -c %u /workspace/repo/by-tmux.txt /workspace/repo/agent-dir", user="1000:1000"))[1] == "1000\n1000"

        # On the host the agent's files are the server user's: writable, and no subuid.
        by_tmux = clone / "by-tmux.txt"
        assert _host_owned(by_tmux) and _host_owned(clone / "agent-dir")
        with by_tmux.open("a") as f:
            f.write("host edit\n")
        (clone / "agent-dir" / "from-host").write_text("x")

        # Destroy needs no `podman unshare`.
        assert (await client.delete(f"/workspaces/{workspace_id}")).status_code == 204
        assert not clone.exists()
        assert spy.unshare_calls == []


async def test_git_pull_works_after_the_agent_created_files(
    itest_env: dict[str, object], itest_docker_base_image: str, clone_project, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    clone_project(itest_docker_base_image)
    # `pull` updates a root clone or `git-worktree` folders (not `git-clone` ones).
    project_file = Path(os.environ["WARREN_PROJECTS_DIR"]) / "p.yaml"
    project_file.write_text(project_file.read_text().replace("type: git-clone", "type: git-worktree"))
    from warren.app import app, lifespan

    async with lifespan(app), AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", headers=_AUTH
    ) as client:
        workspace_id = await _provision(client)
        container = await _container(app, workspace_id)
        await _workload_uids(container)
        clone = _clone_dir(app, workspace_id)

        # The agent works in the checkout: a new dir with a mode-0700 subdir and an
        # edit of a tracked file's neighbour.
        await _tmux_creates(container, "agent-file.txt")
        code, out = await _exec(
            container,
            "mkdir -m 700 /workspace/repo/agent-dir/private && echo s > /workspace/repo/agent-dir/private/secret",
            user="1000:1000",
        )
        assert code == 0, out

        # Upstream moves on; the server pulls into the checkout the agent has been using.
        src_repo = Path(str(itest_env["data_dir"])) / "src-repo"
        (src_repo / "NEWS.md").write_text("news\n")
        _git(src_repo, "add", "NEWS.md")
        _git(src_repo, "commit", "-q", "-m", "news")

        pulled = await client.post(f"/workspaces/{workspace_id}/git/pull")
        assert pulled.status_code == 200, pulled.text
        assert (clone / "NEWS.md").read_text() == "news\n"
        assert (clone / "agent-file.txt").exists()
        assert (clone / "agent-dir" / "private" / "secret").read_text() == "s\n"


async def test_host_userns_keeps_a_root_workload(
    itest_env: dict[str, object], itest_docker_base_image: str, clone_project, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("WARREN_PODMAN_USERNS", "host")
    clone_project(itest_docker_base_image)
    from warren.app import app, lifespan

    async with lifespan(app), AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", headers=_AUTH
    ) as client:
        workspace_id = await _provision(client)
        container = await _container(app, workspace_id)
        # The server user is container root here, so the workload stays root...
        assert await _workload_uids(container) == {"tail": "0", "entrypoint": "0"}
        assert (await _exec(container, "test -e /etc/warren/workload"))[0] != 0
        # ...no exec-user pin, and root's files are the server user's on the host.
        assert "warren.exec_user" not in container.labels
        await _tmux_creates(container, "by-root.txt")
        assert (await _exec(container, "ls -d /tmp/tmux-0"))[0] == 0
        clone = _clone_dir(app, workspace_id)
        assert _host_owned(clone / "by-root.txt")
        (clone / "by-root.txt").write_text("host edit\n")
        assert (await client.delete(f"/workspaces/{workspace_id}")).status_code == 204
        assert not clone.exists()


async def test_ssh_warren_and_the_workload_are_one_user_with_docker_ssh_base(
    itest_env: dict[str, object],
    itest_docker_ssh_on_new_base: str,
    clone_project,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """warren-docker-ssh-base's own sshd, users and hardening on the new docker-base:
    sshd stays container root, the SSH `warren` login is the workload's uid 1000 and
    sees its files; `warren-shell` (1001) is still a separate login; root is refused."""
    if shutil.which("ssh") is None:
        pytest.skip("ssh (openssh-client) not installed on this host")
    clone_project(itest_docker_ssh_on_new_base)
    monkeypatch.setenv("WARREN_SSH_ACCESS_ENABLED", "true")
    from warren.app import app, lifespan

    async with lifespan(app), AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test", headers=_AUTH
    ) as client:
        workspace_id = await _provision(client)
        container = await _container(app, workspace_id)
        payload = (await client.post(f"/workspaces/{workspace_id}/connect")).json()
        keyfile = tmp_path / "id_ed25519"
        keyfile.write_text(payload["private_key"])
        keyfile.chmod(0o600)
        assert payload["user"] == "warren" and payload["break_glass_user"] == "warren-shell"

        # Workload = uid 1000; sshd itself is still root (it is not the entrypoint's child).
        assert (await _workload_uids(container))["tail"] == "1000"
        sshd = await _exec(container, 'for p in /proc/[0-9]*; do [ "$(cat $p/comm 2>/dev/null)" = sshd ] && stat -c %u $p; done')
        assert sshd[1].splitlines()[:1] == ["0"], sshd

        await _tmux_creates(container, "by-agent.txt")
        result = await _ssh(
            keyfile, payload["port"], "warren",
            "id -u && cat /workspace/repo/by-agent.txt >/dev/null && echo saved > /workspace/repo/saved-by-ssh.txt"
            " && echo ok >> /workspace/repo/README.md && ls -ld /tmp/tmux-1000 | cut -c1-10",
        )
        assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
        assert result.stdout.split()[0] == "1000"
        clone = _clone_dir(app, workspace_id)
        assert (clone / "saved-by-ssh.txt").read_text() == "saved\n"
        assert _host_owned(clone / "saved-by-ssh.txt") and _host_owned(clone / "by-agent.txt")
        # The agent can read what the SSH login wrote.
        assert (await _exec(container, "cat /workspace/repo/saved-by-ssh.txt", user="1000:1000"))[1] == "saved"

        # warren-shell: still its own account (uid 1001), not the workload user.
        shell = await _ssh(keyfile, payload["port"], "warren-shell", "id -un && id -u")
        assert shell.returncode == 0, shell.stderr
        assert shell.stdout.split() == ["warren-shell", "1001"]
        root = await _ssh(keyfile, payload["port"], "root", "true")
        assert root.returncode != 0 and "Permission denied" in root.stderr
