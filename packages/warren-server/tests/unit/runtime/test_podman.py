"""PodmanRuntime unit tests — mocked podman-py client.

These cases assert the contract that Plan 03 must land:
  a) provision applies all four warren.* labels
  b) provision passes init=True
  c) preflight raises when socket missing
  d) preflight raises when subuid UIDMap sum < 65536
  e) preflight warns when graphDriver == "vfs"
"""

from __future__ import annotations

import io
import tarfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from podman.errors import APIError, BuildError, ImageNotFound, NotFound

from warren.images.build_spec import BuildSpec
from warren.runtime import podman as podman_runtime
from warren_common.errors import ImageUnavailable, RuntimeUnreachable
from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec
from warren.runtime.podman import PodmanRuntime, run_preflight  # RED until Plan 03


_real_ensure_workspace_network = podman_runtime._ensure_workspace_network


@pytest.fixture(autouse=True)
def _no_real_network_ensure():
    """Default every test in this module to a no-op _ensure_workspace_network.

    The mocked client's networks.get returns a MagicMock that is never an
    isolated network, so provision() tests that don't care about networking
    would otherwise fail closed. Network tests re-patch or call the real helper.
    """
    with patch("warren.runtime.podman._ensure_workspace_network"):
        yield


def _spec() -> WorkspaceSpec:
    return WorkspaceSpec(
        workspace_id="ws-1",
        project="proj",
        intent="dev",
        image="localhost/warren-base:latest",
        root_path="/tmp/ws-1",
    )


@pytest.mark.asyncio
async def test_labels_applied_on_provision():
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        container = MagicMock(id="ctr-abc")
        client.containers.create.return_value = container
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        await runtime.provision(_spec())
        _, kwargs = client.containers.create.call_args
        labels = kwargs["labels"]
        assert labels["warren.workspace_id"] == "ws-1"
        assert labels["warren.server_instance"] == "srv-1"
        assert labels["warren.project"] == "proj"
        assert labels["warren.intent"] == "dev"


@pytest.mark.asyncio
async def test_provision_passes_init_true():
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.containers.create.return_value = MagicMock(id="ctr-abc")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        await runtime.provision(_spec())
        _, kwargs = client.containers.create.call_args
        assert kwargs.get("init") is True


@pytest.mark.asyncio
async def test_preflight_raises_when_socket_missing(tmp_path: Path):
    missing = tmp_path / "no.sock"
    with pytest.raises(Exception) as ei:
        await run_preflight(socket_path=str(missing))
    assert "socket" in str(ei.value).lower()


@pytest.mark.asyncio
async def test_preflight_raises_when_subuid_too_small(tmp_path: Path):
    sock = tmp_path / "podman.sock"
    sock.touch()
    info = {
        "host": {"idMappings": {"uidmap": [{"size": 1000}]}},
        "store": {"graphDriverName": "overlay"},
    }
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.ping.return_value = True
        client.info.return_value = info
        with pytest.raises(Exception) as ei:
            await run_preflight(socket_path=str(sock))
        assert "subuid" in str(ei.value).lower() or "65536" in str(ei.value)


@pytest.mark.asyncio
async def test_preflight_warns_on_vfs_driver(tmp_path: Path, caplog):
    sock = tmp_path / "podman.sock"
    sock.touch()
    info = {
        "host": {"idMappings": {"uidmap": [{"size": 65536}]}},
        "store": {"graphDriverName": "vfs"},
    }
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.ping.return_value = True
        client.info.return_value = info
        with caplog.at_level("WARNING"):
            await run_preflight(socket_path=str(sock))
        assert any("vfs" in r.getMessage().lower() for r in caplog.records)


@pytest.mark.asyncio
async def test_provision_injects_warren_workspace_id():
    """provision() must inject WARREN_WORKSPACE_ID into container env (04-05)."""
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.containers.create.return_value = MagicMock(id="ctr-abc")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        await runtime.provision(_spec())
        _, kwargs = client.containers.create.call_args
        env = kwargs["environment"]
        assert "WARREN_WORKSPACE_ID" in env
        assert env["WARREN_WORKSPACE_ID"] == "ws-1"


@pytest.mark.asyncio
async def test_provision_injects_warren_app_from_spec():
    """entrypoint.py picks its foreground app from WARREN_APP -- this was never
    set here, so every workspace silently ran bash regardless of spec.app."""
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.containers.create.return_value = MagicMock(id="ctr-abc")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        spec = _spec()
        spec.app = "acp-serve --port 9000"
        await runtime.provision(spec)
        _, kwargs = client.containers.create.call_args
        assert kwargs["environment"]["WARREN_APP"] == "acp-serve --port 9000"
        assert "WARREN_SHELL_FIRST" not in kwargs["environment"]


@pytest.mark.asyncio
async def test_provision_harness_app_starts_at_the_warren_shell():
    """AG2a: entrypoint.py keeps the container up and connect runs the shell in tmux."""
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.containers.create.return_value = MagicMock(id="ctr-abc")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        spec = _spec()
        spec.app = "zsh"
        spec.harnesses = ["claude", "codex"]
        await runtime.provision(spec)
        env = client.containers.create.call_args.kwargs["environment"]
        assert env["WARREN_APP"] == "zsh"
        assert env["WARREN_SHELL_FIRST"] == "1"
        assert env["WARREN_HARNESSES"] == "claude codex"
        assert env["WARREN_HARNESS_DEFAULT"] == "claude"


@pytest.mark.asyncio
async def test_provision_defaults_warren_app_to_bash():
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.containers.create.return_value = MagicMock(id="ctr-abc")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        await runtime.provision(_spec())
        _, kwargs = client.containers.create.call_args
        assert kwargs["environment"]["WARREN_APP"] == "bash"


@pytest.mark.asyncio
async def test_provision_injects_warren_project_and_template():
    """UX-1: the baked-in .zshrc's shared banner/prompt snippet
    (warren_common/assets/warren_banner.zsh) reads these at shell-start time
    -- never set for remote (podman) workspaces before this."""
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.containers.create.return_value = MagicMock(id="ctr-abc")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        await runtime.provision(_spec())
        _, kwargs = client.containers.create.call_args
        env = kwargs["environment"]
        assert env["WARREN_PROJECT"] == "proj"
        assert env["WARREN_TEMPLATE"] == "dev"


@pytest.mark.asyncio
async def test_status_with_empty_runtime_id_returns_unknown_without_calling_podman():
    """A workspace that failed before a container was ever created has
    runtime_id == "" (registry.py's list_non_terminal: `r.container_id or ""`).
    podman-py's containers.get("") does not raise NotFound for this -- it
    crashes trying to parse podman's response into a Container at all.
    Observed directly 2026-10-13: the reaper polling such a row every 2s,
    crashing repeatedly and contending for the podman socket badly enough to
    make an unrelated, concurrent real provision fail with runtime_unreachable."""
    from warren_common.runtime.base import WorkspaceHandle

    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        handle = WorkspaceHandle(workspace_id="ws-1", runtime_id="", root_path="")

        result = await runtime.status(handle)

        assert result == "unknown"
        client.containers.get.assert_not_called()


@pytest.mark.asyncio
async def test_provision_injects_warren_worktree_paths_empty():
    """provision() with no worktree_paths injects WARREN_WORKTREE_PATHS="" (04-05)."""
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.containers.create.return_value = MagicMock(id="ctr-abc")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        await runtime.provision(_spec())
        _, kwargs = client.containers.create.call_args
        env = kwargs["environment"]
        assert "WARREN_WORKTREE_PATHS" in env
        assert env["WARREN_WORKTREE_PATHS"] == ""


@pytest.mark.asyncio
async def test_provision_injects_warren_worktree_paths_populated():
    """provision() with worktree_paths injects colon-delimited container paths (04-05)."""
    spec = WorkspaceSpec(
        workspace_id="ws-2",
        project="proj",
        intent="dev",
        image="localhost/warren-base:latest",
        root_path="/tmp/ws-2",
        worktree_paths=[
            ("/host/repo-a", "/workspace/repo-a"),
            ("/host/repo-b", "/workspace/repo-b"),
        ],
    )
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.containers.create.return_value = MagicMock(id="ctr-xyz")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        await runtime.provision(spec)
        _, kwargs = client.containers.create.call_args
        env = kwargs["environment"]
        assert env["WARREN_WORKTREE_PATHS"] == "/workspace/repo-a:/workspace/repo-b"


@pytest.mark.asyncio
async def test_provision_returns_handle_with_sidecar_socket_path():
    """provision() must set sidecar_socket_path on the returned WorkspaceHandle (04-05, D-12)."""
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.containers.create.return_value = MagicMock(id="ctr-abc")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        handle = await runtime.provision(_spec())
        assert handle.sidecar_socket_path == "/tmp/warren-sidecar.sock"


def _extract_authorized_keys(data: bytes) -> tuple[list[str], bytes]:
    """Read a put_archive tar payload back and return (member names, content of authorized_keys)."""
    with tarfile.open(fileobj=io.BytesIO(data)) as tar:
        names = tar.getnames()
        member = tar.extractfile("authorized_keys")
        content = member.read() if member is not None else b""
    return names, content


# --- Task 1: publish ssh_port and inject the public key ---


@pytest.mark.asyncio
async def test_provision_publishes_ssh_port_when_given():
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.containers.create.return_value = MagicMock(id="ctr-abc")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        await runtime.provision(_spec(), ssh_port=30017)
        _, kwargs = client.containers.create.call_args
        assert kwargs["ports"] == {"22/tcp": 30017}


@pytest.mark.asyncio
async def test_provision_omits_ports_kwarg_when_no_ssh_port():
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.containers.create.return_value = MagicMock(id="ctr-abc")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        await runtime.provision(_spec())
        _, kwargs = client.containers.create.call_args
        assert "ports" not in kwargs


@pytest.mark.asyncio
async def test_provision_omits_ports_kwarg_when_publish_ssh_port_false():
    """Audit R12: the allocated SSH port used to be published on every
    workspace's container unconditionally, even though the in-container sshd
    this was meant to serve was never actually built. publish_ssh_port=False
    (the registry's real default, from settings.ssh_access_enabled=False)
    must suppress the publish even when a real ssh_port value is given --
    port ALLOCATION/bookkeeping is unaffected, only the container-level
    publish is gated."""
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.containers.create.return_value = MagicMock(id="ctr-abc")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        await runtime.provision(_spec(), ssh_port=30017, publish_ssh_port=False)
        _, kwargs = client.containers.create.call_args
        assert "ports" not in kwargs


@pytest.mark.asyncio
async def test_provision_publish_ssh_port_defaults_to_true_for_direct_callers():
    """publish_ssh_port's default (True) preserves the old unconditional
    behavior for any caller that constructs PodmanRuntime directly and
    doesn't pass it -- only the registry's own call site threads the real
    settings.ssh_access_enabled-derived value (see
    test_provision_omits_ports_kwarg_when_publish_ssh_port_false above)."""
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.containers.create.return_value = MagicMock(id="ctr-abc")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        await runtime.provision(_spec(), ssh_port=30017)
        _, kwargs = client.containers.create.call_args
        assert kwargs["ports"] == {"22/tcp": 30017}


@pytest.mark.asyncio
async def test_provision_injects_public_key_via_put_archive():
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        container = MagicMock(id="ctr-abc")
        client.containers.create.return_value = container
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        await runtime.provision(
            _spec(), ssh_port=30017, ssh_public_key="ssh-ed25519 AAAA...")
        container.put_archive.assert_called_once()
        _, kwargs = container.put_archive.call_args
        assert kwargs["path"] == "/etc/warren"
        names, content = _extract_authorized_keys(kwargs["data"])
        assert names == ["authorized_keys"]
        assert content == b"ssh-ed25519 AAAA...\n"


@pytest.mark.asyncio
async def test_provision_injects_key_before_start():
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        container = MagicMock(id="ctr-abc")
        client.containers.create.return_value = container
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        await runtime.provision(
            _spec(), ssh_port=30017, ssh_public_key="ssh-ed25519 AAAA...")
        call_names = [c[0] for c in container.mock_calls]
        assert call_names.index("put_archive") < call_names.index("start")


@pytest.mark.asyncio
async def test_provision_does_not_call_put_archive_when_no_public_key():
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        container = MagicMock(id="ctr-abc")
        client.containers.create.return_value = container
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        await runtime.provision(_spec(), ssh_port=30017)
        container.put_archive.assert_not_called()


@pytest.mark.asyncio
async def test_inject_ssh_key_resolves_container_and_writes_authorized_keys():
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        container = MagicMock(id="ctr-abc")
        client.containers.get.return_value = container
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        handle = WorkspaceHandle(
            workspace_id="ws-1", runtime_id="ctr-abc", root_path="/tmp/ws-1"
        )
        await runtime.inject_ssh_key(handle, "ssh-ed25519 AAAA...")
        client.containers.get.assert_called_once_with("ctr-abc")
        _, kwargs = container.put_archive.call_args
        assert kwargs["path"] == "/etc/warren"
        names, content = _extract_authorized_keys(kwargs["data"])
        assert names == ["authorized_keys"]
        assert content == b"ssh-ed25519 AAAA...\n"


@pytest.mark.asyncio
async def test_inject_ssh_key_raises_runtime_unreachable_when_container_missing():
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.containers.get.side_effect = NotFound("no such container")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        handle = WorkspaceHandle(
            workspace_id="ws-1", runtime_id="ctr-missing", root_path="/tmp/ws-1"
        )
        with pytest.raises(RuntimeUnreachable):
            await runtime.inject_ssh_key(handle, "ssh-ed25519 AAAA...")


@pytest.mark.asyncio
async def test_inject_ssh_key_raises_runtime_unreachable_on_put_archive_api_error():
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        container = MagicMock(id="ctr-abc")
        container.put_archive.side_effect = APIError("boom")
        client.containers.get.return_value = container
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        handle = WorkspaceHandle(
            workspace_id="ws-1", runtime_id="ctr-abc", root_path="/tmp/ws-1"
        )
        with pytest.raises(RuntimeUnreachable):
            await runtime.inject_ssh_key(handle, "ssh-ed25519 AAAA...")


# --- Task 2: invalidate the injected key on stop and destroy (D-03) ---


@pytest.mark.asyncio
async def test_stop_wipes_authorized_keys_before_stopping():
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        container = MagicMock(id="ctr-abc")
        client.containers.get.return_value = container
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        handle = WorkspaceHandle(
            workspace_id="ws-1", runtime_id="ctr-abc", root_path="/tmp/ws-1"
        )
        await runtime.stop(handle)

        container.stop.assert_called_once_with(timeout=5)
        _, kwargs = container.put_archive.call_args
        assert kwargs["path"] == "/etc/warren"
        names, content = _extract_authorized_keys(kwargs["data"])
        assert names == ["authorized_keys"]
        assert content == b""

        call_names = [c[0] for c in container.mock_calls]
        assert call_names.index("put_archive") < call_names.index("stop")


@pytest.mark.asyncio
async def test_destroy_wipes_authorized_keys_before_removing():
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        container = MagicMock(id="ctr-abc")
        client.containers.get.return_value = container
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        handle = WorkspaceHandle(
            workspace_id="ws-1", runtime_id="ctr-abc", root_path="/tmp/ws-1"
        )
        await runtime.destroy(handle)

        container.remove.assert_called_once_with(force=True)
        _, kwargs = container.put_archive.call_args
        names, content = _extract_authorized_keys(kwargs["data"])
        assert names == ["authorized_keys"]
        assert content == b""

        call_names = [c[0] for c in container.mock_calls]
        assert call_names.index("put_archive") < call_names.index("remove")


@pytest.mark.asyncio
async def test_destroy_on_missing_container_returns_without_wipe():
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.containers.get.side_effect = NotFound("no such container")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        handle = WorkspaceHandle(
            workspace_id="ws-1", runtime_id="ctr-missing", root_path="/tmp/ws-1"
        )
        # Must not raise.
        await runtime.destroy(handle)


@pytest.mark.asyncio
async def test_stop_put_archive_failure_does_not_block_stop():
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        container = MagicMock(id="ctr-abc")
        container.put_archive.side_effect = APIError("boom")
        client.containers.get.return_value = container
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        handle = WorkspaceHandle(
            workspace_id="ws-1", runtime_id="ctr-abc", root_path="/tmp/ws-1"
        )
        # Must not raise — wipe failure is logged, not propagated.
        await runtime.stop(handle)
        container.stop.assert_called_once_with(timeout=5)


@pytest.mark.asyncio
async def test_destroy_put_archive_failure_does_not_block_remove():
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        container = MagicMock(id="ctr-abc")
        container.put_archive.side_effect = APIError("boom")
        client.containers.get.return_value = container
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        handle = WorkspaceHandle(
            workspace_id="ws-1", runtime_id="ctr-abc", root_path="/tmp/ws-1"
        )
        await runtime.destroy(handle)
        container.remove.assert_called_once_with(force=True)


# --- Finding 9: per-workspace isolated bridge networks (LIFE-02 egress counting) ---


def _isolated_net(server_id: str = "srv-1", isolate: str = "true") -> MagicMock:
    return MagicMock(
        attrs={
            "options": {"isolate": isolate},
            "labels": {"warren.server_instance": server_id},
        }
    )


@pytest.mark.asyncio
async def test_provision_attaches_its_own_workspace_network():
    with (
        patch("warren.runtime.podman.PodmanClient") as ClientCls,
        patch("warren.runtime.podman._ensure_workspace_network") as ensure_mock,
    ):
        client = ClientCls.return_value
        client.containers.create.return_value = MagicMock(id="ctr-abc")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        await runtime.provision(_spec())
        _, kwargs = client.containers.create.call_args
        assert kwargs["networks"] == {"warren-egress-ws-1": {}}
        ensure_mock.assert_called_once_with(
            client,
            "warren-egress-ws-1",
            {
                "warren.workspace_id": "ws-1",
                "warren.server_instance": "srv-1",
                "warren.network": "workspace",
            },
        )


@pytest.mark.asyncio
async def test_two_workspaces_never_share_a_network():
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.containers.create.return_value = MagicMock(id="ctr-abc")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        await runtime.provision(_spec())
        other = _spec()
        other.workspace_id = "ws-2"
        await runtime.provision(other)
        first, second = (c.kwargs["networks"] for c in client.containers.create.call_args_list)
        assert first.keys().isdisjoint(second.keys())


@pytest.mark.asyncio
async def test_provision_sets_network_mode_bridge_alongside_networks():
    """Regression guard (live node2 finding, 2026-09-19): podman-py only
    populates the create payload's `netns` field when `network_mode` is
    explicitly passed; the Podman REST API rejects a `networks` dict against
    any non-bridge netns."""
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.containers.create.return_value = MagicMock(id="ctr-abc")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        await runtime.provision(_spec())
        _, kwargs = client.containers.create.call_args
        assert kwargs["network_mode"] == "bridge"


@pytest.mark.asyncio
async def test_network_ensure_failure_blocks_container_create():
    with (
        patch("warren.runtime.podman.PodmanClient") as ClientCls,
        patch("warren.runtime.podman._ensure_workspace_network") as ensure_mock,
    ):
        ensure_mock.side_effect = RuntimeUnreachable("not isolated")
        client = ClientCls.return_value
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        with pytest.raises(RuntimeUnreachable):
            await runtime.provision(_spec())
        client.containers.create.assert_not_called()


@pytest.mark.asyncio
async def test_container_create_failure_removes_workspace_network():
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.containers.create.side_effect = APIError("boom")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        with pytest.raises(RuntimeUnreachable):
            await runtime.provision(_spec())
        client.networks.remove.assert_called_once_with("warren-egress-ws-1")


@pytest.mark.asyncio
async def test_empty_bridge_name_skips_network_kwarg():
    with (
        patch("warren.runtime.podman.PodmanClient") as ClientCls,
        patch("warren.runtime.podman._ensure_workspace_network") as ensure_mock,
    ):
        client = ClientCls.return_value
        client.containers.create.return_value = MagicMock(id="ctr-abc")
        runtime = PodmanRuntime(
            socket_path="/tmp/sock", server_id="srv-1", egress_bridge_name=""
        )
        await runtime.provision(_spec())
        _, kwargs = client.containers.create.call_args
        assert "networks" not in kwargs
        ensure_mock.assert_not_called()
        await runtime.destroy(WorkspaceHandle(workspace_id="ws-1", runtime_id="ctr-abc", root_path=""))
        client.networks.remove.assert_not_called()


def test_ensure_workspace_network_creates_isolated_bridge():
    client = MagicMock()
    client.networks.get.side_effect = NotFound("missing")
    labels = {"warren.server_instance": "srv-1", "warren.workspace_id": "ws-1"}
    _real_ensure_workspace_network(client, "warren-egress-ws-1", labels)
    client.networks.create.assert_called_once_with(
        "warren-egress-ws-1", driver="bridge", labels=labels, options={"isolate": "true"}
    )


@pytest.mark.parametrize("isolate", ["true", "strict"])
def test_ensure_workspace_network_adopts_existing_isolated_network(isolate):
    client = MagicMock()
    client.networks.get.return_value = _isolated_net(isolate=isolate)
    _real_ensure_workspace_network(client, "n", {"warren.server_instance": "srv-1"})
    client.networks.create.assert_not_called()


@pytest.mark.parametrize(
    "existing",
    [
        MagicMock(attrs={"options": {}, "labels": {"warren.server_instance": "srv-1"}}),
        _isolated_net(isolate="false"),
        _isolated_net(server_id="someone-else"),
    ],
)
def test_ensure_workspace_network_fails_closed_on_foreign_or_open_network(existing):
    client = MagicMock()
    client.networks.get.return_value = existing
    with pytest.raises(RuntimeUnreachable, match="not an isolated"):
        _real_ensure_workspace_network(client, "n", {"warren.server_instance": "srv-1"})


def test_ensure_workspace_network_create_race_rechecks_winner():
    client = MagicMock()
    client.networks.get.side_effect = [NotFound("missing"), _isolated_net()]
    client.networks.create.side_effect = APIError("network name n already exists")
    _real_ensure_workspace_network(client, "n", {"warren.server_instance": "srv-1"})


def test_ensure_workspace_network_api_error_is_runtime_unreachable():
    client = MagicMock()
    client.networks.get.side_effect = NotFound("missing")
    client.networks.create.side_effect = APIError("netavark: boom")
    with pytest.raises(RuntimeUnreachable):
        _real_ensure_workspace_network(client, "n", {"warren.server_instance": "srv-1"})


@pytest.mark.asyncio
async def test_destroy_removes_workspace_network_after_container():
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        order = MagicMock()
        container = MagicMock(id="ctr-abc")
        container.remove.side_effect = lambda **_: order.container_removed()
        client.containers.get.return_value = container
        client.networks.remove.side_effect = lambda name: order.network_removed(name)
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        await runtime.destroy(WorkspaceHandle(workspace_id="ws-1", runtime_id="ctr-abc", root_path=""))
        assert [c[0] for c in order.mock_calls] == ["container_removed", "network_removed"]
        order.network_removed.assert_called_once_with("warren-egress-ws-1")


@pytest.mark.asyncio
async def test_destroy_without_container_still_removes_network():
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.containers.get.side_effect = NotFound("gone")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        await runtime.destroy(WorkspaceHandle(workspace_id="ws-1", runtime_id="ctr-abc", root_path=""))
        await runtime.destroy(WorkspaceHandle(workspace_id="ws-1", runtime_id="", root_path=""))
        assert client.networks.remove.call_count == 2
        client.containers.get.assert_called_once_with("ctr-abc")


@pytest.mark.asyncio
async def test_destroy_network_remove_failure_is_not_fatal():
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.containers.get.return_value = MagicMock(id="ctr-abc")
        client.networks.remove.side_effect = APIError("network in use")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        await runtime.destroy(WorkspaceHandle(workspace_id="ws-1", runtime_id="ctr-abc", root_path=""))


@pytest.mark.asyncio
async def test_prune_workspace_networks_removes_only_this_servers_orphans():
    def net(name, labels):
        n = MagicMock(attrs={"labels": labels})
        n.name = name
        return n

    ws = {"warren.network": "workspace", "warren.server_instance": "srv-1"}
    networks = [
        net("keep", {**ws, "warren.workspace_id": "ws-live"}),
        net("orphan", {**ws, "warren.workspace_id": "ws-gone"}),
        net("other-server", {**ws, "warren.server_instance": "srv-2", "warren.workspace_id": "x"}),
        net("not-ours", {"warren.workspace_id": "ws-gone"}),
        net("podman", {}),
    ]
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.networks.list.return_value = networks
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        await runtime.prune_workspace_networks("srv-1", {"ws-live"})
        client.networks.remove.assert_called_once_with("orphan")


# --- 04-04 Task 1: PodmanRuntime.build_image (LIFE-04, D-09) ---


def _build_spec(tmp_path: Path) -> BuildSpec:
    project_dir = tmp_path / "demo"
    project_dir.mkdir()
    containerfile = project_dir / "Containerfile"
    containerfile.write_text("FROM debian:bookworm-slim\n")
    return BuildSpec(
        containerfile=containerfile.resolve(),
        context_dir=project_dir.resolve(),
        tag="localhost/warren-project-demo:abc123",
        memory="2g",
        cpus=2.0,
    )


def test_supports_image_build_capability_flag() -> None:
    assert PodmanRuntime.supports_image_build is True


@pytest.mark.asyncio
async def test_build_image_returns_tag(tmp_path: Path):
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.images.list.return_value = []
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        spec = _build_spec(tmp_path)
        tag = await runtime.build_image(spec)
        assert tag == spec.tag
        client.images.build.assert_called_once()
        _, kwargs = client.images.build.call_args
        assert kwargs["tag"] == spec.tag
        assert kwargs["path"] == str(spec.context_dir)
        assert kwargs["dockerfile"] == "Containerfile"
        assert kwargs["container_limits"]["memory"] == 2 * 1024**3


@pytest.mark.asyncio
async def test_build_image_short_circuits_when_tag_exists(tmp_path: Path):
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.images.list.return_value = [MagicMock()]
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        spec = _build_spec(tmp_path)
        tag = await runtime.build_image(spec)
        assert tag == spec.tag
        client.images.build.assert_not_called()


@pytest.mark.asyncio
async def test_build_image_maps_image_not_found_to_image_unavailable(tmp_path: Path):
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.images.list.return_value = []
        client.images.build.side_effect = ImageNotFound("no such base image")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        with pytest.raises(ImageUnavailable):
            await runtime.build_image(_build_spec(tmp_path))


@pytest.mark.asyncio
async def test_build_image_maps_api_error_to_runtime_unreachable(tmp_path: Path):
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.images.list.return_value = []
        client.images.build.side_effect = APIError("boom")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        with pytest.raises(RuntimeUnreachable):
            await runtime.build_image(_build_spec(tmp_path))


@pytest.mark.asyncio
async def test_build_image_maps_build_error_to_runtime_unreachable(tmp_path: Path):
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.images.list.return_value = []
        client.images.build.side_effect = BuildError("build failed", iter([]))
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        with pytest.raises(RuntimeUnreachable):
            await runtime.build_image(_build_spec(tmp_path))


def _tar(name: str, data: bytes, *, symlink: bool = False) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        info = tarfile.TarInfo(name)
        if symlink:
            info.type = tarfile.SYMTYPE
            info.linkname = "/outside"
            tar.addfile(info)
        else:
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


@pytest.mark.asyncio
async def test_exit_code_of_exited_container():
    """AH2: State.ExitCode once the container has exited; None while it runs."""
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        container = MagicMock(attrs={"State": {"Status": "exited", "ExitCode": 2}})
        ClientCls.return_value.containers.get.return_value = container
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        handle = WorkspaceHandle(workspace_id="ws-1", runtime_id="ctr", root_path="")
        assert await runtime.exit_code(handle) == 2
        container.attrs = {"State": {"Status": "running", "ExitCode": 0}}
        assert await runtime.exit_code(handle) is None


@pytest.mark.asyncio
async def test_read_file_from_container_archive():
    """AH2: verdict.json from a stopped container; only a regular file under the cap."""
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        container = MagicMock()
        ClientCls.return_value.containers.get.return_value = container
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        handle = WorkspaceHandle(workspace_id="ws-1", runtime_id="ctr", root_path="")
        path = "/workspace/.warren/verdict.json"

        container.get_archive.return_value = (iter([_tar("verdict.json", b'{"ok":1}')]), {})
        assert await runtime.read_file(handle, path, 1024) == b'{"ok":1}'

        container.get_archive.return_value = (iter([_tar("verdict.json", b"", symlink=True)]), {})
        with pytest.raises(ValueError):
            await runtime.read_file(handle, path, 1024)

        container.get_archive.return_value = (iter([_tar("verdict.json", b"x" * 2048)]), {})
        with pytest.raises(ValueError):
            await runtime.read_file(handle, path, 1024)

        container.get_archive.side_effect = NotFound("gone")
        assert await runtime.read_file(handle, path, 1024) is None


@pytest.mark.asyncio
async def test_provision_injects_template_env_under_secrets_and_reserved_vars():
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.containers.create.return_value = MagicMock(id="ctr-abc")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        spec = _spec()
        spec.env = {"API_KEY": "secret-value"}
        spec.template_env = {
            "OLLAMA_HOST": "http://gpu:11434",
            "API_KEY": "plain-would-shadow",
            "WARREN_APP": "evil",
        }
        await runtime.provision(spec)
        env = client.containers.create.call_args.kwargs["environment"]
        assert env["OLLAMA_HOST"] == "http://gpu:11434"
        assert env["API_KEY"] == "secret-value"
        assert env["WARREN_APP"] == "bash"


@pytest.mark.asyncio
async def test_provision_appends_seed_prompt_to_warren_app():
    import shlex

    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.containers.create.return_value = MagicMock(id="ctr-abc")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        spec = _spec()
        spec.app = "claude"
        spec.mode = "single-turn"
        spec.seed_prompt = "fix the failing test"
        await runtime.provision(spec)
        env = client.containers.create.call_args.kwargs["environment"]
        assert shlex.split(env["WARREN_APP"]) == ["claude", "fix the failing test"]

        spec.mode = "interactive"
        spec.harnesses = ["claude"]
        await runtime.provision(spec)
        env = client.containers.create.call_args.kwargs["environment"]
        assert env["WARREN_APP"] == "bash"
        assert env["WARREN_SEED_PROMPT"] == "fix the failing test"


@pytest.mark.asyncio
async def test_provision_points_harness_config_at_workspace_dir():
    """AG3."""
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.containers.create.return_value = MagicMock(id="ctr-abc")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        spec = _spec()
        spec.harnesses = ["opencode"]
        spec.app = "acp-serve"
        await runtime.provision(spec)
        env = client.containers.create.call_args.kwargs["environment"]
        assert env["WARREN_HARNESSES"] == "opencode"
        assert env["OPENCODE_CONFIG_DIR"] == "/var/lib/warren/harness/opencode/config"
        assert env["OPENCODE_DB"] == "/var/lib/warren/harness/opencode/data/opencode.db"
        assert "CLAUDE_CONFIG_DIR" not in env


@pytest.mark.asyncio
async def test_provision_mints_a_fresh_sidecar_token_per_container():
    """Audit finding 12: the sidecar gets a random token held only in its own env --
    never a same-named secret's value, never returned on the handle."""
    spec = _spec()
    spec.env = {"WARREN_SIDECAR_TOKEN": "attacker-chosen"}
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.containers.create.return_value = MagicMock(id="ctr-abc")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        handle = await runtime.provision(spec)
        first = client.containers.create.call_args.kwargs["environment"]["WARREN_SIDECAR_TOKEN"]
        await runtime.provision(_spec())
        second = client.containers.create.call_args.kwargs["environment"]["WARREN_SIDECAR_TOKEN"]
    assert first != "attacker-chosen" and len(first) >= 32
    assert second != first
    assert first not in repr(vars(handle))
