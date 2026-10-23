"""Wave 0 RED → GREEN: DockerRuntime provision/status/destroy/network/connect (Plan 05b-03).

Tests use the ``mock_docker_client`` fixture (conftest.py) injected via
``runtime._client = mock_docker_client`` — DockerRuntime lazily creates a
``docker.from_env()`` client inside ``_ensure_client`` which returns the
pre-set attribute if present.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from warren_common.runtime import docker as docker_runtime

_real_ensure_isolated_network = docker_runtime._ensure_isolated_network


@pytest.fixture(autouse=True)
def _isolated_network(monkeypatch):
    """Keep provision() tests' networks.get/create mocks about docker_networks only."""
    net = MagicMock()
    net.name = docker_runtime.ISOLATED_NETWORK

    async def _fake(client):
        return net

    monkeypatch.setattr(docker_runtime, "_ensure_isolated_network", _fake)
    return net


def _spec(root_path: str, docker_networks=None):
    from warren_common.runtime.base import WorkspaceSpec

    return WorkspaceSpec(
        workspace_id="ws-abcdef12",
        project="demo-project",
        intent="claude",
        image="warren-base:latest",
        root_path=root_path,
        env={"ANTHROPIC_API_KEY": "sk-test"},
        worktree_paths=[(f"{root_path}/main", "/workspace/main")],
        reference_paths=[(f"{root_path}/refs/lib", "/refs/lib")],
        bind_mounts=[],
        app="claude",
        docker_networks=list(docker_networks or []),
    )


def _make_runtime(mock_docker_client) -> "object":
    from warren_common.runtime.docker import DockerRuntime

    rt = DockerRuntime(server_id="test-server")
    rt._client = mock_docker_client
    rt._preflight_ok = True
    return rt


def _mkdirs(root: str, spec) -> None:
    Path(root).mkdir(parents=True, exist_ok=True)
    for host, _ in spec.worktree_paths:
        Path(host).mkdir(parents=True, exist_ok=True)
    for host, _ in spec.reference_paths:
        Path(host).mkdir(parents=True, exist_ok=True)


def test_provision_labels(mock_docker_client, tmp_path):
    root = str(tmp_path / "ws")
    spec = _spec(root)
    _mkdirs(root, spec)
    fake_container = MagicMock(name="Container", id="cid-1234abcd", short_id="cid-1234")
    mock_docker_client.containers.run.return_value = fake_container

    rt = _make_runtime(mock_docker_client)
    handle = asyncio.run(rt.provision(spec))

    assert handle.workspace_id == spec.workspace_id
    assert handle.runtime_id == "cid-1234abcd"

    kwargs = mock_docker_client.containers.run.call_args.kwargs
    assert kwargs["detach"] is True
    assert kwargs["init"] is True
    assert kwargs["remove"] is False
    assert kwargs["tty"] is True
    assert kwargs["command"] == ["sleep", "infinity"]
    labels = kwargs["labels"]
    assert labels["warren.workspace_id"] == spec.workspace_id
    assert labels["warren.server_instance"] == "test-server"
    assert labels["warren.project"] == "demo-project"
    assert labels["warren.intent"] == "claude"

    state_path = Path(root) / "state.json"
    assert state_path.exists()
    state = json.loads(state_path.read_text())
    assert state["schema_version"] == 1
    assert state["container_id"] == "cid-1234abcd"
    assert state["workspace_id"] == spec.workspace_id


def test_provision_injects_warren_project_and_template(mock_docker_client, tmp_path):
    """UX-1: the baked-in .zshrc's shared banner/prompt snippet
    (warren_common/assets/warren_banner.zsh) reads these at shell-start time
    -- never set for Docker workspaces before this."""
    root = str(tmp_path / "ws")
    spec = _spec(root)
    _mkdirs(root, spec)
    fake_container = MagicMock(name="Container", id="cid-1234abcd", short_id="cid-1234")
    mock_docker_client.containers.run.return_value = fake_container

    rt = _make_runtime(mock_docker_client)
    asyncio.run(rt.provision(spec))

    env = mock_docker_client.containers.run.call_args.kwargs["environment"]
    assert env["WARREN_PROJECT"] == "demo-project"
    assert env["WARREN_TEMPLATE"] == "claude"


def test_provision_mints_sidecar_token(mock_docker_client, tmp_path):
    """Audit finding 12: a fresh token in the container env only -- not on the
    handle, not in state.json, never a same-named secret's value."""
    root = str(tmp_path / "ws")
    spec = _spec(root)
    spec.env["WARREN_SIDECAR_TOKEN"] = "attacker-chosen"
    _mkdirs(root, spec)
    mock_docker_client.containers.run.return_value = MagicMock(id="cid-1234abcd")

    handle = asyncio.run(_make_runtime(mock_docker_client).provision(spec))

    token = mock_docker_client.containers.run.call_args.kwargs["environment"]["WARREN_SIDECAR_TOKEN"]
    assert token != "attacker-chosen" and len(token) >= 32
    assert token not in repr(vars(handle))
    assert token not in (Path(root) / "state.json").read_text()


def test_provision_uses_mount_objects(mock_docker_client, tmp_path):
    from docker.types import Mount

    root = str(tmp_path / "ws")
    spec = _spec(root)
    _mkdirs(root, spec)
    fake_container = MagicMock(id="cid-abc")
    mock_docker_client.containers.run.return_value = fake_container

    rt = _make_runtime(mock_docker_client)
    asyncio.run(rt.provision(spec))

    mounts = mock_docker_client.containers.run.call_args.kwargs["mounts"]
    assert isinstance(mounts, list)
    assert len(mounts) >= 2
    for m in mounts:
        assert isinstance(m, Mount)
    # no legacy volumes=... dict
    assert "volumes" not in mock_docker_client.containers.run.call_args.kwargs


def test_network_attach_calls_connect(mock_docker_client, tmp_path):
    root = str(tmp_path / "ws")
    spec = _spec(root, docker_networks=["mynet"])
    _mkdirs(root, spec)
    container = MagicMock(id="cid-net")
    net = MagicMock(name="mynet-network")
    mock_docker_client.containers.run.return_value = container
    mock_docker_client.networks.get.return_value = net

    rt = _make_runtime(mock_docker_client)
    asyncio.run(rt.provision(spec))

    mock_docker_client.networks.get.assert_called_with("mynet")
    net.connect.assert_called_once_with(container)


def test_warren_default_network_created_on_notfound(mock_docker_client, tmp_path):
    import docker.errors

    root = str(tmp_path / "ws")
    spec = _spec(root, docker_networks=["warren_default"])
    _mkdirs(root, spec)
    container = MagicMock(id="cid-def")
    created_net = MagicMock(name="warren_default")

    mock_docker_client.containers.run.return_value = container
    mock_docker_client.networks.get.side_effect = docker.errors.NotFound("no such network")
    mock_docker_client.networks.create.return_value = created_net

    rt = _make_runtime(mock_docker_client)
    asyncio.run(rt.provision(spec))

    mock_docker_client.networks.create.assert_called_once_with(
        "warren_default", driver="bridge"
    )
    created_net.connect.assert_called_once_with(container)


def test_provision_joins_isolated_network_not_default_bridge(mock_docker_client, tmp_path):
    """Finding 9: never the default `bridge` (ICC on), always the ICC-off network."""
    root = str(tmp_path / "ws")
    spec = _spec(root)
    _mkdirs(root, spec)
    mock_docker_client.containers.run.return_value = MagicMock(id="cid-iso")

    rt = _make_runtime(mock_docker_client)
    asyncio.run(rt.provision(spec))

    assert mock_docker_client.containers.run.call_args.kwargs["network"] == "warren-isolated"


def test_isolated_network_created_with_icc_disabled(mock_docker_client):
    import docker.errors

    mock_docker_client.networks.get.side_effect = docker.errors.NotFound("no such network")
    created = MagicMock()
    mock_docker_client.networks.create.return_value = created

    assert asyncio.run(_real_ensure_isolated_network(mock_docker_client)) is created
    mock_docker_client.networks.create.assert_called_once_with(
        "warren-isolated",
        driver="bridge",
        options={"com.docker.network.bridge.enable_icc": "false"},
        labels={"warren.network": "isolated"},
    )


def test_isolated_network_reused_when_icc_disabled(mock_docker_client):
    net = MagicMock(attrs={"Options": {"com.docker.network.bridge.enable_icc": "false"}})
    mock_docker_client.networks.get.return_value = net

    assert asyncio.run(_real_ensure_isolated_network(mock_docker_client)) is net
    mock_docker_client.networks.create.assert_not_called()


@pytest.mark.parametrize("options", [{}, {"com.docker.network.bridge.enable_icc": "true"}])
def test_isolated_network_with_icc_enabled_fails_closed(mock_docker_client, options):
    from warren_common.errors import ProvisionError

    mock_docker_client.networks.get.return_value = MagicMock(attrs={"Options": options})

    with pytest.raises(ProvisionError, match="enable_icc"):
        asyncio.run(_real_ensure_isolated_network(mock_docker_client))


def test_isolated_network_create_race_rereads(mock_docker_client):
    import docker.errors

    winner = MagicMock(attrs={"Options": {"com.docker.network.bridge.enable_icc": "false"}})
    mock_docker_client.networks.get.side_effect = [docker.errors.NotFound("missing"), winner]
    conflict = docker.errors.APIError("409 Conflict")
    conflict.response = MagicMock(status_code=409)
    mock_docker_client.networks.create.side_effect = conflict

    assert asyncio.run(_real_ensure_isolated_network(mock_docker_client)) is winner


def test_status_reloads_before_read(mock_docker_client, tmp_path):
    root = str(tmp_path / "ws")
    spec = _spec(root)
    _mkdirs(root, spec)
    container = MagicMock(id="cid-status")
    container.status = "running"
    mock_docker_client.containers.run.return_value = container
    mock_docker_client.containers.get.return_value = container

    rt = _make_runtime(mock_docker_client)
    handle = asyncio.run(rt.provision(spec))

    container.reload.reset_mock()
    result = asyncio.run(rt.status(handle))
    assert result == "running"
    container.reload.assert_called_once()

    container.status = "exited"
    assert asyncio.run(rt.status(handle)) == "stopped"

    container.status = "created"
    assert asyncio.run(rt.status(handle)) == "unknown"


def test_destroy_stops_then_removes(mock_docker_client, tmp_path):
    root = str(tmp_path / "ws")
    spec = _spec(root)
    _mkdirs(root, spec)
    container = MagicMock(id="cid-destroy")
    mock_docker_client.containers.run.return_value = container
    mock_docker_client.containers.get.return_value = container

    rt = _make_runtime(mock_docker_client)
    handle = asyncio.run(rt.provision(spec))
    asyncio.run(rt.destroy(handle))

    container.stop.assert_called_once_with(timeout=5)
    container.remove.assert_called_once_with(force=True)
    # order: stop before remove
    stop_call = next(
        i for i, c in enumerate(container.mock_calls) if c[0] == "stop"
    )
    remove_call = next(
        i for i, c in enumerate(container.mock_calls) if c[0] == "remove"
    )
    assert stop_call < remove_call


def test_connect_execvp_shape():
    """Placeholder — connect handoff lives in dispatch plan 05b-05."""
    pytest.skip("connect handoff is implemented in dispatch plan 05b-05")


def test_windows_client_uses_detected_pipe(monkeypatch):
    import docker

    import warren_common.winsupport as ws
    from warren_common.runtime.docker import DockerRuntime

    seen = {}
    monkeypatch.setattr(ws.sys, "platform", "win32")
    monkeypatch.setattr(ws.os, "listdir", lambda p: ["podman-machine-default"])
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    monkeypatch.setattr(docker, "DockerClient", lambda base_url: seen.setdefault("url", base_url))
    monkeypatch.setattr(docker, "from_env", lambda: pytest.fail("from_env used"))
    DockerRuntime(server_id="s")._ensure_client()
    assert seen["url"] == "npipe:////./pipe/podman-machine-default"


def test_docker_host_env_wins_on_windows(monkeypatch):
    import docker

    import warren_common.winsupport as ws
    from warren_common.runtime.docker import DockerRuntime

    monkeypatch.setattr(ws.sys, "platform", "win32")
    monkeypatch.setattr(ws.os, "listdir", lambda p: ["docker_engine"])
    monkeypatch.setenv("DOCKER_HOST", "tcp://127.0.0.1:2375")
    sentinel = object()
    monkeypatch.setattr(docker, "from_env", lambda: sentinel)
    assert DockerRuntime(server_id="s")._ensure_client() is sentinel
