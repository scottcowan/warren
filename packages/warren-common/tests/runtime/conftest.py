"""Shared fixtures for warren_common.runtime tests."""

from __future__ import annotations

import pytest


@pytest.fixture
def fake_runtime():
    """Return a fresh FakeRuntime bound to a deterministic server_id."""
    from warren_common.runtime.fake import FakeRuntime

    return FakeRuntime(server_id="test-server")


@pytest.fixture
def mock_docker_client():
    """MagicMock shaped like docker.DockerClient for DockerRuntime unit tests."""
    from unittest.mock import MagicMock

    client = MagicMock(name="DockerClient")
    client.containers = MagicMock(name="containers")
    client.containers.run = MagicMock(name="containers.run")
    client.containers.get = MagicMock(name="containers.get")
    client.networks = MagicMock(name="networks")
    client.networks.get = MagicMock(name="networks.get")
    client.networks.create = MagicMock(name="networks.create")
    return client
