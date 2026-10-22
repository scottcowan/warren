"""The live-podman tests' environment: throwaway HOME, host podman store paths."""

from __future__ import annotations

import os
from pathlib import Path


def test_podman_cli_uses_host_store_but_home_is_throwaway(host_podman_env):
    assert "pytest" in str(Path.home())
    for key, value in host_podman_env.items():
        assert os.environ[key] == value
        assert not value.startswith(str(Path.home()))
