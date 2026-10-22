"""First real (non-collect-only) proof that the shared `itest_*` fixtures work
end-to-end against a live rootless-Podman socket.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.mark.requires_podman
def test_itest_env_produces_usable_values(itest_env: dict[str, object]) -> None:
    server_id = itest_env["server_id"]
    image = itest_env["image"]
    data_dir = itest_env["data_dir"]

    assert isinstance(server_id, str) and server_id.startswith("itest-")
    assert image == "localhost/warren-itest-longrunning:latest"
    assert isinstance(data_dir, Path) and data_dir.is_dir()
