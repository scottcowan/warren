"""Shared pytest fixtures for `tests/integration/` live-Podman tests.

IMPORTANT (RESEARCH.md Pitfall 5): `PODMAN_SOCKET` (the env var already used by
`tests/conftest.py::pytest_collection_modifyitems` to gate `requires_podman` tests)
must always be a **bare filesystem path** (e.g. `/run/user/1000/podman/podman.sock`),
never a `unix://`-prefixed URL. `PodmanClient(base_url=...)` is the only place that
should prepend the `unix://` scheme. Do not store an already-prefixed value in
`WARREN_PODMAN_SOCKET` or you will end up with a `unix://unix://...` double-scheme
bug when `PodmanRuntime` builds its own client.
"""

from __future__ import annotations

import os
import uuid
from pathlib import Path
from typing import Iterator

import pytest
import structlog

log = structlog.get_logger(__name__)

_LONG_RUNNING_IMAGE_TAG = "localhost/warren-itest-longrunning:latest"
_SSH_TEST_IMAGE_TAG = "localhost/warren-itest-ssh:latest"

# Per-test pytest-timeout budget for live-Podman tests (overrides the 60s unit default
# in pyproject.toml). Includes fixture setup, so it must cover the session-scoped SSH
# fixture image build (apt-get install on a Debian base; CI pre-pulls the base image)
# on the first test that requests it. A hang -- podman API call, ssh, lifespan
# shutdown -- then fails that one test with a traceback instead of the whole job
# being killed by the workflow's wall-clock `timeout` with exit 124.
_INTEGRATION_TEST_TIMEOUT_S = 240


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    here = Path(__file__).parent
    for item in items:
        if here in item.path.parents and item.get_closest_marker("timeout") is None:
            item.add_marker(pytest.mark.timeout(_INTEGRATION_TEST_TIMEOUT_S))


@pytest.fixture(autouse=True)
def _host_podman_paths(monkeypatch, host_podman_env):
    """Live-podman tests: HOME stays a throwaway dir (tests/conftest.py), but the
    podman CLI must see the same rootless config/storage as the API socket, or
    e.g. the `warren-egress` network it creates lands in a store the socket
    can't find."""
    for key, value in host_podman_env.items():
        monkeypatch.setenv(key, value)


@pytest.fixture
def itest_server_id() -> str:
    """Return a fresh, unique server_id computed exactly once for this test.

    Must NOT be regenerated across multiple `lifespan()` entries within the same
    test function (RESEARCH.md Pitfall 1) — callers should capture the returned
    value once and reuse it, which this fixture's function scope guarantees.
    """
    return f"itest-{uuid.uuid4().hex[:12]}"


@pytest.fixture(scope="session")
def itest_long_running_image(tmp_path_factory: pytest.TempPathFactory) -> Iterator[str]:
    """Build (once per session) a long-running local test image.

    Skips immediately if `PODMAN_SOCKET` is unset, mirroring the repo-root skip
    gate so this fixture never errors on hosts without Podman.
    """
    socket_path = os.environ.get("PODMAN_SOCKET")
    if not socket_path:
        pytest.skip("PODMAN_SOCKET not set")

    from podman import PodmanClient

    build_dir = tmp_path_factory.mktemp("itest-image")
    containerfile = build_dir / "Containerfile"
    containerfile.write_text(
        'FROM docker.io/library/busybox:latest\nCMD ["sleep", "infinity"]\n'
    )

    client = PodmanClient(base_url=f"unix://{socket_path}", timeout=30)
    try:
        # `timeout` bounds the streamed build response's HTTP call. Without it,
        # a stalled/never-closing build stream (e.g. a podman-py/podman-server
        # API version mismatch) hangs this call indefinitely rather than
        # failing with an actionable error.
        client.images.build(
            path=str(build_dir),
            dockerfile="Containerfile",
            tag=_LONG_RUNNING_IMAGE_TAG,
            rm=True,
            timeout=120,
        )
        yield _LONG_RUNNING_IMAGE_TAG
    finally:
        client.close()


@pytest.fixture(scope="session")
def itest_workspace_docker_image() -> Iterator[str]:
    """Build (once per session) the SSH test fixture image.

    This is a test-only fixture (tests/integration/fixtures/ssh_test_image/), not the
    production reference image — the ACP-over-SSH ForceCommand pattern was extracted to
    github.com/scottcowan/agent-poc (standalone, no warren dependency). This fixture
    stays self-contained (no external repo dependency during test setup) and keeps the
    exact usernames warren-server's production code hardcodes
    (_SSH_LOGIN_USER="warren", _SSH_BREAK_GLASS_USER="warren-shell" in
    routes/workspaces.py), which agent-poc's generic agent/agent-shell naming wouldn't
    match.

    Skips immediately if `PODMAN_SOCKET` is unset, mirroring the repo-root skip
    gate so this fixture never errors on hosts without Podman.
    """
    socket_path = os.environ.get("PODMAN_SOCKET")
    if not socket_path:
        pytest.skip("PODMAN_SOCKET not set")

    from podman import PodmanClient

    build_dir = Path(__file__).parent / "fixtures" / "ssh_test_image"

    client = PodmanClient(base_url=f"unix://{socket_path}", timeout=30)
    try:
        # 300s, not the busybox fixture's 120s: this build pulls a full Debian
        # base image and runs `apt-get update && apt-get install`, which is
        # slower than the single-layer busybox pull the other fixture uses.
        client.images.build(
            path=str(build_dir),
            dockerfile="Containerfile",
            tag=_SSH_TEST_IMAGE_TAG,
            rm=True,
            timeout=300,
        )
        yield _SSH_TEST_IMAGE_TAG
    finally:
        client.close()


@pytest.fixture
def itest_env(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    itest_server_id: str,
    itest_long_running_image: str,
) -> Iterator[dict[str, object]]:
    """Set up WARREN_* env vars for one test and guarantee container cleanup.

    Sets `WARREN_DATA_DIR` once per test (not per `lifespan()` entry) so multiple
    `lifespan()` invocations within the same test share the same SQLite file.

    On teardown, force-destroys every container labelled
    `warren.server_instance=<this fixture's server_id>` regardless of test
    outcome (RESEARCH.md Pitfall 4). Cleanup never raises past the fixture
    boundary; it is constructed independently of `PodmanRuntime` so cleanup
    stays valid even if the runtime under test is broken.
    """
    socket_path = os.environ["PODMAN_SOCKET"]

    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_BOOTSTRAP_TOKEN", "itest-bootstrap-token00000000000")
    monkeypatch.setenv("WARREN_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("WARREN_PODMAN_SOCKET", socket_path)  # bare path — Pitfall 5
    monkeypatch.setenv("WARREN_SERVER_ID", itest_server_id)

    try:
        yield {
            "server_id": itest_server_id,
            "image": itest_long_running_image,
            "data_dir": tmp_path,
        }
    finally:
        from podman import PodmanClient
        from podman.errors import NotFound

        client = PodmanClient(base_url=f"unix://{socket_path}", timeout=30)
        try:
            # Filter client-side, not via the API's filters={"label": ...} query —
            # confirmed (Phase 1, 01-03) that server-side label filters can
            # silently return zero matches on some Podman API versions even
            # against genuinely matching containers.
            all_containers = client.containers.list(all=True)
            containers = [
                c
                for c in all_containers
                if c.labels.get("warren.server_instance") == itest_server_id
            ]
            for container in containers:
                try:
                    container.remove(force=True)
                except NotFound:
                    pass
                except Exception:
                    log.warning(
                        "itest_env teardown: failed to remove container",
                        container_id=getattr(container, "id", None),
                        server_id=itest_server_id,
                    )
        except Exception:
            log.warning(
                "itest_env teardown: failed to list containers for cleanup",
                server_id=itest_server_id,
            )
        finally:
            client.close()
