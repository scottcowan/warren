from __future__ import annotations

import asyncio
import os as _os
import tempfile as _tempfile

import pytest as _pytest

# No test may reach the operator's real HOME (~/.claude, ~/.aws, ...): a
# throwaway HOME is set before any test module (and any import-time
# Path.home()) loads, and each test then gets its own.
#
# Rootless `podman` CLI calls (e.g. egress.read_container_egress_bytes) locate their
# config and storage via XDG_CONFIG_HOME/XDG_DATA_HOME, falling back to $HOME.
# Pin those to the runner's real locations before HOME moves, so live-podman
# integration tests share the store the podman API socket uses (see
# tests/integration/conftest.py::_host_podman_paths). Only these two podman
# dirs are exposed, never HOME itself.
_REAL_HOME = _os.environ.get("HOME", "")
HOST_PODMAN_ENV = {
    "XDG_CONFIG_HOME": _os.environ.get("XDG_CONFIG_HOME") or _os.path.join(_REAL_HOME, ".config"),
    "XDG_DATA_HOME": _os.environ.get("XDG_DATA_HOME") or _os.path.join(_REAL_HOME, ".local", "share"),
}
_os.environ["HOME"] = _tempfile.mkdtemp(prefix="warren-test-home-")
# Windows resolves Path.home()/expanduser("~") from USERPROFILE, not HOME.
_os.environ["USERPROFILE"] = _os.environ["HOME"]
_HOST_ENV = ("REAL_HOME", "AWS_PROFILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE")
for _var in _HOST_ENV:
    _os.environ.pop(_var, None)


@_pytest.fixture(autouse=True)
def _isolated_home(tmp_path_factory, monkeypatch):
    # Outside tmp_path, so a test that mounts its tmp_path never contains HOME.
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    for var in _HOST_ENV:
        monkeypatch.delenv(var, raising=False)


@_pytest.fixture
def host_podman_env() -> dict[str, str]:
    return dict(HOST_PODMAN_ENV)


@_pytest.fixture(autouse=True)
def _no_real_exec(monkeypatch):
    """A test that forgets to fake exec must fail, not replace pytest."""

    def _refuse(*_a, **_kw):
        raise RuntimeError("unexpected real exec in a test")

    for name in ("execv", "execve", "execvp", "execvpe"):
        monkeypatch.setattr(_os, name, _refuse)


import os
import tempfile
from pathlib import Path
from typing import Iterator

import pytest

# aiosqlite.core.Connection spawns a non-daemon worker thread
# (Thread(target=_connection_worker_thread, ...), no daemon=True) that only
# stops when .close() sends it a sentinel. Any test that opens a connection
# (directly or via registry/store helpers) without closing it in teardown
# leaves that thread running forever, which blocks the whole pytest process
# from exiting — it doesn't fail, it just hangs until something external
# (CI's `timeout 300`, or a human killing it) kills the process. This has
# been silently true since warren-server's test suite was created; CI has
# never actually passed because of it (every run hits the 300s kill, not a
# real assertion failure). Patching daemon=True here is a safety net, not a
# substitute for closing connections properly — it just stops one leaked
# connection from hanging the entire suite.
import aiosqlite.core  # noqa: E402

_original_connection_init = aiosqlite.core.Connection.__init__

# BB11: connections opened during the current test, closed by the autouse
# _close_leaked_aiosqlite_connections fixture below. A connection left for the
# garbage collector instead stops its worker thread against whatever event loop
# is current by then (usually an already-closed one), which surfaced as ~110
# "Event loop is closed" thread-exception warnings; those are now errors
# (pyproject filterwarnings), so a leak the fixture can't reach still fails.
_test_connections: list | None = None


def _daemon_connection_init(self, *args, **kwargs):  # type: ignore[no-untyped-def]
    _original_connection_init(self, *args, **kwargs)
    self._thread.daemon = True
    if _test_connections is not None:
        _test_connections.append(self)


aiosqlite.core.Connection.__init__ = _daemon_connection_init


@pytest.fixture(autouse=True)
def _close_leaked_aiosqlite_connections() -> Iterator[None]:
    global _test_connections
    _test_connections = opened = []
    try:
        yield
    finally:
        _test_connections = None
        leaked = [c for c in opened if c._connection is not None]
        if leaked:

            async def _close_all() -> None:
                await asyncio.gather(*(c.close() for c in leaked))

            loop = asyncio.new_event_loop()
            try:
                loop.run_until_complete(_close_all())
            finally:
                loop.close()
        for c in opened:
            c._thread.join(timeout=5)

@pytest.fixture(autouse=True)
def _fresh_middleware_stack() -> Iterator[None]:
    """The shared `warren.app.app` builds its middleware stack once, so AuthMiddleware's
    per-IP failed-auth limiter (20/min) would otherwise carry 401s across tests."""
    yield
    import sys

    module = sys.modules.get("warren.app")
    if module is not None:
        module.app.middleware_stack = None


TEST_BOOTSTRAP_TOKEN ="test-bootstrap-token000000000000"
"""Shared bootstrap token used by route-test env_defaults fixtures (see auth_headers below).

The bootstrap admin lifespan step mints exactly this value as its token when
WARREN_BOOTSTRAP_TOKEN is set to it, so tests authenticate through the real resolve_token path."""


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip tests marked requires_podman unless PODMAN_SOCKET is set."""
    if os.environ.get("PODMAN_SOCKET"):
        return
    skip_marker = pytest.mark.skip(reason="PODMAN_SOCKET not set; skipping live-podman integration test")
    for item in items:
        if "requires_podman" in item.keywords:
            item.add_marker(skip_marker)


@pytest.fixture
def sqlite_path() -> Iterator[str]:
    """Yield a fresh temp SQLite path; unlink on teardown (Pitfall #13)."""
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    try:
        yield tmp.name
    finally:
        try:
            Path(tmp.name).unlink()
        except FileNotFoundError:
            pass


@pytest.fixture
def fake_runtime():
    """Return a fresh FakeRuntime bound to a deterministic server_id."""
    from warren_common.runtime.fake import FakeRuntime

    return FakeRuntime(server_id="test-server")


@pytest.fixture
def auth_headers() -> dict[str, str]:
    """Default Authorization header carrying the shared bootstrap-minted test token.

    Pass as TestClient(app, headers=auth_headers) so every request the client issues
    authenticates via the real resolve_token path once AuthMiddleware is wired in."""
    return {"Authorization": f"Bearer {TEST_BOOTSTRAP_TOKEN}"}


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
