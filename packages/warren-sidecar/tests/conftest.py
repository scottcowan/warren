"""Shared fixtures for warren-sidecar tests."""

from __future__ import annotations

import os as _os
import tempfile as _tempfile

import pytest as _pytest

# No test may reach the operator's real HOME (~/.claude, ~/.aws, ...): a
# throwaway HOME is set before any test module (and any import-time
# Path.home()) loads, and each test then gets its own.
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


@_pytest.fixture(autouse=True)
def _no_real_exec(monkeypatch):
    """A test that forgets to fake exec must fail, not replace pytest."""

    def _refuse(*_a, **_kw):
        raise RuntimeError("unexpected real exec in a test")

    for name in ("execv", "execve", "execvp", "execvpe"):
        monkeypatch.setattr(_os, name, _refuse)


import os

import pytest


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    """Skip tests marked requires_podman unless PODMAN_SOCKET is set."""
    if os.environ.get("PODMAN_SOCKET"):
        return
    skip_marker = pytest.mark.skip(
        reason="PODMAN_SOCKET not set; skipping live-podman integration test"
    )
    for item in items:
        if "requires_podman" in item.keywords:
            item.add_marker(skip_marker)


TEST_SIDECAR_TOKEN = "test-sidecar-token"


@pytest.fixture
def env_defaults(monkeypatch, tmp_path):
    """Monkeypatch env vars required by warren-sidecar; clear app state on teardown."""
    monkeypatch.setenv("WARREN_WORKSPACE_ID", "ws-test")
    monkeypatch.setenv("WARREN_APP", "bash")
    monkeypatch.setenv("WARREN_SOCKET_PATH", str(tmp_path / "test.sock"))
    monkeypatch.setenv("WARREN_SIDECAR_TOKEN", TEST_SIDECAR_TOKEN)
    yield
    from warren_sidecar.app import app

    app.state._state.clear()


@pytest.fixture
def auth_headers() -> dict[str, str]:
    """Header set every authenticated /files or /exec request must send."""
    return {"X-Warren-Sidecar-Token": TEST_SIDECAR_TOKEN}


@pytest.fixture(autouse=True)
def _fast_supervisor_session_wait(monkeypatch):
    """Keep WorkspaceAppSupervisor's tmux-session wait from slowing the suite.

    No test environment has a real "main" tmux session, so every TestClient(app)
    test would otherwise pay the full production retry budget during lifespan
    startup. Tests that exercise the wait/retry logic itself override these
    again locally.
    """
    import warren_sidecar.supervisor as supervisor_mod

    monkeypatch.setattr(supervisor_mod, "_SESSION_WAIT_RETRIES", 1)
    monkeypatch.setattr(supervisor_mod, "_SESSION_WAIT_DELAY_S", 0.0)
