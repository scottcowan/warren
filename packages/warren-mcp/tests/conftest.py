"""Shared fixtures for warren-mcp tests."""

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
