"""Shared fixtures for warren-common tests."""

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


@_pytest.fixture(autouse=True)
def _no_real_keychain(monkeypatch):
    """Never read the operator's login Keychain."""
    from warren_common import harness_config

    monkeypatch.setattr(harness_config, "_read_keychain", lambda *_a: None)


import os
from pathlib import Path

import pytest
import structlog
from structlog.testing import capture_logs


_SAMPLE_YAML_CLEAN = """\
name: demo-project
description: Test project
repo: git@github.com:example/demo-project.git
bare_path: /tmp/demo-project/.git-store
docker_image: ghcr.io/example/base:latest
mounts:
  - host: /tmp/demo-project/knowledge/refs
    container: /workspace/knowledge/refs
    mode: rw
templates:
  observe:
    description: Read-only browse
    app: bash
"""


_SAMPLE_YAML_WITH_UNKNOWN = """\
name: demo-project
description: Test project
repo: git@github.com:example/demo-project.git
bare_path: /tmp/demo-project/.git-store
docker_image: ghcr.io/example/base:latest
bogus_field: 1
templates:
  observe:
    description: Read-only browse
    app: bash
"""


@pytest.fixture
def tmp_projects_dir(tmp_path: Path) -> Path:
    d = tmp_path / "projects"
    d.mkdir(mode=0o700)
    return d


@pytest.fixture
def sample_project_yaml_text() -> str:
    return _SAMPLE_YAML_CLEAN


@pytest.fixture
def sample_project_yaml_unknown_field() -> str:
    return _SAMPLE_YAML_WITH_UNKNOWN


@pytest.fixture
def write_project_yaml(tmp_projects_dir: Path):
    def _write(name: str, text: str) -> Path:
        path = tmp_projects_dir / f"{name}.yaml"
        path.write_text(text)
        return path
    return _write


@pytest.fixture
def structlog_capture():
    with capture_logs() as logs:
        yield logs


posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX permissions only")
