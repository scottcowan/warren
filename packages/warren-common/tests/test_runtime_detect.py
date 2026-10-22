"""RuntimeDetector platform branches (Plan 05b-02).

Verifies D-01 recommendation priority and D-04 import-cheap constraint.
"""

from __future__ import annotations

import subprocess
import sys

import pytest


@pytest.fixture(autouse=True)
def _not_wsl(monkeypatch):
    """Platform-branch tests must not depend on the host's real /proc (AC2)."""
    import warren_common.runtime_detect as rd

    monkeypatch.setattr(rd.wsl, "wsl_version", lambda: None)
    monkeypatch.setattr(rd.wsl, "apparmor_restricts_userns", lambda: False)


def test_macos_recommends_seatbelt(monkeypatch):
    import warren_common.runtime_detect as rd

    monkeypatch.setattr(rd.sys, "platform", "darwin")
    monkeypatch.setattr(rd.os.path, "isfile", lambda p: p == "/usr/bin/sandbox-exec")
    monkeypatch.setattr(rd.shutil, "which", lambda _: None)
    monkeypatch.setattr(rd, "_docker_socket_reachable", lambda: False)
    monkeypatch.delenv("WARREN_NSJAIL_PATH", raising=False)

    result = rd.detect()
    assert result.seatbelt is True
    assert result.recommended == "seatbelt"


def test_linux_prefers_bwrap_over_nsjail(monkeypatch):
    import warren_common.runtime_detect as rd

    monkeypatch.setattr(rd.sys, "platform", "linux")
    monkeypatch.setattr(rd.os.path, "isfile", lambda p: False)
    monkeypatch.setattr(
        rd.shutil, "which", lambda name: "/usr/bin/" + name if name in {"bwrap", "nsjail"} else None
    )
    monkeypatch.setattr(rd, "_docker_socket_reachable", lambda: False)
    monkeypatch.delenv("WARREN_NSJAIL_PATH", raising=False)

    result = rd.detect()
    assert result.bwrap is True
    assert result.nsjail is True
    assert result.recommended == "bubblewrap"


def test_linux_falls_back_to_nsjail_when_no_bwrap(monkeypatch):
    import warren_common.runtime_detect as rd

    monkeypatch.setattr(rd.sys, "platform", "linux")
    monkeypatch.setattr(rd.os.path, "isfile", lambda p: False)
    monkeypatch.setattr(
        rd.shutil, "which", lambda name: "/usr/bin/nsjail" if name == "nsjail" else None
    )
    monkeypatch.setattr(rd, "_docker_socket_reachable", lambda: False)
    monkeypatch.delenv("WARREN_NSJAIL_PATH", raising=False)

    result = rd.detect()
    assert result.bwrap is False
    assert result.nsjail is True
    assert result.recommended == "nsjail"


def test_docker_fallback_when_no_native(monkeypatch):
    import warren_common.runtime_detect as rd

    monkeypatch.setattr(rd.sys, "platform", "linux")
    monkeypatch.setattr(rd.os.path, "isfile", lambda p: False)
    monkeypatch.setattr(rd.shutil, "which", lambda _: None)
    monkeypatch.setattr(rd, "_docker_socket_reachable", lambda: True)
    monkeypatch.delenv("WARREN_NSJAIL_PATH", raising=False)

    result = rd.detect()
    assert result.docker is True
    assert result.recommended == "docker"


def test_none_when_nothing_available(monkeypatch):
    import warren_common.runtime_detect as rd

    monkeypatch.setattr(rd.sys, "platform", "linux")
    monkeypatch.setattr(rd.os.path, "isfile", lambda p: False)
    monkeypatch.setattr(rd.shutil, "which", lambda _: None)
    monkeypatch.setattr(rd, "_docker_socket_reachable", lambda: False)
    monkeypatch.delenv("WARREN_NSJAIL_PATH", raising=False)

    result = rd.detect()
    assert result.recommended == "none"


@pytest.mark.skipif(sys.platform == "win32", reason="AF_UNIX docker socket probe is POSIX-only")
def test_docker_socket_check_uses_short_timeout(monkeypatch):
    import warren_common.runtime_detect as rd

    monkeypatch.setattr(rd.os.path, "exists", lambda p: True)

    captured = {}

    class _FakeSock:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def settimeout(self, t):
            captured["timeout"] = t

        def connect(self, path):
            captured["path"] = path

    monkeypatch.setattr(rd.socket, "socket", lambda *a, **kw: _FakeSock())
    assert rd._docker_socket_reachable() is True
    assert captured["timeout"] == 0.2
    assert captured["path"] == "/var/run/docker.sock"


def test_no_docker_import_at_module_level():
    # Fresh subprocess so we get a clean import environment.
    code = (
        "import sys; import warren_common.runtime_detect; "
        "assert 'docker' not in sys.modules, sorted(k for k in sys.modules if 'docker' in k)"
    )
    subprocess.run([sys.executable, "-c", code], check=True)


def test_nsjail_env_var_honored(monkeypatch, tmp_path):
    import warren_common.runtime_detect as rd

    exe = tmp_path / "my-nsjail"
    exe.write_text("#!/bin/sh\n")
    exe.chmod(0o755)

    monkeypatch.setattr(rd.sys, "platform", "linux")
    monkeypatch.setattr(rd.os.path, "isfile", lambda p: False)
    monkeypatch.setattr(rd.shutil, "which", lambda _: None)
    monkeypatch.setattr(rd, "_docker_socket_reachable", lambda: False)
    monkeypatch.setenv("WARREN_NSJAIL_PATH", str(exe))

    result = rd.detect()
    assert result.nsjail is True
    assert result.recommended == "nsjail"


def _windows(monkeypatch, pipes):
    import warren_common.runtime_detect as rd
    import warren_common.winsupport as ws

    monkeypatch.setattr(rd.sys, "platform", "win32")
    monkeypatch.setattr(ws.sys, "platform", "win32")
    monkeypatch.setattr(rd.shutil, "which", lambda _: None)
    monkeypatch.setattr(ws.os, "listdir", lambda p: list(pipes) if p == ws.PIPE_PREFIX else [])
    monkeypatch.setattr(ws, "windows_build", lambda: "26100.9278")
    monkeypatch.setattr(ws, "probe_mxc", lambda: ws.MxcProbe(False, "unknown", "not probed"))
    monkeypatch.delenv("WARREN_NSJAIL_PATH", raising=False)
    return rd


def test_windows_docker_desktop_pipe_detected(monkeypatch):
    rd = _windows(monkeypatch, ["docker_engine", "other"])
    result = rd.detect()
    assert result.docker is True
    assert result.docker_host == "npipe:////./pipe/docker_engine"
    assert result.recommended == "docker"
    assert result.note == ""


def test_windows_podman_machine_pipe_detected(monkeypatch):
    rd = _windows(monkeypatch, ["podman-machine-default"])
    result = rd.detect()
    assert result.docker is True
    assert result.docker_host == "npipe:////./pipe/podman-machine-default"


def test_windows_without_sandbox_points_at_wsl2(monkeypatch):
    rd = _windows(monkeypatch, [])
    result = rd.detect()
    assert result.recommended == "none"
    assert "WSL2" in result.note
    assert not (result.seatbelt or result.bwrap or result.nsjail or result.docker)


def test_windows_pipe_listing_error_is_not_fatal(monkeypatch):
    import warren_common.winsupport as ws

    def _boom(_):
        raise OSError("no pipe fs")

    monkeypatch.setattr(ws.os, "listdir", _boom)
    assert ws.pipe_exists("docker_engine") is False


def test_non_windows_has_no_note(monkeypatch):
    import warren_common.runtime_detect as rd

    monkeypatch.setattr(rd.sys, "platform", "linux")
    monkeypatch.setattr(rd.os.path, "isfile", lambda p: False)
    monkeypatch.setattr(rd.shutil, "which", lambda _: None)
    monkeypatch.setattr(rd, "_docker_socket_reachable", lambda: False)
    monkeypatch.delenv("WARREN_NSJAIL_PATH", raising=False)
    assert rd.detect().note == ""


@pytest.mark.skipif(sys.platform == "win32", reason="creates a symlink; Linux binary resolution")
def test_detect_records_resolved_absolute_linux_binaries(monkeypatch, tmp_path):
    """AE2: detection resolves bwrap/nsjail to absolute, symlink-free paths."""
    import warren_common.runtime_detect as rd

    real = tmp_path / "real-bwrap"
    real.write_text("")
    link = tmp_path / "bwrap"
    link.symlink_to(real)
    monkeypatch.setattr(rd.sys, "platform", "linux")
    monkeypatch.setattr(rd.shutil, "which", lambda name: str(link) if name == "bwrap" else None)
    monkeypatch.setattr(rd, "_docker_socket_reachable", lambda: False)
    monkeypatch.delenv("WARREN_NSJAIL_PATH", raising=False)

    result = rd.detect()
    assert result.bwrap_path == str(real.resolve())
    assert result.recommended == "bubblewrap"


# --- AC2: WSL ---------------------------------------------------------------


def _linux_with_bwrap(monkeypatch, rd):
    monkeypatch.setattr(rd.sys, "platform", "linux")
    monkeypatch.setattr(rd.os.path, "isfile", lambda p: False)
    monkeypatch.setattr(
        rd.shutil, "which", lambda name: "/usr/bin/" + name if name in {"bwrap", "nsjail"} else None
    )
    monkeypatch.setattr(rd, "_docker_socket_reachable", lambda: False)
    monkeypatch.delenv("WARREN_NSJAIL_PATH", raising=False)


def test_wsl2_recommends_bubblewrap(monkeypatch):
    import warren_common.runtime_detect as rd

    _linux_with_bwrap(monkeypatch, rd)
    monkeypatch.setattr(rd.wsl, "wsl_version", lambda: 2)
    result = rd.detect()
    assert result.wsl_version == 2
    assert result.recommended == "bubblewrap"
    assert result.note == ""


def test_wsl2_without_bwrap_says_install_it(monkeypatch):
    import warren_common.runtime_detect as rd

    _linux_with_bwrap(monkeypatch, rd)
    monkeypatch.setattr(rd.shutil, "which", lambda _: None)
    monkeypatch.setattr(rd.os, "access", lambda *_a: False)
    monkeypatch.setattr(rd.wsl, "wsl_version", lambda: 2)
    result = rd.detect()
    assert result.recommended == "none"
    assert result.note == rd.wsl.WSL2_NO_BWRAP_NOTE


def test_wsl1_never_offers_namespace_sandboxes(monkeypatch):
    import warren_common.runtime_detect as rd

    _linux_with_bwrap(monkeypatch, rd)
    monkeypatch.setattr(rd.wsl, "wsl_version", lambda: 1)
    result = rd.detect()
    assert result.bwrap is False and result.nsjail is False
    assert result.recommended == "none"
    assert "WSL1" in result.note and "wsl --set-version" in result.note


def test_wsl1_falls_back_to_docker(monkeypatch):
    import warren_common.runtime_detect as rd

    _linux_with_bwrap(monkeypatch, rd)
    monkeypatch.setattr(rd, "_docker_socket_reachable", lambda: True)
    monkeypatch.setattr(rd.wsl, "wsl_version", lambda: 1)
    assert rd.detect().recommended == "docker"


def test_apparmor_restriction_reported(monkeypatch):
    import warren_common.runtime_detect as rd

    _linux_with_bwrap(monkeypatch, rd)
    monkeypatch.setattr(rd.wsl, "apparmor_restricts_userns", lambda: True)
    assert rd.detect().apparmor_userns_restricted is True
