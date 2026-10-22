"""AC1.3: owner-only files — chmod on POSIX, a protected owner-only DACL on Windows."""

from __future__ import annotations

import os
import stat
import subprocess
import sys
import types

import pytest

from warren_common import fileperms

posix_only = pytest.mark.skipif(os.name == "nt", reason="POSIX permissions only")
windows_only = pytest.mark.skipif(sys.platform != "win32", reason="real Windows ACLs only")

_SID = "S-1-5-21-1111-2222-3333-1001"


@posix_only
def test_posix_file_and_dir_modes(tmp_path):
    f = tmp_path / "token"
    f.write_text("x")
    f.chmod(0o644)
    d = tmp_path / "state"
    d.mkdir(mode=0o755)
    fileperms.restrict_to_owner(f)
    fileperms.restrict_to_owner(d)
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert stat.S_IMODE(d.stat().st_mode) == 0o700


def _force_windows(monkeypatch):
    monkeypatch.setattr(fileperms.winsupport.sys, "platform", "win32")
    monkeypatch.setattr(fileperms.os, "chmod", lambda *a: pytest.fail("chmod on Windows"))


def _no_pywin32(monkeypatch):
    for name in ("win32security", "win32api", "ntsecuritycon"):
        monkeypatch.setitem(sys.modules, name, None)


def test_windows_icacls_fallback_grants_only_current_user(monkeypatch, tmp_path):
    _force_windows(monkeypatch)
    _no_pywin32(monkeypatch)
    calls = []

    def _run(argv, **kw):
        calls.append(argv)
        if argv[0] == "whoami":
            return subprocess.CompletedProcess(argv, 0, stdout=f'"desk\\me","{_SID}"\r\n')
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(fileperms.subprocess, "run", _run)
    fileperms.restrict_to_owner(tmp_path / "config.toml", directory=False)
    fileperms.restrict_to_owner(tmp_path / "state", directory=True)

    target = str(tmp_path / "config.toml")
    assert calls[1] == ["icacls", target, "/reset"]
    assert calls[2] == ["icacls", target, "/inheritance:r", "/grant:r", f"*{_SID}:F"]
    assert calls[5][-1] == f"*{_SID}:(OI)(CI)F"


def test_windows_icacls_failure_raises(monkeypatch, tmp_path):
    _force_windows(monkeypatch)
    _no_pywin32(monkeypatch)

    def _run(argv, **kw):
        if argv[0] == "whoami":
            return subprocess.CompletedProcess(argv, 0, stdout=f'"desk\\me","{_SID}"')
        raise subprocess.CalledProcessError(5, argv)

    monkeypatch.setattr(fileperms.subprocess, "run", _run)
    with pytest.raises(subprocess.CalledProcessError):
        fileperms.restrict_to_owner(tmp_path / "f", directory=False)


def test_windows_unparseable_whoami_raises(monkeypatch, tmp_path):
    _force_windows(monkeypatch)
    _no_pywin32(monkeypatch)
    monkeypatch.setattr(
        fileperms.subprocess, "run",
        lambda argv, **kw: subprocess.CompletedProcess(argv, 0, stdout="garbage"),
    )
    with pytest.raises(OSError):
        fileperms.restrict_to_owner(tmp_path / "f", directory=False)


def test_windows_pywin32_sets_protected_single_ace_dacl(monkeypatch, tmp_path):
    _force_windows(monkeypatch)
    monkeypatch.setattr(fileperms.subprocess, "run", lambda *a, **k: pytest.fail("icacls used"))
    recorded: dict = {}

    class _ACL:
        def __init__(self):
            self.aces = []

        def AddAccessAllowedAceEx(self, rev, flags, mask, sid):
            self.aces.append((flags, mask, sid))

    sec = types.SimpleNamespace(
        TOKEN_QUERY=8, TokenUser=1, ACL_REVISION=2, SE_FILE_OBJECT=1,
        DACL_SECURITY_INFORMATION=4, PROTECTED_DACL_SECURITY_INFORMATION=0x80000000,
        OpenProcessToken=lambda proc, access: "tok",
        GetTokenInformation=lambda tok, cls: ("me-sid", 0),
        ACL=_ACL,
        SetNamedSecurityInfo=lambda *a: recorded.setdefault("args", a),
    )
    con = types.SimpleNamespace(OBJECT_INHERIT_ACE=1, CONTAINER_INHERIT_ACE=2, FILE_ALL_ACCESS=0x1F01FF)
    api = types.SimpleNamespace(GetCurrentProcess=lambda: "proc")
    monkeypatch.setitem(sys.modules, "win32security", sec)
    monkeypatch.setitem(sys.modules, "ntsecuritycon", con)
    monkeypatch.setitem(sys.modules, "win32api", api)

    fileperms.restrict_to_owner(tmp_path / "state", directory=True)
    path, objtype, info, owner, group, dacl, sacl = recorded["args"]
    assert path == str(tmp_path / "state")
    assert info & sec.PROTECTED_DACL_SECURITY_INFORMATION
    assert info & sec.DACL_SECURITY_INFORMATION
    assert dacl.aces == [(3, 0x1F01FF, "me-sid")]


@windows_only
def test_windows_real_dacl_excludes_other_principals(tmp_path):
    f = tmp_path / "token"
    f.write_text("secret")
    fileperms.restrict_to_owner(f)
    out = subprocess.run(["icacls", str(f)], capture_output=True, text=True, check=True).stdout
    aces = [line for line in out.splitlines() if ":(" in line]
    assert len(aces) == 1, out
    assert "(I)" not in aces[0], out
    user = os.environ.get("USERNAME", "")
    assert user.lower() in aces[0].lower(), out
