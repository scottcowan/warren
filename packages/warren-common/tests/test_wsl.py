"""AC2: WSL detection, AppArmor userns guidance, drvfs checks.

Everything runs against fake /proc files and mount tables, so it runs on any
OS. Tests that need a real Linux /proc or exec a fake bwrap are marked."""

from __future__ import annotations

import sys

import pytest

from warren_common import wsl

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="POSIX paths / sh scripts")
linux_only = pytest.mark.skipif(not sys.platform.startswith("linux"), reason="needs a real Linux /proc")


def _proc(tmp_path, release: str | None, interop: bool = False):
    osrelease = tmp_path / "osrelease"
    if release is not None:
        osrelease.write_text(release + "\n")
    interop_path = tmp_path / "WSLInterop"
    if interop:
        interop_path.write_text("enabled\n")
    return {"osrelease_path": osrelease, "interop_path": interop_path}


@pytest.mark.parametrize(
    "release,interop,expected",
    [
        ("5.15.153.1-microsoft-standard-WSL2", True, 2),
        ("6.6.36.6-microsoft-standard-WSL2+", False, 2),
        ("4.4.0-19041-Microsoft", True, 1),
        ("4.19.128-microsoft-standard", True, 2),
        ("6.8.0-custom", True, 2),  # custom WSL2 kernel: only WSLInterop says so
        ("6.8.0-45-generic", False, None),
        (None, False, None),
    ],
)
def test_wsl_version(tmp_path, release, interop, expected):
    assert wsl.wsl_version(**_proc(tmp_path, release, interop)) == expected


@pytest.mark.parametrize("value,expected", [("1", True), ("0", False), (None, False)])
def test_apparmor_restricts_userns(tmp_path, value, expected):
    f = tmp_path / "apparmor_restrict_unprivileged_userns"
    if value is not None:
        f.write_text(value + "\n")
    assert wsl.apparmor_restricts_userns(f) is expected


def test_classify_bwrap_error_apparmor():
    err = "bwrap: setting up uid map: Permission denied"
    msg = wsl.classify_bwrap_error(err, apparmor_restricted=True)
    assert msg == wsl.APPARMOR_USERNS_FIX
    assert "bwrap-userns-restrict" in msg
    assert "apparmor_parser -r" in msg


def test_classify_bwrap_error_generic_when_no_apparmor():
    err = "bwrap: No permissions to creating new namespace, likely because the kernel does not allow"
    assert wsl.classify_bwrap_error(err, apparmor_restricted=False) == wsl.USERNS_GENERIC_FIX


def test_classify_bwrap_error_ignores_unrelated():
    assert wsl.classify_bwrap_error("bwrap: Can't find source path /nope", apparmor_restricted=True) is None


def test_classify_reads_live_sysctl(tmp_path, monkeypatch):
    f = tmp_path / "restrict"
    f.write_text("1")
    monkeypatch.setattr(wsl, "PROC_APPARMOR_USERNS", str(f))
    assert wsl.classify_bwrap_error("bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted") == wsl.APPARMOR_USERNS_FIX


@posix_only
def test_probe_bwrap_classifies_failure(tmp_path, monkeypatch):
    fake = tmp_path / "bwrap"
    fake.write_text("#!/bin/sh\necho 'bwrap: setting up uid map: Permission denied' >&2\nexit 1\n")
    fake.chmod(0o755)
    restrict = tmp_path / "restrict"
    restrict.write_text("1")
    monkeypatch.setattr(wsl, "PROC_APPARMOR_USERNS", str(restrict))
    probe = wsl.probe_bwrap(str(fake))
    assert not probe.ok
    assert "uid map" in probe.stderr
    assert probe.guidance == wsl.APPARMOR_USERNS_FIX


@posix_only
def test_probe_bwrap_ok(tmp_path):
    fake = tmp_path / "bwrap"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    assert wsl.probe_bwrap(str(fake)).ok


def test_probe_bwrap_missing_binary(tmp_path):
    probe = wsl.probe_bwrap(str(tmp_path / "nope"))
    assert not probe.ok and probe.guidance is None


WSL2_MOUNTS = """\
/dev/sdc / ext4 rw,relatime,discard,errors=remount-ro,data=ordered 0 0
none /mnt/wsl tmpfs rw,relatime 0 0
drvfs /mnt/wsl/docker-desktop-bind-mounts 9p rw,noatime,aname=drvfs;path=C:\\;uid=1000 0 0
C:\\134 /mnt/c 9p rw,noatime,dirsync,aname=drvfs;path=C:\\;uid=1000;gid=1000;metadata 0 0
D:\\134 /mnt/d\\040drive 9p rw,noatime,aname=drvfs;path=D:\\ 0 0
tmpfs /mnt/c/tmpfs-over tmpfs rw 0 0
"""

WSL1_MOUNTS = """\
rootfs / lxfs rw,noatime 0 0
C:\\134 /mnt/c drvfs rw,noatime,uid=1000,gid=1000 0 0
"""


def test_parse_mounts_unescapes():
    entries = wsl.parse_mounts(WSL2_MOUNTS)
    assert entries[3].device == "C:\\"
    assert entries[4].mountpoint == "/mnt/d drive"


@posix_only
@pytest.mark.parametrize(
    "path,mountpoint",
    [
        ("/mnt/c/Users/me/.warren", "/mnt/c"),
        ("/mnt/c", "/mnt/c"),
        ("/mnt/d drive/x", "/mnt/d drive"),
    ],
)
def test_drvfs_detected(tmp_path, path, mountpoint):
    table = tmp_path / "mounts"
    table.write_text(WSL2_MOUNTS)
    entry = wsl.drvfs_mount_for(path, mounts_path=table)
    assert entry is not None and entry.mountpoint == mountpoint and entry.fstype == "9p"


@posix_only
@pytest.mark.parametrize("path", ["/home/me/.warren", "/mnt/cc/x", "/mnt/c/tmpfs-over/x", "/mnt/wsl/x"])
def test_linux_paths_not_drvfs(tmp_path, path):
    table = tmp_path / "mounts"
    table.write_text(WSL2_MOUNTS)
    assert wsl.drvfs_mount_for(path, mounts_path=table) is None


@posix_only
def test_wsl1_drvfs(tmp_path):
    table = tmp_path / "mounts"
    table.write_text(WSL1_MOUNTS)
    assert wsl.drvfs_mount_for("/mnt/c/x", mounts_path=table).fstype == "drvfs"


def test_unreadable_mount_table_is_not_drvfs(tmp_path):
    assert wsl.drvfs_mount_for("/mnt/c/x", mounts_path=tmp_path / "missing") is None


@posix_only
def test_drvfs_problems_labels(tmp_path):
    table = tmp_path / "mounts"
    table.write_text(WSL2_MOUNTS)
    problems = wsl.drvfs_problems(
        {"warren state dir": "/mnt/c/Users/me/.warren/state", "projects dir": "/home/me/p"},
        mounts_path=table,
    )
    assert len(problems) == 1
    assert problems[0].startswith("warren state dir /mnt/c/Users/me/.warren/state")
    assert "Linux filesystem" in problems[0]


@linux_only
def test_real_proc_reads_do_not_raise():
    # Sanity on a real Linux host (CI runners aren't WSL, so expect None there).
    wsl.wsl_version()
    wsl.apparmor_restricts_userns()
    wsl.drvfs_mount_for("/")
