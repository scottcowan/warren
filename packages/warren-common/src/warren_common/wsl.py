"""WSL detection, AppArmor user-namespace guidance, and drvfs checks (AC2).

Warren's local sandbox on Windows is WSL2 + the existing bubblewrap runtime.
Everything here reads plain files (``/proc``, ``/proc/mounts``) through
injectable paths so it can be tested with fake proc trees on any OS.

Import-cheap: stdlib only, nothing runs at import time.
"""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

PROC_OSRELEASE = "/proc/sys/kernel/osrelease"
PROC_WSL_INTEROP = "/proc/sys/fs/binfmt_misc/WSLInterop"
PROC_APPARMOR_USERNS = "/proc/sys/kernel/apparmor_restrict_unprivileged_userns"
PROC_MOUNTS = "/proc/mounts"

WSL1_REFUSAL = (
    "WSL1 detected: it has no Linux namespaces, so bubblewrap/nsjail cannot "
    "sandbox anything here. Convert this distro to WSL2 from PowerShell "
    "(`wsl --set-version <distro> 2`), or use a remote (podman/ECS) workspace"
)
WSL2_NO_BWRAP_NOTE = (
    "WSL2 detected: install bubblewrap (`sudo apt install bubblewrap`) to get "
    "the local sandbox runtime"
)

# The fix Ubuntu documents for 24.04+ (kernel.apparmor_restrict_unprivileged_userns=1).
# The apparmor package ships `bwrap-userns-restrict` under extra-profiles; it
# lets bwrap create its user namespace while keeping the namespace's children
# unprivileged.
APPARMOR_USERNS_FIX = (
    "AppArmor is blocking bubblewrap's user namespace "
    "(kernel.apparmor_restrict_unprivileged_userns=1, Ubuntu 24.04+ default).\n"
    "Fix: load the AppArmor profile for bwrap:\n"
    "  sudo cp /usr/share/apparmor/extra-profiles/bwrap-userns-restrict /etc/apparmor.d/\n"
    "  sudo apparmor_parser -r /etc/apparmor.d/bwrap-userns-restrict\n"
    "If that profile isn't shipped on this release, create /etc/apparmor.d/bwrap with:\n"
    "  abi <abi/4.0>,\n"
    "  include <tunables/global>\n"
    "  profile bwrap /usr/bin/bwrap flags=(unconfined) {\n"
    "    userns,\n"
    "  }\n"
    "and load it with `sudo apparmor_parser -r /etc/apparmor.d/bwrap`.\n"
    "Don't disable the restriction system-wide (sysctl ...=0); it protects the whole host."
)
USERNS_GENERIC_FIX = (
    "bubblewrap could not create its namespaces. Check that unprivileged user "
    "namespaces are enabled (`sysctl kernel.unprivileged_userns_clone`, "
    "`sysctl user.max_user_namespaces`) and that you aren't inside a container "
    "without CAP_SYS_ADMIN"
)

# Filesystem types where Unix permission bits aren't a security boundary:
# drvfs (WSL1) and 9p (WSL2's /mnt/<drive>). Windows-side processes read these
# files through NTFS ACLs regardless of chmod, even with drvfs `metadata`.
_DRVFS_TYPES = frozenset({"drvfs", "9p", "v9fs"})

# bwrap stderr fragments for "could not create a namespace".
_USERNS_ERROR_MARKERS = (
    "setting up uid map",
    "setting up gid map",
    "no permissions to creating new namespace",
    "no permissions to create new namespace",
    "creating new namespace failed",
    "unshare failed",
    "failed rtm_newaddr",
    "loopback: failed",
    "operation not permitted",
)


def _read(path: str | os.PathLike[str]) -> str | None:
    try:
        return Path(path).read_text(errors="replace").strip()
    except OSError:
        return None


def wsl_version(
    *,
    osrelease_path: str | os.PathLike[str] | None = None,
    interop_path: str | os.PathLike[str] | None = None,
) -> int | None:
    """1 for WSL1, 2 for WSL2, None when not running under WSL.

    WSL2 kernels report ``...-microsoft-standard-WSL2``; WSL1's synthetic
    kernel reports ``4.4.0-<build>-Microsoft``. ``WSLInterop`` exists under both,
    so on its own (a custom WSL2 kernel without "microsoft" in its release)
    it means WSL2: WSL1 always has the Microsoft string.
    """
    release = (_read(osrelease_path or PROC_OSRELEASE) or "").lower()
    if "wsl2" in release or "microsoft-standard" in release:
        return 2
    if "microsoft" in release:
        return 1
    if os.path.exists(interop_path or PROC_WSL_INTEROP):
        return 2
    return None


def apparmor_restricts_userns(
    path: str | os.PathLike[str] | None = None,
) -> bool:
    """True when ``kernel.apparmor_restrict_unprivileged_userns=1``."""
    return _read(path or PROC_APPARMOR_USERNS) == "1"


def classify_bwrap_error(stderr: str, *, apparmor_restricted: bool | None = None) -> str | None:
    """Actionable guidance for a bwrap namespace-creation failure, else None.

    ``apparmor_restricted`` defaults to reading the live sysctl.
    """
    text = (stderr or "").lower()
    if not any(m in text for m in _USERNS_ERROR_MARKERS):
        return None
    if apparmor_restricted is None:
        apparmor_restricted = apparmor_restricts_userns()
    return APPARMOR_USERNS_FIX if apparmor_restricted else USERNS_GENERIC_FIX


@dataclass(frozen=True)
class BwrapProbe:
    ok: bool
    stderr: str = ""
    guidance: str | None = None


def probe_bwrap(bwrap_path: str, *, timeout: float = 5.0) -> BwrapProbe:
    """Run a no-op sandbox with the same namespace flags warren uses, so a
    namespace failure is reported with its fix before the real hand-off
    (after ``execvp`` there is no chance to rewrite bwrap's raw error)."""
    argv = [
        bwrap_path,
        "--unshare-pid", "--unshare-uts", "--unshare-ipc",
        "--ro-bind", "/", "/",
        "--proc", "/proc", "--dev", "/dev",
        "--", "/bin/true",
    ]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return BwrapProbe(False, str(exc), None)
    if proc.returncode == 0:
        return BwrapProbe(True)
    stderr = (proc.stderr or "").strip()
    return BwrapProbe(False, stderr, classify_bwrap_error(stderr))


@dataclass(frozen=True)
class MountEntry:
    device: str
    mountpoint: str
    fstype: str
    options: str


def _unescape_mount_field(field: str) -> str:
    # /proc/mounts octal-escapes space, tab, newline and backslash.
    return (
        field.replace("\\040", " ").replace("\\011", "\t")
        .replace("\\012", "\n").replace("\\134", "\\")
    )


def parse_mounts(text: str) -> list[MountEntry]:
    entries: list[MountEntry] = []
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        entries.append(
            MountEntry(
                _unescape_mount_field(parts[0]),
                _unescape_mount_field(parts[1]),
                parts[2],
                parts[3],
            )
        )
    return entries


def mount_for(path: str | os.PathLike[str], mounts: list[MountEntry]) -> MountEntry | None:
    """The mount containing ``path`` (longest mountpoint prefix; later entries
    win ties, matching mount stacking order)."""
    target = os.path.realpath(path)
    best: MountEntry | None = None
    for entry in mounts:
        mp = entry.mountpoint.rstrip("/") or "/"
        if mp == "/" or target == mp or target.startswith(mp + "/"):
            if best is None or len(mp) >= len(best.mountpoint.rstrip("/") or "/"):
                best = entry
    return best


def drvfs_mount_for(
    path: str | os.PathLike[str],
    *,
    mounts_path: str | os.PathLike[str] | None = None,
) -> MountEntry | None:
    """The drvfs/9p mount ``path`` lives on, or None (also None when the mount
    table can't be read, e.g. not Linux)."""
    text = _read(mounts_path or PROC_MOUNTS)
    if not text:
        return None
    entry = mount_for(path, parse_mounts(text))
    if entry is not None and entry.fstype in _DRVFS_TYPES:
        return entry
    return None


def drvfs_message(label: str, path: str | os.PathLike[str], entry: MountEntry) -> str:
    return (
        f"{label} {path} is on a Windows drive ({entry.mountpoint}, {entry.fstype}): "
        "Unix permissions aren't enforced there, so tokens, the secrets DB and "
        "sandbox profiles would be readable from Windows and by other users. "
        "Keep warren's state and workspaces on the Linux filesystem "
        "(e.g. /home/<you>/.warren), which is also much faster"
    )


def drvfs_problems(
    paths: dict[str, str | os.PathLike[str]],
    *,
    mounts_path: str | os.PathLike[str] | None = None,
) -> list[str]:
    """One message per labelled path that sits on drvfs."""
    problems: list[str] = []
    for label, path in paths.items():
        entry = drvfs_mount_for(path, mounts_path=mounts_path)
        if entry is not None:
            problems.append(drvfs_message(label, path, entry))
    return problems
