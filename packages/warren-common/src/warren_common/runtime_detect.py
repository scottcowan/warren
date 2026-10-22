"""Import-cheap runtime detection (D-04).

Zero imports of `docker`/`boto3` at module scope so `warren --help` stays fast.
Recommendation priority (D-01): macOS → seatbelt; Linux → bwrap → nsjail;
otherwise docker; otherwise "none" (with a ``note`` saying why on Windows).
WSL2 is Linux (bubblewrap); WSL1 has no namespaces, so bwrap/nsjail are never
offered there (AC2).
"""

from __future__ import annotations

import os
import shutil
import socket
import sys
from dataclasses import dataclass

from . import winsupport, wsl

WINDOWS_NO_SANDBOX_NOTE = (
    "native Windows has no local sandbox runtime; use a remote (podman/ECS) "
    "workspace, Docker Desktop/podman machine, or run warren inside WSL2"
)


# Sandbox binaries are always exec'd by absolute path (AE2): a PATH lookup at
# connect time would run whatever `sandbox-exec`/`bwrap` sits first on the
# operator's PATH, unsandboxed.
SANDBOX_EXEC_PATH = "/usr/bin/sandbox-exec"
DEFAULT_NSJAIL_PATH = "/usr/sbin/nsjail"


@dataclass(frozen=True)
class RuntimeAvailability:
    seatbelt: bool
    bwrap: bool
    nsjail: bool
    docker: bool
    ecs: bool
    recommended: str  # "seatbelt" | "bubblewrap" | "nsjail" | "docker" | "none"
    bwrap_path: str | None = None
    nsjail_path: str | None = None
    docker_host: str | None = None
    note: str = ""
    # Microsoft Execution Containers (AC4): report only, never selected.
    mxc: bool = False
    mxc_status: str = "n/a"  # "available" | "unavailable" | "unknown" | "n/a"
    mxc_reason: str = ""
    windows_build: str | None = None
    # AC2: 1 / 2 under WSL, else None. WSL1 never gets a namespace sandbox.
    wsl_version: int | None = None
    # AC2: Ubuntu 24.04+ kernel.apparmor_restrict_unprivileged_userns=1.
    apparmor_userns_restricted: bool = False


def resolve_bwrap() -> str | None:
    """Absolute, symlink-resolved path of `bwrap`, looked up once."""
    found = shutil.which("bwrap")
    return os.path.realpath(found) if found else None


def resolve_nsjail() -> str | None:
    """Absolute path of nsjail: WARREN_NSJAIL_PATH (must be absolute), else PATH,
    else the default install location."""
    env = os.environ.get("WARREN_NSJAIL_PATH")
    if env and os.path.isabs(env) and os.access(env, os.X_OK):
        return os.path.realpath(env)
    found = shutil.which("nsjail")
    if found:
        return os.path.realpath(found)
    if os.access(DEFAULT_NSJAIL_PATH, os.X_OK):
        return DEFAULT_NSJAIL_PATH
    return None


def _ecs_available() -> bool:
    if shutil.which("aws") is None:
        return False
    if os.environ.get("AWS_ACCESS_KEY_ID") or os.environ.get("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"):
        return True
    aws_dir = os.path.join(os.path.expanduser("~"), ".aws")
    return any(os.path.exists(os.path.join(aws_dir, name)) for name in ("credentials", "config"))


def _docker_socket_reachable() -> bool:
    if winsupport.is_windows():
        return winsupport.docker_pipe_host() is not None
    sock_path = "/var/run/docker.sock"
    if not os.path.exists(sock_path):
        return False
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(0.2)
            s.connect(sock_path)
        return True
    except OSError:
        return False


def detect() -> RuntimeAvailability:
    is_mac = sys.platform == "darwin"
    is_linux = sys.platform.startswith("linux")

    seatbelt = is_mac and os.path.isfile(SANDBOX_EXEC_PATH)
    wsl_ver = wsl.wsl_version() if is_linux else None
    # WSL1 has no namespaces: bwrap/nsjail binaries may be installed but can't
    # sandbox anything, so never offer them there (AC2).
    namespaces_ok = is_linux and wsl_ver != 1
    bwrap_path = resolve_bwrap() if namespaces_ok else None
    nsjail_path = resolve_nsjail() if namespaces_ok else None
    bwrap = bwrap_path is not None
    nsjail = nsjail_path is not None
    docker = _docker_socket_reachable()
    ecs = _ecs_available()

    if is_mac and seatbelt:
        recommended = "seatbelt"
    elif is_linux and bwrap:
        recommended = "bubblewrap"
    elif is_linux and nsjail:
        recommended = "nsjail"
    elif docker:
        recommended = "docker"
    else:
        recommended = "none"

    is_windows = winsupport.is_windows()
    docker_host = winsupport.docker_pipe_host() if is_windows and docker else None
    note = WINDOWS_NO_SANDBOX_NOTE if is_windows and recommended == "none" else ""
    if wsl_ver == 1:
        note = wsl.WSL1_REFUSAL
    elif wsl_ver == 2 and not bwrap:
        note = wsl.WSL2_NO_BWRAP_NOTE
    mxc = winsupport.probe_mxc() if is_windows else winsupport.MxcProbe(False, "n/a", "")

    return RuntimeAvailability(
        seatbelt=seatbelt,
        bwrap=bwrap,
        nsjail=nsjail,
        docker=docker,
        ecs=ecs,
        recommended=recommended,
        bwrap_path=bwrap_path,
        nsjail_path=nsjail_path,
        docker_host=docker_host,
        note=note,
        mxc=mxc.available,
        mxc_status=mxc.status,
        mxc_reason=mxc.reason,
        windows_build=winsupport.windows_build() if is_windows else None,
        wsl_version=wsl_ver,
        apparmor_userns_restricted=is_linux and wsl.apparmor_restricts_userns(),
    )
