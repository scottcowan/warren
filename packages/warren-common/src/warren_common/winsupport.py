"""Windows client helpers: named pipes, ssh-agent, build number, MXC probe.

Import-cheap: ctypes/winreg are only imported inside Windows-only branches.
"""

from __future__ import annotations

import functools
import os
import sys
from dataclasses import dataclass

PIPE_PREFIX = "\\\\.\\pipe\\"
DOCKER_DESKTOP_PIPE = "docker_engine"
PODMAN_MACHINE_PIPE = "podman-machine-default"
OPENSSH_AGENT_PIPE = "openssh-ssh-agent"


def is_windows() -> bool:
    return sys.platform == "win32"


def pipe_exists(name: str) -> bool:
    """Whether ``\\\\.\\pipe\\<name>`` exists. Lists the pipe namespace rather
    than opening the pipe, which would consume a server instance."""
    try:
        return name in os.listdir(PIPE_PREFIX)
    except OSError:
        return False


def docker_pipe_host() -> str | None:
    """``npipe://`` URL of a reachable Docker Desktop or podman machine engine."""
    for name in (DOCKER_DESKTOP_PIPE, PODMAN_MACHINE_PIPE):
        if pipe_exists(name):
            return f"npipe:////./pipe/{name}"
    return None


def ssh_agent_socket(environ: dict[str, str] | None = None) -> str | None:
    """The ssh-agent endpoint: ``SSH_AUTH_SOCK`` if it exists, else on Windows
    the OpenSSH agent pipe (``SSH_AUTH_SOCK`` is normally unset there, and an
    MSYS-style ``/tmp/...`` value is unusable by Windows ssh)."""
    env = os.environ if environ is None else environ
    sock = env.get("SSH_AUTH_SOCK")
    if sock and os.path.exists(sock):
        return sock
    if is_windows() and pipe_exists(OPENSSH_AGENT_PIPE):
        return PIPE_PREFIX + OPENSSH_AGENT_PIPE
    return None


def ssh_client_env(environ: dict[str, str] | None = None) -> dict[str, str] | None:
    """Env for running the host's ``ssh``, or None to inherit unchanged
    (POSIX). On Windows, point ``SSH_AUTH_SOCK`` at a usable agent or drop a
    stale value so ssh falls back to its default pipe."""
    if not is_windows():
        return None
    env = dict(os.environ if environ is None else environ)
    agent = ssh_agent_socket(env)
    if agent:
        env["SSH_AUTH_SOCK"] = agent
    else:
        env.pop("SSH_AUTH_SOCK", None)
    return env


_PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
_STILL_ACTIVE = 259


def windows_pid_alive(pid: int) -> bool:
    """Liveness check for Windows, where ``os.kill(pid, 0)`` is not a probe:
    signal 0 is CTRL_C_EVENT and interrupts every process on the console."""
    import ctypes  # noqa: PLC0415
    from ctypes import wintypes  # noqa: PLC0415

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.OpenProcess.restype = wintypes.HANDLE
    handle = kernel32.OpenProcess(_PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return False
    try:
        code = wintypes.DWORD()
        if not kernel32.GetExitCodeProcess(handle, ctypes.byref(code)):
            return False
        return code.value == _STILL_ACTIVE
    finally:
        kernel32.CloseHandle(handle)


@functools.lru_cache(maxsize=1)
def windows_build() -> str | None:
    """``<build>.<UBR>`` (e.g. ``26100.9278``), or None off Windows."""
    if not is_windows():
        return None
    build = str(sys.getwindowsversion().build)
    try:
        import winreg  # noqa: PLC0415

        with winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        ) as key:
            ubr, _ = winreg.QueryValueEx(key, "UBR")
        return f"{build}.{ubr}"
    except OSError:
        return build


@dataclass(frozen=True)
class MxcProbe:
    available: bool
    status: str  # "available" | "unavailable" | "unknown" | "n/a"
    reason: str


_PSEC_API_SET = b"api-win-appmodel-processmodel~securityenvironment"
_PSEC_EXPORTS = (
    b"CreateProcessSecurityEnvironment",
    b"QueryProcessSecurityEnvironmentSupport",
    b"CloseProcessSecurityEnvironment",
)
_LOAD_LIBRARY_SEARCH_SYSTEM32 = 0x00000800


def _psec_exports_present() -> tuple[bool, str]:
    import ctypes  # noqa: PLC0415
    from ctypes import wintypes  # noqa: PLC0415

    kernelbase = ctypes.WinDLL("kernelbase", use_last_error=True)
    is_api_set = getattr(kernelbase, "IsApiSetImplemented", None)
    if is_api_set is None:
        return False, "IsApiSetImplemented not exported (pre-MXC Windows)"
    is_api_set.argtypes = [ctypes.c_char_p]
    is_api_set.restype = wintypes.BOOL
    if not is_api_set(_PSEC_API_SET):
        return False, "process security environment API set not implemented"

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.LoadLibraryExW.argtypes = [wintypes.LPCWSTR, wintypes.HANDLE, wintypes.DWORD]
    kernel32.LoadLibraryExW.restype = wintypes.HMODULE
    kernel32.GetProcAddress.argtypes = [wintypes.HMODULE, ctypes.c_char_p]
    kernel32.GetProcAddress.restype = ctypes.c_void_p
    module = kernel32.LoadLibraryExW("processmodel.dll", None, _LOAD_LIBRARY_SEARCH_SYSTEM32)
    if not module:
        return False, f"processmodel.dll not loadable (error {ctypes.get_last_error()})"
    missing = [n.decode() for n in _PSEC_EXPORTS if not kernel32.GetProcAddress(module, n)]
    if missing:
        return False, f"processmodel.dll lacks {', '.join(missing)}"
    return True, ""


@functools.lru_cache(maxsize=1)
def probe_mxc() -> MxcProbe:
    """Report-only Microsoft Execution Containers availability (AC4).

    Missing API set/DLL/exports means unavailable. Present exports are NOT
    proof (transitional builds ship them before the feature is enabled), and
    the real check -- creating and closing a PSEC environment -- needs a
    FlatBuffer spec plus a startup-info attribute list, so it is not attempted
    here and the result is "unknown". Never raises.
    """
    if not is_windows():
        return MxcProbe(False, "n/a", "not Windows")
    try:
        present, reason = _psec_exports_present()
    except Exception as exc:  # noqa: BLE001
        return MxcProbe(False, "unavailable", f"probe failed: {exc}")
    if not present:
        return MxcProbe(False, "unavailable", reason)
    return MxcProbe(
        False,
        "unknown",
        "PSEC exports present; creating an environment needs a FlatBuffer spec, not probed",
    )
