"""Startup preflight — Podman socket, subuid range, and storage driver checks (D-03).

Uses `podman info` via podman-py rather than shelling out or parsing /etc/subuid;
`podman info` is authoritative for what podman itself sees at runtime.

`podman info` field-name casing has varied across releases — support both
camelCase (5.x default) and PascalCase keys defensively (Assumptions A1/A2).
"""

from __future__ import annotations

import asyncio
import logging
import re
import socket as _socket_mod
from pathlib import Path
from typing import Any

import structlog

from warren.errors import PreflightError
from warren.podman_host import pasta_apparmor_warning, pasta_host_loopback_warning, read_local_pasta_profile
from warren.runtime import podman as _podman_module
from warren.runtime.userns import KEEP_ID_OPTIONS_MIN_PODMAN, needs_keep_id_options

log = structlog.get_logger(__name__)
_stdlib_log = logging.getLogger(__name__)

_MIN_SUBUID_RANGE = 65536

try:
    from importlib.metadata import PackageNotFoundError as _PNF
    from importlib.metadata import version as _pkg_version

    _WARREN_VERSION: str = _pkg_version("warren-server")
except Exception:
    _WARREN_VERSION = "dev"


def _idmap_uidmap(info: dict[str, Any]) -> list[dict[str, Any]]:
    host = info.get("host") or info.get("Host") or {}
    mappings = host.get("idMappings") or host.get("IDMappings") or {}
    return mappings.get("uidmap") or mappings.get("UIDMap") or []


def _graph_driver(info: dict[str, Any]) -> str | None:
    store = info.get("store") or info.get("Store") or {}
    return store.get("graphDriverName") or store.get("GraphDriverName")


def _info_hostname(info: dict[str, Any]) -> str | None:
    host = info.get("host") or info.get("Host") or {}
    return host.get("hostname") or host.get("Hostname")


def _warn_pasta_apparmor(info: dict[str, Any], socket: Path, same_host: bool) -> None:
    # Read the local pasta profile only when podman is on this host: same filesystem
    # (not containerized) and podman reports our hostname (not a socket forwarded over SSH).
    profile = None
    if same_host and _info_hostname(info) == _socket_mod.gethostname():
        profile = read_local_pasta_profile()
    warning = pasta_apparmor_warning(info, profile)
    if warning is None:
        return
    log.warning("podman_pasta_apparmor", socket=str(socket), **warning)
    _stdlib_log.warning(
        "Podman %s uses pasta under AppArmor: container removal may fail on Ubuntu 26.04. Set %s (%s)",
        warning["podman_version"],
        warning["fix"],
        warning["docs"],
    )


def _podman_version(info: dict[str, Any]) -> tuple[int, int] | None:
    version = info.get("version") or info.get("Version") or {}
    text = version.get("Version") or version.get("version") if isinstance(version, dict) else None
    m = re.match(r"\s*v?(\d+)\.(\d+)", str(text or ""))
    return (int(m.group(1)), int(m.group(2))) if m else None


def _check_userns_support(info: dict[str, Any], userns: str) -> None:
    """keep-id's uid/gid options need podman >= 4.3; older podman rejects the create."""
    if not needs_keep_id_options(userns):
        return
    version = _podman_version(info)
    if version is not None and version < KEEP_ID_OPTIONS_MIN_PODMAN:
        want = ".".join(str(p) for p in KEEP_ID_OPTIONS_MIN_PODMAN)
        raise PreflightError(
            f"WARREN_PODMAN_USERNS={userns!r} needs podman >= {want} "
            f"(found {version[0]}.{version[1]}). Upgrade podman, or set "
            "WARREN_PODMAN_USERNS=host to keep podman's default mapping."
        )


def _warn_pasta_host_loopback(info: dict[str, Any], socket: Path) -> None:
    warning = pasta_host_loopback_warning(info)
    if warning is None:
        return
    log.warning("podman_pasta_host_loopback", socket=str(socket), **warning)
    _stdlib_log.warning(
        "Podman %s runs rootless networking through pasta: workspaces can reach host loopback "
        "via 169.254.1.2, including other workspaces' published ports (docs/threat-model.md, "
        "residual risk 6)",
        warning["podman_version"],
    )


async def run_preflight(
    socket_path: str | Path, *, same_host: bool = False, userns: str = ""
) -> None:
    """Raise PreflightError on fatal misconfiguration; log warning for `vfs`.

    Fatal:
      * socket path does not exist on disk
      * `client.ping()` raises (socket present but unreachable)
      * summed UIDMap size < 65536 (Pitfall #4)

    Warning (non-fatal):
      * graphDriverName == "vfs" (Pitfall #5)
      * rootless pasta under AppArmor on podman 5.x (warren.podman_host)
      * rootless pasta at all: host loopback reachable from containers (warren.podman_host)

    `same_host` says the server shares podman's filesystem, so the pasta AppArmor
    profile can be read locally to rule the pasta warning out.
    """
    socket = Path(str(socket_path))
    if not socket.exists():
        raise PreflightError(f"Podman socket not found at {socket}")

    # Route through the podman module namespace so tests can patch PodmanClient.
    client = _podman_module.PodmanClient(base_url=f"unix://{socket}")
    try:
        await asyncio.to_thread(client.ping)
    except Exception as e:
        raise PreflightError(f"Podman socket unreachable: {e}") from e

    info = await asyncio.to_thread(client.info)
    log.debug("podman info", info=info, socket=str(socket))

    uid_map = _idmap_uidmap(info)
    total_uids = sum(int(m.get("size") or m.get("Size") or 0) for m in uid_map)
    if total_uids < _MIN_SUBUID_RANGE:
        raise PreflightError(
            f"subuid range too small ({total_uids}); need >= {_MIN_SUBUID_RANGE}. "
            "Run: sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $USER"
        )

    driver = _graph_driver(info)
    if driver == "vfs":
        log.warning(
            "vfs storage driver",
            socket=str(socket),
            hint="install fuse-overlayfs for 10-100x speedup",
        )
        _stdlib_log.warning(
            "Podman using vfs storage driver at %s — install fuse-overlayfs for 10-100x speedup",
            socket,
        )

    _warn_pasta_apparmor(info, socket, same_host)
    _check_userns_support(info, userns)
    _warn_pasta_host_loopback(info, socket)


async def check_podman_health(socket_path: str | Path) -> dict:
    """Return Podman reachability dict without raising.

    Returns {"type": "podman", "reachable": bool, "socket": str}.
    Never raises — catches all exceptions including TimeoutError.
    Uses asyncio.wait_for with a 2-second timeout to guard against a slow Podman daemon.
    """
    socket = Path(str(socket_path))
    result_base = {"type": "podman", "socket": str(socket)}

    if not socket.exists():
        return {**result_base, "reachable": False}

    try:
        client = _podman_module.PodmanClient(base_url=f"unix://{socket}")
        await asyncio.wait_for(asyncio.to_thread(client.ping), timeout=2.0)
        await asyncio.wait_for(asyncio.to_thread(client.info), timeout=2.0)
        return {**result_base, "reachable": True}
    except Exception:
        return {**result_base, "reachable": False}
