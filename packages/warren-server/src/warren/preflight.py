"""Startup preflight — Podman socket, subuid range, and storage driver checks (D-03).

Uses `podman info` via podman-py rather than shelling out or parsing /etc/subuid;
`podman info` is authoritative for what podman itself sees at runtime.

`podman info` field-name casing has varied across releases — support both
camelCase (5.x default) and PascalCase keys defensively (Assumptions A1/A2).
"""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

import structlog

from warren.errors import PreflightError
from warren.runtime import podman as _podman_module

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


async def run_preflight(socket_path: str | Path) -> None:
    """Raise PreflightError on fatal misconfiguration; log warning for `vfs`.

    Fatal:
      * socket path does not exist on disk
      * `client.ping()` raises (socket present but unreachable)
      * summed UIDMap size < 65536 (Pitfall #4)

    Warning (non-fatal):
      * graphDriverName == "vfs" (Pitfall #5)
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
