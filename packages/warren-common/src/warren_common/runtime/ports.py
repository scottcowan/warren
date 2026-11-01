"""Publishing a podman/docker workspace's template-declared ports on host loopback.

Each port a template declares under ``ports:`` is published on the server host's
loopback interface, on a host port the container engine picks (ephemeral), so
`warren proxy` can reach it with an SSH forward to the server host (or directly,
when the CLI runs on that host). Never on ``0.0.0.0`` or a LAN address: rootless
podman with slirp4netns gives containers no route to host loopback, which is what
keeps one workspace from reaching another's published ports (pasta's
``169.254.1.2`` mapping can reach it; docs/threat-model.md, residual risk 6).
"""

from __future__ import annotations

import ipaddress
from collections.abc import Mapping
from typing import Any

DEFAULT_PUBLISH_HOST = "127.0.0.1"


def is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def loopback_publish_host(host: str | None) -> str:
    """The address app ports are published on: ``host`` (WARREN_SSH_PUBLISH_HOST)
    when it is a loopback address, else 127.0.0.1. An operator who exposes the SSH
    port on the LAN (or ``""`` = every interface) doesn't expose app ports with it."""
    return host if host and is_loopback(host) else DEFAULT_PUBLISH_HOST


def declared_container_ports(ports: Mapping[str, Any] | None) -> dict[str, int]:
    """``{name: container_port}`` from a spec's ``ports`` ({name: {"port": int, ...}})."""
    out: dict[str, int] = {}
    for name, entry in (ports or {}).items():
        port = entry.get("port") if isinstance(entry, Mapping) else entry
        if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535:
            out[str(name)] = port
    return out


def app_port_bindings(
    ports: Mapping[str, Any] | None, host: str, *, taken: set[str] | frozenset[str] = frozenset()
) -> dict[str, str]:
    """``{"<port>/tcp": host}`` for every declared port not already in ``taken``
    (e.g. the SSH port's ``22/tcp``). ``host`` must be loopback; the runtime adds
    the engine's "pick a free host port" value (podman 0, docker None)."""
    if not is_loopback(host):
        raise ValueError(f"refusing to publish workspace ports on non-loopback address {host!r}")
    out: dict[str, str] = {}
    for port in sorted(set(declared_container_ports(ports).values())):
        key = f"{port}/tcp"
        if key not in taken:
            out[key] = host
    return out


def parse_published(network_ports: Mapping[str, Any] | None) -> dict[int, tuple[str, int]]:
    """``{container_port: (host_ip, host_port)}`` from an inspect's
    ``NetworkSettings.Ports`` (``{"3773/tcp": [{"HostIp": "127.0.0.1", "HostPort": "41234"}]}``),
    loopback bindings only, tcp only."""
    out: dict[int, tuple[str, int]] = {}
    for key, bindings in (network_ports or {}).items():
        port_s, _, proto = str(key).partition("/")
        if (proto or "tcp") != "tcp" or not port_s.isdigit() or not isinstance(bindings, list):
            continue
        for b in bindings:
            if not isinstance(b, Mapping):
                continue
            ip = str(b.get("HostIp") or "")
            hp = str(b.get("HostPort") or "")
            if is_loopback(ip) and hp.isdigit() and 1 <= int(hp) <= 65535:
                out[int(port_s)] = (ip, int(hp))
                break
    return out


def host_ports_by_name(
    ports: Mapping[str, Any] | None, published: Mapping[int, tuple[str, int]]
) -> dict[str, dict[str, Any]]:
    """``{name: {"host": ip, "port": host_port}}`` for each declared port that is published."""
    out: dict[str, dict[str, Any]] = {}
    for name, port in declared_container_ports(ports).items():
        if port in published:
            ip, hp = published[port]
            out[name] = {"host": ip, "port": hp}
    return out
