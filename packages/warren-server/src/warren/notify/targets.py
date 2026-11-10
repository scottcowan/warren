"""Webhook targets: URL validation and where each one comes from.

A target is a webhook URL (always a SecretStr: Slack-style incoming webhook URLs are
bearer credentials), a payload format and the events it wants. The server-wide target
comes from WARREN_NOTIFY_WEBHOOK_URL; an owner's target is one encrypted record in the
secrets store (warren.notify.store). URLs are never logged or returned by the API.
"""

from __future__ import annotations

import asyncio
import ipaddress
import re
import socket
from collections.abc import Awaitable, Callable, Iterable
from dataclasses import dataclass, field
from typing import Literal
from urllib.parse import urlsplit

from pydantic import SecretStr
from warren.notify.events import EVENTS

Format = Literal["json", "slack"]
FORMATS: tuple[str, ...] = ("json", "slack")

# Same shape WARREN_BEDROCK_GATEWAY_URL accepts: https, a host name, optional port,
# a plain path. No userinfo, no query, no fragment.
_URL_RE = re.compile(r"https://[A-Za-z0-9.-]+(:\d+)?(/[A-Za-z0-9._~/-]*)?")
MAX_URL_LENGTH = 2048


def validate_webhook_url(url: str) -> str:
    """The URL, stripped, or ValueError (whose message never contains the URL)."""
    url = url.strip()
    if len(url) > MAX_URL_LENGTH or not _URL_RE.fullmatch(url):
        raise ValueError("webhook URL must be an https:// URL with no credentials, query or fragment")
    return url


def parse_events(value: str | Iterable[str] | None) -> frozenset[str]:
    """Event names, validated. Empty (or None) means every event."""
    if value is None:
        return frozenset(EVENTS)
    items = [v.strip() for v in value.split(",")] if isinstance(value, str) else [str(v).strip() for v in value]
    items = [v for v in items if v]
    if not items:
        return frozenset(EVENTS)
    unknown = sorted(set(items) - set(EVENTS))
    if unknown:
        raise ValueError(f"unknown notification event(s): {', '.join(unknown)}")
    return frozenset(items)


@dataclass(frozen=True)
class Target:
    url: SecretStr
    format: Format = "json"
    events: frozenset[str] = field(default_factory=lambda: frozenset(EVENTS))
    # "server" or "owner"; the only thing about a target that is ever logged.
    kind: str = "server"
    # Owner-registered URLs must resolve to public addresses (no SSRF into the
    # control plane's own network). The operator's server-wide URL is trusted.
    require_public: bool = False

    def wants(self, event: str) -> bool:
        return event in self.events


Resolver = Callable[[str, int], Awaitable[list[str]]]


async def default_resolver(host: str, port: int) -> list[str]:
    infos = await asyncio.get_running_loop().getaddrinfo(host, port, type=socket.SOCK_STREAM)
    return [str(info[4][0]) for info in infos]


_BLOCKED_V6 = tuple(
    ipaddress.ip_network(n)
    for n in (
        "2002::/16",  # 6to4: embeds an arbitrary IPv4 address
        "64:ff9b::/96",  # NAT64: reaches IPv4 through a gateway
        "64:ff9b:1::/48",  # local-use NAT64
        "2001::/32",  # Teredo
        "100::/64",  # discard-only
    )
)


def is_public_address(addr: str) -> bool:
    """Whether `addr` is a globally routable unicast address a webhook may be sent to.

    Rejects loopback, private, link-local (incl. cloud metadata 169.254.169.254),
    multicast, reserved and unspecified space, plus IPv6 forms that smuggle an IPv4
    address (IPv4-mapped, 6to4, NAT64, Teredo) and unique-local (fc00::/7).
    """
    try:
        ip = ipaddress.ip_address(addr.split("%", 1)[0])
    except ValueError:
        return False
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.ipv4_mapped is not None:
            return is_public_address(str(ip.ipv4_mapped))
        if any(ip in net for net in _BLOCKED_V6):
            return False
    return bool(ip.is_global) and not (ip.is_multicast or ip.is_reserved or ip.is_unspecified or ip.is_loopback)


async def resolve_public_destination(
    url: str,
    resolver: Resolver = default_resolver,
    *,
    allowed_ports: frozenset[int] | None = None,
    timeout: float = 5.0,
) -> list[str] | None:
    """Resolve `url`'s host once and return its addresses, or None if any is unsafe.

    Every returned address is public (`is_public_address`), so the caller can connect
    to one of them directly and never lets the HTTP client resolve the name again
    (DNS rebinding). `allowed_ports` (None: any) restricts the URL's port.
    """
    parts = urlsplit(url)
    host = parts.hostname or ""
    try:
        port = parts.port or 443
    except ValueError:
        return None
    if allowed_ports is not None and port not in allowed_ports:
        return None
    if not host or host == "localhost" or host.endswith(".localhost"):
        return None
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        return [host] if is_public_address(host) else None
    try:
        addrs = await asyncio.wait_for(resolver(host, port), timeout=timeout)
    except Exception:
        return None
    if not addrs or not all(is_public_address(a) for a in addrs):
        return None
    # Deduplicate, keeping the resolver's order.
    return list(dict.fromkeys(a.split("%", 1)[0] for a in addrs))


async def is_public_destination(url: str, resolver: Resolver = default_resolver) -> bool:
    """Whether every address `url`'s host resolves to is globally routable."""
    return await resolve_public_destination(url, resolver) is not None
