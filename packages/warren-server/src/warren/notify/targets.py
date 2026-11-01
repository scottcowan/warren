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


async def is_public_destination(url: str, resolver: Resolver = default_resolver) -> bool:
    """Whether every address `url`'s host resolves to is globally routable.

    Rejects loopback, private, link-local (incl. cloud metadata 169.254.169.254),
    and other non-global ranges. A DNS answer can change between this check and the
    connect; this narrows SSRF, it does not pin the address.
    """
    parts = urlsplit(url)
    host = parts.hostname or ""
    if not host or host == "localhost" or host.endswith(".localhost"):
        return False
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        return literal.is_global
    try:
        addrs = await resolver(host, parts.port or 443)
    except Exception:
        return False
    if not addrs:
        return False
    for addr in addrs:
        try:
            if not ipaddress.ip_address(addr.split("%", 1)[0]).is_global:
                return False
        except ValueError:
            return False
    return True
