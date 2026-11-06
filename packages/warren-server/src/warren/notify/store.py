"""Per-owner webhook subscriptions, kept in the secrets store.

One record per owner, the reserved secret name `warren.notify.webhook`, stored through
the server's `SecretStoreProtocol` (state/protocols.py) like every other secret: Fernet
in SQLite, or Secrets Manager with WARREN_SECRETS_BACKEND=secretsmanager. The value is
JSON `{"url", "format", "events"}`; the whole record is a secret because the URL is the
credential. The name isn't an environment variable name, so no template can have it
delivered into a workspace, and the generic PUT /secrets refuses the reserved prefix.

Keyed by the workspace owner id (the warren user id that stamps `workspaces.owner_id`),
since that is how a notification finds its owner.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from pydantic import SecretStr
from warren.notify.targets import FORMATS, Target, parse_events, validate_webhook_url

if TYPE_CHECKING:
    from warren.state.protocols import SecretStoreProtocol

RESERVED_PREFIX = "warren.notify."
SECRET_NAME = RESERVED_PREFIX + "webhook"


def encode(url: str, fmt: str, events: frozenset[str]) -> str:
    return json.dumps({"url": url, "format": fmt, "events": sorted(events)})


def decode(raw: str) -> Target | None:
    """The stored record as a Target, or None if it doesn't validate (fail closed)."""
    try:
        obj = json.loads(raw)
        url = validate_webhook_url(obj["url"])
        fmt = obj.get("format", "json")
        if fmt not in FORMATS:
            return None
        events = parse_events(obj.get("events") or None)
    except (ValueError, KeyError, TypeError):
        return None
    return Target(url=SecretStr(url), format=fmt, events=events, kind="owner", require_public=True)


async def put(secrets: SecretStoreProtocol, owner_id: str, url: str, fmt: str, events: frozenset[str]) -> None:
    await secrets.set(owner_id, SECRET_NAME, encode(url, fmt, events))


async def get(secrets: SecretStoreProtocol, owner_id: str) -> Target | None:
    raw = (await secrets.resolve(owner_id, [SECRET_NAME])).get(SECRET_NAME)
    return decode(raw) if raw is not None else None


async def delete(secrets: SecretStoreProtocol, owner_id: str) -> bool:
    return await secrets.delete(owner_id, SECRET_NAME)


async def subscribed_owners(secrets: SecretStoreProtocol) -> set[str]:
    return await secrets.owners_with(SECRET_NAME)
