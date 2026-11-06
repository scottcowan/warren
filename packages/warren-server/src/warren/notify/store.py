"""Per-owner webhook subscriptions, kept in the secrets store.

One record per owner, the reserved secret name `warren.notify.webhook`, Fernet-encrypted
like every other secret (warren.secrets.store). The value is JSON
`{"url", "format", "events"}`; the whole record is encrypted because the URL is the
credential. The name isn't an environment variable name, so no template can have it
delivered into a workspace, and the generic PUT /secrets refuses the reserved prefix.

Keyed by the workspace owner id (the warren user id that stamps `workspaces.owner_id`),
since that is how a notification finds its owner.
"""

from __future__ import annotations

import json

import aiosqlite
from pydantic import SecretStr
from warren.notify.targets import FORMATS, Target, parse_events, validate_webhook_url
from warren.secrets import store as secret_store
from warren.secrets.cipher import LocalCipher

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


async def put(
    db: aiosqlite.Connection, cipher: LocalCipher, owner_id: str, url: str, fmt: str, events: frozenset[str]
) -> None:
    await secret_store.set_secret(db, cipher, owner_id, SECRET_NAME, encode(url, fmt, events))


async def get(db: aiosqlite.Connection, cipher: LocalCipher, owner_id: str) -> Target | None:
    values = await secret_store.resolve_secrets_for_names(db, cipher, owner_id, [SECRET_NAME])
    raw = values.get(SECRET_NAME)
    return decode(raw) if raw is not None else None


async def delete(db: aiosqlite.Connection, owner_id: str) -> bool:
    return await secret_store.delete_secret(db, owner_id, SECRET_NAME)


async def subscribed_owners(db: aiosqlite.Connection) -> set[str]:
    async with db.execute("SELECT owner_id FROM secrets WHERE name = ?", (SECRET_NAME,)) as cur:
        rows = await cur.fetchall()
    return {row[0] for row in rows}
