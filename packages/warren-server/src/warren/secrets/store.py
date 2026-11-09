"""Local (Podman/Docker) secret store — CRUD against the shared SQLite `secrets` table.

Keyed by (owner_id, name) — isolated per-owner (see schema.sql's comment on the
`secrets` table): every operation here is scoped to one caller's own `owner_id`,
never another user's. Values are Fernet-encrypted (`cipher.py`) before ever
reaching this module's INSERT statements; nothing here ever writes or logs
plaintext.

There is no permission-tier concept here (removed 2026-10-13 — tiers gated
which secrets a workspace could see in a way that silently starved
readonly-permission templates of secrets like WARREN_GIT_SSH_KEY/GITHUB_PAT
needed just to clone repos, for no real security benefit since every secret
was already owner-isolated regardless of tier). Instead, which secrets a given
workspace gets is an explicit allow-list by name: each template declares the
secret names it needs (ProjectConfig.secrets), and resolve_secrets_for_names
below resolves exactly that list, nothing more, against the caller's own
secrets.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import TYPE_CHECKING

import aiosqlite

from warren.secrets.cipher import LocalCipher

if TYPE_CHECKING:
    from warren.state.protocols import SecretStoreProtocol


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


async def set_secret(
    db: aiosqlite.Connection,
    cipher: LocalCipher,
    owner_id: str,
    name: str,
    value: str,
) -> None:
    ciphertext = cipher.encrypt(value)
    now = _utcnow_iso()
    await db.execute(
        """
        INSERT INTO secrets (secret_id, owner_id, name, ciphertext, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?, ?)
        ON CONFLICT(owner_id, name) DO UPDATE SET
            ciphertext = excluded.ciphertext,
            updated_at = excluded.updated_at
        """,
        (str(uuid.uuid4()), owner_id, name, ciphertext, now, now),
    )


async def reencrypt_secret(
    db: aiosqlite.Connection, cipher: LocalCipher, owner_id: str, name: str
) -> bool:
    """Re-encrypt one stored ciphertext under the cipher's current key, without
    the plaintext ever leaving the cipher. False if the secret doesn't exist."""
    async with db.execute(
        "SELECT ciphertext FROM secrets WHERE owner_id = ? AND name = ?",
        (owner_id, name),
    ) as cur:
        row = await cur.fetchone()
    if row is None:
        return False
    await db.execute(
        "UPDATE secrets SET ciphertext = ?, updated_at = ? WHERE owner_id = ? AND name = ?",
        (cipher.rotate(row[0]), _utcnow_iso(), owner_id, name),
    )
    return True


async def secret_exists(db: aiosqlite.Connection, owner_id: str, name: str) -> bool:
    async with db.execute(
        "SELECT 1 FROM secrets WHERE owner_id = ? AND name = ?",
        (owner_id, name),
    ) as cur:
        return await cur.fetchone() is not None


async def delete_secret(db: aiosqlite.Connection, owner_id: str, name: str) -> bool:
    cur = await db.execute(
        "DELETE FROM secrets WHERE owner_id = ? AND name = ?",
        (owner_id, name),
    )
    return cur.rowcount > 0


async def list_secrets(db: aiosqlite.Connection, owner_id: str) -> list[dict[str, str]]:
    """Return [{"name", "created_at", "updated_at"}] for `owner_id`'s own
    secrets only — never values, never another owner's rows."""
    async with db.execute(
        "SELECT name, created_at, updated_at FROM secrets WHERE owner_id = ? ORDER BY name",
        (owner_id,),
    ) as cur:
        rows = await cur.fetchall()
    return [{"name": row[0], "created_at": row[1], "updated_at": row[2]} for row in rows]



async def resolve_secrets_for_names(
    db: aiosqlite.Connection, cipher: LocalCipher, owner_id: str, names: list[str]
) -> dict[str, str]:
    """Return {name: decrypted_value} for exactly the named secrets among
    `owner_id`'s own — never another owner's, and never a secret not in `names`
    even if the owner has it. An empty `names` list (a template declaring no
    secrets) resolves to no secrets at all, not "all of them"."""
    if not names:
        return {}
    placeholders = ",".join("?" for _ in names)
    async with db.execute(
        f"SELECT name, ciphertext FROM secrets WHERE owner_id = ? AND name IN ({placeholders})",
        (owner_id, *names),
    ) as cur:
        rows = await cur.fetchall()
    return {name: cipher.decrypt(ciphertext) for name, ciphertext in rows}


class SqliteSecretStore:
    """`SecretStoreProtocol` (state/protocols.py) over the functions above: the default
    WARREN_SECRETS_BACKEND=sqlite, Fernet-encrypted rows in the shared database."""

    def __init__(self, db: aiosqlite.Connection, cipher: LocalCipher) -> None:
        self._db = db
        self._cipher = cipher

    async def set(self, owner_id: str, name: str, value: str) -> None:
        await set_secret(self._db, self._cipher, owner_id, name, value)

    async def exists(self, owner_id: str, name: str) -> bool:
        return await secret_exists(self._db, owner_id, name)

    async def delete(self, owner_id: str, name: str) -> bool:
        return await delete_secret(self._db, owner_id, name)

    async def list(self, owner_id: str) -> list[dict[str, str]]:
        return await list_secrets(self._db, owner_id)

    async def resolve(self, owner_id: str, names: list[str]) -> dict[str, str]:
        return await resolve_secrets_for_names(self._db, self._cipher, owner_id, names)

    async def reencrypt(self, owner_id: str, name: str) -> bool:
        return await reencrypt_secret(self._db, self._cipher, owner_id, name)

    async def count(self) -> int:
        async with self._db.execute("SELECT COUNT(*) FROM secrets") as cur:
            row = await cur.fetchone()
        return int(row[0])

    async def owners_with(self, name: str) -> set[str]:
        async with self._db.execute("SELECT owner_id FROM secrets WHERE name = ?", (name,)) as cur:
            rows = await cur.fetchall()
        return {row[0] for row in rows}


def secret_store_from_state(state: object) -> "SecretStoreProtocol":
    """The app's secret store: `app.state.secret_store` when lifespan wired one, else
    (tests that only set `db`/`settings`) the SQLite store over `app.state.db`."""
    store = getattr(state, "secret_store", None)
    # A SQLite store always follows app.state.db (tests swap the connection).
    if store is not None and not (
        isinstance(store, SqliteSecretStore) and store._db is not getattr(state, "db", None)
    ):
        return store
    settings = getattr(state, "settings")
    return SqliteSecretStore(getattr(state, "db"), LocalCipher(settings.secret_key.get_secret_value()))
