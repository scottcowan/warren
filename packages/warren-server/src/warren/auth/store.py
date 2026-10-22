"""aiosqlite-backed AuthStore over the users/tokens tables, mirroring WorkspaceStore."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from pathlib import Path

import aiosqlite
from warren.auth.models import Token, User, WorkspaceToken
from warren.registry.store import open_db


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row_to_user(row: aiosqlite.Row | tuple) -> User:
    user_id, username, is_admin, created_at, disabled_at = row
    return User(
        user_id=user_id,
        username=username,
        is_admin=bool(is_admin),
        created_at=datetime.fromisoformat(created_at),
        disabled_at=datetime.fromisoformat(disabled_at) if disabled_at else None,
    )


def _row_to_token(row: aiosqlite.Row | tuple) -> Token:
    token_id, user_id, created_at, expires_at, revoked_at, created_by_token_id = row
    return Token(
        token_id=token_id,
        user_id=user_id,
        created_at=datetime.fromisoformat(created_at),
        expires_at=datetime.fromisoformat(expires_at) if expires_at else None,
        revoked_at=datetime.fromisoformat(revoked_at) if revoked_at else None,
        created_by_token_id=created_by_token_id,
    )


class AuthStore:
    """CRUD wrapper around the users/tokens tables."""

    def __init__(self, db: aiosqlite.Connection) -> None:
        self._db = db

    @classmethod
    async def open(cls, path: str | Path) -> "AuthStore":
        db = await open_db(path)
        return cls(db)

    async def close(self) -> None:
        await self._db.close()

    async def create_user(self, *, username: str, is_admin: bool) -> User:
        user_id = uuid.uuid4().hex
        now = _utcnow_iso()
        await self._db.execute(
            """
            INSERT INTO users (user_id, username, is_admin, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (user_id, username, 1 if is_admin else 0, now),
        )
        return User(user_id=user_id, username=username, is_admin=is_admin, created_at=datetime.fromisoformat(now))

    async def get_user(self, user_id: str) -> User | None:
        async with self._db.execute(
            "SELECT user_id, username, is_admin, created_at, disabled_at FROM users WHERE user_id = ?",
            (user_id,),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        return _row_to_user(row)

    async def get_user_by_username(self, username: str) -> User | None:
        async with self._db.execute(
            "SELECT user_id, username, is_admin, created_at, disabled_at FROM users WHERE username = ?",
            (username,),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        return _row_to_user(row)

    async def list_users(self) -> list[User]:
        async with self._db.execute(
            "SELECT user_id, username, is_admin, created_at, disabled_at FROM users ORDER BY created_at"
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_user(r) for r in rows]

    async def disable_user(self, user_id: str) -> bool:
        """Mark a user disabled (idempotent-safe: re-disabling an already-disabled user
        is a no-op that still returns True as long as the user exists).

        Returns False only if user_id doesn't exist. Does not itself revoke the user's
        existing tokens -- callers that want "disable implies logout" should also call
        `revoke_all_tokens_for_user` (routes/admin.py's disable route does exactly this).
        """
        user = await self.get_user(user_id)
        if user is None:
            return False
        if user.disabled_at is None:
            await self._db.execute(
                "UPDATE users SET disabled_at = ? WHERE user_id = ?",
                (_utcnow_iso(), user_id),
            )
        return True

    async def enable_user(self, user_id: str) -> bool:
        """Clear a user's disabled_at (idempotent: re-enabling an already-enabled
        user is a no-op that still returns True as long as the user exists).

        Audit R9/S9: added alongside recover_admin_token's new `reenable` option
        -- without this, a disabled last-admin was a PERMANENT lockout: recovery
        could mint a token for them, but the token would never authenticate
        (auth middleware rejects disabled users), and count_admins() counting
        disabled admins too meant re-bootstrap stayed permanently skipped.
        Returns False only if user_id doesn't exist.
        """
        user = await self.get_user(user_id)
        if user is None:
            return False
        if user.disabled_at is not None:
            await self._db.execute(
                "UPDATE users SET disabled_at = NULL WHERE user_id = ?",
                (user_id,),
            )
        return True

    async def count_admins(self) -> int:
        async with self._db.execute(
            "SELECT COUNT(*) FROM users WHERE is_admin = 1"
        ) as cur:
            row = await cur.fetchone()
        return int(row[0])

    async def count_enabled_admins(self) -> int:
        """Like count_admins(), but excludes disabled admins -- used by the
        disable route's last-admin guard (audit V5). count_admins() itself
        stays unchanged (it only gates ensure_bootstrap_admin's
        never-re-bootstrap-once-any-admin-row-exists decision, which is
        deliberately indifferent to disabled_at -- recovery goes through
        `warren-server recover-admin --reenable`, not automatic
        re-bootstrap)."""
        async with self._db.execute(
            "SELECT COUNT(*) FROM users WHERE is_admin = 1 AND disabled_at IS NULL"
        ) as cur:
            row = await cur.fetchone()
        return int(row[0])

    async def list_admins(self) -> list[User]:
        """Return every admin user, enabled or not (audit #44 admin recovery path --
        `warren-server recover-admin` needs to find a target even for a disabled admin,
        since re-enabling and recovering are separate concerns)."""
        async with self._db.execute(
            "SELECT user_id, username, is_admin, created_at, disabled_at "
            "FROM users WHERE is_admin = 1 ORDER BY created_at"
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_user(r) for r in rows]

    async def create_token(
        self,
        *,
        user_id: str,
        hashed_token: str,
        expires_at: datetime | None = None,
        created_by_token_id: str | None = None,
    ) -> Token:
        token_id = uuid.uuid4().hex
        now = _utcnow_iso()
        expires_at_iso = expires_at.isoformat() if expires_at else None
        await self._db.execute(
            """
            INSERT INTO tokens (
                token_id, user_id, hashed_token, created_at, expires_at, revoked_at,
                created_by_token_id
            )
            VALUES (?, ?, ?, ?, ?, NULL, ?)
            """,
            (token_id, user_id, hashed_token, now, expires_at_iso, created_by_token_id),
        )
        return Token(
            token_id=token_id,
            user_id=user_id,
            created_at=datetime.fromisoformat(now),
            expires_at=expires_at,
            revoked_at=None,
            created_by_token_id=created_by_token_id,
        )

    async def list_tokens_for_user(self, user_id: str) -> list[Token]:
        async with self._db.execute(
            "SELECT token_id, user_id, created_at, expires_at, revoked_at, created_by_token_id "
            "FROM tokens WHERE user_id = ? ORDER BY created_at",
            (user_id,),
        ) as cur:
            rows = await cur.fetchall()
        return [_row_to_token(r) for r in rows]

    async def count_active_tokens_for_user(self, user_id: str) -> int:
        """Count this user's live tokens: not revoked, not expired.

        Used to enforce the per-user token cap (Issue #11) at mint time -- a revoked or
        expired token frees up room for a new one.
        """
        async with self._db.execute(
            """
            SELECT COUNT(*) FROM tokens
            WHERE user_id = ?
              AND revoked_at IS NULL
              AND (expires_at IS NULL OR expires_at > ?)
            """,
            (user_id, _utcnow_iso()),
        ) as cur:
            row = await cur.fetchone()
        return int(row[0])

    async def revoke_all_tokens_for_user(self, user_id: str) -> int:
        """Revoke every live (non-revoked) token for a user. Returns the number revoked."""
        cursor = await self._db.execute(
            "UPDATE tokens SET revoked_at = ? WHERE user_id = ? AND revoked_at IS NULL",
            (_utcnow_iso(), user_id),
        )
        return cursor.rowcount

    async def get_active_user_by_hashed_token(self, hashed_token: str) -> User | None:
        result = await self.get_active_user_and_token_id_by_hashed_token(hashed_token)
        return result[0] if result else None

    async def get_active_user_and_token_id_by_hashed_token(
        self, hashed_token: str
    ) -> tuple[User, str] | None:
        """Like `get_active_user_by_hashed_token`, but also returns the resolved token's
        id -- callers that mint further tokens (routes/tokens.py, routes/admin.py) use it
        to stamp `created_by_token_id` provenance on the new token.

        # SQL equality (not hmac.compare_digest) on the lookup is intentional here: hashed_token
        # is an HMAC-SHA256 digest of the raw bearer token (see auth/tokens.py hash_token), not
        # the raw secret itself. A timing side-channel on this comparison would at most let an
        # attacker infer bytes of a value that is already a one-way function of a 256-bit random
        # token — it does not shortcut forging a valid token, and comparing byte-for-byte in
        # constant time here would require abandoning the indexed equality lookup for a full
        # table scan. Not worth that trade for this threat model.
        """
        async with self._db.execute(
            """
            SELECT u.user_id, u.username, u.is_admin, u.created_at, u.disabled_at, t.token_id
            FROM tokens t
            JOIN users u ON u.user_id = t.user_id
            WHERE t.hashed_token = ?
              AND t.revoked_at IS NULL
              AND (t.expires_at IS NULL OR t.expires_at > ?)
              AND u.disabled_at IS NULL
            """,
            (hashed_token, _utcnow_iso()),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        *user_fields, token_id = row
        return _row_to_user(tuple(user_fields)), token_id

    async def get_token(self, token_id: str) -> Token | None:
        async with self._db.execute(
            "SELECT token_id, user_id, created_at, expires_at, revoked_at, created_by_token_id "
            "FROM tokens WHERE token_id = ?",
            (token_id,),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        return _row_to_token(row)

    async def revoke_token(self, token_id: str) -> bool:
        cursor = await self._db.execute(
            "UPDATE tokens SET revoked_at = ? WHERE token_id = ? AND revoked_at IS NULL",
            (_utcnow_iso(), token_id),
        )
        return cursor.rowcount == 1

    async def create_workspace_token(
        self,
        *,
        workspace_id: str,
        user_id: str,
        hashed_token: str,
        expires_at: datetime,
        public_key: str | None = None,
        created_by_token_id: str | None = None,
        provision_grant: bool = False,
    ) -> WorkspaceToken:
        token_id = uuid.uuid4().hex
        now = _utcnow_iso()
        await self._db.execute(
            """
            INSERT INTO workspace_tokens (
                token_id, workspace_id, user_id, hashed_token, public_key,
                created_at, expires_at, revoked_at, created_by_token_id, provision_grant
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, NULL, ?, ?)
            """,
            (
                token_id,
                workspace_id,
                user_id,
                hashed_token,
                public_key,
                now,
                expires_at.isoformat(),
                created_by_token_id,
                int(provision_grant),
            ),
        )
        return WorkspaceToken(
            token_id=token_id,
            workspace_id=workspace_id,
            user_id=user_id,
            created_at=datetime.fromisoformat(now),
            expires_at=expires_at,
            public_key=public_key,
            created_by_token_id=created_by_token_id,
            provision_grant=provision_grant,
        )

    async def get_active_workspace_token(
        self, hashed_token: str
    ) -> tuple[User, WorkspaceToken] | None:
        """Live only while the token is unrevoked and unexpired and its user enabled, and
        its workspace exists, is still owned by the token's user and isn't destroyed --
        except (AI8/AJ2) an unprovisioned reservation, and a single-turn workspace that
        completed (destroyed with its verdict retained), which the token may still read."""
        async with self._db.execute(
            """
            SELECT u.user_id, u.username, u.is_admin, u.created_at, u.disabled_at,
                   t.token_id, t.workspace_id, t.created_at, t.expires_at,
                   t.public_key, t.created_by_token_id, t.provision_grant, w.status
            FROM workspace_tokens t
            JOIN users u ON u.user_id = t.user_id
            LEFT JOIN workspaces w ON w.workspace_id = t.workspace_id
            WHERE t.hashed_token = ?
              AND t.revoked_at IS NULL
              AND t.expires_at > ?
              AND u.disabled_at IS NULL
              AND (
                (w.workspace_id IS NULL AND t.provision_grant = 1)
                OR (
                  w.owner_id = t.user_id
                  AND (
                    w.status != 'destroyed'
                    OR json_extract(w.spec_json, '$.mode') = 'single-turn'
                  )
                )
              )
            """,
            (hashed_token, _utcnow_iso()),
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return None
        user = _row_to_user(tuple(row[:5]))
        token_id, workspace_id, created_at, expires_at, public_key, created_by, grant, status = row[5:]
        return user, WorkspaceToken(
            token_id=token_id,
            workspace_id=workspace_id,
            user_id=user.user_id,
            created_at=datetime.fromisoformat(created_at),
            expires_at=datetime.fromisoformat(expires_at),
            public_key=public_key,
            created_by_token_id=created_by,
            provision_grant=bool(grant),
            workspace_status=status,
        )

    async def consume_provision_grant(self, token_id: str) -> bool:
        """AI8/AJ2: atomically spend a reservation token's one provision."""
        cursor = await self._db.execute(
            "UPDATE workspace_tokens SET provision_grant = 0 "
            "WHERE token_id = ? AND provision_grant = 1 AND revoked_at IS NULL",
            (token_id,),
        )
        return cursor.rowcount == 1

    async def revoke_workspace_tokens(self, workspace_id: str, *, keep_token_id: str | None = None) -> int:
        cursor = await self._db.execute(
            "UPDATE workspace_tokens SET revoked_at = ? "
            "WHERE workspace_id = ? AND revoked_at IS NULL AND token_id IS NOT ?",
            (_utcnow_iso(), workspace_id, keep_token_id),
        )
        return cursor.rowcount
