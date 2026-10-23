"""AWS SSM Parameter Store mirror of `warren.secrets.store` for ECS deployments.

warren's own local `secrets` table (store.py) is the single source of truth for
secret names and values on every runtime. On ECS each write/delete is mirrored
to an SSM SecureString parameter so the ECS agent can resolve it at container
start from the task definition's `secrets` ARNs (runtime/ecs.py builds those
from the local store's names, never by listing SSM).

The control plane only ever WRITES SSM: ssm:PutParameter and
ssm:DeleteParameter under /{prefix}/{server_id}/*. It holds no SSM read action
-- ssm:GetParametersByPath can't be limited to WithDecryption=false in IAM, so
holding it would let a compromised control plane decrypt every secret.

Convergence is a durable outbox (the `ssm_outbox` table) rather than listing
SSM. Each change records an outbox row for (owner_id, name) BEFORE the local
write, then pushes to SSM and clears the row. A row means "make this secret's
SSM parameter match the local store": the retry re-reads (and decrypts) the
local row and puts it, or deletes the parameter when there's no local row. The
row never holds a value. Recording it before the local write (instead of in one
transaction, which the shared autocommit connection can't safely do) is safe
because the retry syncs from whatever the local store says, whether the local
write landed or not. Pending rows are retried at startup, periodically, on the
next write, and before a workspace that needs them is provisioned.

Path convention (runtime/ecs.ssm_parameter_name), isolated per owner:
    /{resource_prefix}/{server_id}/{owner_id}/{name}
"""

from __future__ import annotations

import asyncio
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncIterator, Callable, Iterable

import structlog
from warren.runtime.ecs import ssm_parameter_name
from warren_common.errors import ProvisionError

log = structlog.get_logger(__name__)


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _require_segment(label: str, value: str) -> None:
    # An empty, padded or slash-bearing segment would put parameters (and IAM
    # scope) outside this server's own /{prefix}/{server_id}/ subtree.
    if not value or value != value.strip() or "/" in value:
        raise ValueError(f"{label} {value!r} is not a safe SSM path segment")


async def put_secret(
    ssm: Any,
    resource_prefix: str,
    server_id: str,
    owner_id: str,
    name: str,
    value: str,
    kms_key_id: str = "",
) -> None:
    """PutParameter one secret as a Standard-tier SecureString. Standard tier is
    explicit so SSM encrypts with kms:Encrypt only (Advanced tier would need
    kms:GenerateDataKey), whatever the account's default tier is."""
    path = ssm_parameter_name(resource_prefix, server_id, owner_id, name)

    def _put() -> None:
        kwargs: dict[str, Any] = {
            "Name": path,
            "Value": value,
            "Type": "SecureString",
            "Tier": "Standard",
            "Overwrite": True,
        }
        if kms_key_id:
            kwargs["KeyId"] = kms_key_id
        ssm.put_parameter(**kwargs)

    await asyncio.to_thread(_put)


async def delete_secret(
    ssm: Any, resource_prefix: str, server_id: str, owner_id: str, name: str
) -> bool:
    """DeleteParameter one secret; False if it was already gone."""
    path = ssm_parameter_name(resource_prefix, server_id, owner_id, name)

    def _delete() -> bool:
        try:
            ssm.delete_parameter(Name=path)
            return True
        except ssm.exceptions.ParameterNotFound:
            return False

    return await asyncio.to_thread(_delete)


class SsmMirror:
    """Outbox-backed SSM mirror for one server's secrets."""

    def __init__(
        self,
        db: Any,
        cipher: Any,
        ssm_client: Callable[[], Any],
        resource_prefix: str,
        server_id: str,
        kms_key_id: str = "",
    ) -> None:
        _require_segment("resource prefix", resource_prefix)
        _require_segment("server id", server_id)
        self._db = db
        self._cipher = cipher
        self._ssm_client = ssm_client
        self._prefix = resource_prefix
        self._server_id = server_id
        self._kms_key_id = kms_key_id
        self._locks: dict[tuple[str, str], asyncio.Lock] = {}

    @asynccontextmanager
    async def _locked(self, owner_id: str, name: str) -> AsyncIterator[None]:
        # One server process per DB (registry.store.acquire_writer_lock), so an
        # in-process lock serializes record -> local write -> push per secret.
        key = (owner_id, name)
        lock = self._locks.setdefault(key, asyncio.Lock())
        async with lock:
            yield
        if not lock.locked() and self._locks.get(key) is lock:
            self._locks.pop(key, None)

    async def apply(self, owner_id: str, name: str, op: str, mutate: Callable[[], Any]) -> bool:
        """Record the outbox row, run the local `mutate()`, then push to SSM.
        True when SSM is in line; False when the push failed and stays pending.
        A failing `mutate()` raises, leaving a harmless row that re-syncs SSM to
        the unchanged local state."""
        _require_segment("owner id", owner_id)
        async with self._locked(owner_id, name):
            await self._record(owner_id, name, op)
            await mutate()
            return await self._push(owner_id, name)

    async def _record(self, owner_id: str, name: str, op: str) -> None:
        await self._db.execute(
            """
            INSERT INTO ssm_outbox (owner_id, name, op, op_id, created_at, attempts)
            VALUES (?, ?, ?, ?, ?, 0)
            ON CONFLICT(owner_id, name) DO UPDATE SET
                op = excluded.op, op_id = excluded.op_id,
                created_at = excluded.created_at, attempts = 0, last_error = NULL
            """,
            (owner_id, name, op, uuid.uuid4().hex, _utcnow_iso()),
        )

    async def _push(self, owner_id: str, name: str) -> bool:
        from warren.secrets import store as local_store

        async with self._db.execute(
            "SELECT op_id FROM ssm_outbox WHERE owner_id = ? AND name = ?", (owner_id, name)
        ) as cur:
            row = await cur.fetchone()
        if row is None:
            return True
        op_id = row[0]
        try:
            values = await local_store.resolve_secrets_for_names(
                self._db, self._cipher, owner_id, [name]
            )
            ssm = self._ssm_client()
            if name in values:
                await put_secret(
                    ssm, self._prefix, self._server_id, owner_id, name, values[name],
                    kms_key_id=self._kms_key_id,
                )
            else:
                await delete_secret(ssm, self._prefix, self._server_id, owner_id, name)
        except Exception as exc:
            log.warning(
                "secret_ssm_mirror_pending", owner_id=owner_id, name=name,
                error=type(exc).__name__,
            )
            await self._db.execute(
                "UPDATE ssm_outbox SET attempts = attempts + 1, last_error = ? WHERE op_id = ?",
                (type(exc).__name__, op_id),
            )
            return False
        await self._db.execute("DELETE FROM ssm_outbox WHERE op_id = ?", (op_id,))
        return True

    async def pending(
        self, owner_id: str | None = None, names: Iterable[str] | None = None
    ) -> list[tuple[str, str]]:
        sql, args = "SELECT owner_id, name FROM ssm_outbox", []
        if owner_id is not None:
            sql, args = sql + " WHERE owner_id = ?", [owner_id]
        async with self._db.execute(sql + " ORDER BY created_at", args) as cur:
            rows = [(r[0], r[1]) for r in await cur.fetchall()]
        if names is not None:
            wanted = set(names)
            rows = [r for r in rows if r[1] in wanted]
        return rows

    async def flush(
        self, owner_id: str | None = None, names: Iterable[str] | None = None
    ) -> list[tuple[str, str]]:
        """Retry pending rows (optionally one owner's / some names); return what's
        still pending."""
        still: list[tuple[str, str]] = []
        for row_owner, name in await self.pending(owner_id, names):
            async with self._locked(row_owner, name):
                if not await self._push(row_owner, name):
                    still.append((row_owner, name))
        return still

    async def mirrored_names(self, owner_id: str, declared: list[str]) -> list[str]:
        """The declared names this owner has, with their SSM parameter in line.
        Raises ProvisionError rather than launching a task that would get a stale
        or missing value."""
        from warren.secrets import store as local_store

        if not owner_id or not declared:
            return []
        still = await self.flush(owner_id, declared)
        if still:
            raise ProvisionError(
                "secrets not yet mirrored to SSM (retrying in the background): "
                + ", ".join(sorted(name for _, name in still))
            )
        present = await local_store.existing_names(self._db, owner_id, declared)
        return [name for name in declared if name in present]


async def run_outbox_retry(mirror: SsmMirror, interval_seconds: float = 60.0) -> None:
    """Retry pending outbox rows until cancelled."""
    while True:
        await asyncio.sleep(interval_seconds)
        try:
            still = await mirror.flush()
            if still:
                log.warning("secret_ssm_outbox_still_pending", count=len(still))
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("secret_ssm_outbox_retry_failed")
