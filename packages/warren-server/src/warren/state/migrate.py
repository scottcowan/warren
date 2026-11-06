"""`warren-server --migrate-state`: copy an existing deployment's SQLite state into the
configured DynamoDB table and/or Secrets Manager.

- Dry run by default: reports what would be copied. `--apply` writes.
- Idempotent: every item is written only if it isn't there yet (attribute_not_exists;
  a secret only if no secret of that owner and name exists), so a rerun copies nothing
  new and never overwrites state the new backend has since changed. After copying, the
  workspace and admin counters are recomputed from the table.
- Stop the server first: this takes the SQLite writer lock and fails if it is held.
- Never prints secret values or token hashes, only counts.
"""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from pathlib import Path
from typing import Any

from warren.state.dynamodb import (
    _WS_FIELDS,
    DynamoAuthStore,
    DynamoTable,
    _epoch_after,
    recount,
    user_item,
    workspace_item,
)

_ENTITIES = (
    "workspaces", "launch_attempts", "ebs_snapshots", "idle_stops", "ebs_seeds",
    "ebs_seed_repos", "operations", "users", "tokens", "workspace_tokens",
)


async def _rows(db: Any, sql: str) -> list[dict[str, Any]]:
    async with db.execute(sql) as cur:
        cols = [c[0] for c in cur.description]
        return [dict(zip(cols, row, strict=True)) for row in await cur.fetchall()]


async def _dynamo_items(db: Any, settings: Any) -> dict[str, list[list[dict]]]:
    """entity -> one list of items per SQLite row (a token row is three items)."""
    from warren.registry.store import _SEED_COLUMNS, _SEED_REPO_COLUMNS

    auth = DynamoAuthStore(None, token_retention_days=settings.dynamodb_token_retention_days)  # type: ignore[arg-type]
    out: dict[str, list[list[dict]]] = {}
    out["workspaces"] = [
        [workspace_item(r)] for r in await _rows(db, f"SELECT {', '.join(_WS_FIELDS)} FROM workspaces")
    ]
    out["launch_attempts"] = [
        [{"pk": f"WS#{r['workspace_id']}", "sk": "LAUNCH", **r}]
        for r in await _rows(db, "SELECT * FROM ecs_launch_attempts")
    ]
    out["ebs_snapshots"] = [
        [{"pk": f"WS#{r['workspace_id']}", "sk": "EBSSNAP", **r}]
        for r in await _rows(db, "SELECT * FROM ecs_ebs_snapshots")
    ]
    out["idle_stops"] = [
        [{
            "pk": f"WS#{r['workspace_id']}", "sk": "IDLESTOP", "gsi1pk": "IDLESTOPS", "gsi1sk": r["workspace_id"],
            "ttl": _epoch_after(r["stopped_at"], settings.dynamodb_idle_stop_retention_days), **r,
        }]
        for r in await _rows(db, "SELECT workspace_id, stopped_at FROM idle_stops")
    ]
    out["ebs_seeds"] = [
        [{"pk": f"SEED#{r['owner_id']}", "sk": "META", "gsi1pk": "SEEDS", "gsi1sk": r["owner_id"], **r}]
        for r in await _rows(db, f"SELECT {', '.join(_SEED_COLUMNS)} FROM ecs_ebs_seeds")
    ]
    out["ebs_seed_repos"] = [
        [{
            "pk": f"SEED#{r['owner_id']}", "sk": f"REPO#{r['repo_key']}", "gsi1pk": "SEEDREPOS",
            "gsi1sk": f"{r['owner_id']}#{r['repo_key']}", **r,
        }]
        for r in await _rows(db, f"SELECT {', '.join(_SEED_REPO_COLUMNS)} FROM ecs_ebs_seed_repos")
    ]
    out["operations"] = [
        [{"pk": f"OP#{r['principal']}", "sk": f"OP#{r['operation_id']}", **r}]
        for r in await _rows(db, "SELECT * FROM operations")
    ]
    out["users"] = [
        [user_item(r), {"pk": f"USERNAME#{r['username']}", "sk": "META", "user_id": r["user_id"]}]
        for r in await _rows(db, "SELECT user_id, username, is_admin, created_at, disabled_at FROM users")
    ]
    out["tokens"] = [auth.token_items(r) for r in await _rows(db, "SELECT * FROM tokens")]
    out["workspace_tokens"] = [
        auth.workspace_token_items(r) for r in await _rows(db, "SELECT * FROM workspace_tokens")
    ]
    return out


async def migrate_state(
    settings: Any,
    *,
    apply: bool = False,
    sqlite_path: str | Path | None = None,
    dynamodb_client: Any = None,
    secretsmanager_client: Any = None,
    echo: Callable[[str], None] = print,
) -> dict[str, dict[str, int]]:
    """Copy SQLite -> the configured non-default backends. Returns, per entity,
    {"copied": n, "present": m} (with apply=False, "copied" counts what would be)."""
    from warren.paths import db_path
    from warren.registry.store import acquire_writer_lock, open_db
    from warren.secrets.cipher import LocalCipher
    from warren.state import dynamo_table, secretsmanager_store

    to_dynamo = settings.state_backend == "dynamodb"
    to_sm = settings.secrets_backend == "secretsmanager"
    if not (to_dynamo or to_sm):
        raise ValueError(
            "nothing to migrate to: set WARREN_STATE_BACKEND=dynamodb and/or "
            "WARREN_SECRETS_BACKEND=secretsmanager (plus their settings) first"
        )
    source = Path(sqlite_path) if sqlite_path else db_path(settings)
    if not source.exists():
        raise FileNotFoundError(f"no SQLite database at {source}")

    lock = await asyncio.to_thread(acquire_writer_lock, source, 0.0)
    db = await open_db(source)
    summary: dict[str, dict[str, int]] = {}
    try:
        if to_dynamo:
            table: DynamoTable = dynamo_table(settings, dynamodb_client)
            for entity, rows in (await _dynamo_items(db, settings)).items():
                copied = present = 0
                for items in rows:
                    if await table.get(items[0]["pk"], items[0]["sk"]) is not None:
                        present += 1
                        continue
                    copied += 1
                    if apply:
                        for item in items:
                            await table.put(item, condition="attribute_not_exists(pk)")
                summary[entity] = {"copied": copied, "present": present}
            if apply:
                await recount(table)
        if to_sm:
            store = secretsmanager_store(settings, secretsmanager_client)
            cipher = LocalCipher(settings.secret_key.get_secret_value())
            copied = present = 0
            for row in await _rows(db, "SELECT owner_id, name, ciphertext FROM secrets ORDER BY owner_id, name"):
                if await store.exists(row["owner_id"], row["name"]):
                    present += 1
                    continue
                copied += 1
                if apply:
                    await store.set(row["owner_id"], row["name"], cipher.decrypt(row["ciphertext"]))
            summary["secrets"] = {"copied": copied, "present": present}
    finally:
        await db.close()
        lock.release()

    verb = "copied" if apply else "would copy"
    echo(f"{'Migrated' if apply else 'Dry run (pass --apply to write)'}: {source}")
    for entity, counts in summary.items():
        echo(f"  {entity:<17} {verb} {counts['copied']:>6}, already present {counts['present']:>6}")
    return summary


__all__ = ["migrate_state", "_ENTITIES"]
