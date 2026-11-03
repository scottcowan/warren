"""State backend selection (WARREN_STATE_BACKEND, WARREN_SECRETS_BACKEND).

`open_state(settings)` builds every store the server uses behind the interfaces in
`state/protocols.py`. Two independent switches:

- WARREN_STATE_BACKEND=sqlite (default) | dynamodb: registry, launch attempts, EBS
  snapshots and seeds, operations, idle stops, users and tokens.
- WARREN_SECRETS_BACKEND=sqlite (default) | secretsmanager: user secrets.

The SQLite file (and its writer lock) is only opened while either switch is sqlite.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    import aiosqlite

    from warren.state.protocols import (
        AuthStoreProtocol,
        EbsSeedStoreProtocol,
        EbsSnapshotStoreProtocol,
        LaunchAttemptStoreProtocol,
        OperationStoreProtocol,
        SecretStoreProtocol,
        WorkspaceStoreProtocol,
    )


@dataclass
class StateBackend:
    workspaces: "WorkspaceStoreProtocol"
    launch_attempts: "LaunchAttemptStoreProtocol"
    ebs_snapshots: "EbsSnapshotStoreProtocol"
    ebs_seeds: "EbsSeedStoreProtocol"
    operations: "OperationStoreProtocol"
    auth: "AuthStoreProtocol"
    secrets: "SecretStoreProtocol"
    # The SQLite connection, while either backend is sqlite; else None.
    db: "aiosqlite.Connection | None" = None

    async def close(self) -> None:
        if self.db is not None:
            await self.db.close()


def uses_sqlite(settings: Any) -> bool:
    return (
        getattr(settings, "state_backend", "sqlite") == "sqlite"
        or getattr(settings, "secrets_backend", "sqlite") == "sqlite"
    )


def secretsmanager_prefix(settings: Any) -> str:
    """WARREN_SECRETSMANAGER_PREFIX, else `warren/<server_id>`."""
    from warren.state.secretsmanager import encode_component

    return settings.secretsmanager_prefix or f"warren/{encode_component(settings.server_id)}"


def dynamo_table(settings: Any, client: Any = None):
    from warren.state.dynamodb import DynamoTable

    return DynamoTable(settings.dynamodb_table, settings.aws_region, client=client)


def dynamo_stores(table: Any, settings: Any) -> dict[str, Any]:
    from warren.state import dynamodb as d

    return {
        "workspaces": d.DynamoWorkspaceStore(
            table, idle_stop_retention_days=settings.dynamodb_idle_stop_retention_days
        ),
        "launch_attempts": d.DynamoLaunchAttemptStore(table),
        "ebs_snapshots": d.DynamoEbsSnapshotStore(table),
        "ebs_seeds": d.DynamoEbsSeedStore(table),
        "operations": d.DynamoOperationStore(table),
        "auth": d.DynamoAuthStore(table, token_retention_days=settings.dynamodb_token_retention_days),
    }


def secretsmanager_store(settings: Any, client: Any = None):
    from warren.state.secretsmanager import SecretsManagerSecretStore

    return SecretsManagerSecretStore(
        prefix=secretsmanager_prefix(settings),
        server_id=settings.server_id,
        region=settings.aws_region,
        kms_key_id=settings.secretsmanager_kms_key_id,
        force_delete=settings.secretsmanager_force_delete,
        recovery_window_days=settings.secretsmanager_recovery_window_days,
        cache_ttl_s=settings.secretsmanager_cache_ttl_s,
        client=client,
    )


async def open_state(
    settings: Any,
    *,
    db_file: str | Path | None = None,
    dynamodb_client: Any = None,
    secretsmanager_client: Any = None,
) -> StateBackend:
    """Open the configured backends. `db_file` defaults to `<data_dir>/warren.db`; the
    clients are injectable for tests (moto) and default to boto3 in WARREN_AWS_REGION."""
    from warren.auth.store import AuthStore
    from warren.paths import db_path
    from warren.registry.store import (
        EbsSeedStore,
        EbsSnapshotStore,
        LaunchAttemptStore,
        OperationStore,
        WorkspaceStore,
        open_db,
    )
    from warren.secrets.cipher import LocalCipher
    from warren.secrets.store import SqliteSecretStore

    db = None
    if uses_sqlite(settings):
        db = await open_db(
            db_file or db_path(settings), journal_mode=getattr(settings, "sqlite_journal_mode", "auto")
        )
    if settings.state_backend == "dynamodb":
        stores = dynamo_stores(dynamo_table(settings, dynamodb_client), settings)
    else:
        stores = {
            "workspaces": WorkspaceStore(db),
            "launch_attempts": LaunchAttemptStore(db),
            "ebs_snapshots": EbsSnapshotStore(db),
            "ebs_seeds": EbsSeedStore(db),
            "operations": OperationStore(db),
            "auth": AuthStore(db),
        }
    if settings.secrets_backend == "secretsmanager":
        secrets = secretsmanager_store(settings, secretsmanager_client)
    else:
        secrets = SqliteSecretStore(db, LocalCipher(settings.secret_key.get_secret_value()))
    return StateBackend(secrets=secrets, db=db, **stores)
