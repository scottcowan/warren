"""Backend-parametrised store fixtures (warren/state/).

`workspace_store`, `auth_store`, `launch_store`, `snapshot_store`, `seed_store`,
`operation_store` and `run_store` run each test against SQLite and against DynamoDB
under moto;
`secret_store` against SQLite + Fernet and against Secrets Manager under moto. moto
intercepts every AWS call in-process: nothing here reaches AWS.
"""

from __future__ import annotations

import pytest

from warren.secrets.cipher import LocalCipher

TABLE = "warren-test-state"
REGION = "us-east-1"


@pytest.fixture
def moto_aws(monkeypatch):
    """moto's in-process AWS, with dummy credentials (never the host's)."""
    from moto import mock_aws

    for var in ("AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_SECURITY_TOKEN"):
        monkeypatch.setenv(var, "testing")
    monkeypatch.setenv("AWS_DEFAULT_REGION", REGION)
    for var in ("AWS_PROFILE", "AWS_ENDPOINT_URL", "AWS_ENDPOINT_URL_DYNAMODB", "AWS_ENDPOINT_URL_SECRETS_MANAGER"):
        monkeypatch.delenv(var, raising=False)
    with mock_aws():
        yield


@pytest.fixture
def dynamo_table(moto_aws):
    """An empty table shaped like the reference IaC's (pk/sk, gsi1, TTL on `ttl`)."""
    import boto3

    from warren.state.dynamodb import DynamoTable, create_table_kwargs

    client = boto3.Session(region_name=REGION).resource("dynamodb").meta.client
    client.create_table(**create_table_kwargs(TABLE))
    client.update_time_to_live(
        TableName=TABLE, TimeToLiveSpecification={"Enabled": True, "AttributeName": "ttl"}
    )
    return DynamoTable(TABLE, REGION, client=_AtomicRequests(client))


class _AtomicRequests:
    """DynamoDB evaluates each request's condition atomically; moto, called from several
    threads at once, doesn't. One lock per client restores per-request atomicity, so the
    racing tests exercise warren's conditions rather than moto's thread safety."""

    def __init__(self, client) -> None:
        import threading

        self._client = client
        self._lock = threading.Lock()

    def __getattr__(self, name):
        attr = getattr(self._client, name)
        if not callable(attr):
            return attr

        def call(*args, **kwargs):
            with self._lock:
                return attr(*args, **kwargs)

        return call


@pytest.fixture
def sm_client(moto_aws):
    import boto3

    return boto3.Session(region_name=REGION).client("secretsmanager")

@pytest.fixture(params=["sqlite", "dynamodb"])
def state_backend(request) -> str:
    return request.param


@pytest.fixture
async def _stores(state_backend, request, sqlite_path):
    """name -> store, for the parametrised backend."""
    if state_backend == "dynamodb":
        from types import SimpleNamespace

        from warren.state import dynamo_stores

        table = request.getfixturevalue("dynamo_table")
        settings = SimpleNamespace(dynamodb_idle_stop_retention_days=90.0, dynamodb_token_retention_days=30.0)
        yield dynamo_stores(table, settings)
        return
    from warren.auth.store import AuthStore
    from warren.registry.runs import RunStore
    from warren.registry.store import (
        EbsSeedStore,
        EbsSnapshotStore,
        LaunchAttemptStore,
        OperationStore,
        WorkspaceStore,
        open_db,
    )

    db = await open_db(sqlite_path)
    yield {
        "workspaces": WorkspaceStore(db),
        "launch_attempts": LaunchAttemptStore(db),
        "ebs_snapshots": EbsSnapshotStore(db),
        "ebs_seeds": EbsSeedStore(db),
        "operations": OperationStore(db),
        "auth": AuthStore(db),
        "runs": RunStore(db),
    }
    await db.close()


@pytest.fixture
def workspace_store(_stores):
    return _stores["workspaces"]


@pytest.fixture
def auth_store(_stores):
    return _stores["auth"]


@pytest.fixture
def launch_store(_stores):
    return _stores["launch_attempts"]


@pytest.fixture
def snapshot_store(_stores):
    return _stores["ebs_snapshots"]


@pytest.fixture
def seed_store(_stores):
    return _stores["ebs_seeds"]


@pytest.fixture
def operation_store(_stores):
    return _stores["operations"]


@pytest.fixture
def run_store(_stores):
    return _stores["runs"]


@pytest.fixture(params=["sqlite", "secretsmanager"])
async def secret_store(request, sqlite_path):
    if request.param == "secretsmanager":
        from warren.state.secretsmanager import SecretsManagerSecretStore

        client = request.getfixturevalue("sm_client")
        yield SecretsManagerSecretStore(
            prefix="warren/test-server", server_id="test-server", region=REGION, client=client
        )
        return
    from warren.registry.store import open_db
    from warren.secrets.store import SqliteSecretStore

    db = await open_db(sqlite_path)
    yield SqliteSecretStore(db, LocalCipher("test-secret-key-" + "x" * 32))
    await db.close()
