"""`warren-server --migrate-state`: SQLite -> DynamoDB + Secrets Manager (moto)."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from pydantic import SecretStr

from warren.auth.store import AuthStore
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
from warren.state import dynamo_stores, secretsmanager_store
from warren.state.migrate import migrate_state

KEY = "k" * 40


def _settings(table: str, **overrides) -> SimpleNamespace:
    base = dict(
        state_backend="dynamodb", secrets_backend="secretsmanager", dynamodb_table=table,
        aws_region="us-east-1", secret_key=SecretStr(KEY), server_id="warren-prod",
        secretsmanager_prefix="warren/prod", secretsmanager_kms_key_id="", secretsmanager_force_delete=False,
        secretsmanager_recovery_window_days=7, secretsmanager_cache_ttl_s=0.0,
        dynamodb_token_retention_days=30.0, dynamodb_idle_stop_retention_days=90.0,
    )
    return SimpleNamespace(**{**base, **overrides})


@pytest.fixture
async def populated(tmp_path):
    path = tmp_path / "warren.db"
    db = await open_db(path)
    auth = AuthStore(db)
    admin = await auth.create_user(username="admin", is_admin=True)
    alice = await auth.create_user(username="alice", is_admin=False)
    await auth.disable_user(alice.user_id)
    expires = datetime.now(timezone.utc) + timedelta(days=90)
    tok = await auth.create_token(user_id=admin.user_id, hashed_token="hash-admin", expires_at=expires)
    ws = WorkspaceStore(db)
    await ws.insert(workspace_id="ws-1", project="p", intent="i", image="img", root_path="", server_instance="s1",
                    status="running", owner_id=admin.user_id, labels={"a": "b"}, idle_ttl_seconds=60.0, spec_json="{}")
    await ws.insert(workspace_id="ws-2", project="p", intent="i", image="img", root_path="", server_instance="s1",
                    status="destroyed", owner_id=admin.user_id)
    await ws.mark_idle_stopped("ws-2")
    await ws.update_host_ports("ws-1", {"t3": {"host": "127.0.0.1", "port": 41234}})
    from warren.registry.runs import RunStore

    run_store = RunStore(db)
    started = datetime(2026, 11, 1, 12, 0, tzinfo=timezone.utc)
    await run_store.create(run_id="ws-2", owner_id=admin.user_id, project="p", template="t",
                           timeout_seconds=90.0, started_at=started)
    await run_store.finish("ws-2", status="succeeded", result={"schema": "warren.run.result/v1", "exit_code": 0},
                           ended_at=started + timedelta(seconds=30))
    await run_store.create(run_id="ws-1", owner_id=admin.user_id, project="p", template="t",
                           timeout_seconds=None, started_at=started + timedelta(minutes=1))
    await auth.create_workspace_token(workspace_id="ws-1", user_id=admin.user_id, hashed_token="wh", expires_at=expires)
    await LaunchAttemptStore(db).put("ws-1", {"generation": "g", "fingerprint": "f", "task_definition_arn": "arn", "client_token": "ct"})
    await EbsSnapshotStore(db).put("ws-1", "snap-1")
    seeds = EbsSeedStore(db)
    await seeds.update_seed(admin.user_id, snapshot_id="seed-snap", size_gib=10)
    await seeds.put_repo(admin.user_id, {"repo_key": "r", "url": "u", "kind": "github", "cred_kind": "pat",
                                          "cred_secret": "PAT", "branches": ["main"], "last_used_at": "2026-11-01"})
    await OperationStore(db).create(principal="p", operation_id="op", kind="k", request_hash="h", workspace_id="ws-1")
    secrets = SqliteSecretStore(db, LocalCipher(KEY))
    await secrets.set(admin.user_id, "API_KEY", "sk-admin")
    await secrets.set("arn:aws:iam::1:role/x", "GITHUB_PAT", "ghp-1")
    await db.close()
    return SimpleNamespace(path=path, admin=admin, alice=alice, token=tok)


async def test_dry_run_writes_nothing(populated, dynamo_table, sm_client):
    out: list[str] = []
    summary = await migrate_state(
        _settings(dynamo_table.name), sqlite_path=populated.path, dynamodb_client=dynamo_table.client,
        secretsmanager_client=sm_client, echo=out.append,
    )
    assert summary["workspaces"] == {"copied": 2, "present": 0}
    assert summary["users"]["copied"] == 2 and summary["tokens"]["copied"] == 1
    assert summary["runs"] == {"copied": 2, "present": 0}
    assert summary["secrets"] == {"copied": 2, "present": 0}
    assert await dynamo_table.scan() == []
    assert sm_client.list_secrets()["SecretList"] == []
    assert out[0].startswith("Dry run")
    text = "\n".join(out)
    assert "sk-admin" not in text and "hash-admin" not in text


async def test_apply_copies_everything_and_is_idempotent(populated, dynamo_table, sm_client):
    settings = _settings(dynamo_table.name)
    kwargs = dict(sqlite_path=populated.path, dynamodb_client=dynamo_table.client, secretsmanager_client=sm_client,
                  echo=lambda _line: None)
    await migrate_state(settings, apply=True, **kwargs)
    stores = dynamo_stores(dynamo_table, settings)

    # Auth: the same token hash authenticates (same WARREN_SECRET_KEY pepper).
    user, token_id = await stores["auth"].get_active_user_and_token_id_by_hashed_token("hash-admin")
    assert (user.user_id, token_id) == (populated.admin.user_id, populated.token.token_id)
    assert (await stores["auth"].get_user_by_username("alice")).disabled_at is not None
    assert await stores["auth"].count_admins() == 1 and await stores["auth"].count_enabled_admins() == 1
    assert (await stores["auth"].get_active_workspace_token("wh"))[1].workspace_id == "ws-1"

    # Registry and the rest.
    ws1 = await stores["workspaces"].get("ws-1")
    assert (ws1.status, ws1.labels, ws1.idle_ttl_seconds, ws1.spec_json) == ("running", {"a": "b"}, 60.0, "{}")
    assert [w.workspace_id for w in await stores["workspaces"].list_non_terminal()] == ["ws-1"]
    assert [w for w, _ in await stores["workspaces"].list_idle_stopped()] == ["ws-2"]
    assert (await stores["launch_attempts"].get("ws-1"))["client_token"] == "ct"
    assert await stores["ebs_snapshots"].get("ws-1") == "snap-1"
    assert (await stores["ebs_seeds"].get_seed(populated.admin.user_id))["size_gib"] == 10
    assert (await stores["ebs_seeds"].repos(populated.admin.user_id))[0]["branches"] == ["main"]
    assert (await stores["operations"].get("p", "op"))["workspace_id"] == "ws-1"
    assert ws1.host_ports_json is not None and "41234" in ws1.host_ports_json

    # Headless runs (#72): finished and running, newest first, result intact.
    runs = await stores["runs"].list(populated.admin.user_id)
    assert [(r["run_id"], r["status"]) for r in runs] == [("ws-1", "running"), ("ws-2", "succeeded")]
    assert runs[1]["result"] == {"schema": "warren.run.result/v1", "exit_code": 0}
    assert runs[1]["timeout_seconds"] == 90.0 and runs[1]["ended_at"] == "2026-11-01T12:00:30Z"
    assert runs[0]["timeout_seconds"] is None and runs[0]["result"] is None

    # Counters were rebuilt: the cap sees the migrated live workspace.
    from warren.registry.store import CapacityExhausted

    with pytest.raises(CapacityExhausted):
        await stores["workspaces"].insert(workspace_id="ws-3", project="p", intent="i", image="img", root_path="",
                                          server_instance="s1", status="provisioning", max_total=1)

    # Secrets: decrypted from Fernet, stored as plain SecretString under the prefix.
    sm = secretsmanager_store(settings, sm_client)
    assert await sm.resolve(populated.admin.user_id, ["API_KEY"]) == {"API_KEY": "sk-admin"}
    assert await sm.resolve("arn:aws:iam::1:role/x", ["GITHUB_PAT"]) == {"GITHUB_PAT": "ghp-1"}

    # Rerun: nothing new, and state changed since is not overwritten.
    await stores["workspaces"].update_status("ws-1", "stopped")
    await sm.set(populated.admin.user_id, "API_KEY", "rotated")
    again = await migrate_state(settings, apply=True, **kwargs)
    assert all(c["copied"] == 0 for c in again.values())
    assert (await stores["workspaces"].get("ws-1")).status == "stopped"
    assert await sm.resolve(populated.admin.user_id, ["API_KEY"]) == {"API_KEY": "rotated"}


async def test_only_secrets(populated, sm_client):
    settings = _settings("unused", state_backend="sqlite")
    summary = await migrate_state(settings, apply=True, sqlite_path=populated.path, secretsmanager_client=sm_client,
                                  echo=lambda _line: None)
    assert list(summary) == ["secrets"]


async def test_refuses_without_a_target_or_source(tmp_path, populated):
    with pytest.raises(ValueError, match="nothing to migrate"):
        await migrate_state(_settings("t", state_backend="sqlite", secrets_backend="sqlite"), sqlite_path=populated.path)
    with pytest.raises(FileNotFoundError):
        await migrate_state(_settings("t"), sqlite_path=tmp_path / "missing.db")


async def test_refuses_while_a_server_holds_the_writer_lock(populated, dynamo_table):
    from warren.registry.store import WriterLockHeld, acquire_writer_lock

    lock = acquire_writer_lock(populated.path)
    try:
        with pytest.raises(WriterLockHeld):
            await migrate_state(_settings(dynamo_table.name), sqlite_path=populated.path,
                                dynamodb_client=dynamo_table.client)
    finally:
        lock.release()


def test_cli_flag_runs_the_migration(monkeypatch, populated):
    import sys

    from warren import __main__ as cli

    seen = {}

    async def fake(settings, *, apply, sqlite_path):
        seen.update(apply=apply, sqlite_path=sqlite_path)

    monkeypatch.setenv("WARREN_SECRET_KEY", KEY)
    monkeypatch.setattr("warren.state.migrate.migrate_state", fake)
    monkeypatch.setattr(sys, "argv", ["warren-server", "--migrate-state", "--sqlite-path", str(populated.path)])
    with pytest.raises(SystemExit) as exc:
        cli.main()
    assert exc.value.code == 0
    assert seen == {"apply": False, "sqlite_path": str(populated.path)}
