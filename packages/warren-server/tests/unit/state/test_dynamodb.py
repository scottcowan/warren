"""DynamoDB backend specifics (moto): atomic caps under interleaved writers, idempotent
launch attempts, TTL attributes, GSI lag, counter repair, retry and preflight."""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from botocore.exceptions import ClientError

from warren.auth.store import LastAdminError, TokenLimitReached
from warren.registry.store import CapacityExhausted
from warren.state import dynamo_stores
from warren.state.dynamodb import DynamoTable, create_table_kwargs, recount
from warren.state.errors import StateBackendError
from warren.state.preflight import check_dynamodb_table, check_secretsmanager

SETTINGS = SimpleNamespace(dynamodb_idle_stop_retention_days=90.0, dynamodb_token_retention_days=30.0)
DAY = 86400


def _ws(wid: str, owner: str = "u1", status: str = "provisioning") -> dict:
    return dict(workspace_id=wid, project="p", intent="i", image="img", root_path="", server_instance="s1",
                status=status, owner_id=owner)


def _twin(table: DynamoTable) -> dict:
    """A second control-plane task's stores: same table, its own DynamoTable object."""
    return dynamo_stores(DynamoTable(table.name, "us-east-1", client=table.client), SETTINGS)


async def _counter(table: DynamoTable, sk: str) -> int:
    item = await table.get("COUNTER#workspaces", sk)
    return int(item["n"]) if item else 0


# -- atomic caps ---------------------------------------------------------------


async def test_caps_hold_across_two_control_plane_tasks(dynamo_table):
    a, b = dynamo_stores(dynamo_table, SETTINGS), _twin(dynamo_table)
    results = await asyncio.gather(*(
        (a if i % 2 else b)["workspaces"].insert(**_ws(f"ws-{i}", owner=f"u{i % 3}"), max_total=5, max_per_owner=2)
        for i in range(20)
    ), return_exceptions=True)
    assert all(isinstance(r, CapacityExhausted) for r in results if isinstance(r, BaseException))
    live = await a["workspaces"].list_non_terminal()
    assert len(live) == 5
    for owner in ("u0", "u1", "u2"):
        assert len([w for w in live if w.owner_id == owner]) <= 2
        assert await _counter(dynamo_table, f"OWNER#{owner}") == len([w for w in live if w.owner_id == owner])
    assert await _counter(dynamo_table, "ALL") == 5


async def test_status_change_racing_another_writer_keeps_counters_exact(dynamo_table):
    """Task A reads `running`; before it writes, task B destroys the workspace. A's
    write is conditioned on the status it read, so it fails, re-reads and applies the
    right (zero) counter delta instead of decrementing a second time."""
    a, b = dynamo_stores(dynamo_table, SETTINGS), _twin(dynamo_table)
    await a["workspaces"].insert(**_ws("ws-1", status="running"), max_total=1)
    assert await _counter(dynamo_table, "ALL") == 1

    real_get = dynamo_table.get
    raced = False

    async def get_then_race(pk, sk="META"):
        nonlocal raced
        item = await real_get(pk, sk)
        if pk == "WS#ws-1" and not raced:
            raced = True
            await b["workspaces"].update_status("ws-1", "destroyed")
        return item

    dynamo_table.get = get_then_race
    await a["workspaces"].update_status("ws-1", "stopped")
    dynamo_table.get = real_get

    assert raced
    assert (await a["workspaces"].get("ws-1")).status == "stopped"
    assert await _counter(dynamo_table, "ALL") == 0
    assert await _counter(dynamo_table, "OWNER#u1") == 0
    await a["workspaces"].insert(**_ws("ws-2"), max_total=1)  # the slot really is free


async def test_token_cap_racing_mint_recounts(dynamo_table):
    """Mint A counts 1 live token (cap 2); mint B takes the last slot before A commits.
    A's commit is conditioned on the user's token_seq, so it retries, recounts 2 and
    refuses."""
    a, b = dynamo_stores(dynamo_table, SETTINGS), _twin(dynamo_table)
    user = await a["auth"].create_user(username="racer", is_admin=False)
    await a["auth"].create_token(user_id=user.user_id, hashed_token="h0", max_active=2)

    real_query = dynamo_table.query
    raced = False

    async def query_then_race(pk, sk_prefix=None, *, index=None):
        nonlocal raced
        items = await real_query(pk, sk_prefix, index=index)
        if sk_prefix == "TOKEN#" and not raced:
            raced = True
            await b["auth"].create_token(user_id=user.user_id, hashed_token="hB", max_active=2)
        return items

    dynamo_table.query = query_then_race
    with pytest.raises(TokenLimitReached):
        await a["auth"].create_token(user_id=user.user_id, hashed_token="hA", max_active=2)
    dynamo_table.query = real_query
    assert raced
    assert await a["auth"].count_active_tokens_for_user(user.user_id) == 2
    assert await a["auth"].get_active_user_by_hashed_token("hA") is None


async def test_disabling_the_last_two_admins_concurrently_leaves_one(dynamo_table):
    a, b = dynamo_stores(dynamo_table, SETTINGS), _twin(dynamo_table)
    x = await a["auth"].create_user(username="x", is_admin=True)
    y = await a["auth"].create_user(username="y", is_admin=True)
    results = await asyncio.gather(
        a["auth"].disable_user(x.user_id, keep_last_admin=True),
        b["auth"].disable_user(y.user_id, keep_last_admin=True),
        return_exceptions=True,
    )
    assert sum(isinstance(r, LastAdminError) for r in results) == 1
    assert await a["auth"].count_enabled_admins() == 1
    assert await a["auth"].count_admins() == 2
    disabled = next(u for u, r in zip((x, y), results, strict=True) if r is True)
    assert await a["auth"].enable_user(disabled.user_id) is True
    assert await a["auth"].count_enabled_admins() == 2


async def test_duplicate_workspace_id_conflicts_without_counting(dynamo_table):
    from warren.state.errors import StateConflict

    ws = dynamo_stores(dynamo_table, SETTINGS)["workspaces"]
    await ws.insert(**_ws("ws-1"))
    with pytest.raises(StateConflict):
        await ws.insert(**_ws("ws-1"))
    assert await _counter(dynamo_table, "ALL") == 1


async def test_token_for_unknown_user_conflicts(dynamo_table):
    from warren.state.errors import StateConflict

    auth = dynamo_stores(dynamo_table, SETTINGS)["auth"]
    with pytest.raises(StateConflict):
        await auth.create_token(user_id="nobody", hashed_token="h")
    with pytest.raises(StateConflict):
        await auth.create_workspace_token(
            workspace_id="w", user_id="nobody", hashed_token="h", expires_at=datetime.now(timezone.utc)
        )


# -- launch attempts (AI3) -------------------------------------------------------


async def test_launch_claim_from_two_tasks_shares_one_client_token(dynamo_table):
    a, b = dynamo_stores(dynamo_table, SETTINGS), _twin(dynamo_table)
    base = {"generation": "g", "fingerprint": "f", "task_definition_arn": "arn:td"}
    results = await asyncio.gather(*(
        s["launch_attempts"].claim("ws-1", {**base, "client_token": f"t{i}", "secrets_blobs": f"blob{i}"})
        for i, s in enumerate([a, b] * 4)
    ))
    assert len({(r["client_token"], r["secrets_blobs"]) for r in results}) == 1


async def test_ecs_launch_adopts_a_concurrent_tasks_attempt(dynamo_table):
    """ECSRuntime keeps the stored attempt's task definition when its claim loses."""
    store = dynamo_stores(dynamo_table, SETTINGS)["launch_attempts"]
    await store.claim("ws-1", {"generation": "g", "fingerprint": "f", "task_definition_arn": "arn:first", "client_token": "t1"})
    won = await store.claim("ws-1", {"generation": "g", "fingerprint": "f", "task_definition_arn": "arn:second", "client_token": "t2"})
    assert (won["task_definition_arn"], won["client_token"]) == ("arn:first", "t1")


# -- TTL --------------------------------------------------------------------------


def _epoch(iso: str) -> int:
    return int(datetime.fromisoformat(iso).timestamp())


async def test_idle_stop_ttl(dynamo_table):
    ws = dynamo_stores(dynamo_table, SETTINGS)["workspaces"]
    await ws.mark_idle_stopped("ws-1")
    item = await dynamo_table.get("WS#ws-1", "IDLESTOP")
    assert int(item["ttl"]) == _epoch(item["stopped_at"]) + 90 * DAY


async def test_token_ttl_on_all_three_items_and_shortened_on_revoke(dynamo_table):
    auth = dynamo_stores(dynamo_table, SETTINGS)["auth"]
    user = await auth.create_user(username="t", is_admin=False)
    expires = datetime.now(timezone.utc) + timedelta(days=90)
    tok = await auth.create_token(user_id=user.user_id, hashed_token="hh", expires_at=expires)
    expected = int((expires + timedelta(days=30)).timestamp())
    items = [
        await dynamo_table.get(f"USER#{user.user_id}", f"TOKEN#{tok.token_id}"),
        await dynamo_table.get("TOKENHASH#hh"),
        await dynamo_table.get(f"TOKENID#{tok.token_id}"),
    ]
    assert [int(i["ttl"]) for i in items] == [expected] * 3
    assert await auth.revoke_token(tok.token_id) is True
    revoked = await dynamo_table.get(f"USER#{user.user_id}", f"TOKEN#{tok.token_id}")
    shortened = _epoch(revoked["revoked_at"]) + 30 * DAY
    assert int(revoked["ttl"]) == shortened < expected
    assert int((await dynamo_table.get("TOKENHASH#hh"))["ttl"]) == shortened
    assert int((await dynamo_table.get(f"TOKENID#{tok.token_id}"))["ttl"]) == shortened


async def test_no_ttl_on_live_unexpiring_tokens_users_workspaces_operations(dynamo_table):
    stores = dynamo_stores(dynamo_table, SETTINGS)
    user = await stores["auth"].create_user(username="n", is_admin=False)
    tok = await stores["auth"].create_token(user_id=user.user_id, hashed_token="nh")
    await stores["workspaces"].insert(**_ws("ws-1"))
    await stores["operations"].create(principal="p", operation_id="o", kind="k", request_hash="h", workspace_id="ws-1")
    for pk, sk in (
        (f"USER#{user.user_id}", f"TOKEN#{tok.token_id}"), (f"USER#{user.user_id}", "META"),
        ("WS#ws-1", "META"), ("OP#p", "OP#o"),
    ):
        assert "ttl" not in await dynamo_table.get(pk, sk)


async def test_workspace_token_ttl(dynamo_table):
    auth = dynamo_stores(dynamo_table, SETTINGS)["auth"]
    user = await auth.create_user(username="w", is_admin=False)
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    tok = await auth.create_workspace_token(workspace_id="ws-1", user_id=user.user_id, hashed_token="wh", expires_at=expires)
    expected = int((expires + timedelta(days=30)).timestamp())
    assert int((await dynamo_table.get("WS#ws-1", f"WSTOKEN#{tok.token_id}"))["ttl"]) == expected
    assert int((await dynamo_table.get("WSTOKENHASH#wh"))["ttl"]) == expected


async def test_token_whose_items_ttl_deleted_resolves_to_nothing(dynamo_table):
    auth = dynamo_stores(dynamo_table, SETTINGS)["auth"]
    user = await auth.create_user(username="g", is_admin=False)
    tok = await auth.create_token(user_id=user.user_id, hashed_token="gh")
    await dynamo_table.delete(f"USER#{user.user_id}", f"TOKEN#{tok.token_id}")  # as TTL would
    assert await auth.get_active_user_by_hashed_token("gh") is None
    assert await auth.get_token(tok.token_id) is None
    assert await auth.revoke_token(tok.token_id) is False


# -- GSI lag, counter repair, retries -----------------------------------------------


async def test_list_non_terminal_rechecks_status_behind_a_lagging_index(dynamo_table):
    ws = dynamo_stores(dynamo_table, SETTINGS)["workspaces"]
    await ws.insert(**_ws("ws-1", status="running"))
    # The index still files it under `running` though the item now says destroyed.
    await dynamo_table.update("WS#ws-1", sets={"status": "destroyed"})
    assert await ws.list_non_terminal() == []


async def test_recount_repairs_counters(dynamo_table):
    stores = dynamo_stores(dynamo_table, SETTINGS)
    await stores["workspaces"].insert(**_ws("ws-1", status="running"))
    await stores["workspaces"].insert(**_ws("ws-2", owner="u2", status="stopped"))
    await stores["auth"].create_user(username="adm", is_admin=True)
    await dynamo_table.put({"pk": "COUNTER#workspaces", "sk": "ALL", "n": 7})
    await dynamo_table.put({"pk": "COUNTER#workspaces", "sk": "OWNER#ghost", "n": 3})
    await dynamo_table.put({"pk": "COUNTER#admins", "sk": "META", "total": 0, "enabled": 0})
    assert await recount(dynamo_table) == {"live_workspaces": 1, "admins": 1, "enabled_admins": 1}
    assert await _counter(dynamo_table, "ALL") == 1
    assert await _counter(dynamo_table, "OWNER#u1") == 1
    assert await _counter(dynamo_table, "OWNER#ghost") == 0
    assert await stores["auth"].count_enabled_admins() == 1


async def test_transaction_conflict_is_retried(dynamo_table):
    real = dynamo_table.client
    calls = {"n": 0}

    class Flaky:
        def __getattr__(self, name):
            fn = getattr(real, name)
            if name != "transact_write_items":
                return fn

            def wrapped(**kwargs):
                calls["n"] += 1
                if calls["n"] == 1:
                    raise ClientError(
                        {"Error": {"Code": "TransactionCanceledException", "Message": "conflict"},
                         "CancellationReasons": [{"Code": "TransactionConflict"}, {"Code": "None"}]},
                        "TransactWriteItems",
                    )
                return fn(**kwargs)

            return wrapped

    table = DynamoTable(dynamo_table.name, "us-east-1", client=Flaky())
    ws = dynamo_stores(table, SETTINGS)["workspaces"]
    await ws.insert(**_ws("ws-1"), max_total=3)
    assert calls["n"] == 2
    assert (await ws.get("ws-1")) is not None


# -- preflight -----------------------------------------------------------------------


async def test_preflight_accepts_the_reference_table(dynamo_table):
    await check_dynamodb_table(dynamo_table.client, dynamo_table.name, "us-east-1")


async def test_preflight_missing_table(dynamo_table):
    with pytest.raises(StateBackendError, match="no such table"):
        await check_dynamodb_table(dynamo_table.client, "nope", "us-east-1")


async def test_preflight_wrong_key_schema_or_missing_index(dynamo_table):
    client = dynamo_table.client
    client.create_table(
        TableName="bad-keys", BillingMode="PAY_PER_REQUEST",
        AttributeDefinitions=[{"AttributeName": "id", "AttributeType": "S"}],
        KeySchema=[{"AttributeName": "id", "KeyType": "HASH"}],
    )
    with pytest.raises(StateBackendError, match="partition key `pk`"):
        await check_dynamodb_table(client, "bad-keys", "us-east-1")
    kwargs = create_table_kwargs("no-gsi")
    del kwargs["GlobalSecondaryIndexes"]
    kwargs["AttributeDefinitions"] = kwargs["AttributeDefinitions"][:2]
    client.create_table(**kwargs)
    with pytest.raises(StateBackendError, match="gsi1"):
        await check_dynamodb_table(client, "no-gsi", "us-east-1")


class _Denied:
    def __getattr__(self, name):
        def call(**_kwargs):
            raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "no"}}, name)

        return call


async def test_preflight_access_denied_names_the_permission():
    with pytest.raises(StateBackendError, match="dynamodb:DescribeTable"):
        await check_dynamodb_table(_Denied(), "t", "us-east-1")
    with pytest.raises(StateBackendError, match="secretsmanager:ListSecrets"):
        await check_secretsmanager(_Denied(), "warren/x")


async def test_preflight_secretsmanager_ok(sm_client):
    await check_secretsmanager(sm_client, "warren/x")
