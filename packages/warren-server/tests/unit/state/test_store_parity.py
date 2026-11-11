"""The stores without a suite of their own elsewhere (launch attempts, EBS snapshots and
seeds, operations, idle stops, workspace tokens), against every WARREN_STATE_BACKEND
(fixtures in tests/unit/conftest.py)."""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timedelta, timezone

import pytest


def _ws(wid: str, owner: str = "u1", status: str = "provisioning", **extra) -> dict:
    return dict(
        workspace_id=wid, project="p", intent="i", image="img", root_path="", server_instance="s1",
        status=status, owner_id=owner, **extra,
    )


# -- launch attempts (AI3) ----------------------------------------------------


def _attempt(gen: str = "g1", fp: str = "f1", token: str = "tok-1", **extra) -> dict:
    return {"generation": gen, "fingerprint": fp, "task_definition_arn": "arn:td:1", "client_token": token, **extra}


async def test_launch_attempt_roundtrip(launch_store):
    assert await launch_store.get("ws-1") is None
    await launch_store.put("ws-1", _attempt(secrets_blobs='{"c": "b"}'))
    assert await launch_store.get("ws-1") == _attempt(secrets_blobs='{"c": "b"}')
    await launch_store.put("ws-1", _attempt(token="tok-2"))
    assert (await launch_store.get("ws-1"))["client_token"] == "tok-2"
    assert "secrets_blobs" not in await launch_store.get("ws-1")
    await launch_store.delete("ws-1")
    assert await launch_store.get("ws-1") is None


async def test_launch_claim_keeps_the_first_attempt_of_a_generation(launch_store):
    first = await launch_store.claim("ws-1", _attempt(token="tok-a"))
    second = await launch_store.claim("ws-1", _attempt(token="tok-b"))
    assert first["client_token"] == second["client_token"] == "tok-a"
    assert (await launch_store.get("ws-1"))["client_token"] == "tok-a"


async def test_launch_claim_replaces_a_stale_generation_or_fingerprint(launch_store):
    await launch_store.claim("ws-1", _attempt(gen="g1", token="tok-a"))
    assert (await launch_store.claim("ws-1", _attempt(gen="g2", token="tok-b")))["client_token"] == "tok-b"
    assert (await launch_store.claim("ws-1", _attempt(gen="g2", fp="f2", token="tok-c")))["client_token"] == "tok-c"
    assert (await launch_store.get("ws-1"))["client_token"] == "tok-c"


async def test_launch_claims_racing_agree_on_one_client_token(launch_store):
    results = await asyncio.gather(*(launch_store.claim("ws-r", _attempt(token=f"tok-{i}")) for i in range(8)))
    assert len({r["client_token"] for r in results}) == 1
    assert (await launch_store.get("ws-r"))["client_token"] == results[0]["client_token"]


# -- EBS snapshots ------------------------------------------------------------


async def test_ebs_snapshot_roundtrip(snapshot_store):
    assert await snapshot_store.get("ws-1") is None
    await snapshot_store.put("ws-1", "snap-1")
    await snapshot_store.put("ws-1", "snap-2")
    assert await snapshot_store.get("ws-1") == "snap-2"
    await snapshot_store.delete("ws-1")
    assert await snapshot_store.get("ws-1") is None


# -- EBS seeds ----------------------------------------------------------------


async def test_seed_update_get_list_delete(seed_store):
    assert await seed_store.get_seed("alice") is None
    await seed_store.update_seed("alice", snapshot_id="snap-1", size_gib=20, repo_keys='["r"]')
    seed = await seed_store.get_seed("alice")
    assert seed["owner_id"] == "alice"
    assert (seed["snapshot_id"], seed["size_gib"], seed["repo_keys"]) == ("snap-1", 20, '["r"]')
    assert seed["pending_snapshot_id"] is None and seed["updated_at"]
    await seed_store.update_seed("alice", pending_snapshot_id="snap-2", snapshot_id=None)
    seed = await seed_store.get_seed("alice")
    assert seed["snapshot_id"] is None and seed["pending_snapshot_id"] == "snap-2"
    assert seed["size_gib"] == 20
    await seed_store.update_seed("bob", snapshot_id="snap-b")
    assert sorted(s["owner_id"] for s in await seed_store.list_seeds()) == ["alice", "bob"]
    with pytest.raises(ValueError):
        await seed_store.update_seed("alice", not_a_column=1)
    await seed_store.delete_seed("alice")
    assert await seed_store.get_seed("alice") is None


async def test_seed_claim_refresh_is_single_flight(seed_store):
    now = "2026-11-03T12:00:00+00:00"
    stale = "2026-11-03T11:30:00+00:00"
    results = await asyncio.gather(*(seed_store.claim_refresh("alice", now, stale) for _ in range(8)))
    assert results.count(True) == 1
    assert (await seed_store.get_seed("alice"))["refreshing_since"] == now
    # Held and fresh: refused. Older than the stale cutoff: reclaimable.
    assert await seed_store.claim_refresh("alice", "2026-11-03T12:01:00+00:00", stale) is False
    assert await seed_store.claim_refresh("alice", "2026-11-03T13:00:00+00:00", "2026-11-03T12:30:00+00:00") is True
    # Released by the refresh: claimable again at once.
    await seed_store.update_seed("alice", refreshing_since=None)
    assert await seed_store.claim_refresh("alice", now, stale) is True


async def test_seed_repos(seed_store):
    row = {
        "repo_key": "b", "url": "https://x/b.git", "kind": "github", "cred_kind": "pat",
        "cred_secret": "GITHUB_PAT", "branches": ["main", "dev", "main"], "ref_shas": {"main": "abc"},
        "last_used_at": "2026-11-01T00:00:00+00:00",
    }
    await seed_store.put_repo("alice", row)
    await seed_store.put_repo("alice", {**row, "repo_key": "a", "ref_shas": None})
    await seed_store.put_repo("alice", {**row, "repo_key": "c", "last_used_at": "2026-11-02T00:00:00+00:00"})
    await seed_store.put_repo("bob", {**row, "repo_key": "z"})
    repos = await seed_store.repos("alice")
    assert [r["repo_key"] for r in repos] == ["c", "a", "b"]
    assert repos[2]["branches"] == ["dev", "main"] and repos[2]["ref_shas"] == {"main": "abc"}
    assert repos[1]["ref_shas"] == {} and repos[1]["released_at"] is None
    assert await seed_store.repo_owners() in (["alice", "bob"], ["bob", "alice"])
    await seed_store.set_ref_shas("alice", "a", {"main": "def"})
    assert {r["repo_key"]: r["ref_shas"] for r in await seed_store.repos("alice")}["a"] == {"main": "def"}
    await seed_store.set_ref_shas("alice", "a", None)
    await seed_store.set_ref_shas("alice", "missing", {"x": "y"})  # no-op, like UPDATE
    assert [r["repo_key"] for r in await seed_store.repos("alice")] == ["c", "a", "b"]
    await seed_store.delete_repo("alice", "c")
    assert [r["repo_key"] for r in await seed_store.repos("alice")] == ["a", "b"]
    assert await seed_store.repos("carol") == []


# -- operations (AM2) ---------------------------------------------------------


async def test_operations(operation_store):
    kwargs = dict(principal="u1", operation_id="op-1", kind="provision", request_hash="h", workspace_id="ws-1")
    assert await operation_store.create(**kwargs) is True
    assert await operation_store.create(**{**kwargs, "workspace_id": "ws-2"}) is False
    assert await operation_store.create(**{**kwargs, "principal": "u2"}) is True
    row = await operation_store.get("u1", "op-1")
    assert {k: row[k] for k in ("operation_id", "kind", "request_hash", "stage", "workspace_id")} == {
        "operation_id": "op-1", "kind": "provision", "request_hash": "h", "stage": "accepted", "workspace_id": "ws-1",
    }
    await operation_store.set_stage("u1", "op-1", "launched")
    assert (await operation_store.get("u1", "op-1"))["stage"] == "launched"
    await operation_store.set_stage("u1", "missing", "launched")
    assert await operation_store.get("u1", "missing") is None
    await operation_store.delete("u1", "op-1")
    assert await operation_store.get("u1", "op-1") is None


async def test_operation_create_races_have_one_winner(operation_store):
    results = await asyncio.gather(*(
        operation_store.create(principal="u1", operation_id="op", kind="k", request_hash="h", workspace_id=f"ws-{i}")
        for i in range(8)
    ))
    assert results.count(True) == 1


# -- workspaces: idle stops, mark_running, updates -----------------------------


async def test_idle_stops_follow_status(workspace_store):
    await workspace_store.insert(**_ws("ws-1", status="running"))
    await workspace_store.update_status("ws-1", "stopped")
    await workspace_store.mark_idle_stopped("ws-1")
    stops = await workspace_store.list_idle_stopped()
    assert [w for w, _ in stops] == ["ws-1"] and isinstance(stops[0][1], datetime)
    await workspace_store.update_status("ws-1", "stopped")
    assert len(await workspace_store.list_idle_stopped()) == 1
    await workspace_store.mark_running("ws-1", "task-arn")
    assert await workspace_store.list_idle_stopped() == []
    row = await workspace_store.get("ws-1")
    assert (row.status, row.container_id) == ("running", "task-arn")


async def test_updates_on_missing_workspace_are_noops(workspace_store):
    await workspace_store.update_status("nope", "running")
    await workspace_store.mark_running("nope", "c")
    await workspace_store.update_container_id("nope", "c")
    await workspace_store.update_image("nope", "img2")
    await workspace_store.update_ssh_port("nope", 1)
    assert await workspace_store.get("nope") is None
    assert await workspace_store.list_all() == []


async def test_workspace_updates_and_list_order(workspace_store):
    await workspace_store.insert(**_ws("ws-a", labels={"k": "v"}, spec_json='{"mode": "x"}', idle_ttl_seconds=1.5))
    await asyncio.sleep(0.01)
    await workspace_store.insert(**_ws("ws-b", owner=None))
    await workspace_store.update_container_id("ws-a", "c-1")
    await workspace_store.update_image("ws-a", "img2")
    await workspace_store.update_container_id("ws-a", None)
    row = await workspace_store.get("ws-a")
    assert (row.container_id, row.image, row.labels, row.idle_ttl_seconds) == (None, "img2", {"k": "v"}, 1.5)
    assert row.spec_json == '{"mode": "x"}'
    assert [w.workspace_id for w in await workspace_store.list_all()] == ["ws-b", "ws-a"]


async def test_caps_follow_status_transitions(workspace_store):
    from warren.registry.store import CapacityExhausted

    await workspace_store.insert(**_ws("ws-1"), max_total=2, max_per_owner=2)
    await workspace_store.insert(**_ws("ws-2"), max_total=2, max_per_owner=2)
    with pytest.raises(CapacityExhausted):
        await workspace_store.insert(**_ws("ws-3"), max_total=2, max_per_owner=2)
    await workspace_store.update_status("ws-1", "failed")  # leaves the live set
    await workspace_store.insert(**_ws("ws-3"), max_total=2, max_per_owner=2)
    await workspace_store.update_status("ws-1", "unknown")  # back in: over cap until one leaves
    with pytest.raises(CapacityExhausted):
        await workspace_store.insert(**_ws("ws-4"), max_total=3, max_per_owner=3)
    await workspace_store.update_status("ws-2", "destroyed")
    await workspace_store.insert(**_ws("ws-4"), max_total=3, max_per_owner=3)
    assert len(await workspace_store.list_non_terminal()) == 3


async def test_owner_cap_counts_ownerless_together(workspace_store):
    from warren.registry.store import CapacityExhausted

    await workspace_store.insert(**_ws("ws-1", owner=None), max_per_owner=1)
    with pytest.raises(CapacityExhausted):
        await workspace_store.insert(**_ws("ws-2", owner=None), max_per_owner=1)
    await workspace_store.insert(**_ws("ws-3", owner="u1"), max_per_owner=1)


# -- workspace tokens (AI9, AI8/AJ2) ------------------------------------------


async def _user(auth_store, name: str = "alice"):
    return await auth_store.create_user(username=name, is_admin=False)


async def test_workspace_token_lifecycle(auth_store, workspace_store):
    user = await _user(auth_store)
    await workspace_store.insert(**_ws("ws-1", owner=user.user_id))
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    tok = await auth_store.create_workspace_token(
        workspace_id="ws-1", user_id=user.user_id, hashed_token="wh1", expires_at=expires, public_key="pk",
    )
    found = await auth_store.get_active_workspace_token("wh1")
    assert found is not None
    resolved_user, wt = found
    assert resolved_user.user_id == user.user_id
    assert (wt.token_id, wt.workspace_id, wt.public_key, wt.workspace_status) == (tok.token_id, "ws-1", "pk", "provisioning")
    assert await auth_store.get_active_workspace_token("other") is None
    # Destroyed: dead, unless the workspace was single-turn.
    await workspace_store.update_status("ws-1", "destroyed")
    assert await auth_store.get_active_workspace_token("wh1") is None
    await workspace_store.insert(**_ws("ws-st", owner=user.user_id, spec_json=json.dumps({"mode": "single-turn"})))
    await auth_store.create_workspace_token(workspace_id="ws-st", user_id=user.user_id, hashed_token="wh2", expires_at=expires)
    await workspace_store.update_status("ws-st", "destroyed")
    assert (await auth_store.get_active_workspace_token("wh2"))[1].workspace_status == "destroyed"


async def test_workspace_token_needs_matching_owner_and_live_user(auth_store, workspace_store):
    alice, bob = await _user(auth_store, "alice"), await _user(auth_store, "bob")
    await workspace_store.insert(**_ws("ws-1", owner=bob.user_id))
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    await auth_store.create_workspace_token(workspace_id="ws-1", user_id=alice.user_id, hashed_token="wh", expires_at=expires)
    assert await auth_store.get_active_workspace_token("wh") is None
    await workspace_store.insert(**_ws("ws-2", owner=alice.user_id))
    await auth_store.create_workspace_token(workspace_id="ws-2", user_id=alice.user_id, hashed_token="wh2", expires_at=expires)
    assert await auth_store.get_active_workspace_token("wh2") is not None
    await auth_store.disable_user(alice.user_id)
    assert await auth_store.get_active_workspace_token("wh2") is None


async def test_workspace_token_expiry_and_revocation(auth_store, workspace_store):
    user = await _user(auth_store)
    await workspace_store.insert(**_ws("ws-1", owner=user.user_id))
    now = datetime.now(timezone.utc)
    await auth_store.create_workspace_token(workspace_id="ws-1", user_id=user.user_id, hashed_token="old", expires_at=now - timedelta(seconds=1))
    assert await auth_store.get_active_workspace_token("old") is None
    keep = await auth_store.create_workspace_token(workspace_id="ws-1", user_id=user.user_id, hashed_token="k", expires_at=now + timedelta(hours=1))
    await auth_store.create_workspace_token(workspace_id="ws-1", user_id=user.user_id, hashed_token="r", expires_at=now + timedelta(hours=1))
    assert await auth_store.revoke_workspace_tokens("ws-1", keep_token_id=keep.token_id) == 2
    assert await auth_store.get_active_workspace_token("r") is None
    assert await auth_store.get_active_workspace_token("k") is not None
    assert await auth_store.revoke_workspace_tokens("ws-1") == 1
    assert await auth_store.revoke_workspace_tokens("ws-1") == 0


async def test_reservation_token_provision_grant(auth_store):
    user = await _user(auth_store)
    expires = datetime.now(timezone.utc) + timedelta(hours=1)
    tok = await auth_store.create_workspace_token(
        workspace_id="ws-future", user_id=user.user_id, hashed_token="res", expires_at=expires, provision_grant=True,
    )
    found = await auth_store.get_active_workspace_token("res")
    assert found is not None and found[1].provision_grant is True and found[1].workspace_status is None
    results = await asyncio.gather(*(auth_store.consume_provision_grant(tok.token_id) for _ in range(6)))
    assert results.count(True) == 1
    assert await auth_store.get_active_workspace_token("res") is None  # unprovisioned, grant spent
    assert await auth_store.consume_provision_grant("unknown") is False


# -- host ports (#73) ---------------------------------------------------------


async def test_host_ports_roundtrip(workspace_store):
    await workspace_store.insert(**_ws("ws-hp"))
    assert (await workspace_store.get("ws-hp")).host_ports_json is None
    ports = {"t3": {"host": "127.0.0.1", "port": 41234}}
    await workspace_store.update_host_ports("ws-hp", ports)
    assert json.loads((await workspace_store.get("ws-hp")).host_ports_json) == ports
    assert [json.loads(w.host_ports_json) for w in await workspace_store.list_all()] == [ports]
    await workspace_store.update_host_ports("ws-hp", {})
    assert (await workspace_store.get("ws-hp")).host_ports_json is None
    await workspace_store.update_host_ports("missing", ports)  # no-op, as the SQLite UPDATE
    assert await workspace_store.get("missing") is None


async def test_list_for_owner_pages_newest_first_across_statuses(workspace_store):
    statuses = ["running", "stopped", "failed", "provisioning", "running", "stopped", "running"]
    for i, st in enumerate(statuses):
        await workspace_store.insert(**_ws(f"mine-{i}", owner="u1", status=st))
        await workspace_store.insert(**_ws(f"theirs-{i}", owner="u2", status=st))
        await asyncio.sleep(0.005)
    seen: list[str] = []
    after = None
    while True:
        page = await workspace_store.list_for_owner("u1", limit=3, after=after)
        assert len(page) <= 3
        seen += [w.workspace_id for w in page]
        if len(page) < 3:
            break
        last = page[-1]
        after = (last.created_at.isoformat() if hasattr(last.created_at, "isoformat") else last.created_at, last.workspace_id)
    assert seen == [f"mine-{i}" for i in reversed(range(7))]
    assert await workspace_store.list_for_owner("nobody", limit=5) == []


# -- workspace token cap and purge (auth hardening) ------------------------------


async def test_workspace_token_active_cap_counts_live_rows_only(auth_store, workspace_store):
    from warren.auth.store import WorkspaceTokenLimitReached

    user = await _user(auth_store)
    other = await _user(auth_store, "bob")
    await workspace_store.insert(**_ws("ws-cap", owner=user.user_id))
    soon = datetime.now(timezone.utc) + timedelta(hours=1)

    async def mint(h: str, uid=user.user_id, exp=soon, reservation=False):
        return await auth_store.create_workspace_token(
            workspace_id="ws-cap", user_id=uid, hashed_token=h, expires_at=exp,
            provision_grant=reservation, max_active=2,
        )

    first = await mint("c1")
    await mint("c2", reservation=True)
    with pytest.raises(WorkspaceTokenLimitReached):
        await mint("c3")
    assert await auth_store.get_active_workspace_token("c3") is None
    await mint("o1", uid=other.user_id)  # another user is unaffected
    await auth_store.revoke_workspace_tokens("ws-cap", keep_token_id=None)  # frees room
    await mint("c4")
    assert first.token_id  # the first token was a real row


async def test_workspace_token_cap_ignores_expired_rows(auth_store, workspace_store):
    from warren.auth.store import WorkspaceTokenLimitReached

    user = await _user(auth_store)
    await workspace_store.insert(**_ws("ws-exp", owner=user.user_id))
    past = datetime.now(timezone.utc) - timedelta(minutes=5)
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    await auth_store.create_workspace_token(
        workspace_id="ws-exp", user_id=user.user_id, hashed_token="e1", expires_at=past, max_active=1
    )
    await auth_store.create_workspace_token(
        workspace_id="ws-exp", user_id=user.user_id, hashed_token="e2", expires_at=future, max_active=1
    )
    with pytest.raises(WorkspaceTokenLimitReached):
        await auth_store.create_workspace_token(
            workspace_id="ws-exp", user_id=user.user_id, hashed_token="e3", expires_at=future, max_active=1
        )


async def test_purge_workspace_tokens_drops_only_dead_rows(auth_store, workspace_store):
    user = await _user(auth_store)
    await workspace_store.insert(**_ws("ws-purge", owner=user.user_id))
    now = datetime.now(timezone.utc)
    old = await auth_store.create_workspace_token(
        workspace_id="ws-purge", user_id=user.user_id, hashed_token="p1", expires_at=now - timedelta(days=40)
    )
    live = await auth_store.create_workspace_token(
        workspace_id="ws-purge", user_id=user.user_id, hashed_token="p2", expires_at=now + timedelta(hours=1)
    )
    removed = await auth_store.purge_workspace_tokens(now - timedelta(days=30))
    # DynamoDB expires rows with its own TTL attribute and purges nothing here.
    assert removed in (0, 1)
    if hasattr(auth_store, "_db"):
        assert removed == 1
        async with auth_store._db.execute("SELECT token_id FROM workspace_tokens") as cur:
            assert [r[0] for r in await cur.fetchall()] == [live.token_id]
    assert old.token_id != live.token_id
    assert await auth_store.get_active_workspace_token("p2") is not None
