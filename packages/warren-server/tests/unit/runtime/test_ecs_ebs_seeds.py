"""EBS bare seeds (runtime/ebs_seeds.py): the create path, the refresh lifecycle, owner
isolation, the SHA skip, the repo union and its TTL, and the sweep. AWS is faked like
test_ecs_ebs.py; the database is a real SQLite file."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from warren.registry.store import EbsSeedStore, open_db
from warren.runtime.ebs import TAG_ECS_CREATED
from warren.runtime.ebs_seeds import (
    BareSeeds,
    OwnerUnion,
    SeedRepo,
    _iso,
    live_union,
    ls_remote_sync,
    seed_repos_from_folders,
)
from warren_common.models import FolderSpec
from warren_common.runtime.base import WorkspaceSpec
from warren_common.safe_git import SafeGitError

from .test_ecs_ebs import SERVER, WS, FakeEC2, _env, _runtime, _settings, _volume_config

ALICE, BOB = "o-alice", "o-bob"
APP_URL = "https://github.com/org/app.git"
LIB_URL = "https://github.com/org/lib.git"
APP = FolderSpec(name="app", type="git-worktree", mount="code/app", url=APP_URL, branch="main")
LIB = FolderSpec(name="lib", type="git-clone", mount="refs/lib", url=LIB_URL, branch="trunk")
T0 = float(int(datetime.now(UTC).timestamp()))
DAY = 86400.0


class SeedEC2(FakeEC2):
    """FakeEC2 whose snapshots carry VolumeSize and complete on their next describe."""

    auto_complete = True

    def create_snapshot(self, **kw):
        resp = super().create_snapshot(**kw)
        sid = resp["SnapshotId"]
        self.snapshots[sid]["VolumeSize"] = self.volumes[kw["VolumeId"]].get("Size", 20)
        if self.auto_complete:
            self.snapshot_transitions[sid] = ["completed"]
        return resp

    def add_seed_snapshot(self, owner=ALICE, size=50, state="completed", server=SERVER, age_s=0):
        sid = self._id("snap")
        self.snapshots[sid] = {
            "SnapshotId": sid, "State": state, "VolumeSize": size,
            "StartTime": datetime.now(UTC) - timedelta(seconds=age_s),
            "Tags": [
                {"Key": "warren", "Value": "true"},
                {"Key": "warren.server_instance", "Value": server},
                {"Key": "warren.storage", "Value": "ebs-seed"},
                {"Key": "warren.owner_id", "Value": owner},
            ],
        }
        return sid

    def add_seed_volume(self, owner=ALICE, state="available", age_s=3600, server=SERVER):
        vid = self._id("vol")
        self.volumes[vid] = {
            "VolumeId": vid, "State": state, "Size": 20,
            "CreateTime": datetime.now(UTC) - timedelta(seconds=age_s),
            "Tags": [
                {"Key": "warren", "Value": "true"},
                {"Key": "warren.server_instance", "Value": server},
                {"Key": "warren.storage", "Value": "ebs-seed"},
                {"Key": "warren.owner_id", "Value": owner},
            ],
        }
        return vid


class FakeSeedECS:
    """ECS for the seed-refresh task: RunTask creates its tagged volume, the task stops
    after `running` describes, and git-init exits with `exit_code`."""

    def __init__(self, ec2: SeedEC2, *, exit_code=0, running=1) -> None:
        self.ec2 = ec2
        self.exit_code = exit_code
        self.running = running
        self.runs: list[dict] = []
        self.task_defs: list[dict] = []
        self.stops: list[dict] = []
        self.vol = ""

    def register_task_definition(self, **kw):
        self.task_defs.append(kw)
        return {"taskDefinition": {"taskDefinitionArn": f"arn:td/{kw['family']}:1"}}

    def run_task(self, **kw):
        self.runs.append(kw)
        arn = f"arn:aws:ecs:eu-west-1:123:task/cl/seed{len(self.runs)}"
        m = kw["volumeConfigurations"][0]["managedEBSVolume"]
        tags = [{"Key": t["key"], "Value": t["value"]} for t in m["tagSpecifications"][0]["tags"]]
        self.vol = self.ec2._id("vol")
        self.ec2.volumes[self.vol] = {
            "VolumeId": self.vol, "State": "in-use", "Size": m.get("sizeInGiB", 20),
            "CreateTime": datetime.now(UTC), "Tags": [*tags, {"Key": TAG_ECS_CREATED, "Value": arn}],
        }
        return {"tasks": [{"taskArn": arn}], "failures": []}

    def describe_tasks(self, **kw):
        if self.running > 0:
            self.running -= 1
            return {"tasks": [{"taskArn": kw["tasks"][0], "lastStatus": "RUNNING"}]}
        self.ec2.volumes[self.vol]["State"] = "available"
        return {
            "tasks": [{
                "taskArn": kw["tasks"][0], "lastStatus": "STOPPED",
                "containers": [{"name": "git-init", "exitCode": self.exit_code}],
            }]
        }

    def stop_task(self, **kw):
        self.stops.append(kw)
        self.running = 0
        self.exit_code = 137


class _Clock:
    def __init__(self) -> None:
        self.t = 0.0
        self.wall = T0

    def __call__(self) -> float:
        return self.t

    def now(self) -> float:
        return self.wall

    async def sleep(self, s: float) -> None:
        self.t += s
        self.wall += s


SHAS = {"HEAD": "a" * 40, "refs/heads/main": "a" * 40}


def _seed_settings(**over):
    base = dict(
        ecs_ebs_bare_seeds=True,
        ecs_ebs_seed_repo_ttl_days=30.0,
        ecs_ebs_seed_refresh_interval_seconds=DAY,
        ecs_ebs_seed_refresh_timeout_seconds=600.0,
        ecs_git_init_image="",
        ecs_git_known_hosts="",
        ecs_task_role_arn="arn:aws:iam::123456789012:role/ws",
        ecs_task_execution_role_arn="arn:aws:iam::123456789012:role/exec",
        git_clone_filter="",
    )
    base.update(over)
    return _settings(**base)


_OPEN_DBS: list = []


@pytest.fixture(autouse=True)
async def _close_dbs():
    yield
    while _OPEN_DBS:
        await _OPEN_DBS.pop().close()


async def _setup(tmp_path, *, settings=None, secrets=None, ls=None, union=None, ecs_kw=None):
    ec2 = SeedEC2()
    clock = _Clock()
    settings = settings or _seed_settings()
    rt, ecs, _ = _runtime(ec2, settings, clock=clock, secrets=secrets)
    db = await open_db(tmp_path / "warren.db")
    _OPEN_DBS.append(db)
    store = EbsSeedStore(db)
    calls: list[tuple] = []

    def fake_ls(url, token, refs):
        calls.append((url, token, tuple(refs)))
        out = ls(url, token, refs) if callable(ls) else (ls if ls is not None else SHAS)
        return dict(out)

    seeds = BareSeeds(rt, rt.ebs, settings, store, ls_remote=fake_ls, now=clock.now, sleep=clock.sleep, clock=clock)
    state = {"union": union or {}}

    async def live():
        return state["union"]

    seeds.live_repos = live
    rt.seeds = seeds
    fake_ecs = FakeSeedECS(ec2, **(ecs_kw or {}))
    ns = SimpleNamespace(
        rt=rt, ecs=ecs, ec2=ec2, clock=clock, store=store, seeds=seeds, db=db,
        ls_calls=calls, state=state, seed_ecs=fake_ecs,
    )
    return ns


def _spec(owner=ALICE, folders=(APP,), **over) -> WorkspaceSpec:
    kw = dict(
        workspace_id=WS, project="p", intent="dev", image="img:1", root_path="",
        owner_id=owner, ecs_storage="ebs", folders=list(folders),
    )
    kw.update(over)
    return WorkspaceSpec(**kw)


def _repos(*folders) -> list[SeedRepo]:
    return seed_repos_from_folders(list(folders))


async def _install_seed(t, owner=ALICE, size=50, keys=("github.com/org/app",), shas=SHAS, verified=None):
    sid = t.ec2.add_seed_snapshot(owner, size=size)
    await t.store.update_seed(
        owner, snapshot_id=sid, size_gib=size, repo_keys=json.dumps(list(keys)),
        verified_at=_iso(verified if verified is not None else t.clock.wall), image="img:1",
    )
    for key in keys:
        url = f"https://{key}.git"
        await t.store.put_repo(owner, {
            "repo_key": key, "url": url, "kind": "worktree", "cred_kind": "pat",
            "cred_secret": "GITHUB_PAT", "branches": ["main"], "ref_shas": dict(shas),
            "last_used_at": _iso(t.clock.wall), "released_at": None,
        })
    return sid


# --- create path ------------------------------------------------------------------------


async def test_create_without_a_seed_launches_empty_and_queues_a_refresh(tmp_path):
    t = await _setup(tmp_path)
    t.seeds.queue_refresh = MagicMock()

    await t.rt.provision(_spec())

    m = _volume_config(t.ecs)["managedEBSVolume"]
    assert "snapshotId" not in m and m["sizeInGiB"] == 20
    assert "WARREN_GIT_SEEDED" not in _env(t.ecs, "git-init")
    t.seeds.queue_refresh.assert_called_once_with(ALICE)
    (row,) = await t.store.repos(ALICE)
    assert row["repo_key"] == "github.com/org/app" and row["cred_secret"] == "GITHUB_PAT"
    assert row["branches"] == ["main"] and row["released_at"] is None


async def test_create_with_a_seed_launches_from_it_at_least_its_size(tmp_path):
    t = await _setup(tmp_path)
    sid = await _install_seed(t, size=50)
    t.seeds.queue_refresh = MagicMock()

    await t.rt.provision(_spec())

    m = _volume_config(t.ecs)["managedEBSVolume"]
    assert m["snapshotId"] == sid and m["sizeInGiB"] == 50
    assert _env(t.ecs, "git-init")["WARREN_GIT_SEEDED"] == "1"
    # The volume is still the workspace's: its tags (and so its stop snapshots) aren't the seed's.
    tags = {x["key"]: x["value"] for x in m["tagSpecifications"][0]["tags"]}
    assert tags["warren.storage"] == "ebs" and tags["warren.workspace_id"] == WS
    t.seeds.queue_refresh.assert_not_called()  # complete and fresh


async def test_a_seed_smaller_than_the_configured_size_gets_the_configured_size(tmp_path):
    t = await _setup(tmp_path, settings=_seed_settings(ecs_ebs_size_gib=100))
    await _install_seed(t, size=8)
    t.seeds.queue_refresh = MagicMock()
    await t.rt.provision(_spec())
    assert _volume_config(t.ecs)["managedEBSVolume"]["sizeInGiB"] == 100


@pytest.mark.parametrize("why", ["missing-repo", "stale"])
async def test_a_seed_missing_a_repo_or_stale_is_used_and_refreshed(tmp_path, why):
    t = await _setup(tmp_path)
    sid = await _install_seed(t, verified=T0 - 2 * DAY if why == "stale" else None)
    t.seeds.queue_refresh = MagicMock()
    folders = (APP, LIB) if why == "missing-repo" else (APP,)
    await t.rt.provision(_spec(folders=folders))
    assert _volume_config(t.ecs)["managedEBSVolume"]["snapshotId"] == sid
    t.seeds.queue_refresh.assert_called_once_with(ALICE)


async def test_relaunch_of_an_existing_workspace_never_uses_the_seed(tmp_path):
    t = await _setup(tmp_path)
    await _install_seed(t)
    own = t.ec2.add_snapshot()  # the workspace's own stop snapshot
    t.seeds.queue_refresh = MagicMock()
    await t.rt.provision(_spec(provision_generation="arn:task/1"))
    assert _volume_config(t.ecs)["managedEBSVolume"]["snapshotId"] == own
    assert "WARREN_GIT_SEEDED" not in _env(t.ecs, "git-init")


async def test_a_seed_lookup_error_never_fails_the_create(tmp_path):
    t = await _setup(tmp_path)
    t.seeds.prepare_launch = AsyncMock(side_effect=RuntimeError("boom"))
    await t.rt.provision(_spec())
    assert "snapshotId" not in _volume_config(t.ecs)["managedEBSVolume"]


# --- owner isolation -------------------------------------------------------------------


async def test_owner_b_never_gets_owner_as_seed(tmp_path):
    t = await _setup(tmp_path)
    alice_sid = await _install_seed(t, owner=ALICE)
    t.seeds.queue_refresh = MagicMock()

    await t.rt.provision(_spec(owner=BOB))
    assert "snapshotId" not in _volume_config(t.ecs)["managedEBSVolume"]

    # Even a (corrupted or crafted) seed row for Bob that names Alice's snapshot is
    # refused: the snapshot's own owner tag must match.
    await t.store.update_seed(BOB, snapshot_id=alice_sid, size_gib=50,
                              repo_keys=json.dumps(["github.com/org/app"]), verified_at=_iso(T0))
    t.rt._task_def_cache.clear()
    await t.rt.provision(_spec(owner=BOB, workspace_id="ws-abcdef12-0003"))
    assert "snapshotId" not in _volume_config(t.ecs)["managedEBSVolume"]
    # ... and so is another server's seed, or one that isn't a seed at all.
    other = t.ec2.add_seed_snapshot(BOB, server="another-server")
    ws_snap = t.ec2.add_snapshot(workspace_id="ws-bob-0001")
    for sid in (other, ws_snap):
        await t.store.update_seed(BOB, snapshot_id=sid)
        assert await t.seeds._usable(BOB, await t.store.get_seed(BOB)) is None


async def test_no_owner_no_seed(tmp_path):
    t = await _setup(tmp_path)
    t.seeds.queue_refresh = MagicMock()
    assert await t.seeds.prepare_launch(_spec(owner=""), image="img:1") is None
    t.seeds.queue_refresh.assert_not_called()


async def test_union_is_per_owner_from_each_workspaces_own_spec():
    from warren.registry.registry import serialize_spec_extra

    def row(ws_id, owner, folders, status="running", storage="ebs"):
        spec = _spec(owner=owner, folders=folders, workspace_id=ws_id, ecs_storage=storage)
        return SimpleNamespace(status=status, spec_json=serialize_spec_extra(spec), image="img:1")

    union = live_union([
        row("ws-1", ALICE, (APP,)),
        row("ws-2", BOB, (LIB,)),
        row("ws-3", BOB, (APP,), status="destroyed"),
        row("ws-4", BOB, (APP,), storage="efs"),
    ])
    assert {r.key for r in union[ALICE].repos} == {"github.com/org/app"}
    assert {r.key for r in union[BOB].repos} == {"github.com/org/lib"}


# --- union membership and TTL -----------------------------------------------------------


async def test_union_shared_repo_survives_one_destroy_then_ttl_then_seed_deleted(tmp_path):
    t = await _setup(tmp_path)
    sid = await _install_seed(t)
    t.seeds.queue_refresh = MagicMock()
    both = OwnerUnion(repos=_repos(APP) + _repos(APP, LIB), image="img:1")
    t.state["union"] = {ALICE: both}
    await t.seeds.sweep()
    keys = {r["repo_key"] for r in await t.store.repos(ALICE)}
    assert keys == {"github.com/org/app", "github.com/org/lib"}

    # One of the two workspaces using app is destroyed: app stays, unreleased.
    t.state["union"] = {ALICE: OwnerUnion(repos=_repos(APP, LIB), image="img:1")}
    await t.seeds.sweep()
    rows = {r["repo_key"]: r for r in await t.store.repos(ALICE)}
    assert rows["github.com/org/app"]["released_at"] is None

    # Both destroyed: the TTL starts, the repos stay in the seed until it passes.
    t.state["union"] = {}
    await t.seeds.sweep()
    rows = await t.store.repos(ALICE)
    assert len(rows) == 2 and all(r["released_at"] for r in rows)
    t.clock.wall += 29 * DAY
    await t.seeds.sweep()
    assert len(await t.store.repos(ALICE)) == 2
    assert t.ec2.snapshots.get(sid)

    t.clock.wall += 2 * DAY
    stats = await t.seeds.sweep()
    assert await t.store.repos(ALICE) == []
    assert stats["seeds_deleted"] == 1
    assert sid not in t.ec2.snapshots and await t.store.get_seed(ALICE) is None


async def test_a_released_repo_used_again_is_unreleased(tmp_path):
    t = await _setup(tmp_path)
    t.seeds.queue_refresh = MagicMock()
    t.state["union"] = {ALICE: OwnerUnion(repos=_repos(APP))}
    await t.seeds.sweep()
    t.state["union"] = {}
    await t.seeds.sweep()
    assert (await t.store.repos(ALICE))[0]["released_at"]
    await t.seeds.prepare_launch(_spec(), image="img:1")
    assert (await t.store.repos(ALICE))[0]["released_at"] is None


async def test_owner_b_workspaces_never_add_to_owner_as_union(tmp_path):
    t = await _setup(tmp_path)
    t.seeds.queue_refresh = MagicMock()
    t.state["union"] = {ALICE: OwnerUnion(repos=_repos(APP)), BOB: OwnerUnion(repos=_repos(LIB))}
    await t.seeds.prepare_launch(_spec(owner=BOB, folders=(LIB, APP)), image="img:1")
    await t.seeds.sweep()
    assert {r["repo_key"] for r in await t.store.repos(ALICE)} == {"github.com/org/app"}
    assert {r["repo_key"] for r in await t.store.repos(BOB)} == {"github.com/org/lib", "github.com/org/app"}


# --- refresh ----------------------------------------------------------------------------


async def test_refresh_lifecycle_task_snapshot_delete_and_prune(tmp_path):
    t = await _setup(tmp_path, secrets={"GITHUB_PAT": "ghp_alice", "OTHER": "nope"})
    t.rt._ecs = t.seed_ecs
    old = await _install_seed(t, shas={"HEAD": "0" * 40})
    t.state["union"] = {ALICE: OwnerUnion(repos=_repos(APP, LIB), image="img:1")}

    assert await t.seeds.refresh(ALICE) == "refreshed"

    (run,) = t.seed_ecs.runs
    assert run["startedBy"] != t.rt.started_by and run["startedBy"].startswith("warren-seed-")
    assert run["enableExecuteCommand"] is False
    tags = {x["key"]: x["value"] for x in run["tags"]}
    assert tags == {"warren.server_instance": SERVER, "warren.owner_id": ALICE, "warren.task_kind": "seed-refresh"}
    m = run["volumeConfigurations"][0]["managedEBSVolume"]
    assert m["snapshotId"] == old and m["sizeInGiB"] == 50
    vtags = {x["key"]: x["value"] for x in m["tagSpecifications"][0]["tags"]}
    assert vtags == {"warren": "true", "warren.server_instance": SERVER, "warren.storage": "ebs-seed",
                     "warren.owner_id": ALICE}
    (td,) = t.seed_ecs.task_defs
    assert [c["name"] for c in td["containerDefinitions"]] == ["git-init"]
    assert td["family"] == "warren-seed-refresh" and td["containerDefinitions"][0]["image"] == "img:1"
    env = {e["name"]: e["value"] for e in run["overrides"]["containerOverrides"][0]["environment"]}
    assert env["WARREN_GIT_MODE"] == "refresh-seed"
    assert set(env["WARREN_GIT_SEED_REPOS"].splitlines()) == {
        f"github.com/org/app\t{APP_URL}\tpat\tGITHUB_PAT",
        f"github.com/org/lib\t{LIB_URL}\tpat\tGITHUB_PAT",
    }
    assert "ghp_alice" not in json.dumps(run)  # only as KMS ciphertext
    assert env["WARREN_WORKSPACE_ID"] == t.seeds.pseudo_id(ALICE)
    ctx = t.rt._kms.calls[-1]["EncryptionContext"]
    assert ctx == {"warren:workspace_id": t.seeds.pseudo_id(ALICE), "warren:container": "git-init"}
    t.rt.secret_values.assert_awaited_with(ALICE, ["GITHUB_PAT"])
    # ls-remote ran with Alice's own token.
    assert {c[1] for c in t.ls_calls} == {"ghp_alice"}

    # Stopped → snapshot of the retained volume, tagged as Alice's seed → volume deleted.
    assert t.seed_ecs.vol not in t.ec2.volumes
    seed = await t.store.get_seed(ALICE)
    new = seed["snapshot_id"]
    assert new != old and seed["previous_snapshot_id"] == old and seed["refreshing_since"] is None
    snap_tags = {x["Key"]: x["Value"] for x in t.ec2.snapshots[new]["Tags"]}
    assert snap_tags["warren.storage"] == "ebs-seed" and snap_tags["warren.owner_id"] == ALICE
    assert "warren.workspace_id" not in snap_tags
    assert set(json.loads(seed["repo_keys"])) == {"github.com/org/app", "github.com/org/lib"}
    rows = {r["repo_key"]: r for r in await t.store.repos(ALICE)}
    assert rows["github.com/org/app"]["ref_shas"] == SHAS

    # The replaced seed survives the grace period (a launch may be creating from it).
    t.seeds.queue_refresh = MagicMock()
    await t.seeds.sweep()
    assert old in t.ec2.snapshots
    t.clock.wall += 2 * 3600
    await t.seeds.sweep()
    assert old not in t.ec2.snapshots and new in t.ec2.snapshots
    assert (await t.store.get_seed(ALICE))["previous_snapshot_id"] is None


async def test_first_refresh_starts_empty_with_the_configured_size(tmp_path):
    t = await _setup(tmp_path, settings=_seed_settings(ecs_git_init_image="init:1"))
    t.rt._ecs = t.seed_ecs
    t.state["union"] = {ALICE: OwnerUnion(repos=_repos(APP))}
    assert await t.seeds.refresh(ALICE) == "refreshed"
    m = t.seed_ecs.runs[0]["volumeConfigurations"][0]["managedEBSVolume"]
    assert "snapshotId" not in m and m["sizeInGiB"] == 20
    env = {e["name"]: e["value"] for e in t.seed_ecs.runs[0]["overrides"]["containerOverrides"][0]["environment"]}
    assert "WARREN_SECRETS_BLOB" not in env  # Alice has no PAT: public fetch
    assert env["WARREN_GIT_SEED_REPOS"] == f"github.com/org/app\t{APP_URL}\tnone\t-"


async def test_refresh_is_single_flight(tmp_path):
    t = await _setup(tmp_path)
    now = t.clock.wall
    assert await t.store.claim_refresh(ALICE, _iso(now), _iso(now - 3600))
    assert await t.seeds.refresh(ALICE) == "busy"
    # A claim from a crashed server goes stale and can be taken over.
    t.clock.wall += 4 * 3600
    t.state["union"] = {}
    assert await t.seeds.refresh(ALICE) == "deleted"

    t.seeds.refresh = AsyncMock(return_value="refreshed")
    first = t.seeds.queue_refresh(BOB)
    assert t.seeds.queue_refresh(BOB) is first
    await first
    t.seeds.refresh.assert_awaited_once_with(BOB)


async def test_sha_skip_when_nothing_moved(tmp_path):
    t = await _setup(tmp_path)
    t.rt._ecs = t.seed_ecs
    await _install_seed(t, verified=T0 - 2 * DAY)
    t.state["union"] = {ALICE: OwnerUnion(repos=_repos(APP), image="img:1")}

    assert await t.seeds.refresh(ALICE) == "current"
    assert t.seed_ecs.runs == []
    assert (await t.store.get_seed(ALICE))["verified_at"] == _iso(t.clock.wall)


async def test_sha_moved_or_unknown_refreshes(tmp_path):
    moved = {"HEAD": "b" * 40, "refs/heads/main": "b" * 40}
    t = await _setup(tmp_path, ls=moved)
    t.rt._ecs = t.seed_ecs
    await _install_seed(t)
    t.state["union"] = {ALICE: OwnerUnion(repos=_repos(APP), image="img:1")}
    assert await t.seeds.refresh(ALICE) == "refreshed"
    assert len(t.seed_ecs.runs) == 1

    def boom(*_a):
        raise RuntimeError("network")

    t2 = await _setup(tmp_path / "2", ls=boom)
    t2.rt._ecs = t2.seed_ecs
    await _install_seed(t2)
    t2.state["union"] = {ALICE: OwnerUnion(repos=_repos(APP), image="img:1")}
    assert await t2.seeds.refresh(ALICE) == "refreshed"


async def test_refresh_timeout_stops_the_task_and_keeps_the_old_seed(tmp_path):
    t = await _setup(tmp_path, ls={"HEAD": "c" * 40}, ecs_kw={"running": 10**6})
    t.rt._ecs = t.seed_ecs
    old = await _install_seed(t)
    t.state["union"] = {ALICE: OwnerUnion(repos=_repos(APP), image="img:1")}

    assert await t.seeds.refresh(ALICE) == "failed"

    assert t.seed_ecs.stops and "timeout" in t.seed_ecs.stops[0]["reason"]
    assert t.seed_ecs.vol not in t.ec2.volumes  # deleted, not snapshotted
    seed = await t.store.get_seed(ALICE)
    assert seed["snapshot_id"] == old and "137" in seed["last_error"] and seed["refreshing_since"] is None


async def test_partial_refresh_promotes_but_records_no_shas(tmp_path):
    t = await _setup(tmp_path, ecs_kw={"exit_code": 3})
    t.rt._ecs = t.seed_ecs
    t.state["union"] = {ALICE: OwnerUnion(repos=_repos(APP), image="img:1")}
    assert await t.seeds.refresh(ALICE) == "refreshed"
    seed = await t.store.get_seed(ALICE)
    assert seed["snapshot_id"] and "could not be fetched" in seed["last_error"]
    assert (await t.store.repos(ALICE))[0]["ref_shas"] == {}


async def test_a_failed_new_snapshot_keeps_the_old_seed(tmp_path):
    t = await _setup(tmp_path, ls={"HEAD": "d" * 40})
    t.rt._ecs = t.seed_ecs
    t.ec2.auto_complete = False
    old = await _install_seed(t)
    t.state["union"] = {ALICE: OwnerUnion(repos=_repos(APP), image="img:1")}

    orig = t.ec2.create_snapshot

    def failing(**kw):
        resp = orig(**kw)
        t.ec2.snapshot_transitions[resp["SnapshotId"]] = ["error"]
        return resp

    t.ec2.create_snapshot = failing
    assert await t.seeds.refresh(ALICE) == "failed"
    seed = await t.store.get_seed(ALICE)
    assert seed["snapshot_id"] == old and seed["pending_snapshot_id"] is None


# --- reapers and sweep ------------------------------------------------------------------


async def test_refresh_tasks_are_never_workspace_tasks(tmp_path):
    t = await _setup(tmp_path)
    t.ecs.list_tasks.return_value = {"taskArns": ["arn:seed", "arn:ws"]}
    t.ecs.describe_tasks.return_value = {"tasks": [
        {"taskArn": "arn:seed", "tags": [
            {"key": "warren.server_instance", "value": SERVER},
            {"key": "warren.task_kind", "value": "seed-refresh"},
        ]},
        {"taskArn": "arn:ws", "tags": [
            {"key": "warren.server_instance", "value": SERVER},
            {"key": "warren.workspace_id", "value": WS},
        ]},
    ]}
    assert [x["task_arn"] for x in await t.rt.list_owned_tasks()] == ["arn:ws"]
    assert t.seeds.started_by != t.rt.started_by

    # The workspace volume sweep never sees seed volumes or snapshots.
    vol = t.ec2.add_seed_volume()
    snap = t.ec2.add_seed_snapshot()

    async def exists(_ws):
        return False

    def lock(_ws):
        async def _l():
            return asyncio.Lock()
        return _l()

    await t.rt.ebs.sweep(exists, lambda ws: lock(ws), min_age_seconds=0)
    assert vol in t.ec2.volumes and snap in t.ec2.snapshots


async def test_sweep_cleans_orphans_by_tag_and_queues_stale_refreshes(tmp_path):
    t = await _setup(tmp_path)
    t.seeds.queue_refresh = MagicMock()
    kept = await _install_seed(t, verified=T0 - 2 * DAY)
    t.state["union"] = {ALICE: OwnerUnion(repos=_repos(APP), image="img:1")}
    orphan_vol = t.ec2.add_seed_volume(age_s=3600)
    young_vol = t.ec2.add_seed_volume(age_s=10)
    foreign_vol = t.ec2.add_seed_volume(server="another-server")
    orphan_snap = t.ec2.add_seed_snapshot(age_s=3600)
    foreign_snap = t.ec2.add_seed_snapshot(server="another-server", age_s=3600)

    stats = await t.seeds.sweep(min_age_seconds=900)

    assert orphan_vol not in t.ec2.volumes and young_vol in t.ec2.volumes and foreign_vol in t.ec2.volumes
    assert orphan_snap not in t.ec2.snapshots and kept in t.ec2.snapshots and foreign_snap in t.ec2.snapshots
    assert stats["volumes_deleted"] == 1 and stats["snapshots_deleted"] == 1
    t.seeds.queue_refresh.assert_called_once_with(ALICE)


async def test_sweep_loop_runs_the_seed_sweep(tmp_path):
    from warren.registry.ebs_sweep import sweep_ebs

    t = await _setup(tmp_path)
    t.seeds.sweep = AsyncMock(return_value={"seeds_deleted": 1})
    t.rt.ebs.sweep = AsyncMock(return_value={"snapshotted": 0})
    registry = SimpleNamespace(runtime=t.rt, store=MagicMock(), _lock_for=AsyncMock())
    stats = await sweep_ebs(registry, min_age_seconds=5)
    t.seeds.sweep.assert_awaited_once_with(min_age_seconds=5)
    assert stats["seed_seeds_deleted"] == 1


# --- store, settings, ls-remote ------------------------------------------------------------


async def test_seed_tables_are_created_on_an_existing_database(tmp_path):
    import aiosqlite

    path = tmp_path / "old.db"
    async with aiosqlite.connect(str(path)) as db:
        await db.execute("CREATE TABLE ecs_ebs_snapshots (workspace_id TEXT PRIMARY KEY, snapshot_id TEXT NOT NULL, updated_at TEXT NOT NULL)")
        await db.commit()
    db = await open_db(path)
    store = EbsSeedStore(db)
    await store.update_seed(ALICE, snapshot_id="snap-1")
    assert (await store.get_seed(ALICE))["snapshot_id"] == "snap-1"
    assert await store.get_seed(BOB) is None
    with pytest.raises(ValueError):
        await store.update_seed(ALICE, bogus_column="x")
    await db.close()


def test_bare_seeds_setting_needs_ebs(monkeypatch):
    from pydantic import ValidationError
    from warren.config import WarrenSettings

    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)

    with pytest.raises(ValidationError, match="WARREN_ECS_EBS_BARE_SEEDS"):
        WarrenSettings(ecs_ebs_bare_seeds=True)
    s = WarrenSettings(
        ecs_ebs_bare_seeds=True,
        ecs_ebs_infra_role_arn="arn:aws:iam::123456789012:role/x",
        ecs_secrets_kms_key_id="k",
    )
    assert s.ecs_ebs_seed_repo_ttl_days == 30 and s.ecs_ebs_seed_refresh_interval_seconds == 86400
    assert WarrenSettings().git_clone_filter == ""
    with pytest.raises(ValidationError):
        WarrenSettings(git_clone_filter="sparse:oid=x")


async def test_clone_filter_reaches_git_init_only_when_set(tmp_path):
    t = await _setup(tmp_path, settings=_seed_settings(git_clone_filter="blob:none"))
    t.seeds.queue_refresh = MagicMock()
    await t.rt.provision(_spec())
    assert _env(t.ecs, "git-init")["WARREN_GIT_CLONE_FILTER"] == "blob:none"
    assert "WARREN_GIT_CLONE_FILTER" not in _env(t.ecs, "workspace")


@pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")
def test_ls_remote_reads_refs_with_the_token_only_in_the_askpass_env(tmp_path):
    from .test_ecs_git import _git

    repo = tmp_path / "up"
    repo.mkdir()
    _git("init", cwd=repo)
    (repo / "f").write_text("x\n")
    _git("add", ".", cwd=repo)
    _git("commit", "-m", "x", cwd=repo)
    head = _git("rev-parse", "HEAD", cwd=repo)
    out = ls_remote_sync(f"file://{repo}", None, ["HEAD", "refs/heads/main", "refs/heads/nope"],
                         allow_protocol="file")
    assert out == {"HEAD": head, "refs/heads/main": head}
    # The default allows https only.
    with pytest.raises(SafeGitError):
        ls_remote_sync(f"file://{repo}", None, ["HEAD"])
    assert "HOME" in os.environ and not (tmp_path / ".gitconfig").exists()
