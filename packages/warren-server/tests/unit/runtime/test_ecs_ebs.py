"""EBS storage for ECS workspaces (runtime/ebs.py) and its KMS secrets delivery
(runtime/ecs_kms_secrets.py): launch configuration, the snapshot lifecycle on stop,
relaunch and destroy, the sweep, the envelope, and the per-workspace storage mode."""

from __future__ import annotations

import base64
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
from warren.runtime import ecs_kms_secrets as kms_secrets
from warren.runtime.ebs import (
    TAG_ECS_CREATED,
    EBSVolumes,
    WorkspaceVolumeLost,
    WorkspaceVolumeNotReady,
    default_storage,
    storage_configured,
    storage_from_extra,
)
from warren_common.errors import RuntimeUnreachable
from warren_common.models import FolderSpec
from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

from .test_ecs_runtime import _make_runtime, _mock_ecs, _mock_ssm

WS = "ws-abcdef12-0001"
SERVER = "test-server"
ROLE = "arn:aws:iam::123456789012:role/warren-ecs-infra"
KEY = "arn:aws:kms:eu-west-1:123456789012:key/0000-1111"
DATA_KEY = bytes(range(32))
T0 = datetime(2026, 10, 1, tzinfo=timezone.utc)


class _ClientError(Exception):
    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.response = {"Error": {"Code": code}}


class FakeEC2:
    """Just enough EC2 for the snapshot lifecycle, with tag filters."""

    def __init__(self) -> None:
        self.volumes: dict[str, dict] = {}
        self.snapshots: dict[str, dict] = {}
        self.calls: list[tuple[str, dict]] = []
        self._n = 0
        # volume id -> states it reports on successive describes before its final one
        self.transitions: dict[str, list[str]] = {}
        # snapshot id -> states it reports on successive describes
        self.snapshot_transitions: dict[str, list[str]] = {}

    def _id(self, prefix: str) -> str:
        self._n += 1
        return f"{prefix}-{self._n:017x}"

    @staticmethod
    def _match(resource: dict, filters: list[dict]) -> bool:
        tags = {t["Key"]: t["Value"] for t in resource.get("Tags", [])}
        for f in filters:
            key = f["Name"].removeprefix("tag:")
            if tags.get(key) not in f["Values"]:
                return False
        return True

    def add_volume(self, workspace_id=WS, state="available", server=SERVER, age_s=3600, task="arn:task/1"):
        vid = self._id("vol")
        self.volumes[vid] = {
            "VolumeId": vid,
            "State": state,
            "CreateTime": datetime.now(timezone.utc) - timedelta(seconds=age_s),
            "Tags": [
                {"Key": "warren", "Value": "true"},
                {"Key": "warren.workspace_id", "Value": workspace_id},
                {"Key": "warren.server_instance", "Value": server},
                {"Key": "warren.storage", "Value": "ebs"},
                {"Key": "warren.owner_id", "Value": "o-alice"},
                {"Key": TAG_ECS_CREATED, "Value": task},
            ],
        }
        return vid

    def add_snapshot(self, workspace_id=WS, state="completed", start=T0, server=SERVER):
        sid = self._id("snap")
        self.snapshots[sid] = {
            "SnapshotId": sid,
            "State": state,
            "StartTime": start,
            "Progress": "100%" if state == "completed" else "40%",
            "Tags": [
                {"Key": "warren", "Value": "true"},
                {"Key": "warren.workspace_id", "Value": workspace_id},
                {"Key": "warren.server_instance", "Value": server},
                {"Key": "warren.storage", "Value": "ebs"},
            ],
        }
        return sid

    def describe_volumes(self, **kw):
        self.calls.append(("describe_volumes", kw))
        out = []
        for vid, vol in self.volumes.items():
            if self._match(vol, kw.get("Filters", [])):
                pending = self.transitions.get(vid)
                if pending:
                    vol["State"] = pending.pop(0)
                out.append(dict(vol))
        return {"Volumes": out}

    def describe_snapshots(self, **kw):
        self.calls.append(("describe_snapshots", kw))
        if "SnapshotIds" in kw:
            sid = kw["SnapshotIds"][0]
            if sid not in self.snapshots:
                raise _ClientError("InvalidSnapshot.NotFound")
            pending = self.snapshot_transitions.get(sid)
            if pending:
                self.snapshots[sid]["State"] = pending.pop(0)
            return {"Snapshots": [dict(self.snapshots[sid])]}
        return {
            "Snapshots": [dict(s) for s in self.snapshots.values() if self._match(s, kw.get("Filters", []))]
        }

    def create_snapshot(self, **kw):
        self.calls.append(("create_snapshot", kw))
        if kw["VolumeId"] not in self.volumes:
            raise _ClientError("InvalidVolume.NotFound")
        sid = self._id("snap")
        self.snapshots[sid] = {
            "SnapshotId": sid,
            "State": "pending",
            "StartTime": datetime.now(timezone.utc),
            "Progress": "0%",
            "Tags": kw["TagSpecifications"][0]["Tags"],
        }
        return {"SnapshotId": sid, "State": "pending"}

    def delete_volume(self, **kw):
        self.calls.append(("delete_volume", kw))
        vol = self.volumes.get(kw["VolumeId"])
        if vol is None:
            raise _ClientError("InvalidVolume.NotFound")
        if vol["State"] == "in-use":
            raise _ClientError("VolumeInUse")
        del self.volumes[kw["VolumeId"]]

    def delete_snapshot(self, **kw):
        self.calls.append(("delete_snapshot", kw))
        if kw["SnapshotId"] not in self.snapshots:
            raise _ClientError("InvalidSnapshot.NotFound")
        del self.snapshots[kw["SnapshotId"]]

    def names(self) -> list[str]:
        return [c[0] for c in self.calls]


class FakeKMS:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def generate_data_key(self, **kw):
        self.calls.append(kw)
        return {
            "Plaintext": DATA_KEY,
            "CiphertextBlob": b"wrapped:" + json.dumps(kw["EncryptionContext"], sort_keys=True).encode(),
        }


def _settings(**over):
    base = dict(
        aws_region="eu-west-1",
        ecs_cluster="cl",
        ecs_workspace_storage="ebs",
        ecs_ebs_infra_role_arn=ROLE,
        ecs_secrets_kms_key_id=KEY,
        ecs_ebs_size_gib=20,
        ecs_ebs_volume_type="gp3",
        ecs_ebs_filesystem_type="ext4",
        ecs_ebs_kms_key_id="",
        ecs_ebs_volume_initialization_rate=None,
        ecs_ebs_snapshot_wait_seconds=45.0,
        ecs_ebs_detach_wait_seconds=180.0,
        ecs_ebs_poll_interval_seconds=5.0,
        ecs_start_retry_after_seconds=5,
        ecs_security_group_ids=["sg-0ccccccccccccccc3"],
        ecs_subnet_ids=["subnet-1"],
        efs_id="",
        efs_local_mount_path="",
        ecs_owner_storage={},
    )
    base.update(over)
    return SimpleNamespace(**base)


class _Clock:
    """Deterministic monotonic clock advanced by the injected sleep."""

    def __init__(self) -> None:
        self.t = 0.0
        self.sleeps: list[float] = []

    def __call__(self) -> float:
        return self.t

    async def sleep(self, s: float) -> None:
        self.sleeps.append(s)
        self.t += s


def _ebs(ec2: FakeEC2, settings=None, clock: _Clock | None = None) -> EBSVolumes:
    clock = clock or _Clock()
    return EBSVolumes(SERVER, settings or _settings(), ec2_client=ec2, sleep=clock.sleep, clock=clock)


def _runtime(ec2: FakeEC2 | None = None, settings=None, *, storage="ebs", secrets=None, clock=None):
    ec2 = ec2 or FakeEC2()
    ecs = _mock_ecs()
    rt = _make_runtime(ecs, _mock_ssm())
    rt._settings = settings or _settings()
    rt.ebs = _ebs(ec2, rt._settings, clock)
    rt._kms = FakeKMS()
    rt.storage_of = AsyncMock(return_value=storage)
    if secrets is not None:
        rt.secret_values = AsyncMock(return_value=secrets)
    return rt, ecs, ec2


def _spec(**over) -> WorkspaceSpec:
    kw = dict(
        workspace_id=WS, project="p", intent="dev", image="img:1", root_path="",
        owner_id="o-alice", ecs_storage="ebs",
    )
    kw.update(over)
    return WorkspaceSpec(**kw)


def _volume_config(ecs) -> dict:
    (vc,) = ecs.run_task.call_args.kwargs["volumeConfigurations"]
    return vc


def _env(ecs, container: str) -> dict[str, str]:
    for o in ecs.run_task.call_args.kwargs["overrides"]["containerOverrides"]:
        if o["name"] == container:
            return {e["name"]: e["value"] for e in o["environment"]}
    raise AssertionError(container)


# --- mode resolution ---------------------------------------------------------------


def test_storage_mode_helpers():
    assert storage_configured(_settings(), "ebs")
    assert not storage_configured(_settings(ecs_secrets_kms_key_id=""), "ebs")
    assert not storage_configured(_settings(ecs_ebs_infra_role_arn=""), "ebs")
    assert not storage_configured(_settings(), "efs")
    assert storage_configured(_settings(efs_id="fs-0aaaaaaaaaaaaaaa1"), "efs")
    assert default_storage(_settings(ecs_workspace_storage="ebs")) == "ebs"
    assert default_storage(SimpleNamespace()) == "efs"
    # A workspace keeps the mode it was created with; rows from before EBS are EFS.
    assert storage_from_extra({}) == "efs"
    assert storage_from_extra({"ecs_storage": "ebs"}) == "ebs"
    assert storage_from_extra({"ecs_storage": "bogus"}) == "efs"


def test_ecs_storage_is_persisted_for_reprovision():
    from warren.registry.registry import _SPEC_EXTRA_FIELDS, deserialize_spec_extra, serialize_spec_extra

    assert "ecs_storage" in _SPEC_EXTRA_FIELDS
    assert deserialize_spec_extra(serialize_spec_extra(_spec()))["ecs_storage"] == "ebs"


# --- first launch / relaunch ---------------------------------------------------------


async def test_first_launch_gets_an_empty_tagged_volume_and_a_cacheable_task_definition():
    rt, ecs, ec2 = _runtime()
    await rt.provision(_spec())

    vc = _volume_config(ecs)
    assert vc["name"] == "warren-workspace"
    m = vc["managedEBSVolume"]
    assert m["sizeInGiB"] == 20 and "snapshotId" not in m
    assert m["roleArn"] == ROLE and m["encrypted"] is True
    assert m["volumeType"] == "gp3" and m["filesystemType"] == "ext4"
    assert m["terminationPolicy"] == {"deleteOnTermination": False}
    (ts,) = m["tagSpecifications"]
    tags = {t["key"]: t["value"] for t in ts["tags"]}
    assert ts["resourceType"] == "volume"
    assert tags == {
        "warren": "true", "warren.workspace_id": WS, "warren.server_instance": SERVER,
        "warren.storage": "ebs", "warren.owner_id": "o-alice",
    }

    td = ecs.register_task_definition.call_args.kwargs
    assert td["volumes"] == [{"name": "warren-workspace", "configuredAtLaunch": True}]
    assert td["containerDefinitions"][0]["mountPoints"][0]["containerPath"] == "/var/lib/warren"
    assert "efsVolumeConfiguration" not in json.dumps(td)

    # No per-workspace id in the definition, so another workspace reuses it.
    await rt.provision(_spec(workspace_id="ws-abcdef12-0002"))
    assert ecs.register_task_definition.call_count == 1
    assert ecs.run_task.call_count == 2


async def test_kms_key_and_initialization_rate_are_passed_through():
    rt, ecs, ec2 = _runtime(settings=_settings(ecs_ebs_kms_key_id="alias/ebs", ecs_ebs_volume_initialization_rate=200))
    await rt.provision(_spec())
    m = _volume_config(ecs)["managedEBSVolume"]
    assert m["kmsKeyId"] == "alias/ebs"
    assert "volumeInitializationRate" not in m  # only meaningful when restoring a snapshot

    ec2.add_snapshot()
    rt._task_def_cache.clear()
    await rt.provision(_spec(provision_generation="arn:task/1"))
    m = _volume_config(ecs)["managedEBSVolume"]
    assert m["volumeInitializationRate"] == 200 and "sizeInGiB" not in m


async def test_relaunch_restores_the_newest_completed_snapshot_and_prunes_older_ones():
    ec2 = FakeEC2()
    old = ec2.add_snapshot(start=T0)
    new = ec2.add_snapshot(start=T0 + timedelta(hours=1))
    other = ec2.add_snapshot(workspace_id="ws-other-0001")
    foreign = ec2.add_snapshot(server="another-server")
    rt, ecs, _ = _runtime(ec2)

    await rt.provision(_spec(provision_generation="arn:task/1"))

    assert _volume_config(ecs)["managedEBSVolume"]["snapshotId"] == new
    assert "sizeInGiB" not in _volume_config(ecs)["managedEBSVolume"]
    assert set(ec2.snapshots) == {new, other, foreign}
    assert old not in ec2.snapshots
    assert await rt.ebs.snapshot_store.get(WS) == new


async def test_relaunch_snapshots_a_retained_volume_first_and_waits_for_it():
    """The task died on its own (reaper marked it stopped): its volume is still there."""
    ec2 = FakeEC2()
    prev = ec2.add_snapshot(start=T0)
    vol = ec2.add_volume()
    clock = _Clock()
    rt, ecs, _ = _runtime(ec2, clock=clock)
    original = ec2.create_snapshot

    def create_and_complete_later(**kw):
        resp = original(**kw)
        ec2.snapshot_transitions[resp["SnapshotId"]] = ["pending", "completed"]
        return resp

    ec2.create_snapshot = create_and_complete_later

    await rt.provision(_spec(provision_generation="arn:task/1"))

    (snap_call,) = [c for c in ec2.calls if c[0] == "create_snapshot"]
    assert snap_call[1]["VolumeId"] == vol
    new = _volume_config(ecs)["managedEBSVolume"]["snapshotId"]
    assert new != prev and ec2.snapshots[new]["State"] == "completed"
    assert vol not in ec2.volumes
    # The previous snapshot is only deleted once the new one has completed.
    assert prev not in ec2.snapshots
    assert clock.sleeps  # it actually waited
    names = ec2.names()
    assert names.index("create_snapshot") < names.index("delete_volume")


async def test_relaunch_fails_retryably_while_the_snapshot_is_still_pending():
    ec2 = FakeEC2()
    prev = ec2.add_snapshot(start=T0)
    pending = ec2.add_snapshot(state="pending", start=T0 + timedelta(hours=1))
    rt, ecs, _ = _runtime(ec2)

    with pytest.raises(WorkspaceVolumeNotReady) as err:
        await rt.provision(_spec(provision_generation="arn:task/1"))

    assert err.value.reason == "workspace_volume_not_ready"
    assert err.value.retry_after_seconds == 5
    assert "40%" in str(err.value)
    ecs.run_task.assert_not_called()
    assert {prev, pending} <= set(ec2.snapshots)  # nothing deleted


async def test_a_failed_newest_snapshot_falls_back_to_the_previous_one():
    ec2 = FakeEC2()
    prev = ec2.add_snapshot(start=T0)
    ec2.add_snapshot(state="error", start=T0 + timedelta(hours=1))
    rt, ecs, _ = _runtime(ec2)
    await rt.provision(_spec(provision_generation="arn:task/1"))
    assert _volume_config(ecs)["managedEBSVolume"]["snapshotId"] == prev


async def test_a_recorded_snapshot_that_is_gone_is_never_replaced_by_an_empty_volume():
    rt, ecs, ec2 = _runtime()
    await rt.ebs.snapshot_store.put(WS, "snap-0000000000000dead")
    with pytest.raises(WorkspaceVolumeLost):
        await rt.provision(_spec(provision_generation="arn:task/1"))
    ecs.run_task.assert_not_called()


async def test_a_volume_still_attached_to_a_stopping_task_is_waited_on_then_retried():
    ec2 = FakeEC2()
    ec2.add_volume(state="in-use")
    rt, ecs, _ = _runtime(ec2)
    with pytest.raises(WorkspaceVolumeNotReady):
        await rt.provision(_spec(provision_generation="arn:task/1"))
    ecs.run_task.assert_not_called()
    assert "create_snapshot" not in ec2.names()


async def test_a_live_task_is_adopted_without_touching_its_volume():
    ec2 = FakeEC2()
    ec2.add_volume(state="in-use")
    rt, ecs, _ = _runtime(ec2)
    rt._find_live_task = AsyncMock(return_value="arn:task/live")
    handle = await rt.provision(_spec(provision_generation="arn:task/1"))
    assert handle.runtime_id == "arn:task/live"
    ecs.run_task.assert_not_called()
    assert ec2.calls == []


# --- stop (reaper / idle / user) vs destroy ---------------------------------------------


async def test_stop_snapshots_the_retained_volume_then_deletes_it():
    ec2 = FakeEC2()
    prev = ec2.add_snapshot(start=T0)
    vol = ec2.add_volume(state="in-use")
    ec2.transitions[vol] = ["in-use", "available"]  # detaches after StopTask
    clock = _Clock()
    rt, ecs, _ = _runtime(ec2, clock=clock)

    await rt.stop(WorkspaceHandle(workspace_id=WS, runtime_id="arn:task/1", root_path=""))

    ecs.stop_task.assert_called_once()
    assert vol not in ec2.volumes
    (snap_call,) = [c for c in ec2.calls if c[0] == "create_snapshot"]
    tags = {t["Key"]: t["Value"] for t in snap_call[1]["TagSpecifications"][0]["Tags"]}
    assert tags["warren"] == "true" and tags["warren.workspace_id"] == WS
    assert tags["warren.server_instance"] == SERVER and tags["warren.owner_id"] == "o-alice"
    assert tags["warren.source_volume"] == vol and tags["warren.created_at"].endswith("Z")
    new = await rt.ebs.snapshot_store.get(WS)
    assert new in ec2.snapshots and ec2.snapshots[new]["State"] == "pending"
    # The previous snapshot stays until the new one completes.
    assert prev in ec2.snapshots
    assert "delete_snapshot" not in ec2.names()


async def test_stop_that_cannot_wait_for_detach_does_not_fail():
    ec2 = FakeEC2()
    ec2.add_volume(state="in-use")
    rt, ecs, _ = _runtime(ec2, settings=_settings(ecs_ebs_detach_wait_seconds=10))
    await rt.stop(WorkspaceHandle(workspace_id=WS, runtime_id="arn:task/1", root_path=""))
    assert "create_snapshot" not in ec2.names()  # left to the next launch / the sweep


async def test_destroy_deletes_the_volume_and_every_snapshot():
    ec2 = FakeEC2()
    a = ec2.add_snapshot(start=T0)
    b = ec2.add_snapshot(state="pending", start=T0 + timedelta(hours=1))
    other = ec2.add_snapshot(workspace_id="ws-other-0001")
    vol = ec2.add_volume(state="in-use")
    ec2.transitions[vol] = ["available"]
    rt, ecs, _ = _runtime(ec2)
    await rt.ebs.snapshot_store.put(WS, b)

    await rt.destroy(WorkspaceHandle(workspace_id=WS, runtime_id="arn:task/1", root_path=""))

    ecs.stop_task.assert_called_once()
    assert a not in ec2.snapshots and b not in ec2.snapshots
    assert other in ec2.snapshots
    assert vol not in ec2.volumes
    assert "create_snapshot" not in ec2.names()
    assert await rt.ebs.snapshot_store.get(WS) is None


async def test_destroy_with_the_volume_still_attached_leaves_it_to_the_sweep():
    ec2 = FakeEC2()
    snap = ec2.add_snapshot()
    vol = ec2.add_volume(state="in-use")
    rt, ecs, _ = _runtime(ec2, settings=_settings(ecs_ebs_detach_wait_seconds=10))
    await rt.destroy(WorkspaceHandle(workspace_id=WS, runtime_id="arn:task/1", root_path=""))
    assert snap not in ec2.snapshots
    assert vol in ec2.volumes  # still attached; swept once the row is destroyed


async def test_a_workspace_keeps_its_creation_mode_for_stop_and_destroy(tmp_path):
    """Default switched to ebs later: an EFS workspace still stops/destroys as EFS."""
    rt, ecs, ec2 = _runtime(storage="efs")
    vol = MagicMock(last_access_point_id="fsap-1")
    vol.attach, vol.detach = AsyncMock(), AsyncMock()
    rt._volume = vol
    rt._settings.efs_id = "fs-0aaaaaaaaaaaaaaa1"
    handle = WorkspaceHandle(workspace_id=WS, runtime_id="arn:task/1", root_path="")
    await rt.stop(handle)
    await rt.destroy(handle)
    vol.detach.assert_awaited_once_with(WS)
    assert ec2.calls == []

    # And an EBS workspace launched with the default back on efs is still EBS.
    rt2, ecs2, ec2b = _runtime(settings=_settings(ecs_workspace_storage="efs"))
    await rt2.provision(_spec())
    assert "volumeConfigurations" in ecs2.run_task.call_args.kwargs


async def test_registry_stop_preserves_and_registry_destroy_purges():
    """The idle reaper (registry.stop) takes the snapshot path; only destroy deletes."""
    from warren.registry.registry import WorkspaceRegistry

    runtime = MagicMock()
    runtime.stop, runtime.destroy = AsyncMock(), AsyncMock()
    row = SimpleNamespace(
        workspace_id=WS, status="running", container_id="arn:task/1", root_path="", spec_json="{}"
    )
    store = MagicMock()
    store.get = AsyncMock(return_value=row)
    store.update_status = AsyncMock()
    store.update_container_id = AsyncMock()
    reg = WorkspaceRegistry(runtime=runtime, store=store, server_id=SERVER)
    await reg.stop(WS)
    runtime.stop.assert_awaited_once()
    runtime.destroy.assert_not_awaited()
    await reg.destroy(WS)
    runtime.destroy.assert_awaited_once()


# --- secrets: KMS envelopes ------------------------------------------------------------------


def test_envelope_round_trip_and_context_binding():
    blob = kms_secrets.seal(
        DATA_KEY, b"wrapped", {"A": "1", "B": "two\nlines"}, workspace_id=WS, container="workspace",
        region="eu-west-1",
    )
    assert blob.startswith("v1:eu-west-1:")
    assert kms_secrets.wrapped_key_of(blob) == b"wrapped"
    assert kms_secrets.open_envelope(blob, DATA_KEY, workspace_id=WS, container="workspace") == {
        "A": "1", "B": "two\nlines",
    }
    with pytest.raises(Exception):
        kms_secrets.open_envelope(blob, DATA_KEY, workspace_id=WS, container="git-init")
    with pytest.raises(Exception):
        kms_secrets.open_envelope(blob, DATA_KEY, workspace_id="ws-other-0001", container="workspace")
    with pytest.raises(ValueError):
        kms_secrets.seal(DATA_KEY, b"w", {"BAD-NAME": "x"}, workspace_id=WS, container="workspace", region="eu-west-1")


@pytest.mark.parametrize("name", ["vector.json", "vector-git-init.json"])
def test_image_helper_vectors_match_the_server_envelope(name):
    """The Go helper's test vectors (images/ecs-base/secrets-decrypt/testdata) open with
    the server's reference decrypt and give exactly the helper's expected output."""
    path = Path(__file__).parents[3] / "images" / "ecs-base" / "secrets-decrypt" / "testdata" / name
    v = json.loads(path.read_text())
    values = kms_secrets.open_envelope(
        v["blob"], base64.b64decode(v["data_key"]), workspace_id=v["workspace_id"], container=v["container"]
    )
    lines = "".join(f"{k}={base64.b64encode(values[k].encode()).decode()}\n" for k in sorted(values))
    assert lines == v["output"]
    assert kms_secrets.wrapped_key_of(v["blob"]) == base64.b64decode(v["wrapped_key"])


async def test_secrets_reach_each_container_only_as_its_own_envelope():
    app = FolderSpec(name="app", type="git-worktree", mount="code/app",
                     url="https://github.com/org/app.git", branch="main")
    secrets = {"GITHUB_PAT": "ghp_secret", "ANTHROPIC_API_KEY": "sk-secret"}
    rt, ecs, _ = _runtime(secrets=secrets)
    await rt.provision(_spec(folders=[app], secret_names=list(secrets)))

    raw = json.dumps(ecs.run_task.call_args.kwargs)
    assert "ghp_secret" not in raw and "sk-secret" not in raw
    ws_env, init_env = _env(ecs, "workspace"), _env(ecs, "git-init")
    assert kms_secrets.open_envelope(ws_env["WARREN_SECRETS_BLOB"], DATA_KEY, workspace_id=WS,
                                     container="workspace") == {"ANTHROPIC_API_KEY": "sk-secret"}
    assert kms_secrets.open_envelope(init_env["WARREN_SECRETS_BLOB"], DATA_KEY, workspace_id=WS,
                                     container="git-init") == {"GITHUB_PAT": "ghp_secret"}
    assert init_env["WARREN_WORKSPACE_ID"] == WS
    contexts = [c["EncryptionContext"] for c in rt._kms.calls]
    assert contexts == [
        {"warren:workspace_id": WS, "warren:container": "workspace"},
        {"warren:workspace_id": WS, "warren:container": "git-init"},
    ]
    assert all(c["KeyId"] == KEY and c["KeySpec"] == "AES_256" for c in rt._kms.calls)
    # The wrapped key KMS returned is what the envelope carries.
    assert kms_secrets.wrapped_key_of(init_env["WARREN_SECRETS_BLOB"]).startswith(b"wrapped:")
    # The git-init container gets the volume too.
    td = ecs.register_task_definition.call_args.kwargs
    init_def = [c for c in td["containerDefinitions"] if c["name"] == "git-init"][0]
    assert init_def["mountPoints"][0]["sourceVolume"] == "warren-workspace"


async def test_no_secrets_no_envelope_and_no_kms_call():
    rt, ecs, _ = _runtime()
    await rt.provision(_spec())
    assert "WARREN_SECRETS_BLOB" not in _env(ecs, "workspace")
    assert rt._kms.calls == []


async def test_a_retry_resends_the_identical_request_with_the_persisted_envelopes():
    rt, ecs, _ = _runtime(secrets={"API_KEY": "v"})
    ecs.run_task.side_effect = [TimeoutError("lost response"), ecs.run_task.return_value]
    spec = _spec(secret_names=["API_KEY"])
    with pytest.raises(TimeoutError):
        await rt.provision(spec)
    first = ecs.run_task.call_args.kwargs
    await rt.provision(spec)
    second = ecs.run_task.call_args.kwargs
    assert first["clientToken"] == second["clientToken"]
    assert first["overrides"] == second["overrides"]
    assert len(rt._kms.calls) == 1


async def test_oversized_overrides_fail_before_run_task():
    rt, ecs, _ = _runtime(secrets={"BIG": "x" * 7000})
    from warren.runtime.ecs import OverridesTooLarge

    with pytest.raises(OverridesTooLarge) as err:
        await rt.provision(_spec(secret_names=["BIG"]))
    assert err.value.reason == "template_denied" and "8192" in str(err.value)
    ecs.run_task.assert_not_called()


async def test_ebs_secrets_need_no_efs_mount():
    rt, ecs, _ = _runtime(secrets={"API_KEY": "v"})
    await rt.provision(_spec(secret_names=["API_KEY"]))
    ecs.run_task.assert_called_once()


# --- preflight / placement -------------------------------------------------------------


@pytest.mark.parametrize("over, needle", [
    ({"ecs_ebs_infra_role_arn": ""}, "WARREN_ECS_EBS_INFRA_ROLE_ARN"),
    ({"ecs_ebs_infra_role_arn": "not-an-arn"}, "not an IAM role ARN"),
    ({"ecs_secrets_kms_key_id": ""}, "WARREN_ECS_SECRETS_KMS_KEY_ID"),
])
async def test_preflight_requires_the_ebs_settings(over, needle):
    rt, ecs, _ = _runtime(settings=_settings(**over))
    ecs.describe_clusters.return_value = {"clusters": [{"status": "ACTIVE"}]}
    with pytest.raises(RuntimeUnreachable, match=needle):
        await rt.preflight()


async def test_preflight_ok_with_ebs_configured():
    rt, ecs, _ = _runtime()
    ecs.describe_clusters.return_value = {"clusters": [{"status": "ACTIVE"}]}
    await rt.preflight()


async def test_ebs_needs_no_owner_storage_entry_but_keeps_an_owners_groups():
    from warren.runtime.ecs_storage import parse_owner_storage

    storage = parse_owner_storage({"alice": {
        "efs_id": "fs-0aaaaaaaaaaaaaaa1", "security_group_ids": ["sg-0aaaaaaaaaaaaaaa1"],
        "local_mount_path": "/mnt/warren-efs/alice",
    }})
    rt, ecs, _ = _runtime(settings=_settings(ecs_owner_storage=storage))
    rt._owner_storage = storage
    await rt.provision(_spec())  # no storage_key: shared groups, no 409
    sgs = ecs.run_task.call_args.kwargs["networkConfiguration"]["awsvpcConfiguration"]["securityGroups"]
    assert sgs == ["sg-0ccccccccccccccc3"]
    await rt.provision(_spec(workspace_id="ws-abcdef12-0002", storage_key="alice"))
    sgs = ecs.run_task.call_args.kwargs["networkConfiguration"]["awsvpcConfiguration"]["securityGroups"]
    assert sgs == ["sg-0aaaaaaaaaaaaaaa1"]


def test_registry_never_reads_an_ebs_workspace_through_an_efs_mount():
    from warren.registry.registry import WorkspaceRegistry

    reg = SimpleNamespace(settings=SimpleNamespace(ecs_owner_storage={}, efs_local_mount_path="/mnt/shared"))
    ebs_ws = SimpleNamespace(workspace_id=WS, spec_json=json.dumps({"ecs_storage": "ebs"}))
    efs_ws = SimpleNamespace(workspace_id=WS, spec_json=json.dumps({}))
    assert WorkspaceRegistry._ecs_mount(reg, ebs_ws) == ""
    assert WorkspaceRegistry._ecs_mount(reg, efs_ws) == "/mnt/shared"


# --- sweep ---------------------------------------------------------------------------------


async def test_sweep_snapshots_or_deletes_leftovers_and_only_this_servers():
    ec2 = FakeEC2()
    live_vol = ec2.add_volume(workspace_id="ws-live-0001")
    gone_vol = ec2.add_volume(workspace_id="ws-gone-0001")
    young_vol = ec2.add_volume(workspace_id="ws-live-0001", age_s=60)
    attached = ec2.add_volume(workspace_id="ws-live-0002", state="in-use")
    foreign = ec2.add_volume(workspace_id="ws-gone-0001", server="another-server")
    old_live = ec2.add_snapshot(workspace_id="ws-live-0002", start=T0)
    new_live = ec2.add_snapshot(workspace_id="ws-live-0002", start=T0 + timedelta(hours=1))
    gone_snap = ec2.add_snapshot(workspace_id="ws-gone-0002")
    foreign_snap = ec2.add_snapshot(workspace_id="ws-gone-0002", server="another-server")
    ebs = _ebs(ec2)
    locked: list[str] = []

    class _Lock:
        async def __aenter__(self):
            return None

        async def __aexit__(self, *a):
            return None

    async def lock_for(ws):
        locked.append(ws)
        return _Lock()

    async def exists(ws):
        return ws.startswith("ws-live")

    stats = await ebs.sweep(exists, lock_for, min_age_seconds=900)

    assert live_vol not in ec2.volumes and gone_vol not in ec2.volumes
    assert {young_vol, attached, foreign} <= set(ec2.volumes)
    snapped = [c[1]["VolumeId"] for c in ec2.calls if c[0] == "create_snapshot"]
    assert snapped == [live_vol]
    assert old_live not in ec2.snapshots and new_live in ec2.snapshots
    assert gone_snap not in ec2.snapshots and foreign_snap in ec2.snapshots
    assert stats == {"snapshotted": 1, "volumes_deleted": 1, "snapshots_deleted": 2}
    assert "ws-gone-0001" in locked and "ws-live-0001" in locked
    # Only ever filtered on this server's tags.
    for name, kw in ec2.calls:
        if name.startswith("describe_") and "Filters" in kw:
            assert {"Name": "tag:warren.server_instance", "Values": [SERVER]} in kw["Filters"]
            assert {"Name": "tag:warren", "Values": ["true"]} in kw["Filters"]


async def test_sweep_loop_uses_the_registry_rows_and_locks():
    from warren.registry.ebs_sweep import sweep_ebs

    ec2 = FakeEC2()
    vol = ec2.add_volume(workspace_id="ws-destroyed-01")
    runtime = SimpleNamespace(ebs=_ebs(ec2))
    rows = {"ws-destroyed-01": SimpleNamespace(status="destroyed")}
    registry = SimpleNamespace(
        runtime=runtime,
        store=SimpleNamespace(get=AsyncMock(side_effect=lambda ws: rows.get(ws))),
        _lock_for=AsyncMock(return_value=MagicMock(__aenter__=AsyncMock(), __aexit__=AsyncMock())),
    )
    stats = await sweep_ebs(registry, min_age_seconds=0)
    assert vol not in ec2.volumes and stats["volumes_deleted"] == 1
    assert await sweep_ebs(SimpleNamespace(runtime=SimpleNamespace())) == {}


# --- persistence -----------------------------------------------------------------------------


async def test_snapshot_store_and_attempt_envelopes_persist(tmp_path):
    from warren.registry.store import EbsSnapshotStore, LaunchAttemptStore, open_db

    db = await open_db(tmp_path / "w.db")
    try:
        snaps = EbsSnapshotStore(db)
        assert await snaps.get(WS) is None
        await snaps.put(WS, "snap-1")
        await snaps.put(WS, "snap-2")
        assert await snaps.get(WS) == "snap-2"
        await snaps.delete(WS)
        assert await snaps.get(WS) is None

        attempts = LaunchAttemptStore(db)
        base = {"generation": "", "fingerprint": "f", "task_definition_arn": "td", "client_token": "t"}
        await attempts.put(WS, base)
        assert await attempts.get(WS) == base
        await attempts.put(WS, {**base, "secrets_blobs": '{"workspace":"v1:..."}'})
        assert (await attempts.get(WS))["secrets_blobs"] == '{"workspace":"v1:..."}'
    finally:
        await db.close()
