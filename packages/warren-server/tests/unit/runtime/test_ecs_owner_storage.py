"""Per-user ECS storage (WARREN_ECS_OWNER_STORAGE): config validation, the principal
name key, the provisioning route's gate, and the runtime placing each workspace on
its owner's filesystem, security groups and mount only."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient
from pydantic import ValidationError
from warren.runtime.ecs_secrets import WORKSPACE_FILE, decode
from warren.runtime.ecs_storage import (
    OwnerStorage,
    parse_owner_storage,
    principal_name,
    storage_key_from_extra,
)
from warren_common.errors import ProvisionError
from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

from tests.unit.auth.test_aws_identity import (
    _AUDIENCE,
    _STS_RESPONSE_SSO_XML,
    _mock_post,
    _signed_request,
)
from tests.unit.routes.test_workspaces import (  # noqa: F401
    _fake_project,
    _make_fake_registry,
    env_defaults,
)

from .test_ecs_runtime import _make_runtime, _mock_ecs, _mock_ssm

FS_A, FS_B = "fs-0aaaaaaaaaaaaaaa1", "fs-0bbbbbbbbbbbbbbb2"
SG_A, SG_B = "sg-0aaaaaaaaaaaaaaa1", "sg-0bbbbbbbbbbbbbbb2"


def _entry(efs_id=FS_A, sgs=(SG_A,), mount="/mnt/warren-efs/alice"):
    return {"efs_id": efs_id, "security_group_ids": list(sgs), "local_mount_path": mount}


# --- config -------------------------------------------------------------------


def test_parses_a_valid_map():
    out = parse_owner_storage(json.dumps({
        "alice": _entry(), "bob.smith@x": _entry(FS_B, (SG_B,), "/mnt/warren-efs/bob"),
    }))
    assert out["alice"] == OwnerStorage(
        efs_id=FS_A, security_group_ids=(SG_A,), local_mount_path="/mnt/warren-efs/alice"
    )
    assert parse_owner_storage("") == {} and parse_owner_storage(None) == {}


@pytest.mark.parametrize("bad", [
    {"alice": _entry(efs_id="fs-xyz")},
    {"alice": _entry(efs_id="vol-0aaaaaaaaaaaaaaa1")},
    {"alice": _entry(sgs=())},
    {"alice": _entry(sgs=("sg-nothex!",))},
    {"alice": _entry(sgs=(SG_A, SG_A))},
    {"alice": _entry(mount="mnt/relative")},
    {"alice": _entry(mount="/mnt/../etc")},
    {"alice": _entry(mount="/mnt/a/")},
    {"alice": _entry(mount="/")},
    {"alice": {**_entry(), "extra": 1}},
    {"bad/key": _entry()},
    {"": _entry()},
    {"alice": _entry(), "bob": _entry(mount="/mnt/warren-efs/bob")},  # same filesystem
    {"alice": _entry(), "bob": _entry(FS_B, (SG_B,), "/mnt/warren-efs/alice")},  # same mount
    {"alice": _entry(), "bob": _entry(FS_B, (SG_B,), "/mnt/warren-efs/alice/bob")},  # nested
    {"alice": _entry(), "bob": _entry(FS_B, (SG_A,), "/mnt/warren-efs/bob")},  # shared SG
])
def test_rejects_invalid_maps(bad):
    with pytest.raises((ValueError, ValidationError)):
        parse_owner_storage(json.dumps(bad))


@pytest.mark.parametrize("bad", ["[]", '"x"', "not json"])
def test_rejects_non_objects(bad):
    with pytest.raises(ValueError):
        parse_owner_storage(bad)


def test_settings_fail_fast_on_a_bad_map(monkeypatch):
    from warren.config import WarrenSettings

    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_ECS_OWNER_STORAGE", json.dumps({"alice": _entry(efs_id="nope")}))
    with pytest.raises(ValidationError):
        WarrenSettings()
    monkeypatch.setenv("WARREN_ECS_OWNER_STORAGE", json.dumps({"alice": _entry()}))
    assert WarrenSettings().ecs_owner_storage["alice"].efs_id == FS_A
    monkeypatch.delenv("WARREN_ECS_OWNER_STORAGE")
    assert WarrenSettings().ecs_owner_storage == {}


# --- the key: AWS principal name ---------------------------------------------------


@pytest.mark.parametrize(("arn", "key"), [
    ("arn:aws:iam::123456789012:user/alice", "alice"),
    ("arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Dev_0123abcd/scowan", "scowan"),
    ("arn:aws:sts::123456789012:assumed-role/Operator/bob.smith@example.com", "bob.smith@example.com"),
    ("arn:aws:iam::123456789012:root", ""),
])
def test_principal_name(arn, key):
    assert principal_name(arn) == key


async def test_verified_arn_is_reported_only_once_trusted():
    from warren.auth.aws_identity import AwsIdentityError, verify_signed_caller_identity

    seen: list[str] = []
    with patch("httpx.AsyncClient.post", _mock_post(200, _STS_RESPONSE_SSO_XML)):
        with pytest.raises(AwsIdentityError):
            await verify_signed_caller_identity(_signed_request(), _AUDIENCE, [], on_verified_arn=seen.append)
        assert seen == []
        pattern = r"arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_DevAccess_abc123/[^/]+"
        await verify_signed_caller_identity(_signed_request(), _AUDIENCE, [pattern], on_verified_arn=seen.append)
    assert [principal_name(a) for a in seen] == ["alice"]


# --- provisioning route ---------------------------------------------------------------


def _route_client(monkeypatch, auth_headers, principal):
    monkeypatch.setenv("WARREN_RUNTIME_TYPE", "ecs")
    monkeypatch.setenv("WARREN_ECS_OWNER_STORAGE", json.dumps({"alice": _entry()}))
    fake_registry = _make_fake_registry()

    async def verify(signed, audience, patterns, on_verified_arn=None):
        on_verified_arn(f"arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Dev_0123abcd/{principal}")
        return "deadbeef" * 4

    return fake_registry, (
        patch("warren.app.WorkspaceRegistry", return_value=fake_registry),
        patch("warren.runtime.ecs.ECSRuntime", return_value=MagicMock()),
        patch("warren.auth.aws_identity.verify_signed_caller_identity", AsyncMock(side_effect=verify)),
        patch("warren.registry.efs_reaper.run_efs_reaper", AsyncMock()),
    )


_AWS = {"X-AWS-STS-Signed-Request": '{"url": "https://sts.amazonaws.com/"}'}


def test_unknown_user_is_refused_before_anything_is_provisioned(env_defaults, monkeypatch, auth_headers):  # noqa: F811
    fake_registry, patches = _route_client(monkeypatch, auth_headers, "mallory")
    with patches[0], patches[1], patches[2], patches[3]:
        with TestClient(app_module(), headers={**auth_headers, **_AWS}) as client:
            app_module().state.registry = fake_registry
            resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
    assert resp.status_code == 403
    body = resp.json()["detail"]
    assert body["error"] == "workspace_storage_not_configured"
    assert "workspace user list" in body["detail"] and body["user"] == "mallory"
    fake_registry._do_provision.assert_not_called()
    fake_registry.store.insert.assert_not_called()


def test_known_user_gets_their_storage_key_on_the_spec(env_defaults, monkeypatch, auth_headers):  # noqa: F811
    fake_registry, patches = _route_client(monkeypatch, auth_headers, "alice")
    with patches[0], patches[1], patches[2], patches[3]:
        with TestClient(app_module(), headers={**auth_headers, **_AWS}) as client:
            app_module().state.registry = fake_registry
            resp = client.post("/workspaces", json={"project": "demo", "template": "observe"})
    assert resp.status_code == 202
    _, spec = fake_registry._do_provision.call_args.args
    assert spec.storage_key == "alice"


def app_module():
    from warren.app import app

    return app


# --- runtime placement ------------------------------------------------------------------


def _owner_runtime(tmp_path: Path, keys=("alice", "bob")):
    fs = {"alice": (FS_A, SG_A), "bob": (FS_B, SG_B)}
    for k in keys:
        (tmp_path / k).mkdir()  # the control plane's mount point of each user's filesystem
    storage = parse_owner_storage({
        k: _entry(fs[k][0], (fs[k][1],), str(tmp_path / k)) for k in keys
    })
    ecs = _mock_ecs()
    rt = _make_runtime(ecs, _mock_ssm())
    rt._settings = SimpleNamespace(
        ecs_owner_storage=storage, efs_id="fs-0ccccccccccccccc3",
        ecs_security_group_ids=["sg-0ccccccccccccccc3"], efs_local_mount_path=str(tmp_path / "shared"),
    )
    rt._owner_storage = storage
    vols = {}
    for k in keys:
        v = MagicMock(last_access_point_id=f"fsap-{k}")
        v.attach, v.detach = AsyncMock(), AsyncMock()
        vols[k] = v
    rt._volumes = vols
    rt.secret_values = AsyncMock(side_effect=lambda owner, names: {"API_KEY": f"v-{owner}"})
    return rt, ecs, vols


def _spec(key: str, owner: str = "o-alice") -> WorkspaceSpec:
    return WorkspaceSpec(
        workspace_id="ws-abcdef12-0001", project="p", intent="dev", image="img:1", root_path="",
        owner_id=owner, storage_key=key, secret_names=["API_KEY"],
    )


def test_workspace_is_placed_on_its_owners_filesystem_sgs_and_mount_only(tmp_path):
    rt, ecs, vols = _owner_runtime(tmp_path)
    asyncio.run(rt.provision(_spec("alice")))

    vols["alice"].attach.assert_awaited_once()
    vols["bob"].attach.assert_not_awaited()
    efs = ecs.register_task_definition.call_args.kwargs["volumes"][0]["efsVolumeConfiguration"]
    assert efs["fileSystemId"] == FS_A
    assert efs["authorizationConfig"]["accessPointId"] == "fsap-alice"
    net = ecs.run_task.call_args.kwargs["networkConfiguration"]["awsvpcConfiguration"]
    assert net["securityGroups"] == [SG_A]
    ws_file = tmp_path / "alice" / "workspaces" / "ws-abcdef12-0001" / ".warren" / WORKSPACE_FILE
    assert decode(ws_file.read_bytes()) == {"API_KEY": "v-o-alice"}
    assert list((tmp_path / "bob").iterdir()) == [] and not (tmp_path / "shared").exists()


@pytest.mark.parametrize(("key", "message"), [("mallory", "workspace user list"), ("", "recreate")])
def test_unknown_or_legacy_owner_is_refused_with_no_aws_call(tmp_path, key, message):
    rt, ecs, vols = _owner_runtime(tmp_path)
    rt._preflight_ok = False
    with pytest.raises(ProvisionError, match=message):
        asyncio.run(rt.provision(_spec(key)))
    assert ecs.method_calls == [] and rt._logs.method_calls == []
    for v in vols.values():
        v.attach.assert_not_awaited()
    rt.secret_values.assert_not_awaited()


def test_legacy_workspace_relaunch_is_a_clean_409_not_a_crash(tmp_path):
    from warren.routes.workspaces import _provision_http_error
    from warren.runtime.ecs_storage import WorkspaceStorageUnavailable

    rt, _, _ = _owner_runtime(tmp_path)
    with pytest.raises(WorkspaceStorageUnavailable) as info:
        asyncio.run(rt.provision(_spec("")))
    err = _provision_http_error(info.value)
    assert err.status_code == 409
    assert err.detail["error"] == "workspace_storage_unavailable" and "recreate" in err.detail["detail"]


def test_owner_removed_from_the_map_is_refused(tmp_path):
    rt, ecs, _ = _owner_runtime(tmp_path, keys=("alice",))
    with pytest.raises(ProvisionError, match="workspace user list"):
        asyncio.run(rt.provision(_spec("bob")))
    ecs.run_task.assert_not_called()


@pytest.mark.parametrize("method", ["stop", "destroy"])
def test_stop_and_destroy_act_only_through_the_workspaces_own_filesystem(tmp_path, method):
    rt, ecs, vols = _owner_runtime(tmp_path)
    asyncio.run(rt.provision(_spec("alice")))
    rt.storage_key_of = AsyncMock(return_value="alice")
    handle = WorkspaceHandle(workspace_id="ws-abcdef12-0001", runtime_id="arn:task/1", root_path="")
    asyncio.run(getattr(rt, method)(handle))
    assert not (tmp_path / "alice" / "workspaces" / "ws-abcdef12-0001" / ".warren" / WORKSPACE_FILE).exists()
    if method == "destroy":
        vols["alice"].detach.assert_awaited_once()
    vols["bob"].detach.assert_not_awaited()


@pytest.mark.parametrize("known", [None, "", "mallory"])
def test_destroy_of_a_legacy_or_unknown_workspace_stops_the_task_and_touches_no_filesystem(tmp_path, known):
    rt, ecs, vols = _owner_runtime(tmp_path)
    rt.storage_key_of = AsyncMock(return_value=known)
    handle = WorkspaceHandle(workspace_id="ws-old", runtime_id="arn:task/old", root_path="")
    asyncio.run(rt.destroy(handle))
    ecs.stop_task.assert_called_once()
    for v in vols.values():
        v.detach.assert_not_awaited()


def test_without_the_setting_the_shared_filesystem_is_used(tmp_path):
    ecs = _mock_ecs()
    rt = _make_runtime(ecs, _mock_ssm())
    rt._settings = SimpleNamespace(efs_id=FS_A, ecs_security_group_ids=[SG_A], efs_local_mount_path="")
    vol = MagicMock(last_access_point_id="fsap-shared")
    vol.attach = AsyncMock()
    rt._volume = vol
    asyncio.run(rt.provision(WorkspaceSpec(
        workspace_id="ws-1", project="p", intent="dev", image="img:1", root_path="", owner_id="o",
    )))
    assert ecs.register_task_definition.call_args.kwargs["volumes"][0]["efsVolumeConfiguration"]["fileSystemId"] == FS_A
    assert ecs.run_task.call_args.kwargs["networkConfiguration"]["awsvpcConfiguration"]["securityGroups"] == [SG_A]


# --- registry: per-workspace mount -------------------------------------------------------


def test_registry_mount_is_the_owners_and_never_another_users(tmp_path):
    from warren.registry.registry import WorkspaceRegistry

    storage = parse_owner_storage({"alice": _entry(), "bob": _entry(FS_B, (SG_B,), "/mnt/warren-efs/bob")})
    reg = SimpleNamespace(settings=SimpleNamespace(ecs_owner_storage=storage, efs_local_mount_path="/mnt/shared"))

    def ws(extra):
        return SimpleNamespace(workspace_id="ws-1", spec_json=json.dumps(extra) if extra is not None else None)

    assert WorkspaceRegistry._ecs_mount(reg, ws({"storage_key": "bob"})) == "/mnt/warren-efs/bob"
    assert WorkspaceRegistry._ecs_mount(reg, ws({})) == ""  # legacy shared-filesystem row
    assert WorkspaceRegistry._ecs_mount(reg, ws(None)) == ""
    assert WorkspaceRegistry._ecs_mount(reg, ws({"storage_key": "mallory"})) == ""
    reg.settings = SimpleNamespace(ecs_owner_storage={}, efs_local_mount_path="/mnt/shared")
    assert WorkspaceRegistry._ecs_mount(reg, ws({})) == "/mnt/shared"


def test_storage_key_is_persisted_for_reprovision():
    from warren.registry.registry import _SPEC_EXTRA_FIELDS

    assert "storage_key" in _SPEC_EXTRA_FIELDS
    assert storage_key_from_extra({"storage_key": "alice"}) == "alice"
    assert storage_key_from_extra({"storage_key": 3}) == ""


# --- lifespan: one EFSMount and one reaper per filesystem --------------------------------


async def test_lifespan_wires_a_volume_and_a_reaper_per_user_filesystem(monkeypatch, tmp_path):
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.setenv("WARREN_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("WARREN_SERVER_ID", "test-server")
    monkeypatch.setenv("WARREN_RUNTIME_TYPE", "ecs")
    monkeypatch.setenv("WARREN_REAPER_ENABLED", "0")
    monkeypatch.setenv("WARREN_EFS_PURGE_WORKSPACE_DATA", "true")
    monkeypatch.setenv("WARREN_ECS_OWNER_STORAGE", json.dumps({
        "alice": _entry(), "bob": _entry(FS_B, (SG_B,), "/mnt/warren-efs/bob"),
    }))
    registry = MagicMock()
    registry.reconcile_from_disk = AsyncMock()
    reaped: list[tuple[str, str]] = []

    async def fake_reaper(client, efs_id, server_id, *, interval_seconds, local_mount_path):
        reaped.append((efs_id, local_mount_path))

    with (
        patch("warren.runtime.ecs.ECSRuntime.preflight", AsyncMock()),
        patch("warren.app.WorkspaceRegistry", return_value=registry),
        patch("warren.runtime.efs.EFSMount._ensure_client", return_value=MagicMock()),
        patch("warren.registry.efs_reaper.run_efs_reaper", fake_reaper),
    ):
        from warren.app import app, lifespan

        async with lifespan(app):
            await asyncio.sleep(0)
            rt = app.state.runtime
            assert {k: v._efs_id for k, v in rt._volumes.items()} == {"alice": FS_A, "bob": FS_B}
            assert rt._volume is None
            assert rt._volumes["bob"]._local_mount_path == "/mnt/warren-efs/bob"
            assert rt.storage_key_of is not None
    assert sorted(reaped) == sorted([(FS_A, "/mnt/warren-efs/alice"), (FS_B, "/mnt/warren-efs/bob")])


@pytest.mark.parametrize("path", ["terraform/main.tf", "cdk/warren_stack.py", "setup.sh"])
def test_control_plane_may_list_access_points(path):
    # efs.py's reattach and every per-filesystem reaper call DescribeAccessPoints.
    text = (Path(__file__).parents[5] / "resources" / "ecs" / path).read_text()
    assert '"elasticfilesystem:DescribeAccessPoints"' in text
