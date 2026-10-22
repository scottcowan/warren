"""Wave 0 RED scaffolds for EFSMount unit behaviors (Plan 09-01).

Tests are NOT marked xfail — Tasks 2 and 3 in this same plan turn them green.
A strict xfail would mask regressions after those tasks complete.

Structure mirrors test_ecs_runtime.py: synchronous helpers, asyncio.run() for
async calls, MagicMock injected directly into the instance attribute that would
otherwise hold the lazy boto3 client.
"""

from __future__ import annotations

import asyncio
import inspect
import time
from unittest.mock import MagicMock

import pytest


# ---------------------------------------------------------------------------
# Test helpers
# ---------------------------------------------------------------------------

def _mock_efs() -> MagicMock:
    """Return a pre-wired EFS client mock with verified response shapes."""
    m = MagicMock(name="efs_client")
    m.create_access_point.return_value = {
        "AccessPointId": "fsap-0123456789abcdef0",
        "AccessPointArn": "arn:aws:elasticfilesystem:us-east-1:123:access-point/fsap-0123456789abcdef0",
        "LifeCycleState": "creating",
        "Tags": [
            {"Key": "warren.workspace_id", "Value": "ws-abcdef12"},
            {"Key": "warren.server_instance", "Value": "test-server"},
            {"Key": "warren.retention_days", "Value": "7"},
        ],
    }
    m.describe_access_points.return_value = {
        "AccessPoints": [
            {
                "AccessPointId": "fsap-0123456789abcdef0",
                "LifeCycleState": "available",
                "Tags": [
                    {"Key": "warren.workspace_id", "Value": "ws-abcdef12"},
                    {"Key": "warren.server_instance", "Value": "test-server"},
                    {"Key": "warren.retention_days", "Value": "7"},
                ],
                "RootDirectory": {"Path": "/var/lib/warren/workspaces/ws-abcdef12"},
            }
        ]
    }
    m.tag_resource.return_value = {}
    m.delete_access_point.return_value = {}
    return m


def _make_mount(mock_efs: MagicMock, **kw) -> "object":
    """Construct an EFSMount with the boto3 client injected directly."""
    from warren.runtime.efs import EFSMount

    mount = EFSMount(
        efs_id="fs-0123456789abcdef0",
        server_id="test-server",
        retention_days=kw.pop("retention_days", 7),
        **kw,
    )
    mount._efs_client = mock_efs
    return mount


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_protocol_conformance():
    """EFSMount structurally satisfies WorkspaceVolume Protocol."""
    from warren_common.runtime.base import WorkspaceVolume
    from warren.runtime.efs import EFSMount

    mock_efs = _mock_efs()
    mount = _make_mount(mock_efs)

    for method_name in ("attach", "detach", "delete"):
        method = getattr(EFSMount, method_name, None)
        assert method is not None, f"EFSMount missing {method_name}"
        assert inspect.iscoroutinefunction(method), f"EFSMount.{method_name} must be async"

    assert isinstance(mount, WorkspaceVolume)


def test_attach_creates_access_point():
    """attach() calls create_access_point with correct FileSystemId, PosixUser, and RootDirectory."""
    mock_efs = _mock_efs()
    mount = _make_mount(mock_efs)

    asyncio.run(mount.attach("ws-abcdef12"))

    call_kwargs = mock_efs.create_access_point.call_args[1]
    assert call_kwargs["FileSystemId"] == "fs-0123456789abcdef0"
    assert call_kwargs["PosixUser"] == {"Uid": 1000, "Gid": 1000}
    assert call_kwargs["RootDirectory"]["Path"] == "/var/lib/warren/workspaces/ws-abcdef12"
    assert call_kwargs["RootDirectory"]["CreationInfo"] == {
        "OwnerUid": 1000,
        "OwnerGid": 1000,
        "Permissions": "0700",
    }
    assert "ClientToken" in call_kwargs
    assert len(call_kwargs["ClientToken"]) <= 64


def test_attach_returns_mount_path():
    """attach() returns /var/lib/warren (the container mount root)."""
    mock_efs = _mock_efs()
    mount = _make_mount(mock_efs)

    result = asyncio.run(mount.attach("ws-abcdef12"))
    assert result == "/var/lib/warren"


def test_attach_tags_workspace_and_retention():
    """attach() sets warren.workspace_id, warren.server_instance, warren.retention_days tags.

    attach() must NOT set warren.expires_at — an attached workspace must be
    invisible to the reaper (T-09-04).
    """
    mock_efs = _mock_efs()
    mount = _make_mount(mock_efs)

    asyncio.run(mount.attach("ws-abcdef12"))

    call_kwargs = mock_efs.create_access_point.call_args[1]
    tags_dict = {t["Key"]: t["Value"] for t in call_kwargs["Tags"]}

    assert tags_dict["warren.workspace_id"] == "ws-abcdef12"
    assert tags_dict["warren.server_instance"] == "test-server"
    assert tags_dict["warren.retention_days"] == "7"
    assert "warren.expires_at" not in tags_dict


def test_attach_retention_override():
    """attach(retention_days=30) overrides the instance default of 7."""
    mock_efs = _mock_efs()
    mount = _make_mount(mock_efs)

    asyncio.run(mount.attach("ws-abcdef12", retention_days=30))

    call_kwargs = mock_efs.create_access_point.call_args[1]
    tags_dict = {t["Key"]: t["Value"] for t in call_kwargs["Tags"]}
    assert tags_dict["warren.retention_days"] == "30"


def test_attach_tags_owner_id_when_provided():
    """attach(owner_id=...) sets warren.owner_id (issue #6) -- lets an
    orchestrator-side IAM/app layer enforce "only your own workspaces" by
    reading the tag back, since IAM conditions can't express per-request
    ownership themselves."""
    mock_efs = _mock_efs()
    mount = _make_mount(mock_efs)

    asyncio.run(mount.attach("ws-abcdef12", owner_id="user-123"))

    call_kwargs = mock_efs.create_access_point.call_args[1]
    tags_dict = {t["Key"]: t["Value"] for t in call_kwargs["Tags"]}
    assert tags_dict["warren.owner_id"] == "user-123"


def test_attach_omits_owner_id_tag_when_not_provided():
    """No owner_id -> no warren.owner_id tag at all, not an empty-string one --
    existing deployments that never pass it are unaffected."""
    mock_efs = _mock_efs()
    mount = _make_mount(mock_efs)

    asyncio.run(mount.attach("ws-abcdef12"))

    call_kwargs = mock_efs.create_access_point.call_args[1]
    tags_dict = {t["Key"]: t["Value"] for t in call_kwargs["Tags"]}
    assert "warren.owner_id" not in tags_dict


def test_attach_adds_configurable_extra_tag_when_both_settings_present():
    """Issue #7: an external deployment can require its own extra tag on every
    access point it creates (e.g. to scope its own CreateAccessPoint/
    DeleteAccessPoint IAM), via WarrenSettings.efs_access_point_tag_key/_value --
    without this app hardcoding knowledge of that deployment's tag scheme."""
    from types import SimpleNamespace

    mock_efs = _mock_efs()
    settings = SimpleNamespace(
        efs_access_point_tag_key="workspace-provisioner-service",
        efs_access_point_tag_value="example-dev",
    )
    mount = _make_mount(mock_efs, settings=settings)

    asyncio.run(mount.attach("ws-abcdef12"))

    call_kwargs = mock_efs.create_access_point.call_args[1]
    tags_dict = {t["Key"]: t["Value"] for t in call_kwargs["Tags"]}
    assert tags_dict["workspace-provisioner-service"] == "example-dev"


def test_attach_omits_extra_tag_when_settings_unset():
    """Purely additive: default (no settings, or settings without these two
    fields) -- existing deployments see no new tag at all."""
    mock_efs = _mock_efs()
    mount = _make_mount(mock_efs)

    asyncio.run(mount.attach("ws-abcdef12"))

    call_kwargs = mock_efs.create_access_point.call_args[1]
    tags_dict = {t["Key"]: t["Value"] for t in call_kwargs["Tags"]}
    assert len(tags_dict) == 4  # warren, workspace_id, server_instance, retention_days only


def test_attach_omits_extra_tag_when_only_key_set():
    """A key with no value (or vice versa) is treated as unset, not a tag with
    an empty-string value -- avoids a half-configured deployment silently
    writing a useless tag."""
    from types import SimpleNamespace

    mock_efs = _mock_efs()
    settings = SimpleNamespace(efs_access_point_tag_key="only-key-set", efs_access_point_tag_value="")
    mount = _make_mount(mock_efs, settings=settings)

    asyncio.run(mount.attach("ws-abcdef12"))

    call_kwargs = mock_efs.create_access_point.call_args[1]
    tags_dict = {t["Key"]: t["Value"] for t in call_kwargs["Tags"]}
    assert "only-key-set" not in tags_dict


def test_attach_idempotent_on_already_exists():
    """attach() recovers from AccessPointAlreadyExists by resolving the existing access point.

    Per research_corrections Correction 1: ClientToken does NOT silently return
    the existing access point — attach() must catch AccessPointAlreadyExists and
    resolve via describe_access_points.
    """
    import botocore.exceptions

    mock_efs = _mock_efs()
    error_response = {"Error": {"Code": "AccessPointAlreadyExists", "Message": "already exists"}}
    mock_efs.create_access_point.side_effect = botocore.exceptions.ClientError(
        error_response, "CreateAccessPoint"
    )
    # describe_access_points is already pre-wired to return an existing AP tagged ws-abcdef12

    mount = _make_mount(mock_efs)
    result = asyncio.run(mount.attach("ws-abcdef12"))

    assert result == "/var/lib/warren"
    assert mount.last_access_point_id == "fsap-0123456789abcdef0"


def test_attach_removes_expiry_tag_on_reattach():
    """Regression for issue #5: reattaching a previously-detached access point
    must remove warren.expires_at, or the reaper deletes this now-active
    workspace's storage once the stale expiry passes."""
    import botocore.exceptions

    mock_efs = _mock_efs()
    error_response = {"Error": {"Code": "AccessPointAlreadyExists", "Message": "already exists"}}
    mock_efs.create_access_point.side_effect = botocore.exceptions.ClientError(
        error_response, "CreateAccessPoint"
    )

    mount = _make_mount(mock_efs)
    asyncio.run(mount.attach("ws-abcdef12"))

    mock_efs.untag_resource.assert_called_once_with(
        ResourceId="fsap-0123456789abcdef0", TagKeys=["warren.expires_at"]
    )


def test_attach_rejects_unsafe_workspace_id():
    """attach() raises ProvisionError for path-traversal workspace_id without any boto3 call."""
    from warren_common.runtime.base import ProvisionError

    mock_efs = _mock_efs()
    mount = _make_mount(mock_efs)

    with pytest.raises(ProvisionError):
        asyncio.run(mount.attach("../../etc/passwd"))

    mock_efs.create_access_point.assert_not_called()


def test_detach_tags_expiry_and_does_not_delete():
    """detach() writes warren.expires_at and never calls delete_access_point (D-04)."""
    mock_efs = _mock_efs()
    mount = _make_mount(mock_efs)

    now = int(time.time())
    asyncio.run(mount.detach("ws-abcdef12"))

    mock_efs.tag_resource.assert_called_once()
    tag_call = mock_efs.tag_resource.call_args[1]
    assert tag_call["ResourceId"] == "fsap-0123456789abcdef0"
    tags_dict = {t["Key"]: t["Value"] for t in tag_call["Tags"]}
    assert "warren.expires_at" in tags_dict
    expires_at = float(tags_dict["warren.expires_at"])
    assert expires_at > now, "warren.expires_at must be in the future"

    mock_efs.delete_access_point.assert_not_called()


def test_detach_uses_tagged_retention_over_default():
    """detach() respects warren.retention_days tag (30 days) even when mount default is 7."""
    mock_efs = _mock_efs()
    # Override the AP tags to declare 30-day retention
    mock_efs.describe_access_points.return_value = {
        "AccessPoints": [
            {
                "AccessPointId": "fsap-0123456789abcdef0",
                "LifeCycleState": "available",
                "Tags": [
                    {"Key": "warren.workspace_id", "Value": "ws-abcdef12"},
                    {"Key": "warren.retention_days", "Value": "30"},
                ],
                "RootDirectory": {"Path": "/var/lib/warren/workspaces/ws-abcdef12"},
            }
        ]
    }
    mount = _make_mount(mock_efs)  # default retention_days=7

    asyncio.run(mount.detach("ws-abcdef12"))

    tag_call = mock_efs.tag_resource.call_args[1]
    tags_dict = {t["Key"]: t["Value"] for t in tag_call["Tags"]}
    expires_at = float(tags_dict["warren.expires_at"])
    eight_days_from_now = time.time() + 8 * 86400
    assert expires_at > eight_days_from_now, "30-day retention must produce expiry > 8 days out"


def test_detach_missing_access_point_is_noop():
    """detach() silently returns when no access point is found (idempotent)."""
    mock_efs = _mock_efs()
    mock_efs.describe_access_points.return_value = {"AccessPoints": []}

    mount = _make_mount(mock_efs)
    asyncio.run(mount.detach("ws-abcdef12"))  # must not raise

    mock_efs.tag_resource.assert_not_called()


def test_delete_removes_access_point():
    """delete() calls delete_access_point with the resolved AccessPointId."""
    mock_efs = _mock_efs()
    mount = _make_mount(mock_efs)

    asyncio.run(mount.delete("ws-abcdef12"))

    mock_efs.delete_access_point.assert_called_once()
    call_kwargs = mock_efs.delete_access_point.call_args[1]
    assert call_kwargs["AccessPointId"] == "fsap-0123456789abcdef0"


def test_delete_purges_workspace_data_before_access_point(tmp_path):
    """AD2: delete() must remove workspaces/<id> through efs_local_mount_path
    before the access point goes, or the reaper can never find the data again."""
    from types import SimpleNamespace

    workspace_dir = tmp_path / "workspaces" / "ws-abcdef12"
    workspace_dir.mkdir(parents=True)
    (workspace_dir / "f.txt").write_text("data")
    sibling = tmp_path / "workspaces" / "ws-other"
    sibling.mkdir()

    mock_efs = _mock_efs()
    seen: list[bool] = []
    mock_efs.delete_access_point.side_effect = lambda **_: seen.append(workspace_dir.exists()) or {}
    mount = _make_mount(mock_efs, settings=SimpleNamespace(efs_local_mount_path=str(tmp_path)))

    asyncio.run(mount.delete("ws-abcdef12"))

    assert not workspace_dir.exists()
    assert sibling.exists()
    assert seen == [False]


def test_delete_keeps_access_point_when_purge_fails(tmp_path, monkeypatch):
    """A failed purge must leave the access point in place so delete() can be retried."""
    from types import SimpleNamespace

    import warren.runtime.efs as efs_mod

    (tmp_path / "workspaces" / "ws-abcdef12").mkdir(parents=True)

    def _boom(*_a, **_k):
        raise OSError("nfs gone")

    monkeypatch.setattr(efs_mod.shutil, "rmtree", _boom)
    mock_efs = _mock_efs()
    mount = _make_mount(mock_efs, settings=SimpleNamespace(efs_local_mount_path=str(tmp_path)))

    with pytest.raises(OSError):
        asyncio.run(mount.delete("ws-abcdef12"))
    mock_efs.delete_access_point.assert_not_called()


def test_delete_without_mount_path_still_deletes_access_point(tmp_path):
    mock_efs = _mock_efs()
    mount = _make_mount(mock_efs)

    asyncio.run(mount.delete("ws-abcdef12"))

    mock_efs.delete_access_point.assert_called_once()


def test_delete_not_found_is_noop():
    """delete() treats AccessPointNotFound as a no-op (D-05)."""
    import botocore.exceptions

    mock_efs = _mock_efs()
    error_response = {"Error": {"Code": "AccessPointNotFound", "Message": "not found"}}
    mock_efs.delete_access_point.side_effect = botocore.exceptions.ClientError(
        error_response, "DeleteAccessPoint"
    )
    # describe_access_points still returns the AP so we attempt the delete
    mount = _make_mount(mock_efs)

    asyncio.run(mount.delete("ws-abcdef12"))  # must not raise


def test_resolve_paginates_access_points():
    """_resolve_access_point pages via NextToken to find the target access point.

    Per research_corrections Correction 2: describe_access_points has no tag
    filter — pagination and client-side matching are required.
    """
    mock_efs = _mock_efs()

    # First page: unrelated AP + NextToken
    first_page = {
        "AccessPoints": [
            {
                "AccessPointId": "fsap-unrelated000000001",
                "LifeCycleState": "available",
                "Tags": [{"Key": "warren.workspace_id", "Value": "ws-other"}],
                "RootDirectory": {"Path": "/var/lib/warren/workspaces/ws-other"},
            }
        ],
        "NextToken": "page2token",
    }
    # Second page: the target AP, no NextToken
    second_page = {
        "AccessPoints": [
            {
                "AccessPointId": "fsap-0123456789abcdef0",
                "LifeCycleState": "available",
                "Tags": [
                    {"Key": "warren.workspace_id", "Value": "ws-abcdef12"},
                    {"Key": "warren.retention_days", "Value": "7"},
                ],
                "RootDirectory": {"Path": "/var/lib/warren/workspaces/ws-abcdef12"},
            }
        ]
    }
    mock_efs.describe_access_points.side_effect = [first_page, second_page]

    mount = _make_mount(mock_efs)
    asyncio.run(mount.delete("ws-abcdef12"))  # triggers _resolve

    assert mock_efs.describe_access_points.call_count == 2
    second_call_kwargs = mock_efs.describe_access_points.call_args_list[1][1]
    assert second_call_kwargs.get("NextToken") == "page2token"
