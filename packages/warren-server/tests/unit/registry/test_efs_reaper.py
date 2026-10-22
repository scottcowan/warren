"""Tests for warren.registry.efs_reaper — TTL access point cleanup loop."""
from __future__ import annotations

import asyncio
import time
from unittest.mock import MagicMock, call, patch

import pytest

from warren.registry.efs_reaper import run_efs_reaper

_SERVER_ID = "test-server"


def _mock_efs(access_points=None, next_token=None):
    """Build a mock EFS client with describe_access_points returning the given APs."""
    client = MagicMock(name="efs_client")
    response: dict = {"AccessPoints": access_points or []}
    if next_token:
        response["NextToken"] = next_token
    client.describe_access_points.return_value = response
    return client


def _expired_ap(
    ap_id: str, workspace_id: str = "ws-1", state: str = "available", server_id: str = _SERVER_ID
) -> dict:
    """Build an expired access point dict."""
    return {
        "AccessPointId": ap_id,
        "LifeCycleState": state,
        "Tags": [
            {"Key": "warren.workspace_id", "Value": workspace_id},
            {"Key": "warren.server_instance", "Value": server_id},
            {"Key": "warren.expires_at", "Value": str(int(time.time()) - 100)},
        ],
    }


def _future_ap(ap_id: str, workspace_id: str = "ws-2", server_id: str = _SERVER_ID) -> dict:
    """Build a future (not-yet-expired) access point dict."""
    return {
        "AccessPointId": ap_id,
        "LifeCycleState": "available",
        "Tags": [
            {"Key": "warren.workspace_id", "Value": workspace_id},
            {"Key": "warren.server_instance", "Value": server_id},
            {"Key": "warren.expires_at", "Value": str(int(time.time()) + 86400)},
        ],
    }


def _untagged_ap(ap_id: str, server_id: str = _SERVER_ID) -> dict:
    """Build an access point without warren.expires_at (active workspace)."""
    return {
        "AccessPointId": ap_id,
        "LifeCycleState": "available",
        "Tags": [
            {"Key": "warren.workspace_id", "Value": "ws-active"},
            {"Key": "warren.server_instance", "Value": server_id},
        ],
    }


async def _run_one_iteration(
    efs_client, efs_id: str = "fs-test", server_id: str = _SERVER_ID, local_mount_path: str = ""
) -> None:
    """Run one reaper iteration then stop.

    Patches asyncio.sleep to raise CancelledError on first call — this causes
    the reaper to run its iteration body exactly once and then propagate the
    CancelledError out of the while loop.
    """
    with patch("warren.registry.efs_reaper.asyncio.sleep", side_effect=asyncio.CancelledError):
        try:
            await run_efs_reaper(
                efs_client,
                efs_id,
                server_id,
                interval_seconds=0.001,
                local_mount_path=local_mount_path,
            )
        except asyncio.CancelledError:
            pass


def test_reaper_deletes_expired():
    """Expired AP owned by this server should be deleted."""
    efs = _mock_efs([_expired_ap("fsap-expired")])

    asyncio.run(_run_one_iteration(efs))

    efs.delete_access_point.assert_called_once_with(AccessPointId="fsap-expired")


def test_reaper_skips_future():
    """AP whose expiry is in the future must not be deleted."""
    efs = _mock_efs([_future_ap("fsap-future")])

    asyncio.run(_run_one_iteration(efs))

    efs.delete_access_point.assert_not_called()


def test_reaper_skips_untagged():
    """AP without warren.expires_at (active workspace) must not be deleted."""
    efs = _mock_efs([_untagged_ap("fsap-active")])

    asyncio.run(_run_one_iteration(efs))

    efs.delete_access_point.assert_not_called()


def test_reaper_skips_deleting_state():
    """AP in 'deleting' state must not trigger a second delete call."""
    ap = _expired_ap("fsap-deleting", state="deleting")
    efs = _mock_efs([ap])

    asyncio.run(_run_one_iteration(efs))

    efs.delete_access_point.assert_not_called()


def test_reaper_skips_other_server_even_if_expired():
    """Regression for issue #6: an expired AP tagged to a different
    warren.server_instance must never be deleted, even past its expiry —
    servers sharing one EFS filesystem must not delete each other's storage."""
    ap = _expired_ap("fsap-foreign", server_id="some-other-server")
    efs = _mock_efs([ap])

    asyncio.run(_run_one_iteration(efs, server_id=_SERVER_ID))

    efs.delete_access_point.assert_not_called()


def test_reaper_skips_ap_with_no_server_instance_tag():
    """An AP with no warren.server_instance tag at all is foreign/untagged,
    not implicitly ours — must not be deleted."""
    ap = {
        "AccessPointId": "fsap-no-tag",
        "LifeCycleState": "available",
        "Tags": [
            {"Key": "warren.workspace_id", "Value": "ws-x"},
            {"Key": "warren.expires_at", "Value": str(int(time.time()) - 100)},
        ],
    }
    efs = _mock_efs([ap])

    asyncio.run(_run_one_iteration(efs))

    efs.delete_access_point.assert_not_called()


def test_reaper_paginates():
    """Reaper must paginate describe_access_points via NextToken."""
    non_expired = _future_ap("fsap-future")
    expired = _expired_ap("fsap-expired-p2")

    efs = MagicMock(name="efs_client")
    # First call returns a non-expired AP and a NextToken
    first_resp = {"AccessPoints": [non_expired], "NextToken": "tok"}
    # Second call returns the expired AP with no NextToken
    second_resp = {"AccessPoints": [expired]}
    efs.describe_access_points.side_effect = [first_resp, second_resp]

    asyncio.run(_run_one_iteration(efs))

    assert efs.describe_access_points.call_count == 2
    # Second call must include NextToken="tok"
    second_call_kwargs = efs.describe_access_points.call_args_list[1][1]
    assert second_call_kwargs.get("NextToken") == "tok" or \
        efs.describe_access_points.call_args_list[1][0][0].get("NextToken") == "tok" or \
        efs.describe_access_points.call_args_list[1] == call(FileSystemId="fs-test", NextToken="tok")

    efs.delete_access_point.assert_called_once_with(AccessPointId="fsap-expired-p2")


def test_reaper_purges_workspace_directory_when_mount_path_configured(tmp_path):
    """Issue #30a: deleting the access point alone never frees space -- when
    local_mount_path is configured (the control plane has the EFS filesystem
    NFS-mounted there), the reaper must also remove the workspace's actual
    data directory, not just the access point."""
    workspace_dir = tmp_path / "workspaces" / "ws-1"
    workspace_dir.mkdir(parents=True)
    (workspace_dir / "some-file.txt").write_text("data")

    efs = _mock_efs([_expired_ap("fsap-expired", workspace_id="ws-1")])

    asyncio.run(_run_one_iteration(efs, local_mount_path=str(tmp_path)))

    assert not workspace_dir.exists()
    efs.delete_access_point.assert_called_once_with(AccessPointId="fsap-expired")


def test_reaper_skips_purge_when_mount_path_not_configured(tmp_path):
    """Without local_mount_path set (the default), the reaper must only delete
    the access point -- it has no way to reach the actual data, and must not
    pretend to by touching any local path."""
    workspace_dir = tmp_path / "workspaces" / "ws-1"
    workspace_dir.mkdir(parents=True)

    efs = _mock_efs([_expired_ap("fsap-expired", workspace_id="ws-1")])

    asyncio.run(_run_one_iteration(efs, local_mount_path=""))

    assert workspace_dir.exists()
    efs.delete_access_point.assert_called_once_with(AccessPointId="fsap-expired")


def test_reaper_purge_rejects_path_traversal_workspace_id(tmp_path):
    """A workspace_id tag that doesn't match the strict allow-regex must never
    reach shutil.rmtree -- reuses efs.py's own validation so this can't be
    tricked into deleting outside workspaces/<id>."""
    outside = tmp_path / "outside-marker"
    outside.mkdir()

    efs = _mock_efs([_expired_ap("fsap-expired", workspace_id="../outside-marker")])

    asyncio.run(_run_one_iteration(efs, local_mount_path=str(tmp_path)))

    assert outside.exists()
    efs.delete_access_point.assert_called_once_with(AccessPointId="fsap-expired")


def test_reaper_keeps_access_point_when_purge_fails(tmp_path):
    """AD2: a failed purge must leave the access point in place so the next
    interval can find and retry it; deleting it would orphan the data."""
    efs = _mock_efs([_expired_ap("fsap-1", workspace_id="ws-1"), _expired_ap("fsap-2", workspace_id="ws-2")])

    def _purge(_mount, workspace_id):
        if workspace_id == "ws-1":
            raise OSError("permission denied")

    with patch("warren.runtime.efs.purge_workspace_directory", side_effect=_purge):
        asyncio.run(_run_one_iteration(efs, local_mount_path=str(tmp_path)))

    efs.delete_access_point.assert_called_once_with(AccessPointId="fsap-2")


def test_reaper_cancelled_propagates():
    """CancelledError must propagate out of run_efs_reaper."""
    efs = _mock_efs([])

    async def _run():
        task = asyncio.create_task(
            run_efs_reaper(efs, "fs-test", _SERVER_ID, interval_seconds=100.0)
        )
        # Give the task a moment to enter its sleep
        await asyncio.sleep(0.01)
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            return True
        return False

    result = asyncio.run(_run())
    assert result is True, "CancelledError should propagate from run_efs_reaper"
