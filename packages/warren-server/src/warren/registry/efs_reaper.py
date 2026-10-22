"""EFS access point TTL reaper — background asyncio loop (RT-09a).

Scans all access points for the deployment EFS file system, finds those
tagged warren.expires_at with a timestamp in the past, and deletes them.
Access points without warren.expires_at (i.e. currently active workspaces)
are never touched.
"""
from __future__ import annotations

import asyncio
import time
from typing import Any

import structlog

from warren.runtime.efs import purge_and_delete_access_point

log = structlog.get_logger(__name__)


def _list_all_access_points(efs_client: Any, efs_id: str) -> list[dict]:
    """Synchronous paginated list of all access points for efs_id.

    Must be called inside asyncio.to_thread — EFS client is synchronous.
    Paginates via NextToken loop (identical to _fetch_ssm_secrets pattern
    in ecs.py).
    """
    items: list[dict] = []
    kwargs: dict[str, Any] = {"FileSystemId": efs_id}
    while True:
        resp = efs_client.describe_access_points(**kwargs)
        items.extend(resp.get("AccessPoints", []))
        next_token = resp.get("NextToken")
        if not next_token:
            break
        kwargs["NextToken"] = next_token
    return items


async def run_efs_reaper(
    efs_client: Any,
    efs_id: str,
    server_id: str,
    *,
    interval_seconds: float = 21600.0,
    local_mount_path: str = "",
) -> None:
    """Async EFS access point cleanup loop; runs until cancelled.

    Only ever deletes access points tagged warren.server_instance == server_id.
    Multiple warren servers can share one EFS filesystem (each still gets its
    own per-workspace access point); without this check, one server's reaper
    would delete another server's storage the moment any access point on the
    shared filesystem expires, regardless of which server created it.

    `local_mount_path`: when set, the workspace's actual data directory is
    removed (not just its access point) before the access point is deleted --
    see `purge_and_delete_access_point`. Empty (default): only the access point
    is deleted, same as before issue #30a was fixed; the data is orphaned.
    """
    while True:
        try:
            now_ts = time.time()
            access_points = await asyncio.to_thread(
                _list_all_access_points, efs_client, efs_id
            )
            for ap in access_points:
                # Avoid double-delete on already-in-flight deletions
                if ap.get("LifeCycleState") in ("deleting", "deleted", "error"):
                    continue

                tags = {t["Key"]: t["Value"] for t in ap.get("Tags", [])}

                # Not this server's access point — never touch it, regardless
                # of expiry state (a missing tag is untagged/foreign, not ours).
                if tags.get("warren.server_instance") != server_id:
                    continue

                expires_at_str = tags.get("warren.expires_at")

                # No expiry tag — active workspace, skip (T-09-04)
                if expires_at_str is None:
                    continue

                try:
                    expires_ts = float(expires_at_str)
                except ValueError:
                    log.warning(
                        "efs_reaper_bad_expiry_tag",
                        access_point_id=ap["AccessPointId"],
                    )
                    continue

                if expires_ts < now_ts:
                    workspace_id = tags.get("warren.workspace_id", "unknown")
                    # AD2: a failed purge keeps the access point (deleting it would
                    # orphan the data for good); the next interval retries.
                    try:
                        await purge_and_delete_access_point(
                            efs_client, ap["AccessPointId"], workspace_id, local_mount_path
                        )
                    except Exception:
                        log.exception(
                            "efs_reaper_delete_failed",
                            workspace_id=workspace_id,
                            access_point_id=ap["AccessPointId"],
                        )

        except asyncio.CancelledError:
            log.info("efs_reaper_cancelled")
            raise
        except Exception:
            log.exception("efs_reaper_iteration_failed")

        await asyncio.sleep(interval_seconds)
