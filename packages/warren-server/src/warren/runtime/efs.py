"""EFSMount — EFS access-point lifecycle for persistent workspace volumes (RT-09a).

Implements the WorkspaceVolume Protocol using EFS access points so workspace
data survives Fargate task destruction.

Security invariants:
    - workspace_id is validated against a strict allow-regex before any boto3
      call, blocking path-traversal into adjacent workspace paths (T-09-02).
    - Access point RootDirectory is per-workspace with PosixUser uid/gid 1000
      and permissions 0700; EFS enforces the root server-side (T-09-01).
    - attach() never sets warren.expires_at; that tag is only written by
      detach() so a live workspace is invisible to the reaper (T-09-04).
    - delete_access_point is NEVER called from detach(); only delete() is
      destructive (D-04, D-05).
    - All boto3 calls are wrapped in asyncio.to_thread (T-09-06).
"""
from __future__ import annotations

import asyncio
import re
import shutil
import time
from pathlib import Path
from typing import Any

import structlog

from warren_common.errors import ProvisionError
from warren_common.runtime.base import WorkspaceVolume

log = structlog.get_logger(__name__)

# ---------------------------------------------------------------------------
# Module-level constants
# ---------------------------------------------------------------------------

EFS_MOUNT_PATH = "/var/lib/warren"  # container mount root (D-01)

# Strict allow-list: alphanumeric + hyphen, 1-64 chars, must start
# with alphanumeric. Simultaneously guards against path traversal AND
# enforces the 64-char ClientToken limit (T-09-02).
_WORKSPACE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}$")

# Tag key constants — the canonical keys written to every warren-managed AP.
# TAG_MANAGED is a bare marker tag (key "warren", value "true") distinct from the
# namespaced warren.* keys below — it exists purely so IAM conditions
# (aws:RequestTag/warren, elasticfilesystem:AccessPointTag/warren in both
# terraform/main.tf and cdk/warren_stack.py) have an exact tag key to match.
# IAM's RequestTag/ResourceTag conditions match a tag key verbatim, not by
# prefix, so a namespaced key like warren.workspace_id can never satisfy a
# condition on "warren" — without this tag, CreateAccessPoint/DeleteAccessPoint
# would be denied outright wherever those IAM conditions are enforced.
TAG_MANAGED = "warren"
TAG_WORKSPACE_ID = "warren.workspace_id"
TAG_SERVER_INSTANCE = "warren.server_instance"
TAG_RETENTION_DAYS = "warren.retention_days"
TAG_EXPIRES_AT = "warren.expires_at"
# warren.owner_id: carries the creating user's id so an orchestrator-side IAM/app
# layer can enforce "only your own workspaces" -- IAM conditions can't express
# per-request ownership themselves, so this tag is the only way that check gets
# anything to read back (issue #6). Optional: omitted entirely when owner_id is
# unavailable/empty, same as the configurable extra tag below.
TAG_OWNER_ID = "warren.owner_id"

# LifeCycleState values that mean the access point is gone / in error.
_DEAD_STATES = frozenset({"deleting", "deleted", "error"})


# ---------------------------------------------------------------------------
# Input validation
# ---------------------------------------------------------------------------

def _validate_workspace_id(workspace_id: str) -> None:
    """Raise ProvisionError if workspace_id fails the allow-regex (T-09-02)."""
    if not _WORKSPACE_ID_RE.match(workspace_id):
        raise ProvisionError(
            f"workspace_id {workspace_id!r} is invalid — must match "
            r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}$"
        )


def purge_workspace_directory(local_mount_path: str, workspace_id: str) -> None:
    """Remove a workspace's actual data directory (issue #30a).

    Deleting the access point alone never frees space -- the directory at
    /var/lib/warren/workspaces/{id} lives on the EFS filesystem itself, which
    boto3's EFS API has no delete-directory call for. This only does anything
    when the control plane's own task has the filesystem NFS-mounted locally
    at `local_mount_path` (wired via IaC); see config.py's efs_local_mount_path
    docstring. Uses the workspace_id allow-regex so this can never be tricked
    into deleting outside workspaces/<id>. Shared by EFSMount.delete() and the
    reaper (AD2).
    """
    if not _WORKSPACE_ID_RE.match(workspace_id):
        log.warning("efs_purge_bad_workspace_id", workspace_id=workspace_id)
        return
    target = Path(local_mount_path) / "workspaces" / workspace_id
    if not target.is_dir():
        log.debug("efs_purge_noop_missing", path=str(target))
        return
    shutil.rmtree(target)
    log.info("efs_purged_directory", path=str(target), workspace_id=workspace_id)


async def purge_and_delete_access_point(
    efs_client: Any, access_point_id: str, workspace_id: str, local_mount_path: str
) -> None:
    """Purge the workspace's data, then delete its access point (AD2).

    Shared by EFSMount.delete() and the reaper. A failed purge raises before the
    access point is touched, so it stays findable and a later call can retry.
    AccessPointNotFound on delete is a no-op.
    """
    if local_mount_path:
        await asyncio.to_thread(purge_workspace_directory, local_mount_path, workspace_id)
    else:
        log.warning(
            "efs_data_orphaned_no_mount",
            workspace_id=workspace_id,
            access_point_id=access_point_id,
        )

    try:
        await asyncio.to_thread(efs_client.delete_access_point, AccessPointId=access_point_id)
    except Exception as exc:
        err_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
        if err_code == "AccessPointNotFound":
            log.debug(
                "efs_delete_already_gone",
                workspace_id=workspace_id,
                access_point_id=access_point_id,
            )
            return
        raise

    log.info("efs_delete_ok", workspace_id=workspace_id, access_point_id=access_point_id)


# ---------------------------------------------------------------------------
# EFSMount
# ---------------------------------------------------------------------------

class EFSMount:
    """WorkspaceVolume backed by AWS EFS access points.

    Each workspace gets a dedicated access point rooted at
    /var/lib/warren/workspaces/{workspace_id} with PosixUser uid=1000/gid=1000
    and directory permissions 0700 (D-01, D-02).

    attach()  — provision access point, return EFS_MOUNT_PATH
    detach()  — tag warren.expires_at (non-destructive, D-04)
    delete()  — purge workspace data, then remove access point (D-05, AD2)
    """

    def __init__(
        self,
        efs_id: str,
        server_id: str,
        *,
        retention_days: int = 7,
        settings: Any = None,
        efs_client: Any = None,
        local_mount_path: str | None = None,
    ) -> None:
        self._efs_id = efs_id
        # The control plane's mount of THIS filesystem (per-user storage gives each
        # filesystem its own); None falls back to settings.efs_local_mount_path.
        self._local_mount_path = local_mount_path
        self._server_id = server_id
        self._retention_days = retention_days
        self._settings = settings
        self._efs_client: Any = efs_client
        self.last_access_point_id: str | None = None

    # ------------------------------------------------------------------
    # Lazy boto3 client
    # ------------------------------------------------------------------

    def _ensure_client(self) -> Any:
        """Lazily initialise the EFS boto3 client (deferred import).

        Passes region_name explicitly so WARREN_AWS_REGION controls the boto3
        endpoint — same WR-02 reason documented in ecs.py.
        """
        if self._efs_client is None:
            import boto3  # deferred — keeps module import cheap

            region = getattr(self._settings, "aws_region", "us-east-1") or "us-east-1"
            session = boto3.Session(region_name=region)
            self._efs_client = session.client("efs")
        return self._efs_client

    # ------------------------------------------------------------------
    # Access point resolution helpers
    # ------------------------------------------------------------------

    async def _resolve_access_point(self, workspace_id: str) -> dict[str, Any] | None:
        """Page describe_access_points and return the full AP dict for workspace_id.

        Per research_corrections Correction 2: describe_access_points has NO
        tag-filter parameter — pagination + client-side matching is the only
        approach. The set of valid input members is: AccessPointId, FileSystemId,
        MaxResults, NextToken.

        Skips APs in dead states (deleting/deleted/error).
        """
        efs = self._ensure_client()
        kwargs: dict[str, Any] = {"FileSystemId": self._efs_id}
        while True:
            resp = await asyncio.to_thread(efs.describe_access_points, **kwargs)
            for ap in resp.get("AccessPoints", []):
                if ap.get("LifeCycleState", "") in _DEAD_STATES:
                    continue
                tags = {t["Key"]: t["Value"] for t in ap.get("Tags", [])}
                if tags.get(TAG_WORKSPACE_ID) == workspace_id:
                    return ap
            next_token = resp.get("NextToken")
            if not next_token:
                return None
            kwargs["NextToken"] = next_token

    async def _resolve_access_point_id(self, workspace_id: str) -> str | None:
        """Thin wrapper over _resolve_access_point returning just the id."""
        ap = await self._resolve_access_point(workspace_id)
        return ap["AccessPointId"] if ap else None

    # ------------------------------------------------------------------
    # WorkspaceVolume Protocol methods
    # ------------------------------------------------------------------

    async def attach(
        self,
        workspace_id: str,
        *,
        retention_days: int | None = None,
        owner_id: str | None = None,
    ) -> str:
        """Provision an EFS access point for workspace_id.

        Returns EFS_MOUNT_PATH (/var/lib/warren) — the container mount root.

        Idempotent: if AccessPointAlreadyExists is returned (Correction 1 —
        ClientToken does NOT silently return the existing AP), resolves and
        reuses the existing access point.

        Does NOT set warren.expires_at — live workspaces must be invisible to
        the reaper (T-09-04).
        """
        _validate_workspace_id(workspace_id)
        efs = self._ensure_client()

        effective_days = retention_days if retention_days is not None else self._retention_days
        tags = [
            {"Key": TAG_MANAGED, "Value": "true"},
            {"Key": TAG_WORKSPACE_ID, "Value": workspace_id},
            {"Key": TAG_SERVER_INSTANCE, "Value": self._server_id},
            {"Key": TAG_RETENTION_DAYS, "Value": str(effective_days)},
        ]
        if owner_id:
            tags.append({"Key": TAG_OWNER_ID, "Value": owner_id})

        # Configurable extra tag (issue #7) — purely additive, only written when
        # an external deployment has set both halves via WarrenSettings.
        extra_key = getattr(self._settings, "efs_access_point_tag_key", "") or ""
        extra_value = getattr(self._settings, "efs_access_point_tag_value", "") or ""
        if extra_key and extra_value:
            tags.append({"Key": extra_key, "Value": extra_value})

        try:
            resp = await asyncio.to_thread(
                efs.create_access_point,
                ClientToken=workspace_id,
                FileSystemId=self._efs_id,
                PosixUser={"Uid": 1000, "Gid": 1000},
                RootDirectory={
                    "Path": f"/var/lib/warren/workspaces/{workspace_id}",
                    # CreationInfo is required — without it EFS will not create
                    # the directory on first mount and the task will fail.
                    "CreationInfo": {
                        "OwnerUid": 1000,
                        "OwnerGid": 1000,
                        "Permissions": "0700",
                    },
                },
                Tags=tags,
            )
            access_point_id = resp["AccessPointId"]
        except Exception as exc:
            # Extract error code using the exact ecs.py idiom so non-ClientErrors
            # (missing .response) are handled gracefully.
            err_code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")
            if err_code == "AccessPointAlreadyExists":
                # Correction 1: ClientToken does NOT return the existing AP —
                # we must resolve it explicitly.
                existing_id = await self._resolve_access_point_id(workspace_id)
                log.debug(
                    "efs_attach_already_exists",
                    workspace_id=workspace_id,
                    existing_id=existing_id,
                )
                access_point_id = existing_id or ""
                if access_point_id:
                    # Reattaching an access point a prior detach() tagged with
                    # warren.expires_at (T-09-04 inverse): that tag must come off
                    # on reattach, or the reaper deletes this now-active
                    # workspace's storage once the old expiry passes, even
                    # though it's live again. untag_resource on an absent key
                    # is a no-op per the EFS API, so this is safe to call
                    # unconditionally rather than only when the tag is known
                    # to be present.
                    await asyncio.to_thread(
                        efs.untag_resource,
                        ResourceId=access_point_id,
                        TagKeys=[TAG_EXPIRES_AT],
                    )
            else:
                raise

        self.last_access_point_id = access_point_id
        log.info(
            "efs_attach_ok",
            workspace_id=workspace_id,
            access_point_id=access_point_id,
        )
        return EFS_MOUNT_PATH

    async def detach(self, workspace_id: str) -> None:
        """Tag warren.expires_at on the access point. Non-destructive (D-04).

        Reads warren.retention_days off the existing access point tag so the
        expiry honours any per-attach override, falling back to self._retention_days
        if the tag is absent or unparseable.

        The destructive call is reserved for delete() only — the reaper (Plan 09-02) owns it (D-04).
        """
        _validate_workspace_id(workspace_id)
        efs = self._ensure_client()

        ap = await self._resolve_access_point(workspace_id)
        if ap is None:
            log.debug("efs_detach_noop_already_gone", workspace_id=workspace_id)
            return

        access_point_id = ap["AccessPointId"]
        ap_tags = {t["Key"]: t["Value"] for t in ap.get("Tags", [])}

        # Honour the retention days written at attach time (may differ from the
        # instance default if attach() was called with a per-call override).
        try:
            days = int(ap_tags.get(TAG_RETENTION_DAYS, self._retention_days))
        except (ValueError, TypeError):
            days = self._retention_days

        expires_at = int(time.time()) + days * 86400

        await asyncio.to_thread(
            efs.tag_resource,
            ResourceId=access_point_id,
            Tags=[{"Key": TAG_EXPIRES_AT, "Value": str(expires_at)}],
        )
        log.info(
            "efs_detach_tagged",
            workspace_id=workspace_id,
            access_point_id=access_point_id,
            expires_at=expires_at,
        )

    async def delete(self, workspace_id: str) -> None:
        """Permanently delete the workspace's data and EFS access point (D-05).

        AD2: the data directory is purged first (via efs_local_mount_path, same
        as the reaper), because once the access point is gone the reaper can no
        longer find this workspace and the data would be orphaned for good. A
        failed purge raises before the access point is touched, so a retry
        still can. Treats AccessPointNotFound as a no-op so repeated delete
        calls are safe.
        """
        _validate_workspace_id(workspace_id)
        efs = self._ensure_client()

        access_point_id = await self._resolve_access_point_id(workspace_id)
        if access_point_id is None:
            log.debug("efs_delete_noop_not_found", workspace_id=workspace_id)
            return

        local_mount_path = self._local_mount_path
        if local_mount_path is None:
            local_mount_path = getattr(self._settings, "efs_local_mount_path", "") or ""
        if not getattr(self._settings, "efs_purge_workspace_data", True):
            local_mount_path = ""
        await purge_and_delete_access_point(efs, access_point_id, workspace_id, local_mount_path)


# Protocol conformance reference — keeps the import explicit and visible.
_ = WorkspaceVolume
