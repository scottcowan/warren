"""EBS storage for ECS workspaces (WARREN_ECS_WORKSPACE_STORAGE=ebs).

Each launch gets an ECS-managed EBS volume (RunTask volumeConfigurations, the task
definition's `configuredAtLaunch` volume) mounted at /var/lib/warren in both the
workspace and git-init containers. ECS can't attach an existing volume to a new task
(TaskManagedEBSVolumeConfiguration has no volume id), so a workspace persists through
snapshots:

    first launch       empty volume of WARREN_ECS_EBS_SIZE_GIB
    stop (any kind     the task stops; its volume is retained (deleteOnTermination
    but destroy)       false); once it is `available`: CreateSnapshot, record the id,
                       DeleteVolume (the snapshot completes on its own)
    relaunch           wait for the latest snapshot to be `completed`, launch from it,
                       then delete the older ones (the previous one is kept until the
                       new one has completed)
    destroy            delete every snapshot and the volume, immediately
    sweep              this server's leftover `available` volumes (a crash between stop
                       and snapshot, a task that died on its own) are snapshotted, or
                       deleted when their workspace is gone; snapshots of workspaces
                       that are gone are deleted

Everything is found and scoped by tag: the bare `warren=true` marker the IAM
conditions match (same convention as efs.py), plus warren.server_instance (never
another server's volumes) and warren.workspace_id. All boto3 calls go through
asyncio.to_thread.
"""
from __future__ import annotations

import asyncio
import time
from collections.abc import Awaitable, Callable
from datetime import UTC, datetime
from typing import Any

import structlog
from warren.runtime.efs import (
    TAG_MANAGED,
    TAG_OWNER_ID,
    TAG_SERVER_INSTANCE,
    TAG_WORKSPACE_ID,
    _validate_workspace_id,
)
from warren_common.errors import ProvisionError

log = structlog.get_logger(__name__)

VOLUME_NAME = "warren-workspace"
STORAGE_MODES = ("efs", "ebs")
TAG_STORAGE = "warren.storage"
# warren.storage values: a workspace's volumes/snapshots, and an owner's bare-repo seed
# (runtime/ebs_seeds.py). Every lookup filters on one of them, so the workspace lifecycle
# and its sweep never see a seed, and the seed code never sees a workspace's data.
STORAGE_WORKSPACE = "ebs"
STORAGE_SEED = "ebs-seed"
TAG_CREATED_AT = "warren.created_at"
TAG_SOURCE_VOLUME = "warren.source_volume"
# ECS's own reserved tag on the volumes it creates: the creating task's ARN.
TAG_ECS_CREATED = "AmazonECSCreated"

_LIVE_VOLUME_STATES = frozenset({"creating", "in-use"})
_USABLE_SNAPSHOT_STATES = frozenset({"pending", "completed"})


def storage_configured(settings: Any, mode: str) -> bool:
    """Whether this deployment can host a workspace on `mode` storage."""
    if mode == "ebs":
        return bool(
            getattr(settings, "ecs_ebs_infra_role_arn", "")
            and getattr(settings, "ecs_secrets_kms_key_id", "")
        )
    if mode == "efs":
        return bool(getattr(settings, "efs_id", "") or getattr(settings, "ecs_owner_storage", None))
    return False


def default_storage(settings: Any) -> str:
    mode = getattr(settings, "ecs_workspace_storage", "efs")
    return mode if mode in STORAGE_MODES else "efs"


def storage_from_extra(extra: dict) -> str:
    """A workspace's recorded mode; rows from before EBS storage existed are EFS."""
    mode = extra.get("ecs_storage") or "efs"
    return mode if mode in STORAGE_MODES else "efs"


class WorkspaceVolumeNotReady(ProvisionError):
    """The workspace's snapshot (or its previous task's volume) isn't ready yet; 503."""

    reason = "workspace_volume_not_ready"

    def __init__(self, message: str = "", *, retry_after_seconds: int = 15) -> None:
        super().__init__(message)
        self.retry_after_seconds = retry_after_seconds


class WorkspaceVolumeLost(ProvisionError):
    """The workspace has a recorded snapshot that no longer exists or failed; 409.
    Launching an empty volume instead would silently lose the workspace's data."""

    reason = "workspace_volume_lost"


class _MemorySnapshotStore:
    def __init__(self) -> None:
        self._rows: dict[str, str] = {}

    async def get(self, workspace_id: str) -> str | None:
        return self._rows.get(workspace_id)

    async def put(self, workspace_id: str, snapshot_id: str) -> None:
        self._rows[workspace_id] = snapshot_id

    async def delete(self, workspace_id: str) -> None:
        self._rows.pop(workspace_id, None)


def _code(exc: Exception) -> str:
    return (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "")


def _tags(resource: dict) -> dict[str, str]:
    return {t.get("Key", ""): t.get("Value", "") for t in resource.get("Tags", []) or []}


def _ts(value: Any) -> float:
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.timestamp()
    return 0.0


class EBSVolumes:
    """Snapshot lifecycle of this server's EBS-backed workspaces."""

    def __init__(
        self,
        server_id: str,
        settings: Any = None,
        *,
        ec2_client: Any = None,
        snapshot_store: Any = None,
        sleep: Callable[[float], Awaitable[Any]] = asyncio.sleep,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self._server_id = server_id
        self._settings = settings
        self._ec2: Any = ec2_client
        self.snapshot_store: Any = snapshot_store or _MemorySnapshotStore()
        self._sleep = sleep
        self._clock = clock

    def _setting(self, name: str, default: Any) -> Any:
        value = getattr(self._settings, name, None)
        return default if value is None or value == "" else value

    def _ensure_client(self) -> Any:
        if self._ec2 is None:
            import boto3  # deferred — keeps module import cheap

            region = getattr(self._settings, "aws_region", "us-east-1") or "us-east-1"
            self._ec2 = boto3.Session(region_name=region).client("ec2")
        return self._ec2

    # ------------------------------------------------------------------
    # Launch configuration
    # ------------------------------------------------------------------

    def _base_tags(self, workspace_id: str, owner_id: str | None) -> list[tuple[str, str]]:
        tags = [
            (TAG_MANAGED, "true"),
            (TAG_WORKSPACE_ID, workspace_id),
            (TAG_SERVER_INSTANCE, self._server_id),
            (TAG_STORAGE, STORAGE_WORKSPACE),
        ]
        if owner_id:
            tags.append((TAG_OWNER_ID, owner_id))
        return tags

    def volume_configuration(
        self,
        workspace_id: str,
        *,
        owner_id: str | None,
        snapshot_id: str | None,
        size_gib: int | None = None,
        tags: list[tuple[str, str]] | None = None,
    ) -> dict[str, Any]:
        """The RunTask volumeConfigurations entry: empty volume, or one from snapshot_id.

        `size_gib` with a snapshot: at least that size (a volume restored from a bare
        seed, runtime/ebs_seeds.py, is never smaller than the seed). `tags` replaces the
        workspace tags (the seed-refresh task's volume)."""
        if tags is None:
            tags = self._base_tags(workspace_id, owner_id)
        managed: dict[str, Any] = {
            "roleArn": self._setting("ecs_ebs_infra_role_arn", ""),
            "encrypted": True,
            "volumeType": self._setting("ecs_ebs_volume_type", "gp3"),
            "filesystemType": self._setting("ecs_ebs_filesystem_type", "ext4"),
            # Kept after the task stops so stop() can snapshot it; then warren deletes it.
            "terminationPolicy": {"deleteOnTermination": False},
            "tagSpecifications": [
                {
                    "resourceType": "volume",
                    "tags": [{"key": k, "value": v} for k, v in tags],
                    "propagateTags": "NONE",
                }
            ],
        }
        kms_key = self._setting("ecs_ebs_kms_key_id", "")
        if kms_key:
            managed["kmsKeyId"] = kms_key
        if snapshot_id:
            managed["snapshotId"] = snapshot_id
            rate = getattr(self._settings, "ecs_ebs_volume_initialization_rate", None)
            if isinstance(rate, int) and rate > 0:
                managed["volumeInitializationRate"] = rate
            if size_gib:
                managed["sizeInGiB"] = int(size_gib)
        else:
            managed["sizeInGiB"] = int(size_gib or self._setting("ecs_ebs_size_gib", 20))
        return {"name": VOLUME_NAME, "managedEBSVolume": managed}

    # ------------------------------------------------------------------
    # Lookups
    # ------------------------------------------------------------------

    def _filters(self, workspace_id: str | None, storage: str = STORAGE_WORKSPACE) -> list[dict[str, Any]]:
        filters = [
            {"Name": f"tag:{TAG_MANAGED}", "Values": ["true"]},
            {"Name": f"tag:{TAG_SERVER_INSTANCE}", "Values": [self._server_id]},
            {"Name": f"tag:{TAG_STORAGE}", "Values": [storage]},
        ]
        if workspace_id is not None:
            filters.append({"Name": f"tag:{TAG_WORKSPACE_ID}", "Values": [workspace_id]})
        return filters

    def _owned(self, resource: dict, workspace_id: str | None, storage: str = STORAGE_WORKSPACE) -> bool:
        # Re-check the filter client-side: never act on anything not provably ours.
        tags = _tags(resource)
        if tags.get(TAG_MANAGED) != "true" or tags.get(TAG_SERVER_INSTANCE) != self._server_id:
            return False
        if tags.get(TAG_STORAGE) != storage:
            return False
        return workspace_id is None or tags.get(TAG_WORKSPACE_ID) == workspace_id

    async def volumes(self, workspace_id: str | None = None, *, storage: str = STORAGE_WORKSPACE) -> list[dict]:
        ec2 = self._ensure_client()
        kwargs: dict[str, Any] = {"Filters": self._filters(workspace_id, storage)}
        out: list[dict] = []
        while True:
            resp = await asyncio.to_thread(ec2.describe_volumes, **kwargs)
            out.extend(v for v in resp.get("Volumes", []) if self._owned(v, workspace_id, storage))
            token = resp.get("NextToken")
            if not token:
                return out
            kwargs["NextToken"] = token

    async def snapshots(self, workspace_id: str | None = None, *, storage: str = STORAGE_WORKSPACE) -> list[dict]:
        ec2 = self._ensure_client()
        kwargs: dict[str, Any] = {"OwnerIds": ["self"], "Filters": self._filters(workspace_id, storage)}
        out: list[dict] = []
        while True:
            resp = await asyncio.to_thread(ec2.describe_snapshots, **kwargs)
            out.extend(s for s in resp.get("Snapshots", []) if self._owned(s, workspace_id, storage))
            token = resp.get("NextToken")
            if not token:
                return out
            kwargs["NextToken"] = token

    async def _snapshot(self, snapshot_id: str) -> dict | None:
        ec2 = self._ensure_client()
        try:
            resp = await asyncio.to_thread(ec2.describe_snapshots, SnapshotIds=[snapshot_id], OwnerIds=["self"])
        except Exception as exc:
            if _code(exc) == "InvalidSnapshot.NotFound":
                return None
            raise
        found = resp.get("Snapshots", [])
        return found[0] if found else None

    # ------------------------------------------------------------------
    # Mutations (each idempotent against "already gone")
    # ------------------------------------------------------------------

    async def _delete_volume(self, volume_id: str) -> bool:
        """True once the volume is gone; False if it is still attached."""
        ec2 = self._ensure_client()
        try:
            await asyncio.to_thread(ec2.delete_volume, VolumeId=volume_id)
        except Exception as exc:
            code = _code(exc)
            if code == "InvalidVolume.NotFound":
                return True
            if code in ("VolumeInUse", "IncorrectState"):
                return False
            raise
        log.info("ebs_volume_deleted", volume_id=volume_id)
        return True

    async def _delete_snapshot(self, snapshot_id: str) -> None:
        ec2 = self._ensure_client()
        try:
            await asyncio.to_thread(ec2.delete_snapshot, SnapshotId=snapshot_id)
        except Exception as exc:
            if _code(exc) == "InvalidSnapshot.NotFound":
                return
            raise
        log.info("ebs_snapshot_deleted", snapshot_id=snapshot_id)

    async def create_tagged_snapshot(
        self, volume_id: str, tags: list[tuple[str, str]], description: str
    ) -> str | None:
        """CreateSnapshot of `volume_id` tagged with `tags` (plus created_at and
        source_volume); None when the volume is already gone."""
        ec2 = self._ensure_client()
        snap_tags = [
            *tags,
            (TAG_CREATED_AT, datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")),
            (TAG_SOURCE_VOLUME, volume_id),
        ]
        try:
            resp = await asyncio.to_thread(
                ec2.create_snapshot,
                VolumeId=volume_id,
                Description=description,
                TagSpecifications=[
                    {"ResourceType": "snapshot", "Tags": [{"Key": k, "Value": v} for k, v in snap_tags]}
                ],
            )
        except Exception as exc:
            if _code(exc) == "InvalidVolume.NotFound":
                return None
            raise
        return resp["SnapshotId"]

    async def snapshot_and_delete(self, volume: dict) -> str | None:
        """Snapshot a detached volume, record the snapshot, delete the volume."""
        tags = _tags(volume)
        workspace_id = tags.get(TAG_WORKSPACE_ID, "")
        _validate_workspace_id(workspace_id)
        volume_id = volume["VolumeId"]
        snapshot_id = await self.create_tagged_snapshot(
            volume_id,
            self._base_tags(workspace_id, tags.get(TAG_OWNER_ID) or None),
            f"warren workspace {workspace_id}",
        )
        if snapshot_id is None:
            return None  # someone else (stop vs sweep) already handled it
        await self.snapshot_store.put(workspace_id, snapshot_id)
        log.info("ebs_snapshot_started", workspace_id=workspace_id, volume_id=volume_id, snapshot_id=snapshot_id)
        await self._delete_volume(volume_id)
        return snapshot_id

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    async def _settle(self, workspace_id: str, wait_seconds: float) -> bool:
        """Snapshot+delete every detached volume of the workspace, waiting up to
        `wait_seconds` for attached ones to detach. True when none are left."""
        deadline = self._clock() + wait_seconds
        poll = float(self._setting("ecs_ebs_poll_interval_seconds", 5.0))
        while True:
            vols = sorted(await self.volumes(workspace_id), key=lambda v: _ts(v.get("CreateTime")))
            live = False
            for vol in vols:
                state = vol.get("State", "")
                if state == "available":
                    await self.snapshot_and_delete(vol)
                elif state in _LIVE_VOLUME_STATES:
                    live = True
                elif state == "error":
                    log.warning("ebs_volume_error_state", workspace_id=workspace_id, volume_id=vol["VolumeId"])
            if not live:
                return True
            if self._clock() >= deadline:
                return False
            await self._sleep(poll)

    async def preserve(self, workspace_id: str) -> bool:
        """After a non-destroy stop: snapshot the retained volume and delete it. False
        when it didn't detach in time (the next launch or the sweep finishes the job)."""
        _validate_workspace_id(workspace_id)
        done = await self._settle(workspace_id, float(self._setting("ecs_ebs_detach_wait_seconds", 180.0)))
        if not done:
            log.warning("ebs_preserve_deferred", workspace_id=workspace_id)
        return done

    async def purge(self, workspace_id: str) -> bool:
        """Explicit destroy: delete every snapshot and volume of the workspace now. False
        when a volume was still attached at the deadline (the sweep deletes it, since its
        workspace is destroyed by then)."""
        _validate_workspace_id(workspace_id)
        recorded = await self.snapshot_store.get(workspace_id)
        snap_ids = {s["SnapshotId"] for s in await self.snapshots(workspace_id)}
        if recorded:
            snap_ids.add(recorded)
        for snap_id in sorted(snap_ids):
            await self._delete_snapshot(snap_id)
        await self.snapshot_store.delete(workspace_id)

        deadline = self._clock() + float(self._setting("ecs_ebs_detach_wait_seconds", 180.0))
        poll = float(self._setting("ecs_ebs_poll_interval_seconds", 5.0))
        while True:
            pending = False
            for vol in await self.volumes(workspace_id):
                if vol.get("State") in ("deleting", "deleted"):
                    continue
                if vol.get("State") in _LIVE_VOLUME_STATES or not await self._delete_volume(vol["VolumeId"]):
                    pending = True
            if not pending:
                log.info("ebs_workspace_purged", workspace_id=workspace_id, snapshots=len(snap_ids))
                return True
            if self._clock() >= deadline:
                log.warning("ebs_purge_volume_deferred", workspace_id=workspace_id)
                return False
            await self._sleep(poll)

    async def restore_point(self, workspace_id: str) -> str | None:
        """The snapshot the next launch restores from (None: a fresh, empty volume).

        Settles any retained volume first, then waits (bounded by
        WARREN_ECS_EBS_SNAPSHOT_WAIT_SECONDS) for the newest snapshot to complete,
        falling back to the previous one if the newest failed. Raises
        WorkspaceVolumeNotReady (retryable) on timeout, WorkspaceVolumeLost when the
        workspace had a snapshot and none is usable."""
        _validate_workspace_id(workspace_id)
        wait = float(self._setting("ecs_ebs_snapshot_wait_seconds", 45.0))
        retry_after = max(1, int(self._setting("ecs_start_retry_after_seconds", 5)))
        deadline = self._clock() + wait
        if not await self._settle(workspace_id, wait):
            raise WorkspaceVolumeNotReady(
                "the workspace's previous task is still releasing its volume; retry shortly",
                retry_after_seconds=retry_after,
            )

        recorded = await self.snapshot_store.get(workspace_id)
        snaps = {s["SnapshotId"]: s for s in await self.snapshots(workspace_id)}
        if recorded and recorded not in snaps:
            found = await self._snapshot(recorded)
            if found is not None:
                snaps[recorded] = found
        candidates = sorted(
            (s for s in snaps.values() if s.get("State") in _USABLE_SNAPSHOT_STATES),
            key=lambda s: _ts(s.get("StartTime")),
            reverse=True,
        )
        if not candidates:
            if recorded or snaps:
                raise WorkspaceVolumeLost(
                    f"workspace {workspace_id}'s volume snapshot is missing or failed; "
                    "its data can't be restored. Destroy and recreate the workspace"
                )
            return None

        poll = float(self._setting("ecs_ebs_poll_interval_seconds", 5.0))
        chosen: dict | None = None
        for snap in candidates:
            while snap.get("State") == "pending":
                if self._clock() >= deadline:
                    raise WorkspaceVolumeNotReady(
                        f"the workspace's volume snapshot is {snap.get('Progress') or '0%'} complete; "
                        "retry shortly",
                        retry_after_seconds=retry_after,
                    )
                await self._sleep(poll)
                snap = await self._snapshot(snap["SnapshotId"]) or {"SnapshotId": snap["SnapshotId"], "State": "error"}
            if snap.get("State") == "completed":
                chosen = snap
                break
            log.warning("ebs_snapshot_unusable", workspace_id=workspace_id, snapshot_id=snap["SnapshotId"])
        if chosen is None:
            raise WorkspaceVolumeLost(
                f"workspace {workspace_id}'s volume snapshots all failed; "
                "its data can't be restored. Destroy and recreate the workspace"
            )
        await self.snapshot_store.put(workspace_id, chosen["SnapshotId"])
        for snap_id in snaps:
            if snap_id != chosen["SnapshotId"]:
                await self._delete_snapshot(snap_id)
        return chosen["SnapshotId"]

    async def prune(self, workspace_id: str, snaps: list[dict]) -> int:
        """Keep the newest completed snapshot and anything newer (still pending);
        returns how many were deleted."""
        ordered = sorted(snaps, key=lambda s: _ts(s.get("StartTime")), reverse=True)
        newest_done = next((s for s in ordered if s.get("State") == "completed"), None)
        if newest_done is None:
            return 0
        cutoff = _ts(newest_done.get("StartTime"))
        deleted = 0
        for snap in ordered:
            if snap is newest_done:
                continue
            if _ts(snap.get("StartTime")) <= cutoff or snap.get("State") not in _USABLE_SNAPSHOT_STATES:
                await self._delete_snapshot(snap["SnapshotId"])
                deleted += 1
        settled = not any(s.get("State") == "pending" for s in ordered)
        if settled and await self.snapshot_store.get(workspace_id) != newest_done["SnapshotId"]:
            await self.snapshot_store.put(workspace_id, newest_done["SnapshotId"])
        return deleted

    async def sweep(
        self,
        workspace_exists: Callable[[str], Awaitable[bool]],
        lock_for: Callable[[str], Awaitable[Any]],
        *,
        min_age_seconds: float = 900.0,
        now: Callable[[], float] = time.time,
    ) -> dict[str, int]:
        """One pass over this server's leftover volumes and snapshots.

        A volume is only touched once it is `available` and older than
        min_age_seconds (ECS creates a launch's volume `available` before attaching
        it), under the workspace's lock (so never during its stop/launch/destroy)."""
        stats = {"snapshotted": 0, "volumes_deleted": 0, "snapshots_deleted": 0}
        for vol in await self.volumes():
            if vol.get("State") != "available":
                continue
            if now() - _ts(vol.get("CreateTime")) < min_age_seconds:
                continue
            workspace_id = _tags(vol).get(TAG_WORKSPACE_ID, "")
            try:
                _validate_workspace_id(workspace_id)
            except ProvisionError:
                log.warning("ebs_sweep_untagged_volume", volume_id=vol["VolumeId"])
                continue
            try:
                async with await lock_for(workspace_id):
                    if await workspace_exists(workspace_id):
                        if await self.snapshot_and_delete(vol):
                            stats["snapshotted"] += 1
                    elif await self._delete_volume(vol["VolumeId"]):
                        stats["volumes_deleted"] += 1
            except Exception:
                log.exception("ebs_sweep_volume_failed", volume_id=vol["VolumeId"], workspace_id=workspace_id)

        by_ws: dict[str, list[dict]] = {}
        for snap in await self.snapshots():
            by_ws.setdefault(_tags(snap).get(TAG_WORKSPACE_ID, ""), []).append(snap)
        for workspace_id, snaps in by_ws.items():
            try:
                _validate_workspace_id(workspace_id)
            except ProvisionError:
                continue
            try:
                async with await lock_for(workspace_id):
                    if await workspace_exists(workspace_id):
                        stats["snapshots_deleted"] += await self.prune(workspace_id, snaps)
                    else:
                        for snap in snaps:
                            await self._delete_snapshot(snap["SnapshotId"])
                            stats["snapshots_deleted"] += 1
                        await self.snapshot_store.delete(workspace_id)
            except Exception:
                log.exception("ebs_sweep_snapshots_failed", workspace_id=workspace_id)
        return stats
