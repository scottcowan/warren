"""Per-user ECS storage and network placement (WARREN_ECS_OWNER_STORAGE).

When configured, each user gets their own EFS filesystem and workspace security
group(s), defined statically by the deployment's IaC; the shared workspace task role
is unchanged and the network is the boundary between users. warren then places every
workspace on its owner's entry: the access point on the owner's filesystem, RunTask
in the owner's security groups, and secret delivery / purges / agent state through
the control plane's mount of the owner's filesystem. A user with no entry can't
create ECS workspaces.

The map is keyed by a name the operator can hardcode: the AWS principal name of the
caller's verified identity (`principal_name`), i.e. the IAM user name, or the
RoleSessionName of a trusted assumed role (for IAM Identity Center, the SSO user
name, e.g. `scowan` in `.../AWSReservedSSO_Dev_0123abcd/scowan`). Only ARNs that
already passed warren's trust check (aws_identity.derive_owner_id) yield one.

    WARREN_ECS_OWNER_STORAGE='{"scowan": {"efs_id": "fs-0123456789abcdef0",
        "security_group_ids": ["sg-0123456789abcdef0"],
        "local_mount_path": "/mnt/warren-efs/scowan"}}'

Absent or empty: the single shared filesystem (WARREN_EFS_ID, WARREN_ECS_SECURITY_GROUP_IDS,
WARREN_EFS_LOCAL_MOUNT_PATH), as before.
"""
from __future__ import annotations

import json
import posixpath
import re
from typing import Any

from pydantic import BaseModel, ConfigDict, field_validator
from warren_common.errors import ProvisionError

KEY_RE = re.compile(r"^[\w+=,.@-]{1,64}$")
_EFS_ID_RE = re.compile(r"^fs-[0-9a-f]{8,40}$")
_SG_ID_RE = re.compile(r"^sg-[0-9a-f]{8,17}$")


class OwnerStorage(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)

    efs_id: str
    security_group_ids: tuple[str, ...]
    local_mount_path: str

    @field_validator("efs_id")
    @classmethod
    def _efs_id(cls, v: str) -> str:
        if not _EFS_ID_RE.match(v):
            raise ValueError(f"efs_id {v!r} is not an EFS filesystem id (fs-...)")
        return v

    @field_validator("security_group_ids")
    @classmethod
    def _sgs(cls, v: tuple[str, ...]) -> tuple[str, ...]:
        if not v:
            raise ValueError("security_group_ids must not be empty")
        for sg in v:
            if not _SG_ID_RE.match(sg):
                raise ValueError(f"security group id {sg!r} is not sg-...")
        if len(set(v)) != len(v):
            raise ValueError("security_group_ids has duplicates")
        return v

    @field_validator("local_mount_path")
    @classmethod
    def _mount(cls, v: str) -> str:
        if not v.startswith("/") or v == "/" or posixpath.normpath(v) != v or "//" in v:
            raise ValueError(f"local_mount_path {v!r} must be an absolute, normalised path")
        return v


def parse_owner_storage(value: Any) -> dict[str, OwnerStorage]:
    """Parse and strictly validate the WARREN_ECS_OWNER_STORAGE JSON object."""
    if value in (None, "", {}):
        return {}
    if isinstance(value, str):
        value = json.loads(value)
    if not isinstance(value, dict):
        raise ValueError("WARREN_ECS_OWNER_STORAGE must be a JSON object of user -> storage")
    out: dict[str, OwnerStorage] = {}
    for key, entry in value.items():
        if not isinstance(key, str) or not KEY_RE.match(key):
            raise ValueError(f"WARREN_ECS_OWNER_STORAGE key {key!r} is not an AWS principal name")
        out[key] = entry if isinstance(entry, OwnerStorage) else OwnerStorage.model_validate(entry)
    for field, label in (("efs_id", "filesystem"), ("local_mount_path", "mount path")):
        seen: dict[str, str] = {}
        for key, entry in out.items():
            v = getattr(entry, field)
            if v in seen:
                raise ValueError(f"users {seen[v]!r} and {key!r} share the same {label} {v!r}")
            seen[v] = key
    mounts = sorted(e.local_mount_path for e in out.values())
    for a, b in zip(mounts, mounts[1:]):
        if b.startswith(a + "/"):
            raise ValueError(f"mount path {b!r} is inside {a!r}")
    sgs: dict[str, str] = {}
    for key, entry in out.items():
        for sg in entry.security_group_ids:
            if sg in sgs:
                raise ValueError(f"users {sgs[sg]!r} and {key!r} share security group {sg!r}")
            sgs[sg] = key
    return out


def principal_name(arn: str) -> str:
    """The IAM user name, or an assumed role's RoleSessionName, from a verified ARN."""
    if ":assumed-role/" in arn or ":user/" in arn:
        return arn.rsplit("/", 1)[-1]
    return ""


def storage_key_from_extra(extra: dict) -> str:
    key = extra.get("storage_key") or ""
    return key if isinstance(key, str) else ""


class StorageUnavailable(Exception):
    """A workspace's owner has no (or no longer an) entry in WARREN_ECS_OWNER_STORAGE."""


class WorkspaceStorageUnavailable(ProvisionError):
    """Provisioning refused for StorageUnavailable; 409 on the wire."""

    reason = "workspace_storage_unavailable"


NOT_SET_UP = (
    "you're not set up for workspaces on this deployment; ask an operator to add you to "
    "the workspace user list (WARREN_ECS_OWNER_STORAGE)"
)
LEGACY = (
    "this workspace was created on the shared filesystem before per-user storage was "
    "configured; destroy and recreate it"
)
