"""AWS SSM Parameter Store mirror of `warren.secrets.store` for ECS deployments.

warren's own local `secrets` table (store.py) is the single source of truth
for secret VALUES on every runtime, including ECS. This module does not read
or decrypt that source of truth — it only mirrors each write/delete of a
secret to an SSM SecureString parameter, so that runtime/ecs.py's existing,
unchanged, per-provision read path (`_fetch_ssm_parameter_names` ->
task-definition `secrets` ARNs, resolved by the ECS agent itself at container
start, never by this process) keeps working exactly as it always has.

Two deliberate properties this design gets from mirroring on write rather than
syncing on provision:
  - Provisioning a workspace never calls PutParameter/DeleteParameter -- only
    the already-existing, read-only ListParametersByPath call, same as before
    this feature existed. Create/delete only happen on the caller's own rare
    PUT/DELETE /secrets call, not on every single provision.
  - SSM is no longer hand-populated by an operator with broad ssm:PutParameter
    access -- warren-server's own role is the only writer, and `kms_key_id`
    (WARREN_KMS_KEY_ID) lets a customer-managed CMK scope *decryption* to just
    the ECS task execution role, tighter than relying on IAM over the default
    `alias/aws/ssm` key alone.

Path convention (must match runtime/ecs.py's read side exactly) — isolated
per-owner, same as the local store (schema.sql's comment on the `secrets`
table): a workspace's provisioning path only ever lists parameters under its
OWN owner's segment, never another user's. No permission-tier segment
(removed 2026-10-13 — see store.py's module docstring for why):
    /{resource_prefix}/{server_id}/{owner_id}/{name}
"""

from __future__ import annotations

import asyncio
from typing import Any

import structlog

# Reuse the existing names-only SSM fetch rather than re-implementing its
# pagination loop -- it's private to runtime/ecs.py by convention, not by any
# real module boundary; both modules are warren-server-internal.
from warren.runtime.ecs import _fetch_ssm_parameter_names

log = structlog.get_logger(__name__)


def _param_path(resource_prefix: str, server_id: str, owner_id: str, name: str) -> str:
    return f"/{resource_prefix}/{server_id}/{owner_id}/{name}"


async def put_secret(
    ssm: Any,
    resource_prefix: str,
    server_id: str,
    owner_id: str,
    name: str,
    value: str,
    kms_key_id: str = "",
) -> None:
    """Mirror one secret write to SSM. Called only from the owner's own
    PUT /secrets call (store.py's write already happened) -- never from
    provisioning."""
    path = _param_path(resource_prefix, server_id, owner_id, name)

    def _put() -> None:
        kwargs: dict[str, Any] = {"Name": path, "Value": value, "Type": "SecureString", "Overwrite": True}
        if kms_key_id:
            kwargs["KeyId"] = kms_key_id
        ssm.put_parameter(**kwargs)

    await asyncio.to_thread(_put)


async def delete_secret(
    ssm: Any, resource_prefix: str, server_id: str, owner_id: str, name: str
) -> bool:
    """Mirror one secret delete to SSM. Called only from the owner's own
    DELETE /secrets call -- never from provisioning."""
    path = _param_path(resource_prefix, server_id, owner_id, name)

    def _delete() -> bool:
        try:
            ssm.delete_parameter(Name=path)
            return True
        except ssm.exceptions.ParameterNotFound:
            return False

    return await asyncio.to_thread(_delete)


async def list_secrets_for_owner(
    ssm: Any, resource_prefix: str, server_id: str, owner_id: str
) -> list[dict[str, str]]:
    """Return [{"name"}] mirrored under this owner's own SSM path segment --
    names only, never values, never another owner's. Diagnostic/
    reconciliation use only; routes/secrets.py's GET /secrets reads the local
    store (the actual source of truth), not this."""
    path = f"/{resource_prefix}/{server_id}/{owner_id}/"
    names = await asyncio.to_thread(_fetch_ssm_parameter_names, ssm, path)
    return [{"name": leaf} for leaf in names]


async def reconcile_mirror(
    ssm: Any,
    db: Any,
    cipher: Any,
    resource_prefix: str,
    server_id: str,
    kms_key_id: str = "",
) -> dict[str, int]:
    """Audit #13: converge this server's SSM mirror onto the local store (the
    source of truth) after a crash between the mirror write and the local write.
    Deletes parameters with no local row and re-puts local secrets with no
    parameter. A crash mid-overwrite (both sides present, values differ) is not
    detectable here without decrypting SSM values, which this role deliberately
    cannot do; it heals on the next write of that secret."""
    from warren.secrets import store as local_store

    for part in (resource_prefix, server_id):
        if not part or not part.strip() or "/" in part or part != part.strip():
            # An empty or slash-bearing segment would widen the listing (and the
            # orphan delete) beyond this server's own /{prefix}/{server_id}/ subtree.
            log.error(
                "secret_ssm_reconcile_refused_unsafe_scope",
                resource_prefix=resource_prefix,
                server_id=server_id,
            )
            return {"deleted": 0, "restored": 0}

    root = f"/{resource_prefix}/{server_id}/"
    mirrored = set(await asyncio.to_thread(_fetch_ssm_parameter_names, ssm, root))
    local = {
        f"{owner_id}/{name}": (owner_id, name)
        for owner_id, name in await local_store.list_all_secret_keys(db)
    }

    orphans = sorted(mirrored - local.keys())
    if orphans and not local:
        # An empty local store next to a populated mirror looks like a lost or
        # misplaced data dir, not a crash: refuse to wipe every owner's secrets.
        log.error("secret_ssm_reconcile_skipped_empty_local_store", orphans=len(orphans))
        orphans = []

    deleted = 0
    for key in orphans:
        owner_id, _, name = key.partition("/")
        if not name:
            continue
        await delete_secret(ssm, resource_prefix, server_id, owner_id, name)
        log.warning("secret_ssm_orphan_deleted", owner_id=owner_id, name=name)
        deleted += 1

    restored = 0
    for key in sorted(local.keys() - mirrored):
        owner_id, name = local[key]
        values = await local_store.resolve_secrets_for_names(db, cipher, owner_id, [name])
        if name not in values:
            continue
        await put_secret(
            ssm, resource_prefix, server_id, owner_id, name, values[name], kms_key_id=kms_key_id
        )
        log.warning("secret_ssm_mirror_restored", owner_id=owner_id, name=name)
        restored += 1
    return {"deleted": deleted, "restored": restored}
