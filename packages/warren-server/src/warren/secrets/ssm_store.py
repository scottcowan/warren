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

# Reuse the existing names-only SSM fetch rather than re-implementing its
# pagination loop -- it's private to runtime/ecs.py by convention, not by any
# real module boundary; both modules are warren-server-internal.
from warren.runtime.ecs import _fetch_ssm_parameter_names


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
