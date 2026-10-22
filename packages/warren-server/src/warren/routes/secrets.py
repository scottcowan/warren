"""Server-side secret store routes — isolated per caller.

warren's own local `secrets` table (`warren.secrets.store`, Fernet-encrypted
from WARREN_SECRET_KEY) is the single source of truth on EVERY runtime,
including ECS -- there is no SSM Parameter Store backend to read from here.
When `settings.runtime_type == "ecs"`, a write or delete is additionally
mirrored to an SSM SecureString parameter (`warren.secrets.ssm_store`) purely
so runtime/ecs.py's existing, unchanged, read-only provisioning path keeps
finding what it expects; GET /secrets always answers from the local store,
never from SSM. See warren.secrets's package docstring and ssm_store.py's
module docstring for the full reasoning.

Isolation: every secret is owned by the caller who created it (`owner_id`,
from `warren.auth.deps.resolve_owner_id` — warren's own bearer-token user_id
on podman/docker, the caller's verified AWS IAM identity on ECS), on both
backends — the SSM mirror's path carries the same owner_id segment. There is
no admin override and no server-wide secret: a caller can only ever create,
list, or delete their OWN secrets.

No permission-tier concept (removed 2026-10-13): a workspace's provisioning
resolves exactly the secret names its resolved template declares
(routes/workspaces.py, runtime/ecs.py's `_filter_secrets_by_name`), not a
tier -- a tier bought no real isolation (every secret was already owner-scoped)
but did silently starve readonly-permission templates of secrets like
WARREN_GIT_SSH_KEY/GITHUB_PAT that they still needed just to clone repos.
"""

from __future__ import annotations

import re

import structlog
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel

from warren.audit import audit_event
from warren.auth.deps import resolve_owner_id
from warren.secrets import store as local_store
from warren.secrets.cipher import LocalCipher

log = structlog.get_logger(__name__)

router = APIRouter()

# SSM Parameter Store's allowed name charset (letters, numbers, `.`, `-`, `_`,
# `/`) -- validated up front so a bad name fails fast on podman/docker too,
# rather than only once it reaches the ECS mirror step.
_SSM_SAFE_NAME_RE = re.compile(r"^[a-zA-Z0-9_.\-/]+$")

# SSM Standard tier caps a parameter *value* at 4 KB.
_SSM_MAX_VALUE_BYTES = 4096


class SecretWriteRequest(BaseModel):
    name: str
    value: str


class SecretMeta(BaseModel):
    name: str


async def _mirror_put_to_ssm(request: Request, owner_id: str, name: str, value: str) -> None:
    """Best-effort SSM mirror for ECS deployments, called BEFORE the local
    write (see put_secret's own comment on why the mirror runs first) -- a
    mirror failure is raised (as a 502) rather than only logged, and the
    local write never runs at all in that case, so the caller sees neither
    half silently succeed while the other failed.

    Audit R14: this docstring and the error message below used to describe
    the OLD ordering (local write first, mirror second) -- wrong since the
    reorder above. Keep both in sync with whichever write actually runs
    first if that ever changes again.
    """
    settings = request.app.state.settings
    if getattr(settings, "runtime_type", "podman") != "ecs":
        return
    from warren.secrets import ssm_store

    try:
        ssm = request.app.state.runtime.ssm_client()
        await ssm_store.put_secret(
            ssm, settings.ecs_resource_prefix, settings.server_id, owner_id,
            name, value, kms_key_id=getattr(settings, "kms_key_id", "") or "",
        )
    except Exception as exc:
        log.warning("secret_ssm_mirror_failed", owner_id=owner_id, name=name, exc_info=True)
        raise HTTPException(
            status_code=502,
            detail={
                "error": "ssm_mirror_failed",
                "detail": (
                    f"secret {name!r} was NOT saved -- the SSM mirror write failed before "
                    f"the local write ran: {exc}. Nothing changed; retry the write."
                ),
            },
        ) from exc


async def _mirror_delete_to_ssm(request: Request, owner_id: str, name: str) -> None:
    """Mirror delete, called BEFORE the local row is removed (see
    delete_secret's own comment) -- audit R14: the error message below used
    to claim the local row was already gone by the time this could fail,
    which hasn't been true since that reorder."""
    settings = request.app.state.settings
    if getattr(settings, "runtime_type", "podman") != "ecs":
        return
    from warren.secrets import ssm_store

    try:
        ssm = request.app.state.runtime.ssm_client()
        await ssm_store.delete_secret(ssm, settings.ecs_resource_prefix, settings.server_id, owner_id, name)
    except Exception as exc:
        log.warning("secret_ssm_mirror_delete_failed", owner_id=owner_id, name=name, exc_info=True)
        raise HTTPException(
            status_code=502,
            detail={
                "error": "ssm_mirror_delete_failed",
                "detail": (
                    f"secret {name!r} was NOT deleted -- the SSM mirror delete failed "
                    f"before the local delete ran: {exc}. The secret still exists; retry "
                    "the delete."
                ),
            },
        ) from exc


class SecretRotateRequest(BaseModel):
    value: str | None = None


def _validate_secret_write(name: str, value: str) -> None:
    if not _SSM_SAFE_NAME_RE.match(name):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_secret_name",
                "detail": f"secret name {name!r} must match {_SSM_SAFE_NAME_RE.pattern!r}",
            },
        )
    if len(value.encode("utf-8")) > _SSM_MAX_VALUE_BYTES:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "secret_value_too_large",
                "detail": f"secret value exceeds the {_SSM_MAX_VALUE_BYTES}-byte SSM Standard limit",
            },
        )


@router.put("/secrets", status_code=204)
async def put_secret(body: SecretWriteRequest, request: Request) -> Response:
    _validate_secret_write(body.name, body.value)

    owner_id = await resolve_owner_id(request)
    settings = request.app.state.settings
    db = request.app.state.db
    cipher = LocalCipher(settings.secret_key.get_secret_value())

    # Mirror to SSM before the local write: the local store is the thing that
    # reflects "did this fully succeed", so a failed mirror must not leave a
    # ghost secret visible via GET /secrets that ECS workspaces never receive.
    # The two writes are independent (the mirror doesn't read the local row),
    # so this is a plain reorder rather than a write-then-compensate.
    await _mirror_put_to_ssm(request, owner_id, body.name, body.value)
    await local_store.set_secret(db, cipher, owner_id, body.name, body.value)
    # Audit #46: secret writes weren't logged at all -- name/owner/action only, never
    # the value, same discipline as every other secret-touching log line in this module.
    log.info("secret_written", owner_id=owner_id, name=body.name)
    audit_event("secret.write", request=request, owner_id=owner_id, secret_names=[body.name])
    return Response(status_code=204)


@router.get("/secrets", response_model=list[SecretMeta])
async def list_secrets(request: Request) -> list[SecretMeta]:
    owner_id = await resolve_owner_id(request)
    db = request.app.state.db
    rows = await local_store.list_secrets(db, owner_id)
    return [SecretMeta(name=r["name"]) for r in rows]


@router.delete("/secrets/{name}", status_code=204)
async def delete_secret(name: str, request: Request) -> Response:
    owner_id = await resolve_owner_id(request)
    db = request.app.state.db

    if not await local_store.secret_exists(db, owner_id, name):
        raise HTTPException(status_code=404, detail={"error": "secret_not_found"})

    # Mirror delete before the local row is removed: if the mirror fails, the
    # local row must stay so a retry can actually retry against the
    # still-present SSM parameter, instead of 404ing against a row that's
    # already gone while the orphaned parameter keeps being injected forever.
    await _mirror_delete_to_ssm(request, owner_id, name)
    await local_store.delete_secret(db, owner_id, name)
    log.info("secret_deleted", owner_id=owner_id, name=name)
    audit_event("secret.delete", request=request, owner_id=owner_id, secret_names=[name])
    return Response(status_code=204)


@router.post("/secrets/{name}/rotate", status_code=204)
async def rotate_secret(name: str, request: Request, body: SecretRotateRequest | None = None) -> Response:
    """Rotate an existing secret (AH6). With `value`, replace it (SSM mirror
    first, same ordering as PUT). Without, re-encrypt the stored ciphertext
    under the current key; there is no key-history (MultiFernet) support yet,
    so that is a fresh-IV re-encryption under the same WARREN_SECRET_KEY."""
    owner_id = await resolve_owner_id(request)
    settings = request.app.state.settings
    db = request.app.state.db
    cipher = LocalCipher(settings.secret_key.get_secret_value())

    if not await local_store.secret_exists(db, owner_id, name):
        raise HTTPException(status_code=404, detail={"error": "secret_not_found"})

    value = body.value if body is not None else None
    if value is not None:
        _validate_secret_write(name, value)
        await _mirror_put_to_ssm(request, owner_id, name, value)
        await local_store.set_secret(db, cipher, owner_id, name, value)
        log.info("secret_rotated", owner_id=owner_id, name=name, mode="new_value")
    else:
        await local_store.reencrypt_secret(db, cipher, owner_id, name)
        log.info("secret_rotated", owner_id=owner_id, name=name, mode="reencrypt")
    audit_event(
        "secret.rotate", request=request, owner_id=owner_id, secret_names=[name],
        rotation="new_value" if value is not None else "reencrypt",
    )
    return Response(status_code=204)
