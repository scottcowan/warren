"""Server-side secret store routes — isolated per caller.

warren's own local `secrets` table (`warren.secrets.store`, Fernet-encrypted
from WARREN_SECRET_KEY) is the single source of truth on EVERY runtime,
including ECS -- there is no SSM Parameter Store backend to read from here.
When `settings.runtime_type == "ecs"`, a write or delete is additionally
mirrored to an SSM SecureString parameter through a durable outbox
(`warren.secrets.ssm_store.SsmMirror`) so the ECS agent can resolve it at
container start. A write answers 204 once SSM is in line, or 202
`mirror_pending` when it's saved locally and the SSM push is still being
retried. GET /secrets always answers from the local store, never from SSM.

Isolation: every secret is owned by the caller who created it (`owner_id`,
from `warren.auth.deps.resolve_owner_id` — warren's own bearer-token user_id
on podman/docker, the caller's verified AWS IAM identity on ECS), on both
backends — the SSM mirror's path carries the same owner_id segment. There is
no admin override and no server-wide secret: a caller can only ever create,
list, or delete their OWN secrets.

No permission-tier concept (removed 2026-10-13): a workspace's provisioning
resolves exactly the secret names its resolved template declares
(routes/workspaces.py, SsmMirror.mirrored_names on ECS), not a
tier -- a tier bought no real isolation (every secret was already owner-scoped)
but did silently starve readonly-permission templates of secrets like
WARREN_GIT_SSH_KEY/GITHUB_PAT that they still needed just to clone repos.
"""

from __future__ import annotations

import re

import structlog
from fastapi import APIRouter, HTTPException, Request, Response
from fastapi.responses import JSONResponse
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
    # ECS only: the SSM mirror hasn't caught up with this secret yet.
    mirror_pending: bool = False


def _mirror(request: Request):
    """The SSM outbox mirror on ECS (app.state.secret_mirror), else None."""
    return getattr(request.app.state, "secret_mirror", None)


async def _apply(request: Request, owner_id: str, name: str, op: str, mutate) -> bool:
    """Run the local change; on ECS, through the outbox so SSM converges even if
    the push fails or the process dies. True when SSM is already in line."""
    mirror = _mirror(request)
    if mirror is None:
        await mutate()
        return True
    return await mirror.apply(owner_id, name, op, mutate)


def _done(name: str, mirrored: bool) -> Response:
    if mirrored:
        return Response(status_code=204)
    # Saved locally; the outbox keeps retrying the SSM push (startup, periodically,
    # next write, and before any workspace that needs it is provisioned).
    return JSONResponse(
        status_code=202,
        content={
            "status": "mirror_pending",
            "detail": (
                f"secret {name!r} is saved, but the SSM mirror is not updated yet; it is "
                "retried automatically and ECS workspaces needing it won't start until then"
            ),
        },
    )


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

    mirrored = await _apply(
        request, owner_id, body.name, "put",
        lambda: local_store.set_secret(db, cipher, owner_id, body.name, body.value),
    )
    # Audit #46: secret writes weren't logged at all -- name/owner/action only, never
    # the value, same discipline as every other secret-touching log line in this module.
    log.info("secret_written", owner_id=owner_id, name=body.name)
    audit_event("secret.write", request=request, owner_id=owner_id, secret_names=[body.name])
    return _done(body.name, mirrored)


@router.get("/secrets", response_model=list[SecretMeta], response_model_exclude_defaults=True)
async def list_secrets(request: Request) -> list[SecretMeta]:
    owner_id = await resolve_owner_id(request)
    db = request.app.state.db
    rows = await local_store.list_secrets(db, owner_id)
    mirror = _mirror(request)
    pending = {name for _, name in await mirror.pending(owner_id)} if mirror is not None else set()
    return [SecretMeta(name=r["name"], mirror_pending=r["name"] in pending) for r in rows]


@router.delete("/secrets/{name}", status_code=204)
async def delete_secret(name: str, request: Request) -> Response:
    owner_id = await resolve_owner_id(request)
    db = request.app.state.db

    if not await local_store.secret_exists(db, owner_id, name):
        raise HTTPException(status_code=404, detail={"error": "secret_not_found"})

    mirrored = await _apply(
        request, owner_id, name, "delete", lambda: local_store.delete_secret(db, owner_id, name)
    )
    log.info("secret_deleted", owner_id=owner_id, name=name)
    audit_event("secret.delete", request=request, owner_id=owner_id, secret_names=[name])
    return _done(name, mirrored)


@router.post("/secrets/{name}/rotate", status_code=204)
async def rotate_secret(name: str, request: Request, body: SecretRotateRequest | None = None) -> Response:
    """Rotate an existing secret (AH6). With `value`, replace it (through the SSM
    outbox, same as PUT). Without, re-encrypt the stored ciphertext
    under the current key; there is no key-history (MultiFernet) support yet,
    so that is a fresh-IV re-encryption under the same WARREN_SECRET_KEY."""
    owner_id = await resolve_owner_id(request)
    settings = request.app.state.settings
    db = request.app.state.db
    cipher = LocalCipher(settings.secret_key.get_secret_value())

    if not await local_store.secret_exists(db, owner_id, name):
        raise HTTPException(status_code=404, detail={"error": "secret_not_found"})

    value = body.value if body is not None else None
    mirrored = True
    if value is not None:
        _validate_secret_write(name, value)
        mirrored = await _apply(
            request, owner_id, name, "put",
            lambda: local_store.set_secret(db, cipher, owner_id, name, value),
        )
        log.info("secret_rotated", owner_id=owner_id, name=name, mode="new_value")
    else:
        await local_store.reencrypt_secret(db, cipher, owner_id, name)
        log.info("secret_rotated", owner_id=owner_id, name=name, mode="reencrypt")
    audit_event(
        "secret.rotate", request=request, owner_id=owner_id, secret_names=[name],
        rotation="new_value" if value is not None else "reencrypt",
    )
    return _done(name, mirrored)
