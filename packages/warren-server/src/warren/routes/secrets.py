"""Server-side secret store routes — isolated per caller.

warren's own local `secrets` table (`warren.secrets.store`, Fernet-encrypted
from WARREN_SECRET_KEY) is the only place secrets live, on every runtime. Podman
and docker workspaces get theirs as container env at create time; an ECS task
gets its declared ones as a file on its own EFS volume written just before
RunTask (runtime/ecs_secrets.py). Nothing is copied to SSM or any other store.

Isolation: every secret is owned by the caller who created it (`owner_id`,
from `warren.auth.deps.resolve_owner_id` — warren's own bearer-token user_id
on podman/docker, the caller's verified AWS IAM identity on ECS). There is
no admin override and no server-wide secret: a caller can only ever create,
list, or delete their OWN secrets.

No permission-tier concept (removed 2026-10-13): a workspace's provisioning
resolves exactly the secret names its resolved template declares
(routes/workspaces.py, runtime/ecs.py's `_resolve_secrets`), not a
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

# Letters, numbers, `.`, `-`, `_`, `/`. Only names that are also environment
# variable names ([A-Za-z_][A-Za-z0-9_]*) can be delivered to a workspace.
_SAFE_NAME_RE = re.compile(r"^[a-zA-Z0-9_.\-/]+$")

_MAX_VALUE_BYTES = 4096


class SecretWriteRequest(BaseModel):
    name: str
    value: str


class SecretMeta(BaseModel):
    name: str


class SecretRotateRequest(BaseModel):
    value: str | None = None


def _validate_secret_write(name: str, value: str) -> None:
    if not _SAFE_NAME_RE.match(name):
        raise HTTPException(
            status_code=400,
            detail={
                "error": "invalid_secret_name",
                "detail": f"secret name {name!r} must match {_SAFE_NAME_RE.pattern!r}",
            },
        )
    if len(value.encode("utf-8")) > _MAX_VALUE_BYTES:
        raise HTTPException(
            status_code=400,
            detail={
                "error": "secret_value_too_large",
                "detail": f"secret value exceeds {_MAX_VALUE_BYTES} bytes",
            },
        )


@router.put("/secrets", status_code=204)
async def put_secret(body: SecretWriteRequest, request: Request) -> Response:
    _validate_secret_write(body.name, body.value)

    owner_id = await resolve_owner_id(request)
    settings = request.app.state.settings
    db = request.app.state.db
    cipher = LocalCipher(settings.secret_key.get_secret_value())

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

    await local_store.delete_secret(db, owner_id, name)
    log.info("secret_deleted", owner_id=owner_id, name=name)
    audit_event("secret.delete", request=request, owner_id=owner_id, secret_names=[name])
    return Response(status_code=204)


@router.post("/secrets/{name}/rotate", status_code=204)
async def rotate_secret(name: str, request: Request, body: SecretRotateRequest | None = None) -> Response:
    """Rotate an existing secret (AH6). With `value`, replace it. Without, re-encrypt
    the stored ciphertext under the current key; there is no key-history (MultiFernet)
    support yet, so that is a fresh-IV re-encryption under the same WARREN_SECRET_KEY.
    A running workspace keeps the value it started with until it is relaunched."""
    owner_id = await resolve_owner_id(request)
    settings = request.app.state.settings
    db = request.app.state.db
    cipher = LocalCipher(settings.secret_key.get_secret_value())

    if not await local_store.secret_exists(db, owner_id, name):
        raise HTTPException(status_code=404, detail={"error": "secret_not_found"})

    value = body.value if body is not None else None
    if value is not None:
        _validate_secret_write(name, value)
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
