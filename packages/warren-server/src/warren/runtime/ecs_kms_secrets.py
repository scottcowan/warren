"""Deliver a workspace's secrets to an EBS-backed ECS task as KMS-wrapped ciphertext.

An EBS workspace volume doesn't exist until ECS creates it at launch, so the EFS
file drop (ecs_secrets.py) has nowhere to write. Instead, right before each RunTask
the control plane:

    1. calls kms:GenerateDataKey (WARREN_ECS_SECRETS_KMS_KEY_ID) with the encryption
       context {"warren:workspace_id": <id>, "warren:container": <container>},
    2. encrypts that container's secrets (a JSON object) locally with AES-256-GCM
       under the plaintext data key, with the same context bound in as AAD,
    3. drops the plaintext key and passes only the envelope, as WARREN_SECRETS_BLOB,
       in that container's RunTask containerOverrides.

The control plane never needs kms:Decrypt. The image's warren-secrets-decrypt helper
(images/ecs-base/secrets-decrypt/) unwraps the key with the task role (kms:Decrypt
under the same context), decrypts, and prints `NAME=<base64 value>` lines, the same
format the EFS file uses, which the entrypoint / git-init parse without any shell
evaluation. git-init gets a blob of only its clone credentials, the workspace
container one of the rest, so each container's context differs and neither blob
decrypts as the other.

DescribeTasks and CloudTrail record the overrides, so they see only the envelope:
reading it needs kms:Decrypt on the key with this workspace's context.

Envelope (ASCII, std base64 with padding):
    v1:<region>:<KMS CiphertextBlob>:<12-byte nonce>:<ciphertext || 16-byte tag>
AAD: b"warren-secrets-v1\\n" + workspace_id + b"\\n" + container.
"""
from __future__ import annotations

import asyncio
import base64
import json
import os
import re
from collections.abc import Mapping
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from warren_common.errors import ProvisionError

BLOB_ENV = "WARREN_SECRETS_BLOB"
VERSION = "v1"
CTX_WORKSPACE = "warren:workspace_id"
CTX_CONTAINER = "warren:container"
CONTAINERS = ("workspace", "git-init")

_REGION_RE = re.compile(r"^[a-z]{2}(-[a-z]+)+-\d+$")
_WORKSPACE_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,63}$")
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def encryption_context(workspace_id: str, container: str) -> dict[str, str]:
    return {CTX_WORKSPACE: workspace_id, CTX_CONTAINER: container}


def aad(workspace_id: str, container: str) -> bytes:
    return f"warren-secrets-{VERSION}\n{workspace_id}\n{container}".encode()


def _check(workspace_id: str, container: str, region: str) -> None:
    if not _WORKSPACE_ID_RE.match(workspace_id):
        raise ProvisionError(f"invalid workspace id {workspace_id!r}")
    if container not in CONTAINERS:
        raise ProvisionError(f"unknown secrets container {container!r}")
    if not _REGION_RE.match(region):
        raise ProvisionError(f"invalid AWS region {region!r} for secrets delivery")


def seal(
    data_key: bytes,
    wrapped_key: bytes,
    secrets: Mapping[str, str],
    *,
    workspace_id: str,
    container: str,
    region: str,
    nonce: bytes | None = None,
) -> str:
    """Encrypt `secrets` under `data_key` into the envelope string. Pure; no AWS."""
    _check(workspace_id, container, region)
    for name in secrets:
        if not _ENV_NAME_RE.match(name):
            raise ValueError(f"secret name {name!r} is not an environment variable name")
    plaintext = json.dumps(dict(secrets), sort_keys=True, separators=(",", ":")).encode()
    nonce = nonce if nonce is not None else os.urandom(12)
    ct = AESGCM(data_key).encrypt(nonce, plaintext, aad(workspace_id, container))
    parts = [base64.b64encode(p).decode("ascii") for p in (wrapped_key, nonce, ct)]
    return ":".join([VERSION, region, *parts])


def open_envelope(blob: str, data_key: bytes, *, workspace_id: str, container: str) -> dict[str, str]:
    """Inverse of seal() given the unwrapped data key; the reference for the image helper."""
    version, region, _wrapped, nonce_b64, ct_b64 = blob.split(":")
    if version != VERSION:
        raise ValueError(f"unsupported envelope version {version!r}")
    _check(workspace_id, container, region)
    nonce = base64.b64decode(nonce_b64, validate=True)
    pt = AESGCM(data_key).decrypt(nonce, base64.b64decode(ct_b64, validate=True), aad(workspace_id, container))
    data = json.loads(pt)
    if not isinstance(data, dict) or not all(isinstance(v, str) for v in data.values()):
        raise ValueError("envelope plaintext is not a JSON object of strings")
    return data


def wrapped_key_of(blob: str) -> bytes:
    return base64.b64decode(blob.split(":")[2], validate=True)


async def seal_with_kms(
    kms: Any,
    key_id: str,
    secrets: Mapping[str, str],
    *,
    workspace_id: str,
    container: str,
    region: str,
) -> str:
    """GenerateDataKey under this container's context, seal, and drop the key."""
    _check(workspace_id, container, region)
    try:
        resp = await asyncio.to_thread(
            kms.generate_data_key,
            KeyId=key_id,
            KeySpec="AES_256",
            EncryptionContext=encryption_context(workspace_id, container),
        )
    except Exception as exc:
        code = (getattr(exc, "response", None) or {}).get("Error", {}).get("Code", "") or type(exc).__name__
        raise ProvisionError(f"cannot encrypt secrets for workspace {workspace_id}: kms {code}") from exc
    data_key = bytearray(resp["Plaintext"])
    try:
        return seal(
            bytes(data_key), resp["CiphertextBlob"], secrets,
            workspace_id=workspace_id, container=container, region=region,
        )
    finally:
        # Best effort: Python can't guarantee the bytes copies are gone, but the
        # key never leaves this function and no reference to it is kept.
        for i in range(len(data_key)):
            data_key[i] = 0
        resp.pop("Plaintext", None)
