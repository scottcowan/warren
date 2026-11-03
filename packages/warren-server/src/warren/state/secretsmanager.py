"""AWS Secrets Manager secret store (WARREN_SECRETS_BACKEND=secretsmanager).

One secret per (owner, name), named `<prefix>/<owner>/<name>` with both components
encoded by `encode_component` (owner ids are IAM ARNs, emails or hex ids, and secret
names may contain `/`; Secrets Manager names only allow `A-Za-z0-9/_+=.@-`). The value
is the SecretString itself: Secrets Manager encrypts it at rest with KMS (the
WARREN_SECRETSMANAGER_KMS_KEY_ID customer managed key when set, else
aws/secretsmanager), so there is no Fernet layer here. WARREN_SECRET_KEY is still
required: it derives the token-hashing pepper.

Every secret is tagged `warren=true`, `warren.owner_id=<owner>` and
`warren.server_instance=<server id>`; the reference IAM policy only allows actions on
`<prefix>/*` secrets carrying `warren=true`.

Delete schedules deletion with a recovery window (WARREN_SECRETSMANAGER_RECOVERY_WINDOW_DAYS,
default 7, the minimum Secrets Manager allows) unless WARREN_SECRETSMANAGER_FORCE_DELETE
is set. Writing a name that is scheduled for deletion restores it first.

Cost: about $0.40 per secret per month plus $0.05 per 10,000 API calls, so launches
read through an in-memory cache (`SecretValueCache`, WARREN_SECRETSMANAGER_CACHE_TTL_S).
Every boto3 call runs in `asyncio.to_thread`.
"""

from __future__ import annotations

import asyncio
import re
import string
import time
from collections.abc import Callable
from typing import Any

import structlog

log = structlog.get_logger(__name__)

TAG_MANAGED = "warren"
TAG_OWNER_ID = "warren.owner_id"
TAG_SERVER_INSTANCE = "warren.server_instance"
_CURRENT = "AWSCURRENT"
_MAX_NAME = 512
_SAFE = frozenset(string.ascii_letters + string.digits + "_.-@+")
_TAG_VALUE_RE = re.compile(r"[A-Za-z0-9 _.:/=+\-@]{0,256}")


def encode_component(value: str) -> str:
    """Reversible encoding of one name component into Secrets Manager's name alphabet.
    Letters, digits and `_.-@+` pass through; every other byte of the UTF-8 encoding,
    including `/` and `=` itself, becomes `=XX` (upper-case hex)."""
    if not value:
        raise ValueError("secret name components must be non-empty")
    out = []
    for ch in value:
        if ch in _SAFE:
            out.append(ch)
        else:
            out.extend(f"={b:02X}" for b in ch.encode("utf-8"))
    return "".join(out)


def decode_component(encoded: str) -> str:
    raw = bytearray()
    i = 0
    while i < len(encoded):
        if encoded[i] == "=":
            raw.append(int(encoded[i + 1 : i + 3], 16))
            i += 3
        else:
            raw.extend(encoded[i].encode())
            i += 1
    return raw.decode("utf-8")


def _error_code(exc: Exception) -> str:
    return getattr(exc, "response", {}).get("Error", {}).get("Code", "")


class SecretValueCache:
    """In-memory TTL cache of secret values, keyed by (owner, name, version). Lives in
    one process only; a write through this process invalidates its entries, another
    task's write is picked up once the entry expires."""

    def __init__(self, ttl_s: float, clock: Callable[[], float] = time.monotonic) -> None:
        self.ttl_s = ttl_s
        self._clock = clock
        self._entries: dict[tuple[str, str, str], tuple[float, str]] = {}

    def get(self, owner_id: str, name: str, version: str = _CURRENT) -> str | None:
        entry = self._entries.get((owner_id, name, version))
        if entry is None:
            return None
        expires, value = entry
        if self._clock() >= expires:
            self._entries.pop((owner_id, name, version), None)
            return None
        return value

    def put(self, owner_id: str, name: str, value: str, version: str = _CURRENT) -> None:
        if self.ttl_s > 0:
            self._entries[(owner_id, name, version)] = (self._clock() + self.ttl_s, value)

    def invalidate(self, owner_id: str, name: str) -> None:
        for key in [k for k in self._entries if k[0] == owner_id and k[1] == name]:
            del self._entries[key]

    def __len__(self) -> int:
        return len(self._entries)


class SecretsManagerSecretStore:
    """`SecretStoreProtocol` (state/protocols.py) over AWS Secrets Manager."""

    def __init__(
        self,
        *,
        prefix: str,
        server_id: str,
        region: str | None = None,
        kms_key_id: str = "",
        force_delete: bool = False,
        recovery_window_days: int = 7,
        cache_ttl_s: float = 60.0,
        client: Any = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.prefix = prefix.strip("/")
        self._server_id = server_id
        self._region = region
        self._kms_key_id = kms_key_id
        self._force_delete = force_delete
        self._recovery_window_days = recovery_window_days
        self._client = client
        self.cache = SecretValueCache(cache_ttl_s, clock)

    @property
    def client(self) -> Any:
        if self._client is None:
            import boto3  # deferred: keeps the sqlite-only import path cheap

            self._client = boto3.Session(region_name=self._region).client("secretsmanager")
        return self._client

    async def _call(self, op: str, **kwargs: Any) -> Any:
        return await asyncio.to_thread(getattr(self.client, op), **kwargs)

    # -- naming --------------------------------------------------------------

    def owner_prefix(self, owner_id: str) -> str:
        return f"{self.prefix}/{encode_component(owner_id)}/"

    def secret_name(self, owner_id: str, name: str) -> str:
        full = self.owner_prefix(owner_id) + encode_component(name)
        if len(full) > _MAX_NAME:
            raise ValueError(f"secret {name!r} is too long once encoded for Secrets Manager")
        return full

    def _tags(self, owner_id: str) -> list[dict[str, str]]:
        owner_tag = owner_id if _TAG_VALUE_RE.fullmatch(owner_id) else encode_component(owner_id)[:256]
        tags = [{"Key": TAG_MANAGED, "Value": "true"}, {"Key": TAG_OWNER_ID, "Value": owner_tag}]
        if self._server_id and _TAG_VALUE_RE.fullmatch(self._server_id):
            tags.append({"Key": TAG_SERVER_INSTANCE, "Value": self._server_id})
        return tags

    # -- reads ---------------------------------------------------------------

    async def _absent(self, exc: Exception, secret_id: str) -> bool:
        """Whether `exc` means the secret doesn't exist. With the reference policy's
        `secretsmanager:ResourceTag/warren` condition, AWS answers AccessDenied (not
        ResourceNotFound) for a secret that doesn't exist, since there is no tag to
        match; ListSecrets (allowed on *) tells the two apart."""
        code = _error_code(exc)
        if code == "ResourceNotFoundException":
            return True
        if code not in ("AccessDeniedException", "AccessDenied"):
            return False
        resp = await self._call(
            "list_secrets", Filters=[{"Key": "name", "Values": [secret_id]}], IncludePlannedDeletion=True
        )
        return not any(e.get("Name") == secret_id for e in resp.get("SecretList", []))

    async def _describe(self, secret_id: str) -> dict | None:
        try:
            return await self._call("describe_secret", SecretId=secret_id)
        except Exception as exc:
            if await self._absent(exc, secret_id):
                return None
            raise

    async def _value(self, secret_id: str) -> str | None:
        try:
            resp = await self._call("get_secret_value", SecretId=secret_id, VersionStage=_CURRENT)
        except Exception as exc:
            # Scheduled for deletion answers InvalidRequestException.
            if _error_code(exc) == "InvalidRequestException" or await self._absent(exc, secret_id):
                return None
            raise
        return resp.get("SecretString")

    async def exists(self, owner_id: str, name: str) -> bool:
        meta = await self._describe(self.secret_name(owner_id, name))
        return meta is not None and not meta.get("DeletedDate")

    async def _list(self, name_prefix: str) -> list[dict]:
        kwargs: dict[str, Any] = {
            "Filters": [
                {"Key": "name", "Values": [name_prefix]},
                {"Key": "tag-key", "Values": [TAG_MANAGED]},
            ],
            "MaxResults": 100,
        }
        out: list[dict] = []
        while True:
            resp = await self._call("list_secrets", **kwargs)
            for entry in resp.get("SecretList", []):
                # The name filter is a case-insensitive prefix match: re-check exactly.
                tags = {t["Key"]: t["Value"] for t in entry.get("Tags") or []}
                if entry["Name"].startswith(name_prefix) and tags.get(TAG_MANAGED) == "true" and not entry.get("DeletedDate"):
                    out.append(entry)
            token = resp.get("NextToken")
            if not token:
                return out
            kwargs["NextToken"] = token

    async def list(self, owner_id: str) -> list[dict[str, str]]:
        prefix = self.owner_prefix(owner_id)
        rows = []
        for entry in await self._list(prefix):
            rest = entry["Name"][len(prefix) :]
            if "/" in rest:
                continue
            created = entry.get("CreatedDate")
            changed = entry.get("LastChangedDate") or created
            rows.append({
                "name": decode_component(rest),
                "created_at": created.isoformat() if created else "",
                "updated_at": changed.isoformat() if changed else "",
            })
        return sorted(rows, key=lambda r: r["name"])

    async def count(self) -> int:
        return len(await self._list(f"{self.prefix}/"))

    async def resolve(self, owner_id: str, names: list[str]) -> dict[str, str]:
        """Exactly the named secrets of `owner_id`, through the cache."""
        if not names:
            return {}
        wanted = list(dict.fromkeys(names))
        out: dict[str, str] = {}
        misses = []
        for name in wanted:
            cached = self.cache.get(owner_id, name)
            if cached is not None:
                out[name] = cached
            else:
                misses.append(name)
        values = await asyncio.gather(*(self._value(self.secret_name(owner_id, n)) for n in misses))
        for name, value in zip(misses, values, strict=True):
            if value is not None:
                self.cache.put(owner_id, name, value)
                out[name] = value
        return out

    # -- writes --------------------------------------------------------------

    async def set(self, owner_id: str, name: str, value: str) -> None:
        secret_id = self.secret_name(owner_id, name)
        self.cache.invalidate(owner_id, name)
        create: dict[str, Any] = {"Name": secret_id, "SecretString": value, "Tags": self._tags(owner_id)}
        if self._kms_key_id:
            create["KmsKeyId"] = self._kms_key_id
        try:
            await self._call("create_secret", **create)
            return
        except Exception as exc:
            if _error_code(exc) not in ("ResourceExistsException", "InvalidRequestException"):
                raise
        meta = await self._describe(secret_id)
        if meta is not None and meta.get("DeletedDate"):
            # Scheduled for deletion: a name can't be reused inside its recovery window.
            await self._call("restore_secret", SecretId=secret_id)
            await self._call("tag_resource", SecretId=secret_id, Tags=self._tags(owner_id))
        await self._call("put_secret_value", SecretId=secret_id, SecretString=value)
        self.cache.invalidate(owner_id, name)

    async def reencrypt(self, owner_id: str, name: str) -> bool:
        """Write the current value back as a new version, under the configured KMS key
        (UpdateSecret re-encrypts with KmsKeyId)."""
        secret_id = self.secret_name(owner_id, name)
        value = await self._value(secret_id)
        if value is None:
            return False
        update: dict[str, Any] = {"SecretId": secret_id, "SecretString": value}
        if self._kms_key_id:
            update["KmsKeyId"] = self._kms_key_id
        await self._call("update_secret", **update)
        self.cache.invalidate(owner_id, name)
        return True

    async def delete(self, owner_id: str, name: str) -> bool:
        secret_id = self.secret_name(owner_id, name)
        self.cache.invalidate(owner_id, name)
        meta = await self._describe(secret_id)
        if meta is None or meta.get("DeletedDate"):
            return False
        kwargs: dict[str, Any] = {"SecretId": secret_id}
        if self._force_delete:
            kwargs["ForceDeleteWithoutRecovery"] = True
        else:
            kwargs["RecoveryWindowInDays"] = self._recovery_window_days
        try:
            await self._call("delete_secret", **kwargs)
        except Exception as exc:
            if _error_code(exc) in ("ResourceNotFoundException", "InvalidRequestException"):
                return False
            raise
        return True
