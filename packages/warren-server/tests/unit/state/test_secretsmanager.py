"""Secrets Manager backend specifics (moto): name encoding, tags, KMS key, delete modes
and the GetSecretValue cache."""

from __future__ import annotations

import re

import pytest

from warren.state.secretsmanager import (
    SecretsManagerSecretStore,
    SecretValueCache,
    decode_component,
    encode_component,
)

# Secrets Manager's name alphabet.
_SM_NAME = re.compile(r"[A-Za-z0-9/_+=.@-]+")
_OWNERS = [
    "0f3c9b2e8d",
    "arn:aws:iam::123456789012:role/Admin",
    "arn:aws:sts::123456789012:assumed-role/Dev/alice@example.com",
    "alice@example.com",
    "with space",
    "a/b",
    "a=2Fb",
    "ünïcødé",
    "=",
]


@pytest.mark.parametrize("value", [*_OWNERS, "API_KEY", "nested/name.v2", "GITHUB_PAT"])
def test_encoding_round_trips_into_the_allowed_alphabet(value):
    encoded = encode_component(value)
    assert _SM_NAME.fullmatch(encoded)
    assert "/" not in encoded
    assert decode_component(encoded) == value


def test_encoding_is_injective():
    values = [*_OWNERS, "a", "A", "a_b", "a-b", "a.b"]
    assert len({encode_component(v) for v in values}) == len(values)


def test_empty_component_is_refused():
    with pytest.raises(ValueError):
        encode_component("")


def _store(sm_client, **kwargs) -> SecretsManagerSecretStore:
    return SecretsManagerSecretStore(prefix="warren/prod", server_id="warren-prod", client=sm_client, **kwargs)


def test_secret_names(sm_client):
    store = _store(sm_client)
    assert store.secret_name("arn:aws:iam::1:role/x", "API_KEY") == "warren/prod/arn=3Aaws=3Aiam=3A=3A1=3Arole=2Fx/API_KEY"
    assert store.secret_name("u1", "a/b") == "warren/prod/u1/a=2Fb"
    with pytest.raises(ValueError, match="too long"):
        store.secret_name("u1", "x" * 600)


async def test_create_tags_and_kms_key(sm_client):
    import boto3

    key_id = boto3.Session(region_name="us-east-1").client("kms").create_key()["KeyMetadata"]["KeyId"]
    store = _store(sm_client, kms_key_id=key_id)
    owner = "arn:aws:iam::123456789012:role/Admin"
    await store.set(owner, "API_KEY", "sk-1")
    meta = sm_client.describe_secret(SecretId=store.secret_name(owner, "API_KEY"))
    tags = {t["Key"]: t["Value"] for t in meta["Tags"]}
    assert tags == {"warren": "true", "warren.owner_id": owner, "warren.server_instance": "warren-prod"}
    assert meta["KmsKeyId"].endswith(key_id)
    assert sm_client.get_secret_value(SecretId=meta["Name"])["SecretString"] == "sk-1"  # no Fernet layer


async def test_untaggable_owner_id_is_encoded_in_its_tag(sm_client):
    store = _store(sm_client)
    await store.set("ünï", "A", "v")
    tags = {t["Key"]: t["Value"] for t in sm_client.describe_secret(SecretId=store.secret_name("ünï", "A"))["Tags"]}
    assert tags["warren.owner_id"] == encode_component("ünï")


async def test_owner_listing_does_not_bleed_between_similar_owners(sm_client):
    store = _store(sm_client)
    await store.set("a", "X", "1")
    await store.set("a/b", "Y", "2")
    await store.set("ab", "Z", "3")
    assert [r["name"] for r in await store.list("a")] == ["X"]
    assert [r["name"] for r in await store.list("a/b")] == ["Y"]


async def test_listing_ignores_untagged_and_foreign_secrets(sm_client):
    store = _store(sm_client)
    await store.set("u1", "MINE", "1")
    sm_client.create_secret(Name="warren/prod/u1/HANDMADE", SecretString="x")  # no warren tag
    sm_client.create_secret(Name="other/u1/X", SecretString="x", Tags=[{"Key": "warren", "Value": "true"}])
    assert [r["name"] for r in await store.list("u1")] == ["MINE"]
    assert await store.count() == 1


async def test_delete_defaults_to_a_recovery_window(sm_client):
    store = _store(sm_client)
    await store.set("u1", "A", "v")
    assert await store.delete("u1", "A") is True
    meta = sm_client.describe_secret(SecretId=store.secret_name("u1", "A"))
    assert meta.get("DeletedDate") is not None  # scheduled, recoverable
    assert await store.exists("u1", "A") is False
    assert await store.delete("u1", "A") is False
    # Re-setting the name restores it and writes the new value.
    await store.set("u1", "A", "v2")
    assert await store.resolve("u1", ["A"]) == {"A": "v2"}
    tags = {t["Key"] for t in sm_client.describe_secret(SecretId=store.secret_name("u1", "A"))["Tags"]}
    assert "warren" in tags


async def test_force_delete_removes_immediately(sm_client):
    store = _store(sm_client, force_delete=True)
    await store.set("u1", "A", "v")
    assert await store.delete("u1", "A") is True
    with pytest.raises(sm_client.exceptions.ResourceNotFoundException):
        sm_client.describe_secret(SecretId=store.secret_name("u1", "A"))


class _TagConditionedPolicy:
    """What the reference IAM policy does to a secret that doesn't exist: there is no
    `warren` tag to match, so AWS answers AccessDenied instead of ResourceNotFound."""

    def __init__(self, client):
        self._client = client

    def __getattr__(self, name):
        fn = getattr(self._client, name)
        if name not in ("describe_secret", "get_secret_value"):
            return fn

        def call(**kwargs):
            try:
                return fn(**kwargs)
            except self._client.exceptions.ResourceNotFoundException as exc:
                from botocore.exceptions import ClientError

                raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, name) from exc

        return call


async def test_missing_secrets_behind_a_tag_conditioned_policy(sm_client):
    store = _store(_TagConditionedPolicy(sm_client))
    assert await store.exists("u1", "NOPE") is False
    assert await store.delete("u1", "NOPE") is False
    assert await store.resolve("u1", ["NOPE"]) == {}
    await store.set("u1", "A", "v")
    assert await store.exists("u1", "A") is True
    assert await store.resolve("u1", ["A", "NOPE"]) == {"A": "v"}


async def test_real_access_denied_still_raises(sm_client):
    from botocore.exceptions import ClientError

    class _Denied(_TagConditionedPolicy):
        def __getattr__(self, name):
            fn = getattr(self._client, name)
            if name != "get_secret_value":
                return fn

            def call(**_kwargs):
                raise ClientError({"Error": {"Code": "AccessDeniedException", "Message": "denied"}}, name)

            return call

    await _store(sm_client).set("u1", "A", "v")
    with pytest.raises(ClientError):
        await _store(_Denied(sm_client), cache_ttl_s=0).resolve("u1", ["A"])


# -- cache -------------------------------------------------------------------------


class _Counting:
    def __init__(self, client):
        self._client = client
        self.reads = 0

    def __getattr__(self, name):
        fn = getattr(self._client, name)
        if name != "get_secret_value":
            return fn

        def counted(**kwargs):
            self.reads += 1
            return fn(**kwargs)

        return counted


async def test_resolve_reads_through_the_cache(sm_client):
    now = [0.0]
    counting = _Counting(sm_client)
    store = SecretsManagerSecretStore(
        prefix="warren/prod", server_id="s", client=counting, cache_ttl_s=60, clock=lambda: now[0]
    )
    await store.set("u1", "A", "v1")
    await store.set("u1", "B", "b")
    assert await store.resolve("u1", ["A", "B"]) == {"A": "v1", "B": "b"}
    assert counting.reads == 2
    assert await store.resolve("u1", ["A", "B", "A"]) == {"A": "v1", "B": "b"}
    assert counting.reads == 2  # both cached
    now[0] = 61.0  # expired
    assert await store.resolve("u1", ["A"]) == {"A": "v1"}
    assert counting.reads == 3
    # A write through this process invalidates its entry at once.
    await store.set("u1", "A", "v2")
    assert await store.resolve("u1", ["A"]) == {"A": "v2"}
    assert counting.reads == 4
    await store.delete("u1", "A")
    assert await store.resolve("u1", ["A"]) == {}


async def test_cache_is_keyed_per_owner_and_name(sm_client):
    store = _store(sm_client)
    await store.set("u1", "A", "one")
    await store.set("u2", "A", "two")
    assert await store.resolve("u1", ["A"]) == {"A": "one"}
    assert await store.resolve("u2", ["A"]) == {"A": "two"}
    assert len(store.cache) == 2


def test_cache_unit():
    now = [0.0]
    cache = SecretValueCache(10, clock=lambda: now[0])
    cache.put("o", "n", "v")
    cache.put("o", "n", "old", version="v1")
    assert cache.get("o", "n") == "v" and cache.get("o", "n", "v1") == "old"
    assert cache.get("o", "other") is None and cache.get("other", "n") is None
    cache.invalidate("o", "n")
    assert len(cache) == 0
    cache.put("o", "n", "v")
    now[0] = 10.0
    assert cache.get("o", "n") is None
    off = SecretValueCache(0)
    off.put("o", "n", "v")
    assert off.get("o", "n") is None
