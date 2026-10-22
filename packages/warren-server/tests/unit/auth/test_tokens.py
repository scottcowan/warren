"""generate_token/hash_token/resolve_token unit tests."""

from __future__ import annotations

import string

import pytest

from warren.auth.store import AuthStore
from warren.auth.tokens import generate_token, hash_token, resolve_active_token, resolve_token


def test_generate_token_has_prefix_and_length():
    token = generate_token()
    assert token.startswith("wrn_")
    assert len(token) >= 40


def test_generate_token_is_unique():
    assert generate_token() != generate_token()


def test_hash_token_is_deterministic_for_same_pepper():
    token = generate_token()
    assert hash_token(token, "pepper-a") == hash_token(token, "pepper-a")


def test_hash_token_differs_for_different_pepper():
    token = generate_token()
    assert hash_token(token, "pepper-a") != hash_token(token, "pepper-b")


def test_hash_token_output_shape():
    digest = hash_token(generate_token(), "pepper")
    assert len(digest) == 64
    assert all(c in string.hexdigits.lower() for c in digest)


def test_hash_token_never_contains_raw_token():
    token = generate_token()
    digest = hash_token(token, "pepper")
    assert token not in digest


@pytest.mark.asyncio
async def test_resolve_token_returns_user_for_minted_token(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    user = await store.create_user(username="alice", is_admin=False)
    raw = generate_token()
    pepper = "test-pepper"
    await store.create_token(user_id=user.user_id, hashed_token=hash_token(raw, pepper))

    resolved = await resolve_token(store, raw, pepper)
    assert resolved is not None
    assert resolved.user_id == user.user_id


@pytest.mark.asyncio
async def test_resolve_token_returns_none_for_unminted_token(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    resolved = await resolve_token(store, generate_token(), "test-pepper")
    assert resolved is None


@pytest.mark.asyncio
async def test_resolve_token_returns_none_for_revoked_token(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    user = await store.create_user(username="bob", is_admin=False)
    raw = generate_token()
    pepper = "test-pepper"
    token = await store.create_token(user_id=user.user_id, hashed_token=hash_token(raw, pepper))
    await store.revoke_token(token.token_id)

    assert await resolve_token(store, raw, pepper) is None


@pytest.mark.asyncio
async def test_resolve_token_returns_none_for_expired_token(sqlite_path: str):
    from datetime import datetime, timedelta, timezone

    store = await AuthStore.open(sqlite_path)
    user = await store.create_user(username="carol", is_admin=False)
    raw = generate_token()
    pepper = "test-pepper"
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    await store.create_token(
        user_id=user.user_id, hashed_token=hash_token(raw, pepper), expires_at=past
    )

    assert await resolve_token(store, raw, pepper) is None


@pytest.mark.asyncio
async def test_resolve_token_returns_none_for_empty_string(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    assert await resolve_token(store, "", "test-pepper") is None


@pytest.mark.asyncio
async def test_resolve_token_returns_none_for_malformed_token(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    assert await resolve_token(store, "not-a-real-token", "test-pepper") is None


@pytest.mark.asyncio
async def test_resolve_active_token_returns_user_and_token_id(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    user = await store.create_user(username="dana", is_admin=False)
    raw = generate_token()
    pepper = "test-pepper"
    created = await store.create_token(user_id=user.user_id, hashed_token=hash_token(raw, pepper))

    resolved = await resolve_active_token(store, raw, pepper)
    assert resolved is not None
    resolved_user, token_id = resolved
    assert resolved_user.user_id == user.user_id
    assert token_id == created.token_id


@pytest.mark.asyncio
async def test_resolve_active_token_returns_none_for_disabled_user(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    user = await store.create_user(username="eve", is_admin=False)
    raw = generate_token()
    pepper = "test-pepper"
    await store.create_token(user_id=user.user_id, hashed_token=hash_token(raw, pepper))

    await store.disable_user(user.user_id)

    assert await resolve_active_token(store, raw, pepper) is None
    assert await resolve_token(store, raw, pepper) is None
