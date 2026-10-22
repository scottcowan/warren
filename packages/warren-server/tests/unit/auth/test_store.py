"""AuthStore CRUD unit tests against a tempfile SQLite DB, mirroring test_store.py style."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import aiosqlite
import pytest

from warren.auth.store import AuthStore


@pytest.mark.asyncio
async def test_create_user_and_get_roundtrip(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    user = await store.create_user(username="alice", is_admin=False)
    assert user.username == "alice"
    assert user.is_admin is False

    fetched = await store.get_user(user.user_id)
    assert fetched is not None
    assert fetched.user_id == user.user_id
    assert fetched.username == "alice"
    assert fetched.is_admin is False
    assert isinstance(fetched.created_at, datetime)


@pytest.mark.asyncio
async def test_create_user_duplicate_username_raises(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    await store.create_user(username="bob", is_admin=False)
    with pytest.raises(aiosqlite.IntegrityError):
        await store.create_user(username="bob", is_admin=True)


@pytest.mark.asyncio
async def test_get_user_by_username(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    created = await store.create_user(username="carol", is_admin=True)
    fetched = await store.get_user_by_username("carol")
    assert fetched is not None
    assert fetched.user_id == created.user_id


@pytest.mark.asyncio
async def test_get_user_by_username_missing_returns_none(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    assert await store.get_user_by_username("nope") is None


@pytest.mark.asyncio
async def test_list_users(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    await store.create_user(username="u1", is_admin=False)
    await store.create_user(username="u2", is_admin=True)
    users = await store.list_users()
    assert {u.username for u in users} == {"u1", "u2"}


@pytest.mark.asyncio
async def test_count_admins(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    assert await store.count_admins() == 0

    await store.create_user(username="notadmin", is_admin=False)
    assert await store.count_admins() == 0

    await store.create_user(username="admin1", is_admin=True)
    assert await store.count_admins() == 1


@pytest.mark.asyncio
async def test_count_enabled_admins_excludes_disabled(sqlite_path: str):
    """Audit V5: count_admins() stays indifferent to disabled_at (it only gates
    ensure_bootstrap_admin), but the disable route's last-admin guard needs the
    enabled-only count."""
    store = await AuthStore.open(sqlite_path)
    admin1 = await store.create_user(username="admin1", is_admin=True)
    await store.create_user(username="admin2", is_admin=True)
    assert await store.count_enabled_admins() == 2
    assert await store.count_admins() == 2

    await store.disable_user(admin1.user_id)
    assert await store.count_enabled_admins() == 1
    assert await store.count_admins() == 2  # unchanged -- still counts the disabled one


@pytest.mark.asyncio
async def test_create_token_and_resolve_active_user(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    user = await store.create_user(username="dave", is_admin=False)
    token = await store.create_token(user_id=user.user_id, hashed_token="hash-1")
    assert token.user_id == user.user_id

    resolved = await store.get_active_user_by_hashed_token("hash-1")
    assert resolved is not None
    assert resolved.user_id == user.user_id


@pytest.mark.asyncio
async def test_get_active_user_by_hashed_token_unknown_returns_none(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    assert await store.get_active_user_by_hashed_token("no-such-hash") is None


@pytest.mark.asyncio
async def test_revoke_token_prevents_resolution(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    user = await store.create_user(username="erin", is_admin=False)
    token = await store.create_token(user_id=user.user_id, hashed_token="hash-2")

    revoked = await store.revoke_token(token.token_id)
    assert revoked is True

    assert await store.get_active_user_by_hashed_token("hash-2") is None


@pytest.mark.asyncio
async def test_revoke_one_user_token_leaves_other_user_resolvable(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    user_a = await store.create_user(username="alice2", is_admin=False)
    user_b = await store.create_user(username="bob2", is_admin=False)
    token_a = await store.create_token(user_id=user_a.user_id, hashed_token="hash-a")
    await store.create_token(user_id=user_b.user_id, hashed_token="hash-b")

    await store.revoke_token(token_a.token_id)

    assert await store.get_active_user_by_hashed_token("hash-a") is None
    resolved_b = await store.get_active_user_by_hashed_token("hash-b")
    assert resolved_b is not None
    assert resolved_b.user_id == user_b.user_id


@pytest.mark.asyncio
async def test_expired_token_does_not_resolve(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    user = await store.create_user(username="frank", is_admin=False)
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    await store.create_token(user_id=user.user_id, hashed_token="hash-expired", expires_at=past)

    assert await store.get_active_user_by_hashed_token("hash-expired") is None


@pytest.mark.asyncio
async def test_future_expiry_token_resolves(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    user = await store.create_user(username="grace", is_admin=False)
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    await store.create_token(user_id=user.user_id, hashed_token="hash-future", expires_at=future)

    resolved = await store.get_active_user_by_hashed_token("hash-future")
    assert resolved is not None
    assert resolved.user_id == user.user_id


@pytest.mark.asyncio
async def test_no_expiry_token_resolves(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    user = await store.create_user(username="heidi", is_admin=False)
    await store.create_token(user_id=user.user_id, hashed_token="hash-noexp", expires_at=None)

    resolved = await store.get_active_user_by_hashed_token("hash-noexp")
    assert resolved is not None
    assert resolved.user_id == user.user_id


@pytest.mark.asyncio
async def test_revoke_token_already_revoked_returns_false(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    user = await store.create_user(username="ivan", is_admin=False)
    token = await store.create_token(user_id=user.user_id, hashed_token="hash-double")

    assert await store.revoke_token(token.token_id) is True
    assert await store.revoke_token(token.token_id) is False


@pytest.mark.asyncio
async def test_revoke_token_unknown_returns_false(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    assert await store.revoke_token("no-such-token-id") is False


@pytest.mark.asyncio
async def test_get_token(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    user = await store.create_user(username="judy", is_admin=False)
    created = await store.create_token(user_id=user.user_id, hashed_token="hash-get")

    fetched = await store.get_token(created.token_id)
    assert fetched is not None
    assert fetched.token_id == created.token_id
    assert fetched.user_id == user.user_id
    assert fetched.revoked_at is None


@pytest.mark.asyncio
async def test_create_token_records_created_by_token_id(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    user = await store.create_user(username="minter", is_admin=False)
    parent = await store.create_token(user_id=user.user_id, hashed_token="hash-parent")
    child = await store.create_token(
        user_id=user.user_id, hashed_token="hash-child", created_by_token_id=parent.token_id
    )

    assert child.created_by_token_id == parent.token_id
    fetched = await store.get_token(child.token_id)
    assert fetched is not None
    assert fetched.created_by_token_id == parent.token_id


@pytest.mark.asyncio
async def test_create_token_created_by_token_id_defaults_to_none(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    user = await store.create_user(username="nomint", is_admin=False)
    token = await store.create_token(user_id=user.user_id, hashed_token="hash-noparent")
    assert token.created_by_token_id is None


@pytest.mark.asyncio
async def test_count_active_tokens_for_user_excludes_revoked_and_expired(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    user = await store.create_user(username="counter", is_admin=False)

    live = await store.create_token(user_id=user.user_id, hashed_token="hash-live")
    await store.create_token(
        user_id=user.user_id,
        hashed_token="hash-expired",
        expires_at=datetime.now(timezone.utc) - timedelta(hours=1),
    )
    to_revoke = await store.create_token(user_id=user.user_id, hashed_token="hash-revoked")
    await store.revoke_token(to_revoke.token_id)

    assert await store.count_active_tokens_for_user(user.user_id) == 1
    assert (await store.get_token(live.token_id)) is not None


@pytest.mark.asyncio
async def test_disable_user_sets_disabled_at(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    user = await store.create_user(username="disableme", is_admin=False)
    assert user.disabled_at is None

    assert await store.disable_user(user.user_id) is True

    fetched = await store.get_user(user.user_id)
    assert fetched is not None
    assert fetched.disabled_at is not None


@pytest.mark.asyncio
async def test_disable_user_unknown_returns_false(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    assert await store.disable_user("no-such-user") is False


@pytest.mark.asyncio
async def test_disable_user_blocks_token_resolution(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    user = await store.create_user(username="blockme", is_admin=False)
    await store.create_token(user_id=user.user_id, hashed_token="hash-blocked")

    await store.disable_user(user.user_id)

    assert await store.get_active_user_by_hashed_token("hash-blocked") is None


@pytest.mark.asyncio
async def test_enable_user_clears_disabled_at(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    user = await store.create_user(username="reenableme", is_admin=False)
    await store.disable_user(user.user_id)
    assert (await store.get_user(user.user_id)).disabled_at is not None

    assert await store.enable_user(user.user_id) is True

    fetched = await store.get_user(user.user_id)
    assert fetched is not None
    assert fetched.disabled_at is None


@pytest.mark.asyncio
async def test_enable_user_unknown_returns_false(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    assert await store.enable_user("no-such-user") is False


@pytest.mark.asyncio
async def test_enable_user_restores_token_resolution(sqlite_path: str):
    """Audit R9/S9: enable_user is the other half of the admin-recovery fix --
    a token that stopped resolving when the user was disabled must resolve
    again once re-enabled, not just have its disabled_at flag flip."""
    store = await AuthStore.open(sqlite_path)
    user = await store.create_user(username="restoreme", is_admin=False)
    await store.create_token(user_id=user.user_id, hashed_token="hash-restored")
    await store.disable_user(user.user_id)
    assert await store.get_active_user_by_hashed_token("hash-restored") is None

    await store.enable_user(user.user_id)

    assert await store.get_active_user_by_hashed_token("hash-restored") is not None


@pytest.mark.asyncio
async def test_revoke_all_tokens_for_user(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    user_a = await store.create_user(username="revokeall", is_admin=False)
    user_b = await store.create_user(username="untouched", is_admin=False)
    await store.create_token(user_id=user_a.user_id, hashed_token="hash-a1")
    await store.create_token(user_id=user_a.user_id, hashed_token="hash-a2")
    await store.create_token(user_id=user_b.user_id, hashed_token="hash-b1")

    revoked_count = await store.revoke_all_tokens_for_user(user_a.user_id)

    assert revoked_count == 2
    assert await store.get_active_user_by_hashed_token("hash-a1") is None
    assert await store.get_active_user_by_hashed_token("hash-a2") is None
    assert await store.get_active_user_by_hashed_token("hash-b1") is not None


@pytest.mark.asyncio
async def test_revoke_all_tokens_for_user_with_no_tokens_returns_zero(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    user = await store.create_user(username="notokens", is_admin=False)
    assert await store.revoke_all_tokens_for_user(user.user_id) == 0
