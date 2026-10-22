"""recover_admin_token unit tests — audit 2026-10-16 P2 #44 admin recovery path."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from warren.auth.recover import (
    AmbiguousAdminError,
    NoAdminFoundError,
    TargetAdminDisabledError,
    recover_admin_token,
)
from warren.auth.store import AuthStore
from warren.auth.tokens import derive_token_pepper, resolve_token


def _settings(*, secret_key: str = "test-secret-key" * 3, token_ttl_days: int = 90):
    settings = MagicMock()
    settings.secret_key = MagicMock(get_secret_value=lambda: secret_key)
    settings.token_ttl_days = token_ttl_days
    return settings


@pytest.mark.asyncio
async def test_recover_mints_working_token_for_sole_admin(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    settings = _settings()
    admin = await store.create_user(username="the-admin", is_admin=True)

    user, token, raw_token = await recover_admin_token(store, settings)

    assert user.user_id == admin.user_id
    assert token.user_id == admin.user_id

    pepper = derive_token_pepper(settings.secret_key.get_secret_value())
    resolved = await resolve_token(store, raw_token, pepper)
    assert resolved is not None
    assert resolved.user_id == admin.user_id


@pytest.mark.asyncio
async def test_recover_raises_when_no_admin_exists(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    settings = _settings()
    await store.create_user(username="not-an-admin", is_admin=False)

    with pytest.raises(NoAdminFoundError):
        await recover_admin_token(store, settings)


@pytest.mark.asyncio
async def test_recover_raises_ambiguous_without_username_when_multiple_admins(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    settings = _settings()
    await store.create_user(username="admin-one", is_admin=True)
    await store.create_user(username="admin-two", is_admin=True)

    with pytest.raises(AmbiguousAdminError):
        await recover_admin_token(store, settings)


@pytest.mark.asyncio
async def test_recover_with_username_picks_that_admin(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    settings = _settings()
    await store.create_user(username="admin-one", is_admin=True)
    target = await store.create_user(username="admin-two", is_admin=True)

    user, _token, _raw = await recover_admin_token(store, settings, username="admin-two")

    assert user.user_id == target.user_id


@pytest.mark.asyncio
async def test_recover_unknown_username_raises_no_admin_found(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    settings = _settings()
    await store.create_user(username="admin-one", is_admin=True)

    with pytest.raises(NoAdminFoundError):
        await recover_admin_token(store, settings, username="nonexistent")


@pytest.mark.asyncio
async def test_recover_never_logs_raw_token(sqlite_path: str, caplog):
    import logging

    from warren.logging import configure_logging

    configure_logging()
    store = await AuthStore.open(sqlite_path)
    settings = _settings()
    await store.create_user(username="the-admin", is_admin=True)

    with caplog.at_level(logging.INFO):
        _user, _token, raw_token = await recover_admin_token(store, settings)

    rendered = " ".join(r.getMessage() for r in caplog.records)
    assert raw_token not in rendered


# --- Audit R9/S9: disabled-admin lockout -----------------------------------


@pytest.mark.asyncio
async def test_recover_refuses_disabled_admin_without_reenable(sqlite_path: str):
    """A token minted for a disabled admin would never authenticate -- silently
    minting one anyway would report success while leaving the operator just as
    locked out. Must refuse instead."""
    store = await AuthStore.open(sqlite_path)
    settings = _settings()
    admin = await store.create_user(username="the-admin", is_admin=True)
    await store.disable_user(admin.user_id)

    with pytest.raises(TargetAdminDisabledError):
        await recover_admin_token(store, settings)


@pytest.mark.asyncio
async def test_recover_with_reenable_clears_disabled_and_mints_working_token(sqlite_path: str):
    """The real fix for the permanent-lockout scenario (R9): --reenable clears
    disabled_at as part of the same recovery operation, and the resulting
    token must actually authenticate afterward."""
    store = await AuthStore.open(sqlite_path)
    settings = _settings()
    admin = await store.create_user(username="the-admin", is_admin=True)
    await store.disable_user(admin.user_id)

    user, _token, raw_token = await recover_admin_token(store, settings, reenable=True)

    assert user.user_id == admin.user_id
    refetched = await store.get_user(admin.user_id)
    assert refetched.disabled_at is None

    pepper = derive_token_pepper(settings.secret_key.get_secret_value())
    resolved = await resolve_token(store, raw_token, pepper)
    assert resolved is not None
    assert resolved.user_id == admin.user_id


@pytest.mark.asyncio
async def test_recover_enabled_admin_with_reenable_is_a_harmless_noop(sqlite_path: str):
    """--reenable on an already-enabled admin must not error or do anything
    surprising -- it's a safe default to always pass, not a dangerous one."""
    store = await AuthStore.open(sqlite_path)
    settings = _settings()
    admin = await store.create_user(username="the-admin", is_admin=True)

    user, _token, _raw = await recover_admin_token(store, settings, reenable=True)

    assert user.user_id == admin.user_id
    refetched = await store.get_user(admin.user_id)
    assert refetched.disabled_at is None
