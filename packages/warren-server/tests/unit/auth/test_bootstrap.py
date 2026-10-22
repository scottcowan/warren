"""ensure_bootstrap_admin unit tests — first-admin creation and idempotency (D-03/D-04)."""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from warren.auth.bootstrap import ensure_bootstrap_admin
from warren.auth.store import AuthStore
from warren.auth.tokens import derive_token_pepper, resolve_token


def _settings(*, bootstrap_token: str | None, secret_key: str = "test-secret-key"):
    settings = MagicMock()
    settings.bootstrap_token = MagicMock(get_secret_value=lambda: bootstrap_token) if bootstrap_token else None
    settings.secret_key = MagicMock(get_secret_value=lambda: secret_key)
    # A real int, not an auto-MagicMock attribute: ensure_bootstrap_admin does
    # datetime arithmetic (timedelta(days=...)) with this value.
    settings.token_ttl_days = 90
    return settings


@pytest.mark.asyncio
async def test_bootstrap_creates_one_admin_from_empty_table(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    settings = _settings(bootstrap_token="bootstrap-value-1")

    user_id = await ensure_bootstrap_admin(store, settings)

    assert user_id is not None
    users = await store.list_users()
    assert len(users) == 1
    assert users[0].user_id == user_id
    assert users[0].is_admin is True


@pytest.mark.asyncio
async def test_bootstrap_admin_resolves_via_bootstrap_token(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    settings = _settings(bootstrap_token="bootstrap-value-2")

    user_id = await ensure_bootstrap_admin(store, settings)

    pepper = derive_token_pepper(settings.secret_key.get_secret_value())
    resolved = await resolve_token(store, "bootstrap-value-2", pepper)
    assert resolved is not None
    assert resolved.user_id == user_id


@pytest.mark.asyncio
async def test_bootstrap_second_call_is_noop(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    settings = _settings(bootstrap_token="bootstrap-value-3")

    first = await ensure_bootstrap_admin(store, settings)
    second = await ensure_bootstrap_admin(store, settings)

    assert first is not None
    assert second is None
    users = await store.list_users()
    assert len(users) == 1


@pytest.mark.asyncio
async def test_bootstrap_with_existing_admin_mints_no_new_token(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    settings = _settings(bootstrap_token="bootstrap-value-4")

    await ensure_bootstrap_admin(store, settings)

    different_settings = _settings(bootstrap_token="a-totally-different-token")
    result = await ensure_bootstrap_admin(store, different_settings)

    assert result is None
    users = await store.list_users()
    assert len(users) == 1
    pepper = derive_token_pepper(different_settings.secret_key.get_secret_value())
    resolved = await resolve_token(store, "a-totally-different-token", pepper)
    assert resolved is None


@pytest.mark.asyncio
async def test_bootstrap_no_token_no_admin_returns_none(sqlite_path: str):
    store = await AuthStore.open(sqlite_path)
    settings = _settings(bootstrap_token=None)

    result = await ensure_bootstrap_admin(store, settings)

    assert result is None
    users = await store.list_users()
    assert users == []


@pytest.mark.asyncio
async def test_bootstrap_never_logs_raw_token(sqlite_path: str, caplog):
    import logging

    from warren.logging import configure_logging

    configure_logging()
    store = await AuthStore.open(sqlite_path)
    settings = _settings(bootstrap_token="super-secret-raw-token-value")

    with caplog.at_level(logging.INFO):
        await ensure_bootstrap_admin(store, settings)

    rendered = " ".join(r.getMessage() for r in caplog.records)
    assert "super-secret-raw-token-value" not in rendered
