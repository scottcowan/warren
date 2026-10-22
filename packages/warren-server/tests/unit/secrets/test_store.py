from __future__ import annotations

import pytest

from warren.registry.store import open_db
from warren.secrets import store as local_store
from warren.secrets.cipher import LocalCipher


@pytest.fixture
async def db(sqlite_path):
    conn = await open_db(sqlite_path)
    yield conn
    await conn.close()


@pytest.fixture
def cipher():
    return LocalCipher("test-secret-key")


async def test_set_and_resolve_secret(db, cipher):
    await local_store.set_secret(db, cipher, "user-1", "API_KEY", "sk-abc")
    resolved = await local_store.resolve_secrets_for_names(db, cipher, "user-1", ["API_KEY"])
    assert resolved == {"API_KEY": "sk-abc"}


async def test_set_is_upsert_on_same_owner_name(db, cipher):
    await local_store.set_secret(db, cipher, "user-1", "API_KEY", "old-value")
    await local_store.set_secret(db, cipher, "user-1", "API_KEY", "new-value")
    resolved = await local_store.resolve_secrets_for_names(db, cipher, "user-1", ["API_KEY"])
    assert resolved == {"API_KEY": "new-value"}


async def test_resolve_returns_only_named_secrets(db, cipher):
    await local_store.set_secret(db, cipher, "user-1", "A_SECRET", "a")
    await local_store.set_secret(db, cipher, "user-1", "B_SECRET", "b")
    await local_store.set_secret(db, cipher, "user-1", "C_SECRET", "c")

    assert await local_store.resolve_secrets_for_names(db, cipher, "user-1", ["A_SECRET"]) == {
        "A_SECRET": "a"
    }
    assert await local_store.resolve_secrets_for_names(
        db, cipher, "user-1", ["A_SECRET", "B_SECRET"]
    ) == {"A_SECRET": "a", "B_SECRET": "b"}
    # A secret the owner has but didn't name is never returned.
    assert "C_SECRET" not in await local_store.resolve_secrets_for_names(
        db, cipher, "user-1", ["A_SECRET", "B_SECRET"]
    )


async def test_resolve_empty_names_list_returns_empty(db, cipher):
    await local_store.set_secret(db, cipher, "user-1", "A_SECRET", "a")
    assert await local_store.resolve_secrets_for_names(db, cipher, "user-1", []) == {}


async def test_resolve_never_sees_another_owners_secrets(db, cipher):
    await local_store.set_secret(db, cipher, "user-1", "SHARED_NAME", "owner-1-value")
    await local_store.set_secret(db, cipher, "user-2", "SHARED_NAME", "owner-2-value")

    assert await local_store.resolve_secrets_for_names(db, cipher, "user-1", ["SHARED_NAME"]) == {
        "SHARED_NAME": "owner-1-value"
    }
    assert await local_store.resolve_secrets_for_names(db, cipher, "user-2", ["SHARED_NAME"]) == {
        "SHARED_NAME": "owner-2-value"
    }


async def test_list_secrets_scoped_to_owner(db, cipher):
    await local_store.set_secret(db, cipher, "user-1", "A", "va")
    await local_store.set_secret(db, cipher, "user-2", "B", "vb")

    rows = await local_store.list_secrets(db, "user-1")
    assert [r["name"] for r in rows] == ["A"]


async def test_delete_secret_removes_only_matching_owner_name(db, cipher):
    await local_store.set_secret(db, cipher, "user-1", "A", "va")
    await local_store.set_secret(db, cipher, "user-2", "A", "vb")

    deleted = await local_store.delete_secret(db, "user-1", "A")
    assert deleted is True

    assert await local_store.list_secrets(db, "user-1") == []
    assert len(await local_store.list_secrets(db, "user-2")) == 1


async def test_delete_unknown_secret_returns_false(db, cipher):
    assert await local_store.delete_secret(db, "user-1", "NOPE") is False
