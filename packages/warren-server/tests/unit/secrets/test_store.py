"""Secret store behaviour, run against every WARREN_SECRETS_BACKEND (the `secret_store`
fixture in tests/unit/conftest.py: SQLite + Fernet, and Secrets Manager under moto)."""

from __future__ import annotations


async def test_set_and_resolve_secret(secret_store):
    await secret_store.set("user-1", "API_KEY", "sk-abc")
    resolved = await secret_store.resolve("user-1", ["API_KEY"])
    assert resolved == {"API_KEY": "sk-abc"}


async def test_set_is_upsert_on_same_owner_name(secret_store):
    await secret_store.set("user-1", "API_KEY", "old-value")
    await secret_store.set("user-1", "API_KEY", "new-value")
    resolved = await secret_store.resolve("user-1", ["API_KEY"])
    assert resolved == {"API_KEY": "new-value"}


async def test_resolve_returns_only_named_secrets(secret_store):
    await secret_store.set("user-1", "A_SECRET", "a")
    await secret_store.set("user-1", "B_SECRET", "b")
    await secret_store.set("user-1", "C_SECRET", "c")

    assert await secret_store.resolve("user-1", ["A_SECRET"]) == {"A_SECRET": "a"}
    assert await secret_store.resolve("user-1", ["A_SECRET", "B_SECRET"]) == {"A_SECRET": "a", "B_SECRET": "b"}
    # A secret the owner has but didn't name is never returned.
    assert "C_SECRET" not in await secret_store.resolve("user-1", ["A_SECRET", "B_SECRET"])


async def test_resolve_empty_names_list_returns_empty(secret_store):
    await secret_store.set("user-1", "A_SECRET", "a")
    assert await secret_store.resolve("user-1", []) == {}


async def test_resolve_skips_unknown_names(secret_store):
    await secret_store.set("user-1", "A_SECRET", "a")
    assert await secret_store.resolve("user-1", ["A_SECRET", "MISSING"]) == {"A_SECRET": "a"}


async def test_resolve_never_sees_another_owners_secrets(secret_store):
    await secret_store.set("user-1", "SHARED_NAME", "owner-1-value")
    await secret_store.set("user-2", "SHARED_NAME", "owner-2-value")

    assert await secret_store.resolve("user-1", ["SHARED_NAME"]) == {"SHARED_NAME": "owner-1-value"}
    assert await secret_store.resolve("user-2", ["SHARED_NAME"]) == {"SHARED_NAME": "owner-2-value"}


async def test_list_secrets_scoped_to_owner(secret_store):
    await secret_store.set("user-1", "A", "va")
    await secret_store.set("user-2", "B", "vb")

    rows = await secret_store.list("user-1")
    assert [r["name"] for r in rows] == ["A"]
    assert rows[0]["created_at"] and rows[0]["updated_at"]


async def test_list_is_sorted_and_case_sensitive_per_owner(secret_store):
    await secret_store.set("Alice", "B", "1")
    await secret_store.set("Alice", "A", "2")
    await secret_store.set("alice", "C", "3")
    assert [r["name"] for r in await secret_store.list("Alice")] == ["A", "B"]
    assert [r["name"] for r in await secret_store.list("alice")] == ["C"]


async def test_delete_secret_removes_only_matching_owner_name(secret_store):
    await secret_store.set("user-1", "A", "va")
    await secret_store.set("user-2", "A", "vb")

    deleted = await secret_store.delete("user-1", "A")
    assert deleted is True

    assert await secret_store.list("user-1") == []
    assert len(await secret_store.list("user-2")) == 1
    assert await secret_store.exists("user-1", "A") is False
    assert await secret_store.resolve("user-1", ["A"]) == {}


async def test_delete_unknown_secret_returns_false(secret_store):
    assert await secret_store.delete("user-1", "NOPE") is False


async def test_set_after_delete_recreates(secret_store):
    await secret_store.set("user-1", "A", "first")
    assert await secret_store.delete("user-1", "A") is True
    await secret_store.set("user-1", "A", "second")
    assert await secret_store.exists("user-1", "A") is True
    assert await secret_store.resolve("user-1", ["A"]) == {"A": "second"}


async def test_reencrypt_keeps_value(secret_store):
    await secret_store.set("user-1", "A", "va")
    assert await secret_store.reencrypt("user-1", "A") is True
    assert await secret_store.resolve("user-1", ["A"]) == {"A": "va"}
    assert await secret_store.reencrypt("user-1", "NOPE") is False


async def test_count_counts_every_owner(secret_store):
    assert await secret_store.count() == 0
    await secret_store.set("user-1", "A", "va")
    await secret_store.set("user-2", "A", "vb")
    assert await secret_store.count() == 2
