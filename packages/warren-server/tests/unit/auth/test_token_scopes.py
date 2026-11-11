"""Token scopes and lineage on every state backend (auth_store fixture: SQLite and DynamoDB
under moto): default scope, child-never-broader, child expiry <= parent, lineage revoke."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from warren.auth.scopes import TokenLineageViolation

NOW = datetime.now(timezone.utc)


async def _user(store, name="alice"):
    return await store.create_user(username=name, is_admin=False)


async def _mint(store, user, h, **kw):
    return await store.create_token(user_id=user.user_id, hashed_token=h, **kw)


@pytest.mark.asyncio
async def test_default_scope_is_full(auth_store):
    u = await _user(auth_store)
    t = await _mint(auth_store, u, "h1")
    assert t.scope == "full"
    assert (await auth_store.get_token(t.token_id)).scope == "full"
    assert [x.scope for x in await auth_store.list_tokens_for_user(u.user_id)] == ["full"]


@pytest.mark.asyncio
async def test_scope_roundtrips_and_resolves(auth_store):
    u = await _user(auth_store)
    t = await _mint(auth_store, u, "h1", scope="ui-read")
    assert (await auth_store.get_token(t.token_id)).scope == "ui-read"
    user, tok = await auth_store.get_active_user_and_token_by_hashed_token("h1")
    assert user.user_id == u.user_id and tok.token_id == t.token_id and tok.scope == "ui-read"
    assert await auth_store.get_active_user_and_token_by_hashed_token("nope") is None


@pytest.mark.asyncio
async def test_unknown_scope_rejected(auth_store):
    u = await _user(auth_store)
    with pytest.raises(ValueError):
        await _mint(auth_store, u, "h1", scope="root")


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("parent", "child", "ok"),
    [
        ("full", "full", True), ("full", "ui-act", True), ("full", "ui-read", True),
        ("ui-act", "ui-act", True), ("ui-act", "ui-read", True), ("ui-act", "full", False),
        ("ui-read", "ui-read", True), ("ui-read", "ui-act", False), ("ui-read", "full", False),
    ],
)
async def test_child_scope_never_broader(auth_store, parent, child, ok):
    u = await _user(auth_store)
    p = await _mint(auth_store, u, "hp", scope=parent)
    if ok:
        c = await _mint(auth_store, u, "hc", scope=child, created_by_token_id=p.token_id)
        assert c.scope == child
    else:
        with pytest.raises(TokenLineageViolation):
            await _mint(auth_store, u, "hc", scope=child, created_by_token_id=p.token_id)
        assert await auth_store.get_active_user_and_token_by_hashed_token("hc") is None


@pytest.mark.asyncio
async def test_child_expiry_not_beyond_parent(auth_store):
    u = await _user(auth_store)
    exp = NOW + timedelta(days=1)
    p = await _mint(auth_store, u, "hp", expires_at=exp)
    await _mint(auth_store, u, "ok", expires_at=exp, created_by_token_id=p.token_id)
    for bad in (exp + timedelta(seconds=1), None):
        with pytest.raises(TokenLineageViolation):
            await _mint(auth_store, u, "bad", expires_at=bad, created_by_token_id=p.token_id)


@pytest.mark.asyncio
async def test_unknown_parent_is_not_a_violation(auth_store):
    # Provenance may point at a token already purged; nothing to compare against.
    u = await _user(auth_store)
    await _mint(auth_store, u, "h1", created_by_token_id="gone")


@pytest.mark.asyncio
async def test_lineage_revoke_takes_all_descendants_only(auth_store):
    u, v = await _user(auth_store), await _user(auth_store, "bob")
    root = await _mint(auth_store, u, "r")
    kid = await _mint(auth_store, u, "k", created_by_token_id=root.token_id)
    grandkid = await _mint(auth_store, u, "g", created_by_token_id=kid.token_id)
    cross = await _mint(auth_store, v, "x", created_by_token_id=grandkid.token_id)  # other user
    sibling = await _mint(auth_store, u, "s")
    other_kid = await _mint(auth_store, u, "o", created_by_token_id=sibling.token_id)

    assert await auth_store.revoke_token_lineage(kid.token_id) == 3
    for t, h in ((kid, "k"), (grandkid, "g"), (cross, "x")):
        assert (await auth_store.get_token(t.token_id)).revoked_at is not None
        assert await auth_store.get_active_user_and_token_by_hashed_token(h) is None
    for t in (root, sibling, other_kid):
        assert (await auth_store.get_token(t.token_id)).revoked_at is None

    assert await auth_store.revoke_token_lineage(kid.token_id) == 0  # idempotent
    assert await auth_store.revoke_token_lineage("missing") == 0
    assert await auth_store.revoke_token_lineage(root.token_id) == 1  # only root left live


@pytest.mark.asyncio
async def test_lineage_revoke_is_iterative_on_deep_chains(auth_store, state_backend):
    depth = 1200 if state_backend == "sqlite" else 60  # moto mints are slow; sqlite exceeds the recursion limit
    u = await _user(auth_store)
    prev = await _mint(auth_store, u, "c0")
    root = prev
    for i in range(1, depth):  # deeper than the recursion limit
        prev = await _mint(auth_store, u, f"c{i}", created_by_token_id=prev.token_id)
    assert await auth_store.revoke_token_lineage(root.token_id) == depth
