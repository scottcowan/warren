from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from warren.secrets import ssm_store


def _mock_ssm() -> MagicMock:
    m = MagicMock(name="ssm_client")

    class _ParameterNotFound(Exception):
        pass

    m.exceptions.ParameterNotFound = _ParameterNotFound
    return m


async def test_put_secret_writes_securestring_with_owner_scoped_path():
    ssm = _mock_ssm()
    await ssm_store.put_secret(ssm, "warren", "server-1", "user-1", "API_KEY", "sk-abc")

    ssm.put_parameter.assert_called_once()
    kwargs = ssm.put_parameter.call_args.kwargs
    assert kwargs["Name"] == "/warren/server-1/user-1/API_KEY"
    assert kwargs["Value"] == "sk-abc"
    assert kwargs["Type"] == "SecureString"
    assert kwargs["Overwrite"] is True
    assert kwargs["Tier"] == "Standard"  # Encrypt-only KMS use, whatever the account default tier
    assert "KeyId" not in kwargs


async def test_put_secret_passes_kms_key_id_when_given():
    ssm = _mock_ssm()
    await ssm_store.put_secret(
        ssm, "warren", "server-1", "user-1", "API_KEY", "sk-abc", kms_key_id="arn:aws:kms:...:key/abc"
    )
    kwargs = ssm.put_parameter.call_args.kwargs
    assert kwargs["KeyId"] == "arn:aws:kms:...:key/abc"


async def test_delete_secret_returns_true_on_success():
    ssm = _mock_ssm()
    found = await ssm_store.delete_secret(ssm, "warren", "server-1", "user-1", "API_KEY")
    assert found is True
    ssm.delete_parameter.assert_called_once_with(Name="/warren/server-1/user-1/API_KEY")


async def test_delete_secret_returns_false_when_not_found():
    ssm = _mock_ssm()
    ssm.delete_parameter.side_effect = ssm.exceptions.ParameterNotFound()
    found = await ssm_store.delete_secret(ssm, "warren", "server-1", "user-1", "MISSING")
    assert found is False


async def _local_db(sqlite_path, secrets):
    from warren.registry.store import open_db
    from warren.secrets import store as local_store
    from warren.secrets.cipher import LocalCipher

    db = await open_db(sqlite_path)
    cipher = LocalCipher("test-secret-key")
    for owner, name, value in secrets:
        await local_store.set_secret(db, cipher, owner, name, value)
    return db, cipher


@pytest.fixture
async def mirror_env(sqlite_path):
    db, cipher = await _local_db(sqlite_path, [])
    ssm = _mock_ssm()
    mirror = ssm_store.SsmMirror(db, cipher, lambda: ssm, "warren", "server-1", kms_key_id="alias/k")
    yield mirror, db, cipher, ssm
    await db.close()


async def _outbox(db):
    async with db.execute("SELECT owner_id, name, op, attempts FROM ssm_outbox") as cur:
        return await cur.fetchall()


async def test_apply_pushes_and_clears_outbox(mirror_env):
    from warren.secrets import store as local_store

    mirror, db, cipher, ssm = mirror_env
    ok = await mirror.apply("alice", "A", "put", lambda: local_store.set_secret(db, cipher, "alice", "A", "v"))
    assert ok is True
    kwargs = ssm.put_parameter.call_args.kwargs
    assert (kwargs["Name"], kwargs["Value"], kwargs["KeyId"]) == ("/warren/server-1/alice/A", "v", "alias/k")
    assert await _outbox(db) == []


async def test_failed_push_stays_pending_without_plaintext_and_retries(mirror_env):
    from warren.secrets import store as local_store

    mirror, db, cipher, ssm = mirror_env
    ssm.put_parameter.side_effect = RuntimeError("down")
    ok = await mirror.apply("alice", "A", "put", lambda: local_store.set_secret(db, cipher, "alice", "A", "sk-1"))
    assert ok is False
    assert await _outbox(db) == [("alice", "A", "put", 1)]
    async with db.execute("SELECT * FROM ssm_outbox") as cur:
        assert "sk-1" not in repr(await cur.fetchall())

    # A crash/restart loses nothing: a fresh mirror on the same DB converges it.
    ssm.put_parameter.side_effect = None
    fresh = ssm_store.SsmMirror(db, cipher, lambda: ssm, "warren", "server-1")
    assert await fresh.flush() == []
    assert ssm.put_parameter.call_args.kwargs["Value"] == "sk-1"
    assert await _outbox(db) == []


async def test_retry_syncs_from_current_local_state(mirror_env):
    # A row recorded before a local write that never landed re-syncs SSM to the local
    # state at retry time: no local row -> DeleteParameter, never a stale put.
    mirror, db, _, ssm = mirror_env
    await mirror._record("alice", "GONE", "put")
    assert await mirror.flush() == []
    ssm.put_parameter.assert_not_called()
    ssm.delete_parameter.assert_called_once_with(Name="/warren/server-1/alice/GONE")


async def test_mirrored_names_filters_to_declared_and_existing(mirror_env):
    from warren.secrets import store as local_store

    mirror, db, cipher, _ = mirror_env
    for owner, name in [("alice", "A"), ("alice", "EXTRA"), ("bob", "B")]:
        await mirror.apply(owner, name, "put", lambda o=owner, n=name: local_store.set_secret(db, cipher, o, n, "v"))
    assert await mirror.mirrored_names("alice", ["A", "B", "MISSING"]) == ["A"]
    assert await mirror.mirrored_names("bob", ["A", "B"]) == ["B"]
    assert await mirror.mirrored_names("", ["A"]) == []
    assert await mirror.mirrored_names("alice", []) == []


async def test_mirrored_names_flushes_then_refuses_still_pending(mirror_env):
    from warren.secrets import store as local_store
    from warren_common.errors import ProvisionError

    mirror, db, cipher, ssm = mirror_env
    ssm.put_parameter.side_effect = RuntimeError("down")
    await mirror.apply("alice", "A", "put", lambda: local_store.set_secret(db, cipher, "alice", "A", "v"))
    with pytest.raises(ProvisionError, match="A"):
        await mirror.mirrored_names("alice", ["A"])
    # An unrelated pending name doesn't block a workspace that doesn't declare it.
    assert await mirror.mirrored_names("alice", ["OTHER"]) == []

    ssm.put_parameter.side_effect = None
    assert await mirror.mirrored_names("alice", ["A"]) == ["A"]


async def test_mirror_never_reads_ssm(mirror_env):
    from warren.secrets import store as local_store

    mirror, db, cipher, ssm = mirror_env
    await mirror.apply("alice", "A", "put", lambda: local_store.set_secret(db, cipher, "alice", "A", "v"))
    await mirror.apply("alice", "A", "delete", lambda: local_store.delete_secret(db, "alice", "A"))
    await mirror.mirrored_names("alice", ["A"])
    await mirror.flush()
    assert {name for name, _, _ in ssm.method_calls} == {"put_parameter", "delete_parameter"}


@pytest.mark.parametrize(
    ("prefix", "server_id"),
    [("", "server-1"), ("warren", ""), ("  ", "server-1"), ("warren", " "),
     ("warren/x", "server-1"), ("warren", "a/b"), ("warren", "/"), ("warren", " server-1")],
)
async def test_mirror_refuses_a_scope_wider_than_its_own_server(sqlite_path, prefix, server_id):
    db, cipher = await _local_db(sqlite_path, [])
    try:
        with pytest.raises(ValueError):
            ssm_store.SsmMirror(db, cipher, _mock_ssm, prefix, server_id)
    finally:
        await db.close()


async def test_apply_refuses_unsafe_owner_segment(mirror_env):
    mirror, _, _, ssm = mirror_env
    with pytest.raises(ValueError):
        await mirror.apply("../x", "A", "put", lambda: None)
    with pytest.raises(ValueError):
        await mirror.apply("", "A", "put", lambda: None)
    ssm.put_parameter.assert_not_called()
