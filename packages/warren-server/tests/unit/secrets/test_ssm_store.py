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


async def test_list_secrets_for_owner_returns_leaf_names():
    ssm = _mock_ssm()
    ssm.get_parameters_by_path.return_value = {
        "Parameters": [
            {"Name": "/warren/server-1/user-1/API_KEY"},
            {"Name": "/warren/server-1/user-1/ROOT_TOKEN"},
        ]
    }
    rows = await ssm_store.list_secrets_for_owner(ssm, "warren", "server-1", "user-1")
    assert {"name": "API_KEY"} in rows
    assert {"name": "ROOT_TOKEN"} in rows

    call_kwargs = ssm.get_parameters_by_path.call_args.kwargs
    assert call_kwargs["Path"] == "/warren/server-1/user-1/"
    assert call_kwargs["WithDecryption"] is False


def _mirrored(ssm: MagicMock, names: list[str]) -> None:
    ssm.get_parameters_by_path.return_value = {
        "Parameters": [{"Name": f"/warren/server-1/{n}"} for n in names]
    }


async def _local_db(sqlite_path, secrets):
    from warren.registry.store import open_db
    from warren.secrets import store as local_store
    from warren.secrets.cipher import LocalCipher

    db = await open_db(sqlite_path)
    cipher = LocalCipher("test-secret-key")
    for owner, name, value in secrets:
        await local_store.set_secret(db, cipher, owner, name, value)
    return db, cipher


async def test_reconcile_mirror_deletes_orphans_and_restores_missing(sqlite_path):
    # Audit #13: crash after the SSM write but before the local write (orphan
    # "bob/GHOST"), and after an SSM delete but before the local delete
    # ("alice/KEPT" missing from SSM).
    db, cipher = await _local_db(
        sqlite_path, [("alice", "KEPT", "v-kept"), ("alice", "BOTH", "v-both")]
    )
    try:
        ssm = _mock_ssm()
        _mirrored(ssm, ["alice/BOTH", "bob/GHOST"])
        result = await ssm_store.reconcile_mirror(ssm, db, cipher, "warren", "server-1")
    finally:
        await db.close()

    assert result == {"deleted": 1, "restored": 1}
    assert ssm.get_parameters_by_path.call_args.kwargs["Path"] == "/warren/server-1/"
    ssm.delete_parameter.assert_called_once_with(Name="/warren/server-1/bob/GHOST")
    put = ssm.put_parameter.call_args.kwargs
    assert ssm.put_parameter.call_count == 1
    assert (put["Name"], put["Value"]) == ("/warren/server-1/alice/KEPT", "v-kept")


@pytest.mark.parametrize(
    ("prefix", "server_id"),
    [("", "server-1"), ("warren", ""), ("  ", "server-1"), ("warren", " "),
     ("warren/x", "server-1"), ("warren", "a/b"), ("warren", "/"), ("warren", " server-1")],
)
async def test_reconcile_mirror_refuses_a_scope_wider_than_its_own_server(
    sqlite_path, prefix, server_id
):
    db, cipher = await _local_db(sqlite_path, [("alice", "KEPT", "v")])
    try:
        ssm = _mock_ssm()
        _mirrored(ssm, ["secret-key", "alice/OTHER"])
        result = await ssm_store.reconcile_mirror(ssm, db, cipher, prefix, server_id)
    finally:
        await db.close()

    assert result == {"deleted": 0, "restored": 0}
    ssm.get_parameters_by_path.assert_not_called()
    ssm.delete_parameter.assert_not_called()
    ssm.put_parameter.assert_not_called()


async def test_reconcile_mirror_never_wipes_mirror_when_local_store_is_empty(sqlite_path):
    db, cipher = await _local_db(sqlite_path, [])
    try:
        ssm = _mock_ssm()
        _mirrored(ssm, ["alice/A", "bob/B"])
        result = await ssm_store.reconcile_mirror(ssm, db, cipher, "warren", "server-1")
    finally:
        await db.close()

    assert result == {"deleted": 0, "restored": 0}
    ssm.delete_parameter.assert_not_called()
