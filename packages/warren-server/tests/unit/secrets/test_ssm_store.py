from __future__ import annotations

from unittest.mock import MagicMock

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
