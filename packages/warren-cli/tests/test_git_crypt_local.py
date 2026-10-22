"""AK2 local materialization: the git-crypt key is read by the CLI, never put in the workspace env."""

from __future__ import annotations

import base64

import pytest
import typer
from warren_common import SecretLoader
from warren_common.models import ProjectConfig

from warren_cli import dispatch


def _template(**over) -> ProjectConfig:
    return ProjectConfig.model_validate({"name": "vault", **over})


def test_none_never_reads_the_key(tmp_path):
    SecretLoader.add_local("vault", "GIT_CRYPT_KEY", base64.b64encode(b"k").decode(), tmp_path)
    assert dispatch._local_git_crypt_key("vault", _template(), [], tmp_path) is None


def test_unlock_and_drop_reads_base64_key_from_local_secrets(tmp_path):
    SecretLoader.add_local("vault", "VAULT_KEY", base64.b64encode(b"\x00GITCRYPTKEY").decode(), tmp_path)
    template = _template(git_crypt="unlock_and_drop", git_crypt_key_secret="VAULT_KEY")
    assert dispatch._local_git_crypt_key("vault", template, [], tmp_path) == b"\x00GITCRYPTKEY"


def test_unlock_and_drop_without_key_secret_exits(tmp_path):
    with pytest.raises(typer.Exit):
        dispatch._local_git_crypt_key("vault", _template(git_crypt="unlock_and_drop"), [], tmp_path)


def test_key_listed_as_workspace_secret_is_refused(tmp_path):
    with pytest.raises(typer.Exit):
        dispatch._local_git_crypt_key("vault", _template(), ["GIT_CRYPT_KEY"], tmp_path)
