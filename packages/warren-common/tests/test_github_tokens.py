"""AK1: issuer contract -- grants from template folders, narrowed minting, workspace files."""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from warren_common.github_tokens import (
    GitHubAppMinter,
    GitHubGrant,
    TokenIssuerError,
    credential_store_deny_paths,
    git_credential_env,
    github_grants_for,
    grant_for_path,
    parse_github_repo,
    write_workspace_credential_files,
)
from warren_common.models import FolderSpec


@pytest.fixture(scope="module")
def test_key() -> tuple[bytes, object]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )
    return pem, key.public_key()


def _folder(url: str, type_: str = "git-worktree", readonly: bool = False, mount: str = "code/x") -> FolderSpec:
    return FolderSpec(name=mount, type=type_, url=url, mount=mount, readonly=readonly)


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://github.com/acme/app.git", ("acme", "app")),
        ("https://github.com/acme/app", ("acme", "app")),
        ("git@github.com:acme/app.git", ("acme", "app")),
        ("ssh://git@github.com/acme/app.git", ("acme", "app")),
        ("https://gitlab.com/acme/app.git", None),
        ("https://github.com.evil.com/acme/app.git", None),
        (None, None),
    ],
)
def test_parse_github_repo(url, expected):
    assert parse_github_repo(url) == expected


def test_grants_are_per_owner_and_write_only_when_template_pushes():
    grants = github_grants_for(
        [
            _folder("https://github.com/acme/app.git", mount="code/app"),
            _folder("https://github.com/acme/docs.git", type_="git-clone", mount="refs/docs"),
            _folder("https://github.com/other/lib.git", readonly=True, mount="code/lib"),
            _folder("https://gitlab.com/acme/ignored.git", mount="code/ign"),
            FolderSpec(name="wiki", type="local-path", path="~/wiki", mount="wiki"),
        ]
    )
    assert set(grants) == {"acme", "other"}
    assert grants["acme"].repositories == ("app", "docs")
    assert grants["acme"].permissions == {"contents": "write", "pull_requests": "write"}
    assert grants["other"].permissions == {"contents": "read", "pull_requests": "read"}


def test_grant_for_path_refuses_repos_outside_the_template():
    grants = github_grants_for([_folder("https://github.com/acme/app.git")])
    assert grant_for_path(grants, "acme/app.git") is grants["acme"]
    assert grant_for_path(grants, "acme/app") is grants["acme"]
    assert grant_for_path(grants, "acme/secret-repo.git") is None
    assert grant_for_path(grants, "evil/app.git") is None
    assert grant_for_path(grants, "") is grants["acme"]


def _github(calls: list, *, installation_status: int = 200):
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.path == "/repos/acme/app/installation":
            return httpx.Response(installation_status, json={"id": 42})
        if request.url.path == "/app/installations/42/access_tokens":
            return httpx.Response(
                201, json={"token": "ghs_minted", "expires_at": "2099-01-01T00:00:00Z"}
            )
        return httpx.Response(404)

    return httpx.MockTransport(handler)


def test_minter_narrows_token_to_grant_and_caches(test_key):
    pem, public = test_key
    calls: list[httpx.Request] = []
    minter = GitHubAppMinter("123", lambda: pem, transport=_github(calls))
    grant = GitHubGrant("acme", ("app",), {"contents": "read", "pull_requests": "read"})

    issued = minter.issue(grant)
    assert issued.token == "ghs_minted"
    assert "ghs_minted" not in repr(issued)

    mint = calls[-1]
    assert json.loads(mint.content) == {
        "repositories": ["app"],
        "permissions": {"contents": "read", "pull_requests": "read"},
    }
    claims = jwt.decode(mint.headers["Authorization"].removeprefix("Bearer "), public, algorithms=["RS256"])
    assert claims["iss"] == "123"
    assert claims["exp"] - claims["iat"] <= 600

    minter.issue(grant)
    assert len(calls) == 2


def test_minter_fails_closed(test_key):
    pem, _ = test_key
    with pytest.raises(TokenIssuerError):
        GitHubAppMinter("123", lambda: pem, transport=_github([])).issue(GitHubGrant("acme", (), {}))
    with pytest.raises(TokenIssuerError, match="not installed"):
        GitHubAppMinter("123", lambda: pem, transport=_github([], installation_status=404)).issue(
            GitHubGrant("acme", ("app",), {"contents": "read"})
        )

    def _no_key() -> bytes:
        raise TokenIssuerError("no key")

    with pytest.raises(TokenIssuerError, match="no key"):
        GitHubAppMinter("123", _no_key, transport=_github([])).issue(
            GitHubGrant("acme", ("app",), {"contents": "read"})
        )


@pytest.mark.skipif(sys.platform == "win32", reason="asserts POSIX mode bits on sandbox credential files")
def test_workspace_files_hold_no_token_and_env_holds_only_paths(tmp_path: Path):
    env = write_workspace_credential_files(tmp_path, "http://127.0.0.1:9/git-credential/ws", "bearer-xyz")
    helper = tmp_path / ".warren" / "bin" / "git-credential-warren"
    assert env == git_credential_env(helper)
    assert env["GIT_CONFIG_VALUE_0"] == ""
    assert env["GIT_CONFIG_VALUE_1"] == str(helper)
    assert env["GIT_CONFIG_KEY_2"] == "credential.https://github.com.useHttpPath"
    assert "bearer-xyz" not in json.dumps(env)
    auth = tmp_path / ".warren" / "credential-auth"
    assert auth.read_text() == "Authorization: Bearer bearer-xyz\n"
    assert stat.S_IMODE(auth.stat().st_mode) == 0o600
    assert stat.S_IMODE(helper.stat().st_mode) == 0o700
    assert (tmp_path / ".warren" / "bin" / "gh").exists()


def test_credential_store_deny_paths_cover_keychain_and_key_file(tmp_path: Path):
    paths = credential_store_deny_paths(tmp_path)
    assert str(tmp_path / "Library" / "Keychains") in paths
    assert str(tmp_path / ".warren" / "github-app") in paths
