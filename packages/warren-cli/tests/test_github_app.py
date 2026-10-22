"""AK1 local CLI issuer: OS credential store, local endpoint, workspace helper, gh wrapper.

Uses a generated RSA test key, an in-memory/fake credential store and a mocked
GitHub API -- never the real Keychain or a real App key.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from warren_common.github_tokens import github_grants_for
from warren_common.models import FolderSpec

from warren_cli import github_app
from warren_cli.config import GitHubAppSection
from warren_cli.credential_store import InMemoryCredentialStore, LibsecretStore, LoginKeychainStore

posix_sh_only = pytest.mark.skipif(
    sys.platform == "win32", reason="POSIX sh credential helper / fake keychain binaries; local sandbox credentials are POSIX-only"
)

_MINTED = "ghs_test_minted_token"


@pytest.fixture(scope="module")
def pem() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def _mock_github(calls: list) -> httpx.MockTransport:
    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        if request.url.path == "/app/installations/7/access_tokens":
            return httpx.Response(201, json={"token": _MINTED, "expires_at": "2099-01-01T00:00:00Z"})
        return httpx.Response(404)

    return httpx.MockTransport(handler)


@pytest.fixture
def endpoint(tmp_path, pem):
    store = InMemoryCredentialStore()
    section = GitHubAppSection(app_id="123", installations={"acme": "7"})
    store.set(section.key_service, section.app_id, pem)
    calls: list[httpx.Request] = []
    issuer = github_app.local_issuer(section, store, transport=_mock_github(calls))
    state_root = tmp_path / "state"
    server = github_app.serve(issuer, state_root)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server, state_root, calls
    server.shutdown()
    server.server_close()


def _grants():
    return github_grants_for(
        [FolderSpec(name="app", type="git-worktree", url="https://github.com/acme/app.git", mount="code/app")]
    )


def _workspace(endpoint, tmp_path) -> tuple[Path, dict[str, str]]:
    server, state_root, _ = endpoint
    root = tmp_path / "ws"
    root.mkdir()
    env = github_app.setup_workspace_git_credentials(
        "ws-1", root, _grants(), port=server.server_address[1], state_root=state_root
    )
    return root, env


def _git_env(root: Path, env: dict[str, str]) -> dict[str, str]:
    return {
        **env,
        "HOME": str(root),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
    }


def _credential_fill(root: Path, env: dict[str, str], path: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git", "credential", "fill"],
        input=f"protocol=https\nhost=github.com\npath={path}\n\n",
        capture_output=True,
        text=True,
        env=_git_env(root, env),
        cwd=root,
    )


@pytest.mark.skipif(not shutil.which("curl"), reason="curl required by the helper")
@posix_sh_only
def test_git_gets_token_through_helper_never_from_config_or_env(endpoint, tmp_path):
    root, env = _workspace(endpoint, tmp_path)
    _, _, calls = endpoint

    result = _credential_fill(root, env, "acme/app.git")
    assert result.returncode == 0, result.stderr
    assert f"password={_MINTED}" in result.stdout
    assert "username=x-access-token" in result.stdout

    assert json.loads(calls[-1].content)["repositories"] == ["app"]
    assert _MINTED not in json.dumps(env)
    for f in root.rglob("*"):
        if f.is_file():
            assert _MINTED not in f.read_text(errors="ignore")


@pytest.mark.skipif(not shutil.which("curl"), reason="curl required by the helper")
def test_helper_gets_nothing_for_repo_outside_template(endpoint, tmp_path):
    root, env = _workspace(endpoint, tmp_path)
    result = _credential_fill(root, env, "acme/not-in-template.git")
    assert _MINTED not in result.stdout


@pytest.mark.skipif(not shutil.which("curl"), reason="curl required by the gh wrapper")
@posix_sh_only
def test_gh_wrapper_sets_gh_token_only_for_gh(endpoint, tmp_path):
    root, env = _workspace(endpoint, tmp_path)
    fake_bin = tmp_path / "fakebin"
    fake_bin.mkdir()
    fake_gh = fake_bin / "gh"
    fake_gh.write_text('#!/bin/sh\nprintf "%s" "$GH_TOKEN"\n')
    fake_gh.chmod(0o755)
    repo = root / "code" / "app"
    repo.mkdir(parents=True)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(
        ["git", "remote", "add", "origin", "https://github.com/acme/app.git"], cwd=repo, check=True
    )
    path = f"{root / '.warren' / 'bin'}:{fake_bin}:/usr/bin:/bin"
    result = subprocess.run(
        ["gh", "pr", "list"],
        capture_output=True,
        text=True,
        cwd=repo,
        env={**_git_env(root, env), "PATH": path},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == _MINTED
    assert "GH_TOKEN" not in env


def _get(server, path: str, bearer: str | None) -> httpx.Response:
    headers = {"Authorization": f"Bearer {bearer}"} if bearer else {}
    return httpx.get(f"http://127.0.0.1:{server.server_address[1]}{path}", headers=headers)


def test_endpoint_requires_the_workspaces_own_bearer(endpoint, tmp_path):
    server, state_root, _ = endpoint
    bearer_1 = github_app.register_workspace("ws-1", _grants(), state_root)
    bearer_2 = github_app.register_workspace("ws-2", _grants(), state_root)
    assert _get(server, "/git-credential/ws-1?path=acme/app.git", None).status_code == 401
    assert _get(server, "/git-credential/ws-1?path=acme/app.git", bearer_2).status_code == 401
    assert _get(server, "/git-credential/ws-1?path=acme/app.git", bearer_1).status_code == 200
    assert _get(server, "/git-credential/ws-1?path=acme/other.git", bearer_1).status_code == 403
    assert _get(server, "/git-credential/..%2Fx?path=acme/app.git", bearer_1).status_code == 401
    registration = (state_root / "ws-1" / github_app.REGISTRATION_FILE).read_text()
    assert bearer_1 not in registration


def test_endpoint_reports_missing_key(tmp_path):
    section = GitHubAppSection(app_id="123", installations={"acme": "7"})
    issuer = github_app.local_issuer(section, InMemoryCredentialStore(), transport=_mock_github([]))
    server = github_app.serve(issuer, tmp_path)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        bearer = github_app.register_workspace("ws-1", _grants(), tmp_path)
        resp = _get(server, "/git-credential/ws-1?path=acme/app.git", bearer)
        assert resp.status_code == 502
        assert "set-key" in resp.text
    finally:
        server.shutdown()
        server.server_close()


def test_ensure_local_endpoint_reuses_running_or_spawns(tmp_path, monkeypatch):
    spawned: list[list[str]] = []

    def _spawn(argv, **kwargs):
        spawned.append(argv)
        (tmp_path / github_app.ENDPOINT_STATE_FILE).write_text(json.dumps({"pid": os.getpid(), "port": 4242}))

    monkeypatch.setattr(github_app, "_healthy", lambda port: port == 4242)
    assert github_app.ensure_local_endpoint(tmp_path, spawn=_spawn) == 4242
    assert spawned and spawned[0][1:3] == ["-m", "warren_cli.github_app"]
    assert github_app.ensure_local_endpoint(tmp_path, spawn=_spawn) == 4242
    assert len(spawned) == 1


def _fake_binary(tmp_path: Path, name: str, stdout: str = "") -> tuple[Path, Path]:
    record = tmp_path / f"{name}.record"
    script = tmp_path / name
    script.write_text(
        f'#!/bin/sh\necho "ARGV:$*" >> "{record}"\ncat >> "{record}"\nprintf "%s" "{stdout}"\n'
    )
    script.chmod(0o755)
    return script, record


@posix_sh_only
def test_login_keychain_store_keeps_value_off_argv(tmp_path):
    import base64

    script, record = _fake_binary(tmp_path, "security", stdout=base64.b64encode(b"PEM").decode())
    store = LoginKeychainStore(binary=str(script))
    store.set("svc", "123", b"PEM")
    assert store.get("svc", "123") == b"PEM"
    lines = record.read_text().splitlines()
    argv_lines = [line for line in lines if line.startswith("ARGV:")]
    assert argv_lines[0] == "ARGV:-i"
    assert base64.b64encode(b"PEM").decode() not in "".join(argv_lines)
    assert "find-generic-password -s svc -a 123 -w" in argv_lines[1]


@posix_sh_only
def test_libsecret_store_keeps_value_off_argv(tmp_path):
    import base64

    script, record = _fake_binary(tmp_path, "secret-tool", stdout=base64.b64encode(b"PEM").decode())
    store = LibsecretStore(binary=str(script))
    store.set("svc", "123", b"PEM")
    assert store.get("svc", "123") == b"PEM"
    argv_lines = [line for line in record.read_text().splitlines() if line.startswith("ARGV:")]
    assert all(base64.b64encode(b"PEM").decode() not in line for line in argv_lines)


def test_dispatch_installs_credentials_only_for_local_runtimes_with_config(tmp_path, monkeypatch):
    from warren_cli import dispatch
    from warren_cli.config import WarrenCLIConfig

    monkeypatch.setattr(github_app, "ensure_local_endpoint", lambda *a, **k: 5555)
    folders = [FolderSpec(name="app", type="git-worktree", url="https://github.com/acme/app.git", mount="code/app")]
    cfg = WarrenCLIConfig.model_validate({"github_app": {"app_id": "123"}})

    env = dispatch._local_git_credentials(cfg, "ws-9", tmp_path, folders, "seatbelt")
    assert env["GIT_CONFIG_COUNT"] == "3"
    assert env["PATH"].startswith(str(tmp_path / ".warren" / "bin"))
    assert (tmp_path / ".warren" / "credential-endpoint").read_text().strip().endswith(":5555/git-credential/ws-9")

    assert dispatch._local_git_credentials(cfg, "ws-9", tmp_path, folders, "docker") == {}
    assert dispatch._local_git_credentials(WarrenCLIConfig(), "ws-9", tmp_path, folders, "seatbelt") == {}
