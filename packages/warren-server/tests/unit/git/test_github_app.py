"""GitHub App JWT -> installation-token exchange unit tests (Phase 4 Plan 03, LIFE-03).

All ten behaviors from 04-03-PLAN.md are covered. The GitHub API is mocked with `respx`
(never real network I/O); RSA keypairs are generated on the fly with `cryptography` and
written to `tmp_path` — no key material is ever committed to the repo. Time is controlled
by monkeypatching the module's `_now` clock reference, never real `asyncio.sleep`.
"""

from __future__ import annotations

import re
import time
from pathlib import Path

import httpx
import jwt
import pytest
import respx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from warren.git import github_app
from warren.git.github_app import (
    GitHubAppCredentials,
    GitHubAuthError,
    make_jwt,
)

INSTALLATION_ID = "12345"
APP_ID = "app-1"
API_BASE = "https://api.github.com"


@pytest.fixture(scope="module")
def rsa_keypair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return private_pem, public_pem


@pytest.fixture
def key_path(tmp_path, rsa_keypair) -> Path:
    private_pem, _ = rsa_keypair
    path = tmp_path / "github-app.pem"
    path.write_bytes(private_pem)
    # T4/V5: token() now fails closed on a group/world-accessible key file --
    # write_bytes leaves the OS default (umask-dependent) mode, so set the
    # documented operator-managed 0600 explicitly; the one test that exercises
    # the permissive-mode refusal chmods it back to 0644 itself.
    path.chmod(0o600)
    return path


@pytest.fixture
def credentials(key_path) -> GitHubAppCredentials:
    return GitHubAppCredentials(
        app_id=APP_ID,
        private_key_path=key_path,
        installation_id=INSTALLATION_ID,
        api_base=API_BASE,
        # Audit T2: token() now fails closed on an empty allow-list -- these tests are
        # about the JWT/exchange/caching mechanics, not the allow-list itself, so give
        # them a non-empty one. The allow-list's own enforcement has dedicated tests
        # below ("--- Audit T2/T4 ---").
        allowed_repos=["warren"],
    )


def _token_url() -> str:
    return f"{API_BASE}/app/installations/{INSTALLATION_ID}/access_tokens"


def _mint_response(token: str = "ghs_minted", expires_in: int = 3600) -> dict:
    expires_at = time.strftime(
        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() + expires_in)
    )
    return {"token": token, "expires_at": expires_at}


# --- Case 1 & 2: make_jwt signing contract -----------------------------------


def test_make_jwt_produces_decodable_rs256_jwt_with_expected_claims(rsa_keypair):
    private_pem, public_pem = rsa_keypair
    now = 1_700_000_000

    token = make_jwt(APP_ID, private_pem, now=now)

    decoded = jwt.decode(
        token,
        public_pem,
        algorithms=["RS256"],
        options={"verify_iat": False, "verify_exp": False},
    )
    assert decoded["iss"] == APP_ID
    assert decoded["iat"] == now - 60
    assert decoded["exp"] == now + 600


def test_make_jwt_lifetime_never_exceeds_github_ten_minute_ceiling(rsa_keypair):
    private_pem, public_pem = rsa_keypair
    now = 1_700_000_000

    token = make_jwt(APP_ID, private_pem, now=now)

    decoded = jwt.decode(
        token,
        public_pem,
        algorithms=["RS256"],
        options={"verify_iat": False, "verify_exp": False},
    )
    assert decoded["exp"] - decoded["iat"] <= 660


# --- Case 3: token() performs the exchange ------------------------------------


@pytest.mark.asyncio
async def test_token_posts_to_installation_access_tokens_with_bearer_jwt(
    credentials,
):
    captured = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        captured["auth"] = request.headers.get("authorization")
        captured["accept"] = request.headers.get("accept")
        return httpx.Response(201, json=_mint_response(token="ghs_abc123"))

    with respx.mock(assert_all_called=True) as mock:
        mock.post(_token_url()).mock(side_effect=_handler)
        result = await credentials.token()

    assert result == "ghs_abc123"
    assert captured["auth"].startswith("Bearer ")
    assert captured["accept"] == "application/vnd.github+json"


# --- Case 4: cache reuse within validity window -------------------------------


@pytest.mark.asyncio
async def test_token_reuses_cache_within_validity_window_zero_further_requests(
    credentials,
):
    with respx.mock(assert_all_called=True) as mock:
        route = mock.post(_token_url()).mock(
            return_value=httpx.Response(201, json=_mint_response(token="ghs_cached"))
        )
        first = await credentials.token()
        second = await credentials.token()

    assert first == "ghs_cached"
    assert second == "ghs_cached"
    assert route.call_count == 1


# --- Case 5: remint when close to expiry --------------------------------------


@pytest.mark.asyncio
async def test_token_reexchanges_when_cached_token_expires_soon(
    credentials, monkeypatch
):
    fake_now = 1_700_000_000.0
    monkeypatch.setattr(github_app, "_now", lambda: fake_now)

    with respx.mock(assert_all_called=True) as mock:
        route = mock.post(_token_url()).mock(
            side_effect=[
                httpx.Response(
                    201,
                    json={
                        "token": "ghs_first",
                        "expires_at": time.strftime(
                            "%Y-%m-%dT%H:%M:%SZ", time.gmtime(fake_now + 200)
                        ),
                    },
                ),
                httpx.Response(201, json=_mint_response(token="ghs_second")),
            ]
        )
        first = await credentials.token()
        second = await credentials.token()

    assert first == "ghs_first"
    assert second == "ghs_second"
    assert route.call_count == 2


# --- Case 6: non-2xx maps to GitHubAuthError ----------------------------------


@pytest.mark.asyncio
async def test_token_non_2xx_response_raises_githubautherror_not_httpstatuserror(
    credentials,
):
    with respx.mock(assert_all_called=True) as mock:
        mock.post(_token_url()).mock(return_value=httpx.Response(401, json={}))

        with pytest.raises(GitHubAuthError):
            await credentials.token()


# --- Case 7: missing/unreadable key file --------------------------------------


@pytest.mark.asyncio
async def test_token_missing_private_key_file_raises_githubautherror_naming_path(
    tmp_path,
):
    missing_path = tmp_path / "does-not-exist.pem"
    credentials = GitHubAppCredentials(
        app_id=APP_ID,
        private_key_path=missing_path,
        installation_id=INSTALLATION_ID,
        api_base=API_BASE,
        allowed_repos=["warren"],
    )

    with pytest.raises(GitHubAuthError) as exc_info:
        await credentials.token()

    assert str(missing_path) in str(exc_info.value)


# --- Case 8: unconfigured credentials fail loudly -----------------------------


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "app_id,installation_id,key_path_present",
    [
        ("", INSTALLATION_ID, True),
        (APP_ID, "", True),
        (APP_ID, INSTALLATION_ID, False),
    ],
)
async def test_token_unconfigured_credentials_raise_githubautherror(
    app_id, installation_id, key_path_present, key_path
):
    credentials = GitHubAppCredentials(
        app_id=app_id,
        private_key_path=key_path if key_path_present else None,
        installation_id=installation_id,
        api_base=API_BASE,
    )

    with pytest.raises(GitHubAuthError) as exc_info:
        await credentials.token()

    assert "github app not configured" in str(exc_info.value)


# --- Case 9: clone_url construction -------------------------------------------


def test_clone_url_embeds_x_access_token(credentials):
    url = credentials.clone_url("https://github.com/o/r.git", "ghs_xxx")
    assert url == "https://x-access-token:ghs_xxx@github.com/o/r.git"


# --- Issue #10: credential_host pins the token to one host -------------------


def test_credential_host_is_github_com_for_public_default(credentials):
    """api_base for the public default is api.github.com, but the git host
    the token is actually usable against is github.com -- these differ, so
    credential_host is special-cased rather than derived from api_base."""
    assert credentials.credential_host == "github.com"


def test_credential_host_follows_enterprise_api_base(key_path):
    enterprise = GitHubAppCredentials(
        app_id=APP_ID,
        private_key_path=key_path,
        installation_id=INSTALLATION_ID,
        api_base="https://github.example.com/api/v3",
    )
    assert enterprise.credential_host == "github.example.com"


# --- Case 10: log hygiene ------------------------------------------------------


def test_module_source_never_logs_secret_named_variables():
    source = Path(github_app.__file__).read_text()
    forbidden_names = {"token", "jwt", "private_key_pem", "raw"}
    for match in re.finditer(r"log\.(info|warning|error|debug|exception)\(([^)]*)\)", source):
        call_body = match.group(2)
        for arg in re.split(r",", call_body):
            arg = arg.strip()
            var_name = arg.split("=")[-1].strip()
            assert var_name not in forbidden_names, (
                f"log call passes forbidden variable name: {arg!r}"
            )


@pytest.mark.asyncio
async def test_full_mint_cycle_never_logs_the_token_value(credentials, caplog):
    from warren.logging import configure_logging

    configure_logging()

    minted_token = "ghs_super_secret_value"

    with respx.mock(assert_all_called=True) as mock:
        mock.post(_token_url()).mock(
            return_value=httpx.Response(201, json=_mint_response(token=minted_token))
        )
        with caplog.at_level("INFO"):
            result = await credentials.token()

    assert result == minted_token
    for record in caplog.records:
        assert minted_token not in record.getMessage()


# --- Audit T2/T4 -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_token_refuses_to_mint_with_empty_allowed_repos(key_path):
    """T2: with no scoping, a minted token carries the installation's FULL access
    (every repo it's installed on) -- and any authenticated non-admin user can
    trigger a clone via their own user-scoped project. token() must fail closed
    rather than silently minting an unscoped token."""
    credentials = GitHubAppCredentials(
        app_id=APP_ID,
        private_key_path=key_path,
        installation_id=INSTALLATION_ID,
        api_base=API_BASE,
        allowed_repos=[],
    )
    with respx.mock(assert_all_called=False) as mock:
        route = mock.post(_token_url())
        with pytest.raises(GitHubAuthError, match="github_app_allowed_repos"):
            await credentials.token()
    assert not route.called


@pytest.mark.asyncio
async def test_token_mint_request_scopes_repositories_field(credentials):
    """T2: the mint request must narrow the token via GitHub's own `repositories`
    field — enforced by GitHub itself, not just warren's own logic."""
    captured = {}

    def _handler(request: httpx.Request) -> httpx.Response:
        import json as _json

        captured["body"] = _json.loads(request.content)
        return httpx.Response(201, json=_mint_response())

    with respx.mock(assert_all_called=True) as mock:
        mock.post(_token_url()).mock(side_effect=_handler)
        await credentials.token()

    assert captured["body"] == {"repositories": ["warren"]}


@pytest.mark.asyncio
async def test_private_key_permissive_mode_refused(key_path, caplog):
    """T4/V5: the module docstring claims the key is '0600 permissions' but nothing
    ever checked that -- a group/world-readable key grants full GitHub App
    impersonation to any other local user/process that can read it, so this must
    fail closed (and log a warning), not just warn and mint anyway."""
    import os
    import stat

    os.chmod(key_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IROTH)  # 0644

    credentials = GitHubAppCredentials(
        app_id=APP_ID,
        private_key_path=key_path,
        installation_id=INSTALLATION_ID,
        api_base=API_BASE,
        allowed_repos=["warren"],
    )

    with respx.mock(assert_all_called=False) as mock:
        mock.post(_token_url()).mock(return_value=httpx.Response(201, json=_mint_response()))
        with caplog.at_level("WARNING"), pytest.raises(GitHubAuthError, match="group/world-accessible"):
            await credentials.token()

    assert not mock.calls.called
    assert any(
        "github_app_private_key_permissive_mode" in record.getMessage()
        for record in caplog.records
    )
