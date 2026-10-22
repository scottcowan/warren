"""GitHub App JWT signing and installation-token minting (LIFE-03, D-08).

D-08 requires warren-server to obtain git credentials for private repositories with zero
human interaction after a one-time setup step, on a headless server (node2). A GitHub App's
JWT -> installation-token exchange satisfies this: the App's RSA private key signs a
short-lived (<=10 minute) JWT, which is exchanged for a ~1-hour installation access token.
Unlike OAuth Device Flow (the other option 04-RESEARCH.md considered), no human ever visits
a login page again after the App is installed once — the private key alone is sufficient
for every future mint. D-08 also explicitly declines `warren.secrets`'s encrypted-at-rest
secret store for this credential: the private key lives on node2's filesystem (operator-managed,
0600 permissions) and the minted token lives in this module's memory only, never in the
database, mirroring `registry.py::issue_ssh_credential`'s never-persisted SSH key discipline.

We use PyJWT for RS256 signing rather than hand-rolling the JWT (base64url encoding with
correct padding, and the header/payload/signature concatenation) — 04-RESEARCH.md's "Don't
Hand-Roll" guidance flags both as easy to get subtly wrong, and PyJWT is already a
pinned, human-approved dependency (04-01).

Secret-never-logged discipline (mirrors `ssh_keys.py`, `routes/admin.py::mint_token`,
`registry.py`'s SSH private-key handling): no log call in this module ever receives the
minted token, the signed JWT, or the private key bytes. Only identifiers (installation_id,
expires_at) are logged.
"""

from __future__ import annotations

import asyncio
import time
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

import httpx
import jwt
import structlog

log = structlog.get_logger(__name__)

# Re-mint margin (04-RESEARCH.md Pitfall 3): re-exchange once the cached token has fewer
# than this many seconds of remaining validity, rather than waiting for it to fully expire
# mid-operation.
_REMINT_MARGIN_SECONDS = 300

# Fallback validity window used only when GitHub's response omits `expires_at`.
_DEFAULT_TOKEN_TTL_SECONDS = 3600


class GitHubAuthError(Exception):
    """Raised for every GitHub App credential failure mode.

    Callers never need to catch httpx, PyJWT, or OSError individually — every failure
    from key-reading, JWT signing, or the installation-token exchange surfaces here.
    """


def _now() -> float:
    """Indirection point so tests can monkeypatch the clock without real sleeps."""
    return time.time()


def make_jwt(app_id: str, private_key_pem: bytes, *, now: int | None = None) -> str:
    """Sign a short-lived RS256 JWT identifying this GitHub App.

    `iat` is backdated 60s to tolerate clock skew between this host and GitHub's servers
    (a common JWT pitfall). `exp` is fixed at `iat + 600`, i.e. a hard 660s ceiling, which
    is by construction always within GitHub's enforced 10-minute App-JWT lifetime.
    """
    current = now if now is not None else int(_now())
    payload = {"iat": current - 60, "exp": current + 600, "iss": app_id}
    return jwt.encode(payload, private_key_pem, algorithm="RS256")


def _parse_expiry(expires_at: str | None) -> float:
    """Parse GitHub's `expires_at` ISO-8601 timestamp into an epoch float.

    Falls back to `_now() + _DEFAULT_TOKEN_TTL_SECONDS` if the field is absent or
    unparsable, so a cache-freshness check never crashes on an unexpected response shape.
    """
    if not expires_at:
        return _now() + _DEFAULT_TOKEN_TTL_SECONDS
    try:
        return datetime.fromisoformat(expires_at.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return _now() + _DEFAULT_TOKEN_TTL_SECONDS


class GitHubAppCredentials:
    """Mints and caches a GitHub App installation access token.

    One instance is intended to be held for the lifetime of the process (or per
    installation, if warren-server ever manages more than one). The cache is a plain
    instance attribute, never persisted to disk or the database.
    """

    def __init__(
        self,
        app_id: str,
        private_key_path: Path | None,
        installation_id: str,
        *,
        api_base: str = "https://api.github.com",
        allowed_repos: list[str] | None = None,
    ) -> None:
        self.app_id = app_id
        self.private_key_path = private_key_path
        self.installation_id = installation_id
        self.api_base = api_base
        # Audit T2: with no scoping, a minted token carries the installation's FULL
        # access (every repo it's installed on), and any authenticated non-admin user
        # can trigger a clone of any github.com URL via their own user-scoped project
        # (routes/projects.py has no admin check on that write path) -- handing every
        # user org-wide clone access through this App. Required non-empty: token() fails
        # closed rather than silently minting an unscoped token when this is unset.
        self.allowed_repos = allowed_repos or []
        self._cached: tuple[str, float] | None = None

    @property
    def credential_host(self) -> str:
        """The only host `token()`'s return value may ever be sent to (issue #10).

        For the public default, the API host (`api.github.com`) and the git host
        (`github.com`) differ, so that case is special-cased rather than derived
        from `api_base`. For a GitHub Enterprise Server install, the API and git
        host are the same hostname (only the path differs, `/api/v3`), so
        `api_base`'s own host is correct there.
        """
        if self.api_base == "https://api.github.com":
            return "github.com"
        return urlsplit(self.api_base).hostname or ""

    async def token(self) -> str:
        """Return a valid installation access token, minting or re-minting as needed."""
        if not self.app_id or not self.installation_id or self.private_key_path is None:
            raise GitHubAuthError("github app not configured")
        if not self.allowed_repos:
            # Audit T2: fail closed. Minting with no `repositories` scoping would hand
            # out full installation-wide access to whichever user/project triggered this
            # clone -- see the constructor's allowed_repos docstring note above.
            raise GitHubAuthError(
                "github_app_allowed_repos is empty -- refusing to mint an unscoped "
                "installation token (it would carry access to every repo this App "
                "installation can see). Set WARREN_GITHUB_APP_ALLOWED_REPOS to the "
                "specific repo names this deployment needs."
            )

        if self._cached is not None:
            cached_token, expiry = self._cached
            if expiry - _now() > _REMINT_MARGIN_SECONDS:
                return cached_token

        minted_token, expiry = await self._mint()
        self._cached = (minted_token, expiry)
        return minted_token

    async def _mint(self) -> tuple[str, float]:
        key_path = self.private_key_path
        try:
            key_bytes = await asyncio.to_thread(key_path.read_bytes)
        except OSError as e:
            raise GitHubAuthError(
                f"cannot read GitHub App private key at {key_path}"
            ) from e

        # Audit T4/V5: this module's own header docstring claims the key is "operator-
        # managed, 0600 permissions" but nothing ever checked that -- a key file left
        # group/world-readable grants full GitHub App impersonation to any other local
        # user/process that can read it, the same severity class as the allowed_repos
        # fail-closed check above. A warn-only version of this check shipped first and
        # was itself flagged in review: silently minting anyway defeats the point of
        # checking at all. Fail closed -- an operator with a genuinely permissive mode
        # needs to `chmod 600` the file, not have warren keep using it regardless.
        try:
            mode = (await asyncio.to_thread(key_path.stat)).st_mode & 0o777
        except OSError as e:
            raise GitHubAuthError(
                f"cannot stat GitHub App private key at {key_path}"
            ) from e
        if mode & 0o077:
            log.warning(
                "github_app_private_key_permissive_mode",
                path=str(key_path),
                mode=oct(mode),
            )
            raise GitHubAuthError(
                f"GitHub App private key at {key_path} is group/world-accessible "
                f"(mode {oct(mode)}) -- refusing to use it. Run `chmod 600 {key_path}`."
            )

        try:
            signed_jwt = make_jwt(self.app_id, key_bytes)
        except jwt.PyJWTError as e:
            raise GitHubAuthError("failed to sign GitHub App JWT") from e

        url = f"{self.api_base}/app/installations/{self.installation_id}/access_tokens"
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    url,
                    headers={
                        "Authorization": f"Bearer {signed_jwt}",
                        "Accept": "application/vnd.github+json",
                    },
                    # Audit T2: scope the minted token to only these repos via GitHub's
                    # own `repositories` narrowing — enforced by GitHub itself, not just
                    # warren's own logic, so a bug elsewhere in the clone path can't
                    # widen it back out. `token()` already refuses to call this at all
                    # with an empty allowed_repos.
                    json={"repositories": self.allowed_repos},
                )
                response.raise_for_status()
        except httpx.HTTPError as e:
            raise GitHubAuthError("GitHub installation-token exchange failed") from e

        try:
            payload = response.json()
            minted_token = payload["token"]
        except (ValueError, KeyError) as e:
            raise GitHubAuthError("malformed GitHub installation-token response") from e

        expiry = _parse_expiry(payload.get("expires_at"))
        log.info(
            "github_installation_token_minted",
            installation_id=self.installation_id,
            expires_at=payload.get("expires_at"),
        )
        return minted_token, expiry

    def clone_url(self, repo_url: str, token: str) -> str:
        """Embed an installation token as HTTPS Basic auth in a clone URL.

        The result must never be logged — it carries the live installation token.
        """
        parsed = urlsplit(repo_url)
        netloc = f"x-access-token:{token}@{parsed.netloc}"
        return urlunsplit((parsed.scheme, netloc, parsed.path, parsed.query, parsed.fragment))
