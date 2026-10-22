"""GitHub App installation tokens for workspaces (AK1): one contract, two issuers.

The workspace side never changes: a git credential helper (and a `gh` wrapper)
inside the workspace asks a local HTTP endpoint for a token, authenticated with
a per-workspace bearer. Which `TokenIssuer` answers depends on the workspace:

- the local CLI issuer (warren_cli.github_app), key in the OS credential store,
  for local sandboxes and interactive sessions;
- the control-plane issuer (warren.git.token_issuer), key in Secrets Manager /
  SSM, for server, ECS and `kind: agent` workspaces.

Both mint with `GitHubAppMinter`: `POST /app/installations/{id}/access_tokens`
with `repositories` = the template's repos for one owner and `permissions` =
contents + pull_requests, `write` only when the template has a writable
git-worktree folder for that owner. GitHub caps installation tokens at 1 hour.

The token never goes into a remote URL, `.git/config`, the environment or a
task definition: the helper prints it to git over a pipe, and the `gh` wrapper
sets GH_TOKEN only on the `gh` process it execs.
"""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    import httpx

    from .models import FolderSpec

GITHUB_HOST = "github.com"
DEFAULT_API_BASE = "https://api.github.com"
TOKEN_TTL_SECONDS = 3600
_REMINT_MARGIN_SECONDS = 300

_HTTPS_RE = re.compile(r"^https://(?:[^@/]+@)?github\.com/([^/]+)/([^/]+?)(?:\.git)?/?$")
_SSH_RE = re.compile(r"^(?:ssh://)?git@github\.com[:/]([^/]+)/([^/]+?)(?:\.git)?/?$")
_PATH_RE = re.compile(r"^/?([^/]+)/([^/]+?)(?:\.git)?/?$")


class TokenIssuerError(Exception):
    """Every issuer failure (key unavailable, GitHub exchange failed, repo not granted)."""


@dataclass(frozen=True)
class GitHubGrant:
    owner: str
    repositories: tuple[str, ...]
    permissions: Mapping[str, str] = field(hash=False)

    @property
    def writes(self) -> bool:
        return self.permissions.get("contents") == "write"

    def to_json(self) -> dict:
        return {
            "owner": self.owner,
            "repositories": list(self.repositories),
            "permissions": dict(self.permissions),
        }

    @classmethod
    def from_json(cls, data: Mapping) -> "GitHubGrant":
        return cls(
            owner=str(data["owner"]),
            repositories=tuple(str(r) for r in data["repositories"]),
            permissions=dict(data["permissions"]),
        )


@dataclass(frozen=True)
class IssuedToken:
    token: str = field(repr=False)
    expires_at: float
    grant: GitHubGrant


class TokenIssuer(Protocol):
    def issue(self, grant: GitHubGrant) -> IssuedToken: ...


def parse_github_repo(url: str | None) -> tuple[str, str] | None:
    """(owner, repo) for a github.com https/ssh URL, else None."""
    if not url:
        return None
    for pattern in (_HTTPS_RE, _SSH_RE):
        match = pattern.match(url.strip())
        if match:
            return match.group(1), match.group(2)
    return None


def github_grants_for(folders: Iterable["FolderSpec"]) -> dict[str, GitHubGrant]:
    """One grant per GitHub owner across a template's git folders.

    A folder pushes when it's a `git-worktree` that isn't `readonly`; a
    `git-clone` reference is read-only.
    """
    repos: dict[str, list[str]] = {}
    writes: dict[str, bool] = {}
    for folder in folders:
        if folder.type not in ("git-worktree", "git-clone"):
            continue
        parsed = parse_github_repo(folder.url)
        if parsed is None:
            continue
        owner, repo = parsed
        owner_repos = repos.setdefault(owner, [])
        if repo not in owner_repos:
            owner_repos.append(repo)
        pushes = folder.type == "git-worktree" and not folder.readonly
        writes[owner] = writes.get(owner, False) or pushes
    grants = {}
    for owner, names in repos.items():
        level = "write" if writes[owner] else "read"
        grants[owner] = GitHubGrant(
            owner=owner,
            repositories=tuple(sorted(names)),
            permissions={"contents": level, "pull_requests": level},
        )
    return grants


def grant_for_path(grants: Mapping[str, GitHubGrant], path: str | None) -> GitHubGrant | None:
    """The grant that covers `owner/repo(.git)`, or None if the repo isn't granted.

    With no path (e.g. `gh` outside a checkout) the only grant is returned if
    there's exactly one.
    """
    if not path:
        return next(iter(grants.values())) if len(grants) == 1 else None
    match = _PATH_RE.match(path.strip())
    if match is None:
        return None
    owner, repo = match.group(1), match.group(2)
    grant = grants.get(owner)
    if grant is None or repo not in grant.repositories:
        return None
    return grant


def git_credential_response(token: IssuedToken) -> str:
    return f"username=x-access-token\npassword={token.token}\n"


def _parse_expiry(expires_at: str | None, now: float) -> float:
    if not expires_at:
        return now + TOKEN_TTL_SECONDS
    try:
        return datetime.fromisoformat(expires_at.replace("Z", "+00:00")).timestamp()
    except ValueError:
        return now + TOKEN_TTL_SECONDS


class GitHubAppMinter:
    """Mints installation tokens narrowed to a grant; the issuer contract's shared core.

    `private_key` is called only when a mint is needed and its bytes are never
    stored on the instance. Minted tokens are cached in memory per grant until
    five minutes before expiry.
    """

    def __init__(
        self,
        app_id: str,
        private_key: Callable[[], bytes],
        *,
        installations: Mapping[str, str] | None = None,
        api_base: str = DEFAULT_API_BASE,
        transport: "httpx.BaseTransport | None" = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        if not app_id:
            raise TokenIssuerError("github app id is not configured")
        self.app_id = app_id
        self._private_key = private_key
        self._installations = dict(installations or {})
        self.api_base = api_base.rstrip("/")
        self._transport = transport
        self._clock = clock
        self._cache: dict[tuple, IssuedToken] = {}
        self._lock = threading.Lock()

    def _jwt(self) -> str:
        import jwt  # noqa: PLC0415

        try:
            key = self._private_key()
        except TokenIssuerError:
            raise
        except Exception as exc:
            raise TokenIssuerError("github app private key unavailable") from exc
        now = int(self._clock())
        try:
            return jwt.encode(
                {"iat": now - 60, "exp": now + 540, "iss": self.app_id}, key, algorithm="RS256"
            )
        except Exception as exc:
            raise TokenIssuerError("failed to sign github app jwt") from exc

    def _client(self) -> "httpx.Client":
        import httpx  # noqa: PLC0415

        return httpx.Client(transport=self._transport, timeout=20.0)

    def _headers(self, signed: str) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {signed}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _installation_id(self, client: "httpx.Client", signed: str, grant: GitHubGrant) -> str:
        if grant.owner in self._installations:
            return self._installations[grant.owner]
        repo = grant.repositories[0]
        resp = client.get(
            f"{self.api_base}/repos/{grant.owner}/{repo}/installation", headers=self._headers(signed)
        )
        if resp.status_code != 200:
            raise TokenIssuerError(
                f"github app is not installed for {grant.owner}/{repo} (HTTP {resp.status_code})"
            )
        installation_id = str(resp.json()["id"])
        self._installations[grant.owner] = installation_id
        return installation_id

    def issue(self, grant: GitHubGrant) -> IssuedToken:
        if not grant.repositories:
            raise TokenIssuerError("refusing to mint a token with no repositories")
        cache_key = (grant.owner, grant.repositories, tuple(sorted(grant.permissions.items())))
        with self._lock:
            cached = self._cache.get(cache_key)
            if cached is not None and cached.expires_at - self._clock() > _REMINT_MARGIN_SECONDS:
                return cached
            signed = self._jwt()
            import httpx  # noqa: PLC0415

            try:
                with self._client() as client:
                    installation_id = self._installation_id(client, signed, grant)
                    resp = client.post(
                        f"{self.api_base}/app/installations/{installation_id}/access_tokens",
                        headers=self._headers(signed),
                        json={
                            "repositories": list(grant.repositories),
                            "permissions": dict(grant.permissions),
                        },
                    )
            except httpx.HTTPError as exc:
                raise TokenIssuerError("github installation-token exchange failed") from exc
            if resp.status_code != 201:
                raise TokenIssuerError(
                    f"github installation-token exchange failed (HTTP {resp.status_code})"
                )
            try:
                payload = resp.json()
                token = payload["token"]
            except (ValueError, KeyError) as exc:
                raise TokenIssuerError("malformed github installation-token response") from exc
            issued = IssuedToken(
                token=token,
                expires_at=_parse_expiry(payload.get("expires_at"), self._clock()),
                grant=grant,
            )
            self._cache[cache_key] = issued
            return issued


# Workspace-side files. Same layout for every issuer: only the endpoint URL and
# the bearer differ (a local CLI endpoint + random bearer, or the control plane's
# /workspaces/{id}/git-credential + an AI9 workspace-scoped token).
WORKSPACE_CREDENTIALS_DIR = ".warren"

CREDENTIAL_HELPER_SCRIPT = """#!/bin/sh
# warren git credential helper (AK1). Holds no token: asks warren's endpoint.
[ "$1" = get ] || exit 0
d="$(cd "$(dirname "$0")/.." && pwd)"
host=""; path=""
while IFS='=' read -r k v; do
  [ -z "$k" ] && break
  case "$k" in host) host="$v" ;; path) path="$v" ;; esac
done
[ "$host" = "github.com" ] || exit 0
exec curl -fsS --max-time 30 -G -H "@$d/credential-auth" \\
  --data-urlencode "path=$path" "$(cat "$d/credential-endpoint")"
"""

GH_WRAPPER_SCRIPT = """#!/bin/sh
# warren gh wrapper (AK1): GH_TOKEN is set for this one gh process only.
self_dir="$(cd "$(dirname "$0")" && pwd)"
d="$(dirname "$self_dir")"
real=""
IFS=:
for p in $PATH; do
  [ "$p" = "$self_dir" ] && continue
  if [ -x "$p/gh" ]; then real="$p/gh"; break; fi
done
unset IFS
[ -n "$real" ] || { echo "warren: gh not found on PATH" >&2; exit 127; }
path=""
remote="$(git remote get-url origin 2>/dev/null || true)"
case "$remote" in
  https://github.com/*) path="${remote#https://github.com/}" ;;
  git@github.com:*) path="${remote#git@github.com:}" ;;
  ssh://git@github.com/*) path="${remote#ssh://git@github.com/}" ;;
esac
GH_TOKEN="$(curl -fsS --max-time 30 -G -H "@$d/credential-auth" \\
  --data-urlencode "path=$path" --data-urlencode "format=token" \\
  "$(cat "$d/credential-endpoint")")" || { echo "warren: no GitHub token for this repo" >&2; exit 1; }
export GH_TOKEN
exec "$real" "$@"
"""


def _write(path: Path, text: str, mode: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text)
    tmp.chmod(mode)
    tmp.replace(path)


def write_endpoint(workspace_root: Path, endpoint_url: str) -> None:
    _write(workspace_root / WORKSPACE_CREDENTIALS_DIR / "credential-endpoint", endpoint_url + "\n", 0o600)


HELPER_RELPATH = f"{WORKSPACE_CREDENTIALS_DIR}/bin/git-credential-warren"


def workspace_credential_files(endpoint_url: str, bearer: str) -> dict[str, tuple[str, int]]:
    """{path relative to the workspace home: (content, mode)} for the helper,
    the gh wrapper, the endpoint URL and the bearer header. Runtimes that
    materialize somewhere other than a local directory (ECS git-init) write
    these themselves."""
    return {
        HELPER_RELPATH: (CREDENTIAL_HELPER_SCRIPT, 0o700),
        f"{WORKSPACE_CREDENTIALS_DIR}/bin/gh": (GH_WRAPPER_SCRIPT, 0o700),
        f"{WORKSPACE_CREDENTIALS_DIR}/credential-auth": (f"Authorization: Bearer {bearer}\n", 0o600),
        f"{WORKSPACE_CREDENTIALS_DIR}/credential-endpoint": (endpoint_url + "\n", 0o600),
    }


def write_workspace_credential_files(
    workspace_root: Path, endpoint_url: str, bearer: str
) -> dict[str, str]:
    """Install `workspace_credential_files` under `workspace_root` and return
    the env that wires git and gh to them. The env carries paths only, never a
    token."""
    for relpath, (content, mode) in workspace_credential_files(endpoint_url, bearer).items():
        _write(workspace_root / relpath, content, mode)
    return git_credential_env(workspace_root / HELPER_RELPATH)


def git_credential_env(helper: Path) -> dict[str, str]:
    """GIT_CONFIG_* entries: reset any inherited github.com helper (e.g. the
    system osxkeychain one), then use warren's, keyed per repo path."""
    key = f"credential.https://{GITHUB_HOST}"
    entries = [(f"{key}.helper", ""), (f"{key}.helper", str(helper)), (f"{key}.useHttpPath", "true")]
    env = {"GIT_CONFIG_COUNT": str(len(entries))}
    for i, (k, v) in enumerate(entries):
        env[f"GIT_CONFIG_KEY_{i}"] = k
        env[f"GIT_CONFIG_VALUE_{i}"] = v
    return env


# Paths a local sandbox must never read: the OS credential store holding the
# GitHub App key (macOS login keychain files, libsecret's keyring dir) and the
# reserved location for a key file. Consumed by the seatbelt profile.
def credential_store_deny_paths(home: Path) -> list[str]:
    return [
        str(home / "Library" / "Keychains"),
        str(home / ".local" / "share" / "keyrings"),
        str(home / ".warren" / "github-app"),
    ]
