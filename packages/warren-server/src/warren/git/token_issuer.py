"""Control-plane GitHub token issuer for workspaces (AK1).

Same contract as the local CLI issuer (warren_common.github_tokens): a
workspace's git credential helper asks `GET /workspaces/{id}/git-credential`
with an AI9 workspace-scoped token, and gets an installation token narrowed to
that workspace's template repos. Required for ECS, `kind: agent` and any
workspace that may outlive the user's connection.

The App private key is read from Secrets Manager or SSM (or, for a single-host
podman deployment, a 0600 file), and is meant to be readable only by the
control-plane role -- never by a workspace task role, whose credentials the
agent can read (AD1). It is held in memory for at most `_KEY_CACHE_SECONDS`.

Separate from `github_app.py`'s clone credentials: those carry the
deployment-wide clone allow-list and never reach a workspace.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from warren_common.github_tokens import GitHubAppMinter, TokenIssuerError, workspace_credential_files

_KEY_CACHE_SECONDS = 300.0


class SecretsManagerKeySource:
    def __init__(self, secret_id: str, client: Any = None) -> None:
        self.secret_id = secret_id
        self._client = client

    def __call__(self) -> bytes:
        client = self._client
        if client is None:
            import boto3  # noqa: PLC0415

            client = boto3.client("secretsmanager")
        try:
            return client.get_secret_value(SecretId=self.secret_id)["SecretString"].encode()
        except Exception as exc:
            raise TokenIssuerError("cannot read the GitHub App key from Secrets Manager") from exc


class SsmKeySource:
    def __init__(self, name: str, client: Any = None) -> None:
        self.name = name
        self._client = client

    def __call__(self) -> bytes:
        client = self._client
        if client is None:
            import boto3  # noqa: PLC0415

            client = boto3.client("ssm")
        try:
            resp = client.get_parameter(Name=self.name, WithDecryption=True)
            return resp["Parameter"]["Value"].encode()
        except Exception as exc:
            raise TokenIssuerError("cannot read the GitHub App key from SSM") from exc


class FileKeySource:
    def __init__(self, path: Path) -> None:
        self.path = path

    def __call__(self) -> bytes:
        try:
            if self.path.stat().st_mode & 0o077:
                raise TokenIssuerError(
                    f"GitHub App key at {self.path} is group/world-accessible; chmod 600 it"
                )
            return self.path.read_bytes()
        except OSError as exc:
            raise TokenIssuerError(f"cannot read GitHub App key at {self.path}") from exc


class CachedKey:
    def __init__(self, source: Callable[[], bytes], clock: Callable[[], float] = time.monotonic) -> None:
        self._source = source
        self._clock = clock
        self._cached: tuple[bytes, float] | None = None
        self._lock = threading.Lock()

    def __call__(self) -> bytes:
        with self._lock:
            if self._cached is not None and self._clock() - self._cached[1] < _KEY_CACHE_SECONDS:
                return self._cached[0]
            key = self._source()
            self._cached = (key, self._clock())
            return key


def key_source_from_settings(settings: Any) -> Callable[[], bytes] | None:
    kind = settings.github_workspace_token_key_source
    if kind == "secretsmanager":
        return SecretsManagerKeySource(settings.github_workspace_token_key_id)
    if kind == "ssm":
        return SsmKeySource(settings.github_workspace_token_key_id)
    if kind == "file" and settings.github_app_private_key_path is not None:
        return FileKeySource(Path(settings.github_app_private_key_path))
    return None


def control_plane_credential_files(
    control_plane_url: str, workspace_id: str, workspace_token: str
) -> dict[str, tuple[str, int]]:
    """Hook point for server-side materialization (ECS git-init container, PR #29;
    podman): the files to write into the workspace home so its credential helper
    asks this control plane with an AI9 workspace token. Pair with
    `git_credential_env(<home>/HELPER_RELPATH)` in the workspace container's env.
    Not wired yet; the token needs re-minting before its 1h expiry."""
    url = f"{control_plane_url.rstrip('/')}/workspaces/{workspace_id}/git-credential"
    return workspace_credential_files(url, workspace_token)


def control_plane_issuer(settings: Any, **minter_kwargs: Any) -> GitHubAppMinter | None:
    """None (endpoint answers 503) unless both the App id and a key source are configured."""
    source = key_source_from_settings(settings)
    if source is None or not settings.github_app_id:
        return None
    return GitHubAppMinter(
        settings.github_app_id,
        CachedKey(source),
        api_base=settings.github_api_base,
        **minter_kwargs,
    )
