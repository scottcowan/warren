"""Host-side AWS credentials endpoint for `aws.mode: export` (AK3).

Warren runs `aws configure export-credentials` for the template's single
profile on the HOST and serves the result to the workspace over loopback in
the container-credentials format the AWS SDKs/CLI read via
`AWS_CONTAINER_CREDENTIALS_FULL_URI` + `AWS_CONTAINER_AUTHORIZATION_TOKEN`.
The workspace never sees the SSO token cache or any other profile.
"""
from __future__ import annotations

import hmac
import json
import os
import secrets
import shutil
import subprocess
import threading
import time
from collections.abc import Callable
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

REFRESH_MARGIN_SECONDS = 300

# Host AWS config env that must not reach an `export`-mode workspace.
HOST_AWS_ENV = (
    "AWS_PROFILE",
    "AWS_DEFAULT_PROFILE",
    "AWS_CONFIG_FILE",
    "AWS_SHARED_CREDENTIALS_FILE",
    "AWS_SSO_CACHE_DIR",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
)


class CredentialsUnavailable(Exception):
    pass


def _aws_cli() -> str:
    aws = shutil.which("aws")
    if not aws:
        raise CredentialsUnavailable("aws CLI not found on the host")
    return aws


def export_credentials(profile: str, *, run: Callable[..., Any] = subprocess.run) -> dict:
    """Short-lived credentials for `profile`, resolved on the host."""
    r = run(
        [_aws_cli(), "configure", "export-credentials", "--profile", profile, "--format", "process"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    if r.returncode != 0:
        raise CredentialsUnavailable(
            f"could not get credentials for AWS profile {profile!r}; "
            f"run `aws sso login --profile {profile}` on the host"
        )
    try:
        data = json.loads(r.stdout)
    except json.JSONDecodeError as exc:
        raise CredentialsUnavailable("aws configure export-credentials returned invalid JSON") from exc
    if not data.get("AccessKeyId") or not data.get("SecretAccessKey"):
        raise CredentialsUnavailable("aws configure export-credentials returned no credentials")
    return data


def profile_region(profile: str, *, run: Callable[..., Any] = subprocess.run) -> str | None:
    try:
        r = run(
            [_aws_cli(), "configure", "get", "region", "--profile", profile],
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (CredentialsUnavailable, OSError, subprocess.SubprocessError):
        return None
    region = (r.stdout or "").strip()
    return region if r.returncode == 0 and region else None


def _expiry_epoch(expiration: str | None) -> float | None:
    if not expiration:
        return None
    return datetime.fromisoformat(expiration.replace("Z", "+00:00")).timestamp()


class CredentialCache:
    """Caches exported credentials, refetching `margin` seconds before expiry."""

    def __init__(
        self,
        fetch: Callable[[], dict],
        *,
        clock: Callable[[], float] = time.time,
        margin: float = REFRESH_MARGIN_SECONDS,
    ) -> None:
        self._fetch = fetch
        self._clock = clock
        self._margin = margin
        self._lock = threading.Lock()
        self._creds: dict | None = None
        self._expiry: float | None = None

    def get(self) -> dict:
        with self._lock:
            fresh = self._creds is not None and (
                self._expiry is None or self._clock() < self._expiry - self._margin
            )
            if not fresh:
                data = self._fetch()
                self._expiry = _expiry_epoch(data.get("Expiration"))
                self._creds = {
                    "AccessKeyId": data["AccessKeyId"],
                    "SecretAccessKey": data["SecretAccessKey"],
                    "Token": data.get("SessionToken", ""),
                    "Expiration": data.get("Expiration", ""),
                }
            return dict(self._creds)


def make_server(cache: CredentialCache, path: str, token: str) -> ThreadingHTTPServer:
    """Loopback-only server answering GET `path` with `Authorization: <token>`."""

    class _Handler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:  # noqa: N802
            if self.path != path:
                return self._send(404, {"code": "NotFound", "message": "not found"})
            supplied = self.headers.get("Authorization", "")
            if not hmac.compare_digest(supplied.encode(), token.encode()):
                return self._send(403, {"code": "AccessDenied", "message": "bad token"})
            try:
                return self._send(200, cache.get())
            except CredentialsUnavailable as exc:
                return self._send(503, {"code": "CredentialsUnavailable", "message": str(exc)})

        def _send(self, status: int, body: dict) -> None:
            payload = json.dumps(body).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def log_message(self, *_args: Any) -> None:
            return None

    return ThreadingHTTPServer(("127.0.0.1", 0), _Handler)


def start_credentials_endpoint(
    profile: str,
    workspace_id: str,
    *,
    fork: bool = True,
    fetch: Callable[[], dict] | None = None,
) -> dict[str, str]:
    """Start serving `profile`'s credentials and return the workspace env for it.

    With `fork=True` the server runs in a host-side child process that outlives
    the caller's exec into the sandbox and exits once that process is gone.
    Otherwise it runs on a daemon thread of the current process.
    """
    token = secrets.token_urlsafe(32)
    path = f"/creds/{workspace_id}"
    cache = CredentialCache(fetch or (lambda: export_credentials(profile)))
    server = make_server(cache, path, token)
    port = server.server_address[1]

    if fork:
        parent = os.getpid()
        if os.fork() == 0:
            try:
                os.setsid()
                devnull = os.open(os.devnull, os.O_RDWR)
                for fd in (0, 1, 2):
                    os.dup2(devnull, fd)
                threading.Thread(target=server.serve_forever, daemon=True).start()
                while os.getppid() == parent:
                    time.sleep(1)
            finally:
                os._exit(0)
        server.server_close()
    else:
        threading.Thread(target=server.serve_forever, daemon=True).start()

    return {
        "AWS_CONTAINER_CREDENTIALS_FULL_URI": f"http://127.0.0.1:{port}{path}",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN": token,
    }
