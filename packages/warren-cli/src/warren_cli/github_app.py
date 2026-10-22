"""Local CLI GitHub token issuer and its credentials endpoint (AK1).

For local workspaces (seatbelt/bwrap/nsjail) the CLI is the issuer: it reads the
GitHub App private key from the OS credential store on demand and mints
installation tokens narrowed to the template's repos. A small HTTP server on
127.0.0.1, run as a detached `python -m warren_cli.github_app` process (the CLI
itself execs into the sandbox on connect), answers the workspace's credential
helper. Each workspace gets its own random bearer; only its SHA-256 is kept,
in the workspace's out-of-tree state dir, next to the repos it was granted.

For a team deployment the control plane is the only key holder: leave
`[github_app]` out of the CLI config and the local issuer is never used.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import time
from collections.abc import Callable, Mapping
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

import httpx
from warren_common import winsupport
from warren_common.github_tokens import (
    GitHubAppMinter,
    GitHubGrant,
    TokenIssuer,
    TokenIssuerError,
    git_credential_response,
    grant_for_path,
    write_endpoint,
    write_workspace_credential_files,
)
from warren_common.fileperms import restrict_to_owner
from warren_common.runtime.sandbox_env import state_root as default_state_root

from warren_cli.config import GitHubAppSection
from warren_cli.credential_store import CredentialStore, default_credential_store

REGISTRATION_FILE = "github-credentials.json"
ENDPOINT_STATE_FILE = "credentials-endpoint.json"
_WORKSPACE_ID_RE = re.compile(r"^[A-Za-z0-9-]{1,64}$")
_SPAWN_WAIT_SECONDS = 5.0


def local_issuer(
    section: GitHubAppSection, store: CredentialStore | None = None, **minter_kwargs
) -> GitHubAppMinter:
    def _key() -> bytes:
        value = (store or default_credential_store()).get(section.key_service, section.app_id)
        if value is None:
            raise TokenIssuerError(
                "GitHub App private key not found in the OS credential store; "
                "run `warren github-app set-key`"
            )
        return value

    return GitHubAppMinter(
        section.app_id,
        _key,
        installations=section.installations,
        api_base=section.api_base,
        **minter_kwargs,
    )


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _registration_path(state_root: Path, workspace_id: str) -> Path:
    if not _WORKSPACE_ID_RE.match(workspace_id):
        raise ValueError(f"invalid workspace id {workspace_id!r}")
    return state_root / workspace_id / REGISTRATION_FILE


def register_workspace(
    workspace_id: str, grants: Mapping[str, GitHubGrant], state_root: Path
) -> str:
    bearer = secrets.token_urlsafe(32)
    path = _registration_path(state_root, workspace_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    restrict_to_owner(path.parent, directory=True)
    data = {"bearer_sha256": _sha256(bearer), "grants": [g.to_json() for g in grants.values()]}
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(data))
    restrict_to_owner(tmp)
    tmp.replace(path)
    return bearer


def _load_registration(state_root: Path, workspace_id: str) -> dict | None:
    try:
        return json.loads(_registration_path(state_root, workspace_id).read_text())
    except (OSError, ValueError):
        return None


class CredentialsServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, issuer: TokenIssuer, state_root: Path) -> None:
        super().__init__(address, _CredentialsHandler)
        self.issuer = issuer
        self.state_root = state_root


class _CredentialsHandler(BaseHTTPRequestHandler):
    server: CredentialsServer

    def log_message(self, format, *args) -> None:  # noqa: A002
        return

    def _reply(self, status: int, body: str) -> None:
        payload = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        url = urlsplit(self.path)
        if url.path == "/healthz":
            self._reply(200, "ok\n")
            return
        match = re.match(r"^/git-credential/([^/]+)$", url.path)
        if match is None:
            self._reply(404, "not found\n")
            return
        workspace_id = match.group(1)
        try:
            registration = _load_registration(self.server.state_root, workspace_id)
        except ValueError:
            registration = None
        auth = self.headers.get("Authorization", "")
        scheme, _, bearer = auth.partition(" ")
        if (
            registration is None
            or scheme.lower() != "bearer"
            or not hmac.compare_digest(_sha256(bearer), registration["bearer_sha256"])
        ):
            self._reply(401, "unauthorized\n")
            return
        query = parse_qs(url.query)
        grants = {g["owner"]: GitHubGrant.from_json(g) for g in registration["grants"]}
        grant = grant_for_path(grants, (query.get("path") or [""])[0])
        if grant is None:
            self._reply(403, "repository not granted to this workspace\n")
            return
        try:
            issued = self.server.issuer.issue(grant)
        except TokenIssuerError as exc:
            self._reply(502, f"{exc}\n")
            return
        if (query.get("format") or ["git"])[0] == "token":
            self._reply(200, issued.token)
        else:
            self._reply(200, git_credential_response(issued))


def serve(issuer: TokenIssuer, state_root: Path, port: int = 0) -> CredentialsServer:
    return CredentialsServer(("127.0.0.1", port), issuer, state_root)


def _pid_alive(pid: int) -> bool:
    if winsupport.is_windows():
        return winsupport.windows_pid_alive(pid)
    try:
        os.kill(pid, 0)
    except (OSError, ProcessLookupError):
        return False
    return True


def _healthy(port: int) -> bool:
    try:
        return httpx.get(f"http://127.0.0.1:{port}/healthz", timeout=1.0).status_code == 200
    except httpx.HTTPError:
        return False


def _running_port(state_root: Path) -> int | None:
    try:
        data = json.loads((state_root / ENDPOINT_STATE_FILE).read_text())
    except (OSError, ValueError):
        return None
    pid, port = data.get("pid"), data.get("port")
    if isinstance(pid, int) and isinstance(port, int) and _pid_alive(pid) and _healthy(port):
        return port
    return None


def ensure_local_endpoint(
    state_root: Path | None = None,
    *,
    spawn: Callable[..., object] = subprocess.Popen,
    wait_seconds: float = _SPAWN_WAIT_SECONDS,
) -> int:
    root = state_root or default_state_root()
    port = _running_port(root)
    if port is not None:
        return port
    root.mkdir(parents=True, exist_ok=True)
    log = open(root / "credentials-endpoint.log", "ab")  # noqa: SIM115
    spawn(
        [sys.executable, "-m", "warren_cli.github_app", "--state-root", str(root)],
        stdin=subprocess.DEVNULL,
        stdout=log,
        stderr=log,
        start_new_session=True,
        close_fds=True,
    )
    deadline = time.monotonic() + wait_seconds
    while time.monotonic() < deadline:
        port = _running_port(root)
        if port is not None:
            return port
        time.sleep(0.1)
    raise TokenIssuerError("local GitHub credentials endpoint did not start")


def endpoint_url(port: int, workspace_id: str) -> str:
    return f"http://127.0.0.1:{port}/git-credential/{workspace_id}"


def setup_workspace_git_credentials(
    workspace_id: str,
    workspace_root: Path,
    grants: Mapping[str, GitHubGrant],
    *,
    port: int,
    state_root: Path | None = None,
) -> dict[str, str]:
    """Register the workspace with the local endpoint and install its helper
    files; returns env (paths only) to add to the workspace."""
    bearer = register_workspace(workspace_id, grants, state_root or default_state_root())
    env = write_workspace_credential_files(workspace_root, endpoint_url(port, workspace_id), bearer)
    bin_dir = workspace_root / ".warren" / "bin"
    env["PATH"] = f"{bin_dir}{os.pathsep}{os.environ.get('PATH', '/usr/bin:/bin')}"
    return env


def refresh_workspace_endpoint(
    workspace_id: str, workspace_root: Path, *, state_root: Path | None = None
) -> bool:
    """On connect: restart the endpoint if needed and point the workspace at its
    current port. No-op for a workspace that never registered."""
    root = state_root or default_state_root()
    if _load_registration(root, workspace_id) is None:
        return False
    port = ensure_local_endpoint(root)
    write_endpoint(workspace_root, endpoint_url(port, workspace_id))
    return True


def _main(argv: list[str]) -> int:
    import argparse  # noqa: PLC0415

    from warren_cli.config import WarrenCLIConfig  # noqa: PLC0415

    parser = argparse.ArgumentParser(prog="warren-credentials-endpoint")
    parser.add_argument("--state-root", type=Path, default=None)
    args = parser.parse_args(argv)
    cfg = WarrenCLIConfig.load()
    if cfg.github_app is None:
        print("no [github_app] section in the warren CLI config", file=sys.stderr)
        return 1
    root = args.state_root or default_state_root()
    server = serve(local_issuer(cfg.github_app), root)
    state = root / ENDPOINT_STATE_FILE
    tmp = state.with_name(state.name + ".tmp")
    tmp.write_text(json.dumps({"pid": os.getpid(), "port": server.server_address[1]}))
    restrict_to_owner(tmp)
    tmp.replace(state)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
