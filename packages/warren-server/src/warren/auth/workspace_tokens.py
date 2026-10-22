"""Workspace-scoped machine tokens (AI9, SEED-008).

A process running inside a workspace (an AG2b supervisor, an AI8 MCP caller,
the AK1 git credential helper) calls back to the control plane with one of
these instead of a human's token. A workspace token:

- names exactly one workspace and only resolves while that workspace exists,
  isn't destroyed and is still owned by the token's user;
- always expires (at most `MAX_TTL_SECONDS`);
- may be bound to an Ed25519 public key, in which case every request must
  carry `X-Warren-Proof: <unix-ts>.<base64url signature>` over
  `"<ts>\\n<METHOD>\\n<path>"`, within `PROOF_WINDOW_SECONDS`;
- reaches only the method/path pairs in `_SCOPED_ROUTES`, all under its own
  `/workspaces/{id}`, plus the control-plane MCP endpoint (whose tools apply the
  same scope). Enforced in AuthMiddleware, so a new route is denied to
  workspace tokens until it is added here.

A reservation token (AI8/AJ2, `POST /workspace-tokens`) is minted before its
workspace exists, for a server-chosen workspace id; it can provision that one
workspace exactly once and then behaves like any other workspace token.
"""

from __future__ import annotations

import base64
import binascii
import re
import secrets
import time
from typing import TYPE_CHECKING

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from warren.auth.tokens import hash_token

if TYPE_CHECKING:
    from warren.auth.models import User, WorkspaceToken
    from warren.auth.store import AuthStore

WORKSPACE_TOKEN_PREFIX = "wrnw_"
DEFAULT_TTL_SECONDS = 900
MAX_TTL_SECONDS = 3600
PROOF_WINDOW_SECONDS = 60
PROOF_HEADER = b"x-warren-proof"

_SCOPED_ROUTES: tuple[tuple[str, str], ...] = (
    ("DELETE", ""),
    ("GET", "/status"),
    ("GET", "/events"),
    ("POST", "/exec"),
    ("POST", "/git/pull"),
    ("GET", "/git-credential"),
    ("GET", "/refs"),
)

_WORKSPACE_PATH_RE = re.compile(r"^/workspaces/([^/]+)(/.*)?$")

MCP_PATH = "/mcp"

# AI8/AJ2: a completed single-turn workspace's token may only read its verdict and
# make the (idempotent) destroy call.
_COMPLETED_ROUTES: tuple[tuple[str, str], ...] = (
    ("DELETE", ""),
    ("GET", "/status"),
    ("GET", "/events"),
)


def generate_workspace_token() -> str:
    return f"{WORKSPACE_TOKEN_PREFIX}{secrets.token_urlsafe(32)}"


def is_workspace_token(token: str) -> bool:
    return token.startswith(WORKSPACE_TOKEN_PREFIX)


def scoped_route_allowed(
    method: str, path: str, workspace_id: str, routes: tuple[tuple[str, str], ...] = _SCOPED_ROUTES
) -> bool:
    match = _WORKSPACE_PATH_RE.match(path)
    if match is None or match.group(1) != workspace_id:
        return False
    suffix = (match.group(2) or "").rstrip("/")
    return (method.upper(), suffix) in routes


def scoped_request_allowed(method: str, path: str, token: "WorkspaceToken") -> bool:
    """AI8: the MCP endpoint (tools re-check scope per call); an unprovisioned
    reservation may only POST /workspaces; a completed workspace is read-only."""
    if path.rstrip("/") == MCP_PATH:
        return True
    if token.workspace_status is None:
        return token.provision_grant and method.upper() == "POST" and path.rstrip("/") == "/workspaces"
    if token.workspace_status == "destroyed":
        return scoped_route_allowed(method, path, token.workspace_id, _COMPLETED_ROUTES)
    return scoped_route_allowed(method, path, token.workspace_id)


def parse_public_key(encoded: str) -> Ed25519PublicKey:
    try:
        raw = base64.b64decode(encoded, validate=True)
        return Ed25519PublicKey.from_public_bytes(raw)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("public_key must be a base64 raw 32-byte Ed25519 public key") from exc


def proof_message(ts: int, method: str, path: str) -> bytes:
    return f"{ts}\n{method.upper()}\n{path}".encode()


def verify_proof(
    public_key_b64: str, proof: str | None, method: str, path: str, *, now: float | None = None
) -> bool:
    if not proof:
        return False
    ts_str, _, sig_b64 = proof.partition(".")
    try:
        ts = int(ts_str)
        sig = base64.urlsafe_b64decode(sig_b64 + "=" * (-len(sig_b64) % 4))
        key = parse_public_key(public_key_b64)
    except (ValueError, binascii.Error):
        return False
    current = time.time() if now is None else now
    if abs(current - ts) > PROOF_WINDOW_SECONDS:
        return False
    try:
        key.verify(sig, proof_message(ts, method, path))
    except InvalidSignature:
        return False
    return True


async def resolve_workspace_token(
    store: "AuthStore", token: str, pepper: str
) -> "tuple[User, WorkspaceToken] | None":
    if not is_workspace_token(token):
        return None
    return await store.get_active_workspace_token(hash_token(token, pepper))
