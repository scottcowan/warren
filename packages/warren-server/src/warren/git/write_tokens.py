"""Scoped, short-lived git write credentials for agent workspaces (`git_write: true`).

A template opts in with `git_write: true` (warren_common.models.ProjectConfig), which
provisioning accepts only when the deployment has a GitHub App issuer configured
(WARREN_GITHUB_APP_ID + WARREN_GITHUB_WORKSPACE_TOKEN_KEY_SOURCE, git/token_issuer.py)
and the runtime can deliver tokens.

Token
    One GitHub App installation token per GitHub owner, minted fresh (never shared
    through the minter's cache) with `repositories` = the template's writable
    github.com `git-worktree` repos for that owner and `permissions` = exactly
    contents:write + pull_requests:write (warren_common.github_tokens.git_write_grants).
    Never administration, workflows or secrets. GitHub caps it at 1 hour.

Delivery
    Launch: with the launch-time secrets, as the `WARREN_GIT_TOKENS` entry
    ("<owner> <token>" lines). ECS/EBS: inside the workspace container's KMS envelope;
    ECS/EFS: in the secrets file on the workspace's volume; podman: a tar written by
    the podman API (put_archive). The entrypoint installs it and unsets it.

    Refresh: REFRESH_MARGIN_SECONDS before the earliest expiry the control plane mints
    a replacement and writes it into the running workspace, then revokes the old one.
    - ECS: the new tokens are sealed into a fresh KMS envelope
      (runtime/ecs_kms_secrets.py, context {workspace_id, container: workspace}) and the
      envelope, not the token, is the argument of the ECS Exec command
      (`warren-git-token install-envelope`). CloudTrail records the ExecuteCommand
      `command`, so it records ciphertext only; reading it needs kms:Decrypt on the
      secrets key under that workspace's context. Nothing is sent over the session's
      stdin, so there's nothing for the TTY to echo, and the in-container helper prints
      only a count, so the ECS Exec session log (CloudWatch) sees no token either.
      The helper runs as root (ECS Exec's user), decrypts with the task role and
      writes the files. Requires WARREN_ECS_SECRETS_KMS_KEY_ID on ECS, EFS too.
    - podman: put_archive again. The tar travels over the podman API socket and isn't
      a command line, so it never appears in `podman exec`/event records.

In the workspace
    /run/warren-git/<owner>, one per owner, mode 0600, uid 1000 (the workspace user),
    in the container's own filesystem (not the volume, so not in EBS snapshots or on
    EFS). /usr/local/bin/git-credential-warren answers github.com https only
    (system gitconfig: credential.https://github.com.helper, useHttpPath). `gh`:
    `GH_TOKEN=$(cat /run/warren-git/<owner>) gh pr create ...`.

Revocation
    On stop and destroy: the files are dropped (best effort, through the same channel)
    and every held token is revoked with DELETE /installation/token. A workspace that
    stopped without going through the registry (crash, reconcile) is revoked by the
    refresh loop when it notices it is no longer running.

Audit
    `git_write_token.mint` / `.refresh` / `.revoke` audit events with workspace id,
    owner, repositories, permissions and expiry. Never the token.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import Callable, Iterable, Mapping
from typing import Any

import structlog
from warren.audit import audit_event
from warren_common.github_tokens import (
    GitHubGrant,
    IssuedToken,
    TokenIssuerError,
    git_write_grants,
)
from warren_common.runtime.base import WorkspaceHandle

log = structlog.get_logger(__name__)

TOKENS_SECRET = "WARREN_GIT_TOKENS"
TOKEN_DIR = "/run/warren-git"
TOKEN_UID = 1000
TOKEN_INSTALLER = "/usr/local/bin/warren-git-token"
# GitHub tokens last 1h; re-mint with 10 minutes left so a slow refresh or one failed
# attempt still lands before expiry.
REFRESH_MARGIN_SECONDS = 600.0
REFRESH_POLL_SECONDS = 60.0
DELIVERY_TIMEOUT_SECONDS = 90.0

_OWNER_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,38}$")
_TOKEN_RE = re.compile(r"^[A-Za-z0-9_]{20,255}$")


class GitWriteError(Exception):
    """A git_write token could not be minted or delivered."""


def encode_tokens(tokens: Mapping[str, str]) -> str:
    """The `WARREN_GIT_TOKENS` payload: one `<owner> <token>` line per owner."""
    lines = []
    for owner, token in sorted(tokens.items()):
        if not _OWNER_RE.fullmatch(owner):
            raise GitWriteError(f"invalid github owner {owner!r}")
        if not _TOKEN_RE.fullmatch(token):
            raise GitWriteError(f"token for {owner} has an unexpected shape")
        lines.append(f"{owner} {token}")
    return "\n".join(lines) + "\n"


def grants_for(folders: Iterable[Any]) -> dict[str, GitHubGrant]:
    return {o: g for o, g in git_write_grants(folders).items() if _OWNER_RE.fullmatch(o)}


def runtime_problem(runtime: Any) -> str:
    """Why `runtime` can't carry git_write tokens, or ""."""
    if not hasattr(runtime, "install_git_tokens"):
        return f"the {type(runtime).__name__} runtime can't deliver git_write tokens"
    check = getattr(runtime, "git_write_problem", None)
    return check() if callable(check) else ""


class GitWriteTokens:
    """Mints, holds, refreshes and revokes each git_write workspace's tokens.

    `minter` is a warren_common.github_tokens.GitHubAppMinter (issue(grant, fresh=True),
    revoke(token)). Held tokens live in memory only; after a server restart a running
    workspace is simply re-minted on the loop's next pass (its old tokens expire
    within the hour)."""

    def __init__(
        self,
        minter: Any,
        *,
        clock: Callable[[], float] = time.time,
        margin: float = REFRESH_MARGIN_SECONDS,
    ) -> None:
        self._minter = minter
        self._clock = clock
        self._margin = margin
        self._held: dict[str, dict[str, IssuedToken]] = {}

    # --- bookkeeping -------------------------------------------------------

    def held(self, workspace_id: str) -> dict[str, IssuedToken]:
        return dict(self._held.get(workspace_id, {}))

    def held_ids(self) -> set[str]:
        return set(self._held)

    def next_refresh_at(self, workspace_id: str) -> float | None:
        held = self._held.get(workspace_id)
        if not held:
            return None
        return min(t.expires_at for t in held.values()) - self._margin

    def due(self, workspace_id: str) -> bool:
        at = self.next_refresh_at(workspace_id)
        return at is None or self._clock() >= at

    # --- minting -----------------------------------------------------------

    async def mint(
        self, workspace_id: str, folders: Iterable[Any], *, owner_id: str | None = None, action: str = "mint"
    ) -> dict[str, IssuedToken]:
        grants = grants_for(folders)
        if not grants:
            raise GitWriteError("git_write needs at least one writable github.com git-worktree folder")
        issued: dict[str, IssuedToken] = {}
        try:
            for owner, grant in grants.items():
                issued[owner] = await asyncio.to_thread(self._minter.issue, grant, fresh=True)
        except TokenIssuerError as exc:
            await self._revoke_tokens(workspace_id, issued, owner_id=owner_id, reason="mint_failed")
            audit_event(
                f"git_write_token.{action}", outcome="failure", owner_id=owner_id,
                workspace_id=workspace_id, error=str(exc),
            )
            raise GitWriteError(str(exc)) from exc
        for owner, tok in issued.items():
            audit_event(
                f"git_write_token.{action}",
                owner_id=owner_id,
                workspace_id=workspace_id,
                github_owner=owner,
                repositories=list(tok.grant.repositories),
                permissions=dict(tok.grant.permissions),
                expires_at=tok.expires_at,
            )
        return issued

    def hold(self, workspace_id: str, issued: Mapping[str, IssuedToken]) -> dict[str, IssuedToken]:
        """Record `issued` as what the workspace now has; returns the superseded tokens."""
        previous = self._held.get(workspace_id, {})
        self._held[workspace_id] = dict(issued)
        return previous

    async def launched(
        self, workspace_id: str, issued: Mapping[str, IssuedToken], *, delivered: bool, owner_id: str | None = None
    ) -> None:
        """After runtime.provision: hold what reached the workspace, revoke what didn't
        (e.g. an ECS launch that adopted an already-running task)."""
        if not issued:
            return
        if not delivered:
            await self._revoke_tokens(workspace_id, issued, owner_id=owner_id, reason="not_delivered")
            return
        superseded = self.hold(workspace_id, issued)
        await self._revoke_tokens(workspace_id, superseded, owner_id=owner_id, reason="superseded")

    async def discard(self, workspace_id: str, issued: Mapping[str, IssuedToken], *, owner_id: str | None = None) -> None:
        await self._revoke_tokens(workspace_id, issued, owner_id=owner_id, reason="launch_failed")

    # --- refresh -----------------------------------------------------------

    async def refresh(
        self,
        workspace_id: str,
        folders: Iterable[Any],
        runtime: Any,
        handle: WorkspaceHandle,
        *,
        owner_id: str | None = None,
    ) -> dict[str, IssuedToken]:
        """Mint replacements, write them into the running workspace, then revoke the old
        ones. A failed delivery revokes the new tokens and keeps the old ones held."""
        issued = await self.mint(workspace_id, folders, owner_id=owner_id, action="refresh")
        plain = {owner: tok.token for owner, tok in issued.items()}
        try:
            await asyncio.wait_for(
                runtime.install_git_tokens(handle, plain), timeout=DELIVERY_TIMEOUT_SECONDS
            )
        except Exception as exc:
            await self._revoke_tokens(workspace_id, issued, owner_id=owner_id, reason="delivery_failed")
            raise GitWriteError(f"cannot deliver git_write tokens: {type(exc).__name__}") from exc
        finally:
            plain.clear()
        superseded = self.hold(workspace_id, issued)
        await self._revoke_tokens(workspace_id, superseded, owner_id=owner_id, reason="superseded")
        return issued

    # --- revocation --------------------------------------------------------

    async def revoke(
        self,
        workspace_id: str,
        *,
        runtime: Any = None,
        handle: WorkspaceHandle | None = None,
        owner_id: str | None = None,
        reason: str = "stopped",
    ) -> None:
        """Drop the workspace's token files (best effort) and revoke everything held."""
        held = self._held.pop(workspace_id, {})
        if runtime is not None and handle is not None and handle.runtime_id and hasattr(runtime, "drop_git_tokens"):
            try:
                await asyncio.wait_for(runtime.drop_git_tokens(handle), timeout=DELIVERY_TIMEOUT_SECONDS)
            except Exception as exc:  # noqa: BLE001
                log.warning("git_write_token_drop_failed", workspace_id=workspace_id, error=type(exc).__name__)
        await self._revoke_tokens(workspace_id, held, owner_id=owner_id, reason=reason)

    async def _revoke_tokens(
        self, workspace_id: str, tokens: Mapping[str, IssuedToken], *, owner_id: str | None, reason: str
    ) -> None:
        for owner, tok in tokens.items():
            try:
                ok = await asyncio.to_thread(self._minter.revoke, tok.token)
                outcome = "success" if ok else "failure"
            except TokenIssuerError:
                outcome = "failure"
            audit_event(
                "git_write_token.revoke",
                outcome=outcome,
                owner_id=owner_id,
                workspace_id=workspace_id,
                github_owner=owner,
                repositories=list(tok.grant.repositories),
                expires_at=tok.expires_at,
                reason=reason,
            )


async def refresh_once(registry: Any, manager: GitWriteTokens) -> None:
    """One pass: refresh due tokens of running git_write workspaces, revoke the tokens
    of workspaces that have reached a terminal or stopped state."""
    from warren.registry.registry import deserialize_spec_extra  # noqa: PLC0415

    alive: set[str] = set()
    for ws in await registry.store.list_non_terminal():
        alive.add(ws.workspace_id)
        extra = deserialize_spec_extra(ws.spec_json)
        if not extra.get("git_write") or ws.status != "running" or not ws.container_id:
            continue
        if not manager.due(ws.workspace_id):
            continue
        lock = await registry._lock_for(ws.workspace_id)
        if lock.locked():
            continue  # a provision/stop/destroy is in flight; next pass
        async with lock:
            current = await registry.store.get(ws.workspace_id)
            if current is None or current.status != "running" or not current.container_id:
                continue
            handle = WorkspaceHandle(
                workspace_id=current.workspace_id, runtime_id=current.container_id, root_path=current.root_path
            )
            try:
                await manager.refresh(
                    current.workspace_id, extra.get("folders", []), registry.runtime, handle,
                    owner_id=current.owner_id,
                )
            except GitWriteError as exc:
                log.warning("git_write_refresh_failed", workspace_id=current.workspace_id, error=str(exc))
    # Stopped, failed or destroyed without passing through registry.stop/destroy.
    for workspace_id in manager.held_ids() - alive:
        await manager.revoke(workspace_id, reason="not_running")


async def run_refresh_loop(registry: Any, manager: GitWriteTokens, *, poll_interval: float = REFRESH_POLL_SECONDS) -> None:
    while True:
        try:
            await refresh_once(registry, manager)
        except asyncio.CancelledError:
            raise
        except Exception:
            log.exception("git_write_refresh_loop_error")
        await asyncio.sleep(poll_interval)
