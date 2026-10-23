"""`python -m warren` — starts uvicorn on the FastAPI app (D-16).

`--dry-run` runs the lifespan startup sequence (settings, preflight, DB open,
runtime + registry construction) and exits 0 without binding to a port. Set
`WARREN_DRY_RUN_SKIP_PREFLIGHT=1` to bypass the Podman socket check when the
host has no rootless socket (e.g. CI).
"""

from __future__ import annotations

import argparse
import asyncio
import os
import sys

import structlog
import uvicorn

from warren.logging import configure_logging

log = structlog.get_logger(__name__)


async def _dry_run() -> None:
    from warren.config import WarrenSettings
    from warren.paths import db_path
    from warren.preflight import run_preflight
    from warren.registry.registry import WorkspaceRegistry
    from warren.registry.store import WorkspaceStore, open_db
    from warren.runtime.podman import PodmanRuntime

    settings = WarrenSettings()

    if not os.environ.get("WARREN_DRY_RUN_SKIP_PREFLIGHT"):
        await run_preflight(settings.podman_socket)

    db = await open_db(db_path(settings))
    try:
        runtime = PodmanRuntime(
            socket_path=settings.podman_socket,
            server_id=settings.server_id,
        )
        store = WorkspaceStore(db)
        WorkspaceRegistry(runtime=runtime, store=store, server_id=settings.server_id)
        log.info("dry-run ok", server_id=settings.server_id)
    finally:
        await db.close()


async def _recover_admin(username: str | None, reenable: bool) -> int:
    """Mint a fresh admin token directly against the DB (audit #44) -- the recovery path
    for a deployment that has lost its only working admin token. Requires the same
    process-level access (WARREN_SECRET_KEY, the data dir) as running the server itself."""
    from warren.auth.recover import (
        AmbiguousAdminError,
        NoAdminFoundError,
        TargetAdminDisabledError,
        recover_admin_token,
    )
    from warren.auth.store import AuthStore
    from warren.config import WarrenSettings
    from warren.paths import db_path

    settings = WarrenSettings()
    store = await AuthStore.open(db_path(settings))
    try:
        try:
            user, token, raw_token = await recover_admin_token(
                store, settings, username=username, reenable=reenable
            )
        except (NoAdminFoundError, AmbiguousAdminError, TargetAdminDisabledError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    finally:
        await store.close()

    verb = "Re-enabled and recovered" if reenable else "Recovered"
    print(f"{verb} admin token for user {user.username!r} ({user.user_id}):")
    print(raw_token)
    print("This token is shown once and is not recoverable -- store it now.")
    return 0


def main() -> None:
    parser = argparse.ArgumentParser(prog="python -m warren")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run lifespan startup and exit 0 without binding a port.",
    )
    parser.add_argument(
        "--recover-admin",
        action="store_true",
        help=(
            "Mint a fresh token for an existing admin user directly against the DB and "
            "exit (audit #44 recovery path -- use when the last working admin token is "
            "lost; requires --username when more than one admin exists)."
        ),
    )
    parser.add_argument(
        "--username",
        default=None,
        help="Admin username to target with --recover-admin (required if there's more than one).",
    )
    parser.add_argument(
        "--reenable",
        action="store_true",
        help=(
            "With --recover-admin: also clear the target admin's disabled_at if they're "
            "disabled. Without this, recovering a token for a disabled admin is refused "
            "-- the token would never authenticate, so minting one anyway would silently "
            "leave you just as locked out (audit R9/S9)."
        ),
    )
    args = parser.parse_args()

    # `configure_logging()` installs `redact_secrets` as the first processor
    # and renders exceptions as plain KeyValueRenderer text. Nothing called it
    # before this fix -- structlog silently ran on its own built-in default
    # config the whole time, which auto-detects `rich` (pulled in transitively
    # via the `typer` dependency, never actually imported by this package) and
    # renders any `exc_info=True` call as a Rich traceback with `show_locals`
    # -- printing full secret values (e.g. an SSH private key passed to
    # GitManager) in plaintext to container logs, completely bypassing
    # redact_secrets. Must run before `warren.app` (and everything it imports)
    # gets loaded, so no logger caches the unconfigured default first.
    configure_logging()

    if args.dry_run:
        asyncio.run(_dry_run())
        return

    if args.recover_admin:
        exit_code = asyncio.run(_recover_admin(args.username, args.reenable))
        raise SystemExit(exit_code)

    uvicorn.run("warren.app:app", log_level="info", **_listen_kwargs())


def _listen_kwargs() -> dict:
    from pydantic import ValidationError

    from warren.config import BindSettings

    try:
        bind = BindSettings()
    except ValidationError as exc:
        print(f"error: {exc.errors()[0]['msg']}", file=sys.stderr)
        raise SystemExit(2) from None
    if not bind.is_loopback and not bind.tls_enabled:
        log.warning(
            "insecure_http_listener",
            host=bind.host,
            port=bind.port,
            detail="serving cleartext HTTP on a non-loopback address (WARREN_ALLOW_INSECURE_HTTP=1); "
            "bearer tokens are exposed to anything that can reach this port",
        )
    kwargs: dict = {"host": bind.host, "port": bind.port}
    if bind.tls_enabled:
        kwargs |= {"ssl_certfile": str(bind.tls_certfile), "ssl_keyfile": str(bind.tls_keyfile)}
    return kwargs


if __name__ == "__main__":
    main()
