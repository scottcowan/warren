"""warren proxy — stable loopback addresses for ports inside ECS workspaces (see warren_cli.proxy)."""

from __future__ import annotations

import asyncio
import json
import logging
import signal
from pathlib import Path
from typing import Optional

import structlog
import typer

from .. import proxy as core
from .. import ui
from ..config import WarrenCLIConfig

proxy_app = typer.Typer(
    no_args_is_help=True,
    help=(
        "Stable 127.0.0.1 addresses for ports inside ECS workspaces, started on demand "
        "over SSM (e.g. a `t3 serve` for the T3 Code app). See docs/proxy.md."
    ),
)


def _load_cfg(config: Optional[Path]) -> WarrenCLIConfig:
    try:
        return WarrenCLIConfig.load(config)
    except FileNotFoundError as e:
        ui.error(str(e))
        raise typer.Exit(1) from e


def _pick_server(cfg: WarrenCLIConfig, server: Optional[str]) -> str:
    if server:
        return server
    ecs = sorted(name for name, r in cfg.remotes.items() if r.runtime_type == "ecs")
    if len(ecs) == 1:
        return ecs[0]
    if not ecs:
        ui.error("no ECS remotes configured — warren proxy only reaches ECS workspaces (add one with `warren remote add`)")
    else:
        ui.error(f"more than one ECS remote ({', '.join(ecs)}): pass --server")
    raise typer.Exit(1)


@proxy_app.command("add")
def proxy_add(
    workspace: str = typer.Argument(help="Workspace ID (or a prefix unique on that server)"),
    remote_port: int = typer.Argument(help="Port inside the workspace"),
    local_port: Optional[int] = typer.Option(
        None, "--local-port", help="Local port to use (default: the first free one from [proxy] port_base)"
    ),
    server: Optional[str] = typer.Option(None, "--server", help="ECS remote profile (default: the only one)"),
    config: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Record a mapping and print its stable local address.

    Nothing connects to AWS here; `warren proxy run` starts the SSM session the
    first time something connects to the address.
    """
    cfg = _load_cfg(config)
    server = _pick_server(cfg, server)
    try:
        core.remote_for(cfg, server)
        mapping, created = core.MappingStore().add(
            server, workspace, remote_port, local_port=local_port, port_base=cfg.proxy.port_base
        )
    except core.ProxyError as exc:
        ui.error(str(exc))
        raise typer.Exit(1) from exc
    verb = "added" if created else "already mapped"
    typer.echo(f"{mapping.label} {verb}: {mapping.address}")
    if created:
        typer.echo("Serve it with `warren proxy run` (picks up new mappings while running).", err=True)


@proxy_app.command("list")
def proxy_list(output_json: bool = typer.Option(False, "--json", help="Print JSON")) -> None:
    """List saved mappings."""
    try:
        mappings = core.MappingStore().load()
    except core.ProxyError as exc:
        ui.error(str(exc))
        raise typer.Exit(1) from exc
    if output_json:
        typer.echo(json.dumps([{**m.__dict__, "address": m.address} for m in mappings], indent=2))
        return
    if not mappings:
        typer.echo("no mappings — add one with `warren proxy add <workspace> <port>`")
        return
    for m in sorted(mappings, key=lambda m: m.local_port):
        typer.echo(f"{m.address:<24} -> {m.label}")


@proxy_app.command("rm")
def proxy_rm(
    selector: str = typer.Argument(help="Local port, <workspace>, or <workspace>:<remote-port>"),
    server: Optional[str] = typer.Option(None, "--server", help="Only mappings on this remote"),
) -> None:
    """Remove mappings (a running proxy stops serving them within a few seconds)."""
    try:
        removed = core.MappingStore().remove(selector, server=server)
    except core.ProxyError as exc:
        ui.error(str(exc))
        raise typer.Exit(1) from exc
    if not removed:
        ui.error(f"no mapping matches {selector!r}")
        raise typer.Exit(1)
    for m in removed:
        typer.echo(f"removed {m.label} ({m.address})")


@proxy_app.command("run")
def proxy_run(
    config: Optional[Path] = typer.Option(None, "--config"),
    idle_minutes: Optional[float] = typer.Option(
        None, "--idle-minutes", min=0, help="Stop a session after this long with no connections (0 = never) [proxy] idle_minutes"
    ),
    keepalive_seconds: Optional[float] = typer.Option(
        None, "--keepalive-seconds", min=0, help="Probe interval while clients are connected (0 = off) [proxy] keepalive_seconds"
    ),
    bind: str = typer.Option(core.LOOPBACK_HOST, "--bind", help="Loopback address to listen on"),
    log_level: str = typer.Option("info", "--log-level", help="debug, info, warning or error"),
) -> None:
    """Serve every mapping in the foreground until interrupted (run it under
    launchd or systemd to keep it up; see docs/proxy.md)."""
    level = getattr(logging, log_level.upper(), None)
    if not isinstance(level, int):
        ui.error(f"unknown --log-level {log_level!r}")
        raise typer.Exit(2)
    # Only the level: the processors/renderer stay as main._configure_logging set them.
    structlog.configure(wrapper_class=structlog.make_filtering_bound_logger(level))
    cfg = _load_cfg(config)
    settings = core.ProxySettings(
        idle_minutes=cfg.proxy.idle_minutes if idle_minutes is None else idle_minutes,
        keepalive_seconds=cfg.proxy.keepalive_seconds if keepalive_seconds is None else keepalive_seconds,
        bind=bind,
    )
    store = core.MappingStore()
    try:
        core.check_loopback(bind)
        if not store.load():
            ui.error("no mappings — add one with `warren proxy add <workspace> <port>`")
            raise typer.Exit(1)
    except core.ProxyError as exc:
        ui.error(str(exc))
        raise typer.Exit(1) from exc
    daemon = core.ProxyDaemon(store, core.ControlPlaneResolver(cfg), core.SsmForwarder(), settings)

    async def _main() -> None:
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, stop.set)
            except (NotImplementedError, RuntimeError):  # Windows: Ctrl-C raises KeyboardInterrupt instead
                pass

        def _started() -> None:
            if not daemon.proxies:
                ui.error("could not listen on any mapping's port (see the log above)")
                stop.set()

        await daemon.run(stop, started=_started)

    try:
        asyncio.run(_main())
    except KeyboardInterrupt:
        pass
