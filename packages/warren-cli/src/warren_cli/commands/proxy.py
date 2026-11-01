"""warren proxy — stable loopback addresses for ports inside workspaces (see warren_cli.proxy)."""

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
        "Stable 127.0.0.1 addresses for ports inside workspaces, started on demand: over SSM "
        "for ECS, over SSH (or directly, for a local server) for podman/docker "
        "(e.g. a `t3 serve` for the T3 Code app). See docs/proxy.md."
    ),
)


def _load_cfg(config: Optional[Path]) -> WarrenCLIConfig:
    try:
        return WarrenCLIConfig.load(config)
    except FileNotFoundError as e:
        ui.error(str(e))
        raise typer.Exit(1) from e


def _pick_server(cfg: WarrenCLIConfig, server: Optional[str]) -> str:
    """--server, else [defaults] server if the proxy can reach it, else the only remote
    it can reach (ecs, ssh, or an http remote on this machine's loopback)."""
    if server:
        return server
    capable = sorted(name for name, r in cfg.remotes.items() if core.proxy_capable(r))
    default = cfg.defaults.server
    if default and default in capable:
        return default
    if len(capable) == 1:
        return capable[0]
    if not capable:
        ui.error(
            "no remotes warren proxy can reach: it needs an ecs or ssh remote, or an http remote on "
            "this machine's loopback (add one with `warren remote add`)"
        )
    else:
        ui.error(f"more than one remote warren proxy can reach ({', '.join(capable)}): pass --server")
    raise typer.Exit(1)


def _declared_ports(cfg: WarrenCLIConfig, server: str, workspace: str) -> dict[str, int]:
    """The workspace's template `ports` ({name: port}), read from the control plane."""
    ws = core.match_workspace(asyncio.run(core.fetch_workspaces(cfg, server)), workspace)
    return core.declared_ports(ws)


@proxy_app.command("add")
def proxy_add(
    workspace: str = typer.Argument(help="Workspace ID (or a prefix unique on that server)"),
    remote_port: Optional[str] = typer.Argument(
        None, help="Port inside the workspace: a number, or a port name the workspace's template declares"
    ),
    from_template: bool = typer.Option(
        False, "--from-template", help="Map every port the workspace's template declares under `ports:`"
    ),
    local_port: Optional[int] = typer.Option(
        None, "--local-port", help="Local port to use (default: the first free one from [proxy] port_base)"
    ),
    server: Optional[str] = typer.Option(
        None, "--server", help="Remote profile (default: [defaults] server, else the only ecs/ssh/local one)"
    ),
    config: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Record a mapping and print its stable local address.

    With a port number nothing connects to the server here; a port name or
    --from-template reads the workspace's declared ports from the control plane.
    `warren proxy run` starts the forward (SSM for ECS, SSH for an ssh remote,
    none for a local server) the first time something connects to the address.
    On podman/docker only template-declared ports are published. Re-running is
    safe: existing mappings keep their address.
    """
    if from_template and remote_port is not None:
        ui.error("pass a port or --from-template, not both")
        raise typer.Exit(2)
    if not from_template and remote_port is None:
        ui.error("pass a port (number or declared name), or --from-template")
        raise typer.Exit(2)
    if from_template and local_port is not None:
        ui.error("--local-port maps one port; it can't be combined with --from-template")
        raise typer.Exit(2)
    cfg = _load_cfg(config)
    server = _pick_server(cfg, server)
    store = core.MappingStore()
    wanted: list[tuple[int, Optional[str]]]
    try:
        core.remote_for(cfg, server)
        if remote_port is not None and remote_port.isdigit():
            wanted = [(int(remote_port), None)]
        else:
            declared = _declared_ports(cfg, server, workspace)
            if from_template:
                if not declared:
                    raise core.ProxyError(
                        f"workspace {workspace!r} declares no ports (add `ports:` to its template, "
                        "or map a port number)"
                    )
                wanted = [(port, name) for name, port in sorted(declared.items())]
            elif remote_port in declared:
                wanted = [(declared[remote_port], remote_port)]
            else:
                known = ", ".join(sorted(declared)) or "none"
                raise core.ProxyError(
                    f"workspace {workspace!r} declares no port named {remote_port!r} (declared: {known})"
                )
        results = [
            store.add(server, workspace, port, local_port=local_port, name=name, port_base=cfg.proxy.port_base)
            for port, name in wanted
        ]
    except core.ProxyError as exc:
        ui.error(str(exc))
        raise typer.Exit(1) from exc
    for mapping, created in results:
        verb = "added" if created else "already mapped"
        typer.echo(f"{mapping.label} {verb}: {mapping.address}")
    if any(created for _, created in results):
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
        suffix = f" (port {m.remote_port})" if m.name else ""
        typer.echo(f"{m.address:<24} -> {m.label}{suffix}")


@proxy_app.command("rm")
def proxy_rm(
    selector: str = typer.Argument(
        help="Local port, <workspace>, <workspace>:<remote-port> or <workspace>/<port-name>"
    ),
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
    daemon = core.ProxyDaemon(store, core.ControlPlaneResolver(cfg), core.RuntimeForwarder(), settings)

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
