"""warren remote — manage remote warren-server instances, with an optional bearer token
for servers that enforce the built-in per-user auth provider (Phase 2)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional

import typer

from .. import ui
from ..config import (
    WarrenCLIConfig,
    is_insecure_http_url,
    read_config_toml,
    write_config_toml,
)

remote_app = typer.Typer(
    no_args_is_help=True,
    help="Manage remote warren-server instances.",
)

_NAME_RE = re.compile(r"^[a-z0-9_-]+$")


@remote_app.command("add")
def remote_add(
    name: str = typer.Argument(help="Remote name (e.g. node2)"),
    url: Optional[str] = typer.Argument(
        None, help="Server URL (e.g. http://node2:8080) — omit when using --ssh-host"
    ),
    token: Optional[str] = typer.Option(
        None,
        "--token",
        help=(
            "Bearer token, for a server with auth enforcement enabled. Omit entirely for a "
            "server with no auth. Pass '-' to be prompted for the token with hidden input "
            "(recommended over passing it directly -- a token passed on the command line "
            "lands in shell history and is visible to other users via `ps`); a literal "
            "token value is still accepted for scripting/CI use."
        ),
    ),
    ssh_host: Optional[str] = typer.Option(
        None, "--ssh-host",
        help=(
            "SSH host (an ssh config Host alias, or user@ip) to tunnel the control plane "
            "through — for a podman/docker server whose control plane is loopback-only on "
            "its own host (the normal deployment shape). warren establishes "
            "`ssh -L <port>:localhost:8420 <ssh-host>` itself before every call instead of "
            "you running that by hand first."
        ),
    ),
    ssh_key: Optional[str] = typer.Option(
        None, "--ssh-key", help="SSH private key path, passed to `ssh -i` (only with --ssh-host)"
    ),
    ssh_remote_port: int = typer.Option(
        8420, "--ssh-remote-port", help="Control plane port on the far side of the SSH tunnel"
    ),
    ecs_cluster: Optional[str] = typer.Option(
        None, "--ecs-cluster",
        help="ECS cluster name — makes this an ECS remote (no direct network path; "
        "warren reaches it via an SSM port-forward into the orchestrator task). "
        "Requires --ecs-service and --aws-audience.",
    ),
    ecs_service: Optional[str] = typer.Option(
        None, "--ecs-service", help="ECS service name (only with --ecs-cluster)"
    ),
    aws_audience: Optional[str] = typer.Option(
        None, "--aws-audience",
        help="The ECS server's own settings.server_id (shown by `warren healthz` as "
        "warren_id) — binds the signed GetCallerIdentity request's X-Warren-Audience "
        "header. Required for an ECS remote.",
    ),
    config: Optional[Path] = typer.Option(None, "--config", help="Config file path"),
) -> None:
    """Register a remote warren-server instance.

    Give a directly-reachable URL, --ssh-host for a server whose control plane is
    loopback-only (warren tunnels to it itself on every call — no need to hand-run
    `ssh -L` first), or --ecs-cluster/--ecs-service/--aws-audience for a server only
    reachable via an SSM port-forward into its own ECS task.
    """
    if not _NAME_RE.match(name):
        ui.error(f"Invalid remote name {name!r}: must match ^[a-z0-9_-]+$")
        raise typer.Exit(1)
    if ecs_cluster or ecs_service:
        if not (ecs_cluster and ecs_service):
            ui.error("--ecs-cluster and --ecs-service must be given together.")
            raise typer.Exit(1)
        if not aws_audience:
            ui.error("--aws-audience is required with --ecs-cluster/--ecs-service.")
            raise typer.Exit(1)
        if url or ssh_host:
            ui.error("--ecs-cluster can't be combined with a URL or --ssh-host.")
            raise typer.Exit(1)
    elif not url and not ssh_host:
        ui.error("Either a URL, --ssh-host, or --ecs-cluster is required.")
        raise typer.Exit(1)
    config_path = config or Path.home() / ".warren" / "config.toml"
    if not config_path.exists():
        ui.error(f"No config found at {config_path}. Run 'warren init' first.")
        raise typer.Exit(1)

    if token == "-":
        token = typer.prompt("Bearer token", hide_input=True)

    if url and token is not None and is_insecure_http_url(url):
        ui.warn(
            f"{url!r} is plaintext http:// and not localhost -- the bearer token will be "
            "readable by anyone on the network path. Prefer an https:// URL if this server "
            "supports one."
        )

    data = read_config_toml(config_path)
    remotes = data.setdefault("remotes", {})
    if name in remotes:
        ui.error(f"Remote '{name}' already exists. Edit {config_path} to update it.")
        raise typer.Exit(1)

    entry: dict = {}
    if ecs_cluster:
        entry["runtime_type"] = "ecs"
        entry["ecs_cluster"] = ecs_cluster
        entry["ecs_service"] = ecs_service
        entry["aws_audience"] = aws_audience
    elif ssh_host:
        entry["runtime_type"] = "ssh"
        entry["ssh_host"] = ssh_host
        if ssh_key:
            entry["ssh_key_path"] = ssh_key
        if ssh_remote_port != 8420:
            entry["ssh_remote_port"] = ssh_remote_port
    else:
        entry["url"] = url
    if token is not None:
        entry["auth_token"] = token
    remotes[name] = entry
    write_config_toml(config_path, data)
    label = f"ecs:{ecs_cluster}/{ecs_service}" if ecs_cluster else (ssh_host if ssh_host else url)
    ui.ok(f"Remote '{name}' added ({label}).")


@remote_app.command("list")
def remote_list(
    output_json: bool = typer.Option(False, "--json", help="Output remotes as a JSON array."),
    config: Optional[Path] = typer.Option(None, "--config", help="Config file path"),
) -> None:
    """List all configured remote warren-server instances."""
    config_path = config or Path.home() / ".warren" / "config.toml"
    if not config_path.exists():
        if output_json:
            typer.echo("[]")
            return
        ui.error("No config found. Run 'warren init' first.")
        raise typer.Exit(1)
    cfg = WarrenCLIConfig.load(config_path)

    def _target(profile) -> str:
        if profile.runtime_type == "ssh":
            return f"ssh://{profile.ssh_host} -> :{profile.ssh_remote_port}"
        if profile.runtime_type == "ecs":
            return f"ecs:{profile.ecs_cluster}/{profile.ecs_service}"
        return profile.url or ""

    if output_json:
        typer.echo(json.dumps([
            {
                "name": remote_name,
                "runtime_type": profile.runtime_type,
                "target": _target(profile),
                "authed": profile.auth_token is not None,
            }
            for remote_name, profile in cfg.remotes.items()
        ]))
        return

    if not cfg.remotes:
        typer.echo("No remotes configured. Run 'warren remote add' to register one.")
        return
    rows = [
        (remote_name, _target(profile), "(authed)" if profile.auth_token is not None else "(no auth)")
        for remote_name, profile in cfg.remotes.items()
    ]
    ui.print_table(("NAME", "TARGET", "AUTH"), rows)


@remote_app.command("remove")
def remote_remove(
    name: str = typer.Argument(help="Remote name to remove"),
    config: Optional[Path] = typer.Option(None, "--config", help="Config file path"),
) -> None:
    """Remove a remote warren-server instance from config."""
    config_path = config or Path.home() / ".warren" / "config.toml"
    if not config_path.exists():
        ui.error(f"No config found at {config_path}.")
        raise typer.Exit(1)
    data = read_config_toml(config_path)
    remotes = data.get("remotes", {})
    if name not in remotes:
        ui.error(f"Remote '{name}' not found in {config_path}.")
        raise typer.Exit(1)
    del remotes[name]
    write_config_toml(config_path, data)
    ui.ok(f"Remote '{name}' removed.")
