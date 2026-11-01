"""warren ssh-config — an ~/.ssh/config Host block for a workspace's sshd (see warren_cli.ssh_access)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Optional

import typer

from .. import proxy as core
from .. import ssh_access, ui
from .proxy import _load_cfg


def _pick_any_server(cfg, server: Optional[str]) -> str:
    if server:
        return server
    if len(cfg.remotes) == 1:
        return next(iter(cfg.remotes))
    if not cfg.remotes:
        ui.error("no remotes configured — add one with `warren remote add`")
    else:
        ui.error(f"more than one remote ({', '.join(sorted(cfg.remotes))}): pass --server")
    raise typer.Exit(1)


def ssh_config(
    workspace: str = typer.Argument(help="Workspace ID (or a prefix unique on that server)"),
    server: Optional[str] = typer.Option(None, "--server", help="Remote profile (default: the only one)"),
    host: Optional[str] = typer.Option(None, "--host", help="Host alias to write (default: warren-<first 8 of the id>)"),
    identity_file: Optional[str] = typer.Option(
        None, "--identity-file", "-i",
        help="ECS: private key to use (its public half must be in SSH_AUTHORIZED_KEYS). "
        "podman/docker: ignored, the server mints the key",
    ),
    user: Optional[str] = typer.Option(
        None, "--user", help="podman/docker: login user (default: the server's shell user, break_glass_user)"
    ),
    jump: Optional[str] = typer.Option(
        None, "--jump",
        help="podman/docker: reach the server host through this ssh destination ('' = connect directly); "
        "default: the remote's ssh_host, nothing for a loopback URL, else the server's advertised host",
    ),
    resolve: bool = typer.Option(
        True, "--resolve/--no-resolve",
        help="Look the workspace up on the control plane to get its full id (--no-resolve: use WORKSPACE as given)",
    ),
    config: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Print an ~/.ssh/config Host block for a workspace's sshd, for VS Code Remote-SSH,
    Cursor or JetBrains Gateway (docs/workspace-ssh.md).

    ECS (warren-ecs-ssh-base): the block's ProxyCommand is `warren proxy stdio <ws> 2222`,
    an SSM port-forward to the sshd on the task's 127.0.0.1:2222.

    podman/docker servers: mints the workspace's SSH key (POST /workspaces/{id}/connect,
    which replaces the previous one), keeps it in ~/.warren/ssh/, and the block reaches
    the port the server publishes on its host's 127.0.0.1, through the server host.

    Either way HostKeyAlias is pinned to the workspace, so its known_hosts entry
    survives restarts. Append the block to ~/.ssh/config.
    """
    cfg = _load_cfg(config)
    server = _pick_any_server(cfg, server)
    try:
        try:
            remote = cfg.get_remote(server)
        except KeyError as exc:
            raise ssh_access.SshAccessError(str(exc.args[0]) if exc.args else str(exc)) from exc
        if remote.runtime_type == "ecs":
            core.remote_for(cfg, server)
            workspace_id = (
                asyncio.run(ssh_access.match_remote_workspace(remote, server, workspace)) if resolve else workspace
            )
            block = ssh_access.render_ssh_config(
                server=server,
                workspace_id=workspace_id,
                host=host,
                identity_file=identity_file,
                config=str(config.expanduser().resolve()) if config else None,
            )
        else:
            if identity_file:
                ui.warn("--identity-file is ignored for podman/docker servers: the server mints the key")

            async def _issue() -> tuple[str, dict]:
                wid = await ssh_access.match_remote_workspace(remote, server, workspace) if resolve else workspace
                return wid, await ssh_access.issue_connection(remote, server, wid)

            workspace_id, connection = asyncio.run(_issue())
            path = ssh_access.key_path(server, workspace_id)
            block = ssh_access.render_podman_ssh_config(
                server=server,
                workspace_id=workspace_id,
                remote=remote,
                connection=connection,
                identity_file=str(path),
                host=host,
                user=user,
                jump=jump,
            )
            # Only once the block is known to be valid: the key is the new (and only) one.
            ssh_access.save_private_key(path, str(connection.get("private_key") or ""))
            typer.echo(f"key for {workspace_id[:8]} saved to {path} (the previous one no longer works)", err=True)
    except (core.ProxyError, ssh_access.SshAccessError) as exc:
        ui.error(str(exc))
        raise typer.Exit(1) from exc
    typer.echo(block, nl=False)
