"""`warren doctor --verify-intent`: a canary that provisions a throwaway local
workspace, checks that every path the template marks read-only really refuses
a write from inside the sandbox, and destroys the workspace again (AH9)."""

from __future__ import annotations

import asyncio
from typing import Any

import typer

# rc 0: write succeeded (violation), 1: write refused, 2: path missing (inconclusive).
# A relative path is resolved against the sandbox's $HOME (the workspace root).
_CANARY_SCRIPT = (
    'd="$1"; [ "${d#/}" = "$d" ] && d="$HOME/$d"; [ -d "$d" ] || exit 2; '
    'f="$d/.warren-verify-intent-$$"; '
    'if ( : > "$f" ) 2>/dev/null; then rm -f "$f"; exit 0; fi; exit 1'
)


def readonly_targets(template_cfg: Any) -> list[str]:
    targets = [f.mount for f in template_cfg.effective_folders() if f.readonly]
    targets += [m.container for m in template_cfg.mounts if m.mode == "ro"]
    return list(dict.fromkeys(targets))


def _destroy(state: dict, cfg: Any) -> None:
    from warren_cli import dispatch  # noqa: PLC0415
    from warren_cli.main import workspaces_destroy  # noqa: PLC0415
    from warren_common.runtime.base import WorkspaceHandle  # noqa: PLC0415

    if state.get("runtime_type") == "docker" and state.get("container_id"):
        handle = WorkspaceHandle(
            workspace_id=state["workspace_id"], runtime_id=state["container_id"],
            root_path=state.get("root_path", ""),
        )
        try:
            asyncio.run(dispatch.get_runtime(cfg).destroy(handle))
        except Exception as exc:
            typer.echo(f"  warning: could not remove container {state['container_id'][:12]}: {exc}", err=True)
    workspaces_destroy(workspace_id=state["workspace_id"], server=None, config=None)


def verify_intent(spec: str, cfg: Any) -> int:
    """Return 0 if every read-only path refused the write, 1 otherwise."""
    from warren_cli import dispatch  # noqa: PLC0415
    from warren_cli.machine_config import load_project  # noqa: PLC0415
    from warren_common import list_template_paths, resolve_template  # noqa: PLC0415
    from warren_common.errors import TemplateNotFoundError  # noqa: PLC0415

    project, _, template = spec.partition("/")
    if not project or not template:
        typer.echo("--verify-intent expects PROJECT/TEMPLATE, e.g. myproject/observe", err=True)
        return 1
    projects_dir = cfg.projects_path()
    project_cfg = load_project(project, projects_dir)
    try:
        template_cfg = resolve_template(project_cfg, template)
    except TemplateNotFoundError:
        typer.echo(f"template {template!r} not found (available: {list_template_paths(project_cfg)})", err=True)
        return 1

    targets = readonly_targets(template_cfg)
    typer.echo(f"verify-intent {project}/{template}:")
    if not targets:
        typer.echo("  nothing marked read-only (folders.readonly / mounts mode: ro); nothing to verify")
        return 0

    state = dispatch.provision_local(project, template, projects_dir, cfg=cfg, connect=False)
    failures = 0
    try:
        for target in targets:
            rc = dispatch._exec_in_sandbox(state, ["/bin/sh", "-c", _CANARY_SCRIPT, "sh", target])
            if rc == 1:
                typer.echo(f"  ✓ {target}: write refused")
            elif rc == 0:
                failures += 1
                typer.echo(f"  ✗ {target}: WRITE SUCCEEDED, template says read-only")
            else:
                failures += 1
                typer.echo(f"  ✗ {target}: not present in the workspace (rc={rc}), cannot verify")
    finally:
        _destroy(state, cfg)
    typer.echo("  canary workspace destroyed")
    return 1 if failures else 0
