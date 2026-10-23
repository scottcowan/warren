"""Local-mode `warren workspaces` subcommands.

`list_local` scans ``~/.warren/workspaces/*/state.json`` and prints one row per
workspace. It never talks to a warren-server — state.json is written by the
local NsjailRuntime (D-19).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import structlog
import typer

from .. import ui

log = structlog.get_logger(__name__)


_ACTIVE_STATUSES = {"running", "provisioning"}


def _state_json_for(ws_dir: Path, real_home: Path) -> Path:
    """Locate a workspace's state.json for display purposes: seatbelt/bwrap/
    nsjail all keep it under ``~/.warren/state/<id>/`` (audit finding #1 —
    root_path is sandbox-writable, so state.json can't live there); only
    docker has no such state.json at all, and workspaces provisioned before
    the state-dir fix fall back to the (untrusted) in-root copy. This is a
    read-only listing path — `connect_local`/`exec_local` below go through
    `_load_workspace_state`, which migrates the untrusted copy instead of
    just reading it.
    """
    out_of_tree = real_home / ".warren" / "state" / ws_dir.name / "state.json"
    if out_of_tree.is_file():
        return out_of_tree
    return ws_dir / "state.json"


def list_local(show_all: bool = False) -> None:
    """Scan ``~/.warren/workspaces/`` and print one row per state.json found.

    By default only shows active workspaces (running/provisioning).
    Pass show_all=True to include stopped/failed.

    Missing state.json → silently skipped (workspace mid-destroy).
    Invalid JSON → logs a warning and skips (partial write survived a crash).
    """
    import os as _os; _wh = Path(_os.environ.get("REAL_HOME", str(Path.home()))); root = _wh / ".warren" / "workspaces"
    if not root.is_dir():
        return

    rows: list[tuple[str, str, str, str, str]] = []
    for sub in sorted(root.iterdir()):
        if not sub.is_dir():
            continue
        state_file = _state_json_for(sub, _wh)
        if not state_file.is_file():
            continue
        try:
            data = json.loads(state_file.read_text())
        except (json.JSONDecodeError, OSError):
            log.warning("state_json_invalid", dir=str(sub))
            continue

        # Local workspaces don't have an explicit status field — they're
        # considered active if the directory exists (they were connect-mode).
        # Filter by runtime_type presence as a proxy for "was provisioned".
        workspace_id = str(data.get("workspace_id", sub.name))
        project = str(data.get("project", ""))
        intent = str(data.get("intent", ""))
        app_name = str(data.get("app", ""))
        created = ui.relative_time(data.get("created_at"))
        rows.append((workspace_id[:8], project, intent, app_name, created))

    if not rows:
        return

    ui.print_table(("ID", "PROJECT", "TEMPLATE", "APP", "CREATED"), rows)


def load_local_workspaces() -> list[dict]:
    """Return list of workspace state dicts from ~/.warren/workspaces/."""
    import os as _os; _wh = Path(_os.environ.get("REAL_HOME", str(Path.home()))); root = _wh / ".warren" / "workspaces"
    if not root.is_dir():
        return []
    results = []
    for sub in sorted(root.iterdir()):
        if not sub.is_dir():
            continue
        state_file = _state_json_for(sub, _wh)
        if not state_file.is_file():
            continue
        try:
            data = json.loads(state_file.read_text())
            data["_dir"] = str(sub)
            results.append(data)
        except (json.JSONDecodeError, OSError):
            continue
    return results


def pick_workspace(prompt: str = "Select workspace") -> str:
    """Interactive picker — returns workspace_id of selected workspace."""
    workspaces = load_local_workspaces()
    if not workspaces:
        ui.error("No local workspaces.")
        raise typer.Exit(1)

    choices = []
    for ws in workspaces:
        wid = str(ws.get("workspace_id", ""))
        project = ws.get("project", "")
        intent = ws.get("intent", "")
        created = ui.relative_time(ws.get("created_at"))
        choices.append((f"{wid[:8]}  {project}/{intent}  {created}", wid))

    return ui.arrow_select(f"{prompt}:", choices, non_tty_hint="pass the workspace ID argument")


def resolve_local_workspace_dir(root: Path, workspace_id: str) -> Path:
    """Map a workspace id (or unique prefix) to its directory directly under
    `root`. The id must be a single safe component and the match a real,
    non-symlinked directory whose parent is exactly `root`; exits otherwise."""
    from warren_common.paths import PathEscapeError, validate_workspace_id, workspace_child  # noqa: PLC0415

    try:
        validate_workspace_id(workspace_id)
    except PathEscapeError as e:
        ui.error(str(e))
        raise typer.Exit(1) from e
    ws_dir = root / workspace_id
    if not (ws_dir.is_dir() or ws_dir.is_symlink()):
        matches = [
            d for d in root.iterdir()
            if d.name.startswith(workspace_id) and (d.is_dir() or d.is_symlink())
        ]
        if len(matches) == 0:
            ui.error(f"workspace {workspace_id!r} not found")
            raise typer.Exit(1)
        if len(matches) > 1:
            ui.error(f"ambiguous workspace id {workspace_id!r}: {[m.name for m in matches]}")
            raise typer.Exit(1)
        ws_dir = matches[0]
    try:
        ws_dir = workspace_child(root, ws_dir.name)
    except PathEscapeError as e:
        ui.error(f"refusing workspace {workspace_id!r}: {e}")
        raise typer.Exit(1) from e
    if not ws_dir.is_dir():
        ui.error(f"workspace {workspace_id!r} not found")
        raise typer.Exit(1)
    return ws_dir


def _load_workspace_state(workspace_id: str) -> dict:
    """Resolve a workspace ID (or prefix) to its state dict.

    Scans ~/.warren/workspaces/, prefix-matches on the first 8 characters,
    loads state.json, infers runtime_type from on-disk artefacts, and returns
    the merged state dict ready for dispatch._connect_via_execvp or
    dispatch._exec_in_sandbox.
    """
    import os as _os
    _wh = Path(_os.environ.get("REAL_HOME", str(Path.home())))
    root = _wh / ".warren" / "workspaces"
    if not root.is_dir():
        ui.error(f"no local workspaces found under {root}")
        raise typer.Exit(1)

    ws_dir = resolve_local_workspace_dir(root, workspace_id)

    # seatbelt/bwrap/nsjail keep sandbox.sb/state.json OUTSIDE the workspace
    # root, under ~/.warren/state/<id>/ (audit finding #1: root_path is
    # writable from inside the sandbox itself, so a profile/state.json stored
    # there could be rewritten by the sandboxed process and trusted on THIS
    # next connect — the exact attack this function exists to prevent). Check
    # there first; only docker has no such out-of-tree state at all.
    from warren_common.paths import PathEscapeError, ensure_private_dir  # noqa: PLC0415

    proper_state_dir = _wh / ".warren" / "state" / ws_dir.name
    try:
        ensure_private_dir(proper_state_dir)
    except PathEscapeError as e:
        ui.error(f"refusing workspace state dir: {e}")
        raise typer.Exit(1) from e
    using_legacy_root_state = not (proper_state_dir / "state.json").is_file()
    state_dir = ws_dir if using_legacy_root_state else proper_state_dir

    state_path = state_dir / "state.json"
    if not state_path.is_file():
        ui.error(f"missing state.json at {state_path}")
        raise typer.Exit(1)

    payload = json.loads(state_path.read_text())
    if (state_dir / "sandbox.sb").is_file():
        runtime_type = "seatbelt"
    elif payload.get("runtime_type") == "nsjail" or "cfg_path" in payload:
        # Legacy nsjail state.json carried cfg_path; an in-root nsjail.cfg is
        # workspace-writable and no longer used as a signal (BB3).
        runtime_type = "nsjail"
    elif "container_id" in payload:
        runtime_type = "docker"
    else:
        runtime_type = "bwrap"

    # A workspace provisioned before state moved out of the (sandbox-writable)
    # root has only an untrusted in-root state.json/sandbox.sb. Neither can be
    # validated or regenerated from trusted inputs (the profile is built from
    # the full WorkspaceSpec, which state.json does not persist), so refuse
    # rather than promote possibly tampered bytes into the trusted state dir.
    # Docker's state stays in-root: a container has no host write access to it.
    if using_legacy_root_state and runtime_type != "docker":
        log.warning(
            "workspace_legacy_root_state_refused",
            workspace_id=ws_dir.name,
            runtime_type=runtime_type,
        )
        ui.error(
            f"workspace {ws_dir.name} was created by an older warren that kept its "
            "sandbox state inside the writable workspace root, so it can't be "
            f"trusted. Recreate it: `warren destroy {ws_dir.name}`, then start a "
            "new workspace from the same template."
        )
        raise typer.Exit(1)

    state: dict = {
        **payload,
        "workspace_id": ws_dir.name,
        "runtime_type": runtime_type,
        "app": payload.get("app", "bash"),
        "root_path": payload.get("root_path", str(ws_dir)),
    }
    if runtime_type == "nsjail":
        from warren_common.errors import WorkspaceNeedsRecreate  # noqa: PLC0415
        from warren_common.runtime.nsjail import check_nsjail_state  # noqa: PLC0415

        try:
            check_nsjail_state(payload, state["workspace_id"])
        except WorkspaceNeedsRecreate as e:
            ui.error(str(e))
            raise typer.Exit(1) from e
        state.pop("cfg_path", None)
        state["nsjail_state_dir"] = str(state_dir)
    elif runtime_type == "docker":
        state["container_id"] = payload["container_id"]
    elif runtime_type == "seatbelt":
        state["profile_path"] = str(state_dir / "sandbox.sb")
    elif runtime_type == "bwrap":
        state["bwrap_state_dir"] = str(state_dir)
    return state


def connect_local(workspace_id: str, *, harness: str | None = None, new: bool = False) -> None:
    """Re-attach to a local workspace via execvp."""
    from warren_cli.dispatch import _connect_via_execvp  # noqa: PLC0415
    _connect_via_execvp(_load_workspace_state(workspace_id), harness=harness, new=new)


def exec_local(workspace_id: str, cmd: list[str]) -> int:
    """Run a command non-interactively inside a local workspace; return exit code."""
    from warren_cli.dispatch import _exec_in_sandbox  # noqa: PLC0415
    return _exec_in_sandbox(_load_workspace_state(workspace_id), cmd)
