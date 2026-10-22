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

    ws_dir = root / workspace_id
    if not ws_dir.is_dir():
        matches = [d for d in root.iterdir() if d.is_dir() and d.name.startswith(workspace_id)]
        if len(matches) == 1:
            ws_dir = matches[0]
        elif len(matches) == 0:
            ui.error(f"workspace {workspace_id!r} not found")
            raise typer.Exit(1)
        else:
            ui.error(f"ambiguous workspace id {workspace_id!r}: {[m.name for m in matches]}")
            raise typer.Exit(1)

    # seatbelt/bwrap/nsjail keep sandbox.sb/state.json OUTSIDE the workspace
    # root, under ~/.warren/state/<id>/ (audit finding #1: root_path is
    # writable from inside the sandbox itself, so a profile/state.json stored
    # there could be rewritten by the sandboxed process and trusted on THIS
    # next connect — the exact attack this function exists to prevent). Check
    # there first; only docker has no such out-of-tree state at all.
    proper_state_dir = _wh / ".warren" / "state" / ws_dir.name
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

    # R3 (2026-10-17): a workspace provisioned before state.json moved out of
    # the (sandbox-writable) workspace root must be MIGRATED, not silently
    # read in place — reading the in-root copy and carrying on would defeat
    # finding #1's fix for every workspace that predates it: a sandboxed
    # process could still have rewritten that copy to affect THIS connect.
    #
    # W3 (Round 5 audit, 2026-10-17 -- investigated, NOT fixed, documented as a real
    # structural limitation rather than guessed at): this migration MOVES src -> dest
    # as-is below, including sandbox.sb's actual profile text and state.json's own
    # content -- if a jailed/compromised process already tampered with either while
    # sitting in the writable workspace root (before this migration ever runs), this
    # just launders the tampered bytes into the newly-trusted proper_state_dir, and
    # every call site that reads state_dir afterward (this function's own re-read
    # below, seatbelt.py's exec()/status()) trusts it unconditionally from then on.
    #
    # The fix the audit suggests -- regenerate the profile/state fresh from the
    # original project/template spec instead of moving untrusted bytes -- turns out not
    # to be safely implementable from what's available here:
    #   - build_sbpl_profile() reads spec.folders, spec.ssh_key_paths,
    #     spec.git_store_paths, and spec.bind_mounts, none of which state.json
    #     persists (seatbelt.py's provision() only ever wrote project/intent/app/
    #     root_path/env_snapshot/worktree_paths/reference_paths).
    #   - worktree_paths/reference_paths ARE in state.json, but pulling from them
    #     doesn't help either -- they live in the SAME untrusted, attacker-writable
    #     file being migrated. A tampered state.json could add bogus reference_paths
    #     entries naming arbitrary host paths, and "regenerating" a profile from
    #     that list would just grant read access to whatever the attacker named --
    #     a different elevation (arbitrary host-path disclosure), not the fix.
    # A genuinely safe regeneration needs the full original WorkspaceSpec
    # re-resolved from the project YAML + verified-on-disk paths, independent of
    # anything in the pre-migration file -- the same ingredients a fresh
    # dispatch.py::provision_local() call assembles, but without re-cloning/
    # re-materializing worktrees that already exist on disk for THIS workspace.
    # That's a materially larger rewrite of this migration path than a mechanical
    # "move" -> "rebuild" swap, and risks silently producing a wrong or weaker
    # profile for every existing local workspace if done hastily. Left as an open,
    # tracked gap rather than an unsafe guess.
    # docker's state intentionally stays in-root — a docker container has no
    # host-filesystem write access to it the way seatbelt/nsjail/bwrap do.
    if using_legacy_root_state and runtime_type != "docker":
        import shutil as _shutil

        from warren_common.fileperms import restrict_to_owner

        proper_state_dir.mkdir(parents=True, exist_ok=True)
        try:
            restrict_to_owner(proper_state_dir, directory=True)
        except PermissionError:
            pass
        migrated_names = ["state.json"]
        if runtime_type == "seatbelt":
            migrated_names.append("sandbox.sb")
        for name in migrated_names:
            src = ws_dir / name
            if not src.is_file():
                continue
            dest = proper_state_dir / name
            _shutil.move(str(src), str(dest))
            try:
                restrict_to_owner(dest)
            except PermissionError:
                pass
        log.warning(
            "workspace_state_migrated_from_root",
            workspace_id=ws_dir.name,
            runtime_type=runtime_type,
            dest=str(proper_state_dir),
        )
        ui.warn(
            f"migrated {runtime_type} workspace state out of the writable "
            "workspace root (one-time)"
        )
        state_dir = proper_state_dir
        state_path = state_dir / "state.json"
        payload = json.loads(state_path.read_text())

    state: dict = {
        **payload,
        "workspace_id": payload.get("workspace_id", ws_dir.name),
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
