"""warren CLI — manage AI-agent workspaces on a warren-server."""

from __future__ import annotations

import asyncio
import json
import logging
import sys
from pathlib import Path
from typing import Any, Optional

import click
import httpx
import structlog
import typer

from warren_common import SecretLoader
from warren_common.errors import ProjectNotFoundError
from warren_common.fileperms import restrict_to_owner
from warren_common.logging import redact_processor

from . import dispatch, ui

import os as _os


def _check_not_nested() -> None:
    """Raise a clean error if we're already inside a warren workspace."""
    project = _os.environ.get("WARREN_PROJECT")
    template = _os.environ.get("WARREN_TEMPLATE")
    if project:
        ui.error(
            f"You're already inside a warren workspace "
            f"({project}/{template or '?'}).\n"
            f"   Host-level warren commands don't work from inside a sandbox.\n"
            f"   Exit this workspace first (Ctrl-D or `exit`), then re-run.\n"
        )
        raise typer.Exit(1)
from .client import make_remote_client
from .commands import workspaces as workspaces_local
from .commands.doctor import doctor as _doctor
from .commands.remote import remote_app
from .config import (
    WarrenCLIConfig,
    ServerProfile,
    is_insecure_http_url,
    read_config_toml,
    write_config_toml,
)

_configured = False


class _StderrPrintLogger:
    """A structlog logger that resolves `sys.stderr` at *print* time, not at
    construction time -- `structlog.PrintLogger(file=sys.stderr)` binds the
    actual stream object once, which breaks the moment that object is closed
    and replaced (e.g. `typer.testing.CliRunner`, which opens/closes a fresh
    stderr buffer on every single invocation within the same process)."""

    def _emit(self, message: str, *_a: Any, **_kw: Any) -> None:
        print(message, file=sys.stderr, flush=True)

    debug = info = warning = warn = error = err = critical = fatal = failure = exception = msg = log = _emit


class _StderrPrintLoggerFactory:
    def __call__(self, *_a: Any) -> _StderrPrintLogger:
        return _StderrPrintLogger()


def _configure_logging(verbose: bool = False) -> None:
    """Wire structlog with redact_processor BEFORE any renderer (Pitfall 5).

    Default (no ``-v``): WARNING and above only, printed to stderr -- never
    stdout, which must stay clean for the command's own output/table/--json
    (structlog's own default logger factory prints to stdout, which is what
    let e.g. `dispatching_connect` or loader warnings interrupt a table
    mid-render). Pass ``-v`` for full INFO/DEBUG logging.
    """
    global _configured
    if _configured:
        return
    renderer = (
        structlog.dev.ConsoleRenderer()
        if sys.stderr.isatty()
        else structlog.processors.JSONRenderer()
    )
    level = logging.DEBUG if verbose else logging.WARNING
    structlog.configure(
        processors=[
            structlog.stdlib.add_log_level,
            redact_processor,
            structlog.processors.TimeStamper(fmt="iso"),
            renderer,
        ],
        wrapper_class=structlog.make_filtering_bound_logger(level),
        logger_factory=_StderrPrintLoggerFactory(),
    )
    _configured = True


# stderr, not stdout: keeps a spinner shown while fetching remote data from
# ever corrupting stdout (the actual table, or --json output meant to be piped).
_err_console = ui.stderr

app = typer.Typer(no_args_is_help=True)
secrets_app = typer.Typer(no_args_is_help=True, help="Manage secrets in the warren-server secret store.")
server_app = typer.Typer(no_args_is_help=True, help="Manage warren-server connection profiles.")
project_app = typer.Typer(no_args_is_help=True, help="Manage project definitions.")
app.add_typer(secrets_app, name="secrets")
app.add_typer(server_app, name="server")
app.add_typer(project_app, name="project")
app.add_typer(remote_app, name="remote")
app.command(name="doctor")(_doctor)

# Workspaces are what this CLI is for, so workspace commands (new/destroy/connect/list/
# status/exec/tunnel) live at the top level rather than behind a `workspaces` subcommand —
# unlike secrets/server/project, which are distinct enough nouns to warrant namespacing.

WARREN_DIR = Path.home() / ".warren"
PROJECTS_DIR = WARREN_DIR / "projects"
CONFIG_PATH = WARREN_DIR / "config.toml"


@app.callback()
def _root(
    verbose: bool = typer.Option(
        False, "-v", "--verbose", help="Show full INFO/DEBUG logging (default: warnings and errors only)."
    ),
) -> None:
    """warren — manage AI-agent workspaces on a warren-server."""
    _configure_logging(verbose)


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------

@app.command()
def init(
    config: Optional[Path] = typer.Option(
        None, "--config", help="Override config path (default ~/.warren/config.toml)."
    ),
) -> None:
    """Interactive first-run setup: save server URL and auth token."""
    _check_not_nested()
    config_path = config or Path.home() / ".warren" / "config.toml"
    if config_path.exists():
        typer.echo(f"Config already exists at {config_path}")
        typer.echo("Edit it directly or use 'warren server add' to add a new profile.")
        raise typer.Exit(0)

    typer.echo("warren init\n")

    mode = typer.prompt(
        "Mode",
        type=click.Choice(["local", "server"]),
        default="local",
        prompt_suffix=" [local/server]: ",
        show_choices=False,
    )

    config_path.parent.mkdir(parents=True, exist_ok=True)
    PROJECTS_DIR.mkdir(parents=True, exist_ok=True)

    if mode == "local":
        from warren_common.runtime_detect import detect  # noqa: PLC0415

        r = detect()
        typer.echo("")
        typer.echo("Detected runtimes:")
        typer.echo(f"  Seatbelt (macOS): {'✓' if r.seatbelt else '✗'}")
        typer.echo(f"  Bubblewrap (Linux): {'✓' if r.bwrap else '✗'}")
        typer.echo(f"  nsjail (Linux): {'✓' if r.nsjail else '✗'}")
        typer.echo(f"  Docker: {'✓' if r.docker else '✗'}")
        if r.windows_build:
            typer.echo(f"  MXC (Windows {r.windows_build}, not used yet): {r.mxc_status}")
        if r.note:
            typer.echo(f"  Note: {r.note}")
        detected_default = "bwrap" if r.recommended == "bubblewrap" else r.recommended
        if detected_default == "none":
            detected_default = "docker"
        runtime_choice = typer.prompt(
            "Runtime",
            default=detected_default,
            show_default=True,
        )
        if runtime_choice not in ("seatbelt", "bwrap", "nsjail", "docker", "auto"):
            ui.error(f"Unknown runtime '{runtime_choice}'. Valid: seatbelt, bwrap, nsjail, docker")
            raise typer.Exit(1)
        # tomli_w escapes Windows backslash paths, which an f-string TOML would not.
        write_config_toml(
            config_path,
            {
                "defaults": {"mode": "local", "projects_dir": str(PROJECTS_DIR)},
                "runtime": {"type": runtime_choice},
            },
        )
        ui.ok(f"Local mode configured (runtime: {runtime_choice}).")
        typer.echo(f"  Projects: {PROJECTS_DIR}")
        typer.echo(f"  Add a project: warren project add <name>")
    else:
        url = typer.prompt("Server URL", default="http://node2.local:8420")
        if is_insecure_http_url(url):
            ui.warn(
                f"{url!r} is plaintext http:// and not localhost -- the auth token will be "
                "readable by anyone on the network path. Prefer an https:// URL if this server "
                "supports one."
            )
        token = typer.prompt("Auth token", hide_input=True)
        name = typer.prompt("Profile name", default="default")
        write_config_toml(
            config_path,
            {
                "defaults": {"mode": "server", "server": name, "projects_dir": str(PROJECTS_DIR)},
                "servers": {name: {"url": url, "auth_token": token}},
            },
        )
        ui.ok("Server mode configured.")
        typer.echo(f"  Run 'warren healthz' to verify the connection.")


# ---------------------------------------------------------------------------
# projects
# ---------------------------------------------------------------------------

@app.command()
def projects(
    server: Optional[str] = typer.Option(None, "--server", help="Remote name from config."),
    output_json: bool = typer.Option(False, "--json", help="Output the raw server response as JSON."),
    config: Optional[Path] = typer.Option(
        None, "--config", help="Override config path (default ~/.warren/config.toml)."
    ),
) -> None:
    """List projects and their available templates.

    Uses `[remotes.*]` (the same config section and tunnel-aware client as
    every other remote-facing command) -- see the `healthz` fix for the same
    [servers.*]/ServerProfile bug this command shared, caught live the same way.
    """
    cfg = _load_cfg(config)
    remote_name = server
    if remote_name is None:
        remote_name = _pick_remote_interactively(cfg)
    try:
        remote = cfg.get_remote(remote_name)
    except KeyError as e:
        ui.error(str(e))
        raise typer.Exit(1) from e

    async def _fetch() -> httpx.Response:
        async with make_remote_client(remote) as c:
            return await c.get("/projects")

    try:
        resp = asyncio.run(_fetch())
    except httpx.ConnectError:
        target = remote.url or f"ssh://{remote.ssh_host}"
        ui.error(f"warren-server unreachable at {target}")
        raise typer.Exit(1)
    except httpx.HTTPError as e:
        ui.error(f"request failed: {type(e).__name__}")
        raise typer.Exit(1)

    if output_json:
        _handle_response(resp)
        return

    if resp.status_code == 401:
        ui.error("authentication failed — check auth_token in ~/.warren/config.toml")
        raise typer.Exit(1)
    if resp.status_code >= 400:
        ui.error(f"warren-server returned HTTP {resp.status_code}")
        raise typer.Exit(1)

    _print_projects_table(resp.json())


_DESCRIPTION_MAX_LEN = 100


def _truncate_description(description: str) -> str:
    """First line, then hard-capped length -- YAML block-scalar folding joins
    wrapped lines with spaces rather than '\\n', so a "first line only" rule
    alone does nothing for the common case (one long folded paragraph with
    no embedded newline at all); real project descriptions run to several
    hundred characters and would otherwise blow out every row's width."""
    if not description:
        return ""
    first_line = description.strip().splitlines()[0]
    if len(first_line) <= _DESCRIPTION_MAX_LEN:
        return first_line
    return first_line[: _DESCRIPTION_MAX_LEN - 1].rstrip() + "…"


def _print_projects_table(projects_data: list[dict]) -> None:
    """Render GET /projects's response as a name/scope/templates/description table.

    This used to just dump the raw JSON unconditionally (`_handle_response`'s
    generic fallback) -- never given a real table the way `warren list` and
    the local `warren project list` were, just never revisited after the
    first quick implementation.
    """
    from warren_common.models import ProjectConfig
    from warren_common.templates import list_template_paths

    if not projects_data:
        typer.echo("No projects visible on this server.")
        return

    rows: list[tuple[str, str, str, str]] = []
    for entry in projects_data:
        name = entry.get("name") or ""
        scope = entry.get("_scope") or ""
        # GET /projects always adds `_scope` (see routes/projects.py) -- strip it
        # before constructing ProjectConfig so its unknown-field warning doesn't
        # fire on every single row.
        entry_for_config = {k: v for k, v in entry.items() if k != "_scope"}
        try:
            cfg_obj = ProjectConfig(**entry_for_config)
            templates = ", ".join(list_template_paths(cfg_obj)) or "—"
            description = _truncate_description(cfg_obj.description)
        except Exception as e:
            templates = "—"
            description = f"(failed to parse: {e})"
        rows.append((name, scope, templates, description))

    ui.print_table(("NAME", "SCOPE", "TEMPLATES", "DESCRIPTION"), rows)


def _load_cfg(config: Optional[Path]) -> WarrenCLIConfig:
    try:
        return WarrenCLIConfig.load(config)
    except FileNotFoundError as e:
        ui.error(str(e))
        raise typer.Exit(1) from e


_REMOTE_STATE_FILE = Path.home() / ".warren" / "remotes-state.json"
_ACTIVE_STATUSES = {"running", "provisioning"}

# Re-exported for backward compatibility -- `ui.py` now owns the one
# interactive-picker implementation (UX-2: previously duplicated here and as
# numbered `[n]` prompts elsewhere).
_is_interactive = ui.is_interactive
_arrow_select = ui.arrow_select


def _pick_remote_interactively(cfg: WarrenCLIConfig) -> str:
    """Prompt for a configured remote by name when --server was omitted.

    Commands that act on a remote workspace (status, tunnel) used to just
    error out ("--server <name> is required") when it wasn't given — this
    picks interactively instead, matching how `new`/`connect` already handle
    an omitted project/workspace_id rather than demanding it upfront.
    """
    names = sorted(cfg.remotes)
    if not names:
        ui.error("no remotes configured — add one with 'warren remote add' or pass --server")
        raise typer.Exit(1)
    return _arrow_select(
        "Select a server:", [(name, name) for name in names], non_tty_hint="pass --server"
    )


def _load_remote_state() -> dict:
    try:
        return json.loads(_REMOTE_STATE_FILE.read_text())
    except Exception:
        return {}


def _save_remote_state(state: dict) -> None:
    try:
        _REMOTE_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        _REMOTE_STATE_FILE.write_text(json.dumps(state, indent=2))
        restrict_to_owner(_REMOTE_STATE_FILE)
    except Exception:
        pass


async def _gather_remote_workspaces(remotes: dict) -> list:
    """Fan out GET /workspaces and GET /healthz to all configured remotes concurrently.

    Returns list of (name, workspaces_or_None, health_or_None) 3-tuples.
    Unreachable remotes return (name, None, None) — never propagate exceptions
    (T-03-10: timeout=5.0 enforced by make_remote_client).
    Updates last-seen state on success.
    """
    from datetime import datetime, timezone  # noqa: PLC0415

    state = _load_remote_state()

    async def fetch(name: str, profile) -> tuple:
        try:
            async with make_remote_client(profile, timeout=5.0) as c:
                ws_resp, hz_resp = await asyncio.gather(
                    c.get("/workspaces"),
                    c.get("/healthz"),
                    return_exceptions=True,
                )
            # Extract workspaces
            if isinstance(ws_resp, (Exception, BaseException)) or not ws_resp.is_success:
                data = None
            else:
                data = ws_resp.json()
            # Extract health (non-fatal — partial success OK)
            if isinstance(hz_resp, (Exception, BaseException)) or not hz_resp.is_success:
                health = None
            else:
                health = hz_resp.json()
            if data is not None:
                state[name] = {
                    "last_seen": datetime.now(timezone.utc).isoformat(),
                    "workspaces": [
                        {"workspace_id": w.get("workspace_id", ""), "project": w.get("project", ""),
                         "intent": w.get("intent", ""), "status": w.get("status", "")}
                        for w in data if w.get("status") in _ACTIVE_STATUSES
                    ],
                }
            return name, data, health
        except Exception:
            return name, None, None  # offline / unreachable — never propagate

    results = list(await asyncio.gather(*[fetch(n, p) for n, p in remotes.items()]))
    _save_remote_state(state)
    return results


def _workspace_shell(ws: dict) -> str:
    """The warren shell for the workspace's template (AG2a): its `app` when that's a shell, else bash."""
    from warren_common.harness_shell import workspace_shell  # noqa: PLC0415

    app_name = ws.get("app")
    if app_name is None:
        try:
            app_name = json.loads(ws.get("spec_json") or "{}").get("app")
        except (ValueError, AttributeError):
            app_name = None
    return workspace_shell(app_name or "bash")


def _check_remote_harness(ws: dict, harness: Optional[str]) -> None:
    if not harness:
        return
    from warren_common.harness_shell import valid_harness_name  # noqa: PLC0415

    names = ws.get("harnesses")
    if not valid_harness_name(harness) or (names is not None and harness not in names):
        ui.error(f"harness {harness!r} is not in this workspace's template (harnesses: {sorted(names or []) or 'none'})")
        raise typer.Exit(1)


async def _sleep(seconds: float) -> None:
    await asyncio.sleep(seconds)


def _clock() -> float:
    import time as _time  # noqa: PLC0415

    return _time.monotonic()


def _retry_after_seconds(response: httpx.Response) -> Optional[float]:
    if response.status_code != 503:
        return None
    value = response.headers.get("Retry-After")
    if value is None:
        return None
    try:
        return min(max(float(value), 1.0), 30.0)
    except ValueError:
        return 5.0


async def _ensure_running_with_retry(c: httpx.AsyncClient, workspace_id: str, start_timeout: float) -> httpx.Response:
    """POST ensure_running until the workspace is up. The server answers 503 +
    Retry-After when a task is still starting after its own bounded wait, and a client
    timeout means the same; both retry until `start_timeout` has elapsed."""
    started = _clock()
    while True:
        try:
            r = await c.post(f"/workspaces/{workspace_id}/ensure_running")
        except httpx.TimeoutException:
            delay: Optional[float] = 5.0
        else:
            delay = _retry_after_seconds(r)
            if delay is None:
                r.raise_for_status()
                return r
        elapsed = _clock() - started
        if elapsed + delay > start_timeout:
            ui.error(
                f"workspace {workspace_id[:8]} did not start within {start_timeout:.0f}s. "
                "It may still be starting: run `warren connect` again shortly, "
                "or pass a larger --start-timeout."
            )
            raise typer.Exit(1)
        ui.warn(f"workspace {workspace_id[:8]} is still starting ({elapsed:.0f}s), retrying in {delay:.0f}s")
        await _sleep(delay)


def _match_remote_workspace(workspaces: list[dict], workspace_id: str) -> dict:
    """Resolve `workspace_id` (exact or short prefix) against a remote's
    workspace list, same ambiguous-prefix contract as the local picker's
    `_load_workspace_state` (commands/workspaces.py) -- an exact match wins
    outright; otherwise a prefix matching more than one workspace is a hard
    error naming every match, never a silent first-match pick (audit
    2026-10-16 #35: `connect`/`tunnel` used to `break` on the first prefix
    hit, unlike the local picker, which already rejected ambiguity).

    Raises `typer.Exit(1)` (after printing a clear error) on no match or an
    ambiguous match; returns the single matching workspace dict otherwise.
    """
    for w in workspaces:
        if w.get("workspace_id", "") == workspace_id:
            return w
    matches = [w for w in workspaces if w.get("workspace_id", "").startswith(workspace_id)]
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        ids = [w.get("workspace_id", "") for w in matches]
        ui.error(f"ambiguous workspace id {workspace_id!r} matches {ids}")
        raise typer.Exit(1)
    ui.error(f"workspace {workspace_id!r} not found")
    raise typer.Exit(1)


def _handle_response(resp: httpx.Response) -> None:
    if resp.status_code == 401:
        ui.error("authentication failed — check auth_token in ~/.warren/config.toml")
        raise typer.Exit(1)
    if resp.status_code >= 400:
        ui.error(f"warren-server returned HTTP {resp.status_code}")
        raise typer.Exit(1)
    try:
        typer.echo(json.dumps(resp.json(), indent=2))
    except ValueError:
        typer.echo(resp.text)


@app.command()
def healthz(
    server: Optional[str] = typer.Option(None, "--server", help="Remote name from config."),
    output_json: bool = typer.Option(False, "--json", help="Output the raw server response as JSON."),
    config: Optional[Path] = typer.Option(
        None, "--config", help="Override config path (default ~/.warren/config.toml)."
    ),
) -> None:
    """Health-check a configured remote warren-server.

    Named `healthz`, not `connect` — `connect` is the top-level shortcut for
    `workspaces connect` (see "Top-level shortcuts" below). Having both
    registered under the name "connect" previously meant this command was
    silently shadowed and unreachable (the later `app.command("connect")(...)`
    registration always won); this is a distinct command and needed its own
    name.

    Uses `[remotes.*]` (the same config section and tunnel-aware client as
    every other remote-facing command) -- this used to look up `[servers.*]`
    via the old ServerProfile/make_client path instead, which doesn't know
    about ssh/ecs remotes at all and raised a bare KeyError for any config
    that only has `[remotes.*]` entries (the normal case now).
    """

    cfg = _load_cfg(config)
    remote_name = server
    if remote_name is None:
        remote_name = _pick_remote_interactively(cfg)
    try:
        remote = cfg.get_remote(remote_name)
    except KeyError as e:
        ui.error(str(e))
        raise typer.Exit(1) from e

    async def _fetch() -> httpx.Response:
        async with make_remote_client(remote) as c:
            return await c.get("/healthz")

    try:
        resp = asyncio.run(_fetch())
    except httpx.ConnectError:
        target = remote.url or f"ssh://{remote.ssh_host}"
        ui.error(f"warren-server unreachable at {target}")
        raise typer.Exit(1)
    except httpx.HTTPError as e:
        ui.error(f"request failed: {type(e).__name__}")
        raise typer.Exit(1)

    if output_json:
        _handle_response(resp)
        return

    if resp.status_code == 401:
        ui.error("authentication failed — check auth_token in ~/.warren/config.toml")
        raise typer.Exit(1)
    if resp.status_code >= 400:
        ui.error(f"warren-server returned HTTP {resp.status_code}")
        raise typer.Exit(1)

    data = resp.json()
    rt = data.get("runtime", {})
    ws = data.get("workspaces", {})
    ui.ok(f"{remote_name}  warren {data.get('version', '?')}  ({data.get('warren_id', '?')})")
    typer.echo(
        f"  runtime: {rt.get('type', 'unknown')} "
        f"{ui.OK if rt.get('reachable') else ui.FAIL}"
    )
    typer.echo(f"  workspaces: {ws.get('running', 0)} running / {ws.get('total', 0)} total")


def _parse_timestamp(ts: str) -> "datetime":
    from datetime import datetime, timezone  # noqa: PLC0415

    try:
        return datetime.fromisoformat(ts.rstrip("Z")).replace(tzinfo=timezone.utc)
    except Exception:
        return datetime.fromtimestamp(0, tz=timezone.utc)


def _sort_workspaces_live_then_reaped(workspaces: list) -> list:
    """Live workspaces (running/provisioning) first, then reaped/stopped ones,
    each group most-recently-updated first -- so a workspace listing reads
    top-to-bottom as "what's live" then "what recently died", not an
    arbitrary server-row order."""

    def _sort_key(ws: dict) -> tuple[int, float]:
        is_reaped = ws.get("status") not in _ACTIVE_STATUSES
        recency = _parse_timestamp(str(ws.get("updated_at") or ws.get("created_at") or ""))
        return (1 if is_reaped else 0, -recency.timestamp())

    return sorted(workspaces, key=_sort_key)


def _print_remote_workspace_table(workspaces: list) -> None:
    """Print remote workspace list in the same table format as list_local."""
    workspaces = _sort_workspaces_live_then_reaped(workspaces)

    rows = []
    for ws in workspaces:
        rows.append((
            str(ws.get("workspace_id", ""))[:8],
            str(ws.get("project", "")),
            str(ws.get("intent", "")),
            str(ws.get("status", "")),
            ui.relative_time(str(ws.get("created_at", ""))),
        ))

    ui.print_table(("ID", "PROJECT", "TEMPLATE", "STATUS", "CREATED"), rows)


@app.command("list")
def workspaces_list(
    server: Optional[str] = typer.Option(None, "--server", help="Named profile from config."),
    config: Optional[Path] = typer.Option(None, "--config"),
    show_all: bool = typer.Option(False, "--all", help="Include stopped and failed workspaces."),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON (local + remotes combined)."),
    merged: bool = typer.Option(
        False, "--merged", help="Only local workspaces whose branch's PR is merged (via gh), and offer to destroy them."
    ),
) -> None:
    """List workspaces — active only by default; use --all to include stopped/failed."""
    if merged:
        _list_merged(config, output_json)
        return
    if output_json:
        local_ws = workspaces_local.load_local_workspaces()
        combined: dict = {"local": local_ws, "remotes": {}}
        try:
            # WarrenCLIConfig.load (not _load_cfg) — a missing config is normal for
            # local-only use and must not print "config not found" noise; remotes are
            # purely optional here, not a required precondition like other commands.
            cfg = WarrenCLIConfig.load(config)
            if cfg.remotes:
                with _err_console.status("Fetching remote workspaces..."):
                    results = asyncio.run(_gather_remote_workspaces(cfg.remotes))
                for remote_name, data, _health in results:
                    combined["remotes"][remote_name] = data  # None = unreachable
        except (FileNotFoundError, Exception):
            pass
        typer.echo(json.dumps(combined, indent=2, default=str))
        return

    # Local workspaces (always active — no status field in local state.json)
    workspaces_local.list_local(show_all=show_all)

    # Fan out to all configured remotes. WarrenCLIConfig.load (not _load_cfg) —
    # same reasoning as the output_json branch above: a missing config just means
    # no remotes are configured, not an error worth printing.
    try:
        cfg = WarrenCLIConfig.load(config)
        if not cfg.remotes:
            return
        remote_state = _load_remote_state()
        with _err_console.status("Fetching remote workspaces..."):
            results = asyncio.run(_gather_remote_workspaces(cfg.remotes))
        for remote_name, data, health in results:
            if data is None:
                cached = remote_state.get(remote_name, {})
                last = cached.get("last_seen")
                cached_ws = cached.get("workspaces", [])
                if last:
                    ui.warn(f"[{remote_name}] offline (last seen {ui.relative_time(last)})")
                else:
                    ui.warn(f"[{remote_name}] unreachable")
                # Show cached active workspaces as disconnected
                if cached_ws and not show_all:
                    disc = [{**w, "status": "disconnected"} for w in cached_ws]
                    _print_remote_workspace_table(disc)
            else:
                active = [w for w in data if w.get("status") in _ACTIVE_STATUSES] if not show_all else data
                # Always show the online header once a remote actually answers (even
                # with zero active workspaces) -- this used to print nothing at all
                # in that case, making a successful, possibly multi-second remote
                # fetch (ssh/ecs tunnel setup included) look like it silently failed.
                if health is not None:
                    rt = health.get("runtime", {})
                    ws_counts = health.get("workspaces", {})
                    rt_mark = ui.OK if rt.get("reachable") else ui.FAIL
                    rt_type = rt.get("type", "unknown")
                    n_running = ws_counts.get("running", 0)
                    header = f"\n[{remote_name}]  online  {rt_type} {rt_mark}  {n_running} running"
                else:
                    header = f"\n[{remote_name}]  online"
                typer.echo(header)
                if active:
                    _print_remote_workspace_table(active)
    except FileNotFoundError:
        pass
    except Exception:
        pass


def _worktree_branch(repo_dir: Path, bares: list[Path]) -> Optional[str]:
    """The worktree's checked-out branch, read from its admin dir inside the
    warren-owned bare store (no git process, nothing workspace-writable)."""
    admin = _trusted_worktree_git_dir(repo_dir, bares)
    if admin is None:
        return None
    try:
        head = (admin / "HEAD").read_text().strip()
    except OSError:
        return None
    return head.removeprefix("ref: refs/heads/") if head.startswith("ref: refs/heads/") else None


def _merged_local_workspaces(projects_dir: Path) -> list[tuple[dict, list[str]]]:
    """(workspace, ["mount: owner/repo#branch", ...]) for every local workspace
    with at least one merged PR and no open/closed-unmerged one."""
    from warren_cli import gh  # noqa: PLC0415
    from warren_cli.machine_config import load_project  # noqa: PLC0415

    found = []
    for ws in workspaces_local.load_local_workspaces():
        project = ws.get("project")
        try:
            folders = {f.mount: f for f in load_project(project, projects_dir).effective_folders()}
        except Exception:
            continue
        bares = _project_bare_stores(projects_dir, project)
        merged_refs, blocked = [], False
        for entry in ws.get("worktree_paths", []):
            if not isinstance(entry, (list, tuple)) or len(entry) < 2:
                continue
            host, mount = Path(entry[0]), entry[1]
            folder = folders.get(mount)
            repo = gh.github_repo(folder.url if folder else None)
            branch = _worktree_branch(host, bares)
            if not repo or not branch:
                continue
            state = gh.pr_state(repo, branch)
            if state == "MERGED":
                merged_refs.append(f"{mount}: {repo}#{branch}")
            elif state is not None:
                blocked = True
        if merged_refs and not blocked:
            found.append((ws, merged_refs))
    return found


def _list_merged(config: Optional[Path], output_json: bool) -> None:
    from warren_cli import gh  # noqa: PLC0415

    cfg = WarrenCLIConfig.load(config) if config is not None else None
    projects_dir = cfg.projects_path() if cfg is not None else PROJECTS_DIR
    try:
        found = _merged_local_workspaces(projects_dir)
    except gh.GhError as exc:
        ui.error(f"gh: {exc}")
        raise typer.Exit(1) from exc
    if output_json:
        typer.echo(json.dumps(
            [{"workspace_id": ws.get("workspace_id"), "project": ws.get("project"),
              "intent": ws.get("intent"), "merged": refs} for ws, refs in found],
            indent=2,
        ))
        return
    if not found:
        typer.echo("No local workspaces with merged PRs.")
        return
    ui.print_table(
        ("ID", "PROJECT", "TEMPLATE", "MERGED"),
        [(str(ws.get("workspace_id", ""))[:8], ws.get("project", ""), ws.get("intent", ""), "; ".join(refs))
         for ws, refs in found],
    )
    if not sys.stdin.isatty():
        typer.echo("Destroy with: warren destroy <id>")
        return
    if not typer.confirm(f"Destroy {len(found)} merged workspace(s)?", default=False):
        return
    for ws, _ in found:
        workspaces_destroy(workspace_id=str(ws["workspace_id"]), server=None, config=None)


@app.command("new")
def workspaces_provision(
    project: Optional[str] = typer.Argument(default=None, help="Project name (omit for interactive picker)"),
    template: Optional[str] = typer.Argument(
        default=None, help="Template name — dotted for nested, e.g. develop.claude (default: observe)"
    ),
    daemon: bool = typer.Option(False, "--daemon", help="Provision in background without connecting."),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print the resolved template (image, folders, mounts, secret names) and exit."
    ),
    pin_green: bool = typer.Option(
        False, "--pin-green", help="Start each GitHub worktree at the newest base-branch commit whose checks all passed (uses gh)."
    ),
    server: Optional[str] = typer.Option(None, "--server"),
    config: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Provision a workspace and connect into it immediately.

    No args → interactive picker (project then template).
    Template defaults to 'observe' (read-only).
    Use --daemon to provision without connecting.

    Examples:
      warren new                                  # interactive
      warren new connected-compliance             # observe, connect
      warren new connected-compliance develop     # develop, connect
      warren new connected-compliance develop.claude  # nested sub-template
      warren new connected-compliance --daemon    # provision only
    """
    _check_not_nested()

    cfg = _load_cfg(config)
    remote = None
    if server:
        try:
            remote = cfg.get_remote(server)
        except KeyError as e:
            ui.error(str(e))
            raise typer.Exit(1) from e

    if not project:
        if remote is not None:
            # Targeting a remote: the picker must offer what's actually on
            # THAT server, not the local ~/.warren/projects/*.yaml files --
            # those two sets routinely differ (e.g. a project someone else
            # defined server-side that was never `warren project clone`d).
            async def _fetch_remote_projects() -> list[dict]:
                async with make_remote_client(remote) as c:
                    r = await c.get("/projects")
                    r.raise_for_status()
                    return r.json()

            try:
                remote_projects = asyncio.run(_fetch_remote_projects())
            except Exception as exc:
                ui.error(f"could not list projects on {server}: {exc}")
                raise typer.Exit(1) from exc
            names = sorted({p["name"] for p in remote_projects if p.get("name")})
            if not names:
                ui.error(f"no projects visible on {server}")
                raise typer.Exit(1)
            project = ui.arrow_select(
                "Select project:",
                [(name, name) for name in names],
                non_tty_hint=f"pass the project argument, e.g. `warren new <project> --server {server}`",
            )
        else:
            projects_dir = PROJECTS_DIR
            if not projects_dir.exists() or not list(projects_dir.glob("*.yaml")):
                ui.error("No projects found. Run: warren project add <name>")
                raise typer.Exit(1)
            project_files = sorted(projects_dir.glob("*.yaml"))
            project = ui.arrow_select(
                "Select project:",
                [(f.stem, f.stem) for f in project_files],
                non_tty_hint="pass the project argument, e.g. `warren new <project>`",
            )

    if not template:
        from warren_common import list_template_paths  # noqa: PLC0415
        from warren_common.models import ProjectConfig  # noqa: PLC0415

        non_tty_hint = f"pass the template argument, e.g. `warren new {project} <template>`"
        if remote is not None:
            non_tty_hint += f" --server {server}"

            async def _fetch_remote_detail() -> Optional[dict]:
                async with make_remote_client(remote) as c:
                    r = await c.get(f"/projects/{project}")
                    if r.status_code == 404:
                        return None
                    r.raise_for_status()
                    return r.json()

            try:
                detail = asyncio.run(_fetch_remote_detail())
            except Exception as exc:
                ui.error(f"could not load project {project!r} on {server}: {exc}")
                raise typer.Exit(1) from exc
            if detail is None:
                ui.error(f"project {project!r} not found on {server}")
                raise typer.Exit(1)
            template_paths = list_template_paths(ProjectConfig(**detail["effective"]))
        else:
            from warren_cli.machine_config import load_project  # noqa: PLC0415

            project_file = PROJECTS_DIR / f"{project}.yaml"
            if not project_file.exists():
                # Downstream (dispatch.provision_local) raises ProjectNotFoundError
                # for this same case with a clear message -- let it get there
                # rather than erroring twice over the same root cause.
                template_paths = []
            else:
                proj = load_project(project, PROJECTS_DIR)
                template_paths = list_template_paths(proj)

        if not template_paths:
            # No templates declared at all -- 'observe' is the project schema's
            # own documented default, not a silent fallback from an error.
            template = "observe"
        else:
            template = ui.arrow_select(
                f"Select template for {project}:",
                [(path, path) for path in template_paths],
                non_tty_hint=non_tty_hint,
            )

    if dry_run:
        _print_dry_run(cfg, remote, server, project, template)
        return

    connect = not daemon
    if server and pin_green:
        ui.error("--pin-green is local-only for now (the server picks the worktree start point)")
        raise typer.Exit(1)
    if server:
        async def _provision_and_poll():
            # routes/workspaces.py's POST /workspaces awaits the ENTIRE
            # provisioning call (every git clone, container create) before
            # responding at all -- it is not fire-and-forget despite the
            # polling loop below suggesting otherwise. A multi-folder
            # template (e.g. 26 folders) can legitimately take 30-60+
            # seconds; the old 10.0s timeout here was sized for a simple
            # pull-and-run workspace with no cloning and failed every real
            # multi-folder provision with a ReadTimeout (observed directly
            # 2026-10-13, immediately after GitManager's clone paths were
            # finally wired up end-to-end).
            # AM2: one operationId for every attempt, so a retry after a dropped
            # connection gets the original workspace rather than a second one.
            import uuid as _uuid  # noqa: PLC0415
            body = {"project": project, "template": template, "operationId": f"cli-{_uuid.uuid4().hex}"}
            for attempt in range(3):
                try:
                    async with make_remote_client(remote, timeout=120.0) as c:
                        resp = await c.post("/workspaces", json=body)
                    break
                except httpx.TransportError:
                    if attempt == 2:
                        raise
                    await asyncio.sleep(1.0)
            resp.raise_for_status()
            ws = resp.json()
            workspace_id = ws["workspace_id"]
            short_id = workspace_id[:8]
            typer.echo(f"  {short_id}  {project}/{template}  provisioning...")
            # By the time POST /workspaces above returned, provisioning has
            # already fully finished (see comment above) -- this poll loop's
            # first iteration should already see the real terminal status.
            # The 30s deadline is just a safety margin, not the expected
            # common case.
            import time as _time  # noqa: PLC0415
            deadline = _time.monotonic() + 30.0
            last_status = "provisioning"
            while _time.monotonic() < deadline:
                await asyncio.sleep(0.5)
                try:
                    async with make_remote_client(remote) as c:
                        r = await c.get(f"/workspaces/{workspace_id}/status")
                        r.raise_for_status()
                        status = r.json().get("status", "unknown")
                except Exception:
                    status = last_status
                if status != last_status:
                    typer.echo(f"  {short_id}  {project}/{template}  {status}")
                    last_status = status
                if status in ("running", "stopped", "failed", "unknown"):
                    break
            return workspace_id, last_status

        try:
            workspace_id, final_status = asyncio.run(_provision_and_poll())
            short_id = workspace_id[:8]
            if final_status == "running":
                ui.ok(f"{short_id}  {project}/{template}  running")
                if remote.url:
                    typer.echo(f"  Events: curl -sN http://{remote.url.replace('http://', '')}/workspaces/{workspace_id}/events")
                else:
                    # ssh/ecs remotes have no directly-curlable URL (loopback-only
                    # control plane, tunneled per-call) -- `warren connect` tunnels
                    # for you instead of printing a dead curl command here.
                    typer.echo(f"  Connect: warren connect {short_id} --server {server}")
            elif final_status == "stopped":
                ui.warn(f"{short_id}  stopped (app exited — check image CMD or use a long-running app)")
            else:
                ui.error(f"{short_id}  {final_status}")
        except httpx.ConnectError:
            target = remote.url or f"ssh://{remote.ssh_host}"
            ui.error(f"warren-server unreachable at {target}")
            raise typer.Exit(1)
        except httpx.HTTPStatusError as e:
            ui.error(f"provision failed: HTTP {e.response.status_code}")
            raise typer.Exit(1)
        return
    if cfg.defaults.mode != "local":
        ui.error("server-mode workspace provisioning requires --server <name>")
        raise typer.Exit(1)
    try:
        dispatch.provision_local(
            project,
            template,
            projects_dir=cfg.projects_path(),
            cfg=cfg,
            connect=connect,
            pin_green=pin_green,
        )
    except NotImplementedError:
        ui.error("nsjail runtime not yet available (lands in Phase 5)")
        raise typer.Exit(1)
    except ProjectNotFoundError as e:
        ui.error(f"project {project!r} not found: {e}")
        raise typer.Exit(1)


def _print_dry_run(cfg, remote, server: Optional[str], project: str, template: str) -> None:
    from warren_common import list_template_paths, resolve_template  # noqa: PLC0415
    from warren_common.errors import TemplateNotFoundError  # noqa: PLC0415
    from warren_common.models import ProjectConfig  # noqa: PLC0415

    from .commands.dry_run import plan_for, print_plan  # noqa: PLC0415

    if remote is not None:
        async def _fetch() -> Optional[dict]:
            async with make_remote_client(remote) as c:
                r = await c.get(f"/projects/{project}")
                if r.status_code == 404:
                    return None
                r.raise_for_status()
                return r.json()

        try:
            detail = asyncio.run(_fetch())
        except Exception as exc:
            ui.error(f"could not load project {project!r} on {server}: {exc}")
            raise typer.Exit(1) from exc
        if detail is None:
            ui.error(f"project {project!r} not found on {server}")
            raise typer.Exit(1)
        project_cfg = ProjectConfig(**detail["effective"])
    else:
        from warren_cli.machine_config import load_project  # noqa: PLC0415

        project_cfg = load_project(project, cfg.projects_path())

    try:
        template_cfg = resolve_template(project_cfg, template)
    except TemplateNotFoundError:
        ui.error(f"template {template!r} not found (available: {list_template_paths(project_cfg)})")
        raise typer.Exit(1)

    if remote is not None:
        image = (
            f"{template_cfg.docker_image} (podman/docker) | {template_cfg.ecs_image} (ecs); "
            "the server substitutes its default for an unsanctioned image"
        )
        target = f"server {server}"
    else:
        from warren_common.images import ImageResolver  # noqa: PLC0415

        image = ImageResolver.from_config(cfg).resolve(template_cfg.docker_image)
        target = f"local ({dispatch._resolve_runtime_type(cfg)})"
    print_plan(plan_for(template_cfg, project=project, template=template, target=target, image=image))


def _project_bare_stores(projects_root: Path, project: object) -> list[Path]:
    """The project's warren-owned bare stores. `project` may come from an
    in-tree (workspace-writable) state.json, so it must name a direct child
    of projects_root and every store must be a real dir inside it."""
    from warren_common.paths import ensure_within  # noqa: PLC0415

    if not isinstance(project, str) or project in ("", ".", "..") or "/" in project:
        return []
    bares = []
    for bare in sorted((projects_root / project).glob("*.git-store")):
        try:
            if not bare.is_symlink() and bare.is_dir():
                ensure_within(projects_root, bare)
                bares.append(bare)
        except Exception:
            continue
    return bares


def _trusted_worktree_git_dir(repo_dir: Path, bares: list[Path]) -> Path | None:
    """The admin dir (`<bare>/worktrees/<name>`) whose recorded gitdir is
    `repo_dir/.git`, found from the bare side only."""
    import os  # noqa: PLC0415

    want = os.path.realpath(repo_dir / ".git")
    for bare in bares:
        admin_root = bare / "worktrees"
        if not admin_root.is_dir():
            continue
        for admin in admin_root.iterdir():
            try:
                recorded = (admin / "gitdir").read_text().strip()
            except OSError:
                continue
            if os.path.realpath(recorded) == want and not admin.is_symlink():
                return admin
    return None


@app.command("destroy")
def workspaces_destroy(
    workspace_id: Optional[str] = typer.Argument(default=None, help="Workspace ID (omit for interactive picker)"),
    server: Optional[str] = typer.Option(None, "--server"),
    config: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Stop and destroy a workspace (local mode: removes workspace directory)."""
    _check_not_nested()
    if server:
        cfg = _load_cfg(config)
        remote = cfg.get_remote(server)
        if not workspace_id:
            ui.error("workspace_id required with --server")
            raise typer.Exit(1)

        async def _destroy_remote():
            async with make_remote_client(remote) as c:
                return await c.delete(f"/workspaces/{workspace_id}")

        resp = asyncio.run(_destroy_remote())
        if resp.status_code not in (200, 204):
            ui.error(f"Error: HTTP {resp.status_code}")
            raise typer.Exit(1)
        ui.ok(f"Workspace {workspace_id} destroyed on {server}.")
        return
    if not workspace_id:
        workspace_id = workspaces_local.pick_workspace("Select workspace to destroy")
    import json
    import shutil
    import subprocess

    from warren_common.safe_git import (  # noqa: PLC0415
        SafeGitError,
        object_scrubbed_environ,
        own_objects_dir,
        safe_git_argv,
    )
    git_env = object_scrubbed_environ()
    from warren_common.paths import PathEscapeError, workspace_child  # noqa: PLC0415

    workspaces_root = Path.home() / ".warren" / "workspaces"
    if not workspaces_root.is_dir():
        ui.error(f"Workspace '{workspace_id}' not found.")
        raise typer.Exit(1)
    ws_dir = workspaces_local.resolve_local_workspace_dir(workspaces_root, workspace_id)

    # seatbelt/bwrap keep state.json outside root_path (audit finding #1) —
    # check there first, falling back to the workspace root for nsjail/docker.
    try:
        state_dir = workspace_child(Path.home() / ".warren" / "state", ws_dir.name)
    except PathEscapeError as e:
        ui.error(f"refusing workspace state dir: {e}")
        raise typer.Exit(1) from e
    state_file = state_dir / "state.json"
    if not state_file.exists():
        state_file = ws_dir / "state.json"
    state: dict = {}
    if state_file.exists():
        try:
            state = json.loads(state_file.read_text())
        except (OSError, ValueError):
            state = {}
    bares = _project_bare_stores(Path.home() / ".warren" / "projects", state.get("project"))

    # Safety check — warn about uncommitted or unpushed changes. Host git only
    # ever reads the worktree's admin dir inside the warren-owned bare store,
    # never the workspace's own (writable) `.git` (BB7/BB12).
    code_dir = ws_dir / "code"
    if code_dir.exists():
        warnings = []
        for repo_dir in code_dir.iterdir():
            if repo_dir.is_symlink() or not (repo_dir / ".git").exists():
                continue
            git_dir = _trusted_worktree_git_dir(repo_dir, bares)
            if git_dir is None:
                warnings.append(f"  {repo_dir.name}: not checked (not a warren-managed worktree)")
                continue
            # Object lookup stays in the bare store's own objects dir: refuse
            # (rather than read through) any alternates there.
            try:
                own_objects_dir(git_dir.parent.parent)
            except SafeGitError as e:
                warnings.append(f"  {repo_dir.name}: not checked ({e})")
                continue
            loc = ["--git-dir", str(git_dir), "--work-tree", str(repo_dir)]
            # Uncommitted changes
            r = subprocess.run(
                safe_git_argv(*loc, "status", "--porcelain", "--ignore-submodules=all"),
                capture_output=True, text=True, cwd="/", env=git_env,
            )
            if r.stdout.strip():
                warnings.append(f"  {repo_dir.name}: uncommitted changes")
            # Unpushed commits
            r2 = subprocess.run(
                safe_git_argv(*loc, "log", "--oneline", "--no-show-signature", "@{u}..HEAD"),
                capture_output=True, text=True, cwd="/", env=git_env,
            )
            if r2.returncode == 0 and r2.stdout.strip():
                count = len(r2.stdout.strip().splitlines())
                warnings.append(f"  {repo_dir.name}: {count} unpushed commit(s)")
        if warnings:
            ui.warn("This workspace has unsaved work:\n")
            for w in warnings:
                ui.stderr.print(w)
            typer.echo("")
            confirm = typer.confirm("Destroy anyway?", default=False)
            if not confirm:
                typer.echo("Cancelled.")
                raise typer.Exit(0)

    # Prune git worktrees and workspace branches before deleting the dir.
    # worktree_paths in state.json is [[host_path, mount], ...]; derive bare
    # repo path from the host_path (host_path is workspace_root/subdir, bare is
    # under projects_dir/<project>/<slug>.git-store).
    if state:
        try:
            workspace_id_full = state.get("workspace_id", "")
            short_id = workspace_id_full[:8]
            seen_bares: set[str] = set()
            for _wt in state.get("worktree_paths", []):
                # Each entry is [host_path, mount]; bares are the project's
                # <projects_dir>/<project>/*.git-store
                for bare in bares:
                    key = str(bare)
                    if key in seen_bares:
                        continue
                    seen_bares.add(key)
                    # Delete branches: warren/<intent>/<short-id>/<subdir> — glob on short_id
                    r = subprocess.run(
                        safe_git_argv("-C", str(bare), "branch", "--list", f"warren/*/{short_id}/*"),
                        capture_output=True, text=True, env=git_env,
                    )
                    for branch in r.stdout.strip().splitlines():
                        branch = branch.strip()
                        if branch:
                            subprocess.run(
                                safe_git_argv("-C", str(bare), "branch", "-D", branch),
                                capture_output=True, env=git_env,
                            )
                    subprocess.run(
                        safe_git_argv("-C", str(bare), "worktree", "prune"),
                        capture_output=True, env=git_env,
                    )
        except Exception:
            pass  # best-effort; deletion proceeds regardless

    try:
        workspace_child(workspaces_root, ws_dir.name)
        workspace_child(state_dir.parent, state_dir.name)
    except PathEscapeError as e:
        ui.error(f"refusing to delete: {e}")
        raise typer.Exit(1) from e
    shutil.rmtree(ws_dir)
    # Clean up the out-of-tree sandbox state dir too (finding #1) — it holds
    # env_snapshot secret values (T-05b-19) and must not be left orphaned.
    if state_dir.is_dir():
        shutil.rmtree(state_dir)
    ui.ok(f"Workspace {workspace_id[:8]}... destroyed.")


@app.command("status")
def workspaces_status(
    workspace_id: str = typer.Argument(help="Workspace ID"),
    server: Optional[str] = typer.Option(None, "--server"),
    output_json: bool = typer.Option(False, "--json", help="Output the raw server response as JSON."),
    config: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Show status of a workspace on a remote warren-server.

    Local workspaces have no server-tracked status — use 'warren list' for those instead.
    """
    cfg = _load_cfg(config)
    if not server:
        server = _pick_remote_interactively(cfg)
    remote = cfg.get_remote(server)

    async def _status_remote():
        async with make_remote_client(remote) as c:
            return await c.get(f"/workspaces/{workspace_id}/status")

    resp = asyncio.run(_status_remote())
    if output_json:
        _handle_response(resp)
        return
    if resp.status_code == 401:
        ui.error("authentication failed — check auth_token in ~/.warren/config.toml")
        raise typer.Exit(1)
    if resp.status_code >= 400:
        ui.error(f"warren-server returned HTTP {resp.status_code}")
        raise typer.Exit(1)
    data = resp.json()
    typer.echo(f"  {workspace_id}  {data.get('status', 'unknown')}")


@app.command("exec")
def workspaces_exec(
    workspace_id: str = typer.Argument(help="Workspace ID or short prefix"),
    cmd: list[str] = typer.Argument(help="Command and arguments to run inside the workspace"),
    server: Optional[str] = typer.Option(None, "--server"),
    config: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Run a command non-interactively inside an existing local workspace.

    Example: warren exec cc123 -- pytest packages/
    """
    cfg = _load_cfg(config)
    if cfg.defaults.mode != "local":
        ui.error("server-mode workspace exec requires the sidecar — available in Phase 4")
        raise typer.Exit(1)
    if not cmd:
        ui.error("no command specified")
        raise typer.Exit(1)
    rc = workspaces_local.exec_local(workspace_id, list(cmd))
    raise typer.Exit(rc)


@app.command("connect")
def workspaces_connect(
    workspace_id: Optional[str] = typer.Argument(default=None, help="Workspace ID (omit for interactive picker)"),
    server: Optional[str] = typer.Option(None, "--server"),
    config: Optional[Path] = typer.Option(None, "--config"),
    start_timeout: float = typer.Option(
        300.0, "--start-timeout", help="Seconds to wait for a stopped remote workspace to start"
    ),
    harness: Optional[str] = typer.Option(
        None, "--harness", help="Start this harness in the shell, resuming its conversation"
    ),
    new: bool = typer.Option(
        False, "--new", help="Ignore the recorded conversation (with --harness: start a new one)"
    ),
) -> None:
    """Open the warren shell inside a workspace.

    The template's harnesses (e.g. claude, codex) are commands in that shell;
    exiting one returns to the shell, and `warren resume [<harness>]` continues a
    conversation. Reconnecting returns to what you were doing: a harness still
    running is reattached (podman/ECS), one that was cut off is resumed. Leaving
    the shell disconnects; the workspace keeps running.
    """
    cfg = _load_cfg(config)
    # `--server` omitted used to fall straight through to the local-mode branch
    # below whenever `[defaults] mode = "local"` was set, never considering
    # `[remotes.*]` at all -- so a config with remotes configured (the normal
    # shape, e.g. node2) silently showed no remote picker and no error naming
    # them, just a generic "requires the sidecar PTY" message or a local
    # picker with nothing in it. Every other remote command (`tunnel`,
    # `healthz`, `projects`, `list`) already prefers a configured remote over
    # local mode when `--server` is omitted; this brings `connect` in line.
    if not server and cfg.remotes:
        server = _pick_remote_interactively(cfg)
    if server:
        remote = cfg.get_remote(server)
        # Resolve workspace ID — fetch remote list if not given
        if not workspace_id:
            async def _list_remote():
                async with make_remote_client(remote, timeout=5.0) as c:
                    r = await c.get("/workspaces")
                    r.raise_for_status()
                    return r.json()
            try:
                workspaces = asyncio.run(_list_remote())
            except Exception:
                target = remote.url or f"ssh://{remote.ssh_host}"
                ui.error(f"warren-server unreachable at {target}")
                raise typer.Exit(1)
            # Reaped (stopped/idle-killed) workspaces are offered here too, not
            # just live ones -- ensure_running below resurrects them, so a
            # reaped workspace is a valid, pickable target, not a dead end
            # that forces typing its id from memory.
            if not workspaces:
                ui.error(f"No workspaces on {server}.")
                raise typer.Exit(1)
            ordered = _sort_workspaces_live_then_reaped(workspaces)
            workspace_id = _arrow_select(
                f"Select workspace to connect on {server}:",
                [
                    (
                        f"{w['workspace_id'][:8]}  {w['project']}/{w['intent']}  "
                        f"({w.get('status', 'unknown')})",
                        w["workspace_id"],
                    )
                    for w in ordered
                ],
                non_tty_hint="pass the workspace ID argument",
            )
        # workspace_id may be a short prefix (e.g. the 8-char id `new --daemon`
        # prints in its "Connect: warren connect <id> --server <name>" hint) --
        # resolve it against the full id, same prefix-match convention `tunnel`
        # already uses, before calling ensure_running (which needs the exact id).
        # Also returns the full workspace dict so the caller can print WHICH
        # workspace it's attaching to -- with one remote and one active
        # workspace (the common case), both get auto-picked with zero prompts,
        # and silently attaching with no confirmation of what you landed on
        # was a real gap (caught live).
        async def _resolve_workspace() -> dict:
            async with make_remote_client(remote, timeout=5.0) as c:
                r = await c.get("/workspaces")
                r.raise_for_status()
                workspaces = r.json()
            if not workspaces:
                return {"workspace_id": workspace_id}
            return _match_remote_workspace(workspaces, workspace_id)

        async def _ensure_running() -> tuple[dict, dict]:
            ws = await _resolve_workspace()
            full_id = ws["workspace_id"]
            async with make_remote_client(remote, timeout=60.0) as c:
                r = await _ensure_running_with_retry(c, full_id, start_timeout)
                return ws, r.json()

        try:
            ws, running = asyncio.run(_ensure_running())
        except httpx.HTTPStatusError as exc:
            ui.error(f"connect failed: HTTP {exc.response.status_code} — {exc.response.text}")
            raise typer.Exit(1)
        except typer.Exit:
            # _resolve_workspace's own not-found/ambiguous-prefix error (via
            # _match_remote_workspace) already printed a clear message --
            # don't let the broad except below relabel it "unreachable".
            raise
        except Exception as exc:
            target = remote.url or remote.ssh_host or f"ecs:{remote.ecs_cluster}/{remote.ecs_service}"
            ui.error(f"warren-server unreachable at {target}: {exc}")
            raise typer.Exit(1)

        container_id = running["container_id"]
        if running.get("newer_image"):
            ui.warn(
                f"a newer image is available for this workspace ({running['newer_image']}); "
                "it is used the next time its task or container is recreated, "
                "and harness conversations carry over"
            )
        _check_remote_harness(ws, harness)
        dispatch.set_terminal_title(
            str(ws.get("project", "")), str(ws.get("intent", "")), str(ws.get("workspace_id", ""))
        )
        if remote.runtime_type == "ssh":
            # Replaces this process — never returns (except when mocked in tests).
            dispatch.connect_via_ssh_podman_exec(
                remote.ssh_host,
                container_id,
                ssh_key_path=remote.ssh_key_path,
                shell=_workspace_shell(ws),
                harness=harness,
                new=new,
            )
            return
        if remote.runtime_type == "ecs":
            ecs_cluster = remote.ecs_cluster or _os.environ.get("WARREN_ECS_CLUSTER", "")
            if not ecs_cluster:
                ui.error("no ECS cluster configured — set ecs_cluster on this remote profile or WARREN_ECS_CLUSTER")
                raise typer.Exit(1)
            if not container_id:
                ui.error(f"workspace {ws['workspace_id'][:8]} on {server} has no ECS task ARN")
                raise typer.Exit(1)
            # Replaces this process — never returns (except when mocked in tests).
            dispatch.connect_via_ecs_exec(
                ecs_cluster, container_id, shell=_workspace_shell(ws), harness=harness, new=new
            )
            return
        ui.error(
            f"warren connect has no direct attach path for runtime_type={remote.runtime_type!r} yet.\n"
            f"To attach manually (if you have your own access to the server host):\n"
            f"  podman exec -it {container_id[:12]} tmux attach -t main"
        )
        raise typer.Exit(1)
    if cfg.defaults.mode == "local":
        wid = workspace_id or workspaces_local.pick_workspace("Select workspace to connect")
        workspaces_local.connect_local(wid, harness=harness, new=new)
        return
    ui.error("server-mode workspace connect requires the sidecar PTY — available in Phase 4")
    raise typer.Exit(1)


@app.command("tunnel")
def workspaces_tunnel(
    workspace_id: str = typer.Argument(help="Workspace ID or short prefix (ECS-backed workspaces only)"),
    remote_port: Optional[int] = typer.Argument(
        None, metavar="[PORT]", help="Port inside the workspace (default: an agent workspace's ACP port)"
    ),
    port: Optional[int] = typer.Option(None, "--port", help="Port to reach inside the workspace"),
    local_port: Optional[int] = typer.Option(
        None, "--local-port", help="Local port to bind (defaults to --port)"
    ),
    server: Optional[str] = typer.Option(
        None, "--server", help="Remote warren-server profile name (omit for interactive picker)"
    ),
    config: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Port-forward a local port to a port inside an ECS-backed workspace, via
    the same SSM channel ECS Exec already uses (`enableExecuteCommand`) —
    no server-side relay, protocol-agnostic (this command has no idea what's
    listening on --port; it could be an HTTP server, a raw socket, anything).

    Blocks in the foreground until interrupted — same lifecycle as
    `aws ssm start-session`.

    An agent workspace (AM3) serves one ACP endpoint on loopback; with no port
    given, the tunnel goes to it.

    Example: warren tunnel ws-abc123 8420 --server prod
             # then point a client at localhost:8420
    """
    if port is not None and remote_port is not None and port != remote_port:
        ui.error(f"two different ports given ({remote_port} and --port {port})")
        raise typer.Exit(2)
    port = port if port is not None else remote_port
    cfg = _load_cfg(config)
    if not server:
        server = _pick_remote_interactively(cfg)
    remote = cfg.get_remote(server)

    async def _get_workspace() -> dict:
        async with make_remote_client(remote, timeout=5.0) as c:
            r = await c.get("/workspaces")
            r.raise_for_status()
            workspaces = r.json()
        if not workspaces:
            return {}
        return _match_remote_workspace(workspaces, workspace_id)

    try:
        ws = asyncio.run(_get_workspace())
        container_id = ws.get("container_id")
    except typer.Exit:
        # _get_container_id's own not-found/ambiguous-prefix error (via
        # _match_remote_workspace) already printed a clear message.
        raise
    except Exception as exc:
        target = remote.url or remote.ssh_host or f"ecs:{remote.ecs_cluster}/{remote.ecs_service}"
        ui.error(f"warren-server unreachable at {target}: {exc}")
        raise typer.Exit(1)
    if not container_id:
        ui.error(f"workspace {workspace_id!r} not found on {server}, or has no ECS task ARN")
        raise typer.Exit(1)
    if port is None:
        port = ws.get("acp_port")
        if not isinstance(port, int):
            ui.error(f"workspace {workspace_id!r} is not an agent workspace; give the port to reach")
            raise typer.Exit(2)

    # `cfg` (WarrenCLIConfig) has no `ecs_cluster` attribute at all -- the
    # getattr fallback below always missed, silently ignoring whatever this
    # remote profile actually declared (audit 2026-10-16 #35). The profile's
    # own `ecs_cluster` is the one `RemoteProfile.model_post_init` already
    # requires for runtime_type="ecs" remotes; prefer it over the env var.
    ecs_cluster = remote.ecs_cluster or _os.environ.get("WARREN_ECS_CLUSTER", "")
    if not ecs_cluster:
        ui.error("no ECS cluster configured — set WARREN_ECS_CLUSTER or [defaults] ecs_cluster in config.toml")
        raise typer.Exit(1)

    dispatch._tunnel_via_execvp(
        {"runtime_type": "ecs", "container_id": container_id, "ecs_cluster": ecs_cluster, "workspace_id": workspace_id},
        remote_port=port,
        local_port=local_port,
    )


# ---------------------------------------------------------------------------
# secrets
# ---------------------------------------------------------------------------

@secrets_app.command("add")
def secrets_add(
    name: str = typer.Argument(help="Secret name"),
    project: str = typer.Option(..., "--project", help="Project name"),
) -> None:
    """Add a secret to a project's local secrets.env (interactive prompt)."""
    entered = typer.prompt(
        f"Value for {name}", hide_input=True, confirmation_prompt=True
    )
    SecretLoader.add_local(
        project_name=project,
        secret_name=name,
        value=entered,
        projects_dir=PROJECTS_DIR,
    )
    ui.ok(f"Secret '{name}' added to project '{project}'.")


@secrets_app.command("list")
def secrets_list(
    project: str = typer.Option(..., "--project", help="Project name"),
    output_json: bool = typer.Option(False, "--json", help="Output secret names as a JSON array."),
) -> None:
    """List secret names for a project (never values)."""
    names = SecretLoader.list_local(project, PROJECTS_DIR)
    if output_json:
        typer.echo(json.dumps(names))
        return
    if not names:
        typer.echo(f"No secrets defined for project '{project}'.")
        return
    for n in names:
        typer.echo(n)


@secrets_app.command("delete")
def secrets_delete(
    name: str = typer.Argument(help="Secret name"),
    project: str = typer.Option(..., "--project", help="Project name"),
) -> None:
    """Delete a secret from a project's local secrets.env."""
    removed = SecretLoader.delete_local(project, name, PROJECTS_DIR)
    if not removed:
        ui.error(f"Secret '{name}' not found in project '{project}'.")
        raise typer.Exit(1)
    ui.ok(f"Secret '{name}' deleted from project '{project}'.")


@secrets_app.command("rotate")
def secrets_rotate(
    name: str = typer.Argument(help="Secret name"),
    project: Optional[str] = typer.Option(None, "--project", help="Project name (local secrets.env)"),
    server: Optional[str] = typer.Option(None, "--server", help="Rotate in a remote warren-server's store"),
    reencrypt_only: bool = typer.Option(
        False, "--reencrypt-only", help="With --server: keep the value, re-encrypt it under the current key."
    ),
    config: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Replace an existing secret's value (prompted, never echoed).

    Running workspaces keep the old value until they are reprovisioned.
    """
    if (project is None) == (server is None):
        ui.error("pass exactly one of --project (local) or --server (remote)")
        raise typer.Exit(1)
    if reencrypt_only and server is None:
        ui.error("--reencrypt-only applies to --server only (local secrets.env is not encrypted)")
        raise typer.Exit(1)

    if project is not None:
        if name not in SecretLoader.list_local(project, PROJECTS_DIR):
            ui.error(f"Secret '{name}' not found in project '{project}'.")
            raise typer.Exit(1)
        entered = typer.prompt(f"New value for {name}", hide_input=True, confirmation_prompt=True)
        SecretLoader.add_local(
            project_name=project, secret_name=name, value=entered, projects_dir=PROJECTS_DIR
        )
        ui.ok(f"Secret '{name}' rotated in project '{project}'.")
        return

    cfg = _load_cfg(config)
    try:
        remote = cfg.get_remote(server)
    except KeyError as e:
        ui.error(str(e))
        raise typer.Exit(1) from e
    body = None
    if not reencrypt_only:
        body = {"value": typer.prompt(f"New value for {name}", hide_input=True, confirmation_prompt=True)}

    async def _rotate() -> httpx.Response:
        async with make_remote_client(remote) as c:
            return await c.post(f"/secrets/{name}/rotate", json=body)

    try:
        resp = asyncio.run(_rotate())
    except httpx.HTTPError as e:
        ui.error(f"request failed: {type(e).__name__}")
        raise typer.Exit(1) from e
    if resp.status_code == 404:
        ui.error(f"Secret '{name}' not found on {server}.")
        raise typer.Exit(1)
    if resp.status_code != 204:
        ui.error(f"warren-server returned HTTP {resp.status_code}")
        raise typer.Exit(1)
    verb = "re-encrypted" if reencrypt_only else "rotated"
    ui.ok(f"Secret '{name}' {verb} on {server}.")


# ---------------------------------------------------------------------------
# server profile management
# ---------------------------------------------------------------------------

@server_app.command("add")
def server_add(
    name: str = typer.Argument(help="Profile name"),
    url: str = typer.Argument(help="Server URL"),
    token: Optional[str] = typer.Option(
        None,
        "--token",
        help=(
            "Auth token. Omit this and you'll be prompted for it with hidden input "
            "(recommended -- a token passed on the command line lands in shell history "
            "and is visible to other users via `ps`); only pass --token for scripting/CI."
        ),
    ),
    config: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Add a warren-server connection profile."""
    config_path = config or Path.home() / ".warren" / "config.toml"
    if not config_path.exists():
        ui.error("No config found. Run 'warren init' first.")
        raise typer.Exit(1)
    if token is None:
        token = typer.prompt("Auth token", hide_input=True)
    if is_insecure_http_url(url):
        ui.warn(
            f"{url!r} is plaintext http:// and not localhost -- the bearer token will be "
            "readable by anyone on the network path. Prefer an https:// URL if this server "
            "supports one."
        )
    data = read_config_toml(config_path)
    servers = data.setdefault("servers", {})
    if name in servers:
        ui.error(f"Profile '{name}' already exists. Edit {config_path} to update it.")
        raise typer.Exit(1)
    servers[name] = {"url": url, "auth_token": token}
    write_config_toml(config_path, data)
    ui.ok(f"Profile '{name}' added.")


@server_app.command("use")
def server_use(
    name: str = typer.Argument(help="Profile name to set as default"),
    config: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Set the default `[servers.*]` profile (what `warren.get_profile(None)` resolves to).

    This is the top-level `default_server` key, not `[defaults] server` (a separate,
    unrelated field) -- the previous version of this command pointed at the wrong key
    and never actually wrote anything. Note this only affects the `[servers.*]`/
    `ServerProfile` namespace; none of the CLI's remote-facing commands (which all take
    `--server <name>` meaning a `[remotes.*]` entry) consult `default_server` today.
    """
    config_path = config or Path.home() / ".warren" / "config.toml"
    if not config_path.exists():
        typer.echo(f"No config found at {config_path}. Run 'warren init' first.", err=True)
        raise typer.Exit(1)
    data = read_config_toml(config_path)
    servers = data.get("servers", {})
    if name not in servers:
        typer.echo(
            f"Server profile '{name}' not found in {config_path} "
            f"(known profiles: {sorted(servers)}). Add it first with 'warren server add'.",
            err=True,
        )
        raise typer.Exit(1)
    data["default_server"] = name
    write_config_toml(config_path, data)
    typer.echo(f"Default server set to '{name}'.")


# ---------------------------------------------------------------------------
# project management (local file-based)
# ---------------------------------------------------------------------------

_PROJECT_TEMPLATE = """\
name: {name}
description: ""
repo: {repo}
bare_path: {projects_dir}/{name}/.git-store

# Image used for Podman/Docker runtimes.
# For local nsjail mode, tools come from the host PATH + workspace venv.
# Extension images (e.g. Claude Code, CUDA) aren't published by warren --
# build and tag them yourself from the Dockerfiles under images/
# (e.g. images/warren-base-claude-code/Dockerfile) and reference your own tag below.
docker_image: ghcr.io/scottcowan/warren-docker-base:latest

# Persistent mounts — survive workspace destroy/recreate.
# knowledge/refs: ingested external docs (API specs, crawled pages) — lives outside the repo.
# knowledge/wiki: project notes mirroring code structure — lives IN the repo (no mount needed).
mounts:
  - host: {projects_dir}/{name}/knowledge/refs
    container: /workspace/knowledge/refs
    mode: rw

# Secrets referenced by name — values stored in warren secret store. A
# template only gets exactly the secret names it declares here (resolved
# against the caller's own secrets, per-owner isolated) -- nothing else.
# secrets:
#   - name: GITHUB_TOKEN

# Templates — each is a sub-template of the project above (and can nest its own
# `templates:` in turn). A child inherits everything above unless it overrides it;
# mounts/secrets/docker_networks are additive, not replaced. Provision with
# `warren new {name} <template>` — dotted for a nested one, e.g. develop.claude.
templates:
  observe:
    description: Browse code, ask questions, view logs
    # app: the command run when you 'warren connect' to this template
    app: zsh

  develop:
    description: Normal development work
    app: zsh
    # Uncomment to add a nested Claude Code variant: `warren new {name} develop.claude`
    # (build images/warren-base-claude-code/Dockerfile yourself first and tag it --
    # warren doesn't publish this one, see the docker_image comment above)
    # templates:
    #   claude:
    #     description: Claude Code agent session
    #     docker_image: my-warren-claude-code:latest
    #     app: claude
"""


@project_app.command("add")
def project_add(
    name: str = typer.Argument(help="Project name (e.g. myproject)"),
    repo: Optional[str] = typer.Option(None, "--repo", help="Git remote URL"),
    config: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Add a project definition to ~/.warren/projects/."""
    projects_dir = PROJECTS_DIR
    projects_dir.mkdir(parents=True, exist_ok=True)

    project_file = projects_dir / f"{name}.yaml"
    if project_file.exists():
        typer.echo(f"Project '{name}' already exists at {project_file}")
        raise typer.Exit(0)

    if not repo:
        repo = typer.prompt(f"Git remote URL for {name}")

    # Create persistent dirs that live outside the repo
    refs_dir = projects_dir / name / "knowledge" / "refs"
    refs_dir.mkdir(parents=True, exist_ok=True)
    (projects_dir / name / "knowledge").mkdir(parents=True, exist_ok=True)

    project_file.write_text(
        _PROJECT_TEMPLATE.format(name=name, repo=repo, projects_dir=projects_dir)
    )
    ui.ok(f"Project '{name}' created at {project_file}")
    typer.echo(f"  Knowledge refs: {refs_dir}")
    typer.echo(f"  Edit {project_file} to configure templates, mounts, and secrets.")
    typer.echo(f"  Provision: warren new {name} observe")


@project_app.command("list")
def project_list(
    output_json: bool = typer.Option(False, "--json", help="Output projects as a JSON array."),
    config: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """List project definitions in ~/.warren/projects/."""
    projects_dir = PROJECTS_DIR
    if not projects_dir.exists() or not list(projects_dir.glob("*.yaml")):
        if output_json:
            typer.echo("[]")
            return
        typer.echo("No projects found. Add one with: warren project add <name>")
        raise typer.Exit(0)

    from warren_cli.machine_config import load_project  # noqa: PLC0415

    files = sorted(projects_dir.glob("*.yaml"))
    entries: list[dict] = []
    rows: list[tuple[str, str]] = []
    for f in files:
        try:
            project = load_project(f.stem, projects_dir)
            desc = project.description or ""
            entries.append({"name": f.stem, "description": desc})
            rows.append((f.stem, desc))
        except Exception as e:
            entries.append({"name": f.stem, "error": str(e)})
            rows.append((f.stem, f"(failed to load: {e})"))

    if output_json:
        typer.echo(json.dumps(entries))
        return
    ui.print_table(("NAME", "DESCRIPTION"), rows)


def _collect_secret_refs(project_cfg) -> set[str]:
    """Return every secret name declared anywhere in the project — root plus
    every nested template."""
    result: set[str] = set()

    def _walk(node) -> None:
        for ref in node.secrets:
            result.add(ref.name)
        for child in node.templates.values():
            _walk(child)

    _walk(project_cfg)
    return result


@project_app.command("sync")
def project_sync(
    name: Optional[str] = typer.Argument(default=None, help="Project name (omit when inside a workspace — inferred from WARREN_PROJECT)"),
    server: Optional[str] = typer.Option(None, "--server", help="Push local YAML to named remote warren-server via PUT /projects/{name}"),
    server_wide: bool = typer.Option(
        False, "--server-wide", help="Push as the shared server-wide project instead of your own user-scoped one (admin-only)."
    ),
    config: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Fetch latest changes for all repos in a project.

    Run this when you want fresh code before provisioning a workspace, or from
    inside a running workspace to pull upstream changes into the shared bare
    clone and reference clones. Worktrees are not touched — merging is up to you.

    When called from inside a workspace, project name is inferred automatically
    and only git-worktree bare clones and git-clone refs are fetched (not the
    active worktrees themselves, which may have local changes).
    """
    import asyncio as _asyncio
    from warren_cli.machine_config import load_project
    from warren_common.git import GitManager

    inside = bool(_os.environ.get("WARREN_PROJECT"))

    if inside:
        # Inside a workspace: infer project from env, allow running without exiting
        resolved_name = name or _os.environ.get("WARREN_PROJECT", "")
        if not resolved_name:
            ui.error("Cannot infer project name — pass it explicitly.")
            raise typer.Exit(1)
        real_home = Path(_os.environ.get("REAL_HOME", str(Path.home())))
        projects_dir = real_home / ".warren" / "projects"
    else:
        if not name:
            ui.error("Project name required outside a workspace.")
            raise typer.Exit(1)
        resolved_name = name
        projects_dir = PROJECTS_DIR

    project_file = projects_dir / f"{resolved_name}.yaml"
    if not project_file.exists():
        ui.error(f"Project '{resolved_name}' not found.")
        raise typer.Exit(1)

    if server:
        # Push local YAML to the named remote via PUT /projects/{name}
        cfg = _load_cfg(config)
        remote = cfg.get_remote(server)
        yaml_bytes = project_file.read_bytes()

        async def _get_detail():
            async with make_remote_client(remote) as c:
                r = await c.get(f"/projects/{resolved_name}")
                if r.status_code == 404:
                    return None
                r.raise_for_status()
                return r.json()

        detail = asyncio.run(_get_detail())

        if not server_wide:
            # Creation-time guard: don't let someone silently fork a server-wide
            # template they haven't overridden yet — surface it and let them
            # choose, rather than quietly creating a shadowing user-scoped copy.
            has_server_wide = detail is not None and detail.get("server_wide_yaml")
            has_user_scoped = detail is not None and detail.get("user_scoped_yaml")
            if has_server_wide and not has_user_scoped:
                use_existing = typer.confirm(
                    f"A server-wide template '{resolved_name}' already exists on {server}. "
                    f"Use it instead of creating your own?",
                    default=True,
                )
                if use_existing:
                    typer.echo(f"Using the existing server-wide template '{resolved_name}'.")
                    return

        params: dict[str, str] = {}
        if server_wide:
            params["server_wide"] = "true"
            if detail is not None and detail.get("server_wide_yaml"):
                params["expected_version"] = detail["server_wide_version"]

        async def _push():
            async with make_remote_client(remote) as c:
                return await c.put(
                    f"/projects/{resolved_name}",
                    content=yaml_bytes,
                    params=params,
                    headers={"Content-Type": "application/yaml"},
                )

        resp = asyncio.run(_push())
        if resp.status_code == 409:
            ui.error(
                f"push failed: the server-wide template changed since you last fetched it. "
                f"Run 'warren project promote {resolved_name} --server {server}' to review and resolve."
            )
            raise typer.Exit(1)
        if resp.status_code not in (200, 204):
            ui.error(f"push failed: HTTP {resp.status_code} — {resp.text}")
            raise typer.Exit(1)
        scope_desc = "server-wide" if server_wide else "your user-scoped"
        ui.ok(f"Project '{resolved_name}' pushed to {server} ({scope_desc}).")

        # Ingest secrets.env: push the value of every locally-stored secret that
        # the project (or one of its templates) actually declares via SecretRef.
        # The server stores secrets per-caller (routes/secrets.py) — this never
        # touches another user's secrets, and a --server-wide project push does
        # NOT make these secrets server-wide.
        from warren_common.loader import ProjectLoader as _PL  # noqa: PLC0415

        local_secret_names = SecretLoader.list_local(resolved_name, projects_dir)
        if local_secret_names:
            declared = _collect_secret_refs(_PL.load(project_file))
            local_values = SecretLoader.load_local(resolved_name, projects_dir)
            to_push = [name for name in local_secret_names if name in declared]
            skipped = [name for name in local_secret_names if name not in declared]

            if to_push and not typer.confirm(
                f"Push {len(to_push)} local secret(s) ({', '.join(to_push)}) to {server}?",
                default=False,
            ):
                typer.echo("Secrets not pushed.")
                return

            async def _push_secrets():
                pushed = 0
                async with make_remote_client(remote) as c:
                    for secret_name in to_push:
                        r = await c.put(
                            "/secrets",
                            json={"name": secret_name, "value": local_values[secret_name]},
                        )
                        if r.status_code == 204:
                            pushed += 1
                        else:
                            ui.error(f"secret '{secret_name}': push failed — HTTP {r.status_code} {r.text}")
                return pushed

            pushed = asyncio.run(_push_secrets())
            if pushed:
                typer.echo(f"Synced {pushed} secret(s) from secrets.env to {server}.")
            if skipped:
                typer.echo(
                    f"  {len(skipped)} local secret(s) not declared by any template, skipped: {', '.join(skipped)}"
                )
        return

    project = load_project(resolved_name, projects_dir)

    async def _sync():
        for folder in project.effective_folders():
            if folder.type == "git-worktree":
                typer.echo(f"  Fetching {folder.url}...")
                await GitManager.ensure_bare_for_repo(
                    project.name, folder.url, projects_dir, fetch=True
                )
            elif folder.type == "git-clone":
                typer.echo(f"  Fetching {folder.url} (ref)...")
                from warren_common.models import RepoSpec as _RS  # noqa: PLC0415
                _repo = _RS(url=folder.url, branch=folder.branch, type="reference")
                await GitManager.ensure_reference(resolved_name, _repo, projects_dir, fetch=True)

    _asyncio.run(_sync())
    ui.ok(f"Project '{resolved_name}' synced.")


@project_app.command("promote")
def project_promote(
    name: str = typer.Argument(help="Project name"),
    server: str = typer.Option(..., "--server", help="Remote warren-server profile name"),
    yes: bool = typer.Option(False, "--yes", help="Skip the diff confirmation prompt."),
    config: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Promote your user-scoped project to the server-wide one everyone shares.

    If a server-wide version already exists, prints a diff against your
    user-scoped version and asks for confirmation before overwriting it — a
    promotion never silently clobbers whatever another admin last published.
    """
    import difflib

    cfg = _load_cfg(config)
    remote = cfg.get_remote(server)

    async def _get_detail():
        async with make_remote_client(remote) as c:
            r = await c.get(f"/projects/{name}")
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r.json()

    detail = asyncio.run(_get_detail())
    if detail is None or not detail.get("user_scoped_yaml"):
        ui.error(f"No user-scoped project '{name}' found on {server} to promote.")
        raise typer.Exit(1)

    user_yaml = detail["user_scoped_yaml"]
    server_yaml = detail.get("server_wide_yaml")

    if server_yaml and server_yaml != user_yaml and not yes:
        typer.echo(f"\nDiff — current server-wide '{name}' vs. your version:\n")
        diff = difflib.unified_diff(
            server_yaml.splitlines(keepends=True),
            user_yaml.splitlines(keepends=True),
            fromfile="server-wide (current)",
            tofile="yours (proposed)",
        )
        typer.echo("".join(diff))
        if not typer.confirm(f"\nOverwrite the server-wide '{name}' with your version?"):
            typer.echo("Promotion cancelled.")
            raise typer.Exit(0)

    params: dict[str, str] = {"server_wide": "true"}
    if server_yaml:
        params["expected_version"] = detail["server_wide_version"]

    async def _put():
        async with make_remote_client(remote) as c:
            return await c.put(
                f"/projects/{name}",
                content=user_yaml.encode(),
                params=params,
                headers={"Content-Type": "application/yaml"},
            )

    resp = asyncio.run(_put())
    if resp.status_code == 409:
        ui.error("promote failed: the server-wide template changed since this check — re-run to retry.")
        raise typer.Exit(1)
    if resp.status_code == 403:
        ui.error("promote failed: admin privileges required to publish a server-wide template.")
        raise typer.Exit(1)
    if resp.status_code not in (200, 204):
        ui.error(f"promote failed: HTTP {resp.status_code} — {resp.text}")
        raise typer.Exit(1)
    ui.ok(f"'{name}' promoted to server-wide on {server}.")


@project_app.command("clone")
def project_clone(
    name: str = typer.Argument(help="Project name on the server"),
    server: str = typer.Option(..., "--server", help="Remote warren-server profile name"),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing local project file."),
    config: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Pull a server project down for local-mode use (`warren new <name> <template>`,
    no --server) -- e.g. a new team member getting set up on an existing project.

    Writes the project's STRUCTURE only (templates, folders, declared secret
    names) to ~/.warren/projects/<name>.yaml -- never secret VALUES. There is
    no server endpoint that returns a decrypted secret (by design: PUT writes
    one in, nothing ever reads one back out over HTTP), and local-mode git
    cloning doesn't need the server's secrets anyway -- it authenticates with
    YOUR OWN ambient local git/SSH setup, same as any other local git clone.
    Any other declared secret (e.g. GRAFANA_PASSWORD) still needs its own
    value added to the local secrets.env yourself (`warren secrets add`),
    same as any teammate would have to provide their own.
    """
    cfg = _load_cfg(config)
    remote = cfg.get_remote(server)

    projects_dir = PROJECTS_DIR
    project_file = projects_dir / f"{name}.yaml"
    if project_file.exists() and not force:
        ui.error(f"'{project_file}' already exists locally. Use --force to overwrite.")
        raise typer.Exit(1)

    async def _get():
        async with make_remote_client(remote) as c:
            r = await c.get(f"/projects/{name}")
            if r.status_code == 404:
                return None
            r.raise_for_status()
            return r.json()

    detail = asyncio.run(_get())
    if detail is None:
        ui.error(f"Project '{name}' not found on {server}.")
        raise typer.Exit(1)

    import yaml as _yaml  # noqa: PLC0415

    effective = detail["effective"]
    projects_dir.mkdir(parents=True, exist_ok=True)
    project_file.write_text(_yaml.safe_dump(effective, sort_keys=False))

    declared = sorted(_collect_secret_refs_from_dict(effective))
    ui.ok(f"Project '{name}' cloned from {server} to {project_file}")
    if declared:
        typer.echo(
            f"  Declares {len(declared)} secret(s) by name ({', '.join(declared)}) -- "
            f"add your own values to {projects_dir / name / 'secrets.env'} for local use."
        )
    typer.echo(f"  Provision locally: warren new {name} <template>")


@project_app.command("delete")
def project_delete(
    name: str = typer.Argument(help="Project name"),
    server: Optional[str] = typer.Option(
        None, "--server", help="Delete your own user-scoped project from this remote warren-server (DELETE /projects/{name}) instead of the local one."
    ),
    yes: bool = typer.Option(False, "--yes", "-y", help="Skip the confirmation prompt."),
    config: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Delete a project definition.

    Without --server, deletes the local ~/.warren/projects/<name>.yaml file.
    With --server, deletes your own user-scoped project on that remote
    warren-server instead -- it can never delete the shared server-wide
    project (the server enforces the same restriction on DELETE /projects/{name}
    that PUT does for server_wide=true, just with no opt-in: this endpoint only
    ever touches the caller's own user-scoped override).
    """
    if server:
        cfg = _load_cfg(config)
        remote = cfg.get_remote(server)
        if not yes and not typer.confirm(
            f"Delete your project '{name}' from {server}? This cannot be undone."
        ):
            typer.echo("Aborted.")
            raise typer.Exit(0)

        async def _delete():
            async with make_remote_client(remote) as c:
                return await c.delete(f"/projects/{name}")

        resp = asyncio.run(_delete())
        if resp.status_code == 404:
            typer.echo(
                f"Project '{name}' not found on {server} (you may not have a "
                f"user-scoped copy of it — only your own can be deleted this way).",
                err=True,
            )
            raise typer.Exit(1)
        if resp.status_code != 204:
            typer.echo(f"delete failed: HTTP {resp.status_code} — {resp.text}", err=True)
            raise typer.Exit(1)
        typer.echo(f"✓ Project '{name}' deleted from {server}.")
        return

    project_file = PROJECTS_DIR / f"{name}.yaml"
    if not project_file.exists():
        typer.echo(f"Project '{name}' not found.", err=True)
        raise typer.Exit(1)

    if not yes and not typer.confirm(
        f"Delete local project '{name}' at {project_file}? This cannot be undone."
    ):
        typer.echo("Aborted.")
        raise typer.Exit(0)

    project_file.unlink()
    typer.echo(f"✓ Project '{name}' deleted.")


def _collect_secret_refs_from_dict(node: dict) -> set[str]:
    """Same walk as _collect_secret_refs, but over a plain effective-project
    dict (from GET /projects/{name}'s `effective` field) rather than a
    ProjectConfig instance -- the server's JSON response, not a loaded model."""
    result: set[str] = set()

    def _walk(n: dict) -> None:
        for ref in n.get("secrets") or []:
            if isinstance(ref, dict) and ref.get("name"):
                result.add(ref["name"])
        for child in (n.get("templates") or {}).values():
            if isinstance(child, dict):
                _walk(child)

    _walk(node)
    return result


_FOLDER_ICON = {
    "git-worktree": "\U0001f527",  # wrench — editable checkout
    "git-clone": "\U0001f4d6",     # book — read/fetch reference
    "local-path": "\U0001f4c1",    # folder — direct host bind
}


def _render_project_tree(project) -> str:
    """Render the ~/ layout a workspace gets for this project, as a tree."""
    tree: dict = {}
    meta: dict[str, object] = {}
    for folder in project.effective_folders():
        parts = folder.mount.split("/")
        node = tree
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = None
        meta[folder.mount] = folder

    # rows: (tree_column_text, type_column_text, source_text) — aligned as a table.
    rows: list[tuple[str, str, str]] = []

    def _walk(node: dict, prefix: str, path: str) -> None:
        keys = sorted(node.keys())
        for i, key in enumerate(keys):
            is_last = i == len(keys) - 1
            connector = "└── " if is_last else "├── "
            child_path = f"{path}/{key}" if path else key
            folder = meta.get(child_path)
            if folder is not None:
                icon = _FOLDER_ICON.get(folder.type, "")
                src = folder.url or folder.path or ""
                rows.append((f"{prefix}{connector}{key}", f"{icon} {folder.type}", src))
            else:
                rows.append((f"{prefix}{connector}{key}/", "", ""))
            child = node[key]
            if isinstance(child, dict) and child:
                extension = "    " if is_last else "│   "
                _walk(child, prefix + extension, child_path)

    _walk(tree, "", "")

    tree_width = max((len(r[0]) for r in rows), default=0)
    type_width = max((len(r[1]) for r in rows), default=0)
    lines = [f"~/  ({project.name})"]
    for tree_col, type_col, src in rows:
        if not type_col:
            lines.append(tree_col)
            continue
        lines.append(f"{tree_col:<{tree_width}}  {type_col:<{type_width}}  {src}")
    return "\n".join(lines)


@project_app.command("show")
def project_show(
    name: str = typer.Argument(help="Project name"),
    yaml_out: bool = typer.Option(False, "--yaml", help="Print the raw YAML definition instead of the tree view."),
    output_json: bool = typer.Option(False, "--json", help="Output description/folders/templates as JSON."),
    config: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    """Show a project's workspace layout — what you get before spawning it."""
    project_file = PROJECTS_DIR / f"{name}.yaml"
    if not project_file.exists():
        ui.error(f"Project '{name}' not found. Run 'warren project list' to see available projects.")
        raise typer.Exit(1)
    if yaml_out:
        typer.echo(project_file.read_text())
        return

    from warren_cli.machine_config import load_project  # noqa: PLC0415
    from warren_common import list_template_paths, resolve_template  # noqa: PLC0415

    project = load_project(name, PROJECTS_DIR)
    paths = list_template_paths(project)
    templates = [
        {"path": path, "description": resolve_template(project, path, validate=False).description or ""}
        for path in paths
    ]

    if output_json:
        folders = [
            {"mount": f.mount, "type": f.type, "source": f.url or f.path or ""}
            for f in project.effective_folders()
        ]
        typer.echo(json.dumps({
            "name": name,
            "description": project.description or "",
            "folders": folders,
            "templates": templates,
        }))
        return

    if project.description:
        typer.echo(f"{project.description}\n")
    typer.echo(_render_project_tree(project))
    typer.echo("")
    typer.echo("Templates:")
    ui.print_table(("PATH", "DESCRIPTION"), [(t["path"], t["description"]) for t in templates])


# ---------------------------------------------------------------------------
# github-app (AK1: local token issuer)
# ---------------------------------------------------------------------------

github_app_cli = typer.Typer(
    no_args_is_help=True,
    help="Local GitHub App token issuer for local workspaces (key kept in the OS credential store).",
)
app.add_typer(github_app_cli, name="github-app")


@github_app_cli.command("set-key")
def github_app_set_key(
    key_file: Path = typer.Argument(..., help="The GitHub App's private key .pem (delete it after import)."),
    config: Optional[Path] = typer.Option(None, "--config", help="Path to config.toml"),
) -> None:
    """Store the GitHub App private key in the OS credential store."""
    from warren_cli.credential_store import CredentialStoreError, default_credential_store  # noqa: PLC0415

    cfg = _load_cfg(config)
    if cfg.github_app is None:
        ui.error("add a [github_app] section with app_id to the warren config first")
        raise typer.Exit(1)
    try:
        default_credential_store().set(
            cfg.github_app.key_service, cfg.github_app.app_id, key_file.read_bytes()
        )
    except (OSError, CredentialStoreError) as e:
        ui.error(f"could not store the key: {e}")
        raise typer.Exit(1) from e
    typer.echo(
        f"stored GitHub App {cfg.github_app.app_id} key in the OS credential store "
        f"({cfg.github_app.key_service}); you can now delete {key_file}"
    )
