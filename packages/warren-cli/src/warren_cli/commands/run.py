"""warren run — headless task runs on a warren-server (docs/runs.md).

    warren run <project>/<template> --prompt TEXT | --prompt-file PATH [--wait] [--json]
    warren run status <run-id> [--json]
    warren run result <run-id> [--json]
    warren run list [--all] [--json]

A run is a single-turn workspace started with a prompt: the template's app runs once,
headless, and the workspace is destroyed when it exits. Its result (status, times, exit
code, final message, git changes, pull request URLs) stays on the server.

Exit codes with --wait and for `result`: 0 succeeded, 1 failed, 124 timed out, 75 still
running when --wait-timeout ran out.
"""

from __future__ import annotations

import asyncio
import json
import sys
import time
import uuid
from pathlib import Path
from typing import Any

import click
import httpx
import typer
from typer.core import TyperGroup

from .. import ui
from ..client import make_remote_client

EXIT_FAILED = 1
EXIT_TIMED_OUT = 124
EXIT_STILL_RUNNING = 75
_FINAL = ("succeeded", "failed", "timed_out")


class _RunGroup(TyperGroup):
    """`warren run <project>/<template> ...` is `warren run start ...`."""

    def parse_args(self, ctx: click.Context, args: list[str]) -> list[str]:
        if args and not args[0].startswith("-") and args[0] not in self.commands:
            args = ["start", *args]
        return super().parse_args(ctx, args)


run_app = typer.Typer(
    cls=_RunGroup,
    no_args_is_help=True,
    help=(
        "Headless runs: start a template on a prompt, then read its result.\n\n"
        "Start one with: warren run <project>/<template> --prompt TEXT | --prompt-file PATH "
        "[--timeout S] [--wait] [--json] (see `warren run start --help`)."
    ),
)


# Indirection points so tests can drive polling with a fake clock.
async def _sleep(seconds: float) -> None:
    await asyncio.sleep(seconds)


def _clock() -> float:
    return time.monotonic()


def _remote(server: str | None, config: Path | None):
    from ..main import _load_cfg, _pick_remote_interactively

    cfg = _load_cfg(config)
    if not server:
        server = _pick_remote_interactively(cfg)
    try:
        return cfg.get_remote(server)
    except KeyError as e:
        ui.error(str(e))
        raise typer.Exit(1) from e


def _split_target(target: str, project: str | None) -> tuple[str, str]:
    if project:
        return project, target
    name, sep, template = target.partition("/")
    if not sep or not name or not template:
        ui.error("give the template as <project>/<template> (or pass --project)")
        raise typer.Exit(2)
    return name, template


def _read_prompt(prompt: str | None, prompt_file: Path | None) -> str:
    if (prompt is None) == (prompt_file is None):
        ui.error("pass exactly one of --prompt or --prompt-file")
        raise typer.Exit(2)
    if prompt_file is not None:
        try:
            text = sys.stdin.read() if str(prompt_file) == "-" else prompt_file.read_text()
        except OSError as e:
            ui.error(f"cannot read {prompt_file}: {e.strerror or e}")
            raise typer.Exit(2) from e
    else:
        text = prompt or ""
    if not text.strip():
        ui.error("the prompt is empty")
        raise typer.Exit(2)
    return text


def _http_error(resp: httpx.Response, what: str) -> None:
    if resp.status_code < 400:
        return
    if resp.status_code == 401:
        ui.error("authentication failed — check auth_token in ~/.warren/config.toml")
        raise typer.Exit(1)
    try:
        detail = resp.json().get("detail")
    except ValueError:
        detail = None
    if isinstance(detail, dict):
        detail = detail.get("detail") or detail.get("error")
    ui.error(f"{what}: HTTP {resp.status_code}" + (f" — {detail}" if detail else ""))
    raise typer.Exit(1)


async def _get(remote, path: str, *, timeout: float = 30.0) -> httpx.Response:
    async with make_remote_client(remote, timeout=timeout) as c:
        return await c.get(path)


def _exit_code(status: str) -> int:
    return {"succeeded": 0, "timed_out": EXIT_TIMED_OUT}.get(status, EXIT_FAILED)


async def _wait(remote, run_id: str, *, poll_interval: float, wait_timeout: float | None, quiet: bool) -> dict:
    """Poll GET /runs/{id} until the run finishes; return its result (or the last view)."""
    started = _clock()
    last_status = None
    while True:
        try:
            resp = await _get(remote, f"/runs/{run_id}")
        except httpx.TransportError as e:
            if not quiet:
                ui.warn(f"run {run_id[:8]}: server unreachable ({type(e).__name__}), retrying")
            resp = None
        if resp is not None:
            _http_error(resp, "run status")
            status = resp.json().get("status")
            if status != last_status and not quiet:
                ui.stderr.print(f"  {run_id[:8]}  {status}")
            last_status = status
            if status in _FINAL:
                result = await _get(remote, f"/runs/{run_id}/result")
                _http_error(result, "run result")
                return result.json()
        if wait_timeout is not None and _clock() - started + poll_interval > wait_timeout:
            return {"run_id": run_id, "status": last_status or "running"}
        await _sleep(poll_interval)


def _print_result(result: dict) -> None:
    status = result.get("status", "unknown")
    mark = {"succeeded": ui.OK, "running": "…"}.get(status, ui.FAIL)
    typer.echo(f"{mark} run {result.get('run_id', '')}  {status}")
    for key in ("project", "template", "started_at", "ended_at", "duration_seconds", "exit_code", "timeout_seconds"):
        if result.get(key) is not None:
            typer.echo(f"  {key.replace('_', ' ')}: {result[key]}")
    if result.get("error"):
        typer.echo(f"  error: {result['error']}")
    harness = result.get("harness_result") or {}
    if harness.get("total_cost_usd") is not None or harness.get("num_turns") is not None:
        typer.echo(f"  harness: turns {harness.get('num_turns')}, cost ${harness.get('total_cost_usd')}")
    for repo in result.get("git") or []:
        label = repo.get("mount") or "."
        if repo.get("error"):
            typer.echo(f"  git {label}: {repo['error']}")
            continue
        stat = repo.get("diffstat") or {}
        pushed = f", pushed to {repo['remote_branch']}" if repo.get("pushed") else ""
        typer.echo(
            f"  git {label}: {repo.get('branch') or '(detached)'}  {stat.get('files', 0)} files "
            f"+{stat.get('insertions', 0)} -{stat.get('deletions', 0)}{pushed}"
        )
        for f in (repo.get("changed_files") or [])[:20]:
            typer.echo(f"      {f.get('status', ''):<9} {f.get('path', '')}")
        more = len(repo.get("changed_files") or []) - 20
        if more > 0 or repo.get("changed_files_truncated"):
            typer.echo("      ...")
    for url in result.get("pull_requests") or []:
        typer.echo(f"  pull request: {url}")
    transcript = result.get("transcript")
    if transcript:
        kept = "kept" if transcript.get("retained") else "removed with the workspace"
        typer.echo(f"  transcript: {transcript.get('harness')} session {transcript.get('session_id')} ({kept})")
    for err in result.get("capture_errors") or []:
        ui.warn(f"capture: {err}")
    if result.get("final_message"):
        typer.echo("")
        typer.echo(result["final_message"])


@run_app.command("start", hidden=True)
def run_start(
    target: str = typer.Argument(help="<project>/<template> (or just <template> with --project)"),
    prompt: str | None = typer.Option(None, "--prompt", help="The task for the agent."),
    prompt_file: Path | None = typer.Option(None, "--prompt-file", help="Read the prompt from a file ('-': stdin)."),
    project: str | None = typer.Option(None, "--project", help="Project name, when TARGET is only the template."),
    timeout: float | None = typer.Option(None, "--timeout", min=1, help="Seconds before the server ends the run as timed out."),
    wait: bool = typer.Option(False, "--wait", help="Wait for the run to finish and print its result."),
    poll_interval: float = typer.Option(10.0, "--poll-interval", min=1, help="Seconds between status checks with --wait."),
    wait_timeout: float | None = typer.Option(None, "--wait-timeout", min=1, help="Stop waiting after this long (the run keeps going)."),
    output_json: bool = typer.Option(False, "--json", help="Print JSON (the run, or with --wait its result)."),
    server: str | None = typer.Option(None, "--server"),
    config: Path | None = typer.Option(None, "--config"),
) -> None:
    """Start a headless run of a template on a prompt."""
    project_name, template = _split_target(target, project)
    text = _read_prompt(prompt, prompt_file)
    remote = _remote(server, config)
    body: dict[str, Any] = {
        "project": project_name,
        "template": template,
        "prompt": text,
        # One operationId for every attempt, so a retried POST can't start a second run.
        "operationId": f"cli-run-{uuid.uuid4().hex}",
    }
    if timeout is not None:
        body["timeout_seconds"] = timeout

    async def _start() -> httpx.Response:
        for attempt in range(3):
            try:
                async with make_remote_client(remote, timeout=180.0) as c:
                    return await c.post("/runs", json=body)
            except httpx.TransportError:
                if attempt == 2:
                    raise
                await _sleep(1.0)
        raise AssertionError("unreachable")

    try:
        resp = asyncio.run(_start())
    except httpx.TransportError as e:
        ui.error(f"warren-server unreachable: {e}")
        raise typer.Exit(1) from e
    _http_error(resp, "run failed to start")
    run = resp.json()
    run_id = run["run_id"]
    if not wait:
        if output_json:
            typer.echo(json.dumps(run, indent=2))
        else:
            typer.echo(run_id)
            ui.stderr.print(f"  started {project_name}/{template}; `warren run result {run_id[:8]}` when done")
        return
    try:
        result = asyncio.run(
            _wait(remote, run_id, poll_interval=poll_interval, wait_timeout=wait_timeout, quiet=output_json)
        )
    except httpx.TransportError as e:
        ui.error(f"warren-server unreachable: {e}")
        raise typer.Exit(1) from e
    if output_json:
        typer.echo(json.dumps(result, indent=2))
    else:
        _print_result(result)
    status = result.get("status")
    if status not in _FINAL:
        if not output_json:
            ui.warn(f"run {run_id} is still running; check later with `warren run result {run_id}`")
        raise typer.Exit(EXIT_STILL_RUNNING)
    raise typer.Exit(_exit_code(status))


def _resolve_id(remote, run_id: str) -> str:
    """A full id, or a unique prefix of one of the caller's recent runs."""
    if len(run_id) >= 32:
        return run_id
    resp = asyncio.run(_get(remote, "/runs?limit=500"))
    _http_error(resp, "list runs")
    matches = [r["run_id"] for r in resp.json() if r.get("run_id", "").startswith(run_id)]
    if run_id in matches:
        return run_id
    if len(matches) == 1:
        return matches[0]
    if len(matches) > 1:
        ui.error(f"ambiguous run id {run_id!r} matches {matches}")
        raise typer.Exit(1)
    return run_id


@run_app.command("status")
def run_status(
    run_id: str = typer.Argument(help="Run id (or a unique prefix)"),
    output_json: bool = typer.Option(False, "--json"),
    server: str | None = typer.Option(None, "--server"),
    config: Path | None = typer.Option(None, "--config"),
) -> None:
    """Show a run's status."""
    remote = _remote(server, config)
    resp = asyncio.run(_get(remote, f"/runs/{_resolve_id(remote, run_id)}"))
    _http_error(resp, "run status")
    data = resp.json()
    if output_json:
        typer.echo(json.dumps(data, indent=2))
        return
    line = f"  {data['run_id']}  {data['project']}/{data['template']}  {data['status']}"
    if data.get("exit_code") is not None:
        line += f"  exit {data['exit_code']}"
    typer.echo(line)


@run_app.command("result")
def run_result(
    run_id: str = typer.Argument(help="Run id (or a unique prefix)"),
    output_json: bool = typer.Option(False, "--json", help="Print the result JSON (schema warren.run.result/v1)."),
    server: str | None = typer.Option(None, "--server"),
    config: Path | None = typer.Option(None, "--config"),
) -> None:
    """Show a run's result. Exits 0 succeeded, 1 failed, 124 timed out, 75 still running."""
    remote = _remote(server, config)
    resp = asyncio.run(_get(remote, f"/runs/{_resolve_id(remote, run_id)}/result"))
    _http_error(resp, "run result")
    result = resp.json()
    if output_json:
        typer.echo(json.dumps(result, indent=2))
    else:
        _print_result(result)
    status = result.get("status")
    raise typer.Exit(_exit_code(status) if status in _FINAL else EXIT_STILL_RUNNING)


@run_app.command("list")
def run_list(
    all_owners: bool = typer.Option(False, "--all", help="Every owner's runs (admin)."),
    output_json: bool = typer.Option(False, "--json"),
    server: str | None = typer.Option(None, "--server"),
    config: Path | None = typer.Option(None, "--config"),
) -> None:
    """List recent runs, newest first."""
    remote = _remote(server, config)
    resp = asyncio.run(_get(remote, "/runs" + ("?all=true" if all_owners else "")))
    _http_error(resp, "list runs")
    data = resp.json()
    if output_json:
        typer.echo(json.dumps(data, indent=2))
        return
    ui.print_table(
        ("RUN", "TEMPLATE", "STATUS", "EXIT", "STARTED"),
        [
            (r["run_id"][:8], f"{r['project']}/{r['template']}", r["status"],
             "" if r.get("exit_code") is None else r["exit_code"], ui.relative_time(r.get("started_at")))
            for r in data
        ],
    )
