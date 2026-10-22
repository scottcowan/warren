"""`warren doctor` — diagnose local environment (Plan 05b-06).

Synchronous by design (D-A8): one-shot diagnostic; asyncio buys nothing.
Always exits 0 so it's safe to run before `warren init`.
"""
from __future__ import annotations

import asyncio
import json as _json
import os
import re
import subprocess
from pathlib import Path
from typing import Callable, Optional

import httpx
import typer

from warren_common.runtime_detect import detect
from warren_common.images import ImageResolver

# Audit P2 #43: warren-base-claude-code has no publish workflow -- it's a
# build-it-yourself extension Dockerfile (images/warren-base-claude-code/), not
# an image warren actually publishes, so it doesn't belong in this list.
_CANONICAL_IMAGES = (
    "ghcr.io/scottcowan/warren-docker-base:latest",
)

Out = Callable[[str], None]

# AI6: minimum host harness versions for local (seatbelt/bwrap/nsjail)
# workspaces, which run the host's binary rather than an image pin. This is a
# floor, not the image pin: scripts/bump_pins.py moves the Dockerfile pins
# weekly; raise this by hand when warren starts depending on a newer feature.
# binary -> minimum "X.Y.Z"
_HARNESS_MIN_VERSIONS: dict[str, str] = {
    "claude": "2.1.0",
}
_SEMVER_RE = re.compile(r"(\d+)\.(\d+)\.(\d+)")


def _check_harnesses(out: Out = typer.echo) -> dict:
    """Warn when a host harness binary is older than its minimum. Never raises."""
    out("\nHarnesses (host binaries, used by local runtimes):")
    result: dict = {}
    for binary, minimum in _HARNESS_MIN_VERSIONS.items():
        entry: dict = {"minimum": minimum, "version": None, "ok": None}
        try:
            import shutil as _shutil  # noqa: PLC0415

            if _shutil.which(binary) is None:
                out(f"  {binary}: (not installed)")
            else:
                proc = subprocess.run(
                    [binary, "--version"], capture_output=True, text=True, timeout=10, check=False
                )
                m = _SEMVER_RE.search(proc.stdout or "")
                if m is None:
                    out(f"  {binary}: ⚠ could not parse `{binary} --version`")
                else:
                    found = tuple(int(g) for g in m.groups())
                    floor = tuple(int(g) for g in _SEMVER_RE.match(minimum).groups())  # type: ignore[union-attr]
                    entry["version"] = m.group(0)
                    entry["ok"] = found >= floor
                    marker = "✓" if entry["ok"] else f"⚠ below minimum {minimum}; upgrade it"
                    out(f"  {binary}: {m.group(0)}  {marker}")
        except Exception:
            out(f"  {binary}: ✗ error checking version")
        result[binary] = entry
    return result


def _check_ecs(cfg, cred_ok: bool = False, out: Out = typer.echo) -> dict:
    """Print an ECS Runtime section with aws CLI, SSM plugin, credentials, SSM path, and cluster checks.

    ``cred_ok`` should be passed from the caller to avoid a second STS round-trip.
    Never raises — all exceptions are caught per check so doctor() always exits 0.
    Returns a structured dict of the same facts, for `--json` mode.
    """
    out("\nECS Runtime:")
    result: dict = {}
    try:
        import shutil as _shutil
        aws_ok = _shutil.which("aws") is not None
        out(f"  aws CLI:                {'✓' if aws_ok else '✗ install from https://aws.amazon.com/cli/'}")
        ssm_ok = _shutil.which("session-manager-plugin") is not None
        out(f"  session-manager-plugin: {'✓' if ssm_ok else '✗ install from https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html'}")
        result["aws_cli"] = aws_ok
        result["session_manager_plugin"] = ssm_ok
    except Exception:
        out("  tool checks: ✗ error")
        aws_ok = False
        result["aws_cli"] = None
        result["session_manager_plugin"] = None

    # Use the cred_ok value from the caller to avoid a duplicate STS call.
    if aws_ok and not cred_ok:
        out("  AWS credentials:        ✗ run `aws sso login` or set AWS_ACCESS_KEY_ID")
        result["aws_credentials"] = False
    elif not aws_ok:
        out("  AWS credentials:        (skipped — aws CLI not installed)")
        result["aws_credentials"] = None
    else:
        out(f"  AWS credentials:        {'✓' if cred_ok else '✗ run `aws sso login` or set AWS_ACCESS_KEY_ID'}")
        result["aws_credentials"] = cred_ok

    server_id = getattr(cfg, "server_id", None) if cfg else None
    try:
        if cred_ok and server_id:
            import boto3 as _boto3
            ssm = _boto3.client("ssm")
            ssm_path = f"/warren/{server_id}/"
            ssm.describe_parameters(
                ParameterFilters=[{"Key": "Path", "Values": [ssm_path]}],
                MaxResults=1,
            )
            out(f"  SSM path: {ssm_path}  ✓")
            result["ssm_path"] = {"path": ssm_path, "ok": True}
        elif cred_ok:
            out("  SSM path:               (skipped — server_id not configured)")
            result["ssm_path"] = None
        else:
            out("  SSM path:               (skipped — no credentials)")
            result["ssm_path"] = None
    except Exception:
        ssm_path = f"/warren/{server_id}/" if server_id else "/warren/.../"
        out(f"  SSM path: {ssm_path}  ✗")
        result["ssm_path"] = {"path": ssm_path, "ok": False}

    ecs_cluster = getattr(cfg, "ecs_cluster", None) if cfg else None
    ecs_cluster = ecs_cluster or os.environ.get("WARREN_ECS_CLUSTER")
    try:
        if cred_ok and ecs_cluster:
            import boto3 as _boto3
            ecs_client = _boto3.client("ecs")
            resp = ecs_client.describe_clusters(clusters=[ecs_cluster])
            clusters = resp.get("clusters", [])
            if clusters:
                exec_cfg = clusters[0].get("configuration", {}).get("executeCommandConfiguration", {})
                logging_val = exec_cfg.get("logging", "NONE")
                exec_ok = logging_val in ("ENABLED", "OVERRIDE")
                marker = "✓" if exec_ok else "⚠"
                out(f"  ECS Exec logging ({ecs_cluster}): {marker} ({logging_val})")
                result["ecs_exec_logging"] = {"cluster": ecs_cluster, "logging": logging_val, "ok": exec_ok}
            else:
                out(f"  ECS Exec logging:       ✗ cluster not found: {ecs_cluster}")
                result["ecs_exec_logging"] = {"cluster": ecs_cluster, "error": "cluster not found"}
        elif cred_ok:
            out("  ECS Exec logging:       (skipped — ecs_cluster not configured)")
            result["ecs_exec_logging"] = None
        else:
            out("  ECS Exec logging:       (skipped — no credentials)")
            result["ecs_exec_logging"] = None
    except Exception:
        out("  ECS Exec logging:       ✗ error checking cluster")
        result["ecs_exec_logging"] = {"cluster": ecs_cluster, "error": "exception"}

    return result


def _check_efs(cfg, cred_ok: bool = False, out: Out = typer.echo) -> dict:
    """Print an EFS workspace persistence section with availability check.
    Never raises — all exceptions are caught per check so doctor() always exits 0.
    Returns a structured dict of the same facts, for `--json` mode.
    """
    out("\nEFS Workspace Persistence:")
    efs_id = getattr(cfg, "efs_id", "") if cfg else ""
    if not efs_id:
        out("  EFS persistence: (disabled — WARREN_EFS_ID not set)")
        return {"efs_id": None, "enabled": False}

    out(f"  File system:     {efs_id}")

    if not cred_ok:
        out("  EFS check:       (skipped — no AWS credentials)")
        return {"efs_id": efs_id, "enabled": True, "state": None}

    try:
        import boto3 as _boto3
        efs = _boto3.client("efs")
        resp = efs.describe_file_systems(FileSystemId=efs_id)
        filesystems = resp.get("FileSystems", [])
        if filesystems:
            lc_state = filesystems[0].get("LifeCycleState", "unknown")
            out(f"  EFS check:       {'✓' if lc_state == 'available' else f'✗ state={lc_state}'}")
            return {"efs_id": efs_id, "enabled": True, "state": lc_state}
        out(f"  EFS check:       ✗ file system {efs_id!r} not found")
        return {"efs_id": efs_id, "enabled": True, "state": None, "error": "not found"}
    except Exception:
        out("  EFS check:       ✗ error checking EFS file system")
        return {"efs_id": efs_id, "enabled": True, "state": None, "error": "exception"}


def _list_configured_aws_profiles() -> set[str]:
    """Profile names present in ~/.aws/config (does not require live creds)."""
    path = Path.home() / ".aws" / "config"
    if not path.exists():
        return set()
    profiles: set[str] = set()
    for line in path.read_text().splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            name = line[1:-1].strip()
            if name.startswith("profile "):
                name = name[len("profile "):].strip()
            profiles.add(name)
    return profiles


def _walk_template_aws_profiles(node, _prefix: str = ""):
    """Yield (dotted_path, profile) for every template node that explicitly
    declares an aws profile, recursing into nested templates."""
    for name, child in node.templates.items():
        path = f"{_prefix}{name}"
        profile = getattr(getattr(child, "aws", None), "profile", "") or ""
        if profile:
            yield path, profile
        yield from _walk_template_aws_profiles(child, _prefix=f"{path}.")


def _check_project_aws_profiles(cfg, out: Out = typer.echo) -> list[dict]:
    """Cross-check each project template's AWS profile against machine.toml's
    whitelist and against what's actually in ~/.aws/config — catches a
    project that was never set up on this machine (SC-portable-config).
    Never raises — all exceptions are caught so doctor() always exits 0.
    Returns the list of per-template findings, for `--json` mode.
    """
    out("\nProject AWS Profiles:")
    projects_dir = cfg.projects_path() if cfg else Path.home() / ".warren" / "projects"
    if not projects_dir.exists() or not list(projects_dir.glob("*.yaml")):
        out("  (no projects found)")
        return []

    from warren_cli.machine_config import load_project, known_aws_profiles

    whitelist = set(known_aws_profiles())
    configured = _list_configured_aws_profiles()

    findings: list[dict] = []
    for f in sorted(projects_dir.glob("*.yaml")):
        try:
            project = load_project(f.stem, projects_dir)
        except Exception:
            continue
        for template_path, profile in _walk_template_aws_profiles(project):
            if profile not in configured:
                status = "not_found_in_aws_config"
                marker = "✗ not found in ~/.aws/config"
            elif profile not in whitelist:
                status = "not_in_machine_toml_whitelist"
                marker = "⚠ not in ~/.warren/machine.toml known_profiles"
            else:
                status = "ok"
                marker = "✓"
            out(f"  {f.stem}/{template_path}: {profile}  {marker}")
            findings.append({
                "project": f.stem,
                "template": template_path,
                "profile": profile,
                "status": status,
            })

    if not findings:
        out("  (no templates declare an aws profile)")
    return findings


def _check_linux_sandbox(r, cfg, out: Out = typer.echo) -> dict:
    """WSL / AppArmor / drvfs checks for the Linux local sandbox (AC2).
    Never raises. Prints nothing off Linux-like hosts with nothing to report."""
    from warren_common import wsl  # noqa: PLC0415
    from warren_common.runtime.sandbox_env import state_root  # noqa: PLC0415

    wsl_version = getattr(r, "wsl_version", None)
    restricted = getattr(r, "apparmor_userns_restricted", False)
    bwrap_path = getattr(r, "bwrap_path", None)
    result: dict = {
        "wsl_version": wsl_version,
        "apparmor_userns_restricted": restricted,
        "bwrap_probe": None,
        "drvfs": [],
    }
    if wsl_version is None and not bwrap_path and not restricted:
        return result
    out("\nLinux sandbox:")
    if wsl_version == 1:
        out(f"  WSL: 1  ✗ {wsl.WSL1_REFUSAL}")
    elif wsl_version == 2:
        out("  WSL: 2  ✓ bubblewrap is the recommended local runtime")
    if restricted:
        out("  AppArmor userns restriction: on (kernel.apparmor_restrict_unprivileged_userns=1)")
    if bwrap_path:
        probe = wsl.probe_bwrap(bwrap_path)
        result["bwrap_probe"] = {"ok": probe.ok, "stderr": probe.stderr, "guidance": probe.guidance}
        if probe.ok:
            out("  bwrap self-test: ✓")
        else:
            out(f"  bwrap self-test: ✗ {probe.stderr or 'failed'}")
            if probe.guidance:
                for line in probe.guidance.splitlines():
                    out(f"    {line}")
    projects_dir = cfg.projects_path() if cfg else Path.home() / ".warren" / "projects"
    problems = wsl.drvfs_problems({
        "warren home": Path.home() / ".warren",
        "warren state dir": state_root(),
        "projects dir": projects_dir,
    })
    result["drvfs"] = problems
    for msg in problems:
        out(f"  ✗ {msg}")
    return result


def doctor(
    config: Optional[Path] = typer.Option(
        None, "--config", help="Override config path (default ~/.warren/config.toml)."
    ),
    output_json: bool = typer.Option(False, "--json", help="Output the full report as JSON."),
    verify_intent: Optional[str] = typer.Option(
        None,
        "--verify-intent",
        metavar="PROJECT/TEMPLATE",
        help="Provision a throwaway local workspace, check every read-only path refuses writes, destroy it. Exits 1 on a violation.",
    ),
) -> None:
    """Diagnose warren's local environment: runtimes, images, AWS SSO."""
    if verify_intent is not None:
        from warren_cli.commands.verify_intent import verify_intent as _verify  # noqa: PLC0415

        cfg = _try_load_cfg(config)
        if cfg is None:
            typer.echo("--verify-intent needs a warren config (run `warren init`)", err=True)
            raise typer.Exit(1)
        raise typer.Exit(_verify(verify_intent, cfg))
    out: Out = (lambda *_a, **_kw: None) if output_json else typer.echo
    report: dict = {}

    out("warren doctor\n")

    r = detect()
    out("Runtimes:")
    out(f"  Seatbelt (macOS): {'✓' if r.seatbelt else '✗'}")
    out(f"  Bubblewrap (Linux): {'✓' if r.bwrap else '✗'}")
    out(f"  nsjail (Linux): {'✓' if r.nsjail else '✗'}")
    out(f"  Docker: {'✓' if r.docker else '✗'}" + (f" ({r.docker_host})" if r.docker_host else ""))
    out(f"  ECS (AWS Fargate): {'✓' if r.ecs else '✗'}")
    if r.windows_build:
        out(f"  MXC (Windows {r.windows_build}, report only): {r.mxc_status} ({r.mxc_reason})")
    out(f"  recommended: {r.recommended}")
    if r.note:
        out(f"  note: {r.note}")
    out("")
    report["runtimes"] = {
        "seatbelt": r.seatbelt,
        "bwrap": r.bwrap,
        "nsjail": r.nsjail,
        "docker": r.docker,
        "ecs": r.ecs,
        "recommended": r.recommended,
        "docker_host": r.docker_host,
        "note": r.note,
        "mxc": r.mxc,
        "mxc_status": r.mxc_status,
        "mxc_reason": r.mxc_reason,
        "windows_build": r.windows_build,
        "wsl_version": getattr(r, "wsl_version", None),
    }

    cfg = _try_load_cfg(config)
    try:
        report["linux_sandbox"] = _check_linux_sandbox(r, cfg, out=out)
        out("")
    except Exception:
        pass  # preserve always-exits-0 invariant
    if cfg is not None:
        configured = getattr(getattr(cfg, "runtime", None), "type", "auto")
        out(f"Configured runtime: {configured}")
        resolver = ImageResolver.from_config(cfg)
    else:
        configured = None
        out("Configured runtime: (no config found — run `warren init`)")
        resolver = ImageResolver(mapping={})
    report["configured_runtime"] = configured

    out("\nImage resolution:")
    images: dict = {}
    for canonical in _CANONICAL_IMAGES:
        resolved = resolver.resolve(canonical)
        marker = "→" if resolved != canonical else "="
        out(f"  {canonical} {marker} {resolved}")
        images[canonical] = resolved
    report["images"] = images

    out("")
    aws_cred_ok = False
    aws_sso: Optional[bool] = None
    try:
        proc = subprocess.run(
            ["aws", "sts", "get-caller-identity", "--output", "json"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        aws_cred_ok = proc.returncode == 0
        aws_sso = aws_cred_ok
        out("AWS SSO: ✓ authenticated" if aws_cred_ok else "AWS SSO: ✗ run `aws sso login`")
    except FileNotFoundError:
        out("AWS CLI: not installed")
    except subprocess.TimeoutExpired:
        aws_sso = None
        out("AWS SSO: ✗ check timed out (>5s)")
    report["aws_sso"] = aws_sso

    try:
        report["ecs"] = _check_ecs(cfg, cred_ok=aws_cred_ok, out=out)
    except Exception:
        pass  # preserve always-exits-0 invariant

    try:
        report["efs"] = _check_efs(cfg, cred_ok=aws_cred_ok, out=out)
    except Exception:
        pass  # preserve always-exits-0 invariant

    try:
        report["project_aws_profiles"] = _check_project_aws_profiles(cfg, out=out)
    except Exception:
        pass  # preserve always-exits-0 invariant

    try:
        report["harnesses"] = _check_harnesses(out=out)
    except Exception:
        pass  # preserve always-exits-0 invariant

    try:
        report["remotes"] = asyncio.run(_check_remotes(cfg, out=out))
    except Exception:
        pass  # preserve always-exits-0 invariant (D-A8)

    if output_json:
        typer.echo(_json.dumps(report, indent=2, default=str))


def _try_load_cfg(path: Optional[Path]):
    """Load config if available; None on any error. `warren doctor` never fails."""
    try:
        from warren_cli.config import WarrenCLIConfig  # noqa: PLC0415

        return WarrenCLIConfig.load(path)
    except Exception:
        return None


async def _check_remotes(cfg, out: Out = typer.echo) -> dict:
    """Print a Remotes section showing /healthz status for each configured remote (D-08).

    Never raises — all exceptions are caught per remote so doctor() always exits 0.
    Returns a structured dict of the same facts, for `--json` mode.
    """
    out("\nRemotes:")
    if cfg is None or not hasattr(cfg, "remotes") or not cfg.remotes:
        out("  (not configured)")
        return {}

    async def _fetch_one(name: str, profile) -> tuple:
        try:
            async with httpx.AsyncClient(base_url=str(profile.url), timeout=5.0) as c:
                r = await c.get("/healthz")
                r.raise_for_status()
                return name, r.json()
        except Exception:
            return name, None

    results = await asyncio.gather(
        *[_fetch_one(n, p) for n, p in cfg.remotes.items()],
        return_exceptions=True,
    )
    remotes: dict = {}
    for result in results:
        if isinstance(result, Exception):
            out("  (error)")
            continue
        name, data = result
        if data is None:
            out(f"  {name}: offline")
            remotes[name] = {"online": False}
        else:
            rt = data.get("runtime", {})
            ws = data.get("workspaces", {})
            mark = "✓" if rt.get("reachable") else "✗"
            rt_type = rt.get("type", "unknown")
            n_run = ws.get("running", 0)
            n_tot = ws.get("total", 0)
            out(f"  {name}: online  {rt_type} {mark}  {n_run} running / {n_tot} total")
            remotes[name] = {
                "online": True,
                "runtime_type": rt_type,
                "reachable": bool(rt.get("reachable")),
                "running": n_run,
                "total": n_tot,
            }
    return remotes
