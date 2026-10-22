"""Local-mode dispatch: config.toml -> ProjectConfig -> WorkspaceSpec -> runtime.provision.

Keeps ``warren --help`` fast by deferring all runtime imports until a local
provision is actually requested (Pattern 5 in 02-RESEARCH.md).
"""

from __future__ import annotations

import asyncio
import collections
import contextlib
import importlib.resources
import json
import os
import posixpath
import re
import shlex
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import TYPE_CHECKING, Any, NoReturn

import structlog
import typer

from warren_common import SecretLoader, list_template_paths, resolve_template, winsupport
from warren_common.errors import TemplateNotFoundError
from warren_common.models import template_env_for
from warren_common.seed_prompt import seed_prompt_args

from warren_common.harness import (
    BEDROCK_ENV,
    CLAUDE,
    SERVER_HARNESS_ROOT,
    bedrock_mode,
    cloud_handoff_warnings,
    harness_env,
    selected_harnesses,
)
from warren_common.models import check_aws_mode
from warren_common.runtime.base import WorkspaceSpec, harness_spec_kwargs
from warren_common.runtime_detect import SANDBOX_EXEC_PATH

from . import ui

if TYPE_CHECKING:  # pragma: no cover
    from warren_common.runtime.base import ContainerRuntime, WorkspaceHandle

log = structlog.get_logger(__name__)

_IMAGE_ALLOW_RE = re.compile(r"^[A-Za-z0-9_./:@-]+$")


def _validate_image(image: str) -> str:
    """Reject shell metacharacters in image strings (T-05b-07/T-05b-21)."""
    if not image or not _IMAGE_ALLOW_RE.match(image):
        typer.echo(
            f"invalid image reference: {image!r} — must match {_IMAGE_ALLOW_RE.pattern}",
            err=True,
        )
        raise typer.Exit(1)
    return image


def get_runtime(cfg: Any) -> "ContainerRuntime":
    """Return a ContainerRuntime based on ``cfg.runtime.type``.

    Values: ``auto`` (call ``detect().recommended``), ``docker``, ``bwrap``,
    ``seatbelt``, ``nsjail``. Imports happen inside each branch to keep
    ``warren --help`` fast.
    """
    rt_type = getattr(getattr(cfg, "runtime", None), "type", None)
    if rt_type is None:
        # Back-compat: legacy tests pass an object with plain .mode.
        rt_type = "auto"

    if rt_type == "auto":
        from warren_common.runtime_detect import detect  # noqa: PLC0415

        detected = detect()
        recommended = detected.recommended
        # detect().recommended uses "bubblewrap"; normalise to "bwrap".
        if recommended == "bubblewrap":
            recommended = "bwrap"
        if recommended == "none":
            detail = f" ({detected.note})" if detected.note else ""
            typer.echo(
                f"no runtime available on this host{detail}; run `warren doctor`",
                err=True,
            )
            raise typer.Exit(1)
        rt_type = recommended

    import socket  # noqa: PLC0415

    if rt_type in ("nsjail", "bwrap"):
        from warren_common import wsl  # noqa: PLC0415

        if wsl.wsl_version() == 1:
            typer.echo(wsl.WSL1_REFUSAL, err=True)
            raise typer.Exit(1)
    if rt_type == "nsjail":
        from warren_common.runtime.nsjail import NsjailRuntime  # noqa: PLC0415

        return NsjailRuntime(server_id=socket.gethostname())
    if rt_type == "docker":
        from warren_common.runtime.docker import DockerRuntime  # noqa: PLC0415

        return DockerRuntime(server_id=socket.gethostname())
    if rt_type == "bwrap":
        from warren_common.runtime.bubblewrap import BubblewrapRuntime  # noqa: PLC0415

        return BubblewrapRuntime(server_id=socket.gethostname())
    if rt_type == "seatbelt":
        from warren_common.runtime.seatbelt import SeatbeltRuntime  # noqa: PLC0415

        return SeatbeltRuntime(server_id=socket.gethostname())
    raise ValueError(f"unknown runtime type: {rt_type!r}")


def _resolve_runtime_type(cfg: Any) -> str:
    rt_type = getattr(getattr(cfg, "runtime", None), "type", "auto")
    if rt_type == "auto":
        from warren_common.runtime_detect import detect  # noqa: PLC0415

        rt_type = detect().recommended
        if rt_type == "bubblewrap":
            rt_type = "bwrap"
    return rt_type


_CLAUDE_VERSION_RE = re.compile(r"^\s*(\d+\.\d+\.\d+)")


def _claude_version() -> str | None:
    """`claude --version`'s semver (e.g. "2.1.307 (Claude Code)" -> "2.1.307"),
    or None when the binary is missing or the output doesn't parse."""
    claude_bin = shutil.which("claude")
    if not claude_bin:
        return None
    try:
        out = subprocess.check_output([claude_bin, "--version"], text=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return None
    m = _CLAUDE_VERSION_RE.match(out)
    return m.group(1) if m else None


def _patch_claude_onboarding(claude_json: Path) -> None:
    """Mark onboarding done in the workspace's own `.claude.json` (AG3) so
    Claude Code doesn't show it inside the sandbox (it triggers when
    lastOnboardingVersion < current).

    Writes only when a flag isn't set or the parsed version differs, and
    never when the version can't be parsed. The write is atomic (same-dir
    temp file + rename, original mode kept); on any error the file is left
    untouched. The file is sandbox-writable, so a symlink there is never
    followed.
    """
    import tempfile

    if claude_json.is_symlink() or not claude_json.is_file():
        return
    version = _claude_version()
    if version is None:
        return
    target = claude_json
    try:
        cj = json.loads(target.read_text())
    except (OSError, ValueError):
        return
    if not isinstance(cj, dict):
        return
    updates: dict[str, Any] = {
        flag: True for flag in ("hasCompletedFirstRun", "hasCompletedOnboarding") if cj.get(flag) is not True
    }
    if cj.get("lastOnboardingVersion") != version:
        updates["lastOnboardingVersion"] = version
    if not updates:
        return
    cj.update(updates)
    try:
        mode = target.stat().st_mode & 0o7777
        fd, tmp = tempfile.mkstemp(dir=target.parent, prefix=".claude.json.tmp")
    except OSError:
        return
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(cj, f, indent=2)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode)
        os.replace(tmp, target)
    except OSError:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def _declared_local_secrets(
    project_name: str, template_path: str, secret_names: list[str], projects_dir: Path
) -> dict[str, str]:
    """Only the secrets the resolved template declares -- never the whole
    project secrets.env. Exits with a clear error if a declared name is unset."""
    available = SecretLoader.load_local(project_name, projects_dir)
    missing = [n for n in secret_names if n not in available]
    if missing:
        typer.echo(
            f"template {template_path!r} declares secret(s) not set for project "
            f"{project_name!r}: {', '.join(missing)}\n"
            f"add with: warren secrets add <NAME> --project {project_name}",
            err=True,
        )
        raise typer.Exit(1)
    return {n: available[n] for n in secret_names}


def _link_into_workspace(workspace_root: Path, mount: str, source: Path) -> None:
    """Symlink `workspace_root/mount` -> `source`, refusing any mount whose
    link location resolves outside the workspace (persisted specs may predate
    FolderSpec.mount validation)."""
    from warren_common.paths import ensure_within  # noqa: PLC0415

    link = workspace_root / mount
    if link.exists() or link.is_symlink():
        return
    ensure_within(workspace_root, link)
    link.parent.mkdir(parents=True, exist_ok=True)
    ensure_within(workspace_root, link)
    link.symlink_to(source)


_LOCAL_SANDBOX_RUNTIMES = ("seatbelt", "bwrap", "nsjail")


def _local_git_crypt_key(
    project_name: str, template: Any, secret_names: list[str], projects_dir: Path
) -> bytes | None:
    """AK2: the git-crypt key is read here, by the materializer, and never put in
    the workspace env. Only loaded for `git_crypt: unlock_and_drop`."""
    import base64  # noqa: PLC0415
    import binascii  # noqa: PLC0415

    from warren_common.git_crypt import GitCryptError, check_key_not_delivered  # noqa: PLC0415

    try:
        check_key_not_delivered(secret_names, template.git_crypt_key_secret)
    except GitCryptError as e:
        typer.echo(str(e), err=True)
        raise typer.Exit(1)
    if template.git_crypt != "unlock_and_drop":
        return None
    encoded = SecretLoader.load_local(project_name, projects_dir).get(template.git_crypt_key_secret)
    if not encoded:
        typer.echo(
            f"git_crypt: unlock_and_drop needs secret {template.git_crypt_key_secret!r} "
            f"(base64 of the git-crypt key)\nadd with: warren secrets add "
            f"{template.git_crypt_key_secret} --project {project_name}",
            err=True,
        )
        raise typer.Exit(1)
    try:
        return base64.b64decode(encoded, validate=True)
    except (binascii.Error, ValueError):
        typer.echo(f"secret {template.git_crypt_key_secret!r} is not valid base64", err=True)
        raise typer.Exit(1)


def _apply_local_git_crypt(worktree: Path, policy: str, key: bytes | None) -> None:
    from warren_common.git_crypt import GitCryptError, apply_git_crypt_policy  # noqa: PLC0415

    try:
        result = apply_git_crypt_policy(worktree, policy, key)  # type: ignore[arg-type]
    except GitCryptError as e:
        typer.echo(f"{worktree}: {e}", err=True)
        raise typer.Exit(1)
    if result.message:
        typer.echo(f"{worktree.name}: {result.message}", err=True)


def _local_git_credentials(
    cfg: Any, workspace_id: str, workspace_root: Path, folders: list, runtime_type: str
) -> dict[str, str]:
    """AK1 local issuer: when `[github_app]` is configured, install the git
    credential helper + gh wrapper for this workspace's GitHub repos and return
    the (token-free) env that wires them up."""
    section = getattr(cfg, "github_app", None)
    if section is None or runtime_type not in _LOCAL_SANDBOX_RUNTIMES:
        return {}
    from warren_common.github_tokens import TokenIssuerError, github_grants_for  # noqa: PLC0415

    from warren_cli import github_app  # noqa: PLC0415

    grants = github_grants_for(folders)
    if not grants:
        return {}
    try:
        port = github_app.ensure_local_endpoint()
    except (OSError, TokenIssuerError) as e:
        log.warning("github_credentials_endpoint_unavailable", error=str(e))
        return {}
    return github_app.setup_workspace_git_credentials(workspace_id, workspace_root, grants, port=port)


def _refresh_local_git_credentials(state: dict) -> None:
    if state.get("runtime_type") not in _LOCAL_SANDBOX_RUNTIMES:
        return
    workspace_id, root_path = state.get("workspace_id"), state.get("root_path")
    if not workspace_id or not root_path:
        return
    from warren_common.github_tokens import TokenIssuerError  # noqa: PLC0415

    from warren_cli import github_app  # noqa: PLC0415

    try:
        github_app.refresh_workspace_endpoint(workspace_id, Path(root_path))
    except (OSError, ValueError, TokenIssuerError) as e:
        log.warning("github_credentials_endpoint_unavailable", error=str(e))


_LOCAL_SANDBOXES = ("seatbelt", "bwrap", "nsjail")


def _local_harness_root(workspace_id: str) -> Path:
    """Inside the workspace's 0700 sandbox state dir, which the sandbox can't write."""
    from warren_common.runtime.sandbox_env import state_root  # noqa: PLC0415

    return state_root() / workspace_id / "harness"


def _prepare_local_harness_dirs(harnesses: Any, harness_root: str, *, bedrock: bool = False) -> None:
    """Seed the per-workspace harness dirs and copy credentials in (AG3). In
    bedrock mode no model login is handed over, and old copies are removed."""
    from warren_common.harness_config import (  # noqa: PLC0415
        copy_in_credentials,
        prepare_harness_dirs,
        remove_credentials,
    )

    home = Path.home()
    prepare_harness_dirs(harnesses, harness_root, home=home)
    if bedrock:
        remove_credentials(harnesses, harness_root)
    else:
        copy_in_credentials(harnesses, harness_root, home=home)
    if CLAUDE in harnesses:
        _patch_claude_onboarding(Path(harness_root) / CLAUDE / ".claude.json")


def write_turn_sessions(state: dict) -> str | None:
    """HIST-10: start a turn session (`.git/git-turn/session.json`) in each of a
    local workspace's worktrees. `git turn init` is left to the workspace:
    running it here would execute host git against workspace-writable config."""
    from warren_common.turn_refs import worktree_git_dir, write_session_file  # noqa: PLC0415

    session_id = str(uuid.uuid4())
    written = False
    for wt in state.get("worktree_paths", []):
        host_path = wt[0] if isinstance(wt, (list, tuple)) else str(wt)
        git_dir = worktree_git_dir(Path(host_path))
        if git_dir is None:
            continue
        try:
            write_session_file(git_dir, state.get("workspace_id", ""), session_id=session_id)
            written = True
        except OSError as e:
            log.warning("turn_session_write_failed", path=host_path, error=str(e))
    return session_id if written else None


def provision_local(
    project_name: str,
    template_path: str,
    projects_dir: Path,
    *,
    cfg: Any = None,
    runtime: "ContainerRuntime | None" = None,
    connect: bool = False,
    pin_green: bool = False,
) -> dict:
    """Build a WorkspaceSpec from disk state and hand it to the runtime.

    Git materialisation (bare / worktree / reference clones) happens inside
    ``_do()`` before ``runtime.provision``. ``--connect`` handoff via
    ``os.execvp`` runs AFTER ``asyncio.run`` has fully returned (D-05,
    Pitfall 2): the event loop's epoll/pipe fds must not leak into the
    exec'd process.
    """
    from warren_cli.machine_config import load_project  # noqa: PLC0415

    project = load_project(project_name, projects_dir)

    try:
        template = resolve_template(project, template_path)
    except TemplateNotFoundError:
        typer.echo(
            f"template {template_path!r} not found "
            f"(available: {list_template_paths(project)})",
            err=True,
        )
        raise typer.Exit(1)

    secret_names = list(dict.fromkeys(ref.name for ref in template.secrets))
    git_crypt_key = _local_git_crypt_key(project_name, template, secret_names, projects_dir)
    env = _declared_local_secrets(project_name, template_path, secret_names, projects_dir)
    env = {**template_env_for(template.env, exclude=env), **env}
    workspace_id = str(uuid.uuid4())

    # Inject a distinctive bash/zsh-fallback prompt so users know they're inside a
    # warren workspace even on a template whose `app` isn't zsh. A zsh workspace's
    # PROMPT is overridden by the shared banner asset (_warren_banner_zsh_text) --
    # this PROMPT env var only matters there as a pre-zshrc fallback.
    # Format: warren:project/template %  (zsh PROMPT / bash PS1)
    _prompt = f"warren:%F{{cyan}}{project_name}%f/%F{{yellow}}{template_path}%f %# "
    _ps1    = f"(warren:{project_name}/{template_path}) $ "
    env.setdefault("PROMPT", _prompt)   # zsh
    env.setdefault("PS1", _ps1)         # bash fallback
    env.setdefault("WARREN_PROJECT", project_name)
    env.setdefault("WARREN_TEMPLATE", template_path)
    env.setdefault("WARREN_WORKSPACE_ID", workspace_id)
    # Set HOME to workspace root so ~ = workspace and paths feel natural.
    # Keep REAL_HOME for accessing ~/.aws, ~/.ssh etc.
    env.setdefault("REAL_HOME", str(Path.home()))
    env.setdefault("NPM_CONFIG_USERCONFIG", str(Path.home() / ".npmrc"))
    env.setdefault("XDG_CONFIG_HOME", str(Path.home() / ".config"))
    # Pass through terminal identity so Claude Code doesn't show theme picker
    for _tvar in ("TERM", "TERM_PROGRAM", "TERM_PROGRAM_VERSION", "COLORTERM",
                  "TERMINFO", "TERMINFO_DIRS", "GHOSTTY_BIN_DIR", "GHOSTTY_RESOURCES_DIR"):
        _v = os.environ.get(_tvar)
        if _v:
            env.setdefault(_tvar, _v)
    resolved_runtime_type = _resolve_runtime_type(cfg) if cfg is not None else "nsjail"

    # AG3: each harness's config dir is the workspace's own, never the host's.
    harnesses = selected_harnesses(template.app, template.harnesses)
    local_harness_dirs = resolved_runtime_type in _LOCAL_SANDBOXES
    harness_root = (
        str(_local_harness_root(workspace_id)) if local_harness_dirs else SERVER_HARNESS_ROOT
    )
    env.update(harness_env(harnesses, harness_root))
    bedrock = bedrock_mode(template.model_access, env)
    if bedrock:
        env.update(BEDROCK_ENV)

    # AK3: only `aws.mode: sso` (local runtimes only) points the workspace at the
    # host's AWS config and SSO token cache. `export` (the default) gets the
    # profile's credentials from a host-side endpoint at connect time instead.
    aws = getattr(template, "aws", None)
    try:
        check_aws_mode(aws, resolved_runtime_type)
    except ValueError as exc:
        typer.echo(f"template {template_path!r}: {exc}", err=True)
        raise typer.Exit(1) from exc
    aws_sso_paths: list[Path] = []
    if aws is not None and aws.mode == "sso":
        aws_config = Path(aws.config_file or Path.home() / ".aws" / "config")
        aws_sso_cache = Path(aws.sso_cache or Path.home() / ".aws" / "sso" / "cache")
        env["AWS_CONFIG_FILE"] = str(aws_config)
        env["AWS_SSO_CACHE_DIR"] = str(aws_sso_cache)
        if aws.profile:
            env.setdefault("AWS_PROFILE", aws.profile)
        aws_sso_paths = [aws_config, aws_sso_cache]

    # Audit 2026-10-16 P2 #51: AWS_CONFIG_FILE above points at
    # real host paths (~/.aws) that nsjail/bwrap never bind-mounted
    # into the sandbox at all — the sandboxed process got an env var pointing
    # at a file it literally cannot see. nsjail/bwrap both mount reference
    # paths at the SAME absolute host path (never remapped), so mounting these
    # ro at their own real path is enough to make the env vars above actually
    # resolve inside the sandbox. ro: these are read for config/auth, never
    # written to by the sandboxed process.
    extra_reference_paths: list[tuple[str, str]] = []
    for aws_path in aws_sso_paths:
        if aws_path.exists():
            extra_reference_paths.append((str(aws_path), str(aws_path)))

    workspace_root = Path.home() / ".warren" / "workspaces" / workspace_id
    root_path = str(workspace_root)
    if resolved_runtime_type in _LOCAL_SANDBOX_RUNTIMES:
        from warren_common.runtime.sandbox_env import state_root  # noqa: PLC0415

        check_local_paths_not_on_drvfs({
            "warren home (config, tokens)": Path.home() / ".warren",
            "warren state dir (incl. harness credentials)": state_root(),
            "workspace root": workspace_root.parent,
            "projects dir": projects_dir,
        })
    bind_mounts = [(m.host, m.container, m.mode) for m in template.mounts]
    raw_image = template.docker_image

    # T-05b-21: reject shell metachars in image reference.
    image = _validate_image(raw_image)

    # D-26: apply [images] map override.
    if cfg is not None:
        from warren_common.images import ImageResolver  # noqa: PLC0415

        image = ImageResolver.from_config(cfg).resolve(image)

    # SSH: explicit opt-in only — no keys or agent unless the template declares ssh.
    ssh_cfg = getattr(template, "ssh", None)
    ssh_key_paths: list[str] = []
    ssh_agent_sock: str | None = None
    if ssh_cfg is not None:
        for raw_key in ssh_cfg.keys:
            expanded = str(Path(raw_key).expanduser())
            if Path(expanded).exists():
                ssh_key_paths.append(expanded)
            else:
                log.warning("ssh_key_not_found", path=expanded)
        if ssh_cfg.agent:
            sock = winsupport.ssh_agent_socket()
            if sock:
                ssh_agent_sock = sock
                env["SSH_AUTH_SOCK"] = sock
            else:
                log.warning("ssh_agent_requested_but_no_socket")

    pinned = _pin_green_commits(project.effective_folders()) if pin_green else {}

    async def _do() -> dict:
        from warren_common.git import GitManager  # noqa: PLC0415

        worktree_paths: list[tuple[str, str]] = []
        reference_paths: list[tuple[str, str]] = []
        git_store_paths: list[str] = []

        for folder in project.effective_folders():
            mount = folder.mount  # e.g. "code/acme-api", "refs/example-app", "wiki"

            if folder.type == "git-worktree":
                bare = await GitManager.ensure_bare_for_repo(
                    project.name, folder.url, projects_dir,
                    seed_from=folder.seed_from,
                    fetch=mount in pinned,
                )
                git_store_paths.append(str(bare))
                wt = await GitManager.add_worktree(
                    bare, workspace_root, folder.branch,
                    workspace_id=workspace_id,
                    intent=template_path,
                    subdir=mount,
                    start_point=pinned.get(mount),
                )
                _apply_local_git_crypt(wt, template.git_crypt, git_crypt_key)
                worktree_paths.append((str(wt), mount))

            elif folder.type == "git-clone":
                from warren_common.models import RepoSpec as _RS  # noqa: PLC0415
                _repo = _RS(url=folder.url, branch=folder.branch, type="reference")
                ref = await GitManager.ensure_reference(
                    project.name, _repo, projects_dir
                )
                _apply_local_git_crypt(Path(ref), "none", None)
                reference_paths.append((str(ref), mount))
                # Symlink into workspace so it's visible at ~/refs/...
                _link_into_workspace(workspace_root, mount, ref)

            elif folder.type == "local-path":
                # Expand ~ using REAL_HOME or home
                raw = folder.path or ""
                real_home = os.environ.get("REAL_HOME", str(Path.home()))
                host_path = Path(raw.replace("~", real_home)).expanduser()
                if host_path.exists():
                    _link_into_workspace(workspace_root, mount, host_path)
                    reference_paths.append((str(host_path), mount))
                else:
                    log.warning("local_path_not_found", path=str(host_path), folder=folder.name)

        env.update(
            _local_git_credentials(
                cfg, workspace_id, workspace_root, project.effective_folders(), resolved_runtime_type
            )
        )

        spec = WorkspaceSpec(
            workspace_id=workspace_id,
            project=project_name,
            intent=template_path,
            image=image,
            root_path=root_path,
            env=env,
            template_env=dict(template.env),
            secret_names=secret_names,
            ssh_key_paths=ssh_key_paths,
            ssh_agent_sock=ssh_agent_sock,
            bind_mounts=bind_mounts,
            worktree_paths=worktree_paths,
            reference_paths=reference_paths + extra_reference_paths,
            git_store_paths=git_store_paths,
            # Carries FolderSpec.readonly through to seatbelt profile generation
            # (audit finding #5) — keyed by `.mount` against worktree_paths/
            # reference_paths above, both built from this same effective_folders().
            folders=list(project.effective_folders()),
            app=template.app,
            harnesses=sorted(harnesses),
            custom_harness=template.custom_harness,
            harness_root=harness_root,
            model_access="bedrock" if bedrock else "",
            aws=aws,
            docker_networks=list(getattr(template, "docker_networks", []) or []),
        )

        log.info(
            "workspace_provision_attempted",
            workspace_id=workspace_id,
            project=project_name,
            intent=template_path,
            image=image,
            runtime_type=resolved_runtime_type,
            bind_mount_count=len(bind_mounts),
            worktree_count=len(worktree_paths),
            reference_count=len(reference_paths),
            docker_networks=len(spec.docker_networks),
        )

        rt = runtime if runtime is not None else get_runtime(cfg)
        handle = await rt.provision(spec)
        if local_harness_dirs:
            _prepare_local_harness_dirs(harnesses, harness_root, bedrock=bedrock)

        state: dict[str, Any] = {
            "workspace_id": workspace_id,
            "app": template.app,
            "runtime_type": resolved_runtime_type,
            "root_path": handle.root_path,
        }
        # seatbelt/bwrap/nsjail keep their sandbox.sb/state.json outside
        # root_path (handle.state_dir) — the sandboxed process has write
        # access to root_path, so a profile/argv/secrets stored there could be
        # rewritten by the sandboxed process itself and trusted on the next
        # `warren connect` (audit finding #1, R3). docker/ecs have no such
        # handle.state_dir — their state lives in the container runtime.
        state_dir = handle.state_dir or handle.root_path
        if resolved_runtime_type == "nsjail":
            state["nsjail_state_dir"] = state_dir
        elif resolved_runtime_type == "docker":
            state["container_id"] = handle.runtime_id
        elif resolved_runtime_type == "seatbelt":
            state["profile_path"] = str(Path(state_dir) / "sandbox.sb")
        elif resolved_runtime_type == "bwrap":
            # For bwrap the argv is derived at connect time from state.json on
            # disk (BubblewrapRuntime.exec pattern). Pass the state dir, not
            # the workspace dir (finding #1 — see comment above).
            state["bwrap_state_dir"] = state_dir
        elif resolved_runtime_type == "ecs":
            state["container_id"] = handle.runtime_id  # task ARN
            state["ecs_cluster"] = getattr(cfg, "ecs_cluster", "")
            # If ecs_cluster is empty, try WARREN_ECS_CLUSTER env var
            if not state["ecs_cluster"]:
                state["ecs_cluster"] = os.environ.get("WARREN_ECS_CLUSTER", "")

        # Merge in the full state.json so _connect_via_execvp has project/intent/worktrees
        state_json_path = Path(state_dir) / "state.json"
        if state_json_path.exists():
            try:
                state.update(json.loads(state_json_path.read_text()))
            except Exception:
                pass
        return state

    state = asyncio.run(_do())

    if connect:
        if template.seed_prompt:
            state["seed_prompt"] = template.seed_prompt
        _connect_via_execvp(state)
    return state


def _pin_green_commits(folders: list) -> dict[str, str]:
    """{mount: sha} for every GitHub git-worktree folder: the newest commit on
    its branch whose check-runs all passed (`--pin-green`). Exits if a folder
    can't be pinned rather than silently falling back to the branch tip."""
    from warren_cli import gh  # noqa: PLC0415

    pinned: dict[str, str] = {}
    for folder in folders:
        if folder.type != "git-worktree":
            continue
        repo = gh.github_repo(folder.url)
        if repo is None:
            typer.echo(f"--pin-green: {folder.mount} is not a GitHub repo ({folder.url})", err=True)
            raise typer.Exit(1)
        try:
            sha = gh.newest_green_commit(repo, folder.branch)
        except gh.GhError as exc:
            typer.echo(f"--pin-green: {repo}: {exc}", err=True)
            raise typer.Exit(1) from exc
        if sha is None:
            typer.echo(
                f"--pin-green: no recent commit on {repo}@{folder.branch} has all checks passing",
                err=True,
            )
            raise typer.Exit(1)
        typer.echo(f"  pinned ~/{folder.mount} to {sha[:12]} (last green on {folder.branch})", err=True)
        pinned[folder.mount] = sha
    return pinned


def _warren_alias_command() -> str:
    """The command the workspace's zshrc aliases `warren` to.

    Prefers `uv run --package warren --directory <repo>` when a real repo
    checkout is present (packages/warren-cli/src/warren_cli/dispatch.py is
    5 levels under the repo root). Once warren-cli is installed as a wheel
    (audit 2026-10-16 #35) there is no repo at all at that path, and that
    `uv run --package` invocation would just fail -- fall back to the
    already-resolved installed `warren` binary instead.
    """
    repo_candidate = Path(__file__).parent.parent.parent.parent.parent
    if (repo_candidate / "pyproject.toml").is_file():
        return f'uv run --package warren --directory "{repo_candidate}" -- warren'
    return shutil.which("warren") or "warren"


def _warren_banner_zsh_text() -> str:
    """The warren prompt/banner zsh snippet — shared with the baked-in
    ``.zshrc`` in warren's own remote images (images/warren-docker-base,
    packages/warren-server/images/ecs-base/Dockerfile). Reads
    WARREN_PROJECT/WARREN_TEMPLATE/WARREN_WORKSPACE_ID from the environment
    at shell-start time, so this one file is the single source of truth for
    both the locally-written workspace zshrc and the image-baked one.
    """
    return (
        importlib.resources.files("warren_common")
        .joinpath("assets/warren_banner.zsh")
        .read_text(encoding="utf-8")
    )


def _warren_banner_bash_text() -> str:
    """The warren prompt/banner bash snippet (R25) — bash sibling of
    ``_warren_banner_zsh_text``, same purpose: single source of truth for the
    locally-written workspace ``.bashrc``.

    ProjectConfig.app defaults to "bash" (warren_common/models.py), so a
    template that never sets `app` previously showed no banner/prompt at all
    on local connect -- the zshrc-generation block below only ever fired for
    app == "zsh". This closes that gap for the default case.
    """
    return (
        importlib.resources.files("warren_common")
        .joinpath("assets/warren_banner.bash")
        .read_text(encoding="utf-8")
    )


def _write_warren_owned(path: Path, text: str) -> None:
    """Replace a warren-owned file in the (sandbox-writable) workspace root
    without following anything the workspace left at that path."""
    if path.is_symlink() or path.exists():
        path.unlink()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o644)
    with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


@contextlib.contextmanager
def _parent_ignores_sigint():
    """Leave Ctrl-C to the foreground child: the parent must not die (and
    orphan the session) while it waits."""
    try:
        previous = signal.signal(signal.SIGINT, signal.SIG_IGN)
    except ValueError:  # not the main thread
        yield
        return
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous)


def _run_foreground(argv: list[str], env: dict[str, str] | None = None) -> int:
    # Spawn before ignoring SIGINT: on POSIX an ignored disposition is inherited.
    proc = subprocess.Popen(argv, env=env)
    with _parent_ignores_sigint():
        return proc.wait()


def _check_bwrap_before_hand_off(bwrap: str) -> None:
    """After execvp nothing can rewrite bwrap's raw "setting up uid map:
    Permission denied", so probe first and print the fix (e.g. the Ubuntu
    24.04 AppArmor profile) when namespaces are blocked (AC2). An
    unclassified probe failure falls through to the real launch."""
    from warren_common import wsl  # noqa: PLC0415

    probe = wsl.probe_bwrap(bwrap)
    if not probe.ok and probe.guidance:
        typer.echo(probe.guidance, err=True)
        raise typer.Exit(1)


def check_local_paths_not_on_drvfs(paths: dict[str, Path | str]) -> None:
    """Refuse when warren's state or a workspace root is on a Windows drive
    under WSL (drvfs / 9p, e.g. /mnt/c): Unix permissions aren't enforced
    there, so tokens, the secrets DB and sandbox profiles are unprotected (AC2)."""
    from warren_common import wsl  # noqa: PLC0415

    problems = wsl.drvfs_problems({k: str(v) for k, v in paths.items()})
    if problems:
        for msg in problems:
            typer.echo(f"refusing: {msg}", err=True)
        raise typer.Exit(1)


def _hand_off(file: str, argv: list[str], env: dict[str, str] | None = None) -> NoReturn:
    """Replace this process with ``argv`` on POSIX. On Windows ``execvp`` spawns
    a detached child and exits the parent, breaking the console and losing the
    exit code, so run it as a foreground child and exit with its code."""
    if not winsupport.is_windows():
        if env is None:
            os.execvp(file, argv)
        os.execvpe(file, argv, env)
    path = (env if env is not None else os.environ).get("PATH")
    resolved = shutil.which(file, path=path) or file
    raise typer.Exit(_run_foreground([resolved, *argv[1:]], env))


_TITLE_UNSAFE_RE = re.compile(r"[\x00-\x1f\x7f-\x9f]")


def terminal_title(project: str, template: str, workspace_id: str) -> str:
    label = f"{project or '?'}/{template or '?'}"
    short = (workspace_id or "")[:8]
    title = f"warren: {label} ({short})" if short else f"warren: {label}"
    return _TITLE_UNSAFE_RE.sub("", title)


def set_terminal_title(project: str, template: str, workspace_id: str, stream: Any = None) -> None:
    """Set the terminal/tab title via OSC 0 so several warren windows can be told
    apart (AH8). Labels come from server/state data, so control bytes are
    stripped. No-op off a TTY or with WARREN_NO_TERMINAL_TITLE set."""
    out = stream or sys.stdout
    if os.environ.get("WARREN_NO_TERMINAL_TITLE") or not getattr(out, "isatty", lambda: False)():
        return
    out.write(f"\x1b]0;{terminal_title(project, template, workspace_id)}\x07")
    out.flush()


def _connect_via_execvp(state: dict, *, harness: str | None = None, new: bool = False) -> NoReturn:
    """Replace the current process with the runtime-specific interactive shell.

    A user workspace (AG2a) always gets the warren shell, with the template's
    harnesses as shell commands; `harness` starts one inside it, resuming its
    conversation unless `new`.

    MUST be called from synchronous context AFTER ``asyncio.run`` has returned
    so the event loop's fds do not leak into the exec'd process (Pitfall 2).
    """
    from warren_common import harness_shell  # noqa: PLC0415
    from warren_common.runtime.sandbox_env import base_host_env  # noqa: PLC0415

    runtime_type = state.get("runtime_type", "nsjail")
    app = state["app"]
    harnesses = selected_harnesses(app, state.get("harnesses") or ())
    shell_first = harness_shell.shell_first(app)
    shell = harness_shell.workspace_shell(app) if shell_first else app
    if harness and harness not in harnesses:
        ui.error(f"harness {harness!r} is not in this workspace's template (harnesses: {sorted(harnesses) or 'none'})")
        raise typer.Exit(1)

    log.info(
        "dispatching_connect",
        workspace_id=state.get("workspace_id"),
        runtime_type=runtime_type,
        app=app,
    )
    _refresh_local_git_credentials(state)
    bedrock = _state_bedrock(state)
    if runtime_type in _LOCAL_SANDBOXES and state.get("harness_root"):
        _prepare_local_harness_dirs(harnesses, state["harness_root"], bedrock=bedrock)
    for warning in cloud_handoff_warnings(harnesses):
        typer.echo(warning, err=True)
    write_turn_sessions(state)
    set_terminal_title(state.get("project", ""), state.get("intent", ""), state.get("workspace_id", ""))
    sys.stdout.flush()
    sys.stderr.flush()

    _warren_invoke = _warren_alias_command()

    # Build the FULL env the sandboxed process will get — allow-list only
    # (audit finding #4). Previously this mutated os.environ, which os.execvp
    # then inherited WHOLESALE (operator's real os.environ, AWS keys/API
    # tokens/SSH_AUTH_SOCK and all), on top of these overrides rather than
    # instead of it. connect_env is now the ONLY env nsjail/docker/seatbelt get
    # (passed explicitly via execvpe) and the only overrides layered onto
    # bwrap's own env_snapshot-derived --setenv list (bwrap already clears its
    # child's env — see bubblewrap.py's --clearenv).
    connect_env: dict[str, str] = base_host_env()

    # Env comes only from the template-derived env_snapshot -- never from host
    # tool config such as ~/.claude/settings.json (BB6).
    env_snapshot = state.get("env_snapshot", {})
    for k, v in env_snapshot.items():
        connect_env[k] = v

    # WARREN_PROJECT/WARREN_TEMPLATE/WARREN_WORKSPACE_ID drive the shared
    # banner/prompt snippet (_warren_banner_zsh_text) read at shell-start
    # time inside the sandbox — force them from `state` itself rather than
    # only `env_snapshot`, since not every local runtime's state.json
    # carries an env_snapshot (e.g. nsjail) even though project/intent/
    # workspace_id are always present on `state`.
    connect_env.setdefault("WARREN_PROJECT", state.get("project", ""))
    connect_env.setdefault("WARREN_TEMPLATE", state.get("intent", ""))
    connect_env["WARREN_WORKSPACE_ID"] = state.get("workspace_id", "")

    # Set HOME to workspace root so ~ = workspace inside the sandbox.
    # REAL_HOME preserves access to ~/.claude, ~/.aws etc via $REAL_HOME.
    if "root_path" in state:
        connect_env["REAL_HOME"] = connect_env.get("HOME", str(Path.home()))
        connect_env["HOME"] = state["root_path"]

    # Write a minimal rc file into the workspace so the shell doesn't load
    # oh-my-zsh/user rc machinery (which tries to write ~/.cache/oh-my-zsh etc —
    # blocked by sandbox). ZDOTDIR redirects zsh dotfile loading to the workspace
    # dir; bash has no equivalent, so its rc file is sourced directly below.
    #
    # R25: ProjectConfig.app defaults to "bash" (warren_common/models.py), but this
    # block used to only ever fire for app == "zsh" -- a template that never set
    # `app` got NO banner/prompt/refs-listing/cd-nudge on local connect at all.
    # Generalized to cover both shells side by side rather than special-casing one
    # more shell name; the is_zsh split below only matters for the handful of
    # places zsh/bash syntax genuinely differs (autoload/setopt/chpwd vs
    # PROMPT_COMMAND, ZDOTDIR).
    is_zsh = shell in ("zsh", "/bin/zsh")
    is_bash = shell in ("bash", "/bin/bash")
    if (is_zsh or is_bash) and "root_path" in state:
        rc_name = ".zshrc" if is_zsh else ".bashrc"
        dynamic_name = ".warren_dynamic.zsh" if is_zsh else ".warren_dynamic.bash"
        workspace_rc = Path(state["root_path"]) / rc_name
        worktree_paths = state.get("worktree_paths", [])
        reference_paths = state.get("reference_paths", [])
        env_keys = [k for k in state.get("env_snapshot", {}) if not k.startswith(("PROMPT", "PS1"))]

        # Build git branch/ref annotations for worktrees and reference clones
        _branch_lines = []
        for wt in worktree_paths:
            host_path = wt[0] if isinstance(wt, (list, tuple)) else str(wt)
            container_path = wt[1] if isinstance(wt, (list, tuple)) and len(wt) > 1 else host_path
            _branch_lines.append(
                f"  _b=$(git -C {shlex.quote(host_path)} branch --show-current 2>/dev/null); "
                f"echo \"  {container_path}  (${{_b:-?}})\""
            )
        for ref in reference_paths:
            host_path = ref[0] if isinstance(ref, (list, tuple)) else str(ref)
            container_path = ref[1] if isinstance(ref, (list, tuple)) and len(ref) > 1 else host_path
            _branch_lines.append(
                f"  _b=$(git -C {shlex.quote(host_path)} rev-parse --abbrev-ref HEAD 2>/dev/null); "
                f"echo \"  {container_path}  (${{_b:-?}}) [ref]\""
            )
        _branch_script = "\n".join(_branch_lines)

        # Refs/tree listing is workspace-specific (needs host git access) so it
        # isn't part of the shared banner asset -- but it's appended to the SAME
        # always-regenerated file so it can never go stale either (audit finding:
        # the old write-if-missing .zshrc kept whatever labels/wording were
        # current the first time a workspace connected).
        _refs_block = (
            f"tree -L 2 --noreport -a -I "
            f"'.git|sandbox.sb|state.json|.zshrc|.bashrc|.warren_dynamic.zsh|"
            f".warren_dynamic.bash|.warren_harness.sh|.zcompdump*|.claude' "
            f"~ | sed 's/ -> .*//'  "
            f"\necho ''"
            f"\necho 'Refs:'"
            f"\n{_branch_script}"
            f"\necho ''"
        )

        # Regenerate the dynamic (banner + prompt + refs) portion on every
        # connect, not just when missing -- this is what used to go stale.
        #
        # Audit U2 (low severity): this file lives in state["root_path"] (the
        # sandbox-writable workspace root), not alongside sandbox.sb/state.json in the
        # trusted state_dir R3 established for exactly this class of concern. Left as-is
        # deliberately: unlike state.json's env_snapshot, this file is pure display
        # content (banner/prompt/refs listing, no secrets, nothing executed as code
        # beyond being sourced as shell text) that gets fully OVERWRITTEN here on every
        # single connect -- so there is no stale-content window for a sandboxed process
        # to launder tampered bytes through to a future trusted read, the exact
        # mechanism R3/W3 exist to close. Moving it to state_dir would also need a new
        # read-only mount point wired into every local runtime (seatbelt/nsjail/bwrap)
        # just so the in-sandbox shell could still `source` it -- disproportionate for a
        # file with no laundering risk to begin with.
        banner_text = _warren_banner_zsh_text() if is_zsh else _warren_banner_bash_text()
        dynamic_rc = Path(state["root_path"]) / dynamic_name
        _write_warren_owned(dynamic_rc, banner_text + "\n" + _refs_block + "\n")

        # The rc file is warren-owned: rewrite it from scratch on every connect
        # so rc files from older versions lose their env/secret exports (BB13).
        _root = state['root_path']
        _land = worktree_paths[0][0] if worktree_paths else _root
        if is_zsh:
            _preamble = "autoload -Uz compinit colors\ncolors\n"
            _hist = "HISTSIZE=1000\nSAVEHIST=0\nsetopt NO_HUP NO_CHECK_JOBS\n"
            _aliases_src = "aliases.zsh"
            # Audit #55: this is UX polish, not a security boundary — it only
            # nudges an interactive `cd` back inside $HOME. Any program that reads
            # or writes outside $HOME without `cd`-ing there first (or a subshell
            # that doesn't source this rc file) is completely unaffected by it.
            # Real confinement is the sandbox/container boundary, not this hook.
            _cd_nudge = (
                f"\n# UX only (not a security boundary — see #55): nudge interactive cd back to workspace root\n"
                f"function chpwd() {{\n"
                f"  case \"$PWD\" in\n"
                f"    \"$HOME\"*) ;;\n"
                f"    *) echo '⚠  warren: staying in workspace root' >&2\n"
                f"       cd \"$HOME\" ;;\n"
                f"  esac\n"
                f"}}\n"
            )
        else:
            _preamble = ""
            _hist = "HISTSIZE=1000\nHISTFILESIZE=0\nshopt -u huponexit\n"
            _aliases_src = "aliases.bash"
            # bash has no chpwd hook -- PROMPT_COMMAND is the closest equivalent,
            # re-run before every prompt rather than only on cd. Same UX-only
            # caveat as the zsh chpwd above (audit #55): not a security boundary.
            _cd_nudge = (
                f"\n# UX only (not a security boundary — see #55): nudge interactive cd back to workspace root\n"
                f"_warren_cd_nudge() {{\n"
                f"  case \"$PWD\" in\n"
                f"    \"$HOME\"*) ;;\n"
                f"    *) echo '⚠  warren: staying in workspace root' >&2\n"
                f"       cd \"$HOME\" ;;\n"
                f"  esac\n"
                f"}}\n"
                f"PROMPT_COMMAND=\"_warren_cd_nudge${{PROMPT_COMMAND:+; $PROMPT_COMMAND}}\"\n"
            )
        _rc = (
            f"# warren workspace {rc_name} — minimal, no oh-my-zsh/user rc machinery\n"
            f"{_preamble}"
            f"# HOME is set to workspace root — ~ = workspace\n"
            f"# REAL_HOME points to original home for dotfiles\n"
            f"export REAL_HOME=\"${{REAL_HOME:-{_root}}}\"\n"
            + _hist
            + f"[[ -f \"$REAL_HOME/.warren/{_aliases_src}\" ]] && source \"$REAL_HOME/.warren/{_aliases_src}\"\n"
            + _cd_nudge
            + f"\n# AWS SSO refresh — runs on host via REAL_HOME env\n"
            f"function aws-login() {{\n"
            f"  local session=${{1:-sso}}\n"
            f"  echo '  Open the URL above in your browser, then press Enter'\n"
            f"  HOME=\"$REAL_HOME\" AWS_CONFIG_FILE=\"$REAL_HOME/.aws/config\" \\\n"
            f"    aws sso login --sso-session \"$session\" --use-device-code\n"
            f"  echo '✓ SSO refreshed'\n"
            f"}}\n"
            f"\n# Start at workspace root (~)\n"
            f"cd '{_root}'\n"
            f"\n# warren CLI available inside sandbox (the `warren` shell function runs it)\n"
            f"WARREN_CLI={shlex.quote(_warren_invoke)}\n"
            f"\n# Banner/prompt + refs listing -- regenerated on every connect\n"
            f"[[ -f \"$HOME/{dynamic_name}\" ]] && source \"$HOME/{dynamic_name}\"\n"
            f"\n# Harness commands and `warren resume` (AG2a)\n"
            f"[[ -f \"$HOME/{_HARNESS_SH}\" ]] && source \"$HOME/{_HARNESS_SH}\"\n"
        )
        _write_warren_owned(workspace_rc, _rc)
        _write_warren_owned(Path(_root) / _HARNESS_SH, harness_shell.asset_text())
        # An older version may have left the other shell's rc too, exports and all.
        other_rc = Path(_root) / (".bashrc" if is_zsh else ".zshrc")
        if other_rc.is_file() and not other_rc.is_symlink() and other_rc.read_text(
            errors="replace"
        ).startswith("# warren workspace"):
            other_rc.unlink()

        # Symlink dotfiles into workspace so tools find them via $HOME
        real_home = Path(connect_env.get("REAL_HOME", str(Path.home())))
        ws_root = Path(state["root_path"])
        dotfiles = [".gitconfig", ".gitignore_global"]
        if (state.get("aws") or {}).get("mode") == "sso":
            dotfiles.append(".aws")
        for dotfile in dotfiles:
            src = real_home / dotfile
            dst = ws_root / dotfile
            if src.exists() and not dst.exists():
                dst.symlink_to(src)

        if is_zsh:
            connect_env["ZDOTDIR"] = state["root_path"]

    _apply_aws_mode(state, connect_env, fork=True)
    if bedrock:
        _require_bedrock_aws(state, connect_env)

    if shell_first:
        app_argv = [shell]
        if runtime_type in _LOCAL_SANDBOXES and state.get("harness_root"):
            connect_env.update(_shell_session_env(state, harnesses, harness=harness, new=new))
    else:
        app_argv = [app, *seed_prompt_args(app, state.get("seed_prompt"))]
    if runtime_type == "nsjail":
        nsjail = _nsjail_binary(state)
        _hand_off(
            nsjail,
            [nsjail, "--config", _nsjail_cfg_for(state), "--", *app_argv],
            connect_env,
        )
    if runtime_type == "docker":
        _hand_off(
            "docker",
            ["docker", "exec", "-it", state["container_id"], *app_argv],
            connect_env,
        )
    # Sandbox binaries are absolute paths, so execvp* does no PATH search (AE2).
    if runtime_type == "seatbelt":
        _hand_off(
            SANDBOX_EXEC_PATH,
            [SANDBOX_EXEC_PATH, *_seatbelt_profile_args(state), *app_argv],
            connect_env,
        )
    if runtime_type == "bwrap":
        from warren_common.runtime.bubblewrap import bwrap_binary  # noqa: PLC0415

        args = state.get("bwrap_args")
        if args is None:
            args = _bwrap_args_from_state(state, extra_env=connect_env, cmd=app_argv)
        bwrap = bwrap_binary(state)
        _check_bwrap_before_hand_off(bwrap)
        _hand_off(bwrap, [bwrap, *args])
    if runtime_type == "ecs":
        connect_via_ecs_exec(state["ecs_cluster"], state["container_id"], shell=app)
    raise ValueError(f"unknown runtime_type in state: {runtime_type!r}")


_HARNESS_SH = ".warren_harness.sh"


def _shell_session_env(state: dict, harnesses: Any, *, harness: str | None, new: bool) -> dict[str, str]:
    """Env for the warren shell's harness commands (AG2a)."""
    from warren_common import harness_shell  # noqa: PLC0415

    app = state.get("app", "")
    env = harness_shell.session_env(harnesses, state["harness_root"], app=app)
    if not env:
        return {}
    env.update(harness_shell.connect_env(harness, new=new))
    env.update(harness_shell.seed_env(app, harnesses, state.get("seed_prompt")))
    return env


def connect_via_ecs_exec(
    cluster: str, task_arn: str, *, shell: str = "bash", harness: str | None = None, new: bool = False
) -> NoReturn:
    """Run ``aws ecs execute-command`` into the task's ``workspace`` container,
    attached to its persistent tmux session, and exit with its status.

    A RUNNING task doesn't mean ECS Exec is usable yet: wait for the container's
    ExecuteCommandAgent, then retry the transient "agent isn't running" error. It
    runs as a child rather than exec'd so that retry is possible.

    MUST be called from synchronous context AFTER any ``asyncio.run`` has returned,
    same Pitfall-2 reasoning as ``_connect_via_execvp``.
    """
    aws = shutil.which("aws")
    if not aws:
        ui.error(
            "aws CLI not found.\n"
            "Install from https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
        )
        raise typer.Exit(1)
    if not shutil.which("session-manager-plugin"):
        ui.error(
            "session-manager-plugin not found.\n"
            "Install from https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html"
        )
        raise typer.Exit(1)
    try:
        wait_for_ecs_exec_agent(cluster, task_arn)
    except RuntimeError as exc:
        ui.error(str(exc))
        raise typer.Exit(1)
    argv = [
        aws, "ecs", "execute-command",
        "--cluster", cluster,
        "--task", task_arn,
        "--container", "workspace",
        "--interactive",
        "--command", ecs_session_command(shell, harness=harness, new=new),
    ]
    rc = 1
    for attempt in range(ECS_EXEC_ATTEMPTS):
        if attempt:
            delay = 2.0 * 2 ** (attempt - 1)
            ui.warn(f"ECS Exec agent not ready yet, retrying in {delay:.0f}s ({attempt}/{ECS_EXEC_ATTEMPTS - 1})")
            time.sleep(delay)
        sys.stdout.flush()
        sys.stderr.flush()
        rc, stderr_text = _run_ecs_exec(argv)
        if rc == 0 or not _is_transient_ecs_exec_error(stderr_text):
            break
    raise typer.Exit(rc)


ECS_EXEC_ATTEMPTS = 4
_ECS_EXEC_TRANSIENT = ("execute command agent isn't running", "targetnotconnectedexception")


def _is_transient_ecs_exec_error(stderr_text: str) -> bool:
    lowered = stderr_text.lower()
    return any(marker in lowered for marker in _ECS_EXEC_TRANSIENT)


def _run_ecs_exec(argv: list[str]) -> tuple[int, str]:
    """Run an interactive execute-command with stdin/stdout on the terminal,
    teeing stderr so a transient failure can be recognised."""
    proc = subprocess.Popen(argv, stderr=subprocess.PIPE, text=True)
    captured: list[str] = []

    def _tee() -> None:
        for line in proc.stderr:
            captured.append(line)
            sys.stderr.write(line)
            sys.stderr.flush()

    drainer = threading.Thread(target=_tee, daemon=True)
    drainer.start()
    with _parent_ignores_sigint():
        while True:
            try:
                rc = proc.wait()
                break
            except KeyboardInterrupt:
                continue  # Ctrl-C belongs to the session; never orphan it
    drainer.join(timeout=5.0)
    return rc, "".join(captured)


def wait_for_ecs_exec_agent(
    cluster: str,
    task_arn: str,
    container_name: str = "workspace",
    *,
    timeout: float = 120.0,
    interval: float = 3.0,
) -> None:
    """Poll DescribeTasks until the container's ExecuteCommandAgent is RUNNING.

    Raises RuntimeError with a user-facing message on failure or timeout.
    """
    query = (
        f"tasks[0].containers[?name=='{container_name}'] | [0]"
        ".managedAgents[?name=='ExecuteCommandAgent'] | [0].lastStatus"
    )
    deadline = time.monotonic() + timeout
    announced = False
    while True:
        result = subprocess.run(
            [
                "aws", "ecs", "describe-tasks",
                "--cluster", cluster,
                "--tasks", task_arn,
                "--query", query,
                "--output", "text",
            ],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            detail = result.stderr.strip() or f"exit {result.returncode}"
            raise RuntimeError(f"could not check ECS Exec readiness for task {task_arn!r}: {detail}")
        status = result.stdout.strip()
        if status == "RUNNING":
            return
        if status == "STOPPED":
            raise RuntimeError(
                f"the ECS Exec agent in task {task_arn!r} has stopped; restart the workspace and try again"
            )
        if time.monotonic() >= deadline:
            raise RuntimeError(
                f"the ECS Exec agent in task {task_arn!r} was not ready after {timeout:.0f}s "
                f"(last status: {status or 'unknown'}); try `warren connect` again shortly"
            )
        if not announced:
            ui.warn("waiting for the ECS Exec agent in the workspace task to start...")
            announced = True
        time.sleep(interval)


ECS_SESSION_HELPER = "/usr/local/bin/warren-session"
_ECS_SESSION_SHELLS = ("bash", "zsh", "sh")
# `stat -c %u%A`: uid 0, not group/other-writable; the helper must also be u+x.
_ECS_HELPER_MODE_OK = "0-??x?-??-?"
_ECS_DIR_MODE_OK = "0d????-??-?"


def ecs_session_command(shell: str, *, harness: str | None = None, new: bool = False) -> str:
    """ECS Exec ``--command`` that attaches to the task's persistent tmux session (AH7),
    passing `warren connect --harness/--new` on to the warren shell (AG2a).

    ECS Exec runs as root and the task's PATH is workspace-influenced, so the helper
    is run by absolute path, and only once it and every parent directory are
    root-owned and not writable by anyone else. Otherwise it fails closed: there is
    no fallback to a root shell. warren-session drops to the workspace user itself.
    """
    from warren_common.harness_shell import valid_harness_name  # noqa: PLC0415

    if shell not in _ECS_SESSION_SHELLS:
        shell = "bash"
    harness_arg = harness if harness and valid_harness_name(harness) else "-"
    helper = ECS_SESSION_HELPER
    parents = []
    parent = posixpath.dirname(helper)
    while parent != "/":
        parents.append(parent)
        parent = posixpath.dirname(parent)
    refuse = (
        f"echo warren: {helper} is missing, not root-owned or writable by non-root users"
        " - refusing to open a root shell >&2; exit 1"
    )
    script = " ".join([
        "PATH=/usr/sbin:/usr/bin:/sbin:/bin; export PATH;",
        "m() { /bin/stat -c %u%A $1 2>/dev/null || /usr/bin/stat -c %u%A $1 2>/dev/null; };",
        f"case $(m {helper}) in {_ECS_HELPER_MODE_OK}) ;; *) {refuse};; esac;",
        f"for d in {' '.join(parents)}; do",
        f"case $(m $d) in {_ECS_DIR_MODE_OK}) ;; *) {refuse};; esac;",
        "done;",
        f"exec {helper} {shell} {harness_arg} {'new' if new else '-'}",
    ])
    return f"/bin/sh -c '{script}'"


def _resolve_ecs_container_runtime_id(cluster: str, task_arn: str, container_name: str = "workspace") -> str:
    """Look up a task's container ``runtimeId`` via ``aws ecs describe-tasks``.

    Needed to build the ``ecs:{cluster}_{task_id}_{runtime_id}`` SSM target
    string that ``AWS-StartPortForwardingSession`` requires — ECS Exec's own
    ``--task``/``--cluster`` flags hide this from the caller, but manual SSM
    port forwarding (there's no `aws ecs` equivalent of `execute-command` for
    port forwarding) needs it explicitly.
    """
    result = subprocess.run(
        [
            "aws", "ecs", "describe-tasks",
            "--cluster", cluster,
            "--tasks", task_arn,
            "--query", f"tasks[0].containers[?name=='{container_name}'].runtimeId | [0]",
            "--output", "text",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    runtime_id = result.stdout.strip()
    if result.returncode != 0 or not runtime_id or runtime_id == "None":
        detail = result.stderr.strip() or "no runtimeId returned"
        msg = f"could not resolve ECS container runtimeId for task {task_arn!r}: {detail}"
        raise RuntimeError(msg)
    return runtime_id


def _resolve_orchestrator_task_arn(cluster: str, service: str) -> str:
    """Find the currently-running orchestrator task's ARN via its ECS service.

    The orchestrator runs as a long-lived service with ``desiredCount: 1``, not
    a workspace task — its task ARN changes across deploys/restarts, so this
    can't be cached or configured statically; it's re-resolved on every call.

    A rolling deploy can briefly leave more than one task with
    ``desiredStatus=RUNNING`` (the new task starting while the old one is
    still draining) — blindly taking ``taskArns[0]`` could grab the task
    currently being stopped rather than the live one (audit 2026-10-16
    #35). When more than one candidate comes back, this describes each one
    and prefers a task whose ``lastStatus`` is actually ``RUNNING``.
    """
    list_result = subprocess.run(
        [
            "aws", "ecs", "list-tasks",
            "--cluster", cluster,
            "--service-name", service,
            "--desired-status", "RUNNING",
            "--query", "taskArns",
            "--output", "json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if list_result.returncode != 0:
        detail = list_result.stderr.strip() or "list-tasks failed"
        raise RuntimeError(
            f"could not resolve orchestrator task for service {service!r} in cluster {cluster!r}: {detail}"
        )
    try:
        task_arns = json.loads(list_result.stdout) or []
    except json.JSONDecodeError:
        task_arns = []
    if not task_arns:
        raise RuntimeError(
            f"could not resolve orchestrator task for service {service!r} in cluster {cluster!r}: "
            "no running task found"
        )
    if len(task_arns) == 1:
        return task_arns[0]

    describe_result = subprocess.run(
        [
            "aws", "ecs", "describe-tasks",
            "--cluster", cluster,
            "--tasks", *task_arns,
            "--query", "tasks[].{arn: taskArn, lastStatus: lastStatus}",
            "--output", "json",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    if describe_result.returncode == 0:
        try:
            tasks = json.loads(describe_result.stdout) or []
        except json.JSONDecodeError:
            tasks = []
        for task in tasks:
            if task.get("lastStatus") == "RUNNING":
                return task["arn"]

    # describe-tasks failed, or returned nothing with lastStatus=="RUNNING" --
    # fall back to the first candidate rather than failing outright.
    return task_arns[0]


def _free_local_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _drain_pipe(pipe, buffer: "collections.deque[str]") -> None:
    try:
        for line in iter(pipe.readline, ""):
            buffer.append(line)
    except (ValueError, OSError):
        pass  # pipe closed out from under us (process exited) -- nothing left to drain


def _start_pipe_drainers(proc: subprocess.Popen) -> "collections.deque[str]":
    """Continuously drain `proc`'s stdout/stderr in daemon threads for the
    tunnel's whole lifetime (audit 2026-10-16 #35: these pipes were only
    ever read via `communicate()` on the early-failure path -- if the OS
    pipe buffer filled during normal, long-running operation instead, the
    subprocess could stall writing to it). Returns a bounded deque holding
    the last ~40 combined stdout+stderr lines, for the early-failure
    error message; stdout is still drained even though only stderr is
    reported, so it alone can never fill and stall the child.
    """
    tail: "collections.deque[str]" = collections.deque(maxlen=40)
    threading.Thread(target=_drain_pipe, args=(proc.stdout, collections.deque(maxlen=40)), daemon=True).start()
    threading.Thread(target=_drain_pipe, args=(proc.stderr, tail), daemon=True).start()
    return tail


def start_ssh_port_forward(
    ssh_host: str, remote_port: int, *, ssh_key_path: str | None = None
) -> tuple[subprocess.Popen, int]:
    """Start a background SSH local port-forward to a podman/docker-mode
    server's control plane -- the plain-SSH equivalent of
    ``start_orchestrator_port_forward``'s SSM tunnel for ECS. Every
    redeploy in this project's own runbook binds the control plane to
    ``127.0.0.1:8420`` on the server's own host, so ``warren remote add
    --ssh-host`` (``runtime_type="ssh"``) is the only way to reach it
    remotely without the caller hand-running ``ssh -L`` themselves first.

    Returns ``(process, local_port)``; the caller must terminate the
    returned process once done, same contract as the ECS tunnel. Raises
    ``RuntimeError`` if ``ssh`` isn't found or the tunnel doesn't become
    connectable within a few seconds (most commonly: the host is
    unreachable, or the key needs a passphrase/agent not available
    non-interactively).
    """
    ssh = shutil.which("ssh")
    if not ssh:
        raise RuntimeError("ssh not found on PATH")

    # `_free_local_port` binds a probe socket just to learn a free port number, then
    # releases it before ssh binds that same port -- a window in which another process
    # on the same host could grab it first (ssh would then fail to bind and exit early).
    # Full elimination of that race isn't generally possible without handing ssh an
    # already-bound fd, so this retries once with a freshly-chosen port instead, which
    # covers the overwhelmingly common case (a one-off collision, not something actively
    # racing this same port on every attempt).
    last_error: RuntimeError | None = None
    for attempt in range(2):
        local_port = _free_local_port()

        argv = [
            ssh,
            "-N",
            "-o", "BatchMode=yes",  # never hang on an interactive password prompt if key auth fails
            "-o", "ExitOnForwardFailure=yes",  # fail fast if the forward itself can't bind, e.g. this race
            "-L", f"{local_port}:localhost:{remote_port}",
        ]
        if ssh_key_path:
            argv += ["-i", str(Path(ssh_key_path).expanduser())]
        # Audit R10: `--` stops `ssh_host` from ever being parsed as an ssh
        # option if it happens to start with `-` (e.g. a malformed/malicious
        # profile config) -- same reasoning, and same fix, as #12's
        # `connect_via_ssh_podman_exec` below.
        argv += ["--", ssh_host]

        proc = subprocess.Popen(
            argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
            env=winsupport.ssh_client_env(),
        )
        stderr_tail = _start_pipe_drainers(proc)

        deadline = time.monotonic() + 10.0
        while time.monotonic() < deadline:
            if proc.poll() is not None:
                last_error = RuntimeError(
                    f"SSH port-forward to {ssh_host!r} exited early: {''.join(stderr_tail).strip()}"
                )
                break
            try:
                with socket.create_connection(("127.0.0.1", local_port), timeout=0.5):
                    return proc, local_port
            except OSError:
                time.sleep(0.3)
        else:
            proc.terminate()
            last_error = RuntimeError(f"SSH port-forward to {ssh_host!r} did not become reachable within 10s")

    assert last_error is not None
    raise last_error


def connect_via_ssh_podman_exec(
    ssh_host: str,
    container_id: str,
    *,
    ssh_key_path: str | None = None,
    shell: str = "bash",
    harness: str | None = None,
    new: bool = False,
) -> NoReturn:
    """Replace the current process with an interactive attach to a workspace
    container on a podman/docker-mode server, over the operator's own SSH
    access to that server's host.

    This is `warren connect`'s path for `runtime_type="ssh"` remotes --
    deliberately NOT an SSH connection *into* the workspace container itself
    (ACCESS-02/ACCESS-03's in-container sshd was never built; see #8). The
    container already runs its app inside a `tmux`
    session named `main` (`images/warren-docker-base/entrypoint.py`'s
    `_build_argv` in no-TTY/server mode) specifically so this attach works.

    MUST be called from synchronous context AFTER any `asyncio.run` (e.g. the
    `ensure_running` call that resolved `container_id`) has returned, same
    Pitfall-2 reasoning as `_connect_via_execvp`.
    """
    ssh = shutil.which("ssh")
    if not ssh:
        raise RuntimeError("ssh not found on PATH")

    sys.stdout.flush()
    sys.stderr.flush()

    # `container_id` comes from the server's own API response -- a compromised or
    # buggy server could put shell metacharacters in it. ssh joins every argument
    # after the hostname with spaces and hands the result to the REMOTE shell for
    # interpretation (unlike a local argv list, which execvp never shell-parses),
    # so passing container_id as a separate argv element here would let a malicious
    # value run arbitrary commands on the ssh host as the operator (audit 2026-10-16
    # P0 #12). shlex.join builds ONE already-quoted remote command string instead,
    # and "--" stops ssh_host/that string from ever being parsed as an ssh option.
    # Audit R10: `--` before `container_id` stops it from being parsed as a
    # `podman exec` OPTION if it happens to start with `-` -- shlex.join above
    # already protects against shell metacharacters once this reaches the
    # remote shell, but that's an orthogonal concern from argument injection
    # into podman's own flag parser, which only this separator guards against.
    from warren_common.harness_shell import TMUX_SESSION_SCRIPT, valid_harness_name  # noqa: PLC0415

    if shell not in _ECS_SESSION_SHELLS:
        shell = "bash"
    harness_arg = harness if harness and valid_harness_name(harness) else "-"
    # AG2a/AG4: attach to (or create) tmux session `main` running the warren shell.
    remote_cmd = shlex.join(
        [
            "podman", "exec", "-it", "--", container_id,
            "/bin/sh", "-c", TMUX_SESSION_SCRIPT, "warren-session",
            shell, harness_arg, "new" if new else "-",
        ]
    )
    argv = [ssh, "-t"]
    if ssh_key_path:
        argv += ["-i", str(Path(ssh_key_path).expanduser())]
    argv += ["--", ssh_host, remote_cmd]
    _hand_off(ssh, argv, winsupport.ssh_client_env())


def start_orchestrator_port_forward(cluster: str, service: str, remote_port: int) -> tuple[subprocess.Popen, int]:
    """Start a background SSM port-forward to the orchestrator's own task.

    Unlike ``_tunnel_via_execvp`` (which ``execvp``s and blocks in the
    foreground for the standalone ``warren tunnel`` command), this
    returns a live ``Popen`` the caller manages the lifecycle of — used to make
    HTTP API calls against a control plane that has no direct network path at
    all (SSM-only access, per the ownership-chain design). The caller must
    terminate the returned process once done; it does not exit on its own.

    Returns ``(process, local_port)``. Raises ``RuntimeError`` if the AWS CLI,
    ``session-manager-plugin``, or the orchestrator task itself can't be
    resolved, or if the tunnel doesn't become connectable within a few seconds.
    """
    aws = shutil.which("aws")
    if not aws:
        raise RuntimeError(
            "aws CLI not found — install from "
            "https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html"
        )
    if not shutil.which("session-manager-plugin"):
        raise RuntimeError(
            "session-manager-plugin not found — install from "
            "https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html"
        )

    task_arn = _resolve_orchestrator_task_arn(cluster, service)
    task_id = task_arn.rstrip("/").rsplit("/", 1)[-1]
    runtime_id = _resolve_ecs_container_runtime_id(cluster, task_arn, container_name="workspace-provisioner")
    target = f"ecs:{cluster}_{task_id}_{runtime_id}"
    local_port = _free_local_port()

    proc = subprocess.Popen(
        [
            "aws", "ssm", "start-session",
            "--target", target,
            "--document-name", "AWS-StartPortForwardingSession",
            "--parameters", f"portNumber={remote_port},localPortNumber={local_port}",
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    stderr_tail = _start_pipe_drainers(proc)

    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            raise RuntimeError(f"SSM port-forward to orchestrator exited early: {''.join(stderr_tail).strip()}")
        try:
            with socket.create_connection(("127.0.0.1", local_port), timeout=0.5):
                return proc, local_port
        except OSError:
            time.sleep(0.3)

    proc.terminate()
    raise RuntimeError(f"SSM port-forward to orchestrator did not become reachable on port {local_port} within 10s")


def _tunnel_via_execvp(state: dict, remote_port: int, local_port: int | None = None) -> NoReturn:
    """Replace the current process with an SSM port-forwarding session to a
    workspace, generic to whatever is listening on ``remote_port`` inside it
    — this knows nothing about ACP, HTTP, or any other protocol running on
    the other end. Only meaningful for runtimes with no direct network path
    from the operator (currently: ``ecs``); local runtimes are already
    reachable on localhost and don't need tunneling.

    Reuses the exact same ECS Exec plumbing (`aws` CLI + session-manager-
    plugin, the operator's own AWS credentials) `_connect_via_execvp` uses
    for interactive shells — this is the same SSM channel `enableExecuteCommand`
    already sets up per task, just a different SSM document
    (`AWS-StartPortForwardingSession` instead of ECS Exec's own session
    type). Authorization is therefore whatever IAM already enforces on
    `ssm:StartSession`/`ecs:ExecuteCommand` for this principal — no new
    server-side authorization path, per the ownership-chain design.

    Unverified against a live deployment (see ecs-architecture-hld.md) —
    the `ecs:{cluster}_{task_id}_{runtime_id}` target format for a manual
    `ssm start-session` against an ECS Exec-enabled task is documented AWS
    behavior, but this repo has not yet exercised it against a running
    Fargate task.
    """
    runtime_type = state.get("runtime_type", "nsjail")
    if runtime_type != "ecs":
        typer.echo(
            f"tunnel is only meaningful for runtime_type 'ecs' (got {runtime_type!r}) — "
            "local runtimes are already reachable directly, no tunnel needed.",
            err=True,
        )
        raise typer.Exit(1)

    local_port = local_port if local_port is not None else remote_port

    log.info(
        "dispatching_tunnel",
        workspace_id=state.get("workspace_id"),
        remote_port=remote_port,
        local_port=local_port,
    )
    sys.stdout.flush()
    sys.stderr.flush()

    aws = shutil.which("aws")
    if not aws:
        typer.echo(
            "error: aws CLI not found.\n"
            "Install from https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html",
            err=True,
        )
        raise typer.Exit(1)
    ssm_plugin = shutil.which("session-manager-plugin")
    if not ssm_plugin:
        typer.echo(
            "error: session-manager-plugin not found.\n"
            "Install from https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager-working-with-install-plugin.html",
            err=True,
        )
        raise typer.Exit(1)

    cluster = state["ecs_cluster"]
    task_arn = state["container_id"]  # task ARN, same field _connect_via_execvp uses
    task_id = task_arn.rstrip("/").rsplit("/", 1)[-1]

    try:
        runtime_id = _resolve_ecs_container_runtime_id(cluster, task_arn)
    except RuntimeError as exc:
        typer.echo(f"error: {exc}", err=True)
        raise typer.Exit(1) from exc

    target = f"ecs:{cluster}_{task_id}_{runtime_id}"
    _hand_off(aws, [
        "aws", "ssm", "start-session",
        "--target", target,
        "--document-name", "AWS-StartPortForwardingSession",
        "--parameters", f"portNumber={remote_port},localPortNumber={local_port}",
    ])


def _exec_in_sandbox(state: dict, cmd: list[str]) -> int:
    """Run `cmd` non-interactively inside an existing workspace sandbox.

    Unlike _connect_via_execvp this does NOT execvp — it spawns a subprocess,
    streams stdout/stderr to the caller's terminal, and returns the exit code.
    No zshrc setup, no dotfile symlinking, no TTY allocation.
    """
    from warren_common.runtime.sandbox_env import base_host_env  # noqa: PLC0415

    runtime_type = state.get("runtime_type", "nsjail")

    # Allow-list only (audit finding #4) — NOT os.environ.copy(), which would
    # hand every AWS/API key in the operator's own shell to the sandboxed
    # command on top of (not instead of) the template's declared env_snapshot.
    env = base_host_env()
    for k, v in state.get("env_snapshot", {}).items():
        env[k] = v
    # HOME = workspace root so relative paths inside the sandbox work as expected
    if "root_path" in state:
        env["REAL_HOME"] = env.get("HOME", str(Path.home()))
        env["HOME"] = state["root_path"]

    _apply_aws_mode(state, env, fork=False)

    if runtime_type == "seatbelt":
        argv = [SANDBOX_EXEC_PATH, *_seatbelt_profile_args(state), "--", *cmd]
    elif runtime_type == "nsjail":
        nsjail = _nsjail_binary(state)
        argv = [nsjail, "--config", _nsjail_cfg_for(state), "--", *cmd]
    elif runtime_type == "docker":
        # -i (no -t) forwards stdin without allocating a TTY, matching how
        # nsjail/bwrap/seatbelt below already inherit stdin unconditionally
        # via subprocess.run's default. Without it, `docker exec` never
        # forwards the stdin this function already inherited from its caller.
        argv = ["docker", "exec", "-i", state["container_id"], *cmd]
    elif runtime_type == "bwrap":
        # bwrap clears its child's env (--clearenv, finding #4) — `env` above
        # only reaches the outer bwrap binary's own process via subprocess.run's
        # env= kwarg below, NOT the sandboxed child; it's threaded through as
        # extra_env so _bwrap_args_from_state bakes it into the 0600 secret env
        # file bind-mounted into the sandbox (audit 2026-10-16 P2 #51) rather
        # than onto this process's own (ps-visible) argv. `cmd` is passed
        # through directly rather than appended after slicing a trailing
        # `-- <app>` off a prebuilt argv — build_bwrap_args already bakes the
        # caller's cmd into its own trailing shell wrapper.
        from warren_common.runtime.bubblewrap import bwrap_binary  # noqa: PLC0415

        argv = [bwrap_binary(state), *_bwrap_args_from_state(state, extra_env=env, cmd=cmd)]
    elif runtime_type == "ecs":
        # Not a missing feature — an AWS platform limitation. `aws ecs execute-command`
        # only supports --interactive sessions over SSM; there's no non-interactive
        # "run this, capture stdout, exit" mode the way `docker exec -i` gives you.
        # For interactive shell access, use `warren connect`. For programmatic/
        # agent control (e.g. ACP), use `warren tunnel` to port-forward to
        # whatever's listening inside the task over the same SSM channel — it's protocol-
        # agnostic, so this isn't blocked on building anything new here.
        raise ValueError(
            "non-interactive exec is not supported for ECS workspaces (AWS limitation, "
            "not a gap here); use `warren connect` for an interactive shell, "
            "or `warren tunnel` to reach a listener inside the task directly "
            "(e.g. for ACP-based agent control)"
        )
    else:
        raise ValueError(f"unknown runtime_type: {runtime_type!r}")

    result = subprocess.run(argv, env=env)
    return result.returncode


def _seatbelt_profile_args(state: dict) -> list[str]:
    """`-f <profile> -D KEY=VALUE...` for sandbox-exec (AE3)."""
    from warren_common.runtime.sbpl import sandbox_exec_param_args  # noqa: PLC0415

    return ["-f", state["profile_path"], *sandbox_exec_param_args(state.get("profile_params") or {})]


def _nsjail_binary(state: dict) -> str:
    """The absolute nsjail path recorded at provision (AE2)."""
    from warren_common.runtime_detect import DEFAULT_NSJAIL_PATH, resolve_nsjail  # noqa: PLC0415

    path = state.get("nsjail_path") or resolve_nsjail() or DEFAULT_NSJAIL_PATH
    if not os.path.isabs(path):
        raise ValueError(f"nsjail path must be absolute: {path!r}")
    return path


def _apply_aws_mode(state: dict, env: dict[str, str], *, fork: bool) -> None:
    """AK3 at connect/exec time. `sso`: warn that every SSO account and role is
    reachable. `export`: strip host AWS config from the env and, if the template
    names a profile, serve that profile's credentials from the host. State from
    before AK3 (no `aws` key) is left as provisioned."""
    if "aws" not in state:
        return
    aws = state.get("aws") or {}
    if aws.get("mode") == "sso":
        typer.echo(
            "warning: aws.mode is 'sso' -- this workspace can use the host's SSO token "
            "to reach every AWS account and role you have access to",
            err=True,
        )
        return
    from warren_common.aws_credentials import (  # noqa: PLC0415
        HOST_AWS_ENV,
        profile_region,
        start_credentials_endpoint,
    )

    for key in HOST_AWS_ENV:
        env.pop(key, None)
    profile = aws.get("profile")
    if not profile:
        return
    if state.get("runtime_type") not in ("seatbelt", "bwrap"):
        typer.echo(
            f"warning: aws.mode 'export' credentials aren't served to "
            f"{state.get('runtime_type')} workspaces yet",
            err=True,
        )
        return
    env.update(start_credentials_endpoint(profile, state.get("workspace_id", ""), fork=fork))
    region = profile_region(profile)
    if region:
        env.setdefault("AWS_REGION", region)
        env.setdefault("AWS_DEFAULT_REGION", region)


def _state_bedrock(state: dict) -> bool:
    return bedrock_mode(state.get("model_access") or None, state.get("env_snapshot") or {})


def _require_bedrock_aws(state: dict, env: dict[str, str]) -> None:
    """Bedrock mode reaches models only through the workspace's own AWS
    credentials, so refuse to connect without them rather than start a
    harness that would prompt for the operator's Claude login."""
    if state.get("runtime_type") == "ecs":
        return
    aws = state.get("aws") or {}
    has_creds = "AWS_CONTAINER_CREDENTIALS_FULL_URI" in env or (
        aws.get("mode") == "sso" and bool(env.get("AWS_PROFILE"))
    )
    problem = ""
    if not has_creds:
        problem = (
            "it has no AWS credentials: give the template `aws: {profile: <profile>}` "
            "(export mode, seatbelt or bwrap runtimes)"
        )
    elif not (env.get("AWS_REGION") or env.get("AWS_DEFAULT_REGION") or aws.get("mode") == "sso"):
        problem = "no AWS region: set a region on the profile or AWS_REGION in the template's env"
    if problem:
        typer.echo(
            f"error: this workspace uses Bedrock for model access (model_access: bedrock / "
            f"CLAUDE_CODE_USE_BEDROCK) but {problem}. The operator's Claude login is never "
            "handed to Bedrock-mode workspaces.",
            err=True,
        )
        raise typer.Exit(1)


def _nsjail_cfg_for(state: dict) -> str:
    """Regenerate nsjail.cfg in the protected state dir from state.json (BB3) --
    any nsjail.cfg sitting in the writable workspace root is ignored."""
    from warren_common.runtime.nsjail import write_nsjail_cfg  # noqa: PLC0415
    from warren_common.runtime.sandbox_env import state_root  # noqa: PLC0415

    workspace_id = state.get("workspace_id", "")
    state_dir = state.get("nsjail_state_dir") or str(state_root() / workspace_id)
    return str(write_nsjail_cfg(state_dir, workspace_id, state.get("root_path", "")))


def _bwrap_args_from_state(
    state: dict,
    *,
    extra_env: dict[str, str] | None = None,
    cmd: list[str] | None = None,
) -> list[str]:
    """Rebuild bwrap argv from the workspace's on-disk state.json (bwrap
    stores no external cfg — argv is the config).

    state.json lives under ``bwrap_state_dir`` (``~/.warren/state/<id>/``),
    NOT the workspace root (audit finding #1) — root_path itself is bound
    rw into the sandbox, so a sandboxed process could otherwise rewrite its
    own state.json/argv for the next connect. The real workspace root path
    is read back from the payload's own ``root_path`` field.

    ``extra_env`` (e.g. ``_connect_via_execvp``'s allow-listed ``connect_env``
    — HOME/ZDOTDIR/PROMPT overrides only known at connect time) is layered on
    top of the provision-time ``env_snapshot`` and written into a 0600
    secret-env file inside ``bwrap_state_dir`` (audit 2026-10-16 P2 #51:
    this used to go straight onto bwrap's own argv via ``--setenv``, which
    any user on the host can read via ``ps``/``/proc/<pid>/cmdline``). The
    file is deliberately left in place (not unlinked) rather than cleaned up
    after the caller's ``os.execvp`` replaces this process entirely — it
    carries the same 0600-at-rest exposure ``state.json``'s own
    ``env_snapshot`` already has in the same directory, not a new one.
    """
    from warren_common.runtime.bubblewrap import (  # noqa: PLC0415
        build_bwrap_args,
        write_secret_env_file,
    )

    state_dir = Path(state["bwrap_state_dir"])
    payload = json.loads((state_dir / "state.json").read_text())
    spec = WorkspaceSpec(
        workspace_id=payload["workspace_id"],
        project=payload["project"],
        intent=payload["intent"],
        image="",
        root_path=payload["root_path"],
        app=payload.get("app", "bash"),
        env={**payload.get("env_snapshot", {}), **(extra_env or {})},
        worktree_paths=[tuple(p) for p in payload.get("worktree_paths", [])],
        reference_paths=[tuple(p) for p in payload.get("reference_paths", [])],
        **harness_spec_kwargs(payload),
    )
    env_file = write_secret_env_file(spec.env, state_dir)
    return build_bwrap_args(spec, env_file=str(env_file), cmd=cmd)


def _repo_slug(url: str) -> str:
    """Local mirror of warren_common.git._repo_slug — importing lazily to keep
    --help fast, but the slug function is pure and cheap. Delegates for parity."""
    from warren_common.git import _repo_slug as _slug  # noqa: PLC0415

    return _slug(url)
