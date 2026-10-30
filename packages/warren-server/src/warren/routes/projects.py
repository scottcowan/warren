"""Project routes — GET /projects, GET /projects/{name}, PUT /projects/{name}.

Projects can be server-wide (shared, admin-managed — the original behavior) or
user-scoped (owned by the caller, stored under `{projects_dir}/users/{user_id}/`).
A user-scoped project automatically inherits from a server-wide project of the
same name — there's no explicit pointer to declare, same name is the
relationship (see warren_common.loader.ProjectLoader.load_effective).
"""

from __future__ import annotations

import hashlib
import os
import re
import tempfile
from pathlib import Path

import structlog
from fastapi import APIRouter, HTTPException, Request, Response

from warren.auth.deps import current_user
from warren_common.errors import ProjectNotFoundError
from warren_common.loader import ProjectLoader, user_scoped_project_path
from warren_common.models import collect_local_path_folders
from warren_common.templates import list_template_paths

log = structlog.get_logger(__name__)

router = APIRouter()

_SAFE_NAME_RE = re.compile(r"^[a-z0-9_-]+$")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _project_names(projects_dir: Path, user_id: str) -> set[str]:
    """Every project name visible to this user — server-wide ones plus their
    own user-scoped ones, unioned (a user-scoped-only name is still visible)."""
    names: set[str] = set()
    if projects_dir.exists():
        names.update(p.stem for p in projects_dir.glob("*.yaml"))
    user_dir = projects_dir / "users" / user_id
    if user_dir.exists():
        names.update(p.stem for p in user_dir.glob("*.yaml"))
    return names


@router.get("/projects", response_model=list[dict])
async def list_projects(request: Request) -> list[dict]:
    """Return the effective project config for every project visible to the
    caller — server-wide projects, their own user-scoped projects, and the
    merge of both where they share a name. Each entry carries a `_scope` key:
    "server_wide", "user_scoped", or "overridden" (both exist, merged).
    """
    user = current_user(request)
    projects_dir = request.app.state.settings.projects_dir
    names = _project_names(projects_dir, user.user_id)
    result: list[dict] = []
    for name in sorted(names):
        server_wide_path = projects_dir / f"{name}.yaml"
        user_path = user_scoped_project_path(projects_dir, user.user_id, name)
        has_server_wide = server_wide_path.exists()
        has_user_scoped = user_path.exists()
        try:
            effective = ProjectLoader.load_effective(name, projects_dir, user.user_id)
        except Exception as exc:
            log.warning("project_load_failed", project=name, error=str(exc))
            continue
        scope = (
            "overridden"
            if has_server_wide and has_user_scoped
            else "user_scoped" if has_user_scoped else "server_wide"
        )
        dumped = effective.model_dump()
        dumped["_scope"] = scope
        result.append(dumped)
    return result


@router.get("/projects/{name}", response_model=dict)
async def get_project(name: str, request: Request) -> dict:
    """Return the server-wide and user-scoped halves of `name` separately
    (raw YAML text plus a content-version hash for each, for the optimistic
    lock on PUT and for the CLI's promote/diff flow), plus the effective
    merge. 404 if neither half exists.
    """
    if not _SAFE_NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="invalid project name: must match ^[a-z0-9_-]+$")

    user = current_user(request)
    projects_dir = request.app.state.settings.projects_dir
    server_wide_path = projects_dir / f"{name}.yaml"
    user_path = user_scoped_project_path(projects_dir, user.user_id, name)

    server_wide_yaml = server_wide_path.read_text() if server_wide_path.exists() else None
    user_scoped_yaml = user_path.read_text() if user_path.exists() else None

    try:
        effective = ProjectLoader.load_effective(name, projects_dir, user.user_id)
    except ProjectNotFoundError:
        raise HTTPException(status_code=404, detail={"error": "project_not_found"})

    return {
        "name": name,
        "server_wide_yaml": server_wide_yaml,
        "server_wide_version": _sha256(server_wide_yaml.encode()) if server_wide_yaml else None,
        "user_scoped_yaml": user_scoped_yaml,
        "effective": effective.model_dump(),
    }


def _local_path_folder_names(cfg) -> list[str]:
    """Names only -- see `collect_local_path_folders` (warren_common.models)
    for the full FolderSpec objects and the reasoning for the recursive
    walk. Kept as a thin wrapper since this call site only needs names for
    the write-time 422."""
    return [f.name for f in collect_local_path_folders(cfg)]


def _write_project_file(dest: Path, body: bytes, *, server_wide: bool) -> None:
    """Shared write path for both server-wide and user-scoped PUTs: write to a
    temp file in the same directory, validate THAT file, then atomically
    replace the real destination — an invalid update must never destroy a
    previously-valid project (issue #10).

    Audit T1: a `local-path` folder bind-mounts an arbitrary host path
    (read-write unless `readonly`) into the workspace, with no path
    allow-list. Any authenticated user could write their own user-scoped
    project (no admin check on that path) declaring `local-path: /` or the
    podman socket and get it mounted into their own workspace — full host
    compromise. `local-path` is only safe to honor in admin-written
    server-wide projects (admin is already a trusted role); reject it
    entirely in a user-scoped write.
    """
    dest.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=f"{dest.stem}.", suffix=".yaml.tmp", dir=str(dest.parent)
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(body)
        try:
            cfg = ProjectLoader.load(tmp_path)
        except Exception as exc:
            # Audit #46: exc's own text can embed the tempfile's absolute host path
            # (ProjectNotFoundError, PyYAML parse errors) or raw YAML content -- never
            # echo it to the caller. Log the real exception server-side instead.
            log.warning("project_write_validation_failed", dest=str(dest), exc_info=True)
            raise HTTPException(
                status_code=422, detail="project configuration is invalid"
            ) from exc
        if not list_template_paths(cfg):
            # A project with zero templates parses cleanly (ProjectConfig's
            # extra="ignore" doesn't error on an unrecognized/renamed field,
            # e.g. an old intents:/base_image: shape) but is never usable --
            # nothing can provision from it. Reject at write time rather than
            # only warning on load, so the caller finds out immediately
            # instead of discovering it later via an empty TEMPLATES column.
            log.warning("project_write_rejected_no_templates", dest=str(dest))
            raise HTTPException(
                status_code=422,
                detail={
                    "error": "no_templates",
                    "detail": (
                        "project configuration has no usable templates -- check for "
                        "an outdated schema (e.g. 'intents:'/'base_image:' instead of "
                        "'templates:'/'docker_image:')"
                    ),
                },
            )
        if not server_wide:
            bad = _local_path_folder_names(cfg)
            if bad:
                log.warning(
                    "user_scoped_local_path_folder_rejected",
                    dest=str(dest),
                    folders=bad,
                )
                raise HTTPException(
                    status_code=422,
                    detail={
                        "error": "local_path_not_allowed_user_scoped",
                        "detail": (
                            "folder type 'local-path' is only allowed in a "
                            "server-wide project (admin-managed) -- it bind-mounts "
                            "an arbitrary host path into the workspace"
                        ),
                        "folders": bad,
                    },
                )
        os.replace(tmp_path, dest)
    finally:
        tmp_path.unlink(missing_ok=True)


@router.put("/projects/{name}")
async def put_project(
    name: str,
    request: Request,
    server_wide: bool = False,
    expected_version: str | None = None,
) -> Response:
    """Write a project YAML. Defaults to the caller's own user-scoped path —
    any authenticated user may write their own project, no admin needed.

    `server_wide=true` writes the shared `{name}.yaml` instead — admin-only
    (issue #10: shared config is a privilege-escalation surface, not merely a
    personal config edit) — and additionally enforces an optimistic lock: if
    a server-wide version already exists, the caller must pass
    `expected_version` matching its current content hash (from GET
    /projects/{name}'s `server_wide_version`), or the write is rejected with
    409 rather than silently clobbering a concurrent edit. A brand-new
    server-wide project (none exists yet) needs no expected_version.

    Returns 400 if name fails the ^[a-z0-9_-]+$ regex guard (path traversal
    protection). Returns 204 on success. Returns 422 if the written YAML
    fails ProjectLoader validation.
    """
    if not _SAFE_NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="invalid project name: must match ^[a-z0-9_-]+$")

    user = current_user(request)
    body = await request.body()
    projects_dir = request.app.state.settings.projects_dir

    if server_wide:
        if not user.is_admin:
            raise HTTPException(status_code=403, detail="admin required")
        dest = projects_dir / f"{name}.yaml"
        if dest.exists():
            current_version = _sha256(dest.read_bytes())
            if expected_version != current_version:
                raise HTTPException(
                    status_code=409,
                    detail={
                        "error": "version_conflict",
                        "detail": "server-wide project changed since you last read it",
                        "current_version": current_version,
                    },
                )
    else:
        dest = user_scoped_project_path(projects_dir, user.user_id, name)

    _write_project_file(dest, body, server_wide=server_wide)
    return Response(status_code=204)


@router.delete("/projects/{name}")
async def delete_project(name: str, request: Request) -> Response:
    """Delete the caller's own user-scoped project.

    Never deletes the server-wide shared project — there is no `server_wide`
    flag here, unlike PUT. A user-scoped project only ever shadows a
    server-wide one of the same name (warren_common.loader.ProjectLoader.
    load_effective); deleting the user-scoped half just removes that
    override, it can never take down the shared config other users rely on.

    Returns 400 if name fails the ^[a-z0-9_-]+$ regex guard (path traversal
    protection). Returns 404 if the caller has no user-scoped project by
    this name — including when only a server-wide one exists, which this
    endpoint can never see or touch. Returns 204 on success.
    """
    if not _SAFE_NAME_RE.match(name):
        raise HTTPException(status_code=400, detail="invalid project name: must match ^[a-z0-9_-]+$")

    user = current_user(request)
    projects_dir = request.app.state.settings.projects_dir
    dest = user_scoped_project_path(projects_dir, user.user_id, name)

    if not dest.exists():
        raise HTTPException(status_code=404, detail={"error": "project_not_found"})

    dest.unlink()
    return Response(status_code=204)
