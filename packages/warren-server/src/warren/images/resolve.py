"""The image a workspace runs, from its resolved template (LIFE-04 step 2, Z12, V1).

Shared by create_workspace (routes/workspaces.py) and the registry's reprovision
(AB1 req 6), so a workspace that needs a new task or container picks up the
image its template resolves to now, through the same allow-list check.
"""
from __future__ import annotations

import structlog
from warren_common.errors import TemplateNotFoundError
from warren_common.models import ProjectConfig
from warren_common.templates import resolve_template

log = structlog.get_logger(__name__)


def server_sanctioned_image(
    image: str,
    field: str,
    default_literal: str,
    project: str,
    template: str,
    settings,
) -> str:
    """Audit Z12: restrict which image a user-scoped project/template may point a
    workspace at -- same class as R24 (docker_networks) and Y1/V2 (local-path): a
    user-scoped project (one any authenticated non-admin user can write
    themselves -- no admin check on that write path, see routes/projects.py)
    could otherwise name ANY `docker_image`/`ecs_image` from any registry,
    including one it fully controls, unrelated to anything an admin sanctioned.

    An image is permitted in any of three ways:
      1. It's still the model's own hardcoded default (`default_literal`,
         never overridden at all) -- nothing to sanction.
      2. It matches what the server-wide (admin-managed) file declares for
         THIS EXACT template path, re-resolved independently of the
         already-merged `template_cfg` -- the admin already controls this,
         same trust tier the local-path/docker_networks exceptions use. A
         fully server-wide project (no user-scoped override at all) passes
         here automatically, since its merged value and this independently
         re-resolved value are then identical -- same reasoning
         `_server_sanctioned_docker_networks` already relies on, no separate
         "is this project user-scoped" gate needed.
      3. It's in `settings.allowed_images` (a deployment-wide allow-list,
         same shape as `github_app_allowed_repos`/`allowed_docker_networks`).

    Anything failing all three falls back to `default_literal`, logged --
    fail-closed on the image, fail-open on availability, same tradeoff this
    codebase already uses for local-path folders and docker_networks.
    """
    if image == default_literal:
        return image

    from warren_common.loader import ProjectLoader

    server_wide = ProjectLoader.load_optional(settings.projects_dir / f"{project}.yaml")
    if server_wide is not None:
        try:
            server_template = resolve_template(server_wide, template)
            if getattr(server_template, field, None) == image:
                return image
        except TemplateNotFoundError:
            pass

    allow_list = set(getattr(settings, "allowed_images", None) or [])
    if image in allow_list:
        return image

    log.warning(
        "image_not_server_sanctioned",
        project=project,
        template=template,
        field=field,
        image=image,
    )
    return default_literal


def template_image(template_cfg: ProjectConfig, project: str, template: str, settings) -> str:
    """The per-runtime image field of a resolved template, each with its own
    default and no fallback between them: ECS `ecs_image` (the deployment's
    `ecs_default_image` when the template never set one), podman/docker
    `docker_image`."""
    if getattr(settings, "runtime_type", "podman") == "ecs":
        # Z12: re-check BEFORE the V1 ecs_default_image substitution below, so a
        # sanctioned image is never silently swapped for the deployment default.
        ecs_image = server_sanctioned_image(
            template_cfg.ecs_image,
            "ecs_image",
            ProjectConfig.model_fields["ecs_image"].default,
            project,
            template,
            settings,
        )
        # V1: only when the template never overrode ecs_image; an explicit
        # per-project/template value always wins.
        ecs_default_image = getattr(settings, "ecs_default_image", "") or ""
        if ecs_default_image and ecs_image == ProjectConfig.model_fields["ecs_image"].default:
            return ecs_default_image
        return ecs_image
    return server_sanctioned_image(
        template_cfg.docker_image,
        "docker_image",
        ProjectConfig.model_fields["docker_image"].default,
        project,
        template,
        settings,
    )
