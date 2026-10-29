"""Project YAML loader — parses warren.yml files into ProjectConfig."""

from __future__ import annotations

from pathlib import Path

import structlog
import yaml

from pydantic import ValidationError

from .errors import ProjectNotFoundError
from .models import ProjectConfig
from .templates import list_template_paths, merge_projects

log = structlog.get_logger(__name__)


def user_scoped_project_path(projects_dir: Path, user_id: str, name: str) -> Path:
    """Path for a user-scoped project — `{projects_dir}/users/{user_id}/{name}.yaml`,
    separate from the server-wide `{projects_dir}/{name}.yaml`."""
    return projects_dir / "users" / user_id / f"{name}.yaml"


class ProjectLoader:
    @staticmethod
    def load(path: Path) -> ProjectConfig:
        if not path.exists():
            raise ProjectNotFoundError(f"project file not found: {path}")
        with open(path) as f:
            data = yaml.safe_load(f) or {}
        # `name` is optional on ProjectConfig itself (a template node doesn't carry
        # one — it's keyed by its parent's `templates` dict instead), but the root
        # of a project file always needs one.
        if not isinstance(data, dict) or not data.get("name"):
            raise ValidationError.from_exception_data(
                "ProjectConfig", [{"type": "missing", "loc": ("name",), "input": data}]
            )
        cfg = ProjectConfig.model_validate(data)
        # A project file that parses cleanly but ends up with zero templates is
        # never useful -- nothing can provision from it (list_template_paths
        # returning empty means every `warren new <project>` call has no
        # template to resolve). This is near-silent otherwise: ProjectConfig's
        # `extra="ignore"` means a renamed/removed field (e.g. the old
        # `intents:`/`base_image:` shape, superseded by `templates:`/
        # `docker_image:`) parses without a single error, just drops the
        # content -- the same code path a genuinely-new, harmless optional
        # field takes. Only load_all() (every *.yaml at startup) hits this
        # warning in practice; load_optional()/load_effective() calls for a
        # single named project surface the same emptiness to the caller
        # directly via list_template_paths() instead.
        if not list_template_paths(cfg):
            log.warning("project_has_no_templates", path=str(path), name=cfg.name)
        return cfg

    @staticmethod
    def load_all(projects_dir: Path) -> dict[str, ProjectConfig]:
        result: dict[str, ProjectConfig] = {}
        for yml in sorted(projects_dir.glob("*.yaml")):
            try:
                cfg = ProjectLoader.load(yml)
            except Exception as exc:
                log.warning("project_load_failed", path=str(yml), error=str(exc))
                continue
            result[cfg.name] = cfg
        return result

    @staticmethod
    def load_optional(path: Path) -> ProjectConfig | None:
        """Like `load()`, but returns None instead of raising when the file
        doesn't exist — used by load_effective() to check both the server-wide
        and user-scoped paths without a missing one being an error."""
        if not path.exists():
            return None
        return ProjectLoader.load(path)

    @staticmethod
    def load_effective(name: str, projects_dir: Path, user_id: str) -> ProjectConfig:
        """Load the effective project for `name` as seen by `user_id`: the
        server-wide project (`{projects_dir}/{name}.yaml`) merged with that
        user's own override (`{projects_dir}/users/{user_id}/{name}.yaml`), if
        either or both exist. Raises ProjectNotFoundError if neither does.

        A user-scoped project automatically inherits from a server-wide one of
        the same name — there's no explicit `extends` pointer to declare; same
        name is the relationship, same as how a template inherits from its
        parent via nesting (templates.py's resolve_template).
        """
        server_wide = ProjectLoader.load_optional(projects_dir / f"{name}.yaml")
        user_scoped = ProjectLoader.load_optional(
            user_scoped_project_path(projects_dir, user_id, name)
        )
        if server_wide is None and user_scoped is None:
            raise ProjectNotFoundError(f"project {name!r} not found")
        if server_wide is None:
            return user_scoped
        if user_scoped is None:
            return server_wide
        return merge_projects(server_wide, user_scoped)
