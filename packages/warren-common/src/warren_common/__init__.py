"""warren-common — shared models, loader, secrets, logging utilities.

Phase 2 Plan 01 lands placeholder stubs. Real implementations arrive in
Plans 02 (models + loader), 03 (secrets + redaction), 04 (CLI dispatch).
"""

from .errors import (
    ProjectNotFoundError,
    SecretFilePermissionWarning,
    TemplateNotFoundError,
)
from .git import GitManager, ProvisionError
from .images import ImageResolver
from .loader import ProjectLoader, user_scoped_project_path
from .logging import redact_processor
from .models import AwsConfig, MountSpec, ProjectConfig, RepoSpec, ScopeConfig, SecretRef
from .runtime_detect import RuntimeAvailability, detect
from .secrets import SecretLoader, parse_secrets_env
from .templates import list_template_paths, merge_projects, resolve_template

__all__ = [
    "GitManager",
    "ImageResolver",
    "AwsConfig",
    "MountSpec",
    "ProjectConfig",
    "ProjectLoader",
    "ProvisionError",
    "RepoSpec",
    "ProjectNotFoundError",
    "RuntimeAvailability",
    "ScopeConfig",
    "SecretFilePermissionWarning",
    "SecretLoader",
    "SecretRef",
    "TemplateNotFoundError",
    "detect",
    "list_template_paths",
    "merge_projects",
    "parse_secrets_env",
    "redact_processor",
    "resolve_template",
    "user_scoped_project_path",
]
