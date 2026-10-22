"""Build-request validation for LIFE-04 declarative image builds (D-09).

Pure path/tag logic -- this module must never import `podman`
(`tests/unit/test_runtime_boundary.py` enforces the runtime/preflight-only
import boundary project-wide). `resolve_build_spec()` turns a project's
YAML-declared, caller-supplied relative Containerfile path into a validated
`BuildSpec` that `PodmanRuntime.build_image()` can execute, without ever
letting a project name a path outside its own project directory.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class BuildPathError(ValueError):
    """Raised when a project-supplied Containerfile path is invalid or escapes
    its project directory (T-04-04-PT, ASVS V5 Input Validation)."""


@dataclass(frozen=True)
class BuildSpec:
    """A validated, ready-to-build request.

    `containerfile` and `context_dir` are both fully resolved absolute paths
    inside the project's own directory. `tag` is derived server-side from the
    Containerfile's own bytes (T-04-04-SP) -- a project cannot choose its own
    tag. `memory`/`cpus` come from operator settings only, never from the
    project YAML, so a project cannot raise its own build ceiling.
    """

    containerfile: Path
    context_dir: Path
    tag: str
    memory: str
    cpus: float


def resolve_build_spec(
    project_name: str,
    containerfile_rel_path: str,
    projects_dir: Path,
    settings: Any,
) -> BuildSpec:
    """Validate `containerfile_rel_path` and derive a deterministic build tag.

    Containment is enforced with
    `Path(...).resolve().is_relative_to(project_root.resolve())` -- run AFTER
    resolution, precisely because `..` segments and symlinks both survive a
    naive string-prefix check and only reveal an escape once actually
    resolved (T-04-04-PT).
    """
    if Path(containerfile_rel_path).is_absolute():
        raise BuildPathError(
            f"containerfile path must be relative to the project directory: "
            f"{containerfile_rel_path!r}"
        )

    project_root = (Path(projects_dir) / project_name).resolve()
    candidate = project_root / containerfile_rel_path
    resolved = candidate.resolve()

    if not (resolved == project_root or resolved.is_relative_to(project_root)):
        raise BuildPathError(
            f"containerfile path escapes project directory: {containerfile_rel_path!r}"
        )

    if not resolved.is_file():
        raise BuildPathError(
            f"containerfile not found: {containerfile_rel_path!r}"
        )

    # Deterministic, namespaced tag (T-04-04-SP): an unchanged Containerfile
    # reuses the same tag (build_image() short-circuits on a matching local
    # tag); an edited one produces a new tag on its next build.
    digest = hashlib.sha256(resolved.read_bytes()).hexdigest()[:12]
    tag = f"localhost/warren-project-{project_name}:{digest}"

    # memory/cpus come from operator settings only -- never from the project
    # YAML -- so a project cannot raise its own build resource ceiling.
    memory = getattr(settings, "image_build_memory", "2g")
    cpus = getattr(settings, "image_build_cpus", 2.0)

    return BuildSpec(
        containerfile=resolved,
        context_dir=project_root,
        tag=tag,
        memory=memory,
        cpus=cpus,
    )
