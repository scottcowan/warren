"""Per-machine overrides for portable project YAMLs.

Project YAMLs (~/.warren/projects/*.yaml) are meant to be git-tracked and
identical across machines. Anything machine-specific — a local seed_from
path that speeds up the first clone, which AWS profile name this machine
uses for a project's template — lives in an untracked ~/.warren/machine.toml
instead, applied on top of the loaded project at read time.
"""

from __future__ import annotations

import tomllib
from pathlib import Path
from typing import Any

from warren_common import ProjectLoader
from warren_common.models import AwsConfig, ProjectConfig

MACHINE_CONFIG_PATH = Path.home() / ".warren" / "machine.toml"


def load_machine_overrides(path: Path | None = None) -> dict[str, Any]:
    path = path or MACHINE_CONFIG_PATH
    if not path.exists():
        return {}
    return tomllib.loads(path.read_text())


def _apply_template_overrides(
    node: ProjectConfig, template_overrides: dict[str, Any], _prefix: str = ""
) -> None:
    """Recursively apply AWS-profile overrides to every template node, keyed
    by its full dotted path (e.g. "develop" or "develop.claude")."""
    for name, child in node.templates.items():
        path = f"{_prefix}{name}"
        to = template_overrides.get(path)
        if to and to.get("aws_profile"):
            if child.aws is None:
                child.aws = AwsConfig(profile=to["aws_profile"])
            else:
                child.aws.profile = to["aws_profile"]
        _apply_template_overrides(child, template_overrides, _prefix=f"{path}.")


def apply_overrides(project: ProjectConfig, overrides: dict[str, Any]) -> ProjectConfig:
    proj_overrides = overrides.get("projects", {}).get(project.name, {})
    folder_overrides = proj_overrides.get("folders", {})
    template_overrides = proj_overrides.get("templates", {})

    for folder in project.folders:
        fo = folder_overrides.get(folder.name)
        if fo and fo.get("seed_from"):
            folder.seed_from = fo["seed_from"]

    _apply_template_overrides(project, template_overrides)

    return project


def known_aws_profiles(overrides: dict[str, Any] | None = None) -> list[str]:
    overrides = overrides if overrides is not None else load_machine_overrides()
    return overrides.get("aws", {}).get("known_profiles", [])


def load_project(name: str, projects_dir: Path) -> ProjectConfig:
    project = ProjectLoader.load(projects_dir / f"{name}.yaml")
    return apply_overrides(project, load_machine_overrides())
