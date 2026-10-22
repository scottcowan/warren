"""Wave 0 RED tests for ProjectLoader (Plan 02 will turn these GREEN)."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from warren_common import ProjectConfig, ProjectLoader
from warren_common.errors import ProjectNotFoundError


def test_load_valid(write_project_yaml, sample_project_yaml_text):
    path = write_project_yaml("demo-project", sample_project_yaml_text)
    cfg = ProjectLoader.load(path)
    assert isinstance(cfg, ProjectConfig)
    assert cfg.name == "demo-project"
    assert cfg.templates["observe"].app == "bash"


def test_missing_required_field_raises(write_project_yaml):
    from pydantic import ValidationError

    # name is the only truly required field; missing it must raise
    text = "description: no-name\ntemplates: {}\n"
    path = write_project_yaml("bad", text)
    with pytest.raises(ValidationError):
        ProjectLoader.load(path)


def test_unknown_field_warns(
    write_project_yaml, sample_project_yaml_unknown_field, structlog_capture
):
    path = write_project_yaml("demo-project", sample_project_yaml_unknown_field)
    cfg = ProjectLoader.load(path)
    events = [e for e in structlog_capture if e.get("event") == "unknown_project_field"]
    assert events, "expected an unknown_project_field structlog event"
    assert any(e.get("field") == "bogus_field" for e in events)
    assert not hasattr(cfg, "bogus_field")


def test_invalid_yaml_fails(write_project_yaml):
    path = write_project_yaml("malformed", "name: cyber\n  bare_path: [unclosed\n")
    with pytest.raises(yaml.YAMLError):
        ProjectLoader.load(path)


def test_load_all_returns_dict(write_project_yaml, sample_project_yaml_text, tmp_projects_dir):
    write_project_yaml("demo-project", sample_project_yaml_text)
    second = sample_project_yaml_text.replace("demo-project", "otherproj")
    write_project_yaml("otherproj", second)
    result = ProjectLoader.load_all(tmp_projects_dir)
    assert set(result.keys()) == {"demo-project", "otherproj"}


def test_load_all_skips_invalid(
    write_project_yaml, sample_project_yaml_text, tmp_projects_dir, structlog_capture
):
    write_project_yaml("demo-project", sample_project_yaml_text)
    write_project_yaml("broken", "name: broken\n  bare_path: [unclosed\n")
    result = ProjectLoader.load_all(tmp_projects_dir)
    assert "demo-project" in result
    assert "broken" not in result
    assert any(e.get("event") == "project_load_failed" for e in structlog_capture)


def test_load_effective_neither_exists_raises(tmp_projects_dir):
    with pytest.raises(ProjectNotFoundError):
        ProjectLoader.load_effective("nope", tmp_projects_dir, "user-1")


def test_load_effective_server_wide_only(tmp_projects_dir, write_project_yaml, sample_project_yaml_text):
    write_project_yaml("demo-project", sample_project_yaml_text)
    cfg = ProjectLoader.load_effective("demo-project", tmp_projects_dir, "user-1")
    assert cfg.templates["observe"].app == "bash"


def test_load_effective_user_scoped_only(tmp_projects_dir, sample_project_yaml_text):
    user_dir = tmp_projects_dir / "users" / "user-1"
    user_dir.mkdir(parents=True)
    (user_dir / "demo-project.yaml").write_text(sample_project_yaml_text)
    cfg = ProjectLoader.load_effective("demo-project", tmp_projects_dir, "user-1")
    assert cfg.templates["observe"].app == "bash"


def test_load_effective_merges_user_override_onto_server_wide(
    tmp_projects_dir, write_project_yaml
):
    write_project_yaml(
        "demo-project",
        "name: demo-project\n"
        "docker_image: ghcr.io/x/base:latest\n"
        "templates:\n"
        "  observe:\n"
        "    app: bash\n",
    )
    user_dir = tmp_projects_dir / "users" / "user-1"
    user_dir.mkdir(parents=True)
    (user_dir / "demo-project.yaml").write_text(
        "name: demo-project\n"
        "templates:\n"
        "  claude:\n"
        "    app: claude\n"
    )
    cfg = ProjectLoader.load_effective("demo-project", tmp_projects_dir, "user-1")
    assert set(cfg.templates) == {"observe", "claude"}
    assert cfg.templates["observe"].app == "bash"
    assert cfg.templates["claude"].app == "claude"
    # A different user with no override of their own just sees the server-wide project.
    cfg_other = ProjectLoader.load_effective("demo-project", tmp_projects_dir, "user-2")
    assert set(cfg_other.templates) == {"observe"}
