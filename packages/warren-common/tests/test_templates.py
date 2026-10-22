"""Tests for resolve_template()/list_template_paths() — nested template inheritance."""

from __future__ import annotations

import pytest

from warren_common import (
    ProjectConfig,
    TemplateNotFoundError,
    list_template_paths,
    merge_projects,
    resolve_template,
)


def _project(**templates) -> ProjectConfig:
    return ProjectConfig.model_validate(
        {
            "name": "demo",
            "docker_image": "ghcr.io/example/base:latest",
            "app": "zsh",
            "mounts": [{"host": "/h/refs", "container": "/w/refs", "mode": "rw"}],
            "templates": templates,
        }
    )


def test_single_level_scalar_override():
    root = _project(develop={"docker_image": "ghcr.io/example/dev:latest", "app": "bash"})
    resolved = resolve_template(root, "develop")
    assert resolved.docker_image == "ghcr.io/example/dev:latest"
    assert resolved.app == "bash"


def test_list_fields_append_not_replace():
    root = _project(
        develop={
            "mounts": [{"host": "/h/extra", "container": "/w/extra", "mode": "ro"}],
            "secrets": [{"name": "ANTHROPIC_API_KEY"}],
        }
    )
    resolved = resolve_template(root, "develop")
    assert len(resolved.mounts) == 2
    assert resolved.mounts[0].host == "/h/refs"
    assert resolved.mounts[1].host == "/h/extra"
    assert [s.name for s in resolved.secrets] == ["ANTHROPIC_API_KEY"]


def test_nested_object_shallow_merge_preserves_parent_keys():
    root = ProjectConfig.model_validate(
        {
            "name": "demo",
            "ssh": {"keys": ["~/.ssh/id_ed25519"]},
            "templates": {"claude": {"ssh": {"agent": True}}},
        }
    )
    resolved = resolve_template(root, "claude")
    assert resolved.ssh.keys == ["~/.ssh/id_ed25519"]
    assert resolved.ssh.agent is True


def test_two_level_chain_inherits_through_middle():
    root = _project(
        develop={
            "ecs_cpu": "512",
            "templates": {
                "claude": {
                    "app": "claude",
                }
            },
        }
    )
    resolved = resolve_template(root, "develop.claude")
    assert resolved.ecs_cpu == "512"  # inherited from develop
    assert resolved.app == "claude"  # set at claude
    assert resolved.docker_image == "ghcr.io/example/base:latest"  # inherited from root


def test_unknown_segment_raises_template_not_found():
    root = _project(develop={})
    with pytest.raises(TemplateNotFoundError):
        resolve_template(root, "nonexistent")


def test_unknown_segment_in_middle_of_path_raises():
    root = _project(develop={})
    with pytest.raises(TemplateNotFoundError):
        resolve_template(root, "develop.nonexistent")


def test_resolved_node_carries_no_templates_of_its_own():
    root = _project(develop={"templates": {"claude": {}}})
    resolved = resolve_template(root, "develop")
    assert resolved.templates == {}


def test_list_template_paths_depth_first():
    root = _project(
        develop={"templates": {"claude": {}}},
        observe={},
    )
    assert set(list_template_paths(root)) == {"develop", "develop.claude", "observe"}


def test_merge_projects_overlay_scalar_overrides_base():
    base = ProjectConfig.model_validate({"name": "demo", "docker_image": "ghcr.io/example/a:latest"})
    overlay = ProjectConfig.model_validate({"name": "demo", "docker_image": "ghcr.io/example/b:latest"})
    merged = merge_projects(base, overlay)
    assert merged.docker_image == "ghcr.io/example/b:latest"


def test_merge_projects_overlay_adds_new_template_without_touching_others():
    base = ProjectConfig.model_validate(
        {
            "name": "demo",
            "templates": {"observe": {"app": "zsh"}, "develop": {"app": "bash"}},
        }
    )
    overlay = ProjectConfig.model_validate(
        {"name": "demo", "templates": {"claude": {"app": "claude"}}}
    )
    merged = merge_projects(base, overlay)
    assert set(merged.templates) == {"observe", "develop", "claude"}
    assert merged.templates["observe"].app == "zsh"
    assert merged.templates["claude"].app == "claude"


def test_merge_projects_overlay_template_recurses_into_shared_key():
    base = ProjectConfig.model_validate(
        {"name": "demo", "templates": {"develop": {"ecs_cpu": "512", "app": "zsh"}}}
    )
    overlay = ProjectConfig.model_validate(
        {"name": "demo", "templates": {"develop": {"app": "bash"}}}
    )
    merged = merge_projects(base, overlay)
    assert merged.templates["develop"].app == "bash"  # overridden
    assert merged.templates["develop"].ecs_cpu == "512"  # carried through from base


def test_merge_projects_overlay_lists_append():
    base = ProjectConfig.model_validate(
        {"name": "demo", "secrets": [{"name": "GITHUB_TOKEN"}]}
    )
    overlay = ProjectConfig.model_validate(
        {"name": "demo", "secrets": [{"name": "MY_TOKEN"}]}
    )
    merged = merge_projects(base, overlay)
    assert [s.name for s in merged.secrets] == ["GITHUB_TOKEN", "MY_TOKEN"]


def test_app_defaults_to_bash_not_zsh():
    """Audit 2026-10-16 P0 #10: no base image installs zsh (it's commented out in
    both dev-base Dockerfiles), so a template that didn't set `app` got a tmux
    session whose command exited immediately on a remote workspace -- killing the
    container right after it started. bash is guaranteed present on every image."""
    project = ProjectConfig.model_validate({"name": "demo"})
    assert project.app == "bash"


def test_env_merges_key_by_key_child_wins():
    root = ProjectConfig.model_validate(
        {
            "name": "demo",
            "env": {"OLLAMA_HOST": "http://a:11434", "LOG_LEVEL": "info"},
            "templates": {"develop": {"env": {"LOG_LEVEL": "debug", "OTEL_EXPORTER_OTLP_ENDPOINT": "http://otel"}}},
        }
    )
    resolved = resolve_template(root, "develop")
    assert resolved.env == {
        "OLLAMA_HOST": "http://a:11434",
        "LOG_LEVEL": "debug",
        "OTEL_EXPORTER_OTLP_ENDPOINT": "http://otel",
    }


def test_env_merges_through_user_overlay():
    base = ProjectConfig.model_validate({"name": "demo", "env": {"A": "1"}})
    overlay = ProjectConfig.model_validate({"name": "demo", "env": {"B": "2"}})
    assert merge_projects(base, overlay).env == {"A": "1", "B": "2"}


@pytest.mark.parametrize("name", ["WARREN_APP", "WARREN_WORKSPACE_ID", "HOME", "PATH", "1BAD", "A-B"])
def test_env_rejects_reserved_or_invalid_names(name):
    with pytest.raises(ValueError):
        ProjectConfig.model_validate({"name": "demo", "env": {name: "x"}})


def test_template_env_for_drops_reserved_and_excluded_names():
    from warren_common.models import template_env_for

    got = template_env_for(
        {"OLLAMA_HOST": "h", "WARREN_APP": "evil", "HOME": "/", "API_KEY": "plain"},
        exclude=["API_KEY"],
    )
    assert got == {"OLLAMA_HOST": "h"}


def test_harnesses_append_and_unknown_rejected():
    from warren_common.models import ProjectConfig

    root = _project(dev={"harnesses": ["claude"]})
    assert resolve_template(root, "dev").harnesses == ["claude"]
    with pytest.raises(ValueError, match="unknown harness"):
        ProjectConfig.model_validate({"name": "x", "harnesses": ["nope"]})


def test_custom_harness_command_from_parent_template():
    root = _project(agent={"custom_harness": {"command": "python -m g"}, "templates": {"run": {"harnesses": ["custom"]}}})
    assert resolve_template(root, "agent.run").harnesses == ["custom"]


def test_vendor_cloud_ban_inherited_from_parent():
    root = _project(dev={"allow_vendor_cloud": False, "templates": {"c": {"harnesses": ["cursor-agent"]}}})
    with pytest.raises(ValueError, match="allow_vendor_cloud"):
        resolve_template(root, "dev.c")
    assert resolve_template(root, "dev.c", validate=False).harnesses == ["cursor-agent"]


def test_aws_mode_defaults_to_export_and_merges():
    assert resolve_template(_project(dev={"aws": {"profile": "dev"}}), "dev").aws.mode == "export"
    sso = resolve_template(_project(dev={"aws": {"mode": "sso", "profile": "p"}}), "dev")
    assert sso.aws.mode == "sso"


@pytest.mark.parametrize("runtime_type", ["docker", "ecs", "podman", "server (ecs)"])
def test_aws_sso_mode_rejected_outside_local_sandboxes(runtime_type):
    from warren_common.models import AwsConfig, check_aws_mode

    with pytest.raises(ValueError, match="only allowed for local runtimes"):
        check_aws_mode(AwsConfig(mode="sso"), runtime_type)
    check_aws_mode(AwsConfig(mode="export"), runtime_type)


@pytest.mark.parametrize("runtime_type", ["seatbelt", "bwrap", "nsjail"])
def test_aws_sso_mode_allowed_for_local_sandboxes(runtime_type):
    from warren_common.models import AwsConfig, check_aws_mode

    check_aws_mode(AwsConfig(mode="sso"), runtime_type)


def test_kind_defaults_to_user_and_agent_needs_a_harness():
    from warren_common.harness import HarnessSelectionError
    from warren_common.models import ProjectConfig
    from warren_common.templates import resolve_template

    root = ProjectConfig.model_validate({
        "name": "p",
        "agent": {"port": 9000, "restart": {"max_restarts": 2}},
        "templates": {
            "dev": {"harnesses": ["claude"]},
            "bot": {"kind": "agent"},
            "oc": {"kind": "agent", "harness": "opencode", "agent": {"max_peers": 2}},
            "cl": {"kind": "agent", "harness": "claude"},
        },
    })
    assert resolve_template(root, "dev").kind == "user"
    with pytest.raises(HarnessSelectionError, match="needs `harness"):
        resolve_template(root, "bot")
    oc = resolve_template(root, "oc")
    assert (oc.agent.port, oc.agent.max_peers, oc.agent.restart.max_restarts) == (9000, 2, 2)
    with pytest.raises(HarnessSelectionError, match="not ACP: set agent.adapter"):
        resolve_template(root, "cl")
