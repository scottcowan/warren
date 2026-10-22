"""AG1/AJ1: harness profile registry and template validation."""

from __future__ import annotations

import pytest

from warren_common.harness import (
    CUSTOM,
    PROFILES,
    SELECTABLE_HARNESSES,
    HarnessSelectionError,
    cloud_handoff_warnings,
    harness_env,
    sandbox_grants,
    selected_harnesses,
    validate_harness_selection,
)
from warren_common.models import ProjectConfig

INITIAL = {"claude", "codex", "opencode", "cursor-agent", "pi"}


def test_initial_profiles_selectable_and_unverified():
    assert SELECTABLE_HARNESSES == INITIAL | {CUSTOM}
    for name in INITIAL:
        p = PROFILES[name]
        assert p.command and p.host_config and p.config_env and p.resume_args and p.resume_by_id_args
        assert p.verified is False


def test_listed_harnesses_have_config_dirs_but_are_not_selectable():
    listed = [p for p in PROFILES.values() if not p.selectable]
    assert {p.name for p in listed} >= {"copilot", "qwen", "grok", "antigravity-cli"}
    assert all(p.host_config for p in listed)
    with pytest.raises(ValueError, match="not selectable"):
        ProjectConfig.model_validate({"name": "x", "harnesses": ["copilot"]})


def test_unknown_harness_rejected():
    with pytest.raises(ValueError, match="unknown harness"):
        ProjectConfig.model_validate({"name": "x", "harnesses": ["nope"]})


def test_custom_requires_explicit_command():
    with pytest.raises(HarnessSelectionError, match="explicit"):
        validate_harness_selection([CUSTOM])
    with pytest.raises(HarnessSelectionError, match="not in harnesses"):
        validate_harness_selection([], custom_command="python -m g")
    validate_harness_selection([CUSTOM], custom_command="python -m g")


def test_custom_inherits_no_known_harness():
    assert selected_harnesses("claude --x", [CUSTOM]) == {CUSTOM}
    assert selected_harnesses("/usr/local/bin/codex", []) == {"codex"}
    g = sandbox_grants([CUSTOM], home="/h", root="/s/harness")
    assert g.read == () and g.write == () and g.readonly == ()


def test_custom_readonly_paths_are_workspace_relative():
    with pytest.raises(ValueError, match="relative"):
        ProjectConfig.model_validate({"name": "x", "custom_harness": {"command": "x", "readonly": ["/etc"]}})
    g = sandbox_grants([CUSTOM], home="/h", root="/s", custom_readonly=["cfg.yaml"], workspace_root="/w")
    assert g.readonly == ("/w/cfg.yaml",)


@pytest.mark.parametrize("name", ["cursor-agent", "claude", "codex"])
def test_allow_vendor_cloud_false_rejects_cloud_handoff(name):
    with pytest.raises(HarnessSelectionError, match="vendor"):
        validate_harness_selection([name], allow_vendor_cloud=False)


@pytest.mark.parametrize("name", ["opencode", "pi"])
def test_allow_vendor_cloud_false_allows_local_only(name):
    validate_harness_selection([name], allow_vendor_cloud=False)


def test_cloud_handoff_documented():
    assert "&" in PROFILES["cursor-agent"].cloud_handoff.how
    assert all("to verify" in PROFILES[n].cloud_handoff.how for n in ("claude", "codex"))
    assert cloud_handoff_warnings(["pi"]) == []
    assert "cursor-agent" in cloud_handoff_warnings(["cursor-agent"])[0]


def test_harness_env_points_into_workspace_dir():
    env = harness_env(["opencode", "codex"], "/var/lib/warren/harness")
    assert env["CODEX_HOME"] == "/var/lib/warren/harness/codex"
    assert env["OPENCODE_CONFIG_DIR"] == "/var/lib/warren/harness/opencode/config"
    assert env["OPENCODE_DB"] == "/var/lib/warren/harness/opencode/data/opencode.db"
    assert env["OPENCODE_DISABLE_AUTOUPDATE"] == "1"
    assert "CLAUDE_CONFIG_DIR" not in env


def test_every_profile_persists_only_conversation_state():
    """AB1: no shipped profile persists credentials, settings or code."""
    from warren_common.harness import PROFILES, check_persist

    for p in PROFILES.values():
        check_persist(p)


@pytest.mark.parametrize(
    "persist", [(".credentials.json",), ("auth.json",), ("settings.local.json",), ("plugins/",), ("../x",), (".",),
                ("a/b",), ("/abs",), ("config.toml",)],
)
def test_check_persist_rejects_credentials_config_and_escapes(persist):
    from warren_common.harness import HarnessProfile, check_persist

    with pytest.raises(ValueError):
        check_persist(HarnessProfile(name="x", persist=persist, readonly=("config.toml",)))


def test_server_env_is_harness_names_only_for_shell_first():
    from warren_common.harness_shell import server_env

    assert server_env(["claude", "codex", "custom"], app="bash") == {
        "WARREN_HARNESSES": "claude codex",
        "WARREN_HARNESS_ROOT": "/var/lib/warren/harness",
        "WARREN_HARNESS_DEFAULT": "claude",
    }
    pid1 = server_env(["codex"], app="codex", mode="single-turn")
    assert pid1["CODEX_HOME"] == "/var/lib/warren/harness/codex"
    assert server_env(["custom"]) == {}


@pytest.mark.parametrize(
    "model_access,env,expected",
    [
        ("bedrock", {}, True),
        (None, {"CLAUDE_CODE_USE_BEDROCK": "1"}, True),
        (None, {"CLAUDE_CODE_USE_BEDROCK": "true"}, True),
        (None, {"ANTHROPIC_BEDROCK_BASE_URL": "https://b"}, True),
        ("subscription", {"CLAUDE_CODE_USE_BEDROCK": "1"}, True),
        (None, {"CLAUDE_CODE_USE_BEDROCK": "0"}, False),
        ("subscription", {}, False),
        (None, {}, False),
    ],
)
def test_bedrock_mode_from_field_or_env(model_access, env, expected):
    from warren_common.harness import bedrock_mode

    assert bedrock_mode(model_access, env) is expected


def test_bedrock_template_rejects_oauth_token_secret():
    from warren_common.templates import resolve_template

    root = ProjectConfig.model_validate({
        "name": "x",
        "templates": {"b": {"env": {"CLAUDE_CODE_USE_BEDROCK": "1"}, "secrets": [{"name": "CLAUDE_CODE_OAUTH_TOKEN"}]}},
    })
    with pytest.raises(ValueError, match="AWS identity"):
        resolve_template(root, "b")
