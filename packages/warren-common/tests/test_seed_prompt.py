from __future__ import annotations

import shlex

import pytest

from warren_common import ProjectConfig, resolve_template
from warren_common.seed_prompt import app_command_with_seed, seed_prompt_args


@pytest.mark.parametrize(
    ("app", "expected"),
    [
        ("claude", ["fix the tests"]),
        ("/usr/local/bin/claude", ["fix the tests"]),
        ("claude --dangerously-skip-permissions", ["fix the tests"]),
        ("codex", ["fix the tests"]),
        ("gemini", ["-i", "fix the tests"]),
        ("bash", []),
        ("zsh", []),
        ("aider", []),
    ],
)
def test_seed_prompt_args_per_app(app, expected):
    assert seed_prompt_args(app, "fix the tests") == expected


def test_no_seed_prompt_is_a_noop():
    assert seed_prompt_args("claude", None) == []
    assert app_command_with_seed("claude --x", None) == "claude --x"


def test_app_command_with_seed_is_shell_safe():
    cmd = app_command_with_seed("claude --dangerously-skip-permissions", "it's $(rm -rf /)")
    assert shlex.split(cmd) == ["claude", "--dangerously-skip-permissions", "it's $(rm -rf /)"]


def test_seed_prompt_overrides_through_templates():
    root = ProjectConfig.model_validate(
        {"name": "demo", "seed_prompt": "root", "templates": {"a": {}, "b": {"seed_prompt": "child"}}}
    )
    assert resolve_template(root, "a").seed_prompt == "root"
    assert resolve_template(root, "b").seed_prompt == "child"
