"""Template `seed_prompt`: the first turn handed to the workspace app on provision (AH9).

Per-app support (the app's own CLI must accept an initial prompt and stay
interactive afterwards):

- claude: `claude "<prompt>"`
- codex:  `codex "<prompt>"`
- gemini: `gemini -i "<prompt>"` (--prompt-interactive)

Any other app (bash, zsh, aider, ...) ignores seed_prompt. Only the first
connect after provision gets it; reconnects and reprovisions never replay it.
"""

from __future__ import annotations

import shlex
from pathlib import PurePosixPath

_SEED_PROMPT_FLAGS: dict[str, tuple[str, ...]] = {
    "claude": (),
    "codex": (),
    "gemini": ("-i",),
}


def _app_name(app: str) -> str:
    try:
        argv = shlex.split(app)
    except ValueError:
        return ""
    return PurePosixPath(argv[0]).name if argv else ""


def supports_seed_prompt(app: str) -> bool:
    return _app_name(app) in _SEED_PROMPT_FLAGS


def seed_prompt_args(app: str, seed_prompt: str | None) -> list[str]:
    if not seed_prompt or not supports_seed_prompt(app):
        return []
    return [*_SEED_PROMPT_FLAGS[_app_name(app)], seed_prompt]


def app_command_with_seed(app: str, seed_prompt: str | None) -> str:
    """`app` as one shell-safe command string with the seed prompt appended,
    for runtimes that take the app as a single string (WARREN_APP, WARREN_APP_CMD)."""
    extra = seed_prompt_args(app, seed_prompt)
    if not extra:
        return app
    return shlex.join([*shlex.split(app), *extra])
