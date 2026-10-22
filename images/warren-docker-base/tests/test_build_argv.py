"""`_build_argv` quoting/splitting (audit 2026-10-16 #37).

entrypoint.py is a standalone image script, not an installed package --
loaded directly by file path here (no warren-docker-base package to import).
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

_ENTRYPOINT_PATH = Path(__file__).parent.parent / "entrypoint.py"
_spec = importlib.util.spec_from_file_location("warren_entrypoint", _ENTRYPOINT_PATH)
_entrypoint = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_entrypoint)

_build_argv = _entrypoint._build_argv


def _set_tty(monkeypatch, is_tty: bool) -> None:
    monkeypatch.setattr(sys.stdin, "isatty", lambda: is_tty)


def test_tty_mode_splits_multi_word_app_into_argv(monkeypatch):
    """Regression guard: a WARREN_APP like "claude --dangerously-skip-permissions"
    used to become ONE literal argv[0] in TTY mode (fails to exec), while the
    same value worked fine headless. Must split into a proper argv list."""
    _set_tty(monkeypatch, True)
    argv = _build_argv("claude --dangerously-skip-permissions")
    assert argv == ["claude", "--dangerously-skip-permissions"]


def test_tty_mode_single_word_app_unchanged(monkeypatch):
    _set_tty(monkeypatch, True)
    assert _build_argv("bash") == ["bash"]


def test_headless_mode_shell_quotes_app_with_embedded_single_quote(monkeypatch):
    """Regression guard: naive single-quote wrapping around the WHOLE
    constructed `sh -c` command breaks (or injects into) the shell command
    when app_cmd itself contains a single quote."""
    _set_tty(monkeypatch, False)
    malicious = "bash -c 'echo pwned'"
    argv = _build_argv(malicious)
    assert argv[0] == "sh"
    assert argv[1] == "-c"
    command = argv[2]
    # The malicious value must appear as a single properly shell-quoted
    # token, never splitting tmux's own command structure.
    import shlex

    assert shlex.quote(malicious) in command
    # And it must not have let a bare, unescaped "'" from app_cmd terminate
    # the quoted segment early.
    assert command.count("tmux new-session -d -s main") == 1


def test_headless_mode_simple_app_still_builds_tmux_wait_command(monkeypatch):
    _set_tty(monkeypatch, False)
    argv = _build_argv("bash")
    assert argv[0] == "sh"
    assert argv[1] == "-c"
    assert "tmux new-session -d -s main bash" in argv[2]
    assert "tmux wait-for done" in argv[2]


def test_headless_mode_sets_status_left_from_env(monkeypatch):
    """UX-1: status-left must mark the session with project/template so the
    ⬡ mark survives a later `tmux attach -t main` reconnect, not just the
    shell's own one-time banner/PROMPT."""
    _set_tty(monkeypatch, False)
    monkeypatch.setenv("WARREN_PROJECT", "myproj")
    monkeypatch.setenv("WARREN_TEMPLATE", "observe")
    argv = _build_argv("bash")
    command = argv[2]
    assert "set-option -g status-left" in command
    import shlex

    assert shlex.quote("⬡ myproj/observe ") in command


def test_headless_mode_status_left_empty_env_does_not_crash(monkeypatch):
    _set_tty(monkeypatch, False)
    monkeypatch.delenv("WARREN_PROJECT", raising=False)
    monkeypatch.delenv("WARREN_TEMPLATE", raising=False)
    argv = _build_argv("bash")
    assert "set-option -g status-left" in argv[2]


def test_headless_mode_status_left_escapes_tmux_format_hash(monkeypatch):
    """Audit U3: shlex.quote only protects the outer shell -- tmux parses the
    status-left STRING CONTENT itself for "#"-prefixed format sequences
    (e.g. "#(cmd)" runs a shell command at render time), a separate escaping
    layer. A "#" in a project/template name (set by an authenticated, not
    necessarily admin, user) must reach tmux as a literal "##", never as an
    unescaped single "#" that could be interpreted as a format sequence."""
    _set_tty(monkeypatch, False)
    monkeypatch.setenv("WARREN_PROJECT", "proj#(touch /tmp/pwned)")
    monkeypatch.setenv("WARREN_TEMPLATE", "observe")
    argv = _build_argv("bash")
    command = argv[2]
    import shlex

    # The "#" must reach tmux doubled ("##") -- a single unescaped "#(" is
    # what tmux would try to interpret as a format command.
    assert shlex.quote("⬡ proj##(touch /tmp/pwned)/observe ") in command
    assert "proj#(touch" not in command


def test_headless_shell_first_keeps_container_up_without_a_session(monkeypatch):
    """AG2a: connect creates tmux session `main` with the warren shell, so leaving
    the shell or a harness never ends the container."""
    _set_tty(monkeypatch, False)
    monkeypatch.setenv("WARREN_SHELL_FIRST", "1")
    assert _build_argv("bash") == ["tail", "-f", "/dev/null"]


def test_session_env_copies_only_plain_values(monkeypatch, tmp_path):
    monkeypatch.setenv("WARREN_HARNESSES", "claude codex")
    monkeypatch.setenv("WARREN_HARNESS_ROOT", "/var/lib/warren/harness")
    monkeypatch.setenv("WARREN_PROJECT", "x'; rm -rf / #")
    out = tmp_path / "session.env"
    _entrypoint.write_session_env(str(out))
    text = out.read_text()
    assert "WARREN_HARNESSES='claude codex'\n" in text
    assert "WARREN_HARNESS_ROOT='/var/lib/warren/harness'\n" in text
    assert "WARREN_PROJECT" not in text



def test_init_harness_dirs_runs_the_generated_init(monkeypatch, tmp_path):
    """AB1/AG3: preflight hands the harness dirs to the image's warren-harness-init."""
    init = Path(__file__).parents[3] / "packages/warren-common/src/warren_common/assets/warren_harness_init.sh"
    (tmp_path / "claude").mkdir()
    (tmp_path / "claude" / ".credentials.json").write_text("tok")
    monkeypatch.setenv("WARREN_HARNESSES", "claude")
    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    _entrypoint.init_harness_dirs(str(init), str(tmp_path))
    assert sorted(p.name for p in (tmp_path / "claude").iterdir()) == [".claude.json", "projects", "settings.json", "todos"]
    monkeypatch.delenv("WARREN_HARNESSES")
    _entrypoint.init_harness_dirs(str(init), str(tmp_path / "unused"))
    assert not (tmp_path / "unused").exists()


def test_agent_supervisor_starts_beside_the_shell_only_for_agent_workspaces(monkeypatch, tmp_path):
    """AG2b: podman agent workspaces run the supervisor as a child; tmux `main` keeps the shell."""
    script = tmp_path / "sup.py"
    script.write_text("import os, sys\nsys.exit(0 if os.environ.get('WARREN_AGENT_SPEC') == '{}' else 9)\n")
    monkeypatch.delenv("WARREN_AGENT_SPEC", raising=False)
    assert _entrypoint.start_agent_supervisor(str(script)) is None
    monkeypatch.setenv("WARREN_AGENT_SPEC", "{}")
    proc = _entrypoint.start_agent_supervisor(str(script))
    assert proc.wait(10) == 0
