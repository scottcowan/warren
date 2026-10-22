"""The warren shell's harness commands (AG2a). The generated script runs in real
bash/zsh against stub harness binaries on a PATH holding nothing else of note."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from warren_common import harness_shell as hs

# Runs real bash/zsh and /bin/sh against POSIX stub scripts.
pytestmark = pytest.mark.skipif(sys.platform == "win32", reason="POSIX shells and stub executables")

ASSET = Path(hs.__file__).parent / "assets" / hs.ASSET_NAME
INIT = Path(hs.__file__).parent / "assets" / hs.INIT_ASSET_NAME
SHELLS = [s for s in ("bash", "zsh") if shutil.which(s)]
_STUB = """#!/bin/sh
case "$(basename "$0")" in claude) cfg=$CLAUDE_CONFIG_DIR ;; codex) cfg=$CODEX_HOME ;; *) cfg= ;; esac
echo "RAN $(basename "$0") [$*] cfg=$cfg"
if [ -n "$STUB_SID" ]; then
  case "$(basename "$0")" in
    claude) d="$CLAUDE_CONFIG_DIR/projects/$(printf '%s' "$PWD" | sed 's/[^A-Za-z0-9]/-/g')"
            mkdir -p "$d" && : > "$d/$STUB_SID.jsonl" ;;
    codex) mkdir -p "$CODEX_HOME/sessions/2026/10/22"
           : > "$CODEX_HOME/sessions/2026/10/22/rollout-2026-10-22T10-00-00-$STUB_SID.jsonl" ;;
  esac
fi
exit ${STUB_RC:-0}
"""


def test_assets_match_profiles():
    assert INIT.read_text(encoding="utf-8") == hs.render_init(), "regenerate: see below"
    assert ASSET.read_text(encoding="utf-8") == hs.render(), (
        "regenerate: uv run --package warren python -c "
        "'from warren_common import harness_shell as h; h.write_assets()'"
    )


@pytest.fixture
def ws(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name in ("claude", "codex", "agent"):
        stub = bin_dir / name
        stub.write_text(_STUB)
        stub.chmod(0o755)
    (tmp_path / "root").mkdir()
    (tmp_path / "work").mkdir()
    return tmp_path


def run(shell, ws, script, **env):
    base = {
        "HOME": str(ws),
        "PATH": f"{ws / 'bin'}:/usr/bin:/bin",
        "WARREN_HARNESSES": "claude codex",
        "WARREN_HARNESS_ROOT": str(ws / "root"),
        "WARREN_HARNESS_DEFAULT": "claude",
    }
    base.update(env)
    return subprocess.run(
        [shell, "-c", f". {ASSET}\n{script}"],
        env=base, cwd=ws / "work", capture_output=True, text=True, timeout=30,
    )


@pytest.mark.parametrize("shell", SHELLS)
def test_harness_command_applies_profile_and_returns_to_shell(shell, ws):
    r = run(shell, ws, "claude hi there; echo back=$?; codex; echo done")
    root = ws / "root"
    assert f"RAN claude [hi there] cfg={root}/claude" in r.stdout
    assert "back=0" in r.stdout
    assert f"RAN codex [--sandbox danger-full-access] cfg={root}/codex" in r.stdout
    assert r.stdout.rstrip().endswith("done")
    assert (root / ".session" / "last").read_text().strip() == "codex"


@pytest.mark.parametrize("shell", SHELLS)
def test_exit_code_passes_through(shell, ws):
    r = run(shell, ws, "claude; echo rc=$?", STUB_RC="3")
    assert "rc=3" in r.stdout


@pytest.mark.parametrize("shell", SHELLS)
def test_only_selected_harnesses_become_commands(shell, ws):
    r = run(shell, ws, "type codex | grep -q function && echo has-codex; warren resume codex; echo rc=$?",
            WARREN_HARNESSES="claude")
    assert "has-codex" not in r.stdout
    assert "rc=2" in r.stdout
    assert "not one of this workspace's harnesses" in r.stderr


@pytest.mark.parametrize("shell", SHELLS)
def test_warren_resume_defaults_to_last_used_then_default(shell, ws):
    r = run(shell, ws, "warren resume")
    assert "RAN claude [--continue]" in r.stdout
    r = run(shell, ws, "codex; warren resume")
    assert "RAN codex [--sandbox danger-full-access resume --last]" in r.stdout


@pytest.mark.parametrize("shell", SHELLS)
def test_warren_other_commands_use_cli_or_explain(shell, ws):
    r = run(shell, ws, "warren list; echo rc=$?")
    assert "rc=2" in r.stdout and "warren resume" in r.stderr
    r = run(shell, ws, 'warren list a', WARREN_CLI='echo CLI')
    assert "CLI list a" in r.stdout


@pytest.mark.parametrize("shell", SHELLS)
def test_connect_with_harness_starts_it_resuming(shell, ws):
    r = run(shell, ws, "echo after", WARREN_CONNECT="1", WARREN_CONNECT_HARNESS="codex")
    assert "harnesses (" in r.stdout
    assert "RAN codex [--sandbox danger-full-access resume --last]" in r.stdout
    assert r.stdout.rstrip().endswith("after")


@pytest.mark.parametrize("shell", SHELLS)
def test_connect_new_with_harness_starts_fresh(shell, ws):
    r = run(shell, ws, "true", WARREN_CONNECT="1", WARREN_CONNECT_HARNESS="claude", WARREN_CONNECT_NEW="1")
    assert "RAN claude []" in r.stdout


@pytest.mark.parametrize("shell", SHELLS)
def test_connect_without_harness_lands_in_shell(shell, ws):
    r = run(shell, ws, "echo shell", WARREN_CONNECT="1")
    assert "RAN" not in r.stdout
    assert "claude" in r.stdout and "shell" in r.stdout


@pytest.mark.parametrize("shell", SHELLS)
def test_seed_prompt_runs_default_harness_once(shell, ws):
    r = run(shell, ws, "true", WARREN_CONNECT="1", WARREN_SEED_PROMPT="fix the bug")
    assert "RAN claude [fix the bug]" in r.stdout
    r = run(shell, ws, "true", WARREN_CONNECT="1", WARREN_SEED_PROMPT="fix the bug")
    assert "RAN" not in r.stdout


@pytest.mark.parametrize("shell", SHELLS)
def test_multi_command_profile_falls_back_to_second_binary(shell, ws):
    r = run(shell, ws, "cursor-agent", WARREN_HARNESSES="cursor-agent", WARREN_HARNESS_DEFAULT="cursor-agent")
    assert "RAN agent [--sandbox disabled]" in r.stdout


@pytest.mark.parametrize("shell", SHELLS)
def test_missing_binary_reports_not_installed(shell, ws):
    r = run(shell, ws, "pi; echo rc=$?", WARREN_HARNESSES="pi")
    assert "rc=127" in r.stdout
    assert "pi is not installed" in r.stderr


@pytest.mark.parametrize("shell", SHELLS)
def test_inert_without_harnesses(shell, ws):
    r = run(shell, ws, "type _warren_on_connect >/dev/null && echo defined; echo ok",
            WARREN_HARNESSES="", WARREN_CONNECT="1")
    assert r.returncode == 0 and "ok" in r.stdout


def test_shell_first_rules():
    assert hs.shell_first("bash") and hs.shell_first("zsh") and hs.shell_first("claude")
    assert hs.shell_first("/usr/local/bin/codex --foo")
    assert not hs.shell_first("claude", "single-turn")
    assert not hs.shell_first("acp-serve --port 9000")
    assert hs.workspace_shell("claude") == "bash"
    assert hs.workspace_shell("/bin/zsh") == "zsh"


def test_default_harness_prefers_app():
    assert hs.default_harness("codex", ["claude"]) == "codex"
    assert hs.default_harness("bash", ["pi", "claude"]) == "claude"
    assert hs.default_harness("bash", []) == ""


def test_session_env():
    env = hs.session_env(["codex", "claude", "custom"], "/var/lib/warren/harness/", app="codex")
    assert env == {
        "WARREN_HARNESSES": "claude codex",
        "WARREN_HARNESS_ROOT": "/var/lib/warren/harness",
        "WARREN_HARNESS_DEFAULT": "codex",
    }
    assert hs.session_env([], "/x") == {}


def test_seed_env_only_for_positional_prompt_harnesses():
    assert hs.seed_env("claude", ["claude"], "go") == {"WARREN_SEED_PROMPT": "go"}
    assert hs.seed_env("bash", ["pi"], "go") == {}
    assert hs.seed_env("claude", ["claude"], None) == {}


def _fake_tmux(ws, live: bool) -> Path:
    tmux = ws / "bin" / "tmux"
    tmux.write_text(
        '#!/bin/sh\necho "tmux $*" >> "$TMUX_LOG"\n'
        f'[ "$1" = has-session ] && exit {0 if live else 1}\nexit 0\n'
    )
    tmux.chmod(0o755)
    return ws / "tmux.log"


@pytest.mark.parametrize(
    ("live", "harness", "new", "expected"),
    [
        (False, "-", "-", "tmux new-session -A -s main -e WARREN_CONNECT=1 zsh"),
        (True, "-", "-", "tmux new-session -A -s main -e WARREN_CONNECT=1 zsh"),
        (True, "codex", "-",
         "tmux new-window -t main -e WARREN_CONNECT=1 -e WARREN_CONNECT_HARNESS=codex zsh ; attach-session -t main"),
        (False, "codex", "new",
         "tmux new-session -A -s main -e WARREN_CONNECT=1 -e WARREN_CONNECT_HARNESS=codex -e WARREN_CONNECT_NEW=1 zsh"),
        (True, "x;rm", "-", "tmux new-session -A -s main -e WARREN_CONNECT=1 zsh"),
    ],
)
def test_tmux_session_script(ws, live, harness, new, expected):
    log = _fake_tmux(ws, live)
    subprocess.run(
        ["/bin/sh", "-c", hs.TMUX_SESSION_SCRIPT, "warren-session", "zsh", harness, new],
        env={"PATH": f"{ws / 'bin'}:/usr/bin:/bin", "TMUX_LOG": str(log)}, check=True, timeout=10,
    )
    assert log.read_text().splitlines()[-1] == expected


# --- AG4: what each harness was doing, and reconnecting to it -------------------

CODEX_A = "0199a1b2-c3d4-7e5f-8a9b-0c1d2e3f4a5b"


def _session(ws) -> Path:
    return ws / "root" / ".session"


def _write_active(ws, harness, *, session_id="", pid="999999", host=None, cwd=None):
    import platform

    d = _session(ws)
    d.mkdir(parents=True, exist_ok=True)
    (d / "active.marker").write_text("")
    (d / "active.json").write_text(
        "{\n"
        f'  "harness": "{harness}",\n'
        f'  "session_id": "{session_id}",\n'
        f'  "cwd": "{cwd or ws / "work"}",\n'
        '  "started_at": "2026-10-22T10:00:00Z",\n'
        f'  "pid": "{pid}",\n'
        f'  "host": "{host or platform.node()}"\n'
        "}\n"
    )


def _claude_session_file(ws, sid):
    import time

    time.sleep(0.05)
    slug = "".join(c if c.isalnum() else "-" for c in str(ws / "work"))
    d = ws / "root" / "claude" / "projects" / slug
    d.mkdir(parents=True, exist_ok=True)
    (d / f"{sid}.jsonl").write_text("{}")


@pytest.mark.parametrize("shell", SHELLS)
def test_running_harness_is_recorded_and_cleared_on_exit(shell, ws):
    r = run(shell, ws, f"claude; cat {_session(ws)}/claude.last", STUB_SID="sess-a")
    assert r.stdout.splitlines()[-2:] == ["sess-a", str(ws / "work")]
    assert not (_session(ws) / "active.json").exists()
    (ws / "bin" / "claude").write_text(f'#!/bin/sh\ncat {_session(ws)}/active.json\n')
    r = run(shell, ws, "claude")
    assert '"harness": "claude"' in r.stdout and f'"cwd": "{ws / "work"}"' in r.stdout
    assert '"started_at": "20' in r.stdout and '"session_id": ""' in r.stdout


@pytest.mark.parametrize("shell", SHELLS)
def test_resume_each_harness_by_its_own_recorded_id(shell, ws):
    """claude, exit, codex, exit, `warren resume claude` -> claude's conversation."""
    r = run(shell, ws, "claude; codex; warren resume claude; warren resume codex", STUB_SID=CODEX_A)
    assert f"RAN claude [--resume {CODEX_A}]" in r.stdout
    assert f"RAN codex [--sandbox danger-full-access resume {CODEX_A}]" in r.stdout
    r = run(shell, ws, "claude", STUB_SID="sess-new")
    r = run(shell, ws, "warren resume")
    assert "RAN claude [--resume sess-new]" in r.stdout


@pytest.mark.parametrize("shell", SHELLS)
def test_resume_without_recorded_id_falls_back_with_message(shell, ws):
    r = run(shell, ws, "warren resume claude")
    assert "RAN claude [--continue]" in r.stdout
    assert "no claude conversation recorded" in r.stdout


@pytest.mark.parametrize("shell", SHELLS)
def test_reconnect_relaunches_harness_on_the_recorded_conversation(shell, ws):
    """Task relaunched mid-harness: resume THAT conversation by id, even when a
    newer session for the same cwd exists."""
    _write_active(ws, "claude", session_id="sess-old")
    _claude_session_file(ws, "sess-newer")
    r = run(shell, ws, "echo shell", WARREN_CONNECT="1")
    assert "was running when the last connection ended" in r.stdout
    assert "RAN claude [--resume sess-old]" in r.stdout
    assert r.stdout.rstrip().endswith("shell")
    assert not (_session(ws) / "active.json").exists()


@pytest.mark.parametrize("shell", SHELLS)
def test_reconnect_reads_the_id_from_the_harness_store(shell, ws):
    _write_active(ws, "claude")
    _claude_session_file(ws, "sess-store")
    r = run(shell, ws, "true", WARREN_CONNECT="1")
    assert "RAN claude [--resume sess-store]" in r.stdout


@pytest.mark.parametrize("shell", SHELLS)
def test_reconnect_without_any_id_uses_resume_args(shell, ws):
    _write_active(ws, "codex")
    r = run(shell, ws, "true", WARREN_CONNECT="1")
    assert "no session id recorded" in r.stdout
    assert "RAN codex [--sandbox danger-full-access resume --last]" in r.stdout


@pytest.mark.parametrize("shell", SHELLS)
def test_reconnect_leaves_a_harness_another_shell_still_runs(shell, ws):
    import os

    _write_active(ws, "claude", session_id="sess-live", pid=str(os.getpid()))
    r = run(shell, ws, "true", WARREN_CONNECT="1")
    assert "still running" in r.stdout
    assert "RAN" not in r.stdout
    assert (_session(ws) / "active.json").exists()


@pytest.mark.parametrize("shell", SHELLS)
def test_reconnect_on_another_host_treats_the_harness_as_gone(shell, ws):
    import os

    _write_active(ws, "claude", session_id="sess-x", pid=str(os.getpid()), host="old-task")
    r = run(shell, ws, "true", WARREN_CONNECT="1")
    assert "RAN claude [--resume sess-x]" in r.stdout


@pytest.mark.parametrize("shell", SHELLS)
def test_reconnect_resumes_in_the_recorded_directory(shell, ws):
    other = ws / "work" / "sub"
    other.mkdir()
    _write_active(ws, "claude", session_id="s1", cwd=str(other))
    (ws / "bin" / "claude").write_text('#!/bin/sh\necho "RAN in $PWD"\n')
    r = run(shell, ws, "echo here=$PWD", WARREN_CONNECT="1")
    assert f"RAN in {other}" in r.stdout
    assert f"here={ws / 'work'}" in r.stdout


@pytest.mark.parametrize("shell", SHELLS)
def test_connect_new_ignores_the_record(shell, ws):
    _write_active(ws, "claude", session_id="sess-old")
    r = run(shell, ws, "echo shell", WARREN_CONNECT="1", WARREN_CONNECT_NEW="1")
    assert "RAN" not in r.stdout
    assert not (_session(ws) / "active.json").exists()


@pytest.mark.parametrize("shell", SHELLS)
def test_banner_marks_last_used_and_prior_conversation(shell, ws):
    run(shell, ws, "codex", STUB_SID=CODEX_A)
    _claude_session_file(ws, "sess-1")
    r = run(shell, ws, "true", WARREN_CONNECT="1")
    lines = {line.split()[0]: line for line in r.stdout.splitlines() if line.startswith("    ")}
    assert "last used" in lines["codex"] and "previous conversation here" in lines["codex"]
    assert "last used" not in lines["claude"] and "previous conversation here" in lines["claude"]


@pytest.mark.parametrize("shell", SHELLS)
def test_tampered_record_never_reaches_argv_unvalidated(shell, ws):
    _write_active(ws, "claude", session_id="x; touch /tmp/pwned")
    r = run(shell, ws, "true", WARREN_CONNECT="1")
    assert "--resume x" not in r.stdout
    assert "RAN claude [--continue]" in r.stdout


@pytest.mark.parametrize("shell", SHELLS)
def test_bedrock_env_reaches_the_harness_and_nothing_logs_it_in(shell, ws):
    """model_access: bedrock -- the wrapper passes the workspace's Bedrock env
    through and never supplies a model credential of its own."""
    (ws / "bin" / "claude").write_text(
        '#!/bin/sh\necho "bedrock=$CLAUDE_CODE_USE_BEDROCK region=$AWS_REGION token=${CLAUDE_CODE_OAUTH_TOKEN:-none}"\n'
    )
    r = run(shell, ws, "claude", CLAUDE_CODE_USE_BEDROCK="1", AWS_REGION="eu-west-1")
    assert "bedrock=1 region=eu-west-1 token=none" in r.stdout
    assert "credentials" not in ASSET.read_text().replace("credentials.json", "")


# --- AB1/AG3: warren-harness-init at container start --------------------------


def _init(tmp_path, harnesses="claude codex", version_stub=True):
    root = tmp_path / "harness"
    bin_dir = tmp_path / "initbin"
    bin_dir.mkdir(exist_ok=True)
    if version_stub:
        (bin_dir / "claude").write_text('#!/bin/sh\n[ "$1" = --version ] && echo "2.1.307 (Claude Code)"\n')
        (bin_dir / "claude").chmod(0o755)
    r = subprocess.run(
        ["/bin/sh", str(INIT), str(root)],
        env={"PATH": f"{bin_dir}:/usr/bin:/bin", "WARREN_HARNESSES": harnesses},
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0, r.stderr
    return root


def test_init_keeps_only_persist_paths_and_drops_credentials(tmp_path):
    import json

    root = tmp_path / "harness"
    c = root / "claude"
    (c / "projects" / "p").mkdir(parents=True)
    (c / "projects" / "p" / "s.jsonl").write_text("{}")
    (c / "projects" / "p" / "auth.json").write_text("tok")
    (c / "history.jsonl").write_text("h")
    (c / ".credentials.json").write_text("tok")
    (c / "statsig").mkdir()
    (c / ".claude.json").write_text(json.dumps({"mcpServers": {"x": {"command": "evil"}}}))
    (tmp_path / "outside").mkdir()
    (tmp_path / "outside" / "keep").write_text("x")
    (c / "evil").symlink_to(tmp_path / "outside")
    (root / "codex").symlink_to(tmp_path / "outside")
    (root / "pi").mkdir()
    (root / "pi" / "stale").write_text("x")
    (root / ".session").mkdir()
    (root / ".session" / "active.json").write_text("{}")

    _init(tmp_path)

    assert sorted(p.name for p in c.iterdir()) == [".claude.json", "history.jsonl", "projects", "settings.json", "todos"]
    assert (c / "projects" / "p" / "s.jsonl").exists()
    assert not (c / "projects" / "p" / "auth.json").exists()
    assert (tmp_path / "outside" / "keep").exists()
    assert (root / "codex").is_dir() and not (root / "codex").is_symlink()
    assert sorted(p.name for p in (root / "codex").iterdir()) == ["config.toml", "hooks.json", "log", "sessions"]
    assert (root / "pi" / "stale").exists(), "harnesses not in the template are left alone"
    assert (root / ".session" / "active.json").exists()


def test_init_regenerates_a_minimal_claude_json_every_start(tmp_path):
    """No onboarding after a relaunch, and nothing the workspace wrote survives."""
    import json

    root = _init(tmp_path)
    cj = root / "claude" / ".claude.json"
    assert json.loads(cj.read_text()) == {
        "hasCompletedOnboarding": True, "hasCompletedFirstRun": True, "lastOnboardingVersion": "2.1.307",
    }
    assert oct(cj.stat().st_mode & 0o777) == "0o600"
    cj.write_text(json.dumps({"mcpServers": {"x": {"command": "evil"}}, "hasCompletedOnboarding": True}))
    victim = tmp_path / "victim"
    victim.write_text("host")
    cj.unlink()
    cj.symlink_to(victim)
    _init(tmp_path)
    assert not cj.is_symlink() and "mcpServers" not in cj.read_text()
    assert victim.read_text() == "host"


def test_init_without_the_harness_binary_omits_the_version(tmp_path):
    import json

    root = _init(tmp_path, harnesses="claude", version_stub=False)
    assert json.loads((root / "claude" / ".claude.json").read_text()) == {
        "hasCompletedOnboarding": True, "hasCompletedFirstRun": True,
    }


def test_init_ignores_unknown_names(tmp_path):
    root = _init(tmp_path, harnesses="../etc nope")
    assert sorted(p.name for p in root.iterdir()) == [".session"]
