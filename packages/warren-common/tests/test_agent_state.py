"""AG5 state hooks: the hook script, the generated hook config, exact session ids,
and the OSC fallback. Hook events are simulated; no harness binary runs."""

from __future__ import annotations

import json
import shlex
import stat
import subprocess
import sys
from pathlib import Path

import pytest

from warren_common import agent_state as st
from warren_common import harness_shell as hs
from warren_common.harness import PROFILES, sandbox_grants
from warren_common.harness_config import prepare_harness_dirs

HOOK = Path(st.__file__).parent / "assets" / st.HOOK_ASSET_NAME
ASSET = Path(hs.__file__).parent / "assets" / hs.ASSET_NAME
INIT = Path(hs.__file__).parent / "assets" / hs.INIT_ASSET_NAME
posix = pytest.mark.skipif(sys.platform == "win32", reason="POSIX shell")


def fire(d: Path | None, harness: str, event: str, stdin: str = ""):
    env = {"PATH": "/usr/bin:/bin", "WARREN_STATE_HOOK": str(HOOK)}
    if d is not None:
        env["WARREN_STATE_DIR"] = str(d)
    cmd = st.hook_command(harness, event)
    return subprocess.run(["sh", "-c", cmd], input=stdin, env=env, capture_output=True, text=True, timeout=10)


def state(d: Path) -> st.AgentState | None:
    return st.parse_state((d / st.STATE_FILE).read_bytes())


@posix
def test_hook_is_inert_without_warren_env(tmp_path):
    r = fire(None, "claude", "Stop", '{"session_id": "abc"}')
    assert r.returncode == 0 and r.stdout == ""
    r = subprocess.run(["sh", "-c", st.hook_command("claude", "Stop")], env={"PATH": "/usr/bin:/bin"}, timeout=10)
    assert r.returncode == 0
    assert list(tmp_path.iterdir()) == []


@posix
@pytest.mark.parametrize(
    ("harness", "event", "expected"),
    [
        ("claude", "SessionStart", "idle"),
        ("claude", "UserPromptSubmit", "working"),
        ("claude", "PreToolUse", "working"),
        ("claude", "SubagentStart", "working"),
        ("claude", "PermissionRequest", "blocked"),
        ("claude", "Stop", "idle"),
        ("claude", "StopFailure", "idle"),
        ("claude", "SessionEnd", "exited"),
        ("codex", "PostToolUse", "working"),
        ("cursor-agent", "beforeSubmitPrompt", "working"),
        ("cursor-agent", "stop", "idle"),
    ],
)
def test_events_map_to_states(tmp_path, harness, event, expected):
    r = fire(tmp_path, harness, event, '{"hook_event_name": "x", "session_id": "0b5e-41.a_Z"}')
    assert r.returncode == 0 and r.stdout == ""
    s = state(tmp_path)
    assert (s.state, s.harness, s.session_id, s.event) == (expected, harness, "0b5e-41.a_Z", event)
    assert (tmp_path / f"{harness}.sid").read_text().strip() == "0b5e-41.a_Z"


@posix
def test_session_id_from_argument_and_cursor_conversation_id(tmp_path):
    # The opencode plugin and pi extension run the script with the id as an argument.
    env = {"PATH": "/usr/bin:/bin", "WARREN_STATE_DIR": str(tmp_path)}
    subprocess.run(["sh", str(HOOK), "opencode", "SessionStart", "ses_123"], env=env, stdin=subprocess.DEVNULL, timeout=10)
    assert state(tmp_path).session_id == "ses_123"
    fire(tmp_path, "cursor-agent", "sessionStart", '{"conversation_id": "c-9"}')
    assert state(tmp_path).session_id == "c-9"


@posix
def test_unknown_event_and_bad_ids_are_ignored(tmp_path):
    fire(tmp_path, "claude", "Whatever", '{"session_id": "a"}')
    assert not (tmp_path / st.STATE_FILE).exists()
    fire(tmp_path, "claude", "Stop", '{"session_id": "../../etc; rm -rf"}')
    assert state(tmp_path).session_id == ""
    assert not (tmp_path / "claude.sid").exists()
    fire(tmp_path, "../x", "Stop")
    assert state(tmp_path).harness == "claude"


@posix
def test_hook_replaces_links_instead_of_following_them(tmp_path):
    victim = tmp_path / "victim"
    victim.write_text("keep")
    d = tmp_path / "s"
    d.mkdir()
    (d / st.STATE_FILE).symlink_to(victim)
    fire(d, "claude", "Stop", '{"session_id": "s1"}')
    assert victim.read_text() == "keep"
    assert not (d / st.STATE_FILE).is_symlink() and state(d).state == "idle"
    linked = tmp_path / "linked"
    linked.symlink_to(d)
    (d / st.STATE_FILE).unlink()
    fire(linked, "claude", "Stop")
    assert not (d / st.STATE_FILE).exists()


@posix
def test_hook_writes_the_session_id_into_active_json(tmp_path):
    active = '{\n  "harness": "claude",\n  "session_id": "",\n  "cwd": "/w",\n  "started_at": "t",\n  "pid": "1",\n  "host": "h"\n}\n'
    (tmp_path / "active.json").write_text(active)
    fire(tmp_path, "codex", "SessionStart", '{"session_id": "other"}')
    assert '"session_id": ""' in (tmp_path / "active.json").read_text()
    fire(tmp_path, "claude", "SessionStart", '{"session_id": "abc-1"}')
    assert (tmp_path / "active.json").read_text() == active.replace('"session_id": ""', '"session_id": "abc-1"')


def test_profiles_install_hooks_into_readonly_config():
    for name in ("claude", "codex", "cursor-agent", "opencode", "pi"):
        hook = PROFILES[name].state_hook
        assert hook is not None, name
        ro = PROFILES[name].readonly
        for rel in hook.files:
            assert rel in ro or any(rel.startswith(r) for r in ro if r.endswith("/")), (name, rel)
    claude = json.loads(PROFILES["claude"].state_hook.files["settings.json"])["hooks"]
    assert set(claude) == set(st.CLAUDE_EVENTS)
    assert claude["PreToolUse"][0]["matcher"] == "*"
    cursor = json.loads(PROFILES["cursor-agent"].state_hook.files["hooks.json"])
    assert cursor["version"] == 1 and set(cursor["hooks"]) >= {"sessionStart", "stop"}
    assert "codex_hooks = true" in PROFILES["codex"].generated["config.toml"]
    assert "WARREN_STATE_HOOK" in PROFILES["opencode"].state_hook.files["config/plugins/warren-state.js"]
    assert "WARREN_STATE_HOOK" in PROFILES["pi"].state_hook.files["extensions/warren-state.ts"]


@pytest.mark.skipif(sys.platform == "win32", reason="fd-relative writes")
def test_prepare_writes_hook_files_read_only_and_replaces_operator_hooks(tmp_path):
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    (home / ".claude" / "settings.json").write_text(json.dumps({
        "model": "opus", "disableAllHooks": True, "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "host.sh"}]}]},
    }))
    root = tmp_path / "root"
    prepare_harness_dirs(["claude", "codex", "cursor-agent", "opencode", "pi"], root, home=home)
    settings = json.loads((root / "claude" / "settings.json").read_text())
    assert settings["model"] == "opus" and "disableAllHooks" not in settings
    assert "host.sh" not in json.dumps(settings) and set(settings["hooks"]) == set(st.CLAUDE_EVENTS)
    for rel in ("claude/settings.json", "codex/hooks.json", "cursor-agent/hooks.json",
                "opencode/config/plugins/warren-state.js", "pi/extensions/warren-state.ts",
                f"{st.HOOKS_DIR}/{st.HOOK_SCRIPT}"):
        assert stat.S_IMODE((root / rel).lstat().st_mode) == 0o400, rel
    assert (root / st.HOOKS_DIR / st.HOOK_SCRIPT).read_text() == HOOK.read_text()
    grants = sandbox_grants(["claude"], home=home, root=root)
    assert f"{root}/{st.HOOKS_DIR}" in grants.readonly
    assert f"{root}/claude/settings.json" in grants.readonly
    assert f"{root}/.session" in grants.write


@posix
def test_init_writes_the_hook_config_on_server_images(tmp_path):
    root = tmp_path / "harness"
    (root / "codex").mkdir(parents=True)
    (root / "codex" / "hooks.json").write_text('{"hooks": {}}')
    env = {"PATH": "/usr/bin:/bin", "WARREN_HARNESSES": "claude codex cursor-agent opencode pi"}
    subprocess.run(["sh", str(INIT), str(root)], env=env, check=True, timeout=30)
    assert json.loads((root / "codex" / "hooks.json").read_text()) == json.loads(st.codex_hooks())
    assert json.loads((root / "claude" / "settings.json").read_text()) == json.loads(st.claude_settings())
    assert json.loads((root / "cursor-agent" / "hooks.json").read_text())["version"] == 1
    assert (root / "opencode" / "config" / "plugins" / "warren-state.js").read_text() == st.OPENCODE_PLUGIN
    assert (root / "pi" / "extensions" / "warren-state.ts").read_text() == st.PI_EXTENSION


def _stub(sid: str, store_sid: str) -> str:
    """A fake claude: fires its configured SessionStart hook with `sid`, and leaves a
    newer, different session in its own store (the old guess would pick that one)."""
    cmd = st.hook_command("claude", "SessionStart")
    return (
        "#!/bin/sh\n"
        f'echo "RAN claude [$*]"\n'
        f"printf '%s' '{{\"session_id\": \"{sid}\"}}' | sh -c {shlex.quote(cmd)}\n"
        'd="$CLAUDE_CONFIG_DIR/projects/x"; mkdir -p "$d"\n'
        f': > "$d/{store_sid}.jsonl"\n'
    )


@posix
@pytest.mark.parametrize("shell", [s for s in ("bash", "zsh") if __import__("shutil").which(s)])
def test_hook_session_id_beats_the_session_store_guess(shell, tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "claude").write_text(_stub("hook-sid-1", "store-guess-2"))
    (bin_dir / "claude").chmod(0o755)
    root = tmp_path / "root"
    (root / ".session").mkdir(parents=True)
    env = {
        "HOME": str(tmp_path), "PATH": f"{bin_dir}:/usr/bin:/bin",
        "WARREN_HARNESSES": "claude", "WARREN_HARNESS_ROOT": str(root), "WARREN_HARNESS_DEFAULT": "claude",
        "WARREN_STATE_HOOK": str(HOOK),
    }
    run = lambda script: subprocess.run(  # noqa: E731
        [shell, "-c", f". {ASSET}\n{script}"], env=env, cwd=tmp_path, capture_output=True, text=True, timeout=30
    )
    run("claude")
    assert (root / ".session" / "claude.last").read_text().splitlines()[0] == "hook-sid-1"
    assert state(root / ".session").session_id == "hook-sid-1"
    r = run("warren resume claude")
    assert "RAN claude [--resume hook-sid-1]" in r.stdout


def test_session_env_points_local_shells_at_the_readonly_hook(tmp_path):
    env = hs.session_env(["claude"], str(tmp_path))
    assert env["WARREN_STATE_HOOK"] == f"{tmp_path}/{st.HOOKS_DIR}/{st.HOOK_SCRIPT}"
    assert "WARREN_STATE_HOOK" not in hs.session_env(["claude"], "/var/lib/warren/harness")
    text = ASSET.read_text()
    assert 'WARREN_STATE_DIR="$WARREN_HARNESS_ROOT/.session"' in text
    assert f"export WARREN_STATE_HOOK={st.SERVER_HOOK_PATH}" in text


def test_parse_state_validates():
    good = {"harness": "claude", "state": "working", "session_id": "a1", "event": "PreToolUse", "ts": 100}
    s = st.parse_state(json.dumps(good).encode())
    assert (s.state, s.ts, s.session_id, s.source) == ("working", 100.0, "a1", "hook")
    assert st.parse_state(json.dumps({**good, "state": "dead"}).encode()) is None
    assert st.parse_state(json.dumps({**good, "ts": "soon"}).encode()) is None
    assert st.parse_state(json.dumps({**good, "session_id": "a b"}).encode()).session_id == ""
    assert st.parse_state(b"x" * (st.MAX_STATE_BYTES + 1)) is None
    assert st.parse_state(json.dumps(good).encode(), source="osc").session_id == ""


def test_precedence_hook_then_osc_then_unverifiable():
    hook = st.AgentState("idle", 5.0)
    osc = st.AgentState("working", 9.0, source="osc")
    assert st.resolve(hook, osc) is hook
    assert st.resolve(None, osc) is osc
    assert st.resolve(None, None).state == st.UNVERIFIABLE


def test_osc_parsing_and_tracker_across_chunks():
    assert st.parse_osc(b"a\x1b]7501;working\x07b\x1b]7501;state=blocked\x1b\\") == ["working", "blocked"]
    assert st.parse_osc(b"\x1b]7501;busy\x07\x1b]7501;nonsense\x07\x1b]0;title\x07") == ["working"]
    t = st.OscTracker()
    assert t.feed(b"out \x1b]7501;sta", 1.0) is None
    s = t.feed(b"te=idle\x07 more", 2.0)
    assert (s.state, s.ts, s.session_id, s.source) == ("idle", 2.0, "", "osc")
    assert st.parse_state(t.to_json().encode(), source="osc").state == "idle"
