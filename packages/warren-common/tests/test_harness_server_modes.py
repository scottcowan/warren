"""opencode and codex profiles: agent/server modes, XDG data dirs, model config
from the workspace env, codex hook trust, and the supervisor's self-serving
transport. Values pinned here were checked against opencode 1.19.5 and codex
0.166.0 in a throwaway container (docs/harnesses.md)."""
from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from warren_common import agent_state
from warren_common import agent_supervisor as sv
from warren_common import harness_shell as hs
from warren_common.agent_launch import check_agent_template, launch_spec
from warren_common.harness import (
    PROFILES,
    HarnessSelectionError,
    agent_modes,
    codex_config,
    harness_dirs,
    harness_env,
    opencode_config,
    persist_paths,
    process_env,
)
from warren_common.harness_config import prepare_harness_dirs
from warren_common.models import AgentConfig, ProjectConfig

ASSETS = Path(hs.__file__).parent / "assets"
INIT = ASSETS / hs.INIT_ASSET_NAME
HARNESS_SH = ASSETS / hs.ASSET_NAME

GATEWAY_ENV = {
    "CLAUDE_CODE_USE_BEDROCK": "1",
    "AWS_REGION": "eu-west-1",
    "ANTHROPIC_BEDROCK_BASE_URL": "https://llm-proxy.example.com/bedrock",
    "CLAUDE_CODE_SKIP_BEDROCK_AUTH": "1",
    "ANTHROPIC_MODEL": "eu.anthropic.claude-haiku-4-5-20251001-v1:0",
}

# --- profiles and modes ---


def test_mode_names_per_harness():
    assert list(agent_modes(PROFILES["opencode"])) == ["acp", "serve"]
    assert list(agent_modes(PROFILES["codex"])) == ["exec", "app-server", "app-server-stdio"]
    assert list(agent_modes(PROFILES["claude"])) == ["stream-json"]
    serve = agent_modes(PROFILES["opencode"])["serve"]
    assert serve.serves and serve.protocol == "http" and not serve.native_acp
    assert agent_modes(PROFILES["codex"])["app-server"].serves
    assert not agent_modes(PROFILES["codex"])["app-server-stdio"].serves


def test_template_selects_a_mode():
    cfg = ProjectConfig.model_validate(
        {"name": "p", "kind": "agent", "harness": "opencode", "agent": {"mode": "serve", "port": 4096}}
    )
    assert cfg.agent.mode == "serve"
    check_agent_template(cfg)


@pytest.mark.parametrize(
    "harness, agent, match",
    [
        ("opencode", {"mode": "web"}, "no agent mode 'web'"),
        ("opencode", {"mode": "serve", "adapter": "acp-serve --port {port}"}, "drop agent.adapter"),
        ("opencode", {"mode": "serve", "use_adapter": True}, "drop agent.adapter"),
        ("codex", {"mode": "app-server-stdio"}, "set agent.adapter"),
        ("codex", {}, "set agent.adapter"),
    ],
)
def test_bad_mode_choices_are_rejected(harness, agent, match):
    cfg = ProjectConfig.model_validate({"name": "p", "kind": "agent", "harness": harness, "agent": agent})
    with pytest.raises(HarnessSelectionError, match=match):
        check_agent_template(cfg)


def test_launch_specs_per_mode():
    root = "/var/lib/warren/harness"
    acp = launch_spec("opencode", AgentConfig(port=9000))
    assert acp["argv"] == ["opencode", "acp"] and acp["transport"] == "stdio" and acp["adapter"] is None
    assert acp["env"]["OPENCODE_CLIENT"] == "acp"

    serve = launch_spec("opencode", AgentConfig(mode="serve", port=4096))
    assert serve["argv"] == ["opencode", "serve", "--hostname", "127.0.0.1", "--port", "4096"]
    assert serve["transport"] == "self" and serve["adapter"] is None and serve["resume_args"] == []
    assert serve["mode"] == "serve" and serve["protocol"] == "http"
    # opencode's own process gets its XDG data/state under the harness dir.
    assert serve["env"]["XDG_DATA_HOME"] == f"{root}/opencode/data"
    assert serve["env"]["XDG_STATE_HOME"] == f"{root}/opencode/state"
    assert serve["env"]["OPENCODE_CONFIG_DIR"] == f"{root}/opencode/config"

    exec_ = launch_spec("codex", AgentConfig(adapter="acp-serve --port {port}"))
    assert exec_["argv"] == ["codex", "exec", "--json", "--sandbox", "danger-full-access"]
    assert exec_["transport"] == "tcp" and exec_["adapter"] == ["acp-serve", "--port", "{port}"]

    ws = launch_spec("codex", AgentConfig(mode="app-server", port=8772))
    # `--sandbox` is a TUI/exec flag; codex app-server rejects it (0.166.0).
    assert ws["argv"] == ["codex", "app-server", "--listen", "ws://127.0.0.1:8772"]
    assert ws["transport"] == "self" and ws["env"]["CODEX_HOME"] == f"{root}/codex"

    stdio = launch_spec("codex", AgentConfig(mode="app-server-stdio", adapter="bridge", adapter_transport="stdio"))
    assert stdio["argv"] == ["codex", "app-server", "--listen", "stdio://"]
    assert stdio["adapter"] == ["bridge"] and stdio["transport"] == "stdio"


@pytest.mark.parametrize("name, mode", [("opencode", "serve"), ("codex", "app-server"), ("opencode", None)])
def test_specs_load_in_the_supervisor(name, mode):
    spec = sv.load_spec(json.dumps(launch_spec(name, AgentConfig(mode=mode))))
    assert spec["max_peers"] == 1


# --- persisted state, credentials excluded ---


def test_opencode_xdg_dirs_are_process_only_and_persisted():
    root = "/var/lib/warren/harness"
    assert process_env("opencode", root) == {
        "XDG_DATA_HOME": f"{root}/opencode/data",
        "XDG_STATE_HOME": f"{root}/opencode/state",
    }
    # Never exported shell-wide: Claude Code reads XDG_DATA_HOME for its own install.
    assert "XDG_DATA_HOME" not in harness_env(["opencode"], root)
    assert "XDG_DATA_HOME" not in hs._export_case(PROFILES["opencode"])
    assert 'XDG_DATA_HOME="$WARREN_HARNESS_ROOT/opencode/data"' in hs._exec_case(PROFILES["opencode"])
    assert f"{root}/opencode/state" in harness_dirs(["opencode"], root)
    assert persist_paths(["opencode", "codex"], root) == [
        f"{root}/codex/sessions", f"{root}/codex/history.jsonl", f"{root}/codex/log",
        f"{root}/opencode/data", f"{root}/opencode/state",
    ]


def _run_init(root: Path, harnesses: str, env: dict | None = None) -> None:
    r = subprocess.run(
        ["/bin/sh", str(INIT), str(root)],
        env={"PATH": "/usr/bin:/bin", "WARREN_HARNESSES": harnesses, **(env or {})},
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0, r.stderr


def test_init_keeps_opencode_and_codex_history_and_drops_credentials(tmp_path):
    root = tmp_path / "harness"
    oc = root / "opencode"
    (oc / "data" / "opencode" / "storage").mkdir(parents=True)
    (oc / "data" / "opencode.db").write_text("db")
    (oc / "data" / "opencode" / "storage" / "s.json").write_text("{}")
    (oc / "data" / "opencode" / "auth.json").write_text('{"anthropic": {"key": "sk"}}')
    (oc / "data" / "opencode" / "mcp-auth.json").write_text("{}")
    (oc / "state" / "opencode").mkdir(parents=True)
    (oc / "state" / "opencode" / "prompt-history.jsonl").write_text("h")
    (oc / "config" / "plugins").mkdir(parents=True)
    (oc / "config" / "plugins" / "evil.js").write_text("x")
    cx = root / "codex"
    (cx / "sessions" / "2026").mkdir(parents=True)
    (cx / "sessions" / "2026" / "rollout-x.jsonl").write_text("{}")
    (cx / "auth.json").write_text("tok")
    (cx / "sessions" / "auth.json").write_text("tok")
    (cx / "state_5.sqlite").write_text("x")

    _run_init(root, "opencode codex")

    assert (oc / "data" / "opencode.db").exists()
    assert (oc / "data" / "opencode" / "storage" / "s.json").exists()
    assert (oc / "state" / "opencode" / "prompt-history.jsonl").exists()
    assert not (oc / "data" / "opencode" / "auth.json").exists()
    assert not (oc / "data" / "opencode" / "mcp-auth.json").exists()
    assert not (oc / "config" / "plugins" / "evil.js").exists()
    assert sorted(p.name for p in oc.iterdir()) == ["config", "data", "state"]
    assert (cx / "sessions" / "2026" / "rollout-x.jsonl").exists()
    assert not (cx / "auth.json").exists() and not (cx / "sessions" / "auth.json").exists()
    assert sorted(p.name for p in cx.iterdir()) == ["config.toml", "hooks.json", "log", "sessions"]


# --- model config from the workspace env ---


def test_opencode_config_without_bedrock_is_the_base():
    assert json.loads(opencode_config({})) == {"$schema": "https://opencode.ai/config.json", "autoupdate": False}
    assert json.loads(opencode_config({"CLAUDE_CODE_USE_BEDROCK": "0"})) == json.loads(opencode_config({}))


def test_opencode_config_through_the_gateway():
    cfg = json.loads(opencode_config(GATEWAY_ENV))
    assert cfg["enabled_providers"] == ["amazon-bedrock"]
    assert cfg["model"] == "amazon-bedrock/eu.anthropic.claude-haiku-4-5-20251001-v1:0"
    assert cfg["provider"]["amazon-bedrock"]["options"] == {
        "region": "eu-west-1",
        "endpoint": "https://llm-proxy.example.com/bedrock",
        # Resolved by opencode at load time; the key itself never lands in a file.
        "apiKey": "{env:ANTHROPIC_AUTH_TOKEN}",
    }


def test_opencode_config_task_role_bedrock_and_unsafe_values():
    cfg = json.loads(opencode_config({"CLAUDE_CODE_USE_BEDROCK": "1", "AWS_REGION": "us-east-1"}))
    assert cfg["provider"]["amazon-bedrock"]["options"] == {"region": "us-east-1"}
    assert "model" not in cfg
    bad = json.loads(opencode_config({
        "CLAUDE_CODE_USE_BEDROCK": "1",
        "ANTHROPIC_BEDROCK_BASE_URL": 'https://x"}, "evil": {"',
        "ANTHROPIC_MODEL": "m\" ,",
        "AWS_REGION": "EU WEST",
    }))
    assert bad == {"$schema": "https://opencode.ai/config.json", "autoupdate": False,
                   "enabled_providers": ["amazon-bedrock"]}
    # Gateway without skip-auth: opencode signs with the workspace's AWS identity.
    no_skip = json.loads(opencode_config({**GATEWAY_ENV, "CLAUDE_CODE_SKIP_BEDROCK_AUTH": ""}))
    assert "apiKey" not in no_skip["provider"]["amazon-bedrock"]["options"]


def test_codex_config_bedrock_provider_only_without_a_gateway():
    plain = codex_config("/w/codex/hooks.json", {})
    assert plain.startswith('approval_policy = "never"\nsandbox_mode = "danger-full-access"\n\n[features]\nhooks = true\n')
    assert "model_provider" not in plain
    bedrock = codex_config("/w/codex/hooks.json", {"CLAUDE_CODE_USE_BEDROCK": "1", "AWS_REGION": "eu-west-1"})
    assert bedrock.startswith('model_provider = "amazon-bedrock"\n')
    assert '\n[model_providers.amazon-bedrock.aws]\nregion = "eu-west-1"\n' in bedrock
    assert "model_provider" not in codex_config("/w/codex/hooks.json", GATEWAY_ENV)


# Reported by `codex app-server` hooks/list (0.166.0) for warren's hooks.json.
_CODEX_0_166_HASHES = {
    "session_start": "5e0076b506692c0d159abde1b3da2d49b062b47de605a0df3b5eee32eaae28b1",
    "user_prompt_submit": "2906d8057388208ca2564eeea68dbda74da5259c25c056da1c59c3ab18ed5bf3",
    "pre_tool_use": "341c8e03c3ffa17570203b1d57bd7a0343e567554eca7b2204f47345b190adab",
    "post_tool_use": "38aecf9054d2562758a554fc28d404300d555a542ad31231aa5b06ab6f1c4a43",
    "stop": "a64bf10e376a5cf1911295fd05eafcc459c4ebb803f292a4c025fc19dbf54ad5",
}


def test_codex_hook_trust_matches_codex_hashes():
    trust = agent_state.codex_hook_trust("/srv/wh/codex/hooks.json")
    for event, digest in _CODEX_0_166_HASHES.items():
        assert f'[hooks.state."/srv/wh/codex/hooks.json:{event}:0:0"]\ntrusted_hash = "sha256:{digest}"\n' in trust
    hooks = json.loads(agent_state.codex_hooks())["hooks"]
    assert trust.count("[hooks.state.") == len(hooks) == len(agent_state.CODEX_EVENTS)
    for path in ("relative/hooks.json", '/a"b/hooks.json', "/a\\b/hooks.json", "/a\nb/hooks.json"):
        assert agent_state.codex_hook_trust(path) == ""


@pytest.mark.parametrize(
    "env",
    [
        {},
        GATEWAY_ENV,
        {"CLAUDE_CODE_USE_BEDROCK": "true", "AWS_REGION": "us-east-1", "ANTHROPIC_DEFAULT_HAIKU_MODEL": "us.h"},
        {"ANTHROPIC_BEDROCK_BASE_URL": "http://127.0.0.1:9997/bedrock"},
        {"CLAUDE_CODE_USE_BEDROCK": "False"},
        {"CLAUDE_CODE_USE_BEDROCK": "1", "ANTHROPIC_BEDROCK_BASE_URL": "ftp://x", "AWS_REGION": "x y"},
        {**GATEWAY_ENV, "ANTHROPIC_MODEL": "a'b", "CLAUDE_CODE_SKIP_BEDROCK_AUTH": "no"},
    ],
)
def test_init_script_generates_the_same_config_as_python(tmp_path, env):
    root = tmp_path / "harness"
    _run_init(root, "codex opencode", env)
    assert (root / "opencode" / "config" / "opencode.json").read_text() == opencode_config(env)
    assert (root / "codex" / "config.toml").read_text() == codex_config(f"{root}/codex/hooks.json", env)


def test_local_prepare_writes_model_config_and_trust_for_its_own_path(tmp_path):
    root = tmp_path / "ws" / "harness"
    prepare_harness_dirs(["opencode", "codex"], root, home=tmp_path / "home", env=GATEWAY_ENV)
    assert (root / "opencode" / "config" / "opencode.json").read_text() == opencode_config(GATEWAY_ENV)
    toml = (root / "codex" / "config.toml").read_text()
    assert f'[hooks.state."{root}/codex/hooks.json:stop:0:0"]' in toml
    for d in ("data", "state", "config"):
        assert (root / "opencode" / d).is_dir()
    prepare_harness_dirs(["opencode"], root, home=tmp_path / "home")
    assert json.loads((root / "opencode" / "config" / "opencode.json").read_text())["autoupdate"] is False
    assert "provider" not in json.loads((root / "opencode" / "config" / "opencode.json").read_text())


# --- the warren shell runs opencode with its process-only env ---


def test_shell_runs_opencode_with_xdg_dirs_but_never_exports_them(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    (bin_dir / "opencode").write_text('#!/bin/sh\necho "data=$XDG_DATA_HOME state=$XDG_STATE_HOME args=$*"\n')
    (bin_dir / "opencode").chmod(0o755)
    root = tmp_path / "harness"
    script = f'. {HARNESS_SH}\nopencode serve\necho "shell=${{XDG_DATA_HOME:-unset}}"\n'
    r = subprocess.run(
        ["bash", "-c", script],
        env={"PATH": f"{bin_dir}:/usr/bin:/bin", "HOME": str(tmp_path), "WARREN_HARNESSES": "opencode",
             "WARREN_HARNESS_ROOT": str(root)},
        capture_output=True, text=True, timeout=30,
    )
    assert r.returncode == 0, r.stderr
    assert f"data={root}/opencode/data state={root}/opencode/state args=serve" in r.stdout
    assert "shell=unset" in r.stdout


# --- supervisor: a harness serving its own endpoint ---


def _serving_child(port: int) -> list[str]:
    code = (
        "import http.server, sys\n"
        f"s = http.server.HTTPServer(('127.0.0.1', {port}), http.server.SimpleHTTPRequestHandler)\n"
        "s.serve_forever()\n"
    )
    return [sys.executable, "-c", code]


@pytest.mark.asyncio
async def test_self_serving_mode_is_supervised_not_proxied(tmp_path):
    from test_agent_supervisor import free_port  # noqa: PLC0415

    port = free_port()
    spec = sv.load_spec(json.dumps({
        "harness": "opencode", "argv": _serving_child(port), "transport": "self", "host": "127.0.0.1",
        "port": port, "inner_port": free_port(), "state_dir": str(tmp_path / "state"),
        "restart": {"policy": "on-failure", "max_restarts": 1, "backoff_seconds": 0.01},
    }))
    sup = sv.Supervisor(spec, listeners=lambda pid: [("127.0.0.1", port)], listener_check_seconds=0.05)
    task = asyncio.create_task(sup.run())
    try:
        for _ in range(100):
            try:
                r, w = await asyncio.open_connection("127.0.0.1", port)
                break
            except OSError:
                await asyncio.sleep(0.05)
        else:
            raise AssertionError("harness never listened")
        w.write(b"GET / HTTP/1.0\r\n\r\n")
        await w.drain()
        assert (await asyncio.wait_for(r.readline(), 10)).startswith(b"HTTP/1.0 200")
        w.close()
        assert sup.server is None, "the supervisor serves nothing itself"
        state = json.loads((tmp_path / "state" / sv.STATE_FILE).read_text())
        assert state["state"] == "idle" and state["harness"] == "opencode"
    finally:
        sup.stop()
        assert await asyncio.wait_for(task, 10) == 0
    names = [json.loads(line)["event"] for line in (tmp_path / "state" / sv.EVENTS_FILE).read_text().splitlines()]
    assert "agent.self_serving" in names and "acp.listening" not in names


@pytest.mark.asyncio
async def test_self_serving_mode_still_rejects_a_wide_listener(tmp_path):
    from test_agent_supervisor import free_port  # noqa: PLC0415

    port = free_port()
    spec = sv.load_spec(json.dumps({
        "harness": "opencode", "argv": [sys.executable, "-c", "import time; time.sleep(30)"],
        "transport": "self", "host": "127.0.0.1", "port": port, "inner_port": free_port(),
        "state_dir": str(tmp_path / "state"),
    }))
    sup = sv.Supervisor(spec, listeners=lambda pid: [("0.0.0.0", port)], listener_check_seconds=0.05)
    assert await asyncio.wait_for(sup.run(), 10) == sv.EXIT_WIDE_LISTENER


def test_doctor_knows_the_new_harnesses():
    pytest.importorskip("warren_cli")
    from warren_cli.commands.doctor import _HARNESS_MIN_VERSIONS  # noqa: PLC0415

    assert _HARNESS_MIN_VERSIONS["opencode"] == "1.19.5"
    assert _HARNESS_MIN_VERSIONS["codex"] == "0.166.0"


@pytest.mark.skipif(not os.path.exists("/bin/sh"), reason="needs /bin/sh")
def test_assets_are_current():
    assert INIT.read_text(encoding="utf-8") == hs.render_init()
    assert HARNESS_SH.read_text(encoding="utf-8") == hs.render()
