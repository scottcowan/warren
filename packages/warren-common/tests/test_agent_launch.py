"""AG2b/AM3: agent launch specs come from profile data only."""
from __future__ import annotations

import json

import pytest

from warren_common import agent_supervisor
from warren_common.agent_launch import agent_state_dir, launch_spec, template_launch_spec
from warren_common.harness import PROFILES, HarnessSelectionError
from warren_common.models import AgentConfig, ProjectConfig

ADAPTER = "acp-serve --transport jsonrpc --host 127.0.0.1 --port {port} -- {harness_argv}"


@pytest.mark.parametrize("name", sorted(n for n, p in PROFILES.items() if p.agent_mode))
def test_every_agent_mode_builds_a_spec_the_supervisor_accepts(name):
    profile = PROFILES[name]
    spec = launch_spec(name, AgentConfig(adapter=ADAPTER))
    assert spec["argv"][: len(profile.command)] == list(profile.command)
    assert spec["argv"][len(profile.command):][: len(profile.agent_mode.args)] == list(profile.agent_mode.args)
    if profile.agent_mode.native_acp:
        assert (spec["adapter"], spec["transport"]) == (None, "stdio")
    else:
        assert spec["adapter"][0] == "acp-serve" and spec["transport"] == "tcp"
    assert spec["env"]["WARREN_STATE_DIR"] == agent_state_dir()
    assert spec["host"] == "127.0.0.1" and spec["inner_port"] != spec["port"]
    agent_supervisor.load_spec(json.dumps(spec))


def test_native_acp_env_comes_from_the_profile():
    spec = launch_spec("opencode", None)
    assert spec["env"]["OPENCODE_CLIENT"] == "acp"
    assert spec["argv"] == ["opencode", "acp"]


def test_use_adapter_wraps_a_native_harness_too():
    spec = launch_spec("cursor-agent", AgentConfig(adapter=ADAPTER, use_adapter=True))
    assert spec["adapter"] and spec["transport"] == "tcp"


@pytest.mark.parametrize("adapter", [
    "acp-serve --host 0.0.0.0 --port {port}",
    "acp-serve --host :: --port {port}",
    "acp-serve --host [::] --port {port}",
])
def test_adapter_binding_wide_is_rejected(adapter):
    with pytest.raises(ValueError, match="loopback"):
        AgentConfig(adapter=adapter)


def test_user_templates_have_no_launch_spec():
    assert template_launch_spec(ProjectConfig(name="p")) is None
    cfg = ProjectConfig(name="p", kind="agent", harness="pi")
    with pytest.raises(HarnessSelectionError, match="adapter"):
        template_launch_spec(cfg)
    with pytest.raises(HarnessSelectionError, match="no agent mode"):
        template_launch_spec(ProjectConfig(name="p", kind="agent", harness="custom"))


def test_supervisor_refuses_a_non_loopback_endpoint():
    spec = launch_spec("opencode", None)
    for host in ("0.0.0.0", "10.0.0.5", "::", "localhost"):
        with pytest.raises(agent_supervisor.SpecError, match="loopback"):
            agent_supervisor.load_spec(json.dumps({**spec, "host": host}))
    assert agent_supervisor.load_spec(json.dumps({**spec, "host": "::1"}))["max_peers"] == 1
