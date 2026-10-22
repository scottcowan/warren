"""Agent workspace launch specs (AG2b, AM3), built from profile data only.

A `kind: agent` template names one `harness`. Its profile's `agent_mode` says how
it runs headless; native ACP is passed straight through, any other protocol runs
behind the template's `agent.adapter` command. The result is the JSON the
in-workspace supervisor (`agent_supervisor.py`) reads from WARREN_AGENT_SPEC.
"""
from __future__ import annotations

import shlex
from typing import Any

from warren_common.harness import (
    PROFILES,
    SERVER_HARNESS_ROOT,
    SESSION_DIR,
    HarnessSelectionError,
    harness_env,
)
from warren_common.models import AgentConfig

from warren_common.agent_state import AGENT_DIR as AGENT_STATE_SUBDIR

SPEC_ENV = "WARREN_AGENT_SPEC"
LOOPBACK = "127.0.0.1"


def agent_state_dir(root: str = SERVER_HARNESS_ROOT) -> str:
    """Where the agent's hooks and the supervisor report, apart from the shell's
    records, so a human shell next to the agent never resumes or clobbers it."""
    return f"{root.rstrip('/')}/{SESSION_DIR}/{AGENT_STATE_SUBDIR}"


def check_agent_template(cfg: Any) -> None:
    if cfg.kind != "agent":
        return
    name = cfg.harness
    if not name:
        raise HarnessSelectionError("kind: agent needs `harness: <name>`")
    profile = PROFILES.get(name)
    if profile is None or not profile.selectable or profile.agent_mode is None:
        runnable = sorted(n for n, p in PROFILES.items() if p.selectable and p.agent_mode)
        raise HarnessSelectionError(f"harness {name!r} has no agent mode; one of {runnable}")
    agent = cfg.agent or AgentConfig()
    if (agent.use_adapter or not profile.agent_mode.native_acp) and not (agent.adapter or "").strip():
        raise HarnessSelectionError(
            f"{name} speaks {profile.agent_mode.protocol}, not ACP: set agent.adapter "
            "(e.g. acp-serve --transport jsonrpc --host 127.0.0.1 --port {port})"
        )
    if agent.adapter:
        try:
            shlex.split(agent.adapter)
        except ValueError as exc:
            raise HarnessSelectionError(f"agent.adapter is not a valid command: {exc}") from exc


def launch_spec(harness: str, agent: AgentConfig | None, root: str = SERVER_HARNESS_ROOT) -> dict:
    agent = agent or AgentConfig()
    profile = PROFILES[harness]
    mode = profile.agent_mode
    assert mode is not None
    adapter = agent.use_adapter or not mode.native_acp
    state_dir = agent_state_dir(root)
    env = {**harness_env([harness], root), **mode.env, "WARREN_STATE_DIR": state_dir}
    return {
        "harness": harness,
        "argv": [*profile.command, *mode.args, *profile.launch_args],
        "resume_args": list(profile.resume_by_id_args),
        "env": env,
        "adapter": shlex.split(agent.adapter) if adapter and agent.adapter else None,
        "transport": agent.adapter_transport if adapter else "stdio",
        "host": LOOPBACK,
        "port": agent.port,
        "inner_port": agent.port + 1 if agent.port < 65535 else agent.port - 1,
        "state_dir": state_dir,
        "restart": agent.restart.model_dump(),
        "max_line_bytes": agent.max_line_bytes,
        "max_peers": agent.max_peers,
    }


def template_launch_spec(cfg: Any, root: str = SERVER_HARNESS_ROOT) -> dict | None:
    """The spec for a resolved template, or None for user workspaces."""
    if cfg is None or cfg.kind != "agent":
        return None
    check_agent_template(cfg)
    return launch_spec(cfg.harness, cfg.agent, root)
