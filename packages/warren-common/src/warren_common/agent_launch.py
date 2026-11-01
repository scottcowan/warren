"""Agent workspace launch specs (AG2b, AM3), built from profile data only.

A `kind: agent` template names one `harness`. Its profile's `agent_mode` says how
it runs headless; native ACP is passed straight through, any other protocol runs
behind the template's `agent.adapter` command. The result is the JSON the
in-workspace supervisor (`agent_supervisor.py`) reads from WARREN_AGENT_SPEC.
"""
from __future__ import annotations

import shlex
from typing import Any

from warren_common.agent_state import AGENT_DIR as AGENT_STATE_SUBDIR
from warren_common.harness import (
    PROFILES,
    SERVER_HARNESS_ROOT,
    SESSION_DIR,
    AgentMode,
    HarnessProfile,
    HarnessSelectionError,
    agent_modes,
    harness_env,
    process_env,
)
from warren_common.models import AgentConfig

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
    mode = select_mode(profile, agent.mode)
    if mode.serves:
        if agent.use_adapter or agent.adapter:
            raise HarnessSelectionError(
                f"{name} mode {mode.name!r} serves its own {mode.protocol} endpoint on agent.port; "
                "drop agent.adapter/use_adapter"
            )
        return
    if (agent.use_adapter or not mode.native_acp) and not (agent.adapter or "").strip():
        raise HarnessSelectionError(
            f"{name} speaks {mode.protocol}, not ACP: set agent.adapter "
            "(e.g. acp-serve --transport jsonrpc --host 127.0.0.1 --port {port})"
        )
    if agent.adapter:
        try:
            shlex.split(agent.adapter)
        except ValueError as exc:
            raise HarnessSelectionError(f"agent.adapter is not a valid command: {exc}") from exc


def select_mode(profile: HarnessProfile, name: str | None) -> AgentMode:
    """The profile's agent mode called `name`, or its default."""
    modes = agent_modes(profile)
    if not modes:
        raise HarnessSelectionError(f"harness {profile.name!r} has no agent mode")
    if name is None:
        return next(iter(modes.values()))
    if name not in modes:
        raise HarnessSelectionError(f"{profile.name} has no agent mode {name!r}; one of {sorted(modes)}")
    return modes[name]


def launch_spec(harness: str, agent: AgentConfig | None, root: str = SERVER_HARNESS_ROOT) -> dict:
    """The supervisor's spec. A self-serving mode (opencode serve, codex app-server)
    listens on agent.port itself (`{port}` in its args): transport "self", no
    ACP endpoint of the supervisor's own and no adapter."""
    agent = agent or AgentConfig()
    profile = PROFILES[harness]
    mode = select_mode(profile, agent.mode)
    adapter = not mode.serves and (agent.use_adapter or not mode.native_acp)
    state_dir = agent_state_dir(root)
    env = {
        **harness_env([harness], root),
        **process_env(harness, root),
        **mode.env,
        "WARREN_STATE_DIR": state_dir,
    }
    args = [a.replace("{port}", str(agent.port)) for a in mode.args]
    if mode.serves:
        transport = "self"
    else:
        transport = agent.adapter_transport if adapter else "stdio"
    return {
        "harness": harness,
        "mode": mode.name or mode.protocol,
        "protocol": mode.protocol,
        "argv": [*profile.command, *args, *(profile.launch_args if mode.profile_args else ())],
        "resume_args": [] if mode.serves else list(profile.resume_by_id_args),
        "env": env,
        "adapter": shlex.split(agent.adapter) if adapter and agent.adapter else None,
        "transport": transport,
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
