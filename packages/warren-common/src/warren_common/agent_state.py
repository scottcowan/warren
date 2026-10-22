"""Agent state reported by harness hooks (AG5), with the OSC fallback (AM1).

Each harness profile with a `state_hook` gets warren-generated hook config in
its read-only config (claude settings.json hooks, codex hooks.json, cursor
hooks.json, an opencode plugin, a pi extension). Every hook runs
`warren-state-hook <harness> <event> [session id]`, which does nothing unless
WARREN_STATE_HOOK/WARREN_STATE_DIR are set (the warren shell sets them when it
launches a harness). It writes `{harness, state, session_id, event, ts}` to
`<harness root>/.session/state.json` inside the workspace, `<harness>.sid` for
exact resume (AG4), and the session id into active.json.

Harnesses without hooks can print an OSC 7501 status escape (state only); the
sidecar records it as `osc-state.json`. Precedence: hook > OSC > unverifiable.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass

STATE_FILE = "state.json"
OSC_STATE_FILE = "osc-state.json"
# AG2b: the supervised agent reports under `.session/agent/` (agent_launch.agent_state_dir).
AGENT_DIR = "agent"
SUPERVISOR_STATE_FILE = "supervisor.json"
HOOKS_DIR = ".hooks"
HOOK_SCRIPT = "warren-state-hook"
SERVER_HOOK_PATH = "/usr/local/bin/warren-state-hook"
HOOK_ASSET_NAME = "warren_state_hook.sh"
MAX_STATE_BYTES = 4096

WORKING = "working"
BLOCKED = "blocked"
IDLE = "idle"
EXITED = "exited"
UNVERIFIABLE = "unverifiable"
STATES = frozenset({WORKING, BLOCKED, IDLE, EXITED})

_ID = re.compile(r"^[A-Za-z0-9._-]{1,128}$")
_NAME = re.compile(r"^[a-z0-9-]{1,32}$")


@dataclass(frozen=True)
class AgentState:
    state: str
    ts: float = 0.0
    session_id: str = ""
    harness: str = ""
    event: str = ""
    source: str = "hook"  # "hook" | "osc" | "none"


def parse_state(raw: bytes | None, *, source: str = "hook") -> AgentState | None:
    """A state file's content, or None if absent or malformed."""
    if not raw or len(raw) > MAX_STATE_BYTES:
        return None
    try:
        obj = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(obj, dict) or obj.get("state") not in STATES:
        return None
    ts = obj.get("ts")
    if isinstance(ts, bool) or not isinstance(ts, (int, float)) or ts <= 0:
        return None
    sid = obj.get("session_id") if source in ("hook", "supervisor") else ""
    harness = obj.get("harness", "")
    return AgentState(
        state=obj["state"],
        ts=float(ts),
        session_id=sid if isinstance(sid, str) and _ID.match(sid) else "",
        harness=harness if isinstance(harness, str) and _NAME.match(harness) else "",
        event=str(obj.get("event", ""))[:64],
        source=source,
    )


_RANK = {WORKING: 3, BLOCKED: 2, IDLE: 1, EXITED: 0}


def busiest(*states: AgentState | None) -> AgentState | None:
    """The state that most holds a workspace up (working > blocked > idle > exited), newest on a tie."""
    found = [s for s in states if s is not None]
    return max(found, key=lambda s: (_RANK.get(s.state, -1), s.ts)) if found else None


def agent_workspace_state(supervisor: AgentState | None, hook: AgentState | None) -> AgentState | None:
    """AG2b: a supervised agent's state. The supervisor's `exited` (gave up, stopped,
    rejected) is final; otherwise the busier of its ACP view and the agent's hook."""
    if supervisor is not None and supervisor.state == EXITED:
        return supervisor
    return busiest(supervisor, hook)


def resolve(hook: AgentState | None, osc: AgentState | None) -> AgentState:
    if hook is not None:
        return hook
    if osc is not None:
        return osc
    return AgentState(UNVERIFIABLE, source="none")


# OSC 7501: ESC ] 7501 ; <state> | state=<state> [; ...] (BEL | ESC \)
_OSC = re.compile(rb"\x1b\]7501;([^\x07\x1b]{0,256})(?:\x07|\x1b\\)")
_OSC_ALIASES = {"busy": WORKING, "running": WORKING, "waiting": BLOCKED, "permission": BLOCKED, "done": IDLE}


def parse_osc(data: bytes) -> list[str]:
    out: list[str] = []
    for m in _OSC.finditer(data):
        for field in m.group(1).decode("ascii", "replace").split(";"):
            value = field.split("=", 1)[1] if field.startswith("state=") else field
            value = _OSC_ALIASES.get(value.strip().lower(), value.strip().lower())
            if value in STATES:
                out.append(value)
                break
    return out


class OscTracker:
    """Latest OSC 7501 state seen in terminal output (state only; never a session id)."""

    def __init__(self) -> None:
        self.state: AgentState | None = None
        self._tail = b""

    def feed(self, data: bytes, now: float) -> AgentState | None:
        buf = self._tail + data
        states = parse_osc(buf)
        cut = buf.rfind(b"\x1b]7501;")
        self._tail = buf[cut:][-300:] if cut >= 0 and not _OSC.search(buf[cut:]) else b""
        if not states:
            return None
        self.state = AgentState(states[-1], ts=now, source="osc")
        return self.state

    def to_json(self) -> str:
        assert self.state is not None
        return json.dumps({"state": self.state.state, "ts": self.state.ts, "source": "osc"})


# --- hook config written into each harness's read-only config (AG5) ---

def hook_command(harness: str, event: str) -> str:
    return f'[ -z "${{WARREN_STATE_HOOK:-}}" ] || sh "$WARREN_STATE_HOOK" {harness} {event} || :'


CLAUDE_EVENTS = (
    "SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "PostToolUseFailure",
    "PermissionRequest", "SubagentStart", "SubagentStop", "PostCompact", "Stop", "StopFailure", "SessionEnd",
)
CODEX_EVENTS = ("SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop")
CURSOR_EVENTS = ("sessionStart", "beforeSubmitPrompt", "stop")
_TOOL_EVENTS = frozenset({"PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionRequest"})


def _command_hooks(harness: str, events: tuple[str, ...]) -> dict:
    hooks: dict[str, list] = {}
    for e in events:
        entry: dict = {"hooks": [{"type": "command", "command": hook_command(harness, e)}]}
        if e in _TOOL_EVENTS:
            entry = {"matcher": "*", **entry}
        hooks[e] = [entry]
    return {"hooks": hooks}


def claude_settings() -> str:
    return json.dumps(_command_hooks("claude", CLAUDE_EVENTS))


def codex_hooks() -> str:
    return json.dumps(_command_hooks("codex", CODEX_EVENTS))


def cursor_hooks() -> str:
    return json.dumps(
        {"version": 1, "hooks": {e: [{"command": hook_command("cursor-agent", e)}] for e in CURSOR_EVENTS}},

    )


OPENCODE_PLUGIN = """\
// warren state hook (AG5), generated by warren. Inert unless WARREN_STATE_HOOK is set.
import { spawnSync } from "node:child_process";

const EVENTS = {
  "session.created": "SessionStart",
  "session.idle": "Stop",
  "permission.updated": "PermissionRequest",
  "permission.asked": "PermissionRequest",
  "session.deleted": "SessionEnd",
};

export const WarrenState = async () => {
  const hook = process.env.WARREN_STATE_HOOK;
  if (!hook) return {};
  const report = (event, sid) => {
    try {
      spawnSync("sh", [hook, "opencode", event, typeof sid === "string" ? sid : ""], { stdio: "ignore", timeout: 5000 });
    } catch {}
  };
  return {
    event: async ({ event }) => {
      const name = EVENTS[event?.type];
      if (name) report(name, event.properties?.sessionID ?? event.properties?.info?.id);
    },
    "chat.message": async (input) => report("UserPromptSubmit", input?.sessionID),
    "tool.execute.before": async (input) => report("PreToolUse", input?.sessionID),
  };
};
"""

PI_EXTENSION = """\
// warren state hook (AG5), generated by warren. Inert unless WARREN_STATE_HOOK is set.
import { spawnSync } from "node:child_process";

export default function (pi: any) {
  const hook = process.env.WARREN_STATE_HOOK;
  if (!hook) return;
  const report = (event: string, ctx: any) => {
    let sid = "";
    try {
      sid = String(ctx?.sessionManager?.getSessionId?.() ?? "");
    } catch {}
    try {
      spawnSync("sh", [hook, "pi", event, sid], { stdio: "ignore", timeout: 5000 });
    } catch {}
  };
  pi.on("session_start", (_e: any, ctx: any) => report("SessionStart", ctx));
  pi.on("agent_start", (_e: any, ctx: any) => report("UserPromptSubmit", ctx));
  pi.on("tool_call", (_e: any, ctx: any) => report("PreToolUse", ctx));
  pi.on("agent_end", (_e: any, ctx: any) => report("Stop", ctx));
  pi.on("session_shutdown", (_e: any, ctx: any) => report("SessionEnd", ctx));
}
"""


def hook_script() -> str:
    import importlib.resources  # noqa: PLC0415

    return importlib.resources.files("warren_common").joinpath(f"assets/{HOOK_ASSET_NAME}").read_text(encoding="utf-8")
