"""Agent state inside the workspace (AG5/AM1).

Harness state hooks write `<harness root>/.session/state.json`. For harnesses
without hooks, the sidecar watches the tmux pane for the OSC 7501 status escape
(state only, no session id) and records it as `osc-state.json` next to it. The
format matches warren_common.agent_state; the sidecar image doesn't ship it.
"""
from __future__ import annotations

import json
import os
import re
import tempfile
import time
from pathlib import Path

STATES = frozenset({"working", "blocked", "idle", "exited"})
_OSC = re.compile(rb"\x1b\]7501;([^\x07\x1b]{0,256})(?:\x07|\x1b\\)")
_ALIASES = {"busy": "working", "running": "working", "waiting": "blocked", "permission": "blocked", "done": "idle"}
MAX_STATE_BYTES = 4096


def _osc_states(data: bytes) -> list[str]:
    out = []
    for m in _OSC.finditer(data):
        for field in m.group(1).decode("ascii", "replace").split(";"):
            value = field.split("=", 1)[1] if field.startswith("state=") else field
            value = _ALIASES.get(value.strip().lower(), value.strip().lower())
            if value in STATES:
                out.append(value)
                break
    return out


class OscRecorder:
    """Feeds pane output through the OSC 7501 parser; writes the latest state."""

    def __init__(self, session_dir: str | Path, clock=time.time) -> None:
        self._dir = Path(session_dir)
        self._clock = clock
        self._tail = b""

    def feed(self, data: bytes) -> str | None:
        buf = self._tail + data
        cut = buf.rfind(b"\x1b]7501;")
        self._tail = buf[cut:][-300:] if cut >= 0 and not _OSC.search(buf[cut:]) else b""
        states = _osc_states(buf)
        if not states:
            return None
        self._write({"state": states[-1], "ts": self._clock(), "source": "osc"})
        return states[-1]

    def _write(self, obj: dict) -> None:
        if not self._dir.is_dir() or self._dir.is_symlink():
            return
        fd, tmp = tempfile.mkstemp(prefix=".osc.", dir=self._dir)
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(obj, f)
            os.replace(tmp, self._dir / "osc-state.json")
        except OSError:
            Path(tmp).unlink(missing_ok=True)


def _read(path: Path) -> dict | None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return None
    with os.fdopen(fd, "rb") as f:
        raw = f.read(MAX_STATE_BYTES + 1)
    if len(raw) > MAX_STATE_BYTES:
        return None
    try:
        obj = json.loads(raw)
    except ValueError:
        return None
    if not isinstance(obj, dict) or obj.get("state") not in STATES or not isinstance(obj.get("ts"), (int, float)):
        return None
    return obj


def current_state(session_dir: str | Path) -> dict:
    """Hook state wins over OSC, OSC over unverifiable."""
    d = Path(session_dir)
    hook = _read(d / "state.json")
    if hook is not None:
        return {**hook, "source": "hook"}
    osc = _read(d / "osc-state.json")
    if osc is not None:
        return {"state": osc["state"], "ts": osc["ts"], "source": "osc"}
    return {"state": "unverifiable", "source": "none"}
