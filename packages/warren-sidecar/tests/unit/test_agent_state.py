"""AG5/AM1: the OSC 7501 fallback recorder."""

from __future__ import annotations

import json

from warren_sidecar.agent_state import OscRecorder


def test_osc_recorder_writes_latest_state_across_chunks(tmp_path):
    rec = OscRecorder(tmp_path, clock=lambda: 42.0)
    assert rec.feed(b"hello \x1b]7501;sta") is None
    assert rec.feed(b"te=working\x07\n") == "working"
    assert json.loads((tmp_path / "osc-state.json").read_text()) == {"state": "working", "ts": 42.0, "source": "osc"}
    assert rec.feed(b"\x1b]7501;nonsense\x07") is None
    assert rec.feed(b"\x1b]7501;permission\x1b\\") == "blocked"


def test_osc_recorder_ignores_a_missing_or_linked_dir(tmp_path):
    OscRecorder(tmp_path / "missing").feed(b"\x1b]7501;idle\x07")
    (tmp_path / "link").symlink_to(tmp_path)
    OscRecorder(tmp_path / "link").feed(b"\x1b]7501;idle\x07")
    assert not (tmp_path / "osc-state.json").exists()

