"""AG5/AM1: OSC 7501 fallback and GET /agent-state precedence (hook > OSC > unverifiable)."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from warren_sidecar.agent_state import OscRecorder, current_state
from warren_sidecar.app import app


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


def test_precedence(tmp_path):
    assert current_state(tmp_path) == {"state": "unverifiable", "source": "none"}
    (tmp_path / "osc-state.json").write_text(json.dumps({"state": "working", "ts": 1, "session_id": "x"}))
    assert current_state(tmp_path) == {"state": "working", "ts": 1, "source": "osc"}
    (tmp_path / "state.json").write_text(json.dumps({"state": "idle", "ts": 2, "session_id": "s1", "harness": "claude"}))
    assert current_state(tmp_path)["state"] == "idle" and current_state(tmp_path)["session_id"] == "s1"
    (tmp_path / "state.json").write_text("garbage")
    assert current_state(tmp_path)["source"] == "osc"


def test_agent_state_route(env_defaults, auth_headers, monkeypatch, tmp_path):
    monkeypatch.setenv("WARREN_HARNESS_ROOT", str(tmp_path))
    (tmp_path / ".session").mkdir()
    (tmp_path / ".session" / "state.json").write_text(json.dumps({"state": "blocked", "ts": 5}))
    with TestClient(app) as client:
        assert client.get("/agent-state").status_code in (401, 403)
        r = client.get("/agent-state", headers=auth_headers)
    assert r.status_code == 200 and r.json()["state"] == "blocked"
