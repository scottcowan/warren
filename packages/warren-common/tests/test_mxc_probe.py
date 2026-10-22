"""AC4: report-only MXC availability on Windows."""

from __future__ import annotations

import re
import sys

import pytest

import warren_common.winsupport as ws

windows_only = pytest.mark.skipif(sys.platform != "win32", reason="real Windows probe only")


@pytest.fixture(autouse=True)
def _fresh_cache():
    probe = ws.probe_mxc
    probe.cache_clear()
    yield
    probe.cache_clear()


def test_not_windows_is_na(monkeypatch):
    monkeypatch.setattr(ws.sys, "platform", "darwin")
    monkeypatch.setattr(ws, "_psec_exports_present", lambda: pytest.fail("probed off Windows"))
    assert ws.probe_mxc() == ws.MxcProbe(False, "n/a", "not Windows")


def test_missing_exports_is_unavailable_with_reason(monkeypatch):
    monkeypatch.setattr(ws.sys, "platform", "win32")
    monkeypatch.setattr(ws, "_psec_exports_present", lambda: (False, "API set not implemented"))
    probe = ws.probe_mxc()
    assert probe.available is False
    assert probe.status == "unavailable"
    assert probe.reason == "API set not implemented"


def test_present_exports_are_not_proof_of_support(monkeypatch):
    monkeypatch.setattr(ws.sys, "platform", "win32")
    monkeypatch.setattr(ws, "_psec_exports_present", lambda: (True, ""))
    probe = ws.probe_mxc()
    assert probe.available is False
    assert probe.status == "unknown"


def test_probe_failure_never_raises(monkeypatch):
    def _boom():
        raise OSError("processmodel.dll exploded")

    monkeypatch.setattr(ws.sys, "platform", "win32")
    monkeypatch.setattr(ws, "_psec_exports_present", _boom)
    probe = ws.probe_mxc()
    assert probe.status == "unavailable"
    assert "exploded" in probe.reason


def test_probe_is_cached_per_process(monkeypatch):
    calls = []
    monkeypatch.setattr(ws.sys, "platform", "win32")
    monkeypatch.setattr(ws, "_psec_exports_present", lambda: calls.append(1) or (False, "x"))
    ws.probe_mxc()
    ws.probe_mxc()
    assert calls == [1]


def test_detect_reports_mxc_without_changing_recommendation(monkeypatch):
    import warren_common.runtime_detect as rd

    monkeypatch.setattr(rd.sys, "platform", "win32")
    monkeypatch.setattr(ws.sys, "platform", "win32")
    monkeypatch.setattr(rd.shutil, "which", lambda _: None)
    monkeypatch.setattr(ws.os, "listdir", lambda p: [])
    monkeypatch.setattr(ws, "windows_build", lambda: "26100.9278")
    monkeypatch.setattr(ws, "probe_mxc", lambda: ws.MxcProbe(True, "available", ""))
    result = rd.detect()
    assert result.mxc is True
    assert result.windows_build == "26100.9278"
    assert result.recommended == "none"


def test_detect_off_windows_never_probes(monkeypatch):
    import warren_common.runtime_detect as rd

    monkeypatch.setattr(rd.sys, "platform", "linux")
    monkeypatch.setattr(ws.sys, "platform", "linux")
    monkeypatch.setattr(ws, "probe_mxc", lambda: pytest.fail("probed off Windows"))
    result = rd.detect()
    assert (result.mxc, result.mxc_status, result.windows_build) == (False, "n/a", None)


@windows_only
def test_real_windows_probe_is_safe():
    probe = ws.probe_mxc()
    assert probe.available is False
    assert probe.status in {"unavailable", "unknown"}
    assert re.fullmatch(r"\d+(\.\d+)?", ws.windows_build() or "")
