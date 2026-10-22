"""AC1.5: UTF-8 stdio + VT colours on Windows consoles; POSIX-separator-free remote paths."""

from __future__ import annotations

import pytest

from warren_cli import winconsole


class _Stream:
    def __init__(self, encoding):
        self.encoding = encoding
        self.calls = []

    def reconfigure(self, **kw):
        self.calls.append(kw)


def test_enable_is_noop_off_windows(monkeypatch):
    out, err = _Stream("cp1252"), _Stream("cp1252")
    monkeypatch.setattr(winconsole.sys, "platform", "darwin")
    monkeypatch.setattr(winconsole.sys, "stdout", out)
    monkeypatch.setattr(winconsole.sys, "stderr", err)
    monkeypatch.setattr(winconsole, "_enable_vt", lambda: pytest.fail("vt on POSIX"))
    winconsole.enable()
    assert out.calls == [] and err.calls == []


def test_enable_switches_to_utf8_and_vt_on_windows(monkeypatch):
    out, err = _Stream("cp1252"), _Stream("utf-8")
    vt = []
    monkeypatch.setattr(winconsole.sys, "platform", "win32")
    monkeypatch.setattr(winconsole.sys, "stdout", out)
    monkeypatch.setattr(winconsole.sys, "stderr", err)
    monkeypatch.setattr(winconsole, "_enable_vt", lambda: vt.append(True))
    winconsole.enable()
    assert out.calls == [{"encoding": "utf-8", "errors": "replace"}]
    assert err.calls == []
    assert vt == [True]


def test_enable_survives_missing_console_api(monkeypatch):
    def _boom():
        raise OSError("no console")

    monkeypatch.setattr(winconsole.sys, "platform", "win32")
    monkeypatch.setattr(winconsole.sys, "stdout", object())
    monkeypatch.setattr(winconsole.sys, "stderr", object())
    monkeypatch.setattr(winconsole, "_enable_vt", _boom)
    winconsole.enable()


def test_ecs_session_command_walks_remote_posix_parents():
    from warren_cli import dispatch as d

    assert "for d in /usr/local/bin /usr/local /usr; do" in d.ecs_session_command("bash")


def test_warren_owned_rc_is_utf8_with_lf(tmp_path):
    from warren_cli import dispatch as d

    rc = tmp_path / ".bashrc"
    d._write_warren_owned(rc, "echo '⚠  warren'\necho ✓\n")
    assert rc.read_bytes() == "echo '⚠  warren'\necho ✓\n".encode("utf-8")
