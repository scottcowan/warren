"""AC2.5: opt-in Windows -> `wsl warren ...` forwarder. wsl.exe is faked."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import pytest

from warren_cli import wslshim


@pytest.fixture
def windows(monkeypatch):
    import warren_common.winsupport as ws

    monkeypatch.setattr(ws, "is_windows", lambda: True)


def _config(tmp_path: Path, body: str) -> Path:
    p = tmp_path / "config.toml"
    p.write_text(body)
    return p


def test_not_windows_never_forwards(tmp_path, monkeypatch):
    import warren_common.winsupport as ws

    monkeypatch.setattr(ws, "is_windows", lambda: False)
    cfg = _config(tmp_path, "[windows]\nforward_to_wsl = true\n")
    assert wslshim.maybe_forward(["list"], environ={}, config_path=cfg) is None


def test_off_by_default_and_no_probing(tmp_path, monkeypatch, windows):
    monkeypatch.setattr(wslshim, "_no_native_local_runtime", lambda: pytest.fail("probed"))
    monkeypatch.setattr(wslshim, "warren_in_wsl", lambda _d: pytest.fail("probed"))
    assert wslshim.maybe_forward(["list"], environ={}, config_path=tmp_path / "missing.toml") is None


def test_env_flag_overrides_config(tmp_path):
    cfg = _config(tmp_path, '[windows]\nforward_to_wsl = true\nwsl_distro = "Ubuntu-24.04"\n')
    assert wslshim.opted_in({}, cfg) == (True, "Ubuntu-24.04")
    assert wslshim.opted_in({"WARREN_WSL_FORWARD": "0"}, cfg) == (False, "Ubuntu-24.04")
    assert wslshim.opted_in({"WARREN_WSL_FORWARD": "1"}, tmp_path / "missing.toml") == (True, "")


def test_forwards_when_opted_in_no_native_runtime_and_installed(tmp_path, monkeypatch, windows):
    cfg = _config(tmp_path, '[windows]\nforward_to_wsl = true\nwsl_distro = "Ubuntu"\n')
    monkeypatch.setattr(wslshim, "_no_native_local_runtime", lambda: True)
    monkeypatch.setattr(wslshim, "warren_in_wsl", lambda d: d == "Ubuntu")
    ran = []
    import warren_cli.dispatch as d

    monkeypatch.setattr(d, "_run_foreground", lambda argv, env=None: ran.append(argv) or 7)
    assert wslshim.maybe_forward(["connect", "ws 1"], environ={}, config_path=cfg) == 7
    assert ran == [[
        "wsl.exe", "-d", "Ubuntu", "-e", "sh", "-lc", 'exec warren "$@"', "warren", "connect", "ws 1",
    ]]


def test_native_runtime_available_runs_natively(tmp_path, monkeypatch, windows):
    monkeypatch.setattr(wslshim, "_no_native_local_runtime", lambda: False)
    monkeypatch.setattr(wslshim, "warren_in_wsl", lambda _d: pytest.fail("probed"))
    assert wslshim.maybe_forward(["list"], environ={"WARREN_WSL_FORWARD": "1"}, config_path=tmp_path / "x") is None


def test_not_installed_in_wsl_warns_and_runs_natively(tmp_path, monkeypatch, windows, capsys):
    monkeypatch.setattr(wslshim, "_no_native_local_runtime", lambda: True)
    monkeypatch.setattr(wslshim, "warren_in_wsl", lambda _d: False)
    assert wslshim.maybe_forward(["list"], environ={"WARREN_WSL_FORWARD": "1"}, config_path=tmp_path / "x") is None
    assert "isn't installed in WSL" in capsys.readouterr().err


def test_warren_in_wsl_probe(monkeypatch):
    seen = {}

    def _run(argv, **kw):
        seen["argv"] = argv
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(wslshim.subprocess, "run", _run)
    assert wslshim.warren_in_wsl("") is True
    assert seen["argv"] == ["wsl.exe", "-e", "sh", "-lc", "command -v warren >/dev/null"]

    def _missing(*_a, **_kw):
        raise FileNotFoundError("wsl.exe")

    monkeypatch.setattr(wslshim.subprocess, "run", _missing)
    assert wslshim.warren_in_wsl("") is False


def test_main_runs_app_when_not_forwarding(monkeypatch):
    import warren_cli.main as cli_main

    monkeypatch.setattr(wslshim, "maybe_forward", lambda _argv: None)
    called = []
    monkeypatch.setattr(cli_main, "app", lambda: called.append(1))
    wslshim.main()
    assert called == [1]


def test_main_exits_with_forwarded_code(monkeypatch):
    monkeypatch.setattr(wslshim, "maybe_forward", lambda _argv: 3)
    with pytest.raises(SystemExit) as ei:
        wslshim.main()
    assert ei.value.code == 3
