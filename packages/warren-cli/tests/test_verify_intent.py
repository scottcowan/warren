"""`warren doctor --verify-intent` canary (AH9). Provisioning, exec and destroy
are faked; the canary shell script itself runs for real against plain dirs."""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from warren_cli import main as cli_main
from warren_cli.commands import verify_intent as vi

runner = CliRunner()

_PROJECT = (
    "name: demo\n"
    "folders:\n"
    "  - name: wiki\n"
    "    type: local-path\n"
    "    path: /tmp\n"
    "    mount: refs/wiki\n"
    "    readonly: true\n"
    "  - name: notes\n"
    "    type: local-path\n"
    "    path: /tmp\n"
    "    mount: notes\n"
    "templates:\n"
    "  observe:\n"
    "    mounts:\n"
    "      - host: /h/data\n"
    "        container: /w/data\n"
    "        mode: ro\n"
    "  open:\n"
    "    app: bash\n"
)


def _config(tmp_path: Path) -> Path:
    projects = tmp_path / "projects"
    projects.mkdir()
    (projects / "demo.yaml").write_text(_PROJECT.replace("/tmp", str(tmp_path)))
    cfg = tmp_path / "config.toml"
    cfg.write_text(f'[defaults]\nmode = "local"\nprojects_dir = "{projects.as_posix()}"\n\n[runtime]\ntype = "seatbelt"\n')
    return cfg


def _fake_run(monkeypatch, rcs: dict[str, int]):
    events = []
    state = {"workspace_id": "ws-canary-1", "runtime_type": "seatbelt", "root_path": "/x"}
    monkeypatch.setattr(
        "warren_cli.dispatch.provision_local",
        lambda project, template, projects_dir, **kw: events.append(("provision", template, kw["connect"])) or state,
    )

    def _exec(st, cmd):
        target = cmd[-1]
        events.append(("exec", target))
        return rcs[target]

    monkeypatch.setattr("warren_cli.dispatch._exec_in_sandbox", _exec)
    monkeypatch.setattr(cli_main, "workspaces_destroy", lambda **kw: events.append(("destroy", kw["workspace_id"])))
    return events


def test_verify_intent_passes_when_every_readonly_write_is_refused(tmp_path, monkeypatch):
    events = _fake_run(monkeypatch, {"refs/wiki": 1, "/w/data": 1})
    result = runner.invoke(cli_main.app, ["doctor", "--config", str(_config(tmp_path)), "--verify-intent", "demo/observe"])
    assert result.exit_code == 0, result.output
    assert events == [
        ("provision", "observe", False),
        ("exec", "refs/wiki"),
        ("exec", "/w/data"),
        ("destroy", "ws-canary-1"),
    ]
    assert "write refused" in result.output


def test_verify_intent_fails_and_still_destroys_on_violation(tmp_path, monkeypatch):
    events = _fake_run(monkeypatch, {"refs/wiki": 0, "/w/data": 2})
    result = runner.invoke(cli_main.app, ["doctor", "--config", str(_config(tmp_path)), "--verify-intent", "demo/observe"])
    assert result.exit_code == 1
    assert "WRITE SUCCEEDED" in result.output
    assert "cannot verify" in result.output
    assert events[-1] == ("destroy", "ws-canary-1")


def test_verify_intent_destroys_even_if_exec_raises(tmp_path, monkeypatch):
    events = _fake_run(monkeypatch, {})
    with pytest.raises(KeyError):
        vi.verify_intent("demo/observe", cli_main.WarrenCLIConfig.load(_config(tmp_path)))
    assert events[-1] == ("destroy", "ws-canary-1")


def test_verify_intent_nothing_readonly_skips_provisioning(tmp_path, monkeypatch):
    project = tmp_path / "projects"
    cfg = _config(tmp_path)
    (project / "demo.yaml").write_text("name: demo\ntemplates:\n  open:\n    app: bash\n")
    events = _fake_run(monkeypatch, {})
    result = runner.invoke(cli_main.app, ["doctor", "--config", str(cfg), "--verify-intent", "demo/open"])
    assert result.exit_code == 0, result.output
    assert "nothing to verify" in result.output
    assert events == []


def test_verify_intent_bad_spec(tmp_path):
    result = runner.invoke(cli_main.app, ["doctor", "--config", str(_config(tmp_path)), "--verify-intent", "demo"])
    assert result.exit_code == 1


@pytest.mark.skipif(
    sys.platform == "win32" or os.geteuid() == 0,
    reason="POSIX directory write bits (root ignores them)",
)
def test_canary_script_semantics(tmp_path):
    ro = tmp_path / "ro"
    rw = tmp_path / "rw"
    ro.mkdir()
    rw.mkdir()
    ro.chmod(0o555)
    try:
        def rc(target):
            return subprocess.run(
                ["/bin/sh", "-c", vi._CANARY_SCRIPT, "sh", target],
                env={"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"},
            ).returncode

        assert rc(str(ro)) == 1
        assert rc("ro") == 1
        assert rc(str(rw)) == 0
        assert list(rw.iterdir()) == []
        assert rc("missing") == 2
    finally:
        ro.chmod(0o755)
