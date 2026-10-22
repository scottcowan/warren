"""warren server add/use — the legacy [servers.*]/ServerProfile namespace."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner
from warren_cli.config import WarrenCLIConfig
from warren_cli.main import app

runner = CliRunner()


def _init_config(tmp_path: Path) -> Path:
    cfg_file = tmp_path / "config.toml"
    cfg_file.write_text("")
    return cfg_file


def test_server_use_sets_default_server(tmp_path: Path):
    cfg_file = _init_config(tmp_path)
    runner.invoke(
        app,
        ["server", "add", "node2", "http://node2:8420", "--token", "tok-xyz", "--config", str(cfg_file)],
    )
    result = runner.invoke(app, ["server", "use", "node2", "--config", str(cfg_file)])
    assert result.exit_code == 0, result.output
    cfg = WarrenCLIConfig.load(cfg_file)
    assert cfg.default_server == "node2"
    assert cfg.get_profile(None).url == "http://node2:8420"


def test_server_use_unknown_profile_errors(tmp_path: Path):
    cfg_file = _init_config(tmp_path)
    runner.invoke(
        app,
        ["server", "add", "node2", "http://node2:8420", "--token", "tok-xyz", "--config", str(cfg_file)],
    )
    result = runner.invoke(app, ["server", "use", "no-such-server", "--config", str(cfg_file)])
    assert result.exit_code != 0
    assert "not found" in result.output
    cfg = WarrenCLIConfig.load(cfg_file)
    assert cfg.default_server == "default"
