"""warren remote add/list — optional --token for servers with auth enforcement."""

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


def test_remote_add_without_token(tmp_path: Path):
    cfg_file = _init_config(tmp_path)
    result = runner.invoke(app, ["remote", "add", "node2", "http://node2:8420", "--config", str(cfg_file)])
    assert result.exit_code == 0, result.output
    cfg = WarrenCLIConfig.load(cfg_file)
    assert cfg.remotes["node2"].url == "http://node2:8420"
    assert cfg.remotes["node2"].auth_token is None


def test_remote_add_with_token(tmp_path: Path):
    cfg_file = _init_config(tmp_path)
    result = runner.invoke(
        app,
        ["remote", "add", "node2", "http://node2:8420", "--token", "tok-xyz", "--config", str(cfg_file)],
    )
    assert result.exit_code == 0, result.output
    cfg = WarrenCLIConfig.load(cfg_file)
    assert cfg.remotes["node2"].auth_token.get_secret_value() == "tok-xyz"
    # token must never appear in stdout
    assert "tok-xyz" not in result.output


def test_remote_list_shows_authed_vs_no_auth(tmp_path: Path):
    cfg_file = _init_config(tmp_path)
    runner.invoke(app, ["remote", "add", "node2", "http://node2:8420", "--token", "tok-xyz", "--config", str(cfg_file)])
    runner.invoke(app, ["remote", "add", "node3", "http://node3:8420", "--config", str(cfg_file)])
    result = runner.invoke(app, ["remote", "list", "--config", str(cfg_file)])
    assert result.exit_code == 0, result.output
    assert "node2" in result.output and "(authed)" in result.output
    assert "node3" in result.output and "(no auth)" in result.output
    assert "tok-xyz" not in result.output


def test_remote_add_ecs_profile(tmp_path: Path):
    cfg_file = _init_config(tmp_path)
    result = runner.invoke(
        app,
        [
            "remote", "add", "prod-ecs",
            "--ecs-cluster", "warren-cluster",
            "--ecs-service", "warren-service",
            "--aws-audience", "warren-prod",
            "--config", str(cfg_file),
        ],
    )
    assert result.exit_code == 0, result.output
    cfg = WarrenCLIConfig.load(cfg_file)
    profile = cfg.remotes["prod-ecs"]
    assert profile.runtime_type == "ecs"
    assert profile.ecs_cluster == "warren-cluster"
    assert profile.ecs_service == "warren-service"
    assert profile.aws_audience == "warren-prod"


def test_remote_add_ecs_requires_aws_audience(tmp_path: Path):
    cfg_file = _init_config(tmp_path)
    result = runner.invoke(
        app,
        [
            "remote", "add", "prod-ecs",
            "--ecs-cluster", "warren-cluster",
            "--ecs-service", "warren-service",
            "--config", str(cfg_file),
        ],
    )
    assert result.exit_code != 0
    assert "--aws-audience is required" in result.output
    cfg = WarrenCLIConfig.load(cfg_file)
    assert "prod-ecs" not in cfg.remotes


def test_remote_add_ecs_requires_both_cluster_and_service(tmp_path: Path):
    cfg_file = _init_config(tmp_path)
    result = runner.invoke(
        app,
        [
            "remote", "add", "prod-ecs",
            "--ecs-cluster", "warren-cluster",
            "--aws-audience", "warren-prod",
            "--config", str(cfg_file),
        ],
    )
    assert result.exit_code != 0
    assert "must be given together" in result.output


def test_remote_add_ecs_rejects_url(tmp_path: Path):
    cfg_file = _init_config(tmp_path)
    result = runner.invoke(
        app,
        [
            "remote", "add", "prod-ecs", "http://node2:8420",
            "--ecs-cluster", "warren-cluster",
            "--ecs-service", "warren-service",
            "--aws-audience", "warren-prod",
            "--config", str(cfg_file),
        ],
    )
    assert result.exit_code != 0
    assert "can't be combined" in result.output


def test_remote_add_still_requires_target(tmp_path: Path):
    cfg_file = _init_config(tmp_path)
    result = runner.invoke(app, ["remote", "add", "node2", "--config", str(cfg_file)])
    assert result.exit_code != 0
    assert "URL, --ssh-host, or --ecs-cluster is required" in result.output


def test_remote_list_json(tmp_path: Path):
    import json as _json

    cfg_file = _init_config(tmp_path)
    runner.invoke(app, ["remote", "add", "node2", "http://node2:8420", "--token", "tok-xyz", "--config", str(cfg_file)])
    result = runner.invoke(app, ["remote", "list", "--json", "--config", str(cfg_file)])
    assert result.exit_code == 0, result.output
    body = _json.loads(result.output)
    assert body == [{"name": "node2", "runtime_type": "http", "target": "http://node2:8420", "authed": True}]
    assert "tok-xyz" not in result.output
