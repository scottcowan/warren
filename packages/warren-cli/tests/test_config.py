"""warren CLI config load — tomllib round-trip + back-compat upgrade."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from warren_cli.config import ServerProfile, WarrenCLIConfig

posix_only = pytest.mark.skipif(
    os.name == "nt", reason="POSIX mode bits; Windows DACLs covered by warren-common test_fileperms"
)


def _write(path: Path, content: str) -> Path:
    path.write_text(content)
    return path


def test_config_multi_server_round_trip(tmp_path: Path):
    cfg_file = _write(
        tmp_path / "config.toml",
        """
default_server = "node2"

[servers.node2]
url = "http://node2.local:8420"
auth_token = "tok-node2"

[servers.cloud]
url = "https://warren.example.com"
auth_token = "tok-cloud"
""",
    )
    cfg = WarrenCLIConfig.load(cfg_file)
    assert cfg.default_server == "node2"
    assert cfg.servers["node2"].url == "http://node2.local:8420"
    assert cfg.servers["cloud"].auth_token.get_secret_value() == "tok-cloud"


def test_config_backcompat_flat_server(tmp_path: Path):
    cfg_file = _write(
        tmp_path / "config.toml",
        """
[server]
url = "http://old.local:8420"
auth_token = "legacy"
""",
    )
    cfg = WarrenCLIConfig.load(cfg_file)
    assert cfg.default_server == "default"
    assert cfg.servers["default"].url == "http://old.local:8420"
    assert cfg.servers["default"].auth_token.get_secret_value() == "legacy"


def test_config_missing_file_raises_with_path(tmp_path: Path):
    missing = tmp_path / "does-not-exist.toml"
    with pytest.raises(FileNotFoundError) as ei:
        WarrenCLIConfig.load(missing)
    assert str(missing) in str(ei.value)


def test_get_profile_default_and_named(tmp_path: Path):
    cfg_file = _write(
        tmp_path / "config.toml",
        """
default_server = "node2"

[servers.node2]
url = "http://node2.local:8420"
auth_token = "tok-node2"

[servers.cloud]
url = "https://warren.example.com"
auth_token = "tok-cloud"
""",
    )
    cfg = WarrenCLIConfig.load(cfg_file)
    assert cfg.get_profile(None).url == "http://node2.local:8420"
    assert cfg.get_profile("cloud").url == "https://warren.example.com"
    with pytest.raises(KeyError) as ei:
        cfg.get_profile("no-such-server")
    assert "no-such-server" in str(ei.value)


def test_auth_token_is_secret_and_not_leaked_in_repr():
    profile = ServerProfile(url="http://x.local", auth_token="super-secret-value")
    text = repr(profile)
    assert "super-secret-value" not in text
    assert profile.auth_token.get_secret_value() == "super-secret-value"


def test_config_local_only_no_servers(tmp_path: Path):
    cfg_file = _write(
        tmp_path / "config.toml",
        """
[defaults]
mode = "local"
projects_dir = "/tmp/warren-x/projects"
""",
    )
    cfg = WarrenCLIConfig.load(cfg_file)
    assert cfg.defaults.mode == "local"
    assert cfg.defaults.projects_dir == "/tmp/warren-x/projects"
    assert cfg.servers == {}
    assert cfg.projects_path() == Path("/tmp/warren-x/projects")


def test_config_defaults_default_projects_path_when_unset():
    from warren_cli.config import CLIDefaults, WarrenCLIConfig as _C
    cfg = _C(defaults=CLIDefaults(mode="local"), servers={})
    assert cfg.projects_path().name == "projects"
    assert cfg.projects_path().parent.name == ".warren"


def test_config_invalid_mode_rejected(tmp_path: Path):
    cfg_file = _write(
        tmp_path / "config.toml",
        """
[defaults]
mode = "bogus"
""",
    )
    with pytest.raises(Exception):
        WarrenCLIConfig.load(cfg_file)


def test_config_remotes_section(tmp_path: Path):
    cfg_file = _write(
        tmp_path / "config.toml",
        '[remotes.node2]\nurl = "http://node2:8080"\n[remotes.prod]\nurl = "http://192.168.1.100:8420"\n',
    )
    cfg = WarrenCLIConfig.load(cfg_file)
    assert cfg.remotes["node2"].url == "http://node2:8080"
    assert cfg.remotes["prod"].url == "http://192.168.1.100:8420"


def test_get_remote_raises_on_unknown(tmp_path: Path):
    cfg_file = _write(
        tmp_path / "config.toml",
        '[remotes.node2]\nurl = "http://x"\n',
    )
    cfg = WarrenCLIConfig.load(cfg_file)
    with pytest.raises(KeyError) as ei:
        cfg.get_remote("no-such-remote")
    assert "no-such-remote" in str(ei.value)


def test_remote_profile_auth_token_optional_and_defaults_absent():
    from warren_cli.config import RemoteProfile

    p = RemoteProfile(url="http://node2:8080")
    assert p.auth_token is None


def test_remote_profile_accepts_auth_token(tmp_path: Path):
    cfg_file = _write(
        tmp_path / "config.toml",
        '[remotes.node2]\nurl = "http://node2:8080"\nauth_token = "tok-abc"\n',
    )
    cfg = WarrenCLIConfig.load(cfg_file)
    assert cfg.remotes["node2"].auth_token.get_secret_value() == "tok-abc"


def test_remote_profile_ssh_requires_ssh_host():
    from warren_cli.config import RemoteProfile

    with pytest.raises(ValueError, match="requires 'ssh_host'"):
        RemoteProfile(runtime_type="ssh")


def test_remote_profile_ecs_requires_aws_audience():
    """Issue #14: a missing aws_audience on an ecs profile used to only
    surface as a 401 on the first real request -- must fail at config load
    instead, like the existing ecs_cluster/ecs_service check just above it."""
    from warren_cli.config import RemoteProfile

    with pytest.raises(ValueError, match="requires 'aws_audience'"):
        RemoteProfile(runtime_type="ecs", ecs_cluster="my-cluster", ecs_service="my-service")


def test_remote_profile_ecs_accepts_aws_audience():
    from warren_cli.config import RemoteProfile

    p = RemoteProfile(
        runtime_type="ecs", ecs_cluster="my-cluster", ecs_service="my-service", aws_audience="node2"
    )
    assert p.aws_audience == "node2"


def test_remote_profile_ssh_does_not_require_aws_audience():
    """ssh profiles point at podman/docker servers by default, which never
    consult AWS identity headers at all -- aws_audience stays optional there."""
    from warren_cli.config import RemoteProfile

    p = RemoteProfile(runtime_type="ssh", ssh_host="node2")
    assert p.aws_audience is None


def test_remote_profile_ssh_defaults_and_overrides(tmp_path: Path):
    cfg_file = _write(
        tmp_path / "config.toml",
        '[remotes.node2]\nruntime_type = "ssh"\nssh_host = "node2"\n'
        'ssh_key_path = "~/.ssh/id_homelab"\n',
    )
    cfg = WarrenCLIConfig.load(cfg_file)
    profile = cfg.remotes["node2"]
    assert profile.ssh_host == "node2"
    assert profile.ssh_key_path == "~/.ssh/id_homelab"
    assert profile.ssh_remote_port == 8420  # default


@posix_only
def test_write_config_toml_creates_file_mode_0600(tmp_path: Path):
    """S8: a newly created config.toml must be 0600 regardless of the
    process umask -- not whatever umask happens to leave it at (commonly
    0644, world-readable). This file holds the server's auth_token."""
    import os
    import stat

    from warren_cli.config import write_config_toml

    old_umask = os.umask(0o022)  # deliberately loose umask -- would leave 0644 if relied on
    try:
        path = tmp_path / "config.toml"
        write_config_toml(path, {"server": {"url": "http://localhost:8420", "auth_token": "x"}})
    finally:
        os.umask(old_umask)

    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"


@posix_only
def test_write_config_toml_rechmods_existing_file_to_0600(tmp_path: Path):
    """S8: rewriting an existing config.toml must correct its permissions to
    0600 even if it was previously left world/group-readable by an older
    version of this code (or a careless `cp`) -- same pattern
    registry/store.py's open_db already uses for the local secrets DB."""
    import stat

    from warren_cli.config import write_config_toml

    path = tmp_path / "config.toml"
    path.write_text("stale")
    path.chmod(0o644)
    assert stat.S_IMODE(path.stat().st_mode) == 0o644

    write_config_toml(path, {"server": {"url": "http://localhost:8420", "auth_token": "x"}})

    mode = stat.S_IMODE(path.stat().st_mode)
    assert mode == 0o600, f"expected 0600, got {oct(mode)}"


def test_write_config_toml_round_trips_data(tmp_path: Path):
    """Sanity check that the os.open-based rewrite still produces valid,
    round-trippable TOML -- not just correct permissions."""
    import tomllib

    from warren_cli.config import write_config_toml

    path = tmp_path / "config.toml"
    data = {"server": {"url": "http://localhost:8420", "auth_token": "sekret-token"}}
    write_config_toml(path, data)

    with open(path, "rb") as f:
        loaded = tomllib.load(f)
    assert loaded == data


def test_write_config_toml_restricts_to_owner(tmp_path, monkeypatch):
    from warren_cli import config as cfg_mod

    seen = []
    monkeypatch.setattr(cfg_mod, "restrict_to_owner", lambda p: seen.append(p))
    path = tmp_path / "config.toml"
    cfg_mod.write_config_toml(path, {"defaults": {"mode": "local"}})
    assert seen == [path]
