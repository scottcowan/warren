"""AK1: bwrap/nsjail workspaces must not reach the session bus's secret service
(libsecret) or the keyring files holding the GitHub App key."""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from warren_common.errors import TemplateDenied
from warren_common.runtime.base import WorkspaceSpec
from warren_common.runtime.bubblewrap import build_bwrap_args
from warren_common.runtime.nsjail_config import NsjailConfig

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="bwrap/nsjail are Linux sandboxes"
)


@pytest.fixture
def host(tmp_path, monkeypatch):
    home = tmp_path / "home"
    runtime_dir = tmp_path / "run-user"
    runtime_dir.mkdir(parents=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setenv("XDG_RUNTIME_DIR", str(runtime_dir))
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", f"unix:path={runtime_dir}/bus")
    return home, runtime_dir


def _spec(home: Path, **over) -> WorkspaceSpec:
    kw = dict(
        workspace_id="ws-1",
        project="p",
        intent="i",
        image="",
        root_path=str(home / ".warren" / "workspaces" / "ws-1"),
    )
    kw.update(over)
    return WorkspaceSpec(**kw)


def test_default_bwrap_args_bind_no_bus_or_keyring_and_drop_bus_env(host):
    home, runtime_dir = host
    args = build_bwrap_args(_spec(home), env_file="/tmp/env")
    joined = " ".join(args)
    assert "--clearenv" in args
    assert str(runtime_dir) not in joined
    assert "/run/user" not in joined
    assert "keyrings" not in joined
    assert "DBUS_SESSION_BUS_ADDRESS" not in joined


def test_default_nsjail_config_binds_no_bus_and_has_own_netns(host):
    home, runtime_dir = host
    cfg = NsjailConfig.from_spec(_spec(home))
    assert cfg.clone_newnet is True
    rendered = cfg.to_proto_text()
    assert str(runtime_dir) not in rendered
    assert "keyrings" not in rendered
    assert "DBUS_SESSION_BUS_ADDRESS" not in rendered


@pytest.mark.parametrize(
    "mount",
    [
        lambda home, rt: (str(rt), "/run/user/1000", "rw"),
        lambda home, rt: (str(rt / "bus"), "/tmp/bus", "rw"),
        lambda home, rt: (str(home), "/home/me", "ro"),
        lambda home, rt: (str(home / ".local" / "share" / "keyrings"), "/k", "ro"),
        lambda home, rt: (str(home / ".warren" / "github-app"), "/g", "ro"),
        lambda home, rt: ("/", "/host", "ro"),
    ],
)
def test_mounts_exposing_secret_service_are_refused(host, mount):
    home, runtime_dir = host
    spec = _spec(home, bind_mounts=[mount(home, runtime_dir)])
    with pytest.raises(TemplateDenied):
        build_bwrap_args(spec, env_file="/tmp/env")
    with pytest.raises(TemplateDenied):
        NsjailConfig.from_spec(spec)


def test_unrelated_mounts_and_ssh_agent_socket_still_allowed(host):
    home, runtime_dir = host
    spec = _spec(
        home,
        bind_mounts=[(str(home / "projects" / "data"), "/data", "ro")],
        ssh_agent_sock=str(runtime_dir / "keyring" / "ssh"),
    )
    build_bwrap_args(spec, env_file="/tmp/env")
    NsjailConfig.from_spec(spec)
