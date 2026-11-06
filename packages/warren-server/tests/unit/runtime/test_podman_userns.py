"""WARREN_PODMAN_USERNS: the create args PodmanRuntime sends, the setting's parsing,
the preflight version gate, and the host-side cleanup of subuid-owned files."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from podman.errors import ImageNotFound
from warren.errors import PreflightError
from warren.preflight import _check_userns_support
from warren.runtime import userns as userns_mod
from warren.runtime.podman import PodmanRuntime
from warren.runtime.userns import (
    DEFAULT_PODMAN_USERNS,
    needs_keep_id_options,
    parse_podman_userns,
    remove_tree,
)
from warren_common.errors import ImageUnavailable
from warren_common.runtime.base import WorkspaceSpec


@pytest.fixture(autouse=True)
def _no_real_network_ensure():
    with patch("warren.runtime.podman._ensure_workspace_network"):
        yield


def _spec() -> WorkspaceSpec:
    spec = WorkspaceSpec(
        workspace_id="ws-1",
        project="proj",
        intent="dev",
        image="localhost/warren-base:latest",
        root_path="/tmp/ws-1",
    )
    spec.bind_mounts.append(("/srv/warren/worktrees/ws-1", "/workspace", "rw"))
    return spec


async def _create_kwargs(image_attrs: object = None, **runtime_kwargs) -> tuple[dict, MagicMock]:
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.containers.create.return_value = MagicMock(id="ctr-abc")
        client.images.get.return_value = MagicMock(attrs=image_attrs)
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1", **runtime_kwargs)
        await runtime.provision(_spec())
        _, kwargs = client.containers.create.call_args
        return kwargs, client


# --- container create args ---


async def test_default_is_keep_id_mapped_to_uid_1000():
    kwargs, _ = await _create_kwargs({"Config": {}})
    assert kwargs["userns_mode"] == {"nsmode": "keep-id", "value": "uid=1000,gid=1000"}


async def test_keep_id_pins_root_when_the_image_sets_no_user():
    # keep-id alone would start the entrypoint as uid 1000; warren's images expect root.
    kwargs, client = await _create_kwargs({"Config": {"User": ""}})
    assert kwargs["user"] == "0:0"
    client.images.get.assert_called_once_with("localhost/warren-base:latest")


async def test_keep_id_keeps_the_image_user():
    kwargs, _ = await _create_kwargs({"Config": {"User": "warren"}})
    assert kwargs["user"] == "warren"


async def test_keep_id_with_unreadable_image_config_falls_back_to_root():
    kwargs, _ = await _create_kwargs(None)
    assert kwargs["user"] == "0:0"


async def test_bind_mounts_are_unchanged_by_the_userns():
    kwargs, _ = await _create_kwargs({"Config": {}})
    assert kwargs["mounts"] == [
        {"type": "bind", "source": "/srv/warren/worktrees/ws-1", "target": "/workspace", "read_only": False}
    ]


@pytest.mark.parametrize("off", ["", "host", "  host  "])
async def test_host_or_empty_turns_it_off(off: str):
    kwargs, client = await _create_kwargs({"Config": {}}, userns=off)
    assert "userns_mode" not in kwargs
    assert "user" not in kwargs
    client.images.get.assert_not_called()


async def test_other_modes_pass_through():
    kwargs, _ = await _create_kwargs({"Config": {}}, userns="auto:size=65536")
    assert kwargs["userns_mode"] == {"nsmode": "auto", "value": "size=65536"}


async def test_missing_image_is_image_unavailable():
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.images.get.side_effect = ImageNotFound("no such image")
        runtime = PodmanRuntime(socket_path="/tmp/sock", server_id="srv-1")
        with pytest.raises(ImageUnavailable):
            await runtime.provision(_spec())
        client.containers.create.assert_not_called()


async def test_podman_py_sends_the_namespace_object_and_user():
    """podman-py's own payload builder: the dict reaches the libpod API's `userns` field
    unsplit (the REST API doesn't parse `keep-id:...` the way the CLI does)."""
    from podman.domain.containers_create import CreateMixin

    payload = CreateMixin._render_payload(
        {
            "image": "img",
            "userns_mode": {"nsmode": "keep-id", "value": "uid=1000,gid=1000"},
            "user": "0:0",
        }
    )
    assert payload["userns"] == {"nsmode": "keep-id", "value": "uid=1000,gid=1000"}
    assert payload["user"] == "0:0"


# --- parsing the setting ---


def test_parse_default():
    assert parse_podman_userns(DEFAULT_PODMAN_USERNS) == {"nsmode": "keep-id", "value": "uid=1000,gid=1000"}
    assert needs_keep_id_options(DEFAULT_PODMAN_USERNS)


def test_parse_bare_keep_id():
    assert parse_podman_userns("keep-id") == {"nsmode": "keep-id"}
    assert not needs_keep_id_options("keep-id")


@pytest.mark.parametrize("bad", ["root", "keep-id:uid=1000;rm -rf /", "keep-id:", "ns:/proc/1/ns/user", "private"])
def test_parse_rejects(bad: str):
    with pytest.raises(ValueError):
        parse_podman_userns(bad)


def test_settings_default_and_validation(monkeypatch: pytest.MonkeyPatch):
    from warren.config import WarrenSettings

    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    monkeypatch.delenv("WARREN_PODMAN_USERNS", raising=False)
    assert WarrenSettings().podman_userns == DEFAULT_PODMAN_USERNS
    monkeypatch.setenv("WARREN_PODMAN_USERNS", "host")
    assert WarrenSettings().podman_userns == "host"
    monkeypatch.setenv("WARREN_PODMAN_USERNS", "bogus")
    with pytest.raises(ValueError):
        WarrenSettings()


# --- preflight ---


def _info(version: str) -> dict:
    return {"version": {"Version": version}}


def test_preflight_rejects_keep_id_options_on_old_podman():
    with pytest.raises(PreflightError, match="podman >= 4.3"):
        _check_userns_support(_info("4.2.1"), DEFAULT_PODMAN_USERNS)


@pytest.mark.parametrize("version", ["4.3.0", "4.9.3", "5.4.2", "6.0.1"])
def test_preflight_accepts_new_enough_podman(version: str):
    _check_userns_support(_info(version), DEFAULT_PODMAN_USERNS)


@pytest.mark.parametrize("value", ["", "host", "keep-id"])
def test_preflight_ignores_old_podman_without_keep_id_options(value: str):
    _check_userns_support(_info("4.0.0"), value)


# --- host-side cleanup ---


def test_remove_tree_plain(tmp_path: Path):
    target = tmp_path / "ws"
    (target / "a").mkdir(parents=True)
    (target / "a" / "f").write_text("x")
    with patch.object(userns_mod.subprocess, "run") as run:
        assert remove_tree(target) is True
    run.assert_not_called()
    assert not target.exists()


def test_remove_tree_missing_is_fine(tmp_path: Path):
    assert remove_tree(tmp_path / "nope") is True


def test_remove_tree_falls_back_to_podman_unshare(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    target = tmp_path / "ws"
    target.mkdir()
    monkeypatch.setattr(userns_mod.shutil, "rmtree", lambda *a, **k: None)  # left behind
    monkeypatch.setattr(userns_mod.shutil, "which", lambda name: "/usr/bin/podman")

    def fake_run(argv, **kwargs):
        assert argv == ["/usr/bin/podman", "unshare", "rm", "-rf", "--", str(target)]
        target.rmdir()
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(userns_mod.subprocess, "run", fake_run)
    assert remove_tree(target) is True


def test_remove_tree_reports_failure_without_raising(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    target = tmp_path / "ws"
    target.mkdir()
    monkeypatch.setattr(userns_mod.shutil, "rmtree", lambda *a, **k: None)
    monkeypatch.setattr(userns_mod.shutil, "which", lambda name: "/usr/bin/podman")

    def fake_run(argv, **kwargs):
        raise subprocess.CalledProcessError(125, argv)

    monkeypatch.setattr(userns_mod.subprocess, "run", fake_run)
    assert remove_tree(target) is False
    monkeypatch.setattr(userns_mod.shutil, "which", lambda name: None)
    assert remove_tree(target) is False
