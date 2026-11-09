"""pasta + AppArmor detection from canned `podman info` payloads."""

from __future__ import annotations

import copy
import logging
from pathlib import Path
from unittest.mock import patch

import pytest

from warren import podman_host
from warren.podman_host import pasta_apparmor_warning, profile_allows_podman_signal
from warren.errors import PreflightError
from warren.preflight import run_preflight


def _info(version: str, net_cmd: str | None, apparmor: bool = True, rootless: bool = True) -> dict:
    host: dict = {
        "hostname": "node2",
        "idMappings": {"uidmap": [{"size": 65536}]},
        "security": {"apparmorEnabled": apparmor, "rootless": rootless},
        "distribution": {"distribution": "ubuntu", "version": "26.04"},
        "pasta": {"executable": "/usr/bin/pasta"},
        "slirp4netns": {"executable": "/usr/bin/slirp4netns"},
    }
    if net_cmd is not None:
        host["rootlessNetworkCmd"] = net_cmd
    return {"host": host, "store": {"graphDriverName": "overlay"}, "version": {"Version": version}}


PODMAN_49_PASTA = _info("4.9.3", "pasta")  # 4.x: no podman AppArmor profile, not affected
PODMAN_49_OLD = _info("4.9.3", None)  # 4.x doesn't report rootlessNetworkCmd
PODMAN_57_PASTA = _info("5.7.0", "pasta")
PODMAN_57_SLIRP = _info("5.7.0", "slirp4netns")
PODMAN_57_NO_APPARMOR = _info("5.7.0", "pasta", apparmor=False)
PODMAN_57_ROOTFUL = _info("5.7.0", "pasta", rootless=False)


def _drop(info: dict, *path: str) -> dict:
    out = copy.deepcopy(info)
    node = out
    for key in path[:-1]:
        node = node[key]
    del node[path[-1]]
    return out


def test_warns_on_podman5_pasta_apparmor():
    w = pasta_apparmor_warning(PODMAN_57_PASTA)
    assert w is not None
    assert w["podman_version"] == "5.7.0"
    assert w["rootless_network_cmd"] == "pasta"
    assert w["distribution"] == "ubuntu 26.04"
    assert "slirp4netns" in w["fix"] and "containers.conf" in w["fix"]
    assert w["docs"].endswith("#ubuntu-2604-rootless-podman-and-pasta")
    assert w["profile_checked"] is False


@pytest.mark.parametrize(
    "info",
    [PODMAN_49_PASTA, PODMAN_49_OLD, PODMAN_57_SLIRP, PODMAN_57_NO_APPARMOR, PODMAN_57_ROOTFUL],
    ids=["4.9-pasta", "4.9-old", "5.7-slirp4netns", "5.7-no-apparmor", "5.7-rootful"],
)
def test_no_warning(info):
    assert pasta_apparmor_warning(info) is None


@pytest.mark.parametrize(
    "info",
    [
        {},
        {"host": {}},
        _drop(PODMAN_57_PASTA, "version"),
        _drop(PODMAN_57_PASTA, "host", "security"),
        _drop(PODMAN_57_PASTA, "host", "security", "apparmorEnabled"),
        _drop(PODMAN_57_PASTA, "host", "security", "rootless"),
        PODMAN_49_OLD,
    ],
    ids=["empty", "empty-host", "no-version", "no-security", "no-apparmor-field", "no-rootless-field", "4x-no-netcmd"],
)
def test_missing_fields_do_not_warn(info):
    assert pasta_apparmor_warning(info) is None


def test_missing_netcmd_on_podman5_is_pasta_by_default():
    assert pasta_apparmor_warning(_drop(PODMAN_57_PASTA, "host", "rootlessNetworkCmd")) is not None


def test_pascal_case_fields():
    info = {
        "Host": {
            "Security": {"AppArmorEnabled": True, "Rootless": True},
            "RootlessNetworkCmd": "pasta",
        },
        "Version": {"Version": "5.4.2"},
    }
    assert pasta_apparmor_warning(info) is not None


_BROKEN_PROFILE = """
profile pasta /usr/bin/pasta{,.avx2} flags=(attach_disconnected) {
  signal (receive) peer=unconfined,
  signal (send) peer=podman,
}
"""
_FIXED_PROFILE = _BROKEN_PROFILE + "  signal (receive) set=(term) peer=podman,\n"


def test_profile_rule_detection():
    assert not profile_allows_podman_signal(_BROKEN_PROFILE)
    assert profile_allows_podman_signal(_FIXED_PROFILE)
    assert profile_allows_podman_signal('  signal peer="podman",\n')
    assert profile_allows_podman_signal("  signal,\n")


def test_profile_that_allows_podman_clears_warning():
    assert pasta_apparmor_warning(PODMAN_57_PASTA, _FIXED_PROFILE) is None
    w = pasta_apparmor_warning(PODMAN_57_PASTA, _BROKEN_PROFILE)
    assert w is not None and w["profile_checked"] is True


def test_read_local_pasta_profile(tmp_path: Path):
    assert podman_host.read_local_pasta_profile((str(tmp_path / "missing"),)) is None
    (tmp_path / "pasta").write_text(_FIXED_PROFILE)
    text = podman_host.read_local_pasta_profile((str(tmp_path / "missing"), str(tmp_path / "pasta")))
    assert text is not None and "peer=podman" in text


async def _preflight(tmp_path: Path, info: dict, **kwargs) -> None:
    sock = tmp_path / "podman.sock"
    sock.touch()
    with patch("warren.runtime.podman.PodmanClient") as ClientCls:
        client = ClientCls.return_value
        client.ping.return_value = True
        client.info.return_value = info
        await run_preflight(socket_path=str(sock), **kwargs)


@pytest.mark.asyncio
async def test_preflight_warns_without_failing(tmp_path: Path, caplog):
    with caplog.at_level(logging.WARNING):
        await _preflight(tmp_path, PODMAN_57_PASTA, allow_pasta=True)
    assert any("AppArmor" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_preflight_silent_on_slirp4netns(tmp_path: Path, caplog):
    with caplog.at_level(logging.WARNING):
        await _preflight(tmp_path, PODMAN_57_SLIRP)
    assert not any("AppArmor" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_preflight_reads_local_profile_only_on_same_host(tmp_path: Path, caplog):
    with (
        patch("warren.preflight.read_local_pasta_profile", return_value=_FIXED_PROFILE) as read,
        patch("warren.preflight._socket_mod.gethostname", return_value="node2"),
    ):
        # Remote socket (or containerized server): never reads local files, so warns.
        with caplog.at_level(logging.WARNING):
            await _preflight(tmp_path, PODMAN_57_PASTA, same_host=False, allow_pasta=True)
        read.assert_not_called()
        assert any("AppArmor" in r.getMessage() for r in caplog.records)
        caplog.clear()
        # Same host whose pasta profile allows podman's signal: no warning.
        with caplog.at_level(logging.WARNING):
            await _preflight(tmp_path, PODMAN_57_PASTA, same_host=True, allow_pasta=True)
        read.assert_called_once()
        assert not any("AppArmor" in r.getMessage() for r in caplog.records)


@pytest.mark.asyncio
async def test_preflight_hostname_mismatch_skips_local_profile(tmp_path: Path):
    with (
        patch("warren.preflight.read_local_pasta_profile") as read,
        patch("warren.preflight._socket_mod.gethostname", return_value="laptop"),
    ):
        await _preflight(tmp_path, PODMAN_57_PASTA, same_host=True, allow_pasta=True)
    read.assert_not_called()


# --- pasta and host loopback (published workspace ports) ---


@pytest.mark.parametrize("info", [PODMAN_57_PASTA, PODMAN_57_NO_APPARMOR, _info("6.0.1", "pasta", apparmor=False)])
def test_pasta_host_loopback_warns_for_rootless_pasta(info):
    w = podman_host.pasta_host_loopback_warning(info)
    assert w is not None and w["rootless_network_cmd"] == "pasta"
    assert "169.254.1.2" in w["detail"] and "slirp4netns" in w["fix"]


@pytest.mark.parametrize("info", [PODMAN_57_SLIRP, PODMAN_57_ROOTFUL, PODMAN_49_OLD])
def test_pasta_host_loopback_silent_otherwise(info):
    assert podman_host.pasta_host_loopback_warning(info) is None


@pytest.mark.asyncio
async def test_preflight_warns_about_pasta_host_loopback(tmp_path: Path, caplog):
    with caplog.at_level(logging.WARNING):
        await _preflight(tmp_path, _info("6.0.1", "pasta", apparmor=False), allow_pasta=True)
    assert any("169.254.1.2" in r.getMessage() for r in caplog.records)
    caplog.clear()
    with caplog.at_level(logging.WARNING):
        await _preflight(tmp_path, PODMAN_57_SLIRP)
    assert not any("169.254.1.2" in r.getMessage() for r in caplog.records)


# --- pasta refusal -----------------------------------------------------------------


@pytest.mark.asyncio
async def test_preflight_refuses_rootless_pasta_on_podman5(tmp_path: Path):
    with pytest.raises(PreflightError) as exc:
        await _preflight(tmp_path, PODMAN_57_PASTA)
    msg = str(exc.value)
    assert "pasta" in msg and "169.254.1.2" in msg
    assert 'default_rootless_network_cmd = "slirp4netns"' in msg
    assert "~/.config/containers/containers.conf" in msg
    assert "slirp4netns must be installed" in msg
    assert "WARREN_PODMAN_ALLOW_PASTA=1" in msg


@pytest.mark.asyncio
async def test_preflight_pasta_allowed_with_override_logs_warning_once(tmp_path: Path, caplog):
    with caplog.at_level(logging.WARNING):
        await _preflight(tmp_path, PODMAN_57_PASTA, allow_pasta=True)
    msgs = [r.getMessage() for r in caplog.records]
    assert sum("runs rootless networking through pasta" in m for m in msgs) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "info",
    [
        PODMAN_57_SLIRP,
        PODMAN_57_ROOTFUL,
        PODMAN_49_OLD,
        _info("4.9.3", None, apparmor=False),
        _drop(PODMAN_57_PASTA, "host", "security", "rootless"),
    ],
    ids=["slirp", "rootful", "4x-missing", "4x-missing-noaa", "rootless-unreported"],
)
async def test_preflight_no_refusal(tmp_path: Path, info):
    await _preflight(tmp_path, info)


@pytest.mark.asyncio
async def test_preflight_refuses_when_field_missing_on_podman5(tmp_path: Path):
    # podman 5.0+ defaults to pasta, so an unreported helper is pasta.
    with pytest.raises(PreflightError):
        await _preflight(tmp_path, _info("5.7.0", None))
    await _preflight(tmp_path, _info("5.7.0", None), allow_pasta=True)


def test_rootless_uses_pasta_pascal_case():
    info = {
        "Host": {"Security": {"Rootless": True}, "RootlessNetworkCmd": "pasta"},
        "Version": {"Version": "5.7.0"},
    }
    assert podman_host.rootless_uses_pasta(info)
