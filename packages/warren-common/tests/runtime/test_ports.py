"""Publish-config generation for template-declared ports on podman/docker: loopback only."""

from __future__ import annotations

import pytest
from warren_common.runtime import ports

_DECLARED = {"t3": {"port": 3773, "description": ""}, "code": {"port": 8080, "description": "code-server"}}


@pytest.mark.parametrize(
    ("configured", "expected"),
    [
        ("127.0.0.1", "127.0.0.1"),
        ("127.0.0.2", "127.0.0.2"),
        ("::1", "::1"),
        ("", "127.0.0.1"),
        (None, "127.0.0.1"),
        ("0.0.0.0", "127.0.0.1"),
        ("::", "127.0.0.1"),
        ("192.168.1.10", "127.0.0.1"),
        ("node2.lan", "127.0.0.1"),
    ],
)
def test_publish_host_is_always_loopback(configured, expected):
    assert ports.loopback_publish_host(configured) == expected


def test_bindings_cover_every_declared_port_on_the_given_loopback_host():
    assert ports.app_port_bindings(_DECLARED, "127.0.0.1") == {"3773/tcp": "127.0.0.1", "8080/tcp": "127.0.0.1"}
    assert ports.app_port_bindings({}, "127.0.0.1") == {}
    assert ports.app_port_bindings(None, "127.0.0.1") == {}


def test_bindings_skip_ports_already_published():
    assert ports.app_port_bindings({"ssh": {"port": 22}, **_DECLARED}, "127.0.0.1", taken={"22/tcp"}) == {
        "3773/tcp": "127.0.0.1",
        "8080/tcp": "127.0.0.1",
    }


@pytest.mark.parametrize("host", ["0.0.0.0", "", "::", "10.0.0.5"])
def test_bindings_refuse_a_non_loopback_host(host):
    with pytest.raises(ValueError, match="non-loopback"):
        ports.app_port_bindings(_DECLARED, host)


def test_bindings_ignore_malformed_entries():
    assert ports.app_port_bindings({"a": {"port": True}, "b": {"port": 0}, "c": 22, "d": "x"}, "127.0.0.1") == {
        "22/tcp": "127.0.0.1"
    }


def test_parse_published_keeps_loopback_tcp_bindings_only():
    raw = {
        "3773/tcp": [{"HostIp": "127.0.0.1", "HostPort": "41001"}],
        "8080/tcp": [{"HostIp": "0.0.0.0", "HostPort": "41002"}, {"HostIp": "::1", "HostPort": "41003"}],
        "9000/tcp": [{"HostIp": "", "HostPort": "41004"}],
        "53/udp": [{"HostIp": "127.0.0.1", "HostPort": "41005"}],
        "22/tcp": None,
        "bad": [{"HostIp": "127.0.0.1", "HostPort": "1"}],
    }
    assert ports.parse_published(raw) == {3773: ("127.0.0.1", 41001), 8080: ("::1", 41003)}
    assert ports.parse_published(None) == {}


def test_host_ports_by_name_maps_declared_names_to_their_bindings():
    published = {3773: ("127.0.0.1", 41001)}
    assert ports.host_ports_by_name(_DECLARED, published) == {"t3": {"host": "127.0.0.1", "port": 41001}}
