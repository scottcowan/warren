"""Unix-socket listener support: the Mapping/MappingStore fields."""

from __future__ import annotations

import json

from warren_cli import proxy


def test_mapping_defaults_to_tcp_and_omits_listen_fields_when_saved(tmp_path):
    store = proxy.MappingStore(tmp_path / "proxy.json")
    m, _ = store.add("srv", "ws1", 3773)
    assert (m.listen, m.socket_path) == ("tcp", None)
    rows = json.loads((tmp_path / "proxy.json").read_text())["mappings"]
    assert "listen" not in rows[0] and "socket_path" not in rows[0]
    assert store.load() == [m]


def test_unix_mapping_round_trips_without_a_local_port(tmp_path):
    store = proxy.MappingStore(tmp_path / "proxy.json")
    m = proxy.Mapping("srv", "ws1", 3773, 0, listen="unix", socket_path="/tmp/x.sock")
    store.save([m])
    row = json.loads((tmp_path / "proxy.json").read_text())["mappings"][0]
    assert row["listen"] == "unix" and row["socket_path"] == "/tmp/x.sock"
    loaded = store.load()
    assert loaded == [m] and loaded[0].local_port == 0


def test_unix_mapping_without_local_port_key_loads(tmp_path):
    p = tmp_path / "proxy.json"
    p.write_text(json.dumps({"mappings": [{"server": "s", "workspace": "w", "remote_port": 22, "listen": "unix"}]}))
    (m,) = proxy.MappingStore(p).load()
    assert (m.listen, m.local_port, m.socket_path) == ("unix", 0, None)


def test_bad_listen_or_tcp_without_port_is_skipped(tmp_path):
    p = tmp_path / "proxy.json"
    rows = [
        {"server": "s", "workspace": "w", "remote_port": 22, "local_port": 47100, "listen": "pipe"},
        {"server": "s", "workspace": "w", "remote_port": 23},
        {"server": "s", "workspace": "w", "remote_port": 24, "listen": "unix", "socket_path": "rel.sock"},
    ]
    p.write_text(json.dumps({"mappings": rows}))
    assert proxy.MappingStore(p).load() == []


def test_renaming_keeps_listen_fields(tmp_path):
    store = proxy.MappingStore(tmp_path / "proxy.json")
    store.save([proxy.Mapping("srv", "ws1", 3773, 0, listen="unix", socket_path="/tmp/x.sock")])
    m, created = store.add("srv", "ws1", 3773, name="web")
    assert not created and (m.listen, m.socket_path, m.name) == ("unix", "/tmp/x.sock", "web")
