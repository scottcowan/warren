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


def test_add_unix_allocates_no_local_port_and_keeps_tcp_ports_free(tmp_path):
    store = proxy.MappingStore(tmp_path / "proxy.json")
    u, created = store.add("srv", "ws1", 3773, listen="unix", port_free=lambda p: False)
    assert created and (u.listen, u.local_port, u.socket_path) == ("unix", 0, None)
    t, _ = store.add("srv", "ws1", 2222)
    assert t.local_port == 47100 and t.listen == "tcp"
    again, created = store.add("srv", "ws1", 3773, listen="unix")
    assert not created and again == u


def test_add_unix_validates(tmp_path):
    import pytest

    store = proxy.MappingStore(tmp_path / "proxy.json")
    with pytest.raises(proxy.ProxyError, match="absolute"):
        store.add("srv", "ws1", 1, listen="unix", socket_path="rel.sock")
    with pytest.raises(proxy.ProxyError, match="local port"):
        store.add("srv", "ws1", 1, listen="unix", local_port=47200)
    with pytest.raises(proxy.ProxyError, match="unix"):
        store.add("srv", "ws1", 1, socket_path="/tmp/a.sock")
    with pytest.raises(proxy.ProxyError, match="listen"):
        store.add("srv", "ws1", 1, listen="udp")
    store.add("srv", "ws1", 1, listen="unix", socket_path="/tmp/a.sock")
    with pytest.raises(proxy.ProxyError, match="already used"):
        store.add("srv", "ws1", 2, listen="unix", socket_path="/tmp/a.sock")


def test_remove_by_port_skips_unix_and_unix_can_become_tcp(tmp_path):
    store = proxy.MappingStore(tmp_path / "proxy.json")
    store.add("srv", "ws1", 3773, listen="unix")
    assert store.remove("0") == []
    m, created = store.add("srv", "ws1", 3773, listen="tcp")
    assert not created and m.listen == "tcp" and m.local_port == 47100 and m.socket_path is None


def test_unlink_owned_socket_only_removes_our_sockets(tmp_path):
    import socket

    from warren_cli import proxy_unix

    import tempfile
    from pathlib import Path

    d = Path(tempfile.mkdtemp(prefix="wu"))  # short: sun_path limit
    sp = str(d / "a.sock")
    s = socket.socket(socket.AF_UNIX)
    s.bind(sp)
    s.close()
    assert proxy_unix.unlink_owned_socket(sp) is True
    reg = d / "file"
    reg.write_text("x")
    assert proxy_unix.unlink_owned_socket(str(reg)) is False and reg.exists()
    link = d / "l"
    link.symlink_to(reg)
    assert proxy_unix.unlink_owned_socket(str(link)) is False and link.is_symlink()
    assert proxy_unix.unlink_owned_socket(str(d / "missing")) is False


def test_cli_add_unix_prints_socket_path_and_curl_example(tmp_path):
    import json as _json

    from typer.testing import CliRunner

    from warren_cli.main import app
    from test_proxy import _config

    runner = CliRunner()
    cfg = _config(tmp_path)
    sock = "/tmp/wr-test.sock"
    r = runner.invoke(app, ["proxy", "add", "ws1", "3773", "--unix", "--socket", sock, "--kind", "http", "--config", str(cfg)])
    assert r.exit_code == 0, r.output
    assert f"unix:{sock}" in r.output
    assert f"curl --unix-socket {sock} http://localhost/" in r.output
    assert "127.0.0.1" not in r.output
    listed = runner.invoke(app, ["proxy", "list"])
    assert sock in listed.output
    data = _json.loads(runner.invoke(app, ["proxy", "list", "--json"]).output)
    assert data[0]["listen"] == "unix"
    r = runner.invoke(app, ["proxy", "add", "ws1", "2222", "--unix", "--local-port", "47300", "--config", str(cfg)])
    assert r.exit_code != 0
    r = runner.invoke(app, ["proxy", "add", "ws1", "2222", "--socket", sock, "--config", str(cfg)])
    assert r.exit_code == 2 and "--unix" in r.output
    assert runner.invoke(app, ["proxy", "rm", "ws1"]).exit_code == 0


def test_cli_add_unix_refused_on_windows(tmp_path, monkeypatch):
    from typer.testing import CliRunner

    from warren_cli import proxy_unix
    from warren_cli.main import app
    from test_proxy import _config

    monkeypatch.setattr(proxy_unix, "supported", lambda: False)
    r = CliRunner().invoke(app, ["proxy", "add", "ws1", "3773", "--unix", "--config", str(_config(tmp_path))])
    assert r.exit_code == 2 and "not supported" in r.output


def test_cli_rm_unlinks_only_a_real_socket(tmp_path):
    import socket
    import tempfile
    from pathlib import Path

    from typer.testing import CliRunner

    from warren_cli.main import app
    from test_proxy import _config

    d = Path(tempfile.mkdtemp(prefix="wu"))
    sp = str(d / "a.sock")
    s = socket.socket(socket.AF_UNIX)
    s.bind(sp)
    s.close()
    runner = CliRunner()
    cfg = _config(tmp_path)
    runner.invoke(app, ["proxy", "add", "ws1", "3773", "--unix", "--socket", sp, "--config", str(cfg)])
    assert runner.invoke(app, ["proxy", "rm", "ws1"]).exit_code == 0
    assert not Path(sp).exists()
    reg = d / "plain"
    reg.write_text("x")
    runner.invoke(app, ["proxy", "add", "ws1", "3773", "--unix", "--socket", str(reg), "--config", str(cfg)])
    assert runner.invoke(app, ["proxy", "rm", "ws1"]).exit_code == 0
    assert reg.exists()
