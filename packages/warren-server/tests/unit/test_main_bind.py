"""Finding 14: `python -m warren` listens on loopback unless told otherwise, and refuses
cleartext HTTP on a non-loopback address without an explicit acknowledgement."""

from __future__ import annotations

import sys

import pytest

from warren import __main__ as main_module

_BIND_ENV = ("WARREN_HOST", "WARREN_PORT", "WARREN_TLS_CERTFILE", "WARREN_TLS_KEYFILE", "WARREN_ALLOW_INSECURE_HTTP")


@pytest.fixture
def served(monkeypatch) -> list[dict]:
    for name in _BIND_ENV:
        monkeypatch.delenv(name, raising=False)
    calls: list[dict] = []
    monkeypatch.setattr(main_module, "configure_logging", lambda: None)
    monkeypatch.setattr(main_module.uvicorn, "run", lambda *a, **kw: calls.append(kw))
    monkeypatch.setattr(sys, "argv", ["warren"])
    return calls


def test_default_bind_is_loopback(served):
    main_module.main()
    assert served[0]["host"] == "127.0.0.1"
    assert served[0]["port"] == 8420
    assert "ssl_certfile" not in served[0]


@pytest.mark.parametrize("host", ["0.0.0.0", "::", "10.0.0.5", "node2.local"])
def test_non_loopback_without_tls_is_refused(served, monkeypatch, capsys, host):
    monkeypatch.setenv("WARREN_HOST", host)
    with pytest.raises(SystemExit) as exc:
        main_module.main()
    assert exc.value.code == 2
    assert served == []
    assert "WARREN_ALLOW_INSECURE_HTTP" in capsys.readouterr().err


def test_non_loopback_cleartext_needs_explicit_ack_and_warns(served, monkeypatch):
    from structlog.testing import capture_logs

    monkeypatch.setenv("WARREN_HOST", "0.0.0.0")
    monkeypatch.setenv("WARREN_ALLOW_INSECURE_HTTP", "1")
    with capture_logs() as logs:
        main_module.main()
    assert served[0]["host"] == "0.0.0.0"
    assert any(e["event"] == "insecure_http_listener" for e in logs)


def test_non_loopback_with_tls_is_served_over_tls(served, monkeypatch, tmp_path):
    from structlog.testing import capture_logs

    monkeypatch.setenv("WARREN_HOST", "0.0.0.0")
    monkeypatch.setenv("WARREN_PORT", "8443")
    monkeypatch.setenv("WARREN_TLS_CERTFILE", str(tmp_path / "cert.pem"))
    monkeypatch.setenv("WARREN_TLS_KEYFILE", str(tmp_path / "key.pem"))
    with capture_logs() as logs:
        main_module.main()
    assert served[0] == {
        "log_level": "info",
        "host": "0.0.0.0",
        "port": 8443,
        "ssl_certfile": str(tmp_path / "cert.pem"),
        "ssl_keyfile": str(tmp_path / "key.pem"),
    }
    assert not any(e["event"] == "insecure_http_listener" for e in logs)


def test_half_configured_tls_is_refused(served, monkeypatch, tmp_path):
    monkeypatch.setenv("WARREN_TLS_CERTFILE", str(tmp_path / "cert.pem"))
    with pytest.raises(SystemExit):
        main_module.main()
    assert served == []


@pytest.mark.parametrize("host", ["localhost", "::1", "127.0.0.2"])
def test_other_loopback_hosts_need_no_ack(served, monkeypatch, host):
    monkeypatch.setenv("WARREN_HOST", host)
    main_module.main()
    assert served[0]["host"] == host
