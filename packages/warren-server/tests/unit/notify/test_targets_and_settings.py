"""https validation (settings and API), event parsing, the SSRF guard."""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from warren.config import WarrenSettings
from warren.notify import build_notifier
from warren.notify.targets import (
    is_public_destination,
    parse_events,
    validate_webhook_url,
)

SECRET = "https://hooks.slack.com/services/T000/B000/XXXXsecretXXXX"


@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.slack.com/services/x",
        "https://user:pw@hooks.example.com/x",
        "https://hooks.example.com/x?token=abc",
        "https://hooks.example.com/x#frag",
        "ftp://hooks.example.com/x",
        "https:///secretpath",
        "hooks.example.com/x",
        "https://" + "a" * 3000 + ".com",
    ],
)
def test_validate_webhook_url_rejects(url):
    with pytest.raises(ValueError) as info:
        validate_webhook_url(url)
    assert url not in str(info.value) and "secret" not in str(info.value)


@pytest.mark.parametrize("url", [SECRET, "https://example.com", "https://example.com:8443/a/b-c_d.e~f"])
def test_validate_webhook_url_accepts(url):
    assert validate_webhook_url(f"  {url} ") == url


def _settings(monkeypatch, **env) -> WarrenSettings:
    monkeypatch.setenv("WARREN_SECRET_KEY", "x" * 32)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    return WarrenSettings()


def test_settings_defaults(monkeypatch):
    s = _settings(monkeypatch)
    assert s.notify_enabled is True and s.notify_webhook_url is None and s.notify_format == "json"


def test_settings_webhook_is_secret(monkeypatch):
    s = _settings(monkeypatch, WARREN_NOTIFY_WEBHOOK_URL=SECRET, WARREN_NOTIFY_FORMAT="slack")
    assert s.notify_webhook_url.get_secret_value() == SECRET
    assert "XXXXsecretXXXX" not in repr(s) and "XXXXsecretXXXX" not in str(s.model_dump())
    assert s.notify_format == "slack"


def test_settings_reject_http_without_echoing(monkeypatch):
    bad = "http://hooks.example.com/services/leakme"
    with pytest.raises(ValidationError) as info:
        _settings(monkeypatch, WARREN_NOTIFY_WEBHOOK_URL=bad)
    assert "leakme" not in str(info.value)
    assert "WARREN_NOTIFY_WEBHOOK_URL" in str(info.value)


def test_settings_reject_unknown_format(monkeypatch):
    with pytest.raises(ValidationError):
        _settings(monkeypatch, WARREN_NOTIFY_FORMAT="xml")


def test_settings_empty_url_is_unset(monkeypatch):
    assert _settings(monkeypatch, WARREN_NOTIFY_WEBHOOK_URL="").notify_webhook_url is None


def test_build_notifier_server_target(monkeypatch):
    s = _settings(monkeypatch, WARREN_NOTIFY_WEBHOOK_URL=SECRET, WARREN_NOTIFY_EVENTS="agent.failed,agent.waiting")
    n = build_notifier(s, secrets=None)
    assert n.server_target is not None and n.server_target.kind == "server"
    assert n.server_target.events == {"agent.failed", "agent.waiting"}
    assert not n.server_target.require_public


def test_parse_events():
    assert parse_events(None) == parse_events("") == parse_events([])
    assert parse_events(" agent.waiting , workspace.idle_stopped") == {"agent.waiting", "workspace.idle_stopped"}
    with pytest.raises(ValueError):
        parse_events(["agent.waiting", "nope"])


async def test_is_public_destination():
    async def public(host, port):
        return ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]

    async def mixed(host, port):
        return ["93.184.216.34", "10.1.2.3"]

    async def fails(host, port):
        raise OSError("nxdomain")

    assert await is_public_destination("https://hooks.example.com/x", public)
    assert not await is_public_destination("https://hooks.example.com/x", mixed)
    assert not await is_public_destination("https://hooks.example.com/x", fails)
    assert not await is_public_destination("https://localhost/x", public)
    assert not await is_public_destination("https://127.0.0.1/x", public)
    assert not await is_public_destination("https://169.254.169.254/latest", public)
    assert await is_public_destination("https://8.8.8.8/x", fails)
