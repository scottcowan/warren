"""Tests for structlog redactor — secrets under *_TOKEN|*_KEY|*_SECRET must be masked."""

from __future__ import annotations

import io
import logging

import pytest
import structlog

from warren.logging import configure_logging, redact_secrets


def test_redact_secrets_top_level_key():
    event = {"event": "login", "warren_auth_token": "abcd1234"}
    out = redact_secrets(None, "info", dict(event))
    assert out["warren_auth_token"] == "[REDACTED]"
    assert "abcd1234" not in str(out)


def test_redact_secrets_case_insensitive_and_variants():
    event = {
        "AUTH_TOKEN": "t1",
        "Secret_Key": "sk",
        "api_secret": "s1",
        "user": "alice",
    }
    out = redact_secrets(None, "info", dict(event))
    assert out["AUTH_TOKEN"] == "[REDACTED]"
    assert out["Secret_Key"] == "[REDACTED]"
    assert out["api_secret"] == "[REDACTED]"
    assert out["user"] == "alice"


def test_redact_secrets_nested_dict():
    event = {
        "event": "startup",
        "config": {"warren_secret_key": "topsecret", "port": 8420},
    }
    out = redact_secrets(None, "info", dict(event))
    assert out["config"]["warren_secret_key"] == "[REDACTED]"
    assert out["config"]["port"] == 8420
    assert "topsecret" not in str(out)


def test_configure_logging_renders_redacted_line(caplog):
    configure_logging()
    log = structlog.get_logger("test")
    with caplog.at_level(logging.INFO):
        log.info("auth_check", warren_auth_token="abc-super-secret")
    rendered = " ".join(r.getMessage() for r in caplog.records)
    assert "[REDACTED]" in rendered
    assert "abc-super-secret" not in rendered


def test_redact_secrets_bootstrap_token_key():
    event = {"bootstrap_token": "s"}
    out = redact_secrets(None, "info", dict(event))
    assert out["bootstrap_token"] == "[REDACTED]"


def test_redact_secrets_hashed_token_key():
    event = {"hashed_token": "s"}
    out = redact_secrets(None, "info", dict(event))
    assert out["hashed_token"] == "[REDACTED]"


def test_redact_secrets_bare_token_key():
    event = {"token": "s"}
    out = redact_secrets(None, "info", dict(event))
    assert out["token"] == "[REDACTED]"


def test_redact_secrets_user_id_left_unchanged():
    event = {"user_id": "u"}
    out = redact_secrets(None, "info", dict(event))
    assert out["user_id"] == "u"
