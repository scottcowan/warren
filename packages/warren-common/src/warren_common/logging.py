"""Structlog redaction processor — scrubs secret-shaped values before rendering."""

from __future__ import annotations

from typing import Any

_SECRET_KEY_SUFFIXES = frozenset({"_TOKEN", "_KEY", "_SECRET", "_PASSWORD"})
_SECRET_KEY_EXACT = frozenset({"TOKEN", "KEY", "SECRET", "PASSWORD"})
_REDACTED = "[REDACTED]"


def _is_secret_key(key: Any) -> bool:
    if not isinstance(key, str):
        return False
    upper = key.upper()
    if upper in _SECRET_KEY_EXACT:
        return True
    return any(upper.endswith(suf) for suf in _SECRET_KEY_SUFFIXES)


def redact_processor(logger, method_name, event_dict):
    """Scrub secret-shaped values from a structlog event dict.

    Must run before any renderer. Redacts values whose key looks like a
    secret name (*_TOKEN, *_KEY, *_SECRET, *_PASSWORD, case-insensitive)
    and redacts every value inside any dict stored under the key ``env``.
    """
    for key in list(event_dict.keys()):
        value = event_dict[key]
        if _is_secret_key(key):
            event_dict[key] = _REDACTED
            continue
        if key == "env" and isinstance(value, dict):
            event_dict[key] = {k: _REDACTED for k in value}
    return event_dict
