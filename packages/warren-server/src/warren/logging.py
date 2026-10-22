"""structlog configuration with secret-redacting processor.

The redactor walks the event dict recursively and replaces any value whose
key matches `*_TOKEN`, `*_KEY`, `*_SECRET`, a bare `token` key, or the
server's secret-key field name (case-insensitive) with the literal string
`[REDACTED]`.
"""

from __future__ import annotations

import logging
import re
from typing import Any

import structlog

_REDACT_KEY_RE = re.compile(
    r"(.*_TOKEN$|.*_KEY$|.*_SECRET$|^AUTH_TOKEN$|^SECRET_KEY$|^TOKEN$)",
    re.IGNORECASE,
)
_REDACTED = "[REDACTED]"


def _should_redact(key: Any) -> bool:
    if not isinstance(key, str):
        return False
    return bool(_REDACT_KEY_RE.match(key))


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: (_REDACTED if _should_redact(k) else _redact_value(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, tuple):
        return tuple(_redact_value(item) for item in value)
    return value


def redact_secrets(logger, method_name, event_dict):
    """structlog processor — redact values under secret-like keys, recursively."""
    return {
        key: (_REDACTED if _should_redact(key) else _redact_value(value))
        for key, value in event_dict.items()
    }


def configure_logging(level: int = logging.INFO) -> None:
    """Install the structlog processor chain with `redact_secrets` first.

    Routes structlog through the stdlib logging system so caplog / pytest
    see the rendered records.
    """
    root = logging.getLogger()
    root.setLevel(level)
    if not any(isinstance(h, logging.StreamHandler) for h in root.handlers):
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(message)s"))
        root.addHandler(handler)
    structlog.configure(
        processors=[
            redact_secrets,
            structlog.stdlib.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.KeyValueRenderer(key_order=["event", "level"]),
        ],
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=structlog.stdlib.LoggerFactory(),
        cache_logger_on_first_use=True,
    )
