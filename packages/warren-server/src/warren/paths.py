"""Filesystem path helpers derived from WarrenSettings."""

from __future__ import annotations

from pathlib import Path

from warren.config import WarrenSettings


def db_path(settings: WarrenSettings) -> Path:
    return settings.data_dir / "warren.db"
