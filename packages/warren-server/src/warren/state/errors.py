"""Errors shared by the state backends."""

from __future__ import annotations

from warren.errors import PreflightError


class StateConflict(Exception):
    """A uniqueness constraint refused a write: a duplicate username, token hash or id,
    or a row that references a missing user. The SQLite stores raise
    `sqlite3.IntegrityError` for the same cases."""


class StateBackendError(PreflightError):
    """The configured state or secrets backend is unusable (startup preflight)."""
