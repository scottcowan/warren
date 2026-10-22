"""Shared CLI presentation layer: console output, tables, glyphs, the one
interactive picker, and relative-time formatting.

Before this module, warren-cli had three different hand-rolled table
implementations, two numbered-picker styles alongside one arrow-key picker,
a mix of glyphs and plain words for success/warning/error, and two separate
relative-time helpers (main.py and commands/workspaces.py) that could (and
did) drift out of sync. Everything here is the single source of truth for
"what does warren print when it succeeds / warns / fails / asks you to pick
something", so every command reads the same regardless of which module it
lives in.
"""

from __future__ import annotations

import os
import sys
from datetime import datetime, timezone
from typing import Any, Optional, Sequence

import typer
from rich.console import Console
from rich.table import Table

from . import winconsole

winconsole.enable()

OK = "✓"       # ✓
FAIL = "✗"     # ✗
WARN = "⚠"     # ⚠
MARK = "⬡"     # ⬡ — the warren mark, used by ui.banner()


def _no_color() -> bool:
    """NO_COLOR (https://no-color.org/) is honored explicitly here rather than
    relying only on rich's own incidental isatty/env detection, per the audit —
    any non-empty value disables color, matching the spec."""
    return bool(os.environ.get("NO_COLOR"))


# Dynamic `file=` lookup (rich's default) so these pick up whatever sys.stdout/
# sys.stderr currently are at print time, not whatever they were at import time —
# required for typer.testing.CliRunner, which swaps streams per-invocation.
stdout = Console(no_color=_no_color())
stderr = Console(stderr=True, no_color=_no_color())


def table(headers: Sequence[str], rows: Sequence[Sequence[Any]], *, title: Optional[str] = None) -> Table:
    """Build a rich Table with warren's standard look: bold headers, no
    heavy borders, left-aligned columns. Callers print it themselves (via
    `ui.stdout.print(t)`) so a command can build a table without forcing
    where it's rendered."""
    t = Table(title=title, show_header=True, header_style="bold", box=None, pad_edge=False)
    for h in headers:
        t.add_column(h)
    for row in rows:
        t.add_row(*(str(c) for c in row))
    return t


def print_table(headers: Sequence[str], rows: Sequence[Sequence[Any]], *, title: Optional[str] = None) -> None:
    stdout.print(table(headers, rows, title=title))


def ok(message: str) -> None:
    stdout.print(f"{OK} {message}")


def warn(message: str) -> None:
    stderr.print(f"{WARN}  {message}")


def error(message: str) -> None:
    stderr.print(f"{FAIL} {message}")


def banner(text: str) -> None:
    stdout.print(f"{MARK} {text}")


def relative_time(value: "datetime | str | None") -> str:
    """Render a timestamp (ISO-8601 string or datetime) as "<n><unit> ago".

    Accepts the handful of shapes warren-server and local state.json actually
    produce: a trailing 'Z' instead of a UTC offset, no timezone at all
    (assumed UTC), or an already-aware datetime. Unparseable or missing input
    renders as "unknown" rather than raising — every call site here used to
    its own ad-hoc try/except around this.
    """
    if value is None or value == "":
        return "unknown"
    dt: Optional[datetime]
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).rstrip("Z"))
        except (ValueError, TypeError):
            return "unknown"
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    delta = int((datetime.now(timezone.utc) - dt).total_seconds())
    if delta < 0:
        return "future"
    if delta < 60:
        return f"{delta}s ago"
    if delta < 3600:
        return f"{delta // 60}m ago"
    if delta < 86400:
        return f"{delta // 3600}h ago"
    return f"{delta // 86400}d ago"


def is_interactive() -> bool:
    """Whether stdin is a real terminal -- a thin indirection so tests can
    force the interactive path without fighting `io.TextIOWrapper` (an
    immutable C type; `CliRunner.invoke()` also installs its own stdin
    object for the call, so patching `sys.stdin.isatty` beforehand has no
    effect on what the command actually sees)."""
    return sys.stdin.isatty()


def arrow_select(message: str, choices: list[tuple[str, Any]], *, non_tty_hint: str) -> Any:
    """Arrow-key interactive selector (questionary/prompt_toolkit) — the ONLY
    picker in warren; every numbered `[n]` prompt has been migrated to this.

    Always shows the menu — even for a single choice — so the caller sees
    and explicitly confirms what it's about to act on, rather than an
    auto-picked remote/workspace silently taking effect with zero feedback.

    Fails with a clear, actionable message (naming `non_tty_hint`, e.g.
    "pass --server") when stdin isn't a real terminal (tests, scripts, piped
    input) instead of silently picking the first choice — a silent pick is a
    correctness footgun in a script, not a convenience.
    """
    if not choices:
        raise ValueError("arrow_select called with no choices")
    if not is_interactive():
        error(f"not running in an interactive terminal — {non_tty_hint}")
        raise typer.Exit(1)

    import questionary

    selected = questionary.select(
        message,
        choices=[questionary.Choice(title=label, value=value) for label, value in choices],
    ).ask()
    if selected is None:  # Ctrl-C / Esc
        raise typer.Exit(1)
    return selected
