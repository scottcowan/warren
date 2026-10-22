"""warren_cli.ui — the shared console/table/glyph/picker/relative-time module
every command routes through, so output is consistent regardless of which
module a command lives in."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock

import pytest
import typer

from warren_cli import ui


def test_relative_time_seconds_minutes_hours_days():
    now = datetime.now(timezone.utc)
    assert ui.relative_time(now - timedelta(seconds=5)).endswith("s ago")
    assert ui.relative_time(now - timedelta(minutes=5)).endswith("m ago")
    assert ui.relative_time(now - timedelta(hours=5)).endswith("h ago")
    assert ui.relative_time(now - timedelta(days=5)).endswith("d ago")


def test_relative_time_accepts_iso_string_with_trailing_z():
    now = datetime.now(timezone.utc)
    ts = (now - timedelta(minutes=2)).strftime("%Y-%m-%dT%H:%M:%SZ")
    assert ui.relative_time(ts).endswith("m ago")


def test_relative_time_future_and_unparseable():
    future = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    assert ui.relative_time(future) == "future"
    assert ui.relative_time("not-a-date") == "unknown"
    assert ui.relative_time(None) == "unknown"
    assert ui.relative_time("") == "unknown"


def test_print_table_renders_headers_and_rows(capsys):
    ui.print_table(["NAME", "STATUS"], [["demo", "running"], ["other", "stopped"]])
    out = capsys.readouterr().out
    assert "NAME" in out and "STATUS" in out
    assert "demo" in out and "running" in out
    assert "other" in out and "stopped" in out


def test_ok_warn_error_use_one_consistent_glyph_set(capsys):
    ui.ok("all good")
    ui.warn("careful")
    ui.error("broken")
    captured = capsys.readouterr()
    assert f"{ui.OK} all good" in captured.out
    assert ui.WARN in captured.err and "careful" in captured.err
    assert f"{ui.FAIL} broken" in captured.err


def test_no_color_env_honored(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert ui._no_color() is True
    monkeypatch.delenv("NO_COLOR", raising=False)
    assert ui._no_color() is False


def test_arrow_select_raises_on_empty_choices():
    with pytest.raises(ValueError):
        ui.arrow_select("pick:", [], non_tty_hint="pass --x")


def test_arrow_select_non_tty_fails_with_hint_instead_of_auto_picking(monkeypatch, capsys):
    monkeypatch.setattr(ui, "is_interactive", lambda: False)

    with pytest.raises(typer.Exit):
        ui.arrow_select("pick one:", [("first", "a"), ("second", "b")], non_tty_hint="pass --server")

    err = capsys.readouterr().err
    assert "pass --server" in err


def test_arrow_select_tty_shows_menu_even_for_a_single_choice(monkeypatch):
    monkeypatch.setattr(ui, "is_interactive", lambda: True)

    fake_select = MagicMock()
    fake_select.ask.return_value = "the-value"
    questionary_module = MagicMock()
    questionary_module.select.return_value = fake_select
    questionary_module.Choice = lambda title, value: {"title": title, "value": value}
    monkeypatch.setitem(__import__("sys").modules, "questionary", questionary_module)

    result = ui.arrow_select("pick one:", [("only option", "the-value")], non_tty_hint="pass --x")

    assert result == "the-value"
    questionary_module.select.assert_called_once()


def test_arrow_select_tty_ctrl_c_or_esc_exits_nonzero(monkeypatch):
    monkeypatch.setattr(ui, "is_interactive", lambda: True)

    fake_select = MagicMock()
    fake_select.ask.return_value = None
    questionary_module = MagicMock()
    questionary_module.select.return_value = fake_select
    questionary_module.Choice = lambda title, value: {"title": title, "value": value}
    monkeypatch.setitem(__import__("sys").modules, "questionary", questionary_module)

    with pytest.raises(typer.Exit):
        ui.arrow_select("pick one:", [("only option", "the-value")], non_tty_hint="pass --x")
