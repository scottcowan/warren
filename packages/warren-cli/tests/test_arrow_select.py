"""`_arrow_select` — now a thin re-export of `warren_cli.ui.arrow_select`, the
shared arrow-key interactive selector behind every picker in warren (remote,
workspace, project, template) -- promoted from `main.py` into `ui.py` so it's
the ONE picker implementation.

Real bug this replaces: `warren connect` with exactly one remote and one
active workspace configured silently auto-picked both and attached with zero
confirmation of what it connected to. The fix always shows the selector --
even for a single choice -- but in non-interactive contexts (tests, scripts,
piped input) it now fails with a clear message naming how to pass the choice
explicitly, rather than silently auto-picking the first option (see ui.py's
own test suite, test_ui.py, for that non-TTY-failure behavior in detail).
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from warren_cli.main import _arrow_select


def test_tty_shows_menu_even_for_a_single_choice(monkeypatch):
    """The actual fix: a single choice must still go through the interactive
    selector when stdin IS a real terminal, not auto-pick silently."""
    monkeypatch.setattr("warren_cli.ui.is_interactive", lambda: True)

    fake_select = MagicMock()
    fake_select.ask.return_value = "the-value"
    questionary_module = MagicMock()
    questionary_module.select.return_value = fake_select
    questionary_module.Choice = lambda title, value: {"title": title, "value": value}
    monkeypatch.setitem(__import__("sys").modules, "questionary", questionary_module)

    result = _arrow_select("pick one:", [("only option", "the-value")], non_tty_hint="pass --x")

    assert result == "the-value"
    questionary_module.select.assert_called_once()
    call_args = questionary_module.select.call_args
    assert call_args.args[0] == "pick one:"
    assert call_args.kwargs["choices"] == [{"title": "only option", "value": "the-value"}]


def test_tty_ctrl_c_or_esc_exits_nonzero(monkeypatch):
    """questionary returns None on Ctrl-C/Esc rather than raising -- must map
    to a clean non-zero exit, not a crash or a silent wrong pick."""
    import typer

    monkeypatch.setattr("warren_cli.ui.is_interactive", lambda: True)

    fake_select = MagicMock()
    fake_select.ask.return_value = None
    questionary_module = MagicMock()
    questionary_module.select.return_value = fake_select
    questionary_module.Choice = lambda title, value: {"title": title, "value": value}
    monkeypatch.setitem(__import__("sys").modules, "questionary", questionary_module)

    with pytest.raises(typer.Exit):
        _arrow_select("pick one:", [("only option", "the-value")], non_tty_hint="pass --x")


def test_non_tty_fails_with_hint_instead_of_auto_picking(monkeypatch):
    import typer

    monkeypatch.setattr("warren_cli.ui.is_interactive", lambda: False)

    with pytest.raises(typer.Exit):
        _arrow_select("pick one:", [("first", "a"), ("second", "b")], non_tty_hint="pass --server")


def test_raises_on_empty_choices():
    with pytest.raises(ValueError):
        _arrow_select("pick one:", [], non_tty_hint="pass --x")
