"""`_warren_alias_command` repo-root fallback (audit 2026-10-16 #35):
`warren new`'s nsjail zshrc aliases `warren` to a `uv run --package warren
--directory <repo>` invocation that assumes a real repo checkout exists 5
levels above dispatch.py. Once warren-cli is installed as a wheel, there is
no repo at all there, and that command would just fail -- this must
degrade to the already-resolved installed binary instead of crashing or
producing a silently-broken alias.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from warren_cli.dispatch import _warren_alias_command


def test_uses_uv_run_when_repo_checkout_present():
    # The real dev environment running these tests IS a repo checkout.
    cmd = _warren_alias_command()
    assert cmd.startswith("uv run --package warren --directory ")
    assert cmd.endswith(' -- warren')


def test_falls_back_to_installed_binary_when_no_repo_present(tmp_path: Path):
    """Simulate a wheel install: no pyproject.toml exists 5 levels up."""
    fake_dispatch_path = tmp_path / "site-packages" / "warren_cli" / "dispatch.py"
    fake_dispatch_path.parent.mkdir(parents=True)
    fake_dispatch_path.touch()

    with patch("warren_cli.dispatch.__file__", str(fake_dispatch_path)):
        with patch("warren_cli.dispatch.shutil.which", return_value="/usr/local/bin/warren"):
            cmd = _warren_alias_command()

    assert cmd == "/usr/local/bin/warren"


def test_falls_back_to_bare_name_when_binary_not_on_path(tmp_path: Path):
    fake_dispatch_path = tmp_path / "site-packages" / "warren_cli" / "dispatch.py"
    fake_dispatch_path.parent.mkdir(parents=True)
    fake_dispatch_path.touch()

    with patch("warren_cli.dispatch.__file__", str(fake_dispatch_path)):
        with patch("warren_cli.dispatch.shutil.which", return_value=None):
            cmd = _warren_alias_command()

    assert cmd == "warren"
