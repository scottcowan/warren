from __future__ import annotations

from unittest.mock import patch

import pytest

from warren_mcp.cli_bridge import WarrenCLINotFound, WarrenCLITimeout, run_warren


def test_run_warren_raises_when_binary_not_found():
    with patch("warren_mcp.cli_bridge.shutil.which", return_value=None):
        with pytest.raises(WarrenCLINotFound):
            run_warren(["doctor"])


def test_run_warren_captures_real_doctor_output():
    """doctor always exits 0 and prints something — a safe real smoke test
    that needs no server, no config, and no confirmation prompt."""
    result = run_warren(["doctor"])
    assert result.returncode == 0
    assert "Runtimes:" in result.stdout


def test_json_or_raise_parses_valid_json():
    from warren_mcp.cli_bridge import CLIResult

    result = CLIResult(returncode=0, stdout='{"a": 1}', stderr="")
    assert result.json_or_raise() == {"a": 1}


def test_json_or_raise_raises_on_nonzero_exit():
    from warren_mcp.cli_bridge import CLIResult

    result = CLIResult(returncode=1, stdout="", stderr="boom")
    with pytest.raises(RuntimeError, match="boom"):
        result.json_or_raise()


def test_default_timeout_exceeds_warren_new_s_120s_provision_window():
    """Regression guard for audit 2026-10-16 #29: the floor timeout must
    safely exceed `warren new`'s own known-longest operation (120s, see
    main.py's _provision_and_poll), or a real successful provision gets
    killed here while it's still running."""
    from warren_mcp.cli_bridge import _DEFAULT_TIMEOUT

    assert _DEFAULT_TIMEOUT > 120.0


def test_timeout_expired_raises_warren_cli_timeout_not_raw_exception():
    import subprocess

    with patch("warren_mcp.cli_bridge.subprocess.run") as mock_run:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["warren", "new"], timeout=150.0)
        with pytest.raises(WarrenCLITimeout, match="150.0s"):
            run_warren(["new", "myproject"], timeout=150.0)


def test_never_blocks_on_a_prompt():
    """Regression guard: stdin must always be DEVNULL so an accidentally
    interactive subcommand fails fast instead of hanging an MCP tool call
    forever waiting for input nobody can give it."""
    import subprocess

    with patch("warren_mcp.cli_bridge.subprocess.run") as mock_run:
        mock_run.return_value = subprocess.CompletedProcess(
            args=[], returncode=0, stdout="", stderr=""
        )
        run_warren(["list"])
        assert mock_run.call_args.kwargs["stdin"] == subprocess.DEVNULL
