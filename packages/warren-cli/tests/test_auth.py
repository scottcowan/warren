"""warren CLI bearer-token auth — httpx client + typer commands carry Authorization."""

from __future__ import annotations

from pathlib import Path

import httpx
import pytest
import respx
from typer.testing import CliRunner

from warren_cli.client import make_client
from warren_cli.config import ServerProfile, WarrenCLIConfig
from warren_cli.main import app


@pytest.fixture
def cfg_file(tmp_path: Path) -> Path:
    path = tmp_path / "config.toml"
    path.write_text(
        """
[remotes.node2]
url = "http://test.local"
auth_token = "tok-xyz"
"""
    )
    return path


def test_make_client_carries_bearer_header():
    profile = ServerProfile(url="http://test.local", auth_token="tok-xyz")
    client = make_client(profile)
    try:
        assert client.headers["Authorization"] == "Bearer tok-xyz"
        assert str(client.base_url).rstrip("/") == "http://test.local"
    finally:
        # Nothing to close synchronously; httpx.AsyncClient uses aclose()
        pass


@respx.mock
def test_healthz_sends_bearer_and_prints_body(cfg_file: Path):
    """`healthz`, not `connect` — `connect` is the top-level shortcut for
    `workspaces connect` (a local workspace attach), a different command that
    happens to share the name. This health-check command used to be
    registered as `connect` too, which meant `app.command("connect")
    (workspaces_connect)` (registered later) silently won and made it
    unreachable."""
    route = respx.get("http://test.local/healthz").mock(
        return_value=httpx.Response(200, json={"status": "ok"})
    )
    runner = CliRunner()
    result = runner.invoke(app, ["healthz", "--server", "node2", "--config", str(cfg_file)])
    assert result.exit_code == 0, result.output
    assert route.called
    sent_auth = route.calls.last.request.headers["Authorization"]
    assert sent_auth == "Bearer tok-xyz"
    # token must never appear in stdout
    assert "tok-xyz" not in result.output


@respx.mock
def test_healthz_401_exits_nonzero_without_leaking_token(cfg_file: Path):
    respx.get("http://test.local/healthz").mock(
        return_value=httpx.Response(401, json={"detail": "nope"})
    )
    runner = CliRunner()
    result = runner.invoke(app, ["healthz", "--server", "node2", "--config", str(cfg_file)])
    assert result.exit_code == 1
    combined = result.output + (result.stderr if result.stderr_bytes is not None else "")
    assert "authentication failed" in combined.lower()
    assert "tok-xyz" not in combined


# NOTE: there used to be a test_workspaces_list_sends_bearer here, asserting that
# `workspaces list` sends a bearer token from [servers.*] to GET /workspaces. That was true
# under an older implementation; `workspaces list`'s remote fan-out was since rebuilt around
# the no-auth [remotes.*] peer-discovery model (RemoteProfile — bearer-token auth for *that*
# path is an explicit future-phase concern, D-04), which reads cfg.remotes, not cfg.servers.
# A [servers.*]-only config (this file's cfg_file fixture) now has no remotes configured, so
# `workspaces list` only ever prints the local workspace table and never makes an HTTP
# request at all — the old test was asserting behavior the command no longer has by design,
# not a regression.
