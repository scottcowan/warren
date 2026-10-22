"""warren_cli.client — AWS identity header attach (best-effort, no-op without boto3),
and the Bearer-token header a RemoteProfile with auth_token set carries."""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest
import respx
import httpx

from warren_cli.client import _aws_identity_headers, make_remote_client
from warren_cli.config import RemoteProfile


def test_no_op_when_boto3_not_installed():
    with patch.dict(sys.modules, {"boto3": None}):
        assert _aws_identity_headers() == {}


def test_no_op_when_session_raises():
    fake_boto3 = MagicMock()
    fake_boto3.Session.side_effect = RuntimeError("no credentials configured")
    with patch.dict(sys.modules, {"boto3": fake_boto3}):
        assert _aws_identity_headers() == {}


def test_no_op_when_no_credentials_configured():
    fake_session = MagicMock()
    fake_session.get_credentials.return_value = None
    fake_boto3 = MagicMock()
    fake_boto3.Session.return_value = fake_session
    with patch.dict(sys.modules, {"boto3": fake_boto3}):
        assert _aws_identity_headers("https://warren.example.com") == {}


def test_attaches_signed_request_with_audience_when_available():
    import json

    from botocore.credentials import Credentials

    fake_session = MagicMock()
    fake_session.get_credentials.return_value = Credentials("AKIAFAKE", "secretfake")
    fake_session.region_name = "us-east-1"
    fake_boto3 = MagicMock()
    fake_boto3.Session.return_value = fake_session

    with patch.dict(sys.modules, {"boto3": fake_boto3}):
        headers = _aws_identity_headers("https://warren.example.com")

    assert set(headers) == {"X-AWS-STS-Signed-Request"}
    payload = json.loads(headers["X-AWS-STS-Signed-Request"])
    assert payload["url"] == "https://sts.us-east-1.amazonaws.com/"
    assert payload["headers"]["Authorization"].startswith("AWS4-HMAC-SHA256")
    assert "/sts/aws4_request" in payload["headers"]["Authorization"]
    assert payload["headers"]["X-Warren-Audience"] == "https://warren.example.com"
    assert payload["body"] == "Action=GetCallerIdentity&Version=2011-06-15"


@pytest.mark.asyncio
@respx.mock
async def test_make_remote_client_sends_bearer_when_token_set():
    profile = RemoteProfile(url="http://test.local", auth_token="tok-xyz")
    route = respx.get("http://test.local/healthz").mock(return_value=httpx.Response(200))
    async with make_remote_client(profile) as client:
        await client.get("/healthz")
    assert route.calls.last.request.headers["Authorization"] == "Bearer tok-xyz"


@pytest.mark.asyncio
@respx.mock
async def test_make_remote_client_omits_bearer_when_no_token():
    profile = RemoteProfile(url="http://test.local")
    route = respx.get("http://test.local/healthz").mock(return_value=httpx.Response(200))
    async with make_remote_client(profile) as client:
        await client.get("/healthz")
    assert "Authorization" not in route.calls.last.request.headers


@pytest.mark.asyncio
@respx.mock
async def test_make_remote_client_ssh_tunnel_signs_configured_aws_audience():
    """Regression: the ssh/ecs tunnel branches used to call _aws_identity_headers()
    with NO argument at all, signing an empty X-Warren-Audience -- which the server
    rejects outright (an empty audience never matches). RemoteProfile.aws_audience
    must reach the signed request actually sent over the tunnel."""
    import json

    from botocore.credentials import Credentials

    profile = RemoteProfile(
        runtime_type="ssh", ssh_host="node2", ssh_key_path="~/.ssh/id_homelab", aws_audience="node2"
    )
    fake_proc = MagicMock()
    fake_session = MagicMock()
    fake_session.get_credentials.return_value = Credentials("AKIAFAKE", "secretfake")
    fake_session.region_name = "us-east-1"
    fake_boto3 = MagicMock()
    fake_boto3.Session.return_value = fake_session

    route = respx.get("http://127.0.0.1:54321/healthz").mock(return_value=httpx.Response(200))

    with (
        patch("warren_cli.dispatch.start_ssh_port_forward", return_value=(fake_proc, 54321)),
        patch.dict(sys.modules, {"boto3": fake_boto3}),
    ):
        async with make_remote_client(profile) as client:
            await client.get("/healthz")

    sent = route.calls.last.request.headers["X-AWS-STS-Signed-Request"]
    payload = json.loads(sent)
    assert payload["headers"]["X-Warren-Audience"] == "node2"


@pytest.mark.asyncio
async def test_make_remote_client_ssh_tunnels_via_dispatch_and_tears_down():
    """runtime_type='ssh' must establish the SSH tunnel (dispatch.start_ssh_port_forward)
    before connecting, point the client at the resulting local port, and terminate the
    tunnel process on exit -- same contract as the ECS branch's SSM tunnel."""
    profile = RemoteProfile(runtime_type="ssh", ssh_host="node2", ssh_key_path="~/.ssh/id_homelab")
    fake_proc = MagicMock()

    with patch(
        "warren_cli.dispatch.start_ssh_port_forward", return_value=(fake_proc, 54321)
    ) as start_mock:
        async with make_remote_client(profile) as client:
            assert str(client.base_url).rstrip("/") == "http://127.0.0.1:54321"

    start_mock.assert_called_once_with("node2", 8420, ssh_key_path="~/.ssh/id_homelab")
    fake_proc.terminate.assert_called_once()
