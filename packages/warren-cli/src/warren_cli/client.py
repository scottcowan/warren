"""httpx client factory for warren CLI.

One place constructs :class:`httpx.AsyncClient` instances so the ``Authorization: Bearer``
header (D-10) can never be forgotten at a call site.
"""

from __future__ import annotations

import contextlib
import json
from typing import AsyncIterator

import httpx

from .config import RemoteProfile, ServerProfile


DEFAULT_TIMEOUT = 30.0

ORCHESTRATOR_HTTP_PORT = 8420


def _aws_identity_headers(audience: str = "") -> dict[str, str]:
    """Best-effort: a SigV4-signed ``sts:GetCallerIdentity`` POST request so an
    ECS-mode warren-server can verify our AWS identity for warren.secrets
    ownership (warren-server's ``warren/auth/aws_identity.py``), without ever
    seeing our AWS credentials — the server replays this exact request to AWS
    STS itself.

    ``audience`` (the server's own stable identity -- ``profile.aws_audience``
    if the operator set it, else ``str(profile.url)`` for a direct, non-tunneled
    profile where the URL itself is meaningful) is baked into the signature
    itself: it's set on the request's headers BEFORE ``SigV4Auth.add_auth()``
    runs below, so it's part of what gets signed, not attached afterward (an
    unsigned header proves nothing -- the server independently confirms this
    header is in the signature's own ``SignedHeaders=`` list, not just
    present in the header map). A profile reached through an ecs/ssh tunnel
    has no meaningful URL (the local port is an ephemeral implementation
    detail, not the server's identity) and MUST set ``aws_audience``
    explicitly for this to do anything -- see ``RemoteProfile.aws_audience``.

    No-ops (returns ``{}``) whenever boto3 isn't installed (the ``aws`` extra
    isn't a hard dependency — podman-mode servers never read this header) or
    no AWS credentials are configured locally. Signing the request is purely
    local/offline (no network call), so this is cheap to attach to every
    request regardless of whether the target server actually needs it.
    """
    try:
        import boto3  # noqa: PLC0415 — optional [aws] extra, keep import lazy
        from botocore.auth import SigV4Auth  # noqa: PLC0415
        from botocore.awsrequest import AWSRequest  # noqa: PLC0415

        session = boto3.Session()
        credentials = session.get_credentials()
        if credentials is None:
            return {}
        region = session.region_name or "us-east-1"

        request = AWSRequest(
            method="POST",
            url=f"https://sts.{region}.amazonaws.com/",
            data="Action=GetCallerIdentity&Version=2011-06-15",
            headers={
                "Content-Type": "application/x-www-form-urlencoded; charset=utf-8",
                "X-Warren-Audience": audience,
            },
        )
        SigV4Auth(credentials.get_frozen_credentials(), "sts", region).add_auth(request)
        prepared = request.prepare()
        body = prepared.body
        if isinstance(body, bytes):
            body = body.decode()

        signed_request = json.dumps({"url": prepared.url, "headers": dict(prepared.headers), "body": body})
        return {"X-AWS-STS-Signed-Request": signed_request}
    except Exception:
        return {}


def make_client(profile: ServerProfile, *, timeout: float = DEFAULT_TIMEOUT) -> httpx.AsyncClient:
    """Return an httpx.AsyncClient bound to ``profile.url`` with a Bearer header.

    The auth token is read via ``SecretStr.get_secret_value()`` only when the
    header dict is being built, so the plaintext value is never held on the
    :class:`ServerProfile` in a form that survives ``repr()``.
    """

    return httpx.AsyncClient(
        base_url=str(profile.url),
        headers={
            "Authorization": f"Bearer {profile.auth_token.get_secret_value()}",
        },
        timeout=timeout,
    )


def _remote_aws_identity_headers(profile: RemoteProfile) -> dict[str, str]:
    """Only compute the signed AWS identity headers when the profile might actually need
    them: an ECS-mode server (always requires ``aws_audience`` -- see ``RemoteProfile``
    validation) or an ssh/http profile where the operator explicitly set ``aws_audience``
    (the documented rare case of tunnelling into an actual ECS-mode server). A plain
    podman/http or ssh-to-podman profile never needs this and shouldn't have it computed
    and attached to every request it makes.
    """
    if profile.runtime_type == "ecs" or profile.aws_audience:
        return _aws_identity_headers(profile.aws_audience or "")
    return {}


def _remote_auth_headers(profile: RemoteProfile) -> dict[str, str]:
    """``Authorization: Bearer`` header when the profile has a token, else empty.

    ``auth_token`` is optional on RemoteProfile (unlike ServerProfile's required one) so
    no-auth servers keep working; a server with the built-in auth provider enforced will
    401 everything from this client until a token is configured.
    """
    if profile.auth_token is None:
        return {}
    return {"Authorization": f"Bearer {profile.auth_token.get_secret_value()}"}


@contextlib.asynccontextmanager
async def make_remote_client(profile: RemoteProfile, *, timeout: float = 5.0) -> AsyncIterator[httpx.AsyncClient]:
    """Return an httpx.AsyncClient for a RemoteProfile, carrying a Bearer header when configured.

    Default timeout=5.0s for LAN/Tailscale fan-out (Pitfall 5 — never omit timeout).

    ``runtime_type="ecs"`` profiles have no direct network path at all — the control plane is
    never assumed to be reachable at a fixed URL. This transparently establishes an SSM
    port-forward into the orchestrator's own running task first, points the client at the
    resulting local port instead, and tears the tunnel down when the caller's ``async with``
    block exits. ``runtime_type="ssh"`` is the same idea for a podman/docker server whose
    control plane is loopback-only on its own host (this project's own redeploy runbook always
    binds it that way) — a plain ``ssh -L`` tunnel instead of an SSM session. Callers don't need
    to know which case they're in; the ``async with make_remote_client(profile) as c:`` call
    site is identical either way.
    """
    if profile.runtime_type == "ecs":
        from . import dispatch

        assert profile.ecs_cluster and profile.ecs_service  # enforced by RemoteProfile validation
        proc, local_port = dispatch.start_orchestrator_port_forward(
            profile.ecs_cluster, profile.ecs_service, ORCHESTRATOR_HTTP_PORT
        )
        try:
            async with httpx.AsyncClient(
                base_url=f"http://127.0.0.1:{local_port}",
                headers={**_remote_auth_headers(profile), **_remote_aws_identity_headers(profile)},
                timeout=timeout,
            ) as client:
                yield client
        finally:
            proc.terminate()
    elif profile.runtime_type == "ssh":
        from . import dispatch

        assert profile.ssh_host  # enforced by RemoteProfile validation
        proc, local_port = dispatch.start_ssh_port_forward(
            profile.ssh_host, profile.ssh_remote_port, ssh_key_path=profile.ssh_key_path
        )
        try:
            async with httpx.AsyncClient(
                base_url=f"http://127.0.0.1:{local_port}",
                headers={**_remote_auth_headers(profile), **_remote_aws_identity_headers(profile)},
                timeout=timeout,
            ) as client:
                yield client
        finally:
            proc.terminate()
    else:
        async with httpx.AsyncClient(
            base_url=str(profile.url),
            headers={
                **_remote_auth_headers(profile),
                **_remote_aws_identity_headers(profile),
            },
            timeout=timeout,
        ) as client:
            yield client
