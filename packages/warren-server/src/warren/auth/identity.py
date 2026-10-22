"""Pluggable, discoverable owner-identity resolution for warren.secrets.

warren.secrets isolates by `owner_id`, but what "owner" even means differs by
how a workspace is actually provisioned — warren's own bearer-token user_id
for podman/docker, the caller's verified AWS IAM identity for ecs
(warren.auth.aws_identity). This module is the seam between the two: a new
backend (a different cloud, a different internal auth scheme) registers its
own resolver by `settings.runtime_type` instead of extending an if/elif chain
here or at each call site.

    from warren.auth.identity import register_identity_resolver

    async def _my_resolver(request: Request) -> str:
        ...

    register_identity_resolver("my-runtime", _my_resolver)

Re-registering an already-registered runtime_type replaces it silently —
useful for tests, and for a deployment that wants to swap out a builtin
resolver (e.g. a different AWS identity scheme) without forking this module.

`list_identity_resolvers()` makes the current registration discoverable --
e.g. for a `warren doctor`-style diagnostic -- without reading this module's
source to know what's wired up.
"""

from __future__ import annotations

from typing import Awaitable, Callable

from fastapi import HTTPException, Request

IdentityResolver = Callable[[Request], Awaitable[str]]

_RESOLVERS: dict[str, IdentityResolver] = {}


def register_identity_resolver(runtime_type: str, resolver: IdentityResolver) -> None:
    """Register how to resolve warren.secrets' owner_id for `runtime_type`."""
    _RESOLVERS[runtime_type] = resolver


def list_identity_resolvers() -> dict[str, IdentityResolver]:
    """Return the current runtime_type -> resolver registry (a copy)."""
    return dict(_RESOLVERS)


async def _warren_user_resolver(request: Request) -> str:
    """Default resolver: warren's own bearer-token user_id (D-06), same identity
    every other ownership check in this codebase already uses (workspace
    owner_id, project user-scoping)."""
    from warren.auth.deps import current_user

    return current_user(request).user_id


async def _aws_identity_resolver(request: Request) -> str:
    """ECS resolver: the caller's verified AWS IAM identity, not warren's own
    user_id — see warren.auth.aws_identity's module docstring for why and
    how. warren-server's own bearer-token auth still gates the request
    itself (D-06); this only changes what secrets that request can see, so
    it lines up with who can actually `ecs:ExecuteCommand`/SSM-tunnel into
    the resulting task, which is an IAM boundary, not a warren one."""
    from warren.auth.aws_identity import AwsIdentityError, verify_signed_caller_identity

    signed_request = request.headers.get("X-AWS-STS-Signed-Request")
    if not signed_request:
        raise HTTPException(
            status_code=401,
            detail={
                "error": "aws_identity_required",
                "detail": "ECS deployments require an X-AWS-STS-Signed-Request header to resolve secret ownership",
            },
        )
    settings = request.app.state.settings
    try:
        return await verify_signed_caller_identity(
            signed_request,
            settings.server_id,
            settings.aws_trusted_assumed_role_patterns,
        )
    except AwsIdentityError as exc:
        raise HTTPException(
            status_code=401,
            detail={"error": "aws_identity_invalid", "detail": str(exc)},
        ) from exc


register_identity_resolver("podman", _warren_user_resolver)
register_identity_resolver("docker", _warren_user_resolver)
register_identity_resolver("ecs", _aws_identity_resolver)


async def resolve_owner_id(request: Request) -> str:
    """Return the owner_id warren.secrets isolates by for this request --
    dispatches to whichever resolver is registered for
    `settings.runtime_type`, falling back to the warren-user resolver (the
    safe default: today's podman/docker behavior) for an
    unregistered/unknown runtime_type."""
    settings = getattr(request.app.state, "settings", None)
    runtime_type = getattr(settings, "runtime_type", "podman")
    resolver = _RESOLVERS.get(runtime_type, _warren_user_resolver)
    return await resolver(request)
