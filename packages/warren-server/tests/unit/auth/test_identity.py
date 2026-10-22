"""warren.auth.identity — pluggable, discoverable owner-identity resolution."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import patch

import pytest
from fastapi import HTTPException

from warren.auth import identity as identity_module
from warren.auth.identity import (
    list_identity_resolvers,
    register_identity_resolver,
    resolve_owner_id,
)


def _fake_request(runtime_type: str, headers: dict[str, str] | None = None):
    settings = SimpleNamespace(
        runtime_type=runtime_type, server_id="test-server", aws_trusted_assumed_role_patterns=[]
    )
    app = SimpleNamespace(state=SimpleNamespace(settings=settings))
    return SimpleNamespace(
        app=app, headers=headers or {}, state=SimpleNamespace(), base_url="https://warren.example.com/"
    )


def test_builtins_are_registered():
    resolvers = list_identity_resolvers()
    assert set(resolvers) >= {"podman", "docker", "ecs"}


def test_list_identity_resolvers_returns_a_copy():
    resolvers = list_identity_resolvers()
    resolvers["bogus"] = object()  # type: ignore[assignment]
    assert "bogus" not in list_identity_resolvers()


async def test_unregistered_runtime_type_falls_back_to_warren_user():
    with patch("warren.auth.deps.current_user", return_value=SimpleNamespace(user_id="u-1")):
        owner_id = await resolve_owner_id(_fake_request("some-future-cloud"))
    assert owner_id == "u-1"


async def test_podman_resolves_via_warren_user():
    with patch("warren.auth.deps.current_user", return_value=SimpleNamespace(user_id="u-1")):
        owner_id = await resolve_owner_id(_fake_request("podman"))
    assert owner_id == "u-1"


async def test_ecs_without_header_raises_401():
    with pytest.raises(HTTPException) as exc_info:
        await resolve_owner_id(_fake_request("ecs"))
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail["error"] == "aws_identity_required"


async def test_ecs_resolves_via_verified_aws_identity():
    with patch(
        "warren.auth.aws_identity.verify_signed_caller_identity",
        return_value="deadbeef" * 4,
    ) as mock_verify:
        owner_id = await resolve_owner_id(
            _fake_request("ecs", headers={"X-AWS-STS-Signed-Request": '{"url": "https://sts.amazonaws.com/"}'})
        )
    assert owner_id == "deadbeef" * 4
    mock_verify.assert_called_once()
    assert mock_verify.call_args.args[0] == '{"url": "https://sts.amazonaws.com/"}'
    # Audience is the server's own stable server_id, not request.base_url --
    # base_url is meaningless behind an ecs/ssh tunnel (ephemeral local port).
    assert mock_verify.call_args.args[1] == "test-server"
    assert mock_verify.call_args.args[2] == []


async def test_a_new_backend_can_register_its_own_resolver_without_editing_this_module():
    async def _custom_resolver(request) -> str:
        return "custom-identity-value"

    register_identity_resolver("my-custom-runtime", _custom_resolver)
    try:
        owner_id = await resolve_owner_id(_fake_request("my-custom-runtime"))
        assert owner_id == "custom-identity-value"
        assert "my-custom-runtime" in list_identity_resolvers()
    finally:
        # Don't leak this test's registration into other tests in the session.
        del identity_module._RESOLVERS["my-custom-runtime"]


async def test_re_registering_a_runtime_type_replaces_it_silently():
    async def _resolver_a(request) -> str:
        return "a"

    async def _resolver_b(request) -> str:
        return "b"

    register_identity_resolver("replaceable", _resolver_a)
    register_identity_resolver("replaceable", _resolver_b)
    try:
        owner_id = await resolve_owner_id(_fake_request("replaceable"))
        assert owner_id == "b"
    finally:
        del identity_module._RESOLVERS["replaceable"]
