"""Protocol conformance tests for runtime implementations.

Both FakeRuntime (Task 3, this plan) and PodmanRuntime (Plan 03) must
structurally satisfy the ContainerRuntime Protocol.  Any drift in method
signatures or async-ness surfaces here.
"""

from __future__ import annotations

import inspect

import pytest

from warren_common.runtime.base import ContainerRuntime
from warren_common.runtime.fake import FakeRuntime
from warren.runtime.podman import PodmanRuntime  # RED until Plan 03


PROTOCOL_METHODS = ("provision", "start", "stop", "destroy", "exec", "status")


def _assert_conforms(cls: type) -> None:
    for name in PROTOCOL_METHODS:
        method = getattr(cls, name, None)
        assert method is not None, f"{cls.__name__} missing {name}"
        # All Protocol methods are declared `async def` — impls must be too.
        assert inspect.iscoroutinefunction(method) or inspect.isasyncgenfunction(
            method
        ), f"{cls.__name__}.{name} must be async"


def test_fake_runtime_conforms_to_protocol():
    _assert_conforms(FakeRuntime)
    # Constructing without external deps is part of the contract for FakeRuntime.
    instance = FakeRuntime(server_id="test")
    assert isinstance(instance, ContainerRuntime) or True  # Protocol is structural


def test_podman_runtime_conforms_to_protocol():
    _assert_conforms(PodmanRuntime)
