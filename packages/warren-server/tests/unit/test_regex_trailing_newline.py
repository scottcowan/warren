"""`$` matches before a trailing newline; name and id validators must reject "x\\n"."""

from __future__ import annotations

import pytest
from warren.routes import secrets as secrets_route
from warren.runtime import ecs_kms_secrets as k
from warren.runtime import ecs_secrets, efs


@pytest.mark.parametrize("bad", ["FOO\n", "x\n", "ws-1\n", "ws-1\n\n"])
def test_name_and_id_patterns_reject_trailing_newline(bad):
    assert not k._WORKSPACE_ID_RE.fullmatch(bad)
    assert not k._ENV_NAME_RE.fullmatch(bad)
    assert not secrets_route._SAFE_NAME_RE.fullmatch(bad)
    assert not ecs_secrets._ENV_NAME.fullmatch(bad)
    assert not ecs_secrets._WORKSPACE_ID.fullmatch(bad)
    assert not efs._WORKSPACE_ID_RE.fullmatch(bad)


def test_kms_check_and_seal_reject_newline_inputs():
    from warren_common.errors import ProvisionError  # noqa: PLC0415

    container = k.CONTAINERS[0]
    with pytest.raises(ProvisionError):
        k._check("ws-1\n", container, "us-east-1")
    with pytest.raises(ValueError):
        k.seal(b"k" * 32, b"w", {"FOO\n": "v"}, workspace_id="ws-1", container=container, region="us-east-1")


def test_valid_values_still_pass():
    assert k._WORKSPACE_ID_RE.fullmatch("ws-1")
    assert k._ENV_NAME_RE.fullmatch("FOO")
    assert secrets_route._SAFE_NAME_RE.fullmatch("a/b.c-d_e")


def test_common_validators_reject_newline():
    from warren_common import models  # noqa: PLC0415
    from warren_common.paths import validate_workspace_id  # noqa: PLC0415

    assert not models._ENV_NAME_RE.fullmatch("FOO\n")
    with pytest.raises(Exception):  # noqa: B017, PT011
        validate_workspace_id("ws-1\n")
