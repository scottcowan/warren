"""Server-supplied ECS ids are validated before they reach an argv or an SSM target."""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from warren_cli import dispatch

_ARN = "arn:aws:ecs:eu-west-1:123456789012:task/prod/0123abcd4567"


def test_ecs_ssm_target_accepts_matching_ids():
    assert dispatch.ecs_ssm_target("prod", _ARN, "0123abcd-4567_x") == "ecs:prod_0123abcd4567_0123abcd-4567_x"


@pytest.mark.parametrize(
    "cluster,arn,rt",
    [
        ("prod", _ARN, "rt;reboot"),
        ("prod", _ARN, "a b"),
        ("prod", _ARN, ""),
        ("pr od", _ARN, "rt-1"),
        ("other", _ARN, "rt-1"),
        ("prod", "arn:aws:ecs:eu-west-1:123456789012:task/prod/abc/../x", "rt-1"),
        ("prod", "arn:aws:ecs:eu-west-1:1234:task/prod/abc", "rt-1"),
        ("prod", "not-an-arn", "rt-1"),
    ],
)
def test_ecs_ssm_target_rejects_bad_or_mismatched_ids(cluster, arn, rt):
    with pytest.raises(RuntimeError):
        dispatch.ecs_ssm_target(cluster, arn, rt)


def test_resolve_runtime_id_validates_before_and_after_aws(monkeypatch):
    calls = []

    def run(*a, **k):
        calls.append(a)
        return SimpleNamespace(returncode=0, stdout="rt;evil\n", stderr="")

    monkeypatch.setattr(dispatch.subprocess, "run", run)
    with pytest.raises(RuntimeError):
        dispatch._resolve_ecs_container_runtime_id("other", _ARN)
    assert not calls
    with pytest.raises(RuntimeError):
        dispatch._resolve_ecs_container_runtime_id("prod", _ARN)
    monkeypatch.setattr(
        dispatch.subprocess, "run", lambda *a, **k: SimpleNamespace(returncode=0, stdout="rt-1\n", stderr="")
    )
    assert dispatch._resolve_ecs_container_runtime_id("prod", _ARN) == "rt-1"
