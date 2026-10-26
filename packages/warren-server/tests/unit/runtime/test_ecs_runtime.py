"""Wave 0 RED xfail stubs for ECSRuntime unit behaviors (Plan 07-01).

All tests are marked xfail with strict=False because ``warren.runtime.ecs``
does not exist yet. They will turn green as Plans 07-02 and 07-03 implement
each behavior.

Structure mirrors test_docker_runtime.py: synchronous helpers, asyncio.run()
for async calls, MagicMock injected directly into runtime attributes.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock

import pytest

# No pytestmark xfail — ECSRuntime is fully implemented in Plan 07-02.


def _spec():
    from warren_common.runtime.base import WorkspaceSpec

    return WorkspaceSpec(
        workspace_id="ws-abcdef12",
        project="testproject",
        intent="claude",
        image="public.ecr.aws/test/warren-base:latest",
        root_path="",
        env={"ANTHROPIC_API_KEY": "sk-test"},
        owner_id="test-user",
    )


def _make_runtime(
    mock_ecs: MagicMock,
    mock_ssm: MagicMock,
    mock_sts: MagicMock | None = None,
    mock_logs: MagicMock | None = None,
) -> "object":
    from warren.runtime.ecs import ECSRuntime

    rt = ECSRuntime(server_id="test-server")
    rt._ecs = mock_ecs
    rt._logs = mock_logs or _mock_logs()
    rt._preflight_ok = True
    return rt


def _mock_sts() -> MagicMock:
    m = MagicMock(name="sts_client")
    m.get_caller_identity.return_value = {"Account": "123456789012"}
    return m


def _mock_ecs() -> MagicMock:
    m = MagicMock(name="ecs_client")
    m.register_task_definition.return_value = {
        "taskDefinition": {
            "taskDefinitionArn": "arn:aws:ecs:us-east-1:123:task-definition/warren-ws-abcdef12:1"
        }
    }
    m.run_task.return_value = {
        "tasks": [{"taskArn": "arn:aws:ecs:us-east-1:123:task/cl/abc"}],
        "failures": [],
    }
    m.stop_task.return_value = {}
    m.list_tasks.return_value = {"taskArns": []}
    m.describe_tasks.return_value = {
        "tasks": [
            {
                "taskArn": "arn:aws:ecs:us-east-1:123:task/cl/abc",
                "lastStatus": "RUNNING",
            }
        ],
        "failures": [],
    }
    return m


def _mock_ssm() -> MagicMock:
    m = MagicMock(name="ssm_client")
    return m


def _mock_logs() -> MagicMock:
    m = MagicMock(name="logs_client")
    # Real boto3 clients expose exception classes via `.exceptions.<Name>`; a bare
    # MagicMock attribute isn't an Exception subclass, so `except m.exceptions.Foo`
    # would raise TypeError. Give it a real (never-raised-by-the-mock) class instead.
    m.exceptions.ResourceAlreadyExistsException = type(
        "ResourceAlreadyExistsException", (Exception,), {}
    )
    return m


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


def test_provision_ensures_log_group_with_bounded_retention():
    """Audit #53: provisioning must create the workspace log group itself with
    a bounded retention policy, and must NOT rely on the awslogs driver's
    "awslogs-create-group" auto-create (which left log groups with infinite
    retention and no way to expire them)."""
    from warren.runtime.ecs import ECSRuntime

    mock_ecs = _mock_ecs()
    mock_ssm = _mock_ssm()
    rt = _make_runtime(mock_ecs, mock_ssm)
    spec = _spec()

    asyncio.run(rt.provision(spec))

    rt._logs.create_log_group.assert_called_once_with(
        logGroupName="/warren/test-server"
    )
    rt._logs.put_retention_policy.assert_called_once_with(
        logGroupName="/warren/test-server", retentionInDays=90
    )
    register_kwargs = mock_ecs.register_task_definition.call_args.kwargs
    log_opts = register_kwargs["containerDefinitions"][0]["logConfiguration"]["options"]
    assert log_opts["awslogs-create-group"] == "false"


def test_ensure_log_group_tolerates_already_exists():
    """A log group that already exists (ResourceAlreadyExistsException on
    create) must not block setting/refreshing its retention policy."""
    from warren.runtime.ecs import ECSRuntime

    mock_ecs = _mock_ecs()
    mock_ssm = _mock_ssm()
    rt = _make_runtime(mock_ecs, mock_ssm)
    rt._logs.create_log_group.side_effect = (
        rt._logs.exceptions.ResourceAlreadyExistsException()
    )

    asyncio.run(rt._ensure_log_group("/warren/test-server"))

    rt._logs.put_retention_policy.assert_called_once_with(
        logGroupName="/warren/test-server", retentionInDays=90
    )


def test_provision_returns_task_arn():
    """provision() returns WorkspaceHandle with task ARN as runtime_id."""
    from warren.runtime.ecs import ECSRuntime

    mock_ecs = _mock_ecs()
    mock_ssm = _mock_ssm()
    rt = _make_runtime(mock_ecs, mock_ssm)
    spec = _spec()

    handle = asyncio.run(rt.provision(spec))

    assert handle.workspace_id == spec.workspace_id
    assert handle.runtime_id == "arn:aws:ecs:us-east-1:123:task/cl/abc"


def test_provision_run_task_failure():
    """provision() raises ProvisionError when run_task returns non-empty failures[]."""
    from warren_common.runtime.base import ProvisionError
    from warren.runtime.ecs import ECSRuntime

    mock_ecs = _mock_ecs()
    mock_ecs.run_task.return_value = {
        "tasks": [],
        "failures": [{"reason": "RESOURCE:CPU", "arn": ""}],
    }
    mock_ssm = _mock_ssm()
    rt = _make_runtime(mock_ecs, mock_ssm)

    with pytest.raises(ProvisionError):
        asyncio.run(rt.provision(_spec()))


def test_provision_runs_service_app_as_pid1_but_harness_app_at_the_shell():
    """issue #4: a service `app` threads into WARREN_APP_CMD on the RunTask
    containerOverrides. AG2a: a harness `app` (claude) doesn't -- the user starts
    it from the warren shell over ECS Exec."""
    from warren_common.runtime.base import WorkspaceSpec
    from warren.runtime.ecs import ECSRuntime

    mock_ecs = _mock_ecs()
    mock_ssm = _mock_ssm()
    rt = _make_runtime(mock_ecs, mock_ssm)
    spec = WorkspaceSpec(
        workspace_id="ws-abcdef12",
        project="testproject",
        intent="claude",
        image="public.ecr.aws/test/warren-base:latest",
        root_path="",
        env={"ANTHROPIC_API_KEY": "sk-test"},
        owner_id="test-user",
        app="acp-serve --port 9000",
    )

    asyncio.run(rt.provision(spec))

    overrides = mock_ecs.run_task.call_args.kwargs["overrides"]
    env = {e["name"]: e["value"] for e in overrides["containerOverrides"][0]["environment"]}
    assert env["WARREN_APP_CMD"] == "acp-serve --port 9000"

    spec.app = "claude"
    spec.harnesses = ["claude"]
    spec.seed_prompt = "fix it"
    asyncio.run(rt.provision(spec))
    overrides = mock_ecs.run_task.call_args.kwargs["overrides"]
    env = {e["name"]: e["value"] for e in overrides["containerOverrides"][0]["environment"]}
    assert "WARREN_APP_CMD" not in env
    assert env["WARREN_HARNESSES"] == "claude"
    assert env["WARREN_HARNESS_DEFAULT"] == "claude"
    assert env["WARREN_HARNESS_ROOT"] == "/var/lib/warren/harness"
    assert env["WARREN_SEED_PROMPT"] == "fix it"


def test_agent_workspace_runs_the_supervisor_not_the_harness_as_pid1():
    """AG2b: the entrypoint execs warren-agent-supervisor from WARREN_AGENT_SPEC; the
    harness never becomes WARREN_APP_CMD, and the shell still knows its harnesses."""
    import json

    from warren_common.agent_launch import launch_spec
    from warren_common.runtime.base import WorkspaceSpec

    mock_ecs = _mock_ecs()
    rt = _make_runtime(mock_ecs, _mock_ssm())
    agent = launch_spec("opencode", None)
    spec = WorkspaceSpec(
        workspace_id="ws-abcdef12", project="p", intent="bot", image="img", root_path="",
        owner_id="u", app="bash", harnesses=["opencode"], agent=agent,
    )
    asyncio.run(rt.provision(spec))
    overrides = mock_ecs.run_task.call_args.kwargs["overrides"]
    env = {e["name"]: e["value"] for e in overrides["containerOverrides"][0]["environment"]}
    assert "WARREN_APP_CMD" not in env
    assert json.loads(env["WARREN_AGENT_SPEC"]) == agent
    assert env["WARREN_HARNESSES"] == "opencode"


def test_provision_single_turn_harness_app_still_runs_as_pid1():
    from warren_common.runtime.base import WorkspaceSpec

    mock_ecs = _mock_ecs()
    rt = _make_runtime(mock_ecs, _mock_ssm())
    spec = WorkspaceSpec(
        workspace_id="ws-abcdef12", project="p", intent="claude", image="img", root_path="",
        owner_id="test-user", app="claude", mode="single-turn",
    )
    asyncio.run(rt.provision(spec))
    overrides = mock_ecs.run_task.call_args.kwargs["overrides"]
    env = {e["name"]: e["value"] for e in overrides["containerOverrides"][0]["environment"]}
    assert env["WARREN_APP_CMD"] == "claude"


def test_provision_omits_warren_app_cmd_for_default_bash_app():
    """The interactive default (`app: bash`) must NOT set WARREN_APP_CMD -- unlike
    podman's entrypoint.py, ecs-base/entrypoint.sh has no attached tty to run bash
    against; leaving it unset keeps the task idling for `aws ecs execute-command`."""
    from warren.runtime.ecs import ECSRuntime

    mock_ecs = _mock_ecs()
    mock_ssm = _mock_ssm()
    rt = _make_runtime(mock_ecs, mock_ssm)

    asyncio.run(rt.provision(_spec()))  # _spec() leaves app at its "bash" default

    overrides = mock_ecs.run_task.call_args.kwargs["overrides"]
    env = {e["name"]: e["value"] for e in overrides["containerOverrides"][0]["environment"]}
    assert "WARREN_APP_CMD" not in env


def test_provision_injects_warren_project_template_and_workspace_id():
    """UX-1: the baked-in .zshrc's shared banner/prompt snippet
    (warren_common/assets/warren_banner.zsh) reads these at shell-start time
    -- never set for ECS tasks before this."""
    from warren.runtime.ecs import ECSRuntime

    mock_ecs = _mock_ecs()
    mock_ssm = _mock_ssm()
    rt = _make_runtime(mock_ecs, mock_ssm)

    asyncio.run(rt.provision(_spec()))

    overrides = mock_ecs.run_task.call_args.kwargs["overrides"]
    env = {e["name"]: e["value"] for e in overrides["containerOverrides"][0]["environment"]}
    assert env["WARREN_WORKSPACE_ID"] == "ws-abcdef12"
    assert env["WARREN_PROJECT"] == "testproject"
    assert env["WARREN_TEMPLATE"] == "claude"


def test_provision_warren_computed_env_vars_win_over_colliding_spec_env():
    """Audit U1: these used to be `.setdefault(...)`, so a spec.env (or
    secret) key that happened to collide with one of warren's own computed
    names would silently win -- the inverse of #34's established precedent
    that warren's own computed env vars always take precedence over a
    same-named user-supplied one."""
    from warren.runtime.ecs import ECSRuntime

    mock_ecs = _mock_ecs()
    mock_ssm = _mock_ssm()
    rt = _make_runtime(mock_ecs, mock_ssm)
    spec = _spec()
    spec.app = "acp-serve"
    spec.env = {
        "WARREN_PROJECT": "attacker-controlled",
        "WARREN_TEMPLATE": "attacker-controlled",
        "WARREN_WORKSPACE_ID": "attacker-controlled",
        "WARREN_APP_CMD": "attacker-controlled",
    }

    asyncio.run(rt.provision(spec))

    overrides = mock_ecs.run_task.call_args.kwargs["overrides"]
    env = {e["name"]: e["value"] for e in overrides["containerOverrides"][0]["environment"]}
    assert env["WARREN_WORKSPACE_ID"] == spec.workspace_id
    assert env["WARREN_PROJECT"] == spec.project
    assert env["WARREN_TEMPLATE"] == spec.intent
    assert env["WARREN_APP_CMD"] == spec.app


def test_status_with_empty_runtime_id_returns_unknown_without_calling_ecs():
    """issue #5: a workspace whose provision() failed before RunTask ever succeeded
    has runtime_id == "" (registry.py's list_non_terminal: r.container_id or "").
    describe_tasks(tasks=[""]) is very likely to trip botocore's client-side param
    validation -- the reaper polls every non-terminal workspace every 2s, so this is
    the same crash-loop class as the podman bug fixed in 73688df."""
    from warren_common.runtime.base import WorkspaceHandle
    from warren.runtime.ecs import ECSRuntime

    mock_ecs = _mock_ecs()
    mock_ssm = _mock_ssm()
    rt = _make_runtime(mock_ecs, mock_ssm)
    handle = WorkspaceHandle(workspace_id="ws-x", runtime_id="", root_path="")

    status = asyncio.run(rt.status(handle))

    assert status == "unknown"
    mock_ecs.describe_tasks.assert_not_called()

def test_status_mapping_running():
    """describe_tasks lastStatus 'RUNNING' maps to 'running'."""
    from warren_common.runtime.base import WorkspaceHandle
    from warren.runtime.ecs import ECSRuntime

    mock_ecs = _mock_ecs()
    mock_ecs.describe_tasks.return_value = {
        "tasks": [
            {
                "taskArn": "arn:aws:ecs:us-east-1:123:task/cl/abc",
                "lastStatus": "RUNNING",
            }
        ],
        "failures": [],
    }
    mock_ssm = _mock_ssm()
    rt = _make_runtime(mock_ecs, mock_ssm)

    handle = WorkspaceHandle(
        workspace_id="ws-abcdef12",
        runtime_id="arn:aws:ecs:us-east-1:123:task/cl/abc",
        root_path="",
    )
    result = asyncio.run(rt.status(handle))
    assert result == "running"


def test_status_mapping_stopped():
    """describe_tasks lastStatus 'STOPPED' maps to 'stopped'."""
    from warren_common.runtime.base import WorkspaceHandle
    from warren.runtime.ecs import ECSRuntime

    mock_ecs = _mock_ecs()
    mock_ecs.describe_tasks.return_value = {
        "tasks": [
            {
                "taskArn": "arn:aws:ecs:us-east-1:123:task/cl/abc",
                "lastStatus": "STOPPED",
            }
        ],
        "failures": [],
    }
    mock_ssm = _mock_ssm()
    rt = _make_runtime(mock_ecs, mock_ssm)

    handle = WorkspaceHandle(
        workspace_id="ws-abcdef12",
        runtime_id="arn:aws:ecs:us-east-1:123:task/cl/abc",
        root_path="",
    )
    result = asyncio.run(rt.status(handle))
    assert result == "stopped"


def test_status_mapping_unknown():
    """An unrecognised describe_tasks lastStatus maps to 'unknown'."""
    from warren_common.runtime.base import WorkspaceHandle
    from warren.runtime.ecs import ECSRuntime

    mock_ecs = _mock_ecs()
    mock_ecs.describe_tasks.return_value = {
        "tasks": [
            {
                "taskArn": "arn:aws:ecs:us-east-1:123:task/cl/abc",
                "lastStatus": "SOMETHING_NEW",
            }
        ],
        "failures": [],
    }
    mock_ssm = _mock_ssm()
    rt = _make_runtime(mock_ecs, mock_ssm)

    handle = WorkspaceHandle(
        workspace_id="ws-abcdef12",
        runtime_id="arn:aws:ecs:us-east-1:123:task/cl/abc",
        root_path="",
    )
    result = asyncio.run(rt.status(handle))
    assert result == "unknown"


@pytest.mark.parametrize("last_status", ["PROVISIONING", "PENDING", "ACTIVATING"])
def test_status_mapping_transitional_states_are_starting(last_status):
    """BB4: a launching task must not read as "unknown" (which reprovisions)."""
    from warren_common.runtime.base import WorkspaceHandle

    mock_ecs = _mock_ecs()
    mock_ecs.describe_tasks.return_value = {
        "tasks": [{"taskArn": "arn:aws:ecs:us-east-1:123:task/cl/abc", "lastStatus": last_status}],
        "failures": [],
    }
    rt = _make_runtime(mock_ecs, _mock_ssm())
    handle = WorkspaceHandle(
        workspace_id="ws-abcdef12",
        runtime_id="arn:aws:ecs:us-east-1:123:task/cl/abc",
        root_path="",
    )
    assert asyncio.run(rt.status(handle)) == "starting"


def test_destroy_calls_stop_task():
    """destroy() calls stop_task with task ARN and cluster."""
    from warren_common.runtime.base import WorkspaceHandle
    from warren.runtime.ecs import ECSRuntime

    mock_ecs = _mock_ecs()
    mock_ssm = _mock_ssm()
    rt = _make_runtime(mock_ecs, mock_ssm)

    handle = WorkspaceHandle(
        workspace_id="ws-abcdef12",
        runtime_id="arn:aws:ecs:us-east-1:123:task/cl/abc",
        root_path="",
    )
    asyncio.run(rt.destroy(handle))

    mock_ecs.stop_task.assert_called_once()
    call_args = mock_ecs.stop_task.call_args
    # Either positional or keyword — task ARN must appear somewhere
    call_str = str(call_args)
    assert "arn:aws:ecs:us-east-1:123:task/cl/abc" in call_str


def test_stop_calls_stop_task():
    """Regression for finding 9: stop() must actually call ECS StopTask, not
    be a no-op -- the idle reaper calls registry.stop() believing it stops
    the underlying compute, but a no-op here left the Fargate task (and its
    billing) running indefinitely after the DB row was marked "stopped"."""
    from warren_common.runtime.base import WorkspaceHandle
    from warren.runtime.ecs import ECSRuntime

    mock_ecs = _mock_ecs()
    mock_ssm = _mock_ssm()
    rt = _make_runtime(mock_ecs, mock_ssm)

    handle = WorkspaceHandle(
        workspace_id="ws-abcdef12",
        runtime_id="arn:aws:ecs:us-east-1:123:task/cl/abc",
        root_path="",
    )
    asyncio.run(rt.stop(handle))

    mock_ecs.stop_task.assert_called_once()
    call_str = str(mock_ecs.stop_task.call_args)
    assert "arn:aws:ecs:us-east-1:123:task/cl/abc" in call_str


def test_preflight_succeeds_on_active_cluster():
    """preflight() sets _preflight_ok = True when describe_clusters returns an ACTIVE cluster."""
    from warren.runtime.ecs import ECSRuntime

    mock_ecs = MagicMock(name="ecs_client")
    mock_ecs.describe_clusters.return_value = {
        "clusters": [{"clusterName": "test-cluster", "status": "ACTIVE"}]
    }

    rt = ECSRuntime(server_id="test-server")
    rt._ecs = mock_ecs
    rt._ssm = MagicMock(name="ssm_client")
    rt._logs = _mock_logs()

    asyncio.run(rt.preflight())

    assert rt._preflight_ok is True


def test_preflight_raises_on_api_error():
    """preflight() raises RuntimeUnreachable when describe_clusters raises."""
    from warren_common.errors import RuntimeUnreachable
    from warren.runtime.ecs import ECSRuntime

    mock_ecs = MagicMock(name="ecs_client")
    mock_ecs.describe_clusters.side_effect = Exception("boom")

    rt = ECSRuntime(server_id="test-server")
    rt._ecs = mock_ecs
    rt._ssm = MagicMock(name="ssm_client")
    rt._logs = _mock_logs()

    with pytest.raises(RuntimeUnreachable):
        asyncio.run(rt.preflight())


def test_preflight_raises_on_missing_cluster():
    """preflight() raises RuntimeUnreachable when describe_clusters returns an empty clusters list."""
    from warren_common.errors import RuntimeUnreachable
    from warren.runtime.ecs import ECSRuntime

    mock_ecs = MagicMock(name="ecs_client")
    mock_ecs.describe_clusters.return_value = {"clusters": []}

    rt = ECSRuntime(server_id="test-server")
    rt._ecs = mock_ecs
    rt._ssm = MagicMock(name="ssm_client")
    rt._logs = _mock_logs()

    with pytest.raises(RuntimeUnreachable):
        asyncio.run(rt.preflight())


def test_preflight_raises_on_inactive_cluster():
    """preflight() raises RuntimeUnreachable when the returned cluster status is INACTIVE."""
    from warren_common.errors import RuntimeUnreachable
    from warren.runtime.ecs import ECSRuntime

    mock_ecs = MagicMock(name="ecs_client")
    mock_ecs.describe_clusters.return_value = {
        "clusters": [{"clusterName": "test-cluster", "status": "INACTIVE"}]
    }

    rt = ECSRuntime(server_id="test-server")
    rt._ecs = mock_ecs
    rt._ssm = MagicMock(name="ssm_client")
    rt._logs = _mock_logs()

    with pytest.raises(RuntimeUnreachable):
        asyncio.run(rt.preflight())


def test_exec_without_session_manager_plugin_is_unavailable(monkeypatch):
    """#59: exec() rides exec_stream; with no session-manager-plugin it raises on the first __anext__()."""
    import warren.runtime.ecs as ecs_mod
    from warren_common.runtime.base import ExecUnavailable, WorkspaceHandle

    monkeypatch.setattr(ecs_mod.shutil, "which", lambda name: None)

    mock_ecs = _mock_ecs()
    mock_ssm = _mock_ssm()
    rt = _make_runtime(mock_ecs, mock_ssm)
    handle = WorkspaceHandle(
        workspace_id="ws-abcdef12",
        runtime_id="arn:aws:ecs:us-east-1:123:task/cl/abc",
        root_path="",
    )

    with pytest.raises(ExecUnavailable):
        asyncio.run(rt.exec(handle, ["acp-serve"]).__anext__())


def test_tunnel_raises_not_implemented():
    """tunnel() raises NotImplementedError (plain coroutine contract)."""
    from warren_common.runtime.base import WorkspaceHandle

    mock_ecs = _mock_ecs()
    mock_ssm = _mock_ssm()
    rt = _make_runtime(mock_ecs, mock_ssm)
    handle = WorkspaceHandle(
        workspace_id="ws-abcdef12",
        runtime_id="arn:aws:ecs:us-east-1:123:task/cl/abc",
        root_path="",
    )

    with pytest.raises(NotImplementedError):
        asyncio.run(rt.tunnel(handle, 8420))


def test_invalid_cpu_memory_raises():
    """Invalid Fargate cpu/memory pair raises ProvisionError before any AWS call.

    256 CPU with 4096 MiB memory is an invalid Fargate combination
    (valid memory for CPU 256 is 512, 1024, or 2048).
    """
    from warren_common.runtime.base import ProvisionError
    from warren.runtime.ecs import ECSRuntime

    mock_ecs = _mock_ecs()
    mock_ssm = _mock_ssm()

    rt = ECSRuntime(server_id="test-server", ecs_cpu="256", ecs_memory="4096")
    rt._ecs = mock_ecs
    rt._ssm = mock_ssm
    rt._logs = _mock_logs()
    rt._preflight_ok = True

    with pytest.raises(ProvisionError):
        asyncio.run(rt.provision(_spec()))

    # No AWS calls should have been made
    mock_ecs.register_task_definition.assert_not_called()
    mock_ecs.run_task.assert_not_called()


def test_provision_omits_efs_when_no_volume():
    """With no volume wired in, register_task_definition gets no volumes/mountPoints keys.

    D-10: EFS is opt-in — this proves it stays off by default (app.py only builds an
    EFSMount when settings.efs_id is truthy).
    """
    from warren.runtime.ecs import ECSRuntime

    mock_ecs = _mock_ecs()
    mock_ssm = _mock_ssm()
    rt = _make_runtime(mock_ecs, mock_ssm)

    asyncio.run(rt.provision(_spec()))

    call_kwargs = mock_ecs.register_task_definition.call_args.kwargs
    assert "volumes" not in call_kwargs
    assert "mountPoints" not in call_kwargs["containerDefinitions"][0]


def test_provision_passes_owner_id_to_volume_attach():
    """Issue #6: spec.owner_id must reach EFSMount.attach() as the owner_id kwarg
    so the access point gets a warren.owner_id tag -- an orchestrator-side
    IAM/app layer needs it to enforce "only your own workspaces", and the data
    (spec.owner_id) was already available at provision() time, it just never
    reached the volume."""
    from unittest.mock import AsyncMock
    from warren.runtime.ecs import ECSRuntime
    from warren_common.runtime.base import WorkspaceSpec

    mock_ecs = _mock_ecs()
    mock_ssm = _mock_ssm()
    mock_volume = AsyncMock()
    mock_volume.last_access_point_id = "fsap-0123456789abcdef0"

    rt = ECSRuntime(server_id="test-server", volume=mock_volume)
    rt._ecs = mock_ecs
    rt._ssm = mock_ssm
    rt._logs = _mock_logs()
    rt._preflight_ok = True

    spec = WorkspaceSpec(
        workspace_id="ws-abcdef12",
        project="testproject",
        intent="claude",
        image="public.ecr.aws/test/warren-base:latest",
        root_path="",
        env={},
        owner_id="user-123",
    )

    asyncio.run(rt.provision(spec))

    mock_volume.attach.assert_awaited_once_with("ws-abcdef12", owner_id="user-123")


def test_provision_passes_none_owner_id_to_volume_attach_when_unset():
    """Empty/unset spec.owner_id must reach attach() as None, not "" -- matches
    EFSMount.attach()'s own `if owner_id:` guard that omits the tag entirely."""
    from unittest.mock import AsyncMock
    from warren.runtime.ecs import ECSRuntime
    from warren_common.runtime.base import WorkspaceSpec

    mock_ecs = _mock_ecs()
    mock_ssm = _mock_ssm()
    mock_volume = AsyncMock()
    mock_volume.last_access_point_id = "fsap-0123456789abcdef0"

    rt = ECSRuntime(server_id="test-server", volume=mock_volume)
    rt._ecs = mock_ecs
    rt._ssm = mock_ssm
    rt._logs = _mock_logs()
    rt._preflight_ok = True

    spec = WorkspaceSpec(
        workspace_id="ws-abcdef12",
        project="testproject",
        intent="claude",
        image="public.ecr.aws/test/warren-base:latest",
        root_path="",
        env={},
    )

    asyncio.run(rt.provision(spec))

    mock_volume.attach.assert_awaited_once_with("ws-abcdef12", owner_id=None)


def test_destroy_without_volume_is_noop():
    """destroy() completes without touching any EFS code path when no volume is wired in."""
    from warren_common.runtime.base import WorkspaceHandle
    from warren.runtime.ecs import ECSRuntime

    mock_ecs = _mock_ecs()
    mock_ssm = _mock_ssm()
    rt = _make_runtime(mock_ecs, mock_ssm)
    assert rt._volume is None

    handle = WorkspaceHandle(
        workspace_id="ws-abcdef12",
        runtime_id="arn:aws:ecs:us-east-1:123:task/cl/abc",
        root_path="",
    )

    asyncio.run(rt.destroy(handle))

    mock_ecs.stop_task.assert_called_once()


def test_provision_detaches_access_point_when_run_task_fails_after_attach():
    """Issue #30b: if RunTask fails AFTER attach() already created the access
    point, detach() must be called as cleanup before the error propagates --
    otherwise the access point is never detached, never gets an expires_at
    tag, and the reaper (which keys off that tag) never cleans it up."""
    from unittest.mock import AsyncMock
    from warren.runtime.ecs import ECSRuntime
    from warren_common.errors import ProvisionError

    mock_ecs = _mock_ecs()
    mock_ecs.run_task.return_value = {"tasks": [], "failures": [{"reason": "boom"}]}
    mock_ssm = _mock_ssm()
    mock_volume = AsyncMock()
    mock_volume.last_access_point_id = "fsap-0123456789abcdef0"

    rt = ECSRuntime(server_id="test-server", volume=mock_volume)
    rt._ecs = mock_ecs
    rt._ssm = mock_ssm
    rt._logs = _mock_logs()
    rt._preflight_ok = True

    with pytest.raises(ProvisionError):
        asyncio.run(rt.provision(_spec()))

    mock_volume.attach.assert_awaited_once()
    mock_volume.detach.assert_awaited_once_with("ws-abcdef12")


def test_provision_does_not_detach_when_no_volume_and_run_task_fails():
    """No volume wired in -- a RunTask failure must not touch any EFS code path."""
    from warren.runtime.ecs import ECSRuntime
    from warren_common.errors import ProvisionError

    mock_ecs = _mock_ecs()
    mock_ecs.run_task.return_value = {"tasks": [], "failures": [{"reason": "boom"}]}
    mock_ssm = _mock_ssm()
    rt = _make_runtime(mock_ecs, mock_ssm)
    assert rt._volume is None

    with pytest.raises(ProvisionError):
        asyncio.run(rt.provision(_spec()))


def test_destroy_deregisters_workspace_specific_task_definition():
    """Issue #30c: an EFS-backed workspace's task definition is never shared
    (provision() forces a fresh registration per workspace since each access
    point ARN is unique), so destroy() must deregister it -- otherwise
    revisions pile up forever even though DeregisterTaskDefinition is already
    granted."""
    from unittest.mock import AsyncMock
    from warren.runtime.ecs import ECSRuntime
    from warren_common.runtime.base import WorkspaceHandle

    mock_ecs = _mock_ecs()
    mock_ecs.describe_tasks.return_value = {
        "tasks": [
            {
                "taskArn": "arn:aws:ecs:us-east-1:123:task/cl/abc",
                "taskDefinitionArn": "arn:aws:ecs:us-east-1:123:task-definition/warren-ws-abcdef12:1",
                "lastStatus": "RUNNING",
            }
        ],
        "failures": [],
    }
    mock_ssm = _mock_ssm()
    mock_volume = AsyncMock()

    rt = ECSRuntime(server_id="test-server", volume=mock_volume)
    rt._ecs = mock_ecs
    rt._ssm = mock_ssm
    rt._logs = _mock_logs()
    rt._preflight_ok = True

    handle = WorkspaceHandle(
        workspace_id="ws-abcdef12",
        runtime_id="arn:aws:ecs:us-east-1:123:task/cl/abc",
        root_path="",
    )

    asyncio.run(rt.destroy(handle))

    mock_ecs.deregister_task_definition.assert_called_once_with(
        taskDefinition="arn:aws:ecs:us-east-1:123:task-definition/warren-ws-abcdef12:1"
    )


def test_destroy_does_not_deregister_cached_task_definition():
    """A task definition still in the shared cache (a non-EFS workspace, or an
    EFS one reusing an already-cached revision) must never be deregistered --
    only workspace-specific, uncached revisions are cleaned up this way."""
    from unittest.mock import AsyncMock
    from warren.runtime.ecs import ECSRuntime
    from warren_common.runtime.base import WorkspaceHandle

    mock_ecs = _mock_ecs()
    cached_arn = "arn:aws:ecs:us-east-1:123:task-definition/warren-shared:1"
    mock_ecs.describe_tasks.return_value = {
        "tasks": [
            {
                "taskArn": "arn:aws:ecs:us-east-1:123:task/cl/abc",
                "taskDefinitionArn": cached_arn,
                "lastStatus": "RUNNING",
            }
        ],
        "failures": [],
    }
    mock_ssm = _mock_ssm()
    mock_volume = AsyncMock()

    rt = ECSRuntime(server_id="test-server", volume=mock_volume)
    rt._ecs = mock_ecs
    rt._ssm = mock_ssm
    rt._logs = _mock_logs()
    rt._preflight_ok = True
    rt._task_def_cache[("some-key",)] = cached_arn

    handle = WorkspaceHandle(
        workspace_id="ws-abcdef12",
        runtime_id="arn:aws:ecs:us-east-1:123:task/cl/abc",
        root_path="",
    )

    asyncio.run(rt.destroy(handle))

    mock_ecs.deregister_task_definition.assert_not_called()


def test_two_provisions_are_independent_tasks():
    """Two provision() calls with distinct specs produce two independent run_task calls.

    Structural half of POC-03 only — ECS's own per-task boundary is the isolation
    mechanism here, not NsjailRuntime; real cross-task isolation is live-AWS human UAT
    per D-06 and is explicitly NOT asserted here.
    """
    from warren_common.runtime.base import WorkspaceSpec
    from warren.runtime.ecs import ECSRuntime

    mock_ecs = _mock_ecs()
    mock_ecs.run_task.side_effect = [
        {
            "tasks": [{"taskArn": "arn:aws:ecs:us-east-1:123:task/cl/aaa"}],
            "failures": [],
        },
        {
            "tasks": [{"taskArn": "arn:aws:ecs:us-east-1:123:task/cl/bbb"}],
            "failures": [],
        },
    ]
    mock_ssm = _mock_ssm()
    rt = _make_runtime(mock_ecs, mock_ssm)

    spec_a = WorkspaceSpec(
        workspace_id="ws-aaaaaaaa",
        project="testproject",
        intent="claude",
        image="public.ecr.aws/test/warren-base:latest",
        root_path="",
        env={"ANTHROPIC_API_KEY": "sk-test-a"},
    )
    spec_b = WorkspaceSpec(
        workspace_id="ws-bbbbbbbb",
        project="testproject",
        intent="claude",
        image="public.ecr.aws/test/warren-base:latest",
        root_path="",
        env={"ANTHROPIC_API_KEY": "sk-test-b"},
    )

    handle_a = asyncio.run(rt.provision(spec_a))
    handle_b = asyncio.run(rt.provision(spec_b))

    assert mock_ecs.run_task.call_count == 2
    assert handle_a.runtime_id != handle_b.runtime_id
    assert handle_a.runtime_id == "arn:aws:ecs:us-east-1:123:task/cl/aaa"
    assert handle_b.runtime_id == "arn:aws:ecs:us-east-1:123:task/cl/bbb"

    call_a_kwargs = mock_ecs.run_task.call_args_list[0].kwargs
    call_b_kwargs = mock_ecs.run_task.call_args_list[1].kwargs
    assert "ws-bbbbbbbb" not in str(call_a_kwargs)
    assert "ws-aaaaaaaa" not in str(call_b_kwargs)


def test_resource_prefix_defaults_to_warren():
    """With no settings object, SSM path/log group/tags/startedBy all use 'warren'."""
    from warren.runtime.ecs import ECSRuntime

    mock_ecs = _mock_ecs()
    mock_ssm = _mock_ssm()
    rt = _make_runtime(mock_ecs, mock_ssm)
    asyncio.run(rt.provision(_spec()))

    register_kwargs = mock_ecs.register_task_definition.call_args.kwargs
    assert register_kwargs["family"] == "warren-test-warren-base-latest"
    assert "secrets" not in register_kwargs["containerDefinitions"][0]
    log_opts = register_kwargs["containerDefinitions"][0]["logConfiguration"]["options"]
    assert log_opts["awslogs-group"] == "/warren/test-server"
    tag_keys = {t["key"] for t in register_kwargs["tags"]}
    assert "warren.server_instance" in tag_keys

    run_kwargs = mock_ecs.run_task.call_args.kwargs
    run_tag_keys = {t["key"] for t in run_kwargs["tags"]}
    assert run_tag_keys == {
        "warren.workspace_id",
        "warren.server_instance",
        "warren.project",
        "warren.intent",
        "warren.owner_id",
    }
    assert run_kwargs["startedBy"] == "warren-test-server"


def test_run_task_tags_owner_id_from_spec():
    """AI1/AI2: every RunTask carries warren.owner_id = spec.owner_id (server-derived)."""
    mock_ecs = _mock_ecs()
    rt = _make_runtime(mock_ecs, _mock_ssm())

    asyncio.run(rt.provision(_spec()))

    tags = {t["key"]: t["value"] for t in mock_ecs.run_task.call_args.kwargs["tags"]}
    assert tags["warren.owner_id"] == "test-user"
    register_tags = {t["key"] for t in mock_ecs.register_task_definition.call_args.kwargs["tags"]}
    assert "warren.owner_id" not in register_tags


def test_exit_code_reads_workspace_container():
    """AH2: the single-turn exit code is the `workspace` container's, not git-init's."""
    from warren_common.runtime.base import WorkspaceHandle

    mock_ecs = _mock_ecs()
    mock_ecs.describe_tasks.return_value = {
        "tasks": [{
            "lastStatus": "STOPPED",
            "containers": [{"name": "git-init", "exitCode": 0}, {"name": "workspace", "exitCode": 7}],
        }],
        "failures": [],
    }
    rt = _make_runtime(mock_ecs, _mock_ssm())
    handle = WorkspaceHandle(workspace_id="ws-1", runtime_id="arn:task", root_path="")

    assert asyncio.run(rt.exit_code(handle)) == 7
    mock_ecs.describe_tasks.return_value = {"tasks": [], "failures": [{"reason": "MISSING"}]}
    assert asyncio.run(rt.exit_code(handle)) is None


def test_run_task_omits_owner_tag_when_owner_unknown():
    mock_ecs = _mock_ecs()
    rt = _make_runtime(mock_ecs, _mock_ssm())
    spec = _spec()
    spec.owner_id = ""

    asyncio.run(rt.provision(spec))

    keys = {t["key"] for t in mock_ecs.run_task.call_args.kwargs["tags"]}
    assert "warren.owner_id" not in keys


def test_resource_prefix_override_replaces_warren_everywhere(monkeypatch: pytest.MonkeyPatch):
    """issue #2: ecs_resource_prefix threads through SSM path, log group, tags,
    and startedBy — a deployment whose infra naming avoids 'warren' entirely can
    opt into its own prefix without forking ecs.py.
    """
    from types import SimpleNamespace

    from warren.runtime.ecs import ECSRuntime

    mock_ecs = _mock_ecs()
    mock_ssm = _mock_ssm()
    settings = SimpleNamespace(ecs_resource_prefix="control-plane")
    rt = ECSRuntime(server_id="test-server", settings=settings)
    rt._ecs = mock_ecs
    rt._ssm = mock_ssm
    rt._logs = _mock_logs()
    rt._preflight_ok = True
    asyncio.run(rt.provision(_spec()))

    register_kwargs = mock_ecs.register_task_definition.call_args.kwargs
    # finding #15: the task-definition family must carry the resource prefix too, not
    # just tags/log groups/SSM paths — otherwise a deployment can never scope
    # ecs:RunTask/RegisterTaskDefinition IAM to its own task-definition/<prefix>-* families.
    assert register_kwargs["family"] == "control-plane-test-warren-base-latest"
    assert "secrets" not in register_kwargs["containerDefinitions"][0]
    log_opts = register_kwargs["containerDefinitions"][0]["logConfiguration"]["options"]
    assert log_opts["awslogs-group"] == "/control-plane/test-server"
    tag_keys = {t["key"] for t in register_kwargs["tags"]}
    assert tag_keys == {"control-plane.server_instance"}

    run_kwargs = mock_ecs.run_task.call_args.kwargs
    run_tag_keys = {t["key"] for t in run_kwargs["tags"]}
    assert run_tag_keys == {
        "control-plane.workspace_id",
        "control-plane.server_instance",
        "control-plane.project",
        "control-plane.intent",
        "control-plane.owner_id",
    }
    assert "warren" not in str(run_tag_keys)
    assert run_kwargs["startedBy"] == "control-plane-test-server"


def test_boto3_session_reused_across_calls_not_recreated_per_call(monkeypatch: "pytest.MonkeyPatch"):
    """R15: a single ECSRuntime instance (the app-state singleton every HTTP request
    shares, constructed once in app.py's lifespan) must open its boto3 ECS/SSM/STS/
    logs session exactly once and reuse it on every subsequent call -- not open a
    fresh boto3.Session (and therefore a fresh SSM client) per call. _ensure_clients
    already guards client construction behind `if self._ecs is None`, so this proves
    that guard actually prevents repeat boto3.Session() calls across both the public
    ssm_client() accessor (used by the secret mirror) and the internal path."""
    import boto3

    from warren.runtime.ecs import ECSRuntime

    session_calls: list[object] = []
    real_session_cls = boto3.Session

    class _CountingSession:
        def __init__(self, *args, **kwargs):
            session_calls.append((args, kwargs))
            self._inner = real_session_cls(*args, **kwargs)

        def client(self, *args, **kwargs):
            return MagicMock(name=f"{args[0] if args else 'client'}_mock")

    monkeypatch.setattr(boto3, "Session", _CountingSession)

    rt = ECSRuntime(server_id="test-server")

    ecs1 = rt._ensure_clients()
    ecs2 = rt._ensure_clients()

    assert len(session_calls) == 1, "ECSRuntime opened more than one boto3 session (R15)"
    assert ecs1 is ecs2
    assert not hasattr(rt, "ssm_client")


def test_provision_omits_container_user_by_default():
    """AD3: with no ecs_task_user the task inherits the image's USER (warren-ecs-base
    starts as root and its entrypoint drops to warren/1000), so images that install
    tooling under /root keep working."""
    mock_ecs = _mock_ecs()
    rt = _make_runtime(mock_ecs, _mock_ssm())

    asyncio.run(rt.provision(_spec()))

    container = mock_ecs.register_task_definition.call_args.kwargs["containerDefinitions"][0]
    assert "user" not in container


def test_provision_sets_container_user_from_ecs_task_user():
    """AD3: ecs_task_user forces the workspace container's user on the task definition."""
    from types import SimpleNamespace

    from warren.runtime.ecs import ECSRuntime

    mock_ecs = _mock_ecs()
    rt = ECSRuntime(server_id="test-server", settings=SimpleNamespace(ecs_task_user="1000:1000"))
    rt._ecs = mock_ecs
    rt._ssm = _mock_ssm()
    rt._logs = _mock_logs()
    rt._preflight_ok = True

    asyncio.run(rt.provision(_spec()))

    container = mock_ecs.register_task_definition.call_args.kwargs["containerDefinitions"][0]
    assert container["user"] == "1000:1000"


# --- AI3: idempotent RunTask + owned-task listing for the orphan sweep ---


class _LostResponse(Exception):
    pass


def _efs_runtime(mock_ecs: MagicMock):
    rt = _make_runtime(mock_ecs, _mock_ssm())
    rt._settings = MagicMock(
        ecs_cluster="cl", aws_region="us-east-1", efs_id="fs-1", ecs_subnet_ids=[],
        ecs_security_group_ids=[], ecs_assign_public_ip=False, ecs_task_execution_role_arn="",
        ecs_task_role_arn="", ecs_resource_prefix="warren", ecs_task_user="",
        ecs_git_init_image="", ecs_git_known_hosts="",
    )
    volume = MagicMock()
    volume.attach = AsyncMock()
    volume.detach = AsyncMock()
    volume.last_access_point_id = "fsap-1"
    rt._volume = volume
    return rt


def _lost_then_visible(mock_ecs: MagicMock) -> None:
    """RunTask launches the task but the response is lost; ListTasks then sees it."""
    launched: list[str] = []

    def _run_task(**_kwargs):
        launched.append("arn:aws:ecs:us-east-1:123:task/cl/launched")
        raise _LostResponse("connection reset")

    def _list_tasks(**_kwargs):
        return {"taskArns": list(launched)}

    mock_ecs.run_task.side_effect = _run_task
    mock_ecs.list_tasks.side_effect = _list_tasks
    mock_ecs.describe_tasks.return_value = {
        "tasks": [
            {
                "taskArn": "arn:aws:ecs:us-east-1:123:task/cl/launched",
                "tags": [
                    {"key": "warren.server_instance", "value": "test-server"},
                    {"key": "warren.workspace_id", "value": "ws-abcdef12"},
                ],
            }
        ],
        "failures": [],
    }


def test_lost_run_task_response_retry_adopts_the_launched_task():
    """AI3: RunTask succeeds but its response is lost; the retry must not launch twice."""
    mock_ecs = _mock_ecs()
    _lost_then_visible(mock_ecs)
    rt = _efs_runtime(mock_ecs)

    with pytest.raises(_LostResponse):
        asyncio.run(rt.provision(_spec()))
    handle = asyncio.run(rt.provision(_spec()))

    assert handle.runtime_id == "arn:aws:ecs:us-east-1:123:task/cl/launched"
    assert mock_ecs.run_task.call_count == 1
    assert mock_ecs.register_task_definition.call_count == 1


def test_lost_run_task_response_retry_reuses_task_definition_and_token():
    """AI3: if the launched task isn't visible yet, the retry reuses the same
    task definition and clientToken so ECS dedupes it."""
    mock_ecs = _mock_ecs()
    mock_ecs.register_task_definition.side_effect = [
        {"taskDefinition": {"taskDefinitionArn": f"arn:aws:ecs:us-east-1:123:task-definition/warren-x:{n}"}}
        for n in (1, 2)
    ]
    mock_ecs.run_task.side_effect = [
        _LostResponse("connection reset"),
        {"tasks": [{"taskArn": "arn:aws:ecs:us-east-1:123:task/cl/abc"}], "failures": []},
    ]
    rt = _efs_runtime(mock_ecs)

    with pytest.raises(_LostResponse):
        asyncio.run(rt.provision(_spec()))
    asyncio.run(rt.provision(_spec()))

    first, second = mock_ecs.run_task.call_args_list
    assert first.kwargs["clientToken"] == second.kwargs["clientToken"]
    assert first.kwargs["taskDefinition"] == second.kwargs["taskDefinition"]
    assert mock_ecs.register_task_definition.call_count == 1


def test_lost_run_task_retry_reuses_identity_from_persistent_store(sqlite_path):
    """AI3: the launch identity is persisted before RunTask, so it survives a restart."""
    from warren.registry.store import LaunchAttemptStore, open_db

    async def _run():
        db = await open_db(sqlite_path)
        tokens = []
        for outcome in (_LostResponse("reset"), None):
            mock_ecs = _mock_ecs()
            if outcome:
                mock_ecs.run_task.side_effect = outcome
            rt = _efs_runtime(mock_ecs)
            rt.launch_store = LaunchAttemptStore(db)
            try:
                await rt.provision(_spec())
            except _LostResponse:
                pass
            tokens.append(mock_ecs.run_task.call_args.kwargs["clientToken"])
        await db.close()
        return tokens

    first, second = asyncio.run(_run())
    assert first == second


def test_client_token_changes_with_provision_generation():
    """A reprovision after stop (new generation) must not reuse the old token."""
    mock_ecs = _mock_ecs()
    rt = _make_runtime(mock_ecs, _mock_ssm())
    tokens = []
    for generation in ("", "arn:aws:ecs:us-east-1:123:task/cl/old"):
        spec = _spec()
        spec.provision_generation = generation
        asyncio.run(rt.provision(spec))
        tokens.append(mock_ecs.run_task.call_args.kwargs["clientToken"])
    assert tokens[0] != tokens[1]
    assert all(0 < len(t) <= 64 for t in tokens)


def test_definitive_run_task_failure_gets_fresh_identity_on_retry():
    mock_ecs = _mock_ecs()
    mock_ecs.run_task.side_effect = [
        {"tasks": [], "failures": [{"reason": "RESOURCE:CPU"}]},
        {"tasks": [{"taskArn": "arn:aws:ecs:us-east-1:123:task/cl/abc"}], "failures": []},
    ]
    rt = _make_runtime(mock_ecs, _mock_ssm())
    from warren_common.errors import ProvisionError

    with pytest.raises(ProvisionError):
        asyncio.run(rt.provision(_spec()))
    asyncio.run(rt.provision(_spec()))

    first, second = mock_ecs.run_task.call_args_list
    assert first.kwargs["clientToken"] != second.kwargs["clientToken"]


def test_provision_uses_started_by_for_this_server():
    mock_ecs = _mock_ecs()
    rt = _make_runtime(mock_ecs, _mock_ssm())
    asyncio.run(rt.provision(_spec()))
    assert mock_ecs.run_task.call_args.kwargs["startedBy"] == rt.started_by == "warren-test-server"


def test_list_owned_tasks_filters_by_started_by_and_exact_server_tag():
    from datetime import datetime, timezone

    created = datetime(2026, 10, 1, tzinfo=timezone.utc)
    mock_ecs = _mock_ecs()
    mock_ecs.list_tasks.side_effect = [
        {"taskArns": ["arn:t1", "arn:t2"], "nextToken": "n"},
        {"taskArns": ["arn:t3"]},
    ]
    mock_ecs.describe_tasks.return_value = {
        "tasks": [
            {
                "taskArn": "arn:t1",
                "createdAt": created,
                "tags": [
                    {"key": "warren.server_instance", "value": "test-server"},
                    {"key": "warren.workspace_id", "value": "ws-1"},
                ],
            },
            # Same 16-char startedBy prefix, different server: never ours.
            {
                "taskArn": "arn:t2",
                "createdAt": created,
                "tags": [{"key": "warren.server_instance", "value": "test-server-other"}],
            },
            {"taskArn": "arn:t3", "createdAt": created, "tags": []},
        ],
        "failures": [],
    }
    rt = _make_runtime(mock_ecs, _mock_ssm())

    owned = asyncio.run(rt.list_owned_tasks())

    assert owned == [{"task_arn": "arn:t1", "workspace_id": "ws-1", "created_at": created}]
    first, second = mock_ecs.list_tasks.call_args_list
    assert first.kwargs["startedBy"] == "warren-test-server"
    assert second.kwargs["nextToken"] == "n"
    assert mock_ecs.describe_tasks.call_args.kwargs["include"] == ["TAGS"]
    assert mock_ecs.describe_tasks.call_args.kwargs["tasks"] == ["arn:t1", "arn:t2", "arn:t3"]


def test_provision_injects_template_env_without_shadowing_secrets_or_warren_vars():
    mock_ecs = _mock_ecs()
    mock_ssm = _mock_ssm()
    rt = _make_runtime(mock_ecs, mock_ssm)
    spec = _spec()
    spec.env = {}
    spec.secret_names = ["ANTHROPIC_API_KEY"]
    spec.template_env = {
        "OLLAMA_HOST": "http://gpu:11434",
        "ANTHROPIC_API_KEY": "plain",
        "WARREN_PROJECT": "evil",
    }

    asyncio.run(rt.provision(spec))

    overrides = mock_ecs.run_task.call_args.kwargs["overrides"]
    env = {e["name"]: e["value"] for e in overrides["containerOverrides"][0]["environment"]}
    assert env["OLLAMA_HOST"] == "http://gpu:11434"
    assert "ANTHROPIC_API_KEY" not in env
    assert env["WARREN_PROJECT"] == spec.project


def test_provision_appends_seed_prompt_to_warren_app_cmd():
    import shlex

    mock_ecs = _mock_ecs()
    rt = _make_runtime(mock_ecs, _mock_ssm())
    spec = _spec()
    spec.app = "gemini"
    spec.seed_prompt = "summarise the repo"

    asyncio.run(rt.provision(spec))

    overrides = mock_ecs.run_task.call_args.kwargs["overrides"]
    env = {e["name"]: e["value"] for e in overrides["containerOverrides"][0]["environment"]}
    assert shlex.split(env["WARREN_APP_CMD"]) == ["gemini", "-i", "summarise the repo"]


def test_provision_points_harness_config_at_workspace_volume():
    """AG3: a shell-first workspace gets only harness names (the image's harness.sh
    exports the config dirs); an app run as PID 1 gets the config dirs on the EFS
    volume, winning over spec.env."""
    mock_ecs = _mock_ecs()
    rt = _make_runtime(mock_ecs, _mock_ssm())
    spec = _spec()
    spec.harnesses = ["claude", "codex"]

    asyncio.run(rt.provision(spec))

    overrides = mock_ecs.run_task.call_args.kwargs["overrides"]
    env = {e["name"]: e["value"] for e in overrides["containerOverrides"][0]["environment"]}
    assert env["WARREN_HARNESSES"] == "claude codex"
    assert "CLAUDE_CONFIG_DIR" not in env and "WARREN_HARNESS_DIRS" not in env

    spec.app = "claude"
    spec.mode = "single-turn"
    spec.env = {"CLAUDE_CONFIG_DIR": "/home/warren/.claude"}
    asyncio.run(rt.provision(spec))
    overrides = mock_ecs.run_task.call_args.kwargs["overrides"]
    env = {e["name"]: e["value"] for e in overrides["containerOverrides"][0]["environment"]}
    assert env["CLAUDE_CONFIG_DIR"] == "/var/lib/warren/harness/claude"
    assert env["CODEX_HOME"] == "/var/lib/warren/harness/codex"
    assert "OPENCODE_CONFIG_DIR" not in env


def test_overrides_stay_well_under_the_ecs_limit_with_every_harness():
    """RunTask overrides are capped at 8 KB: harness profile data stays in the image."""
    import json

    mock_ecs = _mock_ecs()
    rt = _make_runtime(mock_ecs, _mock_ssm())
    spec = _spec()
    spec.harnesses = ["claude", "codex", "opencode", "cursor-agent", "pi"]
    spec.secret_names = [f"SECRET_{i}" for i in range(8)]
    spec.env = {}
    spec.template_env = {"OLLAMA_HOST": "http://10.0.0.5:11434", "OTEL_EXPORTER_OTLP_ENDPOINT": "http://otel:4317"}
    spec.seed_prompt = "Read CONTRIBUTING.md and run the test suite."

    asyncio.run(rt.provision(spec))

    overrides = mock_ecs.run_task.call_args.kwargs["overrides"]
    size = len(json.dumps(overrides, separators=(",", ":")))
    assert size < 2048, size


def test_provision_bedrock_sets_region_and_no_claude_login():
    """Bedrock via the workspace task role: region set, no OAuth token in the task env."""
    mock_ecs = _mock_ecs()
    rt = _make_runtime(mock_ecs, _mock_ssm())
    spec = _spec()
    spec.harnesses = ["claude"]
    spec.model_access = "bedrock"
    spec.template_env = {"CLAUDE_CODE_USE_BEDROCK": "1"}

    asyncio.run(rt.provision(spec))

    overrides = mock_ecs.run_task.call_args.kwargs["overrides"]
    env = {e["name"]: e["value"] for e in overrides["containerOverrides"][0]["environment"]}
    assert env["CLAUDE_CODE_USE_BEDROCK"] == "1"
    assert env["AWS_REGION"]
    assert "CLAUDE_CODE_OAUTH_TOKEN" not in env


def test_client_token_is_derived_from_operation_id():
    """AM2: the same operationId yields the same clientToken even without the
    persisted launch row (e.g. lost), so ECS dedupes that retry too."""
    import re

    tokens = []
    for operation_id in ("op-1", "op-1", "op-2", ""):
        mock_ecs = _mock_ecs()
        rt = _make_runtime(mock_ecs, _mock_ssm())
        spec = _spec()
        spec.operation_id = operation_id
        asyncio.run(rt.provision(spec))
        tokens.append(mock_ecs.run_task.call_args.kwargs["clientToken"])
    assert tokens[0] == tokens[1]
    assert tokens[2] != tokens[0]
    assert tokens[3] not in tokens[:3]
    assert all(re.fullmatch(r"[A-Za-z0-9_-]{1,64}", t) for t in tokens)


def test_operation_client_token_changes_with_launch_payload():
    """Same operation, different payload (e.g. image): a fresh token, never one ECS
    would reject as reused with different parameters."""
    tokens = []
    for image in ("img:a", "img:b"):
        mock_ecs = _mock_ecs()
        rt = _make_runtime(mock_ecs, _mock_ssm())
        spec = _spec()
        spec.operation_id = "op-1"
        spec.image = image
        asyncio.run(rt.provision(spec))
        tokens.append(mock_ecs.run_task.call_args.kwargs["clientToken"])
    assert tokens[0] != tokens[1]
