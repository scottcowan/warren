"""IaC guards across setup.sh, CDK and Terraform: AI1 (human ECS Exec scoped by the task's
owner tag), AI2 (cost-allocation tag docs), AD1 (minimal workspace task role)."""

from __future__ import annotations

import fnmatch
import json
import re
import subprocess
from pathlib import Path

import pytest

_ECS = Path(__file__).parents[4] / "resources" / "ecs"

OPERATOR_SIDS = {
    "DescribeWorkspaceTasks",
    "ExecOwnWorkspaceTasks",
    "ExecWorkspaceCluster",
    "DenyExecOtherOwners",
    "DenyExecWithoutOwnerTag",
    "PortForwardDocument",
    "PortForwardOwnWorkspaceTasks",
    "DenySsmSessionOtherOwners",
    "DenySsmSessionUntaggedWorkspaceTasks",
    "DenySsmSessionWithoutOwnerTag",
    "DenyNonPortForwardDocuments",
}
BREAK_GLASS_SIDS = {"DescribeClusterTasks", "ClusterWideExec", "ClusterWideSsmSessions", "OwnSessions"}


def _setup_sh_policy(var: str) -> dict:
    text = (_ECS / "setup.sh").read_text()
    m = re.search(rf"{var}=\$\(cat <<POLICY\n(.*?)\nPOLICY\n\)", text, re.DOTALL)
    assert m, var
    script = (
        'ACCOUNT_ID=123456789012 REGION=us-east-1 OWNER_PRINCIPAL_TAG=warren-owner CLUSTER_NAME=warren-cluster-prod '
        'CLUSTER_ARN=arn:aws:ecs:us-east-1:123456789012:cluster/warren-cluster-prod '
        'WORKSPACE_TASK_ARNS="arn:aws:ecs:us-east-1:123456789012:task/warren-cluster-prod/*" '
        'ANY_TASK_ARNS="arn:aws:ecs:us-east-1:123456789012:task/*" '
        'PORT_FORWARD_DOCUMENT=arn:aws:ssm:us-east-1::document/AWS-StartPortForwardingSession\n'
        f"cat <<POLICY\n{m.group(1)}\nPOLICY\n"
    )
    out = subprocess.run(["bash", "-c", script], capture_output=True, text=True, check=True).stdout
    return json.loads(out)


def _sids(doc: dict) -> dict[str, dict]:
    return {s["Sid"]: s for s in doc["Statement"]}


def test_setup_sh_operator_policy_scopes_exec_by_owner_tag():
    stmts = _sids(_setup_sh_policy("OPERATOR_POLICY"))
    assert set(stmts) == OPERATOR_SIDS
    allow = stmts["ExecOwnWorkspaceTasks"]
    assert allow["Condition"]["StringEquals"] == {
        "ecs:ResourceTag/warren.owner_id": "${aws:PrincipalTag/warren-owner}"
    }
    deny_other = stmts["DenyExecOtherOwners"]
    assert deny_other["Effect"] == "Deny"
    assert deny_other["Condition"]["StringNotEquals"] == allow["Condition"]["StringEquals"]
    pf = stmts["PortForwardOwnWorkspaceTasks"]
    assert pf["Condition"] == {
        "StringEquals": {"aws:ResourceTag/warren.owner_id": "${aws:PrincipalTag/warren-owner}"},
        "BoolIfExists": {"ssm:SessionDocumentAccessCheck": "true"},
    }
    assert stmts["PortForwardDocument"]["Resource"].endswith(":document/AWS-StartPortForwardingSession")
    assert "AWS-StartPortForwardingSessionToRemoteHost" not in json.dumps(stmts)


# A minimal IAM evaluator for the statement shapes these policies use: every resource in
# the request must be allowed by some statement and denied by none.
_CLUSTER = "arn:aws:ecs:us-east-1:123456789012:cluster/warren-cluster-prod"
_TASK = "arn:aws:ecs:us-east-1:123456789012:task/warren-cluster-prod/abc"
_PF_DOC = "arn:aws:ssm:us-east-1::document/AWS-StartPortForwardingSession"
_SHELL_DOC = "arn:aws:ssm:us-east-1:123456789012:document/SSM-SessionManagerRunShell"
_SSH_DOC = "arn:aws:ssm:us-east-1::document/AWS-StartSSHSession"


def _subst(value: str, principal_tags: dict[str, str]) -> str | None:
    m = re.fullmatch(r"\$\{aws:PrincipalTag/(.+)\}", value)
    return principal_tags.get(m.group(1)) if m else value


def _cond_ok(cond: dict, ctx: dict[str, str], principal_tags: dict[str, str]) -> bool:
    for op, pairs in cond.items():
        for key, want in pairs.items():
            have = ctx.get(key)
            if op == "Null":
                if (have is None) != (want == "true"):
                    return False
            elif op == "BoolIfExists":
                if have is not None and have != want:
                    return False
            elif op in ("StringEquals", "ArnEquals"):
                if have is None or have != _subst(want, principal_tags):
                    return False
            elif op == "StringNotEquals":
                if have is not None and have == _subst(want, principal_tags):
                    return False
            else:
                raise AssertionError(op)
    return True


def _matches(stmt: dict, action: str, arn: str) -> bool:
    actions = stmt["Action"] if isinstance(stmt["Action"], list) else [stmt["Action"]]
    if action not in actions:
        return False
    if "NotResource" in stmt:
        return not any(fnmatch.fnmatchcase(arn, r) for r in stmt["NotResource"])
    res = stmt["Resource"] if isinstance(stmt["Resource"], list) else [stmt["Resource"]]
    return any(fnmatch.fnmatchcase(arn, r) for r in res)


def _allowed(doc: dict, action: str, resources: dict[str, dict], principal_tags: dict[str, str]) -> bool:
    base = {"ecs:cluster": _CLUSTER, **{f"aws:PrincipalTag/{k}": v for k, v in principal_tags.items()}}
    for arn, tags in resources.items():
        ctx = {**base, **{f"{p}:ResourceTag/{k}": v for k, v in tags.items() for p in ("aws", "ecs")}}
        hits = [
            st for st in doc["Statement"]
            if _matches(st, action, arn) and _cond_ok(st.get("Condition", {}), ctx, principal_tags)
        ]
        if any(st["Effect"] == "Deny" for st in hits) or not any(st["Effect"] == "Allow" for st in hits):
            return False
    return True


_ME = {"warren-owner": "me"}


@pytest.mark.parametrize(
    "resources,principal,expected",
    [
        ({_TASK: {"warren.owner_id": "me"}, _PF_DOC: {}}, _ME, True),
        ({_TASK: {"warren.owner_id": "you"}, _PF_DOC: {}}, _ME, False),
        ({_TASK: {}, _PF_DOC: {}}, _ME, False),
        ({_TASK: {"warren.owner_id": "me"}, _PF_DOC: {}}, {}, False),
        ({_TASK: {"warren.owner_id": "me"}, _SHELL_DOC: {}}, _ME, False),
        ({_TASK: {"warren.owner_id": "me"}, _SSH_DOC: {}}, _ME, False),
    ],
    ids=["own-task", "other-owner", "untagged-task", "untagged-caller", "shell-document", "ssh-document"],
)
def test_operator_policy_port_forwarding_only_into_own_tasks(resources, principal, expected):
    """`warren tunnel` keeps working for owners, and only for owners."""
    doc = _setup_sh_policy("OPERATOR_POLICY")
    assert _allowed(doc, "ssm:StartSession", resources, principal) is expected


@pytest.mark.parametrize(
    "tags,principal,expected",
    [
        ({"warren.owner_id": "me"}, _ME, True),
        ({"warren.owner_id": "you"}, _ME, False),
        ({}, _ME, False),
        ({"warren.owner_id": "me"}, {}, False),
    ],
    ids=["own-task", "other-owner", "untagged-task", "untagged-caller"],
)
def test_operator_policy_exec_only_into_own_tasks(tags, principal, expected):
    doc = _setup_sh_policy("OPERATOR_POLICY")
    resources = {_TASK: tags, _CLUSTER: {}}
    assert _allowed(doc, "ecs:ExecuteCommand", resources, principal) is expected


def test_setup_sh_break_glass_is_the_cluster_wide_exec_holder():
    stmts = _sids(_setup_sh_policy("BREAK_GLASS_POLICY"))
    assert set(stmts) == BREAK_GLASS_SIDS
    assert "StringEquals" not in stmts["ClusterWideExec"].get("Condition", {})
    trust = _setup_sh_policy("BREAK_GLASS_TRUST")["Statement"][0]
    assert trust["Condition"] == {"Bool": {"aws:MultiFactorAuthPresent": "true"}}


@pytest.mark.parametrize(
    "path,owner_key",
    [
        ("terraform/main.tf", 'variable = "aws:ResourceTag/${local.owner_tag_key}"'),
        ("cdk/warren_stack.py", 'ssm_owner_tag_key = f"aws:ResourceTag/{ecs_resource_prefix}.owner_id"'),
    ],
)
def test_terraform_and_cdk_carry_the_same_statements(path: str, owner_key: str):
    text = (_ECS / path).read_text()
    for sid in OPERATOR_SIDS | BREAK_GLASS_SIDS:
        assert f'"{sid}"' in text, sid
    assert owner_key in text
    assert "ssm:SessionDocumentAccessCheck" in text
    assert "document/AWS-StartPortForwardingSession\"" in text
    assert "warren-break-glass-" in text
    assert "warren-workspace-operator-" in text


def test_terraform_owner_tag_key_matches_runtime_tag():
    from warren.runtime.ecs import ECSRuntime
    from warren_common.runtime.base import WorkspaceSpec

    tf = (_ECS / "terraform" / "main.tf").read_text()
    assert re.search(r'owner_tag_key\s+= "\$\{var\.ecs_resource_prefix\}\.owner_id"', tf)
    rt = ECSRuntime(server_id="s")
    spec = WorkspaceSpec(workspace_id="w", project="p", intent="i", image="img", root_path="", owner_id="o")
    assert {"key": "warren.owner_id", "value": "o"} in rt._task_tags(spec)


def test_cost_allocation_docs_activate_the_tag_the_runtime_sets():
    """AI2: the documented cost-allocation tag is the one every RunTask carries."""
    from warren.runtime.ecs import ECSRuntime
    from warren_common.runtime.base import WorkspaceSpec

    readme = (_ECS / "README.md").read_text()
    spec = WorkspaceSpec(workspace_id="w", project="p", intent="i", image="img", root_path="", owner_id="o")
    keys = {t["key"] for t in ECSRuntime(server_id="s")._task_tags(spec)}
    assert "TagKey=warren.owner_id,Status=Active" in readme
    assert "warren.owner_id" in keys
    assert "EFS storage can't be split per user" in readme


# AD1: everything in a Fargate task is agent-controlled, so this is all the agent may hold.
WORKSPACE_ROLE_ALLOWED = {
    "ssmmessages:CreateControlChannel",
    "ssmmessages:CreateDataChannel",
    "ssmmessages:OpenControlChannel",
    "ssmmessages:OpenDataChannel",
    "elasticfilesystem:ClientMount",
    "elasticfilesystem:ClientWrite",
    "logs:DescribeLogGroups",
    "logs:CreateLogStream",
    "logs:DescribeLogStreams",
    "logs:PutLogEvents",
    "kms:Decrypt",
    "kms:GenerateDataKey",
}
_ACTION = re.compile(r'"([a-z0-9]+:[A-Za-z*]+)"')


def _between(text: str, start: str, end: str) -> str:
    i = text.index(start)
    return text[i : text.index(end, i)]


def _workspace_role_actions() -> dict[str, set[str]]:
    tf = _between(
        (_ECS / "terraform" / "main.tf").read_text(),
        'data "aws_iam_policy_document" "workspace_task_role_policy"',
        'resource "aws_iam_role" "workspace_task_role"',
    )
    cdk = _between(
        (_ECS / "cdk" / "warren_stack.py").read_text(),
        '"WarrenWorkspaceTaskPolicy",',
        "task_role = iam.Role(",
    )
    sh_doc = _setup_sh_policy("WORKSPACE_POLICY")
    sh: set[str] = set()
    for stmt in sh_doc["Statement"]:
        actions = stmt["Action"]
        sh.update([actions] if isinstance(actions, str) else actions)
    return {"terraform": set(_ACTION.findall(tf)), "cdk": set(_ACTION.findall(cdk)), "setup.sh": sh}


def test_workspace_task_role_stays_minimal():
    for tool, actions in _workspace_role_actions().items():
        assert actions, tool
        assert actions <= WORKSPACE_ROLE_ALLOWED, (tool, actions - WORKSPACE_ROLE_ALLOWED)


def test_fargate_isolation_is_documented():
    readme = (_ECS / "README.md").read_text()
    assert "## Fargate isolation: the task role is the control" in readme
    assert "SYS_ADMIN is not allowed on Fargate" in readme
    assert "169.254.170.2" in readme


def test_control_plane_role_can_exec_only_into_its_cluster():
    """#59: the exec relay calls ecs:ExecuteCommand as the control plane."""
    doc = _setup_sh_policy("TASK_POLICY")
    stmt = _sids(doc)["ECSExecWorkspaceTasks"]
    assert stmt["Action"] == "ecs:ExecuteCommand"
    assert stmt["Condition"] == {
        "ArnEquals": {"ecs:cluster": "arn:aws:ecs:us-east-1:123456789012:cluster/warren-cluster-prod"}
    }
    assert set(stmt["Resource"]) == {
        "arn:aws:ecs:us-east-1:123456789012:task/warren-cluster-prod/*",
        "arn:aws:ecs:us-east-1:123456789012:cluster/warren-cluster-prod",
    }
    for path in ("terraform/main.tf", "cdk/warren_stack.py"):
        text = (_ECS / path).read_text()
        assert '"ECSExecWorkspaceTasks"' in text, path
