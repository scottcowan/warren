"""AH1: ECS git materialization -- init-container plan, task definition wiring, and
the git-materialize.sh init step itself (run for real against local repos)."""

from __future__ import annotations

import asyncio
import dataclasses
import os
import shutil
import subprocess
from pathlib import Path

import pytest
from warren.runtime.ecs_git import build_git_init_plan, workspace_branch
from warren_common.models import FolderSpec
from warren_common.runtime.base import WorkspaceSpec

from .test_ecs_runtime import _make_runtime, _mock_ecs, _mock_ssm

SCRIPT = Path(__file__).parents[3] / "images" / "ecs-base" / "git-materialize.sh"
WS_ID = "ws-abcdef12-0000"


def _spec(folders, secret_names=()):
    return WorkspaceSpec(
        workspace_id=WS_ID,
        project="proj",
        intent="dev",
        image="public.ecr.aws/test/warren-base:latest",
        root_path="",
        owner_id="test-user",
        folders=list(folders),
        secret_names=list(secret_names),
    )


def _secret(name):
    return {"name": name, "valueFrom": f"arn:aws:ssm:us-east-1:123:parameter/warren/s/u/{name}"}


APP = FolderSpec(name="app", type="git-worktree", mount="code/app",
                 url="https://github.com/org/app.git", branch="main")
WIKI = FolderSpec(name="wiki", type="git-clone", mount="refs/wiki",
                  url="git@github.com:org/wiki.git", branch="trunk", readonly=True)


# --- plan ------------------------------------------------------------------


def test_plan_none_without_git_folders():
    local = FolderSpec(name="v", type="local-path", mount="vault", path="/x")
    assert build_git_init_plan(_spec([local]), [_secret("GITHUB_PAT")]) is None


def test_plan_moves_only_clone_credentials_to_init():
    defs = [_secret("GITHUB_PAT"), _secret("WARREN_GIT_SSH_KEY"), _secret("ANTHROPIC_API_KEY")]
    plan = build_git_init_plan(_spec([APP, WIKI]), defs)

    assert plan.init_secret_names == ("GITHUB_PAT", "WARREN_GIT_SSH_KEY")
    assert [d["name"] for d in plan.workspace_secret_defs] == ["ANTHROPIC_API_KEY"]
    rows = [r.split("\t") for r in plan.folders_env.splitlines()]
    assert rows[0] == ["worktree", "app", "code/app", APP.url, "main",
                       workspace_branch(WS_ID, "dev", "code/app"), "pat", "GITHUB_PAT"]
    assert rows[1] == ["clone", "wiki", "refs/wiki", WIKI.url, "trunk", "-", "ssh", "WARREN_GIT_SSH_KEY"]


def test_plan_per_folder_secret_override_and_missing_secret():
    f = APP.model_copy(update={"pat_secret": "ORG_PAT"})
    plan = build_git_init_plan(_spec([f, WIKI]), [_secret("ORG_PAT"), _secret("GITHUB_PAT")])
    rows = [r.split("\t") for r in plan.folders_env.splitlines()]
    assert rows[0][6:] == ["pat", "ORG_PAT"]
    # WARREN_GIT_SSH_KEY isn't available, so the wiki clone runs without a credential
    assert rows[1][6:] == ["none", "-"]
    assert plan.init_secret_names == ("ORG_PAT",)
    assert [d["name"] for d in plan.workspace_secret_defs] == ["GITHUB_PAT"]


@pytest.mark.parametrize("update", [
    {"url": "file:///etc"},
    {"url": "https://github.com/org/a b.git"},
    {"mount": "../escape"},
    {"mount": "/abs"},
    {"name": ".."},
    {"branch": "-x"},
    {"branch": "a..b"},
])
def test_plan_skips_unsafe_folders(update):
    bad = APP.model_copy(update=update)
    plan = build_git_init_plan(_spec([bad, WIKI]), [])
    assert [r.split("\t")[1] for r in plan.folders_env.splitlines()] == ["wiki"]


def test_workspace_branch_matches_local_layout():
    assert workspace_branch("abcdef1234", "Dev Box", "code/My_App") == "warren/dev-box/abcdef12/code-my-app"


# --- ECS task definition ---------------------------------------------------


def _ssm_with(*names):
    # Secret ARNs come from the spec's declared names, never an SSM listing;
    # `names` only documents which secrets the test's owner has.
    return _mock_ssm()


def test_provision_adds_git_init_container_and_splits_secrets():
    ecs = _mock_ecs()
    rt = _make_runtime(ecs, _ssm_with("GITHUB_PAT", "ANTHROPIC_API_KEY"))
    spec = _spec([APP], secret_names=["GITHUB_PAT", "ANTHROPIC_API_KEY"])

    asyncio.run(rt.provision(spec))

    reg = ecs.register_task_definition.call_args.kwargs
    ws, init = reg["containerDefinitions"]
    assert ws["name"] == "workspace" and init["name"] == "git-init"
    assert ws["dependsOn"] == [{"containerName": "git-init", "condition": "SUCCESS"}]
    assert [s["name"] for s in ws["secrets"]] == ["ANTHROPIC_API_KEY"]
    assert [s["name"] for s in init["secrets"]] == ["GITHUB_PAT"]
    assert init["essential"] is False
    assert init["entryPoint"] == ["/usr/local/bin/warren-git-materialize"]
    assert init["image"] == spec.image
    assert ws["mountPoints"] == init["mountPoints"]
    assert ws["mountPoints"][0]["containerPath"] == "/var/lib/warren"
    # no EFS configured: a task-scoped volume carries the checkout between containers
    assert reg["volumes"] == [{"name": "warren-workspace"}]

    overrides = {
        o["name"]: {e["name"]: e["value"] for e in o["environment"]}
        for o in ecs.run_task.call_args.kwargs["overrides"]["containerOverrides"]
    }
    assert overrides["workspace"]["WARREN_WORKSPACE_DIR"] == "/var/lib/warren/workspace"
    assert "WARREN_GIT_FOLDERS" not in overrides["workspace"]
    assert overrides["git-init"]["WARREN_GIT_FOLDERS"].startswith("worktree\tapp\tcode/app\t")
    assert "GITHUB_PAT" not in overrides["git-init"]


def test_provision_with_efs_mounts_access_point_in_both_containers():
    from unittest.mock import AsyncMock, MagicMock

    ecs = _mock_ecs()
    rt = _make_runtime(ecs, _mock_ssm())
    rt._settings = MagicMock(ecs_task_user="", efs_id="fs-1", ecs_git_init_image="", ecs_git_known_hosts="", ecs_cluster="c",
                             aws_region="us-east-1", ecs_task_execution_role_arn="",
                             ecs_task_role_arn="", ecs_subnet_ids=[], ecs_security_group_ids=[],
                             ecs_assign_public_ip=False)
    vol = MagicMock(last_access_point_id="fsap-1")
    vol.attach = AsyncMock()
    rt._volume = vol

    asyncio.run(rt.provision(_spec([APP])))

    reg = ecs.register_task_definition.call_args.kwargs
    assert reg["volumes"][0]["efsVolumeConfiguration"]["authorizationConfig"]["accessPointId"] == "fsap-1"
    assert all(c["mountPoints"][0]["sourceVolume"] == "warren-workspace" for c in reg["containerDefinitions"])


def test_provision_without_git_folders_is_unchanged():
    ecs = _mock_ecs()
    rt = _make_runtime(ecs, _mock_ssm())
    asyncio.run(rt.provision(_spec([])))
    reg = ecs.register_task_definition.call_args.kwargs
    assert len(reg["containerDefinitions"]) == 1
    assert "volumes" not in reg and "dependsOn" not in reg["containerDefinitions"][0]
    names = [o["name"] for o in ecs.run_task.call_args.kwargs["overrides"]["containerOverrides"]]
    assert names == ["workspace"]


def test_task_definition_cache_never_shares_one_owners_secrets_with_another():
    # Audit BB2: same image, cpu/memory and secret names, no EFS -- only the owner differs.
    ecs = _mock_ecs()
    ecs.register_task_definition.side_effect = lambda **kw: {
        "taskDefinition": {"taskDefinitionArn": f"arn:td:{ecs.register_task_definition.call_count}"}
    }
    ssm = _mock_ssm()
    rt = _make_runtime(ecs, ssm)
    names = ["GITHUB_PAT", "ANTHROPIC_API_KEY"]

    for owner in ("alice", "bob", "alice"):
        spec = dataclasses.replace(_spec([APP], secret_names=names), owner_id=owner)
        asyncio.run(rt.provision(spec))

    calls = ecs.register_task_definition.call_args_list
    assert len(calls) == 2  # alice's second provision reuses alice's own definition
    for call, owner in zip(calls, ("alice", "bob")):
        ws, init = call.kwargs["containerDefinitions"]
        assert [s["name"] for s in init["secrets"]] == ["GITHUB_PAT"]
        assert [s["name"] for s in ws["secrets"]] == ["ANTHROPIC_API_KEY"]
        for s in ws["secrets"] + init["secrets"]:
            assert s["valueFrom"].endswith(f"/warren/test-server/{owner}/{s['name']}")
    task_defs = [c.kwargs["taskDefinition"] for c in ecs.run_task.call_args_list]
    assert task_defs == ["arn:td:1", "arn:td:2", "arn:td:1"]


def test_git_init_image_setting_overrides_workspace_image():
    from unittest.mock import MagicMock

    ecs = _mock_ecs()
    rt = _make_runtime(ecs, _mock_ssm())
    rt._settings = MagicMock(ecs_task_user="", efs_id="", ecs_git_init_image="ghcr.io/x/git-init:1", ecs_git_known_hosts="h ssh-ed25519 AAAA", ecs_cluster="c",
                             aws_region="us-east-1", ecs_task_execution_role_arn="",
                             ecs_task_role_arn="", ecs_subnet_ids=[], ecs_security_group_ids=[],
                             ecs_assign_public_ip=False)
    asyncio.run(rt.provision(_spec([APP])))
    init = ecs.register_task_definition.call_args.kwargs["containerDefinitions"][1]
    assert init["image"] == "ghcr.io/x/git-init:1"
    init_env = ecs.run_task.call_args.kwargs["overrides"]["containerOverrides"][1]["environment"]
    assert {"name": "WARREN_GIT_KNOWN_HOSTS", "value": "h ssh-ed25519 AAAA"} in init_env


def test_task_user_applies_to_workspace_container_only():
    """AD3 + AH1: WARREN_ECS_TASK_USER forces the workspace container's user; git-init keeps
    the image's root USER so it can run warren-init-volume before dropping to 1000."""
    from types import SimpleNamespace

    ecs = _mock_ecs()
    rt = _make_runtime(ecs, _mock_ssm())
    rt._settings = SimpleNamespace(ecs_task_user="1000:1000")
    asyncio.run(rt.provision(_spec([APP])))
    ws, init = ecs.register_task_definition.call_args.kwargs["containerDefinitions"]
    assert ws["user"] == "1000:1000"
    assert "user" not in init


def test_launch_identity_covers_git_init_overrides():
    """AI3 + AH1: the persisted launch identity covers the whole multi-container payload.
    A retry of an identical launch reuses the clientToken, but a change that only touches
    git-init's RunTask overrides (here the folder's branch, which leaves the task
    definition unchanged) gets a fresh token, so ECS can't dedupe it onto a stale launch."""
    from .test_ecs_runtime import _LostResponse

    ecs = _mock_ecs()
    ok = ecs.run_task.return_value
    ecs.run_task.side_effect = [_LostResponse("reset"), ok, ok]
    rt = _make_runtime(ecs, _mock_ssm())
    develop = APP.model_copy(update={"branch": "develop"})

    with pytest.raises(_LostResponse):
        asyncio.run(rt.provision(_spec([APP])))
    asyncio.run(rt.provision(_spec([APP])))
    asyncio.run(rt.provision(_spec([develop])))

    tokens = [c.kwargs["clientToken"] for c in ecs.run_task.call_args_list]
    assert tokens[0] == tokens[1]
    assert tokens[2] != tokens[1]
    defs = [c.kwargs["containerDefinitions"] for c in ecs.register_task_definition.call_args_list]
    assert all(d == defs[0] for d in defs)


# --- git-materialize.sh ----------------------------------------------------

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git not installed")


def _git(*args, cwd=None):
    env = {**os.environ, "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_NOSYSTEM": "1"}
    return subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "init.defaultBranch=main", *args],
        cwd=cwd, env=env, check=True, capture_output=True, text=True,
    ).stdout.strip()


@pytest.fixture
def upstream(tmp_path):
    src = tmp_path / "upstream"
    src.mkdir()
    _git("init", cwd=src)
    (src / "README").write_text("v1\n")
    _git("add", ".", cwd=src)
    _git("commit", "-m", "init", cwd=src)
    _git("checkout", "-b", "trunk", cwd=src)
    _git("checkout", "main", cwd=src)
    return src


def _run(root, records, check=True, **env):
    full_env = {
        "PATH": os.environ["PATH"],
        "WARREN_GIT_ROOT": str(root),
        "WARREN_GIT_ALLOW_PROTOCOL": "file",
        "WARREN_GIT_FOLDERS": "\n".join("\t".join(r) for r in records),
        **env,
    }
    return subprocess.run(["sh", str(SCRIPT)], env=full_env, capture_output=True, text=True, check=check)


def _wt(url, branch="main", wsb="warren/dev/abcdef12/code-app", cred=("none", "-")):
    return ["worktree", "app", "code/app", url, branch, wsb, *cred]


@needs_git
def test_script_creates_bare_store_and_worktree(tmp_path, upstream):
    root = tmp_path / "efs"
    _run(root, [_wt(f"file://{upstream}")])

    bare = root / "git" / "app.git-store"
    target = root / "workspace" / "code" / "app"
    assert _git("rev-parse", "--is-bare-repository", cwd=bare) == "true"
    assert (target / "README").read_text() == "v1\n"
    assert _git("branch", "--show-current", cwd=target) == "warren/dev/abcdef12/code-app"
    assert _git("remote", "get-url", "origin", cwd=bare) == f"file://{upstream}"


@needs_git
def test_script_rerun_never_touches_existing_worktree(tmp_path, upstream):
    root = tmp_path / "efs"
    _run(root, [_wt(f"file://{upstream}")])
    target = root / "workspace" / "code" / "app"
    (target / "README").write_text("user edit\n")
    (target / "new.txt").write_text("untracked\n")
    (upstream / "README").write_text("v2\n")
    _git("commit", "-am", "v2", cwd=upstream)

    result = _run(root, [_wt(f"file://{upstream}")])

    assert "leaving it untouched" in result.stderr
    assert (target / "README").read_text() == "user edit\n"
    assert (target / "new.txt").exists()


@needs_git
def test_script_reuses_workspace_branch_when_worktree_dir_is_gone(tmp_path, upstream):
    root = tmp_path / "efs"
    _run(root, [_wt(f"file://{upstream}")])
    target = root / "workspace" / "code" / "app"
    (target / "work.txt").write_text("x\n")
    _git("add", ".", cwd=target)
    _git("commit", "-m", "user commit", cwd=target)
    head = _git("rev-parse", "HEAD", cwd=target)
    shutil.rmtree(target)

    _run(root, [_wt(f"file://{upstream}")])

    assert _git("rev-parse", "HEAD", cwd=target) == head


@needs_git
def test_script_refuses_non_empty_non_checkout_dir(tmp_path, upstream):
    root = tmp_path / "efs"
    target = root / "workspace" / "code" / "app"
    target.mkdir(parents=True)
    (target / "notes.txt").write_text("keep me\n")

    result = _run(root, [_wt(f"file://{upstream}")])

    assert "refusing to overwrite" in result.stderr
    assert (target / "notes.txt").read_text() == "keep me\n"
    assert not (target / ".git").exists()


@needs_git
def test_script_ignores_hooks_planted_in_bare_store(tmp_path, upstream):
    root = tmp_path / "efs"
    _run(root, [_wt(f"file://{upstream}")])
    bare = root / "git" / "app.git-store"
    marker = tmp_path / "pwned"
    hook = bare / "hooks" / "post-checkout"
    hook.write_text(f"#!/bin/sh\ntouch {marker}\n")
    hook.chmod(0o755)
    shutil.rmtree(root / "workspace" / "code" / "app")

    _run(root, [_wt(f"file://{upstream}")])

    assert (root / "workspace" / "code" / "app" / "README").exists()
    assert not marker.exists()


@needs_git
def test_script_reference_clone_disables_push(tmp_path, upstream):
    root = tmp_path / "efs"
    _run(root, [["clone", "wiki", "refs/wiki", f"file://{upstream}", "trunk", "-", "none", "-"]])
    target = root / "workspace" / "refs" / "wiki"
    assert _git("branch", "--show-current", cwd=target) == "trunk"
    assert _git("remote", "get-url", "--push", "origin", cwd=target) == "no_push"


@needs_git
def test_script_one_failed_folder_does_not_block_others(tmp_path, upstream):
    root = tmp_path / "efs"
    result = _run(root, [
        ["worktree", "bad", "code/bad", f"file://{tmp_path}/missing", "main", "warren/x/y/z", "none", "-"],
        _wt(f"file://{upstream}"),
    ])
    assert "bad: materialization failed" in result.stderr
    assert (root / "workspace" / "code" / "app" / "README").exists()
    assert not (root / "git" / "bad.git-store").exists()


@needs_git
def test_script_credential_never_persisted(tmp_path, upstream):
    root = tmp_path / "efs"
    token = "ghp_supersecrettoken123"
    _run(root, [_wt(f"file://{upstream}", cred=("pat", "MY_PAT"))], MY_PAT=token)

    assert (root / "workspace" / "code" / "app" / "README").exists()
    for p in root.rglob("*"):
        if p.is_file():
            assert token.encode() not in p.read_bytes(), p


def _probe(tmp_path, name):
    """A program that records its environment if anything ever runs it."""
    prog = tmp_path / f"{name}.sh"
    prog.write_text(f"#!/bin/sh\nenv > {tmp_path}/ran-{name}\ncat\n")
    prog.chmod(0o755)
    return prog


@needs_git
def test_script_rerun_executes_nothing_planted_in_bare_store(tmp_path, upstream):
    root = tmp_path / "efs"
    _run(root, [_wt(f"file://{upstream}")])
    bare = root / "git" / "app.git-store"
    with (bare / "config").open("a") as f:
        f.write(
            f'[filter "evil"]\n\tsmudge = {_probe(tmp_path, "smudge")}\n\trequired = true\n'
            f"[core]\n\tsshCommand = {_probe(tmp_path, 'ssh')}\n"
            f"\tfsmonitor = {_probe(tmp_path, 'fsmonitor')}\n"
            f"[credential]\n\thelper = !{_probe(tmp_path, 'cred')}\n"
            f'[remote "origin"]\n\tuploadpack = {_probe(tmp_path, "uploadpack")}\n'
        )
    (bare / "info").mkdir(exist_ok=True)
    (bare / "info" / "attributes").write_text("* filter=evil\n")
    shutil.rmtree(root / "workspace" / "code" / "app")
    token = "ghp_supersecrettoken123"

    # The same run also does a credentialed clone, so the credential is live while the
    # planted store is in use.
    result = _run(root, [
        _wt(f"file://{upstream}"),
        ["clone", "wiki", "refs/wiki", f"file://{upstream}", "trunk", "-", "pat", "MY_PAT"],
    ], MY_PAT=token)

    assert "0 failed" in result.stderr, result.stderr
    assert (root / "workspace" / "code" / "app" / "README").read_text() == "v1\n"
    assert (root / "workspace" / "refs" / "wiki" / "README").exists()
    assert sorted(p.name for p in tmp_path.glob("ran-*")) == []
    config = (bare / "config").read_text()
    assert "evil" not in config and "sshCommand" not in config and "uploadpack" not in config
    assert _git("remote", "get-url", "origin", cwd=bare) == f"file://{upstream}"


@needs_git
def test_script_ignores_planted_commondir(tmp_path, upstream):
    root = tmp_path / "efs"
    _run(root, [_wt(f"file://{upstream}")])
    bare = root / "git" / "app.git-store"
    evil = tmp_path / "evil.git"
    shutil.copytree(bare, evil)
    with (evil / "config").open("a") as f:
        f.write(f'[filter "evil"]\n\tsmudge = {_probe(tmp_path, "smudge")}\n')
    (evil / "info").mkdir(exist_ok=True)
    (evil / "info" / "attributes").write_text("* filter=evil\n")
    (bare / "commondir").write_text(f"{evil}\n")
    shutil.rmtree(root / "workspace" / "code" / "app")

    _run(root, [_wt(f"file://{upstream}")])

    assert (root / "workspace" / "code" / "app" / "README").exists()
    assert not (bare / "commondir").exists()
    assert list(tmp_path.glob("ran-*")) == []


@needs_git
@pytest.mark.skipif(os.geteuid() == 0, reason="root can write anywhere")
def test_script_fails_cleanly_on_unwritable_volume(tmp_path, upstream):
    root = tmp_path / "efs"
    root.mkdir()
    root.chmod(0o555)
    try:
        result = _run(root, [_wt(f"file://{upstream}")], check=False)
    finally:
        root.chmod(0o755)
    assert result.returncode == 1
    assert "not writable" in result.stderr and "Nothing materialized" in result.stderr
    assert list(root.iterdir()) == []


PINNED_KNOWN_HOSTS = SCRIPT.parent / "ssh_known_hosts"
SSH_URL = "ssh://git@git.example.invalid/org/app.git"


@pytest.mark.skipif(shutil.which("ssh-keygen") is None, reason="ssh-keygen not installed")
def test_pinned_known_hosts_are_githubs_published_keys():
    # Fingerprints from https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/githubs-ssh-key-fingerprints
    out = subprocess.run(["ssh-keygen", "-l", "-f", str(PINNED_KNOWN_HOSTS)],
                         capture_output=True, text=True, check=True).stdout
    assert sorted(line.split()[1] for line in out.splitlines()) == sorted([
        "SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU",
        "SHA256:p2QAMXNIC1TJYWeIOttrVc98/R1BUFWu3/LiyKgUfQM",
        "SHA256:uNiVztksCsDhcc0u9e8BujQXVUpKZIDTMczCvj3tD2s",
    ])
    assert all(line.startswith("github.com ") for line in PINNED_KNOWN_HOSTS.read_text().splitlines())


def _fake_ssh(tmp_path):
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    ssh = bin_dir / "ssh"
    ssh.write_text(f'#!/bin/sh\nprintf "%s\\n" "$@" > {tmp_path}/ssh-argv\nexit 255\n')
    ssh.chmod(0o755)
    return f"{bin_dir}:{os.environ['PATH']}"


@needs_git
@pytest.mark.parametrize("cred", [("ssh", "MY_KEY"), ("none", "-")])
def test_script_ssh_clone_uses_pinned_host_keys_only(tmp_path, cred):
    root = tmp_path / "efs"
    result = _run(
        root, [_wt(SSH_URL, cred=cred)],
        PATH=_fake_ssh(tmp_path), WARREN_GIT_ALLOW_PROTOCOL="ssh",
        WARREN_GIT_KNOWN_HOSTS="git.example.invalid ssh-ed25519 AAAAC3Nz", MY_KEY="k",
    )

    argv = (tmp_path / "ssh-argv").read_text().splitlines()
    opts = [argv[i + 1] for i, a in enumerate(argv) if a == "-o"]
    assert "StrictHostKeyChecking=yes" in opts
    assert [o for o in opts if o.startswith("StrictHostKeyChecking")] == ["StrictHostKeyChecking=yes"]
    (known,) = [o for o in opts if o.startswith("UserKnownHostsFile=")]
    files = known.removeprefix("UserKnownHostsFile=").split()
    assert files[0] == "/etc/warren/ssh_known_hosts" and files[1].endswith("/known_hosts_extra")
    assert "GlobalKnownHostsFile=/dev/null" in opts and "UpdateHostKeys=no" in opts
    assert "accept-new" not in " ".join(argv)
    assert ("-i" in argv) == (cred[0] == "ssh")
    assert "app: clone failed (an ssh host key not in" in result.stderr


@needs_git
def test_script_refuses_ssh_clone_without_known_hosts(tmp_path):
    if Path("/etc/warren/ssh_known_hosts").exists():
        pytest.skip("pinned known_hosts installed on this host")
    root = tmp_path / "efs"
    result = _run(root, [_wt(SSH_URL)], PATH=_fake_ssh(tmp_path), WARREN_GIT_ALLOW_PROTOCOL="ssh")
    assert "no pinned ssh known_hosts" in result.stderr
    assert not (tmp_path / "ssh-argv").exists()


def test_script_pins_match_host_safe_git_config():
    """git-materialize.sh applies exactly the fixed-name pins host-side git does
    (warren_common.safe_git.SAFE_GIT_CONFIG), so the in-task and host paths can't drift."""
    import re

    from warren_common.safe_git import SAFE_GIT_CONFIG

    block = re.search(r'^SAFE_GIT_PINS="([^"]*)"', SCRIPT.read_text(), re.M)
    assert block is not None
    pins = re.findall(r"-c (\S+?)=(\S*)", block.group(1))
    assert len(pins) == len(set(k for k, _ in pins))
    assert dict(pins) == dict(SAFE_GIT_CONFIG)


def test_script_root_phase_uses_shared_init_volume_routine():
    """AD3: as root, git-init hands the volume to uid 1000 only via warren-init-volume
    (the routine the workspace entrypoint uses) and never chowns volume content itself."""
    text = SCRIPT.read_text()
    root_phase = text[text.index('if [ "$(id -u)" = 0 ]; then'):text.index("# --- stage 2")]
    assert '"$INIT_VOLUME"' in root_phase
    assert "INIT_VOLUME=/usr/local/bin/warren-init-volume" in text
    chowns = [line.strip() for line in root_phase.splitlines() if "chown" in line]
    assert chowns == ['chown -R "$WARREN_UID:$WARREN_UID" "$PRIV"']
