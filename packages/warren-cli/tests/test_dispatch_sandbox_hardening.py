"""AE2/AE3/AA1/AK3/AG3 wiring in warren-cli dispatch. HOME is a per-test tmp dir (conftest)."""

from __future__ import annotations

import json
import stat
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import typer

from warren_cli import dispatch as d

from test_dispatch import _RecordingRuntime

posix_exec_only = pytest.mark.skipif(
    sys.platform == "win32", reason="asserts the POSIX os.execvp hand-off; Windows covered by test_windows_handoff"
)

posix_harness_dirs = pytest.mark.skipif(
    sys.platform == "win32", reason="per-workspace harness dirs back POSIX local sandboxes; checks mode bits and symlinks"
)


def _project(projects_dir: Path, template_body: str) -> None:
    projects_dir.mkdir(exist_ok=True)
    (projects_dir / "proj.yaml").write_text(
        "name: proj\n"
        "description: t\n"
        "repo: git@example:proj.git\n"
        "bare_path: /tmp/proj/.git-store\n"
        "docker_image: ghcr.io/x/base:latest\n"
        "templates:\n"
        "  t:\n" + template_body
    )


def _provision(tmp_path: Path, template_body: str, runtime_type: str = "seatbelt"):
    projects_dir = tmp_path / "projects"
    _project(projects_dir, template_body)
    rt = _RecordingRuntime()
    cfg = SimpleNamespace(runtime=SimpleNamespace(type=runtime_type), images={})
    d.provision_local("proj", "t", projects_dir, runtime=rt, cfg=cfg)
    return rt.captured_spec


@pytest.fixture
def host_home():
    home = Path.home()
    (home / ".claude").mkdir()
    (home / ".claude.json").write_text("{}")
    (home / ".aws" / "sso" / "cache").mkdir(parents=True)
    (home / ".aws" / "config").write_text("[profile dev]\n")
    (home / ".aws" / "credentials").write_text("[default]\n")
    return home


def test_non_claude_template_gets_no_claude_config(tmp_path, host_home, monkeypatch):
    patched = []
    monkeypatch.setattr(d, "_patch_claude_onboarding", lambda p: patched.append(p))
    spec = _provision(tmp_path, "    app: bash\n")
    assert "CLAUDE_CONFIG_DIR" not in spec.env
    assert all(".claude" not in host for host, _ in spec.reference_paths)
    assert patched == []
    assert not (d._local_harness_root(spec.workspace_id) / "claude").exists()


def _seed_host_claude(home: Path) -> None:
    (home / ".claude" / "settings.json").write_text(
        json.dumps({"theme": "dark", "env": {"ANTHROPIC_API_KEY": "sk-host"}, "apiKeyHelper": "/bin/key"})
    )
    (home / ".claude" / ".credentials.json").write_text('{"token": "host"}')


@posix_harness_dirs
@pytest.mark.parametrize("body", ["    app: claude\n", "    app: zsh\n    harnesses: [claude]\n"])
def test_claude_gets_per_workspace_config_dir(tmp_path, host_home, body):
    """AG3: CLAUDE_CONFIG_DIR is the workspace's own dir, seeded without secrets."""
    _seed_host_claude(host_home)
    spec = _provision(tmp_path, body)
    cdir = d._local_harness_root(spec.workspace_id) / "claude"
    assert spec.env["CLAUDE_CONFIG_DIR"] == str(cdir)
    assert spec.harness_root == str(cdir.parent)
    assert all(".claude" not in host for host, _ in spec.reference_paths)
    settings = cdir / "settings.json"
    seeded = json.loads(settings.read_text())
    assert set(seeded.pop("hooks")) >= {"SessionStart", "Stop", "PermissionRequest"}  # AG5
    assert seeded == {"theme": "dark"}
    assert stat.S_IMODE(settings.stat().st_mode) == 0o400
    creds = cdir / ".credentials.json"
    assert creds.read_text() == '{"token": "host"}'
    assert stat.S_IMODE(creds.stat().st_mode) == 0o600
    assert json.loads((cdir / ".claude.json").read_text())["hasCompletedOnboarding"] is True
    assert (host_home / ".claude.json").read_text() == "{}"


@posix_harness_dirs
def test_codex_gets_generated_readonly_config_and_no_host_auth(tmp_path, host_home):
    (host_home / ".codex").mkdir()
    (host_home / ".codex" / "auth.json").write_text("{}")
    spec = _provision(tmp_path, "    app: bash\n    harnesses: [codex]\n")
    cdir = d._local_harness_root(spec.workspace_id) / "codex"
    assert spec.env["CODEX_HOME"] == str(cdir)
    assert "CLAUDE_CONFIG_DIR" not in spec.env
    toml = cdir / "config.toml"
    assert 'approval_policy = "never"' in toml.read_text()
    assert stat.S_IMODE(toml.stat().st_mode) == 0o400
    assert not (cdir / "auth.json").exists()
    assert sorted(p.name for p in (host_home / ".codex").iterdir()) == ["auth.json"]


@posix_exec_only
@posix_harness_dirs
def test_connect_copies_credentials_in_and_never_back(tmp_path, host_home, monkeypatch, capsys):
    _seed_host_claude(host_home)
    spec = _provision(tmp_path, "    app: zsh\n    harnesses: [claude]\n")
    root = Path(spec.root_path)
    root.mkdir(parents=True, exist_ok=True)
    cdir = d._local_harness_root(spec.workspace_id) / "claude"
    (cdir / ".credentials.json").write_text('{"token": "refreshed-in-sandbox"}')
    _capture_exec(monkeypatch)
    with pytest.raises(SystemExit):
        d._connect_via_execvp({
            "runtime_type": "seatbelt", "app": "zsh", "root_path": str(root),
            "workspace_id": spec.workspace_id, "profile_path": str(tmp_path / "sandbox.sb"),
            "harnesses": ["claude"], "harness_root": spec.harness_root,
        })
    assert (host_home / ".claude" / ".credentials.json").read_text() == '{"token": "host"}'
    assert (cdir / ".credentials.json").read_text() == '{"token": "host"}'
    assert not (root / ".claude").exists() and not (root / ".claude.json").exists()
    assert "vendor's cloud" in capsys.readouterr().err


@posix_harness_dirs
def test_connect_rewrites_planted_symlink_without_following(tmp_path, host_home, monkeypatch):
    _seed_host_claude(host_home)
    spec = _provision(tmp_path, "    app: bash\n    harnesses: [claude]\n")
    cdir = d._local_harness_root(spec.workspace_id) / "claude"
    victim = host_home / "victim"
    victim.write_text("keep")
    (cdir / ".credentials.json").unlink()
    (cdir / ".credentials.json").symlink_to(victim)
    d._prepare_local_harness_dirs({"claude"}, spec.harness_root)
    assert victim.read_text() == "keep"
    assert not (cdir / ".credentials.json").is_symlink()


def test_unknown_harness_rejected(tmp_path):
    with pytest.raises(Exception, match="unknown harness"):
        _provision(tmp_path, "    app: bash\n    harnesses: [nope]\n")


@pytest.mark.parametrize(
    "body,match",
    [
        ("    harnesses: [custom]\n", "explicit"),
        ("    allow_vendor_cloud: false\n    harnesses: [cursor-agent]\n", "vendor"),
    ],
)
def test_harness_selection_rules_enforced_at_provision(tmp_path, body, match):
    with pytest.raises(Exception, match=match):
        _provision(tmp_path, "    app: bash\n" + body)


def test_aws_export_mode_default_exposes_no_host_aws(tmp_path, host_home):
    """AK3: export (the default) puts no host AWS config, profile or SSO cache
    in the workspace env or mounts."""
    spec = _provision(tmp_path, "    app: bash\n    aws:\n      profile: dev\n")
    assert spec.aws.mode == "export"
    for key in ("AWS_PROFILE", "AWS_CONFIG_FILE", "AWS_SHARED_CREDENTIALS_FILE", "AWS_SSO_CACHE_DIR"):
        assert key not in spec.env
    assert all("/.aws" not in host for host, _ in spec.reference_paths)


def test_aws_sso_mode_narrow(tmp_path, host_home):
    spec = _provision(tmp_path, "    app: bash\n    aws:\n      mode: sso\n      profile: dev\n")
    assert spec.env["AWS_PROFILE"] == "dev"
    assert spec.env["AWS_CONFIG_FILE"] == str(host_home / ".aws" / "config")
    assert spec.env["AWS_SSO_CACHE_DIR"] == str(host_home / ".aws" / "sso" / "cache")
    assert "AWS_SHARED_CREDENTIALS_FILE" not in spec.env
    aws_refs = sorted(host for host, _ in spec.reference_paths if ".aws" in Path(host).parts)
    assert aws_refs == [str(host_home / ".aws" / "config"), str(host_home / ".aws" / "sso" / "cache")]


@pytest.mark.parametrize("runtime_type", ["docker", "ecs"])
def test_aws_sso_mode_rejected_for_non_local_runtime(tmp_path, runtime_type, capsys):
    with pytest.raises(typer.Exit):
        _provision(tmp_path, "    app: bash\n    aws:\n      mode: sso\n", runtime_type=runtime_type)
    assert "only allowed for local runtimes" in capsys.readouterr().err


def _capture_exec(monkeypatch):
    calls = []

    def _fake(prog, argv, env=None):
        calls.append((prog, list(argv), env))
        raise SystemExit(0)

    monkeypatch.setattr(d.os, "execvpe", _fake)
    monkeypatch.setattr(d.os, "execvp", _fake)
    return calls


@posix_exec_only
def test_seatbelt_connect_uses_absolute_binary_and_params(tmp_path, monkeypatch):
    """AE2 + AE3: /usr/bin/sandbox-exec by absolute path, paths as -D params."""
    planted = tmp_path / "bin"
    planted.mkdir()
    (planted / "sandbox-exec").write_text("#!/bin/sh\n")
    (planted / "sandbox-exec").chmod(0o755)
    monkeypatch.setenv("PATH", f"{planted}:/usr/bin:/bin")
    calls = _capture_exec(monkeypatch)
    with pytest.raises(SystemExit):
        d._connect_via_execvp({
            "runtime_type": "seatbelt",
            "profile_path": str(tmp_path / "sandbox.sb"),
            "profile_params": {"P_0": "/private/tmp/x"},
            "app": "bash",
            "workspace_id": "ws",
        })
    prog, argv, _env = calls[0]
    assert prog == "/usr/bin/sandbox-exec"
    assert argv == ["/usr/bin/sandbox-exec", "-f", str(tmp_path / "sandbox.sb"), "-D", "P_0=/private/tmp/x", "bash"]


@posix_exec_only
def test_bwrap_connect_uses_recorded_absolute_path(tmp_path, monkeypatch):
    """AE2: bwrap is resolved once at provision, not looked up on PATH at connect."""
    monkeypatch.setattr("warren_common.runtime.bubblewrap.resolve_bwrap", lambda: "/planted/bwrap")
    calls = _capture_exec(monkeypatch)
    with pytest.raises(SystemExit):
        d._connect_via_execvp({
            "runtime_type": "bwrap",
            "bwrap_path": "/usr/bin/bwrap",
            "bwrap_args": ["--", "bash"],
            "app": "bash",
            "workspace_id": "ws",
        })
    assert calls[0][0] == "/usr/bin/bwrap"
    assert calls[0][1][0] == "/usr/bin/bwrap"


def test_nsjail_path_must_be_absolute():
    with pytest.raises(ValueError):
        d._nsjail_binary({"nsjail_path": "nsjail"})
    assert d._nsjail_binary({"nsjail_path": "/opt/nsjail"}) == "/opt/nsjail"


def test_exec_in_sandbox_seatbelt_argv(tmp_path, monkeypatch):
    seen = {}

    def _run(argv, env=None):
        seen["argv"] = argv
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(d.subprocess, "run", _run)
    d._exec_in_sandbox(
        {"runtime_type": "seatbelt", "profile_path": "/s/sandbox.sb", "profile_params": {"P_0": "/x"}},
        ["echo", "hi"],
    )
    assert seen["argv"] == ["/usr/bin/sandbox-exec", "-f", "/s/sandbox.sb", "-D", "P_0=/x", "--", "echo", "hi"]


@posix_exec_only
def test_connect_export_mode_serves_profile_creds(tmp_path, monkeypatch):
    """AK3 export: host AWS env stripped, credentials endpoint env injected."""
    import warren_common.aws_credentials as ac

    started = {}

    def _start(profile, workspace_id, *, fork=True, fetch=None):
        started.update(profile=profile, workspace_id=workspace_id, fork=fork)
        return {"AWS_CONTAINER_CREDENTIALS_FULL_URI": "http://127.0.0.1:1/creds/ws",
                "AWS_CONTAINER_AUTHORIZATION_TOKEN": "tok"}

    monkeypatch.setattr(ac, "start_credentials_endpoint", _start)
    monkeypatch.setattr(ac, "profile_region", lambda profile: "eu-west-1")
    calls = _capture_exec(monkeypatch)
    with pytest.raises(SystemExit):
        d._connect_via_execvp({
            "runtime_type": "seatbelt",
            "profile_path": str(tmp_path / "sandbox.sb"),
            "app": "bash",
            "workspace_id": "ws",
            "aws": {"mode": "export", "profile": "dev"},
            "env_snapshot": {"AWS_PROFILE": "dev", "AWS_CONFIG_FILE": "/x/config"},
        })
    env = calls[0][2]
    assert started == {"profile": "dev", "workspace_id": "ws", "fork": True}
    assert env["AWS_CONTAINER_CREDENTIALS_FULL_URI"] == "http://127.0.0.1:1/creds/ws"
    assert env["AWS_CONTAINER_AUTHORIZATION_TOKEN"] == "tok"
    assert env["AWS_REGION"] == "eu-west-1"
    assert "AWS_PROFILE" not in env
    assert "AWS_CONFIG_FILE" not in env


@posix_exec_only
def test_connect_sso_mode_warns(tmp_path, monkeypatch, capsys):
    calls = _capture_exec(monkeypatch)
    with pytest.raises(SystemExit):
        d._connect_via_execvp({
            "runtime_type": "seatbelt",
            "profile_path": str(tmp_path / "sandbox.sb"),
            "app": "bash",
            "workspace_id": "ws",
            "aws": {"mode": "sso", "profile": "dev"},
            "env_snapshot": {"AWS_PROFILE": "dev"},
        })
    assert "every AWS account and role" in capsys.readouterr().err
    assert calls[0][2]["AWS_PROFILE"] == "dev"
