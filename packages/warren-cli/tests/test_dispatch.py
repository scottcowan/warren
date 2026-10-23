"""Wave 0 RED tests for warren-cli dispatch (Plan 04 will turn GREEN)."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest
import structlog
from structlog.testing import capture_logs

from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec

from warren_cli.dispatch import (
    _exec_in_sandbox,
    connect_via_ssh_podman_exec,
    get_runtime,
    provision_local,
    start_ssh_port_forward,
)

posix_exec_only = pytest.mark.skipif(
    sys.platform == "win32", reason="asserts the POSIX os.execvp hand-off; Windows covered by test_windows_handoff"
)


class _NsjailSentinel:
    def __init__(self, server_id: str = "test-host"):
        self.server_id = server_id


class _RecordingRuntime:
    def __init__(self):
        self.captured_spec: WorkspaceSpec | None = None

    async def provision(self, spec: WorkspaceSpec) -> WorkspaceHandle:
        self.captured_spec = spec
        return WorkspaceHandle(
            workspace_id=spec.workspace_id,
            runtime_id="rec-1",
            root_path=spec.root_path,
            sidecar_url="",
        )

    async def start(self, handle):  # pragma: no cover
        pass

    async def stop(self, handle):  # pragma: no cover
        pass

    async def destroy(self, handle):  # pragma: no cover
        pass

    async def exec(self, handle, cmd):  # pragma: no cover
        if False:
            yield b""

    async def status(self, handle):  # pragma: no cover
        return "running"


def _cfg(runtime_type: str = "nsjail"):
    """Build a cfg-like object that dispatch.get_runtime accepts."""
    return SimpleNamespace(
        defaults=SimpleNamespace(mode="local"),
        runtime=SimpleNamespace(type=runtime_type),
        images={},
    )


def test_get_runtime_nsjail(monkeypatch):
    import warren_common.runtime.nsjail as nsjail_mod

    monkeypatch.setattr(nsjail_mod, "NsjailRuntime", _NsjailSentinel)
    result = get_runtime(_cfg("nsjail"))
    assert isinstance(result, _NsjailSentinel)


def test_get_runtime_docker(monkeypatch):
    import warren_common.runtime.docker as docker_mod

    class _Sentinel:
        def __init__(self, server_id: str) -> None:
            self.server_id = server_id

    monkeypatch.setattr(docker_mod, "DockerRuntime", _Sentinel)
    result = get_runtime(_cfg("docker"))
    assert isinstance(result, _Sentinel)


def test_get_runtime_bwrap(monkeypatch):
    import warren_common.runtime.bubblewrap as bwrap_mod

    class _Sentinel:
        def __init__(self, server_id: str) -> None:
            self.server_id = server_id

    monkeypatch.setattr(bwrap_mod, "BubblewrapRuntime", _Sentinel)
    result = get_runtime(_cfg("bwrap"))
    assert isinstance(result, _Sentinel)


def test_get_runtime_seatbelt(monkeypatch):
    import warren_common.runtime.seatbelt as seatbelt_mod

    class _Sentinel:
        def __init__(self, server_id: str) -> None:
            self.server_id = server_id

    monkeypatch.setattr(seatbelt_mod, "SeatbeltRuntime", _Sentinel)
    result = get_runtime(_cfg("seatbelt"))
    assert isinstance(result, _Sentinel)


def test_get_runtime_auto_dispatches_to_detected(monkeypatch):
    import warren_common.runtime_detect as det_mod
    import warren_common.runtime.bubblewrap as bwrap_mod

    class _Avail:
        recommended = "bwrap"

    class _Sentinel:
        def __init__(self, server_id: str) -> None:
            self.server_id = server_id

    monkeypatch.setattr(det_mod, "detect", lambda: _Avail())
    monkeypatch.setattr(bwrap_mod, "BubblewrapRuntime", _Sentinel)
    result = get_runtime(_cfg("auto"))
    assert isinstance(result, _Sentinel)


def test_get_runtime_auto_none_raises(monkeypatch):
    import warren_common.runtime_detect as det_mod
    import typer

    class _Avail:
        recommended = "none"
        note = ""

    monkeypatch.setattr(det_mod, "detect", lambda: _Avail())
    with pytest.raises((typer.Exit, RuntimeError, SystemExit)):
        get_runtime(_cfg("auto"))


def test_get_runtime_auto_none_explains_windows(monkeypatch, capsys):
    import warren_common.runtime_detect as det_mod
    import typer

    class _Avail:
        recommended = "none"
        note = det_mod.WINDOWS_NO_SANDBOX_NOTE

    monkeypatch.setattr(det_mod, "detect", lambda: _Avail())
    with pytest.raises(typer.Exit):
        get_runtime(_cfg("auto"))
    assert "WSL2" in capsys.readouterr().err


def test_get_runtime_unknown_type_raises():
    with pytest.raises(ValueError):
        get_runtime(_cfg("bogus"))


def test_provision_local_missing_intent_raises(tmp_path: Path):
    import typer

    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    yaml_text = (
        "name: proj\n"
        "description: t\n"
        "repo: git@example:proj.git\n"
        "bare_path: /tmp/proj/.git-store\n"
        "docker_image: ghcr.io/x/base:latest\n"
        "templates:\n"
        "  observe:\n"
        "    permission: readonly\n"
        "    app: bash\n"
    )
    (projects_dir / "proj.yaml").write_text(yaml_text)
    with pytest.raises(typer.Exit) as excinfo:
        provision_local("proj", "nope", projects_dir, runtime=_RecordingRuntime())
    assert excinfo.value.exit_code == 1


def test_provision_local_builds_workspace_spec(tmp_path: Path):
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    proj_dir = projects_dir / "proj"
    proj_dir.mkdir()
    (proj_dir / "secrets.env").write_text("FOO=bar\nUNDECLARED=nope\n")
    (proj_dir / "secrets.env").chmod(0o600)
    yaml_text = (
        "name: proj\n"
        "description: t\n"
        "repo: git@example:proj.git\n"
        "bare_path: /tmp/proj/.git-store\n"
        "docker_image: ghcr.io/x/base:latest\n"
        "mounts:\n"
        "  - host: /a\n"
        "    container: /b\n"
        "    mode: ro\n"
        "templates:\n"
        "  observe:\n"
        "    permission: readonly\n"
        "    docker_image: ghcr.io/x/observe:latest\n"
        "    app: bash\n"
        "    secrets:\n"
        "      - name: FOO\n"
        "    mounts:\n"
        "      - host: /c\n"
        "        container: /d\n"
        "        mode: rw\n"
    )
    (projects_dir / "proj.yaml").write_text(yaml_text)
    rt = _RecordingRuntime()
    try:
        provision_local("proj", "observe", projects_dir, runtime=rt)
    except NotImplementedError:
        pass
    spec = rt.captured_spec
    assert spec is not None, "runtime.provision should have been called"
    assert spec.env.get("FOO") == "bar"
    assert "UNDECLARED" not in spec.env
    assert spec.secret_names == ["FOO"]
    assert "PROMPT" in spec.env  # warren prompt injected
    assert spec.env.get("WARREN_PROJECT") == "proj"
    assert spec.env.get("WARREN_TEMPLATE") == "observe"
    assert spec.env.get("WARREN_WORKSPACE_ID") == spec.workspace_id
    assert ("/a", "/b", "ro") in spec.bind_mounts
    assert ("/c", "/d", "rw") in spec.bind_mounts
    assert spec.image == "ghcr.io/x/observe:latest"
    assert spec.root_path.startswith(str(Path.home() / ".warren" / "workspaces"))


def test_provision_local_resolves_image_via_image_map(tmp_path: Path):
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    yaml_text = (
        "name: proj\n"
        "description: t\n"
        "repo: git@example:proj.git\n"
        "bare_path: /tmp/proj/.git-store\n"
        "docker_image: ghcr.io/x/base:latest\n"
        "templates:\n"
        "  observe:\n"
        "    permission: readonly\n"
        "    app: bash\n"
    )
    (projects_dir / "proj.yaml").write_text(yaml_text)
    rt = _RecordingRuntime()
    cfg = SimpleNamespace(
        defaults=SimpleNamespace(mode="local"),
        runtime=SimpleNamespace(type="nsjail"),
        images={"ghcr.io/x/base:latest": "docker.io/mirror/base:pinned"},
    )
    provision_local("proj", "observe", projects_dir, runtime=rt, cfg=cfg)
    assert rt.captured_spec.image == "docker.io/mirror/base:pinned"


def test_provision_local_wires_docker_networks(tmp_path: Path):
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    yaml_text = (
        "name: proj\n"
        "description: t\n"
        "repo: git@example:proj.git\n"
        "bare_path: /tmp/proj/.git-store\n"
        "docker_image: ghcr.io/x/base:latest\n"
        "templates:\n"
        "  observe:\n"
        "    permission: readonly\n"
        "    app: bash\n"
        "    docker_networks:\n"
        "      - warren_default\n"
        "      - db\n"
    )
    (projects_dir / "proj.yaml").write_text(yaml_text)
    rt = _RecordingRuntime()
    cfg = SimpleNamespace(
        defaults=SimpleNamespace(mode="local"),
        runtime=SimpleNamespace(type="nsjail"),
        images={},
    )
    provision_local("proj", "observe", projects_dir, runtime=rt, cfg=cfg)
    assert rt.captured_spec.docker_networks == ["warren_default", "db"]


def test_provision_local_rejects_shell_metachars_in_image(tmp_path: Path):
    import typer

    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    yaml_text = (
        "name: proj\n"
        "description: t\n"
        "repo: git@example:proj.git\n"
        "bare_path: /tmp/proj/.git-store\n"
        'docker_image: "evil;rm -rf /"\n'
        "templates:\n"
        "  observe:\n"
        "    permission: readonly\n"
        "    app: bash\n"
    )
    (projects_dir / "proj.yaml").write_text(yaml_text)
    rt = _RecordingRuntime()
    cfg = SimpleNamespace(
        defaults=SimpleNamespace(mode="local"),
        runtime=SimpleNamespace(type="nsjail"),
        images={},
    )
    with pytest.raises((typer.Exit, ValueError)):
        provision_local("proj", "observe", projects_dir, runtime=rt, cfg=cfg)


def test_secrets_not_in_logs(tmp_path: Path):
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    proj_dir = projects_dir / "proj"
    proj_dir.mkdir()
    (proj_dir / "secrets.env").write_text("GITHUB_TOKEN=ghp_secret\n")
    (proj_dir / "secrets.env").chmod(0o600)
    yaml_text = (
        "name: proj\n"
        "description: t\n"
        "repo: git@example:proj.git\n"
        "bare_path: /tmp/proj/.git-store\n"
        "docker_image: ghcr.io/x/base:latest\n"
        "templates:\n"
        "  observe:\n"
        "    permission: readonly\n"
        "    app: bash\n"
        "    secrets:\n"
        "      - name: GITHUB_TOKEN\n"
    )
    (projects_dir / "proj.yaml").write_text(yaml_text)
    rt = _RecordingRuntime()
    with capture_logs() as logs:
        try:
            provision_local("proj", "observe", projects_dir, runtime=rt)
        except NotImplementedError:
            pass
    for record in logs:
        for value in record.values():
            assert "ghp_secret" not in str(value)


def test_exec_in_sandbox_docker_forwards_stdin(monkeypatch):
    """docker exec needs -i or piped stdin never reaches the container process,
    even though the Python subprocess itself already inherited it (regression
    for the CLI-piping-into-workspaces todo)."""
    captured: dict = {}

    def _fake_run(argv, env=None):
        captured["argv"] = argv
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("warren_cli.dispatch.subprocess.run", _fake_run)

    rc = _exec_in_sandbox(
        {"runtime_type": "docker", "container_id": "abc123"}, ["pytest", "packages/"]
    )

    assert rc == 0
    assert captured["argv"] == ["docker", "exec", "-i", "abc123", "pytest", "packages/"]


def test_exec_in_sandbox_env_is_allowlisted_not_full_os_environ(monkeypatch):
    """Audit finding #4: _exec_in_sandbox used to build `env` from
    os.environ.copy() — any AWS key/API token sitting in the operator's own
    shell (never declared by the template) would reach the sandboxed command
    on top of env_snapshot. Only the base allow-list (PATH/HOME/TERM/LANG)
    plus env_snapshot may appear in the env handed to subprocess.run."""
    monkeypatch.setenv("WARREN_TOTALLY_UNRELATED_HOST_SECRET", "leaked-if-broken")
    captured: dict = {}

    def _fake_run(argv, env=None):
        captured["env"] = env
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr("warren_cli.dispatch.subprocess.run", _fake_run)

    _exec_in_sandbox(
        {"runtime_type": "docker", "container_id": "abc123", "env_snapshot": {"FOO": "bar"}},
        ["true"],
    )

    assert "WARREN_TOTALLY_UNRELATED_HOST_SECRET" not in captured["env"]
    assert captured["env"]["FOO"] == "bar"


def test_start_ssh_port_forward_dash_dash_precedes_ssh_host(monkeypatch):
    """Audit R10: `--` must stop ssh_host from ever being parsed as an ssh
    option if it happens to start with `-` (e.g. a malformed/malicious
    profile config), same reasoning as connect_via_ssh_podman_exec below."""
    captured: dict = {}

    class _FakeProc:
        def poll(self):
            return None

        def terminate(self):
            pass

    def _fake_popen(argv, **kwargs):
        captured["argv"] = list(argv)
        return _FakeProc()

    monkeypatch.setattr("warren_cli.dispatch.shutil.which", lambda name: "/usr/bin/ssh")
    monkeypatch.setattr("warren_cli.dispatch.subprocess.Popen", _fake_popen)
    monkeypatch.setattr("warren_cli.dispatch._start_pipe_drainers", lambda proc: [])
    monkeypatch.setattr(
        "warren_cli.dispatch.socket.create_connection",
        lambda *a, **k: __import__("contextlib").nullcontext(),
    )

    malicious_ssh_host = "-oProxyCommand=evil"
    proc, port = start_ssh_port_forward(malicious_ssh_host, 8420)

    argv = captured["argv"]
    assert "--" in argv
    dash_dash = argv.index("--")
    assert argv[dash_dash + 1] == malicious_ssh_host
    assert dash_dash + 2 == len(argv)  # ssh_host is the LAST argv element


@posix_exec_only
def test_connect_via_ssh_podman_exec_quotes_malicious_container_id(monkeypatch):
    """Audit 2026-10-16 P0 #12: container_id comes from the server's own API
    response. ssh joins every argument after the hostname with spaces and hands
    the result to the REMOTE shell -- a container_id containing shell
    metacharacters, passed as a separate argv element, would run arbitrary
    commands on the ssh host as the operator. The remote command must be a
    single, already-quoted string, and ssh_host must be preceded by `--` so
    neither it nor that string can be parsed as an ssh option."""
    captured: dict = {}

    def _fake_execvp(prog, argv):
        captured["prog"] = prog
        captured["argv"] = list(argv)
        raise SystemExit(0)

    monkeypatch.setattr("warren_cli.dispatch.shutil.which", lambda name: "/usr/bin/ssh")
    monkeypatch.setattr("warren_cli.dispatch.os.execvp", _fake_execvp)

    malicious_container_id = "abc123; rm -rf ~ #"

    with pytest.raises(SystemExit):
        connect_via_ssh_podman_exec("node2", malicious_container_id)

    argv = captured["argv"]
    assert argv[:2] == ["/usr/bin/ssh", "-t"]
    assert "--" in argv
    dash_dash = argv.index("--")
    assert argv[dash_dash + 1] == "node2"
    # The whole remote command is ONE argv element -- not split across several,
    # which is what would let ssh rejoin+reinterpret pieces of it remotely.
    remote_cmd = argv[dash_dash + 2]
    assert len(argv) == dash_dash + 3
    assert malicious_container_id in remote_cmd
    # Quoted, not bare -- the semicolon/# must not be able to end the podman
    # exec command or start a shell comment on the remote side.
    import shlex

    assert shlex.quote(malicious_container_id) in remote_cmd


@posix_exec_only
def test_connect_via_ssh_podman_exec_dash_dash_precedes_container_id_in_podman_argv(
    monkeypatch,
):
    """Audit R10: distinct from shell-metacharacter quoting (the test above) --
    `--` must appear immediately before container_id WITHIN the `podman exec`
    argument list itself, so a container_id starting with `-` (e.g. a value
    that could be crafted to look like a flag) can't be parsed as a `podman
    exec` OPTION on the remote host, regardless of shell quoting."""
    captured: dict = {}

    def _fake_execvp(prog, argv):
        captured["argv"] = list(argv)
        raise SystemExit(0)

    monkeypatch.setattr("warren_cli.dispatch.shutil.which", lambda name: "/usr/bin/ssh")
    monkeypatch.setattr("warren_cli.dispatch.os.execvp", _fake_execvp)

    with pytest.raises(SystemExit):
        connect_via_ssh_podman_exec("node2", "-evil-flag-like-id")

    import shlex

    dash_dash = captured["argv"].index("--")
    remote_cmd = captured["argv"][dash_dash + 2]
    remote_argv = shlex.split(remote_cmd)
    assert remote_argv[:3] == ["podman", "exec", "-it"]
    assert remote_argv[3] == "--"
    assert remote_argv[4] == "-evil-flag-like-id"


@posix_exec_only
def test_connect_via_ssh_podman_exec_includes_ssh_key_path(monkeypatch):
    captured: dict = {}

    def _fake_execvp(prog, argv):
        captured["argv"] = list(argv)
        raise SystemExit(0)

    monkeypatch.setattr("warren_cli.dispatch.shutil.which", lambda name: "/usr/bin/ssh")
    monkeypatch.setattr("warren_cli.dispatch.os.execvp", _fake_execvp)

    with pytest.raises(SystemExit):
        connect_via_ssh_podman_exec("node2", "ctr-abc", ssh_key_path="~/.ssh/id_homelab")

    argv = captured["argv"]
    assert "-i" in argv
    assert argv[argv.index("-i") + 1].endswith("/.ssh/id_homelab")
    assert "--" in argv


def test_warren_banner_zsh_text_drives_prompt_and_banner_from_env():
    """UX-1: the shared banner asset is the single source of truth for both
    the locally-written workspace zshrc and the image-baked one -- it must
    read project/template/workspace id from the environment at shell-start
    time rather than being pre-templated."""
    from warren_cli.dispatch import _warren_banner_zsh_text

    text = _warren_banner_zsh_text()
    assert "WARREN_PROJECT" in text
    assert "WARREN_TEMPLATE" in text
    assert "WARREN_WORKSPACE_ID" in text
    assert "PROMPT=" in text
    assert "intent" not in text.lower()  # UX-1: renamed to "template" everywhere


@posix_exec_only
def test_connect_via_execvp_zsh_regenerates_banner_on_every_connect(tmp_path, monkeypatch):
    """UX-1 finding: the old write-if-missing .zshrc kept stale banner/prompt
    content for an existing workspace forever. The banner/refs portion must
    now live in a separate file that's rewritten on every connect, while the
    surrounding .zshrc (aliases, chpwd, etc.) is still only written once."""
    from warren_cli.dispatch import _connect_via_execvp, _warren_banner_zsh_text

    root = tmp_path / "ws"
    root.mkdir()

    captured: dict = {}

    def _fake_execvpe(prog, argv, env):
        captured["env"] = env
        raise SystemExit(0)

    monkeypatch.setattr("warren_cli.dispatch.os.execvpe", _fake_execvpe)
    monkeypatch.setattr("warren_cli.dispatch._warren_alias_command", lambda: "warren")

    def _state():
        return {
            "workspace_id": "abcdef12-0000-0000-0000-000000000000",
            "app": "zsh",
            "runtime_type": "nsjail",
            "root_path": str(root),
            "project": "myproj",
            "intent": "observe",
            "bind_mounts": [],
            "ssh_key_paths": [],
            "ssh_agent_sock": None,
            "nsjail_state_dir": str(tmp_path / "nsjail-state"),
        }

    # Pre-seed stale banner content (as if a prior warren version wrote it)
    # to prove the dynamic file gets fully overwritten, not merged.
    (root / ".warren_dynamic.zsh").write_text("stale content that must not survive\n")
    (tmp_path / "nsjail-state").mkdir()
    (tmp_path / "nsjail-state" / "state.json").write_text(json.dumps(_state()))

    with pytest.raises(SystemExit):
        _connect_via_execvp(_state())

    dynamic = (root / ".warren_dynamic.zsh").read_text()
    assert "stale content" not in dynamic
    assert dynamic.startswith(_warren_banner_zsh_text())
    assert "Refs:" in dynamic

    zshrc = (root / ".zshrc").read_text()
    assert ".warren_dynamic.zsh" in zshrc
    assert "PROMPT=" not in zshrc  # no more independent duplicate of the banner's own prompt

    # .zshrc is warren-owned and rewritten from scratch on every connect too
    # (BB13), so content left by an older version can't survive.
    (root / ".zshrc").write_text("export OLD=stale\n")
    (root / ".warren_dynamic.zsh").write_text("stale again\n")

    with pytest.raises(SystemExit):
        _connect_via_execvp(_state())

    assert (root / ".zshrc").read_text() == zshrc
    dynamic_again = (root / ".warren_dynamic.zsh").read_text()
    assert "stale again" not in dynamic_again

    # Connect env carries the vars the baked-in image .zshrc also relies on.
    env = captured["env"]
    assert env["WARREN_PROJECT"] == "myproj"
    assert env["WARREN_TEMPLATE"] == "observe"
    assert env["WARREN_WORKSPACE_ID"] == "abcdef12-0000-0000-0000-000000000000"


def test_warren_banner_bash_text_drives_prompt_and_banner_from_env():
    """R25: the bash sibling of the zsh banner asset must exist and carry the
    same information -- ProjectConfig.app defaults to "bash", so this is the
    banner most workspaces actually see on local connect."""
    from warren_cli.dispatch import _warren_banner_bash_text

    text = _warren_banner_bash_text()
    assert "WARREN_PROJECT" in text
    assert "WARREN_TEMPLATE" in text
    assert "WARREN_WORKSPACE_ID" in text
    assert "PS1=" in text


@posix_exec_only
def test_connect_via_execvp_bash_regenerates_banner_on_every_connect(tmp_path, monkeypatch):
    """R25: a template with no explicit `app` (defaults to "bash") previously
    got no banner/prompt/refs-listing at all on local connect -- the
    rc-generation block only ever fired for app == "zsh". Must now behave the
    same way bash does that zsh already did: dynamic banner file and
    surrounding .bashrc regenerated every connect."""
    from warren_cli.dispatch import _connect_via_execvp, _warren_banner_bash_text

    root = tmp_path / "ws"
    root.mkdir()

    captured: dict = {}

    def _fake_execvpe(prog, argv, env):
        captured["env"] = env
        raise SystemExit(0)

    monkeypatch.setattr("warren_cli.dispatch.os.execvpe", _fake_execvpe)
    monkeypatch.setattr("warren_cli.dispatch._warren_alias_command", lambda: "warren")

    def _state():
        return {
            "workspace_id": "abcdef12-0000-0000-0000-000000000000",
            "app": "bash",
            "runtime_type": "nsjail",
            "root_path": str(root),
            "project": "myproj",
            "intent": "observe",
            "bind_mounts": [],
            "ssh_key_paths": [],
            "ssh_agent_sock": None,
            "nsjail_state_dir": str(tmp_path / "nsjail-state"),
        }

    (root / ".warren_dynamic.bash").write_text("stale content that must not survive\n")
    (tmp_path / "nsjail-state").mkdir()
    (tmp_path / "nsjail-state" / "state.json").write_text(json.dumps(_state()))

    with pytest.raises(SystemExit):
        _connect_via_execvp(_state())

    dynamic = (root / ".warren_dynamic.bash").read_text()
    assert "stale content" not in dynamic
    assert dynamic.startswith(_warren_banner_bash_text())
    assert "Refs:" in dynamic

    bashrc = (root / ".bashrc").read_text()
    assert ".warren_dynamic.bash" in bashrc
    assert "PS1=" not in bashrc  # no independent duplicate of the banner's own prompt

    # .bashrc is warren-owned and rewritten from scratch on every connect too
    # (BB13), so content left by an older version can't survive.
    (root / ".bashrc").write_text("export OLD=stale\n")
    (root / ".warren_dynamic.bash").write_text("stale again\n")

    with pytest.raises(SystemExit):
        _connect_via_execvp(_state())

    assert (root / ".bashrc").read_text() == bashrc
    dynamic_again = (root / ".warren_dynamic.bash").read_text()
    assert "stale again" not in dynamic_again

    env = captured["env"]
    assert env["WARREN_PROJECT"] == "myproj"
    assert env["WARREN_TEMPLATE"] == "observe"
    assert env["WARREN_WORKSPACE_ID"] == "abcdef12-0000-0000-0000-000000000000"
    # bash has no ZDOTDIR equivalent -- must not be set for a bash workspace.
    assert "ZDOTDIR" not in env


@pytest.mark.parametrize("mount", ["../escape", "/abs/escape", "a/../../escape"])
def test_link_into_workspace_rejects_escaping_mount(tmp_path: Path, mount):
    from warren_cli.dispatch import _link_into_workspace

    ws = tmp_path / "ws"
    ws.mkdir()
    src = tmp_path / "src"
    src.mkdir()
    with pytest.raises(ValueError):
        _link_into_workspace(ws, mount, src)
    assert not (tmp_path / "escape").exists()


def test_link_into_workspace_rejects_symlinked_parent(tmp_path: Path):
    from warren_common.paths import PathEscapeError

    from warren_cli.dispatch import _link_into_workspace

    ws = tmp_path / "ws"
    ws.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    (ws / "refs").symlink_to(outside)
    with pytest.raises(PathEscapeError):
        _link_into_workspace(ws, "refs/repo", tmp_path)
    assert list(outside.iterdir()) == []


def test_link_into_workspace_creates_contained_link(tmp_path: Path):
    from warren_cli.dispatch import _link_into_workspace

    ws = tmp_path / "ws"
    ws.mkdir()
    src = tmp_path / "src"
    src.mkdir()
    _link_into_workspace(ws, "refs/repo", src)
    assert (ws / "refs" / "repo").resolve() == src.resolve()


def test_provision_local_rejects_escaping_folder_mount(tmp_path: Path):
    from pydantic import ValidationError

    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    (projects_dir / "proj.yaml").write_text(
        "name: proj\n"
        "folders:\n"
        "  - name: docs\n"
        "    type: local-path\n"
        f"    path: {tmp_path}\n"
        "    mount: ../../Documents\n"
        "templates:\n"
        "  observe:\n"
        "    app: bash\n"
    )
    with pytest.raises((ValidationError, ValueError)):
        provision_local("proj", "observe", projects_dir, runtime=_RecordingRuntime())


def _write_secret_project(tmp_path: Path, template_secrets: str) -> Path:
    projects_dir = tmp_path / "projects"
    (projects_dir / "proj").mkdir(parents=True)
    env_file = projects_dir / "proj" / "secrets.env"
    env_file.write_text("A=1\nB=2\nC=3\n")
    env_file.chmod(0o600)
    (projects_dir / "proj.yaml").write_text(
        "name: proj\n"
        "secrets:\n"
        "  - name: A\n"
        "templates:\n"
        "  low:\n"
        "    app: bash\n"
        "  high:\n"
        "    app: bash\n"
        f"    secrets:\n{template_secrets}"
    )
    return projects_dir


def test_provision_local_passes_only_declared_secrets(tmp_path: Path):
    projects_dir = _write_secret_project(tmp_path, "      - name: B\n")
    rt = _RecordingRuntime()
    provision_local("proj", "low", projects_dir, runtime=rt)
    assert {k for k in ("A", "B", "C") if k in rt.captured_spec.env} == {"A"}

    rt = _RecordingRuntime()
    provision_local("proj", "high", projects_dir, runtime=rt)
    assert {k for k in ("A", "B", "C") if k in rt.captured_spec.env} == {"A", "B"}
    assert rt.captured_spec.secret_names == ["A", "B"]


def test_provision_local_missing_declared_secret_errors(tmp_path: Path, capsys):
    import typer

    projects_dir = _write_secret_project(tmp_path, "      - name: MISSING\n")
    rt = _RecordingRuntime()
    with pytest.raises(typer.Exit) as excinfo:
        provision_local("proj", "high", projects_dir, runtime=rt)
    assert excinfo.value.exit_code == 1
    assert rt.captured_spec is None
    assert "MISSING" in capsys.readouterr().err


def test_provision_local_injects_template_env_without_shadowing_secrets(tmp_path: Path):
    projects_dir = _write_secret_project(tmp_path, "      - name: B\n")
    yaml_path = projects_dir / "proj.yaml"
    yaml_path.write_text(
        yaml_path.read_text().replace(
            "  high:\n    app: bash\n",
            "  high:\n    app: bash\n    env:\n      OLLAMA_HOST: http://gpu:11434\n      B: plain\n",
        )
    )
    rt = _RecordingRuntime()
    provision_local("proj", "high", projects_dir, runtime=rt)
    assert rt.captured_spec.env["OLLAMA_HOST"] == "http://gpu:11434"
    assert rt.captured_spec.env["B"] == "2"
    assert rt.captured_spec.template_env == {"OLLAMA_HOST": "http://gpu:11434", "B": "plain"}


def _write_worktree_project(tmp_path: Path, url: str = "git@github.com:acme/app.git") -> Path:
    projects_dir = tmp_path / "projects"
    projects_dir.mkdir()
    (projects_dir / "proj.yaml").write_text(
        "name: proj\n"
        "folders:\n"
        "  - name: app\n"
        "    type: git-worktree\n"
        f"    url: {url}\n"
        "    branch: main\n"
        "    mount: code/app\n"
        "templates:\n"
        "  develop:\n"
        "    app: bash\n"
    )
    return projects_dir


def test_provision_local_pin_green_starts_worktree_at_green_sha(tmp_path: Path, monkeypatch):
    from warren_cli import gh
    from warren_common.git import GitManager

    projects_dir = _write_worktree_project(tmp_path)
    monkeypatch.setattr(gh, "newest_green_commit", lambda repo, branch: "abc123def4567890")
    seen = {}

    async def _bare(project, url, projects_dir, fetch=False, seed_from=None):
        seen["fetch"] = fetch
        return tmp_path / "bare.git-store"

    async def _wt(bare, workspace_root, branch, workspace_id, intent, subdir="workspace", start_point=None):
        seen["start_point"] = start_point
        seen["branch"] = branch
        return workspace_root / subdir

    monkeypatch.setattr(GitManager, "ensure_bare_for_repo", staticmethod(_bare))
    monkeypatch.setattr(GitManager, "add_worktree", staticmethod(_wt))
    monkeypatch.setattr("warren_cli.dispatch._apply_local_git_crypt", lambda *a, **kw: None)

    provision_local("proj", "develop", projects_dir, runtime=_RecordingRuntime(), pin_green=True)
    assert seen == {"fetch": True, "start_point": "abc123def4567890", "branch": "main"}


def test_provision_local_pin_green_fails_without_green_commit(tmp_path: Path, monkeypatch):
    import typer

    from warren_cli import gh

    projects_dir = _write_worktree_project(tmp_path)
    monkeypatch.setattr(gh, "newest_green_commit", lambda repo, branch: None)
    rt = _RecordingRuntime()
    with pytest.raises(typer.Exit):
        provision_local("proj", "develop", projects_dir, runtime=rt, pin_green=True)
    assert rt.captured_spec is None


def test_provision_local_pin_green_rejects_non_github_repo(tmp_path: Path):
    import typer

    projects_dir = _write_worktree_project(tmp_path, url="git@gitlab.com:acme/app.git")
    with pytest.raises(typer.Exit):
        provision_local("proj", "develop", projects_dir, runtime=_RecordingRuntime(), pin_green=True)
