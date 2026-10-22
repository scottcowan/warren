"""`warren new ... --daemon --server` success-message path.

Regression test for a real crash hit live against node2: an ssh-type remote
(RemoteProfile.url is None -- it only has ssh_host/ssh_key_path) made the
"running" success branch's `remote.url.replace(...)` raise AttributeError
right after a workspace had already provisioned successfully.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import httpx
import respx
from typer.testing import CliRunner

from warren_cli.main import app

runner = CliRunner()


def _write_ssh_remote_config(tmp_path: Path) -> Path:
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        '[remotes.node2]\n'
        'runtime_type = "ssh"\n'
        'ssh_host = "node2"\n'
        'auth_token = "tok-node2"\n'
    )
    return config_path


def test_new_daemon_running_on_ssh_remote_does_not_crash(tmp_path: Path, monkeypatch):
    # --config is passed explicitly rather than relying on HOME/Path.home()
    # monkeypatching: WARREN_DIR/PROJECTS_DIR/DEFAULT_CONFIG_PATH in main.py
    # and config.py are module-level constants resolved from Path.home() at
    # *import* time, so patching Path.home() this late has no effect on them
    # (a real, pre-existing test-isolation gap, out of scope to fix here).
    config_path = _write_ssh_remote_config(tmp_path)

    fake_proc = MagicMock()
    monkeypatch.setattr(
        "warren_cli.dispatch.start_ssh_port_forward",
        lambda *a, **kw: (fake_proc, 54321),
    )

    with respx.mock(base_url="http://127.0.0.1:54321") as m:
        m.post("/workspaces").mock(
            return_value=httpx.Response(200, json={"workspace_id": "08c61556-aaaa-bbbb-cccc-ddddeeeeffff"})
        )
        m.get("/workspaces/08c61556-aaaa-bbbb-cccc-ddddeeeeffff/status").mock(
            return_value=httpx.Response(200, json={"status": "running"})
        )

        result = runner.invoke(
            app,
            ["new", "homelab", "ops", "--daemon", "--server", "node2", "--config", str(config_path)],
        )

    assert result.exit_code == 0, (result.stdout, result.exception)
    assert "running" in result.stdout
    assert "Connect: warren connect 08c61556 --server node2" in result.stdout


def test_new_server_retries_a_dropped_post_with_the_same_operation_id(tmp_path: Path, monkeypatch):
    """AM2: a retried POST /workspaces reuses its operationId so the server dedupes it."""
    config_path = _write_ssh_remote_config(tmp_path)
    monkeypatch.setattr("warren_cli.dispatch.start_ssh_port_forward", lambda *a, **kw: (MagicMock(), 54321))
    monkeypatch.setattr("warren_cli.main.asyncio.sleep", _no_sleep)

    with respx.mock(base_url="http://127.0.0.1:54321") as m:
        post = m.post("/workspaces").mock(
            side_effect=[
                httpx.ConnectError("reset"),
                httpx.Response(202, json={"workspace_id": "08c61556-aaaa-bbbb-cccc-ddddeeeeffff"}),
            ]
        )
        m.get("/workspaces/08c61556-aaaa-bbbb-cccc-ddddeeeeffff/status").mock(
            return_value=httpx.Response(200, json={"status": "running"})
        )
        result = runner.invoke(
            app, ["new", "homelab", "ops", "--daemon", "--server", "node2", "--config", str(config_path)]
        )

    assert result.exit_code == 0, (result.stdout, result.exception)
    first, second = (json.loads(call.request.content) for call in post.calls)
    assert first == second
    assert first["operationId"].startswith("cli-")


async def _no_sleep(_seconds):
    return None


def test_healthz_works_against_ssh_remote(tmp_path: Path, monkeypatch):
    """Regression test for a real bug hit live against node2: `healthz` used
    `cfg.get_profile()`/`make_client()` (the old [servers.*]/ServerProfile path,
    which requires a direct `url` and knows nothing about ssh/ecs tunneling) --
    raised a bare KeyError for any config that only has [remotes.*] entries,
    the normal case now that every other remote-facing command uses RemoteProfile.
    """
    config_path = _write_ssh_remote_config(tmp_path)

    fake_proc = MagicMock()
    monkeypatch.setattr(
        "warren_cli.dispatch.start_ssh_port_forward",
        lambda *a, **kw: (fake_proc, 54321),
    )

    with respx.mock(base_url="http://127.0.0.1:54321") as m:
        m.get("/healthz").mock(
            return_value=httpx.Response(200, json={"warren_id": "node2", "version": "0.2.0"})
        )

        result = runner.invoke(app, ["healthz", "--server", "node2", "--config", str(config_path)])

    assert result.exit_code == 0, (result.stdout, result.exception)
    assert "node2" in result.stdout


def test_projects_works_against_ssh_remote(tmp_path: Path, monkeypatch):
    """`projects` (the top-level remote project listing) shared the exact same
    [servers.*]/ServerProfile bug as `healthz` -- same fix, same regression
    shape, caught the same way by checking a [remotes.*]-only config."""
    config_path = _write_ssh_remote_config(tmp_path)

    fake_proc = MagicMock()
    monkeypatch.setattr(
        "warren_cli.dispatch.start_ssh_port_forward",
        lambda *a, **kw: (fake_proc, 54321),
    )

    with respx.mock(base_url="http://127.0.0.1:54321") as m:
        m.get("/projects").mock(
            return_value=httpx.Response(200, json=[{"name": "homelab"}])
        )

        result = runner.invoke(app, ["projects", "--server", "node2", "--config", str(config_path)])

    assert result.exit_code == 0, (result.stdout, result.exception)
    assert "homelab" in result.stdout


def test_projects_table_shows_scope_templates_and_description(tmp_path: Path, monkeypatch):
    """`projects` used to just dump the raw JSON response -- now renders a
    NAME/SCOPE/TEMPLATES/DESCRIPTION table, matching `warren list`'s and the
    local `warren project list`'s formatting instead of leaving it as the
    only remote-facing command with no human-readable output at all."""
    config_path = _write_ssh_remote_config(tmp_path)

    fake_proc = MagicMock()
    monkeypatch.setattr(
        "warren_cli.dispatch.start_ssh_port_forward",
        lambda *a, **kw: (fake_proc, 54321),
    )

    project_entry = {
        "name": "homelab",
        "description": "Ops environment for the homelab.\nSecond line ignored.",
        "_scope": "user_scoped",
        "templates": {"ops": {"description": ""}},
    }
    with respx.mock(base_url="http://127.0.0.1:54321") as m:
        m.get("/projects").mock(return_value=httpx.Response(200, json=[project_entry]))

        result = runner.invoke(app, ["projects", "--server", "node2", "--config", str(config_path)])

    assert result.exit_code == 0, (result.stdout, result.exception)
    assert "NAME" in result.stdout and "SCOPE" in result.stdout and "TEMPLATES" in result.stdout
    assert "homelab" in result.stdout
    assert "user_scoped" in result.stdout
    assert "ops" in result.stdout
    assert "Ops environment for the homelab." in result.stdout
    assert "Second line ignored." not in result.stdout  # only the first line is shown
    assert "unknown_project_field" not in result.stdout  # _scope must not trip ProjectConfig's warning


def test_projects_table_truncates_long_folded_description(tmp_path: Path, monkeypatch):
    """YAML block-scalar folding joins wrapped lines with spaces, not '\\n' --
    a real project description (e.g. homelab's) is one long line with no
    embedded newline at all, hundreds of characters long. "first line only"
    does nothing for that case; this must also hard-cap the length."""
    config_path = _write_ssh_remote_config(tmp_path)

    fake_proc = MagicMock()
    monkeypatch.setattr(
        "warren_cli.dispatch.start_ssh_port_forward",
        lambda *a, **kw: (fake_proc, 54321),
    )

    long_description = "A " + ("very " * 40) + "long one-line folded description."
    assert "\n" not in long_description and len(long_description) > 150
    with respx.mock(base_url="http://127.0.0.1:54321") as m:
        m.get("/projects").mock(
            return_value=httpx.Response(
                200, json=[{"name": "homelab", "description": long_description, "_scope": "user_scoped"}]
            )
        )

        result = runner.invoke(app, ["projects", "--server", "node2", "--config", str(config_path)])

    assert result.exit_code == 0, (result.stdout, result.exception)
    assert long_description not in result.stdout
    assert "…" in result.stdout


def test_projects_json_flag_still_returns_raw_response(tmp_path: Path, monkeypatch):
    """`--json` keeps the old raw-passthrough behavior, for scripting/piping."""
    config_path = _write_ssh_remote_config(tmp_path)

    fake_proc = MagicMock()
    monkeypatch.setattr(
        "warren_cli.dispatch.start_ssh_port_forward",
        lambda *a, **kw: (fake_proc, 54321),
    )

    with respx.mock(base_url="http://127.0.0.1:54321") as m:
        m.get("/projects").mock(
            return_value=httpx.Response(200, json=[{"name": "homelab", "_scope": "user_scoped"}])
        )

        result = runner.invoke(
            app, ["projects", "--server", "node2", "--json", "--config", str(config_path)]
        )

    assert result.exit_code == 0, (result.stdout, result.exception)
    import json as _json

    body = _json.loads(result.stdout)
    assert body == [{"name": "homelab", "_scope": "user_scoped"}]


def test_connect_shows_arrow_menu_even_with_one_remote_and_one_workspace(tmp_path: Path, monkeypatch):
    """The actual fix: `warren connect` with exactly one remote and one
    active workspace used to attach with zero confirmation of what it
    connected to. With a real terminal (isatty=True), it must now go through
    the arrow-key selector for BOTH the remote and the workspace pick, not
    silently auto-select either one."""
    config_path = _write_ssh_remote_config(tmp_path)
    monkeypatch.setattr("warren_cli.ui.is_interactive", lambda: True)

    questionary_calls = []

    def _fake_select(message, choices):
        questionary_calls.append((message, [c["value"] for c in choices]))
        fake = MagicMock()
        fake.ask.return_value = choices[0]["value"]
        return fake

    questionary_module = MagicMock()
    questionary_module.select.side_effect = _fake_select
    questionary_module.Choice = lambda title, value: {"title": title, "value": value}
    monkeypatch.setitem(__import__("sys").modules, "questionary", questionary_module)

    fake_proc = MagicMock()
    monkeypatch.setattr(
        "warren_cli.dispatch.start_ssh_port_forward",
        lambda *a, **kw: (fake_proc, 54321),
    )
    connect_calls = []
    monkeypatch.setattr(
        "warren_cli.dispatch.connect_via_ssh_podman_exec",
        lambda *a, **kw: connect_calls.append((a, kw)),
    )

    full_id = "29872965-aaaa-bbbb-cccc-ddddeeeeffff"
    with respx.mock(base_url="http://127.0.0.1:54321") as m:
        m.get("/workspaces").mock(
            return_value=httpx.Response(200, json=[
                {"workspace_id": full_id, "project": "homelab", "intent": "ops",
                 "status": "running", "container_id": "abc123"},
            ])
        )
        m.post(f"/workspaces/{full_id}/ensure_running").mock(
            return_value=httpx.Response(200, json={"container_id": "abc123", "status": "running"})
        )

        result = runner.invoke(app, ["connect", "--config", str(config_path)])

    assert result.exit_code == 0, (result.output, result.exception)
    assert connect_calls == [(("node2", "abc123"), {"ssh_key_path": None, "shell": "bash", "harness": None, "new": False})]
    # Both pickers went through the arrow menu, even though each had exactly
    # one choice -- not auto-selected silently.
    messages = [c[0] for c in questionary_calls]
    assert any("server" in m.lower() for m in messages)
    assert any("workspace" in m.lower() for m in messages)


def test_connect_offers_configured_remote_when_server_omitted(tmp_path: Path, monkeypatch):
    """Real bug: `warren connect` with no --server fell straight into the
    local-mode branch whenever [defaults] mode = "local" was set, never
    considering [remotes.*] at all -- so a config with a remote configured
    (the normal shape) showed no remote picker and no error naming it, just
    local-mode's empty-picker/generic-PTY message. `--server` omitted must
    now reach the remote path the same way tunnel/healthz/projects already
    do, not silently skip past it -- and, for an ssh-type remote, actually
    attach via dispatch.connect_via_ssh_podman_exec rather than just printing
    a "not yet wired" message."""
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        '[defaults]\n'
        'mode = "local"\n'
        '[remotes.node2]\n'
        'runtime_type = "ssh"\n'
        'ssh_host = "node2"\n'
        'auth_token = "tok-node2"\n'
    )

    # Neither --server nor the workspace id is passed below -- both pickers
    # must run -- so fake an interactive terminal and auto-select the first
    # (only) choice offered at each one, same as the arrow-menu test above.
    monkeypatch.setattr("warren_cli.ui.is_interactive", lambda: True)

    def _fake_select(message, choices):
        fake = MagicMock()
        fake.ask.return_value = choices[0]["value"]
        return fake

    questionary_module = MagicMock()
    questionary_module.select.side_effect = _fake_select
    questionary_module.Choice = lambda title, value: {"title": title, "value": value}
    monkeypatch.setitem(__import__("sys").modules, "questionary", questionary_module)

    fake_proc = MagicMock()
    monkeypatch.setattr(
        "warren_cli.dispatch.start_ssh_port_forward",
        lambda *a, **kw: (fake_proc, 54321),
    )
    connect_calls = []
    monkeypatch.setattr(
        "warren_cli.dispatch.connect_via_ssh_podman_exec",
        lambda *a, **kw: connect_calls.append((a, kw)),
    )

    with respx.mock(base_url="http://127.0.0.1:54321") as m:
        m.get("/workspaces").mock(
            return_value=httpx.Response(200, json=[
                {"workspace_id": "29872965-aaaa-bbbb-cccc-ddddeeeeffff",
                 "project": "homelab", "intent": "ops", "status": "running",
                 "container_id": "abc123"},
            ])
        )
        m.post("/workspaces/29872965-aaaa-bbbb-cccc-ddddeeeeffff/ensure_running").mock(
            return_value=httpx.Response(200, json={"container_id": "abc123", "status": "running"})
        )

        result = runner.invoke(app, ["connect", "--config", str(config_path)])

    # [remotes.*] is reached even with --server omitted (not just local mode),
    # and resolves the only active workspace and attaches to it.
    assert result.exit_code == 0, (result.output, result.exception)
    assert connect_calls == [(("node2", "abc123"), {"ssh_key_path": None, "shell": "bash", "harness": None, "new": False})]


def test_connect_resurrects_idle_reaped_workspace_by_short_id(tmp_path: Path, monkeypatch):
    """The actual scenario this whole flow exists for: a workspace the idle
    reaper already stopped. `warren connect <short-id> --server node2` must
    resolve the short id, call ensure_running (which restarts/reprovisions
    server-side), and attach to the resulting container -- not require a
    fresh `warren new` just to get back into a workspace that still exists."""
    config_path = _write_ssh_remote_config(tmp_path)

    fake_proc = MagicMock()
    monkeypatch.setattr(
        "warren_cli.dispatch.start_ssh_port_forward",
        lambda *a, **kw: (fake_proc, 54321),
    )
    connect_calls = []
    monkeypatch.setattr(
        "warren_cli.dispatch.connect_via_ssh_podman_exec",
        lambda *a, **kw: connect_calls.append((a, kw)),
    )

    full_id = "08c61556-715a-4dd0-96f1-acc5bbf989aa"
    with respx.mock(base_url="http://127.0.0.1:54321") as m:
        m.get("/workspaces").mock(
            return_value=httpx.Response(200, json=[
                {"workspace_id": full_id, "project": "homelab", "intent": "ops",
                 "status": "stopped", "container_id": "ctr-old"},
            ])
        )
        m.post(f"/workspaces/{full_id}/ensure_running").mock(
            return_value=httpx.Response(200, json={"container_id": "ctr-restarted", "status": "running"})
        )

        result = runner.invoke(
            app, ["connect", "08c61556", "--server", "node2", "--config", str(config_path)]
        )

    assert result.exit_code == 0, (result.output, result.exception)
    assert connect_calls == [(("node2", "ctr-restarted"), {"ssh_key_path": None, "shell": "bash", "harness": None, "new": False})]


def test_connect_picker_offers_reaped_workspace_live_first(tmp_path: Path, monkeypatch):
    """The interactive picker (no workspace_id given) must offer reaped/
    stopped workspaces too -- ensure_running resurrects them -- not just
    active ones, since the whole point of this flow is getting back into a
    workspace the idle reaper already killed. Live workspaces must be listed
    before reaped ones."""
    config_path = _write_ssh_remote_config(tmp_path)
    monkeypatch.setattr("warren_cli.ui.is_interactive", lambda: True)

    offered_choices = []

    def _fake_select(message, choices):
        if "workspace" in message.lower():
            offered_choices.extend(c["value"] for c in choices)
        fake = MagicMock()
        fake.ask.return_value = choices[0]["value"]
        return fake

    questionary_module = MagicMock()
    questionary_module.select.side_effect = _fake_select
    questionary_module.Choice = lambda title, value: {"title": title, "value": value}
    monkeypatch.setitem(__import__("sys").modules, "questionary", questionary_module)

    fake_proc = MagicMock()
    monkeypatch.setattr(
        "warren_cli.dispatch.start_ssh_port_forward",
        lambda *a, **kw: (fake_proc, 54321),
    )
    connect_calls = []
    monkeypatch.setattr(
        "warren_cli.dispatch.connect_via_ssh_podman_exec",
        lambda *a, **kw: connect_calls.append((a, kw)),
    )

    reaped_id = "08c61556-715a-4dd0-96f1-acc5bbf989aa"
    live_id = "29872965-aaaa-bbbb-cccc-ddddeeeeffff"
    with respx.mock(base_url="http://127.0.0.1:54321") as m:
        m.get("/workspaces").mock(
            return_value=httpx.Response(200, json=[
                {"workspace_id": reaped_id, "project": "homelab", "intent": "ops",
                 "status": "stopped", "container_id": "ctr-old"},
                {"workspace_id": live_id, "project": "homelab", "intent": "ops",
                 "status": "running", "container_id": "ctr-live"},
            ])
        )
        m.post(f"/workspaces/{live_id}/ensure_running").mock(
            return_value=httpx.Response(200, json={"container_id": "ctr-live", "status": "running"})
        )

        result = runner.invoke(app, ["connect", "--config", str(config_path)])

    assert result.exit_code == 0, (result.output, result.exception)
    # The reaped workspace was offered at all (not filtered out)...
    assert reaped_id in offered_choices
    assert live_id in offered_choices
    # ...and the live one was listed first.
    assert offered_choices.index(live_id) < offered_choices.index(reaped_id)


def test_connect_falls_back_to_manual_instructions_for_non_ssh_remote(tmp_path: Path, monkeypatch):
    """A direct-URL (runtime_type="http") remote has no server host for the CLI
    to SSH into and podman-exec through, so this must fall back to a manual
    instruction rather than attempting (and failing) an attach."""
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        '[remotes.direct]\n'
        'url = "http://direct.local:8420"\n'
        'auth_token = "tok-direct"\n'
    )

    full_id = "29872965-aaaa-bbbb-cccc-ddddeeeeffff"
    with respx.mock(base_url="http://direct.local:8420") as m:
        m.get("/workspaces").mock(
            return_value=httpx.Response(200, json=[
                {"workspace_id": full_id, "project": "homelab", "intent": "ops",
                 "status": "running", "container_id": "abc123"},
            ])
        )
        m.post(f"/workspaces/{full_id}/ensure_running").mock(
            return_value=httpx.Response(200, json={"container_id": "abc123", "status": "running"})
        )

        result = runner.invoke(
            app, ["connect", full_id, "--server", "direct", "--config", str(config_path)]
        )

    assert result.exit_code == 1, (result.output, result.exception)
    assert "no direct attach path" in result.output
    assert "podman exec -it abc123 tmux attach -t main" in result.output


_DRY_RUN_PROJECT = (
    "name: demo\n"
    "docker_image: ghcr.io/example/base:latest\n"
    "folders:\n"
    "  - name: app\n"
    "    type: git-worktree\n"
    "    url: git@github.com:example/app.git\n"
    "    mount: code/app\n"
    "  - name: wiki\n"
    "    type: git-clone\n"
    "    url: https://github.com/example/wiki.git\n"
    "    mount: refs/wiki\n"
    "    readonly: true\n"
    "mounts:\n"
    "  - host: /h/data\n"
    "    container: /w/data\n"
    "    mode: ro\n"
    "templates:\n"
    "  develop:\n"
    "    app: claude\n"
    "    env:\n"
    "      OLLAMA_HOST: http://gpu:11434\n"
    "    secrets:\n"
    "      - name: ANTHROPIC_API_KEY\n"
)


def test_new_dry_run_local_prints_plan_and_never_provisions(tmp_path: Path, monkeypatch):
    projects = tmp_path / "projects"
    projects.mkdir()
    (projects / "demo.yaml").write_text(_DRY_RUN_PROJECT)
    (projects / "demo").mkdir()
    (projects / "demo" / "secrets.env").write_text("ANTHROPIC_API_KEY=sk-never-printed\n")
    config_path = tmp_path / "config.toml"
    config_path.write_text(
        f'[defaults]\nmode = "local"\nprojects_dir = "{projects.as_posix()}"\n\n[runtime]\ntype = "docker"\n'
    )
    provisioned = []
    monkeypatch.setattr("warren_cli.dispatch.provision_local", lambda *a, **kw: provisioned.append(a))

    result = runner.invoke(app, ["new", "demo", "develop", "--dry-run", "--config", str(config_path)])

    assert result.exit_code == 0, (result.output, result.exception)
    out = result.stdout
    assert "ghcr.io/example/base:latest" in out
    assert "~/code/app  git-worktree  git@github.com:example/app.git@main" in out
    assert "~/refs/wiki  git-clone ro" in out
    assert "/h/data -> /w/data (ro)" in out
    assert "ANTHROPIC_API_KEY" in out
    assert "OLLAMA_HOST" in out
    assert "sk-never-printed" not in out
    assert "local (docker)" in out
    assert not provisioned


def test_new_dry_run_server_uses_effective_project_and_never_posts(tmp_path: Path, monkeypatch):
    import yaml

    config_path = _write_ssh_remote_config(tmp_path)
    monkeypatch.setattr(
        "warren_cli.dispatch.start_ssh_port_forward", lambda *a, **kw: (MagicMock(), 54329)
    )
    effective = yaml.safe_load(_DRY_RUN_PROJECT)
    with respx.mock(base_url="http://127.0.0.1:54329", assert_all_called=False) as m:
        m.get("/projects/demo").mock(return_value=httpx.Response(200, json={"effective": effective}))
        post = m.post("/workspaces").mock(return_value=httpx.Response(500))
        result = runner.invoke(
            app, ["new", "demo", "develop", "--dry-run", "--server", "node2", "--config", str(config_path)]
        )

    assert result.exit_code == 0, (result.output, result.exception)
    assert "server node2" in result.stdout
    assert "ANTHROPIC_API_KEY" in result.stdout
    assert "ghcr.io/scottcowan/warren-ecs-base:latest (ecs)" in result.stdout
    assert not post.called
