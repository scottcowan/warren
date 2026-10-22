"""Wave 0 → GREEN: BubblewrapRuntime arg-list + state.json (Plan 05b-04).

Pins down the behavioural contract for the Linux directory-backed sandbox
sitting alongside NsjailRuntime:

  - build_bwrap_args is a pure function taking a WorkspaceSpec
  - --ro-bind-try for optional system paths (/lib64 on Debian arm64: Pitfall 3)
  - --ro-bind (mandatory) for warren-declared reference/ssh paths
  - namespace flags: --unshare-pid/--unshare-uts/--unshare-ipc/--share-net
  - provision writes state.json (schema_version=1) atomically
  - spec.image is ignored with a WARNING log (D-15, Pitfall 8)
  - prior-art attribution comment references akitaonrails/ai-jail
"""

from __future__ import annotations

import json
import os
import stat
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="bubblewrap is a Linux sandbox"
)


def _spec(root_path: str, *, image: str = "", reference_paths=None, ssh_key_paths=None):
    from warren_common.runtime.base import WorkspaceSpec

    return WorkspaceSpec(
        workspace_id="ws-bwrap-1",
        project="demo-project",
        intent="claude",
        image=image,
        root_path=root_path,
        env={"ANTHROPIC_API_KEY": "sk-test"},
        ssh_key_paths=ssh_key_paths or [],
        worktree_paths=[(f"{root_path}/main", "/workspace/main")],
        reference_paths=reference_paths or [],
        app="claude",
    )


def test_clearenv_present(tmp_path):
    """Audit finding #4: without --clearenv, bwrap's child inherits the
    CALLING process's full environment on top of --setenv — any AWS key/API
    token/SSH_AUTH_SOCK sitting in the operator's own shell would reach every
    local workspace."""
    from warren_common.runtime.bubblewrap import build_bwrap_args

    args = build_bwrap_args(_spec("/tmp/ws-root"), env_file=str(tmp_path / "env.sh"))
    assert "--clearenv" in args


def test_setenv_includes_base_host_env_not_secrets(monkeypatch, tmp_path):
    """With --clearenv dropping the inherited environment, --setenv is the
    only way the sandboxed process gets PATH/HOME/etc — base_host_env() must
    be merged in. spec.env (secrets) must NOT appear on argv at all (audit
    2026-10-16 P2 #51: --setenv values are ps-visible to every user on the
    host) — they're sourced from the bind-mounted env_file instead."""
    from warren_common.runtime.bubblewrap import build_bwrap_args

    monkeypatch.setenv("PATH", "/usr/bin:/bin")
    args = build_bwrap_args(_spec("/tmp/ws-root"), env_file=str(tmp_path / "env.sh"))
    setenv_pairs = {
        args[i + 1]: args[i + 2] for i in range(len(args) - 2) if args[i] == "--setenv"
    }
    assert setenv_pairs["PATH"] == "/usr/bin:/bin"
    assert "ANTHROPIC_API_KEY" not in setenv_pairs
    assert "sk-test" not in args


def test_arg_list_uses_ro_bind_try_for_optional_paths(tmp_path):
    from warren_common.runtime.bubblewrap import build_bwrap_args

    args = build_bwrap_args(_spec(str(tmp_path)), env_file=str(tmp_path / "env.sh"))
    # Pitfall 3: /lib64 may be absent on Debian arm64 → must be --ro-bind-try.
    idx = args.index("--ro-bind-try")
    assert args[idx + 1] == "/lib64"
    assert args[idx + 2] == "/lib64"


def test_arg_list_uses_ro_bind_for_declared_reference_mounts(tmp_path):
    from warren_common.runtime.bubblewrap import build_bwrap_args

    ref_host = tmp_path / "reference"
    ref_host.mkdir()
    spec = _spec(
        str(tmp_path),
        reference_paths=[(str(ref_host), "/reference/repo")],
        ssh_key_paths=["/home/user/.ssh/id_ed25519"],
    )
    args = build_bwrap_args(spec, env_file=str(tmp_path / "env.sh"))

    # reference path uses --ro-bind (mandatory, must exist)
    assert "--ro-bind" in args
    ridx = None
    for i in range(len(args) - 2):
        if (
            args[i] == "--ro-bind"
            and args[i + 1] == str(ref_host)
            and args[i + 2] == "/reference/repo"
        ):
            ridx = i
            break
    assert ridx is not None, f"reference --ro-bind entry missing in args={args!r}"

    # ssh key path also mandatory --ro-bind
    sidx = None
    for i in range(len(args) - 2):
        if (
            args[i] == "--ro-bind"
            and args[i + 1] == "/home/user/.ssh/id_ed25519"
            and args[i + 2] == "/home/user/.ssh/id_ed25519"
        ):
            sidx = i
            break
    assert sidx is not None, f"ssh_key --ro-bind entry missing in args={args!r}"


def test_arg_list_shape(tmp_path):
    from warren_common.runtime.bubblewrap import build_bwrap_args

    spec = _spec(str(tmp_path))
    env_file = tmp_path / "env.sh"
    args = build_bwrap_args(spec, env_file=str(env_file))

    # Namespace flags
    for flag in (
        "--die-with-parent",
        "--unshare-pid",
        "--unshare-uts",
        "--unshare-ipc",
        "--share-net",
    ):
        assert flag in args, f"missing {flag} in {args!r}"

    # System mounts
    assert args[args.index("--proc") + 1] == "/proc"
    assert args[args.index("--dev") + 1] == "/dev"
    assert args[args.index("--tmpfs") + 1] == "/tmp"

    # --bind <root> <root> and --chdir <root>
    root = str(tmp_path)
    bidx = None
    for i in range(len(args) - 2):
        if args[i] == "--bind" and args[i + 1] == root and args[i + 2] == root:
            bidx = i
            break
    assert bidx is not None, "missing --bind <root> <root>"
    assert args[args.index("--chdir") + 1] == root

    # worktree bind
    widx = None
    for i in range(len(args) - 2):
        if (
            args[i] == "--bind"
            and args[i + 1] == f"{root}/main"
            and args[i + 2] == "/workspace/main"
        ):
            widx = i
            break
    assert widx is not None, "missing worktree --bind entry"

    # --setenv KEY VALUE only for base_host_env() (PATH/HOME/TERM/LANG) — actual
    # secrets (ANTHROPIC_API_KEY) are NOT on argv (audit #51); they're sourced
    # from the bind-mounted env_file by the trailing shell wrapper instead.
    setenv_pairs = {
        args[i + 1]: args[i + 2]
        for i in range(len(args) - 2)
        if args[i] == "--setenv"
    }
    assert "ANTHROPIC_API_KEY" not in setenv_pairs
    assert "sk-test" not in args

    # env_file bind-mounted read-only at the fixed in-sandbox path.
    assert "--ro-bind" in args
    ro_idx = None
    for i in range(len(args) - 2):
        if args[i] == "--ro-bind" and args[i + 1] == str(env_file):
            ro_idx = i
            break
    assert ro_idx is not None, f"env_file --ro-bind entry missing in args={args!r}"
    env_dest = args[ro_idx + 2]

    # Terminator + shell wrapper that sources env_dest, then execs the app.
    assert args[-7] == "--"
    assert args[-6] == "/bin/sh"
    assert args[-5] == "-c"
    assert args[-3] == "sh"
    assert args[-2] == env_dest
    assert args[-1] == "claude"


@pytest.mark.asyncio
async def test_provision_writes_state_json(tmp_path, monkeypatch):
    from warren_common.runtime.bubblewrap import BubblewrapRuntime

    fake = tmp_path / "bwrap"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ.get('PATH', '')}")
    # state.json lives OUTSIDE root (finding #1) — WARREN_STATE_DIR keeps this
    # test from writing into the real operator ~/.warren/state/.
    state_root = tmp_path / "state"
    monkeypatch.setenv("WARREN_STATE_DIR", str(state_root))

    root = tmp_path / "ws"
    root.mkdir()
    rt = BubblewrapRuntime(server_id="test-host")
    handle = await rt.provision(_spec(str(root)))

    assert stat.S_IMODE(root.stat().st_mode) == 0o700
    assert not (root / "state.json").exists(), "state.json must not live under root_path"
    state_path = Path(handle.state_dir) / "state.json"
    assert state_path.exists()
    state = json.loads(state_path.read_text())
    assert state["schema_version"] == 1
    for key in ("workspace_id", "project", "intent", "app", "created_at"):
        assert key in state


@pytest.mark.asyncio
async def test_ignores_spec_image_with_warning(tmp_path, monkeypatch):
    from structlog.testing import capture_logs

    from warren_common.runtime.bubblewrap import BubblewrapRuntime

    fake = tmp_path / "bwrap"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(fake.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ.get('PATH', '')}")
    monkeypatch.setenv("WARREN_STATE_DIR", str(tmp_path / "state"))

    root = tmp_path / "ws-image"
    root.mkdir()
    rt = BubblewrapRuntime(server_id="test-host")
    # Captured at the structlog level: other suites (warren-cli) reconfigure where
    # rendered records go, so stdout isn't a reliable place to look for them.
    with capture_logs() as logs:
        await rt.provision(_spec(str(root), image="ghcr.io/warren/agent:latest"))

    ignored = [e for e in logs if e["event"] == "bubblewrap_image_ignored"]
    assert len(ignored) == 1
    assert ignored[0]["log_level"] == "warning"
    assert ignored[0]["image"] == "ghcr.io/warren/agent:latest"
    assert "ignored" in ignored[0]["reason"]


def test_prior_art_attribution_comment():
    import warren_common.runtime.bubblewrap as mod

    src = Path(mod.__file__).read_text()
    assert "akitaonrails/ai-jail" in src, "missing prior-art attribution comment"


@pytest.mark.asyncio
async def test_preflight_raises_when_bwrap_missing(tmp_path, monkeypatch):
    from warren_common.errors import RuntimeUnreachable
    from warren_common.runtime.bubblewrap import BubblewrapRuntime

    monkeypatch.setenv("PATH", str(tmp_path))  # empty dir → no bwrap
    rt = BubblewrapRuntime(server_id="test-host")
    with pytest.raises(RuntimeUnreachable) as ei:
        rt.preflight()
    assert "bwrap" in str(ei.value).lower()


@pytest.mark.asyncio
async def test_provision_records_absolute_bwrap_path_and_exec_uses_it(tmp_path, monkeypatch):
    """AE2: bwrap is resolved to an absolute path once, at provision, and exec
    uses that path rather than a fresh PATH lookup."""
    from unittest.mock import AsyncMock, patch

    from warren_common.runtime.bubblewrap import BubblewrapRuntime

    bindir = tmp_path / "bin"
    bindir.mkdir()
    fake = bindir / "bwrap"
    fake.write_text("#!/bin/sh\nexit 0\n")
    fake.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bindir}:/usr/bin:/bin")
    monkeypatch.setenv("WARREN_STATE_DIR", str(tmp_path / "state"))
    root = tmp_path / "ws"
    root.mkdir()
    rt = BubblewrapRuntime(server_id="test-host")
    handle = await rt.provision(_spec(str(root)))
    state = json.loads((Path(handle.state_dir) / "state.json").read_text())
    assert state["bwrap_path"] == os.path.realpath(fake)

    planted = tmp_path / "planted"
    planted.mkdir()
    (planted / "bwrap").write_text("#!/bin/sh\n")
    (planted / "bwrap").chmod(0o755)
    monkeypatch.setenv("PATH", f"{planted}:/usr/bin:/bin")

    captured = {}

    class _Proc:
        stdout = AsyncMock()

        async def wait(self):
            return 0

    _Proc.stdout.read = AsyncMock(side_effect=[b""])

    async def _create(*args, **kwargs):
        captured["args"] = args
        return _Proc()

    with patch("asyncio.create_subprocess_exec", side_effect=_create):
        async for _ in rt.exec(handle, ["true"]):
            pass
    assert captured["args"][0] == os.path.realpath(fake)


def test_reference_clones_are_read_only_binds(tmp_path):
    """AE1 equivalent: every reference path is a read-only bind, so its git
    dir can't be renamed or rewritten inside bwrap."""
    from warren_common.runtime.bubblewrap import build_bwrap_args

    ref = tmp_path / "ref"
    ref.mkdir()
    args = build_bwrap_args(_spec(str(tmp_path), reference_paths=[(str(ref), str(ref))]), env_file="/e")
    binds = [(args[i], args[i + 1]) for i in range(len(args) - 1) if args[i + 1] == str(ref) and args[i].startswith("--")]
    assert binds == [("--ro-bind", str(ref))]


# --- AC2: WSL1 refusal and AppArmor userns guidance ------------------------


def test_preflight_refuses_wsl1(monkeypatch):
    from warren_common import wsl
    from warren_common.errors import RuntimeUnreachable
    from warren_common.runtime.bubblewrap import BubblewrapRuntime

    monkeypatch.setattr(wsl, "wsl_version", lambda: 1)
    with pytest.raises(RuntimeUnreachable) as ei:
        BubblewrapRuntime(server_id="t").preflight()
    assert "WSL1" in str(ei.value)


@pytest.mark.skipif(sys.platform == "win32", reason="fake bwrap is a sh script")
def test_preflight_prints_apparmor_fix(tmp_path, monkeypatch):
    from warren_common import wsl
    from warren_common.errors import RuntimeUnreachable
    from warren_common.runtime.bubblewrap import BubblewrapRuntime

    fake = tmp_path / "bwrap"
    fake.write_text("#!/bin/sh\necho 'bwrap: setting up uid map: Permission denied' >&2\nexit 1\n")
    fake.chmod(0o755)
    restrict = tmp_path / "restrict"
    restrict.write_text("1\n")
    monkeypatch.setattr(wsl, "PROC_APPARMOR_USERNS", str(restrict))
    monkeypatch.setattr(wsl, "wsl_version", lambda: 2)
    monkeypatch.setenv("PATH", str(tmp_path))
    with pytest.raises(RuntimeUnreachable) as ei:
        BubblewrapRuntime(server_id="t").preflight()
    assert "bwrap-userns-restrict" in str(ei.value)
    assert "uid map" not in str(ei.value)


def test_harness_binds_are_union_with_readonly_rebound_last(tmp_path):
    """AG6: only the template's harnesses are bound; readonly entries ro after the rw dir."""
    from dataclasses import replace

    from warren_common.runtime.bubblewrap import build_bwrap_args

    hroot = str(tmp_path / "harness")
    spec = replace(_spec(str(tmp_path / "ws")), app="bash", harnesses=["codex"], harness_root=hroot)
    args = build_bwrap_args(spec, env_file="/e")
    pairs = [(args[i], args[i + 1]) for i in range(len(args) - 1)]
    rw = pairs.index(("--bind-try", f"{hroot}/codex"))
    ro = pairs.index(("--ro-bind-try", f"{hroot}/codex/config.toml"))
    assert rw < ro
    binds = [v for flag, v in pairs if "bind" in flag]
    assert not any(v.endswith((".claude", ".codex")) or f"{hroot}/claude" in v for v in binds)
