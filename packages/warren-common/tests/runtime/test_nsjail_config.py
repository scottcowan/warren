"""Wave 0 RED: NsjailConfig dataclass -> proto text serialiser (Plan 05-02).

xfail-guarded on the yet-to-exist module. Tests assert:
  - byte-identical output vs golden fixture
  - D-03: exactly one non-comment `clone_newnet: false` line
  - env quoting escapes `"` and `\\`
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="nsjail is a Linux sandbox"
)

HERE = Path(__file__).parent
GOLDEN = HERE / "golden" / "minimal.cfg.golden"


def _canonical_config():
    from warren_common.runtime.nsjail_config import MountEntry, NsjailConfig

    return NsjailConfig(
        mode="ONCE",
        hostname="warren-abc123",
        cwd="/workspace/main",
        keep_env=False,
        clone_newnet=False,
        envar=["HOME=/workspace", "PATH=/usr/local/bin:/usr/bin:/bin"],
        mounts=[
            MountEntry(src="/bin", dst="/bin", rw=False),
            MountEntry(src="/usr", dst="/usr", rw=False),
            MountEntry(src="/workspaces/abc/main", dst="/workspace/main", rw=True),
        ],
        uid_inside=1000,
        uid_outside=1000,
        rlimit_nofile=4096,
    )


def test_serialiser_matches_golden():
    cfg = _canonical_config()
    got = cfg.to_proto_text()
    expected = GOLDEN.read_text()
    assert got == expected


def test_clone_newnet_true_by_default():
    """D-03 default-deny-network: `clone_newnet: true` is what puts the
    jailed process into a fresh, interface-less net namespace -- `false`
    would leave it sharing the HOST's network namespace (audit 2026-10-16
    P2 #51 found the default inverted from what the old comment claimed)."""
    from warren_common.runtime.nsjail_config import NsjailConfig

    text = NsjailConfig().to_proto_text()
    non_comment = [
        line for line in text.splitlines() if not line.lstrip().startswith("#")
    ]
    matches = [line for line in non_comment if "clone_newnet: true" in line]
    assert len(matches) == 1, (
        f"expected exactly one non-comment clone_newnet: true line, got {matches!r}"
    )


def test_env_quoting_escapes():
    from warren_common.runtime.nsjail_config import NsjailConfig

    cfg = NsjailConfig(envar=['KEY=a"b\\c'])
    text = cfg.to_proto_text()
    # Both the backslash and the quote must be escaped in proto text form.
    assert 'envar: "KEY=a\\"b\\\\c"' in text


def _spec(workspace_id: str = "ws-abc12345", **overrides):
    from warren_common.runtime.base import WorkspaceSpec

    kwargs = dict(
        workspace_id=workspace_id,
        project="demo",
        intent="claude",
        image="",
        root_path="/var/lib/warren/workspaces/ws-abc12345",
        env={"ANTHROPIC_API_KEY": "sk-test-should-never-appear-in-cfg"},
    )
    kwargs.update(overrides)
    return WorkspaceSpec(**kwargs)


def test_from_spec_never_puts_secret_values_in_envar():
    """S6: spec.env (secrets) used to go straight into plaintext `envar:`
    lines in nsjail.cfg, where they'd sit on disk for the workspace's whole
    lifetime. from_spec() must never do that -- secrets travel via the
    short-lived bind-mounted env file instead (NsjailRuntime.exec())."""
    from warren_common.runtime.nsjail_config import NsjailConfig

    cfg = NsjailConfig.from_spec(_spec())

    assert cfg.envar == []
    text = cfg.to_proto_text()
    assert "sk-test-should-never-appear-in-cfg" not in text
    assert "ANTHROPIC_API_KEY" not in text


def test_from_spec_mounts_secret_env_file_at_fixed_path():
    """The mandatory bind mount NsjailRuntime.exec() relies on to deliver
    secrets into the jail -- src is the deterministic per-workspace path
    exec() writes fresh on every call, dst is the fixed in-jail path the
    shell wrapper sources from."""
    from warren_common.runtime.nsjail_config import NsjailConfig
    from warren_common.runtime.sandbox_env import ENV_MOUNT_DEST, nsjail_secret_env_path

    cfg = NsjailConfig.from_spec(_spec())

    matches = [m for m in cfg.mounts if m.dst == ENV_MOUNT_DEST]
    assert len(matches) == 1, f"expected exactly one mount at {ENV_MOUNT_DEST}, got {cfg.mounts!r}"
    entry = matches[0]
    assert entry.src == str(nsjail_secret_env_path("ws-abc12345"))
    assert entry.rw is False
    assert entry.mandatory is True


def test_from_spec_emits_pasta_network_block_when_isolated():
    """S6 follow-up: clone_newnet: true alone puts the jail in an
    interface-less netns -- no git fetch, no API calls, nothing. PASTA gives
    it unprivileged outbound NAT without sharing the host's own network
    namespace or needing CAP_NET_ADMIN."""
    from warren_common.runtime.nsjail_config import NsjailConfig

    cfg = NsjailConfig.from_spec(_spec())
    text = cfg.to_proto_text()

    assert cfg.clone_newnet is True
    assert cfg.pasta_network is True
    assert "backend: PASTA" in text
    assert "user_net {" in text


def test_pasta_block_omitted_when_clone_newnet_false():
    """The PASTA block only makes sense paired with an isolated netns --
    it must not appear when clone_newnet is false (shares the host netns,
    needs no NAT setup of its own)."""
    from warren_common.runtime.nsjail_config import NsjailConfig

    cfg = NsjailConfig(clone_newnet=False, pasta_network=True)
    text = cfg.to_proto_text()

    assert "user_net {" not in text
    assert "PASTA" not in text


def test_from_spec_mounts_only_selected_harness_dirs():
    """AG6: harness dir rw, its readonly entries ro after it, nothing for other harnesses."""
    from warren_common.runtime.nsjail_config import NsjailConfig

    hroot = "/st/ws-abc12345/harness"
    cfg = NsjailConfig.from_spec(_spec(app="bash", harnesses=["pi"], harness_root=hroot))
    mounts = [(m.src, m.rw) for m in cfg.mounts]
    rw = mounts.index((f"{hroot}/pi/sessions", True))
    ro = mounts.index((f"{hroot}/pi/settings.json", False))
    assert rw < ro
    assert not any(src and ("/claude" in src or "/.codex" in src) for src, _ in mounts)
