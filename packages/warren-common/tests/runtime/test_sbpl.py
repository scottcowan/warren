"""Wave 0 GREEN: SBPL builder ordering + global-read allow (Plan 05b-05)."""

from __future__ import annotations

import re
import sys

import pytest

from warren_common.models import FolderSpec
from warren_common.runtime import sbpl
from warren_common.runtime.base import WorkspaceSpec


def build_sbpl_profile(spec: WorkspaceSpec) -> str:
    """The generated profile with each `(param "K")` replaced by its quoted
    value, so assertions can name paths directly."""
    profile = sbpl.build_sbpl_profile(spec)
    return re.sub(r'\(param "([A-Z0-9_]+)"\)', lambda m: f'"{profile.params[m.group(1)]}"', profile.text)

pytestmark = pytest.mark.skipif(
    sys.platform == "win32", reason="seatbelt profiles are macOS-only"
)


def _spec(**over) -> WorkspaceSpec:
    kw = dict(
        workspace_id="ws-1",
        project="proj",
        intent="int",
        image="",
        root_path="/tmp/ws-root",
    )
    kw.update(over)
    return WorkspaceSpec(**kw)


def test_global_file_read_allow_present():
    profile = build_sbpl_profile(_spec())
    assert '(allow file-read* (literal "/"))' in profile


# --- Audit finding #2 (2026-10-16): seatbelt's file-read* used to be global,
# letting any local workspace read every OTHER workspace's state.json
# (decrypted secrets), ~/.ssh/id_*, ~/.aws/credentials, etc. ---------------


def test_no_unscoped_global_file_read():
    """The unscoped `(allow file-read*)` (no path restriction at all) must be
    gone — every remaining file-read* grant must be qualified by a path
    clause (literal/subpath/regex)."""
    profile = build_sbpl_profile(_spec())
    for line in profile.splitlines():
        s = line.strip()
        if s.startswith("(allow file-read*") and s != "(allow file-read*)":
            continue
        assert s != "(allow file-read*)", f"found unscoped global file-read*: {line!r}"


def test_other_workspace_root_not_in_read_scope():
    """A workspace's profile must not grant read on a sibling workspace's
    root_path — only its own."""
    profile = build_sbpl_profile(_spec(root_path="/Users/me/.warren/workspaces/ws-1"))
    assert '(subpath "/Users/me/.warren/workspaces/ws-1")' in profile
    assert '(subpath "/Users/me/.warren/workspaces/ws-2")' not in profile


def test_ssh_dir_itself_not_readable_only_declared_keys():
    """Only specific declared ssh_key_paths get a grant — never the whole
    ~/.ssh directory (which would expose every OTHER key on the host too)."""
    profile = build_sbpl_profile(_spec(ssh_key_paths=["/Users/me/.ssh/id_ed25519"]))
    assert '/Users/me/.ssh/id_ed25519"' in profile
    assert '(subpath "/Users/me/.ssh")' not in profile


def test_ssh_key_paths_are_readable_not_just_writable():
    """Z3 (2026-10-17): declared ssh key files used to be granted WRITE-only
    (a stale comment claimed read was "covered separately" — it never was),
    so ssh itself couldn't read its own key. Keys must be read-only, matching
    bubblewrap.py's --ro-bind and nsjail_config.py's rw=False for the same
    paths — never write."""
    key = "/Users/me/.ssh/id_ed25519"
    profile = build_sbpl_profile(_spec(ssh_key_paths=[key]))
    assert f'(allow file-read* (subpath "{key}"))' in profile
    assert f'(allow file-write* (subpath "{key}"))' not in profile


def test_ssh_agent_socket_is_read_write():
    """The agent socket is a live bidirectional connect, not file content —
    unlike key files it needs both directions, matching the other two
    runtimes' rw bind for the same path."""
    sock = "/private/tmp/ssh-agent.sock"
    profile = build_sbpl_profile(_spec(ssh_agent_sock=sock))
    assert f'(allow file-read* (subpath "{sock}"))' in profile
    assert f'(allow file-write* (subpath "{sock}"))' in profile


# --- Audit finding #3 (2026-10-16): seatbelt granted WRITE to ~/.aws (whole
# dir — credential_process host-code-execution), ~/.config (git hooks /
# core.fsmonitor — same host-code-execution path), the dir `uv` lives in
# (binary replacement), and ~/.warren/projects (local-path folder-spec
# escalation). All four must be write-denied; ~/.aws may still be READ (the
# AWS opt-in path only needs read). -----------------------------------------


def test_aws_dir_not_writable():
    """~/.aws/config and ~/.aws/credentials must never be write-allowed — in
    `sso` mode only the SSO token cache is (`aws sso login` needs it), and a
    writable ~/.aws/config could plant a credential_process that runs on the
    HOST."""
    from warren_common.models import AwsConfig

    for aws in (None, AwsConfig(mode="export"), AwsConfig(mode="sso", profile="dev")):
        profile = build_sbpl_profile(_spec(aws=aws))
        for line in profile.splitlines():
            if '(allow file-write* (subpath "' not in line or "/.aws" not in line:
                continue
            assert line.rstrip().endswith('/.aws/sso/cache"))'), line


def test_aws_export_mode_grants_no_host_aws_paths():
    """AK3: `export` (the default) reaches no host AWS file at all — the SSO
    token cache could mint credentials for every account and role."""
    from warren_common.models import AwsConfig

    for aws in (None, AwsConfig(profile="dev")):
        profile = build_sbpl_profile(_spec(aws=aws))
        assert "/.aws" not in profile


def test_aws_sso_mode_narrow_grants(tmp_path):
    """AK3 `sso`: token cache read-write, config read-only, no credentials file,
    and no ~/.aws/sso parent grant."""
    import os

    from warren_common.models import AwsConfig

    home = os.path.realpath(os.path.expanduser("~"))
    profile = build_sbpl_profile(_spec(aws=AwsConfig(mode="sso", profile="dev")))
    cache, config = f"{home}/.aws/sso/cache", f"{home}/.aws/config"
    assert f'(allow file-write* (subpath "{cache}"))' in profile
    assert f'(allow file-read* (subpath "{cache}"))' in profile
    assert f'(allow file-read* (subpath "{config}"))' in profile
    assert f'(allow file-write* (subpath "{config}"))' not in profile
    assert f'"{home}/.aws/sso"' not in profile
    assert "/.aws/credentials" not in profile
    assert f'(subpath "{home}/.aws")' not in profile


def test_config_dir_not_writable():
    profile = build_sbpl_profile(_spec())
    for line in profile.splitlines():
        if "(allow file-write*" in line:
            assert line.rstrip().endswith('/.config"))') is False, (
                f"~/.config must not be write-allowed (git hooks / fsmonitor): {line!r}"
            )


def test_uv_bin_dir_not_writable(monkeypatch, tmp_path):
    fake_uv_dir = tmp_path / "bin"
    fake_uv_dir.mkdir()
    fake_uv = fake_uv_dir / "uv"
    fake_uv.write_text("#!/bin/sh\n")
    fake_uv.chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake_uv_dir}:{__import__('os').environ.get('PATH', '')}")

    profile = build_sbpl_profile(_spec())
    assert f'(allow file-write* (subpath "{fake_uv_dir}"))' not in profile
    # Still readable — just not writable (writable would let a workspace
    # replace the uv/claude binaries themselves, which then run on the HOST).
    assert f'(allow file-read* (subpath "{fake_uv_dir}"))' in profile


def test_warren_projects_never_writable():
    """~/.warren/projects must never be write-allowed from inside a sandboxed
    workspace — a workspace could otherwise declare a local-path folder spec
    pointing at `/`, and the NEXT workspace provisioned would get write
    access there too."""
    profile = build_sbpl_profile(_spec())
    assert "/.warren/projects" not in profile


def test_warren_projects_reference_folder_never_writable():
    """Same as above, but actually exercising a reference folder (R4,
    2026-10-17 review: the test above alone passes even with a reference path
    configured, since reference_paths/folders live outside ~/.warren/projects
    in this builder's own data model — this test pins the real-world case: a
    git-clone reference folder under ~/.warren/projects/<project>/references/
    must never get an unconditional write grant, and even where one exists
    (non-readonly, the default), its own .git/hooks and .git/config must
    still be denied."""
    ref_host = "/Users/me/.warren/projects/proj/references/wiki"
    spec = _spec(
        reference_paths=[(ref_host, "wiki")],
        folders=[
            FolderSpec(
                name="wiki", type="git-clone", mount="wiki",
                url="git@example:wiki.git", readonly=False,
            )
        ],
    )
    profile = build_sbpl_profile(spec)
    assert f'(allow file-write* (subpath "{ref_host}"))' in profile
    assert f'(deny file-write* (subpath "{ref_host}/.git/hooks"))' in profile
    assert f'(deny file-write* (literal "{ref_host}/.git/config"))' in profile


def test_reference_git_hooks_and_config_always_write_denied():
    """R4: regardless of FolderSpec.readonly (default False — advisory, not a
    security boundary), a reference clone's own .git/hooks/.git/config must
    never be write-allowed -- a workspace could otherwise plant
    core.fsmonitor or a post-checkout hook there that runs on the HOST,
    unsandboxed, the next time `warren` fetches that same reference clone
    outside any workspace (same class as finding #3)."""
    ref_host = "/Users/me/.warren/projects/proj/references/other-repo"
    spec = _spec(
        reference_paths=[(ref_host, "refs/other-repo")],
        folders=[
            FolderSpec(
                name="other-repo", type="git-clone", mount="refs/other-repo",
                url="git@example:x.git",
            )
        ],
    )
    profile = build_sbpl_profile(spec)
    assert f'(deny file-write* (subpath "{ref_host}/.git/hooks"))' in profile
    assert f'(deny file-write* (literal "{ref_host}/.git/config"))' in profile
    # The deny must come after the folder's own write grant (last-match-wins).
    lines = profile.splitlines()
    write_idx = next(
        i for i, ln in enumerate(lines)
        if ln.strip() == f'(allow file-write* (subpath "{ref_host}"))'
    )
    deny_idx = next(
        i for i, ln in enumerate(lines)
        if ln.strip() == f'(deny file-write* (literal "{ref_host}/.git/config"))'
    )
    assert deny_idx > write_idx


# --- Audit finding #5 (2026-10-16): FolderSpec.readonly was advisory only —
# never actually enforced in the seatbelt profile. ---------------------------


def test_readonly_reference_path_gets_no_write_grant():
    spec = _spec(
        reference_paths=[("/Users/me/wiki", "wiki")],
        folders=[
            FolderSpec(name="wiki", type="local-path", mount="wiki", path="~/wiki", readonly=True)
        ],
    )
    profile = build_sbpl_profile(spec)
    assert '(allow file-write* (subpath "/Users/me/wiki"))' not in profile
    # Still readable.
    assert '(allow file-read* (subpath "/Users/me/wiki"))' in profile


def test_non_readonly_reference_path_still_gets_write_grant():
    spec = _spec(
        reference_paths=[("/Users/me/other-repo", "refs/other-repo")],
        folders=[
            FolderSpec(
                name="other-repo", type="git-clone", mount="refs/other-repo",
                url="git@example:x.git", readonly=False,
            )
        ],
    )
    profile = build_sbpl_profile(spec)
    assert '(allow file-write* (subpath "/Users/me/other-repo"))' in profile


def test_bind_mount_ro_mode_gets_no_write_grant():
    spec = _spec(bind_mounts=[("/host/ro-data", "/container/ro-data", "ro")])
    profile = build_sbpl_profile(spec)
    assert '(allow file-write* (subpath "/host/ro-data"))' not in profile
    assert '(allow file-read* (subpath "/host/ro-data"))' in profile


def test_bind_mount_rw_mode_gets_write_grant():
    spec = _spec(bind_mounts=[("/host/rw-data", "/container/rw-data", "rw")])
    profile = build_sbpl_profile(spec)
    assert '(allow file-write* (subpath "/host/rw-data"))' in profile


def test_header_and_deny_default():
    profile = build_sbpl_profile(_spec())
    lines = [ln.strip() for ln in profile.splitlines() if ln.strip()]
    assert lines[0] == "(version 1)"
    assert lines[1] == "(deny default)"


def test_deny_after_allow_ordering():
    # v1.0 has no denies, but the builder's self-guard must accept the
    # ordering it produces. Any deny in the profile must occur after
    # every allow rule (last-match-wins semantics — Pitfall 4).
    profile = build_sbpl_profile(_spec())
    last_allow = -1
    first_deny_after_default = -1
    lines = profile.splitlines()
    for i, ln in enumerate(lines):
        stripped = ln.strip()
        if stripped.startswith("(allow "):
            last_allow = i
        # Ignore the mandatory "(deny default)" header at line ~2.
        if stripped.startswith("(deny ") and not stripped.startswith("(deny default"):
            if first_deny_after_default == -1:
                first_deny_after_default = i
    if first_deny_after_default != -1:
        assert first_deny_after_default > last_allow


def test_workspace_write_subpath_present():
    profile = build_sbpl_profile(_spec(root_path="/Users/me/warren/ws-1"))
    assert '(allow file-write* (subpath "/Users/me/warren/ws-1"))' in profile
    assert '(allow file-write* (subpath "/tmp"))' in profile
    assert '(allow file-write* (subpath "/private/tmp"))' in profile
    assert '(allow file-write* (subpath "/private/var/folders"))' in profile


def test_required_allow_blocks_present():
    profile = build_sbpl_profile(_spec())
    for needle in (
        "(allow process-exec)",
        "(allow process-fork)",
        "(allow process-info* (target same-sandbox))",
        "(allow signal)",
        "(allow sysctl-read)",
        "(allow mach-lookup)",
        "(allow mach-register)",
        "(allow mach-host*)",
        "(allow ipc-posix-shm-read-data)",
        "(allow ipc-posix-shm-write-data)",
        "(allow ipc-posix-shm-read-metadata)",
        "(allow ipc-posix-shm-write-create)",
        "(allow ipc-posix-sem)",
        "(allow pseudo-tty)",
        "(allow file-ioctl)",
        '(allow file-read* file-write* (literal "/dev/ptmx"))',
        '(allow file-read* file-write* (regex #"^/dev/ttys[0-9]+"))',
        '(allow file-write* (literal "/dev/null"))',
        '(allow file-write* (literal "/dev/zero"))',
        '(allow file-write* (literal "/dev/random"))',
        '(allow file-write* (literal "/dev/urandom"))',
        "(allow iokit-open)",
        "(allow network-outbound)",
        "(allow network-inbound)",
        "(allow network-bind)",
        "(allow system-socket)",
    ):
        assert needle in profile, f"missing: {needle}"


def test_paths_are_parameters_not_profile_text():
    """AE3: host paths reach sandbox-exec only as `-D` parameters, so quoting
    and escaping in a path can't change the profile's meaning."""
    root = '/Users/me/weird") (allow file-write* (subpath "x'
    profile = sbpl.build_sbpl_profile(_spec(root_path=root))
    assert "weird" not in profile.text
    assert root in profile.params.values()
    assert "(allow file-write* (subpath (param " in profile.text
    args = sbpl.sandbox_exec_param_args(profile.params)
    assert args[0] == "-D" and "=" in args[1]


def test_path_param_rejects_newline():
    with pytest.raises(ValueError):
        sbpl.build_sbpl_profile(_spec(root_path="/tmp/bad\npath"))


def test_paths_are_canonicalized_with_realpath(tmp_path):
    """AA3: seatbelt matches resolved paths, so a grant written via a symlink
    (e.g. /tmp -> /private/tmp) silently fails. Every path is realpath'd."""
    real = tmp_path / "real-ref"
    real.mkdir()
    link = tmp_path / "link-ref"
    link.symlink_to(real)
    profile = build_sbpl_profile(
        _spec(root_path="/tmp/ws-root", reference_paths=[(str(link), "ref")])
    )
    assert '(allow file-write* (subpath "/private/tmp/ws-root"))' in profile
    assert f'(allow file-read* (subpath "{real}"))' in profile
    assert str(link) not in profile


def test_no_unrestricted_appleevent_send():
    """Audit finding #50: unrestricted appleevent-send would let a sandboxed
    process send Apple Events to ANY running app -- including Terminal/System
    Events, which accept Apple Events like "do shell script"/"keystroke" and
    would run them unsandboxed, a known macOS sandbox-escape vector. Verified
    (sandbox-exec) that `open <url>` launches the browser via lsopen alone,
    with no appleevent-send grant needed."""
    profile = build_sbpl_profile(_spec())
    assert "(allow appleevent-send)" not in profile


# --- R2 (2026-10-17): sandbox-exec broke normal use (external review of #50's
# fix). Each grant below was verified against the real binary under real
# sandbox-exec, not just reasoned about — see the agent's report. -----------


def test_xcode_select_and_sh_shim_readable():
    """git (via the Xcode CLI tools shim) and /bin/sh both resolve through
    /private/var/select/* on every invocation."""
    profile = build_sbpl_profile(_spec())
    assert '(allow file-read* (subpath "/private/var/select/developer_dir"))' in profile
    assert '(allow file-read* (literal "/private/var/select/sh"))' in profile


def test_git_global_config_readable():
    """git reads its global config (XDG ~/.config/git/config or ~/.gitconfig)
    before doing anything else — git --version itself fails without this."""
    profile = build_sbpl_profile(_spec())
    assert any(
        line.strip().startswith("(allow file-read*") and "/.config/git" in line
        for line in profile.splitlines()
    )
    assert any(
        line.strip().startswith("(allow file-read*") and line.rstrip().endswith('/.gitconfig"))')
        for line in profile.splitlines()
    )


def test_opt_metadata_readable_for_realpath():
    """Homebrew's awscli calls realpath() through /opt at startup; stat()'ing
    /opt itself needs metadata read even though content lives under the
    already-granted /opt/homebrew subpath."""
    profile = build_sbpl_profile(_spec())
    assert '(allow file-read-metadata (literal "/opt"))' in profile


def test_git_store_paths_readable_not_writable():
    """A worktree's bare `.git-store` (outside root_path, under
    ~/.warren/projects/<project>/) must be readable so git can resolve
    refs/objects from the worktree -- but never writable, since a workspace
    writing hooks/config into its own bare store would be a host-code-
    execution path on the next git operation against that store outside the
    sandbox (same class as finding #3)."""
    bare = "/Users/me/.warren/projects/proj/repo.git-store"
    profile = build_sbpl_profile(_spec(git_store_paths=[bare]))
    assert f'(allow file-read* (subpath "{bare}"))' in profile
    assert f'(allow file-write* (subpath "{bare}"))' not in profile


def test_home_and_warren_metadata_readable_for_path_resolution():
    """git/realpath must stat() every ancestor directory when resolving a
    worktree's gitdir pointer into ~/.warren/projects/.../*.git-store — without
    metadata (not content) read on the home dir and ~/.warren, this fails with
    `fatal: Invalid path '/Users'` even though both endpoints are otherwise
    correctly granted."""
    from pathlib import Path as _P

    profile = build_sbpl_profile(_spec())
    home = str(_P.home())
    assert f'(allow file-read-metadata (literal "{home}"))' in profile
    assert f'(allow file-read-metadata (subpath "{home}/.warren"))' in profile


def test_uv_cache_and_npx_cache_write_denied():
    """R4: ~/.cache and ~/.npm are otherwise broadly read-write (zsh/oh-my-zsh
    caches etc.), but ~/.cache/uv (uv can run sdist build scripts from it) and
    ~/.npm/_npx (npx directly executes whatever's cached there) are genuinely
    HOST-executed, not just read as data -- so a workspace poisoning either
    would run on the HOST the next time the operator's own uv/npx shares that
    cache, outside any sandbox."""
    profile = build_sbpl_profile(_spec())
    for p in ("/.cache/uv", "/.npm/_npx"):
        assert any(
            ln.strip().startswith("(deny file-write*") and p in ln
            for ln in profile.splitlines()
        ), f"missing deny for {p}"
    # ~/.cache/uv stays readable (uv needs this).
    assert any(
        ln.strip().startswith("(allow file-read*") and "/.cache/uv" in ln
        for ln in profile.splitlines()
    )


# --- W1/W2 (Round 5 audit, 2026-10-17): the HOST's own unsandboxed zsh sources
# ~/.zcompdump as part of compinit, and the host's own Claude Code loads/executes
# plugin hooks and MCP servers from ~/.claude/{plugins,skills,agents,commands,hooks} --
# both were previously write-allowed from inside the sandbox, a host-code-execution
# path (not merely a sandbox escape), since a sandboxed/compromised agent process
# could plant something there that runs on the HOST, unsandboxed, the next time the
# real user opens a terminal or starts Claude Code normally. Denials verified
# empirically against a real generated profile with `sandbox-exec`: writes to
# ~/.zcompdump, ~/.cache/oh-my-zsh/<file>, and each of the five ~/.claude subdirs all
# returned "Operation not permitted"; reads and workspace-root writes were
# unaffected. ---------------------------------------------------------------------


def test_zcompdump_and_oh_my_zsh_cache_write_denied():
    """W1: both are sourced/executed by the HOST's own unsandboxed zsh (compinit /
    oh-my-zsh's plugin framework) -- a sandboxed process writing a malicious shell
    function into either gets it executed the next time the real user opens an
    ordinary terminal, completely outside any warren sandbox."""
    profile = build_sbpl_profile(_spec())
    for p in ("/.zcompdump", "/.cache/oh-my-zsh", "/.oh-my-zsh/cache"):
        assert any(
            ln.strip().startswith("(deny file-write*") and p in ln
            for ln in profile.splitlines()
        ), f"missing deny for {p}"
    # Still readable as plain data (e.g. an already-populated compdump).
    assert any(
        ln.strip().startswith("(allow file-read*") and "/.zcompdump" in ln
        for ln in profile.splitlines()
    )


# --- S7 (2026-10-17): the appleevent-send fix (finding #50) was incomplete;
# other Apple-Events-adjacent exit routes were reviewed. See sbpl.py's
# _IOKIT docstring for the full reasoning behind each. ----------------------


def test_lsopen_still_granted_known_residual_risk():
    """lsopen is KNOWN to still be a sandbox escape (verified empirically:
    `open -a Terminal` under a real generated profile launches Terminal.app
    outside the sandbox) -- this test exists so that pins this as a
    documented, tracked gap rather than a silent one. It intentionally
    asserts the CURRENT (unresolved) state; flip it only alongside an actual
    fix (a working narrower lsopen filter, verified against both the escape
    AND the legitimate `open <url>` browser-launch case, or a
    warren-brokered-open replacement)."""
    profile = build_sbpl_profile(_spec())
    assert "(allow lsopen)" in profile


def test_mach_lookup_and_iokit_open_left_broad_by_design():
    """mach-lookup/mach-register are required for any macOS binary to even
    start (per this module's own long-standing comment) and iokit-open is
    needed for ordinary power/battery/display queries -- both reviewed (S7)
    and left unrestricted rather than guess at a narrower grant that could
    break basic binary startup."""
    profile = build_sbpl_profile(_spec())
    assert "(allow mach-lookup)" in profile
    assert "(allow mach-register)" in profile
    assert "(allow iokit-open)" in profile


def test_attribution_present_in_module():
    from pathlib import Path

    src = Path(__file__).parent.parent.parent / "src/warren_common/runtime/sbpl.py"
    text = src.read_text()
    assert "akitaonrails/ai-jail" in text


# --- AG6: harness grants are the union over the template's harnesses; host
# harness config is never granted (AA1, AG3). ---------------------------------


def _home():
    import os

    return os.path.realpath(os.path.expanduser("~"))


_HROOT = "/tmp/warren-state/ws-1/harness"
_ALL_HOST_CONFIG = (".claude", ".claude.json", ".codex", ".config/opencode", ".local/share/opencode", ".cursor", ".pi", ".copilot", ".qwen")


@pytest.mark.parametrize("harnesses", [[], ["claude"], ["codex"], ["claude", "codex", "opencode", "cursor-agent", "pi"]])
def test_every_known_harness_host_config_write_denied_never_granted(harnesses):
    home = _home()
    profile = build_sbpl_profile(_spec(app="claude", harnesses=harnesses, harness_root=_HROOT))
    for rel in _ALL_HOST_CONFIG:
        assert f'(deny file-write* (subpath "{home}/{rel}"))' in profile, rel
        assert f'(allow file-write* (subpath "{home}/{rel}"))' not in profile, rel
        assert f'(allow file-read* (subpath "{home}/{rel}"))' not in profile, rel


def test_host_harness_credentials_denied_both_directions():
    home = _home()
    profile = build_sbpl_profile(_spec())
    for rel in (".claude/.credentials.json", ".codex/auth.json", ".cursor/auth.json", ".pi/agent/auth.json", ".pi/agent/mcp-auth.json"):
        assert f'(deny file-read* file-write* (literal "{home}/{rel}"))' in profile, rel


def test_harness_not_in_template_gets_nothing():
    home = _home()
    hroot = sbpl.canonical_path(_HROOT)
    profile = build_sbpl_profile(_spec(app="bash", harnesses=["codex"], harness_root=_HROOT))
    assert f'(allow file-write* (subpath "{hroot}/codex"))' in profile
    assert f"{hroot}/claude" not in profile
    assert f"{home}/.local/share/claude" not in profile
    assert f"{hroot}/opencode" not in profile


def test_union_of_harness_grants():
    home = _home()
    hroot = sbpl.canonical_path(_HROOT)
    profile = build_sbpl_profile(_spec(harnesses=["claude", "opencode", "pi"], harness_root=_HROOT))
    assert f'(allow file-read* (subpath "{home}/.local/share/claude"))' in profile
    assert f'(allow file-read* (subpath "{home}/.opencode"))' in profile
    for path in (f"{hroot}/claude", f"{hroot}/opencode/data", f"{hroot}/pi/sessions"):
        assert f'(allow file-write* (subpath "{path}"))' in profile, path
    assert f'(allow file-write* (subpath "{hroot}/opencode/config"))' not in profile
    for path in (
        f"{hroot}/claude/settings.json", f"{hroot}/claude/hooks", f"{hroot}/claude/CLAUDE.md",
        f"{hroot}/opencode/config/opencode.json", f"{hroot}/opencode/config/plugins",
        f"{hroot}/pi/extensions", f"{hroot}/pi/trust.json",
    ):
        assert f'(deny file-write* (subpath "{path}"))' in profile, path


def test_codex_generated_config_readonly():
    hroot = sbpl.canonical_path(_HROOT)
    profile = build_sbpl_profile(_spec(harnesses=["codex"], harness_root=_HROOT))
    for name in ("config.toml", "hooks.json", "AGENTS.md", "requirements.toml"):
        assert f'(deny file-write* (subpath "{hroot}/codex/{name}"))' in profile, name


def test_custom_harness_gets_no_known_harness_grants():
    from warren_common.models import CustomHarness

    home = _home()
    profile = build_sbpl_profile(
        _spec(app="claude", harnesses=["custom"], harness_root=_HROOT,
              custom_harness=CustomHarness(command="claude", readonly=["graph.yaml"]))
    )
    assert "/harness/" not in profile
    assert f"{home}/.local/share/claude" not in profile
    assert '(deny file-write* (subpath "/private/tmp/ws-root/graph.yaml"))' in profile


def test_zsh_sessions_write_denied_and_not_granted():
    """AA2: Terminal.app sources $SHELL_SESSION_FILE from ~/.zsh_sessions."""
    home = _home()
    profile = build_sbpl_profile(_spec())
    assert f'(deny file-write* (subpath "{home}/.zsh_sessions"))' in profile
    assert f'(allow file-write* (subpath "{home}/.zsh_sessions"))' not in profile


def test_reference_git_dir_and_clone_root_rename_protected():
    """AE1: denying .git/hooks and .git/config by path is bypassed by renaming
    .git (or the clone itself) away, editing, and renaming it back."""
    ref = "/Users/me/.warren/projects/proj/references/wiki"
    profile = build_sbpl_profile(_spec(reference_paths=[(ref, "wiki")]))
    assert f'(deny file-write* (literal "{ref}/.git"))' in profile
    assert f'(deny file-write-unlink (literal "{ref}"))' in profile
    assert f'(deny file-write* (literal "{ref}/.git/commondir"))' in profile


def test_host_config_reference_paths_never_write_granted():
    """dispatch adds ~/.claude / ~/.aws paths as reference paths for bwrap/nsjail;
    with no backing folder they must not get a seatbelt write grant."""
    home = _home()
    cache = f"{home}/.aws/sso/cache"
    profile = build_sbpl_profile(_spec(reference_paths=[(f"{home}/.aws/config", f"{home}/.aws/config")]))
    assert f'(allow file-write* (subpath "{home}/.aws/config"))' not in profile
    assert cache not in profile


def test_credential_store_and_key_path_denied_after_allows():
    """AK1: the GitHub App key's Keychain files and reserved key path are
    read+write denied, and the denies come after every allow (last match wins)."""
    home = _home()
    profile = build_sbpl_profile(_spec())
    lines = profile.splitlines()
    last_allow = max(i for i, line in enumerate(lines) if line.startswith("(allow "))
    for denied in (f"{home}/Library/Keychains", f"{home}/.warren/github-app"):
        rule = f'(deny file-read* file-write* (subpath "{denied}"))'
        assert rule in lines
        assert lines.index(rule) > last_allow


def test_readonly_reference_and_ro_mount_are_write_denied_after_tmp_allows():
    spec = _spec(
        root_path="/Users/me/.warren/workspaces/ws-1",
        reference_paths=[("/private/tmp/wiki", "wiki")],
        folders=[FolderSpec(name="wiki", type="local-path", mount="wiki", path="/tmp/wiki", readonly=True)],
        bind_mounts=[("/private/tmp/data", "/w/data", "ro")],
    )
    profile = build_sbpl_profile(spec)
    tmp_allow = profile.index('(allow file-write* (subpath "/private/tmp"))')
    for host in ("/private/tmp/wiki", "/private/tmp/data"):
        assert profile.index(f'(deny file-write* (subpath "{host}"))') > tmp_allow


def test_readonly_path_containing_workspace_root_is_not_denied():
    spec = _spec(
        root_path="/Users/me/.warren/workspaces/ws-1",
        reference_paths=[("/Users/me", "home")],
        folders=[FolderSpec(name="home", type="local-path", mount="home", path="~", readonly=True)],
    )
    assert '(deny file-write* (subpath "/Users/me"))' not in build_sbpl_profile(spec)
