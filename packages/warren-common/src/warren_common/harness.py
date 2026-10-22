"""Agent harness profiles (AG1): what each harness needs, as data.

A template selects harnesses with `harnesses: [claude, codex, ...]`. Sandbox
builders (sbpl/bwrap/nsjail), local dispatch and the server runtimes read
these profiles instead of hard-coding per-harness paths.

Paths in a profile are relative to one of two bases:
- `host_*`, `install_read`, `deny_read`, seed/credential sources: the
  operator's $HOME.
- `writable`, `persist`, `readonly`, `generated`, seed/credential targets and
  `config_env` values: the workspace's own per-harness dir (AG3), local
  `<state>/<id>/harness/<name>/`, server `/var/lib/warren/harness/<name>/`.
  "." is the whole dir; a trailing "/" marks a directory.

Values come from upstream source/docs checked 2026-10-18; every profile is
`verified=False` until checked against the pinned harness version.
"""
from __future__ import annotations

import json
import shlex
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path, PurePath, PurePosixPath
from types import MappingProxyType

from warren_common import agent_state

CLAUDE = "claude"
CUSTOM = "custom"

SERVER_HARNESS_ROOT = "/var/lib/warren/harness"
# AG4: the warren shell's records of what each harness was doing (harness_shell).
SESSION_DIR = ".session"


@dataclass(frozen=True)
class CloudHandoff:
    """Whether the harness can move a session to the vendor's cloud, out of warren's sandbox."""

    available: bool
    how: str = ""
    verified: bool = False


@dataclass(frozen=True)
class StateHook:
    """AG5: warren-generated hook files (rel path -> content), written read-only into
    the harness dir. With `merge_hooks`, the file is JSON whose "hooks" replace the
    seeded file's (claude settings.json)."""

    files: Mapping[str, str]
    merge_hooks: bool = False


@dataclass(frozen=True)
class AgentMode:
    """AG2b/AM3: how the harness runs headless in an agent workspace. Protocol
    "acp" is native ACP on stdio, passed straight through; any other protocol
    goes through the template's `agent.adapter` command."""

    args: tuple[str, ...]
    protocol: str
    env: Mapping[str, str] = field(default_factory=dict)

    @property
    def native_acp(self) -> bool:
        return self.protocol == "acp"


@dataclass(frozen=True)
class HarnessProfile:
    name: str
    command: tuple[str, ...] = ()
    selectable: bool = True
    kind: str = "harness"  # "harness" | "custom" (AJ1)
    host_config: tuple[str, ...] = ()
    config_env: Mapping[str, str] = field(default_factory=dict)
    install_read: tuple[str, ...] = ()
    persist: tuple[str, ...] = ()
    writable: tuple[str, ...] = ()
    readonly: tuple[str, ...] = ()
    deny_read: tuple[str, ...] = ()
    seed: tuple[tuple[str, str], ...] = ()
    seed_json_strip: tuple[str, ...] = ()
    credentials: tuple[tuple[str, str], ...] = ()
    # macOS: (service, target) read host-side from the login Keychain, which the
    # sandbox can't reach. The service gets "-<sha256(dir)[:8]>" from the first
    # set var in keychain_suffix_env (empty value: no suffix).
    keychain_credentials: tuple[tuple[str, str], ...] = ()
    keychain_suffix_env: tuple[str, ...] = ()
    # Keys dropped from copied-in credential JSON (one level down too).
    credential_strip: tuple[str, ...] = ()
    auth: str = ""
    generated: Mapping[str, str] = field(default_factory=dict)
    launch_args: tuple[str, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    resume_args: tuple[str, ...] = ()
    resume_by_id_args: tuple[str, ...] = ()  # "{id}" is replaced with the session id (AG4)
    # AG4: where the harness keeps its sessions, relative to its dir: (dir, file
    # glob, `sed -n` script printing the session id from a file's basename).
    session_store: tuple[str, str, str] = ()
    # AG4: dir holding this cwd's sessions ("{slug}": cwd, non-alphanumerics -> "-").
    session_cwd_dir: str = ""
    # AB1: (generated JSON file, key) that gets `<command> --version` when warren
    # regenerates it at container start, so the harness skips onboarding.
    onboarding_version: tuple[str, str] = ()
    agent_mode: AgentMode | None = None  # AG2b
    state_hook: StateHook | None = None  # AG5
    cloud_handoff: CloudHandoff = CloudHandoff(False)
    verified: bool = False


def _ro(mapping: dict[str, str]) -> Mapping[str, str]:
    return MappingProxyType(mapping)


_CLAUDE_SETTINGS_SECRETS = ("env", "apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper")

_PROFILES: tuple[HarnessProfile, ...] = (
    HarnessProfile(
        name=CLAUDE,
        command=("claude",),
        host_config=(".claude", ".claude.json"),
        config_env=_ro({"CLAUDE_CONFIG_DIR": "."}),
        install_read=(".local/share/claude",),
        persist=("projects/", "history.jsonl", "todos/"),
        # Claude Code writes all over its config dir (.claude.json, shell-snapshots/, statsig/, ...).
        writable=(".",),
        # Z4: files that run code or load as instructions.
        readonly=(
            "settings.json", "settings.local.json", "CLAUDE.md", "AGENTS.md", "keybindings.json",
            "statusline-command.sh", "daemon.json",
            "plugins/", "skills/", "agents/", "commands/", "hooks/",
        ),
        deny_read=(".claude/.credentials.json",),
        seed=(
            (".claude/settings.json", "settings.json"),
            (".claude/CLAUDE.md", "CLAUDE.md"),
            (".claude/keybindings.json", "keybindings.json"),
        ),
        seed_json_strip=_CLAUDE_SETTINGS_SECRETS,
        credentials=((".claude/.credentials.json", ".credentials.json"),),
        keychain_credentials=(("Claude Code-credentials", ".credentials.json"),),
        keychain_suffix_env=("CLAUDE_SECURESTORAGE_CONFIG_DIR", "CLAUDE_CONFIG_DIR"),
        # The refresh token stays on the host: a sandbox refresh would rotate it
        # and log the host out, and it outlives the access token.
        credential_strip=("refreshToken",),
        auth=(
            "ANTHROPIC_API_KEY/CLAUDE_CODE_OAUTH_TOKEN secret, or the host's OAuth access token "
            "(Keychain on macOS, else ~/.claude/.credentials.json) copied in per launch without the refresh token"
        ),
        generated=_ro({".claude.json": json.dumps({"hasCompletedOnboarding": True, "hasCompletedFirstRun": True})}),
        onboarding_version=(".claude.json", "lastOnboardingVersion"),
        resume_args=("--continue",),
        resume_by_id_args=("--resume", "{id}"),
        session_store=("projects", "*.jsonl", r"s/\.jsonl$//p"),
        session_cwd_dir="projects/{slug}",
        agent_mode=AgentMode(("-p", "--output-format", "stream-json", "--verbose"), "stream-json"),
        state_hook=StateHook(_ro({"settings.json": agent_state.claude_settings()}), merge_hooks=True),
        cloud_handoff=CloudHandoff(True, "`--remote` / teleport to Claude Code on the web (to verify)"),
    ),
    HarnessProfile(
        name="codex",
        command=("codex",),
        host_config=(".codex",),
        config_env=_ro({"CODEX_HOME": "."}),
        persist=("sessions/", "history.jsonl", "log/"),
        # SQLite state lives at the dir root, with -wal/-journal siblings.
        writable=(".",),
        # A writable config.toml can mark its own hooks trusted.
        readonly=("config.toml", "hooks.json", "AGENTS.md", "requirements.toml"),
        deny_read=(".codex/auth.json",),
        seed=((".codex/AGENTS.md", "AGENTS.md"),),
        auth="OPENAI_API_KEY / CODEX_API_KEY secret; auth.json copy-in not implemented yet",
        generated=_ro({
            "config.toml": 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n\n[features]\ncodex_hooks = true\n'
        }),
        launch_args=("--sandbox", "danger-full-access"),
        resume_args=("resume", "--last"),
        resume_by_id_args=("resume", "{id}"),
        session_store=(
            "sessions",
            "rollout-*.jsonl",
            r"s/^.*\([0-9a-f]\{8\}-[0-9a-f]\{4\}-[0-9a-f]\{4\}-[0-9a-f]\{4\}-[0-9a-f]\{12\}\)\.jsonl$/\1/p",
        ),
        agent_mode=AgentMode(("exec", "--json"), "jsonl"),
        state_hook=StateHook(_ro({"hooks.json": agent_state.codex_hooks()})),
        cloud_handoff=CloudHandoff(True, "`codex cloud` tasks (to verify)"),
    ),
    HarnessProfile(
        name="opencode",
        command=("opencode",),
        host_config=(".config/opencode", ".local/share/opencode"),
        config_env=_ro({"OPENCODE_CONFIG_DIR": "config", "OPENCODE_DB": "data/opencode.db"}),
        install_read=(".opencode",),
        persist=("data/",),
        writable=("data/",),
        readonly=(
            "config/opencode.json", "config/opencode.jsonc", "config/tui.json",
            "config/plugins/", "config/tools/", "config/agents/", "config/commands/", "config/skills/",
        ),
        deny_read=(".local/share/opencode/auth.json",),
        seed=((".config/opencode/tui.json", "config/tui.json"),),
        auth="provider API key secrets; auth.json copy-in not implemented yet",
        generated=_ro({"config/opencode.json": json.dumps({"$schema": "https://opencode.ai/config.json", "autoupdate": False})}),
        env=_ro({
            "OPENCODE_DISABLE_CLAUDE_CODE": "1",
            "OPENCODE_DISABLE_AUTOUPDATE": "1",
            "OPENCODE_DISABLE_LSP_DOWNLOAD": "1",
        }),
        resume_args=("--continue",),
        resume_by_id_args=("--session", "{id}"),
        agent_mode=AgentMode(("acp",), "acp", _ro({"OPENCODE_CLIENT": "acp", "OPENCODE_ENABLE_QUESTION_TOOL": "false"})),
        state_hook=StateHook(_ro({"config/plugins/warren-state.js": agent_state.OPENCODE_PLUGIN})),
        cloud_handoff=CloudHandoff(False, "none known; `/share` publishes a transcript to opencode.ai (to verify)"),
    ),
    HarnessProfile(
        name="cursor-agent",
        command=("cursor-agent", "agent"),
        host_config=(".cursor",),
        config_env=_ro({"CURSOR_CONFIG_DIR": ".", "CURSOR_DATA_DIR": "data"}),
        install_read=(".local/share/cursor-agent",),
        persist=("chats/", "projects/", "data/"),
        writable=("chats/", "projects/", "data/"),
        readonly=("cli-config.json", "hooks.json", "mcp.json", "sandbox.json"),
        deny_read=(".cursor/auth.json",),
        auth="CURSOR_API_KEY secret; auth.json copy-in not implemented yet",
        launch_args=("--sandbox", "disabled"),
        env=_ro({"AGENT_CLI_CREDENTIAL_STORE": "file"}),
        resume_args=("--continue",),
        resume_by_id_args=("--resume", "{id}"),
        agent_mode=AgentMode(("acp",), "acp"),
        state_hook=StateHook(_ro({"hooks.json": agent_state.cursor_hooks()})),
        cloud_handoff=CloudHandoff(True, "prefixing a prompt with `&` hands the session to Cursor Cloud Agents"),
    ),
    HarnessProfile(
        name="pi",
        command=("pi",),
        host_config=(".pi",),
        config_env=_ro({"PI_CODING_AGENT_DIR": ".", "PI_CODING_AGENT_SESSION_DIR": "sessions"}),
        persist=("sessions/",),
        writable=("sessions/",),
        readonly=("settings.json", "models.json", "mcp.json", "trust.json", "extensions/"),
        deny_read=(".pi/agent/auth.json", ".pi/agent/mcp-auth.json"),
        seed=((".pi/agent/settings.json", "settings.json"),),
        auth="provider API key secrets; auth.json copy-in not implemented yet",
        launch_args=("--no-approve",),
        env=_ro({"PI_OFFLINE": "1", "PI_SKIP_VERSION_CHECK": "1", "PI_TELEMETRY": "0"}),
        resume_args=("--continue",),
        resume_by_id_args=("--session", "{id}"),
        session_store=("sessions", "*.jsonl", r"s/^.*_//; s/\.jsonl$//p"),
        agent_mode=AgentMode(("--mode", "rpc"), "jsonl-rpc"),
        state_hook=StateHook(_ro({"extensions/warren-state.ts": agent_state.PI_EXTENSION})),
    ),
    # AJ1: a framework program the template supplies. No grants of its own.
    HarnessProfile(name=CUSTOM, kind="custom"),
)

# herdr's integration registry (herdrdev/herdr @143bf5fd): listed so their host
# config is write-denied, not selectable until resume/own-sandbox flags are researched.
_LISTED: tuple[tuple[str, tuple[str, ...], str], ...] = (
    ("copilot", (".copilot",), "COPILOT_HOME"),
    ("devin", (".config/devin",), ""),
    ("droid", (".factory",), ""),
    ("kimi", (".kimi-code",), "KIMI_CODE_HOME"),
    ("kilo", (".config/kilo",), ""),
    ("hermes", (".hermes",), "HERMES_HOME"),
    ("qodercli", (".qoder",), "QODER_CONFIG_DIR"),
    ("qwen", (".qwen",), "QWEN_HOME"),
    ("letta", (".letta",), ""),
    ("mastracode", (".mastracode",), ""),
    ("antigravity-cli", (".gemini/config",), "ANTIGRAVITY_CLI_CONFIG_DIR"),
    ("grok", (".grok",), "GROK_HOME"),
    ("omp", (".omp",), "OMP_CONFIG_DIR"),
)

PROFILES: Mapping[str, HarnessProfile] = MappingProxyType(
    {
        **{p.name: p for p in _PROFILES},
        **{
            name: HarnessProfile(
                name=name,
                selectable=False,
                host_config=dirs,
                config_env=_ro({env: "."} if env else {}),
            )
            for name, dirs, env in _LISTED
        },
    }
)

SELECTABLE_HARNESSES = frozenset(n for n, p in PROFILES.items() if p.selectable)


class HarnessSelectionError(ValueError):
    pass


def check_harness_names(names: Iterable[str]) -> None:
    unknown = [n for n in names if n not in PROFILES]
    if unknown:
        raise HarnessSelectionError(
            f"unknown harness(es) {unknown}; selectable: {sorted(SELECTABLE_HARNESSES)}"
        )
    listed = [n for n in names if not PROFILES[n].selectable]
    if listed:
        raise HarnessSelectionError(f"harness(es) {listed} are listed but not selectable yet")


# Env that makes Claude Code use Bedrock; a template setting any of these is in bedrock mode.
BEDROCK_SIGNAL_ENV = ("CLAUDE_CODE_USE_BEDROCK", "ANTHROPIC_BEDROCK_BASE_URL")
BEDROCK_ENV: Mapping[str, str] = MappingProxyType({"CLAUDE_CODE_USE_BEDROCK": "1"})
# Operator model-login tokens that must never reach a bedrock-mode workspace.
SUBSCRIPTION_TOKEN_NAMES = ("CLAUDE_CODE_OAUTH_TOKEN",)


def bedrock_mode(model_access: str | None, env: Mapping[str, str] | None = None) -> bool:
    """True when harnesses must reach models through the workspace's own AWS identity."""
    if model_access == "bedrock":
        return True
    env = env or {}
    use = env.get("CLAUDE_CODE_USE_BEDROCK", "").strip().lower()
    return use not in ("", "0", "false", "no") or bool(env.get("ANTHROPIC_BEDROCK_BASE_URL", "").strip())


def validate_harness_selection(
    names: Iterable[str],
    *,
    custom_command: str | None = None,
    allow_vendor_cloud: bool = True,
    bedrock: bool = False,
    secret_names: Iterable[str] = (),
) -> None:
    """Template-level checks on a resolved template (AG1, AJ1)."""
    names = list(names)
    check_harness_names(names)
    if CUSTOM in names and not (custom_command or "").strip():
        raise HarnessSelectionError("harness 'custom' needs an explicit custom_harness.command")
    if custom_command and CUSTOM not in names:
        raise HarnessSelectionError("custom_harness is set but 'custom' is not in harnesses")
    if not allow_vendor_cloud:
        cloud = [n for n in names if PROFILES[n].cloud_handoff.available]
        if cloud:
            raise HarnessSelectionError(
                f"allow_vendor_cloud is false but harness(es) {cloud} can hand sessions to the vendor's cloud"
            )
    if bedrock:
        tokens = [s for s in secret_names if s in SUBSCRIPTION_TOKEN_NAMES]
        if tokens:
            raise HarnessSelectionError(
                f"bedrock model access uses the workspace's AWS identity; remove secret(s) {tokens}"
            )


def _command_name(app: str) -> str:
    try:
        argv = shlex.split(app)
    except ValueError:
        return ""
    return PurePath(argv[0]).name if argv else ""


def selected_harnesses(app: str, harnesses: Iterable[str] = ()) -> frozenset[str]:
    """Harnesses declared by the template, plus a known one `app` launches
    directly. A `custom` template never inherits a known harness from `app`."""
    names = set(harnesses)
    if CUSTOM in names or not app:
        return frozenset(names)
    cmd = _command_name(app)
    for p in PROFILES.values():
        if p.selectable and cmd in p.command:
            names.add(p.name)
    return frozenset(names)


def profiles_for(names: Iterable[str]) -> list[HarnessProfile]:
    return [PROFILES[n] for n in sorted(set(names)) if n in PROFILES]


def harness_dir(root: str | Path, name: str) -> str:
    return f"{str(root).rstrip('/')}/{name}"


def _join(base: str, rel: str) -> str:
    rel = rel.rstrip("/")
    return base if rel in ("", ".") else f"{base.rstrip('/')}/{rel}"


def state_hook_env(root: str | Path) -> dict[str, str]:
    """AG5: makes the installed state hooks report into the workspace's session dir."""
    root = str(root).rstrip("/")
    hook = (
        agent_state.SERVER_HOOK_PATH
        if root == SERVER_HARNESS_ROOT
        else f"{root}/{agent_state.HOOKS_DIR}/{agent_state.HOOK_SCRIPT}"
    )
    return {"WARREN_STATE_HOOK": hook, "WARREN_STATE_DIR": f"{root}/{SESSION_DIR}"}


def harness_env(names: Iterable[str], root: str | Path) -> dict[str, str]:
    """Config-dir env vars (AG3) and lockdown env (AG1) for the selected harnesses."""
    env: dict[str, str] = {}
    for p in profiles_for(names):
        base = harness_dir(root, p.name)
        for var, rel in p.config_env.items():
            env[var] = _join(base, rel)
        env.update(p.env)
        if p.state_hook is not None:
            env.update(state_hook_env(root))
    return env


def harness_dirs(names: Iterable[str], root: str | Path) -> list[str]:
    """Directories to create before a harness starts (some refuse a missing config dir)."""
    dirs: list[str] = []
    for p in profiles_for(names):
        if p.kind == "custom":
            continue
        base = harness_dir(root, p.name)
        dirs.append(base)
        for rel in p.config_env.values():
            pp = PurePosixPath(rel)
            dirs.append(_join(base, str(pp.parent if pp.suffix else pp)))
        dirs += [_join(base, rel) for rel in (*p.writable, *p.persist) if rel.endswith("/")]
    if dirs:
        dirs.append(_join(str(root), SESSION_DIR))
    return list(dict.fromkeys(dirs))


# AB1: never persisted, whatever a profile declares.
_NEVER_PERSIST = frozenset({
    ".credentials.json", "auth.json", "mcp-auth.json", ".claude.json",
    "plugins", "hooks", "skills", "agents", "commands", "extensions",
})


def credential_names() -> tuple[str, ...]:
    """Basenames of every known harness's credential files."""
    names = {PurePosixPath(rel).name for p in PROFILES.values() for rel in p.deny_read}
    names |= {PurePosixPath(dst).name for p in PROFILES.values() for _, dst in p.credentials}
    return tuple(sorted(names))


def check_persist(p: HarnessProfile) -> None:
    """AB1: `persist` names conversation state only: relative, inside the harness
    dir, and never credentials, settings or anything that runs code."""
    for rel in p.persist:
        parts = PurePosixPath(rel.rstrip("/")).parts
        if len(parts) != 1 or rel.startswith("/") or parts[0] in (".", ".."):
            raise ValueError(f"{p.name}: persist path {rel!r} must be a top-level entry of the harness dir")
        readonly = {r.rstrip("/") for r in p.readonly}
        name = parts[-1]
        if (
            rel.rstrip("/") in readonly
            or name in _NEVER_PERSIST
            or name in credential_names()
            or (name.startswith("settings") and name.endswith(".json"))
        ):
            raise ValueError(f"{p.name}: persist path {rel!r} covers credentials or config")


def persist_paths(names: Iterable[str], root: str | Path) -> list[str]:
    """Absolute `persist` paths of the selected harnesses (AB1)."""
    out: list[str] = []
    for p in profiles_for(names):
        if p.kind == "custom":
            continue
        check_persist(p)
        out += [_join(harness_dir(root, p.name), rel) for rel in p.persist]
    return out


@dataclass(frozen=True)
class HarnessGrants:
    """Union of sandbox grants for a workspace's harnesses (AG6). Absolute paths."""

    read: tuple[str, ...] = ()
    write: tuple[str, ...] = ()
    readonly: tuple[str, ...] = ()
    deny_read: tuple[str, ...] = ()
    deny_write: tuple[str, ...] = ()


def sandbox_grants(
    names: Iterable[str],
    *,
    home: str | Path,
    root: str | Path | None,
    custom_readonly: Iterable[str] = (),
    workspace_root: str | Path | None = None,
) -> HarnessGrants:
    """Selected harnesses get install-read, their own per-workspace dir (read,
    with `writable`/`persist` writable and `readonly`/`generated` write-denied).
    Every known harness's HOST config dir is write-denied and its credential
    files read-denied, selected or not: with AG3 no workspace uses them."""
    home = str(home)
    selected = profiles_for(names)
    read: list[str] = []
    write: list[str] = []
    readonly: list[str] = []
    for p in selected:
        read += [_join(home, rel) for rel in p.install_read]
        if root is None or p.kind == "custom":
            continue
        base = harness_dir(root, p.name)
        read.append(base)
        write += [_join(base, rel) for rel in (*p.writable, *p.persist)]
        readonly += [_join(base, rel) for rel in p.readonly]
        session = _join(str(root), SESSION_DIR)
        read.append(session)
        write.append(session)
        if p.state_hook is not None:
            hooks = _join(str(root), agent_state.HOOKS_DIR)
            read.append(hooks)
            readonly.append(hooks)
    if workspace_root is not None:
        readonly += [_join(str(workspace_root), rel) for rel in custom_readonly]
    deny_write: list[str] = []
    deny_read: list[str] = []
    for p in PROFILES.values():
        deny_write += [_join(home, rel) for rel in p.host_config]
        deny_read += [_join(home, rel) for rel in p.deny_read]
    uniq = lambda xs: tuple(dict.fromkeys(xs))  # noqa: E731
    return HarnessGrants(uniq(read), uniq(write), uniq(readonly), uniq(deny_read), uniq(deny_write))


def grants_for_spec(spec, home: str | Path) -> HarnessGrants:
    """`sandbox_grants` for a WorkspaceSpec."""
    custom = getattr(spec, "custom_harness", None)
    return sandbox_grants(
        selected_harnesses(spec.app, spec.harnesses),
        home=home,
        root=spec.harness_root or None,
        custom_readonly=custom.readonly if custom else (),
        workspace_root=spec.root_path or None,
    )


def cloud_handoff_warnings(names: Iterable[str]) -> list[str]:
    return [
        f"warren: {p.name} can hand a session to its vendor's cloud ({p.cloud_handoff.how}); "
        "work there runs outside this workspace's sandbox"
        for p in profiles_for(names)
        if p.cloud_handoff.available
    ]
