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
import re
import shlex
from collections.abc import Callable, Iterable, Mapping
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


# Protocols of a harness that serves its own endpoint on the agent port (`{port}`
# in its args): the supervisor runs and restarts it but proxies nothing.
SELF_SERVING_PROTOCOLS = frozenset({"http", "ws"})


@dataclass(frozen=True)
class AgentMode:
    """AG2b/AM3: how the harness runs headless in an agent workspace. Protocol
    "acp" is native ACP on stdio, passed straight through; "http"/"ws" is the
    harness's own server on loopback `{port}` (opencode serve, codex app-server);
    any other protocol goes through the template's `agent.adapter` command."""

    args: tuple[str, ...]
    protocol: str
    env: Mapping[str, str] = field(default_factory=dict)
    name: str = ""
    # Append the profile's launch_args (codex's --sandbox is a TUI/exec flag only).
    profile_args: bool = True

    @property
    def native_acp(self) -> bool:
        return self.protocol == "acp"

    @property
    def serves(self) -> bool:
        return self.protocol in SELF_SERVING_PROTOCOLS


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
    agent_mode: AgentMode | None = None  # AG2b: the default
    # Other named modes a template picks with `agent.mode` (server modes and the like).
    agent_modes: tuple[AgentMode, ...] = ()
    # Env (relative paths, like config_env) set only on the harness's own process,
    # never exported into the shell: XDG dirs that would move other tools' files too.
    process_env: Mapping[str, str] = field(default_factory=dict)
    # (harness dir, env) -> {rel: content}: generated config that depends on where
    # the dir is and on the workspace env (model gateway). Overrides `generated`; the
    # init script has the same logic in shell (harness_shell, kept equal by a test).
    dynamic_config: Callable[[str, Mapping[str, str]], dict[str, str]] | None = None
    state_hook: StateHook | None = None  # AG5
    cloud_handoff: CloudHandoff = CloudHandoff(False)
    verified: bool = False


def _ro(mapping: dict[str, str]) -> Mapping[str, str]:
    return MappingProxyType(mapping)


# --- model access from the workspace env (Bedrock / a Bedrock gateway) ---
# The same env Claude Code reads (CLAUDE_CODE_USE_BEDROCK, ANTHROPIC_BEDROCK_BASE_URL,
# CLAUDE_CODE_SKIP_BEDROCK_AUTH + ANTHROPIC_AUTH_TOKEN, ANTHROPIC_MODEL, AWS_REGION),
# turned into each harness's own provider config. Values outside these character sets
# are ignored rather than escaped, so the shell twin in warren-harness-init can emit
# them verbatim.
_SAFE_URL = re.compile(r"https?://[A-Za-z0-9._~:/%+-]{1,512}")
_SAFE_MODEL = re.compile(r"[A-Za-z0-9._:/-]{1,200}")
_SAFE_REGION = re.compile(r"[a-z0-9-]{1,32}")
OPENCODE_BASE_CONFIG = {"$schema": "https://opencode.ai/config.json", "autoupdate": False}
CODEX_BASE_CONFIG = 'approval_policy = "never"\nsandbox_mode = "danger-full-access"\n\n[features]\nhooks = true\n'


def _truthy(value: str | None) -> bool:
    return (value or "").lower() not in ("", "0", "false", "no")


def _safe(env: Mapping[str, str], key: str, pattern: re.Pattern) -> str:
    value = env.get(key) or ""
    return value if pattern.fullmatch(value) else ""


def opencode_config(env: Mapping[str, str]) -> str:
    """opencode.json: Amazon Bedrock as the only provider in bedrock mode, through
    the gateway when ANTHROPIC_BEDROCK_BASE_URL is set (opencode's amazon-bedrock
    `endpoint`; the bearer token from ANTHROPIC_AUTH_TOKEN via `{env:}` when
    CLAUDE_CODE_SKIP_BEDROCK_AUTH is set, else SigV4 with the workspace's AWS
    identity). Checked against opencode 1.19.5."""
    cfg: dict = dict(OPENCODE_BASE_CONFIG)
    gateway = _safe(env, "ANTHROPIC_BEDROCK_BASE_URL", _SAFE_URL)
    if not (_truthy(env.get("CLAUDE_CODE_USE_BEDROCK")) or gateway):
        return json.dumps(cfg)
    cfg["enabled_providers"] = ["amazon-bedrock"]
    model = _safe(env, "ANTHROPIC_MODEL", _SAFE_MODEL)
    if model:
        cfg["model"] = f"amazon-bedrock/{model}"
    small = _safe(env, "ANTHROPIC_DEFAULT_HAIKU_MODEL", _SAFE_MODEL)
    if small:
        cfg["small_model"] = f"amazon-bedrock/{small}"
    options: dict = {}
    region = _safe(env, "AWS_REGION", _SAFE_REGION)
    if region:
        options["region"] = region
    if gateway:
        options["endpoint"] = gateway
        if _truthy(env.get("CLAUDE_CODE_SKIP_BEDROCK_AUTH")):
            options["apiKey"] = "{env:ANTHROPIC_AUTH_TOKEN}"
    if options:
        cfg["provider"] = {"amazon-bedrock": {"options": options}}
    return json.dumps(cfg)


def codex_config(hooks_json: str, env: Mapping[str, str]) -> str:
    """config.toml: warren's defaults, the Amazon Bedrock provider in bedrock mode
    without a gateway (codex calls Bedrock's OpenAI-compatible Mantle endpoint, not
    the InvokeModel/Converse API a Claude gateway proxies, so a gateway is left
    unwired), and trust for warren's own state hooks at `hooks_json` (codex runs
    an untrusted hook never; the hash is its sha256 of the normalized hook)."""
    from warren_common.agent_state import codex_hook_trust  # noqa: PLC0415

    out = CODEX_BASE_CONFIG
    if _truthy(env.get("CLAUDE_CODE_USE_BEDROCK")) and not env.get("ANTHROPIC_BEDROCK_BASE_URL"):
        out = 'model_provider = "amazon-bedrock"\n' + out
        region = _safe(env, "AWS_REGION", _SAFE_REGION)
        if region:
            out += f'\n[model_providers.amazon-bedrock.aws]\nregion = "{region}"\n'
    return out + codex_hook_trust(hooks_json)


def _codex_dynamic(base: str, env: Mapping[str, str]) -> dict[str, str]:
    return {"config.toml": codex_config(f"{base.rstrip('/')}/hooks.json", env)}


def _opencode_dynamic(base: str, env: Mapping[str, str]) -> dict[str, str]:
    return {"config/opencode.json": opencode_config(env)}


_CLAUDE_SETTINGS_SECRETS =("env", "apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper")

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
        agent_mode=AgentMode(("-p", "--output-format", "stream-json", "--verbose"), "stream-json", name="stream-json"),
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
        # Without dynamic_config (no harness dir known) the base config, untrusted hooks.
        generated=_ro({"config.toml": CODEX_BASE_CONFIG}),
        dynamic_config=_codex_dynamic,
        launch_args=("--sandbox", "danger-full-access"),
        resume_args=("resume", "--last"),
        resume_by_id_args=("resume", "{id}"),
        session_store=(
            "sessions",
            "rollout-*.jsonl",
            r"s/^.*\([0-9a-f]\{8\}-[0-9a-f]\{4\}-[0-9a-f]\{4\}-[0-9a-f]\{4\}-[0-9a-f]\{12\}\)\.jsonl$/\1/p",
        ),
        agent_mode=AgentMode(("exec", "--json"), "jsonl", name="exec"),
        agent_modes=(
            # Its own JSON-RPC server on loopback websocket; `codex --remote ws://...` attaches.
            AgentMode(("app-server", "--listen", "ws://127.0.0.1:{port}"), "ws", name="app-server", profile_args=False),
            # The same protocol on stdio, for an adapter (e.g. an ACP bridge) to drive.
            AgentMode(
                ("app-server", "--listen", "stdio://"), "codex-app-server", name="app-server-stdio", profile_args=False
            ),
        ),
        state_hook=StateHook(_ro({"hooks.json": agent_state.codex_hooks()})),
        cloud_handoff=CloudHandoff(True, "`codex cloud` tasks (to verify)"),
    ),
    HarnessProfile(
        name="opencode",
        command=("opencode",),
        host_config=(".config/opencode", ".local/share/opencode"),
        config_env=_ro({"OPENCODE_CONFIG_DIR": "config", "OPENCODE_DB": "data/opencode.db"}),
        # OPENCODE_CONFIG_DIR adds a config dir but moves nothing else: data (auth.json,
        # logs, snapshots) and state (prompt history) follow XDG (checked on 1.19.5).
        process_env=_ro({"XDG_DATA_HOME": "data", "XDG_STATE_HOME": "state"}),
        install_read=(".opencode",),
        persist=("data/", "state/"),
        writable=("data/", "state/"),
        readonly=(
            "config/opencode.json", "config/opencode.jsonc", "config/tui.json",
            "config/plugins/", "config/tools/", "config/agents/", "config/commands/", "config/skills/",
        ),
        deny_read=(".local/share/opencode/auth.json",),
        seed=((".config/opencode/tui.json", "config/tui.json"),),
        auth="provider API key secrets; auth.json copy-in not implemented yet",
        generated=_ro({"config/opencode.json": json.dumps(OPENCODE_BASE_CONFIG)}),
        dynamic_config=_opencode_dynamic,
        env=_ro({
            "OPENCODE_DISABLE_CLAUDE_CODE": "1",
            "OPENCODE_DISABLE_AUTOUPDATE": "1",
            "OPENCODE_DISABLE_LSP_DOWNLOAD": "1",
        }),
        resume_args=("--continue",),
        resume_by_id_args=("--session", "{id}"),
        agent_mode=AgentMode(
            ("acp",), "acp", _ro({"OPENCODE_CLIENT": "acp", "OPENCODE_ENABLE_QUESTION_TOOL": "false"}), name="acp"
        ),
        # Its HTTP API on loopback; `opencode attach http://127.0.0.1:<port>` and other
        # clients (T3) use it. OPENCODE_SERVER_PASSWORD (a template secret) adds basic auth.
        agent_modes=(AgentMode(("serve", "--hostname", "127.0.0.1", "--port", "{port}"), "http", name="serve"),),
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
        agent_mode=AgentMode(("acp",), "acp", name="acp"),
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
        agent_mode=AgentMode(("--mode", "rpc"), "jsonl-rpc", name="rpc"),
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


def process_env(name: str, root: str | Path) -> dict[str, str]:
    """`process_env` of one harness, absolute: only for that harness's own process."""
    p = PROFILES[name]
    base = harness_dir(root, p.name)
    return {var: _join(base, rel) for var, rel in p.process_env.items()}


def agent_modes(p: HarnessProfile) -> dict[str, AgentMode]:
    """A profile's agent modes by name, the default first."""
    modes = [m for m in (p.agent_mode, *p.agent_modes) if m is not None]
    return {m.name or m.protocol: m for m in modes}


def harness_dirs(names: Iterable[str], root: str | Path) -> list[str]:
    """Directories to create before a harness starts (some refuse a missing config dir)."""
    dirs: list[str] = []
    for p in profiles_for(names):
        if p.kind == "custom":
            continue
        base = harness_dir(root, p.name)
        dirs.append(base)
        for rel in (*p.config_env.values(), *p.process_env.values()):
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
