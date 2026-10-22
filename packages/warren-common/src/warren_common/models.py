"""Pydantic v2 models for warren.yml project definitions."""

from __future__ import annotations

from pathlib import PurePosixPath
from typing import Any, Literal

import re

import structlog
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

log = structlog.get_logger(__name__)

_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
# Names warren itself sets on every runtime; a template's `env` may never override them.
RESERVED_ENV_PREFIXES = ("WARREN_",)
RESERVED_ENV_NAMES = frozenset(
    {"HOME", "REAL_HOME", "PATH", "PWD", "SHELL", "USER", "ZDOTDIR", "SSH_AUTH_SOCK"}
)


def is_reserved_env_name(name: str) -> bool:
    return name in RESERVED_ENV_NAMES or name.startswith(RESERVED_ENV_PREFIXES)


def template_env_for(
    template_env: dict[str, str] | None, *, exclude: Any = ()
) -> dict[str, str]:
    """The template's plain `env`, minus reserved names and any name in
    `exclude` (a declared secret wins over a same-named plain var)."""
    excluded = set(exclude)
    return {
        k: v
        for k, v in (template_env or {}).items()
        if _ENV_NAME_RE.match(k) and not is_reserved_env_name(k) and k not in excluded
    }


class MountSpec(BaseModel):
    model_config = ConfigDict(extra="ignore")

    host: str
    container: str
    mode: Literal["ro", "rw"] = "ro"


class FolderSpec(BaseModel):
    """A folder declaration in a project config.

    Replaces the old RepoSpec with a unified model supporting three source types:

    - git-worktree: bare clone + per-workspace branch checkout (for active development)
    - git-clone:    shared clone cached in ~/.warren (for reading context, can fetch)
    - local-path:   direct bind from host filesystem (no git, e.g. Obsidian vault)

    The `mount` field is the path inside the workspace (relative to ~).
    """
    model_config = ConfigDict(extra="ignore")

    name: str
    type: Literal["git-worktree", "git-clone", "local-path"]
    mount: str                          # e.g. "code/acme-api", "refs/example-app", "wiki"

    # git-worktree + git-clone
    url: str | None = None
    branch: str = "main"

    # local-path
    path: str | None = None             # host path, ~ expanded at runtime

    # Optional: seed initial clone from a local path instead of remote (speeds up first provision)
    seed_from: str | None = None

    readonly: bool = False              # advisory — enforced in seatbelt profile

    # git-worktree + git-clone, SSH remotes only: names the warren.secrets entry carrying
    # this folder's own SSH private key, overriding the template's default
    # WARREN_GIT_SSH_KEY for this one folder — e.g. a GitLab repo using a different
    # deploy key than the Bitbucket repos in the same template. None (the default) keeps
    # the old shared-key behavior: every SSH-remote folder uses WARREN_GIT_SSH_KEY.
    ssh_key_secret: str | None = None

    # git-worktree + git-clone, HTTPS remotes only: same idea as ssh_key_secret above,
    # but for a GitHub PAT -- names the warren.secrets entry carrying this folder's own
    # token, overriding the template's default GITHUB_PAT. Needed because a fine-grained
    # PAT only covers one GitHub resource owner (your personal account OR one org, never
    # both), so a template spanning two owners' private repos needs two differently-
    # scoped tokens, not one. None (the default) keeps the old shared-token behavior.
    pat_secret: str | None = None

    @field_validator("mount")
    @classmethod
    def _mount_is_contained_relative_path(cls, v: str) -> str:
        return normalise_mount(v)


def normalise_mount(mount: str) -> str:
    """Return `mount` as a normalised relative path, or raise ValueError.

    Rejects empty paths, absolute paths, `~`-prefixed paths and any `..`
    component, so a mount can never resolve outside the workspace root.
    """
    raw = mount.strip()
    if not raw:
        raise ValueError("mount must be a non-empty relative path")
    if raw.startswith(("/", "\\", "~")):
        raise ValueError(f"mount must be relative to the workspace root, got {mount!r}")
    parts = [p for p in PurePosixPath(raw.replace("\\", "/")).parts if p != "."]
    if any(p == ".." for p in parts):
        raise ValueError(f"mount must not contain '..' components, got {mount!r}")
    if not parts:
        raise ValueError("mount must be a non-empty relative path")
    return "/".join(parts)


# Back-compat alias
class RepoSpec(BaseModel):
    """Legacy repo spec — use FolderSpec instead."""
    model_config = ConfigDict(extra="ignore")

    url: str
    branch: str = "main"
    type: Literal["worktree", "reference"] = "worktree"
    local_path: str | None = None

    def to_folder_spec(self, name: str | None = None) -> FolderSpec:
        """Convert legacy RepoSpec to FolderSpec."""
        folder_type = "git-worktree" if self.type == "worktree" else "git-clone"
        slug = self.url.rstrip("/").split("/")[-1].removesuffix(".git")
        prefix = "code" if self.type == "worktree" else "refs"
        return FolderSpec(
            name=name or slug,
            type=folder_type,
            url=self.url,
            branch=self.branch,
            mount=f"{prefix}/{slug}",
            seed_from=self.local_path,
        )


class SecretRef(BaseModel):
    """Declares one secret name a template needs. No permission tier (removed
    2026-10-13) — this list IS the access control: a workspace only ever gets
    exactly the secret names its resolved template declares here, resolved
    against the caller's own secrets (server-side, per-owner isolated)."""

    model_config = ConfigDict(extra="ignore")

    name: str


class ScopeConfig(BaseModel):
    model_config = ConfigDict(extra="ignore")

    paths: list[str] = []
    git: dict[str, str] = {}


# Runtimes where `aws.mode: sso` is allowed (AK3): interactive local work only.
AWS_SSO_RUNTIMES = frozenset({"seatbelt", "bwrap", "nsjail"})


class AwsConfig(BaseModel):
    """`mode: export` (default) serves only `profile`'s short-lived credentials
    to the workspace from the host. `mode: sso` shares the host SSO token cache,
    which can mint credentials for every account and role the user has (AK3)."""

    model_config = ConfigDict(extra="ignore")

    mode: Literal["sso", "export"] = "export"
    profile: str = ""
    config_file: str = ""
    sso_cache: str = ""


def check_aws_mode(aws: AwsConfig | None, runtime_type: str) -> None:
    """Reject `aws.mode: sso` outside local sandbox runtimes (AK3)."""
    if aws is not None and aws.mode == "sso" and runtime_type not in AWS_SSO_RUNTIMES:
        raise ValueError(
            f"aws.mode 'sso' is only allowed for local runtimes "
            f"({', '.join(sorted(AWS_SSO_RUNTIMES))}), not {runtime_type!r}; "
            "use aws.mode 'export'"
        )


class SshConfig(BaseModel):
    """SSH access declaration for a project or template node.

    Explicit opt-in — no ssh block means no keys and no agent are available
    inside the sandbox, even if they exist on the host.

    keys:  specific key file paths (~ expanded at runtime). Only those files
           are bind-mounted, not the whole ~/.ssh dir.
    agent: if true, SSH_AUTH_SOCK is forwarded so the host agent handles
           auth. Preferred over key files for passphrase-protected keys.
    """
    model_config = ConfigDict(extra="ignore")

    keys: list[str] = []
    agent: bool = False


class AgentRestart(BaseModel):
    """AG2b: what the supervisor does when the agent process exits."""

    model_config = ConfigDict(extra="ignore")

    policy: Literal["always", "on-failure", "never"] = "on-failure"
    max_restarts: int = Field(default=5, ge=0, le=100)
    backoff_seconds: float = Field(default=1.0, ge=0, le=600)
    backoff_max_seconds: float = Field(default=60.0, ge=0, le=3600)
    # A run this long resets the restart count.
    stable_seconds: float = Field(default=120.0, ge=0, le=86400)


_WIDE_HOSTS = re.compile(r"(?<![\w.])(0\.0\.0\.0|::|\[::\])(?![\w.])")


class AgentConfig(BaseModel):
    """AG2b/AM3: an agent workspace's one ACP endpoint and its supervisor policy.

    `port` is the in-workspace loopback port `warren tunnel` reaches. `adapter`
    is the command (template: {port} {harness} {harness_argv} {resume_argv}
    {session_id} {state_dir}) that serves ACP for a harness without native ACP,
    e.g. `acp-serve --transport jsonrpc --host 127.0.0.1 --port {port}`."""

    model_config = ConfigDict(extra="ignore")

    port: int = Field(default=8765, ge=1024, le=65535)
    adapter: str | None = None
    adapter_transport: Literal["tcp", "stdio"] = "tcp"
    use_adapter: bool = False
    restart: AgentRestart = AgentRestart()
    max_line_bytes: int = Field(default=4 * 1024 * 1024, ge=1024, le=64 * 1024 * 1024)
    max_peers: int = Field(default=1, ge=1, le=8)

    @field_validator("adapter")
    @classmethod
    def _loopback_only(cls, v: str | None) -> str | None:
        if v is not None and _WIDE_HOSTS.search(v):
            raise ValueError("agent.adapter must not bind a non-loopback address; use 127.0.0.1")
        return v


class CustomHarness(BaseModel):
    """AJ1: the program a `custom` harness runs. `readonly` and `persist` are
    workspace-relative; it gets no known harness's grants."""

    model_config = ConfigDict(extra="ignore")

    command: str
    readonly: list[str] = []
    persist: list[str] = []

    @field_validator("readonly", "persist")
    @classmethod
    def _relative(cls, v: list[str]) -> list[str]:
        for p in v:
            pp = PurePosixPath(p)
            if pp.is_absolute() or ".." in pp.parts:
                raise ValueError(f"custom_harness path {p!r} must be relative to the workspace")
        return v


class ProjectConfig(BaseModel):
    """A project definition, and (recursively) every named template under it.

    There is no separate "intent" type — a named entry under `templates` is a
    full ProjectConfig itself, so it can carry its own `templates` in turn.
    `resolve_template()` (templates.py) walks a dotted path ("develop" or
    "develop.claude") from the root, merging each level's explicitly-set
    fields onto the accumulated parent (scalars override, lists append,
    `scope`/`aws`/`ssh` shallow-merge) to produce the fully resolved node
    that actually gets provisioned.

    `name`, `repo`, `bare_path`, `folders`, and `repos` are only meaningful
    at the root (a template node overriding them is unusual but not
    rejected). Every other field is meaningful — and overridable — at any
    depth.
    """

    model_config = ConfigDict(extra="ignore")

    name: str | None = None
    description: str = ""

    # New unified folder declarations
    folders: list[FolderSpec] = []

    # Legacy fields — kept for back-compat, converted to folders on load
    repo: str | None = None
    bare_path: str | None = None
    repos: list[RepoSpec] = []

    docker_image: str = "ghcr.io/scottcowan/warren-docker-base:latest"  # used for podman/docker runtimes
    # "bash" -- not "zsh" -- because every base image guarantees it (python:3.11-slim's
    # own default shell); zsh is commented out in both dev-base Dockerfiles, so a
    # project that doesn't set `app` got a tmux session whose command exited
    # immediately on a remote workspace, closing the container right after it started
    # (audit 2026-10-16 P0 #10).
    app: str = "bash"
    # AG2: `user` workspaces start at the warren shell, with `app` only the harness
    # `warren connect --harness` defaults to. `agent` (AG2b) runs `harness` headless
    # under warren's supervisor, serving ACP on `agent.port` (AM3).
    kind: Literal["user", "agent"] = "user"
    harness: str | None = None
    agent: AgentConfig | None = None
    # Agent harnesses this workspace runs besides `app` (AG1, warren_common/harness.py).
    harnesses: list[str] = []
    custom_harness: CustomHarness | None = None
    # false: harnesses that can hand a session to the vendor's cloud are rejected.
    allow_vendor_cloud: bool = True
    # How harnesses reach models. `bedrock`: through the workspace's own AWS
    # identity (aws export profile locally, task role on ECS); the operator's
    # Claude login is never handed over. Unset: inferred from env
    # (CLAUDE_CODE_USE_BEDROCK, ANTHROPIC_BEDROCK_BASE_URL).
    model_access: Literal["subscription", "bedrock"] | None = None
    scope: ScopeConfig | None = None
    mounts: list[MountSpec] = []
    secrets: list[SecretRef] = []
    docker_networks: list[str] = []
    aws: AwsConfig | None = None
    ssh: SshConfig | None = None
    ecs_cpu: str | None = None    # per-node Fargate CPU override (D-02)
    ecs_memory: str | None = None  # per-node Fargate memory override (D-02)
    idle_ttl_seconds: float | None = None  # per-project/template idle-reaper TTL override; None falls back to the server's global WarrenSettings.idle_ttl_seconds
    # AK2: git-crypt policy for this template's checkouts (warren_common.git_crypt).
    # `none` never delivers the key; `unlock_and_drop` decrypts at materialization
    # with the key in secret `git_crypt_key_secret` (base64), then deletes it.
    git_crypt: Literal["none", "unlock_and_drop"] = "none"
    git_crypt_key_secret: str = "GIT_CRYPT_KEY"
    # Destroy a workspace this long after the idle reaper stopped it (AH10). None
    # falls back to WarrenSettings.idle_destroy_seconds, which is off by default.
    idle_destroy_seconds: float | None = None
    # Plain, non-secret environment variables (e.g. OLLAMA_HOST). Values are
    # persisted in spec_json and visible in ECS task overrides: never put secrets
    # here, use `secrets`. Merged key-by-key through templates (child wins).
    env: dict[str, str] = {}
    # First turn handed to the app on provision, where the app supports one
    # (warren_common/seed_prompt.py lists which); ignored otherwise. Not a secret.
    seed_prompt: str | None = None
    ecs_image: str = "ghcr.io/scottcowan/warren-ecs-base:latest"  # used for ecs runtimes — a distinct, Alpine-based image built in images/ecs-base/ (no sshd; ECS Exec/SSM instead) — set independently of docker_image, no fallback between them

    templates: dict[str, "ProjectConfig"] = {}

    @field_validator("env")
    @classmethod
    def _env_names_valid(cls, v: dict[str, str]) -> dict[str, str]:
        for name in v:
            if not _ENV_NAME_RE.match(name):
                raise ValueError(f"env name {name!r} is not a valid environment variable name")
            if is_reserved_env_name(name):
                raise ValueError(f"env name {name!r} is reserved by warren")
        return v

    @field_validator("harnesses")
    @classmethod
    def _known_harnesses(cls, v: list[str]) -> list[str]:
        from warren_common.harness import check_harness_names  # noqa: PLC0415

        check_harness_names(v)
        return v

    def validate_harnesses(self) -> None:
        """Cross-field harness checks; run on a resolved template, since
        `custom_harness`/`allow_vendor_cloud` may come from a parent."""
        from warren_common.harness import (  # noqa: PLC0415
            HarnessSelectionError,
            bedrock_mode,
            validate_harness_selection,
        )

        from warren_common.agent_launch import check_agent_template  # noqa: PLC0415

        check_agent_template(self)
        validate_harness_selection(
            [*self.harnesses, *([self.harness] if self.kind == "agent" and self.harness else [])],
            custom_command=self.custom_harness.command if self.custom_harness else None,
            allow_vendor_cloud=self.allow_vendor_cloud,
            bedrock=bedrock_mode(self.model_access, self.env),
            secret_names=[s.name for s in self.secrets],
        )

    @model_validator(mode="before")
    @classmethod
    def _warn_unknown(cls, data: Any) -> Any:
        if isinstance(data, dict):
            known = set(cls.model_fields)
            project_name = data.get("name")
            for key in data:
                if key not in known:
                    log.warning(
                        "unknown_project_field", field=key, project=project_name
                    )
        return data

    def effective_folders(self) -> list[FolderSpec]:
        """Return the canonical folder list, converting legacy repos if needed."""
        if self.folders:
            return self.folders
        # Convert legacy repos to FolderSpec
        result = []
        for repo in self.repos:
            result.append(repo.to_folder_spec())
        return result


def collect_local_path_folders(cfg: ProjectConfig) -> list[FolderSpec]:
    """Every `local-path` folder reachable anywhere in `cfg`'s template tree
    (root `folders` plus every nested `templates.*` node's own `folders` --
    `_merge_fields` in templates.py treats `folders` as an ordinary override
    field, not something confined to the root, so a `local-path` folder
    declared on any nested template node takes effect exactly the same as
    one at the root; checking only the root would miss it).

    Shared by routes/projects.py (write-time reject) and
    routes/workspaces.py (provision-time re-validation, audit Y1/V2: the
    write-time check alone doesn't cover a user-scoped file that already
    held a `local-path` folder before that check existed, or that reached
    disk by some other path).
    """
    found = [f for f in cfg.folders if f.type == "local-path"]
    for child in cfg.templates.values():
        found.extend(collect_local_path_folders(child))
    return found


def collect_docker_networks(cfg: ProjectConfig) -> set[str]:
    """Every `docker_networks` entry reachable anywhere in `cfg`'s template tree
    (root `docker_networks` plus every nested `templates.*` node's own
    `docker_networks` -- same traversal as collect_local_path_folders above,
    since `_merge_fields` in templates.py treats `docker_networks` the same way:
    an ordinary override field, not something confined to the root).

    Used by routes/workspaces.py (R24) to decide whether a resolved template's
    docker_networks entry is admin-sanctioned (declared anywhere in the
    server-wide project file) versus only reachable through a user-scoped
    override, which must additionally pass WarrenSettings.allowed_docker_networks.
    """
    found = set(cfg.docker_networks)
    for child in cfg.templates.values():
        found |= collect_docker_networks(child)
    return found
