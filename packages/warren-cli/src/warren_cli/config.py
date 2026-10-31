"""warren CLI config loader.

Reads ``~/.warren/config.toml`` via stdlib ``tomllib`` and validates it against a
pydantic model that supports both the flat single-server ``[server]`` schema and
the multi-server ``[servers.<name>]`` schema per D-06, plus a local-only schema
(no ``[servers.*]``) written by ``warren init`` in local mode.
"""

from __future__ import annotations

import os
import tomllib
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlparse

import tomli_w
from pydantic import BaseModel, ConfigDict, Field, SecretStr
from warren_common.fileperms import restrict_to_owner


DEFAULT_CONFIG_PATH = Path.home() / ".warren" / "config.toml"

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1"}


def is_insecure_http_url(url: str) -> bool:
    """True when ``url`` is plaintext ``http://`` and not a loopback address.

    Used to gate sending a bearer token: a token sent over plaintext HTTP to
    anything but localhost is readable by anyone on the network path.
    """
    parsed = urlparse(url)
    if parsed.scheme != "http":
        return False
    host = (parsed.hostname or "").lower()
    return host not in _LOOPBACK_HOSTS


def read_config_toml(path: Path) -> dict[str, Any]:
    """Parse ``path`` into a plain dict (stdlib ``tomllib``, read-only)."""
    with open(path, "rb") as f:
        return tomllib.load(f)


def write_config_toml(path: Path, data: dict[str, Any]) -> None:
    """Write ``data`` back out as TOML via ``tomli_w``.

    Values are escaped correctly by the TOML writer rather than interpolated
    into f-strings, so a quote, backslash, or newline in a url/token/ssh_host
    can't break the file's structure or inject unintended keys/tables.

    S8: this file holds the server's own auth_token (bearer token), so its
    permissions matter. ``Path.write_text`` creates a brand-new file at
    whatever the process umask leaves it (commonly 0644, world-readable) --
    relying on umask alone means a deployment with a looser umask (or a
    caller that changed it) silently leaves the token readable by every
    local user. Open with an explicit 0600 mode via ``os.open`` instead of
    relying on umask, and ``os.chmod`` every time regardless of whether the
    file already existed -- same "defense, not reliance on umask" pattern
    warren-server's registry/store.py's ``open_db`` already uses for the
    local secrets DB (chmod'd 0600 on every call, not just on first
    creation, so a file left world/group-readable by an older version of
    this code is corrected on the next write, not just the first one).

    S8 (2): if this ever needs to preserve a user's own hand-edited comments
    in config.toml, ``tomli_w.dumps`` does a full rewrite from the parsed
    dict and has no concept of comments to preserve -- that's a known,
    accepted limitation here, not fixed, since switching to a round-trip
    editor (e.g. tomlkit) is a bigger dependency change than this fix
    warrants on its own.
    """
    text = tomli_w.dumps(data)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        os.write(fd, text.encode("utf-8"))
    finally:
        os.close(fd)
    restrict_to_owner(path)  # 0600 / owner-only DACL, even if the file already existed


class ServerProfile(BaseModel):
    """A single warren-server connection profile."""

    model_config = ConfigDict(extra="forbid")

    url: str
    auth_token: SecretStr


class RemoteProfile(BaseModel):
    """A warren-server remote for workspace/project commands (``--server``/``warren remote add``).

    ``auth_token`` is optional so existing no-auth configs (a server with ``AuthMiddleware``
    disabled, or a local dev server) keep working unchanged — but any server that enforces
    per-user auth (the built-in auth provider added in Phase 2) will 401 every request from
    this profile until a token is set here.

    ``runtime_type="ecs"`` means the server has no direct network path at all — the control
    plane's HTTP API is only reachable via an SSM port-forward into its own orchestrator task,
    never assumed to be directly reachable at ``url``. ``url`` is unused in that case; ``client.py``
    establishes the tunnel and points the HTTP client at the resulting local port instead.

    ``runtime_type="ssh"`` is the podman/docker equivalent: the server commonly binds its
    control plane to loopback only on its own host (every redeploy in this project's own
    runbook uses ``-p 127.0.0.1:8420:8420``), reachable only via an SSH local port-forward to
    that host — same shape as the ECS case, just a plain ``ssh -L`` instead of an SSM session.
    ``url`` is unused here too; ``client.py`` establishes the tunnel via ``ssh_host`` instead.
    """

    model_config = ConfigDict(extra="forbid")

    url: str | None = None
    auth_token: SecretStr | None = None
    runtime_type: Literal["http", "ecs", "ssh"] = "http"
    ecs_cluster: str | None = None
    ecs_service: str | None = None
    ssh_host: str | None = None       # e.g. "node2" (an ssh config Host alias) or "user@1.2.3.4"
    ssh_key_path: str | None = None   # e.g. "~/.ssh/id_homelab" -- passed to ssh -i verbatim
    ssh_remote_port: int = 8420       # the control plane's port on the far side of the tunnel
    # For an ECS AWS-identity server reached behind a tunnel: the server's own
    # `settings.server_id` (shown by `warren healthz` as `warren_id`). The signed
    # GetCallerIdentity request's X-Warren-Audience header is bound to this, not to
    # `url` (meaningless here -- a tunnel's local port is an ephemeral implementation
    # detail, not the server's identity). Required (enforced below) for every
    # `runtime_type="ecs"` profile, since an ECS-mode server's PUT/GET/DELETE /secrets
    # and POST /workspaces all resolve ownership via the AWS-identity path -- an
    # ecs profile with no working audience can't do anything useful. Not enforced for
    # `runtime_type="ssh"`: that tunnel shape is documented above as the podman/docker
    # equivalent, pointed at a server whose own settings.runtime_type is "podman"/
    # "docker", which never consults this header at all -- only set `aws_audience` on
    # an ssh profile in the rare case it tunnels into an actual ECS-mode server instead.
    aws_audience: str | None = None

    def model_post_init(self, __context: Any) -> None:
        if self.runtime_type == "http" and not self.url:
            raise ValueError("RemoteProfile with runtime_type='http' requires 'url'")
        if self.runtime_type == "ecs" and not (self.ecs_cluster and self.ecs_service):
            raise ValueError("RemoteProfile with runtime_type='ecs' requires 'ecs_cluster' and 'ecs_service'")
        if self.runtime_type == "ecs" and not self.aws_audience:
            raise ValueError(
                "RemoteProfile with runtime_type='ecs' requires 'aws_audience' (the server's "
                "server_id, shown by `warren healthz` as warren_id) -- otherwise every AWS-identity "
                "request (secrets, new) 401s at request time instead of failing here at config load"
            )
        if self.runtime_type == "ssh" and not self.ssh_host:
            raise ValueError("RemoteProfile with runtime_type='ssh' requires 'ssh_host'")


class RuntimeSection(BaseModel):
    """Typed [runtime] table from config.toml (D-03)."""

    model_config = ConfigDict(extra="ignore")

    type: Literal["auto", "docker", "bwrap", "seatbelt", "nsjail"] = "auto"


class CLIDefaults(BaseModel):
    """Typed [defaults] table from config.toml."""

    model_config = ConfigDict(extra="ignore")

    mode: Literal["local", "server"] = "local"
    projects_dir: str | None = None
    server: str | None = None
    project: str | None = None


class GitHubAppSection(BaseModel):
    """`[github_app]`: the local CLI GitHub token issuer (AK1). The App's private
    key lives in the OS credential store under (`key_service`, `app_id`), never
    in this file or under ~/.warren. Omit the section to disable the local issuer
    (team deployments: the control plane is the only key holder)."""

    model_config = ConfigDict(extra="ignore")

    app_id: str
    key_service: str = "warren-github-app"
    api_base: str = "https://api.github.com"
    installations: dict[str, str] = Field(default_factory=dict)


class WindowsSection(BaseModel):
    """`[windows]`: opt-in forwarding of `warren ...` on native Windows to
    `wsl warren ...` (AC2.5, read early by `warren_cli.wslshim`)."""

    model_config = ConfigDict(extra="ignore")

    forward_to_wsl: bool = False
    wsl_distro: str = ""


class ProxySection(BaseModel):
    """`[proxy]`: `warren proxy run` settings (flags on `run` override these).

    ``idle_minutes``: stop a mapping's SSM session after this long with no client
    connections (0 = keep it until it dies). ``keepalive_seconds``: while clients are
    connected, open and close a probe connection through the session this often, so
    the SSM session carries traffic even when the app is quiet (0 = off; see
    docs/proxy.md for what this can and can't keep alive). ``port_base``: first local
    port tried when `warren proxy add` picks one."""

    model_config = ConfigDict(extra="ignore")

    idle_minutes: float = Field(default=30.0, ge=0)
    keepalive_seconds: float = Field(default=240.0, ge=0)
    port_base: int = Field(default=47100, ge=1024, le=65535)


class WarrenCLIConfig(BaseModel):
    """Top-level CLI configuration.

    Multi-server schema is canonical; a flat ``[server]`` table is auto-upgraded
    to ``servers.default`` at load time so long-standing single-server configs
    keep working. Local-only configs (no ``[servers.*]``) also validate.
    """

    model_config = ConfigDict(extra="ignore")

    default_server: str = "default"
    servers: dict[str, ServerProfile] = Field(default_factory=dict)
    defaults: CLIDefaults = Field(default_factory=CLIDefaults)
    runtime: RuntimeSection = Field(default_factory=RuntimeSection)
    images: dict[str, str] = Field(default_factory=dict)
    remotes: dict[str, RemoteProfile] = Field(default_factory=dict)
    github_app: GitHubAppSection | None = None
    windows: WindowsSection = Field(default_factory=WindowsSection)
    proxy: ProxySection = Field(default_factory=ProxySection)

    @classmethod
    def load(cls, path: Path | None = None) -> "WarrenCLIConfig":
        target = Path(path) if path is not None else DEFAULT_CONFIG_PATH
        if not target.exists():
            raise FileNotFoundError(
                f"warren CLI config not found at {target} — create it with the "
                "schema documented in the warren-server runbook"
            )
        with open(target, "rb") as f:
            data: dict[str, Any] = tomllib.load(f)
        if "server" in data and "servers" not in data:
            flat = data.pop("server")
            data = {**data, "servers": {"default": flat}, "default_server": "default"}
        return cls.model_validate(data)

    def get_profile(self, name: str | None) -> ServerProfile:
        key = name or self.default_server
        if key not in self.servers:
            raise KeyError(
                f"server profile {key!r} is not defined in this config "
                f"(known profiles: {sorted(self.servers)})"
            )
        return self.servers[key]

    def get_remote(self, name: str) -> RemoteProfile:
        if name not in self.remotes:
            raise KeyError(
                f"remote {name!r} is not defined in this config "
                f"(known remotes: {sorted(self.remotes)})"
            )
        return self.remotes[name]

    def projects_path(self) -> Path:
        if self.defaults.projects_dir:
            return Path(self.defaults.projects_dir)
        return Path.home() / ".warren" / "projects"
