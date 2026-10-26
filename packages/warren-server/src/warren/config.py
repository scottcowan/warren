"""warren-server configuration loaded from WARREN_* environment variables (D-05)."""

from __future__ import annotations

import ipaddress
import re
import socket
from pathlib import Path
from typing import Annotated, Literal

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, NoDecode, SettingsConfigDict

# Audit 2026-10-16 P2 #44: both secret_key and bootstrap_token are used as raw key
# material (secret_key.encode() feeds auth/tokens.py's HMAC pepper derivation and
# secrets/cipher.py's Fernet key derivation directly -- neither is ever base64/hex-
# decoded first), so entropy is measured as raw character count, not decoded byte
# length. 32 is the same floor `generate_token()`'s own 256-bit CSPRNG output clears,
# and is small enough that a real `openssl rand -base64 32` value always passes.
_MIN_SECRET_LENGTH = 32


class WarrenSettings(BaseSettings):
    """Server settings sourced entirely from WARREN_* env vars.

    Fails fast (pydantic ValidationError) when SECRET_KEY is absent.
    """

    model_config = SettingsConfigDict(
        env_prefix="WARREN_",
        frozen=True,
        extra="ignore",
    )

    secret_key: SecretStr
    # Consulted at startup only when the `users` table has no admin yet (D-03/D-04);
    # maps to WARREN_BOOTSTRAP_TOKEN. Optional because normal restarts against an
    # already-bootstrapped database don't need it set.
    bootstrap_token: SecretStr | None = None

    @field_validator("secret_key")
    @classmethod
    def _validate_secret_key_entropy(cls, v: SecretStr) -> SecretStr:
        raw = v.get_secret_value()
        if len(raw) < _MIN_SECRET_LENGTH:
            raise ValueError(
                f"WARREN_SECRET_KEY must be at least {_MIN_SECRET_LENGTH} characters "
                f"(got {len(raw)}) -- generate one with e.g. `openssl rand -base64 32`"
            )
        return v

    @field_validator("bedrock_gateway_url")
    @classmethod
    def _validate_bedrock_gateway_url(cls, v: str) -> str:
        v = v.strip().rstrip("/")
        if v and not re.fullmatch(r"https://[A-Za-z0-9.-]+(:\d+)?(/[A-Za-z0-9._~/-]*)?", v):
            raise ValueError("WARREN_BEDROCK_GATEWAY_URL must be an https:// URL with no query or credentials")
        return v

    @field_validator("bootstrap_token")
    @classmethod
    def _validate_bootstrap_token_entropy(cls, v: SecretStr | None) -> SecretStr | None:
        if v is None:
            return v
        raw = v.get_secret_value()
        if len(raw) < _MIN_SECRET_LENGTH:
            raise ValueError(
                f"WARREN_BOOTSTRAP_TOKEN must be at least {_MIN_SECRET_LENGTH} characters "
                f"(got {len(raw)}) -- generate one with e.g. `openssl rand -base64 32`"
            )
        return v

    podman_socket: Path = Path("/run/user/1000/podman/podman.sock")
    max_workspaces: int = 10
    # Issue #11: max_workspaces is a server-wide cap and doesn't stop one owner from
    # exhausting it for everyone. Checked against non-terminal workspaces with
    # owner_id == user.user_id, alongside (not instead of) the server-wide cap.
    max_workspaces_per_user: int = 3

    # SSH host-port range for Phase 3 interactive access (D-05/D-06): a fixed, operator-
    # configurable range, never an OS-assigned ephemeral port. Half-open [start, end) —
    # scanned with `range(start, end)`. Defaults sit at 30000+, deliberately above 1024,
    # because rootless Podman cannot bind privileged ports without lowering the host's
    # `net.ipv4.ip_unprivileged_port_start` sysctl (RESEARCH.md Pitfall 1). When
    # `ssh_advertised_host` is empty, callers report `settings.server_id` instead.
    ssh_port_range_start: int = 30000
    ssh_port_range_end: int = 31000
    ssh_advertised_host: str = ""
    # Host address the podman workspace SSH port is published on. Loopback keeps it
    # unreachable from other workspaces (rootless podman gives containers no route to
    # host loopback); "" or a LAN address exposes it to the LAN and to workspaces alike,
    # leaving the per-workspace SSH key as the only barrier. `warren connect` doesn't use
    # this port (it runs `podman exec` over the operator's own SSH to the host).
    ssh_publish_host: str = "127.0.0.1"
    # Audit R12: the allocated SSH host port used to be published on every podman
    # workspace's container unconditionally, even though the in-container sshd this was
    # meant to serve was never actually built into the reference image (images/
    # workspace-base/ was never shipped -- see routes/workspaces.py's own "in-container
    # sshd was never built" comment). Publishing a port nothing listens on is at best
    # dead config and at worst an open, unauthenticated host port with nothing behind
    # it. Defaults to False (matches every real deployment today); only an operator
    # running a workspace image that actually ships sshd (e.g. this repo's own
    # integration-test fixture image) should set this. Port ALLOCATION/bookkeeping
    # (allocate_ssh_port, the ssh_port column) is unaffected either way -- this only
    # gates whether PodmanRuntime.provision() actually publishes it on the container.
    ssh_access_enabled: bool = False

    data_dir: Path = Path("/var/lib/warren")
    # Only needed when warren-server itself runs inside a container with
    # data_dir bind-mounted in from the host at a DIFFERENT path (the normal
    # deployment shape -- see the redeploy commands' own
    # `-v /mnt/.../warren-data/_data:/var/lib/warren`). GitManager clones
    # under data_dir, which is only a valid bind-mount SOURCE for a sibling
    # workspace container if it's actually a host path -- podman always
    # resolves bind_mounts sources against the host filesystem, since it
    # talks to the host's own podman daemon, never warren-server's container
    # namespace. Unset (empty, the default) means data_dir already IS a host
    # path (warren-server running directly on the host, not containerized);
    # registry.py's path translation is then a no-op. A real deployment with
    # this unset but warren-server containerized gets a 500 "statfs: no such
    # file or directory" on every git-clone workspace (observed directly
    # 2026-10-13) -- confusing, since the clone itself succeeds (it's visible
    # from inside warren-server's own container just fine).
    host_data_dir: Path | None = None
    # Audit #10: SQLite journal mode for warren.db. "auto" uses WAL on a local
    # filesystem and DELETE when data_dir is on a network filesystem (EFS/NFS),
    # where WAL's shared-memory index is not safe. Explicit "wal"/"delete" override.
    sqlite_journal_mode: Literal["auto", "wal", "delete"] = "auto"
    # Audit #10: how long startup waits for warren.db.lock (a stopped Fargate task's
    # NFSv4 lock can outlive it until the lease expires). 0 fails fast.
    writer_lock_wait_s: float = Field(default=120.0, ge=0)
    projects_dir: Path = Path.home() / ".warren" / "projects"
    server_id: str = Field(default_factory=socket.gethostname)

    # Runtime type selection — replaces hardcoded PodmanRuntime in app.py
    runtime_type: str = "podman"

    # ECS runtime — only consulted when runtime_type == "ecs"
    ecs_cluster: str = ""
    # Resource naming/path prefix used for SSM parameter paths, CloudWatch log
    # groups, and tags (ecs.py). Default "warren" matches every existing
    # deployment; override only when a deployment's own infra naming convention
    # doesn't use "warren" anywhere (see issue #2).
    # Always the leading "<prefix>-" of every task-definition family this server
    # registers, so it must be non-empty and family-safe (letters, digits, -, _).
    ecs_resource_prefix: str = Field(default="warren", pattern=r"^[A-Za-z0-9][A-Za-z0-9_-]{0,31}$")
    # NoDecode: pydantic-settings v2 otherwise JSON-decodes list[str] env vars in
    # EnvSettingsSource before pydantic validators ever run, raising SettingsError on the
    # bare comma-separated format Terraform's outputs.tf actually emits. NoDecode hands the
    # raw string to _split_comma_separated (mode="before") below instead.
    ecs_subnet_ids: Annotated[list[str], NoDecode] = Field(default_factory=list)
    ecs_security_group_ids: Annotated[list[str], NoDecode] = Field(default_factory=list)
    ecs_task_role_arn: str = ""
    ecs_task_execution_role_arn: str = ""
    aws_region: str = "us-east-1"
    # WARREN_BEDROCK_GATEWAY_URL: a Bedrock-compatible gateway (an LLM proxy) for
    # bedrock-mode workspaces. When set they get ANTHROPIC_BEDROCK_BASE_URL and
    # CLAUDE_CODE_SKIP_BEDROCK_AUTH=1 instead of calling Bedrock with their task role,
    # and their template must declare the ANTHROPIC_AUTH_TOKEN secret (the gateway key).
    bedrock_gateway_url: str = ""
    # Assumed-role ARNs trusted for warren.secrets ownership (auth/aws_identity.py) --
    # empty by default, meaning no assumed role is trusted, only plain IAM user ARNs.
    # An assumed role's session-name segment is chosen by whoever calls sts:AssumeRole,
    # not by AWS, so trusting one by a name convention alone (e.g. an "AWSReservedSSO_"
    # prefix) would be trusting whatever IAM allows an account to name a role --
    # that prefix is NOT confirmed to be reserved against customer-created roles.
    # Each entry is a regex matched with re.fullmatch against the ENTIRE assumed-role
    # ARN -- not a prefix match, since a pattern that only anchors the start would also
    # match any longer ARN sharing that prefix (e.g. a different role, or a different
    # session name on the same role), reopening the exact collision this list exists to
    # prevent. To trust one specific role regardless of session name, say so explicitly
    # with a wildcard on that segment, e.g.:
    #   arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Admin_abc123/[^/]+
    # An operator wiring up IAM Identity Center (or any other multi-principal-assumable
    # role) must list their own permission-set role's ARN pattern here explicitly,
    # verified in their own account -- warren never assumes it on their behalf.
    # Issue #31: unlike its NoDecode siblings below, this field must NOT be supplied
    # comma-separated -- each list item is a full regex, and a regex can legitimately
    # contain commas (character classes, among others), so splitting on "," silently
    # corrupts it into broken fragments. Supply this one ONLY as a JSON array, e.g.
    # WARREN_AWS_TRUSTED_ASSUMED_ROLE_PATTERNS='["arn:aws:sts::123456789012:assumed-role/Admin_[^/]+/[^/]+"]'.
    aws_trusted_assumed_role_patterns: Annotated[list[str], NoDecode] = Field(default_factory=list)
    ecs_cpu: str = "256"    # must be str; Fargate minimum; valid pair with 512 MiB
    ecs_memory: str = "512"  # must be str; Fargate minimum
    ecs_assign_public_ip: bool = False  # True = ENABLED (Template B public subnets), False = DISABLED (Templates A/C)
    # AD3: containerDefinitions[].user for workspace tasks. warren-ecs-base starts as root
    # only to take ownership of the volume mount point, then its entrypoint drops to warren
    # (1000:1000). Set this (e.g. "1000:1000") to force non-root for images that don't;
    # that skips the ownership step, which EFS access points don't need. Empty keeps the
    # image's own USER, since images that install tooling under /root
    # (warren-ecs-dev-base) break when forced to another uid.
    ecs_task_user: str = ""

    # Audit V1: ProjectConfig.ecs_image's own hardcoded default
    # ("ghcr.io/scottcowan/warren-ecs-base:latest") is this upstream repo's own public
    # image -- a deployment that builds/publishes its own ECS workspace image had no way
    # to make that the default without editing every project's ecs_image field
    # individually. Empty (default) means no override: routes/workspaces.py::
    # _resolve_image falls through to the resolved template's own ecs_image exactly as
    # before. Non-empty only takes effect for a template that never set its own
    # ecs_image (i.e. still equals ProjectConfig's hardcoded default) -- an explicit
    # per-project/template override always wins.
    ecs_default_image: str = ""

    # Audit #53: workspace log groups created via "awslogs-create-group" got infinite
    # retention with no way to expire them. ecs.py now explicitly creates the group and
    # sets this retention itself rather than relying on the awslogs driver's auto-create.
    ecs_log_retention_days: int = 90

    # BB4: how long connect/ensure_running waits on a task that is still
    # PROVISIONING/PENDING/ACTIVATING before failing with a retryable 503
    # (error "workspace_starting", Retry-After: ecs_start_retry_after_seconds),
    # instead of launching a second task. Keep the wait below client request
    # timeouts (the CLI uses 60s) so clients get the 503 and poll, not a timeout.
    ecs_start_wait_timeout_seconds: float = 45.0
    ecs_start_poll_interval_seconds: float = 3.0
    ecs_start_retry_after_seconds: int = 5
    # AI3: periodic sweep that stops this server's ECS tasks (startedBy + server_instance
    # tag) with no live workspace row. 0 disables. Tasks younger than the min age are
    # skipped so an in-flight provision is never mistaken for an orphan.
    ecs_orphan_sweep_interval_seconds: float = 900.0
    ecs_orphan_sweep_min_age_seconds: float = 900.0
    # AH1: image for the `git-init` container that materializes a workspace's git folders
    # onto its volume (runtime/ecs_git.py). Empty means the workspace's own image, which
    # must then derive from ecs-base (it ships /usr/local/bin/warren-git-materialize).
    ecs_git_init_image: str = ""
    # Extra known_hosts lines for git-init's ssh clones, on top of the GitHub host keys
    # pinned in the image. An ssh host not listed in either is refused.
    ecs_git_known_hosts: str = ""

    # WARREN_KMS_KEY_ID: customer-managed KMS key (ID, ARN or alias) for every SSM
    # SecureString PutParameter the secret mirror makes on ECS -- empty means SSM's
    # default `alias/aws/ssm` key. With a CMK the control plane needs only
    # kms:Encrypt on it and the task execution role kms:Decrypt (resources/ecs/README.md).
    kms_key_id: str = ""

    # EFS workspace persistence — only consulted when runtime_type == "ecs" and efs_id is non-empty
    efs_id: str = ""            # empty = ephemeral task storage only (D-10 opt-out)
    efs_retention_days: int = 7
    efs_reaper_interval_hours: int = 6
    # Configurable extra tag an external IaC deployment can require its own
    # CreateAccessPoint/DeleteAccessPoint IAM to be scoped to -- without hardcoding
    # knowledge of this app's own TAG_MANAGED constant (issue #7). Purely additive:
    # both empty (the default) means no extra tag is written, existing deployments
    # unaffected. Only meaningful together -- a key with no value (or vice versa)
    # is treated as unset.
    efs_access_point_tag_key: str = ""
    efs_access_point_tag_value: str = ""
    # Issue #30a: deleting an access point never frees space -- the actual data
    # under /var/lib/warren/workspaces/{id} lives on the EFS filesystem itself,
    # which boto3's EFS API has no "delete this directory" call for. If this
    # control plane's task has the filesystem NFS-mounted locally (wired via
    # IaC -- not something this setting does on its own), point this at that
    # mount root and the reaper will actually remove a workspace's directory
    # contents before deleting its access point. Empty (default): the reaper
    # still deletes the access point, but the data is orphaned until a mount
    # is wired up -- logged clearly rather than claimed as cleaned up.
    efs_local_mount_path: str = ""

    # Issue #11: `expires_at` existed in the tokens schema and in the query that resolves
    # a token to a user, but nothing ever wrote a value into it, so every minted token was
    # effectively permanent. This is the TTL applied at every token-creation site (bootstrap,
    # admin mint, self-service mint). 90 days balances "a stolen token eventually dies on its
    # own" against not forcing frequent re-auth for long-lived automation.
    token_ttl_days: int = 90
    # Issue #11: POST /tokens (and the admin mint-for-user route) let any valid token mint
    # unlimited further tokens with no cap, unboundedly growing a stolen token's blast radius.
    # Mirrors max_workspaces_per_user's per-user-cap convention/naming. Counts only live
    # (non-expired, non-revoked) tokens for the user — a revoked/expired token frees up room.
    max_tokens_per_user: int = 10

    # Idle-TTL reaper for Podman workspaces (LIFE-01, D-01/D-03): a background loop stops
    # any "running" workspace whose egress byte counter (network/egress.py) has not moved
    # in `idle_ttl_seconds`. KNOWN FALSE-POSITIVE MODE (04-RESEARCH.md Security Domain
    # table): a workspace doing long-running local compute with no network traffic reads
    # as idle and WILL be stopped even though it is legitimately busy. There is no way to
    # distinguish "idle" from "busy but silent on the network" from the host side alone —
    # this is why idle_ttl_seconds is an operator knob, not a hardcoded constant.
    idle_reaper_enabled: bool = True
    idle_ttl_seconds: float = 3600.0
    # AH10: destroy an idle-stopped workspace this long after the stop. None (the
    # default) never destroys; a template's own idle_destroy_seconds still applies.
    idle_destroy_seconds: float | None = None
    idle_reaper_poll_interval: float = 60.0
    # AM1: agent state from harness hooks (AG5) can hold a due workspace back: a
    # permission wait until blocked this long, anything at most hook_max_hold_seconds.
    blocked_ttl_seconds: float = 4 * 3600.0
    hook_max_hold_seconds: float = 24 * 3600.0

    # AH2: how long a destroyed single-turn workspace's events (ending in
    # workspace.completed) stay replayable via GET /workspaces/{id}/events?since=.
    single_turn_event_retention_seconds: float = 3600.0

    # #59: bounds on POST /workspaces/{id}/exec (and the MCP exec_command tool).
    exec_max_output_bytes: int = Field(default=1_048_576, ge=1024)
    exec_default_timeout_seconds: float = Field(default=60.0, gt=0)
    exec_max_timeout_seconds: float = Field(default=600.0, gt=0)

    # Egress shim socket (LIFE-02, node2 finding 2026-09-19): when set, the idle reaper
    # reads egress bytes over this Unix socket instead of shelling out to `podman unshare
    # --rootless-netns` inside warren-server's own container — a rootless container can
    # never genuinely own the kernel-level subuid range that needs, no matter what is
    # bind-mounted in. The socket is served by scripts/egress_shim.py, a small native
    # process run by the real host user (see docs/warren-server-deploy.md). Left unset,
    # the reaper falls back to the direct (nested, non-working) path — deliberately not a
    # hard failure, since containerized deployments predate this shim.
    egress_shim_socket: Path | None = None

    # Egress monitoring bridge (LIFE-02, D-04/D-05): name PREFIX of each workspace's own
    # isolated Podman bridge network (`<prefix>-<workspace_id>`, Finding 9), required because the rootless pasta default has no host-readable veth byte counters
    # (04-RESEARCH.md Pitfall 1). MONITORING ONLY — per D-05 the allowlist is "everything",
    # no egress is ever blocked by this field. ROADMAP.md Phase 4 Success Criterion #2's
    # "no outbound network access unless explicitly allowlisted" is explicitly NOT
    # delivered by this field; it only makes traffic observable, never restricts it.
    egress_bridge_name: str = "warren-egress"

    # GitHub App credentials for server-side git materialization (LIFE-03, D-08). Only the
    # PATH to the App's private key .pem is stored here, never the key bytes — a filesystem
    # path is not itself secret and typing it SecretStr would obstruct the
    # Path.read_bytes() the token minter needs to load it. The key material referenced by
    # this path is never logged and never returned in any API response.
    github_app_id: str = ""
    github_app_installation_id: str = ""
    github_app_private_key_path: Path | None = None
    # Audit T2: with no repository scoping, every minted installation token carries the
    # App installation's FULL access (every repo it's installed on) -- and any
    # authenticated non-admin user can trigger a clone of any github.com URL via their
    # own user-scoped project (no admin check on that write path, see routes/projects.py).
    # That handed any user org-wide clone access through the App. Fail closed: a non-empty
    # allow-list (repo short names, not owner/repo -- an App installation is already
    # scoped to one account/org) is required before GitHubAppCredentials will mint any
    # token at all; see github_app.py's GitHubAppCredentials.token().
    #
    # Audit V4: this allow-list is DEPLOYMENT-WIDE, not per-user -- every authenticated
    # user on this server can mint a token (and clone) for every repo named here, the
    # same as any other authenticated-user capability in this codebase (e.g. the
    # server's own docker socket access). It narrows the installation's full access down
    # to a known repo set; it does not add per-user authorization on top. A deployment
    # that needs per-user repo access control should either run one warren-server per
    # trust boundary, or restrict App-token clones to repos already named in a
    # server-wide (admin-managed) project -- not yet implemented.
    github_app_allowed_repos: Annotated[list[str], NoDecode] = Field(default_factory=list)
    git_worktree_root: Path = Path("/var/lib/warren/worktrees")

    # AK1 control-plane issuer: per-workspace installation tokens served at
    # GET /workspaces/{id}/git-credential, narrowed to that workspace's template
    # repos (not github_app_allowed_repos, which is the clone grant). The key is
    # read from Secrets Manager / SSM (`..._key_id` = secret id / parameter
    # name), which only the control-plane role may read; "file" reuses
    # github_app_private_key_path for single-host deployments. Empty = disabled.
    github_workspace_token_key_source: Literal["", "secretsmanager", "ssm", "file"] = ""
    github_workspace_token_key_id: str = ""
    github_api_base: str = "https://api.github.com"

    # R24: a user-scoped project (one any authenticated non-admin user can write
    # themselves -- no admin check on that write path, see routes/projects.py) can declare
    # `docker_networks: [...]` naming ANY host podman/docker network, including ones that
    # give access to other workspaces' internal traffic or host-adjacent networks. There
    # was no allow-list restricting which network names a user-scoped project may attach
    # to. Fail closed, same posture as github_app_allowed_repos above: an empty/unset
    # allow-list means NO networks may be attached by a user-scoped project, not
    # "everything allowed". Only applies to user-scoped projects -- a server-wide
    # (admin-managed) project is unrestricted, same trust tier as the existing
    # local-path exception (routes/workspaces.py's _server_sanctioned_local_paths).
    allowed_docker_networks: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # Audit Z12: same class as allowed_docker_networks above -- a user-scoped project
    # could otherwise name ANY docker_image/ecs_image from any registry it controls.
    # Fail closed: an empty/unset allow-list means no image outside what the server-wide
    # file (or the model's own hardcoded default) already sanctions may be used by a
    # user-scoped project. Only applies to user-scoped projects -- a server-wide
    # (admin-managed) project is unrestricted, same trust tier as the other exceptions
    # (routes/workspaces.py's _server_sanctioned_image).
    allowed_images: Annotated[list[str], NoDecode] = Field(default_factory=list)

    # Declarative image builds (LIFE-04, D-09). Defaults to False: building a
    # project-supplied arbitrary Containerfile executes arbitrary `RUN` commands on node2
    # with warren-server's own privileges (04-RESEARCH.md Pitfall 5, threat T-04-01-EOP) —
    # the operator must opt in explicitly per deployment.
    image_build_enabled: bool = False
    image_build_memory: str = "2g"
    image_build_cpus: float = 2.0

    @field_validator(
        "ecs_subnet_ids",
        "ecs_security_group_ids",
        "github_app_allowed_repos",
        "allowed_docker_networks",
        "allowed_images",
        mode="before",
    )
    @classmethod
    def _split_comma_separated(cls, v: object) -> object:
        """Accept both comma-separated (Terraform outputs.tf's actual format, D-05) and
        JSON-array env var values for these list[str] fields.

        These fields are annotated with pydantic-settings' `NoDecode` so
        `EnvSettingsSource` hands this validator the raw, un-decoded env var string
        instead of JSON-decoding it itself (and raising `SettingsError` on the bare
        comma-separated format) before any validator gets to run. This validator then
        does its own decode: bracketed strings are JSON-decoded (preserves the existing
        JSON-array behavior), everything else is split on commas. Non-string inputs
        (e.g. the field's own `default_factory=list`) pass through untouched.

        NOT used for aws_trusted_assumed_role_patterns -- see
        _decode_json_array_only below for why that field needs different parsing.
        """
        if isinstance(v, str):
            stripped = v.strip()
            if not stripped:
                return []
            if stripped.startswith("["):
                import json

                return json.loads(stripped)
            return [item.strip() for item in v.split(",") if item.strip()]
        return v

    @field_validator("aws_trusted_assumed_role_patterns", mode="before")
    @classmethod
    def _decode_json_array_only(cls, v: object) -> object:
        """Issue #31: each item in this field is a full regex pattern, and a regex
        can legitimately contain commas (e.g. inside a character class) -- splitting
        on "," the way `_split_comma_separated` does for its NoDecode siblings would
        silently mangle a pattern into broken fragments instead of failing loudly.
        So this field only ever accepts a JSON array; a bare comma-separated string
        (the other fields' format) is rejected rather than guessed at.
        """
        if isinstance(v, str):
            stripped = v.strip()
            if not stripped:
                return []
            if not stripped.startswith("["):
                raise ValueError(
                    "aws_trusted_assumed_role_patterns must be a JSON array (not "
                    "comma-separated) -- each pattern is a regex and commas inside "
                    "one are meaningful, e.g. "
                    '\'["arn:aws:sts::123456789012:assumed-role/Admin_[^/]+/[^/]+"]\''
                )
            import json

            return json.loads(stripped)
        return v


class BindSettings(BaseSettings):
    """Where `python -m warren` listens (finding 14). Separate from WarrenSettings so the
    listener can be validated before the app (and its required secrets) loads.

    Loopback by default: bearer tokens and SSH private keys cross this socket. ECS reaches
    it over an SSM port-forward, which lands on the task's own loopback. Anything else
    (a container published with `-p`, a LAN host) must set WARREN_HOST, and a non-loopback
    bind without WARREN_TLS_CERTFILE/WARREN_TLS_KEYFILE is refused unless
    WARREN_ALLOW_INSECURE_HTTP=1 acknowledges the cleartext transport.
    """

    model_config = SettingsConfigDict(env_prefix="WARREN_", frozen=True, extra="ignore")

    host: str = "127.0.0.1"
    port: int = 8420
    tls_certfile: Path | None = None
    tls_keyfile: Path | None = None
    allow_insecure_http: bool = False

    @property
    def is_loopback(self) -> bool:
        if self.host == "localhost":
            return True
        try:
            return ipaddress.ip_address(self.host).is_loopback
        except ValueError:
            return False

    @property
    def tls_enabled(self) -> bool:
        return self.tls_certfile is not None and self.tls_keyfile is not None

    @model_validator(mode="after")
    def _check_transport(self) -> BindSettings:
        if (self.tls_certfile is None) != (self.tls_keyfile is None):
            raise ValueError("WARREN_TLS_CERTFILE and WARREN_TLS_KEYFILE must be set together")
        if not self.is_loopback and not self.tls_enabled and not self.allow_insecure_http:
            raise ValueError(
                f"refusing to serve cleartext HTTP on non-loopback WARREN_HOST={self.host!r}: "
                "bearer tokens and SSH keys would cross the network unencrypted. Set "
                "WARREN_TLS_CERTFILE/WARREN_TLS_KEYFILE, or WARREN_ALLOW_INSECURE_HTTP=1 if "
                "the port is only reachable through a trusted hop (e.g. `-p 127.0.0.1:8420:8420`)"
            )
        return self
