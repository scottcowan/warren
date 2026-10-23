"""PodmanRuntime — podman-py 5.8 against a rootless Podman socket.

Every podman-py call is synchronous; each is wrapped in `asyncio.to_thread`
exactly once at the method boundary (D-01, Pitfall #17). Container labels
follow D-11 and are the only trust anchor for reconciliation (D-12).
"""

from __future__ import annotations

import asyncio
import io
import json
import threading
import tarfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, AsyncIterator, Literal

import structlog
from podman import PodmanClient
from podman.errors import APIError, BuildError, ImageNotFound, NotFound
from podman.errors.exceptions import PodmanError

from warren.images.build_spec import BuildSpec
from warren_common.errors import ImageUnavailable, RuntimeUnreachable
from warren_common.agent_launch import SPEC_ENV as AGENT_SPEC_ENV
from warren_common.harness_shell import seed_env, server_env, shell_first, workspace_shell
from warren_common.models import template_env_for
from warren_common.seed_prompt import app_command_with_seed
from warren_common.runtime.base import (
    SIDECAR_TOKEN_ENV,
    ExecExit,
    WorkspaceHandle,
    WorkspaceSpec,
    new_sidecar_token,
)

if TYPE_CHECKING:
    from warren.registry.events import WorkspaceEventBuffer

log = structlog.get_logger(__name__)

_WARREN_LABEL_WORKSPACE_ID = "warren.workspace_id"
_WARREN_LABEL_SERVER_INSTANCE = "warren.server_instance"
_WARREN_LABEL_PROJECT = "warren.project"
_WARREN_LABEL_INTENT = "warren.intent"
_WARREN_LABEL_NETWORK = "warren.network"

# Netavark (and CNI, via ingressPolicy) drops forwarded traffic between two
# networks that both carry `isolate`; "strict" (netavark >= 1.7) also drops
# traffic to non-isolated networks. Either keeps one workspace's bridge from
# reaching another's.
_ISOLATE_VALUES = ("true", "strict")

# Injection target for the minted SSH public key (D-01/D-02). Root-owned,
# pre-created by the reference workspace image's Containerfile (plan 03-02) —
# put_archive() extracts INTO an existing directory, it does not create one.
_AUTHORIZED_KEYS_DIR = "/etc/warren"

# Bounds every podman-py HTTP call made through this client. Without an explicit
# timeout, PodmanClient defaults to socket._GLOBAL_DEFAULT_TIMEOUT (effectively
# unbounded) — an unresponsive or slow Podman socket then hangs the calling
# coroutine (and the asyncio.to_thread worker thread backing it) indefinitely,
# with no way to recover short of restarting the process. Discovered via a
# real-socket integration test (Phase 1, 01-02) where provision() took ~5
# minutes against a Podman-version-mismatched host.
_DEFAULT_CLIENT_TIMEOUT_SECONDS = 30.0


_MEMORY_SUFFIXES: dict[str, int] = {"k": 1024, "m": 1024**2, "g": 1024**3}


def _parse_memory_bytes(memory: str) -> int:
    """Parse a docker/podman-style memory string ("2g", "512m", "1024") into bytes.

    Used only to build `container_limits["memory"]` for `build_image()` (LIFE-04,
    T-04-04-DOS) -- node2 (podman 4.9.3) confirmed `--memory`/`--cpus` resource
    limiting is available (04-02-SUMMARY.md), so this ceiling is enforced, not
    merely logged.
    """
    text = memory.strip().lower()
    if text and text[-1] in _MEMORY_SUFFIXES:
        return int(float(text[:-1]) * _MEMORY_SUFFIXES[text[-1]])
    return int(text)


def _authorized_keys_tar(pubkey_line: str) -> bytes:
    """Build an in-memory uncompressed tar containing a single `authorized_keys` member.

    `put_archive()` extracts INTO an existing directory, so the tar
    member name must be the bare filename (not a path) — the target directory
    (`_AUTHORIZED_KEYS_DIR`) is pre-created by the workspace image
    (RESEARCH.md Assumption A3). For a non-empty `pubkey_line` the payload is
    the key line UTF-8 encoded with a single trailing newline; an empty string
    produces a zero-byte member, used by `_wipe_authorized_keys` (D-03) to
    invalidate a previously injected key without deleting the file itself.

    Mode is 0o644, not 0o600: this file is root-owned (put_archive always
    extracts as root) but read by sshd's unprivileged, per-user child process
    running AS the target login user (warren/warren-shell), not as root. A
    0o600 root-owned file is unreadable by that user and sshd fails pubkey
    auth with "Could not open ... Permission denied" — verified live against
    a real rootless Podman host (node2, 2026-09-19) during this phase's
    checkpoint verification. World-readable is safe here: the file's parent
    directory is root-owned 0755 (not writable by warren/warren-shell), so
    only root can ever write this file's contents.
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        data = (pubkey_line.encode() + b"\n") if pubkey_line else b""
        info = tarfile.TarInfo(name="authorized_keys")
        info.size = len(data)
        info.mode = 0o644
        tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


class PodmanRuntime:
    """Concrete ContainerRuntime backed by podman-py."""

    # Capability flag: WorkspaceRegistry gates its SSH wiring on
    # hasattr(runtime, "supports_ssh_access") — the same optional-capability
    # pattern already used for stream_logs at registry.py:68 — because
    # FakeRuntime, DockerRuntime, and ECSRuntime all still expose the 1-arg
    # provision(spec) signature and must keep working untouched.
    supports_ssh_access: bool = True

    # Capability flag: routes/workspaces.py gates LIFE-04 declarative builds on
    # hasattr(runtime, "supports_image_build") -- the same optional-capability
    # pattern as supports_ssh_access above -- because FakeRuntime, DockerRuntime,
    # and ECSRuntime have no `build_image()` method and must keep working
    # untouched. `tests/unit/test_runtime_boundary.py` names workspaces.py
    # explicitly, so routes reach this only through the capability check, never
    # a direct podman import.
    supports_image_build: bool = True

    def __init__(
        self,
        socket_path: str | Path,
        server_id: str,
        *,
        client_timeout: float = _DEFAULT_CLIENT_TIMEOUT_SECONDS,
        egress_bridge_name: str = "warren-egress",
    ) -> None:
        self._socket_path = str(socket_path)
        self._server_id = server_id
        self._client = PodmanClient(
            base_url=f"unix://{self._socket_path}", timeout=client_timeout
        )
        # D-04: prefix of each workspace's own bridge network (Finding 9);
        # app.py threads settings.egress_bridge_name through. "" = pasta default.
        self._egress_bridge_name = egress_bridge_name

    # --- ContainerRuntime Protocol surface ---

    async def provision(
        self,
        spec: WorkspaceSpec,
        *,
        ssh_port: int | None = None,
        ssh_public_key: str | None = None,
        publish_ssh_port: bool = True,
    ) -> WorkspaceHandle:
        labels = {
            _WARREN_LABEL_WORKSPACE_ID: spec.workspace_id,
            _WARREN_LABEL_SERVER_INSTANCE: self._server_id,
            _WARREN_LABEL_PROJECT: spec.project,
            _WARREN_LABEL_INTENT: spec.intent,
        }
        mounts = [
            {"type": "bind", "source": host, "target": container, "read_only": mode == "ro"}
            for (host, container, mode) in spec.bind_mounts
        ]
        # Inject warren-managed env vars (D-05, 04-05). Build a merged dict so
        # that user-supplied spec.env values take precedence for every key
        # EXCEPT warren's own reserved vars (WARREN_WORKSPACE_ID/WARREN_APP/
        # WARREN_WORKTREE_PATHS), which always win over spec.env.
        #
        # Audit 2026-10-16 P1 #34: this previously put **spec.env LAST, so a
        # secret literally named e.g. WARREN_WORKSPACE_ID or WARREN_APP (an
        # innocuous-looking name to whoever created it) silently overrode
        # warren's own value -- breaking the entrypoint's preflight checks or
        # app launch in a very confusing way. spec.env is now merged FIRST,
        # with the reserved vars applied on top so they always win,
        # regardless of what the resolved template/secrets happen to name.
        worktree_paths_val = ":".join(
            container_path for _, container_path in spec.worktree_paths
        )
        sidecar_token = spec.sidecar_token or new_sidecar_token()
        env = {
            **template_env_for(spec.template_env, exclude=spec.env),
            **spec.env,
            # AG3: harness names only; the image's harness.sh/warren-harness-init carry the profile data.
            **server_env(spec.harnesses, app=spec.app, mode=spec.mode),
            "WARREN_WORKSPACE_ID": spec.workspace_id,
            "WARREN_WORKTREE_PATHS": worktree_paths_val,
            # entrypoint.py reads WARREN_APP (falling back to "bash") to pick the
            # foreground app -- this was never set here, so every workspace ran
            # bash regardless of its resolved template's `app` field (real,
            # previously-shipped gap, fixed 2026-10-13 alongside routes/workspaces.py
            # actually threading template_cfg.app into WorkspaceSpec.app at all).
            "WARREN_APP": app_command_with_seed(spec.app, spec.seed_prompt),
            # Read by the shared banner/prompt zsh snippet baked into this image's
            # .zshrc (warren_common/assets/warren_banner.zsh) at shell-start time --
            # UX-1: a zsh template needs these to render the banner on a remote
            # connect, same as the local workspace zshrc already gets from spec.env.
            "WARREN_PROJECT": spec.project,
            "WARREN_TEMPLATE": spec.intent,
            SIDECAR_TOKEN_ENV: sidecar_token,
        }
        if spec.model_access == "bedrock" and not (
            "AWS_ACCESS_KEY_ID" in env or "AWS_CONTAINER_CREDENTIALS_FULL_URI" in env
        ):
            log.warning(
                "bedrock_without_aws_credentials",
                workspace_id=spec.workspace_id,
                detail="podman workspaces have no AWS identity; declare AWS credentials as secrets",
            )
        # AG2a: a user workspace starts at the warren shell, which connect runs in tmux
        # session `main`; the container stays up when the shell or a harness exits.
        # AG2b: an agent workspace runs the supervisor next to that shell.
        if spec.agent is not None:
            env[AGENT_SPEC_ENV] = json.dumps(spec.agent, separators=(",", ":"))
            env["WARREN_APP"] = workspace_shell(spec.app)
            env["WARREN_SHELL_FIRST"] = "1"
        elif shell_first(spec.app, spec.mode):
            env.update(seed_env(spec.app, spec.harnesses, spec.seed_prompt))
            env["WARREN_APP"] = workspace_shell(spec.app)
            env["WARREN_SHELL_FIRST"] = "1"
        create_kwargs: dict[str, Any] = dict(
            image=spec.image,
            labels=labels,
            environment=env,
            mounts=mounts,
            init=True,
            detach=True,
            remove=False,
            restart_policy={"Name": "no"},
        )
        # Publish the allocated SSH host port (D-05: fixed at provision time,
        # lives for the workspace's whole life). Only include the `ports`
        # kwarg when a port was actually allocated — never auto-assign an
        # OS-assigned ephemeral port; D-06 explicitly rejects that in favor
        # of a fixed configured range chosen by the caller before
        # provision() is called.
        #
        # Audit R12: `publish_ssh_port` (default True, matching every existing
        # direct caller of this method, e.g. test_provision_publishes_ssh_port_when_given)
        # additionally gates the actual container-level publish -- the registry
        # threads this from `settings.ssh_access_enabled` (default False), since no
        # shipped workspace image actually runs sshd on this port yet. This is
        # deliberately NOT "omit ssh_port" -- allocation/bookkeeping (the stored
        # ssh_port column, allocate_ssh_port()) stays exactly as it was; only
        # whether the port is actually exposed on the container changes.
        if ssh_port is not None and publish_ssh_port:
            ports={"22/tcp": ssh_port}
            create_kwargs["ports"] = ports

        # D-04: rootless `pasta` has no veth pair and so no host-readable byte
        # counters (04-RESEARCH.md Pitfall 1), so every workspace is attached to
        # a netavark bridge for LIFE-02's egress counting. Finding 9: one bridge
        # PER WORKSPACE, created with `isolate`, so a workspace can't reach any
        # other workspace's ports. Outbound traffic still NATs out through the
        # bridge as before (D-05: observed, never blocked). SSH is a
        # host-published port and the control plane reaches the container
        # through the Podman API (exec/put_archive/logs), so neither needs a
        # network shared between workspaces.
        network_name = ""
        if self._egress_bridge_name:
            network_name = self._workspace_network_name(spec.workspace_id)
            await asyncio.to_thread(
                _ensure_workspace_network,
                self._client,
                network_name,
                {
                    _WARREN_LABEL_WORKSPACE_ID: spec.workspace_id,
                    _WARREN_LABEL_SERVER_INSTANCE: self._server_id,
                    _WARREN_LABEL_NETWORK: "workspace",
                },
            )
            create_kwargs["networks"] = {network_name: {}}
            # podman-py only populates the create payload's `netns` field when
            # `network_mode` is explicitly passed (see containers_create.py's
            # `network_mode in args` check) -- omitting it leaves the
            # server-side default netns mode in place, and the Podman REST
            # API rejects a `networks` dict against any non-bridge netns with
            # "networks and static ip/mac address can only be used with
            # Bridge mode networking". Discovered live against a real node2
            # socket (04-02's own unit tests mock the client and never
            # exercise this server-side validation).
            create_kwargs["network_mode"] = "bridge"

        try:
            container = await asyncio.to_thread(
                self._client.containers.create,
                **create_kwargs,
            )
        except ImageNotFound as e:
            await self._remove_network_quietly(network_name)
            raise ImageUnavailable(str(e)) from e
        except (APIError, PodmanError, ConnectionError) as e:
            await self._remove_network_quietly(network_name)
            raise RuntimeUnreachable(str(e)) from e

        # Inject the minted public key BEFORE start() so sshd never runs a
        # single second with a stale or absent key file. put_archive() does
        # not require a running container (D-01/D-02 mint at connect time,
        # not provision time, so this same path is reused by inject_ssh_key
        # against an already-existing container).
        if ssh_public_key is not None:
            await self._put_authorized_keys(container, ssh_public_key)
            log.info(
                "ssh_key_injected",
                workspace_id=spec.workspace_id,
                ssh_port=ssh_port,
            )

        try:
            await asyncio.to_thread(container.start)
        except (APIError, PodmanError, ConnectionError) as e:
            raise RuntimeUnreachable(str(e)) from e

        return WorkspaceHandle(
            workspace_id=spec.workspace_id,
            runtime_id=container.id,
            root_path=spec.root_path,
            sidecar_url="",
            sidecar_socket_path="/tmp/warren-sidecar.sock",  # D-12: fixed path
            sidecar_token=sidecar_token,
        )

    async def start(self, handle: WorkspaceHandle) -> None:
        container = await asyncio.to_thread(self._client.containers.get, handle.runtime_id)
        await asyncio.to_thread(container.start)

    async def build_image(self, spec: BuildSpec) -> str:
        """Build a project-supplied Containerfile into `spec.tag` (LIFE-04, D-09).

        Short-circuits without rebuilding when `spec.tag` already exists
        locally -- an unchanged Containerfile hashes to the same tag
        (`build_spec.resolve_build_spec`), so this call is naturally
        idempotent across repeated provisions of the same project state.

        Resource limits (`spec.memory`/`spec.cpus`) are always passed as
        `container_limits` -- node2's podman 4.9.3 confirmed `--memory`/
        `--cpus` build flags are available (04-02-SUMMARY.md, Assumption A4),
        so T-04-04-DOS is mitigated, not merely logged as unlimited.
        """
        existing = await asyncio.to_thread(
            self._client.images.list, filters={"reference": spec.tag}
        )
        if existing:
            return spec.tag

        container_limits: dict[str, int] = {"memory": _parse_memory_bytes(spec.memory)}
        if spec.cpus:
            cpu_period = 100_000
            container_limits["cpuperiod"] = cpu_period
            container_limits["cpuquota"] = int(spec.cpus * cpu_period)

        dockerfile_rel = str(spec.containerfile.relative_to(spec.context_dir))
        try:
            await asyncio.to_thread(
                self._client.images.build,
                path=str(spec.context_dir),
                dockerfile=dockerfile_rel,
                tag=spec.tag,
                rm=True,
                pull=False,
                container_limits=container_limits,
            )
        except ImageNotFound as e:
            raise ImageUnavailable(str(e)) from e
        except (APIError, PodmanError, ConnectionError, BuildError) as e:
            raise RuntimeUnreachable(str(e)) from e

        return spec.tag

    async def _put_authorized_keys(self, container: Any, ssh_public_key: str) -> None:
        """Write `_AUTHORIZED_KEYS_DIR/authorized_keys` into `container` via put_archive.

        Shared by `provision()` and `inject_ssh_key()` so there is exactly one
        place that knows the injection path and tar shape. Also reused by
        `_wipe_authorized_keys` with an empty key line to invalidate (D-03).
        `put_archive` — not `exec_run` — is the mechanism precisely because it
        works whether or not the container is running.
        """
        try:
            await asyncio.to_thread(
                container.put_archive,
                path=_AUTHORIZED_KEYS_DIR,
                data=_authorized_keys_tar(ssh_public_key),
            )
        except (APIError, PodmanError, ConnectionError) as e:
            raise RuntimeUnreachable(str(e)) from e

    async def inject_ssh_key(self, handle: WorkspaceHandle, ssh_public_key: str) -> None:
        """Write the minted public key into an EXISTING container's authorized_keys.

        D-01/D-02 mint the credential at connect time, not provision time, so
        the key must be writable into an already-existing container (created,
        running, or stopped — put_archive needs no running process). This is
        what plan 03-04's connect-time credential issuance calls;
        provision() routes through `_put_authorized_keys` internally too.
        """
        try:
            container = await asyncio.to_thread(
                self._client.containers.get, handle.runtime_id
            )
        except NotFound as e:
            # A caller minting a credential must learn the target does not
            # exist — never silently swallow this the way destroy() does.
            raise RuntimeUnreachable(str(e)) from e
        except (APIError, PodmanError, ConnectionError) as e:
            raise RuntimeUnreachable(str(e)) from e
        await self._put_authorized_keys(container, ssh_public_key)
        log.info("ssh_key_injected", workspace_id=handle.workspace_id)

    async def _wipe_authorized_keys(self, container: Any, workspace_id: str) -> None:
        """Empty `authorized_keys` so a previously issued credential stops authenticating (D-03).

        The minted credential's validity is bounded by the workspace's own
        lifecycle, so the credential must die at exactly the moment the
        workspace stops — not on a Phase-3-local idle timer (that is Phase
        4's LIFE-01), and not merely when the container is removed (a
        stopped-but-present container would otherwise still accept the old
        credential on next start). Failure here must never block the
        lifecycle operation it precedes — the container going away (or
        stopping) is itself the stronger invalidation.
        """
        try:
            await self._put_authorized_keys(container, "")
        except Exception:
            log.warning("ssh_key_wipe_failed", workspace_id=workspace_id)

    async def stop(self, handle: WorkspaceHandle) -> None:
        container = await asyncio.to_thread(self._client.containers.get, handle.runtime_id)
        # D-03: invalidate the injected key before stopping so a
        # previously-issued credential stops authenticating the moment the
        # workspace stops, not only once it's later destroyed.
        await self._wipe_authorized_keys(container, handle.workspace_id)
        await asyncio.to_thread(container.stop, timeout=5)

    async def destroy(self, handle: WorkspaceHandle) -> None:
        container = None
        if handle.runtime_id:
            try:
                container = await asyncio.to_thread(self._client.containers.get, handle.runtime_id)
            except NotFound:
                container = None
        if container is not None:
            # D-03: wipe authorized_keys even if container removal later fails.
            await self._wipe_authorized_keys(container, handle.workspace_id)
            await asyncio.to_thread(container.remove, force=True)
        if self._egress_bridge_name and handle.workspace_id:
            await self._remove_network_quietly(self._workspace_network_name(handle.workspace_id))

    def _workspace_network_name(self, workspace_id: str) -> str:
        return f"{self._egress_bridge_name}-{workspace_id}"

    async def _remove_network_quietly(self, name: str) -> None:
        if not name:
            return
        try:
            await asyncio.to_thread(self._client.networks.remove, name)
        except NotFound:
            pass
        except (APIError, PodmanError, ConnectionError):
            log.warning("workspace_network_remove_failed", network=name)

    async def prune_workspace_networks(self, server_id: str, keep_workspace_ids: set[str]) -> None:
        """Remove this server's per-workspace networks whose workspace is gone (reconcile).

        Labels are the trust anchor, as for containers, and are matched client-side for
        the same reason as `list_by_server`. A network still in use fails removal and stays."""
        try:
            networks = await asyncio.to_thread(self._client.networks.list)
        except (APIError, PodmanError, ConnectionError):
            log.warning("workspace_network_list_failed")
            return
        for net in networks:
            labels = (net.attrs.get("labels") or {}) if isinstance(net.attrs, dict) else {}
            if labels.get(_WARREN_LABEL_NETWORK) != "workspace":
                continue
            if labels.get(_WARREN_LABEL_SERVER_INSTANCE) != server_id:
                continue
            if labels.get(_WARREN_LABEL_WORKSPACE_ID) in keep_workspace_ids:
                continue
            log.warning("orphan workspace network", network=net.name)
            await self._remove_network_quietly(net.name)

    async def exec(self, handle: WorkspaceHandle, cmd: list[str]) -> AsyncIterator[bytes]:
        raise NotImplementedError("exec lands in Phase 3/4 with the sidecar")

    async def exec_stream(self, handle: WorkspaceHandle, argv: list[str]) -> AsyncIterator[bytes | ExecExit]:
        """#59: run argv in the container (no TTY, no stdin), yielding output chunks then ExecExit.

        Closing the generator early closes the attach stream; the exec session's process
        isn't killed by the Podman API, so callers bound time by closing."""
        from podman import api as podman_api  # noqa: PLC0415

        def _start() -> tuple[str, Any, Any]:
            container = self._client.containers.get(handle.runtime_id)
            created = container.client.post(
                f"/containers/{container.id}/exec",
                data=json.dumps({"AttachStdout": True, "AttachStderr": True, "AttachStdin": False, "Tty": False, "Cmd": list(argv)}),
            )
            created.raise_for_status()
            exec_id = created.json()["Id"]
            started = container.client.post(
                f"/exec/{exec_id}/start", data=json.dumps({"Detach": False, "Tty": False}), stream=True
            )
            started.raise_for_status()
            return exec_id, container, started

        exec_id, container, started = await asyncio.to_thread(_start)
        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[bytes | BaseException | None] = asyncio.Queue()
        stop = threading.Event()

        def _read() -> None:
            try:
                for frame in podman_api.stream_frames(started, demux=False):
                    if stop.is_set():
                        break
                    if frame:
                        loop.call_soon_threadsafe(queue.put_nowait, frame)
            except Exception as exc:  # noqa: BLE001
                if not stop.is_set():
                    loop.call_soon_threadsafe(queue.put_nowait, exc)
            loop.call_soon_threadsafe(queue.put_nowait, None)

        reader = loop.run_in_executor(None, _read)
        try:
            while True:
                item = await queue.get()
                if item is None:
                    break
                if isinstance(item, BaseException):
                    raise item
                yield item
            await reader

            def _inspect() -> int | None:
                resp = container.client.get(f"/exec/{exec_id}/json")
                resp.raise_for_status()
                code = resp.json().get("ExitCode")
                return int(code) if code is not None else None

            yield ExecExit(await asyncio.to_thread(_inspect))
        finally:
            stop.set()
            await asyncio.to_thread(started.close)

    async def status(self, handle: WorkspaceHandle) -> Literal["running", "stopped", "unknown"]:
        # A workspace whose provision() never got far enough to create a
        # container (e.g. it failed during git clone, before runtime.provision()
        # was even called) has runtime_id == "". podman-py's containers.get("")
        # does NOT raise NotFound for an empty id -- it mis-resolves to a
        # /containers//json request, which podman's own API apparently answers
        # with something podman-py can't parse into a Container at all,
        # crashing with "Can't create Container from [...]" instead. Observed
        # directly 2026-10-13: the reaper polling such a row every cycle,
        # repeatedly crashing and contending for the podman socket badly
        # enough to make an unrelated, concurrent real provision's own
        # container-creation call fail with runtime_unreachable.
        if not handle.runtime_id:
            return "unknown"
        try:
            container = await asyncio.to_thread(self._client.containers.get, handle.runtime_id)
        except NotFound:
            return "unknown"
        state = (container.attrs.get("State") or {}).get("Status", "").lower()
        if state == "running":
            return "running"
        if state in ("exited", "stopped", "dead", "created"):
            return "stopped"
        return "unknown"

    async def exit_code(self, handle: WorkspaceHandle) -> int | None:
        """AH2: State.ExitCode of an exited container (None while it's still running)."""
        if not handle.runtime_id:
            return None
        container = await asyncio.to_thread(self._client.containers.get, handle.runtime_id)
        state = container.attrs.get("State") or {}
        if str(state.get("Status", "")).lower() == "running":
            return None
        code = state.get("ExitCode")
        return int(code) if code is not None else None

    async def read_file(self, handle: WorkspaceHandle, path: str, max_bytes: int) -> bytes | None:
        """AH2: a regular file from the (stopped) container's filesystem, via get_archive.

        None if absent; ValueError if it isn't a regular file or exceeds max_bytes."""
        container = await asyncio.to_thread(self._client.containers.get, handle.runtime_id)
        try:
            stream, _ = await asyncio.to_thread(container.get_archive, path)
        except NotFound:
            return None
        raw = b""
        for chunk in stream:
            raw += chunk
            if len(raw) > max_bytes + 64 * 1024:
                raise ValueError(f"{path} exceeds {max_bytes} bytes")
        with tarfile.open(fileobj=io.BytesIO(raw)) as tar:
            members = tar.getmembers()
            if len(members) != 1 or not members[0].isreg():
                raise ValueError(f"{path} is not a regular file")
            if members[0].size > max_bytes:
                raise ValueError(f"{path} exceeds {max_bytes} bytes")
            f = tar.extractfile(members[0])
            return f.read() if f is not None else None

    async def list_by_server(self, server_id: str) -> list[Any]:
        """Return every container labelled `warren.server_instance=<server_id>`.

        Includes stopped containers (`all=True`) so reconciliation can adopt or
        mark them as needed.

        Filters client-side rather than via the API's `filters={"label": ...}`
        query param: confirmed via a real-socket integration test (Phase 1,
        01-03) that the server-side label filter silently returns zero matches
        against some Podman API versions even for a genuinely matching,
        running container — a client/server filter-serialization
        incompatibility, not a container-state issue. Fetching the full list
        and matching `.labels` in Python avoids depending on that query
        working correctly at all.
        """
        containers = await asyncio.to_thread(self._client.containers.list, all=True)
        return [
            c
            for c in containers
            if c.labels.get(_WARREN_LABEL_SERVER_INSTANCE) == server_id
        ]

    async def stream_logs(
        self,
        runtime_id: str,
        event_buffer: "WorkspaceEventBuffer",
    ) -> None:
        """Read NDJSON lines from container stdout into event_buffer (D-08, D-15).

        Runs a blocking container.logs(follow=True) iterator in a thread-pool
        executor and forwards each decoded line to the event buffer. Chunks are
        NOT line-delimited — accumulates in a bytes buffer and splits on b"\\n".

        Pitfall 1: container.logs blocks the event loop — use run_in_executor.
        Pitfall 4: chunks are not line-delimited — buffer and split on b"\\n".
        Pitfall 6: capture loop reference before spawning the executor thread.
        """
        loop = asyncio.get_event_loop()
        queue: asyncio.Queue[bytes | None] = asyncio.Queue()

        def _read_into_queue() -> None:
            try:
                container = self._client.containers.get(runtime_id)
                for chunk in container.logs(
                    stream=True, follow=True, stdout=True, stderr=False
                ):
                    loop.call_soon_threadsafe(queue.put_nowait, chunk)
            except Exception:
                # Audit 2026-10-16 P1 #33: this previously swallowed every
                # exception silently -- a crash in here (container gone,
                # socket error, etc.) was invisible, with log tailing just
                # quietly stopping. Logged, not re-raised: this executor
                # thread has no caller to propagate to.
                log.exception("stream_logs_reader_failed", runtime_id=runtime_id)
            loop.call_soon_threadsafe(queue.put_nowait, None)  # sentinel

        # Audit 2026-10-16 P1 #33: keep a reference to the executor future --
        # an unreferenced one is eligible for garbage collection mid-run on
        # some Python/asyncio implementations. The `while` loop below already
        # keeps this coroutine (and therefore this local) alive until the
        # sentinel arrives, but the reference is kept explicitly rather than
        # relying on that incidentally.
        reader_future = loop.run_in_executor(None, _read_into_queue)
        buf = b""
        while True:
            chunk = await queue.get()
            if chunk is None:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if line.strip():
                    await event_buffer.push(line.decode(errors="replace"))
        await reader_future


def _ensure_workspace_network(client: Any, name: str, labels: dict[str, str]) -> None:
    """Create (or adopt) a workspace's isolated bridge network; fail closed otherwise.

    An existing network of that name is reused only when it carries this server's label
    and `isolate` -- attaching a workspace to a non-isolated network would reopen the
    east-west path the per-workspace network exists to close."""
    try:
        try:
            network = client.networks.get(name)
        except NotFound:
            try:
                client.networks.create(
                    name, driver="bridge", labels=labels, options={"isolate": "true"}
                )
                return
            except APIError as e:
                if "exist" not in str(e).lower():
                    raise
                network = client.networks.get(name)
    except (APIError, PodmanError, ConnectionError) as e:
        raise RuntimeUnreachable(f"failed to create workspace network {name!r}: {e}") from e
    attrs = network.attrs if isinstance(network.attrs, dict) else {}
    options = attrs.get("options") or {}
    existing_labels = attrs.get("labels") or {}
    if (
        str(options.get("isolate", "")).lower() not in _ISOLATE_VALUES
        or existing_labels.get(_WARREN_LABEL_SERVER_INSTANCE) != labels[_WARREN_LABEL_SERVER_INSTANCE]
    ):
        raise RuntimeUnreachable(
            f"network {name!r} exists but is not an isolated warren workspace network for this server"
        )


async def run_preflight(socket_path: str | Path) -> None:
    """Shim re-export so tests can `from warren.runtime.podman import run_preflight`.

    The real implementation lives in `warren.preflight` (D-03). The import is
    lazy to avoid a circular import: `preflight` needs `PodmanClient` from this
    module's namespace so patches like
    `patch("warren.runtime.podman.PodmanClient")` reach the client construction.
    """
    from warren.preflight import run_preflight as _run_preflight

    await _run_preflight(socket_path)
