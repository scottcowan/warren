"""DockerRuntime — daemon-backed ContainerRuntime (RT-04).

Full implementation per Plan 05b-03. Follows NsjailRuntime file-layout
pattern: workspace dir with atomic ``state.json`` (schema_version=1).

Security invariants (see 05b-RESEARCH.md threat model):
    - NEVER binds ``/var/run/docker.sock`` into any workspace container
      (T-05b-05). Docker socket exposure is out of scope in v1.0.
    - ``spec.bind_mounts`` host paths are ``Path.resolve(strict=True)``'d
      before being turned into Mount objects (T-05b-06).
    - Image string is passed through unmodified — dispatch/ImageResolver
      is the trust boundary (T-05b-07).

All docker-py SDK calls are wrapped in ``asyncio.to_thread`` (docker-py 7.2
is fully synchronous). Client is instantiated lazily on first use via
``_ensure_client`` so module import stays cheap (Plan 05b-02 keeps
``warren doctor`` snappy).
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Iterator, Literal

import structlog

from warren_common.errors import ProvisionError, RuntimeUnreachable
from warren_common.runtime.base import (
    SIDECAR_TOKEN_ENV,
    ContainerRuntime,
    RuntimeConfig,
    WorkspaceHandle,
    WorkspaceSpec,
    new_sidecar_token,
)

log = structlog.get_logger(__name__)

_STATE_SCHEMA_VERSION = 1


class DockerRuntime:
    """ContainerRuntime backed by the local Docker daemon via docker-py 7.2."""

    def __init__(self, server_id: str, config: RuntimeConfig | None = None) -> None:
        self.server_id = server_id
        self.config = config
        self._client: Any = None
        self._preflight_ok = False

    def _ensure_client(self) -> Any:
        if self._client is None:
            import docker

            from warren_common import winsupport

            pipe_host = (
                winsupport.docker_pipe_host()
                if winsupport.is_windows() and not os.environ.get("DOCKER_HOST")
                else None
            )
            self._client = docker.DockerClient(base_url=pipe_host) if pipe_host else docker.from_env()
        return self._client

    def close(self) -> None:
        """Close the underlying docker client (Pitfall 5)."""
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    async def preflight(self) -> None:
        client = self._ensure_client()
        try:
            await asyncio.to_thread(client.ping)
        except Exception as exc:
            raise RuntimeUnreachable(
                f"docker daemon unreachable: {exc}. Is Docker Desktop running?"
            ) from exc
        self._preflight_ok = True

    async def provision(self, spec: WorkspaceSpec) -> WorkspaceHandle:
        if not self._preflight_ok:
            # Skip live ping when a client is pre-injected (tests) — presence
            # of an already-set client means the caller has vouched for it.
            if self._client is None:
                await self.preflight()
            else:
                self._preflight_ok = True

        import docker.errors
        from docker.types import Mount

        client = self._ensure_client()

        # Audit 2026-10-16 P1 #27: `spec.root_path` is "" for every workspace
        # under the normal server wiring (routes/workspaces.py never sets it
        # for a non-ECS runtime) -- `Path("")` resolves to `Path(".")`, the
        # CURRENT directory. Blindly `mkdir`/`chmod`ing that chmod'd the
        # server's OWN working directory, not a workspace path. A per-
        # workspace directory for `state.json` is only created/used when
        # root_path is actually set; when it's empty, container lookups fall
        # back to `handle.runtime_id` (`_read_container_id` below), same as
        # PodmanRuntime, which never relies on a root_path-derived directory
        # at all.
        workspace_dir = Path(spec.root_path) if spec.root_path else None
        if workspace_dir is not None:
            workspace_dir.mkdir(parents=True, exist_ok=True)
            os.chmod(workspace_dir, 0o700)

        mounts = _build_mounts(spec)

        labels = {
            "warren.workspace_id": spec.workspace_id,
            "warren.server_instance": self.server_id,
            "warren.project": spec.project,
            "warren.intent": spec.intent,
        }

        # Audit 2026-10-16 P1 #27: WARREN_APP/WARREN_WORKSPACE_ID were never
        # set for Docker workspaces at all -- an earlier commit (388e284)
        # fixed this only for PodmanRuntime, never ported to DockerRuntime.
        # Mirrors podman.py's merge order exactly (also fixed by #34 in this
        # same audit pass): spec.env is merged FIRST so these reserved vars
        # always win over a same-named secret, never the other way around.
        worktree_paths_val = ":".join(
            container_path for _, container_path in spec.worktree_paths
        )
        sidecar_token = spec.sidecar_token or new_sidecar_token()
        env = {
            **spec.env,
            "WARREN_WORKSPACE_ID": spec.workspace_id,
            "WARREN_WORKTREE_PATHS": worktree_paths_val,
            "WARREN_APP": spec.app,
            # Read by the shared banner/prompt zsh snippet baked into this image's
            # .zshrc (warren_common/assets/warren_banner.zsh) at shell-start time --
            # UX-1: a zsh template needs these to render the banner on a remote
            # connect, same as the local workspace zshrc already gets from spec.env.
            "WARREN_PROJECT": spec.project,
            "WARREN_TEMPLATE": spec.intent,
            SIDECAR_TOKEN_ENV: sidecar_token,
        }

        name = f"warren-{spec.workspace_id[:8]}"

        run_kwargs: dict[str, Any] = dict(
            detach=True,
            init=True,
            remove=False,
            labels=labels,
            environment=env,
            mounts=mounts,
            tty=True,
            command=["sleep", "infinity"],
            name=name,
        )
        if spec.root_path:
            run_kwargs["working_dir"] = spec.root_path

        try:
            container = await asyncio.to_thread(
                client.containers.run,
                spec.image,
                **run_kwargs,
            )
        except docker.errors.ImageNotFound as exc:
            raise ProvisionError(
                f"image {spec.image!r} not found locally; pull or set [images] mapping"
            ) from exc
        except docker.errors.APIError as exc:
            raise ProvisionError(f"docker API error creating container: {exc}") from exc

        # Attach additional networks (D-07b). containers.run's network= kwarg
        # accepts only one network — extras join via network.connect afterwards.
        for net_name in spec.docker_networks:
            network = await _resolve_or_create_network(client, net_name)
            await asyncio.to_thread(network.connect, container)

        if workspace_dir is not None:
            state = {
                "schema_version": _STATE_SCHEMA_VERSION,
                "workspace_id": spec.workspace_id,
                "project": spec.project,
                "intent": spec.intent,
                "app": spec.app,
                "image": spec.image,
                "container_id": container.id,
                "worktree_paths": [list(p) for p in spec.worktree_paths],
                "reference_paths": [list(p) for p in spec.reference_paths],
                "docker_networks": list(spec.docker_networks),
                "sidecar_token": sidecar_token,
                "created_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "status": "provisioned",
            }
            state_path = workspace_dir / "state.json"
            _atomic_write_text(state_path, json.dumps(state, indent=2), mode=0o600)

        log.info(
            "docker_provisioned",
            workspace_id=spec.workspace_id,
            container_id=container.id,
            image=spec.image,
            networks=list(spec.docker_networks),
        )

        return WorkspaceHandle(
            workspace_id=spec.workspace_id,
            runtime_id=container.id,
            root_path=str(workspace_dir),
            sidecar_url="",
            sidecar_token=sidecar_token,
        )

    async def start(self, handle: WorkspaceHandle) -> None:
        container = await self._get_container(handle)
        if container is None:
            return None
        await asyncio.to_thread(container.start)

    async def stop(self, handle: WorkspaceHandle) -> None:
        container = await self._get_container(handle)
        if container is None:
            return None
        await asyncio.to_thread(container.stop, timeout=5)

    async def destroy(self, handle: WorkspaceHandle) -> None:
        """Stop then remove the container (D-11); best-effort on NotFound."""
        import docker.errors

        container = await self._get_container(handle)
        if container is not None:
            try:
                await asyncio.to_thread(container.stop, timeout=5)
            except docker.errors.NotFound:
                pass
            except docker.errors.APIError:
                # already stopped / dead — proceed to remove
                pass
            try:
                await asyncio.to_thread(container.remove, force=True)
            except docker.errors.NotFound:
                pass

        # Audit 2026-10-16 P1 #27: `handle.root_path` is "" for every
        # workspace under the normal server wiring -- `Path("")` resolves to
        # `Path(".")`, which ALWAYS exists, so this unconditionally ran
        # `shutil.rmtree` against the server's OWN working directory on
        # every single docker destroy() call. Only ever touch a real,
        # non-empty root_path's directory, mirroring the same guard added to
        # provision() above.
        if handle.root_path:
            root = Path(handle.root_path)
            if root.exists():
                shutil.rmtree(root, ignore_errors=True)

    async def exec(
        self, handle: WorkspaceHandle, cmd: list[str]
    ) -> AsyncIterator[bytes]:
        container = await self._get_container(handle)
        if container is None:
            return

        def _run() -> Iterator[bytes]:
            _, stream = container.exec_run(cmd, stream=True, demux=False)
            return stream

        stream = await asyncio.to_thread(_run)
        while True:
            chunk = await asyncio.to_thread(next, stream, None)
            if chunk is None:
                break
            yield chunk

    async def status(
        self, handle: WorkspaceHandle
    ) -> Literal["running", "stopped", "unknown"]:
        container = await self._get_container(handle)
        if container is None:
            return "unknown"
        await asyncio.to_thread(lambda: container.reload())
        raw = getattr(container, "status", "") or ""
        if raw == "running":
            return "running"
        if raw in ("exited", "dead"):
            return "stopped"
        return "unknown"

    async def _get_container(self, handle: WorkspaceHandle) -> Any:
        import docker.errors

        cid = _read_container_id(handle)
        if cid is None:
            return None
        client = self._ensure_client()
        try:
            return await asyncio.to_thread(client.containers.get, cid)
        except docker.errors.NotFound:
            return None


def _build_mounts(spec: WorkspaceSpec) -> list[Any]:
    from docker.types import Mount

    mounts: list[Any] = []
    # Audit 2026-10-16 P1 #27: registry.py's git-clone materialization
    # appends the SAME (host, container) entry to both `spec.worktree_paths`
    # (informational for PodmanRuntime, which never mounts it directly) AND
    # `spec.bind_mounts` -- DockerRuntime, unlike podman, builds a real Mount
    # from every one of worktree_paths/reference_paths/bind_mounts, so that
    # one clone ended up mounted TWICE at the same target. Deduping by
    # container target keeps the first (worktree_paths, read_only=False) --
    # equivalent to what bind_mounts would have produced anyway, since a
    # cloned worktree is always mounted "rw".
    seen_targets: set[str] = set()

    def _resolve(host: str) -> str:
        try:
            return str(Path(host).resolve(strict=True))
        except FileNotFoundError as exc:
            raise ProvisionError(
                f"bind mount source does not exist on host: {host!r}"
            ) from exc

    for host, container in spec.worktree_paths:
        if container in seen_targets:
            continue
        seen_targets.add(container)
        mounts.append(
            Mount(target=container, source=_resolve(host), type="bind", read_only=False)
        )
    for host, container in spec.reference_paths:
        if container in seen_targets:
            continue
        seen_targets.add(container)
        mounts.append(
            Mount(target=container, source=_resolve(host), type="bind", read_only=True)
        )
    for host, container, mode in spec.bind_mounts:
        if container in seen_targets:
            continue
        seen_targets.add(container)
        mounts.append(
            Mount(
                target=container,
                source=_resolve(host),
                type="bind",
                read_only=(mode != "rw"),
            )
        )
    return mounts


async def _resolve_or_create_network(client: Any, net_name: str) -> Any:
    """Fetch network; lazily create warren_default; raise for other missing names."""
    import docker.errors

    try:
        return await asyncio.to_thread(client.networks.get, net_name)
    except docker.errors.NotFound as exc:
        if net_name != "warren_default":
            raise ProvisionError(
                f"docker network {net_name!r} not found; create it or edit intent"
            ) from exc
        # Lazy create warren_default (D-07b). Handle 409 collision (Pitfall 7).
        try:
            return await asyncio.to_thread(
                client.networks.create, "warren_default", driver="bridge"
            )
        except docker.errors.APIError as api_exc:
            status = getattr(api_exc, "status_code", None) or 0
            if status == 409 or "409" in str(api_exc):
                return await asyncio.to_thread(client.networks.get, "warren_default")
            raise


def _read_container_id(handle: WorkspaceHandle) -> str | None:
    # An empty root_path (the normal case -- see provision()'s comment
    # above) has no state.json to read at all; go straight to runtime_id
    # rather than resolving `Path("") / "state.json"` into a stray relative
    # path in the server's own cwd.
    if not handle.root_path:
        return handle.runtime_id or None
    state_path = Path(handle.root_path) / "state.json"
    if not state_path.exists():
        # Fall back to runtime_id (set on the handle at provision time).
        return handle.runtime_id or None
    try:
        data = json.loads(state_path.read_text())
    except json.JSONDecodeError:
        return handle.runtime_id or None
    return data.get("container_id") or (handle.runtime_id or None)


def _atomic_write_text(path: Path, data: str, *, mode: int) -> None:
    """Write ``data`` to ``path`` via a same-directory tempfile + os.replace (D-19)."""
    directory = path.parent
    fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=str(directory)
    )
    try:
        with os.fdopen(fd, "w") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp_name, mode)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass
        raise


_ = ContainerRuntime  # keep import for Protocol conformance reference
