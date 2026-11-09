"""Pydantic model mirroring the workspaces SQLite schema."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field
from warren_common.runtime.ports import is_loopback

WorkspaceStatus = Literal[
    "provisioning", "running", "stopping", "stopped", "failed", "unknown", "destroyed"
]


class Workspace(BaseModel):
    workspace_id: str
    project: str
    intent: str
    image: str
    root_path: str
    container_id: str | None = None
    status: WorkspaceStatus
    server_instance: str
    labels: dict[str, str] = Field(default_factory=dict)
    created_at: datetime
    updated_at: datetime
    ssh_port: int | None = None
    owner_id: str | None = None
    idle_ttl_seconds: float | None = None
    # Finding 7: the fully resolved WorkspaceSpec fields a bare DB row can't
    # reconstruct (env/secrets, folders, app, ...), captured at provision time
    # so ensure_running() can reprovision a reaped-and-gone container faithfully
    # instead of as an empty shell. JSON-encoded; see registry.py's
    # serialize_spec_extra/deserialize_spec_extra.
    spec_json: str | None = None
    # podman/docker: where each declared port is published on the server host's
    # loopback ({name: {"host", "port"}}, JSON); see WorkspaceStore.update_host_ports.
    host_ports_json: str | None = None


class WorkspacePort(BaseModel):
    port: int
    description: str = ""


def _ports_view(raw: object) -> dict[str, WorkspacePort]:
    """spec_json's `ports`, skipping anything malformed (rows predating the field have none)."""
    if not isinstance(raw, dict):
        return {}
    out: dict[str, WorkspacePort] = {}
    for name, entry in raw.items():
        if not isinstance(entry, dict):
            continue
        port, desc = entry.get("port"), entry.get("description", "")
        if isinstance(port, int) and not isinstance(port, bool) and 1 <= port <= 65535:
            out[str(name)] = WorkspacePort(port=port, description=desc if isinstance(desc, str) else "")
    return out


class WorkspaceHostPort(BaseModel):
    """Where a declared port is published on the server host (podman/docker): always a
    loopback address, reached with an SSH forward to the host or, on the host, directly."""

    host: str
    port: int


def _host_ports_view(raw: str | None, declared: dict[str, WorkspacePort]) -> dict[str, WorkspaceHostPort]:
    """The recorded host bindings for names the template still declares, loopback only."""
    try:
        data = json.loads(raw or "{}")
    except ValueError:
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, WorkspaceHostPort] = {}
    for name, entry in data.items():
        if name not in declared or not isinstance(entry, dict):
            continue
        host, port = entry.get("host"), entry.get("port")
        if (
            isinstance(host, str)
            and is_loopback(host)
            and isinstance(port, int)
            and not isinstance(port, bool)
            and 1 <= port <= 65535
        ):
            out[name] = WorkspaceHostPort(host=host, port=port)
    return out


class WorkspaceView(BaseModel):
    """What GET/POST /workspaces return (BB15): the row minus anything the CLI
    doesn't read. The persisted spec (secret names, folders, mounts, template
    env, aws/ssh/scope) and the host root_path never leave the server; only
    `app` does, also as a one-key `spec_json` for clients that read it there,
    plus the template's declared `ports` (names and numbers, no secrets) and, on
    podman/docker, `host_ports`: where each is published on the server host's loopback."""

    workspace_id: str
    project: str
    intent: str
    image: str
    container_id: str | None = None
    status: WorkspaceStatus
    server_instance: str
    created_at: datetime
    updated_at: datetime
    ssh_port: int | None = None
    owner_id: str | None = None
    idle_ttl_seconds: float | None = None
    app: str | None = None
    harnesses: list[str] | None = None
    spec_json: str | None = None
    # AG2b/AM3: an agent workspace's harness and its loopback ACP port (`warren tunnel`).
    agent_harness: str | None = None
    acp_port: int | None = None
    # The template's named ports ({name: {port, description}}), for `warren proxy add --from-template`.
    ports: dict[str, WorkspacePort] = {}
    # podman/docker only: {name: {host, port}}, each declared port's loopback binding on
    # the server host (`warren proxy` forwards to it). Empty on ECS and before the
    # container exists; a container that's recreated (docker: restarted) gets new ones.
    host_ports: dict[str, WorkspaceHostPort] = {}

    @classmethod
    def from_workspace(cls, ws: Workspace) -> "WorkspaceView":
        try:
            extra = json.loads(ws.spec_json or "{}")
            app = extra.get("app")
            harnesses = extra.get("harnesses")
            agent = extra.get("agent") if isinstance(extra.get("agent"), dict) else {}
            ports = _ports_view(extra.get("ports"))
        except (ValueError, AttributeError):
            app = harnesses = None
            agent = {}
            ports = {}
        port = agent.get("port")
        return cls(
            workspace_id=ws.workspace_id,
            project=ws.project,
            intent=ws.intent,
            image=ws.image,
            container_id=ws.container_id,
            status=ws.status,
            server_instance=ws.server_instance,
            created_at=ws.created_at,
            updated_at=ws.updated_at,
            ssh_port=ws.ssh_port,
            owner_id=ws.owner_id,
            idle_ttl_seconds=ws.idle_ttl_seconds,
            app=app,
            harnesses=harnesses if isinstance(harnesses, list) else None,
            spec_json=json.dumps({"app": app}) if app is not None else None,
            agent_harness=agent.get("harness") if isinstance(agent.get("harness"), str) else None,
            acp_port=port if isinstance(port, int) and not isinstance(port, bool) else None,
            ports=ports,
            host_ports=_host_ports_view(getattr(ws, "host_ports_json", None), ports),
        )


OperationStage = Literal["accepted", "started", "failed"]


class OperationReceipt(BaseModel):
    """AM2: a client launch operation. `accepted` once recorded (before provisioning),
    `started` once the runtime provisioned the workspace, `failed` if it didn't."""

    id: str
    stage: OperationStage
    workspace_id: str
    created_at: datetime
    updated_at: datetime

    @classmethod
    def from_row(cls, row: dict[str, str]) -> "OperationReceipt":
        return cls(
            id=row["operation_id"],
            stage=row["stage"],
            workspace_id=row["workspace_id"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
        )


class ProvisionedWorkspaceView(WorkspaceView):
    """POST /workspaces: the workspace plus its operation receipt, when an operationId was given."""

    operation: OperationReceipt | None = None
