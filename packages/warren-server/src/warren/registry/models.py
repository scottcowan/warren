"""Pydantic model mirroring the workspaces SQLite schema."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, Field

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


class WorkspaceView(BaseModel):
    """What GET/POST /workspaces return (BB15): the row minus anything the CLI
    doesn't read. The persisted spec (secret names, folders, mounts, template
    env, aws/ssh/scope) and the host root_path never leave the server; only
    `app` does, also as a one-key `spec_json` for clients that read it there."""

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

    @classmethod
    def from_workspace(cls, ws: Workspace) -> "WorkspaceView":
        try:
            extra = json.loads(ws.spec_json or "{}")
            app = extra.get("app")
            harnesses = extra.get("harnesses")
            agent = extra.get("agent") if isinstance(extra.get("agent"), dict) else {}
        except (ValueError, AttributeError):
            app = harnesses = None
            agent = {}
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
