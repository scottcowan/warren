"""FakeRuntime — in-memory ContainerRuntime for tests.

Implements the async surface of `warren_common.runtime.base.ContainerRuntime`
without touching a real Podman socket. Registry / reconcile tests
inject this in place of `PodmanRuntime`.

The label schema follows D-11:
    warren.workspace_id, warren.server_instance, warren.project, warren.intent
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Literal

from warren_common.runtime.base import ExecExit, WorkspaceHandle, WorkspaceSpec


@dataclass
class FakeContainer:
    id: str
    labels: dict[str, str]
    status: Literal["running", "stopped"] = "stopped"


class FakeRuntime:
    """In-memory ContainerRuntime for unit tests."""

    def __init__(self, server_id: str) -> None:
        self._server_id = server_id
        self._containers: dict[str, FakeContainer] = {}
        # exec_stream: (workspace_id, argv) -> (output chunks, exit code)
        self.exec_handler: Callable[[str, list[str]], tuple[list[bytes], int]] | None = None
        self.exec_calls: list[tuple[str, list[str]]] = []

    # --- ContainerRuntime Protocol surface ---

    async def provision(self, spec: WorkspaceSpec) -> WorkspaceHandle:
        runtime_id = f"fake-{spec.workspace_id}"
        labels = {
            "warren.workspace_id": spec.workspace_id,
            "warren.server_instance": self._server_id,
            "warren.project": spec.project,
            "warren.intent": spec.intent,
        }
        self._containers[spec.workspace_id] = FakeContainer(
            id=runtime_id, labels=labels, status="stopped"
        )
        return WorkspaceHandle(
            workspace_id=spec.workspace_id,
            runtime_id=runtime_id,
            root_path=spec.root_path,
        )

    async def start(self, handle: WorkspaceHandle) -> None:
        container = self._containers.get(handle.workspace_id)
        if container is not None:
            container.status = "running"

    async def stop(self, handle: WorkspaceHandle) -> None:
        container = self._containers.get(handle.workspace_id)
        if container is not None:
            container.status = "stopped"

    async def destroy(self, handle: WorkspaceHandle) -> None:
        self._containers.pop(handle.workspace_id, None)

    async def exec(self, handle: WorkspaceHandle, cmd: list[str]) -> AsyncIterator[bytes]:
        async def _empty() -> AsyncIterator[bytes]:
            if False:
                yield b""
        return _empty()

    async def exec_stream(self, handle: WorkspaceHandle, argv: list[str]) -> AsyncIterator[bytes | ExecExit]:
        self.exec_calls.append((handle.workspace_id, list(argv)))
        chunks, code = self.exec_handler(handle.workspace_id, argv) if self.exec_handler else ([], 0)
        for chunk in chunks:
            yield chunk
        yield ExecExit(code)

    async def status(self, handle: WorkspaceHandle) -> Literal["running", "stopped", "unknown"]:
        container = self._containers.get(handle.workspace_id)
        if container is None:
            return "unknown"
        return container.status

    # --- Test helpers ---

    def list_by_server(self, server_id: str) -> list[FakeContainer]:
        """Return every container tagged with the given server_instance label."""
        return [
            c
            for c in self._containers.values()
            if c.labels.get("warren.server_instance") == server_id
        ]

    def _seed(self, container: FakeContainer) -> None:
        """Insert a preexisting container — for arranging orphan and adopted cases."""
        workspace_id = container.labels.get("warren.workspace_id") or container.id
        self._containers[workspace_id] = container

    @property
    def _state(self) -> dict[str, str]:
        return {ws: c.status for ws, c in self._containers.items()}
