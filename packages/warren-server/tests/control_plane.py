"""Shared harness for control-plane MCP tests (AI8) and the framework e2e (AJ2):
the real app, real registry and auth store, on a scripted in-memory runtime."""

from __future__ import annotations

import json
from pathlib import Path

from warren_common.runtime.base import WorkspaceHandle, WorkspaceSpec
from warren_common.runtime.fake import FakeRuntime

from tests.conftest import TEST_BOOTSTRAP_TOKEN

ADMIN_TOKEN = TEST_BOOTSTRAP_TOKEN
TASK_COMMAND = "warren-test-task"

PROJECT_YAML = """\
name: demo
templates:
  observe: {}
  task:
    app: python -m agent
"""


class ScriptedRuntime(FakeRuntime):
    """Containers start running. `warren-test-task <status>` writes
    .warren/verdict.json and makes the app exit 0, so a single-turn workspace
    completes on the next reaper pass. Anything else echoes its argv."""

    def __init__(self, server_id: str = "test-server") -> None:
        super().__init__(server_id)
        self.exit_codes: dict[str, int] = {}
        self.files: dict[tuple[str, str], bytes] = {}
        self.exec_handler = self._handle

    async def provision(self, spec: WorkspaceSpec) -> WorkspaceHandle:
        handle = await super().provision(spec)
        self._containers[spec.workspace_id].status = "running"
        return handle

    def _handle(self, workspace_id: str, argv: list[str]) -> tuple[list[bytes], int]:
        if argv[0] == TASK_COMMAND:
            status = argv[1] if len(argv) > 1 else "pass"
            verdict = {"status": status, "summary": f"ran {TASK_COMMAND}"}
            self.files[(workspace_id, "/workspace/.warren/verdict.json")] = json.dumps(verdict).encode()
            self.exit_codes[workspace_id] = 0
            self._containers[workspace_id].status = "stopped"
            return [b"task done\n"], 0
        return [(" ".join(argv) + "\n").encode()], 0

    async def list_by_server(self, server_id: str) -> list:  # the reaper awaits it
        return super().list_by_server(server_id)

    async def exit_code(self, handle: WorkspaceHandle) -> int | None:
        return self.exit_codes.get(handle.workspace_id)

    async def read_file(self, handle: WorkspaceHandle, path: str, max_bytes: int) -> bytes | None:
        return self.files.get((handle.workspace_id, path))


def server_env_vars(tmp_path: Path, *, reaper: bool = False) -> dict[str, str]:
    projects = tmp_path / "projects"
    projects.mkdir(parents=True, exist_ok=True)
    (projects / "demo.yaml").write_text(PROJECT_YAML)
    return {
        "WARREN_SECRET_KEY": "x" * 32,
        "WARREN_BOOTSTRAP_TOKEN": TEST_BOOTSTRAP_TOKEN,
        "WARREN_DATA_DIR": str(tmp_path / "data"),
        "WARREN_PODMAN_SOCKET": str(tmp_path / "podman.sock"),
        "WARREN_SERVER_ID": "test-server",
        "WARREN_PROJECTS_DIR": str(projects),
        "WARREN_DRY_RUN_SKIP_PREFLIGHT": "1",
        "WARREN_REAPER_ENABLED": "1" if reaper else "0",
        "WARREN_IDLE_REAPER_ENABLED": "0",
        "WARREN_MAX_WORKSPACES_PER_USER": "10",
    }


def server_env(monkeypatch, tmp_path: Path, *, reaper: bool = False) -> None:
    for key, value in server_env_vars(tmp_path, reaper=reaper).items():
        monkeypatch.setenv(key, value)
