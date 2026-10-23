"""Live-Podman coverage for workspace_query: warren-query runs over the podman exec
API as an unprivileged user, never via the sidecar, against a real repository."""

from __future__ import annotations

import os
import shutil
import uuid
from pathlib import Path

import pytest

pytestmark = pytest.mark.requires_podman

_TAG = "localhost/warren-itest-query:latest"
_SCRIPT = Path(__file__).parents[3] / "warren-common" / "src" / "warren_common" / "assets" / "warren_query.sh"
_SETUP = r"""
set -e
mkdir -p /workspace/main /outside
echo TOPSECRET > /outside/secret.txt
cd /workspace/main
git init -q
printf 'hello\n' > a.txt
printf '*.log\n' > .gitignore
git add -A
git -c user.email=t@t -c user.name=t commit -qm init
printf 'changed\n' >> a.txt
echo TOPSECRET > x.log
echo TOPSECRET > .env
ln -s /outside/secret.txt link.txt
chmod -R a+rX /workspace
echo r > rootonly.txt
chmod 600 rootonly.txt
"""


@pytest.fixture(scope="module")
def query_image(tmp_path_factory: pytest.TempPathFactory) -> str:
    from podman import PodmanClient

    build_dir = tmp_path_factory.mktemp("itest-query-image")
    shutil.copy(_SCRIPT, build_dir / "warren_query.sh")
    (build_dir / "Containerfile").write_text(
        "FROM docker.io/library/debian:bookworm-slim\n"
        "RUN apt-get update && apt-get install -y --no-install-recommends git && rm -rf /var/lib/apt/lists/*\n"
        "COPY --chmod=0755 warren_query.sh /usr/local/bin/warren-query\n"
        'CMD ["sleep", "infinity"]\n'
    )
    client = PodmanClient(base_url=f"unix://{os.environ['PODMAN_SOCKET']}", timeout=30)
    try:
        client.images.build(path=str(build_dir), dockerfile="Containerfile", tag=_TAG, rm=True, timeout=300)
    finally:
        client.close()
    return _TAG


async def test_files_read_and_diff_over_podman_exec(query_image: str) -> None:
    from podman import PodmanClient
    from warren import exec_relay, workspace_query as wq
    from warren.runtime.podman import PodmanRuntime
    from warren_common.runtime.base import WorkspaceHandle

    socket_path = os.environ["PODMAN_SOCKET"]
    client = PodmanClient(base_url=f"unix://{socket_path}", timeout=30)
    container = client.containers.create(query_image, name=f"warren-itest-query-{uuid.uuid4().hex[:8]}")
    try:
        container.start()
        runtime = PodmanRuntime(socket_path=socket_path, server_id="itest-query")
        handle = WorkspaceHandle(workspace_id="ws-q", runtime_id=container.id, root_path="")
        setup = await exec_relay.collect(
            exec_relay.relay(runtime, handle, ["sh", "-c", _SETUP], timeout_seconds=120, max_output_bytes=65536)
        )
        assert setup["exit_code"] == 0, setup

        paths = {e["path"] for e in await wq.list_files(runtime, handle)}
        assert {"main/a.txt", "main/.gitignore"} <= paths
        assert not paths & {"main/x.log", "main/.env", "main/link.txt"}

        assert await wq.read_file(runtime, handle, "main/a.txt") == b"hello\nchanged\n"
        for rel, status in (("main/link.txt", 400), ("main/x.log", 404), ("main/rootonly.txt", 403)):
            with pytest.raises(wq.QueryError) as ei:
                await wq.read_file(runtime, handle, rel)
            assert ei.value.status == status, rel

        (repo,) = await wq.diff(runtime, handle)
        assert repo.repo == "main" and "+changed" in repo.diff
    finally:
        container.remove(force=True)
        client.close()
