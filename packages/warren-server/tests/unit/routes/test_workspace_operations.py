"""AM2: idempotent provision by client operationId (real app + sqlite, scripted runtime)."""

from __future__ import annotations

import functools
import itertools
from contextlib import contextmanager
from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from tests.control_plane import ADMIN_TOKEN, ScriptedRuntime, server_env
from warren.app import app

_HEADERS = {"Authorization": f"Bearer {ADMIN_TOKEN}"}
_BODY = {"project": "demo", "template": "observe"}
_ids = itertools.count(1)


class CountingRuntime(ScriptedRuntime):
    def __init__(self) -> None:
        super().__init__()
        self.provisioned: list = []

    async def provision(self, spec):
        self.provisioned.append(spec)
        return await super().provision(spec)


@contextmanager
def _client(monkeypatch, tmp_path, runtime=None):
    server_env(monkeypatch, tmp_path)
    runtime = runtime or CountingRuntime()
    try:
        with patch("warren.app.PodmanRuntime", return_value=runtime), TestClient(app, headers=_HEADERS) as client:
            yield client, runtime
    finally:
        app.state._state.clear()


def _op() -> str:
    return f"op-{next(_ids)}"


def test_same_operation_id_provisions_once_and_returns_the_same_workspace(monkeypatch, tmp_path):
    op = _op()
    with _client(monkeypatch, tmp_path) as (client, runtime):
        first = client.post("/workspaces", json={**_BODY, "operationId": op})
        second = client.post("/workspaces", json={**_BODY, "operationId": op})
    assert first.status_code == second.status_code == 202, (first.text, second.text)
    assert first.json()["workspace_id"] == second.json()["workspace_id"]
    assert len(runtime.provisioned) == 1
    assert runtime.provisioned[0].operation_id == op
    assert first.json()["operation"] == second.json()["operation"]
    assert first.json()["operation"]["id"] == op
    assert first.json()["operation"]["stage"] == "started"
    assert first.json()["operation"]["workspace_id"] == first.json()["workspace_id"]


def test_without_operation_id_each_post_provisions(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as (client, runtime):
        a = client.post("/workspaces", json=_BODY).json()
        b = client.post("/workspaces", json=_BODY).json()
    assert a["workspace_id"] != b["workspace_id"]
    assert a["operation"] is None
    assert len(runtime.provisioned) == 2


def test_same_operation_id_with_a_different_body_is_409(monkeypatch, tmp_path):
    op = _op()
    with _client(monkeypatch, tmp_path) as (client, runtime):
        assert client.post("/workspaces", json={**_BODY, "operationId": op}).status_code == 202
        resp = client.post("/workspaces", json={**_BODY, "mode": "single-turn", "operationId": op})
    assert resp.status_code == 409
    assert resp.json()["detail"]["error"] == "operation_conflict"
    assert len(runtime.provisioned) == 1


def test_invalid_operation_id_is_422(monkeypatch, tmp_path):
    with _client(monkeypatch, tmp_path) as (client, runtime):
        for bad in ("", "x" * 65, "has space", "slash/no"):
            assert client.post("/workspaces", json={**_BODY, "operationId": bad}).status_code == 422
    assert runtime.provisioned == []


def test_operation_receipt_is_readable_and_per_principal(monkeypatch, tmp_path):
    op = _op()
    with _client(monkeypatch, tmp_path) as (client, _):
        created = client.post("/workspaces", json={**_BODY, "operation_id": op}).json()
        receipt = client.get(f"/operations/{op}")
        missing = client.get("/operations/never-used")
        reserved = client.post("/workspace-tokens", json={}).json()
        scoped = client.get(f"/operations/{op}", headers={"Authorization": f"Bearer {reserved['token']}"})
    assert receipt.status_code == 200
    assert receipt.json()["stage"] == "started"
    assert receipt.json()["workspace_id"] == created["workspace_id"]
    assert missing.status_code == 404
    assert scoped.status_code == 403


def test_accepted_is_recorded_before_the_runtime_provisions(monkeypatch, tmp_path):
    op = _op()
    seen: list[str] = []

    class Observing(CountingRuntime):
        async def provision(self, spec):
            row = await app.state.operation_store.get(spec.owner_id, op)
            seen.append(row["stage"] if row else "missing")
            return await super().provision(spec)

    with _client(monkeypatch, tmp_path, Observing()) as (client, _):
        resp = client.post("/workspaces", json={**_BODY, "operationId": op})
    assert resp.json()["operation"]["stage"] == "started"
    assert seen == ["accepted"]


def test_failed_provision_receipt_is_failed_and_not_relaunched(monkeypatch, tmp_path):
    op = _op()

    class Failing(CountingRuntime):
        async def provision(self, spec):
            self.provisioned.append(spec)
            raise RuntimeError("boom")

    with _client(monkeypatch, tmp_path, Failing()) as (client, runtime):
        first = client.post("/workspaces", json={**_BODY, "operationId": op})
        second = client.post("/workspaces", json={**_BODY, "operationId": op})
    assert first.json()["operation"]["stage"] == second.json()["operation"]["stage"] == "failed"
    assert second.json()["workspace_id"] == first.json()["workspace_id"]
    assert len(runtime.provisioned) == 1


def test_operation_survives_a_server_restart(monkeypatch, tmp_path):
    op = _op()
    with _client(monkeypatch, tmp_path) as (client, runtime):
        first = client.post("/workspaces", json={**_BODY, "operationId": op}).json()
    with _client(monkeypatch, tmp_path) as (client, restarted):
        again = client.post("/workspaces", json={**_BODY, "operationId": op})
        conflict = client.post("/workspaces", json={**_BODY, "mode": "single-turn", "operationId": op})
        receipt = client.get(f"/operations/{op}").json()
    assert again.status_code == 202
    assert again.json()["workspace_id"] == first["workspace_id"]
    assert conflict.status_code == 409
    assert receipt["stage"] == "started"
    assert len(runtime.provisioned) == 1
    assert restarted.provisioned == []


def test_accepted_operation_left_by_a_crash_resumes_on_its_recorded_workspace(monkeypatch, tmp_path):
    from warren.routes.workspaces import ProvisionRequest, _operation_hash

    op = _op()
    with _client(monkeypatch, tmp_path) as (client, runtime):
        user_id = client.get("/admin/users").json()[0]["user_id"]
        create = functools.partial(
            app.state.operation_store.create,
            principal=user_id,
            operation_id=op,
            kind="provision",
            request_hash=_operation_hash(ProvisionRequest(**_BODY)),
            workspace_id="ws-crashed",
        )
        assert client.portal.call(create)
        resp = client.post("/workspaces", json={**_BODY, "operationId": op})
        again = client.post("/workspaces", json={**_BODY, "operationId": op})
    assert resp.status_code == 202, resp.text
    assert resp.json()["workspace_id"] == again.json()["workspace_id"] == "ws-crashed"
    assert resp.json()["operation"]["stage"] == "started"
    assert [s.workspace_id for s in runtime.provisioned] == ["ws-crashed"]


def _crashed_launch(client, op: str, workspace_id: str, status: str) -> None:
    """What a crash leaves: an `accepted` operation and its row, but no runtime id."""
    from warren.routes.workspaces import ProvisionRequest, _operation_hash

    user_id = client.get("/admin/users").json()[0]["user_id"]
    create = functools.partial(
        app.state.operation_store.create,
        principal=user_id,
        operation_id=op,
        kind="provision",
        request_hash=_operation_hash(ProvisionRequest(**_BODY)),
        workspace_id=workspace_id,
    )
    assert client.portal.call(create)
    store = app.state.registry.store
    insert = functools.partial(
        store.insert,
        workspace_id=workspace_id,
        project=_BODY["project"],
        intent=_BODY["template"],
        image="img",
        root_path="",
        server_instance=app.state.registry.server_id,
        status="provisioning",
        owner_id=user_id,
    )
    client.portal.call(insert)
    if status != "provisioning":
        client.portal.call(store.update_status, workspace_id, status)


@pytest.mark.parametrize("status", ["provisioning", "stopped", "running", "unknown", "failed"])
def test_accepted_operation_whose_row_never_got_a_runtime_id_is_relaunched(monkeypatch, tmp_path, status):
    op = _op()
    with _client(monkeypatch, tmp_path) as (client, runtime):
        _crashed_launch(client, op, "ws-no-runtime", status)
        resp = client.post("/workspaces", json={**_BODY, "operationId": op})
        again = client.post("/workspaces", json={**_BODY, "operationId": op})
    assert resp.status_code == 202, resp.text
    assert resp.json()["workspace_id"] == again.json()["workspace_id"] == "ws-no-runtime"
    assert resp.json()["status"] == "running"
    assert resp.json()["container_id"]
    assert resp.json()["operation"]["stage"] == again.json()["operation"]["stage"] == "started"
    assert [s.workspace_id for s in runtime.provisioned] == ["ws-no-runtime"]


def test_stopped_workspace_that_has_a_runtime_id_is_replayed_not_relaunched(monkeypatch, tmp_path):
    op = _op()
    with _client(monkeypatch, tmp_path) as (client, runtime):
        _crashed_launch(client, op, "ws-launched", "stopped")
        client.portal.call(app.state.registry.store.update_container_id, "ws-launched", "ctr-1")
        resp = client.post("/workspaces", json={**_BODY, "operationId": op})
    assert resp.status_code == 202, resp.text
    assert resp.json()["status"] == "stopped"
    assert resp.json()["operation"]["stage"] == "started"
    assert runtime.provisioned == []


def test_first_response_matches_the_replay(monkeypatch, tmp_path):
    op = _op()
    with _client(monkeypatch, tmp_path) as (client, _):
        first = client.post("/workspaces", json={**_BODY, "operationId": op}).json()
        replay = client.post("/workspaces", json={**_BODY, "operationId": op}).json()
    assert first["status"] == "running"
    assert first["container_id"]
    assert first == replay


def test_running_status_and_runtime_id_are_one_write(monkeypatch, tmp_path):
    op = _op()
    with _client(monkeypatch, tmp_path) as (client, _):
        store = app.state.registry.store
        real_update_status = store.update_status

        async def no_bare_running(workspace_id, status):
            assert status != "running", "running must be written with its runtime id (mark_running)"
            await real_update_status(workspace_id, status)

        monkeypatch.setattr(store, "update_status", no_bare_running)
        resp = client.post("/workspaces", json={**_BODY, "operationId": op})
        ws = client.portal.call(store.get, resp.json()["workspace_id"])
    assert resp.status_code == 202, resp.text
    assert ws.status == "running" and ws.container_id
