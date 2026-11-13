"""DynamoDB state backend (WARREN_STATE_BACKEND=dynamodb, WARREN_DYNAMODB_TABLE).

One table, string keys `pk` (partition) and `sk` (sort), one global secondary index
`gsi1` (`gsi1pk`/`gsi1sk`, projection ALL) and TTL on the `ttl` attribute. Every
boto3 call runs in `asyncio.to_thread`. Key layout (also in resources/ecs/README.md):

    entity              pk                    sk                 gsi1pk / gsi1sk          ttl
    workspace           WS#<id>               META               WSSTATUS#<status> /     -
                                                                 <created_at>#<id>
    launch attempt      WS#<id>               LAUNCH             -                        -
    EBS snapshot        WS#<id>               EBSSNAP            -                        -
    idle stop           WS#<id>               IDLESTOP           IDLESTOPS / <id>         yes
    workspace token     WS#<id>               WSTOKEN#<tid>      -                        yes
    ws token by hash    WSTOKENHASH#<hash>    META               -                        yes
    ws token by id      WSTOKENID#<tid>       META               -                        yes
    user                USER#<uid>            META               USERS /                  -
                                                                 <created_at>#<uid>
    username (unique)   USERNAME#<name>       META               -                        -
    token               USER#<uid>            TOKEN#<tid>        -                        yes
    token by hash       TOKENHASH#<hash>      META               -                        yes
    token by id         TOKENID#<tid>         META               -                        yes
    EBS seed            SEED#<owner>          META               SEEDS / <owner>          -
    EBS seed repo       SEED#<owner>          REPO#<repo_key>    SEEDREPOS /              -
                                                                 <owner>#<repo_key>
    operation           OP#<principal>        OP#<operation_id>  -                        -
    headless run        WS#<id>               RUN#<run_id>       RUNS /                   -
                                                                 <created_at>#<run_id>
    workspace counters  COUNTER#workspaces    ALL | OWNER#<owner> | OWNERLESS             -
    admin counters      COUNTER#admins        META               -                        -

Consistency: every point read is strongly consistent, and everything a correctness
check reads (token and workspace-token lookups by hash, a user's tokens, a workspace's
tokens) is a GetItem or a base-table Query, never the GSI. The GSI only serves listings
(workspaces by status, users, seeds, idle stops), which are eventually consistent;
`list_non_terminal` re-reads its rows consistently before returning them.

Atomicity, where SQLite relied on one statement or the single writer:
- workspace caps (#28): `COUNTER#workspaces` items hold the live (non-terminal) count,
  server-wide and per owner. An insert is one TransactWriteItems: the workspace put
  (attribute_not_exists) plus `ADD n 1` on both counters, conditioned on `n < cap`.
  A status change that crosses live/terminal is a transaction too: the workspace update,
  conditioned on the status it read, plus the counter deltas. Losers retry.
- token cap (#11): a user's tokens live in the user's partition. A mint counts them with
  a consistent Query and commits the token, its hash and id items together with a bump
  of the user item's `token_seq`, conditioned on the value it read: two racing mints
  can't both commit against the same count.
- last enabled admin: `COUNTER#admins.enabled`, decremented with `enabled > 1`.
- launch attempts (AI3): `claim` is a conditional put; a racing launch of the same
  generation and fingerprint gets the stored attempt (and its clientToken) back.
- seed single-flight: `claim_refresh` is an UpdateItem conditioned on
  `refreshing_since` being absent or older than the stale cutoff.
- operations (AM2), usernames, token hashes: conditional puts on attribute_not_exists.

No writer lock is needed for this backend; see resources/ecs/README.md for what still
assumes one control-plane task.
"""

from __future__ import annotations

import asyncio
import json
import random
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, get_args

import structlog
from warren.auth.models import Token, User, WorkspaceToken
from warren.auth.store import LastAdminError, TokenLimitReached
from warren.registry.models import Workspace, WorkspaceStatus
from warren.registry.store import (
    _NON_TERMINAL,
    _SEED_COLUMNS,
    _SEED_REPO_COLUMNS,
    CapacityExhausted,
    _json_dict,
    _json_list,
)
from warren.state.errors import StateConflict

log = structlog.get_logger(__name__)

GSI1 = "gsi1"
ALL_STATUSES: tuple[str, ...] = get_args(WorkspaceStatus)
_ACTIVE = frozenset(_NON_TERMINAL)
_MAX_ATTEMPTS = 25
_COUNTER_WS = "COUNTER#workspaces"
_COUNTER_ADMINS = "COUNTER#admins"


def _utcnow_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse(iso: str | None) -> datetime | None:
    if not iso:
        return None
    dt = datetime.fromisoformat(iso)
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _epoch_after(iso: str, days: float) -> int:
    """A DynamoDB TTL value (epoch seconds) `days` after the ISO timestamp `iso`."""
    dt = _parse(iso) or datetime.now(timezone.utc)
    return int((dt + timedelta(days=days)).timestamp())


def _to_dynamo(value: Any) -> Any:
    if isinstance(value, float):
        return Decimal(str(value))
    return value


def _from_dynamo(value: Any) -> Any:
    if isinstance(value, Decimal):
        return int(value) if value == value.to_integral_value() else float(value)
    return value


def _clean(item: dict[str, Any]) -> dict[str, Any]:
    """Drop None attributes (absent means NULL here) and convert floats to Decimal."""
    return {k: _to_dynamo(v) for k, v in item.items() if v is not None}


def _key(pk: str, sk: str = "META") -> dict[str, str]:
    return {"pk": pk, "sk": sk}


def _error_code(exc: Exception) -> str:
    return getattr(exc, "response", {}).get("Error", {}).get("Code", "")


def _cancellation_codes(exc: Exception) -> list[str]:
    reasons = getattr(exc, "response", {}).get("CancellationReasons") or []
    return [r.get("Code", "None") for r in reasons]


class TransactionCancelled(Exception):
    def __init__(self, codes: list[str]) -> None:
        super().__init__(f"transaction cancelled: {codes}")
        self.codes = codes

    def failed(self, index: int) -> bool:
        return index < len(self.codes) and self.codes[index] == "ConditionalCheckFailed"


class DynamoTable:
    """The one table, over the boto3 DynamoDB *resource* client (Python-native values
    in and out). Calls run in a worker thread; the client itself is thread-safe."""

    def __init__(self, table_name: str, region: str | None = None, client: Any = None) -> None:
        self.name = table_name
        self._region = region
        self._client = client

    @property
    def client(self) -> Any:
        if self._client is None:
            import boto3  # deferred: keeps the sqlite-only import path cheap

            self._client = boto3.Session(region_name=self._region).resource("dynamodb").meta.client
        return self._client

    async def _call(self, op: str, **kwargs: Any) -> Any:
        return await asyncio.to_thread(getattr(self.client, op), **kwargs)

    async def get(self, pk: str, sk: str = "META") -> dict[str, Any] | None:
        resp = await self._call("get_item", TableName=self.name, Key=_key(pk, sk), ConsistentRead=True)
        return resp.get("Item")

    async def put(self, item: dict[str, Any], *, condition: str | None = None,
                  names: dict[str, str] | None = None, values: dict[str, Any] | None = None) -> bool:
        """Put; False when `condition` refused it."""
        kwargs: dict[str, Any] = {"TableName": self.name, "Item": _clean(item)}
        _add_condition(kwargs, condition, names, values)
        try:
            await self._call("put_item", **kwargs)
        except Exception as exc:
            if _error_code(exc) == "ConditionalCheckFailedException":
                return False
            raise
        return True

    def update_op(
        self,
        pk: str,
        sk: str = "META",
        *,
        sets: dict[str, Any] | None = None,
        removes: tuple[str, ...] | list[str] = (),
        adds: dict[str, Any] | None = None,
        condition: str | None = None,
        names: dict[str, str] | None = None,
        values: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """UpdateItem parameters, usable directly or as a TransactWriteItems `Update`."""
        attr_names: dict[str, str] = dict(names or {})
        attr_values: dict[str, Any] = dict(values or {})
        clauses = []
        set_parts = []
        for i, (attr, value) in enumerate((sets or {}).items()):
            if value is None:
                removes = [*removes, attr]
                continue
            attr_names[f"#s{i}"] = attr
            attr_values[f":s{i}"] = _to_dynamo(value)
            set_parts.append(f"#s{i} = :s{i}")
        if set_parts:
            clauses.append("SET " + ", ".join(set_parts))
        if removes:
            parts = []
            for i, attr in enumerate(removes):
                attr_names[f"#r{i}"] = attr
                parts.append(f"#r{i}")
            clauses.append("REMOVE " + ", ".join(parts))
        if adds:
            parts = []
            for i, (attr, value) in enumerate(adds.items()):
                attr_names[f"#a{i}"] = attr
                attr_values[f":a{i}"] = _to_dynamo(value)
                parts.append(f"#a{i} :a{i}")
            clauses.append("ADD " + ", ".join(parts))
        op: dict[str, Any] = {
            "TableName": self.name,
            "Key": _key(pk, sk),
            "UpdateExpression": " ".join(clauses),
        }
        if condition:
            op["ConditionExpression"] = condition
        if attr_names:
            op["ExpressionAttributeNames"] = attr_names
        if attr_values:
            op["ExpressionAttributeValues"] = attr_values
        return op

    async def update(self, pk: str, sk: str = "META", **kwargs: Any) -> bool:
        """UpdateItem; False when its condition refused it."""
        try:
            await self._call("update_item", **self.update_op(pk, sk, **kwargs))
        except Exception as exc:
            if _error_code(exc) == "ConditionalCheckFailedException":
                return False
            raise
        return True

    async def delete(self, pk: str, sk: str = "META") -> None:
        await self._call("delete_item", TableName=self.name, Key=_key(pk, sk))

    async def query(self, pk: str, sk_prefix: str | None = None, *, index: str | None = None) -> list[dict]:
        """Every item under one partition key (base table: strongly consistent)."""
        key_attr = "gsi1pk" if index else "pk"
        sort_attr = "gsi1sk" if index else "sk"
        kwargs: dict[str, Any] = {
            "TableName": self.name,
            "KeyConditionExpression": "#k = :k",
            "ExpressionAttributeNames": {"#k": key_attr},
            "ExpressionAttributeValues": {":k": pk},
        }
        if sk_prefix is not None:
            kwargs["KeyConditionExpression"] += " AND begins_with(#s, :s)"
            kwargs["ExpressionAttributeNames"]["#s"] = sort_attr
            kwargs["ExpressionAttributeValues"][":s"] = sk_prefix
        if index:
            kwargs["IndexName"] = index
        else:
            kwargs["ConsistentRead"] = True
        items: list[dict] = []
        while True:
            resp = await self._call("query", **kwargs)
            items.extend(resp.get("Items", []))
            last = resp.get("LastEvaluatedKey")
            if not last:
                return items
            kwargs["ExclusiveStartKey"] = last

    async def query_desc_filtered(
        self, pk: str, *, index: str, before: str | None, attr: str, value: str, want: int
    ) -> list[dict]:
        """Up to `want` items of one partition whose `attr` equals `value`, newest sort
        key first, starting strictly below the sort key `before`. The equality filter runs
        server-side (only matching items cross the wire) and the walk stops once `want`
        matches are collected, so a page costs what it reads, not the partition."""
        values: dict[str, Any] = {":k": pk, ":f": value}
        cond = "#k = :k"
        names = {"#k": "gsi1pk", "#f": attr}
        if before is not None:
            cond += " AND #s < :s"
            names["#s"] = "gsi1sk"
            values[":s"] = before
        kwargs: dict[str, Any] = {
            "TableName": self.name, "IndexName": index, "KeyConditionExpression": cond,
            "FilterExpression": "#f = :f",
            "ExpressionAttributeNames": names,
            "ExpressionAttributeValues": values, "ScanIndexForward": False,
        }
        items: list[dict] = []
        while len(items) < want:
            resp = await self._call("query", **kwargs)
            items.extend(resp.get("Items", []))
            last = resp.get("LastEvaluatedKey")
            if not last:
                break
            kwargs["ExclusiveStartKey"] = last
        return items[:want]

    async def batch_get(self, keys: list[dict[str, str]]) -> list[dict]:
        out: list[dict] = []
        for start in range(0, len(keys), 100):
            pending: dict[str, Any] = {self.name: {"Keys": keys[start : start + 100], "ConsistentRead": True}}
            while pending:
                resp = await self._call("batch_get_item", RequestItems=pending)
                out.extend(resp.get("Responses", {}).get(self.name, []))
                pending = resp.get("UnprocessedKeys") or {}
        return out

    async def scan(self) -> list[dict]:
        kwargs: dict[str, Any] = {"TableName": self.name, "ConsistentRead": True}
        items: list[dict] = []
        while True:
            resp = await self._call("scan", **kwargs)
            items.extend(resp.get("Items", []))
            last = resp.get("LastEvaluatedKey")
            if not last:
                return items
            kwargs["ExclusiveStartKey"] = last

    async def transact(self, ops: list[dict[str, Any]]) -> None:
        """TransactWriteItems. Raises TransactionCancelled when a condition failed;
        retries (with jitter) a cancellation caused only by a concurrent transaction."""
        delay = 0.02
        for attempt in range(_MAX_ATTEMPTS):
            try:
                await self._call("transact_write_items", TransactItems=ops)
                return
            except Exception as exc:
                code = _error_code(exc)
                codes = _cancellation_codes(exc)
                conflict = code == "TransactionConflictException" or (
                    code == "TransactionCanceledException"
                    and "ConditionalCheckFailed" not in codes
                    and "TransactionConflict" in codes
                )
                if code == "TransactionCanceledException" and not conflict:
                    raise TransactionCancelled(codes) from exc
                if not conflict or attempt == _MAX_ATTEMPTS - 1:
                    raise
            await asyncio.sleep(delay * random.uniform(0.5, 1.5))
            delay = min(delay * 2, 0.5)

    def put_op(self, item: dict[str, Any], condition: str | None = None,
               names: dict[str, str] | None = None, values: dict[str, Any] | None = None) -> dict:
        op: dict[str, Any] = {"TableName": self.name, "Item": _clean(item)}
        _add_condition(op, condition, names, values)
        return {"Put": op}

    def check_op(self, pk: str, sk: str, condition: str,
                 names: dict[str, str] | None = None, values: dict[str, Any] | None = None) -> dict:
        op: dict[str, Any] = {"TableName": self.name, "Key": _key(pk, sk)}
        _add_condition(op, condition, names, values)
        return {"ConditionCheck": op}


def _add_condition(kwargs: dict, condition: str | None, names: dict | None, values: dict | None) -> None:
    if not condition:
        return
    kwargs["ConditionExpression"] = condition
    if names:
        kwargs["ExpressionAttributeNames"] = {**kwargs.get("ExpressionAttributeNames", {}), **names}
    if values:
        kwargs["ExpressionAttributeValues"] = {
            **kwargs.get("ExpressionAttributeValues", {}),
            **{k: _to_dynamo(v) for k, v in values.items()},
        }


_NOT_EXISTS = "attribute_not_exists(pk)"
_EXISTS = "attribute_exists(pk)"


async def _backoff(attempt: int) -> None:
    await asyncio.sleep(min(0.01 * (2**attempt), 0.25) * random.uniform(0.5, 1.5))


# ----------------------------------------------------------------------------
# Workspaces, idle stops, launch attempts, EBS snapshots
# ----------------------------------------------------------------------------

_WS_FIELDS = (
    "workspace_id", "project", "intent", "image", "root_path", "container_id", "status",
    "server_instance", "labels_json", "created_at", "updated_at", "ssh_port", "owner_id",
    "idle_ttl_seconds", "spec_json", "host_ports_json",
)


_RUN_FIELDS = (
    "run_id", "owner_id", "project", "template", "status", "created_at", "started_at",
    "ended_at", "timeout_seconds", "result_json",
)


def _owner_counter_sk(owner_id: str | None) -> str:
    return f"OWNER#{owner_id}" if owner_id is not None else "OWNERLESS"


def workspace_item(fields: dict[str, Any]) -> dict[str, Any]:
    """The workspace item for a row of `workspaces` column values."""
    wid = fields["workspace_id"]
    return {
        "pk": f"WS#{wid}",
        "sk": "META",
        "gsi1pk": f"WSSTATUS#{fields['status']}",
        "gsi1sk": f"{fields['created_at']}#{wid}",
        **{k: fields.get(k) for k in _WS_FIELDS},
    }


def _item_to_workspace(item: dict[str, Any]) -> Workspace:
    ttl = item.get("idle_ttl_seconds")
    port = item.get("ssh_port")
    return Workspace(
        workspace_id=item["workspace_id"],
        project=item["project"],
        intent=item["intent"],
        image=item["image"],
        root_path=item["root_path"],
        container_id=item.get("container_id"),
        status=item["status"],
        server_instance=item["server_instance"],
        labels=json.loads(item.get("labels_json") or "{}"),
        created_at=datetime.fromisoformat(item["created_at"]),
        updated_at=datetime.fromisoformat(item["updated_at"]),
        ssh_port=int(port) if port is not None else None,
        owner_id=item.get("owner_id"),
        idle_ttl_seconds=float(ttl) if ttl is not None else None,
        spec_json=item.get("spec_json"),
        host_ports_json=item.get("host_ports_json"),
    )


class DynamoWorkspaceStore:
    def __init__(self, table: DynamoTable, *, idle_stop_retention_days: float = 90.0) -> None:
        self._t = table
        self._idle_stop_retention_days = idle_stop_retention_days

    async def close(self) -> None:
        return None

    def _counter_op(self, sk: str, delta: int, cap: int | None) -> dict | None:
        names = {"#n": "n"}
        if delta > 0:
            if cap is None:
                return {"Update": self._t.update_op(_COUNTER_WS, sk, adds={"n": delta})}
            return {"Update": self._t.update_op(
                _COUNTER_WS, sk, adds={"n": delta},
                condition="attribute_not_exists(#n) OR #n < :cap", names=names, values={":cap": cap},
            )}
        if delta < 0:
            return {"Update": self._t.update_op(_COUNTER_WS, sk, adds={"n": delta})}
        if cap is not None:
            return self._t.check_op(
                _COUNTER_WS, sk, "attribute_not_exists(#n) OR #n < :cap", names, {":cap": cap}
            )
        return None

    async def insert(
        self,
        *,
        workspace_id: str,
        project: str,
        intent: str,
        image: str,
        root_path: str,
        server_instance: str,
        status: WorkspaceStatus,
        container_id: str | None = None,
        labels: dict[str, str] | None = None,
        ssh_port: int | None = None,
        owner_id: str | None = None,
        idle_ttl_seconds: float | None = None,
        spec_json: str | None = None,
        max_total: int | None = None,
        max_per_owner: int | None = None,
    ) -> None:
        """Insert, counting toward the caps in the same transaction (module docstring)."""
        if max_total is not None and max_total <= 0:
            raise CapacityExhausted("server", max_total)
        if max_per_owner is not None and max_per_owner <= 0:
            raise CapacityExhausted("owner", max_per_owner)
        now = _utcnow_iso()
        item = workspace_item({
            "workspace_id": workspace_id, "project": project, "intent": intent, "image": image,
            "root_path": root_path, "container_id": container_id, "status": status,
            "server_instance": server_instance, "labels_json": json.dumps(labels or {}),
            "created_at": now, "updated_at": now, "ssh_port": ssh_port, "owner_id": owner_id,
            "idle_ttl_seconds": idle_ttl_seconds, "spec_json": spec_json,
        })
        delta = 1 if status in _ACTIVE else 0
        ops = [self._t.put_op(item, _NOT_EXISTS)]
        counter_ops = [
            self._counter_op("ALL", delta, max_total),
            self._counter_op(_owner_counter_sk(owner_id), delta, max_per_owner),
        ]
        ops.extend(op for op in counter_ops if op is not None)
        try:
            await self._t.transact(ops)
        except TransactionCancelled as exc:
            if exc.failed(0):
                raise StateConflict(f"workspace {workspace_id} already exists") from exc
            if counter_ops[0] is not None and exc.failed(1):
                raise CapacityExhausted("server", max_total or 0) from exc
            raise CapacityExhausted("owner", max_per_owner or 0) from exc

    async def get(self, workspace_id: str) -> Workspace | None:
        item = await self._t.get(f"WS#{workspace_id}")
        return _item_to_workspace(item) if item else None

    async def _transition(self, workspace_id: str, status: str, extra: dict[str, Any] | None = None) -> bool:
        """Set status (and `extra`) conditioned on the status read, moving the live
        counters in the same transaction when the workspace enters or leaves a live
        state. False when the workspace doesn't exist (SQLite's UPDATE no-op)."""
        pk = f"WS#{workspace_id}"
        for attempt in range(_MAX_ATTEMPTS):
            current = await self._t.get(pk)
            if current is None:
                return False
            old = current["status"]
            sets = {"status": status, "updated_at": _utcnow_iso(), "gsi1pk": f"WSSTATUS#{status}", **(extra or {})}
            update = self._t.update_op(
                pk, sets=sets, condition="#cst = :cold", names={"#cst": "status"}, values={":cold": old}
            )
            delta = (status in _ACTIVE) - (old in _ACTIVE)
            try:
                if delta == 0:
                    await self._t._call("update_item", **update)
                else:
                    owner_sk = _owner_counter_sk(current.get("owner_id"))
                    await self._t.transact([
                        {"Update": update},
                        self._counter_op("ALL", delta, None),
                        self._counter_op(owner_sk, delta, None),
                    ])
                return True
            except TransactionCancelled:
                pass
            except Exception as exc:
                if _error_code(exc) != "ConditionalCheckFailedException":
                    raise
            await _backoff(attempt)
        raise RuntimeError(f"workspace {workspace_id}: status kept changing under a concurrent writer")

    async def update_status(self, workspace_id: str, status: WorkspaceStatus) -> None:
        await self._transition(workspace_id, status)
        if status != "stopped":
            await self.clear_idle_stopped(workspace_id)

    async def mark_running(self, workspace_id: str, container_id: str) -> None:
        await self._transition(workspace_id, "running", {"container_id": container_id})
        await self.clear_idle_stopped(workspace_id)

    async def mark_idle_stopped(self, workspace_id: str) -> None:
        now = _utcnow_iso()
        await self._t.put({
            "pk": f"WS#{workspace_id}", "sk": "IDLESTOP", "gsi1pk": "IDLESTOPS", "gsi1sk": workspace_id,
            "workspace_id": workspace_id, "stopped_at": now,
            "ttl": _epoch_after(now, self._idle_stop_retention_days),
        })

    async def clear_idle_stopped(self, workspace_id: str) -> None:
        await self._t.delete(f"WS#{workspace_id}", "IDLESTOP")

    async def list_idle_stopped(self) -> list[tuple[str, datetime]]:
        items = await self._t.query("IDLESTOPS", index=GSI1)
        return [(it["workspace_id"], datetime.fromisoformat(it["stopped_at"])) for it in items]

    async def _update_existing(self, workspace_id: str, **sets: Any) -> None:
        await self._t.update(
            f"WS#{workspace_id}", sets={**sets, "updated_at": _utcnow_iso()}, condition=_EXISTS
        )

    async def update_container_id(self, workspace_id: str, container_id: str | None) -> None:
        await self._update_existing(workspace_id, container_id=container_id)

    async def update_image(self, workspace_id: str, image: str) -> None:
        await self._update_existing(workspace_id, image=image)

    async def update_ssh_port(self, workspace_id: str, port: int) -> None:
        await self._update_existing(workspace_id, ssh_port=port)

    async def update_host_ports(self, workspace_id: str, host_ports: dict | None) -> None:
        # Same encoding as the SQLite column: empty or None clears it.
        await self._update_existing(
            workspace_id, host_ports_json=json.dumps(host_ports) if host_ports else None
        )

    async def _by_status(self, statuses: tuple[str, ...]) -> list[dict]:
        results = await asyncio.gather(*(self._t.query(f"WSSTATUS#{s}", index=GSI1) for s in statuses))
        return [it for items in results for it in items]

    async def list_non_terminal(self) -> list[Workspace]:
        found = await self._by_status(_NON_TERMINAL)
        # The GSI lags the table: re-read the rows consistently and re-check status.
        fresh = await self._t.batch_get([_key(it["pk"], "META") for it in found])
        return [_item_to_workspace(it) for it in fresh if it.get("status") in _ACTIVE]

    async def list_all(self) -> list[Workspace]:
        rows = [_item_to_workspace(it) for it in await self._by_status(ALL_STATUSES)]
        return sorted(rows, key=lambda w: w.created_at, reverse=True)

    async def list_for_owner(
        self, owner_id: str, *, limit: int, after: tuple[str, str] | None = None
    ) -> list[Workspace]:
        """One page of an owner's rows, newest first; see the SQLite store. The only GSI is
        keyed by status, so this walks each status partition newest-first with a server-side
        owner filter and merges, never materialising more than `limit` rows per partition."""
        before = f"{after[0]}#{after[1]}" if after is not None else None
        results = await asyncio.gather(*(
            self._t.query_desc_filtered(
                f"WSSTATUS#{s}", index=GSI1, before=before, attr="owner_id", value=owner_id, want=limit
            )
            for s in ALL_STATUSES
        ))
        rows = sorted(
            (_item_to_workspace(it) for items in results for it in items),
            key=lambda w: (w.created_at, w.workspace_id), reverse=True,
        )
        return rows[:limit]


class DynamoLaunchAttemptStore:
    """AI3 launch identity, at WS#<id>/LAUNCH."""

    _FIELDS = ("generation", "fingerprint", "task_definition_arn", "client_token", "secrets_blobs")

    def __init__(self, table: DynamoTable) -> None:
        self._t = table

    async def get(self, workspace_id: str) -> dict[str, str] | None:
        item = await self._t.get(f"WS#{workspace_id}", "LAUNCH")
        if item is None:
            return None
        # Same shape as the SQLite store: the identity fields are always present (an
        # empty generation, as on a first provision, is stored as null and read back as
        # ""); only the optional secrets_blobs is omitted when empty.
        attempt = {k: item.get(k) or "" for k in self._FIELDS[:4]}
        if item.get("secrets_blobs"):
            attempt["secrets_blobs"] = item["secrets_blobs"]
        return attempt

    def _item(self, workspace_id: str, attempt: dict[str, str]) -> dict[str, Any]:
        return {
            "pk": f"WS#{workspace_id}", "sk": "LAUNCH", "workspace_id": workspace_id,
            "created_at": _utcnow_iso(),
            **{k: attempt.get(k) or None for k in self._FIELDS},
            # The claim condition compares these, and NULL <> "" would let a second claim
            # of an empty-generation attempt overwrite the first; keep "" as "".
            "generation": attempt.get("generation") or "",
            "fingerprint": attempt.get("fingerprint") or "",
        }

    async def put(self, workspace_id: str, attempt: dict[str, str]) -> None:
        await self._t.put(self._item(workspace_id, attempt))

    async def claim(self, workspace_id: str, attempt: dict[str, str]) -> dict[str, str]:
        for _ in range(_MAX_ATTEMPTS):
            stored = await self._t.put(
                self._item(workspace_id, attempt),
                condition="attribute_not_exists(pk) OR #g <> :g OR #f <> :f",
                names={"#g": "generation", "#f": "fingerprint"},
                values={":g": attempt["generation"], ":f": attempt["fingerprint"]},
            )
            if stored:
                return dict(attempt)
            existing = await self.get(workspace_id)
            if existing is not None:
                return existing
        raise RuntimeError(f"workspace {workspace_id}: launch attempt kept changing")

    async def delete(self, workspace_id: str) -> None:
        await self._t.delete(f"WS#{workspace_id}", "LAUNCH")


class DynamoEbsSnapshotStore:
    def __init__(self, table: DynamoTable) -> None:
        self._t = table

    async def get(self, workspace_id: str) -> str | None:
        item = await self._t.get(f"WS#{workspace_id}", "EBSSNAP")
        return item["snapshot_id"] if item else None

    async def put(self, workspace_id: str, snapshot_id: str) -> None:
        await self._t.put({
            "pk": f"WS#{workspace_id}", "sk": "EBSSNAP", "workspace_id": workspace_id,
            "snapshot_id": snapshot_id, "updated_at": _utcnow_iso(),
        })

    async def delete(self, workspace_id: str) -> None:
        await self._t.delete(f"WS#{workspace_id}", "EBSSNAP")


# ----------------------------------------------------------------------------
# Headless runs (registry/runs.py)
# ----------------------------------------------------------------------------

_RUNS_GSI_PK = "RUNS"


def run_item(fields: dict[str, Any]) -> dict[str, Any]:
    """The run item for a row of `runs` column values: in its workspace's partition
    (a run id is its workspace id), listed through `gsi1` under one `RUNS` key."""
    rid = fields["run_id"]
    return {
        "pk": f"WS#{rid}", "sk": f"RUN#{rid}", "gsi1pk": _RUNS_GSI_PK,
        "gsi1sk": f"{fields['created_at']}#{rid}",
        **{k: fields.get(k) for k in _RUN_FIELDS},
    }


class DynamoRunStore:
    """`RunStoreProtocol` at WS#<id>/RUN#<run_id>. Point reads and `finish` are
    consistent and conditional; listings and pruning read the `RUNS` GSI partition,
    which retention and the per-owner cap keep small. A run left in the GSI by lag is
    re-checked by the conditional delete, which never removes a running run."""

    def __init__(self, table: DynamoTable) -> None:
        self._t = table

    @staticmethod
    def _view(item: dict[str, Any]) -> dict[str, Any]:
        from warren.registry.runs import run_view

        return run_view({k: _from_dynamo(item.get(k)) for k in _RUN_FIELDS})

    async def create(
        self,
        *,
        run_id: str,
        owner_id: str,
        project: str,
        template: str,
        timeout_seconds: float | None,
        started_at: datetime | None = None,
    ) -> None:
        from warren.registry.runs import RUNNING, iso, utcnow

        now = iso(started_at or utcnow())
        await self._t.put(
            run_item({
                "run_id": run_id, "owner_id": owner_id, "project": project, "template": template,
                "status": RUNNING, "created_at": now, "started_at": now, "timeout_seconds": timeout_seconds,
            }),
            condition=_NOT_EXISTS,  # INSERT OR IGNORE
        )

    async def get(self, run_id: str) -> dict[str, Any] | None:
        item = await self._t.get(f"WS#{run_id}", f"RUN#{run_id}")
        return self._view(item) if item else None

    async def _all(self) -> list[dict[str, Any]]:
        items = await self._t.query(_RUNS_GSI_PK, index=GSI1)
        return sorted(items, key=lambda it: (it["created_at"], it["run_id"]), reverse=True)

    async def list(self, owner_id: str | None, limit: int = 50) -> list[dict[str, Any]]:
        """Newest first; every owner's when `owner_id` is None (admin)."""
        items = [it for it in await self._all() if owner_id is None or it.get("owner_id") == owner_id]
        return [self._view(it) for it in items[: max(limit, 0)]]

    async def finish(
        self, run_id: str, *, status: str, result: dict[str, Any], ended_at: datetime | None = None
    ) -> bool:
        """Record the result of a still-running run. False if it had already finished."""
        from warren.registry.runs import RUNNING, STATUSES, iso, utcnow

        if status not in STATUSES or status == RUNNING:
            raise ValueError(f"not a final run status: {status!r}")
        return await self._t.update(
            f"WS#{run_id}", f"RUN#{run_id}",
            sets={
                "status": status, "ended_at": iso(ended_at or utcnow()),
                "result_json": json.dumps(result, separators=(",", ":")),
            },
            condition="#st = :running", names={"#st": "status"}, values={":running": RUNNING},
        )

    async def _delete_finished(self, run_id: str) -> bool:
        from warren.registry.runs import RUNNING

        try:
            await self._t._call(
                "delete_item", TableName=self._t.name, Key=_key(f"WS#{run_id}", f"RUN#{run_id}"),
                ConditionExpression="attribute_exists(pk) AND #st <> :running",
                ExpressionAttributeNames={"#st": "status"}, ExpressionAttributeValues={":running": RUNNING},
            )
        except Exception as exc:
            if _error_code(exc) == "ConditionalCheckFailedException":
                return False
            raise
        return True

    async def prune(self, *, retention_seconds: float, max_per_owner: int, now: datetime | None = None) -> int:
        """Drop finished runs older than the retention, then each owner's oldest finished
        runs beyond `max_per_owner` (running ones count toward it but are never pruned),
        as the SQLite store does."""
        from warren.registry.runs import RUNNING, iso, utcnow

        cutoff = iso((now or utcnow()) - timedelta(seconds=retention_seconds))
        removed = 0
        kept: dict[str, list[dict[str, Any]]] = {}
        for it in await self._all():
            finished = it.get("status") != RUNNING
            if finished and (it.get("ended_at") or it["created_at"]) < cutoff:
                removed += await self._delete_finished(it["run_id"])
                continue
            kept.setdefault(it.get("owner_id", ""), []).append(it)
        for rows in kept.values():  # already newest first
            for it in rows[max(max_per_owner, 0):]:
                if it.get("status") != RUNNING:
                    removed += await self._delete_finished(it["run_id"])
        return removed


# ----------------------------------------------------------------------------
# EBS bare seeds
# ----------------------------------------------------------------------------


class DynamoEbsSeedStore:
    """Every read is keyed by owner_id, as in the SQLite store."""

    def __init__(self, table: DynamoTable) -> None:
        self._t = table

    @staticmethod
    def _seed(item: dict) -> dict:
        return {c: _from_dynamo(item.get(c)) for c in _SEED_COLUMNS}

    async def get_seed(self, owner_id: str) -> dict | None:
        item = await self._t.get(f"SEED#{owner_id}")
        return self._seed(item) if item else None

    async def list_seeds(self) -> list[dict]:
        return [self._seed(it) for it in await self._t.query("SEEDS", index=GSI1)]

    def _seed_sets(self, owner_id: str) -> dict[str, Any]:
        return {"owner_id": owner_id, "updated_at": _utcnow_iso(), "gsi1pk": "SEEDS", "gsi1sk": owner_id}

    async def update_seed(self, owner_id: str, **fields: object) -> None:
        bad = set(fields) - set(_SEED_COLUMNS[1:])
        if bad:
            raise ValueError(f"unknown seed columns: {sorted(bad)}")
        await self._t.update(f"SEED#{owner_id}", sets={**fields, **self._seed_sets(owner_id)})

    async def delete_seed(self, owner_id: str) -> None:
        await self._t.delete(f"SEED#{owner_id}")

    async def claim_refresh(self, owner_id: str, now: str, stale_before: str) -> bool:
        return await self._t.update(
            f"SEED#{owner_id}",
            sets={**self._seed_sets(owner_id), "refreshing_since": now},
            condition="attribute_not_exists(#rs) OR #rs < :stale",
            names={"#rs": "refreshing_since"},
            values={":stale": stale_before},
        )

    async def repos(self, owner_id: str) -> list[dict]:
        out = []
        for it in await self._t.query(f"SEED#{owner_id}", "REPO#"):
            row = {c: _from_dynamo(it.get(c)) for c in _SEED_REPO_COLUMNS}
            row["branches"] = _json_list(row["branches"])
            row["ref_shas"] = _json_dict(row["ref_shas"])
            out.append(row)
        out.sort(key=lambda r: r["repo_key"])
        out.sort(key=lambda r: r["last_used_at"] or "", reverse=True)
        return out

    async def repo_owners(self) -> list[str]:
        return sorted({it["owner_id"] for it in await self._t.query("SEEDREPOS", index=GSI1)})

    async def put_repo(self, owner_id: str, row: dict) -> None:
        await self._t.put({
            "pk": f"SEED#{owner_id}", "sk": f"REPO#{row['repo_key']}",
            "gsi1pk": "SEEDREPOS", "gsi1sk": f"{owner_id}#{row['repo_key']}",
            "owner_id": owner_id, "repo_key": row["repo_key"], "url": row["url"], "kind": row["kind"],
            "cred_kind": row["cred_kind"], "cred_secret": row["cred_secret"],
            "branches": json.dumps(sorted(set(row.get("branches") or []))),
            "ref_shas": json.dumps(row["ref_shas"], sort_keys=True) if row.get("ref_shas") else None,
            "last_used_at": row["last_used_at"], "released_at": row.get("released_at"),
        })

    async def delete_repo(self, owner_id: str, repo_key: str) -> None:
        await self._t.delete(f"SEED#{owner_id}", f"REPO#{repo_key}")

    async def set_ref_shas(self, owner_id: str, repo_key: str, shas: dict | None) -> None:
        await self._t.update(
            f"SEED#{owner_id}", f"REPO#{repo_key}",
            sets={"ref_shas": json.dumps(shas, sort_keys=True) if shas else None},
            condition=_EXISTS,
        )


# ----------------------------------------------------------------------------
# Operations (AM2)
# ----------------------------------------------------------------------------

_OP_FIELDS = ("operation_id", "kind", "request_hash", "stage", "workspace_id", "created_at", "updated_at")


class DynamoOperationStore:
    def __init__(self, table: DynamoTable) -> None:
        self._t = table

    async def create(
        self, *, principal: str, operation_id: str, kind: str, request_hash: str, workspace_id: str
    ) -> bool:
        now = _utcnow_iso()
        return await self._t.put(
            {
                "pk": f"OP#{principal}", "sk": f"OP#{operation_id}", "principal": principal,
                "operation_id": operation_id, "kind": kind, "request_hash": request_hash,
                "stage": "accepted", "workspace_id": workspace_id, "created_at": now, "updated_at": now,
            },
            condition=_NOT_EXISTS,
        )

    async def get(self, principal: str, operation_id: str) -> dict[str, str] | None:
        item = await self._t.get(f"OP#{principal}", f"OP#{operation_id}")
        return {k: item.get(k) for k in _OP_FIELDS} if item else None

    async def delete(self, principal: str, operation_id: str) -> None:
        await self._t.delete(f"OP#{principal}", f"OP#{operation_id}")

    async def set_stage(self, principal: str, operation_id: str, stage: str) -> None:
        await self._t.update(
            f"OP#{principal}", f"OP#{operation_id}",
            sets={"stage": stage, "updated_at": _utcnow_iso()}, condition=_EXISTS,
        )


# ----------------------------------------------------------------------------
# Users, tokens, workspace tokens
# ----------------------------------------------------------------------------


def user_item(fields: dict[str, Any]) -> dict[str, Any]:
    uid = fields["user_id"]
    return {
        "pk": f"USER#{uid}", "sk": "META", "gsi1pk": "USERS", "gsi1sk": f"{fields['created_at']}#{uid}",
        "user_id": uid, "username": fields["username"], "is_admin": bool(fields["is_admin"]),
        "created_at": fields["created_at"], "disabled_at": fields.get("disabled_at"),
    }


def _item_to_user(item: dict) -> User:
    return User(
        user_id=item["user_id"],
        username=item["username"],
        is_admin=bool(item.get("is_admin")),
        created_at=datetime.fromisoformat(item["created_at"]),
        disabled_at=datetime.fromisoformat(item["disabled_at"]) if item.get("disabled_at") else None,
    )


def _item_to_token(item: dict) -> Token:
    return Token(
        token_id=item["token_id"],
        user_id=item["user_id"],
        created_at=datetime.fromisoformat(item["created_at"]),
        expires_at=datetime.fromisoformat(item["expires_at"]) if item.get("expires_at") else None,
        revoked_at=datetime.fromisoformat(item["revoked_at"]) if item.get("revoked_at") else None,
        created_by_token_id=item.get("created_by_token_id"),
    )


def _live(item: dict, now: datetime) -> bool:
    if item.get("revoked_at"):
        return False
    expires = _parse(item.get("expires_at"))
    return expires is None or expires > now


class DynamoAuthStore:
    """See the module docstring for the item layout and the atomicity of the caps."""

    def __init__(self, table: DynamoTable, *, token_retention_days: float = 30.0) -> None:
        self._t = table
        self._retention_days = token_retention_days

    async def close(self) -> None:
        return None

    # -- users ---------------------------------------------------------------

    def token_items(self, fields: dict[str, Any]) -> list[dict[str, Any]]:
        """The token item and its by-hash and by-id pointers, for a `tokens` row."""
        ttl = self._token_ttl(fields.get("expires_at"), fields.get("revoked_at"))
        uid, tid = fields["user_id"], fields["token_id"]
        return [
            {
                "pk": f"USER#{uid}", "sk": f"TOKEN#{tid}", "token_id": tid, "user_id": uid,
                "hashed_token": fields["hashed_token"], "created_at": fields["created_at"],
                "expires_at": fields.get("expires_at"), "revoked_at": fields.get("revoked_at"),
                "created_by_token_id": fields.get("created_by_token_id"), "ttl": ttl,
            },
            {"pk": f"TOKENHASH#{fields['hashed_token']}", "sk": "META", "token_id": tid, "user_id": uid, "ttl": ttl},
            {"pk": f"TOKENID#{tid}", "sk": "META", "user_id": uid, "ttl": ttl},
        ]

    def workspace_token_items(self, fields: dict[str, Any]) -> list[dict[str, Any]]:
        ttl = self._token_ttl(fields["expires_at"], fields.get("revoked_at"))
        wid, tid = fields["workspace_id"], fields["token_id"]
        return [
            {
                "pk": f"WS#{wid}", "sk": f"WSTOKEN#{tid}", "token_id": tid, "workspace_id": wid,
                "user_id": fields["user_id"], "hashed_token": fields["hashed_token"],
                "public_key": fields.get("public_key"), "created_at": fields["created_at"],
                "expires_at": fields["expires_at"], "revoked_at": fields.get("revoked_at"),
                "created_by_token_id": fields.get("created_by_token_id"),
                "provision_grant": bool(fields.get("provision_grant")), "ttl": ttl,
            },
            {"pk": f"WSTOKENHASH#{fields['hashed_token']}", "sk": "META", "token_id": tid, "workspace_id": wid, "ttl": ttl},
            {"pk": f"WSTOKENID#{tid}", "sk": "META", "workspace_id": wid, "ttl": ttl},
        ]

    def _token_ttl(self, expires_at: str | None, revoked_at: str | None = None) -> int | None:
        """DynamoDB TTL for a token's items: the earlier of expiry and revocation, plus
        WARREN_DYNAMODB_TOKEN_RETENTION_DAYS. None (kept) for a live token with no expiry."""
        candidates = [_epoch_after(t, self._retention_days) for t in (expires_at, revoked_at) if t]
        return min(candidates) if candidates else None

    async def create_user(self, *, username: str, is_admin: bool) -> User:
        user_id = uuid.uuid4().hex
        now = _utcnow_iso()
        ops = [
            self._t.put_op(user_item({"user_id": user_id, "username": username, "is_admin": is_admin, "created_at": now}), _NOT_EXISTS),
            self._t.put_op({"pk": f"USERNAME#{username}", "sk": "META", "user_id": user_id}, _NOT_EXISTS),
        ]
        if is_admin:
            ops.append({"Update": self._t.update_op(_COUNTER_ADMINS, adds={"total": 1, "enabled": 1})})
        try:
            await self._t.transact(ops)
        except TransactionCancelled as exc:
            raise StateConflict("username already exists") from exc
        return User(user_id=user_id, username=username, is_admin=is_admin, created_at=datetime.fromisoformat(now))

    async def get_user(self, user_id: str) -> User | None:
        item = await self._t.get(f"USER#{user_id}")
        return _item_to_user(item) if item else None

    async def get_user_by_username(self, username: str) -> User | None:
        pointer = await self._t.get(f"USERNAME#{username}")
        return await self.get_user(pointer["user_id"]) if pointer else None

    async def list_users(self) -> list[User]:
        items = await self._t.query("USERS", index=GSI1)
        return sorted((_item_to_user(it) for it in items), key=lambda u: u.created_at)

    async def disable_user(self, user_id: str, *, keep_last_admin: bool = False) -> bool:
        user = await self._t.get(f"USER#{user_id}")
        if user is None:
            return False
        if user.get("disabled_at"):
            return True
        names = {"#d": "disabled_at"}
        update = self._t.update_op(
            f"USER#{user_id}", sets={"disabled_at": _utcnow_iso()},
            condition="attribute_exists(pk) AND attribute_not_exists(#d)", names=names,
        )
        if not user.get("is_admin"):
            try:
                await self._t._call("update_item", **update)
            except Exception as exc:
                if _error_code(exc) != "ConditionalCheckFailedException":
                    raise
            return True
        counter = self._t.update_op(
            _COUNTER_ADMINS, adds={"enabled": -1},
            condition="#e > :one" if keep_last_admin else None,
            names={"#e": "enabled"} if keep_last_admin else None,
            values={":one": 1} if keep_last_admin else None,
        )
        try:
            await self._t.transact([{"Update": update}, {"Update": counter}])
        except TransactionCancelled as exc:
            if exc.failed(0):
                return True  # disabled concurrently
            raise LastAdminError(user_id) from exc
        return True

    async def enable_user(self, user_id: str) -> bool:
        user = await self._t.get(f"USER#{user_id}")
        if user is None:
            return False
        if not user.get("disabled_at"):
            return True
        update = self._t.update_op(
            f"USER#{user_id}", removes=["disabled_at"], condition="attribute_exists(#d)", names={"#d": "disabled_at"}
        )
        ops = [{"Update": update}]
        if user.get("is_admin"):
            ops.append({"Update": self._t.update_op(_COUNTER_ADMINS, adds={"enabled": 1})})
        try:
            await self._t.transact(ops)
        except TransactionCancelled:
            pass  # enabled concurrently
        return True

    async def _admin_counter(self, attr: str) -> int:
        item = await self._t.get(_COUNTER_ADMINS)
        return int(item.get(attr, 0)) if item else 0

    async def count_admins(self) -> int:
        return await self._admin_counter("total")

    async def count_enabled_admins(self) -> int:
        return await self._admin_counter("enabled")

    async def list_admins(self) -> list[User]:
        return [u for u in await self.list_users() if u.is_admin]

    # -- tokens --------------------------------------------------------------

    async def create_token(
        self,
        *,
        user_id: str,
        hashed_token: str,
        expires_at: datetime | None = None,
        created_by_token_id: str | None = None,
        max_active: int | None = None,
    ) -> Token:
        token_id = uuid.uuid4().hex
        expires_iso = expires_at.isoformat() if expires_at else None
        for attempt in range(_MAX_ATTEMPTS):
            user = await self._t.get(f"USER#{user_id}")
            if user is None:
                raise StateConflict(f"user {user_id} does not exist")
            seq = int(user.get("token_seq", 0))
            now = _utcnow_iso()
            if max_active is not None:
                live = [it for it in await self._t.query(f"USER#{user_id}", "TOKEN#") if _live(it, _parse(now))]
                if len(live) >= max_active:
                    raise TokenLimitReached(user_id)
            items = self.token_items({
                "token_id": token_id, "user_id": user_id, "hashed_token": hashed_token,
                "created_at": now, "expires_at": expires_iso, "created_by_token_id": created_by_token_id,
            })
            seq_condition = "attribute_exists(pk) AND " + (
                "#q = :seq" if "token_seq" in user else "attribute_not_exists(#q)"
            )
            ops = [
                *(self._t.put_op(it, _NOT_EXISTS) for it in items),
                {"Update": self._t.update_op(
                    f"USER#{user_id}", sets={"token_seq": seq + 1}, condition=seq_condition,
                    names={"#q": "token_seq"}, values={":seq": seq} if "token_seq" in user else None,
                )},
            ]
            try:
                await self._t.transact(ops)
            except TransactionCancelled as exc:
                if exc.failed(0) or exc.failed(1) or exc.failed(2):
                    raise StateConflict("token hash or id already exists") from exc
                await _backoff(attempt)  # a concurrent mint for this user: count again
                continue
            return Token(
                token_id=token_id, user_id=user_id, created_at=datetime.fromisoformat(now),
                expires_at=expires_at, revoked_at=None, created_by_token_id=created_by_token_id,
            )
        raise RuntimeError(f"user {user_id}: token mint kept racing a concurrent mint")

    async def list_tokens_for_user(self, user_id: str) -> list[Token]:
        items = await self._t.query(f"USER#{user_id}", "TOKEN#")
        return sorted((_item_to_token(it) for it in items), key=lambda t: t.created_at)

    async def count_active_tokens_for_user(self, user_id: str) -> int:
        now = datetime.now(timezone.utc)
        return sum(1 for it in await self._t.query(f"USER#{user_id}", "TOKEN#") if _live(it, now))

    async def _revoke(self, item: dict, now: str) -> bool:
        """Revoke one token item (any kind) and shorten its pointers' TTL."""
        ttl = self._token_ttl(item.get("expires_at"), now)
        ok = await self._t.update(
            item["pk"], item["sk"], sets={"revoked_at": now, "ttl": ttl},
            condition="attribute_exists(pk) AND attribute_not_exists(#rv)", names={"#rv": "revoked_at"},
        )
        if ok:
            ws = item["sk"].startswith("WSTOKEN#")
            for pk in (
                f"{'WSTOKENHASH' if ws else 'TOKENHASH'}#{item['hashed_token']}",
                f"{'WSTOKENID' if ws else 'TOKENID'}#{item['token_id']}",
            ):
                await self._t.update(pk, sets={"ttl": ttl}, condition=_EXISTS)
        return ok

    async def revoke_all_tokens_for_user(self, user_id: str) -> int:
        now = _utcnow_iso()
        count = 0
        for item in await self._t.query(f"USER#{user_id}", "TOKEN#"):
            if not item.get("revoked_at") and await self._revoke(item, now):
                count += 1
        return count

    async def get_active_user_by_hashed_token(self, hashed_token: str) -> User | None:
        result = await self.get_active_user_and_token_id_by_hashed_token(hashed_token)
        return result[0] if result else None

    async def get_active_user_and_token_id_by_hashed_token(self, hashed_token: str) -> tuple[User, str] | None:
        pointer = await self._t.get(f"TOKENHASH#{hashed_token}")
        if pointer is None:
            return None
        token, user = await asyncio.gather(
            self._t.get(f"USER#{pointer['user_id']}", f"TOKEN#{pointer['token_id']}"),
            self._t.get(f"USER#{pointer['user_id']}"),
        )
        if token is None or user is None or token.get("hashed_token") != hashed_token:
            return None
        if not _live(token, datetime.now(timezone.utc)) or user.get("disabled_at"):
            return None
        return _item_to_user(user), token["token_id"]

    async def get_token(self, token_id: str) -> Token | None:
        pointer = await self._t.get(f"TOKENID#{token_id}")
        if pointer is None:
            return None
        item = await self._t.get(f"USER#{pointer['user_id']}", f"TOKEN#{token_id}")
        return _item_to_token(item) if item else None

    async def revoke_token(self, token_id: str) -> bool:
        pointer = await self._t.get(f"TOKENID#{token_id}")
        if pointer is None:
            return False
        item = await self._t.get(f"USER#{pointer['user_id']}", f"TOKEN#{token_id}")
        if item is None or item.get("revoked_at"):
            return False
        return await self._revoke(item, _utcnow_iso())

    # -- workspace tokens ----------------------------------------------------

    async def create_workspace_token(
        self,
        *,
        workspace_id: str,
        user_id: str,
        hashed_token: str,
        expires_at: datetime,
        public_key: str | None = None,
        created_by_token_id: str | None = None,
        provision_grant: bool = False,
    ) -> WorkspaceToken:
        token_id = uuid.uuid4().hex
        now = _utcnow_iso()
        items = self.workspace_token_items({
            "token_id": token_id, "workspace_id": workspace_id, "user_id": user_id,
            "hashed_token": hashed_token, "public_key": public_key, "created_at": now,
            "expires_at": expires_at.isoformat(), "created_by_token_id": created_by_token_id,
            "provision_grant": provision_grant,
        })
        try:
            await self._t.transact([
                *(self._t.put_op(it, _NOT_EXISTS) for it in items),
                self._t.check_op(f"USER#{user_id}", "META", _EXISTS),
            ])
        except TransactionCancelled as exc:
            raise StateConflict("workspace token conflict or unknown user") from exc
        return WorkspaceToken(
            token_id=token_id, workspace_id=workspace_id, user_id=user_id,
            created_at=datetime.fromisoformat(now), expires_at=expires_at, public_key=public_key,
            created_by_token_id=created_by_token_id, provision_grant=provision_grant,
        )

    async def get_active_workspace_token(self, hashed_token: str) -> tuple[User, WorkspaceToken] | None:
        """Same liveness rules as the SQLite store's join (auth/store.py)."""
        pointer = await self._t.get(f"WSTOKENHASH#{hashed_token}")
        if pointer is None:
            return None
        wid = pointer["workspace_id"]
        token = await self._t.get(f"WS#{wid}", f"WSTOKEN#{pointer['token_id']}")
        if token is None or token.get("hashed_token") != hashed_token:
            return None
        if not _live(token, datetime.now(timezone.utc)):
            return None
        user, ws = await asyncio.gather(self._t.get(f"USER#{token['user_id']}"), self._t.get(f"WS#{wid}"))
        if user is None or user.get("disabled_at"):
            return None
        if ws is None:
            if not token.get("provision_grant"):
                return None
        elif ws.get("owner_id") != token["user_id"]:
            return None
        elif ws.get("status") == "destroyed" and _spec_mode(ws.get("spec_json")) != "single-turn":
            return None
        return _item_to_user(user), WorkspaceToken(
            token_id=token["token_id"],
            workspace_id=wid,
            user_id=token["user_id"],
            created_at=datetime.fromisoformat(token["created_at"]),
            expires_at=datetime.fromisoformat(token["expires_at"]),
            public_key=token.get("public_key"),
            created_by_token_id=token.get("created_by_token_id"),
            provision_grant=bool(token.get("provision_grant")),
            workspace_status=ws.get("status") if ws else None,
        )

    async def consume_provision_grant(self, token_id: str) -> bool:
        pointer = await self._t.get(f"WSTOKENID#{token_id}")
        if pointer is None:
            return False
        return await self._t.update(
            f"WS#{pointer['workspace_id']}", f"WSTOKEN#{token_id}", sets={"provision_grant": False},
            condition="#pg = :yes AND attribute_not_exists(#rv)",
            names={"#pg": "provision_grant", "#rv": "revoked_at"}, values={":yes": True},
        )

    async def revoke_workspace_tokens(self, workspace_id: str, *, keep_token_id: str | None = None) -> int:
        now = _utcnow_iso()
        count = 0
        for item in await self._t.query(f"WS#{workspace_id}", "WSTOKEN#"):
            if item["token_id"] == keep_token_id or item.get("revoked_at"):
                continue
            if await self._revoke(item, now):
                count += 1
        return count


def _spec_mode(spec_json: str | None) -> str | None:
    try:
        data = json.loads(spec_json) if spec_json else None
    except ValueError:
        return None
    return data.get("mode") if isinstance(data, dict) else None


# ----------------------------------------------------------------------------
# Counter repair (migration)
# ----------------------------------------------------------------------------


async def recount(table: DynamoTable) -> dict[str, int]:
    """Recompute the workspace and admin counters from the items themselves (a full
    consistent scan). Used by the migration after copying; safe to rerun."""
    live: dict[str, int] = {"ALL": 0}
    total_admins = enabled_admins = 0
    for item in await table.scan():
        if item["sk"] == "META" and item["pk"].startswith("WS#") and item.get("status") in _ACTIVE:
            live["ALL"] += 1
            sk = _owner_counter_sk(item.get("owner_id"))
            live[sk] = live.get(sk, 0) + 1
        elif item["sk"] == "META" and item["pk"].startswith("USER#") and item.get("is_admin"):
            total_admins += 1
            enabled_admins += 0 if item.get("disabled_at") else 1
    for item in await table.query(_COUNTER_WS):
        live.setdefault(item["sk"], 0)
    for sk, n in live.items():
        await table.put({"pk": _COUNTER_WS, "sk": sk, "n": n})
    await table.put({"pk": _COUNTER_ADMINS, "sk": "META", "total": total_admins, "enabled": enabled_admins})
    return {"live_workspaces": live["ALL"], "admins": total_admins, "enabled_admins": enabled_admins}


def create_table_kwargs(table_name: str) -> dict[str, Any]:
    """CreateTable parameters matching the reference IaC (tests and local fakes only:
    warren-server never creates its table)."""
    return {
        "TableName": table_name,
        "BillingMode": "PAY_PER_REQUEST",
        "AttributeDefinitions": [
            {"AttributeName": a, "AttributeType": "S"} for a in ("pk", "sk", "gsi1pk", "gsi1sk")
        ],
        "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}, {"AttributeName": "sk", "KeyType": "RANGE"}],
        "GlobalSecondaryIndexes": [{
            "IndexName": GSI1,
            "KeySchema": [
                {"AttributeName": "gsi1pk", "KeyType": "HASH"},
                {"AttributeName": "gsi1sk", "KeyType": "RANGE"},
            ],
            "Projection": {"ProjectionType": "ALL"},
        }],
    }


__all__ = [
    "DynamoAuthStore",
    "DynamoEbsSeedStore",
    "DynamoEbsSnapshotStore",
    "DynamoLaunchAttemptStore",
    "DynamoOperationStore",
    "DynamoRunStore",
    "DynamoTable",
    "DynamoWorkspaceStore",
    "create_table_kwargs",
    "recount",
]
