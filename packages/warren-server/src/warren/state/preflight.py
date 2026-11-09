"""Startup checks for a non-default state or secrets backend: fail fast, with an error
that names the setting and the missing permission or resource, instead of failing on the
first request."""

from __future__ import annotations

import asyncio
from typing import Any

import structlog
from warren.state.dynamodb import GSI1
from warren.state.errors import StateBackendError

log = structlog.get_logger(__name__)

_DENIED = ("AccessDeniedException", "AccessDenied", "UnrecognizedClientException")


def _code(exc: Exception) -> str:
    return getattr(exc, "response", {}).get("Error", {}).get("Code", "")


async def check_dynamodb_table(client: Any, table_name: str, region: str) -> None:
    """The table exists, is ACTIVE, and has the pk/sk keys and the gsi1 index."""
    try:
        resp = await asyncio.to_thread(client.describe_table, TableName=table_name)
    except Exception as exc:
        code = _code(exc)
        if code == "ResourceNotFoundException":
            raise StateBackendError(
                f"WARREN_DYNAMODB_TABLE={table_name!r}: no such table in {region}. Create it "
                "(resources/ecs/README.md, State backends) or fix the name/WARREN_AWS_REGION"
            ) from exc
        if code in _DENIED:
            raise StateBackendError(
                f"WARREN_DYNAMODB_TABLE={table_name!r}: the control-plane role may not call "
                "dynamodb:DescribeTable on it; grant the statements in resources/ecs/README.md"
            ) from exc
        raise StateBackendError(f"WARREN_DYNAMODB_TABLE={table_name!r}: DescribeTable failed ({code or exc})") from exc
    table = resp["Table"]
    if table.get("TableStatus") not in ("ACTIVE", "UPDATING"):
        raise StateBackendError(f"DynamoDB table {table_name!r} is {table.get('TableStatus')}, not ACTIVE")
    keys = {k["AttributeName"]: k["KeyType"] for k in table.get("KeySchema", [])}
    if keys != {"pk": "HASH", "sk": "RANGE"}:
        raise StateBackendError(
            f"DynamoDB table {table_name!r} must have partition key `pk` and sort key `sk` (strings); has {keys}"
        )
    indexes = {i["IndexName"]: i for i in table.get("GlobalSecondaryIndexes") or []}
    gsi = indexes.get(GSI1)
    gsi_keys = {k["AttributeName"]: k["KeyType"] for k in (gsi or {}).get("KeySchema", [])}
    if gsi_keys != {"gsi1pk": "HASH", "gsi1sk": "RANGE"}:
        raise StateBackendError(
            f"DynamoDB table {table_name!r} needs global secondary index {GSI1!r} on gsi1pk/gsi1sk "
            "with projection ALL"
        )
    try:
        ttl = await asyncio.to_thread(client.describe_time_to_live, TableName=table_name)
        desc = ttl.get("TimeToLiveDescription", {})
        if desc.get("TimeToLiveStatus") not in ("ENABLED", "ENABLING") or desc.get("AttributeName") != "ttl":
            log.warning("dynamodb_ttl_disabled", table=table_name, detail="enable TTL on attribute `ttl`")
    except Exception as exc:  # advisory only
        log.warning("dynamodb_ttl_check_failed", table=table_name, error=_code(exc) or str(exc))


async def check_secretsmanager(client: Any, prefix: str) -> None:
    """The control-plane role can list secrets (the call every read path depends on)."""
    try:
        await asyncio.to_thread(
            client.list_secrets, Filters=[{"Key": "name", "Values": [f"{prefix}/"]}], MaxResults=1
        )
    except Exception as exc:
        code = _code(exc)
        if code in _DENIED:
            raise StateBackendError(
                f"WARREN_SECRETS_BACKEND=secretsmanager: the control-plane role may not call "
                f"secretsmanager:ListSecrets (prefix {prefix!r}); grant the statements in "
                "resources/ecs/README.md"
            ) from exc
        raise StateBackendError(
            f"WARREN_SECRETS_BACKEND=secretsmanager: ListSecrets failed for prefix {prefix!r} ({code or exc})"
        ) from exc


async def check_state_backends(settings: Any, state: Any) -> None:
    """Run the checks for whichever non-default backends `state` (an open StateBackend) uses."""
    if settings.state_backend == "dynamodb":
        table = state.workspaces._t
        await check_dynamodb_table(table.client, table.name, settings.aws_region)
    if settings.secrets_backend == "secretsmanager":
        await check_secretsmanager(state.secrets.client, state.secrets.prefix)
