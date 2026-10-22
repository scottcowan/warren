"""Structured audit events (AI4, SEED-003).

Every security-relevant action (secret write/delete/delivery, workspace
provision/connect/destroy, credential issuance) is emitted through
`audit_event` as one `event="audit"` log record with a fixed set of keys, so
a sink (CloudWatch, a SIEM, a file) can filter on `event == "audit"` and parse
every record the same way:

    audit_version, action, outcome, caller_id, caller_token_id,
    caller_workspace_scope, owner_id, workspace_id, + action-specific fields

`caller_*` always comes from the server-resolved identity on the request
(AuthMiddleware), never from anything the client supplied. Secret values,
tokens and keys are never accepted as fields.
"""

from __future__ import annotations

from typing import Any

import structlog
from fastapi import Request

AUDIT_VERSION = 1

_FORBIDDEN_FIELDS = frozenset(
    {"value", "values", "secret_value", "token", "private_key", "key", "password", "env"}
)


def caller_from_request(request: Request) -> dict[str, str | None]:
    user = getattr(request.state, "user", None)
    return {
        "caller_id": getattr(user, "user_id", None),
        "caller_token_id": getattr(request.state, "token_id", None),
        "caller_workspace_scope": getattr(request.state, "workspace_scope", None),
    }


def audit_event(
    action: str,
    *,
    request: Request | None = None,
    caller_id: str | None = None,
    outcome: str = "success",
    owner_id: str | None = None,
    workspace_id: str | None = None,
    **fields: Any,
) -> dict[str, Any]:
    forbidden = _FORBIDDEN_FIELDS.intersection(fields)
    if forbidden:
        raise ValueError(f"audit events must not carry secret material: {sorted(forbidden)}")
    caller = (
        caller_from_request(request)
        if request is not None
        else {"caller_id": caller_id, "caller_token_id": None, "caller_workspace_scope": None}
    )
    record: dict[str, Any] = {
        "audit_version": AUDIT_VERSION,
        "action": action,
        "outcome": outcome,
        **caller,
        "owner_id": owner_id,
        "workspace_id": workspace_id,
        **fields,
    }
    structlog.get_logger("warren.audit").info("audit", **record)
    return record
