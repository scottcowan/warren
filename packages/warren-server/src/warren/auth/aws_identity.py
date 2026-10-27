"""Verify a caller's AWS IAM identity from a client-signed STS request.

ECS deployments isolate `warren.secrets` by the caller's real AWS identity
(their IAM user/role ARN), not warren's own bearer-token user_id -- the
caller's bearer token still authenticates the HTTP request itself (D-06),
but on ECS it no longer determines secret ownership.

warren-server must never see or require the caller's raw AWS credentials to
learn their identity. Instead the caller signs an `sts:GetCallerIdentity`
POST request with their own local AWS credentials (STS supports this as a
plain SigV4-signed request, same mechanism HashiCorp Vault's AWS IAM auth
method and aws-iam-authenticator use) and sends warren-server the resulting
method/url/headers/body as JSON. warren-server replays that exact request to
AWS STS itself: because the SigV4 signature is already bound to the caller's
real credentials, a successful response proves who they are without
warren-server ever handling a secret key.

Two properties a bare presigned GET URL doesn't give us, which is why this
is a signed POST request (method+url+headers+body) rather than a URL string:

  - Audience binding: a custom header (`X-Warren-Audience`) is included in
    the SIGNED headers (verified via the Authorization header's own
    `SignedHeaders=` list below -- an unsigned header is just a caller's
    claim, worth nothing), so it can't be stripped, altered, or added
    after signing without breaking the signature. The server rejects a
    request whose audience doesn't match its own `settings.server_id`, so a
    request signed for warren-server A can't be replayed against warren-
    server B. `server_id` (not `request.base_url`) is what's compared here:
    behind an SSM/SSH tunnel the client reaches the server at
    `http://127.0.0.1:<ephemeral local port>`, which carries zero identity
    (two different warren-servers reached through two different tunnels can
    land on the same local port) and the CLI doesn't know it when it signs
    the request anyway -- `server_id` is a stable, explicitly operator-
    configured value, exposed over `/healthz` as `warren_id`, that the CLI
    learns once and signs regardless of how it reaches the server.
  - A tight anti-replay window: `X-Amz-Date` (also inside the signature) is
    checked against wall-clock time directly, instead of trusting a
    caller-supplied `X-Amz-Expires` query parameter.

SSRF guard: the request is only ever replayed if its URL's host matches
AWS's own STS endpoint pattern and scheme is https -- a client cannot point
this at an arbitrary internal/external URL.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timezone
from typing import Callable
from urllib.parse import parse_qs, urlparse

import httpx

_STS_HOST_RE = re.compile(r"^sts(\.[a-z0-9-]+)?\.amazonaws\.com$")
_MAX_REQUEST_AGE_SECONDS = 300
_ARN_RE = re.compile(r"<Arn>([^<]+)</Arn>")
_AUDIENCE_HEADER = "x-warren-audience"
_AMZ_DATE_RE = re.compile(r"^\d{8}T\d{6}Z$")

# Plain IAM users are always trusted: the ARN's user-name segment is an
# admin-assigned, immutable name, with no path a caller controls that could
# collide it with another user. An assumed role is NOT trusted by any
# hardcoded name convention (an earlier version of this code special-cased
# an "AWSReservedSSO_" prefix -- that prefix is not confirmed reserved
# against customer-created roles, so trusting it by name alone would trust
# whatever IAM allows the account to name a role). Instead, an assumed-role
# ARN is only trusted when it matches one of `settings.
# aws_trusted_assumed_role_patterns` -- an operator-configured allow-list,
# verified in their own account, naming the exact role(s) whose
# RoleSessionName segment they can personally vouch for (e.g. because IAM
# Identity Center or their own AssumeRole trust policy pins it to the real
# caller).
_IAM_USER_ARN_RE = re.compile(r"^arn:aws:iam::\d{12}:user/[\w+=,.@-]+$")
_ASSUMED_ROLE_ARN_RE = re.compile(r"^arn:aws:sts::\d{12}:assumed-role/[\w+=,.@-]+/[\w+=,.@-]+$")


class AwsIdentityError(Exception):
    """Raised when a signed caller-identity request is malformed, rejected, or unverifiable."""


def derive_owner_id(arn: str, trusted_assumed_role_patterns: list[str] | None = None) -> str:
    """Map a verified AWS ARN to a `warren.secrets` owner_id.

    Raises AwsIdentityError for any ARN shape whose uniqueness-per-human
    isn't guaranteed: a plain IAM user ARN is always accepted; an assumed-
    role ARN is accepted only if it `re.fullmatch`es one of
    `trusted_assumed_role_patterns` (each a regex), the operator-configured
    allow-list from `settings.aws_trusted_assumed_role_patterns` -- see
    module docstring for why no assumed role is trusted by default.

    Full-match, not a prefix match: a pattern like
    `arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Admin_abc` must
    describe the ENTIRE ARN to trust it -- with `re.match` (prefix-anchored
    only), that same pattern would also trust
    `.../AWSReservedSSO_Admin_abcXYZ/anyone`, reopening the exact
    session-name collision this allow-list exists to prevent. A pattern
    that intends to trust any session name on a role must say so
    explicitly, e.g. `arn:aws:sts::123456789012:assumed-role/MyRole/[^/]+`.

    The result is a fixed-length lowercase-hex string: valid in SSM
    parameter names (which allow only letters, numbers, `.`, `-`, `_`, `/`),
    unlike a raw ARN which contains `:`.
    """
    if _IAM_USER_ARN_RE.match(arn):
        return hashlib.sha256(arn.encode()).hexdigest()[:32]

    if _ASSUMED_ROLE_ARN_RE.match(arn):
        for pattern in trusted_assumed_role_patterns or []:
            if re.fullmatch(pattern, arn):
                return hashlib.sha256(arn.encode()).hexdigest()[:32]
        raise AwsIdentityError(
            "AWS identity is not eligible for warren.secrets ownership: "
            f"{arn!r} is an assumed role not covered by any configured "
            "aws_trusted_assumed_role_patterns entry. An assumed role's "
            "session-name segment is chosen by whoever calls "
            "sts:AssumeRole, not by AWS, so an untrusted role allows two "
            "different people to collide; the operator must explicitly "
            "allow-list this role's ARN pattern after verifying, in their "
            "own account, that its RoleSessionName is bound to the real "
            "caller."
        )

    raise AwsIdentityError(
        f"AWS identity is not eligible for warren.secrets ownership: {arn!r} "
        "is neither an IAM user ARN nor an assumed-role ARN."
    )


def _validate_sts_url(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme != "https":
        raise AwsIdentityError("signed request URL must use https")
    if not parsed.hostname or not _STS_HOST_RE.match(parsed.hostname):
        raise AwsIdentityError(f"signed request URL host is not an AWS STS endpoint: {parsed.hostname!r}")


_SIGNED_HEADERS_RE = re.compile(r"SignedHeaders=([^,]+)")


def _validate_signature_scope(authorization: str) -> None:
    """Confirm the Authorization header is a SigV4 signature scoped to STS.

    Doesn't re-derive the signature (AWS STS does that when we replay the
    request) -- just rejects obviously-wrong input before making a network
    call, the same role `_validate_sts_url` plays for the URL.
    """
    if not authorization.startswith("AWS4-HMAC-SHA256"):
        raise AwsIdentityError("signed request is missing a SigV4 Authorization header")
    if "/sts/aws4_request" not in authorization:
        raise AwsIdentityError("signed request's Authorization header is not scoped to the sts service")


def _validate_audience_is_signed(authorization: str) -> None:
    """Confirm `_AUDIENCE_HEADER` is covered by the signature's own `SignedHeaders=`
    list, not just present in the (unsigned, caller-controlled) header map.

    STS only verifies the headers actually named in `SignedHeaders=` -- any
    header NOT in that list is ignored by STS entirely, so a caller could
    sign a `GetCallerIdentity` request that never mentions the audience
    header, then attach any `X-Warren-Audience` value they like afterward
    (the signature still validates, since that header was never part of
    what got signed). Without this check, the audience "binding" the module
    docstring describes is advisory only -- this closes that gap, the same
    way HashiCorp Vault's AWS auth method verifies its own server-ID header
    is in `SignedHeaders` before trusting it.
    """
    match = _SIGNED_HEADERS_RE.search(authorization)
    if not match:
        raise AwsIdentityError("signed request's Authorization header has no SignedHeaders list")
    signed = {h.strip().lower() for h in match.group(1).split(";")}
    if _AUDIENCE_HEADER not in signed:
        raise AwsIdentityError(
            f"signed request does not cover {_AUDIENCE_HEADER!r} in its SignedHeaders -- "
            "an audience header outside the signature proves nothing"
        )


def _validate_action_is_get_caller_identity(body: str) -> None:
    """Confirm the signed body's STS action is GetCallerIdentity, not some other
    action whose signed, successful response might not even carry an <Arn> --
    or one that does something other than what this module's whole trust
    model assumes it's replaying. Cheap to check before ever hitting the
    network; restores a guard the earlier presigned-URL version of this
    module had (it validated an `Action=GetCallerIdentity` query parameter)."""
    params = parse_qs(body)
    action = (params.get("Action") or [""])[0]
    if action != "GetCallerIdentity":
        raise AwsIdentityError(f"signed request body Action must be GetCallerIdentity, got {action!r}")


def _validate_freshness(amz_date: str) -> None:
    if not _AMZ_DATE_RE.match(amz_date):
        raise AwsIdentityError(f"signed request has a malformed X-Amz-Date: {amz_date!r}")
    signed_at = datetime.strptime(amz_date, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    age = (now - signed_at).total_seconds()
    # Small positive allowance for clock skew in the caller's favor.
    if age > _MAX_REQUEST_AGE_SECONDS or age < -30:
        raise AwsIdentityError(
            f"signed request is too old or has a clock-skewed X-Amz-Date (age={age:.0f}s, "
            f"max={_MAX_REQUEST_AGE_SECONDS}s)"
        )


async def verify_signed_caller_identity(
    signed_request_json: str,
    expected_audience: str,
    trusted_assumed_role_patterns: list[str] | None = None,
    on_verified_arn: Callable[[str], None] | None = None,
) -> str:
    """Replay a client-signed STS GetCallerIdentity request and return the owner_id
    derived from the caller's ARN (see `derive_owner_id`).

    `signed_request_json` is the JSON object `{"url", "headers", "body"}` the
    CLI produced by SigV4-signing a GetCallerIdentity POST (warren_cli.client).
    `expected_audience` is this server's own stable identity (`settings.
    server_id` -- see module docstring for why not `request.base_url`); it
    must match the signed `X-Warren-Audience` header exactly, and that
    header must itself be covered by the signature's `SignedHeaders=` list,
    or the request is rejected. `trusted_assumed_role_patterns` is
    `settings.aws_trusted_assumed_role_patterns`, forwarded to
    `derive_owner_id`. `on_verified_arn`, if given, is called with the caller's ARN
    once it has been verified and trusted (the per-user storage key derives from it).

    Raises AwsIdentityError on any validation failure, non-2xx STS response,
    an untrusted ARN shape, or a response we can't parse an Arn out of.
    """
    try:
        payload = json.loads(signed_request_json)
    except (TypeError, ValueError) as exc:
        raise AwsIdentityError(f"signed request header is not valid JSON: {exc}") from exc

    if not isinstance(payload, dict):
        raise AwsIdentityError("signed request header must be a JSON object")

    url = payload.get("url")
    headers = payload.get("headers")
    body = payload.get("body", "")
    if not isinstance(url, str) or not isinstance(headers, dict):
        raise AwsIdentityError("signed request header must have string 'url' and object 'headers'")

    _validate_sts_url(url)

    lower_headers = {str(k).lower(): v for k, v in headers.items()}

    authorization = lower_headers.get("authorization", "")
    _validate_signature_scope(authorization)
    _validate_audience_is_signed(authorization)

    amz_date = lower_headers.get("x-amz-date", "")
    _validate_freshness(amz_date)

    _validate_action_is_get_caller_identity(body)

    audience = lower_headers.get(_AUDIENCE_HEADER, "")
    if not audience or audience != expected_audience:
        raise AwsIdentityError(
            f"signed request audience {audience!r} does not match this server {expected_audience!r}"
        )

    async with httpx.AsyncClient(timeout=5.0) as client:
        try:
            resp = await client.post(url, headers=headers, content=body)
        except httpx.HTTPError as exc:
            raise AwsIdentityError(f"could not reach AWS STS: {exc}") from exc

    if resp.status_code != 200:
        raise AwsIdentityError(f"AWS STS rejected the signed request: HTTP {resp.status_code}")

    match = _ARN_RE.search(resp.text)
    if not match:
        raise AwsIdentityError("AWS STS response did not contain an Arn")

    owner_id = derive_owner_id(match.group(1), trusted_assumed_role_patterns)
    if on_verified_arn is not None:
        on_verified_arn(match.group(1))
    return owner_id
