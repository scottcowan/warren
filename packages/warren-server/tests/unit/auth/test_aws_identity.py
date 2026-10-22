from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import httpx
import pytest

from warren.auth.aws_identity import (
    AwsIdentityError,
    derive_owner_id,
    verify_signed_caller_identity,
)

_AUDIENCE = "test-server"

# A realistic SignedHeaders list: botocore signs host/content-type/x-amz-date and any
# custom header present on the request at signing time, including x-warren-audience.
_DEFAULT_SIGNED_HEADERS = "content-type;host;x-amz-date;x-warren-audience"


def _amz_date(delta_seconds: float = 0) -> str:
    when = datetime.now(timezone.utc) + timedelta(seconds=delta_seconds)
    return when.strftime("%Y%m%dT%H%M%SZ")


def _authorization(signed_headers: str = _DEFAULT_SIGNED_HEADERS) -> str:
    return (
        f"AWS4-HMAC-SHA256 Credential=AKIA.../20260101/us-east-1/sts/aws4_request, "
        f"SignedHeaders={signed_headers}, Signature=abc"
    )


def _signed_request(
    *,
    url: str = "https://sts.amazonaws.com/",
    authorization: str | None = None,
    signed_headers: str = _DEFAULT_SIGNED_HEADERS,
    amz_date: str | None = None,
    audience: str | None = _AUDIENCE,
    body: str = "Action=GetCallerIdentity&Version=2011-06-15",
) -> str:
    headers = {
        "Authorization": authorization if authorization is not None else _authorization(signed_headers),
        "X-Amz-Date": amz_date if amz_date is not None else _amz_date(),
    }
    if audience is not None:
        headers["X-Warren-Audience"] = audience
    return json.dumps({"url": url, "headers": headers, "body": body})


_STS_RESPONSE_XML = """<?xml version="1.0"?>
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:iam::123456789012:user/alice</Arn>
    <UserId>AIDAEXAMPLE</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>
"""

_STS_RESPONSE_SHARED_ROLE_XML = """<?xml version="1.0"?>
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:sts::123456789012:assumed-role/SharedOperatorRole/bob</Arn>
    <UserId>AROAEXAMPLE:bob</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>
"""

_STS_RESPONSE_SSO_XML = """<?xml version="1.0"?>
<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <GetCallerIdentityResult>
    <Arn>arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_DevAccess_abc123/alice</Arn>
    <UserId>AROAEXAMPLE:alice</UserId>
    <Account>123456789012</Account>
  </GetCallerIdentityResult>
</GetCallerIdentityResponse>
"""


def _mock_post(status_code: int, text: str):
    async def _fake_post(self, url, *args, **kwargs):
        return httpx.Response(status_code, text=text, request=httpx.Request("POST", url))

    return _fake_post


# --- derive_owner_id -------------------------------------------------------


def test_derive_owner_id_is_stable_hex_for_iam_user():
    arn = "arn:aws:iam::123456789012:user/alice"
    owner_id = derive_owner_id(arn)
    assert owner_id == hashlib.sha256(arn.encode()).hexdigest()[:32]
    assert all(c in "0123456789abcdef" for c in owner_id)


def test_derive_owner_id_rejects_assumed_role_with_no_configured_trust():
    """No assumed role is trusted by default -- not even an
    AWSReservedSSO_-prefixed one, since that prefix isn't confirmed reserved
    against customer-created roles. An operator must explicitly allow-list
    the exact role(s) they trust."""
    arn = "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_DevAccess_abc123/alice"
    with pytest.raises(AwsIdentityError, match="not covered by any configured"):
        derive_owner_id(arn)


def test_derive_owner_id_accepts_assumed_role_matching_configured_pattern():
    arn = "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_DevAccess_abc123/alice"
    owner_id = derive_owner_id(arn, [r"^arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_.*$"])
    assert len(owner_id) == 32
    assert owner_id == hashlib.sha256(arn.encode()).hexdigest()[:32]


def test_derive_owner_id_rejects_assumed_role_not_matching_any_configured_pattern():
    arn = "arn:aws:sts::123456789012:assumed-role/SomeOtherRole/alice"
    with pytest.raises(AwsIdentityError, match="not covered by any configured"):
        derive_owner_id(arn, [r"^arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_.*$"])


def test_derive_owner_id_rejects_longer_arn_sharing_a_trusted_prefix():
    """Issue #13: a prefix-anchored (but not end-anchored) pattern must NOT
    trust a longer ARN that merely starts the same way -- re.match would
    wrongly accept this, reopening the collision the allow-list exists to
    prevent. The operator's intended, exact role name is one segment
    shorter than the ARN actually presented."""
    trusted_exact_role = "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Admin_abc"
    longer_arn = "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Admin_abcXYZ/anyone"
    with pytest.raises(AwsIdentityError, match="not covered by any configured"):
        derive_owner_id(longer_arn, [trusted_exact_role])


def test_derive_owner_id_wildcard_session_name_pattern_must_say_so_explicitly():
    """The documented escape hatch for issue #13: trusting any session name
    on a specific role requires an explicit wildcard segment, not an
    unanchored prefix."""
    pattern = r"arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Admin_abc/[^/]+"
    arn = "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_Admin_abc/alice"
    owner_id = derive_owner_id(arn, [pattern])
    assert len(owner_id) == 32


def test_derive_owner_id_rejects_plain_assumed_role():
    """The whole point of the fix: a shared, ordinary role's session-name
    segment is chosen by the caller of sts:AssumeRole, not by AWS, so it
    can't be trusted to uniquely identify a human -- even with an empty
    (default) trust list, let alone with none configured at all."""
    arn = "arn:aws:sts::123456789012:assumed-role/SharedOperatorRole/bob"
    with pytest.raises(AwsIdentityError, match="not covered by any configured"):
        derive_owner_id(arn)


def test_derive_owner_id_two_different_humans_never_collide():
    alice = derive_owner_id("arn:aws:iam::123456789012:user/alice")
    bob = derive_owner_id("arn:aws:iam::123456789012:user/bob")
    assert alice != bob


# --- verify_signed_caller_identity -----------------------------------------


async def test_verify_valid_signed_request_returns_derived_owner_id():
    with patch("httpx.AsyncClient.post", _mock_post(200, _STS_RESPONSE_XML)):
        owner_id = await verify_signed_caller_identity(_signed_request(), _AUDIENCE)
    assert owner_id == derive_owner_id("arn:aws:iam::123456789012:user/alice")


async def test_rejects_malformed_json():
    with pytest.raises(AwsIdentityError, match="JSON"):
        await verify_signed_caller_identity("not json", _AUDIENCE)


async def test_rejects_non_https_scheme():
    req = _signed_request(url="http://sts.amazonaws.com/")
    with pytest.raises(AwsIdentityError, match="https"):
        await verify_signed_caller_identity(req, _AUDIENCE)


@pytest.mark.parametrize(
    "host",
    [
        "evil.com",
        "sts.amazonaws.com.evil.com",
        "sts.amazonaws.com.attacker.net",
        "169.254.169.254",
    ],
)
async def test_rejects_non_sts_host(host):
    req = _signed_request(url=f"https://{host}/")
    with pytest.raises(AwsIdentityError, match="STS endpoint"):
        await verify_signed_caller_identity(req, _AUDIENCE)


async def test_rejects_missing_authorization():
    req = _signed_request(authorization="")
    with pytest.raises(AwsIdentityError, match="Authorization"):
        await verify_signed_caller_identity(req, _AUDIENCE)


async def test_rejects_authorization_not_scoped_to_sts():
    req = _signed_request(
        authorization="AWS4-HMAC-SHA256 Credential=AKIA.../20260101/us-east-1/s3/aws4_request, Signature=abc"
    )
    with pytest.raises(AwsIdentityError, match="sts service"):
        await verify_signed_caller_identity(req, _AUDIENCE)


async def test_rejects_stale_request():
    req = _signed_request(amz_date=_amz_date(-301))
    with pytest.raises(AwsIdentityError, match="too old"):
        await verify_signed_caller_identity(req, _AUDIENCE)


async def test_rejects_future_dated_request():
    req = _signed_request(amz_date=_amz_date(31))
    with pytest.raises(AwsIdentityError, match="too old"):
        await verify_signed_caller_identity(req, _AUDIENCE)


async def test_rejects_missing_audience():
    req = _signed_request(audience=None)
    with pytest.raises(AwsIdentityError, match="audience"):
        await verify_signed_caller_identity(req, _AUDIENCE)


async def test_rejects_mismatched_audience():
    """A request signed for one warren-server can't be replayed against another."""
    req = _signed_request(audience="https://a-different-server.example.com")
    with pytest.raises(AwsIdentityError, match="audience"):
        await verify_signed_caller_identity(req, _AUDIENCE)


async def test_rejects_non_200_sts_response():
    with patch("httpx.AsyncClient.post", _mock_post(403, "<Error/>")):
        with pytest.raises(AwsIdentityError, match="403"):
            await verify_signed_caller_identity(_signed_request(), _AUDIENCE)


async def test_rejects_response_with_no_arn():
    with patch("httpx.AsyncClient.post", _mock_post(200, "<NoArnHere/>")):
        with pytest.raises(AwsIdentityError, match="Arn"):
            await verify_signed_caller_identity(_signed_request(), _AUDIENCE)


async def test_rejects_unreachable_sts():
    async def _raise(self, url, *args, **kwargs):
        raise httpx.ConnectError("no route to host")

    with patch("httpx.AsyncClient.post", _raise):
        with pytest.raises(AwsIdentityError, match="could not reach"):
            await verify_signed_caller_identity(_signed_request(), _AUDIENCE)


async def test_rejects_shared_role_impersonation_even_with_valid_signature():
    """Problem 2 from the issue: two different people assuming the same
    shared role with a caller-chosen session name must not collide on a
    single owner_id, even though the signature itself is perfectly valid.
    No trusted_assumed_role_patterns configured -- not even an
    AWSReservedSSO_-style one is special-cased."""
    with patch("httpx.AsyncClient.post", _mock_post(200, _STS_RESPONSE_SHARED_ROLE_XML)):
        with pytest.raises(AwsIdentityError, match="not covered by any configured"):
            await verify_signed_caller_identity(_signed_request(), _AUDIENCE)


async def test_rejects_identity_center_role_with_no_configured_trust():
    """An AWSReservedSSO_ prefix alone is not trusted -- the prefix isn't
    confirmed reserved against customer-created roles, so the operator must
    explicitly configure aws_trusted_assumed_role_patterns."""
    with patch("httpx.AsyncClient.post", _mock_post(200, _STS_RESPONSE_SSO_XML)):
        with pytest.raises(AwsIdentityError, match="not covered by any configured"):
            await verify_signed_caller_identity(_signed_request(), _AUDIENCE)


async def test_accepts_identity_center_sso_role_with_configured_trust():
    patterns = [r"^arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_.*$"]
    with patch("httpx.AsyncClient.post", _mock_post(200, _STS_RESPONSE_SSO_XML)):
        owner_id = await verify_signed_caller_identity(_signed_request(), _AUDIENCE, patterns)
    assert owner_id == derive_owner_id(
        "arn:aws:sts::123456789012:assumed-role/AWSReservedSSO_DevAccess_abc123/alice", patterns
    )


async def test_rejects_audience_header_not_covered_by_signed_headers():
    """Issue follow-up #2: STS only verifies headers actually listed in
    SignedHeaders -- an audience header outside that list could be attached
    (with any value) to an otherwise-valid signed request after the fact,
    making the 'binding' advisory only. Must be rejected even though the
    header value itself matches the expected audience exactly."""
    req = _signed_request(signed_headers="content-type;host;x-amz-date")  # no x-warren-audience
    with pytest.raises(AwsIdentityError, match="SignedHeaders"):
        await verify_signed_caller_identity(req, _AUDIENCE)


async def test_rejects_missing_signed_headers_list():
    req = _signed_request(authorization="AWS4-HMAC-SHA256 Credential=AKIA.../20260101/us-east-1/sts/aws4_request, Signature=abc")
    with pytest.raises(AwsIdentityError, match="SignedHeaders"):
        await verify_signed_caller_identity(req, _AUDIENCE)


async def test_rejects_wrong_sts_action_in_body():
    """Issue follow-up #4: restores the Action=GetCallerIdentity guard the
    presigned-URL version of this module had."""
    req = _signed_request(body="Action=GetSessionToken&Version=2011-06-15")
    with pytest.raises(AwsIdentityError, match="GetCallerIdentity"):
        await verify_signed_caller_identity(req, _AUDIENCE)


async def test_audience_is_server_id_not_a_url():
    """Issue follow-up #3: the audience is a stable, operator-configured
    identity (settings.server_id), not request.base_url -- so it still
    means something behind an ecs/ssh tunnel's ephemeral local port, where
    the URL itself carries no identity at all."""
    req = _signed_request(audience="node2")
    with patch("httpx.AsyncClient.post", _mock_post(200, _STS_RESPONSE_XML)):
        owner_id = await verify_signed_caller_identity(req, "node2")
    assert owner_id == derive_owner_id("arn:aws:iam::123456789012:user/alice")
