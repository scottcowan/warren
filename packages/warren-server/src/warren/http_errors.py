"""Fixed client-facing error messages.

Raw exception text (paths, URLs, library internals) must not reach HTTP
error bodies. ``fixed_detail`` logs the exception server-side and returns a
constant message keyed by the error code.
"""

from __future__ import annotations

import structlog

log = structlog.get_logger(__name__)

_FIXED: dict[str, str] = {
    "invalid_public_key": "invalid public key",
    "invalid_webhook_url": "invalid webhook url",
    "invalid_events": "invalid events",
    "template_denied": "template not permitted",
    "invalid_template": "invalid template",
    "ref_not_found": "ref not found",
    "invalid_ref": "invalid ref",
    "git_failed": "git operation failed",
    "invalid_argv": "invalid argv",
    "provision_failed": "workspace provisioning failed",
    "image_unavailable": "workspace image unavailable",
    "runtime_unreachable": "runtime unreachable",
    "capacity_exhausted": "capacity exhausted; retry later",
    "secret_missing": "a required secret is missing",
    "containerfile_build_failed": "containerfile build failed",
    "git_clone_failed": "git clone failed",
    "git_pull_failed": "git pull failed",
    "workspace_starting": "workspace is still starting; retry",
    "workspace_storage_unavailable": "workspace storage unavailable; destroy and recreate the workspace",
    "aws_identity_invalid": "aws identity could not be verified",
}


def fixed_detail(code: str, exc: BaseException, default: str = "request failed") -> str:
    log.warning("http_error_detail_suppressed", code=code, error=str(exc), exc_type=type(exc).__name__)
    return _FIXED.get(code, default)
