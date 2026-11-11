"""HTTP error bodies carry fixed messages, never raw exception text."""

from __future__ import annotations


from warren.http_errors import fixed_detail

_SECRET = "/home/secret/path http://169.254.169.254/x"


def test_fixed_detail_never_echoes_exception_text() -> None:
    for code in ("invalid_template", "git_failed", "invalid_webhook_url", "unknown_code", "workspace_storage_unavailable"):
        assert _SECRET not in fixed_detail(code, ValueError(_SECRET))


def test_fixed_detail_default_and_known() -> None:
    assert fixed_detail("nope", ValueError("x")) == "request failed"
    assert fixed_detail("nope", ValueError("x"), "custom") == "custom"
    assert fixed_detail("git_failed", ValueError("x")) == "git operation failed"


def test_fixed_detail_logs_server_side() -> None:
    import structlog

    with structlog.testing.capture_logs() as logs:
        fixed_detail("git_failed", ValueError(_SECRET))
    assert any(e.get("error") == _SECRET for e in logs)
