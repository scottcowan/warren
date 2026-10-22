"""Error taxonomy for warren-server.

`ProvisionError` and its subclasses (the WS-01 wire taxonomy) live in
`warren_common.errors` — they're shared with warren-cli's local runtimes.

`PreflightError` stays here: it's server-only, raised during startup
preflight checks (Podman socket / subuid / driver).
"""

from __future__ import annotations


class PreflightError(RuntimeError):
    """Raised at startup when Podman preflight (socket / subuid / driver) fails."""
