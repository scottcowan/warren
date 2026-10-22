"""warren-sidecar configuration loaded from WARREN_* environment variables."""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class SidecarSettings(BaseSettings):
    """Sidecar settings sourced entirely from WARREN_* env vars."""

    model_config = SettingsConfigDict(
        env_prefix="WARREN_",
        frozen=True,
        extra="ignore",
    )

    workspace_id: str = ""
    socket_path: str = "/tmp/warren-sidecar.sock"
    worktree_paths: str = ""  # colon-delimited, WARREN_WORKTREE_PATHS
    harness_root: str = "/var/lib/warren/harness"  # AG5: state hooks report under <root>/.session
    # Audit 2026-10-16 P2 #47: shared-secret auth for every /files and /exec
    # request. Minted per-workspace at provision time and handed to the
    # sidecar the same way every other per-workspace value reaches it (a
    # WARREN_* env var — see WARREN_WORKSPACE_ID above). Empty by default
    # only so a sidecar started with no token configured fails CLOSED (see
    # auth.py) rather than silently accepting every request.
    sidecar_token: str = ""
