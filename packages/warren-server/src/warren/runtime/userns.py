"""WARREN_PODMAN_USERNS: the user namespace rootless podman workspaces run in.

The default, `keep-id:uid=1000,gid=1000`, maps the server's host user to container
uid/gid 1000 (`warren` in warren's images; warren-docker-base runs its workload as that
user over such mounts). Bind mounts the server writes (the git
checkout, the harness dir) are then owned by uid 1000 inside the container, and what
uid 1000 writes there is owned by the server user on the host. Every other container
uid, root included, maps to the server user's subuid range, as with podman's default
mapping: keep-id grants no host privilege.

Kept free of podman-py imports so config.py can validate the setting.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import structlog

log = structlog.get_logger(__name__)

DEFAULT_PODMAN_USERNS = "keep-id:uid=1000,gid=1000"
# `warren` in warren's images: the workload user warren-docker-base drops to.
WORKLOAD_UID = 1000

# Values that mean "don't pass a userns": podman's own default for a rootless
# container, where the host user is container root.
_OFF = ("", "host")
_MODES = ("keep-id", "auto", "nomap")
_OPTIONS = re.compile(r"^[a-z]+=[0-9a-z:/-]+(,[a-z]+=[0-9a-z:/-]+)*$")
# `keep-id:uid=` / `gid=` / `size=` need podman >= 4.3 (podman 4.3.0 release notes).
KEEP_ID_OPTIONS_MIN_PODMAN = (4, 3)


def parse_podman_userns(value: str) -> dict[str, str] | None:
    """Turn a `--userns`-style string into the libpod create API's namespace object.

    The REST API doesn't split `mode:options` the way the CLI does, so
    `keep-id:uid=1000,gid=1000` becomes `{"nsmode": "keep-id", "value": "uid=1000,gid=1000"}`.
    Returns None for "" / "host" (leave podman's default in place). Raises ValueError
    for anything else.
    """
    text = (value or "").strip()
    if text in _OFF:
        return None
    mode, sep, options = text.partition(":")
    if mode not in _MODES:
        raise ValueError(
            f"unsupported podman userns {value!r}: use one of {', '.join(_MODES)} "
            "(optionally with :options), or host / \"\" to turn it off"
        )
    if not sep:
        return {"nsmode": mode}
    if not _OPTIONS.match(options):
        raise ValueError(f"malformed podman userns options in {value!r}")
    return {"nsmode": mode, "value": options}


def needs_keep_id_options(value: str) -> bool:
    """Whether `value` uses keep-id's uid/gid options (podman >= 4.3)."""
    ns = parse_podman_userns(value)
    return ns is not None and ns["nsmode"] == "keep-id" and "value" in ns


def keep_id_uid(userns: dict[str, str] | None) -> int | None:
    """The container uid a parsed keep-id namespace maps the server user to, else None."""
    if not userns or userns.get("nsmode") != "keep-id":
        return None
    for part in userns.get("value", "").split(","):
        key, _, val = part.partition("=")
        if key == "uid" and val.isdigit():
            return int(val)
    return None


_UNSHARE_TIMEOUT_S = 120


def remove_tree(path: Path, *, podman_binary: str = "podman") -> bool:
    """Remove a workspace's host-side directory, even what container root wrote there.

    A warren-docker-base workload runs as uid 1000 and leaves nothing a plain rmtree can't
    remove; this covers `host`-era checkouts and older images. Under keep-id, files a
    workspace writes as container root (or any uid other than
    the mapped 1000) are owned by one of the server user's subuids on the host, and a
    directory created that way can't be emptied by the server user. `podman unshare`
    runs `rm` as root of the server user's own user namespace, where those subuids are
    mapped, so it can. Only reached when a plain rmtree leaves something behind.
    Returns whether the path is gone; never raises.
    """
    shutil.rmtree(path, ignore_errors=True)
    if not os.path.lexists(path):
        return True
    podman = shutil.which(podman_binary)
    if podman is None:
        log.warning("remove_tree_incomplete", path=str(path), detail="no podman binary for podman unshare")
        return False
    try:
        subprocess.run(
            [podman, "unshare", "rm", "-rf", "--", str(path)],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=_UNSHARE_TIMEOUT_S,
            check=True,
        )
    except (OSError, subprocess.SubprocessError) as e:
        log.warning("remove_tree_incomplete", path=str(path), detail=str(e))
        return False
    return not os.path.lexists(path)
