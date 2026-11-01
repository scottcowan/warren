"""Detect the rootless podman + pasta + AppArmor combination that can't remove containers.

On Ubuntu 26.04 podman runs under an AppArmor profile named `podman`, and the shipped
`pasta` profile refuses SIGTERM from it (`apparmor="DENIED" operation="signal"
profile="pasta" signal=term peer="podman"`). Rootless podman then can't stop pasta when
removing a container: `rootless netns: kill network process: permission denied`. The
fix is `default_rootless_network_cmd = "slirp4netns"` in containers.conf.

Detection uses only what `podman info` reports, because the server may talk to a podman
socket on another host (forwarded over SSH) or run in a container itself:

* `host.rootlessNetworkCmd` (podman 5.x; podman 4.x doesn't report it and defaults to
  slirp4netns),
* `host.security.apparmorEnabled` and `host.security.rootless`,
* `version.Version` (podman 5.0 made pasta the rootless default; 4.9 is unaffected).

`podman info` doesn't expose AppArmor profile contents. When the caller knows it shares
the host with podman it can pass the pasta profile text; a profile that lets pasta
receive signals from `podman` clears the warning.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

README_URL = (
    "https://github.com/scottcowan/warren/blob/main/packages/warren-server/README.md"
    "#ubuntu-2604-rootless-podman-and-pasta"
)
FIX = 'default_rootless_network_cmd = "slirp4netns" under [network] in ~/.config/containers/containers.conf'

# Where distro and upstream passt packages install the pasta profile and its local overrides.
PASTA_PROFILE_PATHS = (
    "/etc/apparmor.d/pasta",
    "/etc/apparmor.d/usr.bin.pasta",
    "/etc/apparmor.d/abstractions/pasta",
    "/etc/apparmor.d/local/pasta",
    "/etc/apparmor.d/local/usr.bin.pasta",
)

# `signal,` (everything), or a signal rule naming peer=podman that isn't send-only.
_SIGNAL_ALLOW_ALL = re.compile(r"^\s*(allow\s+)?signal\s*,", re.MULTILINE)
_SIGNAL_RULE = re.compile(r"^\s*(allow\s+)?signal\b([^,]*),", re.MULTILINE)


def _get(d: Any, *keys: str) -> Any:
    if not isinstance(d, dict):
        return None
    for k in keys:
        if k in d:
            return d[k]
    return None


def _major(version: Any) -> int | None:
    m = re.match(r"\s*v?(\d+)\.", str(version or ""))
    return int(m.group(1)) if m else None


def profile_allows_podman_signal(profile: str) -> bool:
    if _SIGNAL_ALLOW_ALL.search(profile):
        return True
    for m in _SIGNAL_RULE.finditer(profile):
        body = m.group(2)
        if "peer=podman" in body.replace('"', "") and not re.search(r"\(\s*send\s*\)", body):
            return True
    return False


def read_local_pasta_profile(paths: tuple[str, ...] = PASTA_PROFILE_PATHS) -> str | None:
    """Concatenated text of the pasta profile files on this host, or None if none is readable."""
    texts = []
    for p in paths:
        try:
            texts.append(Path(p).read_text(errors="replace"))
        except OSError:
            continue
    return "\n".join(texts) if texts else None


def pasta_apparmor_warning(info: dict[str, Any], pasta_profile: str | None = None) -> dict[str, Any] | None:
    """Return warning fields if `info` looks like the broken combination, else None.

    Missing or unrecognised fields mean no warning: this is advice, not a gate.
    """
    host = _get(info, "host", "Host") or {}
    security = _get(host, "security", "Security") or {}
    if _get(security, "apparmorEnabled", "AppArmorEnabled", "apparmor_enabled") is not True:
        return None
    if _get(security, "rootless", "Rootless") is False:
        return None
    version = _get(_get(info, "version", "Version") or {}, "Version", "version")
    major = _major(version)
    if major is None or major < 5:
        return None
    net_cmd = _get(host, "rootlessNetworkCmd", "RootlessNetworkCmd")
    if not isinstance(net_cmd, str) or net_cmd.strip().lower() != "pasta":
        return None
    if pasta_profile is not None and profile_allows_podman_signal(pasta_profile):
        return None
    dist = _get(host, "distribution", "Distribution") or {}
    distro = " ".join(
        str(v) for v in (_get(dist, "distribution", "Distribution"), _get(dist, "version", "Version")) if v
    )
    return {
        "podman_version": str(version),
        "rootless_network_cmd": net_cmd,
        "distribution": distro or None,
        "profile_checked": pasta_profile is not None,
        "detail": (
            "rootless podman uses pasta with AppArmor enabled; if the pasta profile refuses "
            "SIGTERM from the podman profile (Ubuntu 26.04), removing containers fails with "
            "'rootless netns: kill network process: permission denied'"
        ),
        "fix": FIX,
        "docs": README_URL,
    }
