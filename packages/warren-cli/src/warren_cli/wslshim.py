"""Console entry point, with an opt-in Windows -> WSL forwarder (AC2.5).

On native Windows, with ``[windows] forward_to_wsl = true`` in
``~/.warren/config.toml`` (or ``WARREN_WSL_FORWARD=1``), ``warren ...`` runs
``wsl.exe ... warren ...`` instead, when this host has no native local runtime
and warren is installed inside WSL. ``WARREN_WSL_FORWARD=0`` turns it off for
one command. Everything else goes straight to the Typer app.

Kept import-cheap: nothing heavy is imported unless forwarding is opted in.
"""

from __future__ import annotations

import os
import subprocess
import sys
import tomllib
from pathlib import Path

ENV_FLAG = "WARREN_WSL_FORWARD"
_WSL_EXE = "wsl.exe"
# Login shell so ~/.local/bin (uv tool / pipx installs) is on PATH.
_FORWARD_SCRIPT = 'exec warren "$@"'


def _windows_section(config_path: Path) -> dict:
    try:
        with open(config_path, "rb") as f:
            section = tomllib.load(f).get("windows", {})
    except (OSError, tomllib.TOMLDecodeError):
        return {}
    return section if isinstance(section, dict) else {}


def opted_in(environ: dict[str, str], config_path: Path) -> tuple[bool, str]:
    """(forward?, distro). The env flag wins over the config file."""
    section = _windows_section(config_path)
    distro = str(section.get("wsl_distro", "") or "")
    flag = environ.get(ENV_FLAG)
    if flag is not None:
        return flag.strip().lower() in ("1", "true", "yes", "on"), distro
    return section.get("forward_to_wsl") is True, distro


def _wsl_prefix(distro: str) -> list[str]:
    return [_WSL_EXE, *(["-d", distro] if distro else []), "-e", "sh", "-lc"]


def warren_in_wsl(distro: str) -> bool:
    try:
        proc = subprocess.run(
            [*_wsl_prefix(distro), "command -v warren >/dev/null"],
            capture_output=True, timeout=30, check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return proc.returncode == 0


def forward_argv(argv: list[str], distro: str) -> list[str]:
    return [*_wsl_prefix(distro), _FORWARD_SCRIPT, "warren", *argv]


def _no_native_local_runtime() -> bool:
    from warren_common.runtime_detect import detect  # noqa: PLC0415

    return detect().recommended == "none"


def maybe_forward(
    argv: list[str],
    *,
    environ: dict[str, str] | None = None,
    config_path: Path | None = None,
) -> int | None:
    """Exit code of the forwarded WSL run, or None to run warren natively."""
    from warren_common import winsupport  # noqa: PLC0415

    if not winsupport.is_windows():
        return None
    env = os.environ if environ is None else environ
    path = config_path or Path.home() / ".warren" / "config.toml"
    forward, distro = opted_in(dict(env), path)
    if not forward:
        return None
    if not _no_native_local_runtime():
        return None
    if not warren_in_wsl(distro):
        print(
            "warren: forward_to_wsl is on but warren isn't installed in WSL"
            + (f" ({distro})" if distro else "")
            + "; running natively",
            file=sys.stderr,
        )
        return None
    from warren_cli.dispatch import _run_foreground  # noqa: PLC0415

    return _run_foreground(forward_argv(argv, distro))


def main() -> None:
    code = maybe_forward(sys.argv[1:])
    if code is not None:
        sys.exit(code)
    from warren_cli.main import app  # noqa: PLC0415

    app()
