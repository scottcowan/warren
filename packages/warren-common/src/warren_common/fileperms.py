"""Owner-only permissions for tokens, secrets and state files.

POSIX: chmod 0600 (files) / 0700 (directories). Windows, where chmod only
toggles the read-only bit: replace the DACL with one protected ACE granting
the current user full control, via pywin32 when importable (docker-py pulls
it in on Windows), else ``icacls``.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from . import winsupport


def restrict_to_owner(path: Path | str, *, directory: bool | None = None) -> None:
    p = os.fspath(path)
    is_dir = os.path.isdir(p) if directory is None else directory
    if not winsupport.is_windows():
        os.chmod(p, 0o700 if is_dir else 0o600)
        return
    try:
        import win32security  # noqa: F401, PLC0415
    except ImportError:
        _icacls_owner_only(p, is_dir)
    else:
        _pywin32_owner_only(p, is_dir)


def _pywin32_owner_only(path: str, is_dir: bool) -> None:
    import ntsecuritycon as con  # noqa: PLC0415
    import win32api  # noqa: PLC0415
    import win32security  # noqa: PLC0415

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(), win32security.TOKEN_QUERY)
    sid = win32security.GetTokenInformation(token, win32security.TokenUser)[0]
    dacl = win32security.ACL()
    inherit = (con.OBJECT_INHERIT_ACE | con.CONTAINER_INHERIT_ACE) if is_dir else 0
    dacl.AddAccessAllowedAceEx(win32security.ACL_REVISION, inherit, con.FILE_ALL_ACCESS, sid)
    win32security.SetNamedSecurityInfo(
        path,
        win32security.SE_FILE_OBJECT,
        win32security.DACL_SECURITY_INFORMATION | win32security.PROTECTED_DACL_SECURITY_INFORMATION,
        None,
        None,
        dacl,
        None,
    )


def _current_user_sid() -> str:
    out = subprocess.run(
        ["whoami", "/user", "/fo", "csv", "/nh"], capture_output=True, text=True, check=True
    ).stdout.strip()
    sid = out.rsplit(",", 1)[-1].strip().strip('"')
    if not sid.startswith("S-1-"):
        raise OSError(f"could not determine current user SID from whoami: {out!r}")
    return sid


def _icacls_owner_only(path: str, is_dir: bool) -> None:
    grant = f"*{_current_user_sid()}:{'(OI)(CI)F' if is_dir else 'F'}"
    subprocess.run(["icacls", path, "/reset"], capture_output=True, check=True)
    subprocess.run(
        ["icacls", path, "/inheritance:r", "/grant:r", grant], capture_output=True, check=True
    )
