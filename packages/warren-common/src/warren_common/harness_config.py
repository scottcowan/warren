"""Per-workspace harness config dirs on the host (AG3).

Each selected harness gets `<root>/<name>/`, which its `config_env` vars point
at instead of the operator's real config dir. Warren seeds it from the
operator's non-secret config files that the profile lists, writes generated
config, and copies credentials in per launch (never back out). On macOS the
Claude OAuth token comes from the login Keychain, which the sandbox cannot
read, so warren reads it host-side and hands over a copy without the refresh
token.

The dir is writable from inside the sandbox, so every host-side write opens
each path component with O_NOFOLLOW relative to the previous one and replaces
files rather than writing through whatever the workspace left there.
"""
from __future__ import annotations

import hashlib
import json
import os
import stat
import subprocess
import sys
import unicodedata
from collections.abc import Iterable, Mapping
from pathlib import Path

import structlog

from warren_common.fileperms import restrict_to_owner
from warren_common import agent_state
from warren_common.harness import SESSION_DIR, HarnessProfile, harness_dir, profiles_for

log = structlog.get_logger(__name__)

# Windows has no dir_fd/O_NOFOLLOW; it also has no local sandbox writing these dirs.
_FD_RELATIVE = os.open in os.supports_dir_fd and hasattr(os, "O_NOFOLLOW")
_DIR_FLAGS = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)


def _open_dir(parent_fd: int, name: str) -> int:
    """Open (creating if needed) a real directory `name` under `parent_fd`.
    A symlink or file left in its place is removed first."""
    try:
        st = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if not stat.S_ISDIR(st.st_mode):
            os.unlink(name, dir_fd=parent_fd)
            raise FileNotFoundError
    except FileNotFoundError:
        os.mkdir(name, 0o700, dir_fd=parent_fd)
    return os.open(name, _DIR_FLAGS, dir_fd=parent_fd)


def _walk(base_fd: int, rel_dir: str) -> int:
    fd = os.dup(base_fd)
    for part in [p for p in rel_dir.split("/") if p and p != "."]:
        if part == "..":
            raise ValueError("harness paths must not contain '..'")
        nxt = _open_dir(fd, part)
        os.close(fd)
        fd = nxt
    return fd


class _HarnessDir:
    """One harness's dir under `root`, owner-only (restrict_to_owner)."""

    def __init__(self, root: Path, name: str) -> None:
        root.mkdir(parents=True, exist_ok=True)
        restrict_to_owner(root, directory=True)
        self.path = root / name
        self.fd: int | None = None
        if _FD_RELATIVE:
            root_fd = os.open(root, _DIR_FLAGS)
            try:
                self.fd = _open_dir(root_fd, name)
            finally:
                os.close(root_fd)
        else:
            if self.path.is_symlink() or (self.path.exists() and not self.path.is_dir()):
                self.path.unlink()
            self.path.mkdir(exist_ok=True)
            restrict_to_owner(self.path, directory=True)

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)

    def mkdir(self, rel: str) -> None:
        if self.fd is not None:
            os.close(_walk(self.fd, rel))
        else:
            (self.path / rel).mkdir(parents=True, exist_ok=True)

    def exists(self, rel: str) -> bool:
        if self.fd is None:
            return os.path.lexists(self.path / rel)
        parent, _, name = rel.rstrip("/").rpartition("/")
        fd = _walk(self.fd, parent)
        try:
            os.stat(name, dir_fd=fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False
        finally:
            os.close(fd)

    def remove(self, rel: str) -> bool:
        if self.fd is None:
            target = self.path / rel
            if not os.path.lexists(target):
                return False
            os.chmod(target, stat.S_IWRITE)
            target.unlink()
            return True
        parent, _, name = rel.rpartition("/")
        fd = _walk(self.fd, parent)
        try:
            os.unlink(name, dir_fd=fd)
            return True
        except FileNotFoundError:
            return False
        finally:
            os.close(fd)

    def write(self, rel: str, data: bytes, *, readonly: bool) -> None:
        """Replace `rel` with a fresh owner-only regular file, never writing
        through anything the workspace left at that path."""
        if self.fd is None:
            target = self.path / rel
            target.parent.mkdir(parents=True, exist_ok=True)
            if os.path.lexists(target):
                os.chmod(target, stat.S_IWRITE)
                target.unlink()
            target.write_bytes(data)
            restrict_to_owner(target)
            if readonly:
                os.chmod(target, stat.S_IREAD)
            return
        parent, _, name = rel.rpartition("/")
        fd = _walk(self.fd, parent)
        try:
            try:
                st = os.stat(name, dir_fd=fd, follow_symlinks=False)
                if stat.S_ISDIR(st.st_mode):
                    raise IsADirectoryError(rel)
                os.unlink(name, dir_fd=fd)
            except FileNotFoundError:
                pass
            out = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
            try:
                os.write(out, data)
                # fchmod, not restrict_to_owner(path): a path chmod would follow a swapped-in symlink.
                os.fchmod(out, 0o400 if readonly else 0o600)
            finally:
                os.close(out)
        finally:
            os.close(fd)


def _read_operator_file(path: Path) -> bytes | None:
    try:
        if not path.is_file():
            return None
        return path.read_bytes()
    except OSError:
        return None


def _strip_json(data: bytes, keys: tuple[str, ...]) -> bytes | None:
    try:
        obj = json.loads(data)
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None
    return json.dumps({k: v for k, v in obj.items() if k not in keys}, indent=2).encode()


def _prepare_one(p: HarnessProfile, root: Path, home: Path) -> None:
    hdir = _HarnessDir(root, p.name)
    try:
        for rel in (*p.writable, *p.persist, *p.readonly):
            if rel.endswith("/"):
                hdir.mkdir(rel)
        readonly = {r.rstrip("/") for r in p.readonly}
        seeded: dict[str, bytes] = {}
        for src_rel, dst_rel in p.seed:
            data = _read_operator_file(home / src_rel)
            if data is None:
                continue
            if p.seed_json_strip and dst_rel.endswith(".json"):
                data = _strip_json(data, p.seed_json_strip)
                if data is None:
                    log.warning("harness_seed_skipped_unparseable", harness=p.name, file=dst_rel)
                    continue
            seeded[dst_rel] = data
            if dst_rel in readonly or not hdir.exists(dst_rel):
                hdir.write(dst_rel, data, readonly=dst_rel in readonly)
        for rel, text in p.generated.items():
            if rel in readonly or not hdir.exists(rel):
                hdir.write(rel, text.encode(), readonly=rel in readonly)
        if p.state_hook is not None:
            for rel, text in p.state_hook.files.items():
                hdir.write(rel, _hook_file(text, seeded.get(rel) if p.state_hook.merge_hooks else None), readonly=True)
    finally:
        hdir.close()


def _hook_file(text: str, seeded: bytes | None) -> bytes:
    """AG5: warren's hooks replace any the operator's seeded file had."""
    if seeded is None:
        return text.encode()
    try:
        base = json.loads(seeded)
    except ValueError:
        base = None
    if not isinstance(base, dict):
        return text.encode()
    base.pop("disableAllHooks", None)
    base["hooks"] = json.loads(text)["hooks"]
    return json.dumps(base, indent=2).encode()


def prepare_harness_dirs(names: Iterable[str], root: str | Path, *, home: str | Path) -> None:
    """Create and seed `<root>/<name>/` for each selected harness. Readonly
    seeds and generated config are rewritten every call; other seeds only
    when missing, so the harness's own state is kept."""
    prepared = False
    for p in profiles_for(names):
        if p.kind != "custom":
            _prepare_one(p, Path(root), Path(home))
            prepared = True
    if prepared:
        _HarnessDir(Path(root), SESSION_DIR).close()
    if any(p.state_hook is not None for p in profiles_for(names)):
        hooks = _HarnessDir(Path(root), agent_state.HOOKS_DIR)
        try:
            hooks.write(agent_state.HOOK_SCRIPT, agent_state.hook_script().encode(), readonly=True)
        finally:
            hooks.close()


SECURITY = "/usr/bin/security"


def keychain_service(p: HarnessProfile, service: str, env: Mapping[str, str]) -> str:
    """The Keychain service name the host's harness uses, given the host env."""
    for var in p.keychain_suffix_env:
        if var in env:
            value = unicodedata.normalize("NFC", env[var].strip())
            if not value:
                return service
            return f"{service}-{hashlib.sha256(value.encode()).hexdigest()[:8]}"
    return service


def _read_keychain(service: str, account: str) -> bytes | None:
    """The item's secret from the operator's login Keychain, or None. Host-side only."""
    if sys.platform != "darwin" or not os.path.isfile(SECURITY):
        return None
    try:
        r = subprocess.run(
            [SECURITY, "find-generic-password", "-a", account, "-w", "-s", service],
            capture_output=True,
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return None
    return (r.stdout.strip() or None) if r.returncode == 0 else None


def _strip_credential(data: bytes, keys: tuple[str, ...]) -> bytes | None:
    if not keys:
        return data
    try:
        obj = json.loads(data)
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None
    out = {}
    for k, v in obj.items():
        if k in keys:
            continue
        out[k] = {ik: iv for ik, iv in v.items() if ik not in keys} if isinstance(v, dict) else v
    return json.dumps(out).encode()


def _operator_credential(p: HarnessProfile, dst_rel: str, home: Path, env: Mapping[str, str]) -> bytes | None:
    account = env.get("USER") or ""
    for service, dst in p.keychain_credentials:
        if dst == dst_rel and account:
            data = _read_keychain(keychain_service(p, service, env), account)
            if data is not None:
                return data
    for src_rel, dst in p.credentials:
        if dst == dst_rel:
            data = _read_operator_file(home / src_rel)
            if data is not None:
                return data
    return None


def remove_credentials(names: Iterable[str], root: str | Path) -> list[str]:
    """Delete credential copies left in the workspace dirs (bedrock mode)."""
    removed: list[str] = []
    for p in profiles_for(names):
        targets = list(dict.fromkeys(dst for _, dst in (*p.keychain_credentials, *p.credentials)))
        if not targets or not (Path(root) / p.name).is_dir():
            continue
        hdir = _HarnessDir(Path(root), p.name)
        try:
            for dst_rel in targets:
                if hdir.remove(dst_rel):
                    removed.append(f"{harness_dir(root, p.name)}/{dst_rel}")
        finally:
            hdir.close()
    return removed


def copy_in_credentials(
    names: Iterable[str], root: str | Path, *, home: str | Path, env: Mapping[str, str] | None = None
) -> list[str]:
    """Copy each profile's credentials from the operator's Keychain (macOS) or
    home into the workspace dir (0600), minus `credential_strip` keys.
    One-way: nothing is ever copied back."""
    env = os.environ if env is None else env
    copied: list[str] = []
    for p in profiles_for(names):
        targets = list(dict.fromkeys(dst for _, dst in (*p.keychain_credentials, *p.credentials)))
        if not targets:
            continue
        hdir = _HarnessDir(Path(root), p.name)
        try:
            for dst_rel in targets:
                data = _operator_credential(p, dst_rel, Path(home), env)
                if data is not None:
                    data = _strip_credential(data, p.credential_strip)
                if data is None:
                    continue
                hdir.write(dst_rel, data, readonly=False)
                copied.append(f"{harness_dir(root, p.name)}/{dst_rel}")
        finally:
            hdir.close()
    return copied
