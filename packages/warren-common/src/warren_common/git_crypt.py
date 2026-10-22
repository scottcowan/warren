"""Per-template git-crypt policy (AK2): `git_crypt: none | unlock_and_drop`.

- `none` (default): the key never enters the workspace. Encrypted files stay
  ciphertext, and any key left in a checkout's git dir is removed.
- `unlock_and_drop`: during materialization, outside the sandboxed process,
  `git-crypt unlock` with the key, then delete the key and git-crypt's
  filter/diff config before the app starts. The workspace sees the current
  checkout decrypted but can't decrypt history or other branches, or exfiltrate
  the key. Without the key git-crypt's clean/smudge filters can't run, so the
  decrypted paths are marked skip-worktree: git ignores local edits to them
  and they can't be committed (`git update-index --no-skip-worktree` to undo,
  which then fails loudly on commit).

The key is read by the materializer only (local secrets for local runtimes)
and must never be listed in the template's `secrets`, which would deliver it
into the workspace env. Hook for ECS git-init (PR #29): call
`apply_git_crypt_policy` in the init container after clone, with the key
fetched there, before the workspace container starts.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

GitCryptPolicy = Literal["none", "unlock_and_drop"]

SKIP_WORKTREE_NOTE = (
    "git-crypt: {count} encrypted path(s) decrypted for this checkout and marked "
    "skip-worktree; edits to them are not tracked and can't be committed from this workspace"
)


class GitCryptError(Exception):
    pass


@dataclass
class GitCryptResult:
    policy: GitCryptPolicy
    uses_git_crypt: bool
    decrypted_paths: list[str] = field(default_factory=list)
    message: str | None = None


def _git(worktree: Path, *args: str, input: str | None = None) -> str:  # noqa: A002
    proc = subprocess.run(
        ["git", "-C", str(worktree), *args], capture_output=True, text=True, input=input
    )
    if proc.returncode != 0:
        raise GitCryptError(f"git {args[0]} failed: {proc.stderr.strip()}")
    return proc.stdout


def check_key_not_delivered(secret_names: list[str], key_secret: str) -> None:
    if key_secret in secret_names:
        raise GitCryptError(
            f"secret {key_secret!r} is the git-crypt key (git_crypt_key_secret); it must not "
            "be listed in the template's `secrets`, which would deliver it into the workspace"
        )


def encrypted_paths(worktree: Path) -> list[str]:
    tracked = _git(worktree, "ls-files", "-z")
    if not tracked:
        return []
    out = _git(worktree, "check-attr", "-z", "--stdin", "filter", input=tracked)
    fields = out.split("\0")
    paths = []
    for i in range(0, len(fields) - 2, 3):
        path, _attr, value = fields[i : i + 3]
        if value == "git-crypt":
            paths.append(path)
    return paths


def _git_crypt_dirs(worktree: Path) -> list[Path]:
    out = _git(worktree, "rev-parse", "--path-format=absolute", "--git-dir", "--git-common-dir")
    return [Path(line) / "git-crypt" for line in dict.fromkeys(out.split())]


def drop_keys(worktree: Path) -> None:
    for d in _git_crypt_dirs(worktree):
        if d.exists():
            shutil.rmtree(d)


def _drop_filter_config(worktree: Path) -> None:
    for key in (
        "filter.git-crypt.smudge",
        "filter.git-crypt.clean",
        "filter.git-crypt.required",
        "diff.git-crypt.textconv",
    ):
        subprocess.run(
            ["git", "-C", str(worktree), "config", "--unset-all", key], capture_output=True
        )


def apply_git_crypt_policy(
    worktree: Path,
    policy: GitCryptPolicy,
    key: bytes | None = None,
    *,
    git_crypt: str = "git-crypt",
) -> GitCryptResult:
    paths = encrypted_paths(worktree)
    if not paths:
        drop_keys(worktree)
        return GitCryptResult(policy=policy, uses_git_crypt=False)
    if policy == "none":
        drop_keys(worktree)
        _drop_filter_config(worktree)
        return GitCryptResult(policy=policy, uses_git_crypt=True)
    if policy != "unlock_and_drop":
        raise GitCryptError(f"unknown git_crypt policy {policy!r}")
    if not key:
        raise GitCryptError("git_crypt: unlock_and_drop needs the git-crypt key, but none was provided")

    staging = Path(tempfile.mkdtemp(prefix="warren-git-crypt-"))
    try:
        key_file = staging / "key"
        key_file.touch(mode=0o600)
        key_file.write_bytes(key)
        proc = subprocess.run(
            [git_crypt, "unlock", str(key_file)], cwd=worktree, capture_output=True, text=True
        )
        if proc.returncode != 0:
            raise GitCryptError(f"git-crypt unlock failed: {proc.stderr.strip()}")
    finally:
        shutil.rmtree(staging, ignore_errors=True)
        drop_keys(worktree)
        _drop_filter_config(worktree)

    _git(worktree, "update-index", "--skip-worktree", "--", *paths)
    return GitCryptResult(
        policy=policy,
        uses_git_crypt=True,
        decrypted_paths=paths,
        message=SKIP_WORKTREE_NOTE.format(count=len(paths)),
    )
