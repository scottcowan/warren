"""AK1 regression: a seatbelt-sandboxed process can't read the GitHub App key.

Runs the real /usr/bin/sandbox-exec with the real generated profile against a
throwaway keychain file in tmp (never the login keychain or real items). The
keychain is left *unlocked* during the probe -- the worst case, while the
issuer is mid-mint.
"""

from __future__ import annotations

import base64
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from warren_cli import credential_store
from warren_cli.credential_store import CredentialStoreError, InMemoryCredentialStore, MacKeychainStore

_SERVICE = "warren-github-app-sandbox-probe"
_ACCOUNT = "probe"
_SECRET = b"-----BEGIN PRIVATE KEY-----\nprobe-not-a-real-key\n-----END PRIVATE KEY-----\n"

requires_seatbelt = pytest.mark.skipif(
    sys.platform != "darwin" or not Path("/usr/bin/sandbox-exec").exists() or not shutil.which("security"),
    reason="macOS sandbox-exec + security required",
)


@pytest.fixture
def probe_keychain(tmp_path):
    home = tmp_path / "home"
    store = MacKeychainStore(
        keychain=home / ".warren" / "github-app" / "warren.keychain-db",
        password_store=InMemoryCredentialStore(),
    )
    before = store._search_list()
    store.set(_SERVICE, _ACCOUNT, _SECRET)
    try:
        yield home, store
    finally:
        store.delete()
        assert store._search_list() == before


def _profile(tmp_path: Path, home: Path, monkeypatch, *, extra_allow: str = "", strip_denies: bool = False) -> Path:
    """The real generated profile. `extra_allow` is inserted before the deny
    sections (a broad grant the denies must still beat); `strip_denies` drops
    the AK1 credential-store denies for the control run."""
    from warren_common.runtime import sbpl
    from warren_common.runtime.base import WorkspaceSpec

    monkeypatch.setenv("HOME", str(home))
    root = home / ".warren" / "workspaces" / "ws-probe"
    root.mkdir(parents=True, exist_ok=True)
    spec = WorkspaceSpec(workspace_id="ws-probe", project="p", intent="i", image="", root_path=str(root))
    built = sbpl.build_sbpl_profile(spec)
    # Inline the -D parameters so lines can be matched and filtered by path.
    text = re.sub(r'\(param "([A-Z0-9_]+)"\)', lambda m: f'"{built.params[m.group(1)]}"', built.text)
    lines = text.splitlines()
    first_deny = next(
        i for i, line in enumerate(lines) if line.startswith("(deny ") and line != "(deny default)"
    )
    text = "\n".join([*lines[:first_deny], extra_allow, *lines[first_deny:]])
    if strip_denies:
        text = "\n".join(line for line in text.splitlines() if "github-app" not in line and "Keychains" not in line)
    profile = tmp_path / f"sandbox-{int(strip_denies)}.sb"
    profile.write_text(text)
    return profile


def _sandboxed(profile: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["/usr/bin/sandbox-exec", "-f", str(profile), "/usr/bin/security", *args],
        capture_output=True,
        text=True,
        stdin=subprocess.DEVNULL,
        timeout=30,
    )


@requires_seatbelt
def test_sandboxed_process_cannot_read_key_even_while_unlocked(probe_keychain, tmp_path, monkeypatch):
    home, store = probe_keychain
    assert store.get(_SERVICE, _ACCOUNT) == _SECRET
    encoded = base64.b64encode(_SECRET).decode()
    broad = f'(allow file-read* file-write* (subpath "{home}"))'
    hardened = _profile(tmp_path, home, monkeypatch, extra_allow=broad)
    control = _profile(tmp_path, home, monkeypatch, extra_allow=broad, strip_denies=True)
    read_by_path = ("find-generic-password", "-s", _SERVICE, "-a", _ACCOUNT, "-w", str(store.keychain))

    password = store._passwords.get(f"{_SERVICE}.keychain-password", str(store.keychain)).decode()
    with store.unlocked(password):
        control_read = _sandboxed(control, *read_by_path)
        by_path = _sandboxed(hardened, *read_by_path)
        by_search = _sandboxed(hardened, "find-generic-password", "-s", _SERVICE, "-w")

    # The probe is real: without the AK1 denies the sandboxed `security` reads it.
    assert control_read.returncode == 0 and control_read.stdout.strip() == encoded
    for result in (by_path, by_search):
        assert result.returncode != 0
        assert encoded not in result.stdout


@requires_seatbelt
def test_key_keychain_stays_off_the_users_search_list(probe_keychain):
    _, store = probe_keychain
    assert str(store.keychain) not in store._search_list()


@pytest.mark.skipif(sys.platform == "win32", reason="fake /bin/sh `security` binary; macOS keychain store")
def test_mac_store_keeps_key_and_keychain_password_off_argv(tmp_path):
    record = tmp_path / "record"
    fake = tmp_path / "security"
    encoded = base64.b64encode(_SECRET).decode()
    fake.write_text(
        f'#!/bin/sh\necho "ARGV:$*" >> "{record}"\ncat >> "{record}"\n'
        f'case "$*" in *find-generic-password*) printf "%s" "{encoded}" ;; esac\n'
    )
    fake.chmod(0o755)
    passwords = InMemoryCredentialStore()
    keychain = tmp_path / "kc" / "warren.keychain-db"
    store = MacKeychainStore(binary=str(fake), keychain=keychain, password_store=passwords)
    store.set(_SERVICE, _ACCOUNT, _SECRET)
    keychain.touch()
    assert store.get(_SERVICE, _ACCOUNT) == _SECRET

    (password,) = passwords.items.values()
    argv = [line for line in record.read_text().splitlines() if line.startswith("ARGV:")]
    assert all(encoded not in line and password.decode() not in line for line in argv)
    assert any(line.startswith("ARGV:lock-keychain") for line in argv)


def test_libsecret_refused_when_session_bus_is_abstract(monkeypatch):
    monkeypatch.setattr(credential_store.sys, "platform", "linux")
    monkeypatch.setenv("DBUS_SESSION_BUS_ADDRESS", "unix:abstract=/tmp/dbus-XYZ,guid=1")
    with pytest.raises(CredentialStoreError, match="abstract"):
        credential_store.default_credential_store()
