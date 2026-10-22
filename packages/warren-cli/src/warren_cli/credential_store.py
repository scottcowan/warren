"""OS credential store for the local GitHub App issuer's private key (AK1).

The key is never a plain file. It's kept in the platform store: on macOS a
dedicated keychain file in the seatbelt-denied ~/.warren/github-app/ (see
MacKeychainStore), libsecret (`secret-tool`) on Linux, or Windows Credential
Manager. Values are stored base64-encoded (PEM is multi-line) and are never
passed on a command line.
"""

from __future__ import annotations

import base64
import os
import secrets
import shutil
import subprocess
import sys
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Protocol

DEFAULT_SERVICE = "warren-github-app"


class CredentialStoreError(Exception):
    pass


class CredentialStore(Protocol):
    def get(self, service: str, account: str) -> bytes | None: ...

    def set(self, service: str, account: str, secret: bytes) -> None: ...


def _encode(secret: bytes) -> str:
    return base64.b64encode(secret).decode()


def _decode(stored: str) -> bytes:
    return base64.b64decode(stored.strip())


class LoginKeychainStore:
    """Generic-password items in the user's default (login) keychain."""

    def __init__(self, binary: str = "security") -> None:
        self.binary = binary

    def get(self, service: str, account: str) -> bytes | None:
        proc = subprocess.run(
            [self.binary, "find-generic-password", "-s", service, "-a", account, "-w"],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            return None
        return _decode(proc.stdout)

    def set(self, service: str, account: str, secret: bytes) -> None:
        # `security -i` reads the command from stdin so the value stays off argv.
        command = f'add-generic-password -U -s "{service}" -a "{account}" -w "{_encode(secret)}"\n'
        proc = subprocess.run([self.binary, "-i"], input=command, capture_output=True, text=True)
        if proc.returncode != 0:
            raise CredentialStoreError("security add-generic-password failed")


DEFAULT_MAC_KEYCHAIN = Path.home() / ".warren" / "github-app" / "warren.keychain-db"


class MacKeychainStore:
    """The GitHub App key lives in a dedicated keychain file under
    ~/.warren/github-app/, a directory every seatbelt profile denies, so a
    sandboxed process can't open it even while it is unlocked (verified with
    sandbox-exec in tests/test_credential_store_sandbox.py). The keychain is
    unlocked only around a single get/set by the issuer and locked again
    straight after (and auto-locks after 5 minutes). Its random password is kept
    in the login keychain; reading that alone gives nothing without the file.
    Creating the keychain doesn't change the user's keychain search list."""

    def __init__(
        self,
        binary: str = "security",
        keychain: Path | None = None,
        password_store: CredentialStore | None = None,
    ) -> None:
        self.binary = binary
        self.keychain = keychain or DEFAULT_MAC_KEYCHAIN
        self._passwords = password_store or LoginKeychainStore(binary)

    def _security(self, *args: str, stdin: str | None = None) -> subprocess.CompletedProcess:
        return subprocess.run(
            [self.binary, *(["-i"] if stdin is not None else []), *args],
            input=stdin,
            capture_output=True,
            text=True,
        )

    def _search_list(self) -> list[str]:
        out = self._security("list-keychains", "-d", "user").stdout
        return [line.strip().strip('"') for line in out.splitlines() if line.strip()]

    def _password(self, service: str, *, create: bool) -> str | None:
        account = str(self.keychain)
        stored = self._passwords.get(f"{service}.keychain-password", account)
        if stored is not None:
            return stored.decode()
        if not create:
            return None
        password = secrets.token_hex(32)
        self._passwords.set(f"{service}.keychain-password", account, password.encode())
        return password

    def _ensure_keychain(self, password: str) -> None:
        if self.keychain.exists():
            return
        self.keychain.parent.mkdir(parents=True, exist_ok=True)
        os.chmod(self.keychain.parent, 0o700)
        before = self._search_list()
        try:
            proc = self._security(stdin=f'create-keychain -p "{password}" "{self.keychain}"\n')
            if proc.returncode != 0:
                raise CredentialStoreError("security create-keychain failed")
            self._security("set-keychain-settings", "-l", "-u", "-t", "300", str(self.keychain))
        finally:
            if before:
                self._security("list-keychains", "-d", "user", "-s", *before)

    @contextmanager
    def unlocked(self, password: str) -> Iterator[None]:
        proc = self._security(stdin=f'unlock-keychain -p "{password}" "{self.keychain}"\n')
        if proc.returncode != 0:
            raise CredentialStoreError(f"cannot unlock {self.keychain}")
        try:
            yield
        finally:
            self._security("lock-keychain", str(self.keychain))

    def get(self, service: str, account: str) -> bytes | None:
        if not self.keychain.exists():
            return None
        password = self._password(service, create=False)
        if password is None:
            return None
        with self.unlocked(password):
            proc = self._security(
                "find-generic-password", "-s", service, "-a", account, "-w", str(self.keychain)
            )
        if proc.returncode != 0:
            return None
        return _decode(proc.stdout)

    def set(self, service: str, account: str, secret: bytes) -> None:
        password = self._password(service, create=True)
        self._ensure_keychain(password)
        command = (
            f'add-generic-password -U -s "{service}" -a "{account}" '
            f'-w "{_encode(secret)}" "{self.keychain}"\n'
        )
        with self.unlocked(password):
            proc = self._security(stdin=command)
        if proc.returncode != 0:
            raise CredentialStoreError("security add-generic-password failed")

    def delete(self) -> None:
        before = [k for k in self._search_list() if k != str(self.keychain)]
        self._security("delete-keychain", str(self.keychain))
        if before:
            self._security("list-keychains", "-d", "user", "-s", *before)


class LibsecretStore:
    def __init__(self, binary: str = "secret-tool") -> None:
        self.binary = binary

    def get(self, service: str, account: str) -> bytes | None:
        proc = subprocess.run(
            [self.binary, "lookup", "service", service, "account", account],
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0 or not proc.stdout.strip():
            return None
        return _decode(proc.stdout)

    def set(self, service: str, account: str, secret: bytes) -> None:
        proc = subprocess.run(
            [self.binary, "store", f"--label={service} {account}", "service", service, "account", account],
            input=_encode(secret),
            capture_output=True,
            text=True,
        )
        if proc.returncode != 0:
            raise CredentialStoreError("secret-tool store failed")


def _win_credential_struct():
    import ctypes  # noqa: PLC0415
    from ctypes import wintypes  # noqa: PLC0415

    class CREDENTIAL(ctypes.Structure):
        _fields_ = [
            ("Flags", wintypes.DWORD),
            ("Type", wintypes.DWORD),
            ("TargetName", wintypes.LPWSTR),
            ("Comment", wintypes.LPWSTR),
            ("LastWritten", wintypes.FILETIME),
            ("CredentialBlobSize", wintypes.DWORD),
            ("CredentialBlob", ctypes.POINTER(ctypes.c_char)),
            ("Persist", wintypes.DWORD),
            ("AttributeCount", wintypes.DWORD),
            ("Attributes", ctypes.c_void_p),
            ("TargetAlias", wintypes.LPWSTR),
            ("UserName", wintypes.LPWSTR),
        ]

    return ctypes, CREDENTIAL


class WindowsCredentialStore:
    """Generic credentials via advapi32 CredReadW/CredWriteW."""

    _CRED_TYPE_GENERIC = 1
    _CRED_PERSIST_LOCAL_MACHINE = 2

    def _target(self, service: str, account: str) -> str:
        return f"{service}:{account}"

    def get(self, service: str, account: str) -> bytes | None:
        ctypes, CREDENTIAL = _win_credential_struct()
        advapi32 = ctypes.WinDLL("advapi32")  # type: ignore[attr-defined]
        pcred = ctypes.POINTER(CREDENTIAL)()
        if not advapi32.CredReadW(
            self._target(service, account), self._CRED_TYPE_GENERIC, 0, ctypes.byref(pcred)
        ):
            return None
        try:
            blob = ctypes.string_at(pcred.contents.CredentialBlob, pcred.contents.CredentialBlobSize)
        finally:
            advapi32.CredFree(pcred)
        return _decode(blob.decode())

    def set(self, service: str, account: str, secret: bytes) -> None:
        ctypes, CREDENTIAL = _win_credential_struct()
        blob = _encode(secret).encode()
        buf = ctypes.create_string_buffer(blob, len(blob))
        cred = CREDENTIAL(
            Type=self._CRED_TYPE_GENERIC,
            TargetName=self._target(service, account),
            CredentialBlobSize=len(blob),
            CredentialBlob=ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)),
            Persist=self._CRED_PERSIST_LOCAL_MACHINE,
            UserName=account,
        )
        advapi32 = ctypes.WinDLL("advapi32")  # type: ignore[attr-defined]
        if not advapi32.CredWriteW(ctypes.byref(cred), 0):
            raise CredentialStoreError("CredWriteW failed")


class InMemoryCredentialStore:
    """Test double."""

    def __init__(self) -> None:
        self.items: dict[tuple[str, str], bytes] = {}

    def get(self, service: str, account: str) -> bytes | None:
        return self.items.get((service, account))

    def set(self, service: str, account: str, secret: bytes) -> None:
        self.items[(service, account)] = secret


def default_credential_store() -> CredentialStore:
    if sys.platform == "darwin":
        return MacKeychainStore()
    if sys.platform == "win32":
        return WindowsCredentialStore()
    if "abstract=" in os.environ.get("DBUS_SESSION_BUS_ADDRESS", ""):
        # Abstract sockets live in the network namespace, which bwrap workspaces
        # share with the host (--share-net), so they could reach the secret service.
        raise CredentialStoreError(
            "the D-Bus session bus uses an abstract socket, which bwrap workspaces can reach; "
            "refusing to keep the GitHub App key in libsecret (use a path-socket session bus, "
            "e.g. systemd's /run/user/<uid>/bus)"
        )
    if shutil.which("secret-tool"):
        return LibsecretStore()
    raise CredentialStoreError(
        "no OS credential store available: install libsecret's secret-tool"
    )
