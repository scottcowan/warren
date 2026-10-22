"""Fernet envelope encryption for the local (Podman/Docker) secret store.

Mirrors auth/tokens.py's `derive_token_pepper` pattern exactly: the Fernet key
is derived from WARREN_SECRET_KEY with its own fixed context label (HMAC-
SHA256, single-label HKDF-Expand style), so a compromise of this derived key
never also exposes the token-hashing pepper (or vice versa) even though both
ultimately derive from the one root secret.
"""

from __future__ import annotations

import base64
import hashlib
import hmac

from cryptography.fernet import Fernet, MultiFernet

_FERNET_KEY_DERIVATION_LABEL = b"warren-secret-store-fernet-key-v1"


def derive_fernet_key(secret_key: str) -> bytes:
    """Derive a 32-byte, url-safe-base64-encoded Fernet key from `secret_key`."""
    digest = hmac.new(
        secret_key.encode(), _FERNET_KEY_DERIVATION_LABEL, hashlib.sha256
    ).digest()
    return base64.urlsafe_b64encode(digest)


class LocalCipher:
    """Fernet cipher for secret values at rest in the local `secrets` table."""

    def __init__(self, secret_key: str) -> None:
        self._fernet = Fernet(derive_fernet_key(secret_key))
        # Only the current key today: rotate() re-encrypts under it with a fresh
        # IV/timestamp. Previous keys go after it here once key rotation (#44) lands.
        self._multi = MultiFernet([self._fernet])

    def encrypt(self, plaintext: str) -> bytes:
        return self._fernet.encrypt(plaintext.encode())

    def decrypt(self, ciphertext: bytes) -> str:
        return self._multi.decrypt(ciphertext).decode()

    def rotate(self, ciphertext: bytes) -> bytes:
        return self._multi.rotate(ciphertext)
