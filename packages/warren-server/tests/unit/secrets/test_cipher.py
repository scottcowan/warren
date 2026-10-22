from __future__ import annotations

import pytest
from cryptography.fernet import InvalidToken

from warren.secrets.cipher import LocalCipher, derive_fernet_key


def test_roundtrip_encrypt_decrypt():
    cipher = LocalCipher("test-secret-key")
    ciphertext = cipher.encrypt("super-secret-value")
    assert cipher.decrypt(ciphertext) == "super-secret-value"


def test_ciphertext_is_not_plaintext():
    cipher = LocalCipher("test-secret-key")
    ciphertext = cipher.encrypt("super-secret-value")
    assert b"super-secret-value" not in ciphertext


def test_different_secret_keys_cannot_decrypt_each_others_ciphertext():
    cipher_a = LocalCipher("key-a")
    cipher_b = LocalCipher("key-b")
    ciphertext = cipher_a.encrypt("value")
    with pytest.raises(InvalidToken):
        cipher_b.decrypt(ciphertext)


def test_derive_fernet_key_is_deterministic_for_same_input():
    assert derive_fernet_key("same-key") == derive_fernet_key("same-key")


def test_derive_fernet_key_differs_for_different_input():
    assert derive_fernet_key("key-a") != derive_fernet_key("key-b")
