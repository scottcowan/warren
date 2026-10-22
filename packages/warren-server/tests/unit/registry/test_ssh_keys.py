"""mint_ssh_keypair() unit tests (Phase 3 Plan 01 Task 1, D-01/D-02)."""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from warren.registry.ssh_keys import mint_ssh_keypair


def test_mint_ssh_keypair_returns_private_and_public():
    private_pem, public_line = mint_ssh_keypair()
    assert isinstance(private_pem, bytes)
    assert isinstance(public_line, str)


def test_private_key_is_openssh_pem_and_reloadable_ed25519():
    private_pem, _ = mint_ssh_keypair()
    assert private_pem.startswith(b"-----BEGIN OPENSSH PRIVATE KEY-----")
    loaded = serialization.load_ssh_private_key(private_pem, password=None)
    assert isinstance(loaded, Ed25519PrivateKey)


def test_public_key_line_is_ssh_ed25519_and_reloadable():
    _, public_line = mint_ssh_keypair()
    assert public_line.startswith("ssh-ed25519 ")
    loaded = serialization.load_ssh_public_key(public_line.encode())
    assert isinstance(loaded, Ed25519PublicKey)


def test_consecutive_calls_return_different_key_material():
    private_pem_1, public_line_1 = mint_ssh_keypair()
    private_pem_2, public_line_2 = mint_ssh_keypair()
    assert private_pem_1 != private_pem_2
    assert public_line_1 != public_line_2
