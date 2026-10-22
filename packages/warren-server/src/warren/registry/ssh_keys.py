"""Ephemeral Ed25519 SSH keypair minting (D-01/D-02).

`mint_ssh_keypair()` generates one fresh Ed25519 keypair per call, in-process, with
`cryptography.hazmat` — the same package `warren-server` already depends on for its
Fernet secret store, so this adds zero new packages and no subprocess dependency on a
host `ssh-keygen` binary. D-02 requires the minted keypair to be scoped to exactly one
workspace connection (smallest blast radius per credential), so callers must never cache
or reuse a keypair returned from this module across more than one workspace.

The returned private key is secret material and must NEVER be passed to any `structlog`
call or included in a log payload, matching the discipline `routes/admin.py::mint_token`
already applies to `raw_token` and that `GitManager` applies to git deploy keys.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def mint_ssh_keypair() -> tuple[bytes, str]:
    """Generate a fresh Ed25519 keypair and return (private_key_openssh_pem, public_key_line).

    A new keypair is generated on every call — there is no caching or reuse, per D-02.
    The private key is returned as OpenSSH PEM-armored bytes (unencrypted); the public
    key is returned as an "ssh-ed25519 <base64>" line, both re-loadable via
    `cryptography.hazmat.primitives.serialization`'s own SSH loaders.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.OpenSSH,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_line = public_key.public_bytes(
        encoding=serialization.Encoding.OpenSSH,
        format=serialization.PublicFormat.OpenSSH,
    ).decode()
    return private_pem, public_line
