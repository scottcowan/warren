"""HttpxSender pinned delivery against a local TLS server (loopback, no external network)."""

from __future__ import annotations

import asyncio
import datetime
import ssl

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from warren.notify.dispatcher import HttpxSender

HOST = "hooks.warren-test.example"


def _make_cert(tmp_path, name):
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    now = datetime.datetime.now(datetime.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject).issuer_name(subject).public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=1))
        .not_valid_after(now + datetime.timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]), critical=False)
        .sign(key, hashes.SHA256())
    )
    cert_p, key_p = tmp_path / f"{name}.crt", tmp_path / f"{name}.key"
    cert_p.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    key_p.write_bytes(key.private_bytes(
        serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return cert_p, key_p


async def _serve(cert_p, key_p, seen):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert_p, key_p)

    async def handle(reader, writer):
        data = await reader.readuntil(b"\r\n\r\n")
        seen.append(data.decode("latin1"))
        writer.write(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
        await writer.drain()
        writer.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0, ssl=ctx)
    return server, server.sockets[0].getsockname()[1]


def _client_ctx(cert_p):
    return ssl.create_default_context(cafile=str(cert_p))


async def test_pinned_delivery_connects_to_ip_and_verifies_hostname(tmp_path):
    cert_p, key_p = _make_cert(tmp_path, HOST)
    seen: list[str] = []
    server, port = await _serve(cert_p, key_p, seen)
    try:
        sender = HttpxSender(verify=_client_ctx(cert_p))
        # The name does not resolve anywhere: success proves the pinned IP was dialled.
        code = await sender(f"https://{HOST}:{port}/hook/abc", b'{"a":1}', 5.0, "127.0.0.1")
        assert code == 204
        assert "POST /hook/abc" in seen[0]
        assert f"host: {HOST}:{port}".lower() in seen[0].lower()
    finally:
        server.close()


async def test_pinned_delivery_fails_on_hostname_mismatch(tmp_path):
    cert_p, key_p = _make_cert(tmp_path, "other.warren-test.example")
    seen: list[str] = []
    server, port = await _serve(cert_p, key_p, seen)
    try:
        sender = HttpxSender(verify=_client_ctx(cert_p))
        with pytest.raises(Exception) as ei:
            await sender(f"https://{HOST}:{port}/hook/abc", b"{}", 5.0, "127.0.0.1")
        assert "certificate" in str(ei.value).lower() or "ssl" in type(ei.value).__name__.lower() or "connect" in type(ei.value).__name__.lower()
        assert seen == []
    finally:
        server.close()
