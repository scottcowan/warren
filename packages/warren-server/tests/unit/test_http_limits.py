"""BodySizeLimitMiddleware unit tests — audit 2026-10-16 P2 #46."""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.responses import PlainTextResponse, StreamingResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from warren.http_limits import BodySizeLimitMiddleware


async def _echo(request):
    body = await request.body()
    return PlainTextResponse(f"got {len(body)} bytes")


async def _stream(request):
    async def gen():
        for _ in range(3):
            yield b"chunk"

    return StreamingResponse(gen())


def _make_app(max_body_bytes: int) -> Starlette:
    app = Starlette(routes=[Route("/echo", _echo, methods=["POST"]), Route("/stream", _stream)])
    app.add_middleware(BodySizeLimitMiddleware, max_body_bytes=max_body_bytes)
    return app


def test_body_under_limit_passes_through():
    client = TestClient(_make_app(max_body_bytes=1024))
    resp = client.post("/echo", content=b"x" * 100)
    assert resp.status_code == 200
    assert resp.text == "got 100 bytes"


def test_body_over_content_length_rejected_with_413():
    client = TestClient(_make_app(max_body_bytes=10))
    resp = client.post("/echo", content=b"x" * 100)
    assert resp.status_code == 413


def test_body_over_limit_without_content_length_header_still_rejected():
    """Chunked transfer-encoding (no Content-Length) must also be bounded --
    the running-byte-count check in `limited_receive`, not just the header
    short-circuit, is what catches this."""
    client = TestClient(_make_app(max_body_bytes=10))

    def chunked_body():
        yield b"x" * 100

    resp = client.post("/echo", content=chunked_body())
    assert resp.status_code == 413


def test_streaming_response_unaffected_by_body_limit():
    """The middleware only wraps `receive`, never `send` -- a streaming GET response
    (no request body at all) must pass through untouched."""
    client = TestClient(_make_app(max_body_bytes=10))
    resp = client.get("/stream")
    assert resp.status_code == 200
    assert resp.text == "chunkchunkchunk"
