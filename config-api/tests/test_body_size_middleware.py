"""Unit tests for config_api.body_size_middleware — BodySizeLimitMiddleware.

Tests cover the ASGI middleware that enforces a maximum request body size
on POST/PUT/PATCH requests.  Tests use two harnesses:

* ``TestClient`` (via the shared ``client`` fixture) for end-to-end tests
  against the real FastAPI app, exercising auth ordering, global scope,
  and Content-Length based fast-path rejection.
* A direct ASGI harness (``_run_asgi``) that drives a middleware
  instance directly with a small ``max_body_size``, exercising streaming,
  chunked transfer, malformed Content-Length, mid-stream overflow, and
  lifespan passthrough.
"""

from __future__ import annotations

import json
from typing import Awaitable, Callable

import pytest

from config_api.body_size_middleware import BodySizeLimitMiddleware


# ---------------------------------------------------------------------------
# ASGI helpers — direct driving of an ASGI app without httpx/TestClient
# ---------------------------------------------------------------------------


async def _echo_asgi_app(scope, receive, send):
    """Minimal ASGI app that reads body and echoes it back.

    Args:
        scope: ASGI connection scope.
        receive: ASGI receive callable.
        send: ASGI send callable.
    """
    body = b""
    while True:
        message = await receive()
        if message["type"] == "http.request.body":
            body += message.get("body", b"")
            if not message.get("more_body", False):
                break
        elif message["type"] == "http.disconnect":
            break
    response_body = body
    await send(
        {
            "type": "http.response.start",
            "status": 200,
            "headers": [(b"content-type", b"text/plain")],
        }
    )
    await send({"type": "http.response.body", "body": response_body})


async def _run_asgi(
    app,
    path: str = "/",
    method: str = "POST",
    headers: list[tuple[bytes, bytes]] | None = None,
    body_chunks: list[bytes] | None = None,
) -> tuple[int | None, dict[bytes, bytes], bytes]:
    """Drive an ASGI app directly, returning (status, headers_dict, body).

    Args:
        app: The ASGI application (or middleware) to invoke.
        path: HTTP path for the synthetic request.
        method: HTTP method for the synthetic request.
        headers: List of raw ``(name, value)`` byte tuples.
        body_chunks: Body chunks to feed through ``receive``; the final
            chunk is delivered with ``more_body=False``.

    Returns:
        Tuple of (status code, headers dict, accumulated body bytes).
    """
    if headers is None:
        headers = [(b"host", b"testserver")]
    if body_chunks is None:
        body_chunks = [b"hello"]

    scope = {
        "type": "http",
        "method": method,
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": headers,
        "root_path": "",
        "server": ("testserver", 80),
        "client": ("127.0.0.1", 5000),
    }

    received: list[dict] = []
    sent: list[dict] = []

    async def receive() -> dict:
        if received:
            return received.pop(0)
        return {"type": "http.disconnect"}

    async def send(message: dict) -> None:
        sent.append(message)

    # Build request messages — final chunk uses more_body=False
    for i, chunk in enumerate(body_chunks):
        more_body = i < len(body_chunks) - 1
        received.append(
            {
                "type": "http.request.body",
                "body": chunk,
                "more_body": more_body,
            }
        )

    await app(scope, receive, send)

    # Parse response
    status: int | None = None
    resp_headers: dict[bytes, bytes] = {}
    body = b""
    for msg in sent:
        if msg["type"] == "http.response.start":
            status = msg["status"]
            for name, value in msg.get("headers", []):
                resp_headers[name] = value
        elif msg["type"] == "http.response.body":
            body += msg.get("body", b"")
    return status, resp_headers, body


# ---------------------------------------------------------------------------
# Real-app tests (use the shared app/client fixtures)
# ---------------------------------------------------------------------------


class TestBodySizeLimitMiddleware:
    """Tests for the body-size limit middleware."""

    # ----- Tests that drive the real app via TestClient --------------------

    def test_small_request_passes_through(
        self, client, auth_headers: dict[str, str]
    ) -> None:
        """A small POST under the limit reaches the application."""
        response = client.post(
            "/auth/login",
            headers=auth_headers,
            json={"token": "test-token-12345"},
        )
        # The login endpoint validates against CONFIG_API_TOKEN; small body
        # is forwarded, so we expect either 200 or 401 — NOT 413.
        assert response.status_code != 413
        assert response.status_code in (200, 401)

    def test_large_content_length_returns_413(
        self, client, auth_headers: dict[str, str]
    ) -> None:
        """An oversized PUT /config is rejected with 413."""
        # Build a JSON body larger than the 1 MiB limit by stuffing a
        # single very long string into the config.
        big_value = "x" * (1_048_576 + 1024)
        payload = {
            "version": 1,
            "ssh_targets": {
                "t1": {
                    "host": "10.0.0.1",
                    "port": 22,
                    "username": "u",
                    "password": big_value,
                },
            },
            "block_patterns": [],
            "allowed_commands": {
                "default": [{"targets": ["*"], "commands": ["echo"]}],
                "api_keys": [],
                "networks": [],
            },
            "settings": {},
        }
        # Send raw JSON to ensure Content-Length reflects the large body.
        body_text = json.dumps(payload)
        assert len(body_text.encode()) > 1_048_576

        response = client.put(
            "/config",
            headers={**auth_headers, "Content-Type": "application/json"},
            content=body_text,
        )
        assert response.status_code == 413
        data = response.json()
        assert data["error"] is True
        assert data["error_type"] == "PayloadTooLarge"

    def test_unauthenticated_oversized_returns_413_not_401(
        self, client
    ) -> None:
        """Oversized request is rejected with 413 even without auth headers.

        The body-size check runs *before* auth, so an unauthenticated
        oversize PUT must be rejected with 413 — not 401.
        """
        big_body = "x" * (1_048_576 + 1024)
        response = client.put(
            "/config",
            headers={"Content-Type": "application/json"},
            content=big_body,
        )
        assert response.status_code == 413

    def test_small_unauthenticated_still_returns_401(
        self, client
    ) -> None:
        """A small unauthenticated PUT /config still returns 401."""
        response = client.put(
            "/config",
            headers={"Content-Type": "application/json"},
            content=json.dumps({"version": 1}),
        )
        assert response.status_code == 401

    def test_limit_applies_to_non_config_route(self, client) -> None:
        """The middleware enforces limits on every POST/PUT/PATCH endpoint.

        The body-size check is global — it runs before auth/routing.
        Oversized POST to /auth/login must return 413, not 401.
        """
        big_body = "x" * (1_048_576 + 1024)
        response = client.post(
            "/auth/login",
            headers={"Content-Type": "application/json"},
            content=big_body,
        )
        assert response.status_code == 413

    # ----- Direct ASGI tests with a small limit ----------------------------

    @pytest.mark.asyncio
    async def test_exact_limit_passes(self) -> None:
        """Body exactly at the limit is accepted (200)."""
        mw = BodySizeLimitMiddleware(_echo_asgi_app, max_body_size=100)
        body = b"a" * 100
        status, _, echoed = await _run_asgi(
            mw,
            method="POST",
            headers=[
                (b"host", b"testserver"),
                (b"content-type", b"text/plain"),
                (b"content-length", str(len(body)).encode()),
            ],
            body_chunks=[body],
        )
        assert status == 200
        assert echoed == body

    @pytest.mark.asyncio
    async def test_413_includes_connection_close(self) -> None:
        """Oversized body gets 413 with ``Connection: close`` header."""
        mw = BodySizeLimitMiddleware(_echo_asgi_app, max_body_size=100)
        body = b"a" * 200
        status, headers, body_out = await _run_asgi(
            mw,
            method="PUT",
            headers=[
                (b"host", b"testserver"),
                (b"content-type", b"text/plain"),
                (b"content-length", str(len(body)).encode()),
            ],
            body_chunks=[body],
        )
        assert status == 413
        # Headers should include connection: close (case-insensitive)
        assert b"connection" in headers
        assert headers[b"connection"].lower() == b"close"
        # Body should be JSON with the expected error type
        parsed = json.loads(body_out)
        assert parsed["error_type"] == "PayloadTooLarge"

    @pytest.mark.asyncio
    async def test_no_content_length_slow_path(self) -> None:
        """Without Content-Length, the slow path counts bytes accurately."""
        mw = BodySizeLimitMiddleware(_echo_asgi_app, max_body_size=100)

        # Under limit → 200
        status, _, echoed = await _run_asgi(
            mw,
            method="POST",
            headers=[
                (b"host", b"testserver"),
                (b"content-type", b"text/plain"),
            ],
            body_chunks=[b"a" * 50],
        )
        assert status == 200
        assert echoed == b"a" * 50

        # Over limit → 413
        status, _, _ = await _run_asgi(
            mw,
            method="POST",
            headers=[
                (b"host", b"testserver"),
                (b"content-type", b"text/plain"),
            ],
            body_chunks=[b"a" * 200],
        )
        assert status == 413

    @pytest.mark.asyncio
    async def test_mid_stream_overflow_returns_413(self) -> None:
        """Mid-stream overflow: total exceeds limit across chunks → 413."""
        mw = BodySizeLimitMiddleware(_echo_asgi_app, max_body_size=100)
        status, headers, _ = await _run_asgi(
            mw,
            method="POST",
            headers=[
                (b"host", b"testserver"),
                (b"content-type", b"text/plain"),
                # No Content-Length — forces slow-path counting
            ],
            body_chunks=[b"a" * 60, b"b" * 60],
        )
        assert status == 413
        # Connection-close still applied
        assert headers.get(b"connection", b"").lower() == b"close"

    @pytest.mark.asyncio
    async def test_malformed_content_length_falls_through(self) -> None:
        """A non-numeric Content-Length falls through to the slow path.

        Slow path counts actual bytes; under-limit body → 200, no 500.
        """
        mw = BodySizeLimitMiddleware(_echo_asgi_app, max_body_size=100)
        status, _, echoed = await _run_asgi(
            mw,
            method="POST",
            headers=[
                (b"host", b"testserver"),
                (b"content-type", b"text/plain"),
                (b"content-length", b"not-a-number"),
            ],
            body_chunks=[b"a" * 50],
        )
        assert status == 200
        assert echoed == b"a" * 50

    @pytest.mark.asyncio
    async def test_transfer_encoding_skips_fast_path(self) -> None:
        """Transfer-Encoding: chunked forces slow-path counting.

        A spoofed large Content-Length must be ignored when TE is present;
        actual bytes counted via the slow path determine the outcome.
        """
        mw = BodySizeLimitMiddleware(_echo_asgi_app, max_body_size=100)
        status, _, echoed = await _run_asgi(
            mw,
            method="POST",
            headers=[
                (b"host", b"testserver"),
                (b"content-type", b"text/plain"),
                (b"transfer-encoding", b"chunked"),
                # Spoofed large CL — must be ignored because TE is present
                (b"content-length", b"999999"),
            ],
            body_chunks=[b"a" * 50],
        )
        assert status == 200
        assert echoed == b"a" * 50

    @pytest.mark.asyncio
    async def test_lifespan_scope_passthrough(self) -> None:
        """Non-HTTP scopes (lifespan) are passed through untouched."""
        received_scope: dict | None = None

        async def spy_app(scope, receive, send):
            nonlocal received_scope
            received_scope = scope

        mw = BodySizeLimitMiddleware(spy_app, max_body_size=100)
        lifespan_scope = {
            "type": "lifespan",
            "asgi": {"version": "3.0", "spec_version": "2.0"},
        }

        async def receive() -> dict:
            return {"type": "lifespan.startup"}

        async def send(message: dict) -> None:
            pass

        await mw(lifespan_scope, receive, send)

        assert received_scope is not None
        assert received_scope["type"] == "lifespan"