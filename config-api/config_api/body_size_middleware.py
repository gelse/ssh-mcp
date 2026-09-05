from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from starlette.types import ASGIApp, Receive, Scope, Send


class BodySizeLimitMiddleware:
    """ASGI middleware that enforces a maximum request body size.

    Works by intercepting HTTP request body chunks before they reach
    the application.  Supports both fast-path (Content-Length header)
    rejection and slow-path (streaming byte count) rejection.
    """

    def __init__(self, app: ASGIApp, max_body_size: int) -> None:
        """Initialize the middleware.

        Args:
            app: The downstream ASGI application to wrap.
            max_body_size: Maximum allowed request body size in bytes.
        """
        self.app = app
        self.max_body_size = max_body_size

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """ASGI entry point.

        Passes non-HTTP scopes through untouched, applies fast-path
        Content-Length rejection for HTTP requests with a body, and
        wraps ``receive``/``send`` for slow-path streaming enforcement.

        Args:
            scope: ASGI connection scope.
            receive: ASGI receive callable.
            send: ASGI send callable.
        """
        # Pitfall-a: Pass through non-HTTP scopes (lifespan, websocket, etc.)
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # Only check methods that carry request bodies
        method = scope.get("method", "").upper()
        if method not in ("POST", "PUT", "PATCH"):
            await self.app(scope, receive, send)
            return

        # Fast-path: Content-Length check (with D4 guards)
        headers = dict(scope.get("headers", []))

        # D4(b): Skip fast-path when Transfer-Encoding is present
        if b"transfer-encoding" not in headers:
            cl_bytes = headers.get(b"content-length")
            if cl_bytes is not None:
                try:
                    content_length = int(cl_bytes)
                except (ValueError, TypeError):
                    content_length = None  # D4(a): malformed, treat as unknown

                if (
                    content_length is not None
                    and content_length > self.max_body_size
                ):
                    await self._send_413(send)
                    return

        # Slow-path: wrap receive to count bytes
        total_bytes = 0
        overflow = False

        async def _receive():
            nonlocal total_bytes, overflow
            message = await receive()
            if message["type"] == "http.request.body":
                body = message.get("body", b"")
                total_bytes += len(body)
                if total_bytes > self.max_body_size:
                    overflow = True
                    # Return empty body to signal end of stream
                    return {
                        "type": "http.request.body",
                        "body": b"",
                        "more_body": False,
                    }
            return message

        # Pitfall-b: Intercept send to handle mid-stream overflow
        response_started = False

        async def _send(message):
            nonlocal response_started
            if message["type"] == "http.response.start":
                if overflow:
                    # Overflow was detected before the app responded, so the
                    # app's response is swallowed; a 413 is emitted below.
                    return
                response_started = True
                await send(message)
            elif message["type"] == "http.response.body":
                if overflow:
                    # Swallow the app's response body
                    return
                await send(message)
            else:
                await send(message)

        await self.app(scope, _receive, _send)

        # If overflow was detected before the app started responding, the
        # app's response was swallowed and no bytes reached the client:
        # emit the 413 response now.
        if overflow and not response_started:
            await self._send_413(send)
            return

        # If overflow was detected after the response already started, the
        # client received the app's (truncated) response.  A 413 cannot be
        # sent at that point; this is documented as expected behaviour.

    async def _send_413(self, send: Send) -> None:
        """Send a 413 PayloadTooLarge response with connection: close.

        Args:
            send: ASGI send callable to emit the response messages.
        """
        body = json.dumps(
            {
                "error": True,
                "error_type": "PayloadTooLarge",
                "message": "Request body must not exceed 1 MB",
            }
        ).encode()
        await send(
            {
                "type": "http.response.start",
                "status": 413,
                "headers": [
                    (b"content-type", b"application/json"),
                    (
                        b"content-length",
                        str(len(body)).encode(),
                    ),
                    (b"connection", b"close"),
                ],
            }
        )
        await send({"type": "http.response.body", "body": body})
