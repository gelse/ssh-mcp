"""
Request context middleware for MCP tools to access the HTTP request.

Provides context variables that are set by ASGI middleware before each
request and cleared afterward. Tool functions can call
``get_current_request()`` to access the Starlette Request,
``get_client_ip()`` to get the validated client IP address, and
``get_api_key()`` to get the raw API key extracted from headers.

When a :class:`~lib.rate_limiter.RateLimiter` is supplied, the
middleware also enforces per-IP rate limiting, returning HTTP 429
responses with a ``Retry-After`` header on violations.  The
``/health`` endpoint is excluded from rate limiting.
"""

from __future__ import annotations

import ipaddress
import uuid
from contextvars import ContextVar
from typing import TYPE_CHECKING

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from lib.constants import DEFAULT_REQUEST_ID, FALLBACK_CLIENT_IP

if TYPE_CHECKING:
    from lib.rate_limiter import RateLimiter

_current_request: ContextVar[Request | None] = ContextVar("current_request", default=None)
_request_client_ip: ContextVar[str] = ContextVar("request_client_ip", default=FALLBACK_CLIENT_IP)
_request_api_key: ContextVar[str | None] = ContextVar("request_api_key", default=None)
_request_id: ContextVar[str | None] = ContextVar("request_id", default=None)

# Maximum allowed length for a raw API key value extracted from headers.
_API_KEY_MAX_LENGTH = 512

# Maximum accepted length for an incoming X-Request-ID header value.
_REQUEST_ID_MAX_LENGTH = 128


def get_current_request() -> Request | None:
    """Return the current Starlette Request, or ``None`` if outside a request.

    Returns ``None`` when no request context is active (e.g. during
    startup, shutdown, or background tasks). Callers must handle the
    ``None`` case explicitly before dereferencing the returned request.
    """
    return _current_request.get()


def _get_mcp_request() -> Request | None:
    """Return the per-message Starlette Request from the MCP SDK, if any.

    The MCP streamable-HTTP transport stores the Starlette Request for
    the current JSON-RPC message in ``mcp.server.lowlevel.server.request_ctx``
    (a ``ContextVar``).  The ASGI middleware context variables set during the
    initial ``GET /mcp`` do **not** propagate into tool calls, because the
    session task that processes later messages is spawned from that initial
    request's context.  Reading the request from the SDK's per-message
    context gives tools access to the actual POST headers (``X-API-Key``,
    ``X-Forwarded-For``).

    Returns ``None`` when called outside an MCP message context or when
    the MCP SDK is unavailable.
    """
    try:
        from mcp.server.lowlevel.server import request_ctx as sdk_request_ctx
    except ImportError:
        return None
    ctx = sdk_request_ctx.get(None)
    if ctx is None:
        return None
    request = getattr(ctx, "request", None)
    if isinstance(request, Request):
        return request
    return None


def get_client_ip() -> str:
    """Return the validated client IP address for the current request.

    Prefers the per-message MCP request (so ``X-Forwarded-For`` from the
    actual tool-call POST is honoured); falls back to the IP stored by
    :class:`RequestContextMiddleware`, or the safe default
    :data:`~lib.constants.FALLBACK_CLIENT_IP` when called outside any
    request context.
    """
    mcp_request = _get_mcp_request()
    if mcp_request is not None:
        return RequestContextMiddleware._extract_ip(mcp_request)
    return _request_client_ip.get()


def get_api_key() -> str | None:
    """Return the raw API key for the current request, or ``None``.

    The key is extracted from the ``X-API-Key`` header or the
    ``Authorization: Bearer <key>`` header, preferring the per-message
    MCP request (so the actual tool-call POST headers are honoured) and
    falling back to :class:`RequestContextMiddleware`.  Returns ``None``
    when called outside a request context or when no key was provided.

    The returned value is the **raw** key string — hashing and lookup
    are the responsibility of :mod:`lib.auth`.
    """
    mcp_request = _get_mcp_request()
    if mcp_request is not None:
        return RequestContextMiddleware._extract_api_key(mcp_request)
    return _request_api_key.get()


def get_request_id() -> str:
    """Return the correlation ID for the current request.

    The ID is taken from the ``X-Request-ID`` header of the per-message
    MCP request (so the actual tool-call POST is honoured), falling back
    to the header (or generated UUID) stored by
    :class:`RequestContextMiddleware`.  When no request is in progress
    the constant :data:`~lib.constants.DEFAULT_REQUEST_ID` is returned
    so callers always receive a non-empty value.

    The returned ID is truncated to :data:`_REQUEST_ID_MAX_LENGTH`
    characters.
    """
    mcp_request = _get_mcp_request()
    if mcp_request is not None:
        extracted = RequestContextMiddleware._extract_request_id(mcp_request)
        if extracted is not None:
            return extracted
    cached = _request_id.get()
    if cached is not None:
        return cached
    return DEFAULT_REQUEST_ID


class RequestContextMiddleware(BaseHTTPMiddleware):
    """Middleware that stores the current request, client IP, and API key.

    When *rate_limiter* is provided, rate limiting is enforced per
    client IP **before** the context variables are set.  The
    ``/health`` endpoint is always excluded from rate limiting.

    On every request the middleware:

    1. Checks the per-IP rate limit (if *rate_limiter* is set) and
       returns ``429 Too Many Requests`` on violation.
    2. Stores the Starlette ``Request`` in a context variable.
    3. Extracts the client IP (respecting ``X-Forwarded-For``) and
       validates it with :func:`ipaddress.ip_address`.
    4. Extracts the API key from ``X-API-Key`` or ``Authorization:
       Bearer <key>`` headers and performs basic format validation.
    5. Stores the validated IP (or a safe fallback) and the raw API key
       (or ``None``) in context variables.
    """

    # Paths excluded from rate limiting.
    _NO_RATELIMIT_PATHS: set[str] = {"/health"}

    def __init__(
        self,
        app,
        rate_limiter: RateLimiter | None = None,
    ) -> None:
        super().__init__(app)
        self._rate_limiter: RateLimiter | None = rate_limiter

    async def dispatch(self, request: Request, call_next):
        # --- Rate-limit check (before context, excluded for health) ---
        if self._rate_limiter is not None and request.url.path not in self._NO_RATELIMIT_PATHS:
            client_ip = self._extract_ip(request)
            if not self._rate_limiter.check(client_ip):
                retry_after = int(self._rate_limiter.window_seconds)
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "Rate limit exceeded",
                        "detail": (
                            f"Too many requests from {client_ip}. "
                            f"Retry after {retry_after} seconds."
                        ),
                    },
                    headers={"Retry-After": str(retry_after)},
                )

        token = _current_request.set(request)
        ip_token = _request_client_ip.set(self._extract_ip(request))
        api_key_token = _request_api_key.set(self._extract_api_key(request))
        # Every request gets a correlation ID: the X-Request-ID header when
        # present, otherwise a freshly generated UUID.
        extracted_request_id = self._extract_request_id(request)
        request_id_token = _request_id.set(
            extracted_request_id if extracted_request_id is not None else uuid.uuid4().hex
        )
        try:
            response = await call_next(request)
            return response
        finally:
            _current_request.reset(token)
            _request_client_ip.reset(ip_token)
            _request_api_key.reset(api_key_token)
            _request_id.reset(request_id_token)

    @staticmethod
    def _extract_ip(request: Request) -> str:
        """Extract and validate the client IP from the request.

        Checks ``X-Forwarded-For`` first (leftmost entry = original client),
        then falls back to the direct connection address.  The raw value is
        validated via :func:`ipaddress.ip_address`; invalid addresses are
        replaced with :data:`~lib.constants.FALLBACK_CLIENT_IP`.
        """
        # Check X-Forwarded-For header
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            raw_ip = forwarded.split(",")[0].strip()
        elif request.client is not None:
            raw_ip = request.client.host
        else:
            return FALLBACK_CLIENT_IP

        # Validate the IP address
        try:
            ipaddress.ip_address(raw_ip)
            return raw_ip
        except ValueError:
            return FALLBACK_CLIENT_IP

    @staticmethod
    def _extract_api_key(request: Request) -> str | None:
        """Extract and validate the API key from request headers.

        Checks ``X-API-Key`` first, then falls back to ``Authorization:
        Bearer <key>``.  Returns ``None`` if no valid key is found.

        Performs basic format validation (non-empty, not exceeding
        :data:`_API_KEY_MAX_LENGTH` characters) but does **not** hash
        or look up the key — that is the responsibility of
        :mod:`lib.auth`.
        """
        # Check X-API-Key header (takes priority)
        api_key = request.headers.get("X-API-Key", "")
        if api_key and len(api_key) <= _API_KEY_MAX_LENGTH:
            return api_key

        # Check Authorization: Bearer <key>
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            key = auth_header[7:]
            if key and len(key) <= _API_KEY_MAX_LENGTH:
                return key

        return None

    @staticmethod
    def _extract_request_id(request: Request) -> str | None:
        """Extract a request ID from the ``X-Request-ID`` header.

        Returns ``None`` when the header is missing, empty, or exceeds
        :data:`_REQUEST_ID_MAX_LENGTH` characters.  Only the first
        :data:`_REQUEST_ID_MAX_LENGTH` characters are kept, and
        whitespace is stripped.
        """
        raw = request.headers.get("X-Request-ID", "").strip()
        if not raw:
            return None
        return raw[:_REQUEST_ID_MAX_LENGTH]
