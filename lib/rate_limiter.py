"""
In-memory sliding-window rate limiter for the SSH MCP server.

Tracks request timestamps per client IP address using a thread-safe
``dict[str, deque[float]]`` structure.  Provides both a standalone
:class:`RateLimiter` class as well as ASGI middleware
(:class:`RateLimitMiddleware`) that integrates with Starlette.

Health-check endpoints (``/health``) are never rate-limited.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from lib.constants import (
    DEFAULT_RATE_LIMIT_REQUESTS,
    DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
    RATE_LIMIT_CLEANUP_INTERVAL_SECONDS,
)
from lib.exceptions import RateLimitError


class RateLimiter:
    """Sliding-window rate limiter keyed on a string identifier (e.g. IP).

    Parameters:
        max_requests: Maximum requests allowed within *window_seconds*.
        window_seconds: Duration of the sliding window in seconds.
        cleanup_interval: Minimum interval (seconds) between expired-entry
            cleanups.  Cleanup is triggered lazily on :meth:`check`.

    **Thread safety**: All mutable state is guarded by a single
    :class:`threading.Lock`.  Locks are held only for the duration of
    the in-memory operation, ensuring minimal contention.
    """

    def __init__(
        self,
        max_requests: int = DEFAULT_RATE_LIMIT_REQUESTS,
        window_seconds: float = DEFAULT_RATE_LIMIT_WINDOW_SECONDS,
        cleanup_interval: float = RATE_LIMIT_CLEANUP_INTERVAL_SECONDS,
    ) -> None:
        if max_requests < 1:
            raise ValueError("max_requests must be >= 1")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be > 0")
        self._max_requests: int = max_requests
        self._window_seconds: float = window_seconds
        self._cleanup_interval: float = cleanup_interval
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._lock: Lock = Lock()
        self._last_cleanup: float = time.monotonic()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check(self, key: str) -> bool:
        """Check whether a request for *key* is within the rate limit.

        Returns ``True`` if the request is **allowed**, or ``False`` if
        the limit has been exceeded.

        .. note::

            The call **always** records the current timestamp for *key*
            on success, so the caller only needs to act on the boolean
            return value.
        """
        now = time.monotonic()
        with self._lock:
            self._maybe_cleanup(now)
            bucket = self._buckets[key]
            self._prune_bucket(now, bucket)
            if len(bucket) >= self._max_requests:
                return False
            bucket.append(now)
            return True

    def check_and_raise(self, key: str) -> None:
        """Like :meth:`check` but raises :class:`~lib.exceptions.RateLimitError`
        when the limit is exceeded.
        """
        if not self.check(key):
            raise RateLimitError(
                f"Rate limit exceeded for {key}: "
                f"{self._max_requests} requests per "
                f"{self._window_seconds:.0f}s"
            )

    def is_allowed(self, key: str) -> bool:
        """Return ``True`` if a request for *key* would be allowed,
        **without** recording the request.

        Useful for pre-flight checks or inspecting state without
        consuming capacity.
        """
        now = time.monotonic()
        with self._lock:
            self._maybe_cleanup(now)
            bucket = self._buckets[key]
            self._prune_bucket(now, bucket)
            return len(bucket) < self._max_requests

    @property
    def max_requests(self) -> int:
        """Maximum requests allowed per window."""
        return self._max_requests

    @property
    def window_seconds(self) -> float:
        """Sliding-window duration in seconds."""
        return self._window_seconds

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _prune_bucket(self, now: float, bucket: deque[float]) -> None:
        """Remove timestamps from *bucket* that fall outside the window.

        Caller must hold :attr:`_lock`.
        """
        cutoff = now - self._window_seconds
        while bucket and bucket[0] < cutoff:
            bucket.popleft()

    def _maybe_cleanup(self, now: float) -> None:
        """Periodically remove keys whose buckets are empty to prevent
        unbounded memory growth from abandoned IP addresses.

        Caller must hold :attr:`_lock`.
        """
        if now - self._last_cleanup < self._cleanup_interval:
            return
        self._last_cleanup = now
        empty_keys: list[str] = []
        for key, bucket in self._buckets.items():
            self._prune_bucket(now, bucket)
            if not bucket:
                empty_keys.append(key)
        for key in empty_keys:
            del self._buckets[key]


class RateLimitMiddleware(BaseHTTPMiddleware):
    """ASGI middleware that enforces per-IP rate limiting.

    Parameters:
        rate_limiter: Configured :class:`RateLimiter` instance.
        exclude_paths: Set of URL paths to exclude from rate limiting
            (default: ``{"/health"}``).

    On rate-limit violation the middleware returns a ``429 Too Many
    Requests`` JSON response with a ``Retry-After`` header.
    """

    def __init__(
        self,
        app,
        rate_limiter: RateLimiter,
        exclude_paths: set[str] | None = None,
    ) -> None:
        super().__init__(app)
        self._rate_limiter: RateLimiter = rate_limiter
        self._exclude_paths: set[str] = exclude_paths or {"/health"}

    async def dispatch(self, request: Request, call_next):
        # --- Skip rate limiting for excluded paths ---
        if request.url.path in self._exclude_paths:
            return await call_next(request)

        # --- Extract client IP ---
        client_ip = self._extract_ip(request)

        # --- Check rate limit ---
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

        return await call_next(request)

    @staticmethod
    def _extract_ip(request: Request) -> str:
        """Extract client IP from the request.

        Checks ``X-Forwarded-For`` first, then falls back to the direct
        connection address.  Invalid values return ``"unknown"``.
        """
        import ipaddress

        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            raw_ip = forwarded.split(",")[0].strip()
        elif request.client is not None:
            raw_ip = request.client.host
        else:
            return "unknown"

        try:
            ipaddress.ip_address(raw_ip)
            return raw_ip
        except ValueError:
            return "unknown"
