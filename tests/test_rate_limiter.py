"""Unit tests for :mod:`lib.rate_limiter`.

Covers :class:`RateLimiter` and :class:`RateLimitMiddleware`.
"""

from __future__ import annotations

import time
from unittest.mock import patch

import pytest
from starlette.requests import Request
from starlette.responses import Response
from starlette.testclient import TestClient

from lib.constants import DEFAULT_RATE_LIMIT_REQUESTS, DEFAULT_RATE_LIMIT_WINDOW_SECONDS
from lib.exceptions import RateLimitError
from lib.rate_limiter import RateLimiter, RateLimitMiddleware


# ---------------------------------------------------------------------------
# RateLimiter — basic behaviour
# ---------------------------------------------------------------------------


class TestRateLimiterBasic:
    """Tests for the core RateLimiter sliding-window logic."""

    def test_requests_within_limit_succeed(self):
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        key = "192.168.1.1"
        for _ in range(5):
            assert limiter.check(key) is True

    def test_requests_exceeding_limit_fail(self):
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        key = "192.168.1.1"
        for _ in range(3):
            assert limiter.check(key) is True
        # 4th request should be denied
        assert limiter.check(key) is False

    def test_check_and_raise_raises_on_exceed(self):
        limiter = RateLimiter(max_requests=1, window_seconds=60)
        key = "10.0.0.1"
        limiter.check_and_raise(key)  # consumes the only slot
        with pytest.raises(RateLimitError, match="Rate limit exceeded"):
            limiter.check_and_raise(key)

    def test_different_ips_have_independent_limits(self):
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        assert limiter.check("1.1.1.1") is True
        assert limiter.check("1.1.1.1") is True
        assert limiter.check("1.1.1.1") is False  # IP 1 exhausted

        # IP 2 still has full quota
        assert limiter.check("2.2.2.2") is True
        assert limiter.check("2.2.2.2") is True

    def test_is_allowed_does_not_consume_capacity(self):
        limiter = RateLimiter(max_requests=1, window_seconds=60)
        key = "10.0.0.1"
        # Pre-flight check should not record anything
        assert limiter.is_allowed(key) is True
        assert limiter.is_allowed(key) is True
        # Actual check consumes the slot
        assert limiter.check(key) is True
        assert limiter.is_allowed(key) is False

    def test_constructor_rejects_invalid_params(self):
        with pytest.raises(ValueError, match="max_requests"):
            RateLimiter(max_requests=0)
        with pytest.raises(ValueError, match="max_requests"):
            RateLimiter(max_requests=-1)
        with pytest.raises(ValueError, match="window_seconds"):
            RateLimiter(window_seconds=0)
        with pytest.raises(ValueError, match="window_seconds"):
            RateLimiter(window_seconds=-5)


# ---------------------------------------------------------------------------
# RateLimiter — sliding window & cleanup
# ---------------------------------------------------------------------------


class TestRateLimiterWindowAndCleanup:
    """Tests for window expiry and garbage collection."""

    def test_window_resets_after_time_passes(self):
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        key = "1.2.3.4"
        with patch.object(time, "monotonic", return_value=100.0):
            limiter.check(key)
            limiter.check(key)
            assert limiter.check(key) is False  # exhausted

        # Advance time past the window
        with patch.object(time, "monotonic", return_value=161.0):
            # Old entries should be pruned; fresh quota available
            assert limiter.check(key) is True
            assert limiter.check(key) is True

    def test_cleanup_removes_stale_entries(self):
        # Create the limiter under a mock so that _last_cleanup starts at 0.
        with patch.object(time, "monotonic", return_value=0.0):
            limiter = RateLimiter(
                max_requests=2,
                window_seconds=60,
                cleanup_interval=10,
            )
            limiter.check("1.1.1.1")
            limiter.check("2.2.2.2")

        # After cleanup interval + window, entries should be gone
        with patch.object(time, "monotonic", return_value=100.0):
            # Access triggers cleanup
            limiter.check("3.3.3.3")
            # Old entries should have been pruned
            with limiter._lock:
                assert "1.1.1.1" not in limiter._buckets
                assert "2.2.2.2" not in limiter._buckets


# ---------------------------------------------------------------------------
# RateLimiter — thread safety
# ---------------------------------------------------------------------------


class TestRateLimiterThreadSafety:
    """Verify concurrent access does not corrupt state."""

    def test_concurrent_checks_dont_crash(self):
        import threading

        limiter = RateLimiter(max_requests=100, window_seconds=60)
        errors: list[Exception] = []

        def hammer(ip: str, n: int) -> None:
            try:
                for _ in range(n):
                    limiter.check(ip)
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=hammer, args=(f"10.0.{i}.1", 50))
            for i in range(10)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread-safety errors: {errors}"

    def test_concurrent_is_allowed_doesnt_crash(self):
        import threading

        limiter = RateLimiter(max_requests=5, window_seconds=60)
        errors: list[Exception] = []

        def read_check(ip: str, n: int) -> None:
            try:
                for _ in range(n):
                    limiter.is_allowed(ip)
            except Exception as exc:
                errors.append(exc)

        threads = [
            threading.Thread(target=read_check, args=(f"192.168.{i}.1", 30))
            for i in range(10)
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Thread-safety errors: {errors}"


# ---------------------------------------------------------------------------
# RateLimitMiddleware — ASGI behaviour
# ---------------------------------------------------------------------------


class TestRateLimitMiddleware:
    """Tests for the RateLimitMiddleware ASGI middleware via TestClient."""

    @staticmethod
    def _build_app(
        limiter: RateLimiter, exclude_paths: set[str] | None = None
    ) -> TestClient:
        from starlette.applications import Starlette
        from starlette.middleware import Middleware
        from starlette.routing import Route

        async def endpoint(request: Request) -> Response:
            return Response("ok", status_code=200)

        app = Starlette(
            routes=[
                Route("/mcp", endpoint, methods=["GET"]),
                Route("/health", endpoint, methods=["GET"]),
                Route("/custom", endpoint, methods=["GET"]),
            ],
            middleware=[
                Middleware(
                    RateLimitMiddleware,
                    rate_limiter=limiter,
                    exclude_paths=exclude_paths,
                )
            ],
        )
        return TestClient(app, raise_server_exceptions=False)

    def test_normal_request_passes_through(self):
        limiter = RateLimiter(max_requests=10, window_seconds=60)
        client = self._build_app(limiter)

        r = client.get("/mcp", headers={"X-Forwarded-For": "1.2.3.4"})
        assert r.status_code == 200

    def test_rate_limited_returns_429(self):
        limiter = RateLimiter(max_requests=1, window_seconds=60)
        client = self._build_app(limiter)
        headers = {"X-Forwarded-For": "5.5.5.5"}

        # First request passes
        r1 = client.get("/mcp", headers=headers)
        assert r1.status_code == 200

        # Second request exceeds the limit
        r2 = client.get("/mcp", headers=headers)
        assert r2.status_code == 429
        assert "Retry-After" in r2.headers

    def test_health_endpoint_not_rate_limited(self):
        limiter = RateLimiter(max_requests=1, window_seconds=60)
        client = self._build_app(limiter)

        # Same IP, same minute — but /health is excluded
        for _ in range(5):
            r = client.get("/health", headers={"X-Forwarded-For": "9.9.9.9"})
            assert r.status_code == 200

    def test_mcp_path_is_rate_limited(self):
        limiter = RateLimiter(max_requests=1, window_seconds=60)
        client = self._build_app(limiter)
        headers = {"X-Forwarded-For": "8.8.8.8"}

        # First request passes
        assert client.get("/mcp", headers=headers).status_code == 200
        # Second request exceeds the limit
        assert client.get("/mcp", headers=headers).status_code == 429

    def test_custom_exclude_paths(self):
        limiter = RateLimiter(max_requests=1, window_seconds=60)
        client = self._build_app(limiter, exclude_paths={"/health", "/custom"})
        headers = {"X-Forwarded-For": "6.6.6.6"}

        # /custom should be excluded, so it always passes
        assert client.get("/custom", headers=headers).status_code == 200
        assert client.get("/custom", headers=headers).status_code == 200


# ---------------------------------------------------------------------------
# RequestContextMiddleware with rate limiter
# ---------------------------------------------------------------------------


class TestRequestContextWithRateLimiter:
    """Verify RequestContextMiddleware's integrated rate-limiter behavior."""

    def test_middleware_429_on_limit_exceeded_via_testclient(self):
        """End-to-end: RequestContextMiddleware returns 429 when rate-limited."""
        from lib.request_context import RequestContextMiddleware
        from starlette.middleware import Middleware

        limiter = RateLimiter(max_requests=2, window_seconds=60)

        from starlette.applications import Starlette
        from starlette.routing import Route

        async def endpoint(request: Request) -> Response:
            return Response("ok", status_code=200)

        app = Starlette(
            routes=[Route("/mcp", endpoint, methods=["GET"])],
            middleware=[
                Middleware(RequestContextMiddleware, rate_limiter=limiter)
            ],
        )

        client = TestClient(app, raise_server_exceptions=False)

        r1 = client.get("/mcp", headers={"X-Forwarded-For": "1.1.1.1"})
        assert r1.status_code == 200

        r2 = client.get("/mcp", headers={"X-Forwarded-For": "1.1.1.1"})
        assert r2.status_code == 200

        r3 = client.get("/mcp", headers={"X-Forwarded-For": "1.1.1.1"})
        assert r3.status_code == 429
        assert "Retry-After" in r3.headers

    def test_health_endpoint_not_rate_limited_via_testclient(self):
        """Health check passes through even when rate limit is exhausted."""
        from lib.request_context import RequestContextMiddleware
        from starlette.middleware import Middleware

        limiter = RateLimiter(max_requests=1, window_seconds=60)

        from starlette.applications import Starlette
        from starlette.routing import Route

        async def endpoint(request: Request) -> Response:
            return Response("ok", status_code=200)

        app = Starlette(
            routes=[Route("/health", endpoint, methods=["GET"])],
            middleware=[
                Middleware(RequestContextMiddleware, rate_limiter=limiter)
            ],
        )

        client = TestClient(app, raise_server_exceptions=False)

        for _ in range(5):
            r = client.get("/health", headers={"X-Forwarded-For": "1.1.1.1"})
            assert r.status_code == 200


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------


def test_default_limits_are_reasonable():
    limiter = RateLimiter()
    assert limiter.max_requests == DEFAULT_RATE_LIMIT_REQUESTS
    assert limiter.window_seconds == DEFAULT_RATE_LIMIT_WINDOW_SECONDS
