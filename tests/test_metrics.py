"""Unit tests for :mod:`lib.metrics` — the /metrics Prometheus endpoint.

Covers ``attach_metrics_endpoint()`` registration behaviour (via a mock
FastMCP object) and the resulting HTTP semantics (200 on GET with
Prometheus exposition text, 204 on OPTIONS with CORS preflight headers)
using a minimal Starlette app that mirrors how FastMCP wires the
``custom_route`` handler into its ASGI app.
"""

from __future__ import annotations

from unittest.mock import MagicMock

from prometheus_client import CONTENT_TYPE_LATEST
from starlette.applications import Starlette
from starlette.routing import Route
from starlette.testclient import TestClient

from lib.metrics import (
    AUTH_DENIALS_TOTAL,
    COMMAND_DURATION_SECONDS,
    REGISTRY,
    REQUESTS_TOTAL,
    SSH_CONNECTION_DURATION_SECONDS,
    SSH_CONNECTIONS_TOTAL,
    attach_metrics_endpoint,
)


class TestAttachMetricsEndpoint:
    """Tests for attach_metrics_endpoint() registration and behaviour."""

    def test_registers_metrics_route_via_custom_route(self):
        """The endpoint is registered through custom_route with GET + OPTIONS."""
        mcp = MagicMock()
        attach_metrics_endpoint(mcp)

        mcp.custom_route.assert_called_once_with(
            "/metrics", methods=["GET", "OPTIONS"]
        )
        decorator = mcp.custom_route.return_value
        decorator.assert_called_once()
        handler = decorator.call_args.args[0]
        assert callable(handler)

    def test_metrics_returns_prometheus_text_on_get(self):
        """GET /metrics returns 200 with Prometheus exposition format."""
        client = TestClient(self._build_app())
        resp = client.get("/metrics")

        assert resp.status_code == 200
        assert resp.headers["content-type"] == CONTENT_TYPE_LATEST
        body = resp.text
        # Every mcpssh_* metric is declared with HELP and TYPE lines.
        assert "# HELP mcpssh_requests_total" in body
        assert "# TYPE mcpssh_requests_total counter" in body
        assert "mcpssh_ssh_connections_total" in body
        assert "mcpssh_ssh_connection_duration_seconds" in body
        assert "mcpssh_auth_denials_total" in body
        assert "mcpssh_command_duration_seconds" in body

    def test_metrics_options_returns_204_with_cors_headers(self):
        """OPTIONS /metrics returns 204 and CORS preflight headers."""
        client = TestClient(self._build_app())
        resp = client.options("/metrics")

        assert resp.status_code == 204
        assert resp.headers["allow"] == "GET, OPTIONS"
        assert resp.headers["access-control-allow-origin"] == "*"
        assert resp.headers["access-control-allow-methods"] == "GET, OPTIONS"
        assert resp.headers["access-control-allow-headers"] == (
            "Content-Type, Authorization"
        )

    def test_metrics_rejects_post_with_405(self):
        """POST /metrics returns 405 (route is GET/OPTIONS only)."""
        client = TestClient(self._build_app())
        resp = client.post("/metrics")

        assert resp.status_code == 405

    @staticmethod
    def _build_app() -> Starlette:
        """Build a minimal Starlette app with the metrics route attached.

        Mirrors how FastMCP 3.x registers the ``custom_route`` handler:
        the decorated callable becomes the ASGI endpoint for ``/metrics``
        with the ``GET`` and ``OPTIONS`` method restrictions.
        """
        mcp = MagicMock()
        attach_metrics_endpoint(mcp)
        handler = mcp.custom_route.return_value.call_args.args[0]
        return Starlette(
            routes=[Route("/metrics", handler, methods=["GET", "OPTIONS"])]
        )


class TestMetricsDefinitions:
    """Sanity checks for the registered ``mcpssh_*`` metrics.

    Each test uses a unique label value so counter/histogram assertions are
    isolated from other tests sharing the module-level registry.
    """

    def test_request_counter_increments(self):
        """REQUESTS_TOTAL counts tool calls per status label."""
        tool = "unit-test-requests"
        REQUESTS_TOTAL.labels(tool=tool, status="success").inc()
        REQUESTS_TOTAL.labels(tool=tool, status="success").inc()

        value = REGISTRY.get_sample_value(
            "mcpssh_requests_total",
            {"tool": tool, "status": "success"},
        )
        assert value == 2.0

    def test_ssh_connection_counter_increments(self):
        """SSH_CONNECTIONS_TOTAL counts successful connections per target."""
        target = "unit-test-target-conns"
        SSH_CONNECTIONS_TOTAL.labels(target=target).inc()

        value = REGISTRY.get_sample_value(
            "mcpssh_ssh_connections_total", {"target": target}
        )
        assert value == 1.0

    def test_auth_denials_counter_increments(self):
        """AUTH_DENIALS_TOTAL counts denials per reason."""
        reason = "unit-test-reason"
        AUTH_DENIALS_TOTAL.labels(reason=reason).inc()
        AUTH_DENIALS_TOTAL.labels(reason=reason).inc()
        AUTH_DENIALS_TOTAL.labels(reason=reason).inc()

        value = REGISTRY.get_sample_value(
            "mcpssh_auth_denials_total", {"reason": reason}
        )
        assert value == 3.0

    def test_ssh_connection_duration_histogram_observes(self):
        """SSH_CONNECTION_DURATION_SECONDS tracks establishment latency."""
        target = "unit-test-target-latency"
        SSH_CONNECTION_DURATION_SECONDS.labels(target=target).observe(0.5)

        count = REGISTRY.get_sample_value(
            "mcpssh_ssh_connection_duration_seconds_count",
            {"target": target},
        )
        total = REGISTRY.get_sample_value(
            "mcpssh_ssh_connection_duration_seconds_sum",
            {"target": target},
        )
        assert count == 1.0
        assert total == 0.5

    def test_command_duration_histogram_observes(self):
        """COMMAND_DURATION_SECONDS tracks command execution time."""
        target = "unit-test-target-cmd"
        COMMAND_DURATION_SECONDS.labels(target=target).observe(1.5)

        count = REGISTRY.get_sample_value(
            "mcpssh_command_duration_seconds_count", {"target": target}
        )
        total = REGISTRY.get_sample_value(
            "mcpssh_command_duration_seconds_sum", {"target": target}
        )
        assert count == 1.0
        assert total == 1.5
