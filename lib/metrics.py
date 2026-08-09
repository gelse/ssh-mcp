"""
Prometheus metrics for the SSH MCP server.

Defines a dedicated :class:`~prometheus_client.CollectorRegistry` holding
the server's counters and histograms, plus an ``attach_metrics_endpoint``
helper that registers GET /metrics (and OPTIONS /metrics for CORS) on a
FastMCP 3.x server via ``custom_route``.

The registry is deliberately separate from the default registry so tests
can construct metrics without colliding with pre-registered metric names.
"""

from __future__ import annotations

from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from starlette.requests import Request
from starlette.responses import Response

# ---------------------------------------------------------------------------
# Registry + metrics (module-level singletons, registered once)
# ---------------------------------------------------------------------------

REGISTRY = CollectorRegistry()
"""Dedicated registry holding all ``mcpssh_*`` metrics."""

REQUESTS_TOTAL = Counter(
    "mcpssh_requests_total",
    "Total number of MCP tool requests processed.",
    labelnames=("tool", "status"),
    registry=REGISTRY,
)

SSH_CONNECTIONS_TOTAL = Counter(
    "mcpssh_ssh_connections_total",
    "Total number of successful SSH connections established.",
    labelnames=("target",),
    registry=REGISTRY,
)

SSH_CONNECTION_DURATION_SECONDS = Histogram(
    "mcpssh_ssh_connection_duration_seconds",
    "Duration of SSH connections in seconds (establishment latency).",
    labelnames=("target",),
    registry=REGISTRY,
)

AUTH_DENIALS_TOTAL = Counter(
    "mcpssh_auth_denials_total",
    "Total number of authorization denials.",
    labelnames=("reason",),
    registry=REGISTRY,
)

COMMAND_DURATION_SECONDS = Histogram(
    "mcpssh_command_duration_seconds",
    "Duration of remote command executions in seconds.",
    labelnames=("target",),
    registry=REGISTRY,
)

SSH_POOL_ACTIVE_CONNECTIONS = Gauge(
    "mcpssh_pool_active_connections",
    "Number of SSH connections currently checked out of the pool per target.",
    labelnames=("target",),
    registry=REGISTRY,
)

SSH_POOL_IDLE_CONNECTIONS = Gauge(
    "mcpssh_pool_idle_connections",
    "Number of idle (reusable) SSH connections kept in the pool per target.",
    labelnames=("target",),
    registry=REGISTRY,
)

SSH_POOL_CREATED_TOTAL = Counter(
    "mcpssh_pool_created_total",
    "Total number of SSH connections created by the pool per target.",
    labelnames=("target",),
    registry=REGISTRY,
)


def attach_metrics_endpoint(mcp) -> None:
    """
    Register GET /metrics (and OPTIONS /metrics for CORS) on *mcp*.

    Uses FastMCP 3.x's ``custom_route`` decorator API, which adds the
    route directly to the underlying Starlette app during
    ``http_app()`` construction.
    """

    @mcp.custom_route("/metrics", methods=["GET", "OPTIONS"])
    async def metrics(request: Request):
        if request.method == "OPTIONS":
            return Response(
                status_code=204,
                headers={
                    "Allow": "GET, OPTIONS",
                    "Access-Control-Allow-Origin": "*",
                    "Access-Control-Allow-Methods": "GET, OPTIONS",
                    "Access-Control-Allow-Headers": "Content-Type, Authorization",
                },
            )
        body = generate_latest(REGISTRY)
        return Response(
            content=body,
            media_type=CONTENT_TYPE_LATEST,
        )
