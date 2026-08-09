"""
HTTP health-check endpoint for the SSH MCP server.

Uses FastMCP 3.x's ``custom_route`` decorator to register a
GET /health endpoint that returns {"status": "ok"}.
"""

import datetime

from starlette.requests import Request
from starlette.responses import JSONResponse

from lib.constants import LOG_FORMAT_VERSION
from lib.loggers import BaseLogger


def attach_health_endpoint(mcp, logger: BaseLogger | None = None, connection_pool=None):
    """
    Register a GET /health endpoint on the FastMCP server.

    Uses FastMCP 3.x's ``custom_route`` decorator API, which
    adds the route directly to the underlying Starlette app
    during ``http_app()`` construction.

    When *logger* (a :class:`BaseLogger`) is provided, every request
    to the endpoint emits a structured ``health.check`` event.

    When *connection_pool* (an :class:`~lib.connection_pool.SSHConnectionPool`)
    is provided, the response includes a ``connection_pool`` object with
    the pool's aggregate statistics (active/idle connections, total
    created, limits).
    """

    @mcp.custom_route("/health", methods=["GET"])
    async def health(request: Request):
        payload = {"status": "ok"}
        if connection_pool is not None:
            payload["connection_pool"] = connection_pool.stats()
        if logger is not None:
            from lib.request_context import get_request_id

            logger.log(
                {
                    "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "event": "health.check",
                    "level": "INFO",
                    "status": "ok",
                    "request_id": get_request_id(),
                    "log_level": "INFO",
                    "log_format_version": LOG_FORMAT_VERSION,
                }
            )
        return JSONResponse(payload)
