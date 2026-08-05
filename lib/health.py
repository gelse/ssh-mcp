"""
HTTP health-check endpoint for the SSH MCP server.

Attaches a /health route to a FastMCP instance by patching
the underlying Starlette app.
"""

from starlette.requests import Request
from starlette.responses import JSONResponse


def attach_health_endpoint(mcp):
    """
    Add a GET /health endpoint to the FastMCP server.

    This works with streamable HTTP transport by adding a route
    directly to the FastMCP's internal Starlette ASGI app.
    """

    async def health(request: Request):
        return JSONResponse({"status": "ok"})

    # FastMCP stores the Starlette app at mcp._mcp._streamable_http_app
    # Access varies by version; try multiple known paths
    app = None
    for attr in ("_mcp", "_streamable_http_app"):
        # FastMCP >= 2.x structure
        inner = getattr(mcp, "_mcp", None)
        if inner is not None:
            app = getattr(inner, "_streamable_http_app", None)
            if app is not None:
                break
        # Fallback: try directly on mcp
        app = getattr(mcp, "_streamable_http_app", None)
        if app is not None:
            break
        # Alternate: _app attribute
        app = getattr(mcp, "_app", None)
        if app is not None:
            break

    if app is None:
        # Last resort: iterate __dict__
        for attr_name in dir(mcp):
            try:
                candidate = getattr(mcp, attr_name)
            except RuntimeError:
                # Some properties (e.g., session_manager) raise
                # RuntimeError before streamable_http_app() is called.
                continue
            if hasattr(candidate, "add_route"):
                app = candidate
                break

    if app is not None and hasattr(app, "add_route"):
        app.add_route("/health", health, methods=["GET"])
    else:
        import logging
        logging.getLogger(__name__).warning(
            "Could not attach /health endpoint: Starlette app not found"
        )
