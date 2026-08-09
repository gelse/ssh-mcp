"""Unit tests for :mod:`lib.health` — the GET /health endpoint.

Covers ``attach_health_endpoint()`` registration behaviour (via a mock
FastMCP object) and the resulting HTTP semantics (200 on GET, 405 on
POST) using a minimal Starlette app that mirrors how FastMCP wires the
``custom_route`` handler into its ASGI app.
"""

from __future__ import annotations

import asyncio
import json
from unittest.mock import MagicMock

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Route
from starlette.testclient import TestClient

from lib.health import attach_health_endpoint


class TestAttachHealthEndpoint:
    """Tests for attach_health_endpoint() registration and behaviour."""

    def test_registers_health_route_via_custom_route(self):
        """The endpoint is registered through custom_route with GET only."""
        mcp = MagicMock()
        attach_health_endpoint(mcp)

        mcp.custom_route.assert_called_once_with("/health", methods=["GET"])
        decorator = mcp.custom_route.return_value
        decorator.assert_called_once()
        handler = decorator.call_args.args[0]
        assert callable(handler)

    def test_health_returns_ok_on_get(self):
        """GET /health returns 200 with JSON body ``{"status": "ok"}``."""
        client = TestClient(self._build_app())
        resp = client.get("/health")

        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("application/json")
        assert resp.json() == {"status": "ok"}

    def test_health_rejects_post_with_405(self):
        """POST /health returns 405 Method Not Allowed (route is GET-only)."""
        client = TestClient(self._build_app())
        resp = client.post("/health")

        assert resp.status_code == 405

    def test_handler_returns_json_response(self):
        """The registered handler returns a JSONResponse with status 200."""
        mcp = MagicMock()
        attach_health_endpoint(mcp)
        handler = mcp.custom_route.return_value.call_args.args[0]

        resp = asyncio.run(handler(MagicMock(spec=Request)))

        assert resp.status_code == 200
        assert json.loads(resp.body) == {"status": "ok"}

    @staticmethod
    def _build_app() -> Starlette:
        """Build a minimal Starlette app with the health route attached.

        Mirrors how FastMCP 3.x registers the ``custom_route`` handler:
        the decorated callable becomes the ASGI endpoint for ``/health``
        with the ``GET`` method restriction.
        """
        mcp = MagicMock()
        attach_health_endpoint(mcp)
        handler = mcp.custom_route.return_value.call_args.args[0]
        return Starlette(routes=[Route("/health", handler, methods=["GET"])])


class TestHealthCheckResultType:
    """Sanity checks for the ``HealthCheckResult`` TypedDict in lib.types."""

    def test_required_keys_are_declared(self):
        """HealthCheckResult declares 'status' and 'server_count' keys."""
        from typing import get_type_hints

        from lib.types import HealthCheckResult

        hints = get_type_hints(HealthCheckResult)
        assert "status" in hints
        assert "server_count" in hints
        assert hints["status"] is str
        assert hints["server_count"] is int

    def test_dict_conforms_to_structure(self):
        """A dict with the required keys is a valid HealthCheckResult value."""
        from lib.types import HealthCheckResult

        result: HealthCheckResult = {"status": "ok", "server_count": 2}
        assert result["status"] == "ok"
        assert result["server_count"] == 2
