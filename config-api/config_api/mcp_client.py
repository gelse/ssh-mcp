"""MCP HTTP client for calling MCP server tools from the config-api.

Uses JSON-RPC 2.0 over the MCP Streamable HTTP transport to call
tools on the MCP server without importing the full MCP SDK.

Protocol flow (per https://modelcontextprotocol.io/specification/2025-03-26/basic/transports#streamable-http):

1. ``initialize`` request  → server returns ``mcp-session-id`` header
2. ``notifications/initialized`` notification  → server returns 202
3. ``tools/call`` request with session header  → server returns tool result
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any

import httpx


logger = logging.getLogger("config_api.mcp_client")

# Default MCP server URL (Docker Compose internal DNS)
DEFAULT_MCP_SERVER_URL = "http://mcp-ssh:8080/mcp"

# MCP protocol header names
_MCP_SESSION_ID = "mcp-session-id"
_MCP_PROTOCOL_VERSION = "mcp-protocol-version"

# Default headers for all MCP requests
_DEFAULT_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
}


class MCPClientError(Exception):
    """Raised when the MCP client encounters a transport or protocol error."""


class MCPToolError(Exception):
    """Raised when an MCP tool returns an error response."""

    def __init__(
        self, message: str, tool_name: str, error_data: dict | None = None
    ) -> None:
        super().__init__(message)
        self.tool_name = tool_name
        self.error_data = error_data or {}


class MCPClient:
    """Lightweight JSON-RPC 2.0 client for the MCP Streamable HTTP transport.

    Manages the MCP session lifecycle automatically: the first call to
    :meth:`call_tool` performs the ``initialize`` handshake, captures the
    ``mcp-session-id`` header, and sends the ``notifications/initialized``
    notification before executing the actual tool call.

    Args:
        base_url: The MCP server endpoint URL.  Falls back to the
            ``MCP_SERVER_URL`` environment variable, then the Docker
            Compose internal DNS default.
        timeout: HTTP request timeout in seconds.
    """

    def __init__(
        self,
        base_url: str | None = None,
        timeout: int = 30,
    ) -> None:
        self._base_url = (
            base_url
            or os.environ.get("MCP_SERVER_URL")
            or DEFAULT_MCP_SERVER_URL
        )
        self._timeout = timeout
        self._request_id = 0
        self._session_id: str | None = None
        self._protocol_version: str | None = None

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _next_id(self) -> int:
        """Return the next JSON-RPC request id."""
        self._request_id += 1
        return self._request_id

    def _headers(self) -> dict[str, str]:
        """Build request headers including the session id when available."""
        headers = dict(_DEFAULT_HEADERS)
        if self._session_id:
            headers[_MCP_SESSION_ID] = self._session_id
        if self._protocol_version:
            headers[_MCP_PROTOCOL_VERSION] = self._protocol_version
        return headers

    def _initialize(self, timeout: int | None = None) -> None:
        """Perform the MCP ``initialize`` handshake.

        Sends an ``initialize`` request, captures the ``mcp-session-id``
        and ``mcp-protocol-version`` from the response headers, then sends
        the ``notifications/initialized`` notification.
        """
        effective_timeout = timeout or self._timeout
        payload = {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2025-03-26",
                "capabilities": {},
                "clientInfo": {
                    "name": "mcp-ssh-config-api",
                    "version": "1.0.0",
                },
            },
            "id": self._next_id(),
        }

        try:
            with httpx.Client(timeout=effective_timeout) as client:
                response = client.post(
                    self._base_url,
                    json=payload,
                    headers=_DEFAULT_HEADERS,
                )
                response.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise MCPClientError(
                f"MCP initialize failed with HTTP {e.response.status_code}: "
                f"{e.response.text[:200]}"
            ) from e
        except httpx.RequestError as e:
            raise MCPClientError(
                f"Failed to connect to MCP server at {self._base_url}: {e}"
            ) from e

        # Capture session id from response headers
        new_session_id = response.headers.get(_MCP_SESSION_ID)
        if new_session_id:
            self._session_id = new_session_id
            logger.debug("MCP session established: %s", self._session_id)

        # Capture protocol version from response headers
        new_protocol_version = response.headers.get(_MCP_PROTOCOL_VERSION)
        if new_protocol_version:
            self._protocol_version = new_protocol_version

        # Parse the initialize response to extract server capabilities
        # (informational — we don't use them yet)
        try:
            rpc_response = response.json()
        except json.JSONDecodeError as e:
            raise MCPClientError(
                f"Invalid JSON in initialize response: {response.text[:200]}"
            ) from e

        if "error" in rpc_response:
            error = rpc_response["error"]
            raise MCPClientError(
                f"MCP initialize error: {error.get('message', 'Unknown error')}"
            )

        # Send the notifications/initialized notification (no response expected)
        self._send_notification("notifications/initialized", timeout=effective_timeout)

    def _send_notification(
        self, method: str, params: dict[str, Any] | None = None, timeout: int | None = None
    ) -> None:
        """Send a JSON-RPC notification (no ``id``, no response expected)."""
        effective_timeout = timeout or self._timeout
        payload: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
        }
        if params:
            payload["params"] = params

        try:
            with httpx.Client(timeout=effective_timeout) as client:
                response = client.post(
                    self._base_url,
                    json=payload,
                    headers=self._headers(),
                )
                # Notifications should return 202 Accepted; any 2xx is acceptable
                if response.status_code >= 400:
                    logger.warning(
                        "MCP notification '%s' returned HTTP %d: %s",
                        method,
                        response.status_code,
                        response.text[:100],
                    )
        except httpx.RequestError as e:
            logger.warning("Failed to send MCP notification '%s': %s", method, e)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        """Call an MCP tool and return the parsed JSON result.

        On the first call, the client performs the ``initialize`` handshake
        automatically before executing the tool.

        Args:
            tool_name: Name of the MCP tool to call.
            arguments: Arguments to pass to the tool.
            timeout: Optional per-call timeout override in seconds.

        Returns:
            Parsed JSON dict from the tool's ``result.content[0].text``.

        Raises:
            MCPClientError: On transport or protocol errors.
            MCPToolError: When the tool returns a JSON-RPC error.
        """
        # Ensure we have an established session
        if self._session_id is None:
            self._initialize(timeout=timeout)

        effective_timeout = timeout or self._timeout
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments or {},
            },
            "id": self._next_id(),
        }

        try:
            with httpx.Client(timeout=effective_timeout) as client:
                response = client.post(
                    self._base_url,
                    json=payload,
                    headers=self._headers(),
                )
                response.raise_for_status()
        except httpx.HTTPStatusError as e:
            raise MCPClientError(
                f"MCP server returned HTTP {e.response.status_code}: "
                f"{e.response.text[:200]}"
            ) from e
        except httpx.RequestError as e:
            raise MCPClientError(
                f"Failed to connect to MCP server at {self._base_url}: {e}"
            ) from e

        # Parse JSON-RPC response
        try:
            rpc_response = response.json()
        except json.JSONDecodeError as e:
            raise MCPClientError(
                f"Invalid JSON response from MCP server: {response.text[:200]}"
            ) from e

        # Check for JSON-RPC error
        if "error" in rpc_response:
            error = rpc_response["error"]
            raise MCPToolError(
                message=error.get("message", "Unknown MCP error"),
                tool_name=tool_name,
                error_data=error,
            )

        # Extract tool result from MCP response envelope
        result = rpc_response.get("result", {})
        contents = result.get("content", [])

        if not contents:
            raise MCPClientError(
                f"MCP tool '{tool_name}' returned empty result"
            )

        # The tool result is in content[0].text as a JSON string
        text = contents[0].get("text", "")
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # If not JSON, wrap in a simple dict
            return {"output": text, "success": True}
