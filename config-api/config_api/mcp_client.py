"""MCP HTTP client for calling MCP server tools from the config-api.

Uses JSON-RPC 2.0 over the MCP Streamable HTTP transport to call
tools on the MCP server without importing the full MCP SDK.
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

    def call_tool(
        self,
        tool_name: str,
        arguments: dict[str, Any] | None = None,
        timeout: int | None = None,
    ) -> dict[str, Any]:
        """Call an MCP tool and return the parsed JSON result.

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
        self._request_id += 1
        payload = {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": arguments or {},
            },
            "id": self._request_id,
        }

        effective_timeout = timeout or self._timeout

        try:
            with httpx.Client(timeout=effective_timeout) as client:
                response = client.post(
                    self._base_url,
                    json=payload,
                    headers={
                        "Content-Type": "application/json",
                        "Accept": "application/json",
                    },
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
