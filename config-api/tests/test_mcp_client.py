"""Tests for config_api.mcp_client — lightweight JSON-RPC 2.0 client for MCP tools."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest

from config_api.mcp_client import MCPClient, MCPClientError, MCPToolError


def _make_jsonrpc_response(text: str, request_id: int = 1) -> dict:
    """Build a minimal JSON-RPC 2.0 success response wrapping MCP tool output."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [{"type": "text", "text": text}],
        },
    }


def _make_jsonrpc_error(
    message: str, code: int = -32603, request_id: int = 1
) -> dict:
    """Build a JSON-RPC 2.0 error response."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


class TestMCPClient:
    """Tests for MCPClient.call_tool()."""

    def test_call_tool_success(self) -> None:
        """Successful tool call returns parsed JSON from the MCP response."""
        tool_result = {
            "success": True,
            "output": "pong",
            "error": None,
            "exit_code": 0,
            "checkcommand": "echo ping",
        }
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = _make_jsonrpc_response(
            json.dumps(tool_result)
        )

        client = MCPClient(base_url="http://localhost:8080/mcp")
        with patch("config_api.mcp_client.httpx.Client") as MockHTTP:
            mock_http_instance = MagicMock()
            mock_http_instance.post.return_value = mock_response
            mock_http_instance.__enter__ = MagicMock(return_value=mock_http_instance)
            mock_http_instance.__exit__ = MagicMock(return_value=False)
            MockHTTP.return_value = mock_http_instance

            result = client.call_tool(
                "ssh_check_connection",
                arguments={"server_name": "test-server", "timeout": 10},
            )

        assert result == tool_result
        mock_http_instance.post.assert_called_once()
        call_args = mock_http_instance.post.call_args
        assert call_args[0][0] == "http://localhost:8080/mcp"
        payload = call_args[1]["json"]
        assert payload["jsonrpc"] == "2.0"
        assert payload["method"] == "tools/call"
        assert payload["params"]["name"] == "ssh_check_connection"
        assert payload["params"]["arguments"]["server_name"] == "test-server"

    def test_call_tool_json_rpc_error(self) -> None:
        """JSON-RPC error response raises MCPToolError."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = _make_jsonrpc_error(
            "Server 'unknown' not found"
        )

        client = MCPClient(base_url="http://localhost:8080/mcp")
        with patch("config_api.mcp_client.httpx.Client") as MockHTTP:
            mock_http_instance = MagicMock()
            mock_http_instance.post.return_value = mock_response
            mock_http_instance.__enter__ = MagicMock(return_value=mock_http_instance)
            mock_http_instance.__exit__ = MagicMock(return_value=False)
            MockHTTP.return_value = mock_http_instance

            with pytest.raises(MCPToolError, match="Server 'unknown' not found"):
                client.call_tool("ssh_check_connection", arguments={"server_name": "unknown"})

    def test_call_tool_http_error(self) -> None:
        """HTTP status error raises MCPClientError."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_response.text = "Internal Server Error"
        mock_response.raise_for_status.side_effect = httpx.HTTPStatusError(
            "Server Error",
            request=MagicMock(),
            response=mock_response,
        )

        client = MCPClient(base_url="http://localhost:8080/mcp")
        with patch("config_api.mcp_client.httpx.Client") as MockHTTP:
            mock_http_instance = MagicMock()
            mock_http_instance.post.return_value = mock_response
            mock_http_instance.__enter__ = MagicMock(return_value=mock_http_instance)
            mock_http_instance.__exit__ = MagicMock(return_value=False)
            MockHTTP.return_value = mock_http_instance

            with pytest.raises(MCPClientError, match="HTTP 500"):
                client.call_tool("ssh_check_connection")

    def test_call_tool_connection_error(self) -> None:
        """Connection error raises MCPClientError."""
        mock_response = MagicMock()
        mock_response.raise_for_status.side_effect = httpx.ConnectError(
            "Connection refused"
        )

        client = MCPClient(base_url="http://localhost:8080/mcp")
        with patch("config_api.mcp_client.httpx.Client") as MockHTTP:
            mock_http_instance = MagicMock()
            mock_http_instance.post.return_value = mock_response
            mock_http_instance.__enter__ = MagicMock(return_value=mock_http_instance)
            mock_http_instance.__exit__ = MagicMock(return_value=False)
            MockHTTP.return_value = mock_http_instance

            with pytest.raises(MCPClientError, match="Failed to connect"):
                client.call_tool("ssh_check_connection")

    def test_call_tool_invalid_json(self) -> None:
        """Non-JSON response body raises MCPClientError."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.text = "not json"
        mock_response.json.side_effect = json.JSONDecodeError("Expecting value", "", 0)

        client = MCPClient(base_url="http://localhost:8080/mcp")
        with patch("config_api.mcp_client.httpx.Client") as MockHTTP:
            mock_http_instance = MagicMock()
            mock_http_instance.post.return_value = mock_response
            mock_http_instance.__enter__ = MagicMock(return_value=mock_http_instance)
            mock_http_instance.__exit__ = MagicMock(return_value=False)
            MockHTTP.return_value = mock_http_instance

            with pytest.raises(MCPClientError, match="Invalid JSON"):
                client.call_tool("ssh_check_connection")

    def test_call_tool_empty_result(self) -> None:
        """Empty content array raises MCPClientError."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"content": []},
        }

        client = MCPClient(base_url="http://localhost:8080/mcp")
        with patch("config_api.mcp_client.httpx.Client") as MockHTTP:
            mock_http_instance = MagicMock()
            mock_http_instance.post.return_value = mock_response
            mock_http_instance.__enter__ = MagicMock(return_value=mock_http_instance)
            mock_http_instance.__exit__ = MagicMock(return_value=False)
            MockHTTP.return_value = mock_http_instance

            with pytest.raises(MCPClientError, match="empty result"):
                client.call_tool("ssh_check_connection")

    def test_call_tool_non_json_text(self) -> None:
        """Non-JSON text in content[0].text returns fallback dict."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {
                "content": [{"type": "text", "text": "plain text output"}],
            },
        }

        client = MCPClient(base_url="http://localhost:8080/mcp")
        with patch("config_api.mcp_client.httpx.Client") as MockHTTP:
            mock_http_instance = MagicMock()
            mock_http_instance.post.return_value = mock_response
            mock_http_instance.__enter__ = MagicMock(return_value=mock_http_instance)
            mock_http_instance.__exit__ = MagicMock(return_value=False)
            MockHTTP.return_value = mock_http_instance

            result = client.call_tool("ssh_check_connection")

        assert result == {"output": "plain text output", "success": True}

    def test_request_id_increments(self) -> None:
        """Each call increments the JSON-RPC request id."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.raise_for_status = MagicMock()
        mock_response.json.return_value = _make_jsonrpc_response('{"ok": true}')

        client = MCPClient(base_url="http://localhost:8080/mcp")
        with patch("config_api.mcp_client.httpx.Client") as MockHTTP:
            mock_http_instance = MagicMock()
            mock_http_instance.post.return_value = mock_response
            mock_http_instance.__enter__ = MagicMock(return_value=mock_http_instance)
            mock_http_instance.__exit__ = MagicMock(return_value=False)
            MockHTTP.return_value = mock_http_instance

            client.call_tool("ssh_check_connection")
            client.call_tool("ssh_check_connection")
            client.call_tool("ssh_check_connection")

        calls = mock_http_instance.post.call_args_list
        assert calls[0][1]["json"]["id"] == 1
        assert calls[1][1]["json"]["id"] == 2
        assert calls[2][1]["json"]["id"] == 3

    def test_default_url_from_env(self) -> None:
        """MCPClient falls back to MCP_SERVER_URL env var."""
        with patch.dict("os.environ", {"MCP_SERVER_URL": "http://custom:9090/mcp"}):
            client = MCPClient()
            assert client._base_url == "http://custom:9090/mcp"

    def test_default_url_constant(self) -> None:
        """MCPClient uses DEFAULT_MCP_SERVER_URL when no env var is set."""
        with patch.dict("os.environ", {}, clear=True):
            client = MCPClient()
            assert client._base_url == "http://mcp-ssh:8080/mcp"

    def test_explicit_url_overrides_env(self) -> None:
        """Explicit base_url parameter takes precedence over env var."""
        with patch.dict("os.environ", {"MCP_SERVER_URL": "http://env:9090/mcp"}):
            client = MCPClient(base_url="http://explicit:7070/mcp")
            assert client._base_url == "http://explicit:7070/mcp"
